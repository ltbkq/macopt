"""Reader/writer for VMware ``key = "value"`` documents.

Used for both the guest's ``.vmx`` and the global ``~/.vmware/preferences``
file: both are flat UTF-8 files of ``key = "value"`` lines with no sections
(observed on Workstation 26.0.1; the preference file's first line is
``.encoding = "UTF-8"``).

Design rules
------------
* Preserve everything we did not touch, byte for byte (comments, blank lines,
  ordering, odd spacing).
* Detect duplicate keys instead of silently overwriting them.
* Writing is atomic: temp file in the same directory -> fsync -> ``os.replace``
  -> restore the original mode. A crash can never truncate a live ``.vmx``.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

# key chars: VMware keys are ASCII alnum plus '.' ':' '-' (e.g. "sata0:1.present")
_KV_RE = re.compile(
    r"^(?P<lead>\s*)(?P<key>[A-Za-z0-9_][A-Za-z0-9_.:\-]*)(?P<gap1>\s*)=(?P<gap2>\s*)(?P<value>.*)$"
)


def decode_value(raw: str) -> str:
    """Strip the surrounding quotes and undo VMware's backslash escapes."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        body = s[1:-1]
        out: list[str] = []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                if nxt in ('"', "\\"):
                    out.append(nxt)
                    i += 2
                    continue
                if nxt in ("n", "t"):
                    out.append("\n" if nxt == "n" else "\t")
                    i += 2
                    continue
            out.append(ch)
            i += 1
        return "".join(out)
    return s


def encode_value(value: str) -> str:
    """Always quote, escaping backslashes and double quotes."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


@dataclass(frozen=True)
class Entry:
    key: str
    value: str  # decoded
    raw: str  # original line including newline
    lineno: int  # 1-based
    raw_value: str  # as written in the file (still quoted if quoted)

    @property
    def quoted(self) -> bool:
        return self.raw_value.strip().startswith('"')


class Document:
    """An in-memory, order-preserving view of a ``key = "value"`` file."""

    def __init__(self, path: str | Path, lines: list[str]) -> None:
        self.path = Path(path)
        self._lines = lines
        self.entries: dict[str, list[Entry]] = {}
        self._parse()

    # -- construction ------------------------------------------------------ #

    @classmethod
    def load(cls, path: str | Path) -> Document:
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="surrogateescape")
        # keep line terminators so round-tripping is byte-exact
        lines = text.splitlines(keepends=True)
        return cls(p, lines)

    @classmethod
    def from_text(cls, text: str, path: str | Path = "<memory>") -> Document:
        return cls(Path(path), text.splitlines(keepends=True))

    def _parse(self) -> None:
        for idx, raw in enumerate(self._lines, start=1):
            stripped = raw.rstrip("\r\n")
            if not stripped.strip():
                continue
            if stripped.lstrip().startswith("#") or stripped.lstrip().startswith("//"):
                continue
            m = _KV_RE.match(stripped)
            if not m:
                continue
            key = m.group("key")
            raw_value = m.group("value")
            entry = Entry(
                key=key,
                value=decode_value(raw_value),
                raw=raw,
                lineno=idx,
                raw_value=raw_value,
            )
            self.entries.setdefault(key, []).append(entry)

    # -- queries ----------------------------------------------------------- #

    @property
    def duplicates(self) -> dict[str, int]:
        """Keys that appear more than once (informational: VMware keeps last)."""
        return {k: len(v) for k, v in self.entries.items() if len(v) > 1}

    def has(self, key: str) -> bool:
        return key in self.entries

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return the effective value. VMware applies lines in order -> last wins."""
        items = self.entries.get(key)
        return items[-1].value if items else default

    def get_all(self, key: str) -> list[str]:
        return [e.value for e in self.entries.get(key, [])]

    def as_dict(self) -> dict[str, str]:
        return {k: v[-1].value for k, v in self.entries.items()}

    def keys(self) -> list[str]:
        return list(self.entries.keys())

    def raw_lines(self) -> list[str]:
        return list(self._lines)

    # -- mutation ---------------------------------------------------------- #

    def set(self, key: str, value: str) -> tuple[str, str | None]:
        """Set ``key`` in memory. Returns ``(op, before_value)``.

        ``op`` is ``added`` / ``modified`` / ``unchanged`` (mirror of
        :mod:`macopt.model`). On duplicates only the last (effective) line is
        rewritten; the caller gets a warning through :meth:`duplicate_warning`.
        """
        before = self.get(key)
        if before is None:
            line = f"{key} = {encode_value(value)}\n"
            self._lines.append(line)
            self.entries[key] = [
                Entry(key=key, value=value, raw=line, lineno=len(self._lines), raw_value=encode_value(value))
            ]
            return "added", None
        if before == value:
            return "unchanged", before
        items = self.entries[key]
        target = items[-1]
        m = _KV_RE.match(target.raw.rstrip("\r\n"))
        assert m is not None  # it parsed once, it parses again
        newline = "\n" if target.raw.endswith("\n") else ""
        new_raw = (
            f"{m.group('lead')}{m.group('key')}{m.group('gap1')}="
            f"{m.group('gap2')}{encode_value(value)}{newline}"
        )
        self._lines[target.lineno - 1] = new_raw
        items[-1] = Entry(
            key=key,
            value=value,
            raw=new_raw,
            lineno=target.lineno,
            raw_value=encode_value(value),
        )
        return "modified", before

    def _shift_linenos(self, *, below: int) -> None:
        """Move stored line numbers of every entry *under* ``below`` up by one.

        ``Entry.lineno`` is an absolute 1-based position, so closing a gap in
        ``_lines`` invalidates the entries that sit *after* it (not before it).
        Every mutation that removes a line must call this, otherwise the next
        :meth:`set` writes its value onto a neighbouring key's line — a
        silent, wrong-key edit that a read-back check of only the changed
        keys will not notice.
        """
        for key, items in self.entries.items():
            if any(e.lineno > below for e in items):
                self.entries[key] = [
                    replace(e, lineno=e.lineno - 1) if e.lineno > below else e for e in items
                ]

    def delete(self, key: str) -> tuple[str, str | None]:
        """Remove every line for ``key``. Returns ``(op, before_value)``."""
        items = self.entries.get(key)
        if not items:
            return "unchanged", None
        before = items[-1].value
        # Capture the positions first, then delete bottom-up so that a smaller
        # line number can never shift underneath us mid-loop.
        for lineno in sorted((e.lineno for e in items), reverse=True):
            del self._lines[lineno - 1]
            self._shift_linenos(below=lineno)
        del self.entries[key]
        return ("removed", before) if before is not None else ("unchanged", None)

    def render(self) -> str:
        return "".join(self._lines)

    # -- persistence ------------------------------------------------------- #

    def write_atomic(self, *, fsync: bool = True, mode: int | None = None) -> dict[str, object]:
        """Atomically replace the file. Returns a small report dict.

        Refuses to write when the target does not exist yet (caller decides);
        the caller is responsible for backing up first.
        """
        target = self.path
        original_mode = mode
        if original_mode is None and target.exists():
            original_mode = target.stat().st_mode & 0o7777
        data = self.render().encode("utf-8", errors="surrogateescape")
        directory = str(target.parent)
        fd, tmp_path = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".macopt", dir=directory)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                if fsync:
                    os.fsync(fh.fileno())
            if original_mode is not None:
                os.chmod(tmp_path, original_mode)
            os.replace(tmp_path, target)
            if fsync:
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        return {
            "path": str(target),
            "bytes": len(data),
            "mode": oct(original_mode) if original_mode is not None else None,
        }


def duplicate_warning(doc: Document) -> str | None:
    dups = doc.duplicates
    if not dups:
        return None
    shown = ", ".join(f"{k}x{n}" for k, n in sorted(dups.items())[:8])
    more = "" if len(dups) <= 8 else f" (+{len(dups) - 8} more)"
    return f"duplicate keys present (last line wins): {shown}{more}"

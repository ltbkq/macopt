"""Run context: verbosity, machine-readable output and progress lines.

Two output channels only:

* ``out()``  — the payload (human table by default, JSON with ``--json``),
* ``note()`` — diagnostics that always go to stderr so they never pollute
  piped JSON.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Context:
    verbose: int = 0
    quiet: bool = False
    as_json: bool = False
    yes: bool = False
    dry_run: bool = False
    _stream: Any = field(default_factory=lambda: sys.stdout, repr=False)
    _err: Any = field(default_factory=lambda: sys.stderr, repr=False)

    # -- diagnostics ------------------------------------------------------- #

    def note(self, msg: str, level: int = 0) -> None:
        """stderr diagnostic; shown when ``verbose >= level`` (level 0 = always)."""
        if self.quiet and level > 0:
            return
        if level > 0 and self.verbose < level:
            return
        print(msg, file=self._err)

    def warn(self, msg: str) -> None:
        print(f"warning: {msg}", file=self._err)

    # -- payload ----------------------------------------------------------- #

    def out(self, payload: Any, human: str | None = None) -> None:
        """Emit the command payload: JSON when requested, else the text view."""
        if self.as_json:
            print(json.dumps(payload, indent=2, ensure_ascii=False, default=str), file=self._stream)
        elif human is not None:
            print(human, file=self._stream)

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
        if self.as_json:
            return
        body = [[("" if c is None else str(c)) for c in row] for row in rows]
        widths = [len(h) for h in headers]
        for row in body:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(cell))
        line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(line, file=self._stream)
        print("  ".join("-" * w for w in widths), file=self._stream)
        for row in body:
            print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)), file=self._stream)

    def confirm(self, question: str) -> bool:
        """Ask before a real (non-dry-run) write unless ``--yes`` was passed."""
        if self.yes or self.dry_run:
            return True
        if not sys.stdin.isatty():
            return False
        answer = input(f"{question} [y/N] ").strip().lower()
        return answer in ("y", "yes")


def status_glyph(status: str) -> str:
    return {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN", "SKIP": "SKIP"}.get(status, status)

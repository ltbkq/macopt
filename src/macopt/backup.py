"""Timestamped backups, manifest, history and restore (DESIGN §4.12).

Layout (everything lives under the caller-supplied state root):

```
$state_root/
├── backups/<vm-slug>/<id>/
│   ├── <name>.vmx        # byte copy of the file as it was before the write
│   └── manifest.json     # schema 1: tool/argv/host/target/files/before/after/changes
└── history.jsonl         # append-only, one summary line per finalised backup
```

``<id>`` is ``YYYYMMDDTHHMMSSZ-<sha8>`` (UTC + the first 8 hex of the
original's sha256), disambiguated with a counter when two snapshots collide
inside the same second.

Guarantees:

* the stored copy is verified against the manifest hash before any restore —
  a damaged backup is refused (:class:`~macopt.errors.VerificationError`),
* restoring always snapshots the *current* file first, so a restore can
  itself be undone,
* writes are atomic (same-dir temp file + fsync + ``os.replace``) and restore
  reproduces the recorded mode and mtime,
* a restore refuses to run while the VM is in use (same precondition as
  :func:`macopt.writer.apply`).

BackupManager never looks outside its own state root and the target ``.vmx``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .errors import PreconditionError, UnknownStateError, UsageError, VerificationError
from .vmxfile import Document
from .writer import check_precondition

__all__ = ["BackupManager", "BackupRecord"]

MANIFEST_SCHEMA = 1
HISTORY_NAME = "history.jsonl"

_DISALLOWED = re.compile(r"[^a-z0-9]+")


@dataclass
class BackupRecord:
    id: str
    dir: Path
    created_utc: str
    manifest: dict[str, Any]

    @property
    def stored_file(self) -> Path:
        """Path of the stored original copy (``manifest.files[0]``)."""
        files = self.manifest.get("files") or []
        name = files[0].get("name") if files else None
        if not name:
            raise VerificationError(f"backup {self.id}: manifest has no files entry")
        return self.dir / str(name)

    @property
    def before_sha256(self) -> str:
        files = self.manifest.get("files") or []
        return str(files[0].get("sha256") or (self.manifest.get("before") or {}).get("sha256") or "")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return _sha256_bytes(data)


def _count_lines(data: bytes) -> int:
    if not data:
        return 0
    return len(data.splitlines())


def _slugify(stem: str) -> str:
    slug = _DISALLOWED.sub("-", stem.lower()).strip("-")
    slug = slug[:48].strip("-")
    return slug or "vm"


def _same_path(a: object, b: object) -> bool:
    try:
        return os.path.abspath(str(a)) == os.path.abspath(str(b))
    except (OSError, ValueError):  # pragma: no cover - defensive
        return str(a) == str(b)


def _change_to_dict(change: Any) -> dict[str, Any]:
    to_dict = getattr(change, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    if isinstance(change, Mapping):
        return dict(change)
    raise TypeError(f"unsupported change entry: {change!r}")


def _host_to_dict(host: Any) -> dict[str, Any]:
    if host is None:
        return {}
    to_dict = getattr(host, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    if isinstance(host, Mapping):
        return dict(host)
    raise TypeError(f"unsupported host entry: {host!r}")


def _tool_version(value: Any) -> str:
    if isinstance(value, tuple | list):
        return ".".join(str(part) for part in value)
    return str(value)


def _atomic_write_bytes(
    path: Path,
    data: bytes,
    *,
    mode: int | None = None,
    mtime_ns: int | None = None,
) -> None:
    """Same-dir temp file -> fsync -> os.replace, restoring mode/mtime."""
    path.parent.mkdir(parents=True, exist_ok=True)
    directory = str(path.parent)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".macopt", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        if mtime_ns is not None:
            os.utime(path, ns=(mtime_ns, mtime_ns))
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _ordered_keys(first: Document, second: Document) -> list[str]:
    keys = list(first.keys())
    seen = set(keys)
    keys.extend(key for key in second.keys() if key not in seen)
    return keys


def _diff_docs(before: Document, after: Document) -> list[dict[str, Any]]:
    """Key-level changes that turn ``before`` into ``after`` (last line wins)."""
    entries: list[dict[str, Any]] = []
    for key in _ordered_keys(before, after):
        old = before.get(key)
        new = after.get(key)
        if old == new:
            continue
        if old is None:
            op = "added"
        elif new is None:
            op = "removed"
        else:
            op = "modified"
        entries.append({"key": key, "op": op, "before": old, "after": new})
    return entries


def _doc_from_bytes(data: bytes, path: Path) -> Document:
    return Document.from_text(data.decode("utf-8", errors="surrogateescape"), path)


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #


class BackupManager:
    def __init__(self, state_root: Path, vmx_path: Path) -> None:
        self.state_root = Path(state_root)
        self.vmx_path = Path(vmx_path)
        self.backups_root = self.state_root / "backups"
        self.history_path = self.state_root / HISTORY_NAME

    # -- identity ---------------------------------------------------------- #

    @property
    def slug(self) -> str:
        return _slugify(self.vmx_path.stem)

    def _record_dir(self, backup_id: str) -> Path:
        return self.backups_root / self.slug / backup_id

    # -- create / finalize ------------------------------------------------- #

    def create_snapshot(self) -> BackupRecord:
        """Copy the current ``.vmx`` plus a schema-1 manifest skeleton."""
        data = self.vmx_path.read_bytes()
        stat = self.vmx_path.stat()
        digest = _sha256_bytes(data)

        created = datetime.now(UTC)
        created_utc = created.strftime("%Y-%m-%dT%H:%M:%SZ")
        base_id = f"{created.strftime('%Y%m%dT%H%M%SZ')}-{digest[:8]}"
        backup_id = base_id
        counter = 1
        while self._record_dir(backup_id).exists():
            counter += 1
            backup_id = f"{base_id}-{counter}"

        record_dir = self._record_dir(backup_id)
        record_dir.mkdir(parents=True, exist_ok=True)

        stored = record_dir / self.vmx_path.name
        stored.write_bytes(data)
        os.chmod(stored, stat.st_mode & 0o7777)
        os.utime(stored, ns=(stat.st_mtime_ns, stat.st_mtime_ns))

        manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "id": backup_id,
            "created_utc": created_utc,
            "tool": {"name": "macopt", "version": ""},
            "argv": [],
            "host": {},
            "target": {"path": str(self.vmx_path)},
            "files": [
                {
                    "name": self.vmx_path.name,
                    "sha256": digest,
                    "mode": oct(stat.st_mode & 0o7777),
                    "size": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "role": "original",
                }
            ],
            "before": {"sha256": digest, "lines": _count_lines(data)},
        }
        _atomic_write_bytes(record_dir / "manifest.json", _manifest_bytes(manifest))
        return BackupRecord(id=backup_id, dir=record_dir, created_utc=created_utc, manifest=manifest)

    def finalize(
        self,
        record: BackupRecord,
        *,
        changes: Iterable[Any] = (),
        argv: Sequence[str] = (),
        host: Any = None,
        tool_version: Any = __version__,
        after_sha256: str,
    ) -> BackupRecord:
        """Fill in after/changes/tool/argv/host, persist and log to history."""
        manifest = dict(record.manifest)
        manifest["tool"] = {"name": "macopt", "version": _tool_version(tool_version)}
        manifest["argv"] = [str(a) for a in argv]
        manifest["host"] = _host_to_dict(host)
        manifest["changes"] = [_change_to_dict(c) for c in changes]

        data = b""
        try:
            data = self.vmx_path.read_bytes()
        except OSError:
            pass
        manifest["after"] = {
            "sha256": str(after_sha256),
            "lines": _count_lines(data) if data else 0,
        }

        _atomic_write_bytes(record.dir / "manifest.json", _manifest_bytes(manifest))
        record.manifest = manifest
        self._append_history(manifest, record.dir)
        return record

    def _append_history(self, manifest: Mapping[str, Any], record_dir: Path) -> None:
        entry = {
            "schema": MANIFEST_SCHEMA,
            "id": manifest.get("id", ""),
            "created_utc": manifest.get("created_utc", ""),
            "target": (manifest.get("target") or {}).get("path", ""),
            "backup_dir": str(record_dir),
            "before": (manifest.get("before") or {}).get("sha256", ""),
            "after": (manifest.get("after") or {}).get("sha256", ""),
            "changes": len(manifest.get("changes") or []),
            "argv": manifest.get("argv", []),
            "tool": manifest.get("tool", {}),
        }
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        self.state_root.mkdir(parents=True, exist_ok=True)
        with open(self.history_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # -- query ------------------------------------------------------------- #

    def list(self) -> list[BackupRecord]:
        """Every backup of *this* ``.vmx``, newest first."""
        records: list[BackupRecord] = []
        if not self.backups_root.is_dir():
            return records
        try:
            slug_dirs = sorted(self.backups_root.iterdir())
        except OSError:  # pragma: no cover - defensive
            return records
        for slug_dir in slug_dirs:
            if not slug_dir.is_dir() or slug_dir.name != self.slug:
                continue
            try:
                rec_dirs = sorted(slug_dir.iterdir())
            except OSError:  # pragma: no cover - defensive
                continue
            for rec_dir in rec_dirs:
                manifest_path = rec_dir / "manifest.json"
                if not manifest_path.is_file():
                    continue
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(manifest, dict) or "id" not in manifest:
                    continue
                target = (manifest.get("target") or {}).get("path")
                if target is not None and not _same_path(target, self.vmx_path):
                    continue
                records.append(
                    BackupRecord(
                        id=str(manifest["id"]),
                        dir=rec_dir,
                        created_utc=str(manifest.get("created_utc", "")),
                        manifest=manifest,
                    )
                )
        records.sort(key=lambda r: (r.created_utc, r.id), reverse=True)
        return records

    def _resolve(self, backup_id: str | None, *, required: bool) -> BackupRecord | None:
        records = self.list()
        if not records:
            if required:
                raise UnknownStateError(
                    f"no backups recorded for {self.vmx_path}",
                    hint="run an apply first, or check --state-dir",
                )
            return None
        if backup_id is None:
            return records[0]
        for record in records:
            if record.id == backup_id:
                return record
        known = ", ".join(r.id for r in records[:5])
        raise UsageError(f"unknown backup id {backup_id!r} (known: {known})")

    def diff(self, backup_id: str | None = None) -> list[dict[str, Any]]:
        """Key-level diff ``backup -> current file`` (nothing = empty list)."""
        record = self._resolve(backup_id, required=False)
        if record is None:
            return []
        original = _doc_from_bytes(record.stored_file.read_bytes(), record.stored_file)
        current = self._current_doc()
        entries = _diff_docs(original, current)
        for entry in entries:
            entry["backup_id"] = record.id
        return entries

    def _current_doc(self) -> Document:
        if not self.vmx_path.is_file():
            return Document.from_text("", self.vmx_path)
        return Document.load(self.vmx_path)

    # -- restore ----------------------------------------------------------- #

    def restore(self, backup_id: str | None = None, *, dry_run: bool = False) -> dict[str, Any]:
        """Roll the ``.vmx`` back to a backup (default: the newest one)."""
        record = self._resolve(backup_id, required=True)
        assert record is not None

        stored = record.stored_file
        expected = record.before_sha256
        actual = _sha256_file(stored)
        if not expected or actual != expected:
            raise VerificationError(
                f"backup {record.id} is damaged (stored {actual or 'missing'}, "
                f"manifest {expected or 'unset'}); refusing to restore"
            )

        restored_bytes = stored.read_bytes()
        current_sha = _sha256_file(self.vmx_path)
        current_doc = self._current_doc()
        stored_doc = _doc_from_bytes(restored_bytes, stored)
        # How the current file must change to become the backup again.
        preview = _diff_docs(current_doc, stored_doc)

        files = (record.manifest.get("files") or [{}])[0]
        mode = _parse_mode(files.get("mode"))
        mtime_ns = files.get("mtime_ns")

        if dry_run:
            return {
                "backup_id": record.id,
                "target": str(self.vmx_path),
                "dry_run": True,
                "would_restore": True,
                "sha256_before": current_sha,
                "sha256_after": expected,
                "changes": preview,
            }

        reasons = check_precondition(self.vmx_path)
        if reasons:
            raise PreconditionError(
                "refusing to restore a .vmx that is in use: " + "; ".join(reasons),
                hint="power off the virtual machine and close the VMware GUI first",
            )

        # 1) keep the current file safe so a restore can be undone
        snapshot = self.create_snapshot()
        self.finalize(
            snapshot,
            changes=[],
            argv=[],
            host=None,
            tool_version=__version__,
            after_sha256=current_sha,
        )

        # 2) atomic rollback with the recorded mode + mtime
        _atomic_write_bytes(self.vmx_path, restored_bytes, mode=mode, mtime_ns=mtime_ns)

        # 3) verify
        rolled_back = _sha256_file(self.vmx_path)
        if rolled_back != expected:
            raise VerificationError(
                f"restore verification failed for {self.vmx_path}: "
                f"{rolled_back} != {expected}"
            )

        return {
            "backup_id": record.id,
            "target": str(self.vmx_path),
            "dry_run": False,
            "would_restore": True,
            "sha256_before": current_sha,
            "sha256_after": rolled_back,
            "verified": True,
            "snapshot": {"id": snapshot.id, "dir": str(snapshot.dir)},
            "changes": preview,
        }

    # -- maintenance ------------------------------------------------------- #

    def verify(self) -> list[dict[str, Any]]:
        """Re-hash every stored copy against its manifest."""
        results: list[dict[str, Any]] = []
        for record in self.list():
            entry: dict[str, Any] = {
                "id": record.id,
                "dir": str(record.dir),
                "ok": True,
                "expected": "",
                "actual": "",
                "detail": "",
            }
            files = record.manifest.get("files") or []
            expected = str(files[0].get("sha256", "")) if files else ""
            entry["expected"] = expected
            if not expected:
                entry.update(ok=False, detail="manifest has no files[0].sha256")
                results.append(entry)
                continue
            before = (record.manifest.get("before") or {}).get("sha256")
            if before and before != expected:
                entry.update(
                    ok=False,
                    detail=f"manifest before.sha256 {before} != files[0].sha256 {expected}",
                )
                results.append(entry)
                continue
            stored = record.stored_file
            if not stored.is_file():
                entry.update(ok=False, detail=f"stored copy missing: {stored}")
                results.append(entry)
                continue
            actual = _sha256_file(stored)
            entry["actual"] = actual
            if actual != expected:
                entry.update(
                    ok=False,
                    detail=f"hash mismatch: stored {actual}, manifest {expected}",
                )
            results.append(entry)
        return results

    def prune(self, keep: int) -> list[str]:
        """Delete all but the ``keep`` newest backups; return deleted ids."""
        keep = max(int(keep), 0)
        records = self.list()
        doomed = list(reversed(records[keep:]))  # oldest first
        deleted: list[str] = []
        for record in doomed:
            shutil.rmtree(record.dir)
            deleted.append(record.id)
        if deleted and self.backups_root.is_dir():
            for slug_dir in self.backups_root.iterdir():
                if slug_dir.is_dir():
                    try:
                        if not any(slug_dir.iterdir()):
                            slug_dir.rmdir()
                    except OSError:  # pragma: no cover - concurrent activity
                        pass
        return deleted


# --------------------------------------------------------------------------- #


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _parse_mode(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 8)
    except ValueError:
        return None

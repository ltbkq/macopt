"""Plan -> on-disk ``.vmx`` writer (DESIGN §4.12).

Responsibilities:

* **three-state idempotency** — a missing key becomes ``added``, a key whose
  value already matches becomes ``unchanged``, a key holding a different value
  becomes ``modified``, and ``Param.remove`` yields ``removed`` (or
  ``unchanged`` when the key is already absent);
* **confirmation gate** — overwriting an existing value (``modified`` /
  ``removed``) requires ``force`` or ``yes``; otherwise nothing at all is
  written and :class:`~macopt.errors.ConflictError` (exit 5) is raised;
* **error classification** — ``plan.errors`` strings carry prefixes and select
  the exception type: ``whitelist:`` -> :class:`~macopt.errors.WhitelistError`
  (exit 6), ``confirm:`` / anything else -> :class:`~macopt.errors.ConflictError`
  (exit 5). ``--force`` lifts ``confirm:`` errors (they exist for
  ``Param.needs_confirmation``);
* **precondition check** — a ``<vmx>.lck`` directory, its ``MODE`` file or a
  live process whose ``/proc/<pid>/cmdline`` contains the absolute ``.vmx``
  path block the write with :class:`~macopt.errors.PreconditionError` (exit 3);
* **transactional write + read-back** — mutations go through
  ``Document.set`` / ``Document.delete``, one ``Document.write_atomic()``
  (same-dir temp file + fsync + ``os.replace``), then a byte-level and
  key-level read-back verification
  (:class:`~macopt.errors.VerificationError` on mismatch).

This module never creates backups: the caller (``cli``) owns the
:class:`macopt.backup.BackupManager` and wraps :func:`apply` with
``create_snapshot`` / ``finalize`` (and restores on failure). ``apply`` also
never guesses — ``--dry-run`` short-circuits before every gate and cannot
touch a file or create state.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from .errors import ConflictError, PreconditionError, VerificationError, WhitelistError
from .model import OP_ADDED, OP_MODIFIED, OP_REMOVED, OP_UNCHANGED, Change, Param, Plan
from .vmxfile import Document, duplicate_warning

__all__ = [
    "ApplyResult",
    "KeyPolicy",
    "apply",
    "build_plan",
    "check_precondition",
]

#: Injected whitelist: ``True`` = the key is recognised by the installed
#: VMware. ``None`` disables the whitelist entirely (unit tests, offline use).
KeyPolicy = Callable[[str], bool]

#: Prefixes that map ``plan.errors`` entries onto process exit codes.
WHITELIST_PREFIX = "whitelist:"
CONFIRM_PREFIX = "confirm:"

_OP_KEYS = (OP_ADDED, OP_MODIFIED, OP_UNCHANGED, OP_REMOVED)


@dataclass
class ApplyResult:
    """Outcome of one :func:`apply` call (mirrors the §5.1 JSON payload)."""

    path: str
    dry_run: bool
    written: bool
    ops: dict[str, int]  # added / modified / unchanged / removed
    sha256_before: str
    sha256_after: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "dry_run": self.dry_run,
            "written": self.written,
            "ops": dict(self.ops),
            "sha256_before": self.sha256_before,
            "sha256_after": self.sha256_after,
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _sha256_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return hashlib.sha256(data).hexdigest()


def _empty_ops() -> dict[str, int]:
    return {op: 0 for op in _OP_KEYS}


def _change_for(doc: object, param: Param) -> Change:
    """Classify one :class:`Param` against the current document (three-state)."""
    getter = doc.get
    current = getter(param.key)  # None when the key is absent

    if param.remove:
        op = OP_REMOVED if current is not None else OP_UNCHANGED
        return Change(
            key=param.key,
            before=current,
            after=None,
            op=op,
            module=param.module,
            reason=param.reason,
        )

    if current is None:
        op, before = OP_ADDED, None
    elif current == param.value:
        op, before = OP_UNCHANGED, current
    else:
        op, before = OP_MODIFIED, current
    return Change(
        key=param.key,
        before=before,
        after=param.value,
        op=op,
        module=param.module,
        reason=param.reason,
    )


# --------------------------------------------------------------------------- #
# Precondition (DESIGN §4.12 "pre")
# --------------------------------------------------------------------------- #


def check_precondition(vmx_path: str | Path, *, proc_root: str | Path = "/proc") -> list[str]:
    """Return the reasons the ``.vmx`` must not be written right now.

    An empty list means "writable". Detects:

    1. the VMware lock directory ``<vmx>.lck`` (or any lock marker at that
       path),
    2. the ``MODE`` file inside that lock directory,
    3. any live process whose ``/proc/<pid>/cmdline`` contains the **absolute**
       path of the ``.vmx`` (read-only scan; ``proc_root`` is injectable so
       tests never touch the real ``/proc``).

    Our own pid is skipped: ``macopt apply <vmx>`` legitimately carries the
    path in its own argv.
    """
    target = Path(os.path.abspath(os.fspath(vmx_path)))
    reasons: list[str] = []

    lock = Path(str(target) + ".lck")
    if lock.is_dir():
        reasons.append(f"lock directory present: {lock}")
        mode_file = lock / "MODE"
        if mode_file.is_file():
            try:
                mode = mode_file.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                mode = ""
            suffix = f" ({mode})" if mode else ""
            reasons.append(f"lock MODE file present: {mode_file}{suffix}")
    elif lock.exists():
        # Not a directory, but still a lock marker at the canonical path.
        reasons.append(f"lock marker present: {lock}")

    needle = str(target).encode("utf-8", errors="surrogateescape")
    proc = Path(proc_root)
    if proc.is_dir():
        try:
            entries = list(proc.iterdir())
        except OSError:
            entries = []
        own_pid = os.getpid()
        for entry in entries:
            if not entry.name.isdigit() or int(entry.name) == own_pid:
                continue
            try:
                raw = (entry / "cmdline").read_bytes()
            except OSError:
                continue  # vanished / permission denied: read-only scan, skip
            if needle and needle in raw:
                cmdline = raw.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
                reasons.append(
                    f"process {entry.name} references this .vmx: {cmdline[:160]}"
                )
    return reasons


# --------------------------------------------------------------------------- #
# Plan builder
# --------------------------------------------------------------------------- #


def build_plan(
    doc: object,
    params: Iterable[Param],
    *,
    key_policy: KeyPolicy | None = None,
    allow_unknown_keys: bool = False,
    confirmed: bool = False,
) -> Plan:
    """Diff ``params`` against ``doc`` and collect warnings/errors.

    ``doc`` is a :class:`~macopt.vmxfile.Document` or any mapping with
    ``get(key)``. Error strings are prefixed so :func:`apply` can pick the
    exit code:

    * ``whitelist: …`` — key rejected by ``key_policy`` (downgraded to a
      warning when ``allow_unknown_keys``),
    * ``confirm: …`` — ``Param.needs_confirmation`` with ``confirmed=False``,
      emitted only for effective changes so a second, identical plan stays
      idempotent,
    * anything else (``rule: …`` produced by other stages) — conflict.

    Duplicate keys inside ``doc`` and repeated targets inside ``params`` only
    warn: VMware keeps the last line, so the planner follows the same rule.
    """
    items = list(params)
    plan = Plan(params=items)

    # A key targeted by several Params is applied in order -> last wins.
    occurrences: dict[str, int] = {}
    for param in items:
        occurrences[param.key] = occurrences.get(param.key, 0) + 1
    superseded: set[int] = set()
    if any(count > 1 for count in occurrences.values()):
        last_index = {param.key: i for i, param in enumerate(items)}
        for i, param in enumerate(items):
            if occurrences[param.key] > 1 and last_index[param.key] != i:
                superseded.add(i)
        for key, count in sorted(occurrences.items()):
            if count > 1:
                plan.warnings.append(
                    f"plan targets key {key!r} more than once ({count} times); "
                    "the last Param wins"
                )

    for i, param in enumerate(items):
        if i in superseded:
            continue

        change = _change_for(doc, param)
        plan.changes.append(change)

        if key_policy is not None and not key_policy(param.key):
            message = (
                f"{WHITELIST_PREFIX} key {param.key!r} is not recognised by the "
                "installed VMware key set"
            )
            if allow_unknown_keys:
                plan.warnings.append(f"{message} (allowed by allow_unknown_keys)")
            else:
                plan.errors.append(message)

        if param.needs_confirmation and not confirmed and change.op != OP_UNCHANGED:
            plan.errors.append(
                f"{CONFIRM_PREFIX} key {param.key!r} is flagged needs_confirmation "
                f"({param.risk_note or param.reason}); re-plan with confirmed=True "
                "or apply with --force"
            )

    dup = duplicate_warning(doc) if hasattr(doc, "duplicates") else None
    if dup:
        plan.warnings.append(dup)
    return plan


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #


def _raise_for_errors(plan: Plan, *, force: bool) -> None:
    """Map ``plan.errors`` onto the exception carrying the right exit code."""
    errors = [e for e in plan.errors if not (force and e.startswith(CONFIRM_PREFIX))]
    if not errors:
        return
    message = "\n".join(errors)
    if any(e.startswith(WHITELIST_PREFIX) for e in errors):
        raise WhitelistError(
            message,
            hint="pass allow_unknown_keys (--allow-unknown-keys) to write it anyway",
        )
    raise ConflictError(
        message,
        hint="fix the plan, or re-run with --force to accept the flagged items",
    )


def _verify_written(doc: Document, plan: Plan, path: Path) -> None:
    """Read the file back and assert every changed key reached its target."""
    expected = doc.render().encode("utf-8", errors="surrogateescape")
    try:
        actual = path.read_bytes()
    except OSError as exc:  # pragma: no cover - only on I/O failure after write
        raise VerificationError(f"cannot re-read {path} after writing: {exc}") from exc
    if actual != expected:
        raise VerificationError(
            f"post-write byte check failed for {path}: "
            f"{len(actual)} bytes on disk vs {len(expected)} rendered"
        )

    reread = Document.load(path)
    problems: list[str] = []
    for change in plan.changes:
        if change.op == OP_UNCHANGED:
            continue
        if change.op == OP_REMOVED:
            leftover = reread.get(change.key)
            if leftover is not None:
                problems.append(f"{change.key} should be gone but is {leftover!r}")
        else:
            got = reread.get(change.key)
            if got != change.after:
                problems.append(f"{change.key}: expected {change.after!r}, re-read {got!r}")

    # Whole-document cross-check. The loop above only inspects keys the plan
    # touched, but a stale line number would corrupt a key the plan never
    # mentioned — so compare *every* key, plus the duplicate structure.
    memory, on_disk = doc.as_dict(), reread.as_dict()
    for key, value in memory.items():
        if on_disk.get(key) != value:
            problems.append(f"{key}: on disk {on_disk.get(key)!r} != in memory {value!r}")
    for key in on_disk:
        if key not in memory:
            problems.append(f"{key}: present on disk but absent from the document")
    if reread.duplicates != doc.duplicates:
        problems.append(f"duplicate keys changed: {doc.duplicates} -> {reread.duplicates}")
    if problems:
        raise VerificationError(
            "post-write read-back mismatch: " + "; ".join(problems)
        )


def apply(
    doc: Document,
    plan: Plan,
    *,
    force: bool = False,
    yes: bool = False,
    dry_run: bool = False,
) -> ApplyResult:
    """Execute ``plan`` against ``doc`` atomically.

    Gate order (DESIGN §4.12, §6):

    1. ``dry_run`` — always allowed, never reads ``/proc``, never writes,
       never creates state, and does not raise on ``plan.errors`` (the whole
       point of a dry run is to show the plan);
    2. ``plan.errors`` — whitelist -> exit 6, everything else -> exit 5;
    3. no effective change -> nothing to do (idempotent fast path);
    4. precondition (``.lck`` / running process) -> exit 3;
    5. ``modified``/``removed`` without ``force``/``yes`` -> exit 5.

    Only after all of that does the document get mutated, written once via
    ``write_atomic`` and read back for verification.
    """
    path = Path(doc.path)
    sha_before = _sha256_file(path)
    plan_counts = dict(plan.counts())

    if dry_run:
        return ApplyResult(
            path=str(path),
            dry_run=True,
            written=False,
            ops=plan_counts,
            sha256_before=sha_before,
            sha256_after=sha_before,
        )

    _raise_for_errors(plan, force=force)

    if not plan.effective:
        return ApplyResult(
            path=str(path),
            dry_run=False,
            written=False,
            ops=plan_counts,
            sha256_before=sha_before,
            sha256_after=sha_before,
        )

    reasons = check_precondition(path)
    if reasons:
        raise PreconditionError(
            "refusing to write a .vmx that is in use: " + "; ".join(reasons),
            hint="power off the virtual machine (not suspend) and close the "
            "VMware GUI, then re-run",
        )

    overwriting = [c.key for c in plan.effective if c.op in (OP_MODIFIED, OP_REMOVED)]
    if overwriting and not (force or yes):
        shown = ", ".join(overwriting[:8])
        more = "" if len(overwriting) <= 8 else f" (+{len(overwriting) - 8} more)"
        raise ConflictError(
            f"existing values differ and were not confirmed: {shown}{more}",
            hint="review the diff and re-run with --force or --yes",
        )

    # -- mutate in memory -------------------------------------------------- #
    ops = _empty_ops()
    dirty = False
    for change in plan.changes:
        if change.op == OP_UNCHANGED:
            ops[OP_UNCHANGED] += 1
            continue
        if change.op == OP_REMOVED:
            actual, _ = doc.delete(change.key)
        else:
            actual, _ = doc.set(change.key, change.after)
        ops[actual] = ops.get(actual, 0) + 1
        if actual != OP_UNCHANGED:
            dirty = True

    if not dirty:
        # A stale plan that no longer changes anything: still no write.
        return ApplyResult(
            path=str(path),
            dry_run=False,
            written=False,
            ops=ops,
            sha256_before=sha_before,
            sha256_after=sha_before,
        )

    # -- single atomic write + read-back ----------------------------------- #
    doc.write_atomic()
    _verify_written(doc, plan, path)

    return ApplyResult(
        path=str(path),
        dry_run=False,
        written=True,
        ops=ops,
        sha256_before=sha_before,
        sha256_after=_sha256_file(path),
    )

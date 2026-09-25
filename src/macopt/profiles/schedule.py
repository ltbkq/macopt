"""Host-side CPU scheduling: ``plan`` / ``bind`` / ``check`` (DESIGN §4.7).

This module is host-side only — it never produces ``.vmx`` ``Param`` objects
and never writes a file. It hands out copy-pasteable commands, can retune a
*running* process through ``taskset``, and can only ever **verify** a binding
by reading ``/proc/<pid>/status``.

Two measured findings drive the design (docs/evidence/03-cpu-tuning-module.md
line 223 and 228-234, mirrored in docs/DESIGN.md lines 323-324):

1. ``systemd-run --user --scope -p AllowedCPUs=0-11`` **silently does
   nothing** when the ``cpuset`` controller is not delegated to
   ``user@.service``: the command returns rc=0 yet the process keeps
   ``Cpus_allowed_list: 0-15``. Therefore ``plan()`` lists the **system-level**
   scope first and the note says so explicitly.
2. Verification must read ``/proc/<pid>/status``'s ``Cpus_allowed_list`` —
   ``systemctl show -p EffectiveCPUs`` returned *empty* on the reference host.

The system-level cpuset is a hard kernel limit: the guest's own
``sched_setaffinity`` calls are intersected down into the cpuset and cannot
escape it (03 report lines 228-234), while ``taskset`` only sets an affinity
mask that ``vmware-vmx`` may overwrite later (it imports ``sched_setaffinity``).
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Iterable
from typing import Any

from ..model import HostInfo

#: ``subprocess.run``-compatible callable; injected by tests so that no test
#: (or caller) can accidentally poke a real process.
Runner = Callable[..., Any]

#: Launcher path observed in /usr/share/applications/vmware-workstation.desktop
#: (``Exec=/usr/bin/vmware %U``; evidence: 03-cpu-tuning-module.md:33).
VMWARE_LAUNCHER = "/usr/bin/vmware"

#: Binding exists as long as the process does (scope dies / affinity dropped).
DURABILITY_PROCESS = "process-lifetime"
#: Desktop override survives reboots until the user edits it again.
DURABILITY_PERSISTENT = "persistent"

_INT_RE = re.compile(r"[0-9]+")


# --------------------------------------------------------------------------- #
# CPU list parsing / formatting
# --------------------------------------------------------------------------- #


def parse_allowed_list(spec: str) -> set[int]:
    """``"0-11,14"`` -> ``{0, ..., 11, 14}``; raises ``ValueError`` on junk.

    Accepts the kernel's ``Cpus_allowed_list`` syntax (comma separated ids and
    inclusive ranges, optional whitespace). Anything malformed — empty string,
    ``"8-"``, ``"a"``, ``"11-0"``, non-ASCII digits — raises instead of being
    partially accepted: binding to a half-parsed set would be worse than
    refusing.
    """
    if not isinstance(spec, str):
        raise ValueError(f"CPU list must be a string, got {type(spec).__name__}")
    text = spec.strip()
    if not text:
        raise ValueError("empty CPU list")
    out: set[int] = set()
    for part in text.split(","):
        item = part.strip()
        if not item:
            raise ValueError(f"empty element in CPU list {spec!r}")
        if "-" in item:
            lo_s, _, hi_s = item.partition("-")
            if not (_INT_RE.fullmatch(lo_s) and _INT_RE.fullmatch(hi_s)):
                raise ValueError(f"bad range {item!r} in CPU list {spec!r}")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"descending range {item!r} in CPU list {spec!r}")
            out.update(range(lo, hi + 1))
        else:
            if not _INT_RE.fullmatch(item):
                raise ValueError(f"bad CPU id {item!r} in CPU list {spec!r}")
            out.add(int(item))
    return out


def format_allowed_list(ids: Iterable[int]) -> str:
    """``{0..11, 14}`` -> ``"0-11,14"`` (sorted, ranges collapsed)."""
    values: set[int] = set()
    for value in ids:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"CPU ids must be non-negative ints, got {value!r}")
        values.add(value)
    if not values:
        return ""
    ordered = sorted(values)
    ranges: list[str] = []
    start = prev = ordered[0]
    for value in ordered[1:]:
        if value == prev + 1:
            prev = value
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = value
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


# --------------------------------------------------------------------------- #
# cpus derivation
# --------------------------------------------------------------------------- #


def _all_logical_cpus(host: HostInfo) -> list[int] | None:
    """Every logical CPU, preferring measured ids over an assumed 0..N-1 range."""
    union = sorted(set(host.p_cpus) | set(host.e_cpus))
    if host.logical_cpus and len(union) == host.logical_cpus:
        return union
    if host.logical_cpus:
        # HostInfo does not carry the online set; 0..N-1 is the normal Linux
        # numbering (only isolcpus/offline CPUs break it).
        return list(range(host.logical_cpus))
    return union or None


def resolve_cpus(host: HostInfo, profile: str, cpus: str | None = None) -> str | None:
    """CPU set for a profile: explicit ``cpus`` > P cores > all logical cores.

    Returns ``None`` when nothing can be determined — callers must degrade to
    "no binding" rather than invent CPU numbers (DESIGN §4.0 hard rule 2).
    Raises ``ValueError`` for a malformed explicit list or unknown profile.
    """
    if cpus is not None and cpus.strip():
        return format_allowed_list(parse_allowed_list(cpus))
    if profile in ("performance", "balanced"):
        # DESIGN lines 331-332: both tiers bind the P cores (reference host
        # 0-11); balanced keeps numvcpus, performance caps it at 12 vCPU.
        if host.p_cpus:
            return format_allowed_list(host.p_cpus)
        return None
    if profile == "throughput":
        # DESIGN line 333: all logical cores (reference host 0-15).
        all_cpus = _all_logical_cpus(host)
        return format_allowed_list(all_cpus) if all_cpus else None
    if profile == "passthrough":
        return None
    raise ValueError(f"unknown profile: {profile!r}")


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #


def plan(host: HostInfo, profile: str, cpus: str | None = None) -> list[dict[str, Any]]:
    """Three binding paths, ordered by reliability (DESIGN §4.7 schedule table).

    Returns a list of ``{label, command, needs_root, durability, note}`` with
    ``command`` as an argv **list** (never a shell string). An empty list means
    "no CPU set can be derived for this host/profile" — pass ``cpus`` explicitly
    (``macopt schedule plan --cpus 0-11``).
    """
    spec = resolve_cpus(host, profile, cpus)
    if not spec:
        return []
    # Validate what we are about to print (raises ValueError for junk input).
    parse_allowed_list(spec)

    system_scope_note = (
        "Kernel-hard cpuset: the guest's own sched_setaffinity calls are clipped into this set "
        "and cannot escape it. Use the SYSTEM scope on purpose — `systemd-run --user --scope "
        "-p AllowedCPUs=...` silently no-ops when cpuset is not delegated to user@.service "
        "(rc=0 while Cpus_allowed_list stays 0-15; measured, docs/DESIGN.md:323). Verify ONLY by "
        "reading `grep Cpus_allowed_list /proc/<pid>/status`; `systemctl show -p EffectiveCPUs` "
        "returned empty on the reference host (docs/DESIGN.md:324). Non-root shells may need "
        "polkit approval or sudo."
    )
    taskset_note = (
        "Unprivileged, works for a fresh launch (and `bind` applies it to a running process). "
        "Not a hard limit: vmware-vmx imports sched_setaffinity and may widen its own affinity "
        "again — always follow up with `macopt schedule check --pid <pid>`."
    )
    desktop_note = (
        f"Copy /usr/share/applications/vmware-workstation.desktop to ~/.local/share/applications/ "
        f"and prefix its Exec line with `taskset -c {spec}` so every GUI launch is pre-bound; "
        "user-level override, no root, reversible by deleting the copied file."
    )

    return [
        {
            "label": "systemd-run --scope (system-wide cpuset, hard limit)",
            "command": ["systemd-run", "--scope", "-p", f"AllowedCPUs={spec}", VMWARE_LAUNCHER],
            "needs_root": True,
            "durability": DURABILITY_PROCESS,
            "note": system_scope_note,
        },
        {
            "label": "taskset -c (unprivileged launch prefix)",
            "command": ["taskset", "-c", spec, VMWARE_LAUNCHER],
            "needs_root": False,
            "durability": DURABILITY_PROCESS,
            "note": taskset_note,
        },
        {
            "label": ".desktop Exec= (persistent user-level override)",
            "command": ["taskset", "-c", spec, VMWARE_LAUNCHER, "%U"],
            "needs_root": False,
            "durability": DURABILITY_PERSISTENT,
            "note": desktop_note,
        },
    ]


# --------------------------------------------------------------------------- #
# bind / check
# --------------------------------------------------------------------------- #


def bind(pid: int, cpus: str, *, runner: Runner = subprocess.run) -> dict[str, Any]:
    """``taskset -pc <cpus> <pid>`` against a running process.

    argv-list only — no shell, ever (DESIGN §7.9). Returns a report dict with
    ``rc`` / ``stdout`` / ``err`` (plus ``argv`` for auditability); a missing
    ``taskset`` binary yields ``rc=127`` instead of raising, so the CLI can
    print a useful message.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError(f"pid must be a positive int, got {pid!r}")
    parse_allowed_list(cpus)  # validate before touching any process
    argv = ["taskset", "-pc", cpus, str(pid)]
    try:
        result = runner(argv, capture_output=True, text=True, check=False, timeout=30)
    except FileNotFoundError:
        return {"pid": pid, "cpus": cpus, "argv": argv, "rc": 127, "stdout": "", "err": "taskset not found", "ok": False}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"pid": pid, "cpus": cpus, "argv": argv, "rc": 126, "stdout": "", "err": str(exc), "ok": False}

    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", "replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    rc = int(getattr(result, "returncode", 1))
    return {
        "pid": pid,
        "cpus": cpus,
        "argv": argv,
        "rc": rc,
        "stdout": str(stdout),
        "err": str(stderr),
        "ok": rc == 0,
    }


def check(pid: int, *, proc_root: str = "/proc") -> dict[str, Any]:
    """Read ``/proc/<pid>/status`` and report the *effective* allowed CPUs.

    This is the only trustworthy verification channel (see module docstring):
    cgroup tools lie by omission, the kernel's own status file does not.
    A missing file is reported (``found=False``), never raised.
    """
    path = os.path.join(proc_root, str(pid), "status")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return {
            "pid": pid,
            "path": path,
            "found": False,
            "name": None,
            "allowed_list": None,
            "allowed": None,
            "error": f"{exc.__class__.__name__}: {exc.strerror or exc}",
        }

    allowed_list: str | None = None
    name: str | None = None
    for line in text.splitlines():
        if line.startswith("Cpus_allowed_list:"):
            allowed_list = line.split(":", 1)[1].strip()
        elif line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
    if allowed_list is None:
        return {
            "pid": pid,
            "path": path,
            "found": True,
            "name": name,
            "allowed_list": None,
            "allowed": None,
            "error": "Cpus_allowed_list missing from status file",
        }
    return {
        "pid": pid,
        "path": path,
        "found": True,
        "name": name,
        "allowed_list": allowed_list,
        "allowed": sorted(parse_allowed_list(allowed_list)),
        "error": None,
    }

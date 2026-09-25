"""Static ``.vmx`` checks S1–S10 (DESIGN §4.2) — strictly read-only.

``run()`` always returns exactly ten :class:`~macopt.model.CheckResult`
objects in the fixed order S1..S10 so CLI output, JSON payloads and CI diffs
stay stable.

Severity rules (DESIGN §4.0):

* missing evidence is ``SKIP``, never ``FAIL`` — "we did not see it" is not
  "it is broken";
* a value that is present and provably wrong (bad ``coresPerSocket``
  arithmetic, a non-darwin ``guestOS``, a whitelist breach under
  ``--strict``) *is* a ``FAIL``;
* ``strict=True`` promotes only S10's whitelist warning to ``FAIL``.

S6 (identity mutual-exclusion, §4.11) depends on
``macopt.profiles.identity``; that import lives inside the S6 function so the
module can be developed independently — until it lands, S6 reports ``SKIP``.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path

from .errors import UnknownStateError
from .model import FAIL, PASS, SKIP, WARN, CheckResult, Evidence, HostInfo
from .vmxfile import Document

__all__ = ["KNOWN_DARWIN_TIERS", "run"]

KeyPolicy = Callable[[str], bool]

# DESIGN §12.2 lists darwin22-64..darwin25-64 explicitly; older darwin*-64
# ids exist in Workstation, so the whole darwin<N>-64 range is "known" and
# only ids outside it warn ("unknown darwin* tier" -> WARN).
KNOWN_DARWIN_TIERS = frozenset(f"darwin{n}-64" for n in range(9, 26))

_CPUIID_MASK_REGS = frozenset({"eax", "ebx", "ecx", "edx"})

_NO_TOOL_ERROR_VALUES = frozenset({"", "0", "none"})


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _ev(doc: Document, path: Path, *keys: str) -> tuple[Evidence, ...]:
    """``file`` evidence pointing at the line that carries ``key``."""
    out: list[Evidence] = []
    for key in keys:
        entries = doc.entries.get(key)
        if not entries:
            continue
        entry = entries[-1]
        out.append(Evidence("file", f"{path}:{entry.lineno}", entry.raw.strip()))
    return tuple(out)


def _host_ev(host: HostInfo) -> Evidence:
    return Evidence(
        "sysfs",
        "hostinfo",
        f"logical_cpus={host.logical_cpus} physical_cores={host.physical_cores} "
        f"numa_nodes={host.numa_nodes}",
    )


def _as_int(raw: str) -> int | None:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _is_hex(token: str) -> bool:
    return bool(token) and all(c in "0123456789abcdefABCDEF" for c in token)


def _is_cpuid_mask(key: str) -> bool:
    """``cpuid.<leaf>[.<subleaf>].<reg>[.amd]`` — a bit-mask style key.

    Named keys (``cpuid.coresPerSocket``, ``cpuid.brandString``,
    ``cpuid.avx2`` …) are *not* masks: they are legitimate configuration and
    must not be reported by S7 (see acceptance B3's caveat).
    """
    if not key.startswith("cpuid."):
        return False
    parts = key.split(".")[1:]
    if parts and parts[-1] == "amd":
        parts = parts[:-1]
    if len(parts) not in (2, 3):
        return False
    leaf, *rest = parts
    reg = rest[-1]
    if reg.lower() not in _CPUIID_MASK_REGS:
        return False
    return all(_is_hex(token) for token in [leaf, *rest[:-1]])


# --------------------------------------------------------------------------- #
# S1..S10
# --------------------------------------------------------------------------- #


def _s1_guestos(doc: Document, path: Path) -> CheckResult:
    value = doc.get("guestOS")
    evidence = _ev(doc, path, "guestOS")
    title = "guestOS tier"
    if value is None:
        return CheckResult(
            "S1", title, FAIL, "guestOS is not set; the guest type cannot be identified", evidence
        )
    if not value.startswith("darwin"):
        return CheckResult(
            "S1",
            title,
            FAIL,
            f"guestOS={value!r} is not a darwin* id; macopt only handles macOS guests",
            evidence,
        )
    if value in KNOWN_DARWIN_TIERS:
        return CheckResult("S1", title, PASS, f"guestOS={value} is a known darwin tier", evidence)
    return CheckResult(
        "S1",
        title,
        WARN,
        f"guestOS={value} is a darwin* id macopt does not know; masks/Tools selection "
        "may differ from the documented tiers",
        evidence,
    )


def _s2_numvcpus(doc: Document, path: Path, host: HostInfo) -> CheckResult:
    raw = doc.get("numvcpus")
    evidence = _ev(doc, path, "numvcpus")
    title = "numvcpus vs host CPUs"
    if raw is None:
        return CheckResult("S2", title, SKIP, "numvcpus is not set in the .vmx", evidence)
    num = _as_int(raw)
    if num is None or num < 1:
        return CheckResult("S2", title, FAIL, f"numvcpus={raw!r} is not a positive integer", evidence)
    evidence = evidence + (_host_ev(host),)
    if host.logical_cpus <= 0 or host.physical_cores <= 0:
        return CheckResult(
            "S2", title, SKIP, "host CPU topology unknown; cannot judge oversubscription", evidence
        )
    if num > host.logical_cpus:
        return CheckResult(
            "S2",
            title,
            WARN,
            f"numvcpus={num} exceeds the host's {host.logical_cpus} logical CPUs "
            "(thread-level oversubscription)",
            evidence,
        )
    if num > host.physical_cores:
        return CheckResult(
            "S2",
            title,
            WARN,
            f"numvcpus={num} exceeds the host's {host.physical_cores} physical cores "
            f"({num / host.physical_cores:.2f}x core-level oversubscription; pair with "
            "CPU pinning)",
            evidence,
        )
    return CheckResult(
        "S2",
        title,
        PASS,
        f"numvcpus={num} fits within {host.physical_cores} physical / "
        f"{host.logical_cpus} logical host CPUs",
        evidence,
    )


def _s3_cores_per_socket(doc: Document, path: Path) -> CheckResult:
    raw_num = doc.get("numvcpus")
    raw_cps = doc.get("cpuid.coresPerSocket")
    evidence = _ev(doc, path, "numvcpus", "cpuid.coresPerSocket")
    title = "coresPerSocket consistency"
    if raw_num is None or raw_cps is None:
        missing = [k for k, v in (("numvcpus", raw_num), ("cpuid.coresPerSocket", raw_cps)) if v is None]
        return CheckResult(
            "S3", title, SKIP, f"cannot check divisibility: {', '.join(missing)} not set", evidence
        )
    num = _as_int(raw_num)
    cps = _as_int(raw_cps)
    if num is None or cps is None or num < 1 or cps < 1:
        return CheckResult(
            "S3",
            title,
            FAIL,
            f"numvcpus={raw_num!r} / cpuid.coresPerSocket={raw_cps!r} must be positive integers",
            evidence,
        )
    if num % cps:
        return CheckResult(
            "S3",
            title,
            FAIL,
            f"numvcpus={num} is not a multiple of cpuid.coresPerSocket={cps}; "
            "VMware refuses to power on such a topology",
            evidence,
        )
    return CheckResult(
        "S3",
        title,
        PASS,
        f"numvcpus={num} = {num // cps} socket(s) x {cps} core(s); coresPerSocket divides evenly",
        evidence,
    )


def _s4_vnuma(doc: Document, path: Path, host: HostInfo) -> CheckResult:
    raw_num = doc.get("numvcpus")
    raw_mx = doc.get("numa.autosize.vcpu.maxPerVirtualNode")
    evidence = _ev(doc, path, "numvcpus", "numa.autosize.vcpu.maxPerVirtualNode")
    title = "vNUMA split"
    if raw_num is None:
        return CheckResult("S4", title, SKIP, "numvcpus is not set", evidence)
    if raw_mx is None:
        return CheckResult(
            "S4", title, SKIP, "numa.autosize.vcpu.maxPerVirtualNode not set (VMware auto-sizes)",
            evidence,
        )
    num = _as_int(raw_num)
    mx = _as_int(raw_mx)
    if num is None or mx is None or num < 1 or mx < 1:
        return CheckResult(
            "S4",
            title,
            FAIL,
            f"numvcpus={raw_num!r} / maxPerVirtualNode={raw_mx!r} must be positive integers",
            evidence,
        )
    evidence = evidence + (_host_ev(host),)
    if mx < num:
        return CheckResult(
            "S4",
            title,
            WARN,
            f"maxPerVirtualNode={mx} < numvcpus={num}: the guest is cut into multiple vNUMA "
            f"nodes while the host has {host.numa_nodes} NUMA node(s)",
            evidence,
        )
    return CheckResult(
        "S4",
        title,
        PASS,
        f"single vNUMA node ({mx} >= {num} vCPUs per node)",
        evidence,
    )


def _s5_vhv(doc: Document, path: Path) -> CheckResult:
    value = doc.get("vhv.enable")
    evidence = _ev(doc, path, "vhv.enable")
    title = "nested virtualisation (vhv.enable)"
    if value is None:
        return CheckResult(
            "S5", title, PASS, "vhv.enable not set; nested virtualisation stays disabled", evidence
        )
    if value.strip().upper() == "TRUE":
        return CheckResult(
            "S5",
            title,
            WARN,
            "vhv.enable=TRUE: macOS guests do not support nested virtualisation, yet VHV "
            "pages and nested APIC state are still allocated",
            evidence,
        )
    return CheckResult("S5", title, PASS, f"vhv.enable={value} (nested virtualisation off)", evidence)


def _s6_identity(doc: Document, path: Path) -> CheckResult:
    """§4.11: ``<key>.reflectHost=TRUE`` and an explicit ``<key>`` must not coexist."""
    title = "identity mutual exclusion"
    if importlib.util.find_spec("macopt.profiles.identity") is None:
        return CheckResult("S6", title, SKIP, "macopt.profiles.identity is not available yet", ())
    # Deferred on purpose: the identity pipeline owns this module (see DESIGN §4.11).
    from macopt.profiles.identity import mutual_exclusion_violations  # noqa: PLC0415

    mapping = doc.as_dict()
    try:
        violations = mutual_exclusion_violations(mapping)
    except TypeError:  # tolerate a Document-taking implementation
        violations = mutual_exclusion_violations(doc)  # type: ignore[arg-type]

    if violations is None:
        items: list[str] = []
    elif isinstance(violations, bool):
        items = ["identity block is self-contradictory (reflectHost vs explicit value)"]
    elif isinstance(violations, str):
        items = [violations] if violations else []
    elif isinstance(violations, dict | list | tuple | set):
        items = [str(item) for item in violations]
    else:  # pragma: no cover - defensive
        items = [str(violations)]

    if items:
        evidence = _ev(doc, path, "board-id", "hw.model", "serialNumber", "smc.version")
        return CheckResult(
            "S6", title, FAIL, "; ".join(items), evidence
        )
    return CheckResult("S6", title, PASS, "no reflectHost / explicit-value conflicts", ())


def _s7_cpuid_masks(doc: Document, path: Path, key_policy: KeyPolicy | None) -> CheckResult:
    title = "cpuid.* masks"
    keys = doc.keys()
    masks = [k for k in keys if _is_cpuid_mask(k)]
    named = [k for k in keys if k.startswith("cpuid.") and k not in masks]
    if not masks:
        detail = (
            f"no cpuid.* leaf masks (named cpuid keys present: {', '.join(named)})"
            if named
            else "no cpuid.* keys present"
        )
        return CheckResult("S7", title, PASS, detail, ())
    evidence = _ev(doc, path, *masks)
    unknown = [k for k in masks if key_policy is not None and not key_policy(k)]
    if unknown:
        return CheckResult(
            "S7",
            title,
            FAIL,
            f"cpuid leaf masks outside the key whitelist: {', '.join(unknown)}",
            evidence,
        )
    return CheckResult(
        "S7",
        title,
        WARN,
        f"cpuid leaf masks present: {', '.join(masks)} — run the §4.8 rules (R1–R8) review "
        "and verify after boot",
        evidence,
    )


def _s8_tools(doc: Document, path: Path, log_path: str | Path | None) -> CheckResult:
    title = "VMware Tools install state"
    if log_path is None:
        return CheckResult("S8", title, SKIP, "no log_path given; Tools state is runtime-only", ())

    log = Path(log_path)
    if not log.is_file():
        return CheckResult("S8", title, SKIP, f"log not found: {log}", ())
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return CheckResult("S8", title, SKIP, f"log unreadable: {log} ({exc})", ())

    lineno = 0
    raw_line = ""
    value: str | None = None
    for index, line in enumerate(text.splitlines(), start=1):
        if "toolsInstallManager.lastInstallError" not in line or "=" not in line:
            continue
        lineno, raw_line = index, line
        value = line.split("=", 1)[1].strip().strip('"').strip()
        break
    if value is None:
        return CheckResult(
            "S8", title, SKIP, "log carries no toolsInstallManager.lastInstallError line", ()
        )
    evidence = (Evidence("log", f"{log}:{lineno}", raw_line.strip()),)
    sync_time = doc.get("tools.syncTime") or "unset"
    if value.strip().lower() in _NO_TOOL_ERROR_VALUES:
        return CheckResult(
            "S8", title, PASS, "no Tools install error recorded (tools.syncTime=" + sync_time + ")",
            evidence,
        )
    return CheckResult(
        "S8",
        title,
        WARN,
        f"Tools install error {value} recorded; VMware Tools is unavailable so "
        f"tools.syncTime={sync_time} cannot take effect — fix Tools or use guest NTP",
        evidence,
    )


def _s9_duplicates(doc: Document, path: Path) -> CheckResult:
    title = "duplicate keys"
    duplicates = dict(doc.duplicates)
    if not duplicates:
        return CheckResult("S9", title, PASS, "no duplicate keys", ())
    shown = ", ".join(f"{key}x{count}" for key, count in sorted(duplicates.items()))
    evidence = _ev(doc, path, *sorted(duplicates))
    return CheckResult(
        "S9", title, WARN, f"duplicate keys (last line wins): {shown}", evidence
    )


def _s10_whitelist(
    doc: Document, path: Path, key_policy: KeyPolicy | None, strict: bool
) -> CheckResult:
    title = "key whitelist"
    if key_policy is None:
        return CheckResult("S10", title, SKIP, "no key whitelist supplied (keyscan unavailable)", ())
    keys = doc.keys()
    unknown = [k for k in keys if not key_policy(k)]
    evidence = _ev(doc, path, *unknown) if unknown else ()
    if not unknown:
        return CheckResult("S10", title, PASS, f"all {len(keys)} keys are whitelisted", evidence)
    shown = ", ".join(unknown[:10])
    more = "" if len(unknown) <= 10 else f" (+{len(unknown) - 10} more)"
    status = FAIL if strict else WARN
    return CheckResult(
        "S10",
        title,
        status,
        f"{len(unknown)} key(s) outside the whitelist: {shown}{more}",
        evidence,
    )


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def run(
    vmx_path: str | Path,
    host: HostInfo,
    *,
    strict: bool = False,
    key_policy: KeyPolicy | None = None,
    log_path: str | Path | None = None,
) -> list[CheckResult]:
    """Run S1..S10 against ``vmx_path`` in fixed order. Never writes anything."""
    path = Path(vmx_path)
    if host is None:  # tolerate explicit None, same as an empty HostInfo
        host = HostInfo()
    try:
        doc = Document.load(path)
    except OSError as exc:
        raise UnknownStateError(f"cannot read .vmx: {path} ({exc})") from exc

    return [
        _s1_guestos(doc, path),
        _s2_numvcpus(doc, path, host),
        _s3_cores_per_socket(doc, path),
        _s4_vnuma(doc, path, host),
        _s5_vhv(doc, path),
        _s6_identity(doc, path),
        _s7_cpuid_masks(doc, path, key_policy),
        _s8_tools(doc, path, log_path),
        _s9_duplicates(doc, path),
        _s10_whitelist(doc, path, key_policy, strict),
    ]

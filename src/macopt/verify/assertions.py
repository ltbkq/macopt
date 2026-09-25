"""Runtime assertions V0–V10 (``macopt verify``).

Implements ``docs/DESIGN.md`` §4.13 and the original spec in
``docs/evidence/04-verify-acceptance.md`` §1.3.

Two hard rules from the design:

1. **Missing lines are ``SKIP``, never ``FAIL``.** The ``guest vs. host CPUID``
   block is ``-INFO`` and printed once per power-on; a silent boot or a
   rotated log means "we did not see it", not "it is broken".
2. **A line that exists with a wrong value** is a real ``FAIL`` (or ``WARN``
   where the design's verdict column allows only PASS/WARN).

Status budget (from the design's verdict column):

====== ==========================================================
V0     FAIL/SKIP/PASS — freshness + optional version gate
V1     PASS/FAIL
V2     PASS/WARN/FAIL (decode != self-report ⇒ WARN, not FAIL)
V3     PASS/WARN
V4     PASS/WARN — OSXSAVE is dynamic and **never** a FAIL
V5     PASS/WARN/SKIP — degrades to a vCPU proxy, never FAIL
V6     PASS/WARN
V7     PASS/FAIL/SKIP
V8     PASS/FAIL/SKIP
V9     PASS/WARN/SKIP
V10    PASS/FAIL/SKIP
====== ==========================================================
"""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping

from ..model import FAIL, PASS, SKIP, WARN, CheckResult, Evidence
from .parser import LevelRegs, LogFacts, decode_fms, vendor_from_leaf0

# Stable order and titles — the JSON schema exposes them (DESIGN §5.2).
CHECKS: tuple[tuple[str, str], ...] = (
    ("V0", "freshness gate"),
    ("V1", "guest vendor"),
    ("V2", "family/model/stepping decode"),
    ("V3", "hypervisor bit (leaf1 ECX bit31)"),
    ("V4", "feature bits (AVX2/SSE4.2/AES)"),
    ("V5", "per-vCPU APIC ID uniqueness"),
    ("V6", "clock leaves 0x15/0x16"),
    ("V7", "hypervisor vendor leaf 0x40000000"),
    ("V8", "documented values closure"),
    ("V9", "guestOS tier"),
    ("V10", "topology reconciliation"),
)

#: DESIGN §12.2 — ``guestId`` tiers macopt knows about.
KNOWN_DARWIN_TIERS: tuple[str, ...] = (
    "darwin22-64",  # macOS 13
    "darwin23-64",  # macOS 14
    "darwin24-64",  # macOS 15
    "darwin25-64",  # macOS 26
)

KNOWN_TIERS_NOTE = "known tiers: " + ", ".join(KNOWN_DARWIN_TIERS)

_BLOCK_ABSENT = (
    "log has no `guest vs. host CPUID` block (an -INFO line printed once per "
    "power-on): boot the VM once and re-run verify"
)

#: ``expected`` keys that are handled by dedicated checks, not by V8's leaf loop.
_V8_RESERVED_KEYS = frozenset({"vmware_version", "vendor", "guestos"})

_CPUID_KEY_RE = re.compile(
    r"^cpuid\.(?P<leaf>[0-9a-fA-F]{1,8})(?:\.(?P<sub>[0-9a-fA-F]{1,2}))?\.(?P<reg>eax|ebx|ecx|edx)"
    r"(?:\.amd)?$"
)

_REG_INDEX = {"eax": 0, "ebx": 1, "ecx": 2, "edx": 3}

# Proxy-line number extraction. The full lines carry timestamps, so the number
# must be anchored to the marker itself (never "the first digits in the line").
_VMM_VCPUS_RE = re.compile(r"vmm-vcpus:\s*(\d+)")
_LOCAL_APIC_RE = re.compile(r"OvhdUser_LocalApic\s*:\s*(\d+)")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _ev(facts: LogFacts, lineno: int | None, note: str = "") -> tuple[Evidence, ...]:
    if lineno is None:
        return ()
    return (Evidence(kind="log", source=f"{facts.name}:{lineno}", note=note),)


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        try:
            return int(str(value).strip(), 16)
        except ValueError:
            return None


def _proxy_count(kind: str, text: str) -> int | None:
    """Extract the vCPU count from a proxy line (``vmm-vcpus`` / ``LocalApic``)."""
    pat = _VMM_VCPUS_RE if kind == "vmm-vcpus" else _LOCAL_APIC_RE
    m = pat.search(text)
    return int(m.group(1)) if m else None


def _skip(vid: str, title: str, detail: str) -> CheckResult:
    return CheckResult(id=vid, title=title, status=SKIP, detail=detail)


def _result(
    vid: str, title: str, status: str, detail: str, evidence: tuple[Evidence, ...] = ()
) -> CheckResult:
    return CheckResult(id=vid, title=title, status=status, detail=detail, evidence=evidence)


def _expected_int(raw: str) -> tuple[int | None, str | None]:
    """Parse a documented value: hex register, plain int or a 32-char 0/1 string.

    Mask strings containing ``-``/``h`` cannot be compared statically (their
    result depends on the VMware default) and are reported as uncomparable.
    """
    s = str(raw).strip()
    if len(s) == 32 and set(s) <= set("01-h"):
        if set(s) & set("-h"):
            return None, "value is a '01-h' mask string (default/host dependent)"
        return int(s, 2), None
    for base in (0, 16):
        try:
            return int(s, base), None
        except ValueError:
            continue
    return None, f"unparsable documented value {raw!r}"


# --------------------------------------------------------------------------- #
# V0 — freshness + version gate
# --------------------------------------------------------------------------- #

def _v0(
    facts: LogFacts,
    vmx: Mapping[str, str],
    expected: Mapping[str, str] | None,
    vmx_mtime: float | None,
    log_mtime: float | None,
) -> CheckResult:
    vid, title = CHECKS[0]
    evidence = _ev(facts, facts.version_lineno, "log header version line")
    version_note = (
        f"log version {facts.vmware_version}" + (f" build {facts.vmware_build}" if facts.vmware_build else "")
        if facts.vmware_version
        else "log header carries no VMware version"
    )

    # Optional version gate: the caller may pass the host version through
    # ``expected["vmware_version"]`` (run() has no other channel for it).
    host_version = (expected or {}).get("vmware_version")
    version_mismatch = bool(
        host_version and facts.vmware_version and host_version != facts.vmware_version
    )

    if vmx_mtime is None or log_mtime is None:
        missing = []
        if vmx_mtime is None:
            missing.append("vmx_mtime")
        if log_mtime is None:
            missing.append("log_mtime")
        status, detail = SKIP, (
            "cannot determine freshness: " + " and ".join(missing) + " unknown; " + version_note
        )
    elif log_mtime < vmx_mtime:
        status = FAIL
        detail = (
            "stale log: .vmx was modified after the last power-on "
            f"(log mtime {log_mtime:.0f} < vmx mtime {vmx_mtime:.0f}) — "
            "power off, boot the VM again, then re-run verify; " + version_note
        )
        evidence = evidence + (
            Evidence(kind="file", source="mtime: log < vmx", note="conclusions are void"),
        )
    else:
        status, detail = PASS, f"log is newer than .vmx (fresh); {version_note}"
        evidence = evidence + (Evidence(kind="file", source="mtime: log >= vmx"),)

    if version_mismatch:
        detail += (
            f"; log version {facts.vmware_version} != host version {host_version}: "
            "re-verify after the Workstation upgrade (version gate)"
        )
        status = FAIL
    return _result(vid, title, status, detail, evidence)


# --------------------------------------------------------------------------- #
# V1 — guest vendor
# --------------------------------------------------------------------------- #

def _v1(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[1]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)

    leaf0 = facts.guest_levels.get((0, 0))
    derived = vendor_from_leaf0(leaf0)
    vendor = facts.vendor or derived
    if vendor is None:
        return _skip(vid, title, "log has neither a `guest vendor` line nor guest leaf 0 to decode")

    evidence = _ev(facts, facts.vendor_lineno, "guest vendor line")
    if facts.vendor and derived and facts.vendor != derived:
        return _result(
            vid,
            title,
            FAIL,
            f"leaf0 registers spell {derived!r} but the vendor line says {facts.vendor!r}: "
            "inconsistent log / masking in effect",
            evidence + _ev(facts, facts.guest_level_lines.get((0, 0)), "guest leaf 0"),
        )

    if vendor not in ("GenuineIntel", "AuthenticAMD"):
        return _result(
            vid,
            title,
            FAIL,
            f"unexpected guest vendor {vendor!r} (expected GenuineIntel or AuthenticAMD)",
            evidence,
        )

    want = (expected or {}).get("vendor", "GenuineIntel")
    if vendor != want:
        return _result(
            vid,
            title,
            FAIL,
            f"guest sees vendor={vendor}, expected {want}: cpuid.0.* masking is not in effect "
            "or was overridden by a .vmx mask — macOS refuses to boot on a non-Intel vendor",
            evidence + _ev(facts, facts.guest_level_lines.get((0, 0)), "guest leaf 0"),
        )

    detail = f"guest vendor {vendor}"
    if facts.vendor and derived:
        detail += f" (leaf0 spells {derived})"
    return _result(vid, title, PASS, detail, evidence)


# --------------------------------------------------------------------------- #
# V2 — family/model/stepping decode + cross-check
# --------------------------------------------------------------------------- #

def _v2(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[2]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)

    leaf1 = facts.guest_levels.get((1, 0))
    if leaf1 is None:
        self_report = (
            f" (VMware self-reports guest family: 0x{facts.guest_fm[0]:x} "
            f"model: 0x{facts.guest_fm[1]:x} stepping: 0x{facts.guest_fm[2]:x})"
            if facts.guest_fm
            else ""
        )
        return _skip(vid, title, "log has no guest leaf 1 to decode" + self_report)

    eax = int(leaf1[0], 16)
    family, model, stepping = decode_fms(eax)
    evidence = _ev(facts, facts.guest_level_lines[(1, 0)], "guest leaf 1 EAX")
    detail = (
        f"decoded {leaf1[0]} -> family=0x{family:x} model=0x{model:x} stepping=0x{stepping:x}"
    )
    status = PASS

    if facts.guest_fm is not None:
        if facts.guest_fm == (family, model, stepping):
            detail += (
                f" == VMware self-report (0x{facts.guest_fm[0]:x}/0x{facts.guest_fm[1]:x}"
                f"/0x{facts.guest_fm[2]:x})"
            )
            evidence = evidence + _ev(facts, facts.guest_fm_lineno, "self-reported guest family")
        else:
            status = WARN
            detail += (
                f" != VMware self-report (0x{facts.guest_fm[0]:x}/0x{facts.guest_fm[1]:x}"
                f"/0x{facts.guest_fm[2]:x}): log format may have changed, parser needs adaptation"
            )
            evidence = evidence + _ev(facts, facts.guest_fm_lineno, "self-reported guest family")

    host_leaf1 = facts.host_levels.get((1, 0))
    if host_leaf1 is not None and facts.host_fm is not None:
        host_decoded = decode_fms(int(host_leaf1[0], 16))
        if host_decoded == facts.host_fm:
            detail += (
                f"; host {host_leaf1[0]} -> 0x{host_decoded[0]:x}/0x{host_decoded[1]:x}"
                f"/0x{host_decoded[2]:x} == self-report"
            )
        elif status == PASS:
            status = WARN
            detail += (
                f"; host decode 0x{host_decoded[0]:x}/0x{host_decoded[1]:x}/0x{host_decoded[2]:x} "
                f"!= self-report (log format may have changed)"
            )

    vendor = facts.vendor or vendor_from_leaf0(facts.guest_levels.get((0, 0)))
    if vendor == "GenuineIntel" and family != 6:
        return _result(
            vid,
            title,
            FAIL,
            f"vendor is GenuineIntel but decoded family=0x{family:x} (Intel is 6 since P6): "
            "vendor and family are inconsistent — non-Intel characteristics leaked into the guest",
            evidence,
        )
    return _result(vid, title, status, detail, evidence)


# --------------------------------------------------------------------------- #
# V3 — hypervisor bit (leaf1 ECX bit31)
# --------------------------------------------------------------------------- #

def _v3(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[3]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)
    leaf1 = facts.guest_levels.get((1, 0))
    if leaf1 is None:
        return _skip(vid, title, "log has no guest leaf 1 (ECX) to inspect")

    ecx = int(leaf1[2], 16)
    observed = (ecx >> 31) & 1
    evidence = _ev(facts, facts.guest_level_lines[(1, 0)], "guest leaf 1 ECX")

    hv = (vmx.get("hypervisor.cpuid.v0") or "").strip().upper()
    if hv in ("TRUE", "FALSE"):
        want = 1 if hv == "TRUE" else 0
        source = f"hypervisor.cpuid.v0={hv}"
    else:
        # No explicit switch: VMware synthesises the hypervisor bit, so the
        # expected value is what the design calls "当前实测 1".
        want = 1
        source = "no hypervisor.cpuid.v0 in .vmx (VMware synthesises hv bit=1)"
        dict_ev = facts.dict_entries.get("hypervisor.cpuid.v0")
        if dict_ev:
            evidence = evidence + _ev(facts, dict_ev[1], "log DICT echo")

    if observed == want:
        return _result(
            vid,
            title,
            PASS,
            f"guest leaf1 ECX {leaf1[2]} bit31={observed} as expected ({source})",
            evidence,
        )
    return _result(
        vid,
        title,
        WARN,
        f"hypervisor bit={observed}, expected {want} ({source}): the .vmx change did not take "
        "effect (cold boot required) or a mask cleared it — hidden hv bit can break Tools "
        "heartbeats / virtualisation detection",
        evidence,
    )


# --------------------------------------------------------------------------- #
# V4 — AVX2 / SSE4.2 / AES (OSXSAVE is dynamic, never FAIL)
# --------------------------------------------------------------------------- #

def _v4(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[4]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)

    leaf1 = facts.guest_levels.get((1, 0))
    leaf7 = facts.guest_levels.get((7, 0))
    if leaf1 is None and leaf7 is None:
        return _skip(vid, title, "log has neither guest leaf 1 nor leaf 7 to inspect")

    evidence: tuple[Evidence, ...] = ()
    observed: list[tuple[str, int, int]] = []  # (name, bit_value, expected_for_info)
    notes: list[str] = []

    if leaf1 is not None:
        ecx = int(leaf1[2], 16)
        # Intel SDM Vol.1 Table 3-5: SSE4.2=20, AES=25 (DESIGN §12.1 勘误 —
        # v2.1 shipped 0/20 here, which read SSE3 as SSE4.2 and SSE4.2 as AES).
        observed.append(("SSE4.2", (ecx >> 20) & 1, 1))
        observed.append(("AES", (ecx >> 25) & 1, 1))
        osxsave = (ecx >> 27) & 1
        avx = (ecx >> 28) & 1
        evidence = evidence + _ev(facts, facts.guest_level_lines[(1, 0)], "guest leaf 1 ECX")
        notes.append(
            f"OSXSAVE(ECX.27)={osxsave} recorded only — dynamic bit (early-boot dump runs before "
            f"the guest sets CR4.OSXSAVE), never a FAIL; AVX(ECX.28)={avx}"
        )
    else:
        notes.append("guest leaf 1 absent: SSE4.2/AES not verifiable")

    if leaf7 is not None:
        ebx = int(leaf7[1], 16)
        observed.append(("AVX2", (ebx >> 5) & 1, 1))
        evidence = evidence + _ev(facts, facts.guest_level_lines[(7, 0)], "guest leaf 7 EBX")
    else:
        notes.append("guest leaf 7 absent: AVX2 not verifiable")

    caps = []
    for cap in ("cpuid.avx2", "cpuid.sse42", "cpuid.aes", "cpuid.xsave"):
        if cap in facts.capabilities:
            value, lineno = facts.capabilities[cap]
            caps.append(f"{cap}={value}")
            evidence = evidence + _ev(facts, lineno, "capability line (side evidence)")

    off = [name for name, value, _ in observed if value == 0]
    detail_parts = [
        f"{name}={value}" + (" (ok)" if value else " (clear)")
        for name, value, _ in observed
    ]
    detail = "; ".join(detail_parts)
    if caps:
        detail += "; side evidence: " + " ".join(caps)
    detail += "; " + " ".join(notes)

    if off:
        return _result(
            vid,
            title,
            WARN,
            f"{', '.join(off)} bit clear in the guest: macOS binaries may SIGILL — check cpuid "
            "masks; " + detail,
            evidence,
        )
    if not observed:
        return _skip(vid, title, "no feature bits observable in this log; " + detail)
    return _result(vid, title, PASS, detail, evidence)


# --------------------------------------------------------------------------- #
# V5 — per-vCPU APIC IDs (degrades to a vCPU count proxy)
# --------------------------------------------------------------------------- #

def _v5(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[5]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)

    target = _int_or_none(vmx.get("numvcpus"))

    if facts.per_vcpu_leaf1:
        ids = [(ebx >> 24) & 0xFF for (_, _, _, ebx, _, _) in facts.per_vcpu_leaf1]
        evidence = tuple(
            Evidence(kind="log", source=f"{facts.name}:{lineno}", note=f"CPUID[{vcpu}] leaf 1")
            for lineno, vcpu, *_ in facts.per_vcpu_leaf1[:4]
        )
        detail = (
            f"per-vCPU leaf1 EBX APIC IDs: {sorted(set(ids))} "
            f"({len(ids)} vCPU traced, {len(set(ids))} unique)"
        )
        if len(set(ids)) != len(ids):
            return _result(
                vid,
                title,
                WARN,
                f"duplicate initial APIC IDs: {sorted(ids)} — recheck per-core inside the guest; "
                + detail,
                evidence,
            )
        if target is not None and len(ids) != target:
            return _result(
                vid,
                title,
                WARN,
                f"traced {len(ids)} vCPUs but .vmx numvcpus={target}: partial trace, "
                "recheck per-core inside the guest; " + detail,
                evidence,
            )
        return _result(vid, title, PASS, detail, evidence)

    # Degraded proxy (the only path that ever fires on Workstation 26.0.1).
    proxies: dict[str, int] = {}
    evidence: list[Evidence] = []
    for label, source in (("vmm-vcpus", facts.vmm_vcpus), ("LocalApic", facts.local_apic)):
        if source:
            value = _proxy_count(label, source[0][1])
            if value is not None:
                proxies[label] = value
                evidence.append(
                    Evidence(kind="log", source=f"{facts.name}:{source[0][0]}", note=label)
                )
    dict_nv = facts.dict_entries.get("numvcpus")
    if dict_nv:
        value = _int_or_none(dict_nv[0])
        if value is not None:
            proxies["DICT numvcpus"] = value
            evidence.append(Evidence(kind="log", source=f"{facts.name}:{dict_nv[1]}", note="numvcpus"))

    compared: dict[str, int] = dict(proxies)
    if target is not None:
        compared[".vmx numvcpus"] = target
    if len(compared) < 2:
        return _skip(
            vid,
            title,
            "log has no per-vCPU leaf1 (Workstation only traces unhandled leaves) and not enough "
            "proxy data (vmm-vcpus / DICT numvcpus / OvhdUser_LocalApic) to reconcile",
        )

    values = set(compared.values())
    summary = " == ".join(f"{k} {v}" for k, v in sorted(compared.items()))
    if len(values) == 1:
        return _result(
            vid,
            title,
            PASS,
            f"degraded proxy check: {summary} (weak: no per-vCPU leaf1 in the log) — "
            "in-guest per-core recheck required (`macopt verify --in-guest`)",
            tuple(evidence),
        )
    return _result(
        vid,
        title,
        WARN,
        f"vCPU proxy mismatch: {summary} — topology not applied or wrong log; "
        "in-guest per-core recheck required",
        tuple(evidence),
    )


# --------------------------------------------------------------------------- #
# V6 — clock leaves 0x15 / 0x16
# --------------------------------------------------------------------------- #

def _v6(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[6]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)

    present: list[tuple[str, LevelRegs]] = []
    evidence: list[Evidence] = []
    for leaf, label in ((0x15, "0x15"), (0x16, "0x16")):
        regs = facts.guest_levels.get((leaf, 0))
        if regs is not None:
            present.append((label, regs))
            evidence.append(
                Evidence(
                    kind="log",
                    source=f"{facts.name}:{facts.guest_level_lines[(leaf, 0)]}",
                    note=f"guest leaf {label}",
                )
            )
    if not present:
        return _skip(vid, title, "log has no guest leaves 0x15/0x16 to inspect")

    zeros = all(all(int(reg, 16) == 0 for reg in regs) for _, regs in present)
    shown = "; ".join(f"leaf {label}: {' '.join(regs)}" for label, regs in present)
    if not zeros:
        return _result(vid, title, PASS, f"guest clock/frequency leaves exposed; {shown}", tuple(evidence))

    detail = (
        f"guest {'/'.join(label for label, _ in present)} all zero: the guest gets no TSC/core-"
        "frequency calibration — keep hpet0.present=TRUE and use tools.syncTime or guest NTP, "
        "or long runs will drift; " + shown
    )
    sync = (vmx.get("tools.syncTime") or "").strip().upper()
    if sync:
        detail += f"; tools.syncTime={sync}"
    if facts.host_levels.get((0x15, 0)):
        detail += "; host leaf 0x15 is non-zero (host can, guest cannot)"
    if facts.tsc_estimates is not None:
        distinct = {v for v in facts.tsc_estimates if v}
        detail += (
            f"; TSC estimates disagree (vmmon {facts.tsc_estimates[0]}, "
            f"cpuinfo {facts.tsc_estimates[1]}, cpufreq {facts.tsc_estimates[2]})"
            if len(distinct) > 1
            else f"; TSC estimate {facts.tsc_estimates[0]} Hz"
        )
        evidence.append(
            Evidence(kind="log", source=f"{facts.name}:{facts.tsc_estimates_lineno}", note="TSC estimates")
        )
    if facts.khz_estimate is not None:
        detail += f"; VMMon_GetkHzEstimate {facts.khz_estimate} kHz"
    return _result(vid, title, WARN, detail, tuple(evidence))


# --------------------------------------------------------------------------- #
# V7 — hypervisor vendor leaf 0x40000000
# --------------------------------------------------------------------------- #

def _v7(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[7]
    if not facts.has_cpuid_block:
        return _skip(vid, title, _BLOCK_ABSENT)
    regs = facts.guest_levels.get((0x40000000, 0))
    if regs is None:
        return _skip(vid, title, "log has no guest leaf 0x40000000 to inspect")

    eax, ebx, ecx, edx = (int(r, 16) for r in regs)
    blob = struct.pack("<III", ebx, ecx, edx)
    name = "".join(chr(b) if 32 <= b < 127 else "." for b in blob)
    evidence = _ev(facts, facts.guest_level_lines[(0x40000000, 0)], "guest leaf 0x40000000")
    if name == "VMwareVMware":
        return _result(
            vid,
            title,
            PASS,
            f'hypervisor vendor "VMwareVMware" (max leaf 0x{eax:x})',
            evidence,
        )
    return _result(
        vid,
        title,
        FAIL,
        f'hypervisor vendor = "{name}": wrong log (different VM/hypervisor) or the guest is not '
        "running on VMware",
        evidence,
    )


# --------------------------------------------------------------------------- #
# V8 — documented_values closure
# --------------------------------------------------------------------------- #

def _v8(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[8]
    if not expected:
        return _skip(vid, title, "no documented_values recorded by apply — nothing to close the loop on")

    matched: list[str] = []
    mismatches: list[str] = []
    unobserved: list[str] = []
    ignored: list[str] = []
    evidence: list[Evidence] = []

    for key in sorted(expected):
        if key in _V8_RESERVED_KEYS:
            continue  # handled by V0/V1/V9 on purpose
        raw = expected[key]

        if key in ("cpuid.family", "cpuid.model", "cpuid.stepping"):
            decoded = _decoded_from_leaf1(facts)
            if decoded is None:
                unobserved.append(key)
                continue
            want, err = _expected_int(raw)
            if want is None:
                ignored.append(f"{key} ({err})")
                continue
            got = {"cpuid.family": 0, "cpuid.model": 1, "cpuid.stepping": 2}[key]
            (matched if decoded[got] == want else mismatches).append(
                f"{key}: expected {want}, log decodes {decoded[got]}"
            )
            continue

        if key == "cpuid.brandString":
            if facts.guest_name is None:
                unobserved.append(key)
            elif _norm(facts.guest_name) == _norm(raw):
                matched.append(key)
            else:
                mismatches.append(f"{key}: expected {raw!r}, log shows {facts.guest_name!r}")
            continue

        m = _CPUID_KEY_RE.match(key)
        if not m:
            ignored.append(key)
            continue
        leaf = int(m.group("leaf"), 16)
        subleaf = int(m.group("sub"), 16) if m.group("sub") else 0
        regs = facts.guest_levels.get((leaf, subleaf))
        if regs is None:
            unobserved.append(key)
            continue
        want, err = _expected_int(raw)
        if want is None:
            ignored.append(f"{key} ({err})")
            continue
        got = regs[_REG_INDEX[m.group("reg")]]
        evidence.extend(_ev(facts, facts.guest_level_lines[(leaf, subleaf)], key))
        if int(got, 16) == want:
            matched.append(f"{key}={got}")
        else:
            mismatches.append(f"{key}: expected 0x{want:08x}, log shows {got}")

    if mismatches:
        shown = "; ".join(mismatches[:3])
        more = f" (+{len(mismatches) - 3} more)" if len(mismatches) > 3 else ""
        return _result(
            vid,
            title,
            FAIL,
            "documented value(s) not visible in the guest: "
            + shown
            + more
            + " — key may be unknown to this VMware version, ignored, or overridden by "
            "VMware's built-in Darwin masks (cold boot required to re-test)",
            tuple(evidence),
        )
    if matched:
        detail = f"{len(matched)}/{len(matched) + len(unobserved)} documented values match the log"
        if unobserved:
            detail += f"; not observed (leaf absent from this log): {', '.join(unobserved[:4])}"
        if ignored:
            detail += f"; not comparable: {', '.join(ignored[:3])}"
        return _result(vid, title, PASS, detail, tuple(evidence))
    if unobserved:
        return _skip(
            vid,
            title,
            "documented leaves are absent from this log (CPUID block truncated or missing): "
            + ", ".join(unobserved[:4]),
        )
    return _skip(vid, title, "no documented value could be compared" + (f"; ignored: {', '.join(ignored)}" if ignored else ""))


def _decoded_from_leaf1(facts: LogFacts) -> tuple[int, int, int] | None:
    regs = facts.guest_levels.get((1, 0))
    return decode_fms(int(regs[0], 16)) if regs is not None else None


def _norm(text: str) -> str:
    return " ".join(str(text).split()).casefold()


# --------------------------------------------------------------------------- #
# V9 — guestOS tier
# --------------------------------------------------------------------------- #

def _v9(facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None) -> CheckResult:
    vid, title = CHECKS[9]
    if facts.guestos is None:
        return _skip(vid, title, "log has no `Powering on guestOS '…'` line")
    evidence = _ev(facts, facts.guestos_lineno, "power-on line")
    dict_guestos = facts.dict_entries.get("guestOS")
    if dict_guestos:
        evidence = evidence + _ev(facts, dict_guestos[1], "log DICT echo of guestOS")

    want = vmx.get("guestOS")
    if want is None:
        return _skip(vid, title, f"log powered on {facts.guestos!r} but the .vmx has no guestOS key")

    if want != facts.guestos:
        return _result(
            vid,
            title,
            WARN,
            f"log powered on {facts.guestos!r} but .vmx says {want!r}: wrong log, or the guestOS "
            "change was not rebooted into (V0 should also flag staleness)",
            evidence,
        )

    if facts.guestos in KNOWN_DARWIN_TIERS:
        return _result(
            vid,
            title,
            PASS,
            f"guestOS {facts.guestos} matches .vmx (known darwin tier); " + KNOWN_TIERS_NOTE,
            evidence,
        )
    if facts.guestos.startswith("darwin"):
        return _result(
            vid,
            title,
            WARN,
            f"guestOS {facts.guestos} matches .vmx but is not a tier macopt knows; "
            + KNOWN_TIERS_NOTE,
            evidence,
        )
    return _result(
        vid,
        title,
        WARN,
        f"guestOS {facts.guestos} is not a darwin tier — this is not a macOS guest",
        evidence,
    )


# --------------------------------------------------------------------------- #
# V10 — topology reconciliation
# --------------------------------------------------------------------------- #

def _v10(
    facts: LogFacts, vmx: Mapping[str, str], expected: Mapping[str, str] | None
) -> CheckResult:
    vid, title = CHECKS[10]
    vmx_nv = _int_or_none(vmx.get("numvcpus"))
    vmx_cps = _int_or_none(vmx.get("cpuid.coresPerSocket"))

    log_side: dict[str, int] = {}
    evidence: list[Evidence] = []
    for label, source in (
        ("vmm-vcpus", facts.vmm_vcpus),
        ("LocalApic", facts.local_apic),
    ):
        if source:
            value = _proxy_count(label, source[0][1])
            if value is not None:
                log_side[label] = value
                evidence.append(
                    Evidence(kind="log", source=f"{facts.name}:{source[0][0]}", note=label)
                )
    for key in ("numvcpus", "cpuid.coresPerSocket"):
        entry = facts.dict_entries.get(key)
        if entry:
            value = _int_or_none(entry[0])
            if value is not None:
                log_side[f"DICT {key}"] = value
                evidence.append(Evidence(kind="log", source=f"{facts.name}:{entry[1]}", note=key))

    if vmx_nv is None and not log_side:
        return _skip(
            vid,
            title,
            "no topology data: .vmx has no numvcpus and the log has no "
            "vmm-vcpus / OvhdUser_LocalApic / DICT numvcpus lines",
        )
    if vmx_nv is None:
        return _skip(
            vid,
            title,
            ".vmx has no numvcpus to reconcile against; log shows "
            + ", ".join(f"{k}={v}" for k, v in sorted(log_side.items())),
        )

    problems: list[str] = []
    sockets = _int_or_none(vmx.get("sockets"))
    if vmx_cps is not None:
        if sockets is None:
            sockets = vmx_nv // vmx_cps if vmx_cps and vmx_nv % vmx_cps == 0 else 1
        if vmx_nv != vmx_cps * sockets:
            problems.append(
                f".vmx numvcpus={vmx_nv} != cpuid.coresPerSocket={vmx_cps} x sockets={sockets}"
            )
    for label, value in sorted(log_side.items()):
        reference = vmx_nv if "numvcpus" in label else vmx_cps
        if reference is not None and value != reference:
            problems.append(f"{label}={value} != .vmx {'numvcpus' if 'numvcpus' in label else 'cpuid.coresPerSocket'}={reference}")

    if problems:
        return _result(
            vid,
            title,
            FAIL,
            "topology mismatch: " + "; ".join(problems)
            + " — change not applied (cold boot required) or verify picked the wrong log",
            tuple(evidence),
        )
    if not log_side:
        return _skip(
            vid,
            title,
            f".vmx numvcpus={vmx_nv} coresPerSocket={vmx_cps} is internally consistent, but the "
            "log has no topology lines to reconcile against",
        )

    detail = f"numvcpus={vmx_nv}"
    if vmx_cps is not None:
        detail += f" == coresPerSocket={vmx_cps} x sockets={sockets}"
    detail += "; log: " + ", ".join(f"{k}={v}" for k, v in sorted(log_side.items()))
    if facts.khz_estimate is not None:
        detail += f"; VMMon_GetkHzEstimate {facts.khz_estimate} kHz"
    return _result(vid, title, PASS, detail, tuple(evidence))


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

_CHECK_FUNCS = (_v0, _v1, _v2, _v3, _v4, _v5, _v6, _v7, _v8, _v9, _v10)


def run(
    facts: LogFacts,
    vmx: Mapping[str, str],
    *,
    vmx_mtime: float | None = None,
    log_mtime: float | None = None,
    expected: Mapping[str, str] | None = None,
) -> list[CheckResult]:
    """Run V0–V10 in order against parsed log *facts* and the effective *.vmx*.

    :param facts: output of :func:`macopt.verify.parser.parse_log[_path]`.
    :param vmx: effective ``key -> value`` mapping of the guest ``.vmx``
        (``Document.as_dict()`` is fine).
    :param vmx_mtime: mtime of the ``.vmx`` (epoch seconds); ``None`` ⇒ V0 SKIP.
    :param log_mtime: mtime of the log; defaults to ``facts.mtime`` recorded by
        :func:`parse_log_path`.
    :param expected: ``documented_values`` recorded at apply time (keys such as
        ``cpuid.1.eax``); optional ``vendor``/``vmware_version``/``guestos``
        entries feed V1/V0/V9 instead of V8's register loop.
    """
    mapping = dict(vmx or {})
    exp = dict(expected) if expected else None
    effective_log_mtime = facts.mtime if log_mtime is None else log_mtime

    results: list[CheckResult] = [
        _v0(facts, mapping, exp, vmx_mtime, effective_log_mtime),
    ]
    results.extend(func(facts, mapping, exp) for func in _CHECK_FUNCS[1:])
    assert [r.id for r in results] == [vid for vid, _ in CHECKS]
    assert len(results) == 11
    return results


__all__ = ["CHECKS", "KNOWN_DARWIN_TIERS", "run"]

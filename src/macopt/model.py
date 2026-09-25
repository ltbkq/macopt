"""Shared data contracts used by every macopt module.

This module is intentionally dependency-free and side-effect free: profile
builders, the planner, the writer and the verifier all communicate through
these types, which keeps the modules independently testable.

Style note: every ``Param`` carries an :class:`Evidence` tuple. A parameter
without provenance is a bug — the project's review process rejected
unattributed assertions, and the code must not reintroduce them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #

EVIDENCE_KINDS = (
    "log",  # line in a vmware*.log produced by VMware itself
    "binary",  # string / format-fragment observed in a VMware binary
    "sysfs",  # /sys or /proc observation on the host
    "file",  # a file on disk (vmx, preferences, backup manifest, ...)
    "doc",  # upstream documentation, KB, spec
    "measured",  # benchmark or experiment we ran
    "community",  # community report — always paired with "needs verification"
)


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in EVIDENCE_KINDS:
            raise ValueError(f"evidence kind must be one of {EVIDENCE_KINDS}, got {self.kind!r}")

    def render(self) -> str:
        base = f"[{self.kind}] {self.source}"
        return f"{base} — {self.note}" if self.note else base

    def to_dict(self) -> dict[str, str]:
        d: dict[str, str] = {"kind": self.kind, "source": self.source}
        if self.note:
            d["note"] = self.note
        return d


# --------------------------------------------------------------------------- #
# Parameters (what a profile wants written into the .vmx)
# --------------------------------------------------------------------------- #

RISK_NORMAL = "normal"
RISK_HIGH = "high"

MODULES = (
    "guestos",  # guestOS id correction (darwin24-64 -> darwin25-64)
    "topology",  # vCPU topology, vNUMA, vhv, vpmc, hypervisor bit
    "timing",  # tools.syncTime, hpet, clock sources
    "gfxnet",  # svga / mks / ethernet corrected keys
    "identity",  # SMBIOS-ish identity block (mutually exclusive rules)
    "cpuid",  # cpuid.* masking profiles (opt-in, high risk)
    "prefs",  # ~/.vmware/preferences (opt-in)
)


@dataclass(frozen=True)
class Param:
    """One intended configuration change plus why it exists."""

    key: str
    value: str
    module: str
    reason: str
    evidence: tuple[Evidence, ...] = ()
    risk: str = RISK_NORMAL
    risk_note: str = ""
    conflicts_with: tuple[str, ...] = ()
    needs_confirmation: bool = False
    # ``remove=True`` means "this key must not be present at all" (e.g.
    # ``numa.autosize.cookie`` must be deleted, not rewritten). ``value`` is
    # ignored in that case and should be "".
    remove: bool = False

    def __post_init__(self) -> None:
        if self.module not in MODULES:
            raise ValueError(f"module must be one of {MODULES}, got {self.module!r}")
        if self.risk not in (RISK_NORMAL, RISK_HIGH):
            raise ValueError(f"risk must be normal|high, got {self.risk!r}")
        if self.remove and self.value:
            raise ValueError(f"remove=True params must carry an empty value, got {self.value!r}")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "module": self.module,
            "reason": self.reason,
            "risk": self.risk,
        }
        if self.evidence:
            d["evidence"] = [e.to_dict() for e in self.evidence]
        if self.risk_note:
            d["risk_note"] = self.risk_note
        if self.conflicts_with:
            d["conflicts_with"] = list(self.conflicts_with)
        if self.needs_confirmation:
            d["needs_confirmation"] = True
        if self.remove:
            d["remove"] = True
        return d


# --------------------------------------------------------------------------- #
# Plan (diff between the file and what we want)
# --------------------------------------------------------------------------- #

OP_ADDED = "added"
OP_MODIFIED = "modified"
OP_UNCHANGED = "unchanged"
OP_REMOVED = "removed"


@dataclass(frozen=True)
class Change:
    key: str
    before: str | None  # None when the key was absent
    after: str | None  # None only for OP_REMOVED
    op: str
    module: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "key": self.key,
            "op": self.op,
            "before": self.before,
            "after": self.after,
        }
        if self.module:
            d["module"] = self.module
        if self.reason:
            d["reason"] = self.reason
        return d


@dataclass
class Plan:
    """A dry-run-able description of what :func:`macopt.writer.apply` would do."""

    changes: list[Change] = field(default_factory=list)
    params: list[Param] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def effective(self) -> list[Change]:
        """Changes that would actually modify the file."""
        return [c for c in self.changes if c.op in (OP_ADDED, OP_MODIFIED, OP_REMOVED)]

    @property
    def blocking(self) -> bool:
        return bool(self.errors)

    def op_of(self, key: str) -> str | None:
        for c in self.changes:
            if c.key == key:
                return c.op
        return None

    def counts(self) -> dict[str, int]:
        out = {OP_ADDED: 0, OP_MODIFIED: 0, OP_UNCHANGED: 0, OP_REMOVED: 0}
        for c in self.changes:
            out[c.op] = out.get(c.op, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "changes": [c.to_dict() for c in self.changes],
            "params": [p.to_dict() for p in self.params],
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "counts": self.counts(),
        }


# --------------------------------------------------------------------------- #
# Check results (verifier / static checker)
# --------------------------------------------------------------------------- #

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"


@dataclass(frozen=True)
class CheckResult:
    id: str
    title: str
    status: str
    detail: str = ""
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in (PASS, FAIL, WARN, SKIP):
            raise ValueError(f"bad status {self.status!r}")

    @property
    def failed(self) -> bool:
        return self.status == FAIL

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "status": self.status,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.evidence:
            d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


# --------------------------------------------------------------------------- #
# Host facts
# --------------------------------------------------------------------------- #


@dataclass
class HostInfo:
    """Everything profiles need to know about the host (Linux only).

    Fields are lazily populated by :mod:`macopt.hostinfo`; profiles must treat
    ``None`` as "unknown" and degrade rather than guess.
    """

    vendor: str | None = None  # GenuineIntel | AuthenticAMD | None
    brand: str | None = None
    logical_cpus: int = 0
    physical_cores: int = 0
    numa_nodes: int = 1
    hybrid: bool = False
    p_cpus: tuple[int, ...] = ()  # logical CPU ids of performance cores
    e_cpus: tuple[int, ...] = ()  # logical CPU ids of efficiency cores
    freq_mhz_p: int | None = None
    freq_mhz_e: int | None = None
    tsc_hz: int | None = None  # derived from CPUID leaf 0x15 when available
    vmware_version: str | None = None  # "26.0.1"
    vmware_build: str | None = None  # "25688693"
    vmware_build_tag: str | None = None  # "26H1u1"
    unlocker_state: str | None = None  # PATCHED | UNPATCHED | UNKNOWN | ...
    kernel: str | None = None
    systemd_version: int | None = None
    user_cpuset_delegated: bool | None = None  # systemd --user cpuset support
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "brand": self.brand,
            "logical_cpus": self.logical_cpus,
            "physical_cores": self.physical_cores,
            "numa_nodes": self.numa_nodes,
            "hybrid": self.hybrid,
            "p_cpus": list(self.p_cpus),
            "e_cpus": list(self.e_cpus),
            "freq_mhz_p": self.freq_mhz_p,
            "freq_mhz_e": self.freq_mhz_e,
            "tsc_hz": self.tsc_hz,
            "vmware_version": self.vmware_version,
            "vmware_build": self.vmware_build,
            "vmware_build_tag": self.vmware_build_tag,
            "unlocker_state": self.unlocker_state,
            "kernel": self.kernel,
            "systemd_version": self.systemd_version,
            "user_cpuset_delegated": self.user_cpuset_delegated,
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# Profile options
# --------------------------------------------------------------------------- #

PROFILES = ("passthrough", "performance", "balanced", "throughput")


@dataclass
class ProfileOptions:
    """Knobs shared by every profile builder."""

    profile: str = "balanced"  # performance | balanced | throughput
    modules: tuple[str, ...] = ("guestos", "topology", "timing", "gfxnet")
    numvcpus: int | None = None  # override derived from the chosen profile
    cpus: str | None = None  # e.g. "0-11"; None = derive from host topology
    guestos: str | None = None  # target guestOS id; None = keep unless stale
    cpuid_profile: str = "none"  # none | penryn | kabylake-7700k | signed-brand
    identity: bool = False  # opt-in: emit the SMBIOS/identity block
    sync_time: bool = False  # opt-in: flip tools.syncTime (needs working Tools)
    hide_hypervisor_bit: bool = False  # opt-in: hypervisor.cpuid.v0 = FALSE
    allow_apic_risk: bool = False  # lift the cpuid.1.ebx hard-block
    allow_unknown_keys: bool = False  # lift the whitelist hard-block
    extras: dict[str, str] = field(default_factory=dict)

    def wants(self, module: str) -> bool:
        return module in self.modules


@dataclass
class ProfileResult:
    params: tuple[Param, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def merged(self, other: ProfileResult) -> ProfileResult:
        return ProfileResult(
            params=self.params + other.params,
            warnings=self.warnings + other.warnings,
            errors=self.errors + other.errors,
        )


def params_to_dict(params: Sequence[Param]) -> list[dict[str, Any]]:
    return [p.to_dict() for p in params]


def mapping_get(mapping: Mapping[str, str], key: str, default: str | None = None) -> str | None:
    """Small helper so profiles can read either a ``.vmx`` document or a plain dict."""
    return mapping.get(key, default)

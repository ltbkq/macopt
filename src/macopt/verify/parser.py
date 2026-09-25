"""Parse ``vmware*.log`` into structured facts for the runtime verifier.

Evidence basis (``docs/DESIGN.md`` §4.13 and ``docs/evidence/04-verify-acceptance.md``):

* The boot log starts with
  ``Log for VMware Workstation pid=… version=… build=… option=…``.
* ``guest vs. host CPUID …`` is an ``-INFO`` block printed **once per power
  on** (~1.7 s after power-on). Its register lines look like::

      guest vs. host CPUID guest level 00000001,  0: 0x000406e3 … (two spaces)
      guest vs. host CPUID *host level 00000001,  0: 0x000b06a2 …
      hostCPUID level 00000001, 0: 0x000b06a2 …                (one space, header)

  i.e. guest lines carry the literal ``guest level`` marker, host lines inside
  the block carry ``*host level`` (no ``vs. host`` prefix after stripping) and
  the log header separately dumps ``hostCPUID level …`` lines. All three
  spellings are accepted; in-block ``*host`` values win because they are the
  boot-time dump.
* Leaves/sub-leaves are written in hex (``0000000d,  b:``), register values as
  ``0x``-prefixed 32-bit hex strings.
* ``Capability Found: cpuid.avx2 = 1`` lines are *VM capability* lines, not
  guest-visible CPUID — kept separately so assertions never confuse them.
* Workstation 26.0.1 traces ``CPUID[n] level …`` only for leaves the monitor
  does not synthesise, so per-vCPU ``level 00000001`` lines are normally
  absent (see V5 in the design).

Missing lines are data, not errors: the caller must degrade to ``SKIP``
(DESIGN §4.13), never ``FAIL``.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

#: ``(leaf, subleaf)`` — both integers, decoded from the log's hex columns.
LevelKey = tuple[int, int]
#: ``(eax, ebx, ecx, edx)`` exactly as written in the log, e.g. ``"0x000406e3"``.
LevelRegs = tuple[str, str, str, str]

_REG = r"(?P<eax>0x[0-9a-fA-F]+)\s+(?P<ebx>0x[0-9a-fA-F]+)\s+(?P<ecx>0x[0-9a-fA-F]+)\s+(?P<edx>0x[0-9a-fA-F]+)"

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)")
_VERSION_RE = re.compile(
    r"Log for VMware Workstation pid=\d+ version=(?P<version>[\d.]+) build=(?P<build>\d+)"
)
_GUESTOS_RE = re.compile(r"Powering on guestOS '(?P<guestos>[^']+)'")
_VENDOR_RE = re.compile(r"guest vs\. host CPUID guest vendor:\s*(?P<vendor>\S+)")
_FM_TMPL = r"{marker} family:\s*(?P<family>0x[0-9a-fA-F]+)\s+model:\s*(?P<model>0x[0-9a-fA-F]+)\s+stepping:\s*(?P<stepping>0x[0-9a-fA-F]+)"
_GUEST_FM_RE = re.compile(r"guest vs\. host CPUID " + _FM_TMPL.format(marker="guest"))
_HOST_FM_BLOCK_RE = re.compile(r"guest vs\. host CPUID " + _FM_TMPL.format(marker=r"\*host"))
_HOST_FM_HDR_RE = re.compile(_FM_TMPL.format(marker="hostCPUID"))
_GUEST_CODENAME_RE = re.compile(r"guest vs\. host CPUID guest codename:\s*(?P<codename>.+?)\s*$")
_HOST_CODENAME_BLOCK_RE = re.compile(r"guest vs\. host CPUID \*host codename:\s*(?P<codename>.+?)\s*$")
_HOST_CODENAME_HDR_RE = re.compile(r"hostCPUID codename:\s*(?P<codename>.+?)\s*$")
_GUEST_NAME_RE = re.compile(r"guest vs\. host CPUID guest name:\s*(?P<name>.+?)\s*$")
_HOST_NAME_HDR_RE = re.compile(r"hostCPUID name:\s*(?P<name>.+?)\s*$")
_LEVEL_RE = re.compile(
    r"(?P<head>guest vs\. host CPUID (?P<gtag>guest|\*host) level |hostCPUID level )"
    r"(?P<leaf>[0-9a-fA-F]+),\s*(?P<subleaf>[0-9a-fA-F]+):\s*" + _REG
)
_PER_VCPU_RE = re.compile(
    r"CPUID\[(?P<vcpu>\d+)\] level (?P<leaf>[0-9a-fA-F]+),\s*(?P<subleaf>[0-9a-fA-F]+):\s*" + _REG
)
_DICT_RE = re.compile(r'\bDICT\s+(?P<key>[A-Za-z0-9_][A-Za-z0-9_.:\-]*)\s*=\s*"(?P<value>.*)"\s*$')
_CAPABILITY_RE = re.compile(r"Capability Found: (?P<key>cpuid\.[A-Za-z0-9_.]+)\s*=\s*(?P<value>\S+)")
_VMM_VCPUS_RE = re.compile(r"vmm-vcpus:\s*(?P<count>\d+)")
_LOCAL_APIC_RE = re.compile(r"OvhdUser_LocalApic\s*:\s*(?P<count>\d+)")
_KHZ_RE = re.compile(r"VMMon_GetkHzEstimate: Calculated\s+(?P<khz>\d+)\s+kHz")
_TSC_RE = re.compile(
    r"TSC Hz estimates: vmmon\s+(?P<vmmon>\d+),\s*cpuinfo\s+(?P<cpuinfo>\d+),\s*"
    r"cpufreq\s+(?P<cpufreq>\d+)\s*sysctlfreq\s+(?P<sysctlfreq>\d+)"
)

# Lines that indicate something is wrong with VMware Tools (S8/V9 context).
# Deliberately excludes the benign "ToolsISO: …" signature warnings and the
# routine "[RunningStatus] Last heartbeat value …" chatter.
_TOOLS_ERROR_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"lastInstallError"),
    re.compile(r"Tools:.*heartbeat timeout", re.IGNORECASE),
    re.compile(r"VIX_E_TOOLS"),
    re.compile(r"Tools:.*\berror\b", re.IGNORECASE),
    re.compile(r"Tools:.*\bfailed\b", re.IGNORECASE),
)


@dataclass
class LogFacts:
    """Everything the V0–V10 assertions may read from one ``vmware*.log``."""

    # -- raw text ---------------------------------------------------------- #
    raw: str = ""
    lines: list[tuple[int, str]] = field(default_factory=list)  # (1-based, text)
    name: str = "vmware.log"  # basename used in Evidence sources
    mtime: float | None = None  # epoch seconds; set by parse_log_path()

    # -- header ------------------------------------------------------------ #
    timestamp: str | None = None  # ISO-8601 of the first log line
    vmware_version: str | None = None  # "26.0.1"
    vmware_build: str | None = None  # "25688693"
    version_lineno: int | None = None

    # -- power-on / config echo ------------------------------------------- #
    guestos: str | None = None  # from "Powering on guestOS '…'"
    guestos_lineno: int | None = None
    dict_entries: dict[str, tuple[str, int]] = field(default_factory=dict)  # key -> (value, lineno)

    # -- guest vs. host CPUID block ---------------------------------------- #
    has_cpuid_block: bool = False
    block_lineno: int | None = None
    vendor: str | None = None
    vendor_lineno: int | None = None
    guest_fm: tuple[int, int, int] | None = None  # (family, model, stepping)
    host_fm: tuple[int, int, int] | None = None
    guest_fm_lineno: int | None = None
    host_fm_lineno: int | None = None
    guest_codename: str | None = None
    host_codename: str | None = None
    guest_name: str | None = None
    host_name: str | None = None
    guest_levels: dict[LevelKey, LevelRegs] = field(default_factory=dict)
    host_levels: dict[LevelKey, LevelRegs] = field(default_factory=dict)
    guest_level_lines: dict[LevelKey, int] = field(default_factory=dict)
    host_level_lines: dict[LevelKey, int] = field(default_factory=dict)

    # -- per-vCPU trace (normally absent on Workstation 26.0.1) ------------ #
    # (lineno, vcpu, eax, ebx, ecx, edx) for leaf 1 / subleaf 0 only.
    per_vcpu_leaf1: list[tuple[int, int, int, int, int, int]] = field(default_factory=list)

    # -- evidence categories requested by the contract ---------------------- #
    tools_errors: list[tuple[int, str]] = field(default_factory=list)
    local_apic: list[tuple[int, str]] = field(default_factory=list)
    vmm_vcpus: list[tuple[int, str]] = field(default_factory=list)
    numa_lines: list[tuple[int, str]] = field(default_factory=list)

    # -- side evidence ------------------------------------------------------ #
    capabilities: dict[str, tuple[str, int]] = field(default_factory=dict)  # cpuid.avx2 -> (1, lineno)
    khz_estimate: int | None = None
    khz_estimate_lineno: int | None = None
    tsc_estimates: tuple[int, int, int, int] | None = None  # vmmon, cpuinfo, cpufreq, sysctlfreq
    tsc_estimates_lineno: int | None = None

    # -- convenience -------------------------------------------------------- #

    def level_ints(self, which: str, leaf: int, subleaf: int = 0) -> tuple[int, int, int, int] | None:
        """Registers of one level as ints. ``which`` is ``"guest"`` or ``"host"``."""
        table = self.guest_levels if which == "guest" else self.host_levels
        regs = table.get((leaf, subleaf))
        return as_ints(regs) if regs is not None else None


def as_ints(regs: LevelRegs | None) -> tuple[int, int, int, int] | None:
    """Convert ``("0x…", "0x…", "0x…", "0x…")`` to ints (``None`` passes through)."""
    if regs is None:
        return None
    return (int(regs[0], 16), int(regs[1], 16), int(regs[2], 16), int(regs[3], 16))


def decode_fms(eax: int) -> tuple[int, int, int]:
    """Decode CPUID.1 EAX into ``(family, model, stepping)``.

    Standard conditional decode (Intel SDM Vol. 1 §3.4.3 / AMD APM §17.8)::

        base_family = (EAX >> 8) & 0xF ; ext_family = (EAX >> 20) & 0xFF
        family  = base_family + (ext_family << 4) if base_family == 0xF else base_family
        model   = ((EAX >> 4) & 0xF) | ((EAX >> 12) & 0xF0)   # ext model lives in bits 19:16
        stepping = EAX & 0xF

    Verified against VMware's own self-report lines:
    ``0x000406e3`` -> ``(6, 0x4e, 3)`` (guest) and ``0x000b06a2`` ->
    ``(6, 0xba, 2)`` (host, Raptor Lake). The conditional matters: on the host
    value the *un*conditional formula would add ``0xb << 4`` even though the
    base family is not ``0xF``.
    """
    base_family = (eax >> 8) & 0xF
    ext_family = (eax >> 20) & 0xFF
    family = base_family + (ext_family << 4) if base_family == 0xF else base_family
    model = ((eax >> 4) & 0xF) | ((eax >> 12) & 0xF0)
    stepping = eax & 0xF
    return family, model, stepping


def vendor_from_leaf0(regs: LevelRegs | None) -> str | None:
    """Rebuild the CPU vendor string from leaf 0 (EBX | EDX | ECX, little-endian).

    ``0x756e6547 0x6c65746e 0x49656e69`` -> ``"GenuineIntel"``.
    """
    if regs is None:
        return None
    try:
        blob = struct.pack("<III", int(regs[1], 16), int(regs[3], 16), int(regs[2], 16))
    except (ValueError, struct.error):
        return None
    if not all(32 <= b < 127 for b in blob):
        return None
    return blob.decode("ascii")


def _parse_fm(m: re.Match[str]) -> tuple[int, int, int]:
    return (int(m.group("family"), 16), int(m.group("model"), 16), int(m.group("stepping"), 16))


def parse_log(text: str) -> LogFacts:
    """Parse log *text* into :class:`LogFacts`. Pure function; no I/O."""
    facts = LogFacts(raw=text)
    facts.lines = [(i, line) for i, line in enumerate(text.splitlines(), start=1)]

    for lineno, line in facts.lines:
        if facts.timestamp is None:
            m = _TS_RE.match(line)
            if m:
                facts.timestamp = m.group(1)

        if facts.vmware_version is None:
            m = _VERSION_RE.search(line)
            if m:
                facts.vmware_version = m.group("version")
                facts.vmware_build = m.group("build")
                facts.version_lineno = lineno

        if facts.guestos is None:
            m = _GUESTOS_RE.search(line)
            if m:
                facts.guestos = m.group("guestos")
                facts.guestos_lineno = lineno

        if "guest vs. host CPUID" in line:
            if not facts.has_cpuid_block:
                facts.has_cpuid_block = True
                facts.block_lineno = lineno

        m = _VENDOR_RE.search(line)
        if m:
            facts.vendor = m.group("vendor")
            facts.vendor_lineno = lineno

        m = _GUEST_FM_RE.search(line)
        if m:
            facts.guest_fm = _parse_fm(m)
            facts.guest_fm_lineno = lineno
        m = _HOST_FM_BLOCK_RE.search(line)
        if m:
            facts.host_fm = _parse_fm(m)
            facts.host_fm_lineno = lineno
        if facts.host_fm is None and (m := _HOST_FM_HDR_RE.search(line)) is not None:
            facts.host_fm = _parse_fm(m)
            facts.host_fm_lineno = lineno

        if (m := _GUEST_CODENAME_RE.search(line)) is not None:
            facts.guest_codename = m.group("codename")
        if (m := _HOST_CODENAME_BLOCK_RE.search(line)) is not None:
            facts.host_codename = m.group("codename")
        elif facts.host_codename is None and (m := _HOST_CODENAME_HDR_RE.search(line)) is not None:
            facts.host_codename = m.group("codename")

        if (m := _GUEST_NAME_RE.search(line)) is not None:
            facts.guest_name = m.group("name")
        if facts.host_name is None and (m := _HOST_NAME_HDR_RE.search(line)) is not None:
            facts.host_name = m.group("name")

        m = _LEVEL_RE.search(line)
        if m:
            key = (int(m.group("leaf"), 16), int(m.group("subleaf"), 16))
            regs = (m.group("eax"), m.group("ebx"), m.group("ecx"), m.group("edx"))
            if m.group("gtag") == "guest":
                facts.guest_levels[key] = regs
                facts.guest_level_lines[key] = lineno
            else:  # "*host" inside the block, or the "hostCPUID" header dump.
                # Later lines win, so the in-block boot dump overwrites the
                # header copy when both are present.
                facts.host_levels[key] = regs
                facts.host_level_lines[key] = lineno

        m = _PER_VCPU_RE.search(line)
        if m and int(m.group("leaf"), 16) == 1 and int(m.group("subleaf"), 16) == 0:
            facts.per_vcpu_leaf1.append(
                (
                    lineno,
                    int(m.group("vcpu")),
                    int(m.group("eax"), 16),
                    int(m.group("ebx"), 16),
                    int(m.group("ecx"), 16),
                    int(m.group("edx"), 16),
                )
            )

        if (m := _DICT_RE.search(line)) is not None:
            facts.dict_entries.setdefault(m.group("key"), (m.group("value"), lineno))

        if (m := _CAPABILITY_RE.search(line)) is not None:
            facts.capabilities.setdefault(m.group("key"), (m.group("value"), lineno))

        if "vmm-vcpus:" in line:
            facts.vmm_vcpus.append((lineno, line))
        if "OvhdUser_LocalApic" in line:
            facts.local_apic.append((lineno, line))
        if "numa" in line.lower() and "OvhdMem" not in line:
            facts.numa_lines.append((lineno, line))
        for pat in _TOOLS_ERROR_RES:
            if pat.search(line):
                facts.tools_errors.append((lineno, line))
                break

        if facts.khz_estimate is None and (m := _KHZ_RE.search(line)) is not None:
            facts.khz_estimate = int(m.group("khz"))
            facts.khz_estimate_lineno = lineno
        if facts.tsc_estimates is None and (m := _TSC_RE.search(line)) is not None:
            facts.tsc_estimates = (
                int(m.group("vmmon")),
                int(m.group("cpuinfo")),
                int(m.group("cpufreq")),
                int(m.group("sysctlfreq")),
            )
            facts.tsc_estimates_lineno = lineno

    return facts


def parse_log_path(path: str | Path) -> LogFacts:
    """Read *path* and parse it, recording the file's mtime (V0 needs it)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="surrogateescape")
    facts = parse_log(text)
    facts.name = p.name
    try:
        facts.mtime = p.stat().st_mtime
    except OSError:
        facts.mtime = None
    return facts


__all__ = [
    "LevelKey",
    "LevelRegs",
    "LogFacts",
    "as_ints",
    "decode_fms",
    "parse_log",
    "parse_log_path",
    "vendor_from_leaf0",
]

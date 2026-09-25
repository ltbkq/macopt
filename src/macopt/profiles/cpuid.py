"""CPUID masking profiles and the R1–R8 rule engine (DESIGN §4.8).

Nothing here runs by default: ``ProfileOptions.cpuid_profile`` stays
``"none"`` and :func:`build` returns an empty result. Masks are opt-in because
they change what *every* vCPU reports, and a wrong value does not degrade
performance — it stops the guest from powering on.

Mechanism facts that the rules below depend on (DESIGN §4.8.1,
docs/evidence/02-cpuid-review.md §1.1):

* the value is a **bit-by-bit override**, not an AND mask: ``0``/``1`` force,
  ``-`` keeps VMware's default, ``h`` copies the host bit. That is precisely
  why ``AuthenticAMD`` can be rewritten into ``GenuineIntel``;
* a value must be a full 32-bit quantity (``0x078BFBFF`` or a 32-char
  ``01-h`` string);
* key shapes come from the binary's own format strings
  (``cpuid.%x.%s`` / ``cpuid.%x.%x.%s`` / ``.amd`` variants);
* VMware already applies built-in Darwin masks, so the model is
  *built-in mask → user mask* layered, not "VMware does nothing"
  (docs/evidence/02 §1.1(6)); whose precedence applies is open test item T1.

Bit tables
----------
``LEAF1_EDX_BITS`` follows DESIGN §12.1 / Intel SDM (DS=21 … PBE=31) — four
independent sources agree (kernel ``cpufeatures.h``, Wikipedia, the Unlocker's
``cpuid`` tool, a VMware forum reply; docs/evidence/02 §1.3).

``LEAF1_ECX_BITS`` follows **Intel SDM Vol.1 Table 3-5**
(``SSE42=20, POPCNT=23, AES=25, OSXSAVE=27, HYPERVISOR=31``).
Historical note: DESIGN v2.1 initially shipped ``SSE42=0, POPCNT=1, AES=20``
in §12.1 — an erratum that was copied into this module and into
``verify/assertions.py`` V4 before it was caught (see DESIGN §12.1
勘误). The table is now canonical-correct; the private
:data:`_LEAF1_ECX_BITS_SDM` full table remains the superset consulted by
rules, and ``tests/test_cpuid.py`` pins the numbers so this cannot regress.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from ..keys import is_known
from ..model import (
    RISK_HIGH,
    RISK_NORMAL,
    Evidence,
    HostInfo,
    Param,
    ProfileOptions,
    ProfileResult,
)

__all__ = [
    "BLOCK",
    "CPUID_KEYS",
    "FAIL",
    "INFO",
    "KNOWN_VENDORS",
    "LEAF1_ECX_BITS",
    "LEAF1_EDX_BITS",
    "LEAF7_EBX_BITS",
    "PROFILES",
    "RULE_IDS",
    "WARN",
    "CpuIdProfile",
    "CpuSignature",
    "RuleReport",
    "RuleResult",
    "build",
    "decode_leaf1_eax",
    "decode_leaf1_ecx",
    "decode_leaf1_edx",
    "decode_leaf7_ebx",
    "is_explicit",
    "is_mask_value",
    "parse_mask",
    "validate",
]

# --------------------------------------------------------------------------- #
# Bit tables (provenance in the module docstring)
# --------------------------------------------------------------------------- #

#: leaf 1 EDX feature bits — DESIGN §12.1 / Intel SDM Vol.2 CPUID.1:EDX.
LEAF1_EDX_BITS: dict[str, int] = {
    "DS": 21,
    "ACPI": 22,
    "MMX": 23,
    "FXSR": 24,
    "SSE": 25,
    "SSE2": 26,
    "SS": 27,
    "HTT": 28,
    "TM": 29,
    "PBE": 31,
}

#: leaf 1 ECX bits — Intel SDM Vol.1 Table 3-5 (canonical).
#:
#: ``SSE4.2=20`` (not 0), ``POPCNT=23`` (not 1), ``AES=25`` (not 20). The
#: earlier numbers came from a DESIGN §12.1 erratum and would have decoded
#: SSE3 / SSE4.2 under the wrong names; see the module docstring.
LEAF1_ECX_BITS: dict[str, int] = {
    "SSE42": 20,
    "POPCNT": 23,
    "AES": 25,
    "OSXSAVE": 27,
    "HYPERVISOR": 31,
}

#: leaf 7 EBX feature bits (DESIGN §12.1).
LEAF7_EBX_BITS: dict[str, int] = {"AVX2": 5}

#: Private cross-check table, Intel SDM Vol.2 CPUID.1:ECX. Never used for
#: anything user-visible — it only widens the claim set of R4 so a rule can
#: not be blinded by the frozen table above.
_LEAF1_ECX_BITS_SDM: dict[str, int] = {
    "SSE3": 0,
    "PCLMULQDQ": 1,
    "SSSE3": 9,
    "CX16": 13,
    "SSE41": 19,
    "SSE42": 20,
    "X2APIC": 21,
    "MOVBE": 22,
    "POPCNT": 23,
    "TSC_DEADLINE": 24,
    "AES": 25,
    "XSAVE": 26,
    "OSXSAVE": 27,
    "AVX": 28,
    "F16C": 29,
    "RDRAND": 30,
    "HYPERVISOR": 31,
}

#: Features R4 cares about (DESIGN §4.8.2: "声称 AVX/SSE4.2/AES").
_CLAIM_SENSITIVE = frozenset({"AVX", "AVX2", "SSE41", "SSE42", "AES", "POPCNT"})

#: Vendor strings that are legal 12-character x86 vendor ids. VMware has no
#: literal ``GenuineIntel``/``AuthenticAMD`` in its binaries — the string is
#: assembled from the three leaf-0 registers (docs/evidence/02 §1.1(5)).
KNOWN_VENDORS: tuple[str, ...] = (
    "GenuineIntel",
    "AuthenticAMD",
    "HygonGenuine",
    "CentaurHauls",
    "VIA VIA VIA ",
    "Microsoft Hv",
)

#: Prefix writer/cli use to map a plan error onto exit code 6 (EXIT_REFUSED).
_WHITELIST_PREFIX = "whitelist:"

#: Key shapes macopt is allowed to touch in this module.
CPUID_KEYS: tuple[str, ...] = (
    "cpuid.0.eax",
    "cpuid.0.ebx",
    "cpuid.0.edx",
    "cpuid.0.ecx",
    "cpuid.1.eax",
    "cpuid.1.ebx",
    "cpuid.1.ecx",
    "cpuid.1.edx",
)

# --------------------------------------------------------------------------- #
# Value parsing (DESIGN §4.8.1: full 32-bit, four characters of semantics)
# --------------------------------------------------------------------------- #

_HEX_MASK_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")
_CHAR_MASK_RE = re.compile(r"^[01hH-]{32}$")
#: VMware's own Darwin masks are written in 4-bit groups
#: (``----:----:----:0001:----:----:1110:0101``, docs/evidence/02 §1.1(4)).
_GROUPED_MASK_RE = re.compile(r"^(?:[01hH-]{4}:){7}[01hH-]{4}$")
_ALL_EXPLICIT_RE = re.compile(r"^[01]{32}$")
_ALL_EXPLICIT_GROUPED_RE = re.compile(r"^(?:[01]{4}:){7}[01]{4}$")


def _norm_value(raw: object) -> str | None:
    """Strip whitespace and one layer of ``.vmx`` quoting; ``""`` → ``None``."""
    if raw is None:
        return None
    text = str(raw).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1].strip()
    return text or None


def is_mask_value(raw: object) -> bool:
    """True for a syntactically valid 32-bit mask (hex, ``01-h`` or grouped)."""
    text = _norm_value(raw)
    if text is None:
        return False
    return bool(
        _HEX_MASK_RE.match(text)
        or _CHAR_MASK_RE.match(text)
        or _GROUPED_MASK_RE.match(text)
    )


def is_explicit(raw: object) -> bool:
    """True when the value forces **every** bit (no ``-``/``h`` holes)."""
    text = _norm_value(raw)
    if text is None:
        return False
    if _HEX_MASK_RE.match(text):
        return True
    return bool(_ALL_EXPLICIT_RE.match(text) or _ALL_EXPLICIT_GROUPED_RE.match(text))


def parse_mask(raw: object) -> int | None:
    """Integer value of an *explicit* mask, else ``None``.

    ``None`` covers both "not a mask at all" and "partially implicit mask"
    (``-``/``h`` bits): we can reason about a fully forced value, but never
    about a value whose effective bits depend on VMware's (and the host's)
    defaults.
    """
    text = _norm_value(raw)
    if text is None:
        return None
    if _HEX_MASK_RE.match(text):
        value = int(text[2:], 16)
        return value if value <= 0xFFFFFFFF else None
    if _ALL_EXPLICIT_GROUPED_RE.match(text):
        text = text.replace(":", "")
    if _ALL_EXPLICIT_RE.match(text):
        return int(text, 2)
    return None


def _as_int(raw: object) -> int | None:
    """Integer for a hex or decimal string (``documented_values`` helper)."""
    if isinstance(raw, int):
        return raw
    if not isinstance(raw, str):
        return None
    text = raw.strip().strip('"')
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Decoders
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CpuSignature:
    """Decoded ``CPUID.1:EAX`` signature (Intel family/model/stepping rules)."""

    raw: int
    base_family: int
    base_model: int
    ext_family: int
    ext_model: int
    family: int
    model: int
    stepping: int

    @property
    def triple(self) -> tuple[int, int, int]:
        return (self.family, self.model, self.stepping)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"family 0x{self.family:X} model 0x{self.model:X} stepping {self.stepping} (0x{self.raw:08X})"


def decode_leaf1_eax(value: int) -> CpuSignature:
    """Decode ``CPUID.1:EAX`` into family/model/stepping (Intel rules).

    ``base_family = EAX[11:8]``, ``ext_family = EAX[27:20]`` (added only when
    the base family is ``0xF``), ``ext_model = EAX[19:16]`` contributes when
    the base family is ``0x6`` or ``0xF``. So ``0x00010671`` → family 6 /
    model 0x17 (Penryn) and ``0x000906E9`` → family 6 / model 0x9E (Kaby
    Lake) — the two values R5 compares (docs/evidence/02 §1.4(c)).
    """
    raw = int(value) & 0xFFFFFFFF
    stepping = raw & 0xF
    base_model = (raw >> 4) & 0xF
    base_family = (raw >> 8) & 0xF
    ext_model = (raw >> 16) & 0xF
    ext_family = (raw >> 20) & 0xF
    family = base_family + ext_family if base_family == 0xF else base_family
    if base_family in (0x6, 0xF):
        model = base_model | (ext_model << 4)
    else:
        model = base_model
    return CpuSignature(raw, base_family, base_model, ext_family, ext_model, family, model, stepping)


def decode_leaf1_edx(value: int) -> dict[str, bool]:
    """``{feature: bit set?}`` for every name in :data:`LEAF1_EDX_BITS`."""
    raw = int(value) & 0xFFFFFFFF
    return {name: bool(raw >> bit & 1) for name, bit in LEAF1_EDX_BITS.items()}


def decode_leaf1_ecx(value: int) -> dict[str, bool]:
    """``{feature: bit set?}`` using the frozen :data:`LEAF1_ECX_BITS`."""
    raw = int(value) & 0xFFFFFFFF
    return {name: bool(raw >> bit & 1) for name, bit in LEAF1_ECX_BITS.items()}


def decode_leaf7_ebx(value: int) -> dict[str, bool]:
    """``{feature: bit set?}`` using :data:`LEAF7_EBX_BITS`."""
    raw = int(value) & 0xFFFFFFFF
    return {name: bool(raw >> bit & 1) for name, bit in LEAF7_EBX_BITS.items()}


def _claims_of(values: Mapping[str, str]) -> set[str]:
    """Features a value set asserts, via both ECX tables plus leaf 7.

    Both tables are unioned on purpose (module docstring): whichever of
    ``SSE42``/``POPCNT``/``AES`` is meant, the claim is seen.
    """
    claims: set[str] = set()
    ecx = values.get("cpuid.1.ecx")
    parsed = parse_mask(ecx)
    if parsed is not None:
        for table in (LEAF1_ECX_BITS, _LEAF1_ECX_BITS_SDM):
            for name, bit in table.items():
                if parsed >> bit & 1:
                    claims.add(name)
    ebx = values.get("cpuid.7.0.ebx") or values.get("cpuid.7.ebx")
    parsed7 = parse_mask(ebx)
    if parsed7 is not None:
        for name, bit in LEAF7_EBX_BITS.items():
            if parsed7 >> bit & 1:
                claims.add(name)
    return claims & _CLAIM_SENSITIVE


# --------------------------------------------------------------------------- #
# Rule engine (DESIGN §4.8.2)
# --------------------------------------------------------------------------- #

BLOCK = "BLOCK"
FAIL = "FAIL"
WARN = "WARN"
INFO = "INFO"

#: Rules in table order — one per row of DESIGN §4.8.2.
RULE_IDS: tuple[str, ...] = ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8")


@dataclass(frozen=True)
class RuleResult:
    """One rule's verdict. ``level`` decides whether it blocks the plan."""

    id: str
    level: str
    message: str
    key: str = ""

    @property
    def blocking(self) -> bool:
        return self.level in (BLOCK, FAIL)

    def render(self) -> str:
        body = f"{self.id} {self.level}: {self.message}"
        # ``whitelist:`` is the prefix writer/cli map onto EXIT_REFUSED (6).
        if self.id == "R7" and self.blocking:
            return f"{_WHITELIST_PREFIX} {body}"
        return body

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.render()


@dataclass
class RuleReport:
    """All rule verdicts for one value set, plus the derived buckets."""

    results: tuple[RuleResult, ...] = ()

    @property
    def errors(self) -> list[str]:
        """Blocking messages (``BLOCK`` → exit 5/6, ``FAIL`` → exit 5)."""
        return [r.render() for r in self.results if r.blocking]

    @property
    def warnings(self) -> list[str]:
        return [r.render() for r in self.results if r.level == WARN]

    @property
    def notices(self) -> list[str]:
        return [r.render() for r in self.results if r.level == INFO]

    @property
    def fired(self) -> set[str]:
        return {r.id for r in self.results}

    def has(self, rule_id: str) -> RuleResult | None:
        return next((r for r in self.results if r.id == rule_id), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "results": [
                {"id": r.id, "level": r.level, "message": r.message, "key": r.key}
                for r in self.results
            ],
            "errors": self.errors,
            "warnings": self.warnings,
        }


def _vendor_string(values: Mapping[str, str]) -> tuple[str | None, list[str]]:
    """Assemble the leaf-0 vendor id; returns ``(string|None, present_parts)``."""
    parts: list[str] = []
    present: list[str] = []
    for reg in ("ebx", "edx", "ecx"):
        key = f"cpuid.0.{reg}"
        parsed = parse_mask(values.get(key))
        if parsed is None:
            continue
        present.append(key)
        parts.append(
            "".join(chr((parsed >> shift) & 0xFF) for shift in (0, 8, 16, 24))
        )
    if len(present) != 3:
        return None, present
    return "".join(parts), present


def validate(
    values: Mapping[str, str],
    *,
    profile: str = "none",
    host: HostInfo | None = None,
    allow_apic_risk: bool = False,
    allow_unknown_keys: bool = False,
) -> RuleReport:
    """Run R1–R8 against ``values`` (the ``cpuid.*`` set macopt intends).

    :param values: ``key -> raw value`` for the ``cpuid.*`` keys in play.
    :param profile: profile name, read by R4 (feature claims) and R5
        (declared family/model/stepping) and R8 (any non-``none`` profile on
        an Intel host is a no-op the user should know about).
    :param host: host facts for R8; ``None`` means "unknown host" and R8
        stays silent rather than guessing (DESIGN §4.0: 缺失证据 → SKIP).
    :param allow_apic_risk: lifts R1 and downgrades R2 to a warning
        (``--allow-apic-risk``).
    :param allow_unknown_keys: downgrades R7 to a warning
        (``--allow-unknown-keys``).

    Levels: ``BLOCK``/``FAIL`` end up in :attr:`RuleReport.errors` (the plan
    refuses to write), ``WARN`` in :attr:`RuleReport.warnings`.
    """
    results: list[RuleResult] = []

    eax1_raw = parse_mask(values.get("cpuid.1.eax"))
    ebx1_raw = parse_mask(values.get("cpuid.1.ebx"))
    edx1_raw = parse_mask(values.get("cpuid.1.edx"))
    eax0_raw = parse_mask(values.get("cpuid.0.eax"))

    # -- R1: explicit cpuid.1.ebx ---------------------------------------- #
    if "cpuid.1.ebx" in values and is_explicit(values.get("cpuid.1.ebx")):
        detail = (
            "cpuid.1.ebx 被赋予显式完整值 "
            f"({values.get('cpuid.1.ebx')}"
            + (
                f" → APIC ID={(ebx1_raw or 0) >> 24}、max logical={((ebx1_raw or 0) >> 16) & 0xFF}"
                if ebx1_raw is not None
                else ""
            )
            + ")：该值会把初始 APIC ID 与 [23:16] 拓扑字段硬编码到每个 vCPU"
            "（社区值 0x02010800 ⇒ APIC=2、max logical=1，而 VMware 自算值是 0x00100800）"
        )
        if allow_apic_risk:
            results.append(RuleResult("R1", WARN, detail + " —— 已由 --allow-apic-risk 放行", "cpuid.1.ebx"))
        else:
            results.append(
                RuleResult(
                    "R1",
                    BLOCK,
                    detail + " —— 拒绝写入，需 --allow-apic-risk 显式放行（DESIGN §4.8.2）",
                    "cpuid.1.ebx",
                )
            )

    # -- R2 / R3: leaf1 EDX bits the darwin tier requires ------------------ #
    if "cpuid.1.edx" in values and is_explicit(values.get("cpuid.1.edx")) and edx1_raw is not None:
        bits = decode_leaf1_edx(edx1_raw)
        if not bits["SS"]:
            detail = (
                f"cpuid.1.edx={values.get('cpuid.1.edx')} 清除 bit27 (SS)："
                "darwin*-64 已知要求 cpuid.ss:Min:1（vmware.log FeatureCompat: Requirements），"
                "可能触发 `Feature 'cpuid.ss' was absent, but must be present.` → 开机失败（T2 待实测）"
            )
            if allow_apic_risk:
                results.append(RuleResult("R2", WARN, detail + " —— 已由 --allow-apic-risk 放行", "cpuid.1.edx"))
            else:
                results.append(
                    RuleResult("R2", BLOCK, detail + " —— WARN 升级为 BLOCK，需 --allow-apic-risk 放行", "cpuid.1.edx")
                )

        if not bits["HTT"]:
            results.append(
                RuleResult(
                    "R3",
                    WARN,
                    f"cpuid.1.edx={values.get('cpuid.1.edx')} 清除 bit28 (HTT)："
                    "EBX[23:16]「封装内逻辑处理器数」语义随之失效，guest 拓扑信息退化",
                    "cpuid.1.edx",
                )
            )

    # -- R4: leaf-0 max leaf vs the features the profile claims ------------ #
    claims = _claims_of(values) | set(_PROFILE_CLAIMS.get(profile, ()))
    if eax0_raw is not None and eax0_raw < 0xD and claims:
        shown = ", ".join(sorted(claims))
        results.append(
            RuleResult(
                "R4",
                WARN,
                f"cpuid.0.eax=0x{eax0_raw:X} 把基本 leaf 上限定在 < 0xD，而该组 profile 声称 {shown}："
                "leaf 0xD(XSAVE)/0x16/0x1F 将不可枚举，leaf 与特性位不自洽"
                "（0x0B 属社区拼装值，T4 待实测）",
                "cpuid.0.eax",
            )
        )

    # -- R5: signature vs profile name / brand string ---------------------- #
    if eax1_raw is not None:
        signature = decode_leaf1_eax(eax1_raw)
        declared = _PROFILE_SIGNATURE.get(profile)
        if declared is not None and signature.triple != declared:
            results.append(
                RuleResult(
                    "R5",
                    FAIL,
                    f"cpuid.1.eax=0x{eax1_raw:08X} 解码为 {signature}，与 profile {profile!r} 声明的 "
                    f"family {declared[0]} / model 0x{declared[1]:X} / stepping {declared[2]} 冲突"
                    "（例如 profile 叫 kabylake-7700k 却写 0x00010671＝Penryn）",
                    "cpuid.1.eax",
                )
            )
        brand = _norm_value(values.get("cpuid.brandString"))
        if brand:
            lowered = brand.lower()
            for token, want in _BRAND_HINTS:
                if token in lowered and signature.triple != want:
                    results.append(
                        RuleResult(
                            "R5",
                            FAIL,
                            f"cpuid.brandString={brand!r} 暗示 {want[0]}/0x{want[1]:X}/{want[2]}，"
                            f"但 cpuid.1.eax 解码为 {signature}",
                            "cpuid.brandString",
                        )
                    )
                    break

    # -- R6: vendor trio --------------------------------------------------- #
    vendor, present = _vendor_string(values)
    if vendor is None and present:
        results.append(
            RuleResult(
                "R6",
                WARN,
                "leaf 0 厂商串三段（cpuid.0.ebx/edx/ecx）只写了其中 "
                f"{len(present)} 段（{', '.join(present)}）：厂商串必须三段同时给，"
                "否则会拼出不合法/半新半旧的厂商 id",
                "cpuid.0.ebx",
            )
        )
    elif vendor is not None and (
        vendor not in KNOWN_VENDORS
        or not vendor.isascii()
        or not all(c.isprintable() for c in vendor)
    ):
        results.append(
            RuleResult(
                "R6",
                WARN,
                f"leaf 0 三段拼出的厂商串 {vendor!r} 不是合法已知厂商（{', '.join(KNOWN_VENDORS)}）",
                "cpuid.0.ebx",
            )
        )

    # -- R7: whitelist (DESIGN §4.5) --------------------------------------- #
    for key in sorted(values):
        if not key.startswith("cpuid."):
            continue
        if not is_known(key):
            detail = (
                f"cpuid key {key!r} 不在白名单"
                "（cpuid 格式串展开 + data/known_keys.txt 均未命中）"
            )
            if allow_unknown_keys:
                results.append(
                    RuleResult("R7", WARN, detail + "，已由 --allow-unknown-keys 放行", key)
                )
            else:
                results.append(
                    RuleResult("R7", BLOCK, detail + " —— 拒绝写入（§4.5）", key)
                )

    # -- R8: Intel host does not need a disguise --------------------------- #
    if profile and profile != "none":
        vendor_host = (host.vendor if host else None) or "unknown"
        if vendor_host == "GenuineIntel":
            results.append(
                RuleResult(
                    "R8",
                    WARN,
                    f"宿主 vendor=GenuineIntel，启用 cpuid profile {profile!r} —— 本机不需要伪装；"
                    "Intel 宿主跑 macOS 本就不需要掩码，继续前需显式确认",
                )
            )
        elif vendor_host == "AuthenticAMD":
            results.append(
                RuleResult(
                    "R8",
                    INFO,
                    f"宿主 vendor=AuthenticAMD，cpuid profile {profile!r} 属 AMD 场景："
                    "AMD 上的实效结论尚未在本环境实测（验收 A / T7 待办）",
                )
            )
        else:
            results.append(
                RuleResult(
                    "R8",
                    INFO,
                    f"宿主 vendor 未知（{vendor_host}），无法判断本机是否需要伪装 —— 按未知处理",
                )
            )

    return RuleReport(results=tuple(results))


# --------------------------------------------------------------------------- #
# Profiles (DESIGN §4.8.3)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CpuIdProfile:
    """A named, fully described ``cpuid.*`` mask set (DESIGN §4.8.3)."""

    #: ``none`` | ``penryn`` | ``kabylake-7700k`` | ``signed-brand``
    name: str
    #: vendor this profile writes *toward* (``"any"`` when it writes no leaf-0
    #: vendor registers)
    target_vendor: str
    #: ``key -> value`` (complete 32-bit values)
    params: dict[str, str]
    #: what `verify` V8 should observe in the guest log
    documented_values: dict[str, str]
    risk: str = RISK_HIGH
    notes: tuple[str, ...] = ()
    #: human-readable provenance; every value must carry one
    evidence: tuple[Evidence, ...] = ()
    #: short reason appended to each emitted Param
    reason: str = ""

    def signature(self) -> tuple[int, int, int] | None:
        """Declared ``(family, model, stepping)`` — ``None`` if undeclared."""
        return _PROFILE_SIGNATURE.get(self.name)


# -- evidence --------------------------------------------------------------- #

_EV_MASK_SEMANTICS = (
    Evidence(
        "doc",
        "docs/DESIGN.md §4.8.1",
        "掩码语义为逐位覆盖：0/1 强制、- 保留 VMware 默认、h 取宿主位；值必须是完整 32 位",
    ),
    Evidence(
        "community",
        "docs/evidence/02-cpuid-review.md §1.5(1)",
        "Broadcom 社区帖 + HN 中 VMware 方人员：'Ones and zeroes override the default settings, bit by bit'",
    ),
)

_EV_BITS = (
    Evidence(
        "doc",
        "docs/DESIGN.md §12.1",
        "leaf1 EDX 位号：DS=21 ACPI=22 MMX=23 FXSR=24 SSE=25 SSE2=26 SS=27 HTT=28 TM=29 PBE=31",
    ),
    Evidence(
        "doc",
        "docs/evidence/02-cpuid-review.md §1.3",
        "四个独立来源（内核头/Wikipedia/cpuid 工具/VMware 回帖）互证同一张位号表",
    ),
)

_EV_COMMUNITY = (
    Evidence(
        "community",
        "docs/evidence/02-cpuid-review.md §1.5(2)",
        "DavidsonRafaelK / insanelymac 338849 / amd-osx 4696 / exchangetuts / TechSpite / GEEKrar "
        "八行值高度一致：0x0B、Genu+ineI+ntel、0x00010671、0x02010800、0x82982203、0x078BFBFF",
    ),
    Evidence(
        "community",
        "docs/evidence/02-cpuid-review.md §1.5(4)",
        "AMD 场景：无掩码时 Apple logo 卡死 / vCPU shutdown / `The CPU has been disabled`",
    ),
)

_EV_LOG = (
    Evidence(
        "log",
        "docs/evidence/02-cpuid-review.md §1.1(6)",
        "无用户掩码时 guest leaf1 = 0x000406e3 0x00100800 0xf7fa322b 0x1f8bfbff"
        "（VMware 内置 Darwin 掩码），宿主为 0x000b06a2 0x11800800 0x7ffafbff 0xbfebfbff",
    ),
    Evidence(
        "binary",
        "docs/evidence/01-factcheck.md:34",
        "cpuid.1.eax 签名与 brandString 的可写性见 T5（命名键 cpuid.family/model/stepping/brandString）",
    ),
)

_EV_SIGNED = (
    Evidence(
        "binary",
        "docs/evidence/02-cpuid-review.md §1.1(3)",
        "二进制含 cpuid.family / cpuid.model / cpuid.stepping / cpuid.brandString（270 个命名键）",
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md §4.8.3",
        "signed-brand 只写命名键，被标为「首选」；是否为可写 .vmx 键属 T5",
    ),
)

# -- community set (8 lines) ----------------------------------------------- #

#: Community mask set, reproduced verbatim from docs/evidence/02 §1.5(2).
#: Order matters: it is the order macopt emits them in.
_PENRYN_PARAMS: dict[str, str] = {
    "cpuid.0.eax": "0x0000000B",
    "cpuid.0.ebx": "0x756E6547",  # "Genu"
    "cpuid.0.edx": "0x49656E69",  # "ineI"
    "cpuid.0.ecx": "0x6C65746E",  # "ntel"
    "cpuid.1.eax": "0x00010671",  # family 6 / model 0x17 (Penryn) / stepping 1
    "cpuid.1.ebx": "0x02010800",  # APIC ID=2, max logical=1  ← R1
    "cpuid.1.ecx": "0x82982203",  # SSE4.2 + AES community value
    "cpuid.1.edx": "0x078BFBFF",  # clears DS/ACPI/SS/HTT/TM/PBE  ← R2/R3
}

#: Hand-curated Kaby Lake set: the vendor trio, the i7-7700K signature and the
#: leaf-1 EDX/ECX values VMware itself hands to a Darwin guest. Deliberately
#: **no** ``cpuid.1.ebx`` (R1) and **no** ``cpuid.0.eax`` (R4), so the set can
#: only trip R8 on an Intel host.
_KABYLAKE_PARAMS: dict[str, str] = {
    "cpuid.0.ebx": "0x756E6547",
    "cpuid.0.edx": "0x49656E69",
    "cpuid.0.ecx": "0x6C65746E",
    "cpuid.1.eax": "0x000906E9",  # family 6 / model 0x9E (Kaby Lake) / stepping 9
    "cpuid.1.ecx": "0xF7FA322B",  # VMware built-in Darwin guest ECX
    "cpuid.1.edx": "0x1F8BFBFF",  # VMware built-in Darwin guest EDX (SS/HTT kept)
}

#: What each profile *claims* to provide — R4 reads this in addition to the
#: bits actually present in the values (community wording: "AVX/SSE4.2/AES").
_PROFILE_CLAIMS: dict[str, tuple[str, ...]] = {
    "penryn": ("SSE42", "AES", "POPCNT"),
    "kabylake-7700k": ("SSE42", "AES", "POPCNT"),
    "signed-brand": (),
    "none": (),
}

#: Declared ``(family, model, stepping)`` per profile — R5.
_PROFILE_SIGNATURE: dict[str, tuple[int, int, int]] = {
    "penryn": (6, 0x17, 1),
    "kabylake-7700k": (6, 0x9E, 9),
}

#: Brand-string tokens that imply a signature (R5's second half).
_BRAND_HINTS: tuple[tuple[str, tuple[int, int, int]]] = (
    ("7700", (6, 0x9E, 9)),
    ("kaby", (6, 0x9E, 9)),
    ("penryn", (6, 0x17, 1)),
)


def _none_profile() -> CpuIdProfile:
    return CpuIdProfile(
        name="none",
        target_vendor="any",
        params={},
        documented_values={},
        risk=RISK_NORMAL,
        notes=(),
        evidence=(),
        reason="no cpuid masking (default; Intel hosts need no disguise)",
    )


def _penryn_profile() -> CpuIdProfile:
    return CpuIdProfile(
        name="penryn",
        target_vendor="GenuineIntel",
        params=dict(_PENRYN_PARAMS),
        documented_values={
            "vendor": "GenuineIntel",
            "cpuid.0.eax": "0x0000000B",
            "cpuid.1.eax": "0x00010671",
            "cpuid.1.ebx": "0x02010800",
            "cpuid.1.ecx": "0x82982203",
            "cpuid.1.edx": "0x078BFBFF",
        },
        risk=RISK_HIGH,
        notes=(
            "社区拼装值：cpuid.0.eax=0x0B 不是任何真实 Intel 的最大 leaf，会封顶基本 leaf（T4 待实测）",
            "macOS 是安装期还是每次启动校验 CPUID 尚无权威来源（T6），掩码不要假设「装完可撤」",
            "非默认 leaf 掩码是否需要 monitor_control.enable_fullcpuid 属 T8；本 profile 不写该 key"
            "（二进制零命中，见 data/known_keys.txt 的 known non-existent 段）",
        ),
        evidence=_EV_COMMUNITY + _EV_BITS + _EV_MASK_SEMANTICS,
        reason=(
            "community CPUID mask set (SSE4.2/AES/Pentium-era vendor + Penryn signature); "
            "high risk: R1/R2 must be lifted explicitly"
        ),
    )


def _kabylake_profile() -> CpuIdProfile:
    return CpuIdProfile(
        name="kabylake-7700k",
        target_vendor="GenuineIntel",
        params=dict(_KABYLAKE_PARAMS),
        documented_values={
            "vendor": "GenuineIntel",
            "cpuid.1.eax": "0x000906E9",
            "cpuid.1.ecx": "0xF7FA322B",
            "cpuid.1.edx": "0x1F8BFBFF",
        },
        risk=RISK_HIGH,
        notes=(
            "cpuid.1.edx/ecx 取自本机日志里 VMware 的内置 Darwin 值（保留 SS/HTT/OSXSAVE/hypervisor）",
            "无 cpuid.1.ebx、无 cpuid.0.eax ⇒ 不触发 R1/R4；Intel 宿主仍会按 R8 提示「本机不需要伪装」",
            "厂商三串只在 AMD/非 Intel 宿主上有意义；Intel 宿主写它是冗余的",
        ),
        evidence=_EV_LOG + _EV_BITS + _EV_MASK_SEMANTICS,
        reason=(
            "curated Kaby Lake i7-7700K signature using VMware's own built-in Darwin leaf-1 values "
            "(no cpuid.1.ebx, no leaf-0 max-leaf cap)"
        ),
    )


def _signed_brand_profile() -> CpuIdProfile:
    return CpuIdProfile(
        name="signed-brand",
        target_vendor="any",
        params={},
        documented_values={},
        risk=RISK_NORMAL,
        notes=(
            "首选路径（DESIGN §4.8.3）：命名键可读、可审计，位掩码只作兜底",
            "T5 未完成：cpuid.family/model/stepping/brandString 是否为可写 .vmx 键尚未实测 "
            "⇒ 全部标 needs_confirmation",
        ),
        evidence=_EV_SIGNED,
        reason="signed brand/identity keys instead of 32-bit masks (preferred path)",
    )


#: Every selectable profile (DESIGN §4.8.3); ``none`` is the default.
PROFILES: dict[str, CpuIdProfile] = {
    "none": _none_profile(),
    "penryn": _penryn_profile(),
    "kabylake-7700k": _kabylake_profile(),
    "signed-brand": _signed_brand_profile(),
}


# --------------------------------------------------------------------------- #
# build()
# --------------------------------------------------------------------------- #


def _extra(opts: ProfileOptions, *names: str) -> str | None:
    """First non-empty ``opts.extras`` value among ``names`` (order kept)."""
    for name in names:
        raw = opts.extras.get(name)
        value = _norm_value(raw)
        if value:
            return value
    return None


def _signed_brand_values(opts: ProfileOptions) -> tuple[dict[str, str], list[str]]:
    """Materialise ``signed-brand`` from ``opts.extras`` (values are required).

    macopt ships **no** brand string of its own: an invented identity is
    exactly what this project must not produce.
    """
    values: dict[str, str] = {}
    errors: list[str] = []
    brand = _extra(opts, "brandString", "cpuid.brandString", "brand")
    if brand is None:
        errors.append(
            "signed-brand 需要显式品牌串：--extra brandString=\"Intel(R) Core(TM) \""
            "（macopt 不内置任何品牌串/序列号）"
        )
    else:
        values["cpuid.brandString"] = brand
    for short, key in (("family", "cpuid.family"), ("model", "cpuid.model"), ("stepping", "cpuid.stepping")):
        raw = _extra(opts, short, key)
        if raw is None:
            continue
        number = _as_int(raw)
        if number is None:
            errors.append(f"signed-brand: {short}={raw!r} 不是数字（接受十进制或 0x 十六进制）")
        else:
            values[key] = raw if raw.lower().startswith("0x") else str(number)
    if not values:
        errors.append("signed-brand: 至少要提供 brandString（或 family/model/stepping 之一）")
    return values, errors


def build(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> ProfileResult:
    """Emit ``cpuid.*`` ``Param``s for ``opts.cpuid_profile`` (DESIGN §4.8).

    Default (``cpuid_profile="none"``) emits nothing — Intel hosts need no
    disguise. Everything emitted passes through :func:`validate` first, and
    the rule report is returned alongside the params so the CLI can refuse
    (``BLOCK``/``FAIL``) or demand confirmation (``WARN``) before writing.
    """
    name = (opts.cpuid_profile or "none").strip()
    if name in ("", "none"):
        return ProfileResult()

    profile = PROFILES.get(name)
    if profile is None:
        known = ", ".join(sorted(PROFILES))
        return ProfileResult(errors=(f"unknown cpuid profile {name!r} (known: {known})",))

    values: dict[str, str] = dict(profile.params)
    extra_errors: list[str] = []
    if name == "signed-brand":
        signed, extra_errors = _signed_brand_values(opts)
        values.update(signed)

    warnings: list[str] = list(profile.notes)

    # Masks already in the file but not owned by this profile: report, never
    # rewrite (they are the user's, and writer/check audit them separately).
    foreign = sorted(
        key
        for key in mapping
        if str(key).startswith("cpuid.") and str(key) not in values
    )
    if foreign:
        warnings.append(
            "文件里已有本 profile 不管理的 cpuid.* 掩码："
            + ", ".join(foreign)
            + "（macopt 不改写它们；请用 macopt check 的 S7 单独审阅）"
        )

    report = validate(
        values,
        profile=name,
        host=host,
        allow_apic_risk=opts.allow_apic_risk,
        allow_unknown_keys=opts.allow_unknown_keys,
    )
    warnings.extend(report.warnings)

    params: list[Param] = []
    for key, value in values.items():
        if _norm_value(mapping.get(key)) == value:
            continue  # 有则不变：文件已是目标值
        note = profile.reason
        if report.has("R8") and report.has("R8").level == WARN:
            note = f"{note}；本机不需要伪装（R8）"
        params.append(
            Param(
                key=key,
                value=value,
                module="cpuid",
                reason=note,
                evidence=profile.evidence or _EV_MASK_SEMANTICS,
                risk=profile.risk,
                risk_note=_risk_note(profile, key, report),
                needs_confirmation=True,
            )
        )

    return ProfileResult(
        params=tuple(params),
        warnings=tuple(warnings),
        errors=tuple(report.errors) + tuple(extra_errors),
    )


def _risk_note(profile: CpuIdProfile, key: str, report: RuleReport) -> str:
    """Per-key reminder that survives into ``plan.to_dict()`` / ``--json``."""
    fired = report.fired
    if key == "cpuid.1.ebx" and "R1" in fired:
        return "R1：APIC ID 与 [23:16] 拓扑会被硬编码到每个 vCPU（T3 待实测）"
    if key == "cpuid.1.edx" and "R2" in fired:
        return "R2：清掉 SS(27) 可能触发 darwin 的 cpuid.ss:Min:1 要求 → 开机失败（T2 待实测）"
    if key == "cpuid.0.eax" and "R4" in fired:
        return "R4：封顶基本 leaf 会隐藏 0xD/0x16/0x1F（T4 待实测）"
    if profile.risk == RISK_HIGH:
        return "高风险：掩码只在冷启动后生效，改错会导致客户机无法开机；先备份 .vmx"
    return "需人工确认：该键是否可写尚未实测（T5）"

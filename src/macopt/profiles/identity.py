"""Identity / SMBIOS block with the reflect↔explicit mutual exclusion rule.

DESIGN §4.11. Each identity field may be configured **either** by reflection
(``<key>.reflectHost = TRUE`` and no explicit value) **or** explicitly
(``<key>.reflectHost = FALSE`` plus a value) — never both. Doing both is
self-contradictory, and ``check`` reports it as S6 FAIL / ``apply`` refuses.

Why macopt defaults to the explicit path on this host: the reflection chain is
measurably broken (DMI reports ``Default string``/``<oem-default>``, the guest
log prints ``Host: can't find host SMBIOS entry point`` and
``PVNVRAMSetMacOSROM/MLB: Unable to retrieve host value``), so ``reflectHost``
yields nothing useful.

**macopt never invents an identity.** No board-id, no serial, no ROM/MLB ships
in this repository: the values come from ``ProfileOptions.extras`` (CLI flags
``--board-id`` / ``--hw-model`` / ``--serial``), and a missing required value
is an *error*, not a guess.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..model import Evidence, HostInfo, Param, ProfileOptions, ProfileResult

__all__ = [
    "IDENTITY_FIELDS",
    "REFLECT_SUFFIX",
    "IdentityField",
    "build",
    "mutual_exclusion_violations",
    "reflect_host_key",
]

#: Suffix VMware appends to make a field reflect the host.
REFLECT_SUFFIX = ".reflectHost"

_REFLECT_ON = frozenset({"TRUE", "1", "YES", "ON"})


# --------------------------------------------------------------------------- #
# Fields
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IdentityField:
    """One identity value plus how the caller may supply it."""

    #: the ``.vmx`` key (``board-id``, ``hw.model``, ``serialNumber``, …)
    key: str
    #: human label used in messages
    label: str
    #: accepted ``ProfileOptions.extras`` spellings, first match wins
    extras_keys: tuple[str, ...]
    #: must be present when ``--identity`` is on (macopt supplies no default)
    required: bool = True
    #: ``needs_confirmation`` rationale for this particular field
    risk_note: str = ""
    evidence: tuple[Evidence, ...] = ()
    #: why this field exists (what symptom it fixes)
    reason: str = ""

    @property
    def reflect_host_key(self) -> str:
        return f"{self.key}{REFLECT_SUFFIX}"


def reflect_host_key(key: str) -> str:
    """``board-id`` → ``board-id.reflectHost`` (generic, DESIGN §4.11)."""
    return f"{key}{REFLECT_SUFFIX}"


_EV_REFLECTION_BROKEN = (
    Evidence(
        "log",
        "docs/evidence/00-review.md §3.2",
        "本机日志 `Host: can't find host SMBIOS entry point`；DMI board_vendor/board_name=<oem-default>"
        "（DESIGN 事实基线：反射链路不可用，身份必须走显式值）",
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md §4.11",
        "每字段二选一：A 反射（reflectHost=TRUE 且不写显式值）/ B 显式（reflectHost=FALSE + 显式值）；"
        "同时出现 → check S6 FAIL、apply BLOCK",
    ),
)

_EV_SMC = (
    Evidence(
        "binary",
        "docs/evidence/01-factcheck.md §3.1",
        "smc.version / smc.present / AppleSMC 均在 vmware-vmx 中（字面量实证）",
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md §4.11",
        "smc.version 自 cpuid 模块移入本模块并标 needs_confirmation（本机 .vmx 无此键也能开机）",
    ),
)

_EV_NVRAM = (
    Evidence(
        "log",
        "docs/evidence/03-cpu-tuning-module.md:122",
        "PVNVRAMSetMacOSROM/MLB: Unable to retrieve host value.（每次开机成对出现）",
    ),
    Evidence(
        "binary",
        "docs/evidence/03-cpu-tuning-module.md:122",
        "二进制含 efi.nvram.var.ROM / .MLB 及其 .reflectHost 变体",
    ),
)

#: The identity fields macopt knows about (DESIGN §4.11). ``required`` marks
#: the three the user *must* supply; macopt ships no values of its own.
IDENTITY_FIELDS: tuple[IdentityField, ...] = (
    IdentityField(
        key="board-id",
        label="board id",
        extras_keys=("board-id", "boardId"),
        required=True,
        risk_note="板型 ID 决定 macOS 的机型白名单与 IOKit 注册；改动前先做快照并记录旧值",
        evidence=_EV_REFLECTION_BROKEN,
        reason="显式板型：本机 host 反射链路已断（SMBIOS entry point 找不到），反射取不到值",
    ),
    IdentityField(
        key="hw.model",
        label="hardware model",
        extras_keys=("hw-model", "hw.model"),
        required=True,
        risk_note="hw.model 是机型标识，影响 macOS 的机型匹配与电源管理表；改前快照",
        evidence=_EV_REFLECTION_BROKEN,
        reason="显式机型：与 board-id 成对写入，避免只改其一造成身份不一致",
    ),
    IdentityField(
        key="serialNumber",
        label="serial number",
        extras_keys=("serial", "serialNumber"),
        required=True,
        risk_note="序列号会影响 IOKit/nvram 注册与 iServices；macopt 不内置任何序列号，值必须由你提供",
        evidence=_EV_REFLECTION_BROKEN,
        reason="显式序列号：反射链路断时该字段为空，需要用户提供自己的值",
    ),
    IdentityField(
        key="smc.version",
        label="SMC version",
        extras_keys=("smc.version", "smcVersion"),
        required=False,
        risk_note="本机 .vmx 无此键也能开机 → 是否需要写入未实测（needs_confirmation）",
        evidence=_EV_SMC,
        reason="SMC 版本串（AppleSMC）；Unlocker 提供 SMC 设备，本键只在显式要求时写",
    ),
    IdentityField(
        key="efi.nvram.var.ROM",
        label="EFI NVRAM ROM",
        extras_keys=("efi.nvram.var.ROM", "ROM", "rom"),
        required=False,
        risk_note="ROM/MLB 变更影响 iServices，改前必须做快照（docs/evidence/03 风险表 中）",
        evidence=_EV_NVRAM,
        reason="对症 `PVNVRAMSetMacOSROM: Unable to retrieve host value.`",
    ),
    IdentityField(
        key="efi.nvram.var.MLB",
        label="EFI NVRAM MLB",
        extras_keys=("efi.nvram.var.MLB", "MLB", "mlb"),
        required=False,
        risk_note="MLB（主板序列）变更影响 iServices，改前必须做快照",
        evidence=_EV_NVRAM,
        reason="对症 `PVNVRAMSetMacOSMLB: Unable to retrieve host value.`",
    ),
)

_BY_KEY: dict[str, IdentityField] = {f.key: f for f in IDENTITY_FIELDS}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _norm(raw: object) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1].strip()
    return text or None


def _truthy(raw: object) -> bool:
    value = _norm(raw)
    return value is not None and value.upper() in _REFLECT_ON


# --------------------------------------------------------------------------- #
# Mutual exclusion (feeds check S6)
# --------------------------------------------------------------------------- #


def mutual_exclusion_violations(mapping: Mapping[str, str]) -> list[str]:
    """Every ``<key>.reflectHost=TRUE`` that coexists with an explicit value.

    Generic by design: the scan walks *all* ``*.reflectHost`` keys in the
    mapping, not just today's :data:`IDENTITY_FIELDS`, so a field macopt has
    not catalogued yet is still caught. Returns one human-readable string per
    violation (empty list = consistent block) — ``check.S6`` renders them
    verbatim.
    """
    violations: list[str] = []
    for raw_key in mapping:
        key = str(raw_key)
        if not key.endswith(REFLECT_SUFFIX):
            continue
        base = key[: -len(REFLECT_SUFFIX)]
        if not base:
            continue
        if not _truthy(mapping.get(key)):
            continue
        if _norm(mapping.get(base)) is None:
            continue
        meta = _BY_KEY.get(base)
        label = meta.label if meta else base
        violations.append(
            f"{base}: {key}={_norm(mapping.get(key))} 与显式值 "
            f"{base}={_norm(mapping.get(base))} 同时存在（{label}：方案 A 反射 / 方案 B 显式 互斥，"
            "DESIGN §4.11 → check S6 FAIL、apply BLOCK）"
        )
    return sorted(violations)


# --------------------------------------------------------------------------- #
# build()
# --------------------------------------------------------------------------- #


def _value_for(field_: IdentityField, opts: ProfileOptions) -> str | None:
    for name in field_.extras_keys:
        value = _norm(opts.extras.get(name))
        if value is not None:
            return value
    return None


def build(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> ProfileResult:
    """Emit the explicit identity block (DESIGN §4.11, opt-in).

    * ``opts.identity`` off → nothing (the registry only calls us when the
      module was requested, but a caller passing ``identity=False`` is honoured
      too);
    * a field configured *both* ways in the file → error (S6);
    * a required field with no user value → error: macopt will not fill in a
      board-id or a serial number itself;
    * each emitted field writes ``<key>.reflectHost = FALSE`` alongside the
      value so the block stays internally consistent.
    """
    if not opts.identity:
        return ProfileResult()

    violations = mutual_exclusion_violations(mapping)
    errors: list[str] = list(violations)

    params: list[Param] = []
    warnings: list[str] = []

    reflecting = sorted(
        str(key)
        for key in mapping
        if str(key).endswith(REFLECT_SUFFIX) and _truthy(mapping.get(key))
    )
    if reflecting:
        warnings.append(
            "检测到 reflectHost=TRUE 的字段："
            + ", ".join(reflecting)
            + " —— 本机 host 反射链路已断（SMBIOS entry point 找不到 / DMI 为 Default string），"
            "反射只会取到空值；macopt 按 DESIGN §4.11 走显式路径（方案 B）"
        )

    for field_ in IDENTITY_FIELDS:
        value = _value_for(field_, opts)
        current = _norm(mapping.get(field_.key))
        reflect_current = _norm(mapping.get(field_.reflect_host_key))
        wants_reflect = _truthy(mapping.get(field_.reflect_host_key))

        if value is None:
            if field_.required:
                errors.append(
                    f"identity 缺少 {field_.key} 的显式值：--extra {field_.extras_keys[0]}=…"
                    f"（macopt 不内置任何 {field_.label}；DESIGN §4.11 要求显式值由用户提供）"
                )
            continue

        # 身份自相矛盾：文件里既有反射又有显式值 → 已记入 errors（S6），不再产出
        # 自相矛盾的计划；只有「反射但还没有值」才允许按方案 B 正常转换。
        if wants_reflect and current is not None:
            continue

        already = current == value and reflect_current is not None and reflect_current.upper() == "FALSE"
        if already:
            continue  # 有则不变：文件已是「显式值 + reflectHost=FALSE」

        if current != value:
            params.append(
                Param(
                    key=field_.key,
                    value=value,
                    module="identity",
                    reason=field_.reason,
                    evidence=field_.evidence or _EV_REFLECTION_BROKEN,
                    risk_note=field_.risk_note,
                    needs_confirmation=True,
                )
            )

        if reflect_current is None:
            params.append(
                Param(
                    key=field_.reflect_host_key,
                    value="FALSE",
                    module="identity",
                    reason=(
                        f"关闭 {field_.key} 的宿主反射，与显式值配对"
                        "（方案 B：FALSE + 显式值，DESIGN §4.11）"
                    ),
                    evidence=field_.evidence or _EV_REFLECTION_BROKEN,
                    risk_note=field_.risk_note,
                    needs_confirmation=True,
                )
            )
        elif reflect_current.upper() != "FALSE":
            params.append(
                Param(
                    key=field_.reflect_host_key,
                    value="FALSE",
                    module="identity",
                    reason=f"{field_.reflect_host_key}={reflect_current} → FALSE（与显式值互斥）",
                    evidence=field_.evidence or _EV_REFLECTION_BROKEN,
                    risk_note=field_.risk_note,
                    needs_confirmation=True,
                )
            )

    return ProfileResult(
        params=tuple(params),
        warnings=tuple(warnings),
        errors=tuple(dict.fromkeys(errors)),  # 去重，保序
    )

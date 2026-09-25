"""``guestOS`` id mapping and guard (DESIGN §4.8 note, §12.2).

macopt only ever *writes* a ``guestOS`` value it can explain: the four darwin
tiers that the reference evidence maps to a concrete macOS release and to the
``guestId`` VMware stores for them. Everything else is reported, never
invented — a mistyped id is silently accepted by VMware, which is exactly the
failure mode :mod:`macopt.keys` exists to prevent.

Two jobs:

``GUEST_TABLE`` / :func:`resolve_guestos`
    the darwin tier table (DESIGN §12.2, sourced from the ``guestId`` table
    inside ``vmware-vmx``) and the pure decision function behind it.

:func:`build`
    the profile entry point with the frozen signature
    ``build(mapping, host, opts) -> ProfileResult``; it emits a ``guestOS``
    ``Param`` **only** when the caller asked for a tier (``opts.guestos``),
    that tier is a known one, and it differs from what the file already has.

Read-only note: this module reads the incoming mapping and nothing else — no
filesystem, no subprocess, no host probing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .model import Evidence, HostInfo, Param, ProfileOptions, ProfileResult

__all__ = [
    "GUEST_TABLE",
    "KNOWN_TIERS",
    "GuestOsDecision",
    "build",
    "guest_id",
    "macos_name",
    "resolve_guestos",
]

# --------------------------------------------------------------------------- #
# Tier table (DESIGN §12.2)
# --------------------------------------------------------------------------- #

#: ``guestOS`` id -> (macOS release, guestId). Source: the ``guestId`` table
#: inside ``vmware-vmx`` (Workstation 26.0.1), reproduced in DESIGN §12.2.
GUEST_TABLE: dict[str, tuple[str, int]] = {
    "darwin22-64": ("macOS 13", 0x5072),
    "darwin23-64": ("macOS 14", 0x5073),
    "darwin24-64": ("macOS 15", 0x5074),
    "darwin25-64": ("macOS 26", 0x5075),
}

#: Tiers in table order (``tuple`` so tests and docs can print them stably).
KNOWN_TIERS: tuple[str, ...] = tuple(GUEST_TABLE)

_KNOWN_LIST = ", ".join(f"{k} ({v[0]}, guestId 0x{v[1]:04X})" for k, v in GUEST_TABLE.items())

_EV_TIER = (
    Evidence(
        "doc",
        "docs/DESIGN.md §12.2",
        "darwin22-64→0x5072(macOS 13) … darwin25-64→0x5075(macOS 26)，来源 vmware-vmx 内 guestId 表",
    ),
    Evidence(
        "binary",
        "docs/evidence/02-cpuid-review.md §1.1(4)",
        "vmware-vmx 内含 5 条 Darwin 内置掩码与 cpuid.inhibitDarwinMasks：档位决定内置掩码，改档位 = 改掩码基线",
    ),
)



# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def _norm(value: str | None) -> str | None:
    """Strip whitespace and one layer of ``.vmx`` quoting; ``""`` -> ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1].strip()
    return text or None


def macos_name(tier: str | None) -> str | None:
    """macOS release behind a known tier (``None`` when unknown)."""
    entry = GUEST_TABLE.get(_norm(tier) or "")
    return entry[0] if entry else None


def guest_id(tier: str | None) -> int | None:
    """``guestId`` behind a known tier (``None`` when unknown)."""
    entry = GUEST_TABLE.get(_norm(tier) or "")
    return entry[1] if entry else None


# --------------------------------------------------------------------------- #
# Decision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GuestOsDecision:
    """What :func:`resolve_guestos` concluded (value to write + side notes)."""

    #: value macopt may write, or ``None`` when nothing should change
    value: str | None = None
    #: normalised value currently in the ``.vmx`` (``None`` when absent)
    current: str | None = None
    macos: str | None = None
    guest_id: int | None = None
    known: bool = False
    reason: str = ""
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    #: stable key for tests / ``--json`` consumers
    decision: str = "noop"

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "value": self.value,
            "current": self.current,
            "macos": self.macos,
            "guest_id": self.guest_id,
            "known": self.known,
            "reason": self.reason,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def resolve_guestos(requested: str | None, current: str | None = None) -> GuestOsDecision:
    """Decide what ``guestOS`` should become.

    Rules (DESIGN §12.2):

    * no target requested → **no change**; a ``darwin*`` current value that is
      not in the table only produces a warning (we report, we do not guess),
    * target == current → **no change** (idempotent), even if the tier is not
      one macopt knows,
    * unknown target → **error**: macopt refuses to write a ``guestOS`` it
      cannot map to a macOS release and a ``guestId``,
    * known target, different from current → **write** it, warning when the
      current value is outside the table (the transition is then one macopt
      cannot fully describe).
    """
    target = _norm(requested)
    now = _norm(current)
    warnings: list[str] = []
    errors: list[str] = []

    if now is not None and now not in GUEST_TABLE and now.startswith("darwin"):
        warnings.append(
            f"当前 guestOS={now} 不在 macopt 已知档位表（{_KNOWN_LIST}）："
            "无法校验其 guestId 与内置掩码，请人工确认"
        )

    if target is None:
        return GuestOsDecision(
            value=None,
            current=now,
            known=now in GUEST_TABLE if now else False,
            reason="未指定目标档位，保持 guestOS 不变",
            warnings=tuple(warnings),
            decision="keep",
        )

    if target == now:
        return GuestOsDecision(
            value=None,
            current=now,
            macos=macos_name(target),
            guest_id=guest_id(target),
            known=target in GUEST_TABLE,
            reason=f"guestOS 已是 {target}，无需改动",
            warnings=tuple(warnings),
            decision="unchanged",
        )

    if target not in GUEST_TABLE:
        errors.append(
            f"guestOS={target} 不是 macopt 已知的 darwin 档位，拒绝写入"
            f"（已知档位：{_KNOWN_LIST}；macopt 不写无法验证的档位）"
        )
        return GuestOsDecision(
            value=None,
            current=now,
            reason="未知档位",
            warnings=tuple(warnings),
            errors=tuple(errors),
            decision="rejected",
        )

    macos, gid = GUEST_TABLE[target]
    if now is not None and now not in GUEST_TABLE:
        warnings.append(
            f"当前 guestOS={now} 不在已知档位表：{now} → {target} 的掩码/Tools 影响无法由 macopt 全程描述"
        )
    reason = f"set guestOS = {target} ({macos}, guestId 0x{gid:04X})"
    if now is not None:
        reason += f" —— {now} → {target}"

    return GuestOsDecision(
        value=target,
        current=now,
        macos=macos,
        guest_id=gid,
        known=True,
        reason=reason,
        warnings=tuple(warnings),
        decision="change",
    )


# --------------------------------------------------------------------------- #
# Profile entry point
# --------------------------------------------------------------------------- #


def build(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> ProfileResult:
    """Emit the ``guestOS`` ``Param`` for ``opts.guestos`` (DESIGN §4.0).

    Emits nothing when the caller did not ask for a tier, when the tier is
    unknown (that is an error instead) or when the file already holds it.
    ``host`` is unused on purpose: the guest id is a *guest* property, and
    deriving it from the host would be exactly the kind of guess this project
    forbids.
    """
    current = _norm(mapping.get("guestOS"))
    decision = resolve_guestos(opts.guestos, current=current)

    params: list[Param] = []
    if decision.value is not None and decision.value != current:
        params.append(
            Param(
                key="guestOS",
                value=decision.value,
                module="guestos",
                reason=decision.reason,
                evidence=_EV_TIER,
                risk_note=(
                    "guestOS 决定 VMware 为 Darwin 选择的内置 CPUID 掩码与 Tools 版本；"
                    "改动后需冷启动一次并用 verify V9 复核 `Powering on guestOS '…'`"
                ),
            )
        )

    return ProfileResult(
        params=tuple(params),
        warnings=decision.warnings,
        errors=decision.errors,
    )

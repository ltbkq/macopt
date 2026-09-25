"""timing profile — ``tools.syncTime`` and ``hpet0.present`` (DESIGN §4.9).

Two hard rules, both traceable to the measured clock situation on the
reference host (docs/evidence/03-cpu-tuning-module.md §4):

* guest CPUID leaves ``0x15``/``0x16`` come back all zero, so the guest cannot
  read the TSC/base frequency from CPUID and has to self-calibrate off
  HPET/APIC — ``hpet0.present`` must stay ``TRUE`` (DESIGN line 411);
* VMware Tools was broken on the reference host (``lastInstallError=21004``,
  heartbeat timeouts), therefore flipping ``tools.syncTime`` to ``TRUE`` has no
  effect until Tools works — the module only emits it on explicit opt-in
  (``opts.sync_time``) and warns when Tools still looks broken (DESIGN line 410).

``ulm.disableMitigations`` is **never** produced by this module (DESIGN
line 412): the host already runs with side-channel mitigations effectively
disabled, and turning them off is a security decision that must not ride along
with a default profile.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..model import Evidence, HostInfo, Param, ProfileOptions, ProfileResult

_EV_SYNC_TIME = (
    Evidence(
        "log",
        "docs/evidence/03-cpu-tuning-module.md:99",
        'tools.syncTime="FALSE" 现状；同日志 Tools heartbeat timeout、installError 21004 → 置 TRUE 也不生效',
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md:410",
        "默认保持 FALSE；--sync-time 才置 TRUE，且必须先修好 VMware Tools",
    ),
)

_EV_HPET = (
    Evidence(
        "log",
        "docs/evidence/03-cpu-tuning-module.md:92",
        '.vmx 第 19 行 hpet0.present = "TRUE"；guest leaf 0x15/0x16 全 0 ⇒ 只能靠 HPET/APIC 自标定',
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md:411",
        "HPET 是客户机在 CPUID 频率叶子缺失时反推时钟的参考源，禁止关闭",
    ),
)

# Keys this module is forbidden to ever emit (DESIGN line 412 / 00-review.md:92).
FORBIDDEN_KEYS = ("ulm.disableMitigations",)


def _norm(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def _is_true(value: str | None) -> bool:
    return (_norm(value) or "").lower() == "true"


def build(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> ProfileResult:
    params: list[Param] = []
    warnings: list[str] = []

    # -- tools.syncTime ---------------------------------------------------- #
    # Default (opts.sync_time=False): emit nothing at all — "默认不改".
    # Even with the opt-in, writing TRUE while VMware Tools is broken is a
    # silent no-op, so say so instead of pretending time is being synced.
    if opts.sync_time:
        if _norm(mapping.get("toolsInstallManager.lastInstallError")) not in (None, "", "0"):
            warnings.append(
                "timing: tools.syncTime=TRUE was requested but the .vmx records "
                f"toolsInstallManager.lastInstallError="
                f"{_norm(mapping.get('toolsInstallManager.lastInstallError'))} — fix VMware Tools "
                "first, and keep NTP enabled in the guest as the fallback"
            )
        if not _is_true(mapping.get("tools.syncTime")):
            params.append(
                Param(
                    key="tools.syncTime",
                    value="TRUE",
                    module="timing",
                    reason=(
                        "--sync-time requested: let VMware Tools push host time into the guest"
                    ),
                    evidence=_EV_SYNC_TIME,
                    risk_note=(
                        "ineffective while VMware Tools is unavailable (heartbeat timeout / "
                        "installError 21004 on the reference host) — repair Tools, then verify "
                        "with `macopt verify` and keep guest NTP as a second source"
                    ),
                )
            )

    # -- hpet0.present ----------------------------------------------------- #
    # "当前为 FALSE 或缺失时才补成 TRUE"；已是 TRUE 则保持，不产出任何 Param。
    if not _is_true(mapping.get("hpet0.present")):
        current = _norm(mapping.get("hpet0.present"))
        params.append(
            Param(
                key="hpet0.present",
                value="TRUE",
                module="timing",
                reason=(
                    "guest CPUID leaves 0x15/0x16 are all zero, so the guest calibrates its "
                    "clock from HPET — restoring hpet0.present=TRUE"
                    if current is not None
                    else "guest CPUID leaves 0x15/0x16 are all zero — the guest needs HPET to "
                    "calibrate its clock, add hpet0.present=TRUE"
                ),
                evidence=_EV_HPET,
                risk_note="disabling HPET here would measurably increase guest clock drift",
            )
        )

    # ``ulm.disableMitigations`` is intentionally absent: see module docstring.
    assert not any(p.key in FORBIDDEN_KEYS for p in params)
    return ProfileResult(params=tuple(params), warnings=tuple(warnings))

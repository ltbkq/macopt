"""topology profile — vCPU count, coresPerSocket, vNUMA convergence, VHV/vPMC.

This module only ever *proposes* ``.vmx`` writes (DESIGN §4.7 parameter table,
lines 339-345). Host-side CPU binding is deliberately **not** expressed as a
Param: it belongs to :mod:`macopt.profiles.schedule`, which never touches the
``.vmx``.

Hard rules implemented here:

* ``cpuid.coresPerSocket`` must divide ``numvcpus`` exactly (check S3 — a
  non-integral split fails to power on);
* ``numa.autosize.vcpu.maxPerVirtualNode`` must be >= ``numvcpus`` or VMware
  slices the guest into several vNUMA nodes (observed 8+4 on a single-node
  host, evidence 00-review.md:86);
* changing ``numvcpus`` **requires** deleting ``numa.autosize.cookie``
  (``Param(remove=True)``), otherwise ``numa: Invalid NUMA cookie.``
  (risk R17, DESIGN line 669);
* ``hypervisor.cpuid.v0`` is opt-in only (``opts.hide_hypervisor_bit``) and
  carries a risk note about the Tools heartbeat.

Every Param carries Evidence (DESIGN §4.0 hard rule 1); kinds are restricted
to ``log``/``binary``/``sysfs``/``doc``/``measured``/``community``.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..model import Evidence, HostInfo, Param, ProfileOptions, ProfileResult

# --------------------------------------------------------------------------- #
# Evidence (repo paths + line numbers; see docs/DESIGN.md 修订记录 for provenance)
# --------------------------------------------------------------------------- #

_EV_NUMVCPUS = (
    Evidence(
        "log",
        "docs/evidence/00-review.md:84",
        '现状 numvcpus="12"；宿主 16 逻辑线程 / 10 物理核，12 = 6 个 P 物理核 × 2 线程',
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md:331",
        "三档策略 performance = min(6×2, 逻辑核)（默认 12），上限为宿主逻辑核数",
    ),
)

_EV_CORES_PER_SOCKET = (
    Evidence(
        "log",
        "docs/evidence/03-cpu-tuning-module.md:78",
        "日志 numa: coresPerSocket = 12 maxVcpusPerVPD = 8；guest 0x1F/0x0B sub1 EBX=0x0c",
    ),
    Evidence(
        "binary",
        "docs/evidence/03-cpu-tuning-module.md:78",
        "vmware-vmx strings: cpuid.coresPerSocket / cpuid.coresPerSocket.cookie / .auto / .mixedSize",
    ),
)

_EV_MAX_PER_NODE = (
    Evidence(
        "log",
        "docs/evidence/00-review.md:86",
        "maxPerVirtualNode=8 + 12 vCPU ⇒ 被切成 8+4 两个 vNUMA，而宿主单节点",
    ),
    Evidence("doc", "docs/DESIGN.md:341", "取值须 ≥ numvcpus，否则出现 8+4 切分"),
)

_EV_COOKIE = (
    Evidence(
        "log",
        "docs/evidence/03-cpu-tuning-module.md:79",
        'DICT numa.autosize.cookie = "120122"；不删则可能报 numa: Invalid NUMA cookie.',
    ),
    Evidence(
        "binary",
        "docs/evidence/03-cpu-tuning-module.md:79",
        "strings: numa.autosize.cookie / numa: Invalid NUMA cookie. / cpuid.coresPerSocket.cookie",
    ),
    Evidence("doc", "docs/DESIGN.md:669", "风险 R17：改动 numvcpus 未删 NUMA cookie → 启动报错"),
)

_EV_VHV = (
    Evidence(
        "log",
        "docs/evidence/00-review.md:87",
        'vhv.enable="TRUE" 时开机分配 OvhdUser_vhvCachedVMCS/NestedAPIC/VHV 页；guest leaf1 已无 VMX 位',
    ),
    Evidence("doc", "docs/DESIGN.md:343", "macOS 客户机不支持嵌套虚拟化，置 FALSE 省掉 VMX 状态开销"),
)

_EV_VPMC = (
    Evidence(
        "binary",
        "docs/evidence/03-cpu-tuning-module.md:90",
        "vmware-vmx strings: msg.vpmc.* — Virtualized performance counters are incompatible with %s guests",
    ),
    Evidence(
        "doc",
        "docs/evidence/03-cpu-tuning-module.md:90",
        "VMware KB 81623（vPMC 限制）与 KB 344161（vPMC 行为与兼容性检查）",
    ),
)

_EV_HYPERVISOR_BIT = (
    Evidence(
        "log",
        "docs/evidence/00-review.md:88",
        "guest leaf1 ECX=0xf7fa322b → bit31=1（host 0x7ffafbff bit31=0）：客户机确实看得到 hypervisor 位",
    ),
    Evidence(
        "community",
        "docs/evidence/03-cpu-tuning-module.md:89",
        "隐藏 hypervisor.cpuid.v0~v3 可能破坏 Tools 气球驱动 / VMCI 心跳 / 时间同步，须回归",
    ),
)

# DESIGN line 331: performance = min(6x2, logical CPUs), i.e. the reference
# host's 6 P cores x 2 threads = 12 vCPU, capped by whatever the host has.
_PERFORMANCE_VCPUS = 12


def _norm(value: str | None) -> str | None:
    """Strip optional surrounding quotes (mappings may be raw .vmx text)."""
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def _as_int(value: str | None) -> int | None:
    text = _norm(value)
    if text is None or not text.isdigit():
        return None
    return int(text)


def _sockets(opts: ProfileOptions) -> int:
    """Socket count used for coresPerSocket.

    ``HostInfo`` does not carry a socket count (frozen contract layer), so the
    default is 1 socket exactly as DESIGN line 340 prescribes; tests/CLI may
    override through ``opts.extras["sockets"]``.
    """
    raw = _norm(opts.extras.get("sockets"))
    if raw and raw.isdigit() and int(raw) > 0:
        return int(raw)
    return 1


def _target_numvcpus(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> tuple[int | None, str]:
    """Resolve the vCPU count for the chosen profile.

    Returns ``(value, origin)``; ``value`` is ``None`` when it cannot be
    determined — in that case the module degrades instead of guessing.
    """
    if opts.numvcpus is not None:
        if opts.numvcpus < 1:
            raise ValueError(f"--numvcpus must be >= 1, got {opts.numvcpus}")
        return opts.numvcpus, "--numvcpus"

    profile = opts.profile
    if profile == "performance":
        # DESIGN line 331: min(6x2, logical cores). When the host reports no
        # logical CPU count we refuse to invent one (no guessing).
        if host.logical_cpus > 0:
            return min(_PERFORMANCE_VCPUS, host.logical_cpus), "profile=performance"
        return None, "profile=performance"
    if profile == "throughput":
        if host.logical_cpus > 0:
            return host.logical_cpus, "profile=throughput"
        return None, "profile=throughput"
    # balanced (default): keep whatever the .vmx already declares.
    current = _as_int(mapping.get("numvcpus"))
    if current is not None and current > 0:
        return current, "current .vmx"
    return None, "current .vmx"


def build(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> ProfileResult:
    if opts.profile == "passthrough":
        # Explicit "touch nothing" tier: no topology writes at all.
        return ProfileResult(
            warnings=(f"{opts.profile}: topology module emitted nothing (opt-out profile)",)
        )

    params: list[Param] = []
    warnings: list[str] = []
    target, origin = _target_numvcpus(mapping, host, opts)

    if target is None:
        warnings.append(
            "topology: cannot determine a vCPU count ("
            f"{origin}) — leaving numvcpus/coresPerSocket/vNUMA untouched rather than guessing"
        )
    else:
        sockets = _sockets(opts)
        if target % sockets != 0:
            warnings.append(
                f"topology: numvcpus={target} is not divisible by sockets={sockets}; "
                "falling back to 1 socket so cpuid.coresPerSocket stays integral (check S3)"
            )
            sockets = 1
        cores_per_socket = target // sockets

        params.append(
            Param(
                key="numvcpus",
                value=str(target),
                module="topology",
                reason=(
                    f"vCPU count from {origin}; .vmx is only read at power-on, so the VM must be "
                    "powered off (not suspended) and the Workstation GUI closed before applying"
                ),
                evidence=_EV_NUMVCPUS,
                risk_note=(
                    f"core-level over-subscription: {target} vCPU vs "
                    f"{host.physical_cores or '?'} physical cores — an intentional decision, pair it "
                    "with `macopt schedule plan` so threads do not drift onto efficiency cores"
                    if host.physical_cores
                    else f"{target} vCPU vs unknown physical core count"
                ),
            )
        )
        params.append(
            Param(
                key="cpuid.coresPerSocket",
                value=str(cores_per_socket),
                module="topology",
                reason=(
                    f"= numvcpus ({target}) / sockets ({sockets}); must divide numvcpus exactly "
                    "(static check S3) and change together with it"
                ),
                evidence=_EV_CORES_PER_SOCKET,
                risk_note="inconsistent numvcpus/coresPerSocket prevents the guest from powering on",
            )
        )

        # vNUMA convergence: one virtual node, sized >= numvcpus, so a single-node
        # host never sees the observed 8+4 split. Multi-node hosts keep their
        # autosize behaviour (vNUMA then mirrors real topology).
        if host.numa_nodes <= 1:
            params.append(
                Param(
                    key="numa.autosize.vcpu.maxPerVirtualNode",
                    value=str(target),
                    module="topology",
                    reason=(
                        f"≥ numvcpus ({target}) so the guest collapses into a single vNUMA node; "
                        "the host reports 1 NUMA node, so a split only adds placement constraints"
                    ),
                    evidence=_EV_MAX_PER_NODE,
                )
            )
        else:
            warnings.append(
                f"topology: host has {host.numa_nodes} NUMA nodes — leaving "
                "numa.autosize.vcpu.maxPerVirtualNode alone so vNUMA can mirror the host"
            )

        # Cookie: delete (remove=True, value must be ""), never rewrite.
        params.append(
            Param(
                key="numa.autosize.cookie",
                value="",
                module="topology",
                reason=(
                    "vNUMA fingerprint of the old vCPU count; delete the whole line whenever "
                    "numvcpus changes or VMware reports 'numa: Invalid NUMA cookie.'"
                ),
                evidence=_EV_COOKIE,
                risk="normal",
                remove=True,
            )
        )

    params.append(
        Param(
            key="vhv.enable",
            value="FALSE",
            module="topology",
            reason="macOS guests cannot use nested virtualisation; stop paying for VMX state/pages",
            evidence=_EV_VHV,
        )
    )
    params.append(
        Param(
            key="vpmc.enable",
            value="FALSE",
            module="topology",
            reason="virtualised performance counters are unsupported with macOS guests",
            evidence=_EV_VPMC,
            risk_note="only loses in-guest hardware PMU access (rarely used in macOS VMs)",
        )
    )

    if opts.hide_hypervisor_bit:
        params.append(
            Param(
                key="hypervisor.cpuid.v0",
                value="FALSE",
                module="topology",
                reason=(
                    "opt-in (--hide-hypervisor-bit): clear CPUID.1:ECX bit31 which the hypervisor "
                    "currently sets for the guest (host bit is 0)"
                ),
                evidence=_EV_HYPERVISOR_BIT,
                risk_note=(
                    "hiding the hypervisor bit may break VMware Tools heartbeat / balloon / "
                    "time sync — re-verify Tools after applying (evidence: community, needs testing)"
                ),
                needs_confirmation=True,
            )
        )

    if host.p_cpus == () and host.e_cpus == () and host.hybrid is False:
        warnings.append(
            "topology: host P/E classes unknown or homogeneous — no CPU binding is recommended; "
            "macopt never guesses CPU ids (pass an explicit --cpus to `macopt schedule plan`)"
        )

    return ProfileResult(params=tuple(params), warnings=tuple(warnings))

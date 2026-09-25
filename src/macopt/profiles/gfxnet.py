"""gfxnet profile — 3D acceleration, texture size and per-NIC ``virtualDev``.

DESIGN §4.9 (lines 404-414) after the fact-check corrections:

* ``mks.enable3d`` — the only 3D switch that actually takes effect lives in the
  ``.vmx`` (01-factcheck.md:55, 58); the global preference layers carry no
  ``mks.*``/``ulm.*`` entries at all.
* ``svga.maxTextureSize`` — a real key found in ``bin/vmware-vmx``
  (01-factcheck.md:34); target 16384 matches the reference host's
  ``vmotion.svga.maxTextureSize=16384``.
* ``ethernet<N>.virtualDev`` — the key is *device-indexed*: the binary only
  contains the format string ``ethernet%d.virtualDev`` (01-factcheck.md:39),
  so N is discovered from ``ethernet<N>.present`` entries and a ``vmxnet3``
  value is only added for NICs that have no ``virtualDev`` yet
  (``needs_confirmation`` — changing the virtual NIC can break guest
  networking if the guest has no driver for the new device).

**Never emitted** (upstream design error, DESIGN line 414 / 00-review.md:38):
``mks.g3d.maxTextureSize`` and ``mks.enableGLRenderer`` — both are absent from
every VMware binary on the reference host, so writing them would be silently
ignored, exactly the F3 failure mode this project exists to prevent.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from ..model import Evidence, HostInfo, Param, ProfileOptions, ProfileResult

_EV_ENABLE_3D = (
    Evidence(
        "log",
        "docs/evidence/01-factcheck.md:55",
        '.vmx 第 105 行 mks.enable3d = "TRUE" —— .vmx 中唯一实际生效的 3D 开关',
    ),
    Evidence("doc", "docs/DESIGN.md:406", "mks.enable3d = TRUE（已是），全局层无任何 mks.* 生效项"),
)

_EV_MAX_TEXTURE = (
    Evidence(
        "binary",
        "docs/evidence/01-factcheck.md:34",
        "bin/vmware-vmx 含 svga.maxTextureSize / svga.maxTextureSize16K；mks.g3d.maxTextureSize 全树 0 命中",
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md:407",
        "svga.maxTextureSize = 16384；本机已有 vmotion.svga.maxTextureSize = 16384",
    ),
)

_EV_VIRTUAL_DEV = (
    Evidence(
        "binary",
        "docs/evidence/01-factcheck.md:39",
        "机制串 ethernet%d.virtualDev 存在于 vmware-vmx{,-debug,-stats}/vmcli/vmrun/libvmwarebase.so/vmnet.tar",
    ),
    Evidence(
        "doc",
        "docs/DESIGN.md:409",
        "ethernet<N>.virtualDev = vmxnet3，N 由设备探测得到（F5 修正）",
    ),
)

# Keys this module is forbidden to ever emit (DESIGN line 414): they do not
# exist in any VMware binary — writing them would be silently ineffective.
FORBIDDEN_KEYS = ("mks.g3d.maxTextureSize", "mks.enableGLRenderer")

_NIC_PRESENT_RE = re.compile(r"^ethernet([0-9]+)\.present$")


def _norm(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def _present_nics(mapping: Mapping[str, str]) -> list[int]:
    """Device indexes of NICs that are actually present (``present = "TRUE"``)."""
    found: list[int] = []
    for key in mapping:
        match = _NIC_PRESENT_RE.match(str(key))
        if match and (_norm(mapping.get(key)) or "").lower() == "true":
            found.append(int(match.group(1)))
    return sorted(found)


def build(
    mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions
) -> ProfileResult:
    params: list[Param] = []
    warnings: list[str] = []

    # -- mks.enable3d: 缺则补 TRUE，已存在则不动（有则不变） ---------------- #
    if _norm(mapping.get("mks.enable3d")) is None:
        params.append(
            Param(
                key="mks.enable3d",
                value="TRUE",
                module="gfxnet",
                reason="enable 3D acceleration; the .vmx switch is the only one that takes effect",
                evidence=_EV_ENABLE_3D,
            )
        )

    # -- svga.maxTextureSize: 缺则 16384 ---------------------------------- #
    if _norm(mapping.get("svga.maxTextureSize")) is None:
        params.append(
            Param(
                key="svga.maxTextureSize",
                value="16384",
                module="gfxnet",
                reason="raise the guest texture size limit to 16384 (real key, see evidence)",
                evidence=_EV_MAX_TEXTURE,
                risk_note="higher texture limits need enough virtual GPU memory; lower it back if the guest misbehaves",
            )
        )

    # -- ethernet<N>.virtualDev: 只为“已存在且未设置”的网卡补 vmxnet3 ------ #
    for index in _present_nics(mapping):
        key = f"ethernet{index}.virtualDev"
        if _norm(mapping.get(key)) is not None:
            continue  # 有则不变：尊重文件里已有的 virtualDev 选择
        params.append(
            Param(
                key=key,
                value="vmxnet3",
                module="gfxnet",
                reason=(
                    f"NIC ethernet{index} is present but has no virtualDev set; vmxnet3 is the "
                    "paravirtualised adapter with the best guest performance"
                ),
                evidence=_EV_VIRTUAL_DEV,
                risk_note=(
                    "changing the virtual NIC type can leave the guest without networking until "
                    "the right driver is loaded — confirm the guest has vmxnet3 support first"
                ),
                needs_confirmation=True,
            )
        )

    # Structural guarantee: the keys above are the only ones ever constructed,
    # so the forbidden pair can never appear in the output (see tests).
    assert not any(p.key in FORBIDDEN_KEYS for p in params)
    return ProfileResult(params=tuple(params), warnings=tuple(warnings))

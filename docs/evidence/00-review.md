# macopt 功能设计文档 v2.0 — 可行性评审与修改清单（总评）

- 评审日期：2026-09-25
- 评审环境：Linux Mint / user `<user>`，Intel i7-13620H（6P+4E，16 线程），VMware Workstation **26.0.1 build 25688693（26H1u1）**，Unlocker **4.2.7 + 4.2.8**（`backup/` 含 17.6.0~17.6.4 / 25.0.0 / **26.0.1**），目标虚拟机 `/mnt/<media>/DATA/vmware/<vm-name>/`（实际 guest：macOS 26 / Darwin 25）
- 佐证报告：
  - [01-factcheck.md](01-factcheck.md) 事实与路径核查
  - [02-cpuid-review.md](02-cpuid-review.md) CPUID 伪装机制专项
  - [03-cpu-tuning-module.md](03-cpu-tuning-module.md) 缺失的「CPU 拓扑与调度」补章设计
  - [04-verify-acceptance.md](04-verify-acceptance.md) 验收 / verify / 工程化

---

## 1. 总体结论：分层判定

| 层 | 判定 | 说明 |
|---|---|---|
| **定位与分工** | ✅ **可行，保留** | 「Unlocker 解锁 / macopt 只写 .vmx 与全局偏好、不碰二进制」的边界正确，与 Unlocker 的职责表（1.2）可直接沿用。第 2 节三个场景成立。 |
| **§3.1 模块结构 / §4 CLI** | ⚠️ **需补齐后开工** | 模块树与命令表有缺口（`guest-tools` 无模块、缺 `verify`），`install` 命名误导，缺 `--dry-run`/幂等/批处理。 |
| **§3.2 Unlocker 检测** | 🔴 **方案不可行，需换算法** | 「检查二进制特定字符串偏移量」已被本机实测证伪（见 §2.8）。 |
| **§3.3 CPU 检测** | ✅ 可行 | 补一条：AVX2 之外还应检测 `constant_tsc/nonstop_tsc`（老 AMD）、`/sys/devices/cpu_core`（Intel 混合）。 |
| **§3.4 CPUID 伪装（核心）** | 🔴 **不能按 v2.0 实现** | 缺语义、缺完整值、`cpuid.1.ebx` 有开机失败风险、位号口径可能写反、与「VMware 已内置 Darwin 掩码」的事实冲突。需重写。 |
| **§3.5 性能注入** | 🔴 **2 个 key 不存在、1 条事实错误** | 见 §2.3。 |
| **§3.6 全局偏好模块** | 🔴 **整节不成立** | 偏好路径与目标 key 两者都错（见 §2.1、§2.3）。 |
| **§3.7 客户机脚本 / §3.8 备份** | ⚠️ 可行，需加时间戳 manifest、`--list/--diff` | |
| **CPU 类型优化（原始诉求）** | 🔴 **文档缺失** | v2.0 只有 CPUID 伪装与图形/网络调优，**没有**拓扑 / 大小核调度 / 时钟校准 / guestOS 档位——这恰恰是 Intel 宿主（占多数）最需要的部分，见 §4。 |
| **验收标准（第 7 节）** | 🔴 **只剩 1 条且本机不可执行** | 唯一硬性验收是 AMD Ryzen 5800X，本机无 AMD 硬件；必须补 Intel 非回归等 8 类可自动化的验收（见 §5）。 |

**一句话结论**：方向对、边界对，但 **v2.0 直接开工会改错文件、注入不存在的 key、AMD 掩码有开机失败风险、且完全没覆盖"CPU 类型优化"**。建议升级为 **v2.1** 后开工；开工顺序按 §7 分批。

---

## 2. P0 — 必须修改的事实性错误

| # | 位置 | 文档现状 | 实测证据 | 修改为 |
|---|---|---|---|---|
| 2.1 | §3.6 / §3.8 / §4 | 全局偏好 = `~/.config/vmware/preferences.ini`，备份为 `preferences.ini.macopt.bak` | 日志 `DICT --- USER PREFERENCES /home/<user>/.vmware/preferences`；`~/.config/vmware` **不存在**；`grep -ra -F ".config/vmware" /usr/lib/vmware` **0 命中**；`grep -ra -F "preferences.ini"` **0 命中**；strings 命中字面量 `~/.vmware/preferences` | **`~/.vmware/preferences`**（无 `.ini`、不在 `~/.config`）；并列出完整配置层级：`/usr/lib/vmware/settings` → `/usr/lib/vmware/config` → `/etc/vmware/config` → `~/.vmware/config` → `~/.vmware/preferences` → `<vm>.vmx`（低→高）。另有 `~/.vmware/preferences-private`（凭据类） |
| 2.2 | §3.2 | darwin.iso = `/usr/lib/vmware/iso/darwin.iso` | `/usr/lib/vmware/iso` **不存在**；`/usr/lib/vmware/isoimages/darwin.iso` 存在；日志 `ToolsISO: Selected Tools ISO 'darwin.iso' for 'darwin24-64' guest`；格式串 `%s/isoimages/%s` | **`/usr/lib/vmware/isoimages/darwin.iso`**；并区分"VMware 内建 Tools ISO 搜索路径"与 ".vmx 中 `sata0:1.fileName` 手动指定的镜像路径"（本机就是后者） |
| 2.3 | §3.5 / §3.6 | 注入 `mks.g3d.maxTextureSize`、`mks.enableGLRenderer`（写进 preferences.ini） | 两个 key 在**整个 `/usr/lib/vmware` 全树 0 命中**（vmware-vmx、libvmwarebase、mksSandbox、安装器、/usr/bin 全查过） | 删除；纹理上限改用真实 key `svga.maxTextureSize` / `svga.maxTextureSize16K`（.vmx 中已有 `vmotion.svga.maxTextureSize=16384`）；渲染器改用 `mks.enableGLBasicRenderer` / `mks.use3dRenderer` / `mks.prefer3dRenderer` |
| 2.4 | §3.6 | "在 preferences 中启用 mks.enableGLRenderer、mks.gl.allowBlacklistedDrivers" | `mks.gl.allowBlacklistedDrivers` 确实存在，但 `~/.vmware/preferences`、`/etc/vmware/config`、`/usr/lib/vmware/config` 中 **mks.\*/ulm.\* 均为 0 条**；`.vmx` 里唯一生效的是 `mks.enable3d = "TRUE"` | 明确：**全局层当前没有任何 mks/ulm 生效项**；本模块应改为"写入 `~/.vmware/preferences`（若 key 白名单命中）或改写 `.vmx`"，二选一并说明优先级 |
| 2.5 | §3.5 | `ethernet0.virtualDev` 作为 key 描述 | 精确串 0 命中，机制串 `ethernet%d.virtualDev` 存在（设备序号化 key） | 写成 `ethernet<N>.virtualDev`，并保留"需先检测 ethernet 设备定义"的现有逻辑 |
| 2.6 | §1.1 / §5.1 | "Unlocker 官方明确声明不包含 AMD CPU 支持" | `unlocker427/README.md:46` = `add older (non-Ryzen) AMD CPU support`；`unlocker428/README.md:45` = `add AMD CPU support`（均在 `The Unlocker cannot:` 清单）；另有 wiki AMD-CPUs 页 | 按**版本 + 行号**引用，措辞改为"4.2.8 声明 cannot add AMD CPU support；4.2.7 声明 cannot add *older (non-Ryzen)* AMD CPU support"，并注明两者本质都是"不能给 macOS 添加其代码里本就没有的 CPU 能力" |
| 2.7 | §1.1 / §5.2 | "支持 VMware 16/17/25/26"、"VMware 26H1" | Unlocker README 官方只写 **tested against 16/17**；本机 `backup/` 实测打过 **17.6.0/17.6.1/17.6.3/17.6.4/25.0.0/26.0.1**（无 16.x）；`/usr/lib/vmware/vixwrapper-product-config.txt:27` = `# Workstation and Player 26.0.1 (26H1u1)` | 拆成"官方声明"与"实测记录"两栏；产品名统一为 **`VMware Workstation Pro 26.0.1 (build 25688693, 26H1u1)`**，不要把 "26H1" 当独立产品名 |
| 2.8 | §3.2 | Unlocker 检测 = "检查二进制中特定字符串偏移量" | `cmp -l` 实测 patch 仅改 **136 字节**，`strings` 差集仅 2 条新串；`libvmwarebase.so` 改 **42 字节但 strings 零差异**（字符串法**必然漏检**）；`Assuming most recent known Darwin masks…`、`msg.appleSMC.badHost`、`smc.version`、`appleSMC` 在**原件中同样存在**（若当标志位会把未打补丁误判成已打）；`backup/26.0.1/*.sha256` 为**双行格式**，第 1 行 = 备份原件哈希（4/4 相符）、第 2 行 = 当前已打补丁哈希（4/4 相符） | 换成 **hash + 存在性 + 分级**算法：版本门禁 → 备份自校验 → 当前哈希与第 1/2 行比对 → `PATCHED / UNPATCHED / UNKNOWN / UNKNOWN-MODIFIED / DAMAGED` 五态；无 backup 时按 M1(双 marker)~M5(`linux/check`) 降级，**只判存在性、绝不比偏移**，判不出一律 `UNKNOWN` |
| 2.9 | §5.2 | "Python 3.6+" 作为前置条件 | `python3 = 3.13.7`（`/usr/bin/python3 = 3.12.3`），满足；但 Unlocker 是 **Go 静态二进制**，README 明确 `no pre-requisites` | Python 要求仅针对 macopt 自身；删除任何"Unlocker 需要 Python"的暗示 |
| 2.10 | §3.6 | 未区分 Workstation 与 Player | `unlocker427/README.md:89-90`：*"…The Player version does not automatically pick up the ISO images and so the ISO must be maually attached to the VM via the guest's settings."* | 补 Player 说明：Tools ISO 自动识别**仅 Workstation Pro** |

---

## 3. P1 — 核心 CPUID 章节（§3.4）需要重写

### 3.1 必须补的机制说明（缺失即不可实现）

1. **掩码语义未定义**：VMware 的 `cpuid.<leaf>.<reg>` 是**逐位覆盖**——`0`/`1` 强制、`-` 保留默认、`h` 取宿主位（Broadcom 官方帖 + HN 中 VMware 方回帖）。正因为它不是 AND 掩码，才能把 `AuthenticAMD` 拼成 `GenuineIntel`。**文档必须写明**，否则读者按"掩码只能清位"理解会得出错误结论。
2. **值必须是完整 32 位**：表里的 `"...1011"`、`"...0001"` 占位符**无法实现**，每行都要给出完整 `xxxx:xxxx:xxxx:xxxx` 串并注明十六进制值。
3. **格式串证据**（二进制）：`cpuid.%x.%x.%s.amd` / `cpuid.%x.%s.amd` / `cpuid.%x.%x.%s` / `cpuid.%x.%s` —— 支持任意 leaf/subleaf/reg，且 **`.amd` 后缀变体优先查询**；文档当前完全没提 `.amd` 变体与 `monitor_control.enable_fullcpuid`（非默认 leaf 掩码的前置，社区补丁普遍带）。
4. **存在更安全的替代路径**：二进制里有 `cpuid.family` / `cpuid.model` / `cpuid.stepping` / `cpuid.brandString`（另有 270 个 `cpuid.<FEATURE>` 命名键）。签名/品牌串伪装比整段 `cpuid.1.eax` 位掩码更可读、更不易错，应作为**首选方案**，位掩码退为兜底。

### 3.2 必须修的技术缺陷

| 等级 | 问题 | 证据 | 改法 |
|---|---|---|---|
| 🔴 | **`cpuid.1.ebx` 会硬编码 APIC ID 与拓扑** | 社区值 `0x02010800` ⇒ `APIC ID=2`、`max addressable logical processors=1`；VMware **自算**的 guest EBX = `0x00100800`（APIC 0、`[23:16]=16`=12 向上取 2 的幂）。本机 `numvcpus=12`，若掩码对每个 vCPU 同值 → 12 个 vCPU 报同一个 APIC ID | **默认删除该行**；若必须保留，只覆盖 `[15:8]`（CLFLUSH），`[31:24]`/`[23:16]` 用 `-`；并把"逐 vCPU APIC ID 是否唯一"列为必测（T3） |
| 🔴 | **`cpuid.1.edx` 位号口径可能写反 + 副作用未披露** | 权威位号（内核头 `cpufeatures.h` + Wikipedia + unlocker `cpuid` 工具 + VMware 回帖 + 本机 `0xBFEBFBFF`↔`/proc/cpuinfo` 四重印证）：`DS=21、ACPI=22、MMX=23、FXSR=24、SSE=25、SSE2=26、SS=27、HTT=28、TM=29、PBE=31`。`0x078BFBFF` = 保留 MMX/FXSR/SSE/SSE2，**清掉 DS(21)/ACPI(22)/SS(27)/HTT(28)/TM(29)/PBE(31)** | ① 文档必须附位号表并注明出处；② 明确"该值**不清** MMX/SSE/SSE2"（旧记法 MMX=22 会得出相反结论）；③ 披露副作用：**本机日志有 `VM Features Required: cpuid.ss - Bool:Min:1`（darwin24-64）**，清 SS 可能触发 `Feature 'cpuid.ss' was absent, but must be present.`；清 HTT 使 `EBX[23:16]` 拓扑失效；④ 社区 A/B 方向互相矛盾（`0x0FABFBFF` 报错、`0x078BFBFF` 反而解决）→ 列为必测 T2 |
| 🔴 | **与"VMware 已内置 Darwin 掩码"的事实冲突** | 本机 `.vmx` **无任何 `cpuid.*`**，但日志显示：guest `leaf1 EAX=0x000406e3`（**Skylake-Y**）vs host `0x000b06a2`（Raptor Lake）；guest `EDX=0x1f8bfbff` 已清 DS/ACPI/PBE；guest `EBX=0x00100800` 已改写。二进制内含 5 条 `----:----:` Darwin 掩码、`cpuid.inhibitDarwinMasks`、`Assuming most recent known Darwin masks are suitable.` | 把模型改成 **「内置 Darwin 掩码 → 用户 `cpuid.*` 掩码」两层叠加**，明确 `cpuid.inhibitDarwinMasks` 存在且真值语义待测（T1）；删除任何"VMware 不动 CPUID"的表述 |
| 🟠 | **`cpuid.0.eax = 0x0B` 封顶基本 leaf** | guest 现为 `0x20`；写 0x0B 会隐藏 `0xD`(XSAVE)/`0x16`(频率)/`0x1F`(拓扑)；二进制有 `msg.cpuid.guestCpuidLoLevelsZero`、`msg.cpuid.guestRequiresAVX2noAVX`；且 `0x0B` 与 `cpuid.1.eax=0x00010671`(Penryn)、`ECX` 含 SSE4.2+AES **三者不自洽** | 标注 0x0B 为"社区拼装值"；优先用 `-` 保留 0x20，或改用签名/品牌串方案 |
| 🟠 | **i7-7700K 的 EAX 值混用** | 权威计算：`0x000906E9` = fam 6 / model **0x9E** / step 9 = `0000:0000:0000:1001:0000:0110:1110:1001`；`0x00010671` 是 **Penryn**（fam6/model 0x17/step1），**不是** 7700K | 二选一并写清目标型号；若 profile 叫 `kaby-7700k` 就用 `0x000906E9`，另设 `penryn` profile |
| 🟠 | **`smc.version` 被放进 CPUID 模块** | `smc.version` 与 CPUID 无关；本机 `.vmx` **无此键且可正常开机**（Unlocker 已改 SMC 实现） | 移出 §3.4，归到身份/SMC 段；标"可选加固，写入即为行为变更，需回归" |
| 🟠 | **SMBIOS 伪装自相矛盾（§3.4 表末）** | 同时写 `smbios.reflectHost="TRUE"` 与显式 `board-id`/`hw.model`；且本机日志报 `Host: can't find host SMBIOS entry point`、`PVNVRAMSetMacOSROM/MLB: Unable to retrieve host value`；本机 DMI 实测 `board_vendor=<oem-default>`、`board_name=<oem-default>` | 制定**互斥规则**：每字段只走「反射（`*.reflectHost=TRUE` 且不写显式值）」或「显式（`*.reflectHost=FALSE` + 显式值）」之一；本机反射链路已断 → 全部走显式路径，并补 `efi.nvram.var.ROM/MLB`（对症 ROM/MLB 报错）、`serialNumber`、`serialNumber.reflectHost` |
| 🟠 | **`featureCompat.enable` 适用范围** | 二进制 `%s featureCompat.enable is not allowed for HWversion %s 9.`；社区"仅 HWversion<9 有效"；本机 `virtualHW.version=22` | 若文档建议关闭它，必须写明硬件版本限制与半角引号要求，或直接删除该建议 |
| 🟡 | **"macOS 只在安装时校验 CPUID、装完可撤掩码"** | 无权威来源；反证：XNU 每次启动都重读 CPUID，社区失败样例全部**每次开机复现** | 删除或改为"分阶段实测"（T6） |
| 🟡 | **key 大小写** | 二进制是**大写** `cpuid.SS/DS/SSE42/PCID`，featureCompat 日志与社区补丁用**小写** `cpuid.ss/cpuid.ds` | 列为实测（T5），实现时两种都试并记录 |

---

## 4. P2 — 结构性缺失：必须新增「CPU 拓扑与调度调优」模块（对应原始诉求）

> 这是 v2.0 最大的内容缺口。Intel 宿主不需要 CPUID 伪装，但**恰恰最需要**下面这些；目前 §3.5 只有图形与网络。

详细设计见 [03-cpu-tuning-module.md](03-cpu-tuning-module.md)（24 行参数注入表 + 四级 P/E 探测 + 三档策略 + 15 项日志解析器），此处列必须项：

| # | 项 | 现状 → 建议 | 实测依据 |
|---|---|---|---|
| 4.1 | `guestOS` 档位 | `darwin24-64` → **`darwin25-64`** | guest 实为 macOS 26 / Darwin 25（`guestInfo.detailed.data: kernelVersion='25.6.0' buildNumber='25G229'`）；二进制 `msg.gostable8.guest.darwin25-64)macOS 26`、`(cons "darwin25-64" 0x5074)`、`guestOS=%s mapped to guestId=%x`。影响面：guestId、**Darwin 掩码选取**、Tools ISO 选择 → 改前改后必须做 `guest vs. host CPUID` 对比回归 |
| 4.2 | vCPU 拓扑 | `numvcpus=12`（> 宿主 10 物理核，核级超配 1.2×）；**12 恰好 = 6 个 P 核 × 2 线程** | 配合 4.3 绑定即可 1:1 落 P 核，**不必改 vCPU 数**；性能档 6 / 吞吐档 16（上限=逻辑线程数） |
| 4.3 | **P/E 分层绑定（核心）** | 默认绑 `0-11`（P 核），避开 `12-15`（E 核） | L1 探测：`/sys/devices/cpu_core/cpus=0-11`、`/sys/devices/cpu_atom/cpus=12-15`；E 核上限 3600 vs P 核 4900 MHz → **落 E 核单线程慢 40–45%**。实现选型：**首选系统级 `systemd-run --scope -p AllowedCPUs=0-11`（cpuset 硬约束，进程无法逃逸）**；⚠️ 实测 `systemd-run --user --scope` **静默失效**（cpuset 未委派给 user@.service，`Cpus_allowed_list` 仍 0-15）；校验**只能以 `/proc/<pid>/status` 为准**（`systemctl show -p EffectiveCPUs` 本机返回空）。降级方案：用户级 desktop 覆盖 `Exec=taskset -c 0-11 ...` |
| 4.4 | vNUMA 收敛 | `numa.autosize.vcpu.maxPerVirtualNode=8` + 12 vCPU → **被切成 2 个 vNUMA（8+4）**，而宿主单节点 | 日志 `numa: coresPerSocket = 12 maxVcpusPerVPD = 8`、`NUMA node 0` 单节点 → 设为 `12` 或删键；**改 vCPU 必须同时删 `numa.autosize.cookie`（现 `"120122"`）**，否则 `numa: Invalid NUMA cookie.` |
| 4.5 | `vhv.enable` | `TRUE` → **`FALSE`** | macOS 客户机不支持嵌套虚拟化，却分配了 `OvhdUser_vhvCachedVMCS/NestedAPIC/VHV` 页；guest leaf1 已无 VMX 位 |
| 4.6 | `hypervisor.cpuid.v0` | 当前**未设** → 可选 `"FALSE"` | ⚠️ 修正 03 号报告的错误：guest leaf1 ECX `0xf7fa322b` **bit31=1**（host `0x7ffafbff` bit31=0）→ **客户机确实看得到 hypervisor 位**（03 号报告 §2.2/§4.1 写成"两者都是 0"，错误）。`FALSE` 可隐藏，但可能影响 Tools 心跳/校时，需回归 |
| 4.7 | `vpmc.enable` | 显式 `"FALSE"` | 二进制 `msg.vpmc.*`（`Virtualized performance counters are incompatible with %s guests.` + KB 81623/344161） |
| 4.8 | **校时链路** | `tools.syncTime="FALSE"` + Tools **不可用** → **FAIL（无任何自动校时）** | `toolsInstallManager.lastInstallError="21004"`、`Tools heartbeat timeout`；且 **guest leaf `0x15`/`0x16` 全 0**（宿主 `0x15` ECX=38,400,000×(152/2)=**2,918,400,000 Hz** 与 `VMMon_GetkHzEstimate 2918400 kHz` 完全吻合）→ 客户机拿不到 TSC/频率，只能靠 HPET/APIC 自标定 → **必须先修 Tools 再开 syncTime，且客户机内始终开 NTP 兜底，`hpet0.present=TRUE` 禁止关闭** |
| 4.9 | 身份块 | `board-id.reflectHost="TRUE"` → **`FALSE` + 显式值** | 见 §3.2 SMBIOS 行；本机反射已断（`<oem-default>` DMI + SMBIOS entry point 报错） |
| 4.10 | `ulm.disableMitigations` | **不设**（本机已等效关闭） | 本次开机日志无侧信道缓解提示、`Enable Virtual MSR_SPEC_CTRL no`；若要加须注明"关缓解只适合可信单机"（KB 79832） |
| 4.11 | 保持项 | `monitor.phys_bits_used="45"` **保持**（guest `80000008=0x302d` vs host `0x3027`，属正常 GPA 位宽）；`hpet0.present="TRUE"` 保持 | 不必按"与宿主 39 位不符"去改 |

**注入时机硬约束**（需写进文档）：`.vmx` 仅在开机时读取 → 必须 **powerOff（非 suspend）+ 关闭 GUI** 后编辑（GUI 关闭设置窗会回写 `.vmx`，本机文件中已存在运行时回写键 `guestInfo.detailed.data`、`cleanShutdown` 等证据）→ 改完三重回读（文件 / 日志 `DICT` 段 / `Powering on guestOS '...'`）。

---

## 5. P3 — 验收标准与工程化

### 5.1 验收（替换原第 7 节）

| ID | 场景 | 可执行性 |
|---|---|---|
| **A** | AMD Ryzen 7 5800X 全流程（**保留原验收**） | ❌ 本机无 AMD 硬件，**必须另找机器**；否则核心价值长期纸面化（风险 R13） |
| **B** | **Intel 宿主非回归（新增，本机可全自动）** | ✅ apply 后不含**目标 `cpuid.*` 键集**（⚠️ 措辞必须是"目标键集"而非"任何 `cpuid.*`"——本机 `.vmx:39` 已有 `cpuid.coresPerSocket="12"`，原措辞必假失败）；verify 全绿；开机跑分差 <2% |
| **C** | 幂等性（apply 两次 `sha256` 相同、第二次 `changed=0`） | ✅ 全自动 |
| **D** | `--dry-run` 不落盘（sha256+mtime+行数三重断言，不建备份） | ✅ 全自动 |
| **E** | `restore` 精确回滚 + `--list/--diff` | ✅ 全自动 |
| **F** | 坏路径拒绝（非 darwin / 不存在 / 空文件 / 只读） | ✅ 全自动 |
| **G** | 未知 key 默认拒绝（白名单实测 315/315/302/247 并集） | ✅ 全自动 |
| **H** | VM 运行中拒绝 apply（`.lck` / pid 检测） | ✅ 全自动 |
| **I** | 无 backup 的新用户 → `UNKNOWN` 而非撒谎 | ✅ 全自动 |

自动化边界：V0–V10 与多数用例可用**样本日志回放**（本机 4 份历史日志当 fixture）；只有"进客户机看"的部分（`sysctl machdep.cpu.*`、逐核 APIC ID、AVX2 实际可用、30 min 时钟漂移、体感回归）必须人工开一次机；用 `macopt verify --in-guest`（只读脚本）可把其中几项降为半自动。

### 5.2 新增 `macopt verify <vmx>`（check 只能证明"写进去了"，verify 才能证明"真的生效"）

- 输入：虚拟机目录 → 按 mtime 取最新 `vmware*.log`；交叉校验 `displayName`；**新鲜度门禁**（log mtime < vmx mtime → FAIL"改完没重启"）；版本门禁。
- 断言 **V0–V10**（详见 04 号报告，含正则与实测样例）：V0 门禁 / V1 `vendor` / V2 Family-Model-Stepping（解码需与 VMware 自报行交叉校验，本机验算 guest `0x000406e3`→`6/0x4e/3`、host `0x000b06a2`→`6/0xba/2` 均一致）/ V3 hypervisor 位 / V4 AVX2（**OSXSAVE 是动态位，开机早期 dump 为 0，不作 FAIL**）/ V5 APIC 唯一性（**实测 4/4 份日志无 `CPUID[n] leaf1` → 自动降级**：代理 `vmm-vcpus/numvcpus/LocalApic = 12/12/12` + 客户机内 `sysctl`/逐核 cpuid）/ V6 leaf15/16=0 → WARN + 校时建议 / V7 `leaf40000000=VMwareVMware` / V8 **注入期望 vs 日志实测闭环比对** / V9 darwin 前置 / V10 拓扑对账。
- 原则：**缺行一律 SKIP，绝不当 FAIL**（`guest vs. host CPUID` 是 `-INFO`、每次开机只打一次）。
- 退出码 0/1/2/3/4 + `--json` + `--strict`。

### 5.3 工程化改进（原 3.8 / 第 4 节）

1. 备份 **时间戳 + manifest**（`schema/macopt 版本/argv/profile 快照/VMware 版本/文件 sha256+mode+mtime/changes before-after`），同 sha256 去重，`latest` 软链，`history.jsonl`。
2. `restore --list / --diff [id] / --to <id> / --verify / --prune N`。
3. `apply --dry-run`；**幂等三态**（不存在→added / 同值→unchanged / 异值→**默认报错**，需 `--force` 且强制先备份+打印 diff）；同 key 多行→WARN。
4. 写入事务性：临时文件 → fsync → rename；保留 mode/owner。
5. **注入前 key 白名单**（扫 `vmware-vmx{,-debug,-stats}` + `libvmwarebase.so` + `mksSandbox`，正则取并集并缓存）；不在集合 → 默认拒绝，`--allow-unknown-keys` 才放行并 WARN；同时校验 value 形态。
6. `install` → **`setup`**（`install` 保留 deprecated 别名）。
7. 模块树 ↔ CLI 缺口：补 `verify.py`、`guest_tools.py`（`guest-tools` 命令当前无模块）；CI 用 `--help` 与文档命令表比对，缺项即失败。
8. 批处理 `apply --all / --glob`，默认串行、`flock` + 每 VM 锁、单台失败不中断、`--json-report`。
9. 证据留存 `verify --save-report`（日志片段带行号 + sha256 + 命令输出）。
10. 明确边界并写入文档：**macopt 只读 VMware 二进制（哈希/字符串），只写 `.vmx` 与自身 state**；`restore` 只回滚 `.vmx`。

---

## 6. 必须实测才能定论（T1–T8）

> 通用前置：只改**副本**、每次只改一个变量、**必须冷启动**（CPUID 不热更新）；判定统一读 `grep "guest vs. host CPUID"` 的 `guest level` vs `*host level` diff。

| # | 待定问题 | 关键步骤 |
|---|---|---|
| T1 | 用户掩码与内置 Darwin 掩码谁覆盖谁；`cpuid.inhibitDarwinMasks` 真值语义 | 三档：不加 / 只改 1 位 / 加 `inhibitDarwinMasks=TRUE` → 看 guest EAX 是否从 `0x000406e3` 变回 `0x000b06a2` |
| T2 | `cpuid.1.edx=0x078BFBFF` 是否触发 `Feature 'cpuid.ss' was absent…` | A/B/C 三组（`0x0FABFBFF` / `0x078BFBFF` / `+cpuid.ss="1"`） |
| T3 | `cpuid.1.ebx` 是否对每个 vCPU 同值（APIC ID 全变 2？） | 加 `0x02010800` 冷启动，客户机内逐核读 leaf1.EBX + `sysctl -n hw.ncpu hw.physicalcpu` |
| T4 | `cpuid.0.eax=0x0B` 后 leaf 0xD/0x16/0x1F 是否消失 | 看 `guest level 00000000` 的 EAX 与后续 leaf |
| T5 | 命名键大小写；`cpuid.family/model/stepping/brandString` 是否为可写 `.vmx` 键 | 逐个写入并观察 `guest family/model/stepping`、`guest name` |
| T6 | macOS CPUID 校验时机（安装期 vs 每次启动） | A 装机全程带掩码 / B 装完撤掩码 / C 换一套掩码 |
| T7 | **AMD 宿主**真实效果（厂商串、`.amd` 后缀） | 本机 Intel **无法定论**；本机可先测 `.amd` 后缀是否被忽略 |
| T8 | `monitor_control.enable_fullcpuid` 对非默认 leaf 是否必需 | 加开关后注入 `cpuid.7.0.ebx` 比对 |

**最低口径**：T1/T2/T3/T6 未出结果前，不得写"该掩码方案可直接上线"；T7 未做则全文标注"AMD 结论未经本环境实测"。

---

## 7. 交叉校对中发现的报告缺陷（自查）

- **[03] §2.2 / §4.1**：写「guest leaf1 ECX `0xf7fa322b` bit31 已为 0，与 host 一致」——**错误**。`0xf7fa322b` 顶半字节 `f=1111` → **bit31=1**；host `0x7ffafbff` 顶半字节 `7` → bit31=0。正确结论：**VMware 给客户机置了 hypervisor 位**，这正是 `hypervisor.cpuid.v0` 该被纳入设计的原因。[02]、[04] 的判断正确，本文件以它们为准。
- **[02]**：因未在磁盘找到文档原文，按任务转述逐条评审；其中"文档写了某具体值"的断言需在拿到 v2.0 原文后二次比对再落笔。
- **[01]**：`ethernet0.virtualDev` 判为"字面量不存在"，补充说明：机制键 `ethernet%d.virtualDev` 存在、该 key 实际可用，只是不能说"字面量在二进制里"。

---

## 8. 建议的 v2.1 改版与开工顺序

| 批次 | 内容 | 依赖 | 本机可验证 |
|---|---|---|---|
| **B1（先修文档）** | §2 P0 十条事实修正 + 位号表 + 掩码语义 + SMBIOS 互斥规则 | 无 | ✅ |
| **B2（可直接实现）** | 白名单、备份 manifest、幂等/`--dry-run`/`restore`、`verify` 解析器、Unlocker 五态检测 | B1 | ✅ 全自动 |
| **B3（新增模块）** | CPU 拓扑与调度调优（03 号报告整章）+ 宿主绑定 | B1 | ✅ 大部分（含 cpuset 实测） |
| **B4（需外部硬件）** | AMD CPUID 伪装 profile + T1–T8 | B1、AMD 机器 | ❌ 需另行安排 |

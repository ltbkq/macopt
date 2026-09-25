# 模块 03：CPU 拓扑与调度调优（Intel / AMD 通用，不依赖 CPUID 伪装）

> 归属：macopt 补丁设计文档 v2.0 —— 补章
> 章节定位：只处理「宿主怎么摆 CPU、客户机看到什么拓扑与时钟、怎么验证」三件事；
> **不**承担 CPUID 身份伪装（family/model/brandString/AMD 补丁）——那属于身份模块。
> 落盘日期：2026-09-25，全部证据取自本机当前状态。

---

## 0. 证据等级与基线

**证据等级图例（本章每一条建议都必须至少带一个标签）**

| 标签 | 含义 |
|---|---|
| 【本机日志实证】 | 直接取自 `/mnt/<media>/DATA/vmware/<vm-name>/vmware.log` 或该机 `.vmx`/`.vmxf` 的可复现行 |
| 【二进制 strings 实证】 | 直接取自 `/usr/lib/vmware/bin/vmware-vmx`（Workstation 26.0.1 build 25688693）的 strings 输出 |
| 【官方文档】 | VMware KB / vSphere 性能最佳实践 / Intel SDM / systemd.resource-control / 内核 cpuset 文档 |
| 【社区经验，需实测】 | 社区（unlocker 指南、AMD OS X 论坛、Frank Denneman 等）通行做法，本机尚未验证 |
| 【本机实测】 | 本次在宿主上用 sysfs / lscpu / systemd-run 实跑得到（补充标签，与前四者并列） |

**宿主基线（【本机实测】）**

| 项 | 值 |
|---|---|
| CPU | Intel i7-13620H，6P+4E = 10 物理核 / 16 逻辑线程，1 个 NUMA 节点 |
| P 核线程 | CPU `0-11`（`/sys/devices/cpu_core/cpus` = `0-11`），`thread_siblings_list` 成对：`0-1,2-3,4-5,6-7,8-9,10-11` |
| E 核线程 | CPU `12-15`（`/sys/devices/cpu_atom/cpus` = `12-15`），无 SMT |
| 最高频率 | `cpu0-3,cpu8-11` = 4700 MHz；`cpu4-7` = 4900 MHz；`cpu12-15` = 3600 MHz |
| 调频驱动/档位 | `intel_pstate` + `powersave`（全 16 线程），`no_turbo=0`（睿频未关） |
| Hypervisor | VMware Workstation 26.0.1（`vmware --version`），vmx 二进制 setuid root |
| systemd / cgroup | systemd 255，unified hierarchy；根 `cgroup.subtree_control` = `cpu memory pids`（**无 cpuset**） |
| 启动入口 | `/usr/share/applications/vmware-workstation.desktop` → `Exec=/usr/bin/vmware %U`（Bash wrapper） |
| 指纹 | `guestInfo.detailed.data: kernelVersion='25.6.0' distroVersion='26.7' buildNumber='25G229'`（macOS 26 / Darwin 25） |

**关键时钟交叉验证（【本机日志实证】+ 数学验算）**

```
hostCPUID level 00000015, 0: 0x00000002 0x00000098 0x0249f000 0x00000000
                              EAX=2       EBX=152     ECX=38,400,000 Hz（晶振）
hostCPUID level 00000016, 0: 0x00000b54 0x00001324 0x00000064
                              EAX=2900 MHz EBX=4900 MHz ECX=100 MHz
VMMon_GetkHzEstimate: Calculated 2918400 kHz
TSC Hz estimates: vmmon 2918400000, cpuinfo 4641551000, cpufreq 4900000000 sysctlfreq 0. Using 2918400000 Hz
TSC scaling ratio: mult=2147483648, shift=31        → 2^31 / 2^31 = 1.000000
```

`38,400,000 × (152 / 2) = 2,918,400,000 Hz` **与 `VMMon_GetkHzEstimate = 2918400 kHz` 完全一致**，
即宿主不变 TSC = **2918.4 MHz**，且 TSC 缩放比 = 1.0 → 客户机 TSC 也应为 2918.4 MHz。
`cpuinfo 4641.551 MHz` 与 `cpufreq 4900 MHz` 是**核心实时频率/频率上限**，不是 TSC 时基——诊断器不得把它们当成时钟频率。

---

## 1. 模块目标与非目标

**目标**
1. 让 12 vCPU 尽可能全部落在 6 个 P 物理核（12 个硬件线程）上，不被调度到 4 个 3.6 GHz 的 E 核；
2. 让客户机看到**一致、可预测**的 CPU 拓扑（socket/core/thread/vNUMA）；
3. 在「客户机拿不到 CPUID 频率叶子」的既成事实下，把 TSC/校时风险量化、可观测、可兜底；
4. 对 Intel 混合 / Intel 非混合 / AMD 非 Ryzen / AMD Ryzen 四类宿主给出同一套开关矩阵。

**非目标**
- 不改 `cpuid.family / cpuid.model / cpuid.stepping / cpuid.brandString / cpuid.0.* / cpuid.inhibitDarwinMasks`（身份伪装，属另一模块）；
- 不处理 `monitor.phys_bits_used`（见 §3.1 表格末尾说明：45 位 PA 与本次调优无关，保持现状）。

---

## 2. 参数注入表（.vmx，必须在虚拟机断电状态下写入）

> 统一约定：`建议值` 一栏中「**删除该键**」表示整行从 `.vmx` 移除；`保持` 表示现状已是目标值，仅需回归确认。

### 2.1 拓扑与 vCPU

| 参数 | 建议值 | 作用 | 证据/来源 | 风险 |
|---|---|---|---|---|
| `guestOS` | `darwin24-64` → **`darwin25-64`** | 让 guestId、Darwin 掩码表、Tools ISO 选择与真实 guest（macOS 26 / Darwin 25）对齐 | 【本机日志实证】`guestInfo.detailed.data ... distroVersion='26.7' kernelVersion='25.6.0' buildNumber='25G229'`；【二进制 strings 实证】`@&!*@*@(msg.gostable8.guest.darwin25-64)macOS 26`、`(cons "darwin25-64" 0x5074)`、`guestOS=%s mapped to guestId=%x`；【二进制 strings 实证】影响面还包括 `Assuming most recent known Darwin masks are suitable.`（掩码表回退提示） | **中**：会改变 Darwin CPUID 掩码选取，可能让 guest leaf `0x1A/0x1C/0x20`（混合核类型）由「全 0」变为「有值」，XNU 对异构核的调度行为随之改变；必须做改前/改后日志对比回归 |
| `numvcpus` | `12`（默认档）/ `6`（性能档）/ `16`（吞吐档） | vCPU 数，决定能否 1:1 映射到 P 核硬件线程 | 【本机日志实证】现状 `numvcpus = "12"`，宿主 16 逻辑线程、10 物理核；【官方文档】vSphere 性能最佳实践（vCPU 与物理核配比） | **中**：12 > 10 物理核（核级超配 1.2×）；若不绑定会有一部分 vCPU 落到 3.6 GHz E 核 |
| `cpuid.coresPerSocket` | **必须整除 `numvcpus`**；默认档 `12`、性能档 `6`、吞吐档 `16` | 客户机 CPUID 拓扑（socket×core） | 【本机日志实证】`numa: coresPerSocket = 12 maxVcpusPerVPD = 8`；guest `0000001f/0000000b` sub1 EBX=0x0c=12、sub1 ECX 类型=Core、无 SMT；【二进制 strings 实证】键 `cpuid.coresPerSocket`、`cpuid.coresPerSocket.cookie`、`cpuid.coresPerSocket.auto`、`cpuid.coresPerSocket.mixedSize`；【社区经验，需实测】sockets × cores = numvcpus | **中**：与 `numvcpus` 不整除会开机失败；改动必须同时清 cookie（见 §4.5） |
| `numa.autosize.cookie` | **删除该键**（当前 `"120122"`） | 让 VMware 按新的 vCPU 数重算 vNUMA 指纹 | 【本机日志实证】`DICT numa.autosize.cookie = "120122"`；【二进制 strings 实证】`numa.autosize.cookie`、`numa: Invalid NUMA cookie.`、`The VM does not have NUMA size cookie.`；【社区经验，需实测】cookie 随 vCPU 数变化（Frank Denneman NUMA Deep Dive） | **低-中**：不删则新 `numvcpus` 与旧指纹冲突，可能报 `numa: Invalid NUMA cookie.`；GUI 关机回写可能把它加回来 |
| `numa.autosize.vcpu.maxPerVirtualNode` | `12`（= `numvcpus`），或**删除该键** | 把 vNUMA 收敛成 1 个虚拟节点 | 【本机日志实证】现状 `= "8"`、日志 `numa: coresPerSocket = 12 maxVcpusPerVPD = 8` → 12 vCPU 被切成 2 个 vNUMA（8+4）；而宿主只有 1 个节点（`NUMA node 0: 31815MB, cpus 0x0000ffff...`）；【官方文档】vSphere 性能最佳实践 `numa.vcpu.min` / vNUMA 控制；【社区经验，需实测】 | **低**：单节点宿主上 vNUMA 无收益，且会给 VMware 的 vCPU 放置增加分组约束，与 P 核绑定叠加时可能互相打架 |
| `numa.vcpu.min`（可选） | 缺省不设；如需显式关闭 vNUMA 可设为 `> numvcpus` 的值 | 控制「多少 vCPU 起启用 vNUMA」的阈值 | 【二进制 strings 实证】键 `numa.vcpu.min`、`numa.vcpu.coresPerNode`、`numa.autosize.once`；【官方文档】vSphere 性能最佳实践：`numa.vcpu.min = X` 可手动开启/调整 | **低**：与 `maxPerVirtualNode` 二选一即可，同时写可能互相覆盖 |
| `cpuid.numSMT`（实验项） | 不设（现状即无 SMT）；如要呈现「6 核 × 2 线程」拓扑则设 `2`（要求 `numvcpus` 为其倍数、与宿主 SMT=2 一致） | 向客户机呈现超线程拓扑，使其拓扑与 6 个 P 物理核一致 | 【二进制 strings 实证】`cpuid.numSMT`、`The virtual machine cannot be powered on because the number of virtual CPUs is not a multiple of cpuid.numSMT value.`、`The cpuid.numSMT value (%1$d) does not match the host (%2$d).`、`Virtual hyperthreading is not supported in the configured hardware version (%u)` | **中**：属拓扑改动而非身份伪装，但会影响 macOS 的核拓扑推断与并发模型，必须实测；vHW 22 理论满足，需验机 |

### 2.2 虚拟化 / 性能开关

| 参数 | 建议值 | 作用 | 证据/来源 | 风险 |
|---|---|---|---|---|
| `vhv.enable` | `TRUE` → **`FALSE`** | 关闭嵌套虚拟化；macOS 客户机不支持嵌套，省掉 VMX 状态与嵌套 APIC 开销 | 【本机日志实证】现状 `vhv.enable = "TRUE"`，开机分配 `OvhdUser_vhvCachedVMCS: 12`、`OvhdUser_vhvNestedAPIC: 12`、`OvhdMon_VHV: 36`（页）；【本机日志实证】guest leaf1 ECX=`0xf7fa322b`（bit5 VMX=0，客户机本来就看不到 VMX）；【二进制 strings 实证】键 `vhv.enable`；【官方文档】`vhv.enable` 语义 = 向客户机透传硬件虚拟化 | **低**：日志中有 `msg.cpuid.legacyCPU.noVHV` 类提示仅在「宿主本身是虚机」时出现；本机为裸金属，不受影响 |
| `hypervisor.cpuid.v0` | **不设置（保持缺省）**；若要固化则写 `"FALSE"` 并回归 Tools | 控制 CPUID.1:ECX 的 hypervisor 位 | 【本机日志实证】guest leaf1 ECX=`0xf7fa322b`，**bit31 已为 0**（host `0x7ffafbff` bit31 亦为 0）→ 现状已无 hypervisor 位；【本机日志实证】但 guest `40000000 = 0x40000010 "VMwareVMware"` 仍在（该参数不隐藏 leaf 40000000）；【二进制 strings 实证】键 `hypervisor.cpuid.v0` + `hypervisor.cpuid.v1~v5`；【社区经验，需实测】隐藏 `hypervisor.cpuid.v0~v3` 会破坏 Tools 气球驱动 / VMCI 心跳 / 时间同步 | **低-中**：对 macOS 无功能收益；但会与本模块的校时目标（Tools 同步）冲突 → 明确「不动」 |
| `vpmc.enable` | 显式 `"FALSE"`（或保持缺省 = 不设） | 固化「不启用虚拟性能计数器」，避免 PMC 模块开机失败与额外 VM-Exit | 【二进制 strings 实证】键 `vpmc.enable` 与整组 `msg.vpmc.*`：`Virtualized performance counters are not supported on the host CPU type.`、`Virtualized performance counters are incompatible with %s guests.`、`... refer to VMware KB article 81623`；【官方文档】KB 344161（vPMC 行为与兼容性检查）、KB 81623；【社区经验，需实测】Workstation 上 vPMC 常直接报不支持 | **极低**：仅失去客户机内硬件 PMU 访问（macOS 虚拟机内基本用不到） |
| `ulm.disableMitigations` | **不设置**；仅当日志出现侧信道缓解提示时加 `"TRUE"` | 侧信道缓解（Spectre 类）开关，关掉可降开销 | 【本机日志实证】本次开机日志**没有** `side channel mitigations enabled` 提示，且 `Enable Virtual MSR_SPEC_CTRL no` → 当前等效于已关闭；【二进制 strings 实证】键 `ulm.disableMitigations`、消息 `msg.loader.mitigations.wsAndFusion`（原文附 `KB article 79832`）；【官方文档】KB 79832 | **低**（性能收益）/ **安全面**：关闭缓解只适合可信单机 |
| `hpet0.present` | 保持 `"TRUE"` | HPET 是客户机在 CPUID 频率叶子缺失时反推时钟的参考源 | 【本机日志实证】`.vmx` 第 19 行 `hpet0.present = "TRUE"`；【社区经验，需实测】XNU 在 leaf `0x15/0x16` 为 0 时依赖 HPET/APIC 自标定 | **低**：关闭会显著加大时钟漂移风险，禁止关闭 |
| `monitor.phys_bits_used` | 保持 `"45"` | 声明客户机物理地址位宽 | 【本机日志实证】`Host PA size: 39 bits. Guest PA size: 45 bits.`、guest `80000008 = 0x302d`（PA=45、VA=48）vs host `0x3027`（PA=39、VA=48）；【二进制 strings 实证】键存在 | **无**：与 CPU 调度/频率无关，本模块不动 |

### 2.3 时间同步

| 参数 | 建议值 | 作用 | 证据/来源 | 风险 |
|---|---|---|---|---|
| `tools.syncTime` | 分两档：**Tools 修复后 → `"TRUE"`；Tools 仍坏 → 保持 `"FALSE"` 并强制客户机 NTP** | 是否由 VMware Tools 把宿主时间同步进 guest | 【本机日志实证】现状 `tools.syncTime = "FALSE"`；同日志 `Tools: Tools heartbeat timeout.`（11:28:14、11:34:41）与 `.vmxf` `<installError>21004</installError>`、`.vmx` `toolsInstallManager.lastInstallError = "21004"` → **Tools 当前不可用，写 TRUE 也不会生效**；【社区经验，需实测】macOS guest 指南常显式关掉 `tools.syncTime` 与 `time.synchronize.*` 并改用 NTP；【官方文档】`tools.syncTime` 为 VMware 官方配置项 | **中**：与 guest leaf `0x15/0x16` 全 0 叠加 → 若两头都不校时，漂移会累积（见 §5） |

### 2.4 身份块：`reflectHost` 与显式值的**互斥组合规则**

> **本条用于修复 v2.0 文档里 `board-id.reflectHost = "TRUE"` 与「写入显式 board-id」并存的自相矛盾。**

**规则（必须写进设计文档作为硬约束）**
1. 每个身份字段只有两条互斥路径：
   - **路径 A（反射）**：`<key>.reflectHost = "TRUE"`，且 `.vmx` 中**不得出现** `<key>` 显式值；
   - **路径 B（显式）**：`<key>.reflectHost = "FALSE"` **且**同时写 `<key> = "显式值"`。
2. 同名键在 `.vmx` 中**只允许出现一次**（大小写不同也视为不同键，见 §2.5）。
3. `reflectHost=TRUE` 与 `<key>=显式值` **同时存在 = 自相矛盾**：反射链路优先/顺序不确定，客户机看到的值不可复现。
4. 本机路径 A **已实测失败**，因此本机只能走路径 B：

| 参数 | 建议值 | 作用 | 证据/来源 | 风险 |
|---|---|---|---|---|
| `board-id.reflectHost` | `"TRUE"` → **`"FALSE"`** | 关闭宿主板型反射 | 【本机日志实证】现状 `board-id.reflectHost = "TRUE"`，但开机即报 `Host: can't find host SMBIOS entry point` → 反射链路断；【二进制 strings 实证】键 `board-id`、`board-id.reflectHost`、`smbios.suppressPlatformID` | **低**：反射本来就取不到值 |
| `board-id` | 显式写入（路径 B 必需），例如 `"Mac-AA95B1DDAB278B95"`（按目标机型选） | 提供确定的板型 ID | 【二进制 strings 实证】键 `board-id` 存在；【社区经验，需实测】unlocker 系指南统一用 `board-id.reflectHost=FALSE` + 显式值 | **中**：已安装系统改板型可能触发 IOKit/缓存重建，属「改前必须快照」项（§6） |
| `hw.model.reflectHost` | **`"FALSE"`** | 关闭宿主机型反射 | 【二进制 strings 实证】键 `hw.model`、`hw.model.reflectHost`；【社区经验，需实测】 | 低 |
| `hw.model` | 显式写入（如 `"iMac20,1"` / `"iMac19,1"`，按 macOS 26 支持列表选） | 固化机型 | 【社区经验，需实测】多份 macOS on VMware 指南一致 | 中（同上） |
| `serialNumber.reflectHost` | **`"FALSE"`** | 关闭宿主序列号反射 | 【二进制 strings 实证】键 `serialNumber`、`serialNumber.reflectHost` | 低 |
| `serialNumber` | 显式写入 12 位合法序列号 | 固化序列号 | 【二进制 strings 实证】`SMBIOS.use12CharSerialNumber`、`SMBIOS.restrictSerialCharset`；【社区经验，需实测】 | 中：非法序列号会影响 iServices/更新，需与 `smbios.restrictSerialCharset=TRUE` 匹配 |
| `smbios.reflectHost` | **`"FALSE"`** | 关闭整块 SMBIOS 反射，避免与显式值冲突 | 【二进制 strings 实证】`smbios.reflectHost`、`smbios.reflectHost.subtypes`；【社区经验，需实测】 | 低 |
| `efi.nvram.var.ROM.reflectHost` / `efi.nvram.var.MLB.reflectHost` | 均 **`"FALSE"`**，并分别配 `efi.nvram.var.ROM` / `efi.nvram.var.MLB` 显式值 | 直接对症 ROM/MLB 取值失败 | 【本机日志实证】`PVNVRAMSetMacOSROM: Unable to retrieve host value.`、`PVNVRAMSetMacOSMLB: Unable to retrieve host value.`（每次开机成对出现）；【二进制 strings 实证】`efi.nvram.var.ROM`、`efi.nvram.var.MLB` 及其 `.reflectHost` 变体 | 中：ROM/MLB 变更影响 iServices，需快照 |
| `smc.version` | 可选：显式 `"0"`（社区通行）；本机当前**无此键且可正常开机**，属可选加固 | 指定 SMC 版本/键集选择 | 【二进制 strings 实证】键 `smc.version`（邻近 `AppleSMC`、`HostSMCRead`、`AppleSMCCheckpointRequiresPhysicalSMC`）+ `smc.present = "TRUE"` 现状；【社区经验，需实测】多数 unlocker 指南写 `smc.version = "0"` | **中**：本机「不写也能开机」，写入即为行为变更，必须回归开机与 AppleSMC 读写 |
| `smbios.restrictSerialCharset` | 保持 `"TRUE"` | 限制序列号字符集 | 【本机日志实证】`.vmx` 现状为小写 `smbios.restrictSerialCharset`；【二进制 strings 实证】二进制内只有**大写** `SMBIOS.restrictSerialCharset` | 低（见 §2.5 大小写提示） |

**身份块的「正确组合」示例（可直接贴进 .vmx 尾部，路径 B）**
```
board-id.reflectHost = "FALSE"
board-id = "Mac-AA95B1DDAB278B95"
hw.model.reflectHost = "FALSE"
hw.model = "iMac20,1"
serialNumber.reflectHost = "FALSE"
serialNumber = <redacted>"
smbios.reflectHost = "FALSE"
efi.nvram.var.ROM.reflectHost = "FALSE"
efi.nvram.var.ROM = "<12位ROM>"
efi.nvram.var.MLB.reflectHost = "FALSE"
efi.nvram.var.MLB = "<17位MLB>"
smc.version = "0"          # 可选
```
> 反之若坚持路径 A：则上面所有 `*.reflectHost` 保持 `"TRUE"`，且**一条显式值都不能写**。
> 本机因 `can't find host SMBIOS entry point`，路径 A 已被实测否决 → 统一走路径 B。

### 2.5 附带发现（需一并写入回归清单）

- 【二进制 strings 实证】`.vmx` 用小写 `smbios.restrictSerialCharset`，而二进制内只检索到大写 `SMBIOS.restrictSerialCharset`；若该产品配置键大小写敏感，现状设置可能**未生效**。
  处置：改机前先在客户机内记录序列号形态（`ioreg -l | grep -i IOPlatformSerialNumber`），改大小写后再测一次，**以实测为准**。
  【社区经验，需实测】
- 【二进制 strings 实证】存在 `cpuid.inhibitDarwinMasks`（置 `TRUE` 会抑制 Darwin 掩码、把宿主真实 family/model 暴露给客户机）。
  **本模块明确不碰**——它属于身份伪装模块；此处仅登记存在性，避免后续章节重复引入。
- 【二进制 strings 实证】`Assuming most recent known Darwin masks are suitable.` 与掩码表（如 `-----:----:----:0100:----:----:1110:0011` = `EAX 0x000406E3`）相邻。
  本机 guest leaf1 EAX = `0x000406e3`（Skylake-Y 掩码）而 host = `0x000b06a2`（Raptor Lake）→ **掩码确实在生效**，
  改 `guestOS` 后必须比对该值是否变化。

---

## 3. 宿主调度策略子模块

### 3.1 自动识别 P 核 / E 核

按可靠性排序的四级探测（命中即返回，全部落进 `macopt-topo` 输出）：

**L1（首选，内核直接给出混合分组，【本机实测】）**
```bash
PCPUS=$(cat /sys/devices/cpu_core/cpus)     # 本机 → 0-11
ECPUS=$(cat /sys/devices/cpu_atom/cpus)     # 本机 → 12-15
```
存在 `/sys/devices/cpu_core`、`/sys/devices/cpu_atom` 即判定为 Intel 混合架构。

**L2（通用兜底：拓扑聚合 + 频率分层，【本机实测】）**
```bash
lscpu -e=CPU,CORE,SOCKET,NODE,MAXMHZ,ONLINE
# 本机输出：cpu0-11 CORE=0-5 MAXMHZ=4700/4900；cpu12-15 CORE=6-9 MAXMHZ=3600
for c in /sys/devices/system/cpu/cpu[0-9]*; do
  printf '%s core=%s sib=%s max=%s\n' "${c##*/cpu}" \
    "$(cat $c/topology/core_id)" \
    "$(cat $c/topology/thread_siblings_list)" \
    "$(cat $c/cpufreq/cpuinfo_max_freq)"
done
```
判据：把 `cpuinfo_max_freq` 按 5% 聚类，**显著更高的一簇 = P 核（高性能核），更低的一簇 = E 核**；
每簇内 `thread_siblings_list` 的**首个 CPU = 该物理核的主 HT 线程**（性能档只取主 HT）。
本机结果：P 主 HT = `0,2,4,6,8,10`（其中 `4,6` 的上限是 4900 MHz，其余 4700 MHz），P 全线程 = `0-11`，E = `12-15`。

**L3（AMD 专用，【社区经验，需实测】）**
- 无 `/sys/devices/cpu_core`；改用 `lscpu -e` 判定 `Threads per core`（1 或 2）；
- 用 `/sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list` 拿 CCD/CCX 分组（L3 共享域）→ 绑定时**优先落在同一 CCD**，避免跨 L3；
- 用 `amd_pstate` / `cpufreq/scaling_driver`（`amd-pstate` 或 `amd-pstate-epp`）判断是否为 Zen4+；
- 「首选核」：`cpuinfo_max_freq` 最高的一颗（部分 BIOS/驱动暴露 `cpufreq/preferred`）。

**L4（调频与宿主状态校验，【本机实测】）**
```bash
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver      # intel_pstate
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor    # powersave
cat /sys/devices/system/cpu/intel_pstate/{status,no_turbo}   # active / 0
```
> 全机 `powersave` + `no_turbo=0` 属正常配置，**不建议为虚拟机改宿主 governor**（会抬升整机功耗与发热，笔记本上更明显）。
> 若需要，改用**单进程**手段（`taskset`/cgroup + `perf` 采样）而不是改全局 governor。

### 3.2 「12 vCPU ↔ 6 物理 P 核 12 线程」的量化说明

| 观察 | 数值 | 证据等级 |
|---|---|---|
| 宿主线程供给 | P 核 6 × 2 = **12 个硬件线程**（`0-11`）+ E 核 4 × 1 = 4（`12-15`），合计 16 | 【本机实测】 |
| 现状 vCPU | `numvcpus=12`，客户机 CPUID 呈现 12 core / 无 SMT / 单 socket | 【本机日志实证】 |
| 核级超配 | 12 vCPU ÷ 10 物理核 = **1.2×**；线程级 12 ÷ 16 = 0.75× | 由上两行推算 |
| **匹配度** | **12 vCPU 与 P 核 12 个硬件线程恰好 1:1**；只要把 `vmware-vmx` 限制在 `0-11`，vCPU 数就不需要改也能完全避开 E 核 | 【本机实测】 |
| E 核频率代价 | 3600 / 4900 = **73.5%**（频率上限差 26.5%）；叠加 E 核 IPC 约为 P 核 0.7–0.8 → 单线程综合约 **55–60%**，即落到 E 核的 vCPU 单线程慢 **40–45%** | 频率：【本机实测】；IPC 系数：【社区经验，需实测】 |
| P 核内 SMT 代价 | 同一物理核的两个 vCPU 共享执行资源，单线程约降 10–20%，聚合吞吐 +15–25% | 【社区经验，需实测】 |
| 可用吞吐上限 | 仅 `0-11`：约 **7.0–7.5** 个单核当量；放开 `0-15`：约 **9.2–9.7**（+25%），代价是单线程方差大 | 【社区经验，需实测】 |

**为什么必须靠宿主绑定、不能指望客户机自己选核**：
【本机日志实证】guest leaf `0000001a`、`0000001c`、`00000020` 全 0（host 分别为 `0x40000001`、`0x4000000b`、`0x00000001`）
→ 客户机**拿不到混合核类型信息（HFI / native core type）**，只能按同构核调度；
同时日志虽输出了 `Hardware Feedback Index: 0(x2),1(x2),...,6(x4)` 与 `Physical X2APIC IDs: 0-1,8-9,...`（宿主视角），
但这些没有透传成客户机可见的 leaf → **客户机没有任何「优先用 P 核」的能力，只能由宿主侧强制**。

### 3.3 三种实现的对比与选型

| 方案 | 做法 | 优点 | 缺点 / 失效面 | 可靠性 |
|---|---|---|---|---|
| **A. desktop 文件 `Exec` 前置 `taskset`** | 复制 `/usr/share/applications/vmware-workstation.desktop` 到 `~/.local/share/applications/`（用户级覆盖，**无需 root**），改 `Exec=taskset -c 0-11 /usr/bin/vmware %U` | 零依赖、可逆、`vmware` 是 Bash wrapper 且 `vmware-vmx` 为其子进程 → 亲和性经 fork/exec 继承；用户级 desktop 覆盖不污染系统文件；GUI 与 vCPU 线程一起被约束（渲染线程也在 P 核上，界面反而更顺） | 只覆盖 desktop 启动路径；`vmrun`/CLI/`vmware` 直接调用/换用户启动则绕过；`taskset` 只是「设置进程自身的 affinity 掩码」，**可被进程自己再次 `sched_setaffinity` 覆盖**（vmware-vmx 二进制内确实导入了 `sched_setaffinity`，并有 `msg.hostPosix.affinityFailed`、`Cannot retrieve process affinity` 等字符串）；对已运行进程无效 | **中** |
| **B. `systemd-run --scope -p AllowedCPUs=`（cgroup v2 cpuset）** | `systemd-run --scope -p AllowedCPUs=0-11 /usr/bin/vmware %U`（**系统级**） | **内核硬约束**：cgroup cpuset 生效后，进程自身 `sched_setaffinity` 只能在 cpuset 内进一步收窄，**无法逃逸**——即使 vmware-vmx 内部重设亲和也被压回；可记录到 unit、可审计、失败可 fail-closed | **必须用系统级**：【本机实测】`systemd-run --user --scope -p AllowedCPUs=0-11` **静默失效**（scope 内 `Cpus_allowed_list` 仍是 `0-15`，rc=0），原因是 cpuset 未委派（根 `cgroup.subtree_control` = `cpu memory pids`，`user@1000.service/cgroup.controllers` 也仅 `cpu memory pids`）；本机非 root 跑系统级 scope 成功（polkit 放行），**其他环境可能要 sudo**；验证手段要选对：【本机实测】`systemctl show -p EffectiveCPUs` 在本机返回空，**只能以 `/proc/<pid>/status` 的 `Cpus_allowed_list` 为准** | **高（前提是做了强制校验）** |
| **C. 直接 `sched_setaffinity` 小工具** | ① 改 `/usr/bin/vmware` wrapper，在 `exec` 前调 `taskset`；② 或常驻 helper：`pgrep -f vmware-vmx` → `taskset -pc 0-11` 轮询；③ 或独立 C 小工具直接 `sched_setaffinity()` | 可**只**约束 `vmware-vmx`、让 GUI 不受限；可对**已在运行**的进程生效；不依赖 cgroup 委托；只要走 wrapper 就覆盖所有启动路径 | 非硬约束（可被目标进程覆盖）；轮询方案存在窗口期（`vmware-vmx` 已经跑了几百毫秒才被收紧）；wrapper 位于 root 所有路径需 sudo；`vmware-vmx` 是 setuid root 且 `ptrace_scope=1`，**无法 strace 验证内部是否重设亲和**；失败时静默回退到继承集 | **中低** |

**cgroup 硬约束的实测依据（【本机实测】）**
```
$ systemd-run --scope -p AllowedCPUs=0-11 sh -c 'grep Cpus_allowed_list /proc/self/status; taskset -p ffff $$; grep Cpus_allowed_list /proc/self/status'
Cpus_allowed_list: 0-11
pid ...'s current affinity mask: fff      # 0-11
pid ...'s new affinity mask: fff          # 请求 0-15(ffff)，被内核裁剪回 0-11
Cpus_allowed_list: 0-11
```
→ 请求越出 cpuset 的掩码被**静默交集裁剪**，`sched_setaffinity` 永远逃不出 cpuset。
（对应【官方文档】systemd.resource-control `AllowedCPUs=`：*"This setting controls the cpuset controller in the unified hierarchy"*；
以及内核 cpuset 文档：有效 affinity = 进程掩码 ∩ cpuset 掩码。）

**选型结论（写进设计文档）** —— 证据等级：1–4 全部基于【本机实测】（systemd-run 系统级/用户级对照、cpuset 越界裁剪实测）+【官方文档】（systemd.resource-control、内核 cpuset）
1. **首选 = B（系统级 systemd-run / 由它包裹启动器）**，理由即上述硬约束语义；
2. **A 作为无 systemd 时的降级**，或与 B 叠加（`Exec=taskset -c 0-11 systemd-run --scope -p AllowedCPUs=0-11 /usr/bin/vmware %U`）；
3. **C 只用于「只想限 vCPU、放行 GUI」的场景与临时诊断**；
4. **无论用哪个，都必须有开机后强制校验**（见 §7 验收）：
   ```bash
   pid=$(pgrep -x vmware-vmx | head -1)
   grep Cpus_allowed_list /proc/$pid/status    # 期望 0-11（均衡档）
   cat /proc/$pid/cgroup                       # B 方案应落在 system.slice/run-*.scope
   ```
   **校验失败即视为未生效**——尤其 B 方案在 cpuset 未委派时是「假成功」。

### 3.4 三档推荐（对本机 6P+4E）

| 档位 | `numvcpus` | `cpuid.coresPerSocket` | 绑定 CPU 集 | 特征 | 适用 | 证据等级 |
|---|---|---|---|---|---|---|
| **性能优先**（单线程/低延迟） | **6** | **6** | **`4,6`** 优先（4.9 GHz 核），补 `0,2,8,10`（4.7 GHz 核） | 每个 vCPU 独占一个物理 P 核，无 SMT 争用、无 E 核漂移，单线程最高 4.7–4.9 GHz；并发度减半 | 交互/Xcode 单线程阶段/对抖动敏感的工作负载 | 频率与核分配：【本机实测】；独占核的性能增益幅度：【社区经验，需实测】 |
| **均衡（默认推荐）** | **12** | **12** | **`0-11`**（P 核全部 12 线程） | 12 vCPU 与 P 核 12 硬件线程 **1:1**；单线程基本不落 E 核；给宿主桌面留 4 个 E 核 + 无核级过载 | 日常开发、中度并行构建 | 1:1 对应关系：【本机实测】+【本机日志实证】（`numvcpus=12`、guest 拓扑 12 core） |
| **吞吐优先**（多线程/批量编译） | **12 → 16**（上限=宿主逻辑线程数） | = `numvcpus` | **`0-15`**（放开 E 核） | 聚合吞吐 +25% 上限（7.0–7.5 → 9.2–9.7 单核当量）；约 30–50% 的 vCPU 时间可能落在 3.6 GHz E 核，单线程方差大 | 纯批量并行任务（`make -j`、并行测试） | E 核频率上限 3600 vs 4900：【本机实测】；吞吐系数与落核概率：【社区经验，需实测】 |

> 约束：`cpuid.coresPerSocket` 必须整除 `numvcpus`；`numvcpus` 不应超过宿主逻辑线程数（16）；
> 12 vCPU 已经超过宿主 10 个物理核，**任何档位都建议配合绑定**，否则「核级超配 + 异构漂移」会同时发生。

### 3.5 改 `numvcpus` 后必须删除的 cookie

改 vCPU 数/核数后，**同时删除以下两个键**让 VMware 重算（整行删掉，不是改成空值）：

```
numa.autosize.cookie            ← 现状 "120122"
cpuid.coresPerSocket.cookie     ← 当前 .vmx 中不存在；若 VMware 回写了也要删
```

- 【二进制 strings 实证】键名与报错串同时存在：`numa.autosize.cookie`、`numa: Invalid NUMA cookie.`、`The VM does not have NUMA size cookie.`、`cpuid.coresPerSocket.cookie`、`The VM lost its coresPerSocket cookie.`
- 【本机日志实证】现状 `.vmx` 只有 `numa.autosize.cookie = "120122"`，日志 `DICT numa.autosize.cookie = "120122"`、`numa: coresPerSocket = 12 maxVcpusPerVPD = 8`
- 【社区经验，需实测】cookie 是 vNUMA 自动布局的指纹，vCPU 数变化时不再匹配（Frank Denneman：*"This setting is not changed, unless the number of vCPUs of the VM changes"*）
- 【本机日志实证，推断】`"120122"` 的 `12` 与 `22` 疑似对应 `numvcpus=12` 与 `virtualHW.version=22`——仅作提示，**不作为判断依据，以删除后能否正常开机为准**
- 同步动作：关机 → 编辑 `.vmx`（删 cookie + 改 numvcpus/coresPerSocket）→ 开机 → 校验日志中 `numa: coresPerSocket = <新值> maxVcpusPerVPD = <新值>`；
  若出现 `numa: Invalid NUMA cookie.` 说明 cookie 没删干净或 GUI 回写覆盖了改动。

---

## 4. 客户机 CPU 信息与校时验证子模块

### 4.1 为什么必须做这个子模块

【本机日志实证】`guest vs. host CPUID` 段中，客户机可见的关键叶子**全被清零**：

| Leaf | 宿主 | 客户机 | 后果 |
|---|---|---|---|
| `00000015`（TSC/晶体管时钟） | `0x2 / 0x98 / 0x0249f000` → 2918.4 MHz | **全 0** | 客户机拿不到 TSC 频率，XNU 只能靠 HPET/APIC 反推 → **自标定误差直接变成时钟漂移** |
| `00000016`（基频/最高频/总线） | `0xb54(2900) / 0x1324(4900) / 0x64(100)` | **全 0** | 客户机拿不到基频/最高频，`sysctl` 里的频率信息只能自算 |
| `00000018/1a/1c/20` | 有值 | **全 0** | 无拓扑/混合核类型信息（见 §3.2） |
| `40000000` | — | `0x40000010` + `"VMwareVMware"` | hypervisor 指纹仍在（`hypervisor.cpuid.v0` 不管这一层） |
| `00000001` ECX | `0x7ffafbff` | `0xf7fa322b` | **两者 bit31（hypervisor 位）都是 0**；但 guest 并非「与宿主一致」——EAX 也被掩码成 `0x000406e3`（Skylake-Y），品牌串仍透传宿主 `i7-13620H` |
| `80000008` | `0x3027`（PA=39） | `0x302d`（PA=45） | 与 `monitor.phys_bits_used=45` 一致，正常 |

叠加本机 `tools.syncTime = "FALSE"` + `Tools heartbeat timeout` + `installError 21004`
→ **既没有 CPUID 频率、也没有可用的 Tools 校时**，漂移没有任何兜底。这就是本子模块存在的理由。

### 4.2 日志解析器（`macopt-cpu-diag`）设计

输入：`vmware.log`（取最新一份）。逐项抽取 → 交叉计算 → 分级结论（`OK / WARN / FAIL`）。
> 证据等级：下表 **#1–#15 全部为【本机日志实证】**（每行都能在当前 `vmware.log` 复现）；
> 计算/判定规则本身依据【官方文档】（Intel SDM CPUID leaf 15h/16h、1Fh；VMware 日志字段语义）；
> 「#10 两段视图矛盾」的解释为【社区经验，需实测】，不得据此下结论。

| # | 解析目标（正则） | 本机取值 | 判定 |
|---|---|---|---|
| 1 | `VMMon_GetkHzEstimate: Calculated (\d+) kHz` | `2918400` → **2918.4 MHz** | 记为 `TSC_HOST` |
| 2 | `TSC Hz estimates: vmmon (\d+), cpuinfo (\d+), cpufreq (\d+) sysctlfreq (\d+).*Using (\d+) Hz` | `2918400000 / 4641551000 / 4900000000 / 0 → 2918400000` | **`vmmon` 与 `cpuinfo/cpufreq` 不等长纲**：前者是 TSC 时基，后两者是核心频率 → 输出注释「勿混用」；若 `Using` ≠ `vmmon` → WARN |
| 3 | `TSC scaling ratio: .*mult=(\d+), shift=(\d+)` | `mult=2147483648, shift=31` → **1.0** | `TSC_GUEST = TSC_HOST × ratio = 2918.4 MHz`；ratio≠1 时打印换算后的 guest TSC |
| 4 | `PTSC: Host is using tsc as clocksource.` / `hardware TSCs are synchronized.` | 两行都有 | 缺任一行 → **FAIL**（宿主 clocksource 非 TSC 或跨核 TSC 不同步，客户机时钟无解） |
| 5 | `hostCPUID level 00000015.*` | `0x2/0x98/0x0249f000` | 用 `ECX × EBX / EAX` 独立算一遍，与 #1 交叉验证（本机 38,400,000×76 = 2,918,400,000 ✓ 完全吻合）→ 不符则 WARN |
| 6 | `guest vs. host CPUID guest level 00000015` / `00000016` | 全 0 | **WARN（本机常态）**：客户机无法通过 CPUID 得到 TSC/频率 → 输出「需靠 HPET/APIC 反推，存在漂移风险」 |
| 7 | `guest level 00000001.*` ECX | `0xf7fa322b` | 打印 `hypervisor_bit=0`；与 host `0x7ffafbff` 并列，**明确标注 guest leaf1 并非与宿主一致**（掩码已改写 EAX/部分特征位） |
| 8 | `guest level 40000000` | `0x40000010` + `VMwareVMware` | 打印指纹暴露情况（不作 FAIL，仅登记） |
| 9 | `guest level 0000001f` / `0000000b` 的 sub1 EBX、ECX 类型位 | EBX=`0x0c`(12)、ECX 类型=Core | 与 `.vmx` 的 `numvcpus/coresPerSocket` 对账；不一致 → FAIL（说明改了 .vmx 但没生效/没重启） |
| 10 | `host vs. host CPUID` / `CPUID differences from hostCPUID.` 段的 `level 00000016` | 该段出现 EBX=`0xe10`(3600) 与 `0x1324`(4900) 两种值 | 与 #6（全 0）**互相矛盾** → 标 `INFO/待客户机实测`，不得据此下结论 |
| 11 | `Host: Disabling thread priority boosting to work around Linux SMP bug.` | 存在 | INFO：VMware 已关闭线程优先级提升，vCPU 线程不会因优先级被调度器区别对待 |
| 12 | `Tools: Tools heartbeat timeout.` / `toolsInstallManager.lastInstallError` / `.vmxf <installError>` | 有超时、`21004` | **FAIL（校时链路）**：`tools.syncTime=TRUE` 即使写了也无效 → 必须先修 Tools 或改用客户机 NTP |
| 13 | `Host PA size` / `guest level 80000008` | 39 / 45 | OK（与 `monitor.phys_bits_used=45` 对账） |
| 14 | `Powering on guestOS '(.*?)' using the configuration for '(.*?)'` | `darwin24-64`（两处相同） | 校验 `guestOS` 校正是否落地：期望 `darwin25-64` |
| 15 | `Selected Tools ISO 'darwin.iso' for '(.*?)' guest` | `darwin24-64` | 同上，随 `guestOS` 变化，作为影响面回归点 |

### 4.3 漂移风险结论与处置（分级）

| 条件 | 结论 | 处置 | 证据等级 |
|---|---|---|---|
| leaf `0x15/0x16` 全 0 **且** `tools.syncTime=FALSE` **且** Tools 心跳超时 | **FAIL：无任何自动校时，且客户机时基靠自标定** | ① 先修 VMware Tools（`installError 21004`），成功后置 `tools.syncTime="TRUE"`；② 无论 Tools 是否可用，**客户机内始终开 NTP 兜底**（macOS `systemsetup -setusingnetworktime on` / `chronyd`）；③ 保持 `hpet0.present="TRUE"` | 条件三项：【本机日志实证】；处置动作：【官方文档】`tools.syncTime` +【社区经验，需实测】 |
| leaf `0x15/0x16` 全 0 但 Tools 可用且 `syncTime=TRUE` | WARN：有兜底，但同步周期内仍有抖动 | 客户机内仍建议开 NTP（双保险）；记录同步周期 | 【社区经验，需实测】 |
| 宿主 clocksource 非 TSC 或 TSC 不同步 | FAIL | 宿主侧 `cat /sys/devices/system/clocksource/clocksource0/current_clocksource` 应为 `tsc`；不得改用 `hpet` | 【本机日志实证】`PTSC: Host is using tsc as clocksource.` / `hardware TSCs are synchronized.`；【官方文档】内核 clocksource 文档 |

**客户机侧验证命令（【社区经验，需实测】，需在 macOS 26 内逐条试，可用项写回文档）**
```bash
sysctl -a 2>/dev/null | grep -Ei 'tsc|frequency|timebase'   # 是否暴露 TSC 频率
sntp -d time.apple.com                                       # 直接读 NTP offset（ms 级）
ioreg -l -w0 | grep -iE 'tsc|clock-frequency'                # 设备树中的时钟信息
sysctl kern.boottime; date                                   # 与宿主时间做长时间跨度对比
```
判定：`sntp` offset 稳定在 ±50 ms 内 → OK；持续单向增长（如每天漂移 > 1 s）→ **FAIL，回退到 §4.3 处置**。

---

## 5. 按宿主类型的策略矩阵

**行 = 参数/子模块；列 = 宿主类型。`✅ 启用` / `➖ 可选` / `❌ 关闭` / `— 不适用`**

**矩阵逐行证据等级**
- `guestOS` 校正、`numvcpus/cpuid.coresPerSocket`、`hypervisor.cpuid.v0`、`tools.syncTime`、身份块、`hpet0.present`、`vpmc.enable`、`vhv.enable`、诊断器（Intel 混合列）：【本机日志实证】+【二进制 strings 实证】
- `numa.autosize.*` 收敛、`smc.version`、`ulm.disableMitigations`、`cpuid.numSMT`：【二进制 strings 实证】+【社区经验，需实测】
- **P/E 分层绑定**（Intel 混合列）：【本机实测】（`cpu_core`/`cpu_atom`/`lscpu -e` 全部本机跑通）
- Intel 非混合列、AMD 两列的所有判定与替代方案（按 module 分组 / 按 CCD+L3 分组 / `constant_tsc` 加严 / 老 AMD 无 invariant TSC）：【社区经验，需实测】——**本机无 AMD 宿主，全部需上机实测后回填**
- vNUMA 在多 socket/多 CCD 宿主上应保留：【官方文档】vSphere 性能最佳实践（vNUMA 控制）

| 参数 / 子模块 | Intel 混合（本机 12–14 代 H/U 等） | Intel 非混合（≤11 代 / Xeon E） | AMD 非 Ryzen（FX / 旧 Opteron / Bulldozer） | AMD Ryzen（Zen1–Zen5） |
|---|---|---|---|---|
| `guestOS = darwin25-64` 校正 | ✅ | ✅ | ✅ | ✅ |
| `numvcpus` / `cpuid.coresPerSocket`（整除、≤ 逻辑线程） | ✅ | ✅ | ✅ | ✅ |
| **P/E 分层绑定**（`cpu_core`/`cpu_atom` → `0-11` / `12-15`） | ✅ **核心项** | ➖ 退化为「只取每核主 HT」（无分层，`cpu_core` 目录不存在） | ❌ 无大小核；改为**按 module 分组**（FX 的 2 核共享 FPU，绑同一 module 内） | ❌ 无大小核；改为**按 CCD/L3 共享域绑定**（`cache/index3/shared_cpu_list`），优先单 CCD |
| `numa.autosize.*` 收敛为单 vNUMA | ✅（宿主单节点） | ✅（宿主单节点时） | ✅ | ✅（**多 socket/多 CCD 时反而要保留 vNUMA**，让 vNUMA 与 CCD 对齐） |
| `vhv.enable = FALSE` | ✅ | ✅ | ✅ | ✅ |
| `hypervisor.cpuid.v0`（不设 / FALSE） | ➖ 不动（已实测 bit31=0） | ➖ 同左 | ➖ 同左 | ➖ 同左（勿与 AMD CPUID 修补混用） |
| `vpmc.enable = FALSE` | ✅ | ✅ | ✅（更易触发 `msg.vpmc.unsupported`） | ✅（同左） |
| `tools.syncTime` 分档 + 客户机 NTP | ✅ | ✅ | ✅ **更关键**：老 AMD 常无 invariant TSC | ✅（Zen 有 invariant TSC，风险较低） |
| 身份块 `reflectHost=FALSE` + 显式值 | ✅ | ✅ | ✅ | ✅ |
| `smc.version = "0"`（可选） | ➖ | ➖ | ➖ | ➖ |
| `hpet0.present = TRUE` | ✅ | ✅ | ✅ **必需** | ✅ |
| `ulm.disableMitigations` | ➖（当前已等效关闭） | ➖ | ➖ | ➖ |
| **TSC/CPUID 诊断器** | ✅ | ✅ | ✅ **加严**（校验 `constant_tsc`/`nonstop_tsc` 旗标） | ✅ |
| `cpuid.numSMT`（实验） | ➖（宿主 SMT=2，可试） | ➖（宿主 SMT 决定） | ➖（FX 无 SMT） | ➖（宿主 SMT 决定；线程数须整除） |
| 依赖 CPUID 伪装的项 | — 不属本模块 | — | — | —（**Ryzen 上 macOS 需额外 CPUID 补丁，属身份模块**） |

**检测顺序（决定落入哪一列）**：【本机实测】+【社区经验，需实测】
```bash
grep -m1 vendor_id /proc/cpuinfo                 # GenuineIntel / AuthenticAMD
[ -d /sys/devices/cpu_core ] && echo "Intel hybrid"
lscpu -e=CPU,CORE | awk 'NR>1{print $2}' | sort -u | wc -l   # 物理核数，与 CPU 数比较得 SMT
lscpu | grep -i "model name" | grep -qi ryzen && echo "AMD Ryzen (Zen)"
cat /proc/cpuinfo | grep -o -E 'constant_tsc|nonstop_tsc' | sort -u   # 老 AMD 可能缺失
```

---

## 6. 注入时机约束与已安装系统兼容性

### 6.1 「必须在开机前注入」的硬约束

1. **`.vmx` 只在 `VMX_PowerOn` 那一刻被读取**：【本机日志实证】`ConfigVMX_Load: Loaded .../<vm-name>.vmx in 169 us` → 运行中改文件无效，必须**完全断电**（`powerOff`，不是 suspend、不是 snapshot revert）后修改，下次开机才生效。
2. **禁止「运行中 GUI 编辑」与「手工改文件」并存**：VMware GUI 关机/关闭设置窗时会回写整份 `.vmx`，可能覆盖手工改动、并把 `numa.autosize.cookie` 等重新生成。正确顺序：**关机 → 关闭 Workstation GUI → 编辑器改 `.vmx` → 校验 → 再启动 GUI**。证据：【本机日志实证】现有 `.vmx` 中就含有运行时被写回的键（`guestInfo.detailed.data`、`vm.lastPowerRequestTimestamp`、`cleanShutdown`、`toolsInstallManager.*`）→ 证明该文件会被 VMware 进程改写；回写时机粒度：【社区经验，需实测】。
3. **改完必须回读验证**（三处，缺一不可）：
   - `.vmx` 文件本身 `grep -E 'guestOS|numvcpus|coresPerSocket|numa\.autosize|reflectHost|tools.syncTime'`
   - 日志 `DICT ... ` 段是否出现新值（【本机日志实证】该段会完整回显生效配置）
   - 日志 `Powering on guestOS 'darwin25-64' using the configuration for 'darwin25-64'`
4. **cookie 与拓扑类改动必须「删键 + 断电」成套执行**（§3.5），否则 VMware 会按旧指纹拒绝或回滚。证据：【二进制 strings 实证】`numa: Invalid NUMA cookie.`、`The VM lost its coresPerSocket cookie.`；【社区经验，需实测】。
5. **宿主绑定不是 .vmx 参数**，属进程/cgroup 层，须在**启动前**施加（desktop Exec / systemd-run），并对已运行进程无效（方案 C 除外）。证据：【本机实测】（cpuset/taskset 语义）+【官方文档】systemd.resource-control。

### 6.2 对已安装系统（macOS 26 / Darwin 25，已装在 45 GB vmdk 上）的兼容性分级

| 改动 | 对已装系统的影响 | 建议 | 证据等级 |
|---|---|---|---|
| `guestOS` | 不动磁盘/固件；但会换 Darwin 掩码 → 客户机 leaf `0x1A/0x1C/0x20`、leaf1 EAX 可能变化 | **可直接改**，但必须做改前/改后 `guest vs. host CPUID` 对比 + 完整冷启动回归（能进桌面、App 能跑） | 掩码机制：【二进制 strings 实证】+【本机日志实证】；回归项：【社区经验，需实测】 |
| `numvcpus` / `cpuid.coresPerSocket` | XNU 每次开机重新枚举，一般无碍；但并发度、Xcode 并行度、IOKit 拓扑推断会变 | **可改**（先快照）；改后看 CPUID `0x1F` 是否与新值一致 | 【本机日志实证】guest `0x1F` sub1 EBX=12 与 `numvcpus=12` 对账；枚举行为：【社区经验，需实测】 |
| `numa.autosize.*` + cookie | 仅影响 vNUMA 呈现 | **可改**；重点看是否出现 `numa: Invalid NUMA cookie.` | 【二进制 strings 实证】 |
| `vhv.enable` / `vpmc.enable` / `hypervisor.cpuid.v0` | 客户机不可见的主机侧开关（本机 leaf1 已无 VMX/hypervisor 位） | **可改**，风险低；`hypervisor.cpuid.v0` 改动后回归 Tools（气球/心跳/时间同步） | 【本机日志实证】+【社区经验，需实测】 |
| **身份块（`board-id` / `hw.model` / `serialNumber` / ROM / MLB）** | 会被 macOS 写入 NVRAM、影响 IOKit 注册、部分授权与 iServices；安装器还有板型白名单 | **改前必须做快照 + 记录旧值**；改后预期 IOKit/内核缓存重建，首启可能偏慢 | 【本机日志实证】`can't find host SMBIOS entry point`；【社区经验，需实测】 |
| `smc.version` | 本机无此键且能开机 → 属新增行为 | **可选**，加入即视为行为变更，必须回归冷启动与 AppleSMC | 【二进制 strings 实证】+【社区经验，需实测】 |
| `tools.syncTime` | 只影响同步策略，随时可切 | **可改**；但本机 Tools 不可用，先修 Tools | 【本机日志实证】 |
| 宿主侧绑定（taskset / cgroup） | 完全在宿主，与 guest 磁盘无关 | **可随时改**；唯一风险是把 `vmware-vmx` 限到过窄集合导致卡顿 → 按档位校验 | 【本机实测】 |

### 6.3 回滚

- 每次改动前保留三件套：`.vmx` 副本（`<vm-name>.vmx.bak-<时间>`）、当前 `vmware.log`、身份块旧值清单；
- 身份块类改动**必须先做 VMware 快照**（快照回滚不会自动还原 `.vmx` 文本，但会还原 NVRAM 与磁盘）；
- 宿主绑定改动无持久副作用（改回 desktop Exec / 停止 scope 即回滚）。

---

## 7. 验收清单（逐条可执行）

| # | 检查项 | 期望值 | 证据等级 |
|---|---|---|---|
| 1 | 日志 `Powering on guestOS '...'` | `darwin25-64` | 【本机日志实证】 |
| 2 | 日志 `Selected Tools ISO ... for '...' guest` | `darwin25-64` | 【本机日志实证】 |
| 3 | 日志 `numa: coresPerSocket = X maxVcpusPerVPD = Y` | X = `numvcpus`，Y ≥ `numvcpus`（单 vNUMA） | 【本机日志实证】 |
| 4 | 日志无 `numa: Invalid NUMA cookie.` / `The VM lost its coresPerSocket cookie.` | 无 | 【二进制 strings 实证】 |
| 5 | 日志 `TSC scaling ratio` | `mult=2147483648 shift=31`（1.0），`Using 2918400000 Hz` | 【本机日志实证】 |
| 6 | 日志无 `can't find host SMBIOS entry point` / `PVNVRAMSetMacOS* Unable to retrieve host value` | 无（改显式身份块后应消失） | 【本机日志实证】 |
| 7 | `grep Cpus_allowed_list /proc/$(pgrep -x vmware-vmx)/status` | 与所选档位一致（默认 `0-11`） | 【本机实测】 |
| 8 | guest CPUID `0x1F/0x0B` sub1 EBX | 等于 `numvcpus`（默认 12） | 【本机日志实证】 |
| 9 | 客户机 `sntp -d time.apple.com` offset | ±50 ms 内且不单调漂移 | 【社区经验，需实测】 |
| 10 | 客户机冷启动进桌面、无 AppleSMC 相关 panic | 通过 | 【社区经验，需实测】 |

---

## 8. 本模块与其它模块的边界

| 依赖方 | 关系 |
|---|---|
| 身份伪装模块（cpuid.family/model/brandString/inhibitDarwinMasks、AMD 补丁） | 本模块**不碰**；但 `guestOS` 校正会间接改变 Darwin 掩码选取，两者必须**同一次回归**里一起验 |
| 磁盘/显卡/网络补丁 | 无耦合 |
| VMware Tools 模块 | 强耦合：`tools.syncTime` 生效前提是 Tools 心跳正常（本机 `installError 21004` 需先修） |
| 文档 v2.0 身份章节 | **需按 §2.4 修订**：`reflectHost` 与显式值二选一，不得并存；本机必须走显式值路径（反射链路已实测失败） |

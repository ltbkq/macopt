# macopt 设计文档 v2.0 — 核心 CPUID 伪装设计专项评审（02 号报告）

- 评审对象：macopt 补丁设计文档 v2.0 中"AMD 宿主 → 向 macOS `.vmx` 注入 `cpuid.*` 掩码"的核心设计
- 评审性质：**只读**。未修改任何 VMware 系统文件、未修改任何 `.vmx`/虚拟机文件；本目录之外只新增了临时分析文件
- 评审环境：
  - 主机：Linux Mint / user `<user>`，**Intel i7-13620H（6P+8E，16 逻辑核）—— 本机是 Intel 宿主，不是 AMD**
  - VMware Workstation **26.0.1 build 25688693（26H1u1）**，`/usr/lib/vmware/bin/vmware-vmx` 已被 Unlocker 打过补丁
  - Unlocker：`/mnt/<media>/DATA/vmware/unlocker427`（4.2.7）、`unlocker428`（4.2.8）
  - 真实可查日志：`/mnt/<media>/DATA/vmware/<vm-name>/vmware.log`（guestOS `darwin24-64`，`numvcpus=12`，`cpuid.coresPerSocket=12`，**`.vmx` 中没有任何 `cpuid.0/1.*` 掩码**）
- 语料：`/home/<user>/macopt-review/vmx-strings.txt`（`strings -n 4 /usr/lib/vmware/bin/vmware-vmx`，238824 行，551 处 `cpuid`）

> **重要前提**：本机磁盘上**未找到 macopt 设计文档原文**（`find /home/<user> -iname "*macopt*"`、`grep -r "078BFBFF|7700K"` 均只命中本评审目录，0 命中）。因此第二节按任务转述的文档主张逐条评审；凡涉及"文档写了某个具体值"的地方，本报告给出**权威计算/实测值**作为判据，需与文档原文比对后落笔。

---

## 一、确定的事实（带证据）

### 1.1 `vmware-vmx` 里 `cpuid.*` key 的真实机制（strings 分析）

**（1）key 格式化串**（`vmx-strings.txt:159637-159641`、`159668-159669`，相邻排布，说明同属一个解析表）：

```
cpuid.%x.%x.%s.amd      ← leaf, subleaf, register，带 .amd 后缀（厂商变体，排在最前 = 优先查）
cpuid.%x.%s.amd         ← leaf, register
cpuid.%x.%x.%s          ← leaf, subleaf, register
cpuid.%x.%s             ← leaf, register
cpuid.inhibitDarwinMasks
cpuid.%x.edx / cpuid.%x.0.edx
```

`%s` 为寄存器名（`eax/ebx/ecx/edx`），第二个 `%x` 为 subleaf。**即：这套 key 机制在原理上可指定任意 leaf/subleaf/reg**，不限于 leaf 0/1。`.amd` 变体优先于通用变体被查询。

**（2）完整 key 登记表**：`cpuid.0.*`、`cpuid.1.*`、`cpuid.80000000.*`、`cpuid.80000001.*`、`cpuid.80000008.*`（每条都带 `.amd` 后缀变体）与配置路径 `cpuid/cpuid_0_eax` …（`vmx-strings.txt:179227+`）；另有扁平写法 `cpuid.0`/`cpuid.1`/`cpuid.80000000`…（`:151774+`）。

**（3）命名特性 key 共 270 个**（`grep -c -E "^cpuid\.[A-Za-z_0-9]+$"`），抽样行号：

| 类型 | 行号 | 例 |
|---|---|---|
| 特性位（**大写**） | `177057-177300+` | `cpuid.SSE3` `cpuid.SSE41` `cpuid.SSE42` `cpuid.PCID` `cpuid.XSAVE` `cpuid.AVX` `cpuid.PSN` **`cpuid.DS`** **`cpuid.SS`** `cpuid.AVX2` `cpuid.IBRS` `cpuid.CET_IBT` `cpuid.SVM*` … |
| CPU 签名 | `177005-177007` | **`cpuid.family` / `cpuid.model` / `cpuid.stepping`** |
| 品牌串 | `159660`、`159710-159711` | `cpuid.brandString`，日志 `Guest cpuid.brandString set to "%s"` / `… truncated to 47 characters.` |
| 拓扑/多核 | `136130`、`137247`、`151694` | `cpuid.coresPerSocket`、`cpuid.numSMT`、`cpuid.maxVCPUs` |
| 开关 | `135619-135620`、`159670`、`160462`、`159676` | `cpuid.enableMWAIT` `cpuid.enableTSX` `cpuid.enableIBT` `cpuid.enableCPUIDFaulting` `cpuid.ulm.fusionCompatability` |

**（4）Darwin 内置掩码确实编译在二进制里**（`159691-159696`）：

```
----:----:----:0001:----:----:1110:0101
----:----:----:0100:----:----:0101:0001
----:----:----:0100:----:----:1110:0011
----:----:----:0011:----:----:1010:1001
----:----:----:0010:----:----:1010:0111
Assuming most recent known Darwin masks are suitable.
```

源文件标识：`bora/vmcore/vmx/main/x86/cpuid.c`（`159698`）、`bora/lib/cpuidInfo/cpuidInfo.c`、`bora/lib/public/cpuidInfo.h`（`vmx-debug-strings.txt`）。

**（5）值格式与语义（网络核实 + 本机二进制一致）**
- Broadcom 官方社区帖 *Manipulating Guest CPUID*：`cpuid.<leaf>.<reg> = "<32 位>"`，**"Ones and zeroes override the default settings, bit by bit. Dashes are used to leave the default settings alone."** → **逐位覆盖**（`0`/`1` 强制，`-` 保留默认），**不是 AND 掩码**。这正是"能把 `AuthenticAMD` 改写成 `GenuineIntel`"的判定依据。
- HN 上 VMware 方人员补充：还支持 **`h` = 采用宿主该位的值**；非默认掩蔽的 leaf 需加 `monitor_control.enable_fullcpuid = TRUE`；`cpuid.brandstring` 覆盖 leaf 80000002-4。
- 二进制中**没有** `GenuineIntel`/`AuthenticAMD` 字面量（0 命中）→ 厂商串是按位掩码拼出来的，不是查表替换。

**（6）VMware 自己已经在改 CPUID —— 本机真实日志实测**（`<vm-name>/vmware.log:1647-1686`，`.vmx` 无任何 `cpuid.0/1.*` 用户掩码）：

```
guest vs. host CPUID guest vendor: GenuineIntel
guest vs. host CPUID guest family: 0x6 model: 0x4e stepping: 0x3   / *host family: 0x6 model: 0xba stepping: 0x2
guest vs. host CPUID guest codename: Skylake-Y                     / *host codename: Raptor Lake H/P/PX/U
guest level 00000001, 0: 0x000406e3 0x00100800 0xf7fa322b 0x1f8bfbff
*host level 00000001, 0: 0x000b06a2 0x11800800 0x7ffafbff 0xbfebfbff
guest level 00000000, 0: 0x00000020 0x756e6547 0x6c65746e 0x49656e69
```

逐项结论（本机 Intel 宿主、无用户掩码条件下）：

| 项 | host | guest | VMware 已做的改动 |
|---|---|---|---|
| leaf1.EAX 签名 | `0x000b06a2`（RPL, model 0xBA step 2） | `0x000406e3`（**Skylake-Y**, model 0x4E step 3） | **内置 Darwin 掩码把签名改成 Skylake-Y** |
| leaf1.EDX | `0xbfebfbff` | `0x1f8bfbff` | **清掉 bit21 DS、bit22 ACPI、bit31 PBE** |
| leaf1.ECX | `0x7ffafbff` | `0xf7fa322b` | 清掉若干位并**置 bit31 hypervisor** |
| leaf1.EBX | `0x11800800` | `0x00100800` | APIC ID 字段 → 0；`[23:16]` 128 → **16**（= `numvcpus 12` 向上取最近 2 的幂） |
| leaf0 最大基本 leaf | 0x20 | **0x20** | 未封顶 |
| brand string(80000002-4) | i7-13620H | **i7-13620H** | 未改（`board-id.reflectHost=TRUE`） |

→ **"VMware 完全不动 CPUID、全靠用户掩码"这一类说法与本机日志直接矛盾。**

**（7）相关日志/报错串**（证明验证方法与失败模式均真实存在）
- `guest vs. host CPUID`（`:159681`）、`CPUID differences from hostCPUID.`（`:159715`）、`Full guest CPUID with differences from hostCPUID highlighted.`（`:159726`）
- `Inconsistent CPUID: Removing HTT for cpu %d` / `Removing MWAIT` / `Removing XSAVE`（`:179766-179768`）→ **VMware 对"各 vCPU CPUID 不一致"有专门降级逻辑**
- `msg.featurecompat.requirement.bool.mustBeTrue` = `Feature '%s' was absent, but must be present.`（`:177041`）
- `msg.featurecompat.requirement.bool.mustBeFalse` = `Feature '%s' was present, but must be present.`…（`:177040`，原文为 `was present, but must be absent`）
- `msg.featurecompat.invalidmask` = `The virtual machine feature mask incorrectly requires '%s' = '%s'.`（`:158656`）
- `msg.cpuid.guestOSMissingFeatures` = `This virtual machine is missing features%s%s%s required by %s guests and cannot be powered on.`（`:159733`）
- `msg.cpuid.guestCpuidLoLevelsZero` = `The virtual machine requires a nonzero number of basic cpuid levels (value of register eax for cpuid level 0).`（`:159727`）← **直接约束 `cpuid.0.eax`**
- `msg.cpuid.guestRequiresAVX2noAVX` = `This virtual machine requires AVX2 but AVX is not present. This virtual machine cannot be powered on.`（`:159729`）
- `featureCompat.enable`（`:158649`）与 `%s featureCompat.enable is not allowed for HWversion %s 9.`（`:158655`）
- 本机运行日志实测：`FeatureCompat: Capabilities:` 含 `cpuid.ds = 1`、`cpuid.ss = 1`（`vmware.log:1778-1779`）；`FeatureCompat: Requirements:` 含 **`VM Features Required: cpuid.ss - Bool:Min:1`**（`:1918`），并要求 `cpuid.sse41/sse42/pcid/avx2/…`；日志中 **Requirements 里没有 `cpuid.ds`**。

### 1.2 Unlocker 是否已经提供 CPUID / SMC 处理

| 检查项 | 结论 | 证据 |
|---|---|---|
| `templates/` 是否含 CPUID/SMC 模板 | **两个版本的 `templates/` 都是空目录** | `ls -laR unlocker42{7,8}/templates/` → 仅 `.` `..` |
| 为什么会空 | 上游在 4.2.6 主动删除 | `unlocker428/CHANGELOG.md`：`03/03/23 4.2.6 — Removed template VMs`；4.2.3 曾有 `Template VMs for Intel and AMD CPUs with sensible defaults` |
| Unlocker 到底改什么 | 只改"能否被识别/能否启动"与 **SMC** | `unlocker428/README.md`：`Patch vmware-vmx and derivatives to allow macOS to boot`、`modify the implmentation of the virtual SMC controller device` |
| 是否提供 CPUID 掩码 | **不提供** | README 无任何 `cpuid.*` 掩码；`.vmx` 里 `smc.version`/`smc.present` 由 unlock 后的 vmx 支持 |
| 对 AMD 的官方口径 | 4.2.8：`The Unlocker cannot: * add AMD CPU support`；4.2.7 同位置写的是 `* add older (non-Ryzen) AMD CPU support`（措辞不同，引用须标版本行号） | `unlocker42{7,8}/README.md` §1 |
| 项目状态 | 已归档（`Unlocker 2007-2023 This project is now archived.`），但本机 26.0.1 已打补丁（backup/26.0.1 有哈希记录） | `unlocker428/README.md`、`unlocker427/backup/26.0.1/` |
| 附带的 `linux/cpuid` | 是 Todd Allen 的 `cpuid` 工具（ELF64 static、带 debug_info，`--dump`/`--parse`/`--sanity` 可用），**与 `.vmx` 掩码生成无关** | `unlocker428/linux/cpuid --help` |

→ **结论：CPUID 伪装完全是用户侧 `.vmx` 工作，Unlocker 不会替你做；SMC/Apple 菜单/Tools 才是 Unlocker 的活。**

### 1.3 CPUID 位号的权威校准（解决"MMX=22 还是 23"的矛盾）

四个**独立**来源互相印证，本机实测再加一道验证：

| 来源 | 结果 |
|---|---|
| 本机内核头 `cpufeatures.h`（`/usr/src/linux-headers-7.3.0-070300rc3/arch/x86/include/asm/cpufeatures.h`） | `PN 18 / CLFLUSH 19 / DS 21 / ACPI 22 / MMX 23 / FXSR 24 / XMM(sse) 25 / XMM2 26 / SELFSNOOP(ss) 27 / HT 28 / ACC(tm) 29 / IA64 30 / PBE 31` |
| Wikipedia *CPUID*（`EAX=1` 特性表） | 同上：`ds=21 acpi=22 mmx=23 fxsr=24 sse=25 sse2=26 ss=27 htt=28 tm=29 ia64=30 pbe=31`；bit10/20 为 reserved |
| Unlocker 附带 `cpuid` 工具对本机 raw 值的解码 | 输出顺序与上述**逐位吻合**（…CLFLUSH, debug store, ACPI, MMX, FXSAVE, SSE, SSE2, self snoop, max APIC IDs…, thermal monitor, pending break enable） |
| Broadcom 社区帖中 VMware 方的回帖 | *"you are changing **bit 22 of CPUID.1.EDX** … namely 'ACPI'"* → ACPI=22，独立佐证 |
| **本机实测交叉验证** | host `EDX=0xBFEBFBFF` 置位 = `{0-9,11-17,19,21-29,31}`（清 10/18/20/30），`/proc/cpuinfo` 首行 flags 恰好 28 项（`fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe`）→ 一一对应 |

**→ 权威位号（本报告采用）**：`DS=21、ACPI=22、MMX=23、FXSR=24、SSE=25、SSE2=26、SS=27、HTT=28、TM=29、IA64=30、PBE=31`；ECX：`SSE3=0 … SSE4.1=19、SSE4.2=20、X2APIC=21、MOVBE=22、POPCNT=23、TSCDL=24、AES=25、XSAVE=26、OSXSAVE=27、AVX=28、F16C=29、RDRAND=30、HYPERVISOR=31`。
**EBX 字段（Wikipedia 引 Intel）**：`[7:0]` Brand Index、`[15:8]` CLFLUSH 行长（值×8 字节）、`[23:16]` 封装内可寻址逻辑处理器数（**仅当 EDX.HTT(bit28)=1 时有效**）、`[31:24]` 初始 APIC ID。

### 1.4 关键值的逐位解码

**(a) 社区通用 `cpuid.1.edx = 0x078BFBFF`**（`0000:0111:1000:1011:1111:1011:1111:1111`，本机 python 解码）

- 置位（22 位）：`0-9, 11-17, 19, 23, 24, 25, 26`
  → **FPU/VME/DE/PSE/TSC/MSR/PAE/MCE/CX8/APIC/SEP/MTRR/PGE/MCA/CMOV/PAT/PSE36/CLFSH + MMX/FXSR/SSE/SSE2 全部保留**
- 清零（10 位）：`10(reserved), 18(PSN), 20(reserved), 21(DS), 22(ACPI), 27(SS), 28(HTT), 29(TM), 30(IA64), 31(PBE)`

**→ 逐位解码结论：该值不清 MMX/SSE/SSE2；它刻意清掉 DS、ACPI、SS、HTT、TM、PBE。**
（对照：本机 host `0xBFEBFBFF` 置位 `{0-9,11-17,19,21,22,23,24,25,26,27,28,29,31}`；VMware 内置 guest `0x1F8BFBFF` 只比 host 多清 21/22/31。→ `0x078BFBFF` 相当于"VMware 内置值再清掉 SS(27)、HTT(28)、TM(29)"。）

**(b) 旧版变体 `0x0FABFBFF` 与 `0x078BFBFF` 的差异恰是两位**：`bit27(SS) 1→0`、`bit21(DS) 1→0`。社区原话（exchangetuts）：*"I have to change two 1 to 0 … It solved the cpuid.ss and cpuid.ds message"*。

**(c) i7-7700K 的 `cpuid.1.eax`（权威计算值）**

```
0x000906E9 = 0000:0000:0000:1001:0000:0110:1110:1001
stepping = 0x9, base model = 0xE, base family = 0x6, ext model = 0x9
→ family 6, model 0x9E (Kaby Lake), stepping 9
```

（社区通用值 `0x00010671` = family 6 / **model 0x17 (Penryn)** / stepping 1，与 7700K **不是同一个东西**。）

**(d) 社区 `cpuid.1.ebx = 0x02010800`**

```
[31:24] = 0x02  → 初始 APIC ID = 2
[23:16] = 0x01  → 封装内可寻址逻辑处理器数 = 1
[15:8]  = 0x08  → CLFLUSH 行长 64 B
[7:0]   = 0x00  → Brand Index 0
```

对照本机 VMware **自行计算**的 guest EBX `0x00100800`（APIC ID=0、`[23:16]`=16、CLFLUSH=64）→ 用户掩码会把这两个 VMware 会按 vCPU 拓扑动态计算的字段**硬编码成常量**。

**(e) 社区 `cpuid.1.ecx = 0x82982203`** 置位 = `SSE3(0) PCLMUL(1) SSSE3(9) CX16(13) SSE4.1(19) SSE4.2(20) POPCNT(23) AES(25) HYPERVISOR(31)`；**清掉** `MONITOR/MWAIT(3) VMX(5) EST(7) TM2(8) FMA(12) PCID(17) MOVBE(22) TSCDL(24) XSAVE(26) OSXSAVE(27) AVX(28) F16C(29) RDRAND(30)` 等。

### 1.5 网络核实结果

1. **掩码语义 = 逐位覆盖**（Broadcom 官方帖 + HN 中 VMware 方人员：`0`/`1`/`-`/`h` 四种字符）——已确认。
2. **社区值出处**：`DavidsonRafaelK/MacOS-Installation`、`insanelymac 338849 / 362385`、`amd-osx 4696 (drk)`、`exchangetuts`、`TechSpite`、`GEEKrar` 等，八行值高度一致（0x0B / Genu+ineI+ntel / 0x00010671 / 0x02010800 / 0x82982203 / 0x078BFBFF 或 0x0FABFBFF）。
3. **`cpuid.ss`/`cpuid.ds` 与 `featureCompat.enable` 确有其事**：`amd-osx` 帖（drk）同一补丁含 `cpuid.ss="1"` `cpuid.ds="1"` `featureCompat.enable="TRUE"` `monitor_control.enable_fullcpuid="true"`；Reddit/r-vmware 与 iPhoneWired 等多处贴出**完全一致**的报错原文：
   ```
   Feature 'cpuid.ds' was absent, but must be present.
   Feature 'cpuid.ss' was absent, but must be present.
   Module 'FeatureCompatLate' power on failed.
   ```
   与本机二进制 `msg.featurecompat.requirement.bool.mustBeTrue` **逐字吻合**。
4. **AMD 场景下掩码的必要性**：DavidsonRafaelK 明确 "Without this, the VM will hang indefinitely at the Apple logo"；insanelymac 338849 中 AMD 宿主是 "a fault has occurred causing a virtual CPU to enter the shutdown state"；TechSpite/GEEKrar 的 "The CPU has been disabled by the guest operating system"。→ 三类失败都发生在**引导早期**，不是"安装器弹窗提示 CPU 不受支持"。
5. **Unlocker 官方 wiki（AMD-CPUs）**：明确 Unlocker **不能**添加 AMD CPU 支持；项目已归档。
6. **`cpuid.1.ebx` 与 SMP**：本机 host 侧 EBX `[31:24]` 在 16 个逻辑核上各不相同（`0x00,0x01,0x08,0x09,…`），而 VMware 计算的 guest EBX `[31:24]=0`；Wikipedia 引 Intel 说明该字段"用于标识执行中的逻辑处理器"，`[23:16]` 只在 `EDX.HTT=1` 时有效。**社区掩码让所有 vCPU 看到同一个 APIC ID** 这一点无法在本机（Intel 宿主、未注入掩码）证实，列入第三节实测。
7. **macOS CPUID 校验时机**：**没有找到任何权威来源**支持"只在安装时校验、装完即可去掉掩码"。反向旁证：XNU 每次启动都会读取并缓存 CPUID（`cpu_data`/`cpuid_info`），社区的失败样例全部是**每次开机**都失败（Apple logo / vCPU shutdown / bootloop），而非一次性安装提示。→ 文档若给出确定性结论，属于无据断言。

---

## 二、技术上站不住脚或有风险的点

> 风险等级：🔴 高（可能导致无法开机/系统不稳定/结论完全错误）｜🟠 中（结论不完整、易误导）｜🟡 低（表述/可维护性）

### 🔴 风险 1：位号解码口径若沿用"DS=20/ACPI=21/MMX=22"旧记法，`0x078BFBFF` 的结论会完全反了
- 依据：§1.3 五个独立来源一致给出 `MMX=23、SSE=25、SSE2=26、SS=27、HTT=28`；若按错位映射解读，会得出"该掩码清掉了 MMX/SSE/SSE2"的**错误**结论，进而误判"社区值不可用"。
- 修改建议：报告与文档中**必须**给出位号表并注明出处（内核头/Wikipedia/`cpuid` 工具/VMware 回帖四选三即可），随后给出 §1.4(a) 的解码表；对任何十六进制值，先写 4 位一组二进制再逐位命名，不要凭记忆下结论。

### 🔴 风险 2：`0x078BFBFF` 清掉 `SS(27)`、`HTT(28)` 的副作用被低估
- **SS(27)**：本机日志显示 `darwin24-64` 的硬性要求含 `VM Features Required: cpuid.ss - Bool:Min:1`（`vmware.log:1918`）。掩码清零后可能触发 `Feature 'cpuid.ss' was absent, but must be present.` 或 `msg.cpuid.guestOSMissingFeatures` → `Module 'FeatureCompatLate' power on failed`。
- **HTT(28)**：按 Intel 语义，该位=1 才声明 `EBX[23:16]`（封装内逻辑处理器数）有效。清零后 guest 拓扑退化，而 VM 是 `numvcpus=12`、`coresPerSocket=12` 的多核配置；二进制里另有 `Inconsistent CPUID: Removing HTT for cpu %d`（`179766`），说明 VMware 对 HTT 异常很敏感。
- **反向证据**：社区 A/B 结果方向与直觉相反——`0x0FABFBFF`（SS/DS=1）时报错，改成 `0x078BFBFF`（SS/DS=0）后"解决了 cpuid.ss/cpuid.ds 报错"（exchangetuts/TechSpite）。**机制未被 VMware 公开，社区结论互相矛盾。**
- 修改建议：① 不要写"该值无副作用"；② 明确列出被清位及其语义；③ 把"`cpuid.ss` 是否可被掩掉"列为**必须实测项**，并给出第三节 T2 的 A/B 步骤；④ 若只想清 DS/ACPI/TM/PBE，可用 `-` 保留 SS/HTT，例如只覆盖已知安全位。

### 🔴 风险 3：`cpuid.1.ebx` 对所有 vCPU 同值 → APIC ID 与逻辑处理器数被硬编码
- `0x02010800` ⇒ `APIC ID=2`、`max addressable logical processors=1`。若掩码对每个 vCPU 都生效，12 个 vCPU 会**全部报 APIC ID = 2**，且 `max IDs=1` 与实际多核拓扑矛盾（再叠加 HTT 被清，拓扑信息彻底失效）。
- 本机实测：VMware **自行**给出 `guest EBX = 0x00100800`（APIC ID=0、`[23:16]`=16 = 12 向上取 2 的幂）→ 说明该两个字段是 VMware 按配置动态算的，用户掩码会与之冲突；冲突后谁胜出未验证。
- 修改建议：① 文档应默认**不写 `cpuid.1.ebx`**；② 如必须写，只覆盖 `[15:8]`（CLFLUSH），`[31:24]`、`[23:16]` 用 `-` 保留（格式需实测，见 T3）；③ 把"逐 vCPU 的 leaf1 EBX 是否相同"列为实测项，并给出 guest 内验证手段（`sysctl machdep.cpu.*`、`sysctl -n hw.ncpu/hw.physicalcpu`）。

### 🟠 风险 4：`cpuid.0.eax = 0x0B` 会封顶基本 leaf，可能隐藏 `0xD`(XSAVE)/`0x16`/`0x1F`(拓扑)
- 本机实测 VMware 给 guest 的 max basic leaf 是 **0x20**（未封顶）。写 0x0B 后，`CPUID.0xD`（XSAVE 状态大小）、`0x16`（频率）、`0x1F`（拓扑）等都不可枚举。
- 二进制有专门检查 `msg.cpuid.guestCpuidLoLevelsZero`（`159727`）；社区也确有 "requires AVX2 but AVX is not present" 这类因 leaf 掩码导致的 power-on 失败（`msg.cpuid.guestRequiresAVX2noAVX`，`159729`）。
- 另外 0x0B 与 `cpuid.1.eax=0x00010671`（Penryn，其史上最大基本 leaf 是 0x0A）**不自洽**，而 ECX 里又带 SSE4.2+AES（Westmere 及以后）→ 这是一颗"拼装 CPU"，不是任何真实 Intel 型号。
- 修改建议：写明 0x0B 是**社区拼装值**而非某颗 Intel 的真实值；优先尝试 `-`（保留 VMware 的 0x20）或用 `cpuid.brandString`/`cpuid.family|model|stepping` 做最小伪装；把"leaf 0xD 是否仍可见"列入实测（T4）。

### 🟠 风险 5："VMware 不做任何 CPUID 处理、必须全靠掩码"与日志矛盾
- 见 §1.1(6)：无用户掩码时 guest 签名已是 Skylake-Y、EDX 已清 DS/ACPI/PBE、EBX 已被改写、ECX 已置 hypervisor 位。
- 二进制中还有 5 条 `----:----:` Darwin 内置掩码与 `cpuid.inhibitDarwinMasks`（`159641`、`159691-159696`）。
- 修改建议：文档应改为"**内置 Darwin 掩码 → 用户 `cpuid.*` 掩码**"的叠加模型，并说明 `cpuid.inhibitDarwinMasks` 的存在与作用（真值语义需实测，见 T1）；明确"AMD 宿主上厂商串是否已被内置掩码改写"是需要实测的第一个问题（本机 Intel 宿主无法回答）。

### 🟠 风险 6：`featureCompat.enable = "FALSE"` 的建议在新版 Workstation 上可能不成立
- 二进制串 `%s featureCompat.enable is not allowed for HWversion %s 9.`（`158655`）+ 社区经验 "Disabling featureCompat.enable works only on VMware versions less than 9"。本机 VM 是 `virtualHW.version = 22`。
- 社区实测还出现 `Value "…" for variable "featureCompat.enable" is not a valid boolean value. Using value "TRUE".`（引号是花引号导致）。
- 修改建议：若文档给出 `featureCompat.enable`，必须写清**允许的硬件版本范围**与**半角引号**要求，并注明 26.0.1 下的实测结果；不确定时建议"先删该行"。

### 🟠 风险 7：Unlocker 相关表述（模板里已有 CPUID/SMC 掩码）不成立
- 见 §1.2：`templates/` 两个版本均为空，4.2.6 已 `Removed template VMs`；Unlocker 只做 vmx 补丁 + SMC + Apple 菜单 + Tools，**不做 CPUID 掩码**。
- 修改建议：改成"Unlocker 解决 SMC 与 Apple guest 识别；`cpuid.*` 掩码必须由 macopt 自行写入 `.vmx`"；引用 AMD 口径时区分 4.2.7（`older (non-Ryzen) AMD CPU support`）与 4.2.8（`add AMD CPU support`），并标行号（01 号报告已指出同一问题）。

### 🟡 风险 8：命名键的大小写与"更简洁的替代方案"未提及
- 二进制中是**大写** `cpuid.SS`/`cpuid.DS`/`cpuid.SSE42`/`cpuid.PCID`（`177064-177076`），而 featureCompat 日志与社区补丁用**小写** `cpuid.ss`/`cpuid.ds`。大小写是否敏感未验证。
- 同时存在 `cpuid.family`/`cpuid.model`/`cpuid.stepping`（`177005-177007`）与 `cpuid.brandString`（`159660`），比整段 `cpuid.1.eax` 位掩码更安全、更可读。
- 修改建议：① 记录"大写存在于二进制、小写见于日志/社区"这一事实，列为实测（T5）；② 方案中提供 `cpuid.family/model/stepping/brandString` 的替代路径，并说明"若为内部配置键而非 `.vmx` 键则不可用"需实测。

### 🟡 风险 9："macOS 只在安装时校验 CPUID"缺权威来源
- 见 §1.5(7)：无权威证据；社区失败样例全部是每次开机复现。文档若以此为前提给出"装好后可撤掩码"的步骤，属于无据断言。
- 修改建议：改为"安装前/安装后分阶段实测"（T6），并注明 XNU 每次启动都会执行 CPUID 探测这一常识性前提。

---

## 三、必须实测才能定论的点（附验证步骤）

> 通用前置（只读评审未执行）：**先整机复制 `.vmx` 与日志目录到备份**，只改副本；每次只改一个变量；改动后必须**冷启动**（CPUID 掩码不做热更新，VMware 回帖明确 "There is no way to reflect that to the guest os without a VM restart"）。

**日志读取命令（所有测试共用）**
```bash
VM="/mnt/<media>/DATA/vmware/<vm-name>"          # 换成你的测试 VM 目录
grep -n "guest vs. host CPUID" "$VM/vmware.log"
grep -n -E "guest level (00000000|00000001|00000007|80000001)|\*host level (00000000|00000001|00000007|80000001)" "$VM/vmware.log"
grep -n "FeatureCompat\|mustBeTrue\|must be present\|Missing features" "$VM/vmware.log"
grep -n "Inconsistent CPUID\|Assuming most recent known Darwin" "$VM/vmware.log"
```
对照判定：`guest level …` 是**掩码后**的最终值，`*host level …` 是宿主原值；两者 diff 就是掩码的净效果。

| # | 待定论的问题 | 验证步骤 | 判据 |
|---|---|---|---|
| **T1** | 用户 `cpuid.*` 与**内置 Darwin 掩码**谁覆盖谁；`cpuid.inhibitDarwinMasks` 的真值语义 | 副本 `.vmx` 分三档：① 不加 ② `cpuid.1.edx = "…0111:…"`（只改一位）③ ② + `cpuid.inhibitDarwinMasks = "TRUE"`；各冷启动一次 | 比 `guest level 00000001` 的 EDX/EAX：② 若生效说明用户掩码后置；③ 若 guest 签名从 `0x000406e3` 变回 `0x000b06a2`，说明 `TRUE`=禁止内置掩码 |
| **T2** | `cpuid.1.edx = 0x078BFBFF` 是否触发 `Feature 'cpuid.ss' was absent…` | A/B：① `0x0FABFBFF` ② `0x078BFBFF` ③ `0x078BFBFF` + `cpuid.ss = "1"`；观察能否 power-on | 记录三种情况下 `FeatureCompat: Failed Requirements:` 与弹窗文案；回答社区 A/B 方向相反的矛盾 |
| **T3** | `cpuid.1.ebx` 是否对**每个 vCPU** 同值（APIC ID 是否全变成 2） | 副本加 `cpuid.1.ebx = "0000:0010:0000:0001:0000:1000:0000:0000"`，冷启动；guest 内跑 CPUID 读 leaf1.EBX（macOS 侧可用 Unlocker `macos/` 下的工具或自编译），逐核/逐 vCPU 取值；同时 `sysctl -n hw.ncpu hw.physicalcpu machdep.cpu.thread_count` | 若 12 个 vCPU 全报 `0x02010800` → 掩码覆盖 VMware 的动态计算；若 APIC ID 仍逐 vCPU 不同 → VMware 后置改写，风险 3 不成立 |
| **T4** | `cpuid.0.eax = 0x0B` 后 leaf `0xD/0x16/0x1F` 是否消失、macOS 是否仍正常 | 副本加 `cpuid.0.eax = "…:1011"`，冷启动，读 `guest level 00000000` 的 EAX 与后续 leaf；guest 内 `sysctl -a \| grep -i xsave` / 用 cpuid 工具查 max leaf | 若 `guest level 00000000` EAX 变 0x0B 且 0xD 行消失 → 风险 4 成立；同时观察是否出现 `guestCpuidLoLevelsZero` / AVX2 报错 |
| **T5** | 命名键大小写与 `cpuid.family/model/stepping`、`cpuid.brandString` 是否为可写的 `.vmx` 键 | 副本分别加 `cpuid.ss="1"`、`cpuid.SS="1"`、`cpuid.model="0x9E"`、`cpuid.brandString="Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz"`，冷启动后看 `guest family/model/stepping`、`guest name`、80000002-4 行 | 生效 → 推荐用签名/品牌串做最小伪装；无效 → 说明是内部键，需回退位掩码方案 |
| **T6** | macOS 的 CPUID 校验**时机**（安装前 vs 安装后） | 干净副本：A) 装系统全程带掩码；B) 装完后移除掩码再启动；C) 装完后改掩码为另一套值。每次记录 guest 内 `sysctl machdep.cpu.*` 与 vmware.log diff | 若 B 每次开机失败 → "只在安装时校验"不成立（预期结果）；若 B 正常而 C 失败 → 说明校验是"启动期一致性"而非"一次性" |
| **T7** | **AMD 宿主**上的实际效果（厂商串、`0x78BFBFF`、`.amd` 后缀变体） | 本机是 Intel，无法本机定论。可做两件事：① 在本机副本加 `cpuid.1.edx.amd = "…"`，看是否被忽略（验证后缀选择逻辑）；② 在真实 AMD 机器上跑 T1/T2/T3，并记录 `guest vendor` 是否为 `AuthenticAMD` | `.amd` 变体在 Intel 宿主无效 → 说明后缀按宿主厂商选择；AMD 宿主若 `guest vendor` 已是 `GenuineIntel` → 内置 Darwin 掩码已覆盖厂商串，用户掩码可只做签名/特性位微调 |
| **T8** | `.amd` 后缀、`monitor_control.enable_fullcpuid` 对非默认 leaf（如 7、80000001、8000001D）的必要性 | 副本加 `monitor_control.enable_fullcpuid = "TRUE"` 后注入 `cpuid.7.0.ebx`，比对 `guest level 00000007, 0` | 不加该开关则非默认 leaf 掩码不生效 → 文档必须补这一前置项（社区补丁里普遍带 `monitor_control.enable_fullcpuid = "true"`） |

**最低验收口径**：T1、T2、T3、T6 四项不出结果，文档不得给出"该掩码方案可直接上线"的结论；T7 未做则全文必须标注"AMD 宿主结论尚未经本环境实测"。

---

## 四、来源链接

**VMware 官方/半官方**
1. Manipulating Guest CPUID — Broadcom VMware 社区（掩码语义、`monitor_control.enable_fullcpuid`、`cpuid.brandstring`、日志位置）：https://community.broadcom.com/vmware-cloud-foundation/discussion/manipulating-guest-cpuid
2. HN 讨论（VMware 方人员给出 `-` / `h` / `0` / `1` 四种字符语义与 `.vmx` 示例）：https://news.ycombinator.com/item?id=14079163
3. VMware KB 1009458（Wikipedia 引用，`CPUID.1.ECX.bit31 = hypervisor`）：https://kb.vmware.com/s/article/1009458

**位号与 CPUID 规范**
4. Wikipedia — CPUID（`EAX=1` 的 EDX/ECX/EBX 完整位表，本报告位号基准）：https://en.wikipedia.org/wiki/CPUID
5. Linux `arch/x86/include/asm/cpufeatures.h`（本机头文件 `/usr/src/linux-headers-7.3.0-070300rc3/...`；在线镜像）：https://elixir.bootlin.com/linux/v6.6/source/arch/x86/include/asm/cpufeatures.h
6. Intel SDM Vol.2 CPUID 章（位定义原始出处，建议文档引用它而非二手资料）：https://www.intel.com/content/www/public/us/en/developer/articles/technical/intel-sdm.html

**Unlocker**
7. DrDonk/unlocker README（`The Unlocker cannot: add AMD CPU support`、SMC/patch 范围）：https://github.com/DrDonk/unlocker
8. DrDonk/unlocker Wiki — AMD-CPUs（Unlocker 不能添加 AMD CPU 支持）：https://github.com/DrDonk/unlocker/wiki
9. 本机文件：`/mnt/<media>/DATA/vmware/unlocker427/README.md`、`unlocker428/README.md`、`unlocker428/CHANGELOG.md`（4.2.6 `Removed template VMs`）

**社区掩码值与报错实录**
10. DavidsonRafaelK/MacOS-Installation（八行 `cpuid.*` 掩码 + "Without this, the VM will hang indefinitely at the Apple logo"）：https://github.com/DavidsonRafaelK/MacOS-Installation
11. amd-osx 论坛 drk 补丁（`cpuid.ss`/`cpuid.ds`/`featureCompat.enable`/`monitor_control.enable_fullcpuid` 同时出现）：https://forum.amd-osx.com/threads/mac-os-install-on-amd-ryzen-intel-vmware-opencore-improved-performance-works-with-tahoe-sequoia-sonoma-etc.4696/page-28
12. r/vmware — `Feature 'cpuid.ds'/'cpuid.ss' was absent` + `featureCompat.enable` 引号问题实录：https://www.reddit.com/r/vmware/comments/kkqsry/need_help_with_wmware_16/
13. InsanelyMac — AMD 宿主 `a fault has occurred causing a virtual CPU to enter the shutdown state`、Donk 的掩码尝试全过程：https://www.insanelymac.com/forum/topic/338849-switch-from-intel-to-amd-cpu-with-existing-yosemite-image/
14. InsanelyMac — `cpuid.1.eax` 值含义（Penryn `0x00010671` / Merom `0x000006F1`）：https://www.insanelymac.com/forum/topic/362385-cpuid1eax-values-macos-guest-on-vmware-workstation-with-amd-host-cpu/
15. exchangetuts（`0x0FABFBFF` → `0x078BFBFF` 解决 `cpuid.ss/cpuid.ds` 报错的 A/B 记录）：https://www.exchangetuts.com/vmware-macos-bigsur-in-win10-1767350102959837
16. TechSpite（`featureCompat.enable` 仅硬件版本 <9 有效、`cpuid.ss/ds` 已不再支持的说法）：https://techspite.com/how-to-fix-the-cpu-has-been-disabled-by-the-guest-os
17. erkserkserks/vmware_cpuid_tool（用 `cpuid` 工具原始 dump 生成 `.vmx` 掩码，推荐给 macopt 复用）：https://github.com/erkserkserks/vmware_cpuid_tool

**本机证据文件**
18. `/home/<user>/macopt-review/vmx-strings.txt`（本报告全部行号引用）
19. `/home/<user>/macopt-review/vmx-debug-strings.txt`
20. `/mnt/<media>/DATA/vmware/<vm-name>/vmware.log`（`guest vs. host CPUID` 实测段，行 1647-1786、1900-1950）
21. 本机 CPUID 实测工具：`cpuiddump.c`、`cpuidbits.c`、`cpuid3.c`、`cpupin.c`

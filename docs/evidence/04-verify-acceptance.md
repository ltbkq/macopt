# 04 · 验收标准、验证工具与工程化设计（macopt 设计文档 v2.0 评审补充）

> 本篇是对《macopt 设计文档 v2.0》的补充评审，覆盖四块内容：
> ① 新增 `macopt verify <vmx>` 子模块（运行时闭环验证）；
> ② Unlocker 状态检测算法 v2（替换"字符串偏移量"脆弱方案）；
> ③ 修订后的验收标准（原第 7 节）与自动化边界；
> ④ 工程化改进清单（原 3.8 备份 / 第 4 节 CLI）与风险登记表。
>
> 本篇所有结论均基于 2026-09-25 在本机的**实测**（VMware Workstation 26.0.1 build 25688693，
> Linux Mint 22.3，Intel i7-13620H，Unlocker 4.2.7，<vm-name> 虚拟机），实测证据见附录 A。
> 本文件为新增文件，未修改任何既有文件。

---

## 0. 实测环境与关键事实（作为后续设计的依据）

### 0.1 关键路径

| 对象 | 路径 | 备注 |
|---|---|---|
| vmx 主程序 | `/usr/lib/vmware/bin/vmware-vmx` | 当前 sha256 `e989f645…b8d` |
| 基础库 | `/usr/lib/vmware/lib/libvmwarebase.so/libvmwarebase.so` | 当前 sha256 `3efb4af5…80df` |
| Unlocker | `/mnt/<media>/DATA/vmware/unlocker427`（4.2.7） | `linux/{unlock,relock,check}` |
| Unlocker 备份 | `/mnt/<media>/DATA/vmware/unlocker427/backup/26.0.1/` | 含 4 个二进制 + 4 个 `.sha256` |
| 测试虚拟机 | `/mnt/<media>/DATA/vmware/<vm-name>/` | `<vm-name>.vmx`，4 份历史日志 |
| Darwin Tools ISO | `/usr/lib/vmware/isoimages/darwin.iso` | sha256 `e0c96286…9236`，与 unlocker 自带 ISO 逐字节相同 |
| 版本获取 | `vmware --version` → `VMware Workstation 26.0.1 25688693` | 无需 root，rc=0 |

### 0.2 `.sha256` 文件的**双行格式**（实测，文档未记载）

每个 `.sha256` 恰为 129 字节 = `64 位十六进制 + "\n" + 64 位十六进制`（**无尾换行**）：

| 文件 | 第 1 行（= 备份原件自身哈希） | 第 2 行（= 当前运行文件哈希） | `sha256(备份文件)` | `sha256(/usr/lib/vmware/...)` |
|---|---|---|---|---|
| `vmware-vmx` | `48289dbf9a37dab006188d5c14fe31a6eed26458183ec20ceb0bdb07b68f0f54` | `e989f645bab9c8944d5e4dc67ec72ffc899159e0a11682f780990160a970db8d` | `48289dbf…f54` ✅ 相同 | `e989f645…b8d` ✅ = 第 2 行 |
| `vmware-vmx-debug` | `9614ed20ac5d1e13e3e0e43f55388fbd14784afb9703ff58c21199bd7ee7e001` | `4a6db88f39599c10dd98669e1cb11352a34abac9775651562e375084460bfe0a` | `9614ed20…001` ✅ | `4a6db88f…e0a` ✅ |
| `vmware-vmx-stats` | `f796dadacfb67850c4f8660000941766cdd7b56c9d9407ed66a62d317365bbf4` | `92989aa4e85d7d6ee96b3a154d7352addd0659925312b2bbdfdac035ceacabc0` | `f796dada…bbf4` ✅ | `92989aa4…abc0` ✅ |
| `libvmwarebase.so` | `0a3e679d7dfa5b84145b6133ed86446755e9320a96c9c2eb8ee8bfbf4d990bf0` | `3efb4af563bc0d75bf99a983f7cd3ddeba422dae22f278220642d619165280df` | `0a3e679d…9bf0` ✅ | `3efb4af5…80df` ✅ |

**结论（4/4 全部成立）**：`.sha256` 第 1 行就是"备份原件"的校验值，可用作**权威基线**；
第 2 行恰好等于当前被 patch 后的运行文件哈希，可作**已知补丁态**的旁证。
推论：`sha256(当前运行文件) ≠ 第 1 行 ⇒ 该文件已被修改（通常即已打补丁）`，前提是版本一致（见 §2.3 版本门禁）。

### 0.3 二进制差异实测（决定"字符串偏移量"方案为何要换掉）

| 项目 | 实测结果 |
|---|---|
| `vmware-vmx` 大小 | 备份与当前**同为 30,299,088 字节**（原地 patch，不改长度） |
| `cmp -l` 差异字节数 | **136 字节**；偏移 `1,631,257` 起 4 处 + `23,737,553` ~ `23,769,104` 区间 |
| `strings` 差集（当前独有） | **仅 2 条**：`ourhardworkbythesewordsguardedpl`、`easedontsteal(c)AppleComputerInc`（各出现 2 次） |
| `strings` 差集（备份独有） | 0 条 |
| `libvmwarebase.so` | **42 字节不同**（`0x36 → 0x37`，等间距 72），`strings` 差集 **0/0** ⇒ **纯字符串法完全检测不到** |
| `Assuming most recent known Darwin masks are suitable.` | 备份 1 次 / 当前 1 次 ⇒ **stock 字符串，不能当补丁标志** |
| `msg.appleSMC.badHost`、`This virtual machine can run only on an Apple computer`、`smc.version`、`appleSMC` | 备份与当前**均存在** ⇒ 同样不能当补丁标志 |

> **这正是"检查字符串偏移量"方案脆弱的根因**：偏移量随 VMware 每次更新漂移，
> 而 stock 字符串（Darwin masks 提示、SMC 报错文案）在未 patch 的二进制里同样存在，
> 一旦被当作标志位就会把"未打补丁"误判成"已打补丁"。改用 §2 的**哈希 + 存在性 + 分级**算法。

### 0.4 日志可用性实测

| 项 | 实测 |
|---|---|
| 最新日志定位 | `vmware.log`（mtime 2026-09-25 19:37）比 `vmware-0/1/2.log` 新 ⇒ 按 mtime 取最新，可用 `vmware*.log` glob |
| 版本行 | `Log for VMware Workstation pid=8976 version=26.0.1 build=25688693 option=Release` |
| `guest vs. host CPUID` 块 | **4/4 份日志都存在**（约第 1647 行起，`-INFO` 级别，开电后 ~1.7 s 打印一次）⇒ 稳定证据源 |
| `CPUID[n] level 00000001` | **4/4 份日志均为 0 命中**（该 trace 只打未被 vmx 处理的 leaf）⇒ 原设想的 APIC ID 方案**在本机不可行**，必须降级（见 V5） |
| 日志权限 | `vmware.log` = `664 <user>:<user>`；以其他用户运行 verify 需 `--log` 指定或 sudo |
| 运行中标记 | 目录内**无** `.lck`（当前 VM 未运行）；运行时会出现 `<vm-name>.vmx.lck/` |

---

## 1. 新增子模块：`macopt verify <vmx>`

### 1.1 职责与定位

| 命令 | 输入 | 作用 | 是否需开机 |
|---|---|---|---|
| `macopt check <vmx>`（既有） | `.vmx` 文件 | **静态**：解析注入项、幂等性、白名单 | 否 |
| `macopt verify <vmx>`（**新增**） | 虚拟机**目录**或 `.vmx` | **动态**：解析最近一次运行日志，闭环验证"注入是否真的生效" | 需要至少开过一次机 |
| `macopt doctor`（既有/澄清） | 环境 | VMware 版本、Unlocker 状态、ISO、权限 | 否 |

`verify` 的核心价值：`check` 只能证明"配置写进去了"，`verify` 才能证明
"**VMware 真的按配置把 CPUID 喂给了客户机**"（配置被忽略、被 Darwin masks 覆盖、被版本差异吞掉时，只有日志能发现）。

### 1.2 输入解析规则

```
macopt verify "/mnt/<media>/DATA/vmware/<vm-name>"      # 推荐：虚拟机目录
macopt verify "/mnt/<media>/DATA/vmware/<vm-name>/<vm-name>.vmx"   # 兼容：直接给 .vmx
macopt verify <dir> --log /path/to/vmware-N.log        # 显式指定日志
macopt verify <dir> --json                             # 机器可读输出
macopt verify <dir> --strict                           # WARN 也计入非零退出码
```

定位算法：

1. 若参数是目录 → 在其中 glob `vmware.log`、`vmware-*.log`，**按 mtime 取最新**；同名冲突时以 `vmware.log` 优先。
2. 若参数是 `.vmx` → 取其同目录，同样 glob。
3. 解析日志头 `Log for VMware Workstation pid=… version=… build=…`，与 `vmware --version` 比对（版本门禁，见 V0）。
4. 交叉校验：日志中 `DICT displayName = "<名字>"`（或 `DICT nvram = …`）须与所选 `.vmx` 一致，否则 WARN"可能取错日志"。
5. **新鲜度门禁**：`mtime(vmware.log) < mtime(<vmx>)` → FAIL「配置已修改但自上次开机后未重启，日志结论不可信」。

### 1.3 解析项与断言（PASS / WARN / FAIL / SKIP）

统一日志行格式（实测原文，注意 `guest … level` 后是**两个空格**、`hostCPUID … level` 后是**一个空格**）：

```
… guest vs. host CPUID guest level 00000001,  0: 0x000406e3 0x00100800 0xf7fa322b 0x1f8bfbff
… guest vs. host CPUID *host level 00000001,  0: 0x000b06a2 0x11800800 0x7ffafbff 0xbfebfbff
… hostCPUID vendor: GenuineIntel
… Capability Found: cpuid.avx2 = 1
```

> **CPUID.1 EAX 解码（本机已验算，与 VMware 自报值逐位一致）**
> - `Family = ((EAX>>8)&0xF)`；`扩展 Family = ((EAX>>20)&0xFF)`（bits 27:20）
>   标准写法：`family = base==0xF ? base + (ext<<4) : base`
>   文档给出的无条件式 `family = ((EAX>>8)&0xF) + (((EAX>>20)&0xFF)<<4)` 在本机两条数据上均正确（ext=0），
>   但建议按标准条件式实现，避免遇到 base=0xF 的 CPU 时算错。
> - `Model = ((EAX>>4)&0xF) + (((EAX>>16)&0xF)<<4)`，即文档的 `((EAX>>4)&0xF) + ((EAX>>12)&0xF0)`（**等价，成立**）；扩展 Model 在 bits 19:16。
> - `Stepping = EAX & 0xF`
> - 本机验算：guest `0x000406e3` → `6 / 0x4e / 3`（与日志 `guest family: 0x6 model: 0x4e stepping: 0x3` ✅ 一致）；
>   host `0x000b06a2` → `6 / 0xba / 2`（与 `hostCPUID family: 0x6 model: 0xba stepping: 0x2` ✅ 一致）。
>   ⇒ verify 内部解码结果**必须**与 VMware 自带的 `… guest family: … model: … stepping: …` 行交叉校验，不一致即 WARN（解析器 bug 或日志格式变更）。

| ID | 级别 | 解析项 | 通过条件 | 失败/降级提示（文案） | 日志证据格式（正则 + 实测样例） |
|---|---|---|---|---|---|
| **V0** | FAIL | 日志新鲜度 + 版本门禁 | `mtime(log) ≥ mtime(vmx)` 且日志 `version` == `vmware --version` 的版本 | `日志早于 .vmx 修改时间：改完没重启，结论作废，请重新开机后再 verify` / `日志版本 26.0.1 与当前 Workstation 25.0.0 不一致：换机/升级后请重新验证` | `Log for VMware Workstation pid=(\d+) version=([\d.]+) build=(\d+)` |
| **V1** | FAIL | **CPUID.0 vendor**（AMD 伪装后应为 `GenuineIntel`） | `guest vendor == "GenuineIntel"`；且 leaf0 EBX/ECX/EDX 拼出 `Genu`/`ntel`/`ineI` | `客户机可见 vendor=AuthenticAMD：cpuid.0.* 伪装未生效或被 .vmx 里的 mask 覆盖，macOS 将拒绝启动` | `guest vs\. host CPUID guest vendor:\s*(\S+)` → 实测 `GenuineIntel`<br>`guest level 00000000,\s+0:\s+(0x\S+) (0x\S+) (0x\S+) (0x\S+)` → `0x00000020 0x756e6547 0x6c65746e 0x49656e69` |
| **V2** | FAIL | **CPUID.1 EAX 的 Family/Model/Stepping**（Intel 解码） | `vendor==GenuineIntel` **且** `family==0x6`（Intel 自 P6 起恒为 6）；`model≠0`、`stepping≤0xF`；解码值 == VMware 自报 `guest family/model/stepping` 行 | `解码出 family=0xF9（AMD Zen 编码）/ vendor 与 family 不自洽：AMD 特征泄漏到客户机` / `解码结果与 VMware 自报不一致：日志格式可能已变，解析器需适配` | `guest vs\. host CPUID guest level 00000001,\s+0:\s+(0x\S+) …` → `0x000406e3 …`<br>交叉：`guest vs\. host CPUID guest family: (0x\S+) model: (0x\S+) stepping: (0x\S+)` → `0x6 / 0x4e / 0x3`<br>（旁证）`guest vs\. host CPUID \*host level 00000001,\s+0: 0x000b06a2 …` |
| **V3** | WARN/记录 | **CPUID.1 ECX bit31 hypervisor 位** | 静态期望 = `.vmx` 中 `cpuid.1.ecx` 注入/掩码计算值；无注入时期望 `=1`（VMware 合成）。实测 guest `0xf7fa322b` → bit31=**1**；host `0x7ffafbff` → bit31=**0**（裸机） | `客户机 hypervisor 位=0（期望 1）：.vmx 里 cpuid.1.ecx 掩码清掉了 hv 位，个别 macOS 版本/虚拟化检测会异常` / `hypervisor 位与 .vmx 期望值不符：注入未生效` | 同 V2 的 ECX 列，bit31 = `(ecx >> 31) & 1` |
| **V4** | PASS/FAIL/WARN | **AVX2 是否暴露**（leaf7 EBX bit5 + OSXSAVE 组合） | ① `maxLeaf(leaf0.EAX) ≥ 7`（实测 `0x20`）② `guest leaf7.EBX bit5 == 1`（实测 `0x219c27eb` → **1**）③ `guest leaf1.ECX bit28(AVX) == 1`（实测 1）④ 旁证 `Capability Found: cpuid.avx2 = 1`、`cpuid.xsave = 1`、`cpuid.xcr0_master_ymm_h = 1` ⑤ `leaf1.ECX bit27(OSXSAVE)`：**开机早期 dump 实测为 0**（dump 发生在开电后 1.7 s，客户机尚未置 CR4.OSXSAVE）⇒ **不作为 FAIL 依据**，仅记录 | `AVX2 位=0：客户机缺 AVX2，部分 macOS 二进制会 SIGILL` / `AVX2=1 但 OSXSAVE=0 且该日志晚于客户机启动完成：XCR0.YMM 不可用，AVX2 会 #UD，需检查 cpuid 掩码` | `guest vs\. host CPUID guest level 00000007,\s+0:\s+(0x\S+) (0x\S+) …` → `0x00000002 0x219c27eb …`<br>`Capability Found: cpuid\.avx2 = (\d)` → `1` |
| **V5** | SKIP→代理 | **多核正确性：各 vCPU initial APIC ID 不重复** | 主方案：遍历 `CPUID[n] level 00000001` 的 EBX 高字节 `((ebx>>24)&0xFF)`，断言 `len(set(ids)) == numvcpus`。**实测 4/4 份日志 0 命中 → 自动降级为 SKIP 并给出下述替代方案** | `日志未包含 per-vCPU leaf1（Workstation 26.0.1 只 trace 未处理的 leaf）：改用下列任一替代检查` <br>① 日志代理指标：`vmm-vcpus` == `DICT numvcpus` == `OvhdUser_LocalApic` 首列（实测均 = 12）→ PASS(弱)<br>② **客户机内**：`sysctl -n hw.ncpu kern.smp.cpu_count machdep.cpu.core_count` == `numvcpus`<br>③ **客户机内**逐线程读 CPUID.1.EBX（`hackrt` / `cpuid` 工具，绑定到每个核心），断言 APIC ID 为 `0..N-1` 互不重复 | 主：`CPUID\[(\d+)\] level 00000001,\s+0:\s+0x\S+ (0x\S+)`（当前 0 行）<br>代理：`vmm-vcpus:\s+(\d+)`、`DICT\s+numvcpus = "(\d+)"`、`OvhdMem OvhdUser_LocalApic\s+:\s+(\d+)` → 实测 `12 / 12 / 12` |
| **V6** | WARN | **叶 00000015 / 00000016 是否为 0** | `guest leaf15 == 0x0`（实测全 0）且 `*host leaf15 ≠ 0`（实测 `0x2 0x98 0x249f000`）；`guest leaf16 == 0x0`（实测全 0）而 `*host leaf16 = 0xb54/0x1324/0x64` | `客户机拿不到 TSC/核心频率（leaf15/16=0）：时间基准只能靠 tools.syncTime 或客户机 NTP；当前 .vmx tools.syncTime=FALSE，建议置 TRUE 或配置 NTP，否则长时间运行会时钟漂移` | `guest vs\. host CPUID guest level 00000015,\s+0:\s+0x0+ 0x0+ 0x0+ 0x0+`<br>`guest vs\. host CPUID \*host level 00000015,\s+0:\s+(0x\S+) …`<br>`guest level 00000016,  0: 0x0+ …`<br>旁证：`VMMon_GetkHzEstimate: Calculated (\d+) kHz` → `2918400`<br>`TSC Hz estimates: vmmon (\d+), cpuinfo (\d+), cpufreq (\d+) sysctlfreq (\d+)` → `2918400000 / 4641551000 / 4900000000 / 0`（三值不一致 → 追加 WARN） |
| **V7** | FAIL | **leaf 40000000 是否为 `VMwareVMware`** | `LE(EBX,ECX,EDX) == "VMwareVMware"`（实测 `0x61774d56 0x4d566572 0x65726177` → `VMwareVMware`，`EAX=0x40000010` 为最大 leaf） | `Hypervisor vendor = "Microsoft Hv"/"KVMKVMKVM"：日志取错机器，或该 VM 实际跑在别的 hypervisor 上` / `缺少 leaf 40000000：客户机未被识别为 VMware 虚拟机` | `guest vs\. host CPUID guest level 40000000,\s+0:\s+(0x\S+) (0x\S+) (0x\S+) (0x\S+)` |
| **V8** | 闭环 | **`.vmx` 注入期望 vs 日志实测** | 对 `.vmx` 中每个 `cpuid.<leaf>.<reg>[.amd]` 键，按掩码规则算出期望值，与 V1–V7 的实测逐位比对；全部一致 → PASS | `注入项与客户机可见值不符（key=cpuid.1.ecx 期望 0x… 实测 0x…）：该 key 可能未被此版本 VMware 认识，或被 Darwin masks 覆盖` | 输入：`.vmx` 解析；输出：V1–V7 的同一批行 |
| **V9** | FAIL | **虚拟机可运行性前置**（顺带静态项） | `guestOS 以 darwin 开头`、`smc.present = TRUE`、`firmware = "efi"`、Darwin Tools ISO 可读（`/usr/lib/vmware/isoimages/darwin.iso` 或 .vmx 自指路径） | `不是 darwin 虚拟机：macopt 拒绝继续（与 apply 的坏路径检查保持一致）` / `找不到 darwin.iso：VMware Tools 无法挂载` | 静态：`.vmx`；日志旁证：`ToolsISO: Selected Tools ISO '(darwin\.iso)' for '(darwin[\w-]*)' guest.` |
| **V10** | 记录 | 频率/拓扑一致性 | `numvcpus == cpuid.coresPerSocket * sockets` 且与 V5 代理值一致；记录 `VMMon_GetkHzEstimate` | `numvcpus=12 与 coresPerSocket=12 不匹配（sockets 计算为 1）：若期望多 socket 拓扑请调整` | `DICT\s+(numvcpus\|cpuid.coresPerSocket) = "(\d+)"`、`vmm-vcpus:\s+(\d+)` |

**降级原则（必须写进实现）**：必需日志行缺失 → `SKIP`（并提示需要开机 / 日志级别），
**绝不**把"缺行"当 FAIL；只有"行存在且值错"才是 FAIL。原因：`guest vs. host CPUID` 块为 `-INFO` 级别、
每次开机只打印一次，若用户以静默参数启动或日志被轮转，会出现缺行。

### 1.4 输出示例（沿用文档 4.3 的对齐文本框 + 状态前缀风格；`check` 与 `verify` 合并）

```
macopt 0.4.0 · verify
虚拟机: /mnt/<media>/DATA/vmware/<vm-name>   (<vm-name>.vmx)
──────────────────────────────────────────────────────────────────────────────
 [静态 check]  <vm-name>.vmx · 4227 B · mtime 2026-09-25 19:37
   ✔ 可解析             guestOS=darwin24-64  smc.present=TRUE  firmware=efi
   ✔ 注入项             12/12 项已写入且同值（幂等，无需变更）
   ✔ 白名单             12 个 key 均存在于 vmware-vmx/libvmwarebase 并集（315+302）
   ✔ Unlocker           已打补丁  sha256 e989f645… ≠ 原件 48289dbf…（backup/26.0.1）
   ✔ 未在运行           未发现 <vm-name>.vmx.lck

 [动态 verify]  最新日志 vmware.log · 460716 B · mtime 2026-09-25 19:37
   版本  Workstation 26.0.1 build 25688693（与宿主一致 ✔）
──────────────────────────────────────────────────────────────────────────────
  #  状态  检查项                          结果 / 证据
  0  ✔     日志新鲜度/版本                 log ≥ vmx；version=26.0.1 == 宿主
  1  ✔     V1 CPUID.0 vendor               GenuineIntel（leaf0 拼写 Genu|ntel|ineI ✔）
  2  ✔     V2 Family/Model/Stepping        6 / 0x4e / 0x3  == VMware 自报值 ✔
  3  ✔     V3 hypervisor 位                guest ECX 0xf7fa322b bit31=1（期望 1）
  4  ✔     V4 AVX2 暴露                    leaf7.EBX 0x219c27eb bit5=1；AVX=1；
                                            cpuid.avx2=1 cpuid.xsave=1 xcr0_master_ymm_h=1
  5  ⚠     V5 多核 APIC ID 唯一性          SKIP：日志无 CPUID[n] leaf1；
                                            代理 12/12/12（vmm-vcpus/numvcpus/LocalApic）
                                            → 需客户机内 sysctl + hackrt 复核
  6  ⚠     V6 leaf15/16 = 0                客户机拿不到 TSC/核心频率；
                                            vmmon 2918400000 vs cpuinfo 4641551000 Hz
                                            tools.syncTime=FALSE → 建议开启或配 NTP
  7  ✔     V7 leaf40000000                 VMwareVMware（max leaf 0x40000010）
  8  ✔     V8 注入闭环                     12 项期望值与日志实测逐位一致
  9  ✔     V9 darwin 前置                  darwin24-64 + smc.present + darwin.iso ✔
 10  ✔     V10 拓扑/频率                   numvcpus=12, coresPerSocket=12, 2918400 kHz
──────────────────────────────────────────────────────────────────────────────
 结果: 8 OK · 2 WARN · 0 FAIL · 0 SKIP(必需项)      退出码 0（--strict 下为 2）
 提示: WARN 不阻断；开一次机并在客户机内执行 `macopt verify --in-guest` 可将 V5 转为必检项。
```

**退出码约定**：`0` = 无 FAIL（可含 WARN）；`1` = 存在 FAIL；`2` = `--strict` 下存在 WARN；
`3` = 无法解析/找不到日志（全 SKIP）；`4` = 参数/路径错误。
**`--json` 输出骨架**：`{"vm":{…},"log":{"path","mtime","version","build"},"checks":[{"id","level","status","expect","actual","evidence"}],"summary":{"ok","warn","fail","skip"},"exit_code":n}`。

---

## 2. Unlocker 状态检测算法 v2（替换"字符串偏移量"方案）

### 2.1 设计目标

- 不依赖任何**偏移量**（VMware 每次更新都会变）。
- 不把 stock 字符串误判为补丁标志（实测已证伪 5 个候选字符串）。
- 支持三种机器：**有 unlocker backup**、**无 backup（首次使用 macopt 的用户）**、**混合/未知**。
- 结果是**可解释的四态**，而非二值：`PATCHED` / `UNPATCHED` / `UNKNOWN` / `DAMAGED`。

### 2.2 主算法（有 backup 目录时，权威）

```
输入: 目标文件 path（vmware-vmx / vmware-vmx-debug / vmware-vmx-stats / libvmwarebase.so）
      版本 ver（取自 vmware --version 或最新日志头）
      备份根列表（可配置）: unlocker*/backup, ~/unlocker*/backup, /opt/unlocker*/backup,
                           macopt 自身 state 目录
步骤:
 1) 版本门禁: 仅使用 backup/<ver>/ 目录；找不到同版本 → 转 fallback(§2.4)，状态 UNKNOWN。
 2) 自校验: sha256(backup/<ver>/<file>) 是否 == <file>.sha256 第 1 行
      不相等 → 状态 DAMAGED（备份被改动，整套基线不可信，提示重跑 unlock 或从安装包还原）
 3) 计算 h = sha256(当前运行文件)
      h == 第 1 行(== backup 文件)      → UNPATCHED（未打补丁）
      h == 第 2 行                      → PATCHED（与已知补丁态完全一致，最高置信度）
      h != 第 1 行 且 != 第 2 行        → UNKNOWN-MODIFIED（提示"被其他工具改过或版本漂移"，
                                           进入 §2.3 marker 检测做二次判读）
 4) 附带项: darwin.iso / darwinPre15.iso 是否存在且 sha256 命中内建允许列表（加分项，非判据）
输出: 逐文件状态 + 汇总（任一关键文件非 PATCHED → 汇总降级）
```

**置信度排序**：`sha256 == 第2行` > `sha256 != 第1行 + marker 命中` > `marker 命中` > `ISO 存在` > `UNKNOWN`。

### 2.3 marker 检测（无 backup 时的 fallback，**存在性而非偏移量**）

按证据强度分级，**只做"是否存在"，绝不比对偏移**：

| 级别 | 证据 | 判据 | 置信度 / 说明 |
|---|---|---|---|
| M1 | `strings vmware-vmx \| grep -c ourhardworkbythesewordsguardedpl` 与 `easedontsteal(c)AppleComputerInc` | **两条同时出现**（当前 patched 实测各 2 次；pristine 备份实测 0 次） | **高**：实测为 patch 唯一新增字符串 |
| M2 | 内建哈希允许列表（随 macopt 发布，按 `VMware 版本 + 文件 sha256` 组织） | 当前哈希命中"已知补丁态"列表 | 高，但需联网/随版本更新 |
| M3 | `sha256(当前) ∉ {已知 pristine 哈希列表}` | 不等于任何已知原件哈希 | 中：也可能只是 VMware 更新过 → 必须叠加版本比对 |
| M4 | darwin.iso 存在 + `sha256 == unlocker 自带 ISO(e0c96286…9236 / df9daa86…296a)` | 命中 | **低**：stock manifest 已把 `darwin24-64 → darwin.iso`，**仅"存在"毫无证明力**，必须比哈希 |
| M5 | 调用 unlocker 自带 `linux/check`（README 定义："check the patch status of your VMware installation"，需 root） | 解析 `Patch Status: %s (%d)` | 高（权威第三方旁证），但依赖 unlocker 目录存在且需 sudo |
| ✗ | ~~`Assuming most recent known Darwin masks are suitable.`~~ | — | **已证伪**：pristine 与 patched 均存在（stock 提示文案） |
| ✗ | ~~`msg.appleSMC.badHost` / `This virtual machine can run only on an Apple computer` / `smc.version` / `appleSMC`~~ | — | **已证伪**：pristine 与 patched 均存在 |

**注意 `libvmwarebase.so` 的盲区**：实测它被改了 42 字节但 `strings` 零差异 ⇒
**M1 对它完全无效**，必须走 §2.2 哈希路线；无 backup 时只能给 `UNKNOWN`（不得谎报 `UNPATCHED`）。

### 2.4 状态机与用户话术

| 状态 | 触发 | 用户提示 |
|---|---|---|
| `PATCHED` | §2.2 步 3 命中第 2 行，或 M1(双 marker)+M2 | `Unlocker 已打补丁（26.0.1，sha256 e989f645…）` |
| `UNPATCHED` | §2.2 步 3 命中第 1 行 | `vmware-vmx 与备份原件一致 → 未打补丁；macOS 虚拟机将无法启动 SMC，请运行 unlocker unlock` |
| `UNKNOWN` | 无同版本 backup 且 M1/M2 未命中 | `无法判定（本机无 26.0.1 备份基线）。可执行 `sudo <unlocker>/linux/check` 或先运行一次 unlocker 生成备份` |
| `UNKNOWN-MODIFIED` | 哈希既非第 1 行也非第 2 行 | `vmware-vmx 与原件/已知补丁态都不一致（可能被其他补丁工具或 VMware 升级改写）：建议从安装包重装后再打补丁` |
| `DAMAGED` | 备份自身哈希 ≠ `.sha256` 第 1 行 | `备份文件校验失败：基线不可信，请勿执行 restore` |

**实现约束**：`.sha256` 第 2 行的语义**未见官方文档化**，v2 算法只把**第 1 行当权威**，
第 2 行仅作"已知补丁态"旁证；若未来 unlocker 改成单行格式，解析器应按行数自适应（1 行 = 仅原件基线）。

---

## 3. 修订后的验收标准（替换原第 7 节）

### 3.1 场景矩阵总览

| ID | 场景 | 硬件/环境 | 是否必须 | 自动化程度 | 备注 |
|---|---|---|---|---|---|
| A | **AMD Ryzen 7 5800X**（原验收） | 另一台 AMD 宿主 + WS 26.0.1 | 必须 | 半自动 + 人工 | 本机无 AMD 硬件，**不能在本机执行** |
| B | **Intel 宿主非回归**（新增，本机可执行） | i7-13620H + WS 26.0.1 | 必须 | **全自动** | 本机已具备全部前置 |
| C | 幂等性（apply 两次一致） | 任一宿主 | 必须 | 全自动 | |
| D | `--dry-run` 不落盘 | 任一宿主 | 必须 | 全自动 | |
| E | `restore` 精确回滚 | 任一宿主 | 必须 | 全自动 | |
| F | 坏路径/拒绝执行 | 任一宿主 | 必须 | 全自动 | |
| G | 未知 key 默认拒绝 | 任一宿主 | 必须 | 全自动 | 配合 §4.3 白名单 |
| H | VM 运行中拒绝 apply | 任一宿主 | 建议 | 全自动 | |
| I | 无 unlocker backup 的新用户 | 无 `backup/<ver>` 的机器（可用参数模拟） | 必须 | 全自动 | 走 §2.4 `UNKNOWN` 分支 |

### 3.2 具体验收用例

#### A · AMD Ryzen 7 5800X（保留原验收，必须在 AMD 机器上执行）

| ID | 步骤 | 通过条件 | 自动化 |
|---|---|---|---|
| A1 | `macopt apply <vmx> --profile ryzen-5800x` | 退出 0；`.vmx` 写入全部目标 `cpuid.*`；生成带时间戳的备份 + manifest | 自动 |
| A2 | `macopt verify <dir>` | 退出 0；V1 `GenuineIntel`、V2 `family=0x6`、V4 AVX2=1、V7 `VMwareVMware` 全绿 | 自动（需先开一次机） |
| A3 | 开机进入 macOS，客户机内 `sysctl -n machdep.cpu.vendor` | 输出 `GenuineIntel`（**人工截取证据**） | **人工开一次机** |
| A4 | 客户机内 `sysctl -n machdep.cpu.brand_string`、`machdep.cpu.features` | brand 为 `Intel(R) Core(TM) …`；features 含 `AVX` | **人工** |
| A5 | AVX2 实际可用性 | 客户机内跑一次依赖 AVX2 的任务（`sysctl` 无法判定）：如 Homebrew 编译 / HandBrake 转码 10 min 不 SIGILL | **人工** |
| A6 | 多核正确性 | `sysctl -n hw.ncpu` == `numvcpus`；用 `hackrt`/`cpuid` 逐核读 CPUID.1.EBX 高字节 → `0..N-1` 不重复 | **人工** |
| A7 | 30 min 稳定性 + 时钟 | 无 kernel panic、无随机重启；`sysctl -n kern.monotonic_clock`/NTP 漂移 < 1 s/30 min（leaf15/16=0 时尤其要看） | **人工** |
| A8 | 非回归（图形/USB/声音/挂起恢复/快照） | 与 apply 前基线一致 | **人工** |

#### B · Intel 宿主非回归（**本机可执行，必须新增**）

| ID | 步骤 | 通过条件 | 自动化 |
|---|---|---|---|
| B1 | 记录基线：`sha256(<vm-name>.vmx)`、`macopt verify` 输出、一次开机的客户机跑分 | 基线留档（进 `state/baseline/`） | 自动 |
| B2 | `macopt apply <vmx>`（Intel profile 或默认） | 退出 0 | 自动 |
| B3 | 检查 `.vmx` | **不含任何 macopt 目标 `cpuid.*` 键**（`cpuid.0.*`、`cpuid.1.*`、`cpuid.8000000*`、`cpuid.AVX2` 等）；<br>⚠️ 允许保留 VMware 自身合法键：`cpuid.coresPerSocket`（本机 `.vmx:39` 已存在 `cpuid.coresPerSocket="12"`），以及 `tools.*`、`smc.present` | 自动 |
| B4 | `macopt verify <dir>` | **全绿**（V0–V10 无 FAIL；V5/V6 允许 WARN 但须带替代方案提示） | 自动 |
| B5 | apply 前后对比 | `.vmx` 差异仅含 profile 期望的非 cpuid 项（或完全无差异 → B6） | 自动 |
| B6 | 开机回归 | macOS 正常启动、跑分与基线差异 < 2%、V1–V10 与基线一致 | 半自动（开一次机） |

> **B3 的表述必须修正**：原表述"apply 后 .vmx 不含任何 `cpuid.*`"会因 `cpuid.coresPerSocket`
> 而**必然失败**（本机 `.vmx:39` 实测已存在）。应改为"不含 **macopt 目标键集** 中的 `cpuid.*`"，
> 目标键集由 §4.3 白名单表显式定义。

#### C–I · 通用工程验收

| ID | 用例 | 步骤 | 通过条件 | 自动化 |
|---|---|---|---|---|
| C1 | 幂等性 | `apply` → `sha256(A)`；再次 `apply` → `sha256(B)` | `A == B`；第二次输出 `0 changed / N unchanged`；diff 为空；不新增重复行 | **全自动** |
| C2 | 幂等性（日志） | 连续 apply 3 次 | 每次退出 0，`.vmx` 行数恒定，`--json` 的 `changed=0` | **全自动** |
| D1 | `--dry-run` 不落盘 | `apply --dry-run` 前后各取 `sha256 + mtime + 行数` | 三者**完全不变**；仅 stdout 打印 unified diff 与 `would change: N` | **全自动** |
| D2 | `--dry-run` 语义 | dry-run 下同时跑 `verify`/`check` | 无任何文件（含备份目录）被创建；`state/` mtime 不变 | **全自动** |
| E1 | 精确回滚 | `apply` → `restore` → `sha256(vmx)` | == `sha256(备份) == manifest.files[0].sha256`；权限/属主/mtime 语义一致 | **全自动** |
| E2 | `restore --list` | 执行 | 表格列出时间、macopt 版本、VMware 版本、sha256 前 8 位、是否与当前文件一致 | **全自动** |
| E3 | `restore --diff [id]` | 执行 | 输出 unified diff（备份 vs 当前，或两次备份之间）；无备份时给出明确空态提示 | **全自动** |
| E4 | 回滚后复验 | `restore` 后 `verify` | 静态项回到"未注入"状态；动态项因日志陈旧 → V0 FAIL（预期，提示重启） | **全自动** |
| F1 | 非 darwin `.vmx` | 对 `guestOS = "ubuntu64-64"` 的 .vmx 执行 `apply` | 拒绝执行；退出码 4；**不创建备份、不改文件**（哈希前后相同） | **全自动** |
| F2 | 不存在路径 / 目录 / 空文件 | `apply /nonexistent`、`apply <dir>`、`apply empty.vmx` | 退出 4；错误文案指向具体原因 | **全自动** |
| F3 | 无 `guestOS` 字段的 .vmx | 构造样本 | 拒绝执行，提示"无法识别虚拟机类型" | **全自动** |
| F4 | 权限不足 | 对只读 .vmx 执行 | 退出非 0，不产生半截文件（临时文件清理 + 原文件不变） | **全自动** |
| G1 | 未知 key | `apply --set cpuid.notARealKey=0x1` | **默认拒绝**：`该 key 不在本机 VMware 26.0.1 识别的 315 个 cpuid.* 键中`；`--allow-unknown-keys` 才写入并 WARN | **全自动** |
| H1 | VM 运行中 apply | 存在 `<vmx>.lck/` 或日志中 pid 存活时执行 | 拒绝执行，提示"虚拟机运行中，请先关机" | **全自动** |
| I1 | 无 backup 的新用户 | 临时把 backup 根移走（或用 `--backup-root` 指向空目录）执行 `doctor` | 状态 = `UNKNOWN`，提示可跑 `linux/check`；**不得**输出 `UNPATCHED`/`PATCHED` | **全自动** |
| I2 | 备份损坏 | 篡改 backup 文件 1 字节 | 状态 = `DAMAGED`，非零退出，且**拒绝 restore** | **全自动** |

### 3.3 哪些必须人工开一次机

| 分类 | 覆盖项 | 说明 |
|---|---|---|
| **全自动（无开机）** | B1–B5、C1–C2、D1–D2、E1–E4、F1–F4、G1、H1、I1–I2 | 全部是文件/哈希/白名单/解析层测试；`verify` 的日志断言可用**样本日志回放**（把 4 份历史日志当 fixture 跑） |
| **半自动（需开机，但无需登录客户机）** | A1–A2、B6、`verify` 的 V0–V10 | VMware 在开电后 ~1.7 s 就打印 `guest vs. host CPUID` 块，脚本等待该行出现即可判定，无需进入 macOS |
| **必须人工开一次机（进客户机操作/观察）** | A3–A8、V5 的逐核 APIC ID、AVX2 实际可用性、30 min 稳定时钟、图形/USB/声音/挂起恢复/快照回归 | 这些值客户机外部拿不到（`sysctl`、逐核 `cpuid`、体感回归） |
| **降低人工成本的手段** | `macopt verify --in-guest` | 通过 SSH 或 VMware Tools 在客户机内执行**只读**脚本（`sysctl` + 逐核 CPUID 读取），输出 JSON 合并进 `verify` 结果，把 A3/A4/A6 转为半自动 |

---

## 4. 工程化改进清单（针对原 3.8 备份 / 第 4 节 CLI）

| # | 改进项 | 现状/问题 | 具体设计 | 验收方式 |
|---|---|---|---|---|
| **4.1** | **备份加时间戳 + manifest** | 单目录备份，多轮 apply 互相覆盖，回滚无凭据 | `state/<vm-id>/backup/20260925-193700-<sha256前8位>/` 内含原 `.vmx` + `manifest.json`：<br>`{schema, created, macopt:{version,argv}, profile:{参数快照}, vmware:{version,build}, files:[{path,sha256,size,mode,mtime}], changes:[{key,before,after}]}`；同 sha256 复用去重；`latest` 软链；`history.jsonl` 追加 | E1/E2：`restore --list` 能列出全部轮次，且每轮 manifest 的 sha256 与文件实测一致 |
| **4.2** | **`restore --list` / `--diff`** | 只能"恢复到最近一次"，无法审阅 | `--list`（轮次表）；`--diff [轮次]`（unified diff，备份 vs 当前；`--diff A B` 比两次）；`--to <id>` 指定轮次；`--verify` 恢复后校验 sha256；`--prune N` 保留策略 | E2/E3/E4 |
| **4.3** | **`apply --dry-run`** | 缺失 | 内存中生成目标文本 → 打印 unified diff + `would change: N` → **不写任何文件、不建备份**（含 `state/` mtime 不变） | D1/D2（哈希 + mtime + 行数三重断言） |
| **4.4** | **幂等 + 冲突策略** | 重复追加同 key 会产生重复行 | 解析 `.vmx` 为有序键值表：<br>• key 不存在 → 追加（`added`）<br>• key 存在且值相同 → 跳过（`unchanged`）<br>• key 存在且值不同 → **默认报错并打印冲突**（旧行/新行/行号），需 `--force` 才覆盖（记入 manifest 的 `changes.before/after`）<br>• 同 key 多行 → WARN 并按最后生效行处理 | C1/C2：两次 apply 结果 `sha256` 相同、第二次 `changed=0` |
| **4.5** | **写入事务性 + 运行时保护** | 直接改写可能留下半截文件 | 临时文件写入 → `fsync` → `rename`（保留原 mode/owner）；失败即回滚；检测 `<vmx>.lck/` 或日志中 pid 存活 → 拒绝 | F4、H1 |
| **4.6** | **注入前 key 白名单校验** | 注入了当前版本不认识的 key 会被**静默忽略** | 启动时扫描 `/usr/lib/vmware/bin/vmware-vmx`、`vmware-vmx-debug`、`/usr/lib/vmware/lib/libvmwarebase.so*`、`/usr/lib/vmware/bin/mksSandbox`，正则 `^cpuid\.[A-Za-z0-9._]+$` 去重取并集（**实测 315 / 315 / 302 / 247 个**），连同 `^(smc\|smbios\|board-id\|firmware\|tools\|monitor_control\|hypervisor)\.` 一起缓存到 `~/.cache/macopt/keys-<ver>-<sha8>.txt`；不在并集 → **默认拒绝**，`--allow-unknown-keys` 放行并 WARN；同时校验 value 形态（`0x`+8 位 hex / TRUE/FALSE / 数值范围） | G1；并要求 `verify` V8 做事后闭环（白名单只证明"VMware 认识"，不证明"行为正确"） |
| **4.7** | **`install` 改名** | `install` 并不"安装"任何东西，语义误导 | 改为 `macopt setup`（备选 `init` / `prepare`）；`install` 保留为 **deprecated 别名**：stderr 打印迁移提示，退出码 0；一个大版本后移除；文档命令表同步 | 文档 + `--help` 一致性检查；别名回归测试 |
| **4.8** | **模块树 ↔ CLI 命令表缺口** | ① 缺 `verify` 模块（本篇新增）② `guest-tools` 命令无对应模块 ③ `restore`/`status` 归属不明 | 补齐映射：<br>`verify → macopt/verify.py`（新增）<br>`guest-tools → macopt/guest_tools.py`（新增：tools ISO、挂载、`--in-guest` 探测）<br>`restore/list/diff → macopt/backup.py`<br>职责界定：`check`=静态 .vmx；`verify`=运行时日志闭环；`doctor`=环境依赖；`status`=Unlocker 状态（§2）<br>每条 CLI 必须带：模块、参数、退出码、是否需 root、是否幂等、测试用例 ID | CI 用 `--help` 抽取命令清单与文档命令表**比对**，缺项即构建失败 |
| **4.9** | **多虚拟机批处理** | 只能单台执行 | `macopt apply --all`、`--glob '/mnt/<media>/DATA/vmware/*/*.vmx'`、`verify --all`；<br>枚举规则：目录内 `*.vmx` 且 `guestOS = "darwin*"`，跳过 `.vmsd` 快照链与 `.lck`；<br>并发：默认串行（避免 CPU/IO 抖动影响验证），`--jobs N` 可选；`flock` 保护 state 目录 + 每 VM 独立 `<vmx>.macopt.lock`；单台失败不中断，`--fail-fast` 可选；汇总表 + `--json-report out.json` | 造 3 个样本 VM 跑 `--all`：1 个 darwin、1 个 linux、1 个坏路径 → 汇总 `1 ok / 1 skipped / 1 failed` |
| **4.10** | **证据留存** | 验收证据靠人截图 | `macopt verify --json` + `--save-report <dir>` 把日志片段（含行号）、sha256、命令输出一起归档，作为 A/B 场景的交付证据 | A2/A3 的报告可复现比对 |

---

## 5. 风险登记表

| # | 风险 | 影响 | 触发条件 | 缓解措施 |
|---|---|---|---|---|
| R1 | 无 unlocker backup 的新用户无法判定补丁状态 | 误报"未打补丁"（或更糟：误报已打补丁） | 首次使用 macopt、backup 目录被删/在别的机器 | 走 §2.4 四态状态机，宁可 `UNKNOWN` 不撒谎；提供 M1–M5 fallback 与 `linux/check` 引导 |
| R2 | `.sha256` 第 2 行语义未文档化，未来 unlocker 可能改格式 | 检测算法失效 | unlocker 升级 / 改为单行 | 只把第 1 行当权威，第 2 行仅旁证；按行数自适应解析；解析失败 → `UNKNOWN` 而非崩溃 |
| R3 | VMware 更新导致二进制偏移量、日志行格式变化 | 原"偏移量"方案 100% 失效；日志断言缺行 | Workstation 26.0.2+ 发布 | §2 用哈希+存在性替代偏移；verify 对缺失行一律 `SKIP`；日志正则带版本适配层与 fixture 回放测试 |
| R4 | `libvmwarebase.so` 被 patch 但 `strings` 零差异 | 字符串法漏检 → 误报未打补丁 | 本机实测即如此（42 字节改动） | 该文件只走哈希路线；无基线时状态 `UNKNOWN`，并在提示中说明"该文件无法用字符串判定" |
| R5 | 日志陈旧：改了 `.vmx` 但没重启 | verify 结论与当前配置不符，掩盖真问题 | apply 后直接 verify | V0 时间戳门禁 → FAIL「请重新开机」 |
| R6 | 取错日志（多轮 `vmware-N.log`、多虚拟机） | 断言建立在别人的日志上 | 目录含多份日志、VM 克隆 | 按 mtime 取最新 + `displayName`/`nvram` 交叉校验 + `--log` 显式覆盖 |
| R7 | `guest vs. host CPUID` 是 `-INFO` 级别且开电后只打印一次 | 静默启动/日志轮转后无证据 | 用户用静默参数、日志被清 | 缺行 → `SKIP`（退出码 3），提示开机方式与 `--log` |
| R8 | 早期 dump 中 `OSXSAVE(bit27)=0` 被误判为缺陷 | 把正常的开机早期状态判成 FAIL | 直接按静态位断言 | V4 将 bit27 定义为**动态位**：开机早期只记录，需 `--after-boot` 复检或客户机内 `cpuid` 读取 |
| R9 | Intel 非回归被 `cpuid.coresPerSocket` 误伤 | 验收用例 B3 恒定失败（假阴性） | 原验收文案"不含任何 cpuid.*" | 改为"不含**目标键集**中的 `cpuid.*`"，目标键集由白名单表显式列出 |
| R10 | `--force` 覆盖用户手工配置且不可逆 | 用户丢失自定义参数 | 冲突时盲目覆盖 | 默认冲突即报错；`--force` 前强制生成带时间戳备份 + 打印 diff；`restore --list/--diff` 可回溯 |
| R11 | 未知 key 被 VMware **静默忽略** | 注入看似成功、实际无效 | 版本不认识该 key | §4.3 注入前白名单默认拒绝 + `verify` V8 事后闭环比对 |
| R12 | 批处理并发写同一 VM / 与 VM 运行冲突 | 文件损坏、配置半截 | `--jobs N` + 用户在跑虚拟机 | `flock` 全局锁 + 每 VM 锁 + `.lck`/pid 检测（H1） |
| R13 | AMD 验收缺少硬件，长期无法执行 | A 场景（核心价值）变成纸面验收 | 只有 Intel 宿主 | 明确标注"必须在 AMD 机器执行"，用 `--save-report` 留存证据；争取外部 AMD 机器/CI 硬件 |
| R14 | leaf15/16=0 导致时钟漂移 | 客户机长时间运行时间不准、证书/计划任务异常 | 本机实测即为 0，且 `tools.syncTime=FALSE` | V6 WARN 升级提示；验收 A7 30 min 漂移测试；建议 `tools.syncTime=TRUE` 或客户机 NTP |
| R15 | 日志/文件权限不足 | 非 root 或其他用户跑 `verify`/`unlocker check` 直接读不到 | `vmware.log` 为 `664 <user>:<user>`；`linux/check` 需 root | 权限不足 → 明确提示 `sudo` 或 `--log`；不静默 SKIP |
| R16 | macopt 边界越界去改 VMware 二进制 | 与 unlocker 相互覆盖，产生 `UNKNOWN-MODIFIED` 态 | 误实现"顺手补丁" | 明确边界：**macopt 只读二进制（哈希/字符串），只写 `.vmx` 与自己的 state**；`restore` 只回滚 `.vmx`；文档写入禁止事项 |
| R17 | 解析"capability"行当成客户机可见值 | 断言错位（`Capability Found: cpuid.*` 是 VM 能力，不是 guest 可见 CPUID） | 混用两类证据 | 表 1.3 中显式区分"主证据（guest level 行）"与"旁证（Capability 行）"，两者都要且不互相替代 |

---

## 附录 A · 本机实测证据（供文档引用/复核）

### A.1 关键日志行（`/mnt/<media>/DATA/vmware/<vm-name>/vmware.log`）

```
1:   Log for VMware Workstation pid=8976 version=26.0.1 build=25688693 option=Release
78:  hostCPUID vendor: GenuineIntel
79:  hostCPUID family: 0x6 model: 0xba stepping: 0x2
83:  hostCPUID level 00000001, 0: 0x000b06a2 0x11800800 0x7ffafbff 0xbfebfbff
168: CPUID[4] level 00000016, 0: 0x00000b54 0x00000e10 0x00000064 0x00000000   # 非 leaf1；leaf1 trace 缺席
257: VMMon_GetkHzEstimate: Calculated 2918400 kHz
258: TSC Hz estimates: vmmon 2918400000, cpuinfo 4641551000, cpufreq 4900000000 sysctlfreq 0. Using 2918400000 Hz
467: DICT                  numvcpus = "12"
468: DICT      cpuid.coresPerSocket = "12"
1647: guest vs. host CPUID guest vendor: GenuineIntel
1648: guest vs. host CPUID guest family: 0x6 model: 0x4e stepping: 0x3
1653: guest vs. host CPUID       level eaxIn, ecxIn:        eax        ebx        ecx        edx
1654: guest vs. host CPUID guest level 00000000,  0: 0x00000020 0x756e6547 0x6c65746e 0x49656e69
1655: guest vs. host CPUID guest level 00000001,  0: 0x000406e3 0x00100800 0xf7fa322b 0x1f8bfbff
1656: guest vs. host CPUID *host level 00000001,  0: 0x000b06a2 0x11800800 0x7ffafbff 0xbfebfbff
1672: guest vs. host CPUID guest level 00000007,  0: 0x00000002 0x219c27eb 0x9840078c 0xbc004410
1695: guest vs. host CPUID guest level 00000015,  0: 0x00000000 0x00000000 0x00000000 0x00000000
1696: guest vs. host CPUID *host level 00000015,  0: 0x00000002 0x00000098 0x0249f000 0x00000000
1697: guest vs. host CPUID guest level 00000016,  0: 0x00000000 0x00000000 0x00000000 0x00000000
1698: guest vs. host CPUID *host level 00000016,  0: 0x00000b54 0x00001324 0x00000064 0x00000000
1727: guest vs. host CPUID guest level 40000000,  0: 0x40000010 0x61774d56 0x4d566572 0x65726177
1782: Capability Found: cpuid.avx2 = 1
227:  Physical APIC IDs: 50,48,32,25,16-17,8,40,52,33,24,9,54,41,1,0     # 宿主 APIC，非客户机
801:  vmm-vcpus:  12
```

### A.2 逐位验算

| 项 | 计算 | 结果 |
|---|---|---|
| guest `0x000406e3` | Family=`(>>8)&0xF`=6, ExtFamily=`(>>20)&0xFF`=0；Model=`(>>4)&0xF`+`((>>16)&0xF)<<4`=0xE+0x40=0x4E；Stepping=3 | `6 / 0x4e / 3`（== VMware 自报 ✅） |
| host `0x000b06a2` | 6 / 0xA+0xB0=0xBA / 2 | `6 / 0xba / 2`（== VMware 自报 ✅） |
| guest leaf1 ECX `0xf7fa322b` | bit31=1, bit28=1(AVX), **bit27=0(OSXSAVE，开机早期)** | hv=1 ✅ / AVX=1 ✅ / OSXSAVE 动态 |
| host leaf1 ECX `0x7ffafbff` | bit31=0（裸机）, bit27=1, bit28=1 | 对照基准 |
| guest leaf7 EBX `0x219c27eb` | bit5=1(AVX2), bit3=1(FMA), bit18=1(BMI1) | AVX2 暴露 ✅ |
| guest leaf40000000 `0x61774d56 0x4d566572 0x65726177` | LE 拼接 | `VMwareVMware` ✅ |
| guest leaf1 EBX `0x00100800` | `(>>24)&0xFF` = initial APIC ID | `0x00`（仅 1 个样本，无法验唯一性） |

### A.3 可复现命令

```bash
# 1) 备份原件哈希 vs .sha256 第 1 行（4/4 相同）
cd /mnt/<media>/DATA/vmware/unlocker427/backup/26.0.1
for f in vmware-vmx vmware-vmx-debug vmware-vmx-stats libvmwarebase.so; do
  echo "$f  $(sha256sum $f | cut -d' ' -f1)  vs  $(head -1 $f.sha256)"
done
# 2) 当前运行文件哈希 vs .sha256 第 2 行（4/4 相同）
sha256sum /usr/lib/vmware/bin/vmware-vmx{,-debug,-stats} \
          /usr/lib/vmware/lib/libvmwarebase.so/libvmwarebase.so
# 3) 补丁差异（136 字节 / 2 个新增字符串）
cmp -l backup/26.0.1/vmware-vmx /usr/lib/vmware/bin/vmware-vmx | wc -l
comm -13 <(strings -a backup/26.0.1/vmware-vmx | sort -u) \
         <(strings -a /usr/lib/vmware/bin/vmware-vmx | sort -u)
# 4) 白名单规模（315/315/302/247）
for f in /usr/lib/vmware/bin/vmware-vmx /usr/lib/vmware/bin/vmware-vmx-debug \
         /usr/lib/vmware/lib/libvmwarebase.so/libvmwarebase.so /usr/lib/vmware/bin/mksSandbox; do
  printf '%s -> %s\n' "$f" "$(strings -a $f | grep -E '^cpuid\.[A-Za-z0-9._]+$' | sort -u | wc -l)"
done
# 5) 日志断言（4 份日志均无 per-vCPU leaf1）
grep -c 'CPUID\[[0-9]*\] level 00000001' "/mnt/<media>/DATA/vmware/<vm-name>/"vmware*.log
grep -n 'guest vs. host CPUID guest level 00000001,' "/mnt/<media>/DATA/vmware/<vm-name>/vmware.log"
```

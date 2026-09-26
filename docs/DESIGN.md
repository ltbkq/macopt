# macopt 详细设计文档

**项目代号**：macopt
**文档版本**：v2.1（首个可开发版本，取代外部输入的《功能设计文档 v2.0》）
**状态**：Approved for development（本文档冻结后进入实现，改动需走修订记录）
**日期**：2026-09-26
**许可证**：MIT
**语言**：本文档为中文正文；仓库 `README.md` 为英文，`README.zh-CN.md` 为中文。

> **English abstract.** macopt is a Linux-hosted, zero-dependency Python CLI that
> optimises VMware Workstation macOS guests. It only rewrites the guest `.vmx`
> (and, opt-in, `~/.vmware/preferences`), never VMware binaries — the Unlocker
> keeps ownership of binary patching. It ships (a) audited configuration
> profiles with per-parameter provenance, (b) guardrails that block known-dangerous
> CPUID edits, (c) host-side CPU topology/scheduling optimisation for hybrid
> Intel and AMD hosts, (d) a five-state Unlocker detector based on double-hashed
> backups instead of fragile string offsets, and (e) a runtime verifier
> (`macopt verify`) that proves a change actually took effect by parsing the
> hypervisor's own boot log.

---

## 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v2.0 | （外部输入） | 初版功能设计（含 10 处事实错误、CPUID 章节缺失关键机制、缺 CPU 调优模块） |
| v2.1 | 2026-09-26 | 按四路并行评审结论全面修订：修正全部事实错误；重写 CPUID 章节；新增 CPU 拓扑/调度/校时模块；新增 `verify` 与五态 Unlocker 检测；重写验收标准；补工程化与开源合规要求 |

**关联材料（仓库内 `docs/evidence/`，已脱敏）**

| 文件 | 内容 |
|---|---|
| `evidence/00-review.md` | 评审总评与修改清单（本文档的上游） |
| `evidence/01-factcheck.md` | 路径 / key / 版本 / README 事实核查 |
| `evidence/02-cpuid-review.md` | CPUID 掩码机制、位号、风险 |
| `evidence/03-cpu-tuning-module.md` | CPU 拓扑与调度补章设计（24 行参数表） |
| `evidence/04-verify-acceptance.md` | Unlocker 五态检测、`verify` V0–V10、验收与工程化 |

---

## 1. 背景、目标与非目标

### 1.1 背景

在 Linux 宿主上运行 macOS 虚拟机需要两件事：

1. **解锁**：让 VMware 接受 `darwin*-64` guestId 并提供 Apple SMC。这由社区项目 **Unlocker** 完成（它 patch `vmware-vmx`、`libvmwarebase.so` 等二进制并附带 darwin.iso）。
2. **优化**：虚拟机起来之后的性能、稳定性、可观测性——vCPU 拓扑、宿主调度、时钟、身份一致性、以及"改动是否真的生效"的验证。

v2.0 设计文档把第 2 件事的大部分精力放在"AMD 宿主 CPUID 伪装"上，却漏掉了占多数的 Intel 宿主最需要的拓扑/调度/校时，且含有 10 处经不起复查的事实断言。v2.1 予以重构。

### 1.2 目标

- **G1** 一条命令产出一个**可审阅、可回滚、幂等**的 `.vmx` 变更计划。
- **G2** 每一条配置项都带**证据溯源**（日志行号 / 二进制字符串 / sysfs / 官方文档 / 社区经验分级）。
- **G3** 高风险操作（CPUID 掩码、身份伪装）默认**拒绝执行**，必须显式放行并有校验规则拦截已知的开机失败组合。
- **G4** 用 **`macopt verify`** 从 `vmware.log` 反证改动生效——"写进去了"不等于"生效了"。
- **G5** Intel / AMD、混合架构 / 同构架构通用的**宿主 CPU 拓扑与调度优化**（本项目对原始诉求的正面回答）。
- **G6** 对 Unlocker 状态给出**五态**（含 UNKNOWN）而非二值猜测的判定。
- **G7** 零运行时依赖（仅 CPython ≥ 3.11），Linux-only，可 `pip install` 或单文件运行。

### 1.3 非目标

- **不** patch 任何 VMware 二进制文件（那是 Unlocker 的职责，v2.1 明确保留给它）。
- **不** 自动安装/卸载 Unlocker，**不** 下载任何镜像。
- **不** 生成、分发 macOS 恢复镜像、序列号、SMBIOS 真实凭据。
- **不** 面向 Windows 宿主（`.vmx` 语法相同，但路径/调度/检测全部 Linux 专属；Windows 版留待社区贡献）。
- **不** 承诺"提升 X% 性能"——没有基准数据之前只提供有证据的配置项。

### 1.4 与 Unlocker 的分工（不可越界）

| 职责 | Unlocker | macopt |
|---|---|---|
| 修改 VMware 二进制（解锁 darwin guestId、Apple SMC） | ✅ | ❌ 绝不 |
| 附带 darwin.iso（Tools 镜像） | ✅ | 只**检测与引用** |
| 写 `.vmx` 配置 | ❌ | ✅ |
| 写全局偏好 `~/.vmware/preferences` | ❌ | ✅（显式 opt-in） |
| 判定解锁状态 | 自带 `linux/check` | ✅ 五态算法（只读二进制做哈希） |
| 宿主侧 CPU 调度（绑核、cpuset） | ❌ | ✅（只影响自己启动的进程） |
| 运行时验证（读 `vmware.log`） | ❌ | ✅ |

**只读边界**：macopt 对 VMware 安装目录只做 `stat` / `sha256` / 内存映射只读扫描；写操作仅限 §3 的三个目标。

---

## 2. 事实基线（v2.0 十项必改的修正，全部有实测证据）

以下断言在 v2.0 中为错误或不完整，v2.1 以本表为准。证据细节见 `docs/evidence/01-factcheck.md`。

| # | v2.0 断言 | 实测事实 | v2.1 处置 |
|---|---|---|---|
| F1 | 全局偏好文件是 `~/.config/vmware/preferences.ini` | 实际是 **`~/.vmware/preferences`**（无 `.ini`；`~/.config/vmware` 不存在；VMware 日志 `DICT --- USER PREFERENCES` 直接给出路径；二进制含字面量 `~/.vmware/preferences`） | 全部路径改写；并列出完整配置层级（§4.6） |
| F2 | darwin.iso 位于 `/usr/lib/vmware/iso/darwin.iso` | 实际是 **`/usr/lib/vmware/isoimages/darwin.iso`**（前者目录不存在；格式串 `%s/isoimages/%s`） | 检测路径改写，并区分"VMware 内建搜索路径"与 `.vmx` 中手动挂载的 `sata0:1.fileName` |
| F3 | 注入 `mks.g3d.maxTextureSize`、`mks.enableGLRenderer` | 两个 key 在整个 `/usr/lib/vmware` **零命中** | 换成真实 key：`svga.maxTextureSize` / `mks.enableGLBasicRenderer`（§4.9） |
| F4 | 在 preferences 中启用 `mks.*` 即可生效 | 全局层当前**没有任何** `mks.*/ulm.*` 生效项；唯一生效的图形开关是 `.vmx` 里的 `mks.enable3d` | 图形优化下沉到 `.vmx`；`prefs` 模块降为 opt-in |
| F5 | `ethernet0.virtualDev` 是固定 key | 机制是**设备序号化** `ethernet%d.virtualDev` | 动态构造，先探测 ethernet 设备定义 |
| F6 | Unlocker 官方"不包含 AMD 支持" | 4.2.7 `README` 写 `add older (non-Ryzen) AMD CPU support`；4.2.8 写 `add AMD CPU support`，均在 `The Unlocker cannot:` 清单 | 按版本+行号引用，措辞精确化 |
| F7 | "VMware 26H1" 作为产品名 | 实际是 `VMware Workstation Pro 26.0.1 (build 25688693, 26H1u1)`，后者出自 `vixwrapper-product-config.txt` | 统一产品名格式；`26H1u1` 仅作 build tag |
| F8 | Unlocker 检测 = 检查二进制特定字符串偏移量 | patch 仅改 **136 字节**；`libvmwarebase.so` 改 42 字节但 `strings` 零差异 ⇒ 字符串法必漏检；且多个"候选标志串"在**原件中同样存在** | 换为 §4.4 的五态哈希算法 |
| F9 | macOS 只在安装时校验 CPUID、装完可撤掩码 | 无权威来源，反证：社区失败样例每次开机复现 | 删除该论断，改为实测项 T6 |
| F10 | 未区分 Workstation 与 Player | Unlocker README：Player 不会自动拾取 ISO，需手动挂载 | `doctor` 与 `guest-tools` 模块补充 Player 分支 |

**此外必须保留的既有事实**（v2.1 依赖它们）：

- 配置文件格式：`.vmx` 与 `~/.vmware/preferences` 同为 `key = "value"` 平文件（后者首行 `.encoding = "UTF-8"`，无节头）。
- 宿主 CPU：Intel i7-13620H（6P+4E / 16 线程，P=`0-11`，E=`12-15`），单 NUMA 节点。
- `vmware.log` 中 `guest vs. host CPUID` 块证明 **VMware 已经在改写客户机 CPUID**（内置 Darwin 掩码）：无用户掩码时 guest leaf1 已是 `0x000406e3`（Skylake-Y），宿主为 `0x000b06a2`（Raptor Lake）。
- `backup/<version>/*.sha256` 是**双行**结构：第 1 行 = 备份原件哈希，第 2 行 = 打补丁后的运行文件哈希。
- host DMI 主板厂商/产品为 `Default string`（OEM 未填），且日志报 `can't find host SMBIOS entry point` ⇒ **host 反射链路不可用**，身份必须走显式值。

---

## 3. 总体架构

### 3.1 目录结构

```
macopt/
├── LICENSE                     # MIT
├── README.md / README.zh-CN.md
├── CHANGELOG.md
├── pyproject.toml              # 零运行时依赖, console script: macopt
├── .github/workflows/ci.yml    # ruff + unittest + build
├── bin/macopt                  # 无需安装即可运行的启动脚本
├── docs/
│   ├── DESIGN.md               # 本文档
│   └── evidence/               # 脱敏后的评审证据（00-04）
├── scripts/
│   ├── make_fixtures.py        # 从本机 vmware.log 生成脱敏测试 fixture
│   └── sanitize_evidence.py    # 脱敏流水线（可重复执行，幂等）
├── src/macopt/
│   ├── __init__.py  errors.py  model.py  vmxfile.py  context.py   # 契约层
│   ├── cli.py                  # 命令分发
│   ├── doctor.py               # 环境自检
│   ├── unlocker.py             # 五态 Unlocker 检测
│   ├── keys.py                 # key 白名单（运行时扫描 + 种子表）
│   ├── hostinfo.py             # 宿主 CPU/拓扑/cgroup 探测
│   ├── writer.py               # 计划→落盘（幂等三态、事务、锁检查）
│   ├── backup.py               # 时间戳 manifest、history、restore
│   ├── check.py                # 静态检查（只读，不上盘）
│   ├── guestos.py              # guestOS id 映射与守卫
│   ├── verify/                 # 运行时验证
│   │   ├── parser.py           # 解析 vmware.log
│   │   ├── assertions.py       # V0–V10
│   │   └── report.py           # 文本 / JSON 报告
│   ├── profiles/               # 配置生成器
│   │   ├── topology.py  schedule.py  timing.py  gfxnet.py
│   │   ├── cpuid.py     identity.py
│   │   └── __init__.py         # build_all(mapping, host, opts) -> ProfileResult
│   └── data/known_keys.txt     # 白名单种子（附采集来源）
└── tests/
    ├── fixtures/               # 脱敏日志 / 样例 .vmx
    └── test_*.py               # stdlib unittest（CI 里 pytest 亦可跑）
```

### 3.2 分层与依赖方向

```
cli ──► doctor / check / apply / verify / restore / keyscan / schedule / setup
 │
 ├──► profiles/*   (只读 mapping + HostInfo + ProfileOptions → list[Param])
 ├──► keys         (只读二进制 → 白名单)
 ├──► writer       (Plan + Document → 原子落盘)
 ├──► backup       (manifest / history / restore)
 ├──► verify/*     (Document + vmware.log → CheckResult[])
 └──► unlocker / hostinfo   (只读系统状态)

契约层 model / vmxfile / errors / context 被所有模块引用，自身不依赖任何业务模块。
```

**依赖规则**：`profiles/*` 不得 import `cli`/`writer`/`verify`；`verify/*` 不得 import `profiles`。违反即测试失败（CI 中做 import-lint 冒烟）。

### 3.3 数据流（`apply`）

```
vmx 文件 ──Document.load──► mapping ─┐
HostInfo ──detect───────────────────┼──► profiles.build_all ──► list[Param]
ProfileOptions ─────────────────────┘          │
                                               ▼
                              keys.is_known + cpuid/identity 校验规则
                                               │
                                               ▼
                                        Plan (changes/warnings/errors)
                             ┌─────────────┬──┴──────────────┐
                          --dry-run      errors?          正常
                             │             │ exit 5/6       ▼
                          打印表格      拒绝写入     backup.create → writer.apply
                                                     → 打印 manifest → 提示 verify
```

---

## 4. 模块设计

### 4.0 通用契约（`model.py`，已冻结）

```python
Evidence(kind, source, note="")            # kind ∈ log|binary|sysfs|file|doc|measured|community
Param(key, value, module, reason, evidence=(), risk="normal",
      risk_note="", conflicts_with=(), needs_confirmation=False)
Change(key, before, after, op, module="", reason="")   # op ∈ added|modified|unchanged|removed
Plan(changes, params, warnings, errors)     # .effective / .blocking / .counts()
CheckResult(id, title, status, detail="", evidence=())  # status ∈ PASS|FAIL|WARN|SKIP
HostInfo(...)                               # 见源码：vendor/p_cpus/e_cpus/unlocker_state/...
ProfileOptions(...)                         # profile/modules/cpuid_profile/identity/...
ProfileResult(params, warnings, errors)     # .merged(other)
```

**硬规则**：

1. `Param` 没有 `Evidence` 视为实现缺陷；测试对默认配置里的每个 Param 断言 `evidence` 非空。
2. 缺失证据一律 `SKIP`，绝不 `FAIL`——"我们没看到" ≠ "它坏了"。
3. 所有 profile 的函数签名统一为
   `build(mapping: Mapping[str, str], host: HostInfo, opts: ProfileOptions) -> ProfileResult`。

### 4.1 `doctor` — 环境自检

**输入**：无。**输出**：宿主/VMware/Unlocker/配置层级/状态目录的健康摘要（`--json` 全量）。

采集项：`vmware --version` → `(version, build)`；`vixwrapper-product-config.txt` → build tag（形如 `26.0.1 (26H1u1)`）；CPU vendor/拓扑（§4.7）；Unlocker 五态（§4.4）；配置层级（§4.6）；state 目录可写；darwin.iso 是否存在（§4.10）；`.lck` 锁状态。

**失败模式**：VMware 未安装 → `EXIT_UNKNOWN`（不是 FAIL：这台机器可能只是没装）。

### 4.2 `check` — 静态检查（只读）

对一个 `.vmx` 跑全部**不需要开机**的断言，产出 `CheckResult[]`：

| ID | 检查 | 级别 |
|---|---|---|
| S1 | `guestOS` 是否为已知且与日志中真实 guest 匹配 | WARN |
| S2 | `numvcpus` vs 宿主逻辑核/物理核（超配） | WARN |
| S3 | `cpuid.coresPerSocket` 与 `numvcpus` 是否整除一致 | FAIL |
| S4 | `numa.autosize.vcpu.maxPerVirtualNode` vs `numvcpus`（切成多个 vNUMA） | WARN |
| S5 | `vhv.enable=TRUE`（macOS 不支持嵌套虚拟化） | WARN |
| S6 | 身份块互斥违规（同字段既反射又显式，见 §4.11） | FAIL |
| S7 | 任何 `cpuid.*` 掩码 → 跑 §4.8 校验规则 | 视规则 |
| S8 | `tools.syncTime` 与 Tools 可用性（依据日志 `lastInstallError`） | WARN |
| S9 | 重复 key / 无法解析的行 | WARN |
| S10 | 白名单外 key（默认 WARN，`--strict` 升 FAIL） | WARN |

`check` 永不写文件，是 CI 与 pre-commit 的推荐入口。

### 4.3 `setup` — 状态目录初始化

创建 `$XDG_STATE_HOME/macopt/{backups,history,reports,keycache.json}` 与 `$XDG_CONFIG_HOME/macopt/config.toml`（模板）。幂等；`install` 作为废弃别名保留一个次版本周期。

`config.toml` 允许项：`vmware_root`、`backup_roots = []`（Unlocker 备份发现路径）、`vmx_globs = []`（`--all` 扫描模式）。

### 4.4 `unlocker` — 五态检测（替换 v2.0 的字符串偏移法）

```
detect(vmware_root, backup_roots) -> UnlockerStatus
  1. version gate: 解析 `vmware --version` → (26.0.1, 25688693)；拿不到 → UNKNOWN
  2. 定位 backup/<ver>/*.sha256（依次试 build、version、version.major）
  3. 备份自校验: sha256(备份文件) == 文件第1行？ 否 → DAMAGED(backup 自身损坏)
  4. cur = sha256(已安装文件)
       cur == 第1行 → UNPATCHED   # 与原件一致
       cur == 第2行 → PATCHED     # 与记录的补丁后哈希一致
       否则         → UNKNOWN-MODIFIED
  5. 无 backup 目录时降级为"存在性"探测：
       M1 双 marker 同时存在 → 推定 PATCHED（低置信）
       M2..M4 仅有原生 marker → 不能说明任何事
       M5 linux/check 存在 → 提示用户运行（我们不代跑未知脚本）
       全部不成立 → UNKNOWN
  6. 安装文件缺失 → DAMAGED
```

**禁止**：比对字符串偏移量；把"原生也存在"的串当标志；在证据不足时输出 `UNPATCHED/PATCHED`。

实现要点：`.sha256` 为两行 64 位十六进制、无尾换行；逐文件给出 `{file, sha256_installed, sha256_backup, line1, line2, verdict}`；整体状态取各文件的**最弱**结论。发现 `backup_roots` 未配置时按 `config.toml` → CLI `--backup-root`（可重复）→ 无（`UNKNOWN` 并提示）顺序。

### 4.5 `keyscan` / `keys` — key 白名单

**为什么需要**：`.vmx` 里存在大量"存在但无意义/被忽略"的 key；写入一个 VMware 不认识的 key 不会报错，只会**静默无效**——这正是 v2.0 F3 的失败模式。

算法：

```
known_keys() =
   种子表 data/known_keys.txt            # 带来源注释，随版本发布
   ∪ 运行时扫描结果                       # 缓存于 state/keycache.json
扫描 = 对 vmware-vmx{,-debug,-stats}、libvmwarebase.so、mksSandbox 等
       做只读 mmap，按 [A-Za-z0-9_.:\-]{3,64} 抽取 token，
       过滤出形如 `(网卡|svga|mks|numvcpus|cpuid...)` 的候选，
       并显式处理 cpuid 的格式化串：
         cpuid.%x.%s / cpuid.%x.%x.%s / cpuid.%x.%s.amd / cpuid.%x.%x.%s.amd
缓存键 = 各二进制 (path, size, mtime, sha256 前 16 字节)，任一变化即失效
```

`is_known(key) -> bool` 按**固定优先级**判定：

```
0. 黑名单命中 → 拒绝      # 种子表 `# non-existent:` 区，keys.load_nonexistent()
                          # 优先级高于一切正向来源（种子/索引模式/运行时扫描）
1. cpuid 格式化串可展开    # cpuid.<leaf>.<reg> / <leaf>.<subleaf>.<reg> / .amd 变体
2. 种子表 ∪ 扫描缓存       # 精确相等，或 %d/%u/%s 索引模式匹配
其余 → 拒绝；allow_unknown_keys=True 时降级为 WARN
```

> **为什么黑名单必须优先**：二进制里实测存在宽泛模式 `vmotion.%s`，它能匹配"已证实不存在"的 `vmotion.svga.maxTextureSize`，使 `is_known()` 说 True——种子表注释在拒绝、代码在放行。同理 `monitor_control.enable_fullcpuid` 会搭邻居模式的便车。纯散文约定无法阻止这一层，必须由代码强制（`tests/test_keys.py::test_deny_list_beats_a_matching_scan_pattern`）。

> **为什么种子表要收录"VMware 自己写入的 key"**：`pciBridge%d.pciSlotNumber`、`usb_xhci:%d.{present,deviceType,port,parent,speed}`、`sata|scsi|ide %d:%d.redo`、`nvram`、`extendedConfigFile`、`softPowerOff` 这些族由 GUI 内部的格式片段拼装，二进制扫描永远产不出完整 token。不收录它们，**任何一台由 Workstation 自己创建的虚拟机**都会 S10 误报——实测一台 darwin 客户机 132 个 key 中 26 个"白名单外"，全部来自这一族（key **名**收录，值与序列号一概不碰）。

**合规约束**：扫描结果只在**运行时**产生并缓存在用户 state 目录；仓库**不提交**任何从 VMware 二进制导出的字符串转储（专有代码衍生物），只提交人工整理的 key 名单（含注释中的来源出处）。

### 4.6 写入目标与配置层级

层级（低 → 高，后者覆盖前者）：

```
/usr/lib/vmware/settings   (GLOBAL SETTINGS)
/usr/lib/vmware/config     (SITE DEFAULTS)
/etc/vmware/config         (HOST DEFAULTS)
~/.vmware/config           (USER DEFAULTS)
~/.vmware/preferences      (USER PREFERENCES)   ← macopt 允许写的全局层
<vm-dir>/<name>.vmx        (CONFIGURATION)      ← macopt 的主写入目标
```

`prefs` 模块为 **opt-in**（`--module prefs`）：默认关闭（v2.0 的 F4 使然）。写入前对 `~/.vmware/preferences` 做同样格式解析与原子写；**必须先关闭 VMware GUI**，否则 GUI 退出时会整文件回写覆盖我们的修改（这也是为什么 `pref` 层只保留很少的 key）。

### 4.7 `hostinfo` + `schedule` — 宿主 CPU 拓扑与调度（G5 核心）

**探测（四级，逐级降级）**

| 级 | 手段 | 产出 |
|---|---|---|
| L1 | `/sys/devices/cpu_core/cpus`、`/sys/devices/cpu_atom/cpus` | Intel 混合架构的 P/E 逻辑核集 |
| L2 | `/sys/devices/system/cpu/cpu*/topology/{core_id,physical_package_id,thread_siblings_list}` | 同构 CPU 的物理核/线程分组 |
| L3 | `/proc/cpuinfo` 计数 + `lscpu` 兜底 | 核数/线程数/NUMA |
| L4 | cgroup v2：`/sys/fs/cgroup/cgroup.subtree_control` 是否含 `cpuset`；`systemctl --user show -p Delegate` | 用户级 cpuset 是否委派 |

**关键实测结论（进入实现假设，均有证据）**

1. `systemd-run --user --scope -p AllowedCPUs=0-11` 在**未委派 cpuset 的用户单元上静默失效**——命令成功返回，但进程 `Cpus_allowed_list` 仍是 `0-15`。⇒ 绑定必须用**系统级** `systemd-run --scope`（或把任务塞进手工创建的 cgroup），或退回 `taskset`。
2. **校验绑定只能读 `/proc/<pid>/status` 的 `Cpus_allowed_list`**；`systemctl show -p EffectiveCPUs` 在本机返回空。
3. E 核（12–15，上限 3.6 GHz）相对 P 核（4.7–4.9 GHz）单线程慢 40–45% ⇒ 客户机线程落在 E 核上有明显感知代价。

**三档策略**（`--profile`）

| 档 | vCPU | 建议绑定 | 适用 |
|---|---|---|---|
| `performance` | `min(6×2, 逻辑核)`（默认 12） | P 核 0–11 | 桌面交互、单实例 |
| `balanced`（默认） | 保持现有 `numvcpus` | `0-11`（避开 E 核） | 默认推荐 |
| `throughput` | 逻辑核数（16） | 全部 0–15 | 编译/批量 |

**`.vmx` 侧参数（topology 模块）**

| key | 值来源 | 证据/理由 | 风险 |
|---|---|---|---|
| `numvcpus` | 档位或 `--numvcpus` | 宿主 16 逻辑核，核级超配需有意识决策 | 中 |
| `cpuid.coresPerSocket` | `numvcpus ÷ sockets`（默认 1 socket） | 与 `numvcpus` 一致性 = S3 | 中 |
| `numa.autosize.vcpu.maxPerVirtualNode` | ≥ `numvcpus` | 现值 8 + 12 vCPU ⇒ 被切成 8+4 两个 vNUMA，而宿主单节点 | 低 |
| `numa.autosize.cookie` | **删**（改 vCPU 必删） | 否则 `Invalid NUMA cookie` | 低 |
| `vhv.enable` | `FALSE` | macOS 无嵌套虚拟化，却分配了 VHV 页 | 低 |
| `vpmc.enable` | `FALSE` | 虚拟化性能计数器与 *BSD/macOS guest 不兼容（KB 81623/344161） | 低 |
| `hypervisor.cpuid.v0` | `FALSE`（opt-in） | guest leaf1 ECX bit31=1、host=0 ⇒ 客户机确实可见 hypervisor 位；隐藏可能影响 Tools 心跳 | 中 |

**改 vCPU 的硬约束**：`.vmx` 仅在开机时读取 ⇒ 必须 powerOff（非 suspend）+ VMware GUI 关闭 → 改动 → 三重回读（文件 / 日志 `DICT` 段 / `Powering on guestOS '...'`）。

**调度命令**（只影响 macopt 自己启动/指定的进程，不改系统配置）

```
macopt schedule plan   [--profile balanced] [--cpus 0-11]   # 打印可复制的启动/绑定命令
macopt schedule bind   --pid <pid> --cpus 0-11               # 对运行中的 vmware-vmx 生效
macopt schedule check  --pid <pid>                           # 读 /proc/<pid>/status 断言
```

`plan` 输出三条路径并注明优劣：① 系统级 `systemd-run --scope`（cpuset 硬约束，需 polkit/sudo）；② `taskset -c …`（免特权、可对既有进程，但进程可被再次改写）；③ `.desktop` 的 `Exec=taskset …`（无需每次手动）。

### 4.8 `cpuid` — CPUID 伪装模块（高风险，opt-in，带规则引擎）

**默认不生成任何 `cpuid.*` 掩码**（Intel 宿主跑 macOS 本就不需要）。只有 `--cpuid-profile <name>` 时才启用。

#### 4.8.1 必须写进文档与代码注释的机制事实

- **掩码语义是"逐位覆盖"**：`0`/`1` 强制，`-` 保留 VMware 默认，`h` 取宿主位；**不是 AND**。正因如此才能把 `AuthenticAMD` 拼成 `GenuineIntel`。
- 值必须是**完整 32 位**（`0x078BFBFF` 这样的十六进制或 32 字符 `01-h` 串）。
- key 形态（二进制格式串实证）：`cpuid.<leaf>.<reg>`、`cpuid.<leaf>.<subleaf>.<reg>`，以及**优先查询**的 `.amd` 变体。
- 更安全的替代路径：`cpuid.family` / `cpuid.model` / `cpuid.stepping` / `cpuid.brandString`（及 270 个 `cpuid.<FEATURE>` 命名键）——**首选**，位掩码兜底。
- 非默认 leaf 掩码可能需要 `monitor_control.enable_fullcpuid`（社区实践，属 T8 实测项）。
- **VMware 已内置 Darwin 掩码**：即便 `.vmx` 里没有任何 `cpuid.*`，guest leaf1 也已被改为 `0x000406e3`。故真实模型是"内置掩码 → 用户掩码"两层叠加，`cpuid.inhibitDarwinMasks` 的真值语义属 T1 实测项。

#### 4.8.2 校验规则（写入前强制执行）

| 规则 | 条件 | 结果 |
|---|---|---|
| R1 | `cpuid.1.ebx` 被赋予**显式完整值** | **BLOCK**（`EXIT_REFUSED`），除非 `--allow-apic-risk`；提示该值会把 APIC ID 与 `[23:16]` 拓扑写死到每个 vCPU（社区值 `0x02010800` ⇒ APIC=2、max logical=1，而 VMware 自算值是 `0x00100800`） |
| R2 | `cpuid.1.edx` 清除 bit27 (`SS`) | **WARN 升级为 BLOCK**（因 darwin*-64 有 `cpuid.ss:Min:1` 的已知要求），需 `--allow-apic-risk` 同级放行 |
| R3 | `cpuid.1.edx` 清除 bit28 (`HTT`) | WARN：`EBX[23:16]` 拓扑语义失效 |
| R4 | `cpuid.0.eax` 的 max leaf < `0xD` 且同组 profile 声称 AVX/SSE4.2/AES | WARN：leaf 不自洽（`0x0B` 会隐藏 0xD/0x16/0x1F） |
| R5 | `cpuid.1.eax` 解码的 family/model/stepping 与 `cpuid.brandString` 或 profile 名冲突 | FAIL（如 profile 叫 `kabylake-7700k` 却写 `0x00010671`＝Penryn） |
| R6 | vendor 三串（leaf0 EBX/EDX/ECX）不构成合法厂商串 | WARN |
| R7 | 任何 `cpuid.*` key 不在白名单 | BLOCK（§4.5） |
| R8 | Intel 宿主且 profile ≠ `none` | 强制提示"本机不需要伪装"并要求显式确认 |

**位号表（实现必须内嵌，注释注明出处）**：`DS=21, ACPI=22, MMX=23, FXSR=24, SSE=25, SSE2=26, SS=27, HTT=28, TM=29, PBE=31`。据此 `0x078BFBFF` = **保留** MMX/FXSR/SSE/SSE2，**清除** DS/ACPI/SS/HTT/TM/PBE。文档必须同时说明"该值不清 MMX/SSE"，避免旧记法（MMX=22）导致反向理解。

#### 4.8.3 profile 结构

```python
@dataclass
class CpuIdProfile:
    name: str                 # "none" | "penryn" | "kabylake-7700k" | "signed-brand"
    target_vendor: str        # "any" | "GenuineIntel" | "AuthenticAMD"
    params: dict[str, str]    # key -> value（完整 32 位）
    documented_values: dict[str, str]   # 期望在 verify 中观测到的 leaf/reg
    risk: str                 # normal | high
    notes: tuple[str, ...]
```

`none` 为空集（默认）；`signed-brand` 只写 `cpuid.brandString`/`family`/`model`/`stepping`，被标为"首选"。**已知待实测**：`cpuid.family` 等是否为可写 `.vmx` 键（T5）。

### 4.9 `gfxnet` / `timing` — 图形、网络与时钟（修正后）

| 模块 | key | 值 | 证据 |
|---|---|---|---|
| gfxnet | `mks.enable3d` | `TRUE`（已是） | `.vmx` 中唯一生效的 3D 开关 |
| gfxnet | `svga.maxTextureSize` | `16384` | 二进制存在该 key；本机已有 `vmotion.svga.maxTextureSize=16384` |
| gfxnet | `svga.vram0Size` / `svga.autodetect` | 仅在用户显式要求时 | 需实测 |
| gfxnet | `ethernet<N>.virtualDev` | `vmxnet3`（N 由设备探测） | 机制为 `ethernet%d.virtualDev` |
| timing | `tools.syncTime` | `FALSE` 默认保持；`--sync-time` 才置 `TRUE` | 当前 Tools **不可用**（`lastInstallError=21004`、heartbeat timeout）⇒ 置 TRUE 也无效果，必须先修 Tools |
| timing | `hpet0.present` | `TRUE`（保持，禁止改动建议） | guest leaf `0x15`/`0x16` 全 0 ⇒ 客户机拿不到 TSC/频率，只能靠 HPET 自标定 |
| timing | `ulm.disableMitigations` | **不设** | 本机已等效关闭侧信道缓解；加它要注明"仅可信单机"（KB 79832） |

**明确删除**：`mks.g3d.maxTextureSize`、`mks.enableGLRenderer`（不存在）。

### 4.10 `guest-tools` — darwin.iso 与 Tools

- 检测顺序：`.vmx` 中 `sata0:1.fileName` 指向的 ISO（逐个 `sha256` 比对）→ VMware 内建 `/usr/lib/vmware/isoimages/darwin.iso` → Unlocker 自带 ISO。
- 报告三态：`已挂载且匹配` / `已挂载但与内建版不同` / `未挂载`，并给出**手动挂载步骤**；Player 用户必须手动挂载（F10）。
- **只读**：不自动改 `.vmx` 挂载点，不拷贝 ISO。

### 4.11 `identity` — 身份与 SMBIOS（opt-in，互斥规则）

本机证据表明 host 反射链路已断（DMI `Default string`、日志 `can't find host SMBIOS entry point`、`Unable to retrieve host value`），因此设计为：

```
对每个身份字段（board-id / hw.model / serialNumber / smc.version / efi.nvram.var.*）：
  方案 A 反射：  *.reflectHost = TRUE  且 不写显式值
  方案 B 显式：  *.reflectHost = FALSE 且 写显式值
  二者同时出现 → check S6 = FAIL，apply BLOCK
```

- 本机默认走 **B**，显式值必须由用户 `--board-id/--hw-model/--serial` 提供；macopt **不内置**任何序列号。
- 附带建议键：`efi.nvram.var.ROM` / `efi.nvram.var.MLB`（对症 `Unable to retrieve host value`），值同样由用户提供。
- `smc.version` 从 cpuid 模块移入本模块，标 `needs_confirmation=True`（本机 `.vmx` 无此键也能开机）。

### 4.12 `backup` / `writer` — 事务、幂等、回滚

**幂等三态**（每个 key）：

```
文件中不存在            → added     直接写入
文件中值 == 目标值      → unchanged 不做任何事（第二次 apply 应全部落在此态）
文件中值 != 目标值      → modified  属于"覆盖既有取值"，必须显式确认
        确认方式：交互式 y/N，或全局 --yes，或 --force
        非交互且未给 --yes/--force → exit 5 (ConflictError)，不做任何写入
文件中 key 存在但目标是删除（Param.remove=True）→ removed，同样需要确认
```

> 说明：`modified` 不是错误——`apply` 的本职就是改值；exit 5 表达的是"**未经确认地覆盖用户既有取值**"这一意图缺口，而不是格式冲突。`--force` 与 `--yes` 的区别：`--force` 额外放行 `Param.needs_confirmation` 的高危项（例如身份块、`smc.version`），`--yes` 不放行。

**落盘事务**：

```
pre: 目标 VM 未运行（无 <name>.vmx.lck 且无进程 cmdline 命中该 vmx 路径）
     且 VMware GUI 未打开该 VM
     进程扫描跳过**自身 pid 及其全部祖先链**（≤64 跳，读 /proc/<pid>/stat 回溯）：
     `timeout 300 macopt apply <vmx>`、`make`、编辑器运行任务、CI 步骤都会以**相同
     argv** 复制本命令，其 cmdline 同样含 vmx 路径；只跳自身 pid 会把包装进程当成
     "正在运行的虚拟机"，让每一次非交互 apply 都被拒绝（实测）。祖先不可能是待编辑的
     客户机——VMware 不会拉起 macopt。
backup.create() → state/backups/<vm-slug>/<utc-timestamp>-<sha8>/{<name>.vmx, manifest.json}
写入 = Document.set() → write_atomic()（同目录临时文件 + fsync + os.replace + 还原 mode）
post: 回读校验 sha256 与内存渲染一致；写 history.jsonl（append-only）
失败: 任一步异常 → 立即用刚创建的备份 restore → 抛原异常
```

**Document 变更不变式（实现必须满足，测试强制）**

`Entry.lineno` 是**绝对行号**，因此删除一行会让所有**其后**条目的行号过期——方向是"向下失效"，不是"向上"。契约层要求：

1. `delete()` 删除行后必须对所有行号大于被删位置的条目做 **-1 重编号**；重复 key 按行号从大到小依次处理；
2. `set()` 只允许依据**最新**行号写入，任何"删除 → 修改另一 key"的组合都必须落到正确的行；
3. 落盘后 `post` 校验不得只核对**被改动的 key**，必须做**全量交叉核对**：内存中的每个 key 在重新解析后的文件里取值一致、文件里不得出现内存中没有的 key、重复 key 结构不变。

> 起因：2026-09 集成期实测发现，`topology` 的 `cookie` 删除 + `vhv.enable` 修改组合把**未改动的** `vpmc.enable` 行覆盖成了 `vhv.enable = "FALSE"`，而当时只核对被改动 key 的回读校验判定为成功。此缺陷已由 `tests/test_vmxfile.py`（单元）与 `tests/test_apply_e2e.py`（端到端）钉死。

**manifest schema（v1）**

```json
{
  "schema": 1,
  "id": "20260926T101500Z-a1b2c3d4",
  "created_utc": "2026-09-26T10:15:00Z",
  "tool": {"name": "macopt", "version": "0.1.0"},
  "argv": ["macopt", "apply", "<vm-dir>", "--profile", "balanced"],
  "host": {"vmware": "26.0.1", "build": "25688693"},
  "target": {"path": "/…/<name>.vmx"},
  "files": [{"name": "<name>.vmx", "sha256": "…", "mode": "0644", "size": 4096,
             "mtime_ns": 0, "role": "original"}],
  "before": {"sha256": "…", "lines": 137},
  "after":  {"sha256": "…", "lines": 141},
  "changes": [{"key": "vhv.enable", "op": "modified", "before": "TRUE",
               "after": "FALSE", "module": "topology", "reason": "…"}]
}
```

**`restore` 能力**：`--list`（表格：id/时间/diff 数/校验态）、`--diff [id]`（逐 key before→after）、`--to <id>`（回滚，同样走事务 + 先备份当前）、`--verify`（逐备份哈希复核）、`--prune N`（保留最近 N 个）。

### 4.13 `verify` — 运行时验证（G4）

**输入**：虚拟机目录 → 选日志（按 mtime 最新的 `vmware*.log`，`--log` 可覆盖）→ 与 `.vmx` 对账。
**原则**：`check` 只证明"写进去了"；`verify` 证明"真的生效了"。**缺行一律 SKIP，绝不 FAIL**（`guest vs. host CPUID` 是 `-INFO` 级、每次开机仅打印一次）。

| ID | 断言 | 判定 |
|---|---|---|
| V0 | **新鲜度门禁**：log mtime ≥ vmx mtime，否则 `FAIL`（改完没重启）；版本门禁（日志中的 VMware 版本 = 本机版本） | FAIL/SKIP |
| V1 | guest vendor ∈ {GenuineIntel, AuthenticAMD}，与 profile 期望一致 | PASS/FAIL |
| V2 | guest family/model/stepping 解码（如 `0x000406e3` → 6/0x4e/3）与 VMware 自报的 `guest family: 0x… model: 0x…` 行交叉一致；与 profile 的 `documented_values` 对账 | PASS/WARN |
| V3 | leaf1 ECX bit31（hypervisor 位）与 `hypervisor.cpuid.v0` 期望一致 | PASS/WARN |
| V4 | leaf7 EBX bit5（AVX2）与 leaf1 ECX bit27/20/28（SSE4.2/AES/POPCNT）与 profile 期望一致；**OSXSAVE 是动态位，不作 FAIL** | PASS/WARN |
| V5 | APIC 唯一性：日志无 per-vCPU leaf1 时**降级**为 `vmm-vcpus == numvcpus == LocalApic` 三者相等 + 标注"需客户机内逐核复核" | PASS/WARN/SKIP |
| V6 | leaf `0x15`/`0x16` 是否全 0 ⇒ WARN（时钟不可用，提示 HPET/NTP） | PASS/WARN |
| V7 | leaf `0x40000000` = `"VMwareVMware"` | PASS/FAIL |
| V8 | **闭环**：apply 记录的 `documented_values` vs 日志观测的 `guest level …` 寄存器值 | PASS/FAIL/SKIP |
| V9 | `Powering on guestOS '…'` 的 guestOS 与 `.vmx` 一致、且是 `darwin*` 已知档位 | PASS/WARN |
| V10 | 拓扑对账：日志 `LocalApic`/`vmm-vcpus` vs `.vmx` 的 `numvcpus`/`cpuid.coresPerSocket` | PASS/FAIL/SKIP |

**输出**：人读表格 + `--json`（schema 见 §5.2）+ `--save-report <file>`（含行号、原文片段、日志 sha256）+ `--in-guest`（生成只读脚本，输出 `sysctl machdep.cpu.*` 与逐核 CPUID，供人工回填）。
**退出码**：0 全绿（WARN 不算失败，除非 `--strict`）/ 1 有 FAIL / 4 状态不可判定（日志不存在或过旧且无 `--log`）。

### 4.14 `cli` — 命令表

```
macopt setup                          初始化 state/config
macopt doctor      [--json]
macopt check       <vmx|vm-dir> [--strict] [--json]
macopt apply       <vmx|vm-dir> [--profile balanced|performance|throughput]
                   [--module topology,timing,gfxnet,guestos,cpuid,identity,prefs]
                   [--numvcpus N] [--cpus LIST] [--guestos ID]
                   [--cpuid-profile none|penryn|kabylake-7700k|signed-brand]
                   [--sync-time] [--hide-hypervisor-bit] [--identity]
                   [--allow-apic-risk] [--allow-unknown-keys] [--force]
                   [--dry-run] [--yes] [--json]
macopt verify      <vmx|vm-dir> [--log PATH] [--strict] [--save-report F] [--json] [--in-guest]
macopt restore     <vmx|vm-dir> [--list] [--diff [ID]] [--to ID] [--verify] [--prune N]
macopt keyscan     [--refresh] [--json]
macopt unlocker-status [--json] [--backup-root DIR ...]
macopt detect-cpu  [--json]
macopt schedule    plan|bind|check  ...
macopt guest-tools <vmx|vm-dir> [--json]
```

全局选项：`-v/-vv`、`-q`、`--json`、`--yes`、`--dry-run`、`--state-dir`。
`<vm-dir>` 与 `<name>.vmx` 均可，自动解析；`--all --glob 'VMs/*.vmx'` 批处理（串行 + `flock`，单台失败不中断，末尾汇总）。

---

## 5. 数据与接口规范

### 5.1 `apply` 的 JSON 输出（`--json`）

```json
{
  "schema": 1,
  "command": "apply",
  "target": "/…/name.vmx",
  "dry_run": true,
  "host": {"vendor": "GenuineIntel", "vmware_version": "26.0.1", "unlocker_state": "PATCHED"},
  "plan": {"changes": [ {"key": "…", "op": "modified", "before": "…", "after": "…",
                          "module": "topology", "reason": "…"} ],
            "warnings": [], "errors": [], "counts": {"added": 0, "modified": 3, "unchanged": 5, "removed": 0}},
  "backup": {"id": "…", "path": "…"} ,
  "next": "macopt verify '<target>'"
}
```

### 5.2 `verify` 的 JSON 输出

```json
{
  "schema": 1,
  "command": "verify",
  "vmx": "/…/name.vmx",
  "vmx_mtime": "…", "log": "/…/vmware.log", "log_mtime": "…", "fresh": true,
  "vmware": {"version": "26.0.1", "build": "25688693"},
  "assertions": [{"id": "V0", "title": "freshness gate", "status": "PASS",
                   "detail": "log is newer than vmx",
                   "evidence": [{"kind": "log", "source": "vmware.log:1647"}]}],
  "summary": {"pass": 7, "fail": 0, "warn": 2, "skip": 1},
  "exit_code": 0
}
```

### 5.3 稳定性承诺

- `schema` 字段只在破坏性变更时 +1；未知字段必须被忽略。
- 退出码表（§6）与命令名是公共 API，弃用先在 CHANGELOG 标注一个次版本周期。

---

## 6. 错误模型与退出码

| 码 | 名 | 触发 |
|---|---|---|
| 0 | OK | 成功（`verify` 有 WARN 也算 0，除非 `--strict`） |
| 1 | FAIL | 校验存在 FAIL，或操作失败 |
| 2 | USAGE | 参数错误（argparse） |
| 3 | PRECONDITION | VM 运行中 / `.lck` 存在 / 进程占用 / GUI 未关 |
| 4 | UNKNOWN | 无法判定（Unlocker 无备份、日志缺失、VMware 未安装）——**刻意区别于 FAIL** |
| 5 | CONFLICT | 已有值不同且未给 `--force` |
| 6 | REFUSED | key 不在白名单，或 R1/R2/R7 等硬规则拦截 |

所有异常继承 `MacoptError` 并自带 `exit_code`；`cli.main()` 统一映射，未预期异常打印 traceback 且退出 1（`-v` 才显示堆栈）。

---

## 7. 安全、合规与开源要求

1. **只读边界**：对 `/usr/lib/vmware/**` 只 `stat`/哈希/`mmap(PROT_READ)`；代码中出现 `open(..., "w")` 且目标在 VMware 目录 → 单测直接失败。
2. **写入白名单**：目标 `.vmx`、`~/.vmware/preferences`（opt-in）、`$XDG_STATE_HOME/macopt/**`。其余路径一律拒绝。
3. **凭据**：仓库与输出中禁止出现任何密码/token；CI 跑 `scripts/secret_scan.py`（匹配 `sudo.*password`、`BEGIN PRIVATE KEY`、`ghp_`、长随机串）。
4. **不提交专有衍生物**：不提交 `strings` 转储的 VMware 二进制内容、不提交 darwin.iso、不提交任何 VMware 二进制。
5. **脱敏**：`scripts/sanitize_evidence.py` 对 `docs/evidence/*` 与 `tests/fixtures/*` 做幂等脱敏——替换家目录/用户名/主机名/挂载点、VM 显示名、MAC/UUID/序列号、主板 DMI 字符串、磁盘卷标与 ISO 文件名；脱敏后跑 `scripts/secret_scan.py` 必须 0 命中。
6. **fixture 可复现**：`scripts/make_fixtures.py <your-vmware.log>` 让贡献者用自己的日志生成 fixture，仓库内 fixture 仅是脱敏样例。
7. **副作用透明**：`apply` 默认先打印完整 diff 并要求确认（或 `--dry-run`）；`restore` 同样。
8. **无网络**：程序不发起任何网络请求（可单元断言：`socket` 模块未被 import）。
9. **子进程**：仅 `vmware --version`、`taskset`、`systemd-run` 等白名单命令，一律 `subprocess.run([...], check=…)` 列表参数、禁 `shell=True`。
10. **供应链**：零运行时依赖；`pyproject.lock`/hash 不需要；CI 只装 `pytest`/`ruff`。

---

## 8. 测试与验收

### 8.1 测试分层

| 层 | 内容 | 手段 |
|---|---|---|
| 单元 | 解析、解码、位运算、幂等三态、白名单、V0–V10 正则 | `unittest`，纯内存 fixture |
| 契约 | `Param` 必带 Evidence；profile 产出的 key 全在白名单；依赖方向不倒灌 | 单测 |
| 集成 | 对**临时副本** `apply → verify → restore` 全链路 | `tempfile` + 脱敏日志 fixture |
| 快照 | `--json` schema 字段稳定 | `schema` 键断言 |
| 负面 | 坏路径、只读文件、运行中拒绝、未知 key、缺日志 | 单测 |
| 手工 | 需要真开机的部分 | §8.3 清单 |

**绝对禁令**：测试不得修改 `~/VMs`、`/usr/lib/vmware`、`~/.vmware/preferences` 的真实副本；一切写入走 `tempfile.TemporaryDirectory()`。

### 8.2 验收标准（v2.0 的单条 AMD 验收扩为 A–I）

| ID | 场景 | 通过判据 | 本机可自动 |
|---|---|---|---|
| A | AMD 宿主全流程（**保留原验收**） | 掩码注入后 guest vendor=GenuineIntel、macOS 正常启动、`verify` 全绿 | ❌ 需 AMD 机器 |
| B | Intel 宿主非回归 | apply 后不含目标 `cpuid.*` 键集；`check`/`verify` 无 FAIL；开机体感无回退 | ✅ |
| C | 幂等 | 连续两次 apply，第二次 `unchanged==全部`、`changed==0`、文件 sha256 相同 | ✅ |
| D | dry-run | sha256+mtime+行数三重不变，且不产生备份目录 | ✅ |
| E | 回滚 | `restore --to <id>` 后 sha256 与 before 完全一致；`--list/--diff` 输出正确 | ✅ |
| F | 坏输入 | 非 darwin guest / 不存在 / 空文件 / 只读 → 明确退出码、无部分写入 | ✅ |
| G | 白名单 | 未知 key 默认拒绝（exit 6）；`--allow-unknown-keys` 放行且 WARN | ✅ |
| H | 运行中拒绝 | 存在 `.lck` 或进程占用 → exit 3，文件未被触碰 | ✅ |
| I | 无备份新用户 | Unlocker 状态给 `UNKNOWN` + 提示，绝不谎报 | ✅ |

> 注意 B 的措辞：必须是"不含**目标 `cpuid.*` 键集**"，不能是"不含任何 `cpuid.*`"——合法配置里本来就有 `cpuid.coresPerSocket`。

### 8.3 需要真机（人工）的验证

绑定是否真的生效（`Cpus_allowed_list`）、guest 内 `sysctl machdep.cpu.*`、逐核 APIC ID、AVX2 实际可用、30 分钟时钟漂移、体感回归。均可用 `verify --in-guest` 生成的只读脚本半自动化。

### 8.4 CI

`.github/workflows/ci.yml`：`ruff check` → `python -m unittest discover -s tests -v` → `python -m build`（或 `pip install -e .` 后 `macopt --help` 冒烟）→ secret scan → 证据脱敏幂等复核（`sanitize_evidence.py --check`）。矩阵：3.11 / 3.12 / 3.13，`ubuntu-latest`。

---

## 9. 风险登记（17 项）

| ID | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | 注入不存在的 key（v2.0 F3） | 静默无效 | 白名单 + `keyscan` |
| R2 | `cpuid.1.ebx` 硬编码 APIC | 多 vCPU 同 APIC，SMP 异常 | R1 规则 BLOCK |
| R3 | 清 `SS` 违反 darwin 要求 | **开机失败** | R2 规则 BLOCK + T2 |
| R4 | 内置 Darwin 掩码与用户掩码叠加语义未知 | 装饰结果不可预期 | T1 实测 + `verify` 闭环 |
| R5 | 改 `guestOS` 档位改变掩码/Tools 选择 | 行为回归 | V9 + 改动前后 CPUID 对比 |
| R6 | host SMBIOS 反射链路已断 | 拿到 `Default string` | 互斥规则 + 显式值 |
| R7 | GUI 运行时回写覆盖 `.vmx`/preferences | 改动丢失 | precondition 检查 + 关闭 GUI 指引 |
| R8 | 用户级 cpuset 未委派，绑定静默失效 | 性能不达标 | 系统级方案 + `/proc` 校验 |
| R9 | Tools 不可用导致 `syncTime` 无效 | 时钟漂移 | 默认保持 FALSE + V6 WARN |
| R10 | guest 叶 0x15/0x16 全 0 | 时钟自标定退化 | HPET 保留 + NTP 兜底 |
| R11 | 备份被误删/损坏 | 无法回滚 | manifest 双哈希 + `restore --verify` + DAMAGED 态 |
| R12 | 错误判定 Unlocker 状态 | 用户误操作 | 五态 + 证据不足即 UNKNOWN |
| R13 | 无 AMD 硬件，核心场景无法验收 | 核心价值纸面化 | 验收 A 明确标注待外部机器 |
| R14 | 未知的 `cpuid.*`/偏好 key 被后续版本移除 | 升级失效 | 版本门禁 + keycache 失效策略 |
| R15 | 序列号/凭据泄露进仓库 | 合规事故 | 脱敏流水线 + secret scan |
| R16 | 专有字符串转储入库 | 版权风险 | 只提交人工 key 名单 |
| R17 | 改动 numvcpus 未删 NUMA cookie | 启动报错 | 自动删 `numa.autosize.cookie` |

---

## 10. 待实测清单（T1–T8）

> 通用口径：只改**副本**、每次只改一个变量、**必须冷启动**（CPUID 不热更新）、判定读 `guest vs. host CPUID` 的 guest/host diff。

> **已在本机完成的部分**（Intel 宿主，只读套件 + `.vmx` 副本写循环，见 `docs/evidence/06-local-verification.md`）：`check` 对真实 `.vmx` **0 FAIL**（S10 暴露出的 26 项白名单误报已修正，收敛到 1 项即刻意拒绝的 `vmotion.svga.maxTextureSize`）；`verify` 对真实日志 **9 PASS / 1 WARN / 0 FAIL**（V6：guest `0x15`/`0x16` 全零，拿不到频率校准）；`apply → 二次 apply → restore` 在副本上字节级可逆。下表 T1–T8 需要**真实开关机观测 guest 行为**，本机（Intel + 不得改动真实虚拟机）无法替代，仍保持待办。

| # | 问题 | 关键步骤 | 未完成时的限制 |
|---|---|---|---|
| T1 | 用户掩码 vs 内置 Darwin 掩码的覆盖关系；`cpuid.inhibitDarwinMasks` 真值语义 | 三档：不加 / 改 1 位 / `inhibitDarwinMasks=TRUE`，看 guest leaf1 是否从 `0x000406e3` 变回 `0x000b06a2` | 不得声称"掩码模型已知" |
| T2 | `cpuid.1.edx=0x078BFBFF` 是否触发 `Feature 'cpuid.ss' was absent…` | A/B/C 三组（`0x0FABFBFF` / `0x078BFBFF` / `+cpuid.ss="1"`） | R2 规则保持 BLOCK |
| T3 | `cpuid.1.ebx` 是否对每个 vCPU 同值 | 加 `0x02010800` 冷启动，客户机逐核读 leaf1.EBX + `sysctl hw.ncpu hw.physicalcpu` | R1 规则保持 BLOCK |
| T4 | `cpuid.0.eax=0x0B` 后 leaf 0xD/0x16/0x1F 是否消失 | 观察 `guest level 00000000` 的 EAX 与后续 leaf | profile 标注"社区拼装值" |
| T5 | `cpuid.family/model/stepping/brandString` 是否可写；命名键大小写 | 逐个写入并观察 `guest family/…` | `signed-brand` 标"待验" |
| T6 | macOS 校验 CPUID 的时机（安装期 vs 每次启动） | A 装机全程带掩码 / B 装完撤 / C 换掩码 | 删除一切"装完可撤"论断 |
| T7 | AMD 宿主真实效果与 `.amd` 后缀 | 需 AMD 机器；本机可先测 `.amd` 是否被忽略 | 验收 A 保持待办 |
| T8 | `monitor_control.enable_fullcpuid` 对非默认 leaf 是否必需 | 加开关后注入 `cpuid.7.0.ebx` 比对 | 文档保持"可能需要" |

---

## 11. 里程碑

| 批次 | 内容 | 依赖 | 验收 |
|---|---|---|---|
| **B1** 文档 | 本设计文档 + 脱敏证据 + README 双语 | — | 评审通过、secret scan 0 命中 |
| **B2** 读路径与安全网 | `unlocker` 五态、`keys` 白名单、`vmxfile`、`check`、`doctor` | B1 | 验收 F/G/I、单测全绿 |
| **B3** 写路径 | `backup` manifest、`writer` 三态幂等事务、`apply`、`restore` | B2 | 验收 C/D/E/H |
| **B4** 调优模块 | `hostinfo`、`profiles/{topology,schedule,timing,gfxnet,guestos}` | B2 | 验收 B + `detect-cpu` 实测 |
| **B5** 验证闭环 | `verify` V0–V10、`--save-report`、`--in-guest` | B3/B4 | 对既有日志跑出稳定结果 |
| **B6** 高风险模块 | `profiles/{cpuid,identity}` + 规则引擎 R1–R8 | B2 | 验收 G；R1/R2 单测覆盖 |
| **B7** 外部实测 | T1–T8 回填、验收 A（AMD 机器） | 全部 | 更新 §10 状态列 |

**当前批次**：B1–B6（B7 需要外部硬件，文档中保持显式 TODO）。

---

## 12. 附录

### 12.1 CPUID leaf1 关键位（实现内嵌常量的出处）

| bit | 名 | 出处 |
|---|---|---|
| 21 | DS | Intel SDM / Linux `cpufeatures.h` |
| 22 | ACPI | 同上 |
| 23 | MMX | 同上 |
| 24 | FXSR | 同上 |
| 25 | SSE | 同上 |
| 26 | SSE2 | 同上 |
| 27 | SS | 同上（darwin 要求 `cpuid.ss:Min:1`） |
| 28 | HTT | 同上 |
| 29 | TM | 同上 |
| 31 | PBE | 同上 |

leaf1 ECX（**Intel SDM Vol.1 Table 3-5**，2026-09 勘误后）：

| bit | 名 | 出处 |
|---|---|---|
| 0 | SSE3 | Intel SDM |
| 1 | PCLMULQDQ | 同上 |
| 9 | SSSE3 | 同上 |
| 19 | SSE4.1 | 同上 |
| 20 | SSE4.2 | 同上 |
| 23 | POPCNT | 同上 |
| 25 | AES | 同上 |
| 26 | XSAVE | 同上 |
| 27 | OSXSAVE | 同上（动态，取决于 CR4.OSXSAVE，早启动转储常为 0） |
| 28 | AVX | 同上 |
| 31 | HYPERVISOR | 同上 |

leaf7 EBX：bit5 AVX2。
leaf0 EBX/EDX/ECX：厂商串三段（Intel ⇒ `GenuineIntel`）。

> **勘误记录（v2.1 自身引入，已在 B6/B5 批次修正）**
> v2.1 初稿此处写作"bit0 SSE4.2、bit1 POPCNT、bit20 AES"，与 SDM 不符。该错误曾被
> `profiles/cpuid.py` 的 `LEAF1_ECX_BITS` 与 `verify/assertions.py` 的 V4 照抄——
> 后者会把 SSE3 读成 SSE4.2、把 SSE4.2 读成 AES，由于本机实测值 `0xf7fa322b` 的
> bit0/bit20/bit25 恰好全为 1，症状被掩盖。三处均已改为 SDM 位号，并由
> `tests/test_cpuid.py`（表钉死）与 `tests/test_verify_assertions.py`（V4）回归保护。
> 受影响的开放实测项：T1（SSE4.2/AES 声称比对）。

### 12.2 darwin guestId 对照（`guestOS` 档位）

| guestOS | guestId | 对应 macOS |
|---|---|---|
| `darwin22-64` | 0x5072 | macOS 13 |
| `darwin23-64` | 0x5073 | macOS 14 |
| `darwin24-64` | 0x5074 | macOS 15 |
| `darwin25-64` | 0x5075 | macOS 26 |

（来源：`vmware-vmx` 内 `guestId` 表；macopt 只做 `darwin*` 已知档位校验，未知档位 WARN。）

### 12.3 关键路径约定

| 对象 | 路径 |
|---|---|
| 全局偏好 | `~/.vmware/preferences`（同 `.vmx` 格式，首行 `.encoding = "UTF-8"`） |
| VMware 配置层级 | 见 §4.6 |
| 内建 darwin.iso | `/usr/lib/vmware/isoimages/darwin.iso` |
| Unlocker 备份 | `<backup-root>/<version>/*.sha256`（双行） |
| macopt state | `$XDG_STATE_HOME/macopt`（默认 `~/.local/state/macopt`） |
| macopt config | `$XDG_CONFIG_HOME/macopt/config.toml` |
| 测试 fixture | `tests/fixtures/`（脱敏） |

### 12.4 CLI 退出码

见 §6。

---

**文档完。** 实现须与本文档一致；任何偏离先改本文档（含修订记录）再改代码。

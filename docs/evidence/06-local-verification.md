# 本机真实环境验证报告（只读套件 + 隔离写循环）

- 验证人：`macopt` 维护者
- 验证时间：2026-09-26
- 验证环境：
  - 主机：Linux Mint（user `<user>`），Intel 13 代酷睿混合架构（P 核 0–11 / E 核 12–15，16 逻辑核 10 物理核，单 NUMA），内核 `7.3.0-070300rc3-generic`
  - VMware：`VMware Workstation 26.0.1 build 25688693`，安装根 `/usr/lib/vmware`
  - Unlocker 备份根：`/mnt/<media>/DATA/vmware/unlocker427/backup`
  - 真实虚拟机：`/mnt/<media>/DATA/vmware/<vm-name>/{<vm-name>.vmx, vmware.log}`（guestOS `darwin24-64`，`numvcpus=12`）
  - 基线记录：`.vmx` 与 `vmware.log` 的 `路径 + 大小 + mtime` 快照（下称"基线"）

> **只读承诺**：本次验证对 `/mnt/<media>/DATA/vmware/**`、`/usr/lib/vmware/**`、`~/.vmware` **零写入**。所有写入型验证都在 `tempfile` 建的临时副本上进行，结束后删除。

---

## 一、只读验证套件（真实环境）

| # | 命令 | 结果 | 关键输出（已脱敏） |
|---|---|---|---|
| 1 | `macopt doctor` | ✅ | `cpu: Intel … 16 logical / 10 cores, NUMA nodes: 1`；`hybrid: P-cores [0..11] E-cores [12..15]`；`vmware: 26.0.1 build 25688693`；配置五层全部识别（`SITE DEFAULTS`/`HOST DEFAULTS`/`USER PREFERENCES` 各 present，`GLOBAL SETTINGS`/`USER DEFAULTS` absent）；`darwin.iso` 在 `/usr/lib/vmware/isoimages/` present |
| 2 | `macopt unlocker-status --backup-root …/backup` | ✅ | `state: PATCHED  confidence: high`；4 个文件逐个 `PATCHED`（`vmware-vmx`、`-debug`、`-stats`、`libvmwarebase.so`）——**双哈希基线生效后置信度从 low 升到 high** |
| 3 | `macopt detect-cpu` | ✅ | `vendor: GenuineIntel`；`hybrid: True`；P/E 分簇与最大频率（P 4900 / E 3600 MHz）与 `doctor` 一致 |
| 4 | `macopt check <真实 .vmx>` | ✅ | `{'PASS': 5, 'WARN': 5, 'FAIL': 0, 'SKIP': 0}`。WARN 均为真实发现：S2 `numvcpus=12` 超过宿主 10 物理核（1.20x）；S4 `maxPerVirtualNode=8 < numvcpus=12` 而宿主单 NUMA；S5 `vhv.enable=TRUE` 与 macOS 客户机不兼容；S8 Tools 安装错误 `21004`；S10 见第三节 |
| 5 | `macopt verify <真实 .vmx>` | ✅ | `{'PASS': 9, 'FAIL': 0, 'WARN': 1, 'SKIP': 1}`：V0 新鲜度、V1 guest vendor `GenuineIntel`、V2 family/model/stepping 双向自洽（`0x000406e3 → 0x6/0x4e/0x3`，宿主 `0x000b06a2 → 0x6/0xba/0x2`）、V3 hypervisor 位、V4 特征位（SSE4.2/AES/AVX2 全 1，OSXSAVE 记录不判 FAIL）、V5 APIC 数量代理校验、V7……唯一 WARN 是 **V6：guest `0x15`/`0x16` 全零 → 拿不到 TSC/核心频率校准（保留 `hpet0.present`）**；SKIP 为 V8（该 VM 尚无 apply 历史，属预期） |
| 6 | `macopt keyscan --json` | ✅ | 扫描 5 个真实二进制、`scanned: 19950` token、种子 220 条；**暖缓存 0.089 s**（冷跑约 6 s），证明 `state/keycache.json` 在真实二进制上生效 |
| 7 | `macopt schedule plan` | ✅ | 只读规划出 system-level `systemd-run --scope -p AllowedCPUs=0-11`（P 核），并按设计打印"user 级 scope 会静默 no-op"的告警——与本机 cgroup 事实一致 |

**只读承诺证明**：套件跑完后重采基线并 `diff` → 输出为空（`.vmx` 与 `vmware.log` 的路径/大小/mtime 全部一致）。

---

## 二、隔离写循环（真实 `.vmx` 的副本，字节级可逆性）

对真实 `.vmx` **复制到 `tempfile` 目录**后执行（原文件不碰）：

```
1) apply --yes             → 7 行变更：unchanged 2 / modified 2 / removed 1 / added 2
                              （`numa.autosize.vcpu.maxPerVirtualNode` 12→8、
                                `vhv.enable` TRUE→FALSE、`numa.autosize.cookie` 删除、
                                `vpmc.enable`→FALSE、`svga.maxTextureSize`→16384 等）
2) apply --yes 复跑         → counts {'added': 0, 'modified': 0, 'unchanged': 6,
                              'removed': 0}，且文件 hash 不变 ⇒ **幂等**
3) restore --list / --to ID → `verified: True`，`sha256_after` == 原始 `sha256`
4) 比对                     → ✅ 还原后 sha256 与副本初始值**完全一致**（字节级可逆）
```

> 第 1 步特意用 `timeout 300 …` 包装，用于复现并验证第三节的第 ③ 项缺陷。

---

## 三、本机验证发现并修复的缺陷（均已回归测试）

| # | 缺陷 | 现场证据 | 修复 | 回归测试 |
|---|---|---|---|---|
| ① | **S10 误报**：Workstation 自己写入的 26 个 key 不在白名单 | 真实 `.vmx` 132 个 key 中 26 个判"白名单外"（`pciBridge%d.pciSlotNumber`、`usb_xhci:%d.{present,deviceType,port,parent,speed}`、`sata\|scsi\|ide %d:%d.redo`、`nvram`、`extendedConfigFile`、`softPowerOff`）；这些族由 GUI 内部格式片段拼装，二进制扫描产不出完整 token（二进制里只有 `pciBridge%d.present` 等兄弟键） | 种子表新增 `# source:` 区收录该族（只收 **key 名**） | `test_keys_vmware_writes_itself_are_whitelisted`；修后同一 VM 的 S10 由 26 → **1** |
| ② | **黑名单形同虚设**：种子表明写"绝不能进入白名单"，代码却不认 | 实测 `is_known("vmotion.svga.maxTextureSize", extra=扫描缓存) == True`——被二进制里的宽泛模式 `vmotion.%s` 洗白；`monitor_control.enable_fullcpuid` 同样被邻居模式放行 | 种子表改为机器可读 `# non-existent: <key>` 行 → `keys.load_nonexistent()`，且**优先级高于**种子/索引模式/运行时扫描 | `test_deny_list_beats_a_matching_scan_pattern`（含反向：同一模式仍须放行 `vmotion.checkpointFBSize`） |
| ③ | **前置检查把调用者自己的包装进程当成运行中的虚拟机** | `timeout 300 python3 -m macopt.cli apply <vmx>` 被拒：`refusing to edit a running VM: process 575333 references this .vmx`——575333 引用的正是它自己的命令行；只跳过 `own_pid`，`timeout`/`make`/编辑器运行任务/CI 步骤这类以**相同 argv** 复制本命令的祖先进程漏网 ⇒ **每次非交互 apply 都被拒** | `writer._caller_lineage()`：跳过自身 pid **及全部祖先链**（读 `/proc/<pid>/stat` 回溯，≤64 跳，`comm` 含括号/空格时按最后一个 `)` 后解析）；真正的 `vmware-vmx` 进程仍被拒 | `test_caller_wrapper_is_not_mistaken_for_a_running_guest`（同时断言 4242 号真实 VM 进程仍被报）、`test_lineage_stops_on_a_malformed_stat_file` |
| ④ | **`restore` 的 JSON 自相矛盾** | 完成一次真实还原后返回 `"dry_run": false` 且 `"would_restore": true`——JSON 消费方会打印"什么也没做" | 非 dry-run 分支改 `would_restore: false`（预览分支仍为 `true`） | `test_restore_defaults_to_newest_backup`、`test_restore_dry_run_changes_nothing` |

**结论**：只读套件 7/7 通过、写循环 4/4 通过、只读承诺经基线比对成立；本轮 4 个缺陷全部来自"对真实环境真跑一遍"，已修复并被 625 项测试与三道闸门（`ruff` / `secret_scan` / `sanitize_evidence --check` / `guardrails`）覆盖。

**仍未覆盖（需真机）**：验收 A（AMD 全流程）与 T1–T8（需真实开关机观测 guest 行为；本机为 Intel 且不能改动真实虚拟机），见 `docs/DESIGN.md` §10。

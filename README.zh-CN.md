# macopt

[![ci](https://github.com/ltbkq/macopt/actions/workflows/ci.yml/badge.svg)](https://github.com/ltbkq/macopt/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-%E3%89%A53.11-blue.svg)](pyproject.toml)

**面向 Linux 宿主的 VMware Workstation macOS 虚拟机优化工具：可审计、可验证。**

macopt 依据**带证据溯源的配置档案**改写虚拟机 `.vmx`，对已知高危操作
（CPUID 掩码、SMBIOS 反射）设置护栏，为 Intel/AMD 混合架构提供宿主 CPU 调度，
并且——最重要的一点——**通过解析虚拟机监控器自身的开机日志来证明改动真的生效**。

> **其他语言：** [English](README.md)

---

## 为什么需要它

在 Linux 宿主上跑 macOS 虚拟机需要两件互不相干的事：

| 步骤 | 归属 |
|---|---|
| 让 Workstation 接受 `darwin*-64` 与 Apple SMC | **[Unlocker](https://github.com/paolo-projects/unlocker)**（改二进制） |
| 开机之后的一切：拓扑、调度、时钟、身份、验证 | **macopt** |

本项目的 v2.0 设计稿经过四路并行评审，查出**十处事实错误**（不存在的配置 key、
错误的偏好文件路径、脆弱的"字符串偏移量"检测法），并且完全没有覆盖 Intel 宿主
真正需要的 **CPU 拓扑与调度**。这些评审结论被保留为[评审证据](docs/evidence/00-review.md)，
也是本工具"每个参数都必须带出处"这条规矩的由来。

macopt **绝不修改 VMware 二进制**——那是 Unlocker 的职责。

## 功能

- **`macopt doctor`** —— 一键环境报告：宿主 CPU 拓扑（P/E 核）、VMware 构建号、
  Unlocker 状态、配置层级清单。
- **`macopt check`** —— 对 `.vmx` 做**只读**静态分析（S1–S10）：过期的 `guestOS`、
  vCPU 超配、vNUMA 被切分、嵌套虚拟化、身份键互相冲突、白名单外的 key。
- **`macopt apply`** —— 档案驱动、**幂等**、**事务化**写入，支持 `--dry-run`、
  key 白名单与确认门。
- **`macopt verify`** —— 从 `vmware.log` 读取 V0–V10 断言。日志缺行一律降级为
  `SKIP`，**绝不**当成 `FAIL`，保证结论诚实。
- **`macopt restore`** —— 时间戳备份 + 双哈希，`--list` / `--diff` / `--verify` / `--prune`。
- **`macopt unlocker-status`** —— 五态判定（`PATCHED`、`UNPATCHED`、`UNKNOWN`、
  `UNKNOWN-MODIFIED`、`DAMAGED`），依据备份哈希而非脆弱的字符串偏移。
- **`macopt keyscan`** —— 只读扫描已安装二进制构建白名单；默认拒绝未知 key，
  因为 `.vmx` 里的拼写错误是**静默失效**的。
- **`macopt detect-cpu` / `macopt schedule`** —— 四级降级的混合架构 P/E 探测，
  加上绑核方案生成与校验。

## 环境要求

- Linux + VMware Workstation **26.x**（25.x 预计可用；实测 26.0.1）
- Python **≥ 3.11**（**零第三方运行时依赖**）
- 一台已经用 [Unlocker](https://github.com/paolo-projects/unlocker) 解锁过的
  macOS 虚拟机（macopt 只负责检测其状态，不安装、不替代）

## 安装

```bash
python3 -m pip install .        # 从源码安装

bin/macopt --help                # 或者不安装，直接从源码树运行
```

## 快速上手

```bash
macopt doctor                 # 我这是什么环境？Unlocker 在不在？
macopt check    ~/VMs/macOS   # 只读：有哪些问题？
macopt apply    ~/VMs/macOS --dry-run     # 只看计划，不改动
macopt apply    ~/VMs/macOS               # 备份 → 写入 → 回读校验
macopt verify   ~/VMs/macOS               # 启动虚拟机后：改动生效了吗？
macopt restore  ~/VMs/macOS --list        # --diff / --to <id> 回滚
```

> `.vmx` 只在开机时读取：请**关机**（不是挂起）并关闭 VMware 图形界面后再执行
> `apply`。macopt 会强制检查，虚拟机在运行时直接以退出码 `3` 拒绝。

## 安全模型

| 保证 | 手段 |
|---|---|
| 写入边界 | 只写 `<guest>.vmx`、显式开启的 `~/.vmware/preferences`、macopt 自己的状态目录 |
| 不碰二进制 | 对 VMware 安装目录只做 `stat`、哈希与只读扫描 |
| 不留静默拼写错误 | key 不在白名单即拒绝写入（退出码 `6`） |
| 不做意外写入 | 先 `--dry-run`；覆盖既有取值需确认（退出码 `5`） |
| 必可回滚 | 每次写入前都有带时间戳、经哈希校验的备份 |
| 绝不猜测 | 无法判定的状态报 `UNKNOWN`（退出码 `4`），不编造答案 |
| 不联网 | 程序不打开任何 socket（CI 强制检查） |

**退出码**：`0` 成功 · `1` 失败/验证 FAIL · `2` 用法错误 · `3` 前置条件不满足
（虚拟机在运行）· `4` 状态未知 · `5` 需要确认 · `6` key 被拒绝。

## CPUID 护栏

CPUID 掩码是"客户机起不来"的高发区，macopt 默认把它当危险品：

- 档案**默认关闭**（`--cpuid-profile …` 显式开启）；
- `cpuid.1.ebx` 写显式值会被**拦截**——它会把 APIC ID 与线程拓扑写死到每个 vCPU；
- 清除 `SS`（bit 27）会被**拦截**——`darwin*-64` 要求 `cpuid.ss:Min:1`；
- 位号表、掩码语义（**逐位覆盖而非 AND**）、以及"Workstation 自带 Darwin 掩码"
  这一事实，全部写在[设计文档](docs/DESIGN.md)里。

完整分析见 [docs/evidence/02-cpuid-review.md](docs/evidence/02-cpuid-review.md)；
在把任何掩码当生产方案之前，请先完成设计文档里的 T1–T8 实测清单。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | 完整设计（v2.1）：架构、模块契约、算法、风险、验收 |
| [docs/evidence/](docs/evidence/) | 脱敏后的评审证据 |
| [CHANGELOG.md](CHANGELOG.md) | 版本历史 |

## 项目状态

Alpha。读路径（`doctor`/`check`/`unlocker-status`/`verify`）与写路径
（`apply`/`restore`）均已实现并带测试；**AMD 宿主场景（验收 A）**与
**CPUID 实验 T1–T8** 需要本机没有的硬件，已在[设计文档](docs/DESIGN.md)中列为显式待办。

## 参与贡献

```bash
python -m pip install -e ".[dev]"
ruff check src tests scripts
python -m unittest discover -s tests -v
python scripts/secret_scan.py .          # 任何凭据都不得入库
python scripts/sanitize_evidence.py --check
```

提 PR 之前：

1. 每个新增 `Param` 都必须带 `Evidence` 引用——无出处的断言会被测试拒绝；
2. 从你自己的 `vmware.log` 派生的 fixture 要走 `scripts/make_fixtures.py`
   （输出在 git 忽略目录）与 `scripts/sanitize_evidence.py`；
3. 绝不提交本机路径、主机名、序列号、MAC、凭据——CI 会扫描。

## 法务说明

- 采用 MIT 许可（见 [LICENSE](LICENSE)）。
- VMware Workstation 与 macOS 各有自己的许可条款。Apple 的授权允许在
  **Apple 硬件**上虚拟化 macOS；请自行确认你的使用方式合规。本项目不分发
  VMware 代码、macOS 镜像、序列号或 SMBIOS 凭据。
- Unlocker 是独立的第三方项目，有其自己的许可。

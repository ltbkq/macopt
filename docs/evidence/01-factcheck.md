# macOS 虚拟机优化补丁 (macopt) 设计文档 v2.0 — 事实核查报告

- 核查人：subagent（只读核查，未修改任何系统/VM 文件）
- 核查时间：2026-09-25
- 核查环境：
  - 主机：Linux Mint (user `<user>`)，`VMware Workstation 26.0.1 25688693`（`/usr/lib/vmware/bin/vmware --version`）
  - Unlocker：`/mnt/<media>/DATA/vmware/unlocker427`、`/mnt/<media>/DATA/vmware/unlocker428`
  - 备份目录：`/mnt/<media>/DATA/vmware/unlocker427/backup/{17.6.0.24238078,17.6.1,17.6.3,17.6.4,25.0.0,26.0.1}`
  - 测试虚拟机：`/mnt/<media>/DATA/vmware/<vm-name>/`（日志含 4 次运行记录 `vmware.log` / `vmware-0..2.log`）

---

## 一、逐条核查结论表

| # | 文档断言 | 结论 | 证据（命令 + 输出片段） | 建议修改 |
|---|---|---|---|---|
| 1 | 全局偏好文件为 `~/.config/vmware/preferences.ini` | ❌ **错误** | ① `grep -n "USER PREFERENCES" ".../<vm-name>/vmware.log"` →<br>`DICT --- USER PREFERENCES /home/<user>/.vmware/preferences`<br>`DICT --- USER DEFAULTS /home/<user>/.vmware/config`<br>`DICT --- HOST DEFAULTS /etc/vmware/config`<br>`DICT --- SITE DEFAULTS /usr/lib/vmware/config`<br>`DICT --- GLOBAL SETTINGS /usr/lib/vmware/settings`<br>② `ls ~/.config/vmware` → `No such file or directory`；`ls -d ~/.config/vmware*` → 不存在<br>③ `grep -ra -F ".config/vmware" /usr/lib/vmware` → 无输出（0 命中）<br>④ `grep -ra -F "preferences.ini" /usr/lib/vmware` → 无输出（0 命中）<br>⑤ `strings -a /usr/lib/vmware/bin/vmware-vmx \| grep -F ".vmware/preferences"` → `~/.vmware/preferences`<br>⑥ `ls ~/.vmware/*.ini` → `No such file or directory`；`ls ~/.vmware/` → `preferences inventory.vmls shortcuts workstation.log player.log …` | 改为 **`~/.vmware/preferences`（无 `.ini` 后缀，无 `~/.config/` 路径）**。同时应列出完整的配置层次与优先级（低→高）：`GLOBAL SETTINGS /usr/lib/vmware/settings`（本机该文件不存在）→ `SITE DEFAULTS /usr/lib/vmware/config` → `HOST DEFAULTS /etc/vmware/config` → `USER DEFAULTS ~/.vmware/config`（本机不存在）→ `USER PREFERENCES ~/.vmware/preferences` → `CONFIGURATION <VM>.vmx`。<br>补充：`libvmwareui.so` 中还存在 `~/.vmware/preferences-private`（存放凭据类偏好，本机尚未生成）。 |
| 2 | darwin.iso 检测路径为 `/usr/lib/vmware/iso/darwin.iso` | ❌ **错误** | ① `ls /usr/lib/vmware/iso` → `No such file or directory`<br>`ls -la /usr/lib/vmware/isoimages/` → `darwin.iso (3385344, 2023-11-01)`、`darwinPre15.iso`、`windows.iso`、`isoimages_manifest.txt`<br>② 运行时日志（最有说服力）：`grep -n "ToolsISO" ".../<vm-name>/vmware.log"` →<br>`ToolsISO: open of /usr/lib/vmware/isoimages/isoimages_manifest.txt.sig failed …`<br>`ToolsISO: Selected Tools ISO 'darwin.iso' for 'darwin24-64' guest.`<br>`Failed to open … Tools ISO /usr/lib/vmware/isoimages/darwin.iso (Iso9660Result=9).`<br>③ `strings -a /usr/lib/vmware/bin/vmware-vmx \| grep isoimages` → `isoimages_manifest.txt`、**`%s/isoimages/%s`**<br>④ `strings -a /usr/lib/vmware/lib/libvmwarebase.so/libvmwarebase.so \| grep "isoimages\|darwin.iso"` → `darwin.iso`、`%s/isoimages/%s`<br>⑤ 全树 `grep -rl -a isoimages /usr/lib/vmware` → 仅 `bin/vmware-vmx{,-debug,-stats}`、`lib/libvmwarebase.so`、`lib/libvmwareui.so`（格式串 `"%s/isoimages/%s"`，前缀为 libdir=`/usr/lib/vmware`） | 改为 **`/usr/lib/vmware/isoimages/darwin.iso`**（目录名是 `isoimages`，不是 `iso`；`/usr/lib/vmware/iso` 在 VMware 26 中不存在）。<br>另需注意：本机 `<vm-name>.vmx` 里 CD/DVD 指向的是**用户自定义路径** `sata0:1.fileName = "/mnt/<media>/Data1T_Ntfs/iso/isoimages/darwin.iso"`，与 VMware 内建 Tools ISO 搜索路径是两回事，文档应区分"VMware Tools 自动挂载用的内建 ISO 路径"和"`.vmx` 中手动指定的镜像路径"。 |
| 3 | 10 个 config key 在本机 VMware 中真实存在（见下表 3.1） | ⚠️ **部分正确（8/10 存在，2 个不存在）** | 详见下节 **3.1 key 存在性核查表** 与 **3.2 本机实际生效的 mks.*/ulm. 值**。核心命令：<br>`grep -rl -a -F "<key>" /usr/lib/vmware`（全树、含 `bin/`、`lib/`、`modules/`） | 删掉或替换 `mks.g3d.maxTextureSize`、`mks.enableGLRenderer` 两个**不存在**的 key；`ethernet0.virtualDev` 应写成 `ethernetN.virtualDev`（通配形式）。 |
| 4 | "Unlocker 官方明确声明不包含 AMD CPU 支持" | ⚠️ **部分正确（版本间措辞不同，文档未区分）** | ① `unlocker428/README.md:45-47`（`The Unlocker cannot:` 列表内）→ `* add AMD CPU support` —— **4.2.8 确实是笼统的"不支持 AMD"**<br>② `unlocker427/README.md:42-46`（同样在 `The Unlocker cannot:` 列表内）→ `* add older (non-Ryzen) AMD CPU support` —— **4.2.7 只说不能添加"老款（非 Ryzen）AMD CPU"支持，字面上并未否定全部 AMD**<br>③ 两个 CHANGELOG 中 AMD 相关仅 `unlocker4xx/CHANGELOG.md:* Template VMs for Intel and AMD CPUs with sensible defaults …`（是"模板"，不是"CPU 支持声明"） | 建议改成：**"Unlocker 4.2.8 README 的『The Unlocker cannot』清单明确写有 `add AMD CPU support`；4.2.7 同一清单写的是 `add older (non-Ryzen) AMD CPU support`（仅限定老款非 Ryzen 处理器）。两者都是『Unlocker 无法为 macOS 添加其编译代码里本就没有的 CPU 能力』，不能据此断言 Unlocker『声明完全不支持 AMD 平台』。"** 引用时必须标明所依据的版本号与行号。 |
| 5 | 支持 "VMware Workstation 16/17/25/26" 和 "VMware 26H1" | ⚠️ **部分正确（版本来源混装；"26H1" 反而有本机证据）** | ① **官方 README 声明范围只有 16/17**：`unlocker427/README.md:24-27` 与 `unlocker428/README.md:27-30` → `Unlocker 4 is designed for VMware Workstation and Player and has been tested against: * Workstation Pro 16/17 … * Workstation Player 16/17 …`（**未提 25/26**）<br>② **本机实际打过补丁的版本（backup 目录）**：`ls backup/` → `17.6.0.24238078 17.6.1 17.6.3 17.6.4 25.0.0 26.0.1`<br>③ **26.0.1 确实已打补丁（哈希对照）**：<br>  - 当前 `sha256sum /usr/lib/vmware/bin/vmware-vmx` = `e989f645bab9c8944…db8d`<br>  - `backup/26.0.1/vmware-vmx` = `48289dbf9a37dab0…0f54`（原始）<br>  - `backup/26.0.1/vmware-vmx.sha256` 同时记录了这两个哈希<br>  - `stat /usr/lib/vmware/bin/vmware-vmx` → `2026-09-25 06:14:57`（与 backup 时间戳一致）<br>④ **"26H1" 有本机依据**：`/usr/lib/vmware/vixwrapper-product-config.txt:27` → `# Workstation and Player 26.0.1 (26H1u1)`；`strings libvmwareui.so` / `libvmplayer.so` → `26H1u1`<br>⑤ 反面证据：`unlocker428/README.md:92` 用的是 `Version 16/17/25H2 of Workstation Pro`，**全文无 "26H1"**（`grep -ri "26H1" unlocker4xx/` → 0 命中） | 三处分别改写：<br>**a)** "unlocker 官方声明" → 只写 **"Unlocker 4.2.7/4.2.8 README 声明 tested against Workstation Pro/Player 16/17（Windows 与 Linux）"**；<br>**b)** "支持 16/17/25/26" → 拆成"官方声明"与"本机实测"两栏，本机实测写 **"本机 backup 记录显示已对 17.6.0.24238078 / 17.6.1 / 17.6.3 / 17.6.4 / 25.0.0 / 26.0.1 打过补丁"**（无 16.x 记录）；<br>**c)** "VMware 26H1" → **"VMware Workstation Pro 26.0.1（build 25688693，内部标识 26H1u1）"**。可保留 "26H1" 但必须写全为 `26H1u1` 并注明出处是 `vixwrapper-product-config.txt`，不要写成独立产品名 "26H1"。 |
| 6 | （Player 版不会自动识别 darwin.iso） | ✅ **原文确实存在，文档应补 Player 说明** | `unlocker427/README.md` **第 89–90 行**（§2.5 VMware Tools，完整引用）：<br>**"The Unlocker provides the VMware tools ISO images. Version 16/17 of Workstation Pro recognises the darwin.iso files and the tools can be installed in the usual way by using the "Install VMware Tools" menu item. The Player version does not automatically pick up the ISO images and so the ISO must be maually attached to the VM via the guest's settings."**<br>（428 版同一句在 `unlocker428/README.md:92`，区别仅是版本串写成 `Version 16/17/25H2 of Workstation Pro`；`maually` 为上游原文拼写错误） | **需要加 Player 说明**：若文档讨论 darwin.iso 自动挂载/自动安装 VMware Tools，必须注明该自动识别**仅 Workstation Pro**；Player 需在虚拟机设置里手动挂载 ISO。<br>本机安装的是 Workstation（`/etc/vmware/config: product.name = "VMware Workstation"`），不受此限制，但文档面向通用场景应覆盖。 |
| 7 | 要求 Python 3.6+ | ✅ **本机满足（且 Unlocker 本身并不需要 Python）** | ① `python3 --version` → `Python 3.13.7`（`/usr/local/bin/python3 -> python3.13`）<br>② `/usr/bin/python3 --version` → `Python 3.12.3`；`/usr/bin/python --version` → `Python 3.12.3`<br>③ `python3 -c 'import json,os,re,subprocess; print("stdlib ok")'` → `stdlib ok`（可用）<br>④ `file unlocker427/linux/unlock` → `ELF 64-bit … statically linked, Go …`；`unlocker427/README.md` §2.1 → `The code is written in Go and has no pre-requisites and should run directly from the release zip download.` | 若文档的 "Python 3.6+" 指 **macopt 自身脚本**：结论成立，建议写成 **"需要 Python ≥ 3.6（本机为 3.13.7 / 3.12.3，已验证可用）"**。<br>若指 **Unlocker**：应删除该前置条件——Unlocker 4.x 是 Go 静态编译二进制，官方 README 明确 "no pre-requisites"（唯一与 Python 相关的表述是 README 致谢里 "modified the Unlocker code to run on Python 3 in the ESXi 6.5 environment"，指的是历史 ESXi 版本，与本机无关）。 |

---

## 三、第 3 项细化

### 3.1 key 存在性核查表（搜索范围：整个 `/usr/lib/vmware`，`grep -rl -a -F`）

| Key | 结论 | 找到的文件（相对 `/usr/lib/vmware`） | 备注 / 真实同类 key |
|---|---|---|---|
| `ulm.disableMitigations` | ✅ 存在 | `bin/vmware-vmx`、`bin/vmware-vmx-debug`、`bin/vmware-vmx-stats`、`lib/libvmwareui.so/libvmwareui.so` | 上下文：`monitor.allowLegacyCPU` / `monitor.ulm` / `ulm.disableMitigations` |
| `mks.g3d.maxTextureSize` | ❌ **完全找不到** | 无（`grep -ra -F "mks.g3d" /usr/lib/vmware` → 0 命中；大小写不敏感亦 0 命中） | 不存在的 key。真实的纹理尺寸 key 是：`svga.maxTextureSize`、`svga.maxTextureSize16K`、`svga.2DMaxTextureSize8K`（`bin/vmware-vmx`），以及 `.vmx` 里已有的 `vmotion.svga.maxTextureSize = "16384"` |
| `mks.enableGLRenderer` | ❌ **完全找不到** | 无（`grep -ra -F "enableGLRenderer"` → 0 命中） | 真实相邻 key：`mks.enableGLBasicRenderer`、`mks.enableGLPresentation`、`mks.use3dRenderer`、`mks.prefer3dRenderer`、`mks.enableSoftwareRenderer`、`mks.forceRenderer`（均在 `bin/vmware-vmx`） |
| `mks.gl.allowBlacklistedDrivers` | ✅ 存在 | `bin/mksSandbox{,-debug,-stats}`、`bin/vmware-vmx{,-debug,-stats}`、`bin/vmware-remotemks` | 同组还有 `mks.gl.allowSoftwareAndVMwareDrivers`、`mks.gl.allowUnsupportedDrivers` |
| `mks.enableMTLRenderer` | ✅ 存在 | `bin/mksSandbox{,-debug,-stats}`、`bin/vmware-vmx{,-debug,-stats}`、`bin/vmware-remotemks` | 同组：`mks.enableDX11Renderer`、`mks.enableDX12Renderer`、`mks.enableVulkanRenderer`、`mks.enableGLBasicRenderer` 等（**Metal 渲染器是 Windows/Linux 上的无效项，但字符串确实编译进去了**） |
| `smc.version` | ✅ 存在 | `bin/vmware-vmx`、`bin/vmware-vmx-debug`、`bin/vmware-vmx-stats` | 同组：`smc.present`、`AppleSMC`、`smccc.version0101`；`unlocker4xx/linux/unlock` 内也含 `smc.version` |
| `ethernet0.virtualDev` | ❌ 字面量**完全找不到**（⚠️ 但 key 机制存在） | 精确串 `ethernet0.virtualDev` → 0 命中；通配串 `ethernet%d.virtualDev` → `bin/vmware-vmx{,-debug,-stats}`、`bin/vmcli`、`bin/vmrun`、`lib/libvmwarebase.so`、`modules/source/vmnet.tar` | 这是**设备序号化 key**，代码里以 `ethernet%d.virtualDev` 形式存在，`ethernet0.virtualDev` 是实例值。本机 `.vmx:52` 实际生效 `ethernet0.virtualDev = "vmxnet3"` ⇒ key 真实可用，但文档不能说"字面量在二进制里" |
| `svga.vramSize` | ✅ 存在 | `bin/vmware-vmx{,-debug,-stats}`、`bin/vmcli`、`bin/vmrun`、`lib/libvmwarebase.so`、`lib/libvmwareui.so` | 本机 `.vmx:73` → `svga.vramSize = "268435456"` |
| `cpuid.inhibitDarwinMasks` | ✅ 存在 | `bin/vmware-vmx{,-debug,-stats}` | 上下文：`cpuid.%x.%s.amd` / `cpuid.%x.%x.%s` / `cpuid.%x.%s` / **`cpuid.inhibitDarwinMasks`** |
| `hypervisor.cpuid.v0` | ✅ 存在 | `bin/vmware-vmx{,-debug,-stats}`、`bin/vmcli`、`bin/vmrun`、`lib/libvmwarebase.so` | 同组：`hypervisor.cpuid.v1..v5`、`hypervisor.cpuid.v0.vbsBroken` |

> 补充核对：`grep -rl -F "mks.g3d.maxTextureSize" /usr/lib/vmware-installer /usr/bin` → 0 命中（确认不在安装器/系统路径）。

### 3.2 本机实际生效的 `mks.*` / `ulm.*` 值

| 来源 | 文件 | 结果 |
|---|---|---|
| 全局用户偏好 | `~/.vmware/preferences` | **0 条** `mks.*` / `ulm.*`（`grep -c` = 0） |
| 主机级配置 | `/etc/vmware/config` | **0 条**（内容只有 `product.*`、`installerDefaults.*`、`libdir`、`authd.fullpath`、`acceptEULA` 等） |
| 站点级配置 | `/usr/lib/vmware/config` | **0 条**（只有 `tag.*` 帮助主题映射） |
| 用户默认 | `~/.vmware/config` | **文件不存在** |
| 全局设置 | `/usr/lib/vmware/settings` | **文件不存在** |
| 虚拟机配置 | `<vm-name>.vmx` | `mks.enable3d = "TRUE"`（第 105 行）、`svga.vramSize = "268435456"`（73）、`svga.graphicsMemoryKB = "2097152"`（106）、`vmotion.svga.maxTextureSize = "16384"`（110） |
| 运行时确认 | `vmware.log` | `DICT              mks.enable3d = "TRUE"`（第 534 行，位于 `DICT --- CONFIGURATION …/<vm-name>.vmx` 段内）；全 log **无任何 `ulm.*` 条目** |

**结论：本机没有任何 `mks.g3d.*` / `mks.enableGLRenderer` / `ulm.disableMitigations` 之类的偏好设置；唯一实际生效的 mks 开关是 `.vmx` 中的 `mks.enable3d = TRUE`。**

---

## 四、关键命令清单（可复现）

```bash
# 1) 全局偏好路径
grep -n "DICT --- " "/mnt/<media>/DATA/vmware/<vm-name>/vmware.log"
ls -d ~/.config/vmware 2>&1
grep -ra -F ".config/vmware" /usr/lib/vmware | head     # 0 命中
grep -ra -F "preferences.ini" /usr/lib/vmware | head    # 0 命中
strings -a /usr/lib/vmware/bin/vmware-vmx | grep -F ".vmware/preferences"   # ~/.vmware/preferences

# 2) darwin.iso 路径
ls -la /usr/lib/vmware/iso /usr/lib/vmware/isoimages
grep -n "ToolsISO" "/mnt/<media>/DATA/vmware/<vm-name>/vmware.log" | head
strings -a /usr/lib/vmware/bin/vmware-vmx | grep isoimages     # %s/isoimages/%s
strings -a /usr/lib/vmware/lib/libvmwarebase.so/libvmwarebase.so | grep isoimages

# 3) key 全树核查
cd /usr/lib/vmware && for k in ulm.disableMitigations mks.g3d.maxTextureSize \
  mks.enableGLRenderer mks.gl.allowBlacklistedDrivers mks.enableMTLRenderer \
  smc.version "ethernet0.virtualDev" "ethernet%d.virtualDev" svga.vramSize \
  cpuid.inhibitDarwinMasks hypervisor.cpuid.v0; do
  printf '%-32s : ' "$k"; grep -rl -a -F "$k" . 2>/dev/null | tr '\n' ' '; echo; done
grep -c "mks\.\|ulm\." ~/.vmware/preferences /etc/vmware/config /usr/lib/vmware/config   # 均为 0

# 4/5/6) Unlocker 文档
grep -n -i "amd\|ryzen" /mnt/<media>/DATA/vmware/unlocker42{7,8}/README.md
sed -n '42,50p' /mnt/<media>/DATA/vmware/unlocker427/README.md      # The Unlocker cannot: …
sed -n '88,91p' /mnt/<media>/DATA/vmware/unlocker427/README.md      # Player 那句原文
ls /mnt/<media>/DATA/vmware/unlocker427/backup/                     # 实测打过补丁的版本
sha256sum /usr/lib/vmware/bin/vmware-vmx \
  /mnt/<media>/DATA/vmware/unlocker427/backup/26.0.1/vmware-vmx
grep -n "26H1" /usr/lib/vmware/vixwrapper-product-config.txt       # 26.0.1 (26H1u1)

# 7) Python
python3 --version; /usr/bin/python3 --version
python3 -c 'import json,os,re,subprocess; print("stdlib ok")'
```

---

## 五、汇总（按严重度）

| 严重度 | 条目 |
|---|---|
| ❌ 必须改 | #1 全局偏好路径（`~/.config/vmware/preferences.ini` → `~/.vmware/preferences`）<br>#2 darwin.iso 路径（`/usr/lib/vmware/iso/` → `/usr/lib/vmware/isoimages/`）<br>#3 中的 `mks.g3d.maxTextureSize`、`mks.enableGLRenderer`（本机全树不存在，须删除或替换） |
| ⚠️ 需要澄清 | #3 `ethernet0.virtualDev` 应写成 `ethernet%d.virtualDev`（实例 key，机制存在）<br>#4 AMD 说法需区分 4.2.7 / 4.2.8 措辞并引用原文<br>#5 "16/17/25/26" 须拆成"官方声明"与"本机 backup 实测"；"26H1" → `26.0.1 (build 25688693, 26H1u1)` |
| ✅ 需要补充 | #6 补 Player 版 darwin.iso 不自动识别的说明（引 427 README:89-90 原文）<br>#7 Python 3.6+ 本机满足（3.13.7/3.12.3）；若指 Unlocker 则应去掉该依赖（Go 静态二进制） |

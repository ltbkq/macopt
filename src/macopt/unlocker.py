"""Five-state Unlocker detection (DESIGN §4.4, docs/evidence/04 §2).

macopt never patches VMware binaries and never guesses: when the evidence is
insufficient the answer is ``UNKNOWN``, not a coin flip between
``PATCHED``/``UNPATCHED``.

Algorithm
---------
1. **Version gate** — read the installed version from
   ``<vmware_root>/vixwrapper-product-config.txt`` (a plain text file; no
   subprocess, no ``vmware --version``). An explicit ``version`` argument
   overrides it. Version unknown → we only fall back to a single/unnamed
   baseline candidate.
2. **Locate baseline** — ``<backup_root>/<ver>/*.sha256`` (tries exact version,
   then ``<major>.*``; with no version hint it evaluates candidates newest
   first and only keeps a decisive one).
3. **Backup self-check** — ``sha256(backup/<ver>/<file>) == line 1`` of the
   ``.sha256`` file. Mismatch → ``DAMAGED``: the baseline itself is not
   trustworthy, refuse to reason further (and refuse ``restore``).
4. **Compare installed hash** with line 1 (pristine original) and line 2
   (recorded post-patch hash) → ``UNPATCHED`` / ``PATCHED`` /
   ``UNKNOWN-MODIFIED``.
5. **No baseline** → degrade to *existence* probing (never offsets): both
   patch-introduced markers present → ``PATCHED`` (low confidence), anything
   less → ``UNKNOWN`` plus a hint pointing at the Unlocker's own
   ``linux/check`` (we only report that it exists — **macopt never executes
   it**).
6. Installed file missing while a baseline tracks it → ``DAMAGED``.

Prohibited by design (DESIGN §4.4): comparing *string offsets*; treating a
string that exists in pristine binaries as a patch flag (five such candidates
were falsified in docs/evidence/04 §0.3); executing any script.
"""

from __future__ import annotations

import hashlib
import mmap
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "DAMAGED",
    "MARKER_A",
    "MARKER_B",
    "MISSING",
    "PATCHED",
    "STATES",
    "UNKNOWN",
    "UNKNOWN_MODIFIED",
    "UNPATCHED",
    "FileVerdict",
    "UnlockerStatus",
    "detect",
]

# --------------------------------------------------------------------------- #
# States
# --------------------------------------------------------------------------- #

PATCHED = "PATCHED"
UNPATCHED = "UNPATCHED"
UNKNOWN = "UNKNOWN"
UNKNOWN_MODIFIED = "UNKNOWN-MODIFIED"
DAMAGED = "DAMAGED"

#: Overall states (the public contract).
STATES: tuple[str, ...] = (PATCHED, UNPATCHED, UNKNOWN, UNKNOWN_MODIFIED, DAMAGED)

#: File-level only: the baseline tracks this file but it is not installed.
MISSING = "MISSING"

_CONFIDENCE = {
    PATCHED: "high",  # sha256 == recorded post-patch hash, baseline self-checked
    UNPATCHED: "high",  # sha256 == pristine original
    UNKNOWN_MODIFIED: "medium",  # differs from both — we know *that*, not *what*
    DAMAGED: "high",  # baseline (or install) demonstrably broken
    UNKNOWN: "none",  # nothing to compare against
}

# Patch-introduced marker pair (existence only, never offsets). Both strings
# are absent from pristine binaries and appear twice in patched ones —
# measured in docs/evidence/04-verify-acceptance.md §0.3. They come from the
# Unlocker's own patch payload, not from a macopt-authored dump.
MARKER_A = b"ourhardworkbythesewordsguardedpl"
MARKER_B = b"easedontsteal(c)AppleComputerInc"

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_VERSION_DIR_RE = re.compile(r"^\d+\.\d+")
_VERSION_HINT_RE = re.compile(r"Workstation and Player (\d+\.\d+\.\d+)")
_WS_PRODUCT_RE = re.compile(r"^ws\s+\d+\s+\w+\s+(\d+\.\d+\.\d+)", re.MULTILINE)

_HASH_CHUNK = 1024 * 1024


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


@dataclass
class FileVerdict:
    """Per-file evidence: the three hashes we know plus the conclusion."""

    file: str
    sha256_installed: str | None
    sha256_backup_line1: str | None
    sha256_backup_line2: str | None
    verdict: str

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "sha256_installed": self.sha256_installed,
            "sha256_backup_line1": self.sha256_backup_line1,
            "sha256_backup_line2": self.sha256_backup_line2,
            "verdict": self.verdict,
        }


@dataclass
class UnlockerStatus:
    """Aggregate verdict (weakest conclusion wins) plus how sure we are."""

    state: str
    confidence: str
    files: list[FileVerdict] = field(default_factory=list)
    backup_root: str | None = None
    hints: list[str] = field(default_factory=list)

    @property
    def definitive(self) -> bool:
        """True when the answer rests on a hash baseline (not on probing)."""
        return self.confidence in ("high", "medium")

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "confidence": self.confidence,
            "files": [f.to_dict() for f in self.files],
            "backup_root": self.backup_root,
            "hints": list(self.hints),
        }


# --------------------------------------------------------------------------- #
# Primitives (all read-only)
# --------------------------------------------------------------------------- #


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_sha256_file(path: Path) -> tuple[str | None, str | None, str | None]:
    """Parse a ``.sha256`` file.

    Real layout (docs/evidence/04 §0.2): exactly two 64-hex lines, no trailing
    newline — line 1 = pristine backup hash, line 2 = post-patch hash. A
    hypothetical single-line format is accepted (line 1 only, line 2 = None)
    so a future Unlocker change degrades instead of crashing (risk R2 there).
    Returns ``(line1, line2, problem)``.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, None, f"cannot read: {exc}"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    good = [ln for ln in lines if _HEX64.match(ln)]
    if not good:
        return None, None, "no 64-hex line found"
    if len(lines) > 2:
        return good[0], good[1] if len(good) > 1 else None, f"expected 1-2 lines, found {len(lines)}"
    return good[0], (good[1] if len(good) > 1 else None), None


def _installed_candidates(vmware_root: Path, name: str) -> list[Path]:
    """Where a backed-up file lives after installation.

    ``vmware-vmx*`` → ``bin/``; shared libraries are installed as
    ``lib/<libname>/<libname>`` (observed: ``lib/libvmwarebase.so/libvmwarebase.so``).
    """
    return [
        vmware_root / "bin" / name,
        vmware_root / "lib" / name / name,
        vmware_root / "lib" / name,
        vmware_root / "lib64" / name / name,
        vmware_root / name,
    ]


def _version_dirs(backup_roots: Sequence[str | Path]) -> list[Path]:
    """``<root>/<version>/`` directories that actually hold ``*.sha256`` files."""
    found: list[Path] = []
    for raw in backup_roots:
        root = Path(raw)
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for child in children:
            try:
                if not child.is_dir() or not _VERSION_DIR_RE.match(child.name):
                    continue
                if any(child.glob("*.sha256")):
                    found.append(child)
            except OSError:
                continue
    return found


def _installed_version(vmware_root: Path) -> str | None:
    """Version gate without running anything (DESIGN §7.9 subprocess allowlist

    exists, but detection must stay usable in tests and on stripped installs,
    so we parse a text file instead of spawning ``vmware --version``).
    """
    cfg = vmware_root / "vixwrapper-product-config.txt"
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _VERSION_HINT_RE.search(text) or _WS_PRODUCT_RE.search(text)
    return match.group(1) if match else None


# --------------------------------------------------------------------------- #
# Per-file and aggregate judgement
# --------------------------------------------------------------------------- #


def _judge(ver_dir: Path, vmware_root: Path) -> tuple[list[FileVerdict], list[str]]:
    verdicts: list[FileVerdict] = []
    notes: list[str] = []

    for sha_path in sorted(ver_dir.glob("*.sha256")):
        name = sha_path.name[: -len(".sha256")]
        candidates = _installed_candidates(vmware_root, name)
        installed = next((p for p in candidates if p.is_file()), None)
        report_path = str(installed) if installed is not None else str(candidates[0])
        line1, line2, problem = _parse_sha256_file(sha_path)

        if problem or line1 is None:
            verdicts.append(FileVerdict(report_path, None, line1, line2, UNKNOWN))
            notes.append(f"{sha_path.name}: {problem or 'baseline unreadable'}")
            continue
        line1 = line1.lower()
        line2 = line2.lower() if line2 else None

        # step 3 — the baseline must vouch for itself first
        backup_file = ver_dir / name
        if backup_file.is_file():
            if _sha256_file(backup_file) != line1:
                verdicts.append(FileVerdict(report_path, None, line1, line2, DAMAGED))
                notes.append(
                    f"{name}: sha256(backup) != .sha256 line 1 —— 备份自校验失败，基线不可信，请勿 restore"
                )
                continue
        else:
            notes.append(f"{name}: 备份副本缺失（{backup_file}），跳过自校验，仅以 .sha256 第 1 行为基线")

        # step 6 — install missing
        if installed is None:
            verdicts.append(FileVerdict(report_path, None, line1, line2, MISSING))
            notes.append(f"{name}: 基线记录了该文件，但安装位置没有它 → 安装可能不完整")
            continue

        current = _sha256_file(installed)
        if current == line1:
            verdict = UNPATCHED
        elif line2 is not None and current == line2:
            verdict = PATCHED
        else:
            verdict = UNKNOWN_MODIFIED
        verdicts.append(FileVerdict(report_path, current, line1, line2, verdict))

    return verdicts, notes


def _aggregate(verdicts: list[FileVerdict]) -> str | None:
    """Weakest conclusion wins (DESIGN §4.4 step 4/6)."""
    values = [v.verdict for v in verdicts]
    if not values:
        return None
    if any(v in (DAMAGED, MISSING) for v in values):
        return DAMAGED
    if any(v == UNKNOWN for v in values):
        return UNKNOWN
    if any(v == UNKNOWN_MODIFIED for v in values):
        return UNKNOWN_MODIFIED
    if all(v == PATCHED for v in values):
        return PATCHED
    if all(v == UNPATCHED for v in values):
        return UNPATCHED
    return UNKNOWN_MODIFIED  # half patched / half pristine — inconsistent


# --------------------------------------------------------------------------- #
# Fallback: existence probing (no baseline)
# --------------------------------------------------------------------------- #


def _marker_probe(vmware_root: Path) -> tuple[bool, Path | None, str | None]:
    for rel in ("bin/vmware-vmx", "bin/vmware-vmx-debug"):
        path = vmware_root / rel
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as handle:
                mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            return False, path, f"无法只读映射 {path}"
        with mm:
            found = mm.find(MARKER_A) >= 0 and mm.find(MARKER_B) >= 0
        return found, path, None
    return False, None, None


def _check_script_hint(backup_roots: Sequence[str | Path]) -> str | None:
    """Report that the Unlocker's own ``linux/check`` exists — never run it."""
    for raw in backup_roots:
        root = Path(raw)
        for candidate in (root.parent / "linux" / "check", root / "linux" / "check"):
            if candidate.is_file():
                return (
                    f"检测到 Unlocker 自带 {candidate}（macopt 只报告存在，绝不代跑脚本；"
                    "如需权威判定请自行 sudo 执行）"
                )
    return None


def _fallback(vmware_root: Path, backup_roots: Sequence[str | Path], notes: list[str]) -> UnlockerStatus:
    hints = list(notes)
    if not backup_roots:
        hints.append("未配置 Unlocker 备份根（config.toml 的 backup_roots 或 --backup-root），无法建立哈希基线")
    else:
        roots = ", ".join(str(Path(r)) for r in backup_roots)
        hints.append(f"在 {roots} 下没有 <version>/*.sha256 基线，降级为存在性探测")

    check_hint = _check_script_hint(backup_roots)
    if check_hint:
        hints.append(check_hint)

    if not vmware_root.exists():
        hints.append(f"VMware 安装目录不存在: {vmware_root}（VMware 未安装？）")
        return UnlockerStatus(UNKNOWN, "none", [], None, hints)

    marked, probe, err = _marker_probe(vmware_root)
    if err:
        hints.append(err)
    if probe is None:
        hints.append("找不到 bin/vmware-vmx，无法做存在性探测")
        return UnlockerStatus(UNKNOWN, "none", [], None, hints)

    if marked:
        # M1: both patch-introduced markers, existence only.
        hints.append(
            f"仅凭补丁新增字符串的*存在性*推断（{probe.name} 含双 marker，M1，低置信）；"
            "字符串偏移量一律不比对，原生即存在的串一律不作为标志"
        )
        verdict = FileVerdict(str(probe), None, None, None, UNKNOWN)
        # no hash baseline: report the state but say so honestly
        return UnlockerStatus(PATCHED, "low", [verdict], None, hints)

    hints.append(
        "无哈希基线且补丁 marker 未命中：既不能判 PATCHED 也不能判 UNPATCHED（不撒谎 → UNKNOWN）"
    )
    return UnlockerStatus(
        UNKNOWN, "none", [FileVerdict(str(probe), None, None, None, UNKNOWN)], None, hints
    )


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def detect(
    vmware_root: str | Path = "/usr/lib/vmware",
    backup_roots: Sequence[str | Path] = (),
    *,
    version: str | None = None,
) -> UnlockerStatus:
    """Classify the installed VMware build as one of :data:`STATES`.

    ``backup_roots`` are Unlocker backup roots (``<unlocker>/backup``). The
    caller resolves configuration (``config.toml`` → ``--backup-root``); this
    function only reads: ``stat`` / ``sha256`` / ``mmap(PROT_READ)``. It does
    not import ``subprocess`` and does not execute anything — including the
    Unlocker's ``linux/check``.
    """
    root = Path(vmware_root)
    notes: list[str] = []

    if not root.exists():
        return UnlockerStatus(
            UNKNOWN,
            "none",
            [],
            None,
            [f"VMware 安装目录不存在: {root}", "没有可比对的安装文件，无法判定（这不是 FAIL）"],
        )

    candidates = _version_dirs(backup_roots)
    if not candidates:
        return _fallback(root, backup_roots, notes)

    hint = version or _installed_version(root)
    if hint:
        exact = [d for d in candidates if d.name == hint]
        if not exact:
            major = hint.split(".")[0]
            exact = [d for d in candidates if d.name.split(".")[0] == major]
        if not exact:
            return _fallback(
                root,
                backup_roots,
                [f"本机版本 {hint}，但备份根里没有 {hint} / {major}.* 的基线（其余版本的哈希不可比对）"],
            )
        ordered = exact
    else:
        ordered = sorted(candidates, key=lambda p: p.name, reverse=True)
        notes.append("未能确定本机 VMware 版本（vixwrapper-product-config.txt 缺失或未给 version=）")

    chosen: tuple[Path, list[FileVerdict], list[str]] | None = None
    pending: tuple[Path, list[FileVerdict], list[str]] | None = None
    for ver_dir in ordered:
        verdicts, file_notes = _judge(ver_dir, root)
        if not verdicts:
            continue
        decisive = any(v.verdict != UNKNOWN for v in verdicts)
        if decisive:
            chosen = (ver_dir, verdicts, file_notes)
            break
        if pending is None:
            pending = (ver_dir, verdicts, file_notes)

    if chosen is None:
        if pending is None:
            return _fallback(root, backup_roots, notes)
        chosen = pending
        notes.append("所有候选基线都无法与已安装文件对上（版本可能已漂移），结论基于首个候选，置信度下降")

    ver_dir, verdicts, file_notes = chosen
    state = _aggregate(verdicts)
    if state is None:
        return _fallback(root, backup_roots, notes)

    hints = notes + file_notes
    if hint and ver_dir.name != hint:
        hints.append(f"基线版本 {ver_dir.name} 与本机版本 {hint} 不完全一致")
    if state == UNKNOWN_MODIFIED:
        hints.append(
            "与原件/已知补丁态都不一致：可能被其他补丁工具或 VMware 升级改写过，"
            "建议从安装包重装后再由 Unlocker 打补丁"
        )
    if state == UNPATCHED:
        hints.append("与备份原件一致 → 未打补丁，macOS 客户机将无法启动 Apple SMC（请运行 Unlocker 的 unlock）")
    if state == DAMAGED:
        hints.append("备份或安装文件损坏：请勿执行 restore，先重跑 Unlocker 或从安装包还原")

    return UnlockerStatus(
        state,
        _CONFIDENCE[state],
        verdicts,
        str(ver_dir),
        hints,
    )

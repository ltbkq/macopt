"""Unit tests for the five-state Unlocker detection (DESIGN §4.4, §4.5).

All five states are exercised against synthetic, hash-consistent fixtures —
PATCHED / UNPATCHED / UNKNOWN-MODIFIED / DAMAGED / UNKNOWN — plus the two
fallback sub-cases (marker-based PATCHED with low confidence, and "no evidence
at all").

Two hard guarantees are asserted here:

* the ``.sha256`` baseline is the **two-line** structure measured on the
  reference host (64 hex, LF, 64 hex, no trailing newline = 129 bytes);
* **no script ever runs**: the Unlocker's own ``linux/check`` may sit next to
  the backup root, and detection only reports that it exists. ``subprocess``
  is patched to explode for the duration of every ``detect()`` call.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from macopt import unlocker

ORIGINAL = b"ORIGINAL vmware-vmx payload\n" * 8
PATCHED = ORIGINAL + b"\x00PATCH\x00the unlocker's 136 added bytes\n"
OTHER = b"some third-party modified build\n"

BINARY_NAMES = ("vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats")
LIB_NAME = "libvmwarebase.so"
ALL_NAMES = BINARY_NAMES + (LIB_NAME,)

VERSION_CONFIG = "# Workstation and Player 26.0.1 (26H1u1)\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class UnlockerFixture(unittest.TestCase):
    """Builds a fake ``/usr/lib/vmware`` + fake Unlocker backup tree."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="macopt-unlocker-")
        self.root = Path(self._tmp.name)
        self.vmware = self.root / "vmware"
        (self.vmware / "bin").mkdir(parents=True)
        (self.vmware / "lib" / LIB_NAME).mkdir(parents=True)
        (self.vmware / "vixwrapper-product-config.txt").write_text(
            VERSION_CONFIG, encoding="utf-8"
        )
        self.backup_root = self.root / "unlocker" / "backup"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- fixtures ---------------------------------------------------------- #

    def install(self, data: bytes) -> None:
        for name in BINARY_NAMES:
            (self.vmware / "bin" / name).write_bytes(data)
        (self.vmware / "lib" / LIB_NAME / LIB_NAME).write_bytes(data)

    def install_all_but(self, missing: str) -> None:
        self.install(ORIGINAL)
        if missing in BINARY_NAMES:
            (self.vmware / "bin" / missing).unlink()
        else:
            (self.vmware / "lib" / LIB_NAME / LIB_NAME).unlink()

    def baseline(
        self,
        version: str = "26.0.1",
        *,
        backup_data: bytes = ORIGINAL,
        second_line: str | None = None,
        single_line: bool = False,
    ) -> Path:
        """Write ``<backup>/<version>/<file>`` + its two-line ``.sha256``."""
        ver_dir = self.backup_root / version
        ver_dir.mkdir(parents=True, exist_ok=True)
        second = sha(PATCHED) if second_line is None else second_line
        for name in ALL_NAMES:
            (ver_dir / name).write_bytes(backup_data)
            text = sha(backup_data) if single_line else f"{sha(backup_data)}\n{second}"
            # real files carry no trailing newline (04-verify-acceptance §0.2)
            (ver_dir / f"{name}.sha256").write_bytes(text.encode("ascii"))
        return ver_dir

    def corrupt_backup(self, version: str = "26.0.1") -> None:
        """Break the baseline's self-check: backup bytes ≠ .sha256 line 1."""
        (self.backup_root / version / BINARY_NAMES[0]).write_bytes(b"corrupted baseline\n")

    def detect(self, **kwargs) -> unlocker.UnlockerStatus:
        return unlocker.detect(self.vmware, [self.backup_root], **kwargs)

    # -- assertions shared by several states -------------------------------- #

    def assertEveryFileDecided(self, status: unlocker.UnlockerStatus) -> None:
        self.assertEqual(len(status.files), len(ALL_NAMES))
        for verdict in status.files:
            with self.subTest(file=verdict.file):
                self.assertNotEqual(verdict.verdict, unlocker.UNKNOWN)
                self.assertTrue(verdict.sha256_backup_line1)


class TwoLineBaselineTests(UnlockerFixture):
    def test_sha256_files_use_the_measured_two_line_layout(self) -> None:
        ver_dir = self.baseline()
        raw = (ver_dir / f"{BINARY_NAMES[0]}.sha256").read_bytes()
        self.assertEqual(len(raw), 129, "64 hex + LF + 64 hex, no trailing newline")
        line1, line2 = raw.decode("ascii").split("\n")
        self.assertEqual(line1, sha(ORIGINAL))
        self.assertEqual(line2, sha(PATCHED))
        self.assertNotEqual(line1, line2)

    def test_single_line_baseline_degrades_instead_of_crashing(self) -> None:
        self.baseline(single_line=True)
        self.install(ORIGINAL)
        status = self.detect()
        self.assertEqual(status.state, unlocker.UNPATCHED)
        for verdict in status.files:
            self.assertIsNone(verdict.sha256_backup_line2)
        # a *patched* install against a single-line baseline must not be
        # reported as PATCHED: line 2 is what would prove it.
        self.install(PATCHED)
        self.assertEqual(self.detect().state, unlocker.UNKNOWN_MODIFIED)


class FiveStateTests(UnlockerFixture):
    def test_patched(self) -> None:
        self.baseline()
        self.install(PATCHED)
        status = self.detect()
        self.assertEqual(status.state, unlocker.PATCHED)
        self.assertEqual(status.confidence, "high")
        self.assertTrue(status.definitive)
        self.assertEveryFileDecided(status)
        for verdict in status.files:
            self.assertEqual(verdict.verdict, unlocker.PATCHED)
            self.assertEqual(verdict.sha256_installed, verdict.sha256_backup_line2)

    def test_unpatched(self) -> None:
        self.baseline()
        self.install(ORIGINAL)
        status = self.detect()
        self.assertEqual(status.state, unlocker.UNPATCHED)
        self.assertEqual(status.confidence, "high")
        for verdict in status.files:
            self.assertEqual(verdict.sha256_installed, verdict.sha256_backup_line1)

    def test_unknown_modified(self) -> None:
        self.baseline()
        self.install(OTHER)
        status = self.detect()
        self.assertEqual(status.state, unlocker.UNKNOWN_MODIFIED)
        self.assertEqual(status.confidence, "medium")
        self.assertTrue(status.definitive)
        self.assertTrue(any("UNKNOWN-MODIFIED" in h or "不一致" in h for h in status.hints))

    def test_damaged_backup_fails_self_check(self) -> None:
        self.baseline()
        self.install(ORIGINAL)
        self.corrupt_backup()
        status = self.detect()
        self.assertEqual(status.state, unlocker.DAMAGED)
        self.assertEqual(status.confidence, "high")
        self.assertTrue(any("自校验失败" in h for h in status.hints))
        for verdict in status.files:
            if verdict.file.endswith(BINARY_NAMES[0]):
                self.assertEqual(verdict.verdict, unlocker.DAMAGED)
            else:
                self.assertEqual(verdict.verdict, unlocker.UNPATCHED)

    def test_missing_installed_file_is_damaged(self) -> None:
        self.baseline()
        self.install_all_but(missing=LIB_NAME)
        status = self.detect()
        self.assertEqual(status.state, unlocker.DAMAGED)
        verdicts = {Path(v.file).name: v.verdict for v in status.files}
        self.assertEqual(verdicts[LIB_NAME], unlocker.MISSING)

    def test_unknown_without_baseline(self) -> None:
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.install(b"pristine build without markers\n")
        status = self.detect()
        self.assertEqual(status.state, unlocker.UNKNOWN)
        self.assertEqual(status.confidence, "none")
        self.assertFalse(status.definitive)
        self.assertTrue(any("没有" in h for h in status.hints))

    def test_weakest_conclusion_wins(self) -> None:
        # one file untouched, one patched → we cannot claim either state
        self.baseline()
        self.install(ORIGINAL)
        (self.vmware / "bin" / "vmware-vmx-debug").write_bytes(PATCHED)
        self.assertEqual(self.detect().state, unlocker.UNKNOWN_MODIFIED)


class FallbackTests(UnlockerFixture):
    def test_marker_probe_reports_patched_with_low_confidence(self) -> None:
        self.backup_root.mkdir(parents=True, exist_ok=True)
        marked = b"prefix " + unlocker.MARKER_A + b" mid " + unlocker.MARKER_B + b" suffix"
        (self.vmware / "bin" / "vmware-vmx").write_bytes(marked)
        status = self.detect()
        self.assertEqual(status.state, unlocker.PATCHED)
        self.assertEqual(status.confidence, "low")
        self.assertFalse(status.definitive)  # never presented as a hash verdict
        self.assertTrue(any("marker" in h for h in status.hints))

    def test_partial_marker_is_not_enough(self) -> None:
        self.backup_root.mkdir(parents=True, exist_ok=True)
        (self.vmware / "bin" / "vmware-vmx").write_bytes(
            b"pristine build with only " + unlocker.MARKER_A
        )
        self.assertEqual(self.detect().state, unlocker.UNKNOWN)

    def test_native_strings_are_never_treated_as_markers(self) -> None:
        # strings that exist in pristine builds must not decide anything
        self.backup_root.mkdir(parents=True, exist_ok=True)
        (self.vmware / "bin" / "vmware-vmx").write_bytes(
            b"ourhardworkbythesewordsguardedpl only, without the second marker"
        )
        self.assertNotEqual(self.detect().state, unlocker.PATCHED)

    def test_missing_vmware_root_is_unknown_not_fail(self) -> None:
        status = unlocker.detect(self.root / "not-installed", [self.backup_root])
        self.assertEqual(status.state, unlocker.UNKNOWN)
        self.assertEqual(status.confidence, "none")
        self.assertEqual(status.files, [])


class VersionGateTests(UnlockerFixture):
    def test_picks_the_baseline_matching_the_installed_version(self) -> None:
        self.baseline(version="25.0.0", second_line=sha(OTHER))
        self.baseline(version="26.0.1")
        self.install(PATCHED)
        status = self.detect()
        self.assertEqual(status.state, unlocker.PATCHED)
        self.assertTrue(str(status.backup_root).endswith("26.0.1"))

    def test_major_version_fallback(self) -> None:
        # old major (25.0.0) would give a different verdict → proves the
        # <major>.* fallback really picked the 26.x baseline.
        self.baseline(version="25.0.0", backup_data=OTHER, second_line=sha(ORIGINAL))
        self.baseline(version="26.0.1")
        self.install(PATCHED)
        (self.vmware / "vixwrapper-product-config.txt").write_text(
            "# Workstation and Player 26.5.0 (26H9u9)\n", encoding="utf-8"
        )
        status = self.detect()
        self.assertTrue(str(status.backup_root).endswith("26.0.1"))
        self.assertEqual(status.state, unlocker.PATCHED)

    def test_no_version_hint_uses_newest_baseline(self) -> None:
        self.baseline(version="25.0.0", second_line=sha(OTHER))
        self.baseline(version="26.0.1")
        (self.vmware / "vixwrapper-product-config.txt").unlink()
        self.install(PATCHED)
        status = self.detect()
        self.assertTrue(str(status.backup_root).endswith("26.0.1"))
        self.assertEqual(status.state, unlocker.PATCHED)

    def test_explicit_version_argument_overrides_the_gate(self) -> None:
        self.baseline(version="25.0.0", second_line=sha(OTHER))
        self.install(ORIGINAL)  # matches the 25.0.0 backup bytes
        status = self.detect(version="25.0.0")
        self.assertTrue(str(status.backup_root).endswith("25.0.0"))
        self.assertEqual(status.state, unlocker.UNPATCHED)

    def test_unknown_installed_version_degrades_with_a_note(self) -> None:
        self.baseline(version="26.0.1")
        (self.vmware / "vixwrapper-product-config.txt").write_text(
            "# no version here\n", encoding="utf-8"
        )
        self.install(PATCHED)
        status = self.detect()
        self.assertEqual(status.state, unlocker.PATCHED)
        self.assertTrue(any("未能确定本机" in h for h in status.hints))

    def test_version_present_but_no_matching_baseline(self) -> None:
        self.baseline(version="24.0.0")
        self.install(PATCHED)
        status = self.detect()  # installed is 26.0.1
        self.assertEqual(status.state, unlocker.UNKNOWN)
        self.assertTrue(any("26.0.1" in h for h in status.hints))


class NeverExecutesScriptsTests(UnlockerFixture):
    def write_check_script(self) -> Path:
        """An executable Unlocker ``linux/check`` that would leave a trace."""
        sentinel = self.root / "script-ran"
        script = self.root / "unlocker" / "linux" / "check"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(f"#!/bin/sh\ntouch '{sentinel}'\n", encoding="utf-8")
        script.chmod(0o755)
        self.sentinel = sentinel
        return script

    def exploding_patches(self):
        def boom(*args, **kwargs):  # pragma: no cover - must never be called
            raise AssertionError("macopt must never spawn a process during detect()")

        return (
            mock.patch("subprocess.run", side_effect=boom),
            mock.patch("subprocess.Popen", side_effect=boom),
            mock.patch("subprocess.call", side_effect=boom),
            mock.patch("subprocess.check_output", side_effect=boom),
        )

    def test_detect_never_runs_the_unlockers_check_script(self) -> None:
        script = self.write_check_script()
        self.baseline()
        self.install(PATCHED)
        with self.exploding_patches()[0], self.exploding_patches()[1]:
            status = self.detect()
        self.assertEqual(status.state, unlocker.PATCHED)
        self.assertFalse(self.sentinel.exists(), "linux/check was executed!")
        self.assertTrue(script.is_file())

    def test_fallback_reports_the_script_but_does_not_run_it(self) -> None:
        self.write_check_script()
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.install(b"build with no markers\n")
        with self.exploding_patches()[0], self.exploding_patches()[1]:
            status = self.detect()
        self.assertEqual(status.state, unlocker.UNKNOWN)
        self.assertFalse(self.sentinel.exists())
        hints = "\n".join(status.hints)
        self.assertIn("linux", hints)
        self.assertIn("check", hints)
        self.assertIn("绝不代跑脚本", hints)

    def test_module_never_imports_subprocess(self) -> None:
        source = Path(unlocker.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("subprocess.", source)
        self.assertNotIn("subprocess", unlocker.__dict__)
        self.assertFalse(hasattr(unlocker, "subprocess"))

    def test_detection_is_read_only(self) -> None:
        self.baseline()
        self.install(PATCHED)
        before = {
            path: (path.read_bytes(), path.stat().st_mtime)
            for path in sorted(self.vmware.rglob("*"))
            if path.is_file()
        } | {
            path: (path.read_bytes(), path.stat().st_mtime)
            for path in sorted(self.backup_root.rglob("*"))
            if path.is_file()
        }
        self.detect()
        after = {
            path: (path.read_bytes(), path.stat().st_mtime)
            for path in sorted(self.vmware.rglob("*"))
            if path.is_file()
        } | {
            path: (path.read_bytes(), path.stat().st_mtime)
            for path in sorted(self.backup_root.rglob("*"))
            if path.is_file()
        }
        self.assertEqual(before, after, "detect() must not touch a single byte")

    def test_states_constant_lists_exactly_five(self) -> None:
        self.assertEqual(
            unlocker.STATES,
            (
                unlocker.PATCHED,
                unlocker.UNPATCHED,
                unlocker.UNKNOWN,
                unlocker.UNKNOWN_MODIFIED,
                unlocker.DAMAGED,
            ),
        )
        self.assertEqual(len(set(unlocker.STATES)), 5)


if __name__ == "__main__":
    unittest.main()

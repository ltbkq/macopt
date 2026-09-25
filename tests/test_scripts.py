"""Tests for the repository's compliance gates (``scripts/``).

CI runs these three as blocking steps, so they deserve their own tests: a
gate that silently passes everything is worse than no gate. Every negative
test builds its payload from string *fragments* so that the payload never
appears in this file — otherwise ``secret_scan`` would flag the test that
proves it works.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"


def run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=180,
    )


def load_sanitize_module():
    spec = importlib.util.spec_from_file_location("_sanitize", SCRIPTS / "sanitize_evidence.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GuardrailsTest(unittest.TestCase):
    def test_repository_passes(self):
        result = run_script("guardrails.py")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_catches_write_network_import_and_bad_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "guardrails.py").write_text(
                (SCRIPTS / "guardrails.py").read_text(encoding="utf-8"), encoding="utf-8"
            )
            src = root / "src" / "macopt"
            src.mkdir(parents=True)
            # built from fragments: this file itself must stay clean
            path_literal = "/usr/lib/" + "vmware/config"
            key_literal = "mks." + "g3d.maxTextureSize"
            (src / "bad.py").write_text(
                textwrap.dedent(
                    f'''
                    import socket
                    from macopt.model import Param

                    def mutate():
                        open("{path_literal}", "w").write("boom")
                        return Param(
                            key="{key_literal}", value="1",
                            module="gfxnet", reason="x",
                        )
                    '''
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(root / "scripts" / "guardrails.py")],
                capture_output=True, text=True, cwd=root, timeout=60,
            )
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
        self.assertIn("protected path", result.stderr)
        self.assertIn("network import", result.stderr)
        self.assertIn("does not exist", result.stderr)

    def test_read_only_mentions_are_allowed(self):
        """Listing or hashing a VMware path must not trip the gate."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "guardrails.py").write_text(
                (SCRIPTS / "guardrails.py").read_text(encoding="utf-8"), encoding="utf-8"
            )
            src = root / "src" / "macopt"
            src.mkdir(parents=True)
            (src / "ok.py").write_text(
                textwrap.dedent(
                    '''
                    # Read-only inventory: these keys do NOT exist, see docs.
                    FORBIDDEN = ("mks." + "enableGLRenderer",)
                    ROOT = "/usr/lib/" + "vmware"
                    LAYERS = ("~/.vmware/" + "config",)

                    def list_layers():
                        return [p for p in LAYERS]
                    '''
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(root / "scripts" / "guardrails.py")],
                capture_output=True, text=True, cwd=root, timeout=60,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)


class SecretScanTest(unittest.TestCase):
    def test_repository_is_clean(self):
        result = run_script("secret_scan.py", ".")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_flags_a_synthetic_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "leak.txt"
            prefix = "pass" + "word = "
            target.write_text(prefix + '"s3cret-value-42"\n', encoding="utf-8")
            result = run_script("secret_scan.py", str(target))
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
        self.assertIn("password assignment", result.stderr)

    def test_flags_a_synthetic_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "leak.txt"
            token = "gh" + "p_" + "A" * 32
            target.write_text(f"export TOKEN={token}\n", encoding="utf-8")
            result = run_script("secret_scan.py", str(target))
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
        self.assertIn("github token", result.stderr)

    def test_pass_status_constant_is_not_a_credential(self):
        """`PASS = "PASS"` is a test constant, not a password (regression)."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "clean.txt"
            target.write_text('PASS = "PASS"\nFAIL = "FAIL"\n', encoding="utf-8")
            result = run_script("secret_scan.py", str(target))
        self.assertEqual(result.returncode, 0, msg=result.stderr)


class SanitizeTest(unittest.TestCase):
    def test_committed_evidence_is_already_redacted(self):
        result = run_script("sanitize_evidence.py", "--check")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_redacts_personal_detail_and_is_idempotent(self):
        sanitize = load_sanitize_module()
        home = "/home/" + "alice"
        mac = ":".join(["00", "50", "56", "11", "22", "33"])
        raw = f"host {home}/vms with mac {mac} and an ISO [My Volume]:darwin.iso\n"

        # in-process: redaction is idempotent (what --check enforces on disk)
        once = sanitize.sanitize_text(raw)
        self.assertEqual(sanitize.sanitize_text(once), once)

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.md"
            target.write_text(raw, encoding="utf-8")

            first = run_script("sanitize_evidence.py", "--src", str(target))
            self.assertEqual(first.returncode, 0, msg=first.stderr)
            once = target.read_text(encoding="utf-8")
            self.assertNotIn("/home/alice", once)
            self.assertNotIn(mac, once)
            self.assertIn("/home/<user>/", once)
            self.assertIn("<mac>", once)

            second = run_script("sanitize_evidence.py", "--src", str(target))
            self.assertEqual(second.returncode, 0, msg=second.stderr)
            self.assertEqual(second.stdout.strip().splitlines()[-1], "sanitize_evidence: nothing to do")
            self.assertEqual(target.read_text(encoding="utf-8"), once)

            check = run_script("sanitize_evidence.py", "--check", "--src", str(target))
            self.assertEqual(check.returncode, 0, msg=check.stderr)

    def test_check_fails_on_unredacted_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.md"
            target.write_text("owned by " + "/home/" + "alice\n", encoding="utf-8")
            check = run_script("sanitize_evidence.py", "--check", "--src", str(target))
        self.assertEqual(check.returncode, 1, msg=check.stdout + check.stderr)


class MakeFixturesTest(unittest.TestCase):
    def test_produces_a_sanitized_fixture(self):
        script = SCRIPTS / "make_fixtures.py"
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "vmware.log"
            home = "/home/" + "alice"
            log.write_text(
                "\n".join(
                    [
                        "2026-09-25T10:00:00.000Z| I120: guest vs. host CPUID",
                        f"2026-09-25T10:00:01.000Z| I120: path {home}/vms/vmware.log",
                        "2026-09-25T10:00:02.000Z| I120: unrelated noise line",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            result = subprocess.run(
                [sys.executable, str(script), str(log), "-o", str(out)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            produced = out / "vmware.fixture.log"
            self.assertTrue(produced.exists())
            text = produced.read_text(encoding="utf-8")
            self.assertIn("guest vs. host CPUID", text)
            self.assertNotIn("/home/alice", text)
            self.assertNotIn("unrelated noise", text)

    def test_rejects_a_missing_log(self):
        script = SCRIPTS / "make_fixtures.py"
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(script), str(Path(tmp) / "nope.log")],
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()

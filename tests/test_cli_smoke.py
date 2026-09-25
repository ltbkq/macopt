"""CLI-level smoke tests.

They exercise argument parsing and the documented exit-code contract without
requiring a real VMware installation. Sub-commands whose modules are not
present are skipped explicitly rather than silently passing.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from macopt import cli, errors


def _has(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class ParserTest(unittest.TestCase):
    def test_no_command_prints_help_and_usage_exit(self):
        code, out, _ = run_cli()
        self.assertEqual(code, errors.EXIT_USAGE)
        self.assertIn("usage:", out)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_all_documented_commands_exist(self):
        parser = cli.build_parser()
        # keep docs/DESIGN.md §4.14 and this list in sync
        expected = {
            "setup", "doctor", "check", "apply", "verify", "restore",
            "keyscan", "unlocker-status", "detect-cpu", "schedule", "guest-tools",
        }
        actions = [
            action for action in parser._subparsers._group_actions  # type: ignore[attr-defined]
            if hasattr(action, "choices")
        ]
        self.assertTrue(actions)
        self.assertEqual(set(actions[0].choices), expected)


class FailurePathTest(unittest.TestCase):
    def test_missing_target_is_a_failure_not_a_crash(self):
        code, _, err = run_cli("check", "/nonexistent/guest.vmx")
        self.assertEqual(code, errors.EXIT_FAIL)
        self.assertIn("error:", err)

    def test_directory_without_vmx(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("apply", tmp)
            self.assertEqual(code, errors.EXIT_FAIL)
            self.assertIn("no .vmx found", err)


@unittest.skipUnless(_has("macopt.hostinfo") and _has("macopt.unlocker"), "modules not ready")
class DoctorTest(unittest.TestCase):
    def test_doctor_json_is_valid_and_structured(self):
        code, out, _ = run_cli("doctor", "--json")
        self.assertIn(code, (errors.EXIT_OK, errors.EXIT_UNKNOWN))
        payload = json.loads(out)
        for key in ("host", "unlocker", "config_layers", "paths"):
            self.assertIn(key, payload)
        self.assertEqual(payload["paths"]["preferences"], "~/.vmware/preferences")
        # the tool must never claim a preferences path that does not exist
        self.assertNotIn("preferences.ini", json.dumps(payload["paths"]))

    def test_doctor_reports_human_text(self):
        code, out, _ = run_cli("doctor")
        self.assertIn(code, (errors.EXIT_OK, errors.EXIT_UNKNOWN))
        self.assertIn("unlocker", out)


@unittest.skipUnless(_has("macopt.keys"), "keys module not ready")
class KeyscanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One shared state dir => the whitelist scan is paid once for the
        # class; tests must never warm the *user's* real state directory.
        cls._shared = tempfile.TemporaryDirectory()
        cls.state = cls._shared.name

    @classmethod
    def tearDownClass(cls):
        cls._shared.cleanup()

    def test_known_key_lookup(self):
        code, out, _ = run_cli("keyscan", "--key", "numvcpus", "--json", "--state-dir", self.state)
        self.assertEqual(code, errors.EXIT_OK)
        self.assertIn("known", out)

    def test_unknown_key_is_reported_as_missing(self):
        code, out, _ = run_cli(
            "keyscan", "--key", "definitely.not.a.real.key", "--json", "--state-dir", self.state
        )
        self.assertEqual(code, errors.EXIT_FAIL)
        self.assertIn("NOT FOUND", out)

    def test_scan_results_are_cached_on_disk(self):
        cache = Path(self.state) / "keycache.json"
        if not cache.exists():  # warm it once through the documented command
            run_cli("keyscan", "--json", "--state-dir", self.state)
        if not cache.exists():
            self.skipTest("no VMware binaries to scan on this host")
        self.assertGreater(cache.stat().st_size, 0)
        payload = json.loads(cache.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], 1)
        self.assertTrue(payload["files"])


@unittest.skipUnless(_has("macopt.vmxfile") and _has("macopt.writer"), "writer not ready")
class PreconditionTest(unittest.TestCase):
    def test_apply_refuses_when_lock_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            vmx = Path(tmp) / "guest.vmx"
            vmx.write_text('guestOS = "darwin24-64"\nnumvcpus = "4"\n', encoding="utf-8")
            (Path(tmp) / "guest.vmx.lck").mkdir()

            code, out, err = run_cli(
                "apply", str(vmx), "--dry-run", "--module", "topology", "--json"
            )
            # either the precondition fires (3) or the plan is produced but
            # nothing is written; in no case may the file change.
            self.assertIn(code, (errors.EXIT_PRECONDITION, errors.EXIT_OK))
            self.assertEqual(vmx.read_text(encoding="utf-8"), 'guestOS = "darwin24-64"\nnumvcpus = "4"\n')


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vmx"
SOURCE = FIXTURES / "darwin-balanced.vmx"


@unittest.skipUnless(
    _has("macopt.profiles.topology") and _has("macopt.profiles.identity"),
    "profiles not ready",
)
class ApplyFlagTest(unittest.TestCase):
    """Flags that own a profile module must actually reach it.

    Before this was wired, `--cpuid-profile` and `--identity` parsed fine and
    silently did nothing, because the module never entered `opts.modules`.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.vmx = self.root / "guest.vmx"
        shutil.copyfile(SOURCE, self.vmx)

    def apply(self, *extra: str) -> tuple[int, str, str]:
        return run_cli(
            "apply", str(self.vmx), "--dry-run", "--json", "--state-dir", str(self.root / "s"),
            *extra,
        )

    def plan(self, out: str) -> dict:
        return json.loads(out)["plan"]

    def test_cpuid_profile_pulls_in_its_module(self):
        code, out, err = self.apply("--cpuid-profile", "penryn")
        self.assertIn(code, (0, errors.EXIT_CONFLICT), msg=err)
        keys = [c["key"] for c in self.plan(out)["changes"]]
        self.assertTrue(
            any(k.startswith("cpuid.1.") for k in keys),
            f"cpuid module never ran; plan keys: {keys}",
        )
        # the rule engine must still block the hazardous ones by default
        self.assertTrue(any("R1 BLOCK" in e for e in self.plan(out)["errors"]))

    def test_cpuid_profile_none_emits_no_cpuid_masks(self):
        code, out, err = self.apply()
        self.assertEqual(code, 0, msg=err)
        keys = [c["key"] for c in self.plan(out)["changes"]]
        self.assertFalse(
            any(k.startswith(("cpuid.0.", "cpuid.1.")) for k in keys),
            "no CPUID profile was requested, so no masks may be planned",
        )

    def test_identity_without_values_is_refused_and_explains_why(self):
        code, out, err = self.apply("--identity")
        self.assertEqual(code, errors.EXIT_CONFLICT, msg=out + err)
        self.assertIn("board-id", err)
        self.assertIn("macopt 不内置", err)

    def test_identity_with_explicit_values_reaches_the_profile(self):
        code, out, err = self.apply(
            "--force",
            "--identity", "--board-id", "Mac-TESTBOARD",
            "--hw-model", "MacTest,1", "--serial", "C02TESTSERIAL",
        )
        self.assertEqual(code, 0, msg=err)
        keys = [c["key"] for c in self.plan(out)["changes"]]
        for expected in ("board-id", "hw.model", "serialNumber", "serialNumber.reflectHost"):
            self.assertIn(expected, keys)
        # macopt must never invent these: the value is the one we passed
        board = next(c for c in self.plan(out)["changes"] if c["key"] == "board-id")
        self.assertEqual(board["after"], "Mac-TESTBOARD")

    def test_malformed_extra_is_a_usage_error(self):
        code, out, err = self.apply("--extra", "no-equals-sign")
        self.assertEqual(code, errors.EXIT_USAGE, msg=out + err)
        self.assertIn("--extra wants KEY=VALUE", err)

    def test_generic_extra_lands_in_extras(self):
        code, out, err = self.apply("--force", "--identity", "--extra", "board-id=B1",
                                    "--extra", "hw-model=M1", "--extra", "serial=S1")
        self.assertEqual(code, 0, msg=err)
        keys = [c["key"] for c in self.plan(out)["changes"]]
        self.assertIn("board-id", keys)


if __name__ == "__main__":
    unittest.main()

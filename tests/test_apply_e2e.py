"""End-to-end regression tests for the `macopt apply` write path.

These drive the real CLI (parser -> profiles -> writer -> backup) against a
copy of a fixture inside a temporary directory, because the one bug class
they exist for only shows up across layers: an absolute line number that goes
stale after a deletion makes `set()` overwrite an *untouched* neighbour's
line. A per-key round-trip check cannot see that; only a whole-document
comparison can.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from macopt import cli

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vmx"
SOURCE = FIXTURES / "darwin-balanced.vmx"


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lines_with(path: Path, key: str) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.startswith(f"{key} =")]


@unittest.skipUnless(
    importlib.util.find_spec("macopt.profiles.topology"), "topology profile not ready"
)
class ApplyWritePathTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Shared across the class so the one-time whitelist scan runs once
        # (~6 s) instead of per test; backups stay isolated because each test
        # copies the fixture to its own uniquely-named temporary directory.
        cls._shared = tempfile.TemporaryDirectory()
        cls.state_root = Path(cls._shared.name) / "state"

    @classmethod
    def tearDownClass(cls):
        cls._shared.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.vmx = self.root / "guest.vmx"
        self.state = self.state_root
        shutil.copyfile(SOURCE, self.vmx)
        self.before = self.vmx.read_text(encoding="utf-8")

    def apply(self, *extra: str) -> tuple[int, str, str]:
        return run_cli(
            "apply", str(self.vmx), "--yes", "--module", "topology",
            "--state-dir", str(self.state), *extra,
        )

    def test_apply_edits_only_the_planned_keys(self):
        code, out, err = self.apply("--json")
        self.assertEqual(code, 0, msg=err or out)
        after = self.vmx.read_text(encoding="utf-8")

        # the plan: cookie removed, maxPerVirtualNode + vhv.enable modified,
        # vpmc.enable untouched (already FALSE)
        self.assertNotIn("numa.autosize.cookie", after)
        self.assertIn('numa.autosize.vcpu.maxPerVirtualNode = "12"', after)
        self.assertIn('vhv.enable = "FALSE"', after)

        # the neighbour that used to be silently clobbered
        self.assertEqual(lines_with(self.vmx, "vpmc.enable"), ['vpmc.enable = "FALSE"'])

        # no duplicated keys may be introduced
        self.assertEqual(len(lines_with(self.vmx, "vhv.enable")), 1)

        # every line we never planned to touch must be byte-identical
        planned = {"numa.autosize.cookie", "numa.autosize.vcpu.maxPerVirtualNode", "vhv.enable"}
        before_lines = [ln for ln in self.before.splitlines() if ln.split(" =")[0] not in planned]
        after_lines = [ln for ln in after.splitlines() if ln.split(" =")[0] not in planned]
        self.assertEqual(before_lines, after_lines)

    def test_apply_is_idempotent(self):
        self.assertEqual(self.apply()[0], 0)
        first = sha256(self.vmx)

        code, out, _ = self.apply("--json")
        self.assertEqual(code, 0)
        plan = json.loads(out)["plan"]["counts"]
        self.assertEqual(plan.get("added", 0), 0)
        self.assertEqual(plan.get("modified", 0), 0)
        self.assertEqual(plan.get("removed", 0), 0)
        self.assertEqual(sha256(self.vmx), first)

        # a third run must not move either
        self.assertEqual(self.apply()[0], 0)
        self.assertEqual(sha256(self.vmx), first)

    def test_dry_run_never_touches_file_or_state(self):
        # A dry run must not create state, so it gets its own (never warmed)
        # state dir and may not write a whitelist cache either.
        dry_state = self.root / "dry-state"
        code, out, _ = self.apply("--dry-run", "--json", "--state-dir", str(dry_state))
        self.assertEqual(code, 0)
        self.assertEqual(self.vmx.read_text(encoding="utf-8"), self.before)
        self.assertFalse(dry_state.exists(), "a dry run must not create state")

    def test_without_confirmation_the_file_is_untouched(self):
        # `modified`/`removed` require a confirmation gate -> exit 5
        code, out, err = run_cli(
            "apply", str(self.vmx), "--module", "topology", "--state-dir", str(self.state)
        )
        self.assertEqual(code, 5, msg=err or out)
        self.assertEqual(self.vmx.read_text(encoding="utf-8"), self.before)

    def test_backup_is_created_and_restores_byte_exactly(self):
        self.assertEqual(self.apply()[0], 0)
        listing = run_cli(
            "restore", str(self.vmx), "--state-dir", str(self.state), "--json"
        )
        self.assertEqual(listing[0], 0)
        backups = json.loads(listing[1])["backups"]
        self.assertEqual(len(backups), 1)
        backup_id = backups[0]["id"]

        # roll back and compare with the original bytes
        code, out, err = run_cli(
            "restore", str(self.vmx), "--state-dir", str(self.state), "--to", backup_id, "--json"
        )
        self.assertEqual(code, 0, msg=err or out)
        self.assertEqual(self.vmx.read_text(encoding="utf-8"), self.before)


if __name__ == "__main__":
    unittest.main()

"""Write-path tests: three-state idempotency, gates, atomicity (DESIGN §4.12).

Everything runs inside ``tempfile.TemporaryDirectory``: no test may touch
``/usr/lib/vmware``, ``~/.vmware`` or any real VM. Fixtures are only ever
*copied* out of ``tests/fixtures/vmx``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from macopt import writer
from macopt.errors import (
    EXIT_CONFLICT,
    EXIT_FAIL,
    EXIT_PRECONDITION,
    EXIT_REFUSED,
    ConflictError,
    PreconditionError,
    VerificationError,
    WhitelistError,
)
from macopt.model import (
    OP_ADDED,
    OP_MODIFIED,
    OP_REMOVED,
    OP_UNCHANGED,
    Change,
    Evidence,
    Param,
    Plan,
)
from macopt.vmxfile import Document

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vmx"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ev(source: str = "tests/fixtures/vmx/darwin-balanced.vmx") -> tuple[Evidence, ...]:
    return (Evidence("file", source, "sample parameter"),)


def param(
    key: str,
    value: str = "",
    *,
    remove: bool = False,
    module: str = "topology",
    needs_confirmation: bool = False,
) -> Param:
    return Param(
        key=key,
        value=value,
        module=module,
        reason="unit test parameter",
        evidence=ev(),
        needs_confirmation=needs_confirmation,
        remove=remove,
    )


def entries_of(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


class TempVMixin:
    """Copies ``darwin-balanced.vmx`` into a fresh temp dir for every test."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="macopt-writer-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.vmx = self.tmp / "guest.vmx"
        shutil.copy(FIXTURES / "darwin-balanced.vmx", self.vmx)
        self.doc = Document.load(self.vmx)

    def reload(self) -> Document:
        return Document.load(self.vmx)


# --------------------------------------------------------------------------- #
# Plan / three-state classification
# --------------------------------------------------------------------------- #


class PlanTests(TempVMixin, unittest.TestCase):
    def test_three_state_classification(self) -> None:
        plan = writer.build_plan(
            self.doc,
            [
                param("svga.maxTextureSize", "16384", module="gfxnet"),  # absent -> added
                param("vhv.enable", "FALSE"),  # differs -> modified
                param("numvcpus", "12"),  # equal -> unchanged
                param("numa.autosize.cookie", remove=True),  # present -> removed
                param("monitor.phys_bits_used", remove=True),  # absent -> unchanged
            ],
        )
        self.assertEqual(
            plan.counts(),
            {OP_ADDED: 1, OP_MODIFIED: 1, OP_UNCHANGED: 2, OP_REMOVED: 1},
        )
        self.assertEqual(
            {c.key: c.op for c in plan.changes},
            {
                "svga.maxTextureSize": OP_ADDED,
                "vhv.enable": OP_MODIFIED,
                "numvcpus": OP_UNCHANGED,
                "numa.autosize.cookie": OP_REMOVED,
                "monitor.phys_bits_used": OP_UNCHANGED,
            },
        )
        added = next(c for c in plan.changes if c.key == "svga.maxTextureSize")
        self.assertIsNone(added.before)
        self.assertEqual(added.after, "16384")
        removed = next(c for c in plan.changes if c.key == "numa.autosize.cookie")
        self.assertEqual(removed.before, "120122")
        self.assertIsNone(removed.after)
        self.assertEqual(len(plan.effective), 3)
        self.assertFalse(plan.blocking)

    def test_duplicate_document_key_warns(self) -> None:
        self.assertIn("svga.vram0Size", self.doc.duplicates)
        plan = writer.build_plan(self.doc, [param("numvcpus", "12")])
        self.assertTrue(any(w.startswith("duplicate keys") for w in plan.warnings))

    def test_repeated_target_keeps_last_param(self) -> None:
        plan = writer.build_plan(
            self.doc,
            [param("vhv.enable", "FALSE"), param("vhv.enable", "FALSE")],
        )
        self.assertEqual(len(plan.changes), 1)
        self.assertTrue(any("more than once" in w for w in plan.warnings))

    def test_needs_confirmation_only_for_effective_changes(self) -> None:
        blocked = writer.build_plan(
            self.doc, [param("smc.version", "0", module="identity", needs_confirmation=True)]
        )
        self.assertTrue(any(e.startswith("confirm:") for e in blocked.errors))

        no_op = writer.build_plan(
            self.doc,
            [param("smc.present", "TRUE", module="identity", needs_confirmation=True)],
        )
        self.assertEqual(no_op.errors, [])

        confirmed = writer.build_plan(
            self.doc,
            [param("smc.version", "0", module="identity", needs_confirmation=True)],
            confirmed=True,
        )
        self.assertEqual(confirmed.errors, [])


# --------------------------------------------------------------------------- #
# apply(): gates and writing
# --------------------------------------------------------------------------- #


class ApplyTests(TempVMixin, unittest.TestCase):
    def test_apply_performs_every_op_and_verifies(self) -> None:
        plan = writer.build_plan(
            self.doc,
            [
                param("svga.maxTextureSize", "16384", module="gfxnet"),
                param("vhv.enable", "FALSE"),
                param("numvcpus", "12"),
                param("numa.autosize.cookie", remove=True),
            ],
        )
        sha_before = sha256_of(self.vmx)
        result = writer.apply(self.doc, plan, yes=True)
        self.assertTrue(result.written)
        self.assertFalse(result.dry_run)
        self.assertEqual(result.path, str(self.vmx))
        self.assertEqual(result.sha256_before, sha_before)
        self.assertNotEqual(result.sha256_after, sha_before)
        self.assertEqual(result.sha256_after, sha256_of(self.vmx))
        self.assertEqual(
            result.ops, {OP_ADDED: 1, OP_MODIFIED: 1, OP_UNCHANGED: 1, OP_REMOVED: 1}
        )

        reread = self.reload()
        self.assertEqual(reread.get("svga.maxTextureSize"), "16384")
        self.assertEqual(reread.get("vhv.enable"), "FALSE")
        self.assertIsNone(reread.get("numa.autosize.cookie"))
        self.assertEqual(reread.get("numvcpus"), "12")

    def test_second_apply_is_idempotent(self) -> None:
        params = [
            param("svga.maxTextureSize", "16384", module="gfxnet"),
            param("vhv.enable", "FALSE"),
            param("numvcpus", "12"),
            param("numa.autosize.cookie", remove=True),
        ]
        first = writer.apply(self.doc, writer.build_plan(self.doc, params), yes=True)
        self.assertTrue(first.written)
        sha_after_first = sha256_of(self.vmx)

        doc2 = self.reload()
        plan2 = writer.build_plan(doc2, params)
        self.assertEqual(plan2.counts()[OP_UNCHANGED], 4)
        self.assertEqual(plan2.effective, [])
        second = writer.apply(doc2, plan2, yes=True)
        self.assertFalse(second.written)
        self.assertEqual(second.ops[OP_ADDED], 0)
        self.assertEqual(second.ops[OP_MODIFIED], 0)
        self.assertEqual(second.ops[OP_REMOVED], 0)
        self.assertEqual(second.ops[OP_UNCHANGED], 4)
        self.assertEqual(sha256_of(self.vmx), sha_after_first)

    def test_modified_without_confirmation_is_exit_5(self) -> None:
        plan = writer.build_plan(self.doc, [param("vhv.enable", "FALSE")])
        sha_before = sha256_of(self.vmx)
        mtime_before = self.vmx.stat().st_mtime_ns
        with self.assertRaises(ConflictError) as ctx:
            writer.apply(self.doc, plan)
        self.assertEqual(ctx.exception.exit_code, EXIT_CONFLICT)
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(self.vmx.stat().st_mtime_ns, mtime_before)
        self.assertEqual(self.doc.get("vhv.enable"), "TRUE")  # not even mutated in memory
        self.assertEqual(entries_of(self.tmp), ["guest.vmx"])

    def test_removed_without_confirmation_is_exit_5(self) -> None:
        plan = writer.build_plan(self.doc, [param("numa.autosize.cookie", remove=True)])
        with self.assertRaises(ConflictError) as ctx:
            writer.apply(self.doc, plan)
        self.assertEqual(ctx.exception.exit_code, EXIT_CONFLICT)
        self.assertEqual(self.reload().get("numa.autosize.cookie"), "120122")

    def test_added_needs_no_confirmation(self) -> None:
        plan = writer.build_plan(
            self.doc, [param("svga.maxTextureSize", "16384", module="gfxnet")]
        )
        result = writer.apply(self.doc, plan)  # neither force nor yes
        self.assertTrue(result.written)
        self.assertEqual(self.reload().get("svga.maxTextureSize"), "16384")

    def test_force_and_yes_both_lift_the_gate(self) -> None:
        for flag in ("force", "yes"):
            with self.subTest(flag=flag):
                doc = self.reload()
                plan = writer.build_plan(doc, [param("vhv.enable", "FALSE")])
                result = writer.apply(doc, plan, **{flag: True})  # type: ignore[arg-type]
                self.assertTrue(result.written)
                self.assertEqual(self.reload().get("vhv.enable"), "FALSE")
                # restore for the next iteration
                doc = Document.load(self.vmx)
                doc.set("vhv.enable", "TRUE")
                doc.write_atomic()

    def test_no_effective_change_is_a_noop(self) -> None:
        plan = writer.build_plan(self.doc, [param("numvcpus", "12")])
        sha_before = sha256_of(self.vmx)
        mtime_before = self.vmx.stat().st_mtime_ns
        result = writer.apply(self.doc, plan, yes=True)
        self.assertFalse(result.written)
        self.assertEqual(result.ops[OP_UNCHANGED], 1)
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(self.vmx.stat().st_mtime_ns, mtime_before)

    # -- dry run ---------------------------------------------------------- #

    def test_dry_run_triple_invariance_and_no_state(self) -> None:
        state_root = self.tmp / "state"
        plan = writer.build_plan(
            self.doc,
            [param("vhv.enable", "FALSE"), param("svga.maxTextureSize", "16384", module="gfxnet")],
        )
        sha_before = sha256_of(self.vmx)
        mtime_before = self.vmx.stat().st_mtime_ns
        lines_before = len(self.vmx.read_text(encoding="utf-8").splitlines())

        # no force/yes on purpose: dry_run must always be allowed
        result = writer.apply(self.doc, plan, dry_run=True)

        self.assertTrue(result.dry_run)
        self.assertFalse(result.written)
        self.assertEqual(result.sha256_before, sha_before)
        self.assertEqual(result.sha256_after, sha_before)
        self.assertEqual(result.ops[OP_MODIFIED], 1)
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(self.vmx.stat().st_mtime_ns, mtime_before)
        self.assertEqual(
            len(self.vmx.read_text(encoding="utf-8").splitlines()), lines_before
        )
        # no backup directory, no state directory, nothing but the vmx itself
        self.assertEqual(entries_of(self.tmp), ["guest.vmx"])
        self.assertFalse(state_root.exists())
        self.assertEqual(self.doc.get("vhv.enable"), "TRUE")  # doc untouched too

    def test_dry_run_does_not_raise_on_plan_errors(self) -> None:
        policy = lambda key: key != "totally.unknown.key"  # noqa: E731
        plan = writer.build_plan(
            self.doc,
            [param("totally.unknown.key", "1", module="gfxnet")],
            key_policy=policy,
        )
        self.assertTrue(plan.errors)
        sha_before = sha256_of(self.vmx)
        result = writer.apply(self.doc, plan, dry_run=True)
        self.assertTrue(result.dry_run)
        self.assertEqual(sha256_of(self.vmx), sha_before)

    # -- whitelist / classification ---------------------------------------- #

    def test_whitelist_error_is_exit_6_and_writes_nothing(self) -> None:
        policy = lambda key: key != "totally.unknown.key"  # noqa: E731
        plan = writer.build_plan(
            self.doc,
            [param("totally.unknown.key", "1", module="gfxnet")],
            key_policy=policy,
        )
        self.assertTrue(plan.errors)
        self.assertTrue(plan.errors[0].startswith("whitelist:"))
        sha_before = sha256_of(self.vmx)
        with self.assertRaises(WhitelistError) as ctx:
            writer.apply(self.doc, plan, yes=True, force=True)
        self.assertEqual(ctx.exception.exit_code, EXIT_REFUSED)
        self.assertEqual(sha256_of(self.vmx), sha_before)

    def test_allow_unknown_keys_downgrades_to_warning(self) -> None:
        policy = lambda key: key != "totally.unknown.key"  # noqa: E731
        plan = writer.build_plan(
            self.doc,
            [param("totally.unknown.key", "1", module="gfxnet")],
            key_policy=policy,
            allow_unknown_keys=True,
        )
        self.assertEqual(plan.errors, [])
        self.assertTrue(any(w.startswith("whitelist:") for w in plan.warnings))
        result = writer.apply(self.doc, plan)
        self.assertTrue(result.written)
        self.assertEqual(self.reload().get("totally.unknown.key"), "1")

    def test_rule_error_maps_to_conflict(self) -> None:
        plan = Plan(
            changes=[
                Change(key="vhv.enable", before="TRUE", after="FALSE", op=OP_MODIFIED)
            ],
            errors=["rule: guardrail tripped"],
        )
        with self.assertRaises(ConflictError) as ctx:
            writer.apply(self.doc, plan, yes=True)
        self.assertEqual(ctx.exception.exit_code, EXIT_CONFLICT)

    def test_confirm_error_lifted_by_force(self) -> None:
        plan = writer.build_plan(
            self.doc,
            [param("smc.version", "0", module="identity", needs_confirmation=True)],
            confirmed=False,
        )
        self.assertTrue(plan.errors[0].startswith("confirm:"))
        with self.assertRaises(ConflictError) as ctx:
            writer.apply(self.doc, plan, yes=True)  # --yes must NOT lift needs_confirmation
        self.assertEqual(ctx.exception.exit_code, EXIT_CONFLICT)

        result = writer.apply(self.doc, plan, force=True)
        self.assertTrue(result.written)
        self.assertEqual(self.reload().get("smc.version"), "0")

    # -- precondition / verification / atomicity --------------------------- #

    def test_lock_directory_blocks_apply_with_exit_3(self) -> None:
        plan = writer.build_plan(self.doc, [param("vhv.enable", "FALSE")])
        (self.tmp / "guest.vmx.lck").mkdir()
        sha_before = sha256_of(self.vmx)
        with self.assertRaises(PreconditionError) as ctx:
            writer.apply(self.doc, plan, yes=True)
        self.assertEqual(ctx.exception.exit_code, EXIT_PRECONDITION)
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(self.doc.get("vhv.enable"), "TRUE")

    def test_read_back_mismatch_raises_verification_error(self) -> None:
        plan = writer.build_plan(self.doc, [param("vhv.enable", "FALSE")])
        real_load = Document.load

        def tampering_load(path: object) -> Document:
            doc = real_load(path)  # type: ignore[arg-type]
            doc.set("vhv.enable", "TAMPERED")
            return doc

        with mock.patch.object(Document, "load", staticmethod(tampering_load)):
            with self.assertRaises(VerificationError) as ctx:
                writer.apply(self.doc, plan, yes=True)
        self.assertEqual(ctx.exception.exit_code, EXIT_FAIL)
        # the file itself was written correctly; only verification saw the tamper
        self.assertEqual(self.reload().get("vhv.enable"), "FALSE")

    def test_write_failure_leaves_original_file_intact(self) -> None:
        plan = writer.build_plan(self.doc, [param("vhv.enable", "FALSE")])
        sha_before = sha256_of(self.vmx)
        with mock.patch.object(
            Document, "write_atomic", side_effect=OSError("simulated write failure")
        ):
            with self.assertRaises(OSError):
                writer.apply(self.doc, plan, yes=True)
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(entries_of(self.tmp), ["guest.vmx"])

    def test_atomic_write_failure_cleans_up_temp_file(self) -> None:
        sha_before = sha256_of(self.vmx)
        self.doc.set("vhv.enable", "FALSE")
        with mock.patch(
            "macopt.vmxfile.os.replace", side_effect=OSError("simulated disk full")
        ):
            with self.assertRaises(OSError):
                self.doc.write_atomic()
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(entries_of(self.tmp), ["guest.vmx"])


# --------------------------------------------------------------------------- #
# check_precondition(): lock markers + injectable /proc
# --------------------------------------------------------------------------- #


class PreconditionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="macopt-precond-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.vmx = self.tmp / "guest.vmx"
        shutil.copy(FIXTURES / "minimal.vmx", self.vmx)
        self.proc = self.tmp / "proc"
        self.proc.mkdir()

    def add_process(self, pid: int, *args: str) -> None:
        entry = self.proc / str(pid)
        entry.mkdir()
        payload = b"".join(a.encode("utf-8") + b"\0" for a in args)
        (entry / "cmdline").write_bytes(payload)

    def test_clean_environment_is_writable(self) -> None:
        self.add_process(101, "/usr/bin/sleep", "999")
        self.assertEqual(writer.check_precondition(self.vmx, proc_root=self.proc), [])

    def test_missing_proc_root_is_tolerated(self) -> None:
        missing = self.tmp / "no-such-proc"
        self.assertEqual(writer.check_precondition(self.vmx, proc_root=missing), [])

    def test_lock_directory_is_detected(self) -> None:
        Path(str(self.vmx) + ".lck").mkdir()
        reasons = writer.check_precondition(self.vmx, proc_root=self.proc)
        self.assertEqual(len(reasons), 1)
        self.assertIn("lock directory", reasons[0])

    def test_lock_mode_file_is_detected_separately(self) -> None:
        lock = Path(str(self.vmx) + ".lck")
        lock.mkdir()
        (lock / "MODE").write_text("excl", encoding="utf-8")
        reasons = writer.check_precondition(self.vmx, proc_root=self.proc)
        self.assertEqual(len(reasons), 2)
        self.assertIn("lock directory", reasons[0])
        self.assertIn("MODE", reasons[1])
        self.assertIn("excl", reasons[1])

    def test_process_cmdline_hit_is_detected(self) -> None:
        self.add_process(4242, "/usr/lib/vmware/bin/vmware-vmx", str(self.vmx))
        self.add_process(4243, "/usr/bin/sleep", "999")
        reasons = writer.check_precondition(self.vmx, proc_root=self.proc)
        self.assertEqual(len(reasons), 1)
        self.assertIn("4242", reasons[0])
        self.assertIn("vmware-vmx", reasons[0])

    def test_own_pid_is_never_reported(self) -> None:
        # `macopt apply <vmx>` carries the path in its own argv by design.
        self.add_process(os.getpid(), "macopt", "apply", str(self.vmx))
        self.assertEqual(writer.check_precondition(self.vmx, proc_root=self.proc), [])

    def test_caller_wrapper_is_not_mistaken_for_a_running_guest(self) -> None:
        # `timeout 300 macopt apply <vmx>` / `make` / a CI step re-executes us
        # with the same argv, so the wrapper's cmdline carries the path too.
        # Measured on a real host: the wrapper was reported as a running VM
        # and every non-interactive apply was refused.
        own = os.getpid()
        parent = os.getppid()
        entry = self.proc / str(own)
        entry.mkdir()
        (entry / "stat").write_text(f"{own} (python3) S {parent} 0 0 0 0 0 0\n")
        self.add_process(parent, "timeout", "300", "macopt", "apply", str(self.vmx))
        # ...while the real guest process must still be refused
        self.add_process(4242, "/usr/lib/vmware/bin/vmware-vmx", str(self.vmx))
        reasons = writer.check_precondition(self.vmx, proc_root=self.proc)
        self.assertEqual(len(reasons), 1, reasons)
        self.assertIn("4242", reasons[0])

    def test_lineage_stops_on_a_malformed_stat_file(self) -> None:
        own = os.getpid()
        entry = self.proc / str(own)
        entry.mkdir()
        (entry / "stat").write_text("not a stat file\n")
        self.add_process(4242, "/usr/lib/vmware/bin/vmware-vmx", str(self.vmx))
        reasons = writer.check_precondition(self.vmx, proc_root=self.proc)
        self.assertEqual(len(reasons), 1, reasons)
        self.assertIn("4242", reasons[0])

    def test_relative_path_is_resolved_to_absolute(self) -> None:
        lock = Path(str(self.vmx) + ".lck")
        lock.mkdir()
        previous = Path.cwd()
        os.chdir(self.tmp)
        try:
            reasons = writer.check_precondition("guest.vmx", proc_root=self.proc)
        finally:
            os.chdir(previous)
        self.assertTrue(reasons)
        self.assertIn(str(self.vmx), reasons[0])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

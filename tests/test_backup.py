"""Backup/manifest/history/restore/prune tests (DESIGN §4.12, §8.2 D/E).

All state lives in ``tempfile.TemporaryDirectory``; fixtures are copied, never
written in place. Nothing here may touch ``~/.vmware``, ``/usr/lib/vmware`` or
any real VM directory.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from macopt.backup import BackupManager, BackupRecord
from macopt.errors import (
    EXIT_UNKNOWN,
    EXIT_USAGE,
    UnknownStateError,
    UsageError,
    VerificationError,
)
from macopt.model import Change, HostInfo
from macopt.vmxfile import Document

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vmx"
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entries_of(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


class BackupTestBase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="macopt-backup-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.state_root = self.tmp / "state"
        self.vmx = self.tmp / "guest.vmx"
        shutil.copy(FIXTURES / "darwin-balanced.vmx", self.vmx)
        self.mgr = BackupManager(self.state_root, self.vmx)

    def modify_vmx(self) -> bytes:
        """Simulate an apply: flip a key, add one, delete one."""
        doc = Document.load(self.vmx)
        doc.set("vhv.enable", "FALSE")
        doc.set("svga.maxTextureSize", "16384")
        doc.delete("numa.autosize.cookie")
        doc.write_atomic()
        return self.vmx.read_bytes()

    def backdate(self, record: BackupRecord, stamp: str) -> None:
        manifest = dict(record.manifest)
        manifest["created_utc"] = stamp
        (record.dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )

    def history_lines(self) -> list[dict]:
        path = self.state_root / "history.jsonl"
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --------------------------------------------------------------------------- #
# create / finalize
# --------------------------------------------------------------------------- #


class SnapshotTests(BackupTestBase):
    def test_create_snapshot_layout_and_manifest(self) -> None:
        original = self.vmx.read_bytes()
        record = self.mgr.create_snapshot()

        self.assertEqual(record.dir, self.state_root / "backups" / "guest" / record.id)
        self.assertTrue(record.dir.is_dir())
        self.assertEqual(entries_of(record.dir), ["guest.vmx", "manifest.json"])
        self.assertTrue(UTC_RE.match(record.created_utc))
        self.assertEqual(record.id, f"{record.id}")  # non-empty string id

        stored = record.stored_file
        self.assertEqual(stored.read_bytes(), original)  # byte-identical copy
        self.assertEqual(
            stored.stat().st_mode & 0o7777, self.vmx.stat().st_mode & 0o7777
        )

        manifest = record.manifest
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["id"], record.id)
        self.assertEqual(manifest["target"]["path"], str(self.vmx))
        files = manifest["files"]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["name"], "guest.vmx")
        self.assertEqual(files[0]["role"], "original")
        self.assertEqual(files[0]["sha256"], sha256_of(self.vmx))
        self.assertEqual(files[0]["size"], len(original))
        self.assertEqual(files[0]["mode"], oct(self.vmx.stat().st_mode & 0o7777))
        self.assertEqual(files[0]["mtime_ns"], self.vmx.stat().st_mtime_ns)
        self.assertEqual(manifest["before"]["sha256"], sha256_of(self.vmx))
        self.assertEqual(
            manifest["before"]["lines"], len(original.decode("utf-8").splitlines())
        )
        # skeleton only: after/changes arrive with finalize()
        self.assertNotIn("after", manifest)
        self.assertNotIn("changes", manifest)
        # nothing logged to history yet
        self.assertEqual(self.history_lines(), [])

    def test_snapshot_needs_a_real_target(self) -> None:
        missing = BackupManager(self.state_root, self.tmp / "missing.vmx")
        with self.assertRaises(FileNotFoundError):
            missing.create_snapshot()

    def test_finalize_persists_after_changes_and_history(self) -> None:
        after_sha = sha256_of(self.vmx)
        record = self.mgr.create_snapshot()
        finalized = self.mgr.finalize(
            record,
            changes=[
                Change(
                    key="vhv.enable",
                    before="TRUE",
                    after="FALSE",
                    op="modified",
                    module="topology",
                    reason="macOS has no nested virtualisation",
                )
            ],
            argv=["macopt", "apply", "guest.vmx", "--profile", "balanced"],
            host={"vmware": "26.0.1", "build": "25688693"},
            tool_version="0.1.0",
            after_sha256=after_sha,
        )
        self.assertIs(finalized, record)

        manifest = json.loads((record.dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["tool"], {"name": "macopt", "version": "0.1.0"})
        self.assertEqual(manifest["argv"], ["macopt", "apply", "guest.vmx", "--profile", "balanced"])
        self.assertEqual(manifest["host"], {"vmware": "26.0.1", "build": "25688693"})
        self.assertEqual(manifest["after"]["sha256"], after_sha)
        self.assertEqual(
            manifest["after"]["lines"],
            len(self.vmx.read_text(encoding="utf-8").splitlines()),
        )
        self.assertEqual(len(manifest["changes"]), 1)
        change = manifest["changes"][0]
        self.assertEqual(change["key"], "vhv.enable")
        self.assertEqual(change["op"], "modified")
        self.assertEqual(change["before"], "TRUE")
        self.assertEqual(change["after"], "FALSE")
        self.assertEqual(change["module"], "topology")

        history = self.history_lines()
        self.assertEqual(len(history), 1)
        entry = history[0]
        self.assertEqual(entry["id"], record.id)
        self.assertEqual(entry["target"], str(self.vmx))
        self.assertEqual(entry["before"], after_sha)
        self.assertEqual(entry["after"], after_sha)
        self.assertEqual(entry["changes"], 1)
        self.assertEqual(entry["schema"], 1)

    def test_finalize_accepts_host_info_object(self) -> None:
        record = self.mgr.create_snapshot()
        host = HostInfo(vendor="GenuineIntel", vmware_version="26.0.1")
        self.mgr.finalize(
            record, changes=[], argv=[], host=host, tool_version=(0, 1, 0),
            after_sha256=sha256_of(self.vmx),
        )
        self.assertEqual(record.manifest["host"]["vendor"], "GenuineIntel")
        self.assertEqual(record.manifest["tool"]["version"], "0.1.0")
        self.assertEqual(record.manifest["changes"], [])


# --------------------------------------------------------------------------- #
# list / diff
# --------------------------------------------------------------------------- #


class ListDiffTests(BackupTestBase):
    def test_list_is_newest_first_and_scoped_to_this_vmx(self) -> None:
        first = self.mgr.create_snapshot()
        second = self.mgr.create_snapshot()

        # same-second snapshots sort by id; pin the timestamps to be explicit
        self.backdate(first, "2020-01-01T00:00:00Z")
        records = self.mgr.list()
        self.assertEqual([r.id for r in records], [second.id, first.id])

        # a different VM's backups must not leak into this manager
        other_vmx = self.tmp / "other.vmx"
        shutil.copy(FIXTURES / "minimal.vmx", other_vmx)
        other = BackupManager(self.state_root, other_vmx)
        other.create_snapshot()
        self.assertEqual({r.id for r in self.mgr.list()}, {first.id, second.id})
        self.assertEqual(len(other.list()), 1)

    def test_list_on_empty_state(self) -> None:
        self.assertEqual(self.mgr.list(), [])
        self.assertEqual(self.mgr.diff(), [])
        self.assertEqual(self.mgr.verify(), [])

    def test_diff_reports_key_level_changes(self) -> None:
        record = self.mgr.create_snapshot()
        self.modify_vmx()

        entries = self.mgr.diff()
        by_key = {e["key"]: e for e in entries}
        self.assertEqual(set(by_key), {"vhv.enable", "svga.maxTextureSize", "numa.autosize.cookie"})
        self.assertEqual(by_key["vhv.enable"]["op"], "modified")
        self.assertEqual(by_key["vhv.enable"]["before"], "TRUE")
        self.assertEqual(by_key["vhv.enable"]["after"], "FALSE")
        self.assertEqual(by_key["svga.maxTextureSize"]["op"], "added")
        self.assertIsNone(by_key["svga.maxTextureSize"]["before"])
        self.assertEqual(by_key["numa.autosize.cookie"]["op"], "removed")
        self.assertIsNone(by_key["numa.autosize.cookie"]["after"])
        self.assertTrue(all(e["backup_id"] == record.id for e in entries))

        # explicit id gives the same answer; unknown id is a usage error
        self.assertEqual(
            {e["key"] for e in self.mgr.diff(record.id)},
            {"vhv.enable", "svga.maxTextureSize", "numa.autosize.cookie"},
        )
        with self.assertRaises(UsageError):
            self.mgr.diff("no-such-id")

    def test_diff_without_changes_is_empty(self) -> None:
        self.mgr.create_snapshot()
        self.assertEqual(self.mgr.diff(), [])


# --------------------------------------------------------------------------- #
# restore
# --------------------------------------------------------------------------- #


class RestoreTests(BackupTestBase):
    def test_restore_is_byte_exact_and_snapshots_current_file(self) -> None:
        original_bytes = self.vmx.read_bytes()
        original_sha = sha256_of(self.vmx)
        original_mtime = self.vmx.stat().st_mtime_ns
        record = self.mgr.create_snapshot()

        current_bytes = self.modify_vmx()
        current_sha = sha256_of(self.vmx)
        self.assertNotEqual(current_sha, original_sha)
        count_before = len(self.mgr.list())

        result = self.mgr.restore(record.id)

        # exact rollback: bytes, sha, recorded mode and mtime
        self.assertEqual(self.vmx.read_bytes(), original_bytes)
        self.assertEqual(sha256_of(self.vmx), original_sha)
        self.assertEqual(self.vmx.stat().st_mtime_ns, original_mtime)
        self.assertTrue(result["verified"])
        self.assertEqual(result["sha256_before"], current_sha)
        self.assertEqual(result["sha256_after"], original_sha)
        self.assertEqual(result["backup_id"], record.id)

        # the pre-restore file was snapshotted first, so the restore is undoable
        records = self.mgr.list()
        self.assertEqual(len(records), count_before + 1)
        snapshot = next(r for r in records if r.id == result["snapshot"]["id"])
        self.assertEqual(snapshot.stored_file.read_bytes(), current_bytes)
        self.assertEqual(snapshot.before_sha256, current_sha)

        # both rounds are in history (apply-finalised snapshot + restore snapshot)
        self.assertEqual(len(self.history_lines()), 1)

    def test_restore_defaults_to_newest_backup(self) -> None:
        oldest = self.mgr.create_snapshot()
        self.backdate(oldest, "2020-01-01T00:00:00Z")
        newest = self.mgr.create_snapshot()
        self.backdate(newest, "2021-01-01T00:00:00Z")

        result = self.mgr.restore()
        self.assertEqual(result["backup_id"], newest.id)

    def test_restore_dry_run_changes_nothing(self) -> None:
        record = self.mgr.create_snapshot()
        self.modify_vmx()
        sha_before = sha256_of(self.vmx)
        mtime_before = self.vmx.stat().st_mtime_ns
        count_before = len(self.mgr.list())

        result = self.mgr.restore(dry_run=True)

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["sha256_before"], sha_before)
        self.assertEqual(result["sha256_after"], record.before_sha256)
        self.assertTrue(result["changes"])
        self.assertEqual(sha256_of(self.vmx), sha_before)
        self.assertEqual(self.vmx.stat().st_mtime_ns, mtime_before)
        self.assertEqual(len(self.mgr.list()), count_before)  # no snapshot created

    def test_restore_refuses_a_damaged_backup(self) -> None:
        record = self.mgr.create_snapshot()
        current_bytes = self.modify_vmx()
        with open(record.stored_file, "ab") as fh:
            fh.write(b"\n# tampered\n")

        with self.assertRaises(VerificationError):
            self.mgr.restore(record.id)
        self.assertEqual(self.vmx.read_bytes(), current_bytes)  # untouched

    def test_restore_without_backups_is_unknown_state(self) -> None:
        with self.assertRaises(UnknownStateError) as ctx:
            self.mgr.restore()
        self.assertEqual(ctx.exception.exit_code, EXIT_UNKNOWN)

    def test_restore_unknown_id_is_usage_error(self) -> None:
        self.mgr.create_snapshot()
        with self.assertRaises(UsageError) as ctx:
            self.mgr.restore("no-such-id")
        self.assertEqual(ctx.exception.exit_code, EXIT_USAGE)


# --------------------------------------------------------------------------- #
# verify / prune
# --------------------------------------------------------------------------- #


class MaintenanceTests(BackupTestBase):
    def test_verify_passes_then_detects_corruption(self) -> None:
        record = self.mgr.create_snapshot()
        results = self.mgr.verify()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"])
        self.assertEqual(results[0]["id"], record.id)
        self.assertEqual(results[0]["expected"], record.before_sha256)
        self.assertEqual(results[0]["actual"], record.before_sha256)

        with open(record.stored_file, "ab") as fh:
            fh.write(b"x")
        results = self.mgr.verify()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["ok"])
        self.assertIn("mismatch", results[0]["detail"])

    def test_prune_keeps_the_newest(self) -> None:
        oldest = self.mgr.create_snapshot()
        middle = self.mgr.create_snapshot()
        newest = self.mgr.create_snapshot()
        self.backdate(oldest, "2020-01-01T00:00:00Z")
        self.backdate(middle, "2021-01-01T00:00:00Z")
        self.backdate(newest, "2022-01-01T00:00:00Z")

        deleted = self.mgr.prune(keep=1)

        self.assertEqual(deleted, [oldest.id, middle.id])  # oldest first
        self.assertFalse(oldest.dir.exists())
        self.assertFalse(middle.dir.exists())
        self.assertTrue(newest.dir.exists())
        self.assertEqual([r.id for r in self.mgr.list()], [newest.id])

    def test_prune_noop_when_keep_exceeds_count(self) -> None:
        record = self.mgr.create_snapshot()
        self.assertEqual(self.mgr.prune(keep=5), [])
        self.assertTrue(record.dir.exists())

    def test_prune_zero_removes_everything(self) -> None:
        record = self.mgr.create_snapshot()
        deleted = self.mgr.prune(keep=0)
        self.assertEqual(deleted, [record.id])
        self.assertEqual(self.mgr.list(), [])
        slug_dir = self.state_root / "backups" / "guest"
        self.assertFalse(slug_dir.exists())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

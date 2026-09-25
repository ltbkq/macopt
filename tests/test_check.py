"""Static check tests: S1..S10 statuses, order and read-only guarantee.

Fixtures under ``tests/fixtures/vmx`` are only ever read; every synthetic
``.vmx`` / log used to provoke FAIL/WARN/SKIP paths is written to a temp dir.
"""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

from macopt import check
from macopt.errors import EXIT_UNKNOWN, UnknownStateError
from macopt.model import FAIL, PASS, SKIP, WARN, CheckResult, HostInfo

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vmx"

IDENTITY_AVAILABLE = importlib.util.find_spec("macopt.profiles.identity") is not None


def host(**overrides) -> HostInfo:
    """Host baseline matching the fixture (16 logical / 10 physical cores)."""
    base = dict(vendor="GenuineIntel", logical_cpus=16, physical_cores=10, numa_nodes=1)
    base.update(overrides)
    return HostInfo(**base)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def index(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {r.id: r for r in results}


class CheckTestBase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="macopt-check-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write_vmx(self, text: str, name: str = "sample.vmx") -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_check(self, fixture: str, **kwargs) -> list[CheckResult]:
        kwargs.setdefault("host", host())
        return check.run(FIXTURES / fixture, kwargs.pop("host"), **kwargs)

    def run_text(self, text: str, **kwargs) -> dict[str, CheckResult]:
        kwargs.setdefault("host", host())
        path = self.write_vmx(text)
        return index(check.run(path, kwargs.pop("host"), **kwargs))


# --------------------------------------------------------------------------- #
# contract: order, statuses, read-only
# --------------------------------------------------------------------------- #


class ContractTests(CheckTestBase):
    def test_fixed_order_and_ten_results(self) -> None:
        results = self.run_check("darwin-balanced.vmx")
        self.assertEqual([r.id for r in results], [f"S{n}" for n in range(1, 11)])
        for result in results:
            self.assertIn(result.status, (PASS, FAIL, WARN, SKIP), result.id)

    def test_never_writes_the_file(self) -> None:
        for name in ("darwin-balanced.vmx", "minimal.vmx", "empty.vmx"):
            path = FIXTURES / name
            before = sha256_of(path)
            mtime = path.stat().st_mtime_ns
            check.run(path, host(), key_policy=lambda key: True)
            self.assertEqual(sha256_of(path), before, name)
            self.assertEqual(path.stat().st_mtime_ns, mtime, name)

    def test_missing_file_is_unknown_state_exit_4(self) -> None:
        with self.assertRaises(UnknownStateError) as ctx:
            check.run(self.tmp / "nope.vmx", host())
        self.assertEqual(ctx.exception.exit_code, EXIT_UNKNOWN)

    def test_directory_input_is_unknown_state_exit_4(self) -> None:
        with self.assertRaises(UnknownStateError) as ctx:
            check.run(self.tmp, host())
        self.assertEqual(ctx.exception.exit_code, EXIT_UNKNOWN)

    def test_expected_results_on_balanced_fixture(self) -> None:
        results = index(self.run_check("darwin-balanced.vmx"))
        self.assertEqual(results["S1"].status, PASS)
        self.assertEqual(results["S2"].status, WARN)  # 12 vCPU > 10 physical cores
        self.assertEqual(results["S3"].status, PASS)
        self.assertEqual(results["S4"].status, WARN)  # 8 < 12 -> split vNUMA
        self.assertEqual(results["S5"].status, WARN)  # vhv.enable=TRUE
        self.assertEqual(results["S7"].status, PASS)  # coresPerSocket is not a mask
        self.assertEqual(results["S8"].status, SKIP)  # no log given
        self.assertEqual(results["S9"].status, WARN)  # duplicated svga.vram0Size
        self.assertEqual(results["S10"].status, SKIP)  # no key policy given


# --------------------------------------------------------------------------- #
# S1..S10 individually
# --------------------------------------------------------------------------- #


class S1GuestOsTests(CheckTestBase):
    def test_known_darwin_tier_passes(self) -> None:
        for name in ("darwin-balanced.vmx", "minimal.vmx"):
            with self.subTest(fixture=name):
                self.assertEqual(self.run_check(name)[0].status, PASS)

    def test_unknown_darwin_tier_warns(self) -> None:
        results = self.run_text('guestOS = "darwin99-64"\n')
        self.assertEqual(results["S1"].status, WARN)
        self.assertIn("darwin99-64", results["S1"].detail)

    def test_missing_guestos_fails(self) -> None:
        results = self.run_text("numvcpus = \"4\"\n")
        self.assertEqual(results["S1"].status, FAIL)

    def test_non_darwin_guestos_fails(self) -> None:
        results = self.run_text('guestOS = "ubuntu64-64"\n')
        self.assertEqual(results["S1"].status, FAIL)

    def test_empty_file_fails_s1(self) -> None:
        results = self.run_check("empty.vmx")
        self.assertEqual(results[0].status, FAIL)


class S2NumvcpusTests(CheckTestBase):
    def test_oversubscription_warns(self) -> None:
        self.assertEqual(self.run_check("darwin-balanced.vmx")[1].status, WARN)

    def test_sensible_allocation_passes(self) -> None:
        self.assertEqual(self.run_check("minimal.vmx")[1].status, PASS)

    def test_thread_oversubscription_warns(self) -> None:
        results = self.run_text('guestOS = "darwin24-64"\nnumvcpus = "32"\n')
        self.assertEqual(results["S2"].status, WARN)
        self.assertIn("logical CPUs", results["S2"].detail)

    def test_unknown_host_skips(self) -> None:
        results = self.run_check("darwin-balanced.vmx", host=host(logical_cpus=0, physical_cores=0))
        self.assertEqual(index(results)["S2"].status, SKIP)

    def test_missing_numvcpus_skips(self) -> None:
        results = self.run_text("guestOS = \"darwin24-64\"\n")
        self.assertEqual(results["S2"].status, SKIP)

    def test_unparseable_numvcpus_fails(self) -> None:
        results = self.run_text('guestOS = "darwin24-64"\nnumvcpus = "twelve"\n')
        self.assertEqual(results["S2"].status, FAIL)


class S3CoresPerSocketTests(CheckTestBase):
    def test_divisible_topology_passes(self) -> None:
        for name in ("darwin-balanced.vmx", "minimal.vmx"):
            with self.subTest(fixture=name):
                self.assertEqual(self.run_check(name)[2].status, PASS)

    def test_non_divisible_fails(self) -> None:
        results = self.run_text(
            'guestOS = "darwin24-64"\nnumvcpus = "12"\ncpuid.coresPerSocket = "5"\n'
        )
        self.assertEqual(results["S3"].status, FAIL)
        self.assertIn("not a multiple", results["S3"].detail)

    def test_missing_keys_skip(self) -> None:
        results = self.run_text('guestOS = "darwin24-64"\nnumvcpus = "4"\n')
        self.assertEqual(results["S3"].status, SKIP)


class S4VNumaTests(CheckTestBase):
    def test_split_vnuma_warns(self) -> None:
        self.assertEqual(self.run_check("darwin-balanced.vmx")[3].status, WARN)

    def test_single_node_passes(self) -> None:
        results = self.run_text(
            'guestOS = "darwin24-64"\nnumvcpus = "12"\n'
            'numa.autosize.vcpu.maxPerVirtualNode = "12"\n'
        )
        self.assertEqual(results["S4"].status, PASS)

    def test_missing_keys_skip(self) -> None:
        self.assertEqual(self.run_check("minimal.vmx")[3].status, SKIP)

    def test_unparseable_value_fails(self) -> None:
        results = self.run_text(
            'guestOS = "darwin24-64"\nnumvcpus = "12"\n'
            'numa.autosize.vcpu.maxPerVirtualNode = "many"\n'
        )
        self.assertEqual(results["S4"].status, FAIL)


class S5VhvTests(CheckTestBase):
    def test_enabled_warns(self) -> None:
        self.assertEqual(self.run_check("darwin-balanced.vmx")[4].status, WARN)

    def test_disabled_passes(self) -> None:
        self.assertEqual(self.run_check("minimal.vmx")[4].status, PASS)

    def test_absent_passes(self) -> None:
        results = self.run_text('guestOS = "darwin24-64"\n')
        self.assertEqual(results["S5"].status, PASS)


class S6IdentityTests(CheckTestBase):
    CONFLICT = (
        'guestOS = "darwin24-64"\n'
        'board-id.reflectHost = "TRUE"\n'
        'board-id = "Mac-TESTBOARDID0001"\n'
    )
    CLEAN = 'guestOS = "darwin24-64"\nboard-id.reflectHost = "TRUE"\n'

    @unittest.skipUnless(IDENTITY_AVAILABLE, "identity module not ready")
    def test_reflect_and_explicit_value_conflict_fails(self) -> None:
        results = self.run_text(self.CONFLICT)
        self.assertEqual(results["S6"].status, FAIL)
        self.assertIn("board-id", results["S6"].detail)

    @unittest.skipUnless(IDENTITY_AVAILABLE, "identity module not ready")
    def test_consistent_identity_block_passes(self) -> None:
        results = self.run_text(self.CLEAN)
        self.assertEqual(results["S6"].status, PASS)

    @unittest.skipUnless(not IDENTITY_AVAILABLE, "identity module present: S6 runs")
    def test_s6_skips_until_identity_module_exists(self) -> None:
        results = self.run_text(self.CONFLICT)
        self.assertEqual(results["S6"].status, SKIP)
        self.assertIn("not available", results["S6"].detail)


class S7CpuidMaskTests(CheckTestBase):
    MASK_VMX = 'guestOS = "darwin24-64"\ncpuid.1.ebx = "0x02010800"\n'

    def test_no_masks_passes(self) -> None:
        results = self.run_check("darwin-balanced.vmx")[6]
        self.assertEqual(results.status, PASS)
        self.assertIn("cpuid.coresPerSocket", results.detail)  # named key, not a mask

    def test_mask_presence_warns(self) -> None:
        results = self.run_text(self.MASK_VMX)
        self.assertEqual(results["S7"].status, WARN)
        self.assertIn("cpuid.1.ebx", results["S7"].detail)

    def test_mask_outside_whitelist_fails(self) -> None:
        path = self.write_vmx(self.MASK_VMX)
        results = check.run(path, host(), key_policy=lambda key: key != "cpuid.1.ebx")
        self.assertEqual(index(results)["S7"].status, FAIL)

    def test_mask_inside_whitelist_still_notices(self) -> None:
        path = self.write_vmx(self.MASK_VMX)
        results = check.run(path, host(), key_policy=lambda key: True)
        self.assertEqual(index(results)["S7"].status, WARN)

    def test_named_cpuid_keys_are_not_masks(self) -> None:
        self.assertTrue(check._is_cpuid_mask("cpuid.1.ebx"))
        self.assertTrue(check._is_cpuid_mask("cpuid.7.0.edx"))
        self.assertTrue(check._is_cpuid_mask("cpuid.80000001.ecx.amd"))
        self.assertFalse(check._is_cpuid_mask("cpuid.coresPerSocket"))
        self.assertFalse(check._is_cpuid_mask("cpuid.brandString"))
        self.assertFalse(check._is_cpuid_mask("cpuid.avx2"))


class S8ToolsTests(CheckTestBase):
    def write_log(self, text: str, name: str = "vmware.log") -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_without_log_skips(self) -> None:
        self.assertEqual(self.run_check("darwin-balanced.vmx")[7].status, SKIP)

    def test_missing_log_skips(self) -> None:
        results = self.run_check(
            "darwin-balanced.vmx", log_path=self.tmp / "absent.log"
        )
        self.assertEqual(index(results)["S8"].status, SKIP)

    def test_install_error_warns(self) -> None:
        log = self.write_log(
            "Log for VMware Workstation pid=42\n"
            'DICT                  toolsInstallManager.lastInstallError = "21004"\n'
        )
        results = index(self.run_check("darwin-balanced.vmx", log_path=log))
        self.assertEqual(results["S8"].status, WARN)
        self.assertIn("21004", results["S8"].detail)
        self.assertTrue(results["S8"].evidence)
        self.assertTrue(results["S8"].evidence[0].source.endswith(":2"))

    def test_clean_log_passes(self) -> None:
        log = self.write_log('toolsInstallManager.lastInstallError = "0"\n')
        self.assertEqual(
            index(self.run_check("minimal.vmx", log_path=log))["S8"].status, PASS
        )

    def test_log_without_the_line_skips(self) -> None:
        log = self.write_log("Log for VMware Workstation pid=42\nnothing here\n")
        self.assertEqual(
            index(self.run_check("minimal.vmx", log_path=log))["S8"].status, SKIP
        )


class S9DuplicateTests(CheckTestBase):
    def test_duplicates_warn(self) -> None:
        results = self.run_check("darwin-balanced.vmx")[8]
        self.assertEqual(results.status, WARN)
        self.assertIn("svga.vram0Size", results.detail)
        self.assertTrue(results.evidence)

    def test_clean_file_passes(self) -> None:
        self.assertEqual(self.run_check("minimal.vmx")[8].status, PASS)


class S10WhitelistTests(CheckTestBase):
    def test_without_policy_skips(self) -> None:
        self.assertEqual(self.run_check("darwin-balanced.vmx")[9].status, SKIP)

    def test_all_keys_known_passes(self) -> None:
        results = self.run_check("darwin-balanced.vmx", key_policy=lambda key: True)
        self.assertEqual(index(results)["S10"].status, PASS)

    def test_unknown_key_warns_by_default(self) -> None:
        results = self.run_check(
            "darwin-balanced.vmx", key_policy=lambda key: key != "vhv.enable"
        )
        s10 = index(results)["S10"]
        self.assertEqual(s10.status, WARN)
        self.assertIn("vhv.enable", s10.detail)
        self.assertTrue(s10.evidence)

    def test_strict_promotes_to_fail(self) -> None:
        results = self.run_check(
            "darwin-balanced.vmx",
            key_policy=lambda key: key != "vhv.enable",
            strict=True,
        )
        self.assertEqual(index(results)["S10"].status, FAIL)

    def test_strict_without_violations_stays_pass(self) -> None:
        results = self.run_check("minimal.vmx", key_policy=lambda key: True, strict=True)
        self.assertEqual(index(results)["S10"].status, PASS)


class EmptyFileTests(CheckTestBase):
    def test_empty_file_produces_only_valid_statuses(self) -> None:
        results = index(self.run_check("empty.vmx", key_policy=lambda key: True))
        self.assertEqual(results["S1"].status, FAIL)
        for check_id in ("S2", "S3", "S4"):
            self.assertEqual(results[check_id].status, SKIP, check_id)
        self.assertEqual(results["S9"].status, PASS)
        self.assertEqual(results["S10"].status, PASS)  # no keys at all


class FixtureHygieneTests(unittest.TestCase):
    """The fixture set must stay minimal and machine-independent."""

    def test_fixture_files_exist(self) -> None:
        for name in ("darwin-balanced.vmx", "minimal.vmx", "empty.vmx"):
            self.assertTrue((FIXTURES / name).is_file(), name)

    def test_fixture_contains_required_keys(self) -> None:
        from macopt.vmxfile import Document

        doc = Document.load(FIXTURES / "darwin-balanced.vmx")
        self.assertEqual(doc.get("guestOS"), "darwin24-64")
        self.assertEqual(doc.get("numvcpus"), "12")
        self.assertEqual(doc.get("cpuid.coresPerSocket"), "12")
        self.assertEqual(doc.get("numa.autosize.cookie"), "120122")
        self.assertEqual(doc.get("numa.autosize.vcpu.maxPerVirtualNode"), "8")
        self.assertEqual(doc.get("vhv.enable"), "TRUE")
        self.assertIn("svga.vram0Size", doc.duplicates)

    def test_empty_fixture_is_empty(self) -> None:
        self.assertEqual((FIXTURES / "empty.vmx").read_text(encoding="utf-8"), "")

    def test_fixtures_are_not_written_by_tests(self) -> None:
        before = {p: sha256_of(p) for p in FIXTURES.glob("*.vmx")}
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        shutil.copy(FIXTURES / "darwin-balanced.vmx", Path(tmp.name) / "guest.vmx")
        after = {p: sha256_of(p) for p in FIXTURES.glob("*.vmx")}
        self.assertEqual(before, after)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

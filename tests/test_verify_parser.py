"""Unit tests for ``macopt.verify.parser`` (V0–V7 log-fact extraction).

Covers: header facts, guestOS, capability/DICT lines, the ``guest vs. host
CPUID`` block (presence/absence, vendor, family/model/stepping, raw hex
levels, per-vCPU traces), evidence line numbers, degradation paths (no block
⇒ no per-vCPU facts), kHz/TSC estimates, ``decode_fms``/``vendor_from_leaf0``
math and fixture sanitisation.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from macopt.verify.parser import (
    LogFacts,
    as_ints,
    decode_fms,
    parse_log,
    parse_log_path,
    vendor_from_leaf0,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "verify"
FULL = FIXTURES / "full.log"
MINIMAL = FIXTURES / "minimal.log"

# Real host data that must never appear in a shipped fixture.
FORBIDDEN_SUBSTRINGS = (
    "/home/wang",
    "/media/",
    "/mnt/d/",
    "macOS 15",
    "password",
    "secret",
    "token=",
    "vmware.log:",  # evidence sources live in code, never in a fixture
)
# Explicit sanitisation placeholders the fixtures must use instead.
REQUIRED_PLACEHOLDERS = ("/home/<user>", "/mnt/<mount>", "<vm-name>", "<mac>")

MAC_RE = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.IGNORECASE)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def _raw_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


class ParseFullLogTest(unittest.TestCase):
    """``full.log`` exercises every parser feature at least once."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.facts = parse_log_path(FULL)
        cls.lines = _raw_lines(FULL)

    # -- header ------------------------------------------------------------- #

    def test_timestamp_and_version(self) -> None:
        self.assertEqual(self.facts.timestamp, "2026-09-25T11:27:32.558Z")
        self.assertEqual(self.facts.vmware_version, "26.0.1")
        self.assertEqual(self.facts.vmware_build, "25688693")
        self.assertEqual(self.facts.version_lineno, 1)

    def test_guestos_from_powering_on_line(self) -> None:
        self.assertEqual(self.facts.guestos, "darwin24-64")
        self.assertEqual(self.facts.guestos_lineno, 32)
        self.assertIn("Powering on guestOS", self.lines[31])

    def test_guestos_absent_without_powering_on_line(self) -> None:
        text = "\n".join(line for line in self.lines if "Powering on" not in line)
        facts = parse_log(text)
        self.assertIsNone(facts.guestos)
        self.assertIsNone(facts.guestos_lineno)

    def test_path_metadata(self) -> None:
        self.assertEqual(self.facts.name, "full.log")
        self.assertIsInstance(self.facts.mtime, float)
        self.assertGreater(self.facts.mtime, 0)
        self.assertEqual(self.facts.raw, FULL.read_text(encoding="utf-8"))
        self.assertEqual(len(self.facts.lines), len(self.lines))

    # -- CPUID block -------------------------------------------------------- #

    def test_block_detected_with_header_line(self) -> None:
        self.assertTrue(self.facts.has_cpuid_block)
        self.assertEqual(self.facts.block_lineno, 43)  # first block line

    def test_vendor_and_self_reported_fm(self) -> None:
        self.assertEqual(self.facts.vendor, "GenuineIntel")
        self.assertEqual(self.facts.vendor_lineno, 43)
        self.assertEqual(self.facts.guest_fm, (6, 0x4E, 3))
        self.assertEqual(self.facts.guest_fm_lineno, 44)
        self.assertEqual(self.facts.host_fm, (6, 0xBA, 2))
        self.assertEqual(self.facts.host_fm_lineno, 45)

    def test_codenames_and_names(self) -> None:
        self.assertEqual(self.facts.guest_codename, "Skylake-Y")
        self.assertEqual(self.facts.host_codename, "Raptor Lake H/P/PX/U")
        self.assertEqual(self.facts.guest_name, "13th Gen Intel(R) Core(TM) i7-13620H")
        self.assertEqual(self.facts.host_name, "13th Gen Intel(R) Core(TM) i7-13620H")

    def test_guest_levels_keep_raw_hex_strings(self) -> None:
        leaf1 = self.facts.guest_levels[(1, 0)]
        self.assertEqual(
            leaf1, ("0x000406e3", "0x00100800", "0xf7fa322b", "0x1f8bfbff")
        )
        for reg in leaf1:
            self.assertIsInstance(reg, str)
            self.assertTrue(reg.startswith("0x"))
        self.assertEqual(self.facts.guest_levels[(0, 0)][1], "0x756e6547")
        self.assertEqual(self.facts.guest_levels[(7, 0)][1], "0x219c27eb")
        self.assertEqual(
            self.facts.guest_levels[(0x40000000, 0)],
            ("0x40000010", "0x61774d56", "0x4d566572", "0x65726177"),
        )

    def test_guest_level_keys_and_line_numbers(self) -> None:
        self.assertEqual(
            set(self.facts.guest_levels),
            {(0, 0), (1, 0), (7, 0), (0x15, 0), (0x16, 0), (0x40000000, 0), (0x80000001, 0)},
        )
        self.assertEqual(self.facts.guest_level_lines[(1, 0)], 51)
        self.assertEqual(self.facts.guest_level_lines[(0x40000000, 0)], 59)
        for key, lineno in self.facts.guest_level_lines.items():
            self.assertIn("guest level", self.lines[lineno - 1], key)

    def test_host_levels_merge_headers_and_in_block_dump(self) -> None:
        # header dump (hostCPUID level …) supplies leaf 0,
        self.assertEqual(self.facts.host_level_lines[(0, 0)], 6)
        # in-block "*host level …" wins where both exist.
        self.assertEqual(self.facts.host_level_lines[(1, 0)], 52)
        self.assertEqual(self.facts.host_level_lines[(7, 0)], 54)
        self.assertEqual(
            self.facts.host_levels[(1, 0)],
            ("0x000b06a2", "0x11800800", "0x7ffafbff", "0xbfebfbff"),
        )
        self.assertEqual(self.facts.host_levels[(7, 0)][1], "0x239c27eb")
        self.assertEqual(set(self.facts.host_levels), {(0, 0), (1, 0), (7, 0), (0x15, 0), (0x16, 0)})

    def test_fm_decodes_match_self_report(self) -> None:
        """V2's cross-check must hold: decode(guest leaf1) == self-report."""
        eax = int(self.facts.guest_levels[(1, 0)][0], 16)
        self.assertEqual(decode_fms(eax), self.facts.guest_fm)
        host_eax = int(self.facts.host_levels[(1, 0)][0], 16)
        self.assertEqual(decode_fms(host_eax), self.facts.host_fm)

    def test_no_per_vcpu_leaf1_trace(self) -> None:
        # Workstation only traces leaves it does not synthesise (0x16, 0x1f
        # here), so leaf 1 per-vCPU records are absent — V5 degrades.
        self.assertEqual(self.facts.per_vcpu_leaf1, [])

    def test_level_ints_helper(self) -> None:
        ints = self.facts.level_ints("guest", 1)
        self.assertEqual(ints, (0x000406E3, 0x00100800, 0xF7FA322B, 0x1F8BFBFF))
        self.assertEqual(
            self.facts.level_ints("host", 1), (0x000B06A2, 0x11800800, 0x7FFAFBFF, 0xBFEBFBFF)
        )
        self.assertIsNone(self.facts.level_ints("guest", 5))
        self.assertIsNone(self.facts.level_ints("host", 0x40000000))

    # -- evidence categories ------------------------------------------------ #

    def test_tools_errors_evidence(self) -> None:
        self.assertEqual([n for n, _ in self.facts.tools_errors], [28, 37, 38])
        for lineno, text in self.facts.tools_errors:
            self.assertEqual(text, self.lines[lineno - 1])
        self.assertIn("lastInstallError", self.facts.tools_errors[0][1])
        self.assertIn("heartbeat timeout", self.facts.tools_errors[1][1])
        self.assertIn("VIX_E_TOOLS", self.facts.tools_errors[2][1])
        # The benign ToolsISO signature warning is deliberately not an error.
        self.assertFalse(any("ToolsISO" in t for _, t in self.facts.tools_errors))

    def test_proxy_and_numa_evidence(self) -> None:
        self.assertEqual([n for n, _ in self.facts.vmm_vcpus], [35])
        self.assertIn("vmm-vcpus:  12", self.facts.vmm_vcpus[0][1])
        self.assertEqual([n for n, _ in self.facts.local_apic], [61])
        self.assertIn("OvhdUser_LocalApic", self.facts.local_apic[0][1])
        self.assertEqual([n for n, _ in self.facts.numa_lines], [14, 15, 16, 26, 27, 34])
        for lineno, text in self.facts.numa_lines:
            self.assertEqual(text, self.lines[lineno - 1])
            self.assertNotIn("OvhdMem", text)

    def test_all_evidence_is_line_addressed(self) -> None:
        total = (
            len(self.facts.tools_errors)
            + len(self.facts.local_apic)
            + len(self.facts.vmm_vcpus)
            + len(self.facts.numa_lines)
        )
        self.assertGreater(total, 0)
        for category in (self.facts.tools_errors, self.facts.local_apic,
                         self.facts.vmm_vcpus, self.facts.numa_lines):
            for lineno, _text in category:
                self.assertGreaterEqual(lineno, 1)
                self.assertLessEqual(lineno, len(self.lines))

    # -- DICT / capability / estimates -------------------------------------- #

    def test_dict_entries(self) -> None:
        self.assertEqual(len(self.facts.dict_entries), 15)
        value, lineno = self.facts.dict_entries["guestOS"]
        self.assertEqual((value, lineno), ("darwin24-64", 20))
        self.assertEqual(self.facts.dict_entries["numvcpus"][0], "12")
        self.assertEqual(self.facts.dict_entries["cpuid.coresPerSocket"][0], "12")
        self.assertEqual(self.facts.dict_entries["displayName"][0], "<vm-name>")
        self.assertEqual(
            self.facts.dict_entries["sata0:0.fileName"][0],
            "/home/<user>/vmware/<vm-name>/disk.vmdk",
        )
        self.assertEqual(self.facts.dict_entries["sata0:1.fileName"][0], "/mnt/<mount>/iso/<image>.iso")
        self.assertEqual(self.facts.dict_entries["ethernet0.address"][0], "<mac>")
        # first occurrence wins (DICT is echoed once per key in practice)
        for key, (val, ln) in self.facts.dict_entries.items():
            self.assertEqual(
                val, self.lines[ln - 1].split(" = ", 1)[1].strip().strip('"'), key
            )

    def test_capability_lines(self) -> None:
        self.assertEqual(
            set(self.facts.capabilities),
            {"cpuid.sse42", "cpuid.aes", "cpuid.xsave", "cpuid.avx2"},
        )
        self.assertEqual(self.facts.capabilities["cpuid.avx2"], ("1", 42))
        self.assertEqual(self.facts.capabilities["cpuid.sse42"], ("1", 39))

    def test_khz_and_tsc_estimates(self) -> None:
        self.assertEqual(self.facts.khz_estimate, 2918400)
        self.assertEqual(self.facts.khz_estimate_lineno, 12)
        self.assertEqual(
            self.facts.tsc_estimates, (2918400000, 4641551000, 4900000000, 0)
        )
        self.assertEqual(self.facts.tsc_estimates_lineno, 13)

    # -- pure parse ---------------------------------------------------------- #

    def test_parse_log_leaves_mtime_and_name_default(self) -> None:
        text = FULL.read_text(encoding="utf-8")
        facts = parse_log(text)
        self.assertIsNone(facts.mtime)  # only parse_log_path() records mtime
        self.assertEqual(facts.name, "vmware.log")  # default evidence name
        self.assertEqual(facts.raw, text)

    def test_empty_text_is_all_default(self) -> None:
        facts = parse_log("")
        self.assertFalse(facts.has_cpuid_block)
        self.assertIsNone(facts.block_lineno)
        self.assertEqual(facts.lines, [])
        self.assertEqual(facts.guest_levels, {})
        self.assertEqual(facts.tools_errors, [])
        self.assertIsNone(facts.timestamp)


class ParseMinimalLogTest(unittest.TestCase):
    """``minimal.log`` has no CPUID block: everything block-derived is empty."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.facts = parse_log_path(MINIMAL)

    def test_header_and_guestos_present(self) -> None:
        self.assertEqual(self.facts.vmware_version, "26.0.1")
        self.assertEqual(self.facts.timestamp, "2026-09-25T11:27:32.558Z")
        self.assertEqual(self.facts.guestos, "darwin24-64")
        self.assertEqual(self.facts.guestos_lineno, 6)

    def test_no_block_means_no_cpuid_facts(self) -> None:
        self.assertFalse(self.facts.has_cpuid_block)
        self.assertIsNone(self.facts.block_lineno)
        self.assertIsNone(self.facts.vendor)
        self.assertIsNone(self.facts.vendor_lineno)
        self.assertIsNone(self.facts.guest_fm)
        self.assertIsNone(self.facts.host_fm)
        self.assertIsNone(self.facts.guest_codename)
        self.assertEqual(self.facts.guest_levels, {})
        self.assertEqual(self.facts.host_levels, {})
        self.assertEqual(self.facts.guest_level_lines, {})
        self.assertEqual(self.facts.per_vcpu_leaf1, [])
        self.assertIsNone(vendor_from_leaf0(self.facts.guest_levels.get((0, 0))))

    def test_side_evidence_still_available(self) -> None:
        self.assertEqual(self.facts.dict_entries["numvcpus"][0], "8")
        self.assertEqual(self.facts.dict_entries["cpuid.coresPerSocket"][0], "8")
        self.assertEqual([n for n, _ in self.facts.vmm_vcpus], [7])
        self.assertEqual([n for n, _ in self.facts.local_apic], [8])
        self.assertEqual(self.facts.numa_lines, [])
        self.assertEqual(self.facts.tools_errors, [])
        self.assertEqual(self.facts.capabilities, {})
        self.assertIsNone(self.facts.khz_estimate)
        self.assertIsNone(self.facts.tsc_estimates)

    def test_path_metadata(self) -> None:
        self.assertEqual(self.facts.name, "minimal.log")
        self.assertIsInstance(self.facts.mtime, float)
        self.assertGreater(self.facts.mtime, 0)


class DecodeFmsTest(unittest.TestCase):
    def test_spec_samples(self) -> None:
        self.assertEqual(decode_fms(0x000406E3), (6, 0x4E, 3))  # guest
        self.assertEqual(decode_fms(0x000B06A2), (6, 0xBA, 2))  # host

    def test_high_nibble_of_model_comes_from_extended_model(self) -> None:
        # base model 0xE sits in bits 7:4, extended model 4 in bits 19:16.
        self.assertEqual(decode_fms(0x000406E3)[1], 0x4E)
        self.assertEqual(decode_fms(0x000B06A2)[1], 0xBA)

    def test_base_family_below_0xf_ignores_extended_family(self) -> None:
        eax = (5 << 20) | (0xE << 8) | (0x3 << 4) | 0x1  # family 14, ext bits set
        self.assertEqual(decode_fms(eax), (0xE, 0x3, 1))

    def test_base_family_0xf_adds_extended_family_per_spec(self) -> None:
        # spec: family = base==0xF ? base + (ext<<4) : base
        eax = (0x1 << 20) | (0xF << 8) | (0x3 << 4) | 0x2
        self.assertEqual(decode_fms(eax), (0xF + (1 << 4), 0x3, 2))

    def test_stepping_is_low_nibble(self) -> None:
        for eax in (0x000406E3, 0x000B06A2, 0xA5):
            self.assertEqual(decode_fms(eax)[2], eax & 0xF)


class AsIntsTest(unittest.TestCase):
    def test_converts_hex_strings(self) -> None:
        self.assertEqual(
            as_ints(("0x000406e3", "0x00100800", "0xf7fa322b", "0x1f8bfbff")),
            (0x000406E3, 0x00100800, 0xF7FA322B, 0x1F8BFBFF),
        )

    def test_none_passes_through(self) -> None:
        self.assertIsNone(as_ints(None))


class VendorFromLeaf0Test(unittest.TestCase):
    def test_intel(self) -> None:
        self.assertEqual(
            vendor_from_leaf0(
                ("0x00000020", "0x756e6547", "0x6c65746e", "0x49656e69")
            ),
            "GenuineIntel",
        )

    def test_amd(self) -> None:
        self.assertEqual(
            vendor_from_leaf0(
                ("0x0000000d", "0x68747541", "0x444d4163", "0x69746e65")
            ),
            "AuthenticAMD",
        )

    def test_none_for_missing_or_non_ascii(self) -> None:
        self.assertIsNone(vendor_from_leaf0(None))
        self.assertIsNone(vendor_from_leaf0(("0x0", "0x0", "0x0", "0x0")))


class LogFactsDefaultsTest(unittest.TestCase):
    def test_constructible_with_no_arguments(self) -> None:
        facts = LogFacts()
        self.assertEqual(facts.lines, [])
        self.assertEqual(facts.raw, "")
        self.assertIsNone(facts.mtime)
        self.assertEqual(facts.name, "vmware.log")
        self.assertFalse(facts.has_cpuid_block)
        self.assertEqual(facts.dict_entries, {})


class FixtureSanitisationTest(unittest.TestCase):
    """Fixtures must be portable: placeholders only, <=300 lines each."""

    def test_fixture_line_budget(self) -> None:
        for path in (FULL, MINIMAL):
            count = len(path.read_text(encoding="utf-8").splitlines())
            self.assertLessEqual(count, 300, f"{path.name} has {count} lines")

    def test_no_forbidden_substrings(self) -> None:
        for path in (FULL, MINIMAL):
            text = path.read_text(encoding="utf-8")
            for bad in FORBIDDEN_SUBSTRINGS:
                self.assertNotIn(bad, text, f"{path.name} leaks {bad!r}")

    def test_required_placeholders_used(self) -> None:
        text = FULL.read_text(encoding="utf-8")
        for placeholder in REQUIRED_PLACEHOLDERS:
            self.assertIn(placeholder, text, f"missing placeholder {placeholder}")

    def test_no_mac_or_uuid_patterns(self) -> None:
        for path in (FULL, MINIMAL):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(MAC_RE.search(text), f"{path.name} contains a MAC")
            self.assertIsNone(UUID_RE.search(text), f"{path.name} contains a UUID")

    def test_fixtures_still_parse_after_sanitisation(self) -> None:
        facts = parse_log_path(FULL)
        self.assertTrue(facts.has_cpuid_block)
        self.assertEqual(facts.guest_fm, (6, 0x4E, 3))
        self.assertEqual(facts.dict_entries["guestOS"][0], "darwin24-64")
        self.assertEqual(facts.dict_entries["sata0:0.fileName"][0], "/home/<user>/vmware/<vm-name>/disk.vmdk")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

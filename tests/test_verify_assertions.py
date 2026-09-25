"""Unit tests for ``macopt.verify.assertions`` (V0–V10).

Two design invariants are exercised throughout (``docs/DESIGN.md`` §4.13):

* a **missing** log line yields ``SKIP``, never ``FAIL``;
* a present line with a **wrong** value yields ``FAIL`` (or ``WARN`` where
  the design's verdict column allows only PASS/WARN).

Synthetic logs are built line-by-line so each check can be driven down its
individual branches; ``full.log`` anchors the realistic end-to-end path.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from macopt.model import EVIDENCE_KINDS, FAIL, PASS, SKIP, WARN, CheckResult
from macopt.verify.assertions import CHECKS, KNOWN_DARWIN_TIERS, run
from macopt.verify.parser import LogFacts, parse_log, parse_log_path

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "verify"
FULL = FIXTURES / "full.log"
MINIMAL = FIXTURES / "minimal.log"

HEADER = (
    '2026-09-25T11:27:32.558Z -INFO vmware-vmx 1234 [vmx threadName="vmx"] '
    "Log for VMware Workstation pid=1234 version=26.0.1 build=25688693 option=Release"
)

INTEL_LEAF0 = ("0x00000020", "0x756e6547", "0x6c65746e", "0x49656e69")
AMD_LEAF0 = ("0x0000000d", "0x68747541", "0x444d4163", "0x69746e65")

SOURCE_RE = re.compile(r"^vmware\.log:\d+$")


def greg(leaf: int, subleaf: int, eax: str, ebx: str, ecx: str, edx: str) -> str:
    """One ``guest vs. host CPUID guest level …`` register line."""
    return (
        f"guest vs. host CPUID guest level {leaf:08x},  {subleaf:x}: "
        f"{eax} {ebx} {ecx} {edx}"
    )


def make_log(*lines: str) -> LogFacts:
    return parse_log("\n".join(lines) + ("\n" if lines else ""))


def by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {r.id: r for r in results}


def full_facts() -> LogFacts:
    return parse_log_path(FULL)


def vendor_log(*, vendor: str, leaf0: tuple[str, str, str, str] | None = None) -> LogFacts:
    lines = [HEADER, f"guest vs. host CPUID guest vendor: {vendor}"]
    if leaf0 is not None:
        lines.append(greg(0, 0, *leaf0))
    return make_log(*lines)


def cpuid_log(
    *,
    ecx: str = "0xf7fa322b",
    leaf7_ebx: str | None = "0x219c27eb",
    self_report: str | None = None,
    extra: tuple[str, ...] = (),
) -> LogFacts:
    """Minimal block: vendor line + guest leaf 1 (+ optional leaf 7)."""
    lines = [HEADER, "guest vs. host CPUID guest vendor: GenuineIntel"]
    if self_report is not None:
        lines.append(f"guest vs. host CPUID {self_report}")
    lines.append(greg(1, 0, "0x000406e3", "0x00100800", ecx, "0x1f8bfbff"))
    if leaf7_ebx is not None:
        lines.append(greg(7, 0, "0x00000002", leaf7_ebx, "0x9840078c", "0xbc004410"))
    lines.extend(extra)
    return make_log(*lines)


def per_vcpu_log(apic_ids: list[int]) -> LogFacts:
    """Block with per-vCPU ``CPUID[n] level 1`` traces (initial APIC ID in EBX.31:24)."""
    lines = [HEADER, "guest vs. host CPUID guest vendor: GenuineIntel"]
    for vcpu, apic in enumerate(apic_ids):
        lines.append(
            f"CPUID[{vcpu}] level 00000001, 0: 0x000406e3 0x{apic:02x}000000 "
            f"0xf7fa322b 0x1f8bfbff"
        )
    return make_log(*lines)


# --------------------------------------------------------------------------- #
# ordering / contract
# --------------------------------------------------------------------------- #

class OrderingTest(unittest.TestCase):
    def test_returns_eleven_checks_in_design_order(self) -> None:
        results = run(full_facts(), {})
        self.assertEqual(len(results), 11)
        self.assertEqual([r.id for r in results], [f"V{i}" for i in range(11)])
        self.assertEqual([r.title for r in results], [t for _, t in CHECKS])
        self.assertTrue(all(isinstance(r, CheckResult) for r in results))

    def test_results_only_use_the_four_legal_statuses(self) -> None:
        for facts, vmx in ((full_facts(), {}), (parse_log_path(MINIMAL), {}), (make_log(), {})):
            for r in run(facts, vmx):
                self.assertIn(r.status, (PASS, FAIL, WARN, SKIP), r.id)


# --------------------------------------------------------------------------- #
# V0 — freshness gate
# --------------------------------------------------------------------------- #

class V0FreshnessTest(unittest.TestCase):
    def test_stale_log_fails(self) -> None:
        r = by_id(run(full_facts(), {}, vmx_mtime=2000.0, log_mtime=1000.0))["V0"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("stale log", r.detail)
        self.assertIn("power off, boot the VM again", r.detail)
        self.assertTrue(any(e.source == "mtime: log < vmx" for e in r.evidence))

    def test_fresh_log_passes(self) -> None:
        r = by_id(run(full_facts(), {}, vmx_mtime=1000.0, log_mtime=2000.0))["V0"]
        self.assertEqual(r.status, PASS)
        self.assertIn("fresh", r.detail)
        self.assertIn("26.0.1", r.detail)  # version note is always reported
        self.assertTrue(any(e.source == "mtime: log >= vmx" for e in r.evidence))

    def test_missing_vmx_mtime_skips(self) -> None:
        r = by_id(run(full_facts(), {}, vmx_mtime=None, log_mtime=2000.0))["V0"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("vmx_mtime unknown", r.detail)

    def test_missing_log_mtime_skips(self) -> None:
        # parse_log() records no mtime, so run() has nothing to compare.
        r = by_id(run(parse_log(FULL.read_text(encoding="utf-8")), {}, vmx_mtime=1000.0))["V0"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("log_mtime unknown", r.detail)

    def test_version_gate_mismatch_fails_even_when_fresh(self) -> None:
        r = by_id(
            run(
                full_facts(),
                {},
                vmx_mtime=1000.0,
                log_mtime=2000.0,
                expected={"vmware_version": "25.0.0"},
            )
        )["V0"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("version gate", r.detail)

    def test_version_gate_match_keeps_pass(self) -> None:
        r = by_id(
            run(
                full_facts(),
                {},
                vmx_mtime=1000.0,
                log_mtime=2000.0,
                expected={"vmware_version": "26.0.1"},
            )
        )["V0"]
        self.assertEqual(r.status, PASS)

    def test_log_mtime_defaults_to_parsed_mtime(self) -> None:
        facts = full_facts()
        self.assertIsInstance(facts.mtime, float)
        r = by_id(run(facts, {}, vmx_mtime=0.0))["V0"]
        self.assertEqual(r.status, PASS)  # log_mtime taken from facts.mtime


# --------------------------------------------------------------------------- #
# V1 — guest vendor
# --------------------------------------------------------------------------- #

class V1VendorTest(unittest.TestCase):
    def test_full_log_passes(self) -> None:
        r = by_id(run(full_facts(), {}))["V1"]
        self.assertEqual(r.status, PASS)
        self.assertIn("GenuineIntel", r.detail)
        self.assertIn("leaf0 spells GenuineIntel", r.detail)

    def test_authentic_amd_fails_masking_gate(self) -> None:
        r = by_id(run(vendor_log(vendor="AuthenticAMD", leaf0=AMD_LEAF0), {}))["V1"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("expected GenuineIntel", r.detail)
        self.assertIn("masking is not in effect", r.detail)

    def test_unexpected_vendor_fails(self) -> None:
        r = by_id(run(vendor_log(vendor="CentaurHauls"), {}))["V1"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("unexpected guest vendor", r.detail)

    def test_vendor_line_and_leaf0_disagreement_fails(self) -> None:
        r = by_id(run(vendor_log(vendor="GenuineIntel", leaf0=AMD_LEAF0), {}))["V1"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("AuthenticAMD", r.detail)
        self.assertIn("GenuineIntel", r.detail)

    def test_expected_vendor_can_be_overridden(self) -> None:
        r = by_id(run(vendor_log(vendor="AuthenticAMD", leaf0=AMD_LEAF0), {},
                      expected={"vendor": "AuthenticAMD"}))["V1"]
        self.assertEqual(r.status, PASS)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V1"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("guest vs. host CPUID", r.detail)

    def test_block_without_vendor_evidence_skips(self) -> None:
        r = by_id(run(make_log(HEADER), {}))["V1"]
        # header alone never opens a CPUID block
        self.assertEqual(r.status, SKIP)


# --------------------------------------------------------------------------- #
# V2 — family/model/stepping decode
# --------------------------------------------------------------------------- #

class V2DecodeTest(unittest.TestCase):
    def test_decode_cross_checks_against_self_report(self) -> None:
        r = by_id(run(full_facts(), {}))["V2"]
        self.assertEqual(r.status, PASS)
        self.assertIn("decoded 0x000406e3 -> family=0x6 model=0x4e stepping=0x3", r.detail)
        self.assertIn("== VMware self-report", r.detail)
        self.assertIn("host 0x000b06a2", r.detail)

    def test_decode_mismatch_with_self_report_warns(self) -> None:
        facts = cpuid_log(self_report="guest family: 0x6 model: 0x5e stepping: 0x3")
        r = by_id(run(facts, {}))["V2"]
        self.assertEqual(r.status, WARN)
        self.assertIn("!= VMware self-report", r.detail)
        self.assertIn("parser needs adaptation", r.detail)

    def test_intel_vendor_with_non_six_family_fails(self) -> None:
        # 0x00000f00 decodes to family 0xF — impossible for GenuineIntel.
        facts = cpuid_log(ecx="0xf7fa322b", leaf7_ebx=None)
        facts.guest_levels[(1, 0)] = ("0x00000f00", "0x00100800", "0xf7fa322b", "0x1f8bfbff")
        r = by_id(run(facts, {}))["V2"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("family=0xf", r.detail)
        self.assertIn("GenuineIntel", r.detail)

    def test_missing_leaf1_skips(self) -> None:
        facts = vendor_log(vendor="GenuineIntel", leaf0=INTEL_LEAF0)
        r = by_id(run(facts, {}))["V2"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("no guest leaf 1", r.detail)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V2"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("guest vs. host CPUID", r.detail)


# --------------------------------------------------------------------------- #
# V3 — hypervisor bit
# --------------------------------------------------------------------------- #

class V3HypervisorBitTest(unittest.TestCase):
    def test_no_switch_expects_the_synthesised_one(self) -> None:
        r = by_id(run(full_facts(), {}))["V3"]  # ECX 0xf7fa322b → bit31 = 1
        self.assertEqual(r.status, PASS)
        self.assertIn("bit31=1", r.detail)
        self.assertIn("hypervisor.cpuid.v0", r.detail)

    def test_false_switch_with_bit_set_warns(self) -> None:
        r = by_id(run(full_facts(), {"hypervisor.cpuid.v0": "FALSE"}))["V3"]
        self.assertEqual(r.status, WARN)
        self.assertIn("hypervisor bit=1, expected 0", r.detail)
        self.assertIn("cold boot required", r.detail)

    def test_true_switch_with_bit_set_passes(self) -> None:
        r = by_id(run(full_facts(), {"hypervisor.cpuid.v0": "TRUE"}))["V3"]
        self.assertEqual(r.status, PASS)

    def test_false_switch_with_hidden_bit_passes(self) -> None:
        facts = cpuid_log(ecx="0x77fa322b")  # bit31 cleared
        r = by_id(run(facts, {"hypervisor.cpuid.v0": "FALSE"}))["V3"]
        self.assertEqual(r.status, PASS)
        self.assertIn("bit31=0", r.detail)

    def test_cleared_bit_without_switch_warns(self) -> None:
        facts = cpuid_log(ecx="0x77fa322b")
        r = by_id(run(facts, {}))["V3"]
        self.assertEqual(r.status, WARN)
        self.assertIn("hypervisor bit=0, expected 1", r.detail)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V3"]
        self.assertEqual(r.status, SKIP)


# --------------------------------------------------------------------------- #
# V4 — AVX2 / SSE4.2 / AES / OSXSAVE
# --------------------------------------------------------------------------- #

class V4FeatureBitsTest(unittest.TestCase):
    def test_all_feature_bits_set_pass(self) -> None:
        r = by_id(run(full_facts(), {}))["V4"]
        self.assertEqual(r.status, PASS)
        self.assertIn("AVX2=1", r.detail)
        self.assertIn("SSE4.2=1", r.detail)
        self.assertIn("AES=1", r.detail)

    def test_osxsave_clear_is_recorded_but_never_a_fail(self) -> None:
        # ECX 0xf7fa322b has bit27 (OSXSAVE) clear: early-boot dump.
        r = by_id(run(full_facts(), {}))["V4"]
        self.assertNotEqual(r.status, FAIL)
        self.assertIn("OSXSAVE(ECX.27)=0", r.detail)
        self.assertIn("never a FAIL", r.detail)

    def test_osxsave_clear_alone_still_passes(self) -> None:
        facts = cpuid_log(ecx="0xf7fa322b", leaf7_ebx="0x219c27eb")
        r = by_id(run(facts, {}))["V4"]
        self.assertEqual(r.status, PASS)
        self.assertIn("never a FAIL", r.detail)

    def test_avx2_clear_warns(self) -> None:
        facts = cpuid_log(leaf7_ebx="0x219c27cb")  # EBX bit5 clear
        r = by_id(run(facts, {}))["V4"]
        self.assertEqual(r.status, WARN)
        self.assertIn("AVX2 bit clear", r.detail)
        self.assertIn("SIGILL", r.detail)

    def test_leaf1_only_still_checks_sse_and_aes(self) -> None:
        facts = cpuid_log(leaf7_ebx=None)
        r = by_id(run(facts, {}))["V4"]
        self.assertEqual(r.status, PASS)
        self.assertIn("guest leaf 7 absent", r.detail)

    def test_no_feature_leaves_skip(self) -> None:
        facts = vendor_log(vendor="GenuineIntel", leaf0=INTEL_LEAF0)
        r = by_id(run(facts, {}))["V4"]
        self.assertEqual(r.status, SKIP)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V4"]
        self.assertEqual(r.status, SKIP)

    def test_capability_lines_are_side_evidence_only(self) -> None:
        r = by_id(run(full_facts(), {}))["V4"]
        self.assertIn(
            "side evidence: cpuid.avx2=1 cpuid.sse42=1 cpuid.aes=1 cpuid.xsave=1", r.detail
        )


# --------------------------------------------------------------------------- #
# V5 — per-vCPU APIC IDs / proxy degradation
# --------------------------------------------------------------------------- #

class V5PerVcpuTest(unittest.TestCase):
    def test_proxy_reconciles_on_full_log(self) -> None:
        r = by_id(run(full_facts(), {"numvcpus": "12"}))["V5"]
        self.assertEqual(r.status, PASS)
        self.assertIn("degraded proxy check", r.detail)
        self.assertIn("vmm-vcpus 12", r.detail)
        self.assertIn("LocalApic 12", r.detail)
        self.assertIn("DICT numvcpus 12", r.detail)
        self.assertIn(".vmx numvcpus 12", r.detail)
        self.assertIn("in-guest per-core recheck required", r.detail)
        self.assertEqual(len(r.evidence), 3)

    def test_proxy_mismatch_warns(self) -> None:
        r = by_id(run(full_facts(), {"numvcpus": "8"}))["V5"]
        self.assertEqual(r.status, WARN)
        self.assertIn("vCPU proxy mismatch", r.detail)

    def test_unique_per_vcpu_apic_ids_pass(self) -> None:
        r = by_id(run(per_vcpu_log([0, 1, 2, 3]), {}))["V5"]
        self.assertEqual(r.status, PASS)
        self.assertIn("[0, 1, 2, 3]", r.detail)
        self.assertIn("4 unique", r.detail)

    def test_duplicate_apic_ids_warn(self) -> None:
        r = by_id(run(per_vcpu_log([0, 0, 1, 2]), {}))["V5"]
        self.assertEqual(r.status, WARN)
        self.assertIn("duplicate initial APIC IDs", r.detail)

    def test_partial_trace_warns(self) -> None:
        r = by_id(run(per_vcpu_log([0, 1]), {"numvcpus": "4"}))["V5"]
        self.assertEqual(r.status, WARN)
        self.assertIn("partial trace", r.detail)

    def test_no_proxy_data_at_all_skips(self) -> None:
        r = by_id(run(vendor_log(vendor="GenuineIntel"), {}))["V5"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("not enough proxy data", r.detail)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V5"]
        self.assertEqual(r.status, SKIP)

    def test_v5_never_fails(self) -> None:
        cases = [
            (full_facts(), {}),
            (full_facts(), {"numvcpus": "8"}),
            (per_vcpu_log([0, 0]), {"numvcpus": "4"}),
            (vendor_log(vendor="GenuineIntel"), {}),
            (parse_log_path(MINIMAL), {}),
        ]
        for facts, vmx in cases:
            self.assertNotEqual(by_id(run(facts, vmx))["V5"].status, FAIL)


# --------------------------------------------------------------------------- #
# V6 — clock leaves 0x15 / 0x16
# --------------------------------------------------------------------------- #

class V6ClockLeavesTest(unittest.TestCase):
    def test_zero_guest_leaves_warn(self) -> None:
        r = by_id(run(full_facts(), {}))["V6"]
        self.assertEqual(r.status, WARN)
        self.assertIn("0x15/0x16 all zero", r.detail)
        self.assertIn("TSC estimates disagree", r.detail)
        self.assertIn("VMMon_GetkHzEstimate 2918400 kHz", r.detail)
        self.assertTrue(any("leaf 0x15" in e.note for e in r.evidence))

    def test_zero_leaves_mention_sync_time_hint(self) -> None:
        r = by_id(run(full_facts(), {"tools.syncTime": "FALSE"}))["V6"]
        self.assertEqual(r.status, WARN)
        self.assertIn("tools.syncTime=FALSE", r.detail)

    def test_exposed_guest_leaf_passes(self) -> None:
        facts = make_log(
            greg(0x15, 0, "0x00000002", "0x00000098", "0x0249f000", "0x00000000")
        )
        r = by_id(run(facts, {}))["V6"]
        self.assertEqual(r.status, PASS)
        self.assertIn("exposed", r.detail)

    def test_missing_clock_leaves_skip(self) -> None:
        facts = cpuid_log()
        r = by_id(run(facts, {}))["V6"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("0x15/0x16", r.detail)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V6"]
        self.assertEqual(r.status, SKIP)


# --------------------------------------------------------------------------- #
# V7 — hypervisor vendor string
# --------------------------------------------------------------------------- #

class V7HypervisorVendorTest(unittest.TestCase):
    def test_vmware_string_passes(self) -> None:
        r = by_id(run(full_facts(), {}))["V7"]
        self.assertEqual(r.status, PASS)
        self.assertIn("VMwareVMware", r.detail)
        self.assertIn("max leaf 0x40000010", r.detail)
        self.assertTrue(r.evidence and r.evidence[0].source.endswith(":59"))

    def test_foreign_hypervisor_string_fails(self) -> None:
        facts = make_log(
            greg(0x40000000, 0, "0x40000010", "0x7263694d", "0x666f736f", "0x76482074")
        )
        r = by_id(run(facts, {}))["V7"]
        self.assertEqual(r.status, FAIL)
        self.assertIn('"Microsoft Hv"', r.detail)
        self.assertIn("wrong log", r.detail)

    def test_missing_leaf_skips(self) -> None:
        r = by_id(run(cpuid_log(), {}))["V7"]
        self.assertEqual(r.status, SKIP)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}))["V7"]
        self.assertEqual(r.status, SKIP)


# --------------------------------------------------------------------------- #
# V8 — documented_values closure
# --------------------------------------------------------------------------- #

class V8ClosureTest(unittest.TestCase):
    def test_matching_register_passes(self) -> None:
        r = by_id(run(full_facts(), {}, expected={"cpuid.1.eax": "0x000406e3"}))["V8"]
        self.assertEqual(r.status, PASS)
        self.assertIn("1/1 documented values match the log", r.detail)

    def test_mismatching_register_fails(self) -> None:
        r = by_id(run(full_facts(), {}, expected={"cpuid.1.eax": "0x00010671"}))["V8"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("documented value(s) not visible in the guest", r.detail)
        self.assertIn("expected 0x00010671, log shows 0x000406e3", r.detail)

    def test_absent_leaf_skips(self) -> None:
        r = by_id(run(full_facts(), {}, expected={"cpuid.5.eax": "0x00000001"}))["V8"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("absent from this log", r.detail)

    def test_no_documented_values_skips(self) -> None:
        r = by_id(run(full_facts(), {}, expected=None))["V8"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("nothing to close the loop on", r.detail)

    def test_reserved_keys_are_handled_by_other_checks(self) -> None:
        r = by_id(
            run(
                full_facts(),
                {},
                expected={
                    "vmware_version": "26.0.1",
                    "guestos": "darwin24-64",
                    "vendor": "GenuineIntel",
                },
            )
        )["V8"]
        self.assertEqual(r.status, SKIP)  # nothing register-like left to compare
        self.assertNotEqual(r.status, FAIL)

    def test_mask_string_is_reported_not_failed(self) -> None:
        r = by_id(
            run(
                full_facts(),
                {},
                expected={
                    "cpuid.1.eax": "0x000406e3",
                    "cpuid.1.ecx": "0" * 31 + "-",
                },
            )
        )["V8"]
        self.assertEqual(r.status, PASS)
        self.assertIn("not comparable", r.detail)
        self.assertIn("01-h", r.detail)

    def test_family_key_decodes_from_leaf1(self) -> None:
        good = by_id(run(full_facts(), {}, expected={"cpuid.family": "6"}))["V8"]
        self.assertEqual(good.status, PASS)
        bad = by_id(run(full_facts(), {}, expected={"cpuid.family": "15"}))["V8"]
        self.assertEqual(bad.status, FAIL)
        self.assertIn("log decodes 6", bad.detail)

    def test_brand_string_key_compares_against_guest_name(self) -> None:
        match = by_id(
            run(
                full_facts(),
                {},
                expected={"cpuid.brandString": "13th Gen Intel(R) Core(TM) i7-13620H"},
            )
        )["V8"]
        self.assertEqual(match.status, PASS)
        mismatch = by_id(
            run(full_facts(), {}, expected={"cpuid.brandString": "Intel(R) Core(TM) i7-9700K"})
        )["V8"]
        self.assertEqual(mismatch.status, FAIL)

    def test_no_block_skips(self) -> None:
        r = by_id(run(parse_log_path(MINIMAL), {}, expected={"cpuid.1.eax": "0x000406e3"}))["V8"]
        self.assertEqual(r.status, SKIP)


# --------------------------------------------------------------------------- #
# V9 — guestOS tier
# --------------------------------------------------------------------------- #

class V9GuestOsTest(unittest.TestCase):
    def test_known_darwin_tier_passes(self) -> None:
        r = by_id(run(full_facts(), {"guestOS": "darwin24-64"}))["V9"]
        self.assertEqual(r.status, PASS)
        self.assertIn("known darwin tier", r.detail)
        for tier in KNOWN_DARWIN_TIERS:
            self.assertIn(tier, r.detail)

    def test_mismatching_guestos_warns(self) -> None:
        r = by_id(run(full_facts(), {"guestOS": "darwin25-64"}))["V9"]
        self.assertEqual(r.status, WARN)
        self.assertIn("wrong log", r.detail)

    def test_unknown_darwin_tier_warns(self) -> None:
        facts = make_log("Powering on guestOS 'darwin21-64' using the configuration for 'darwin21-64'.")
        r = by_id(run(facts, {"guestOS": "darwin21-64"}))["V9"]
        self.assertEqual(r.status, WARN)
        self.assertIn("not a tier macopt knows", r.detail)

    def test_non_darwin_guest_warns(self) -> None:
        facts = make_log("Powering on guestOS 'windows10-64' using the configuration for 'windows10-64'.")
        r = by_id(run(facts, {"guestOS": "windows10-64"}))["V9"]
        self.assertEqual(r.status, WARN)
        self.assertIn("not a darwin tier", r.detail)

    def test_vmx_without_guestos_skips(self) -> None:
        r = by_id(run(full_facts(), {}))["V9"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("no guestOS key", r.detail)

    def test_log_without_poweron_line_skips(self) -> None:
        r = by_id(run(make_log(HEADER), {"guestOS": "darwin24-64"}))["V9"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("Powering on guestOS", r.detail)


# --------------------------------------------------------------------------- #
# V10 — topology reconciliation
# --------------------------------------------------------------------------- #

class V10TopologyTest(unittest.TestCase):
    def test_consistent_topology_passes(self) -> None:
        vmx = {"numvcpus": "12", "cpuid.coresPerSocket": "12"}
        r = by_id(run(full_facts(), vmx))["V10"]
        self.assertEqual(r.status, PASS)
        self.assertIn("numvcpus=12", r.detail)
        self.assertIn("coresPerSocket=12 x sockets=1", r.detail)
        self.assertIn("vmm-vcpus=12", r.detail)
        self.assertIn("LocalApic=12", r.detail)

    def test_numvcpus_mismatch_fails(self) -> None:
        vmx = {"numvcpus": "8", "cpuid.coresPerSocket": "8"}
        r = by_id(run(full_facts(), vmx))["V10"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("topology mismatch", r.detail)
        self.assertIn("cold boot required", r.detail)

    def test_cores_per_socket_inconsistency_fails(self) -> None:
        vmx = {"numvcpus": "12", "cpuid.coresPerSocket": "5"}
        r = by_id(run(full_facts(), vmx))["V10"]
        self.assertEqual(r.status, FAIL)
        self.assertIn("numvcpus=12 != cpuid.coresPerSocket=5", r.detail)

    def test_vmx_without_numvcpus_skips(self) -> None:
        r = by_id(run(full_facts(), {}))["V10"]
        self.assertEqual(r.status, SKIP)
        self.assertIn(".vmx has no numvcpus", r.detail)

    def test_log_without_topology_lines_skips(self) -> None:
        facts = make_log(
            HEADER,
            "Powering on guestOS 'darwin24-64' using the configuration for 'darwin24-64'.",
        )
        r = by_id(run(facts, {"numvcpus": "8"}))["V10"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("no topology lines", r.detail)

    def test_no_topology_data_anywhere_skips(self) -> None:
        facts = make_log(HEADER)
        r = by_id(run(facts, {}))["V10"]
        self.assertEqual(r.status, SKIP)
        self.assertIn("no topology data", r.detail)

    def test_minimal_log_reconciles_against_vmx(self) -> None:
        vmx = {"numvcpus": "8", "cpuid.coresPerSocket": "8"}
        r = by_id(run(parse_log_path(MINIMAL), vmx))["V10"]
        self.assertEqual(r.status, PASS)
        self.assertIn("vmm-vcpus=8", r.detail)


# --------------------------------------------------------------------------- #
# hard rule: missing lines are SKIP, never FAIL
# --------------------------------------------------------------------------- #

class MissingLinesAreSkipTest(unittest.TestCase):
    def test_no_cpuid_block_skips_v1_through_v8(self) -> None:
        facts = parse_log_path(MINIMAL)
        results = by_id(run(facts, {"guestOS": "darwin24-64", "numvcpus": "8"}))
        for i in range(1, 9):
            vid = f"V{i}"
            self.assertEqual(results[vid].status, SKIP, f"{vid} = {results[vid].detail}")
        self.assertFalse(any(r.status == FAIL for r in results.values()))

    def test_empty_log_never_fails(self) -> None:
        results = run(make_log(), {})
        self.assertFalse(any(r.status == FAIL for r in results))
        self.assertTrue(all(r.status == SKIP for r in results))

    def test_log_without_block_but_with_header_reports_skip_reason(self) -> None:
        results = by_id(run(make_log(HEADER), {}))
        self.assertIn("boot the VM once and re-run verify", results["V1"].detail)
        self.assertEqual(results["V1"].status, SKIP)


# --------------------------------------------------------------------------- #
# evidence contract
# --------------------------------------------------------------------------- #

class EvidenceContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.facts = parse_log(FULL.read_text(encoding="utf-8"))  # name -> "vmware.log"
        cls.results = run(cls.facts, {"numvcpus": "12"}, vmx_mtime=1000.0, log_mtime=2000.0)
        cls.evidence = [e for r in cls.results for e in r.evidence]

    def test_log_evidence_sources_are_relative_line_addresses(self) -> None:
        log_evidence = [e for e in self.evidence if e.kind == "log"]
        self.assertGreaterEqual(len(log_evidence), 5)
        for e in log_evidence:
            self.assertRegex(e.source, SOURCE_RE)
            lineno = int(e.source.split(":")[1])
            self.assertGreaterEqual(lineno, 1)
            self.assertLessEqual(lineno, len(self.facts.lines))
            self.assertIsInstance(e.note, str)

    def test_evidence_kinds_are_from_the_contract(self) -> None:
        for e in self.evidence:
            self.assertIn(e.kind, EVIDENCE_KINDS)
            self.assertTrue(e.source)

    def test_mtime_evidence_is_a_file_record(self) -> None:
        v0 = self.results[0]
        self.assertEqual(v0.id, "V0")
        kinds = {e.kind for e in v0.evidence}
        self.assertEqual(kinds, {"log", "file"})

    def test_failed_checks_carry_evidence(self) -> None:
        stale = by_id(
            run(full_facts(), {"numvcpus": "8"}, vmx_mtime=2000.0, log_mtime=1000.0)
        )
        self.assertEqual(stale["V0"].status, FAIL)
        self.assertTrue(stale["V0"].evidence)
        self.assertEqual(stale["V10"].status, FAIL)
        self.assertTrue(stale["V10"].evidence)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

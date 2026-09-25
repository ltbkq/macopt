"""Unit tests for the CPUID masking profiles and the R1–R8 rule engine.

DESIGN §4.8. One dedicated test exists for every rule in §4.8.2, because a
rule that silently stops firing is indistinguishable from "no problem found"
— the exact failure mode the rule engine exists to prevent.

Bit-decoding tests are pinned to **Intel SDM Vol.1 Table 3-5**, and they
regression-guard a DESIGN §12.1 erratum (v2.1 initially listed SSE4.2 at
bit 0 and AES at bit 20). If anyone restores those numbers, the table
assertions below fail here instead of in production.
"""

from __future__ import annotations

import unittest

from macopt.model import EVIDENCE_KINDS, HostInfo, ProfileOptions, ProfileResult
from macopt.profiles import build_all, cpuid

INTEL = HostInfo(vendor="GenuineIntel", brand="13th Gen Intel(R) Core(TM) i7-13620H")
AMD = HostInfo(vendor="AuthenticAMD", brand="AMD Ryzen 7 5800X 8-Core Processor")
UNKNOWN_HOST = HostInfo(vendor=None)


def levels(report: cpuid.RuleReport, rule_id: str) -> list[str]:
    return [r.level for r in report.results if r.id == rule_id]


class DecodeTests(unittest.TestCase):
    def test_leaf1_eax_signature_decoding(self) -> None:
        penryn = cpuid.decode_leaf1_eax(0x00010671)
        self.assertEqual(penryn.triple, (6, 0x17, 1))
        self.assertEqual(penryn.model, 0x17)

        kabylake = cpuid.decode_leaf1_eax(0x000906E9)
        self.assertEqual(kabylake.triple, (6, 0x9E, 9))

        raptor = cpuid.decode_leaf1_eax(0x000B06A2)
        self.assertEqual(raptor.triple, (6, 0xBA, 2))

        skylake_y = cpuid.decode_leaf1_eax(0x000406E3)
        self.assertEqual(skylake_y.triple, (6, 0x4E, 3))

    def test_leaf1_edx_uses_the_frozen_bit_table(self) -> None:
        self.assertEqual(
            cpuid.LEAF1_EDX_BITS,
            {
                "DS": 21, "ACPI": 22, "MMX": 23, "FXSR": 24, "SSE": 25,
                "SSE2": 26, "SS": 27, "HTT": 28, "TM": 29, "PBE": 31,
            },
        )
        bits = cpuid.decode_leaf1_edx(0x078BFBFF)
        # the community value keeps MMX/FXSR/SSE/SSE2 and clears the rest
        self.assertTrue(bits["MMX"] and bits["FXSR"] and bits["SSE"] and bits["SSE2"])
        for cleared in ("DS", "ACPI", "SS", "HTT", "TM", "PBE"):
            self.assertFalse(bits[cleared], f"{cleared} should be cleared by 0x078BFBFF")

    def test_leaf1_edx_for_vmwares_built_in_darwin_value(self) -> None:
        bits = cpuid.decode_leaf1_edx(0x1F8BFBFF)  # guest value from vmware.log
        self.assertTrue(bits["SS"] and bits["HTT"] and bits["MMX"] and bits["SSE"])
        self.assertFalse(bits["DS"] and bits["ACPI"] and bits["PBE"])

    def test_leaf1_ecx_follows_the_intel_sdm(self) -> None:
        # DESIGN §12.1 erratum guard: SSE4.2=20 (not 0), POPCNT=23 (not 1),
        # AES=25 (not 20). The old numbers decoded SSE3 as SSE4.2.
        self.assertEqual(
            cpuid.LEAF1_ECX_BITS,
            {"SSE42": 20, "POPCNT": 23, "AES": 25, "OSXSAVE": 27, "HYPERVISOR": 31},
        )
        bits = cpuid.decode_leaf1_ecx(0x82982203)
        self.assertTrue(bits["SSE42"] and bits["POPCNT"] and bits["AES"])
        self.assertFalse(bits["OSXSAVE"])
        self.assertTrue(bits["HYPERVISOR"])

        # bit 0 is SSE3: it must not be decoded as SSE4.2 any more
        only_bit0 = cpuid.decode_leaf1_ecx(1)
        self.assertFalse(only_bit0["SSE42"])
        self.assertFalse(only_bit0["POPCNT"])
        self.assertFalse(only_bit0["AES"])

    def test_leaf7_ebx_avx2(self) -> None:
        self.assertEqual(cpuid.LEAF7_EBX_BITS, {"AVX2": 5})
        self.assertTrue(cpuid.decode_leaf7_ebx(1 << 5)["AVX2"])
        self.assertFalse(cpuid.decode_leaf7_ebx(0)["AVX2"])

    def test_claim_detection_reads_the_sdm_bits(self) -> None:
        # Every feature claim must be seen at its SDM position.
        self.assertIn("AES", cpuid._claims_of({"cpuid.1.ecx": "0x02000000"}))  # bit 25
        self.assertIn("SSE42", cpuid._claims_of({"cpuid.1.ecx": "0x00100000"}))  # bit 20
        self.assertIn("POPCNT", cpuid._claims_of({"cpuid.1.ecx": "0x00800000"}))  # bit 23
        # bit 0 = SSE3: never an SSE4.2 claim (regression for the erratum)
        self.assertNotIn("SSE42", cpuid._claims_of({"cpuid.1.ecx": "0x00000001"}))
        # the union with the full SDM table still catches the adjacent features
        self.assertIn("SSE41", cpuid._claims_of({"cpuid.1.ecx": "0x00080000"}))  # bit 19


class MaskParsingTests(unittest.TestCase):
    def test_hex_values(self) -> None:
        self.assertTrue(cpuid.is_mask_value("0x078BFBFF"))
        self.assertTrue(cpuid.is_explicit("0x078BFBFF"))
        self.assertEqual(cpuid.parse_mask("0x078BFBFF"), 0x078BFBFF)
        self.assertEqual(cpuid.parse_mask('"0x0000000B"'), 0x0000000B)  # quoted .vmx value

    def test_thirty_two_char_patterns(self) -> None:
        explicit = "00010000" * 4
        self.assertEqual(cpuid.parse_mask(explicit), int(explicit, 2))
        self.assertTrue(cpuid.is_explicit(explicit))
        dashed = "0001----" + "0" * 24
        self.assertTrue(cpuid.is_mask_value(dashed))
        self.assertFalse(cpuid.is_explicit(dashed))
        self.assertIsNone(cpuid.parse_mask(dashed))

    def test_non_values(self) -> None:
        for bad in ("", "hello", "0xGGGGGGGG", "12", None, 42, "01" * 33):
            with self.subTest(value=bad):
                self.assertFalse(cpuid.is_mask_value(bad))
                self.assertIsNone(cpuid.parse_mask(bad))

    def test_host_bits_are_not_explicit(self) -> None:
        self.assertTrue(cpuid.is_mask_value("h" + "0" * 31))
        self.assertFalse(cpuid.is_explicit("h" + "0" * 31))


class RuleTests(unittest.TestCase):
    """One test per rule of DESIGN §4.8.2."""

    # R1 ------------------------------------------------------------------ #
    def test_r1_explicit_ebx_is_blocked(self) -> None:
        report = cpuid.validate({"cpuid.1.ebx": "0x02010800"})
        self.assertEqual(levels(report, "R1"), ["BLOCK"])
        self.assertTrue(report.errors)
        message = report.has("R1").message
        self.assertIn("0x02010800", message)
        self.assertIn("APIC", message)

    def test_r1_is_lifted_by_allow_apic_risk(self) -> None:
        report = cpuid.validate({"cpuid.1.ebx": "0x02010800"}, allow_apic_risk=True)
        self.assertEqual(levels(report, "R1"), ["WARN"])
        self.assertFalse(report.errors)
        self.assertTrue(report.warnings)

    def test_r1_stays_silent_for_partial_ebx(self) -> None:
        report = cpuid.validate({"cpuid.1.ebx": "----:----:0000:1000:----:----:----:----"})
        self.assertEqual(levels(report, "R1"), [])

    # R2 ------------------------------------------------------------------ #
    def test_r2_clearing_ss_is_blocked(self) -> None:
        report = cpuid.validate({"cpuid.1.edx": "0x078BFBFF"})
        self.assertEqual(levels(report, "R2"), ["BLOCK"])
        self.assertIn("bit27", report.has("R2").message)
        self.assertIn("cpuid.ss", report.has("R2").message)

    def test_r2_is_downgraded_to_a_warning_when_allowed(self) -> None:
        report = cpuid.validate({"cpuid.1.edx": "0x078BFBFF"}, allow_apic_risk=True)
        self.assertEqual(levels(report, "R2"), ["WARN"])
        self.assertFalse(report.errors)

    def test_r2_keeps_quiet_when_ss_survives(self) -> None:
        report = cpuid.validate({"cpuid.1.edx": "0x1F8BFBFF"})
        self.assertEqual(levels(report, "R2"), [])

    # R3 ------------------------------------------------------------------ #
    def test_r3_clearing_htt_warns(self) -> None:
        report = cpuid.validate({"cpuid.1.edx": "0x078BFBFF"})
        self.assertEqual(levels(report, "R3"), ["WARN"])
        self.assertIn("bit28", report.has("R3").message)
        self.assertIn("EBX[23:16]", report.has("R3").message)

    def test_r3_keeps_quiet_when_htt_survives(self) -> None:
        self.assertEqual(levels(cpuid.validate({"cpuid.1.edx": "0x1F8BFBFF"}), "R3"), [])

    # R4 ------------------------------------------------------------------ #
    def test_r4_low_max_leaf_with_claimed_features_warns(self) -> None:
        report = cpuid.validate(cpuid.PROFILES["penryn"].params, profile="penryn")
        self.assertEqual(levels(report, "R4"), ["WARN"])
        message = report.has("R4").message
        self.assertIn("0xB", message)
        self.assertIn("SSE42", message)
        self.assertIn("AES", message)

    def test_r4_stays_silent_without_a_max_leaf_cap(self) -> None:
        report = cpuid.validate(cpuid.PROFILES["kabylake-7700k"].params, profile="kabylake-7700k")
        self.assertEqual(levels(report, "R4"), [])

    def test_r4_stays_silent_when_nothing_is_claimed(self) -> None:
        report = cpuid.validate({"cpuid.0.eax": "0x0000000B"}, profile="none")
        self.assertEqual(levels(report, "R4"), [])

    # R5 ------------------------------------------------------------------ #
    def test_r5_signature_contradicting_the_profile_name_fails(self) -> None:
        report = cpuid.validate({"cpuid.1.eax": "0x00010671"}, profile="kabylake-7700k")
        self.assertEqual(levels(report, "R5"), ["FAIL"])
        self.assertTrue(report.errors)
        self.assertIn("0x00010671", report.has("R5").message)
        self.assertIn("0x9E", report.has("R5").message)

    def test_r5_matching_signature_passes(self) -> None:
        report = cpuid.validate({"cpuid.1.eax": "0x000906E9"}, profile="kabylake-7700k")
        self.assertEqual(levels(report, "R5"), [])
        report = cpuid.validate({"cpuid.1.eax": "0x00010671"}, profile="penryn")
        self.assertEqual(levels(report, "R5"), [])

    def test_r5_brand_string_contradicting_the_signature_fails(self) -> None:
        report = cpuid.validate(
            {"cpuid.1.eax": "0x00010671", "cpuid.brandString": "Intel(R) Core(TM) i7-7700K"},
            profile="none",
        )
        self.assertEqual(levels(report, "R5"), ["FAIL"])
        self.assertIn("brandString", report.has("R5").message)

    # R6 ------------------------------------------------------------------ #
    def test_r6_invalid_vendor_triple_warns(self) -> None:
        report = cpuid.validate(
            {
                "cpuid.0.ebx": "0x41414141",
                "cpuid.0.edx": "0x42424242",
                "cpuid.0.ecx": "0x43434343",
            }
        )
        self.assertEqual(levels(report, "R6"), ["WARN"])
        self.assertIn("AAAABBBBCCCC", report.has("R6").message)

    def test_r6_partial_vendor_triple_warns(self) -> None:
        report = cpuid.validate({"cpuid.0.ebx": "0x756E6547"})
        self.assertEqual(levels(report, "R6"), ["WARN"])
        self.assertIn("只写了其中", report.has("R6").message)

    def test_r6_valid_intel_trio_is_silent(self) -> None:
        report = cpuid.validate(
            {
                "cpuid.0.ebx": "0x756E6547",
                "cpuid.0.edx": "0x49656E69",
                "cpuid.0.ecx": "0x6C65746E",
            }
        )
        self.assertEqual(levels(report, "R6"), [])

    # R7 ------------------------------------------------------------------ #
    def test_r7_unknown_cpuid_key_is_blocked_with_the_whitelist_prefix(self) -> None:
        report = cpuid.validate({"cpuid.1.qqq": "0x1"})
        self.assertEqual(levels(report, "R7"), ["BLOCK"])
        self.assertTrue(report.errors[0].startswith("whitelist:"))
        self.assertIn("cpuid.1.qqq", report.errors[0])

    def test_r7_lower_case_community_spelling_is_blocked(self) -> None:
        report = cpuid.validate({"cpuid.ss": "1"})
        self.assertEqual(levels(report, "R7"), ["BLOCK"])

    def test_r7_is_downgraded_by_allow_unknown_keys(self) -> None:
        report = cpuid.validate({"cpuid.1.qqq": "0x1"}, allow_unknown_keys=True)
        self.assertEqual(levels(report, "R7"), ["WARN"])
        self.assertFalse(report.errors)

    def test_r7_accepts_every_real_mask_key(self) -> None:
        report = cpuid.validate(cpuid.PROFILES["penryn"].params, profile="penryn")
        self.assertEqual(levels(report, "R7"), [])

    # R8 ------------------------------------------------------------------ #
    def test_r8_intel_host_is_told_it_needs_no_disguise(self) -> None:
        report = cpuid.validate(
            cpuid.PROFILES["kabylake-7700k"].params, profile="kabylake-7700k", host=INTEL
        )
        self.assertEqual(levels(report, "R8"), ["WARN"])
        self.assertIn("本机不需要伪装", report.has("R8").message)

    def test_r8_stays_silent_for_profile_none(self) -> None:
        report = cpuid.validate({}, profile="none", host=INTEL)
        self.assertEqual(levels(report, "R8"), [])

    def test_r8_unknown_host_is_reported_never_guessed(self) -> None:
        report = cpuid.validate({}, profile="penryn", host=UNKNOWN_HOST)
        self.assertEqual(levels(report, "R8"), ["INFO"])
        self.assertFalse(report.warnings)
        self.assertIn("未知", report.has("R8").message)

    def test_r8_amd_host_is_informational(self) -> None:
        report = cpuid.validate({}, profile="penryn", host=AMD)
        self.assertEqual(levels(report, "R8"), ["INFO"])
        self.assertIn("T7", report.has("R8").message)

    # report shape ---------------------------------------------------------- #
    def test_report_buckets_and_serialisation(self) -> None:
        report = cpuid.validate({"cpuid.1.ebx": "0x02010800", "cpuid.1.qqq": "0x1"})
        self.assertIn("R1", report.fired)
        self.assertIn("R7", report.fired)
        payload = report.to_dict()
        self.assertEqual(len(payload["results"]), len(report.results))
        self.assertTrue(payload["errors"])
        self.assertEqual(report.notices, [])


class ProfileTests(unittest.TestCase):
    def test_registry_contains_the_documented_profiles(self) -> None:
        self.assertEqual(
            set(cpuid.PROFILES), {"none", "penryn", "kabylake-7700k", "signed-brand"}
        )
        for name, profile in cpuid.PROFILES.items():
            with self.subTest(profile=name):
                self.assertEqual(profile.name, name)
                self.assertIn(profile.risk, ("normal", "high"))
                for value in profile.params.values():
                    self.assertTrue(cpuid.is_mask_value(value), f"{name}: {value}")
                for key in profile.documented_values:
                    self.assertTrue(key in ("vendor", "guestos", "vmware_version") or key.startswith("cpuid."))

    def test_none_profile_is_empty(self) -> None:
        profile = cpuid.PROFILES["none"]
        self.assertEqual(profile.params, {})
        self.assertEqual(profile.documented_values, {})

    def test_penryn_is_the_community_set(self) -> None:
        profile = cpuid.PROFILES["penryn"]
        self.assertEqual(
            profile.params,
            {
                "cpuid.0.eax": "0x0000000B",
                "cpuid.0.ebx": "0x756E6547",
                "cpuid.0.edx": "0x49656E69",
                "cpuid.0.ecx": "0x6C65746E",
                "cpuid.1.eax": "0x00010671",
                "cpuid.1.ebx": "0x02010800",
                "cpuid.1.ecx": "0x82982203",
                "cpuid.1.edx": "0x078BFBFF",
            },
        )
        self.assertEqual(profile.risk, "high")
        self.assertEqual(profile.target_vendor, "GenuineIntel")
        self.assertEqual(profile.documented_values["vendor"], "GenuineIntel")
        self.assertTrue(profile.evidence)

    def test_kabylake_avoids_the_dangerous_keys(self) -> None:
        params = cpuid.PROFILES["kabylake-7700k"].params
        self.assertNotIn("cpuid.1.ebx", params)  # R1
        self.assertNotIn("cpuid.0.eax", params)  # R4
        self.assertEqual(params["cpuid.1.eax"], "0x000906E9")
        self.assertEqual(params["cpuid.1.edx"], "0x1F8BFBFF")

    def test_documented_values_are_parseable_by_verify_v8(self) -> None:
        from macopt.verify import assertions  # local import: read-only consumer

        for name, profile in cpuid.PROFILES.items():
            for key, raw in profile.documented_values.items():
                with self.subTest(profile=name, key=key):
                    if key in assertions._V8_RESERVED_KEYS:
                        continue
                    self.assertIsNotNone(
                        assertions._expected_int(raw), f"{key}={raw!r} is not an int"
                    )

    def test_signed_brand_requires_user_supplied_values(self) -> None:
        result = cpuid.build({}, INTEL, ProfileOptions(cpuid_profile="signed-brand"))
        self.assertEqual(result.params, ())
        self.assertTrue(any("brandString" in e for e in result.errors))

    def test_signed_brand_emits_named_keys_only(self) -> None:
        opts = ProfileOptions(
            cpuid_profile="signed-brand",
            extras={
                "brandString": "Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz",
                "family": "6",
                "model": "0x9E",
                "stepping": "9",
            },
        )
        result = cpuid.build({}, AMD, opts)
        self.assertEqual(
            [p.key for p in result.params],
            ["cpuid.brandString", "cpuid.family", "cpuid.model", "cpuid.stepping"],
        )
        self.assertEqual(result.errors, ())
        for param in result.params:
            self.assertEqual(param.risk, "normal")
            self.assertTrue(param.needs_confirmation)
            self.assertTrue(param.evidence)

    def test_signed_brand_rejects_non_numeric_signature_parts(self) -> None:
        opts = ProfileOptions(
            cpuid_profile="signed-brand",
            extras={"brandString": "Intel(R) Core(TM) i7", "family": "six"},
        )
        result = cpuid.build({}, AMD, opts)
        self.assertTrue(any("family" in e for e in result.errors))


class BuildTests(unittest.TestCase):
    def build(self, mapping=None, host=INTEL, **opts_kwargs) -> ProfileResult:
        return cpuid.build(
            mapping or {}, host, ProfileOptions(**opts_kwargs)
        )

    def test_default_emits_nothing(self) -> None:
        result = self.build()
        self.assertEqual(result.params, ())
        self.assertEqual(result.errors, ())
        self.assertEqual(result.warnings, ())

    def test_unknown_profile_is_an_error(self) -> None:
        result = self.build(cpuid_profile="haswell-secret")
        self.assertEqual(result.params, ())
        self.assertTrue(result.errors[0].startswith("unknown cpuid profile"))

    def test_penryn_is_blocked_until_the_risk_is_accepted(self) -> None:
        result = self.build(cpuid_profile="penryn")
        self.assertEqual(len(result.params), 8)
        joined = "\n".join(result.errors)
        self.assertIn("R1 BLOCK", joined)
        self.assertIn("R2 BLOCK", joined)
        for param in result.params:
            self.assertEqual(param.module, "cpuid")
            self.assertEqual(param.risk, "high")
            self.assertTrue(param.needs_confirmation)
            self.assertTrue(param.evidence, f"{param.key} has no evidence")
            for evidence in param.evidence:
                self.assertIn(evidence.kind, EVIDENCE_KINDS)
            self.assertTrue(param.risk_note)
            self.assertIn("本机不需要伪装", param.reason)  # R8 must be in the reason

    def test_penryn_reasons_still_make_sense_after_r8(self) -> None:
        result = self.build(cpuid_profile="penryn", allow_apic_risk=True)
        self.assertFalse(
            [e for e in result.errors if e.startswith(("R1", "R2"))],
            "allow_apic_risk must lift R1/R2",
        )
        self.assertTrue(any(e.startswith("R3 WARN") for e in result.warnings))
        self.assertTrue(any(e.startswith("R4 WARN") for e in result.warnings))

    def test_kabylake_on_intel_host_only_trips_r8(self) -> None:
        result = self.build(cpuid_profile="kabylake-7700k", host=INTEL)
        self.assertEqual(result.errors, ())
        # R8 must be a WARN on an Intel host (the profile note alone is not
        # evidence — it contains the same phrase).
        report = cpuid.validate(
            dict(cpuid.PROFILES["kabylake-7700k"].params),
            profile="kabylake-7700k",
            host=INTEL,
        )
        self.assertEqual(levels(report, "R8"), ["WARN"])
        self.assertTrue(any(w.startswith("R8 WARN") for w in result.warnings))
        self.assertEqual(len(result.params), 6)

    def test_kabylake_on_amd_host_has_no_r8_warning(self) -> None:
        result = self.build(cpuid_profile="kabylake-7700k", host=AMD)
        # AMD: R8 still fires but only as INFO (验收 A / T7 待办), never WARN.
        self.assertFalse(any(w.startswith("R8 WARN") for w in result.warnings))
        report = cpuid.validate(
            dict(cpuid.PROFILES["kabylake-7700k"].params),
            profile="kabylake-7700k",
            host=AMD,
        )
        self.assertEqual(levels(report, "R8"), ["INFO"])
        self.assertTrue(any(n.startswith("R8 INFO") for n in report.notices))

    def test_already_applied_values_are_not_re_emitted(self) -> None:
        mapping = dict(cpuid.PROFILES["kabylake-7700k"].params)
        result = self.build(mapping, AMD, cpuid_profile="kabylake-7700k")
        self.assertEqual(result.params, ())

    def test_foreign_masks_in_the_file_are_reported_not_rewritten(self) -> None:
        result = self.build(
            {"cpuid.1.ebx": '"0x00100800"'}, AMD, cpuid_profile="kabylake-7700k"
        )
        self.assertNotIn("cpuid.1.ebx", [p.key for p in result.params])
        self.assertTrue(any("不管理" in w for w in result.warnings))

    def test_profile_notes_reach_the_warnings(self) -> None:
        result = self.build(cpuid_profile="penryn")
        notes = cpuid.PROFILES["penryn"].notes
        for note in notes:
            self.assertIn(note, result.warnings)

    def test_registry_integration_runs_the_module(self) -> None:
        result = build_all(
            {}, INTEL, ProfileOptions(modules=("cpuid",), cpuid_profile="kabylake-7700k")
        )
        self.assertEqual(len(result.params), 6)
        self.assertTrue(all(p.module == "cpuid" for p in result.params))

    def test_no_profile_writes_a_key_outside_the_whitelist(self) -> None:
        from macopt import keys

        for name, profile in cpuid.PROFILES.items():
            for key in profile.params:
                with self.subTest(profile=name, key=key):
                    self.assertTrue(keys.is_known(key), f"{key} is not whitelisted")


if __name__ == "__main__":
    unittest.main()

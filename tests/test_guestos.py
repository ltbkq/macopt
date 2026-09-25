"""Unit tests for the ``guestOS`` tier table and guard (DESIGN §12.2, §4.0)."""

from __future__ import annotations

import unittest

from macopt.guestos import (
    GUEST_TABLE,
    KNOWN_TIERS,
    build,
    guest_id,
    macos_name,
    resolve_guestos,
)
from macopt.model import EVIDENCE_KINDS, HostInfo, ProfileOptions, ProfileResult

REFERENCE_HOST = HostInfo(vendor="GenuineIntel", logical_cpus=16, physical_cores=10)


class TierTableTests(unittest.TestCase):
    def test_four_known_tiers_with_the_documented_guest_ids(self) -> None:
        self.assertEqual(
            GUEST_TABLE,
            {
                "darwin22-64": ("macOS 13", 0x5072),
                "darwin23-64": ("macOS 14", 0x5073),
                "darwin24-64": ("macOS 15", 0x5074),
                "darwin25-64": ("macOS 26", 0x5075),
            },
        )
        self.assertEqual(KNOWN_TIERS, tuple(GUEST_TABLE))

    def test_lookup_helpers(self) -> None:
        self.assertEqual(macos_name("darwin24-64"), "macOS 15")
        self.assertEqual(guest_id("darwin24-64"), 0x5074)
        self.assertEqual(macos_name(' "darwin25-64" '), "macOS 26")  # quoted input
        self.assertIsNone(macos_name("darwin26-64"))
        self.assertIsNone(guest_id(None))


class ResolveTests(unittest.TestCase):
    def test_no_target_keeps_the_current_value(self) -> None:
        decision = resolve_guestos(None, "darwin24-64")
        self.assertEqual(decision.decision, "keep")
        self.assertIsNone(decision.value)
        self.assertEqual(decision.current, "darwin24-64")
        self.assertEqual(decision.errors, ())

    def test_same_target_is_a_no_op(self) -> None:
        decision = resolve_guestos("darwin24-64", "darwin24-64")
        self.assertEqual(decision.decision, "unchanged")
        self.assertIsNone(decision.value)
        self.assertEqual(decision.errors, ())

    def test_known_target_differs_from_current(self) -> None:
        decision = resolve_guestos("darwin25-64", "darwin24-64")
        self.assertEqual(decision.decision, "change")
        self.assertEqual(decision.value, "darwin25-64")
        self.assertEqual(decision.macos, "macOS 26")
        self.assertEqual(decision.guest_id, 0x5075)
        self.assertTrue(decision.known)
        self.assertIn("darwin24-64 → darwin25-64", decision.reason)
        self.assertEqual(decision.errors, ())

    def test_unknown_target_is_rejected_not_written(self) -> None:
        for target in ("darwin26-64", "darwin21-64", "windows11-64", "gibberish"):
            with self.subTest(target=target):
                decision = resolve_guestos(target, "darwin24-64")
                self.assertEqual(decision.decision, "rejected")
                self.assertIsNone(decision.value)
                self.assertEqual(len(decision.errors), 1)
                self.assertIn(target, decision.errors[0])
                self.assertIn("darwin22-64", decision.errors[0])  # lists what is known

    def test_unknown_darwin_current_only_warns(self) -> None:
        decision = resolve_guestos(None, "darwin26-64")
        self.assertEqual(len(decision.warnings), 1)
        self.assertIn("darwin26-64", decision.warnings[0])
        self.assertEqual(decision.errors, ())

    def test_transition_from_a_tier_macopt_does_not_know_still_warns(self) -> None:
        decision = resolve_guestos("darwin24-64", "windows10-64")
        self.assertEqual(decision.value, "darwin24-64")
        self.assertEqual(len(decision.warnings), 1)
        self.assertIn("windows10-64", decision.warnings[0])

    def test_to_dict_is_json_shaped(self) -> None:
        payload = resolve_guestos("darwin25-64", "darwin24-64").to_dict()
        self.assertEqual(payload["decision"], "change")
        self.assertEqual(payload["guest_id"], 0x5075)
        self.assertIsInstance(payload["warnings"], list)


class BuildTests(unittest.TestCase):
    def build(self, mapping, **opts_kwargs) -> ProfileResult:
        return build(mapping, REFERENCE_HOST, ProfileOptions(**opts_kwargs))

    def test_emits_only_when_a_target_was_requested(self) -> None:
        result = self.build({"guestOS": '"darwin24-64"'})
        self.assertEqual(result.params, ())
        self.assertEqual(result.errors, ())

    def test_emits_when_the_target_differs(self) -> None:
        result = self.build({"guestOS": '"darwin24-64"'}, guestos="darwin25-64")
        self.assertEqual([p.key for p in result.params], ["guestOS"])
        param = result.params[0]
        self.assertEqual(param.value, "darwin25-64")
        self.assertEqual(param.module, "guestos")
        self.assertEqual(param.risk, "normal")
        self.assertFalse(param.remove)
        self.assertTrue(param.evidence, "Param without evidence is a defect (§4.0)")
        for evidence in param.evidence:
            self.assertIn(evidence.kind, EVIDENCE_KINDS)

    def test_no_op_when_the_file_already_holds_the_target(self) -> None:
        result = self.build({"guestOS": '"darwin25-64"'}, guestos="darwin25-64")
        self.assertEqual(result.params, ())

    def test_missing_guestos_key_still_writes_the_requested_tier(self) -> None:
        result = self.build({}, guestos="darwin24-64")
        self.assertEqual(len(result.params), 1)
        self.assertEqual(result.params[0].value, "darwin24-64")

    def test_unknown_target_becomes_an_error_and_no_param(self) -> None:
        result = self.build({"guestOS": '"darwin24-64"'}, guestos="darwin26-64")
        self.assertEqual(result.params, ())
        self.assertEqual(len(result.errors), 1)
        self.assertIn("darwin26-64", result.errors[0])

    def test_stale_current_value_warns_but_still_writes(self) -> None:
        result = self.build({"guestOS": '"windows10-64"'}, guestos="darwin24-64")
        self.assertEqual(len(result.params), 1)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("windows10-64", result.warnings[0])

    def test_unknown_darwin_tier_in_the_file_only_warns(self) -> None:
        result = self.build({"guestOS": '"darwin26-64"'})
        self.assertEqual(result.params, ())
        self.assertEqual(result.errors, ())
        self.assertEqual(len(result.warnings), 1)

    def test_quoted_values_are_normalised_before_comparing(self) -> None:
        plain = build({"guestOS": "darwin25-64"}, REFERENCE_HOST, ProfileOptions(guestos="darwin25-64"))
        self.assertEqual(plain.params, ())

    def test_every_tier_the_table_lists_can_be_written(self) -> None:
        for tier in KNOWN_TIERS:
            with self.subTest(tier=tier):
                result = self.build({"guestOS": '"darwin22-64"'}, guestos=tier)
                if tier == "darwin22-64":
                    self.assertEqual(result.params, ())
                else:
                    self.assertEqual(len(result.params), 1)
                    self.assertEqual(result.params[0].value, tier)
                    self.assertEqual(result.params[0].evidence[0].source, "docs/DESIGN.md §12.2")


if __name__ == "__main__":
    unittest.main()

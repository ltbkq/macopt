"""Unit tests for the identity / SMBIOS block (DESIGN §4.11).

Two properties matter more than coverage here:

* **macopt never invents an identity** — a missing required value is an
  error, never a guess, and no board-id / serial ships in this repository;
* **the reflect ↔ explicit mutual exclusion** is what `check.S6` and
  `apply` stand on, so ``mutual_exclusion_violations`` is pinned from
  every angle, including fields macopt has not catalogued yet.

All identity values in this file are obviously-fake placeholders.
"""

from __future__ import annotations

import unittest

from macopt.model import EVIDENCE_KINDS, HostInfo, ProfileOptions, ProfileResult
from macopt.profiles import build_all, identity

HOST = HostInfo(vendor="GenuineIntel", brand="13th Gen Intel(R) Core(TM) i7-13620H")

# Obviously-fake placeholders: macopt ships no real identity values.
BOARD = "Mac-TESTBOARDID0001"
HW_MODEL = "Mac-TEST,1"
SERIAL = "TESTONLYSERIAL0001"
SMC = "TEST-SMC-VERSION"


def opts(**kwargs) -> ProfileOptions:
    kwargs.setdefault("identity", True)
    return ProfileOptions(**kwargs)


def with_extras(values: dict[str, str], **kwargs) -> ProfileOptions:
    kwargs.setdefault("identity", True)
    return ProfileOptions(extras=dict(values), **kwargs)


class FieldTableTests(unittest.TestCase):
    def test_six_fields_three_required(self) -> None:
        self.assertEqual(
            [f.key for f in identity.IDENTITY_FIELDS],
            ["board-id", "hw.model", "serialNumber", "smc.version",
             "efi.nvram.var.ROM", "efi.nvram.var.MLB"],
        )
        required = [f.key for f in identity.IDENTITY_FIELDS if f.required]
        self.assertEqual(required, ["board-id", "hw.model", "serialNumber"])

    def test_no_field_ships_a_value(self) -> None:
        # Every field must be filled by the user; the table carries no defaults.
        for field in identity.IDENTITY_FIELDS:
            with self.subTest(key=field.key):
                self.assertTrue(field.required or field.risk_note)
                self.assertFalse(hasattr(field, "value"))
                self.assertTrue(field.reason)
                self.assertTrue(field.risk_note)
                for ev in field.evidence:
                    self.assertIn(ev.kind, EVIDENCE_KINDS)
                    self.assertTrue(ev.source)
                    self.assertTrue(ev.note)

    def test_reflect_host_key_helper(self) -> None:
        self.assertEqual(identity.REFLECT_SUFFIX, ".reflectHost")
        self.assertEqual(identity.reflect_host_key("board-id"), "board-id.reflectHost")
        for field in identity.IDENTITY_FIELDS:
            self.assertEqual(
                field.reflect_host_key, f"{field.key}{identity.REFLECT_SUFFIX}"
            )

    def test_extras_spellings_are_documented(self) -> None:
        by_key = {f.key: f for f in identity.IDENTITY_FIELDS}
        self.assertIn("board-id", by_key["board-id"].extras_keys)
        self.assertIn("hw-model", by_key["hw.model"].extras_keys)
        self.assertIn("serial", by_key["serialNumber"].extras_keys)


class MutualExclusionTests(unittest.TestCase):
    def test_reflect_true_plus_explicit_value_is_a_violation(self) -> None:
        mapping = {"board-id.reflectHost": "TRUE", "board-id": f'"{BOARD}"'}
        violations = identity.mutual_exclusion_violations(mapping)
        self.assertEqual(len(violations), 1)
        self.assertIn("board-id", violations[0])
        self.assertIn("reflectHost", violations[0])
        self.assertIn("§4.11", violations[0])

    def test_reflect_false_plus_value_is_consistent(self) -> None:
        mapping = {"board-id.reflectHost": "FALSE", "board-id": f'"{BOARD}"'}
        self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_reflect_true_alone_is_consistent(self) -> None:
        mapping = {"board-id.reflectHost": "TRUE"}
        self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_explicit_value_alone_is_consistent(self) -> None:
        mapping = {"board-id": f'"{BOARD}"'}
        self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_empty_mapping_is_consistent(self) -> None:
        self.assertEqual(identity.mutual_exclusion_violations({}), [])

    def test_unrelated_keys_are_ignored(self) -> None:
        mapping = {"guestOS": "darwin24-64", "board-id": f'"{BOARD}"'}
        self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_uncatalogued_field_is_still_caught(self) -> None:
        # Generic scan: a reflectHost key macopt has not catalogued yet is a
        # violation just the same (this is what S6 relies on).
        mapping = {
            "future.thing.reflectHost": "TRUE",
            "future.thing": "some value",
        }
        violations = identity.mutual_exclusion_violations(mapping)
        self.assertEqual(len(violations), 1)
        self.assertIn("future.thing", violations[0])

    def test_truthy_variants_and_quoted_values(self) -> None:
        for raw in ("TRUE", "true", '"TRUE"', "1", "yes", "on"):
            with self.subTest(raw=raw):
                mapping = {"hw.model.reflectHost": raw, "hw.model": HW_MODEL}
                self.assertEqual(len(identity.mutual_exclusion_violations(mapping)), 1)

    def test_falsey_values_do_not_violate(self) -> None:
        for raw in ("FALSE", "false", "0", "no", "off", ""):
            with self.subTest(raw=raw):
                mapping = {"hw.model.reflectHost": raw, "hw.model": HW_MODEL}
                self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_blank_explicit_value_is_not_a_violation(self) -> None:
        mapping = {"hw.model.reflectHost": "TRUE", "hw.model": '""'}
        self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_bare_reflect_suffix_key_is_ignored(self) -> None:
        mapping = {".reflectHost": "TRUE", "": "x"}
        self.assertEqual(identity.mutual_exclusion_violations(mapping), [])

    def test_multiple_violations_are_sorted_and_one_per_field(self) -> None:
        mapping = {
            "board-id.reflectHost": "TRUE",
            "board-id": BOARD,
            "hw.model.reflectHost": "TRUE",
            "hw.model": HW_MODEL,
        }
        violations = identity.mutual_exclusion_violations(mapping)
        self.assertEqual(len(violations), 2)
        self.assertEqual(violations, sorted(violations))


class BuildOffTests(unittest.TestCase):
    def test_identity_off_emits_nothing(self) -> None:
        result = identity.build({}, HOST, ProfileOptions(identity=False))
        self.assertEqual(result, ProfileResult())

    def test_identity_off_even_with_extras(self) -> None:
        extras = {"board-id": BOARD, "hw-model": HW_MODEL, "serial": SERIAL}
        result = identity.build({}, HOST, ProfileOptions(extras=extras))
        self.assertEqual(result, ProfileResult())


class MissingValueTests(unittest.TestCase):
    def test_missing_required_values_are_errors_not_guesses(self) -> None:
        result = identity.build({}, HOST, opts())
        self.assertEqual(result.params, ())
        self.assertEqual(len(result.errors), 3)
        joined = "\n".join(result.errors)
        self.assertIn("board-id", joined)
        self.assertIn("hw.model", joined)
        self.assertIn("serialNumber", joined)
        self.assertIn("macopt 不内置", joined)

    def test_partial_extras_reports_only_the_missing_field(self) -> None:
        result = identity.build({}, HOST, with_extras({"board-id": BOARD}))
        # hw.model and serialNumber are still missing; board-id is not
        self.assertEqual(len(result.errors), 2)
        joined = "\n".join(result.errors)
        self.assertIn("hw.model", joined)
        self.assertIn("serialNumber", joined)
        self.assertNotIn("缺少 board-id", joined)
        # the supplied value is emitted even though its siblings are missing
        self.assertIn("board-id", [p.key for p in result.params])

    def test_empty_string_counts_as_missing(self) -> None:
        result = identity.build(
            {}, HOST, with_extras({"board-id": "", "hw-model": " ", "serial": SERIAL})
        )
        self.assertEqual(len(result.errors), 2)
        keys = "\n".join(e for e in result.errors)
        self.assertIn("board-id", keys)
        self.assertIn("hw.model", keys)

    def test_optional_fields_may_be_absent(self) -> None:
        result = identity.build(
            {},
            HOST,
            with_extras({"board-id": BOARD, "hw-model": HW_MODEL, "serial": SERIAL}),
        )
        self.assertEqual(result.errors, ())
        self.assertEqual(
            sorted(p.key for p in result.params),
            sorted(
                ["board-id", "board-id.reflectHost", "hw.model",
                 "hw.model.reflectHost", "serialNumber", "serialNumber.reflectHost"]
            ),
        )


class NormalPathTests(unittest.TestCase):
    FULL = {"board-id": BOARD, "hw-model": HW_MODEL, "serial": SERIAL,
            "smc.version": SMC, "ROM": "TEST-ROM", "MLB": "TEST-MLB"}

    def build(self, mapping=None, **kwargs):
        return identity.build(mapping or {}, HOST, with_extras(self.FULL, **kwargs))

    def test_emits_value_and_reflect_false_pairs(self) -> None:
        result = self.build()
        self.assertEqual(result.errors, ())
        by_key = {p.key: p.value for p in result.params}
        for base in ("board-id", "hw.model", "serialNumber"):
            self.assertEqual(by_key[base], {
                "board-id": BOARD, "hw.model": HW_MODEL, "serialNumber": SERIAL
            }[base])
            self.assertEqual(by_key[f"{base}.reflectHost"], "FALSE")
        for optional in ("smc.version", "efi.nvram.var.ROM", "efi.nvram.var.MLB"):
            self.assertEqual(by_key[f"{optional}.reflectHost"], "FALSE")

    def test_every_param_is_guarded_and_sourced(self) -> None:
        result = self.build()
        for param in result.params:
            with self.subTest(key=param.key):
                self.assertEqual(param.module, "identity")
                self.assertTrue(param.needs_confirmation)
                self.assertTrue(param.reason)
                self.assertTrue(param.risk_note)
                self.assertTrue(param.evidence)
                for ev in param.evidence:
                    self.assertIn(ev.kind, EVIDENCE_KINDS)

    def test_extras_alternate_spellings(self) -> None:
        result = identity.build(
            {},
            HOST,
            with_extras({
                "boardId": BOARD,
                "hw.model": HW_MODEL,
                "serialNumber": SERIAL,
            }),
        )
        self.assertEqual(result.errors, ())
        self.assertIn("board-id", [p.key for p in result.params])

    def test_reflecting_fields_produce_a_warning(self) -> None:
        mapping = {"board-id.reflectHost": "TRUE"}
        result = self.build(mapping)
        self.assertTrue(any("reflectHost=TRUE" in w for w in result.warnings))
        self.assertTrue(any("反射链路已断" in w for w in result.warnings))

    def test_converts_reflect_true_without_value_to_explicit(self) -> None:
        # reflect-only (no explicit value) is consistent, and converting it to
        # the explicit path is allowed: there is nothing to contradict yet.
        mapping = {"board-id.reflectHost": "TRUE"}
        result = self.build(mapping)
        emitted = {p.key: p.value for p in result.params}
        self.assertEqual(emitted.get("board-id"), BOARD)
        self.assertEqual(emitted.get("board-id.reflectHost"), "FALSE")

    def test_violation_is_an_error_and_no_param_contradicts_it(self) -> None:
        mapping = {"board-id.reflectHost": "TRUE", "board-id": '"Mac-OTHER"'}
        result = self.build(mapping)
        self.assertTrue(any("board-id" in e for e in result.errors))
        # the conflicting field is not emitted (the plan stays consistent)
        self.assertNotIn("board-id", [p.key for p in result.params])

    def test_already_applied_block_is_idempotent(self) -> None:
        mapping = {
            "board-id": f'"{BOARD}"', "board-id.reflectHost": "FALSE",
            "hw.model": f'"{HW_MODEL}"', "hw.model.reflectHost": "FALSE",
            "serialNumber": f'"{SERIAL}"', "serialNumber.reflectHost": "FALSE",
            "smc.version": f'"{SMC}"', "smc.version.reflectHost": "FALSE",
            "efi.nvram.var.ROM": '"TEST-ROM"', "efi.nvram.var.ROM.reflectHost": "FALSE",
            "efi.nvram.var.MLB": '"TEST-MLB"', "efi.nvram.var.MLB.reflectHost": "FALSE",
        }
        result = self.build(mapping)
        self.assertEqual(result.params, ())
        self.assertEqual(result.errors, ())

    def test_value_matches_but_reflect_flag_missing_emits_only_the_flag(self) -> None:
        # board-id already holds the target value; only the pair flag is absent
        mapping = {"board-id": f'"{BOARD}"'}
        result = identity.build(
            mapping, HOST, with_extras({"board-id": BOARD})
        )
        self.assertEqual(
            [(p.key, p.value) for p in result.params],
            [("board-id.reflectHost", "FALSE")],
        )

    def test_reflect_flag_true_but_value_matches_still_needs_false(self) -> None:
        mapping = {"board-id": f'"{BOARD}"', "board-id.reflectHost": "TRUE"}
        result = self.build(mapping)
        # S6 violation is reported …
        self.assertTrue(any(e.startswith("board-id:") for e in result.errors))
        # … and the conflicting field contributes no params at all
        self.assertNotIn("board-id", [p.key for p in result.params])
        self.assertNotIn("board-id.reflectHost", [p.key for p in result.params])

    def test_errors_are_deduplicated_and_ordered(self) -> None:
        result = identity.build({}, HOST, opts())
        self.assertEqual(len(result.errors), len(set(result.errors)))


class IntegrationTests(unittest.TestCase):
    def test_build_all_routes_identity_module(self) -> None:
        extras = {"board-id": BOARD, "hw-model": HW_MODEL, "serial": SERIAL}
        result = build_all(
            {}, HOST, ProfileOptions(identity=True, extras=extras,
                                     modules=("identity",)),
        )
        self.assertEqual(result.errors, ())
        self.assertTrue(result.params)
        self.assertTrue(all(p.module == "identity" for p in result.params))

    def test_build_all_skips_identity_when_not_requested(self) -> None:
        extras = {"board-id": BOARD, "hw-model": HW_MODEL, "serial": SERIAL}
        result = build_all(
            {}, HOST, ProfileOptions(identity=False, extras=extras,
                                     modules=("identity",)),
        )
        self.assertEqual(result, ProfileResult())

    def test_registry_exposes_the_builder(self) -> None:
        from macopt.profiles import get_builder

        self.assertIs(get_builder("identity"), identity.build)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

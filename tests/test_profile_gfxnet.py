"""Unit tests for the ``gfxnet`` profile (DESIGN §4.9, lines 404-414).

3D acceleration, texture size and per-NIC ``virtualDev``. The module is
strictly "add if missing" and must never emit the two keys that do not exist
in any VMware binary (``mks.g3d.maxTextureSize`` / ``mks.enableGLRenderer``),
because writing them would be silently ignored — the F3 failure mode.
"""

from __future__ import annotations

import unittest

from macopt.model import EVIDENCE_KINDS, HostInfo, ProfileOptions, ProfileResult
from macopt.profiles import build_all, gfxnet

ALLOWED_EVIDENCE_KINDS = ("log", "sysfs", "binary", "doc", "measured", "community")

REFERENCE_HOST = HostInfo(
    vendor="GenuineIntel",
    brand="13th Gen Intel(R) Core(TM) i7-13620H",
    logical_cpus=16,
    physical_cores=10,
    numa_nodes=1,
    hybrid=True,
    p_cpus=tuple(range(12)),
    e_cpus=(12, 13, 14, 15),
)

# Reference host .vmx: 3D already on, texture key absent, NIC0 present without
# a virtualDev (01-factcheck.md:39, 55).
BASE_MAPPING = {
    "mks.enable3d": '"TRUE"',
    "ethernet0.present": '"TRUE"',
    "ethernet0.addressType": '"generated"',
    "ethernet0.linkedOnStart": '"TRUE"',
    "vmotion.svga.maxTextureSize": "16384",
}


def by_key(result: ProfileResult) -> dict[str, object]:
    return {p.key: p for p in result.params}


class GfxnetCase(unittest.TestCase):
    def build(self, mapping=None, host=None, **opts_kwargs) -> ProfileResult:
        return gfxnet.build(
            mapping if mapping is not None else BASE_MAPPING,
            host or REFERENCE_HOST,
            ProfileOptions(**opts_kwargs),
        )


class TestAddIfMissing(GfxnetCase):
    def test_enable3d_already_true_is_untouched(self) -> None:
        self.assertNotIn("mks.enable3d", by_key(self.build()))

    def test_enable3d_false_is_left_alone(self) -> None:
        # "有则不变": an explicit FALSE in the file is the user's choice.
        mapping = dict(BASE_MAPPING, **{"mks.enable3d": '"FALSE"'})
        self.assertNotIn("mks.enable3d", by_key(self.build(mapping)))

    def test_enable3d_missing_is_added_true(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "mks.enable3d"}
        param = by_key(self.build(mapping))["mks.enable3d"]
        self.assertEqual(param.value, "TRUE")
        self.assertFalse(param.remove)

    def test_texture_size_missing_is_added_16384(self) -> None:
        param = by_key(self.build())["svga.maxTextureSize"]
        self.assertEqual(param.value, "16384")

    def test_texture_size_present_is_not_duplicated(self) -> None:
        mapping = dict(BASE_MAPPING, **{"svga.maxTextureSize": "4096"})
        self.assertNotIn("svga.maxTextureSize", by_key(self.build(mapping)))

    def test_missing_keys_reasons_differ(self) -> None:
        params = by_key(self.build())
        self.assertIn("texture size", params["svga.maxTextureSize"].reason)


class TestVirtualDev(GfxnetCase):
    def test_present_nic_without_virtualdev_gets_vmxnet3(self) -> None:
        param = by_key(self.build())["ethernet0.virtualDev"]
        self.assertEqual(param.value, "vmxnet3")
        self.assertTrue(param.needs_confirmation)
        self.assertTrue(param.risk_note)

    def test_existing_virtualdev_is_respected(self) -> None:
        mapping = dict(BASE_MAPPING, **{"ethernet0.virtualDev": '"e1000"'})
        self.assertNotIn("ethernet0.virtualDev", by_key(self.build(mapping)))

    def test_nics_are_discovered_from_present_entries(self) -> None:
        mapping = dict(
            BASE_MAPPING,
            **{"ethernet1.present": "TRUE", "ethernet2.present": '"TRUE"'},
        )
        params = by_key(self.build(mapping))
        self.assertIn("ethernet1.virtualDev", params)
        self.assertIn("ethernet2.virtualDev", params)

    def test_disabled_nic_is_skipped(self) -> None:
        mapping = dict(BASE_MAPPING, **{"ethernet1.present": "FALSE"})
        params = by_key(self.build(mapping))
        self.assertIn("ethernet0.virtualDev", params)  # still present
        self.assertNotIn("ethernet1.virtualDev", params)

    def test_non_true_nic_present_is_skipped(self) -> None:
        mapping = dict(BASE_MAPPING, **{"ethernet1.present": '"FALSE"'})
        self.assertNotIn("ethernet1.virtualDev", by_key(self.build(mapping)))

    def test_indexes_are_sorted_and_stable(self) -> None:
        mapping = dict(
            BASE_MAPPING,
            **{"ethernet10.present": "TRUE", "ethernet3.present": "TRUE"},
        )
        virtual = [p.key for p in self.build(mapping).params if p.key.endswith(".virtualDev")]
        self.assertEqual(
            virtual,
            ["ethernet0.virtualDev", "ethernet3.virtualDev", "ethernet10.virtualDev"],
        )

    def test_no_nics_at_all_is_fine(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if not k.startswith("ethernet")}
        params = by_key(self.build(mapping))
        self.assertFalse(any(k.startswith("ethernet") for k in params))


class TestForbiddenKeys(GfxnetCase):
    FORBIDDEN = ("mks.g3d.maxTextureSize", "mks.enableGLRenderer")

    def test_forbidden_keys_never_emitted(self) -> None:
        for mapping in ({}, {"mks.enable3d": '"FALSE"'}):
            with self.subTest(mapping=mapping):
                params = by_key(self.build(mapping))
                for key in self.FORBIDDEN:
                    self.assertNotIn(key, params)

    def test_forbidden_keys_absent_even_when_present_in_mapping(self) -> None:
        mapping = dict(
            BASE_MAPPING,
            **{"mks.g3d.maxTextureSize": "16384", "mks.enableGLRenderer": "TRUE"},
        )
        params = by_key(self.build(mapping))
        for key in self.FORBIDDEN:
            self.assertNotIn(key, params)

    def test_module_exposes_forbidden_list(self) -> None:
        self.assertEqual(
            gfxnet.FORBIDDEN_KEYS, ("mks.g3d.maxTextureSize", "mks.enableGLRenderer")
        )


class TestEvidenceContract(GfxnetCase):
    def test_every_param_has_allowed_kind_and_concrete_source(self) -> None:
        mapping = {
            k: v for k, v in BASE_MAPPING.items() if k not in ("mks.enable3d", "svga.maxTextureSize")
        }
        result = self.build(mapping)
        self.assertTrue(result.params)
        for param in result.params:
            with self.subTest(key=param.key):
                self.assertTrue(param.evidence, f"{param.key} has no evidence")
                for ev in param.evidence:
                    self.assertIn(ev.kind, ALLOWED_EVIDENCE_KINDS)
                    self.assertIn(ev.kind, EVIDENCE_KINDS)
                    self.assertTrue(ev.source.startswith("docs/"))
                    self.assertNotIn("*", ev.source)

    def test_module_is_always_gfxnet(self) -> None:
        for param in self.build().params:
            self.assertEqual(param.module, "gfxnet")


class TestBuildAllIntegration(GfxnetCase):
    def test_module_is_registered(self) -> None:
        result = build_all({}, REFERENCE_HOST, ProfileOptions(), modules=("gfxnet",))
        params = by_key(result)
        self.assertIn("mks.enable3d", params)
        self.assertIn("svga.maxTextureSize", params)
        for key in ("mks.g3d.maxTextureSize", "mks.enableGLRenderer"):
            self.assertNotIn(key, params)


if __name__ == "__main__":
    unittest.main()

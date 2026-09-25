"""Unit tests for the ``topology`` profile (DESIGN §4.7 parameter table).

Covers the three tiers, the exact-division rule for ``cpuid.coresPerSocket``,
vNUMA convergence, cookie deletion semantics, the opt-in hypervisor bit and
the "every Param carries Evidence" contract.
"""

from __future__ import annotations

import unittest

from macopt.model import (
    EVIDENCE_KINDS,
    HostInfo,
    ProfileOptions,
    ProfileResult,
)
from macopt.profiles import build_all, topology

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
    freq_mhz_p=4900,
    freq_mhz_e=3600,
)

BASE_MAPPING = {
    "numvcpus": "12",
    "cpuid.coresPerSocket": "12",
    "numa.autosize.vcpu.maxPerVirtualNode": "8",
    "numa.autosize.cookie": "120122",
    "vhv.enable": "TRUE",
    "vpmc.enable": "TRUE",
}


def by_key(result: ProfileResult) -> dict[str, object]:
    return {p.key: p for p in result.params}


class TopologyCase(unittest.TestCase):
    def build(self, mapping=None, host=None, **opts_kwargs) -> ProfileResult:
        return topology.build(
            mapping if mapping is not None else BASE_MAPPING,
            host or REFERENCE_HOST,
            ProfileOptions(**opts_kwargs),
        )


class TestThreeTiers(TopologyCase):
    def test_performance_tier(self) -> None:
        params = by_key(self.build(profile="performance"))
        # DESIGN line 331: min(6x2, logical) = min(12, 16) = 12
        self.assertEqual(params["numvcpus"].value, "12")
        self.assertEqual(params["cpuid.coresPerSocket"].value, "12")
        self.assertEqual(params["numa.autosize.vcpu.maxPerVirtualNode"].value, "12")

    def test_performance_tier_capped_by_host(self) -> None:
        host = HostInfo(logical_cpus=8, physical_cores=4, numa_nodes=1)
        params = by_key(self.build(profile="performance", host=host))
        self.assertEqual(params["numvcpus"].value, "8")

    def test_balanced_tier_keeps_existing_vcpus(self) -> None:
        mapping = dict(BASE_MAPPING, numvcpus="8", **{"cpuid.coresPerSocket": "4"})
        params = by_key(self.build(mapping, profile="balanced"))
        self.assertEqual(params["numvcpus"].value, "8")
        self.assertEqual(params["cpuid.coresPerSocket"].value, "8")
        self.assertEqual(params["numa.autosize.vcpu.maxPerVirtualNode"].value, "8")

    def test_throughput_tier_uses_all_logical_cpus(self) -> None:
        params = by_key(self.build(profile="throughput"))
        self.assertEqual(params["numvcpus"].value, "16")
        self.assertEqual(params["cpuid.coresPerSocket"].value, "16")
        self.assertEqual(params["numa.autosize.vcpu.maxPerVirtualNode"].value, "16")

    def test_explicit_numvcpus_override_wins(self) -> None:
        params = by_key(self.build(profile="performance", numvcpus=6))
        self.assertEqual(params["numvcpus"].value, "6")
        self.assertEqual(params["cpuid.coresPerSocket"].value, "6")
        self.assertEqual(params["numa.autosize.vcpu.maxPerVirtualNode"].value, "6")

    def test_throughput_never_exceeds_host(self) -> None:
        host = HostInfo(logical_cpus=4, physical_cores=2, numa_nodes=1)
        params = by_key(self.build(profile="throughput", host=host))
        self.assertEqual(params["numvcpus"].value, "4")


class TestDivisibilityAndVNuma(TopologyCase):
    def test_cores_per_socket_divides_numvcpus(self) -> None:
        for sockets, expected in ((1, "12"), (2, "6"), (4, "3")):
            with self.subTest(sockets=sockets):
                params = by_key(self.build(profile="balanced", extras={"sockets": str(sockets)}))
                numvcpus = int(params["numvcpus"].value)
                cores = int(params["cpuid.coresPerSocket"].value)
                self.assertEqual(cores, int(expected))
                self.assertEqual(numvcpus % cores, 0)
                self.assertEqual(cores * sockets, numvcpus)

    def test_non_divisible_sockets_fall_back_to_single_socket(self) -> None:
        result = self.build(profile="balanced", extras={"sockets": "5"})
        params = by_key(result)
        self.assertEqual(params["cpuid.coresPerSocket"].value, "12")  # 12 % 5 != 0
        self.assertTrue(any("not divisible" in w for w in result.warnings))

    def test_vnuma_converges_to_one_node(self) -> None:
        # observed bad state: maxPerVirtualNode=8 with 12 vCPU -> 8+4 vNUMA
        params = by_key(self.build(profile="balanced"))
        self.assertGreaterEqual(
            int(params["numa.autosize.vcpu.maxPerVirtualNode"].value),
            int(params["numvcpus"].value),
        )
        self.assertEqual(params["numa.autosize.vcpu.maxPerVirtualNode"].value, "12")

    def test_multi_node_host_keeps_autosize(self) -> None:
        host = HostInfo(logical_cpus=32, physical_cores=24, numa_nodes=2, hybrid=True)
        result = self.build(profile="balanced", host=host)
        params = by_key(result)
        self.assertNotIn("numa.autosize.vcpu.maxPerVirtualNode", params)
        self.assertTrue(any("NUMA nodes" in w for w in result.warnings))


class TestCookieDeletion(TopologyCase):
    def test_cookie_removed_in_every_tier(self) -> None:
        for profile in ("performance", "balanced", "throughput"):
            with self.subTest(profile=profile):
                param = by_key(self.build(profile=profile))["numa.autosize.cookie"]
                self.assertTrue(param.remove)
                self.assertEqual(param.value, "")  # Param contract: remove => empty value
                self.assertTrue(param.evidence)

    def test_cookie_removed_even_when_absent(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "numa.autosize.cookie"}
        param = by_key(self.build(mapping))["numa.autosize.cookie"]
        self.assertTrue(param.remove)


class TestSwitches(TopologyCase):
    def test_vhv_and_vpmc_are_forced_false_in_every_tier(self) -> None:
        for profile in ("performance", "balanced", "throughput"):
            with self.subTest(profile=profile):
                params = by_key(self.build(profile=profile))
                self.assertEqual(params["vhv.enable"].value, "FALSE")
                self.assertEqual(params["vpmc.enable"].value, "FALSE")

    def test_hypervisor_bit_is_opt_in_only(self) -> None:
        self.assertNotIn("hypervisor.cpuid.v0", by_key(self.build()))
        params = by_key(self.build(hide_hypervisor_bit=True))
        param = params["hypervisor.cpuid.v0"]
        self.assertEqual(param.value, "FALSE")
        self.assertIn("Tools", param.risk_note)
        self.assertTrue(param.needs_confirmation)
        self.assertTrue(param.evidence)

    def test_passthrough_emits_nothing(self) -> None:
        result = self.build(profile="passthrough")
        self.assertEqual(result.params, ())

    def test_oversubscription_is_annotated(self) -> None:
        param = by_key(self.build(profile="balanced"))["numvcpus"]
        self.assertIn(str(REFERENCE_HOST.physical_cores), param.risk_note)


class TestDegradation(TopologyCase):
    def test_unknown_host_does_not_invent_vcpu_count(self) -> None:
        host = HostInfo()  # everything unknown
        result = self.build(profile="performance", host=host)
        keys = set(by_key(result))
        self.assertNotIn("numvcpus", keys)
        self.assertNotIn("cpuid.coresPerSocket", keys)
        self.assertNotIn("numa.autosize.vcpu.maxPerVirtualNode", keys)
        # the generic switches are still safe to emit
        self.assertIn("vhv.enable", keys)
        self.assertIn("vpmc.enable", keys)
        self.assertTrue(any("rather than guessing" in w for w in result.warnings))

    def test_balanced_without_vcpu_key_degrades(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "numvcpus"}
        result = self.build(mapping, profile="balanced")
        self.assertNotIn("numvcpus", by_key(result))
        self.assertTrue(result.warnings)

    def test_p_e_unknown_adds_no_binding_warning(self) -> None:
        host = HostInfo(logical_cpus=8, physical_cores=8, numa_nodes=1)
        result = self.build(host=host)
        self.assertTrue(any("no CPU binding" in w for w in result.warnings))


class TestEvidenceContract(TopologyCase):
    def test_every_param_has_allowed_evidence(self) -> None:
        for profile in ("performance", "balanced", "throughput"):
            for opts_kwargs in ({}, {"hide_hypervisor_bit": True}):
                with self.subTest(profile=profile, opts=opts_kwargs):
                    result = self.build(profile=profile, **opts_kwargs)
                    self.assertTrue(result.params)
                    for param in result.params:
                        self.assertTrue(
                            param.evidence,
                            f"{param.key} has no evidence (DESIGN §4.0 hard rule 1)",
                        )
                        for ev in param.evidence:
                            self.assertIn(ev.kind, ALLOWED_EVIDENCE_KINDS)
                            self.assertIn(ev.kind, EVIDENCE_KINDS)
                            self.assertTrue(ev.source)
                            # sources must be concrete repo paths / line refs
                            self.assertTrue(
                                ev.source.startswith("docs/"),
                                f"{param.key}: evidence source must cite a repo doc: {ev.source}",
                            )

    def test_no_forbidden_or_unrelated_keys(self) -> None:
        forbidden = {
            "ulm.disableMitigations",
            "mks.g3d.maxTextureSize",
            "mks.enableGLRenderer",
            "tools.syncTime",
        }
        result = self.build(hide_hypervisor_bit=True)
        keys = set(by_key(result))
        self.assertFalse(keys & forbidden)
        self.assertLessEqual(
            keys,
            {
                "numvcpus",
                "cpuid.coresPerSocket",
                "numa.autosize.vcpu.maxPerVirtualNode",
                "numa.autosize.cookie",
                "vhv.enable",
                "vpmc.enable",
                "hypervisor.cpuid.v0",
            },
        )

    def test_registry_runs_the_module(self) -> None:
        result = build_all(
            BASE_MAPPING,
            REFERENCE_HOST,
            ProfileOptions(modules=("topology",)),
            modules=("topology",),
        )
        self.assertIn("numvcpus", by_key(result))
        self.assertIn("vhv.enable", by_key(result))

    def test_second_run_is_idempotent_at_the_param_level(self) -> None:
        first = by_key(self.build(profile="balanced"))
        converged = {
            key: ("" if param.remove else param.value) for key, param in first.items()
        }
        second = by_key(self.build(dict(BASE_MAPPING, **converged)))
        self.assertEqual(set(first), set(second))
        # values the writer will classify as "unchanged" on the second apply
        for key, param in second.items():
            if param.remove:
                continue
            self.assertEqual(converged[key], param.value)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

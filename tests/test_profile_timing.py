"""Unit tests for the ``timing`` profile (DESIGN §4.9, lines 410-411).

Two rules, both derived from the measured clock situation on the reference
host: ``tools.syncTime`` is opt-in only (and warns while VMware Tools is
broken), ``hpet0.present`` must end up TRUE because the guest's CPUID
frequency leaves are all zero. ``ulm.disableMitigations`` must never appear.
"""

from __future__ import annotations

import unittest

from macopt.model import EVIDENCE_KINDS, HostInfo, ProfileOptions, ProfileResult
from macopt.profiles import build_all, timing

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
    tsc_hz=None,  # measured: cpu*/tsc_freq_khz absent on the reference host
)

# Observed on the reference host's .vmx (03-cpu-tuning-module.md §4).
BASE_MAPPING = {
    "tools.syncTime": '"FALSE"',
    "hpet0.present": '"TRUE"',
    "toolsInstallManager.lastInstallError": '"21004"',
}


def by_key(result: ProfileResult) -> dict[str, object]:
    return {p.key: p for p in result.params}


class TimingCase(unittest.TestCase):
    def build(self, mapping=None, host=None, **opts_kwargs) -> ProfileResult:
        return timing.build(
            mapping if mapping is not None else BASE_MAPPING,
            host or REFERENCE_HOST,
            ProfileOptions(**opts_kwargs),
        )


class TestSyncTimeOptIn(TimingCase):
    def test_default_emits_no_sync_time(self) -> None:
        self.assertNotIn("tools.syncTime", by_key(self.build()))

    def test_opt_in_emits_sync_time_true(self) -> None:
        params = by_key(self.build(sync_time=True))
        self.assertEqual(params["tools.syncTime"].value, "TRUE")

    def test_opt_in_with_already_true_emits_nothing(self) -> None:
        mapping = dict(BASE_MAPPING, **{"tools.syncTime": '"TRUE"'})
        self.assertNotIn("tools.syncTime", by_key(self.build(mapping, sync_time=True)))

    def test_broken_tools_warns_on_opt_in(self) -> None:
        result = self.build(sync_time=True)
        self.assertTrue(any("lastInstallError=21004" in w for w in result.warnings))

    def test_healthy_tools_does_not_warn(self) -> None:
        mapping = dict(BASE_MAPPING, **{"toolsInstallManager.lastInstallError": '"0"'})
        result = self.build(mapping, sync_time=True)
        self.assertFalse(any("lastInstallError" in w for w in result.warnings))

    def test_absent_install_error_does_not_warn(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "toolsInstallManager.lastInstallError"}
        result = self.build(mapping, sync_time=True)
        self.assertFalse(any("lastInstallError" in w for w in result.warnings))

    def test_default_never_warns_about_broken_tools(self) -> None:
        self.assertEqual(self.build().warnings, ())


class TestHpet(TimingCase):
    def test_already_true_emits_no_param(self) -> None:
        self.assertNotIn("hpet0.present", by_key(self.build()))

    def test_false_is_restored_to_true(self) -> None:
        mapping = dict(BASE_MAPPING, **{"hpet0.present": '"FALSE"'})
        param = by_key(self.build(mapping))["hpet0.present"]
        self.assertEqual(param.value, "TRUE")
        self.assertFalse(param.remove)

    def test_missing_key_is_added(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "hpet0.present"}
        param = by_key(self.build(mapping))["hpet0.present"]
        self.assertEqual(param.value, "TRUE")
        self.assertIn("add hpet0.present=TRUE", param.reason)

    def test_false_reason_says_restoring(self) -> None:
        mapping = dict(BASE_MAPPING, **{"hpet0.present": '"FALSE"'})
        self.assertIn("restoring", by_key(self.build(mapping))["hpet0.present"].reason)

    def test_hpet_evidence_mentions_cpuid_zero_leaves(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "hpet0.present"}
        ev = by_key(self.build(mapping))["hpet0.present"].evidence
        self.assertTrue(any("0x15" in e.note for e in ev))
        self.assertTrue(any(e.source.startswith("docs/") for e in ev))


class TestForbiddenKeys(TimingCase):
    def test_ulm_disable_mitigations_never_emitted(self) -> None:
        for kwargs in ({}, {"sync_time": True}):
            with self.subTest(kwargs=kwargs):
                self.assertNotIn("ulm.disableMitigations", by_key(self.build(**kwargs)))

    def test_forbidden_key_still_absent_when_present_in_mapping(self) -> None:
        # Even if the .vmx already carries it, this module must not re-emit it.
        mapping = dict(BASE_MAPPING, **{"ulm.disableMitigations": '"FALSE"'})
        self.assertNotIn("ulm.disableMitigations", by_key(self.build(mapping)))


class TestEvidenceContract(TimingCase):
    def test_every_param_has_allowed_kind_and_concrete_source(self) -> None:
        mapping = {k: v for k, v in BASE_MAPPING.items() if k != "hpet0.present"}
        result = self.build(mapping, sync_time=True)
        self.assertTrue(result.params)
        for param in result.params:
            with self.subTest(key=param.key):
                self.assertTrue(param.evidence, f"{param.key} has no evidence")
                for ev in param.evidence:
                    self.assertIn(ev.kind, ALLOWED_EVIDENCE_KINDS)
                    self.assertIn(ev.kind, EVIDENCE_KINDS)
                    self.assertTrue(ev.source.startswith("docs/"))
                    self.assertNotIn("*", ev.source)  # concrete path/line, not a glob

    def test_reasons_are_non_empty(self) -> None:
        mapping = dict(BASE_MAPPING, **{"hpet0.present": '"FALSE"'})
        result = self.build(mapping, sync_time=True)
        for param in result.params:
            self.assertTrue(param.reason.strip())


class TestBuildAllIntegration(TimingCase):
    def test_module_is_registered(self) -> None:
        result = build_all(BASE_MAPPING, REFERENCE_HOST, ProfileOptions(sync_time=True),
                           modules=("timing",))
        self.assertIn("tools.syncTime", by_key(result))
        self.assertNotIn("ulm.disableMitigations", by_key(result))

    def test_module_only_result_has_no_foreign_keys(self) -> None:
        mapping = dict(BASE_MAPPING, **{"hpet0.present": '"FALSE"'})
        result = build_all(mapping, REFERENCE_HOST, ProfileOptions(), modules=("timing",))
        for param in result.params:
            self.assertEqual(param.module, "timing")
            self.assertIn(param.key, ("tools.syncTime", "hpet0.present"))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for :mod:`macopt.hostinfo`.

Every probe is exercised against a **synthetic** sysfs/proc tree built in a
temporary directory, plus an injected fake ``runner`` for the whitelisted
``lscpu`` / ``vmware`` subprocesses — no test may depend on the real CPU layout
and none of them runs a real privileged command.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace

from macopt import hostinfo

# --------------------------------------------------------------------------- #
# synthetic tree builders
# --------------------------------------------------------------------------- #


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class FakeRunner:
    """Records every argv it is handed; answers lscpu/vmware from fixtures."""

    def __init__(self, *, table: str | None = None, kv: str | None = None,
                 version: str | None = None, rc: int = 1) -> None:
        self.table = table
        self.kv = kv
        self.version = version
        self.rc = rc
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):  # noqa: ANN001 - matches subprocess.run loosely
        self.calls.append(list(argv))
        assert isinstance(argv, list), "commands must be argv lists (no shell)"
        if argv[0] == "lscpu" and len(argv) > 1 and argv[1].startswith("-e"):
            if self.table is None:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout=self.table, stderr="")
        if argv[0] == "lscpu":
            if self.kv is None:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout=self.kv, stderr="")
        if argv[0] == "vmware":
            if self.version is None:
                return SimpleNamespace(returncode=self.rc, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout=self.version, stderr="")
        raise AssertionError(f"unexpected command: {argv}")


def exploding_runner(argv, **kwargs):  # noqa: ANN001
    raise AssertionError(f"no subprocess expected, got {argv}")


def build_hybrid_tree(sys_root: str, *, p_end: int = 12, total: int = 16,
                      freq_p: int = 4900000, freq_e: int = 3600000,
                      with_freq: bool = True) -> None:
    """Reference-host shaped tree: SMT P cores 0-11, single-thread E cores."""
    write(os.path.join(sys_root, "devices", "system", "cpu", "online"),
          f"0-{total - 1}\n")
    write(os.path.join(sys_root, "devices", "cpu_core", "cpus"), f"0-{p_end - 1}\n")
    write(os.path.join(sys_root, "devices", "cpu_atom", "cpus"), f"{p_end}-{total - 1}\n")
    write(os.path.join(sys_root, "devices", "system", "node", "node0", "cpulist"),
          f"0-{total - 1}\n")
    for cpu in range(total):
        base = os.path.join(sys_root, "devices", "system", "cpu", f"cpu{cpu}")
        if cpu < p_end:
            core_id = cpu // 2
            siblings = f"{(cpu // 2) * 2}-{(cpu // 2) * 2 + 1}"
            freq = freq_p
        else:
            core_id = p_end // 2 + (cpu - p_end)
            siblings = str(cpu)
            freq = freq_e
        write(os.path.join(base, "topology", "core_id"), f"{core_id}\n")
        write(os.path.join(base, "topology", "physical_package_id"), "0\n")
        write(os.path.join(base, "topology", "thread_siblings_list"), f"{siblings}\n")
        if with_freq:
            write(os.path.join(base, "cpufreq", "cpuinfo_max_freq"), f"{freq}\n")


def build_freq_tree(sys_root: str, freqs: dict[int, int],
                    cores: dict[int, int], *, smt: dict[int, str] | None = None,
                    with_freq: bool = True) -> None:
    """Tree without cpu_core/cpu_atom: P/E must come from frequency classes."""
    last = max(freqs)
    write(os.path.join(sys_root, "devices", "system", "cpu", "online"), f"0-{last}\n")
    for cpu, freq in freqs.items():
        base = os.path.join(sys_root, "devices", "system", "cpu", f"cpu{cpu}")
        write(os.path.join(base, "topology", "core_id"), f"{cores[cpu]}\n")
        write(os.path.join(base, "topology", "physical_package_id"), "0\n")
        sibs = (smt or {}).get(cpu, str(cpu))
        write(os.path.join(base, "topology", "thread_siblings_list"), f"{sibs}\n")
        if with_freq:
            write(os.path.join(base, "cpufreq", "cpuinfo_max_freq"), f"{freq}\n")


def build_cpuinfo(proc_root: str, count: int, *, vendor: str = "GenuineIntel") -> None:
    blocks = []
    for i in range(count):
        blocks.append(
            f"processor\t: {i}\n"
            f"vendor_id\t: {vendor}\n"
            "cpu family\t: 6\n"
            "model name\t: Test CPU @ synthetic\n"
            f"physical id\t: 0\n"
            f"siblings\t: {count}\n"
            f"core id\t\t: {i // 2}\n"
            f"cpu cores\t: {count // 2}\n"
        )
    write(os.path.join(proc_root, "cpuinfo"), "\n".join(blocks))


LSCPU_TABLE = (
    "CPU CORE SOCKET NODE    MAXMHZ ONLINE\n"
    "  0    0      0    0 3600.0000    yes\n"
    "  1    0      0    0 3600.0000    yes\n"
    "  2    1      0    0 3600.0000    yes\n"
    "  3    1      0    0 3600.0000    yes\n"
    "  4    2      0    0 2400.0000    yes\n"
    "  5    2      0    0 2400.0000    yes\n"
)

LSCPU_KV = (
    "Architecture:                    x86_64\n"
    "CPU(s):                          6\n"
    "On-line CPU(s) list:             0-5\n"
    "Vendor ID:                       AuthenticAMD\n"
    "Model name:                      Synthetic Ryzen\n"
    "Thread(s) per core:              1\n"
    "Core(s) per socket:              6\n"
    "Socket(s):                       1\n"
    "NUMA node(s):                    2\n"
)


class TreeTest(unittest.TestCase):
    """Base class owning the temporary sys/proc roots."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="macopt-hostinfo-")
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.sys_root = os.path.join(self.root, "sys")
        self.proc_root = os.path.join(self.root, "proc")
        os.makedirs(self.sys_root, exist_ok=True)
        os.makedirs(self.proc_root, exist_ok=True)


# --------------------------------------------------------------------------- #
# L1 / L2 P/E probing
# --------------------------------------------------------------------------- #


class TestL1Hybrid(TreeTest):
    def test_l1_gives_p_and_e_sets(self) -> None:
        build_hybrid_tree(self.sys_root)
        build_cpuinfo(self.proc_root, 16)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=exploding_runner
        )
        self.assertEqual(topo["p_cpus"], tuple(range(12)))
        self.assertEqual(topo["e_cpus"], (12, 13, 14, 15))
        self.assertTrue(topo["hybrid"])
        self.assertEqual(topo["p_e_source"], "L1")
        self.assertEqual(topo["count_source"], "sysfs")
        self.assertEqual(topo["logical_cpus"], 16)
        self.assertEqual(topo["physical_cores"], 10)  # 6 SMT P cores + 4 E cores
        self.assertEqual(topo["sockets"], 1)
        self.assertEqual(topo["numa_nodes"], 1)
        self.assertEqual(topo["freq_mhz_p"], 4900)
        self.assertEqual(topo["freq_mhz_e"], 3600)
        self.assertEqual(topo["vendor"], "GenuineIntel")
        # every physical core grouped its two threads together (P) or itself
        self.assertEqual(len(topo["core_groups"]), 10)
        self.assertIn((0, 1), topo["core_groups"])
        self.assertIn((12,), topo["core_groups"])

    def test_l1_missing_files_degrade_without_guessing(self) -> None:
        build_freq_tree(
            self.sys_root,
            {0: 2000000, 1: 2000000, 2: 2000000, 3: 2000000},
            {0: 0, 1: 0, 2: 1, 3: 1},
            with_freq=False,  # no cpufreq either -> nothing to classify
        )
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=FakeRunner()
        )
        # no cpu_core/cpu_atom and no frequency data => no P/E ids at all
        self.assertEqual(topo["p_cpus"], ())
        self.assertEqual(topo["e_cpus"], ())
        self.assertIsNone(topo["p_e_source"])

    def test_l1_unparseable_values_are_ignored(self) -> None:
        build_hybrid_tree(self.sys_root, with_freq=False)
        write(os.path.join(self.sys_root, "devices", "cpu_core", "cpus"), "garbage,,\n")
        build_cpuinfo(self.proc_root, 16)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=FakeRunner()
        )
        self.assertEqual(topo["p_cpus"], ())
        self.assertEqual(topo["e_cpus"], ())
        self.assertIsNone(topo["p_e_source"])


class TestL2FrequencySplit(TreeTest):
    def test_l2_splits_on_frequency_classes(self) -> None:
        freqs = {0: 3000000, 1: 3000000, 2: 3000000, 3: 3000000,
                 4: 1800000, 5: 1800000, 6: 1800000, 7: 1800000}
        cores = {0: 0, 1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3, 7: 3}
        smt = {0: "0-1", 1: "0-1", 2: "2-3", 3: "2-3",
               4: "4-5", 5: "4-5", 6: "6-7", 7: "6-7"}
        build_freq_tree(self.sys_root, freqs, cores, smt=smt)
        build_cpuinfo(self.proc_root, 8)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=exploding_runner
        )
        self.assertEqual(topo["p_cpus"], (0, 1, 2, 3))
        self.assertEqual(topo["e_cpus"], (4, 5, 6, 7))
        self.assertEqual(topo["p_e_source"], "L2")
        self.assertTrue(topo["hybrid"])
        self.assertEqual(topo["physical_cores"], 4)
        self.assertEqual(topo["freq_mhz_p"], 3000)
        self.assertEqual(topo["freq_mhz_e"], 1800)

    def test_l2_uniform_frequency_means_homogeneous(self) -> None:
        freqs = {i: 2400000 for i in range(4)}
        cores = {0: 0, 1: 0, 2: 1, 3: 1}
        build_freq_tree(self.sys_root, freqs, cores)
        build_cpuinfo(self.proc_root, 4)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=exploding_runner
        )
        self.assertEqual(topo["p_cpus"], ())
        self.assertEqual(topo["e_cpus"], ())
        self.assertFalse(topo["hybrid"])
        self.assertTrue(any("homogeneous" in note for note in topo["notes"]))

    def test_l2_ambiguous_gap_does_not_guess(self) -> None:
        # 2000 vs 2150 MHz: two clusters, but the gap (7.5 %) is < 10 % — too
        # close to call one of them an efficiency class.
        freqs = {0: 2000000, 1: 2000000, 2: 2150000, 3: 2150000}
        cores = {0: 0, 1: 1, 2: 2, 3: 3}
        build_freq_tree(self.sys_root, freqs, cores)
        build_cpuinfo(self.proc_root, 4)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=FakeRunner()
        )
        self.assertEqual(topo["p_cpus"], ())
        self.assertEqual(topo["e_cpus"], ())
        self.assertIsNone(topo["p_e_source"])
        self.assertTrue(any("ambiguous" in note for note in topo["notes"]))


# --------------------------------------------------------------------------- #
# L3 / L4 count fallbacks
# --------------------------------------------------------------------------- #


class TestL3L4Fallback(TreeTest):
    def test_l3_cpuinfo_counts_when_sysfs_absent(self) -> None:
        build_cpuinfo(self.proc_root, 16)
        runner = FakeRunner()  # lscpu answers "not available" (rc=1)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=runner
        )
        self.assertEqual(topo["count_source"], "cpuinfo")
        self.assertEqual(topo["logical_cpus"], 16)
        self.assertEqual(topo["physical_cores"], 8)  # 16 logical / 2 threads
        self.assertEqual(topo["sockets"], 1)
        self.assertEqual(topo["vendor"], "GenuineIntel")
        # no P/E ids anywhere -> degrade instead of guessing
        self.assertEqual(topo["p_cpus"], ())
        self.assertEqual(topo["e_cpus"], ())

    def test_l4_lscpu_table_fallback(self) -> None:
        runner = FakeRunner(table=LSCPU_TABLE)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=runner
        )
        self.assertEqual(topo["count_source"], "lscpu")
        self.assertEqual(topo["logical_cpus"], 6)
        self.assertEqual(topo["physical_cores"], 3)
        self.assertEqual(topo["sockets"], 1)
        self.assertEqual(topo["numa_nodes"], 1)
        # MAXMHZ split: 3600 (P) vs 2400 (E)
        self.assertEqual(topo["p_cpus"], (0, 1, 2, 3))
        self.assertEqual(topo["e_cpus"], (4, 5))
        self.assertEqual(topo["p_e_source"], "lscpu")
        self.assertEqual(topo["freq_mhz_p"], 3600)
        self.assertEqual(topo["freq_mhz_e"], 2400)
        # lscpu was called as an argv list, never through a shell
        self.assertTrue(all(isinstance(call, list) for call in runner.calls))
        self.assertEqual(runner.calls[0][0], "lscpu")
        self.assertTrue(runner.calls[0][1].startswith("-e"))

    def test_l4_lscpu_key_value_fallback(self) -> None:
        runner = FakeRunner(kv=LSCPU_KV)
        topo = hostinfo.detect_cpu_topology(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=runner
        )
        self.assertEqual(topo["count_source"], "lscpu")
        self.assertEqual(topo["logical_cpus"], 6)
        self.assertEqual(topo["physical_cores"], 6)
        self.assertEqual(topo["numa_nodes"], 2)
        self.assertEqual(topo["vendor"], "AuthenticAMD")
        self.assertEqual(topo["brand"], "Synthetic Ryzen")
        # extended table offered no frequencies -> no P/E, still no guessing
        self.assertEqual(topo["p_cpus"], ())
        self.assertEqual(topo["e_cpus"], ())
        self.assertEqual(len(runner.calls), 2)


# --------------------------------------------------------------------------- #
# cgroup / vmware / tsc / detect()
# --------------------------------------------------------------------------- #


class TestCgroup(TreeTest):
    def test_user_cpuset_not_delegated(self) -> None:
        root = os.path.join(self.sys_root, "fs", "cgroup")
        write(os.path.join(root, "cgroup.controllers"), "cpuset cpu io memory pids\n")
        write(os.path.join(root, "cgroup.subtree_control"), "cpu memory pids\n")
        unit = os.path.join(root, "user.slice", "user-1000.slice", "user@1000.service")
        write(os.path.join(unit, "cgroup.controllers"), "cpu memory pids\n")
        write(os.path.join(unit, "cgroup.subtree_control"), "cpu memory pids\n")
        info = hostinfo.detect_cgroup(sys_root=self.sys_root)
        self.assertEqual(info["version"], 2)
        self.assertTrue(info["unified"])
        self.assertFalse(info["root_cpuset_enabled"])
        self.assertIsNotNone(info["user_unit"])
        self.assertFalse(info["user_cpuset_delegated"])

    def test_user_cpuset_delegated(self) -> None:
        root = os.path.join(self.sys_root, "fs", "cgroup")
        write(os.path.join(root, "cgroup.controllers"), "cpuset cpu memory pids\n")
        write(os.path.join(root, "cgroup.subtree_control"), "cpuset cpu memory pids\n")
        unit = os.path.join(root, "user.slice", "user-1000.slice", "user@1000.service")
        write(os.path.join(unit, "cgroup.controllers"), "cpuset cpu memory pids\n")
        info = hostinfo.detect_cgroup(sys_root=self.sys_root)
        self.assertTrue(info["root_cpuset_enabled"])
        self.assertTrue(info["user_cpuset_delegated"])

    def test_absent_files_report_unknown(self) -> None:
        info = hostinfo.detect_cgroup(sys_root=self.sys_root)
        self.assertIsNone(info["version"])
        self.assertFalse(info["unified"])
        self.assertIsNone(info["user_unit"])
        self.assertIsNone(info["user_cpuset_delegated"])


class TestVmwareAndTsc(unittest.TestCase):
    def test_version_and_build_parsed(self) -> None:
        runner = FakeRunner(version="VMware Workstation 26.0.1 25688693\n")
        self.assertEqual(
            hostinfo.detect_vmware(runner=runner),
            {"version": "26.0.1", "build": "25688693"},
        )
        self.assertIsInstance(runner.calls[0], list)
        self.assertEqual(runner.calls[0][0], "vmware")
        self.assertIn("--version", runner.calls[0])

    def test_failure_returns_empty_dict(self) -> None:
        self.assertEqual(hostinfo.detect_vmware(runner=FakeRunner()), {})
        self.assertEqual(hostinfo.detect_vmware(runner=FakeRunner(rc=1)), {})

    def test_missing_binary_never_raises(self) -> None:
        def missing(argv, **kwargs):  # noqa: ANN001
            raise FileNotFoundError("vmware")

        self.assertEqual(hostinfo.detect_vmware(runner=missing), {})

    def test_tsc_from_sysfs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macopt-tsc-") as tmp:
            path = os.path.join(tmp, "devices", "system", "cpu", "cpu0", "tsc_freq_khz")
            write(path, "2918400\n")
            self.assertEqual(hostinfo.detect_tsc(sys_root=tmp), 2_918_400_000)

    def test_tsc_absent_or_implausible_is_none(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macopt-tsc-") as tmp:
            self.assertIsNone(hostinfo.detect_tsc(sys_root=tmp))
            path = os.path.join(tmp, "devices", "system", "cpu", "cpu0", "tsc_freq_khz")
            write(path, "5\n")  # 5 kHz is not a TSC
            self.assertIsNone(hostinfo.detect_tsc(sys_root=tmp))
            write(path, "not-a-number\n")
            self.assertIsNone(hostinfo.detect_tsc(sys_root=tmp))


class TestDetect(TreeTest):
    def test_one_shot_detection(self) -> None:
        build_hybrid_tree(self.sys_root)
        build_cpuinfo(self.proc_root, 16)
        write(os.path.join(self.proc_root, "version"),
              "Linux version 6.8.0-test (builder@host) gcc 13\n")
        # cpuset present at the root but NOT delegated to user@.service
        cgroup_root = os.path.join(self.sys_root, "fs", "cgroup")
        write(os.path.join(cgroup_root, "cgroup.controllers"), "cpuset cpu memory pids\n")
        write(os.path.join(cgroup_root, "cgroup.subtree_control"), "cpu memory pids\n")
        unit = os.path.join(cgroup_root, "user.slice", "user-1000.slice", "user@1000.service")
        write(os.path.join(unit, "cgroup.controllers"), "cpu memory pids\n")
        runner = FakeRunner(version="VMware Workstation 26.0.1 25688693\n")
        info = hostinfo.detect(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=runner
        )
        self.assertEqual(info.vendor, "GenuineIntel")
        self.assertEqual(info.logical_cpus, 16)
        self.assertEqual(info.physical_cores, 10)
        self.assertEqual(info.numa_nodes, 1)
        self.assertTrue(info.hybrid)
        self.assertEqual(info.p_cpus, tuple(range(12)))
        self.assertEqual(info.e_cpus, (12, 13, 14, 15))
        self.assertEqual(info.freq_mhz_p, 4900)
        self.assertEqual(info.freq_mhz_e, 3600)
        self.assertEqual(info.kernel, "6.8.0-test")
        self.assertEqual(info.vmware_version, "26.0.1")
        self.assertEqual(info.vmware_build, "25688693")
        # not this module's job — left for unlocker.py / doctor.py
        self.assertIsNone(info.unlocker_state)
        self.assertIsNone(info.systemd_version)
        self.assertIsNone(info.vmware_build_tag)
        # undelegated cpuset must be called out in the notes (03 report:223)
        self.assertTrue(any("AllowedCPUs" in note for note in info.notes))
        self.assertFalse(info.user_cpuset_delegated)

    def test_detect_degrades_on_empty_tree(self) -> None:
        runner = FakeRunner()  # nothing answers anywhere
        info = hostinfo.detect(
            sys_root=self.sys_root, proc_root=self.proc_root, runner=runner
        )
        self.assertEqual(info.logical_cpus, 0)
        self.assertEqual(info.p_cpus, ())
        self.assertFalse(info.hybrid)
        self.assertIsNone(info.tsc_hz)
        self.assertIsNone(info.vmware_version)


class TestRealMachineSmoke(unittest.TestCase):
    """Cheap invariants on the live host (Linux only, read-only)."""

    @unittest.skipUnless(os.path.isdir("/sys/devices/system/cpu"), "not a sysfs host")
    def test_real_detection_is_sane(self) -> None:
        info = hostinfo.detect()
        self.assertGreaterEqual(info.logical_cpus, 1)
        self.assertGreaterEqual(info.physical_cores, 1)
        self.assertGreaterEqual(info.numa_nodes, 1)
        if info.hybrid:
            self.assertTrue(set(info.p_cpus) and set(info.e_cpus))
            self.assertEqual(
                sorted(set(info.p_cpus) | set(info.e_cpus)), list(range(info.logical_cpus))
            )
        if info.tsc_hz is not None:
            self.assertGreater(info.tsc_hz, 10**8)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

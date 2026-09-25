"""Unit tests for the host-side ``schedule`` module (DESIGN §4.7).

Covers CPU list parsing/formatting, profile → CPU set resolution, the three
ordered binding paths (system-level ``systemd-run`` first), ``bind()`` with an
injected runner (no shell, no real process ever touched) and ``check()``
against a fake ``/proc/<pid>/status`` tree.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest

from macopt.model import HostInfo
from macopt.profiles import schedule

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


def write_status(proc_root: str, pid: int, allowed_list: str, name: str = "vmware-vmx") -> None:
    d = os.path.join(proc_root, str(pid))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "status"), "w", encoding="utf-8") as fh:
        fh.write(
            f"Name:\t{name}\n"
            "Umask:\t0022\n"
            "State:\tS (sleeping)\n"
            "Cpus_allowed:\t0000ffff\n"
            f"Cpus_allowed_list:\t{allowed_list}\n"
        )


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Records every invocation; optionally raises to simulate a missing binary."""

    def __init__(self, result=None, raise_exc=None):
        self.calls: list[tuple] = []
        self.result = result if result is not None else FakeResult(0, "pid 4242's current affinity list: 0-11\n")
        self.raise_exc = raise_exc

    def __call__(self, argv, **kwargs):
        self.calls.append((tuple(argv), kwargs))
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.result


class ParseAllowedListTest(unittest.TestCase):
    def test_range_and_single(self) -> None:
        self.assertEqual(schedule.parse_allowed_list("0-11,14"), set(range(12)) | {14})

    def test_whitespace_is_tolerated(self) -> None:
        self.assertEqual(schedule.parse_allowed_list(" 0-2 , 5 "), {0, 1, 2, 5})

    def test_single_id(self) -> None:
        self.assertEqual(schedule.parse_allowed_list("7"), {7})

    def test_empty_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("")

    def test_whitespace_only_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("   ")

    def test_non_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list(None)  # type: ignore[arg-type]

    def test_letters_raise(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("a")

    def test_descending_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("8-3")

    def test_open_ended_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("8-")

    def test_double_comma_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("1,,2")

    def test_trailing_comma_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("1,")

    def test_negative_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("-1")

    def test_non_ascii_digits_raise(self) -> None:
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("١٢")  # Arabic-Indic digits

    def test_partial_acceptance_never_happens(self) -> None:
        # "1,x" must raise, not silently return {1}.
        with self.assertRaises(ValueError):
            schedule.parse_allowed_list("1,x")


class FormatAllowedListTest(unittest.TestCase):
    def test_collapses_ranges(self) -> None:
        self.assertEqual(schedule.format_allowed_list(range(12)), "0-11")

    def test_mixed_ids(self) -> None:
        self.assertEqual(schedule.format_allowed_list({14, 0, 1, 2, 3, 15}), "0-3,14-15")

    def test_round_trip(self) -> None:
        for spec in ("0-11,14", "0", "3,5,7", "0-15"):
            with self.subTest(spec=spec):
                parsed = schedule.parse_allowed_list(spec)
                self.assertEqual(
                    schedule.parse_allowed_list(schedule.format_allowed_list(parsed)), parsed
                )

    def test_empty_iterable_gives_empty_string(self) -> None:
        self.assertEqual(schedule.format_allowed_list([]), "")

    def test_duplicates_and_unsorted_are_normalized(self) -> None:
        self.assertEqual(schedule.format_allowed_list([5, 3, 5, 4]), "3-5")

    def test_negative_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.format_allowed_list([-1])

    def test_bool_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.format_allowed_list([True])


class ResolveCpusTest(unittest.TestCase):
    def test_performance_and_balanced_use_p_cores(self) -> None:
        for profile in ("performance", "balanced"):
            with self.subTest(profile=profile):
                self.assertEqual(
                    schedule.resolve_cpus(REFERENCE_HOST, profile), "0-11"
                )

    def test_throughput_uses_all_logical_cores(self) -> None:
        self.assertEqual(schedule.resolve_cpus(REFERENCE_HOST, "throughput"), "0-15")

    def test_passthrough_resolves_to_none(self) -> None:
        self.assertIsNone(schedule.resolve_cpus(REFERENCE_HOST, "passthrough"))

    def test_explicit_cpus_win(self) -> None:
        self.assertEqual(
            schedule.resolve_cpus(REFERENCE_HOST, "performance", cpus="4-7"), "4-7"
        )

    def test_unknown_profile_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.resolve_cpus(REFERENCE_HOST, "turbo")

    def test_malformed_explicit_cpus_raise(self) -> None:
        with self.assertRaises(ValueError):
            schedule.resolve_cpus(REFERENCE_HOST, "performance", cpus="8-3")

    def test_unknown_topology_degrades_to_none(self) -> None:
        # Never guess: no P/E sets, no logical count -> no binding.
        self.assertIsNone(schedule.resolve_cpus(HostInfo(), "performance"))

    def test_empty_explicit_cpus_falls_through_to_profile(self) -> None:
        self.assertEqual(schedule.resolve_cpus(REFERENCE_HOST, "balanced", cpus="  "), "0-11")

    def test_throughput_without_p_e_uses_logical_count(self) -> None:
        host = HostInfo(logical_cpus=4, physical_cores=2)
        self.assertEqual(schedule.resolve_cpus(host, "throughput"), "0-3")


class PlanTest(unittest.TestCase):
    def test_returns_three_paths(self) -> None:
        self.assertEqual(len(schedule.plan(REFERENCE_HOST, "performance")), 3)

    def test_first_path_is_system_scope_without_user_flag(self) -> None:
        first = schedule.plan(REFERENCE_HOST, "performance")[0]
        self.assertNotIn("--user", first["command"])
        self.assertEqual(first["command"][0], "systemd-run")
        self.assertIn("-p", first["command"])
        self.assertIn("AllowedCPUs=0-11", first["command"])
        self.assertTrue(first["needs_root"])

    def test_order_is_system_then_taskset_then_desktop(self) -> None:
        labels = [p["label"] for p in schedule.plan(REFERENCE_HOST, "performance")]
        self.assertIn("systemd-run", labels[0])
        self.assertIn("taskset", labels[1])
        self.assertIn(".desktop", labels[2])

    def test_every_entry_has_the_contract_keys(self) -> None:
        expected = {"label", "command", "needs_root", "durability", "note"}
        for entry in schedule.plan(REFERENCE_HOST, "balanced"):
            with self.subTest(label=entry["label"]):
                self.assertEqual(set(entry), expected)
                self.assertIsInstance(entry["command"], list)
                self.assertTrue(all(isinstance(x, str) for x in entry["command"]))

    def test_notes_mention_the_measured_traps(self) -> None:
        entries = schedule.plan(REFERENCE_HOST, "performance")
        notes = " ".join(e["note"] for e in entries)
        self.assertIn("systemd-run --user", notes)  # silent no-op warning
        self.assertIn("Cpus_allowed_list", notes)  # the only trustworthy check
        self.assertIn("EffectiveCPUs", notes)  # measured empty on reference host

    def test_notes_carry_concrete_sources(self) -> None:
        notes = " ".join(e["note"] for e in schedule.plan(REFERENCE_HOST, "performance"))
        self.assertIn("docs/DESIGN.md:323", notes)
        self.assertIn("docs/DESIGN.md:324", notes)

    def test_persistent_entry_has_persistent_durability(self) -> None:
        entries = schedule.plan(REFERENCE_HOST, "balanced")
        self.assertEqual(entries[0]["durability"], schedule.DURABILITY_PROCESS)
        self.assertEqual(entries[2]["durability"], schedule.DURABILITY_PERSISTENT)

    def test_unprivileged_entries_do_not_need_root(self) -> None:
        entries = schedule.plan(REFERENCE_HOST, "balanced")
        self.assertFalse(entries[1]["needs_root"])
        self.assertFalse(entries[2]["needs_root"])

    def test_explicit_cpus_are_used(self) -> None:
        entries = schedule.plan(REFERENCE_HOST, "performance", cpus="0-7")
        self.assertIn("AllowedCPUs=0-7", entries[0]["command"])
        self.assertIn("0-7", entries[1]["command"])

    def test_passthrough_gives_empty_plan(self) -> None:
        self.assertEqual(schedule.plan(REFERENCE_HOST, "passthrough"), [])

    def test_unknown_topology_gives_empty_plan(self) -> None:
        self.assertEqual(schedule.plan(HostInfo(), "performance"), [])

    def test_unknown_profile_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule.plan(REFERENCE_HOST, "gaming")

    def test_desktop_note_mentions_the_copy_path(self) -> None:
        entries = schedule.plan(REFERENCE_HOST, "balanced")
        self.assertIn("vmware-workstation.desktop", entries[2]["note"])

    def test_launcher_constant_is_the_measured_path(self) -> None:
        self.assertEqual(schedule.VMWARE_LAUNCHER, "/usr/bin/vmware")


class BindTest(unittest.TestCase):
    def test_command_is_argv_list_without_shell(self) -> None:
        runner = FakeRunner()
        schedule.bind(4242, "0-11", runner=runner)
        argv, kwargs = runner.calls[0]
        self.assertIsInstance(argv, tuple)  # recorded from a list argument
        self.assertEqual(list(argv), ["taskset", "-pc", "0-11", "4242"])
        self.assertTrue(kwargs.get("capture_output"))
        self.assertFalse(kwargs.get("shell", False))
        self.assertNotIn("shell", kwargs)

    def test_report_carries_rc_stdout_and_err(self) -> None:
        runner = FakeRunner(FakeResult(0, "ok\n", ""))
        report = schedule.bind(4242, "0-11", runner=runner)
        self.assertEqual(report["rc"], 0)
        self.assertEqual(report["stdout"], "ok\n")
        self.assertEqual(report["err"], "")
        self.assertTrue(report["ok"])
        self.assertEqual(report["pid"], 4242)
        self.assertEqual(report["cpus"], "0-11")

    def test_failure_is_reported_not_raised(self) -> None:
        report = schedule.bind(4242, "0-11", runner=FakeRunner(FakeResult(1, "", "bad mask\n")))
        self.assertEqual(report["rc"], 1)
        self.assertEqual(report["err"], "bad mask\n")
        self.assertFalse(report["ok"])

    def test_missing_binary_gives_rc_127(self) -> None:
        report = schedule.bind(4242, "0-11", runner=FakeRunner(raise_exc=FileNotFoundError()))
        self.assertEqual(report["rc"], 127)
        self.assertIn("not found", report["err"])
        self.assertFalse(report["ok"])

    def test_os_error_gives_rc_126(self) -> None:
        report = schedule.bind(4242, "0-11", runner=FakeRunner(raise_exc=OSError("boom")))
        self.assertEqual(report["rc"], 126)
        self.assertIn("boom", report["err"])

    def test_bytes_output_is_decoded(self) -> None:
        report = schedule.bind(4242, "0-11", runner=FakeRunner(FakeResult(0, b"hi\n", b"warn\n")))
        self.assertEqual(report["stdout"], "hi\n")
        self.assertEqual(report["err"], "warn\n")

    def test_invalid_pid_raises_before_running(self) -> None:
        runner = FakeRunner()
        for pid in (0, -1, True, "4242"):
            with self.subTest(pid=pid):
                with self.assertRaises(ValueError):
                    schedule.bind(pid, "0-11", runner=runner)  # type: ignore[arg-type]
        self.assertEqual(runner.calls, [])

    def test_invalid_cpus_raise_before_running(self) -> None:
        runner = FakeRunner()
        with self.assertRaises(ValueError):
            schedule.bind(4242, "8-3", runner=runner)
        self.assertEqual(runner.calls, [])

    def test_default_runner_is_subprocess_run(self) -> None:
        self.assertIs(schedule.bind.__kwdefaults__["runner"], subprocess.run)


class CheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = self.tmp.name

    def test_reads_allowed_list(self) -> None:
        write_status(self.proc, 4242, "0-11")
        report = schedule.check(4242, proc_root=self.proc)
        self.assertTrue(report["found"])
        self.assertEqual(report["name"], "vmware-vmx")
        self.assertEqual(report["allowed_list"], "0-11")
        self.assertEqual(report["allowed"], list(range(12)))
        self.assertIsNone(report["error"])

    def test_scattered_list_is_expanded(self) -> None:
        write_status(self.proc, 7, "0,2,4-6")
        report = schedule.check(7, proc_root=self.proc)
        self.assertEqual(report["allowed"], [0, 2, 4, 5, 6])

    def test_missing_process_is_reported_not_raised(self) -> None:
        report = schedule.check(999999, proc_root=self.proc)
        self.assertFalse(report["found"])
        self.assertIsNone(report["allowed"])
        self.assertIsNotNone(report["error"])

    def test_status_without_allowed_list_is_reported(self) -> None:
        d = os.path.join(self.proc, "5")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "status"), "w", encoding="utf-8") as fh:
            fh.write("Name:\tvmware-vmx\n")
        report = schedule.check(5, proc_root=self.proc)
        self.assertTrue(report["found"])
        self.assertIsNone(report["allowed"])
        self.assertIn("missing", report["error"])

    def test_every_branch_returns_the_same_keys(self) -> None:
        expected = {"pid", "path", "found", "name", "allowed_list", "allowed", "error"}
        write_status(self.proc, 1, "0")
        for report in (
            schedule.check(1, proc_root=self.proc),
            schedule.check(2, proc_root=self.proc),
        ):
            self.assertEqual(set(report), expected)

    def test_path_points_into_the_given_proc_root(self) -> None:
        write_status(self.proc, 3, "0")
        report = schedule.check(3, proc_root=self.proc)
        self.assertEqual(report["path"], os.path.join(self.proc, "3", "status"))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for ``macopt.verify.report`` (text table, §5.2 JSON, §6 exit)."""

from __future__ import annotations

import json
import re
import unittest
from datetime import UTC, datetime
from pathlib import Path

from macopt.context import Context
from macopt.errors import EXIT_FAIL, EXIT_OK
from macopt.model import FAIL, PASS, SKIP, WARN, CheckResult, Evidence
from macopt.verify.assertions import CHECKS, run
from macopt.verify.parser import parse_log, parse_log_path
from macopt.verify.report import exit_code, render_text, to_json

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "verify"
FULL = FIXTURES / "full.log"

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

EVIDENCE = (Evidence(kind="log", source="vmware.log:51", note="guest leaf 1 ECX"),)


def res(
    vid: str,
    status: str,
    detail: str = "",
    title: str = "",
    evidence: tuple[Evidence, ...] = (),
) -> CheckResult:
    return CheckResult(id=vid, title=title or vid, status=status, detail=detail, evidence=evidence)


def full_run() -> list[CheckResult]:
    facts = parse_log_path(FULL)
    return run(facts, {"numvcpus": "12", "guestOS": "darwin24-64"},
               vmx_mtime=1000.0, log_mtime=2000.0)


# --------------------------------------------------------------------------- #
# exit_code (DESIGN §6)
# --------------------------------------------------------------------------- #

class ExitCodeTest(unittest.TestCase):
    def test_no_failures_is_zero(self) -> None:
        results = [res("V0", PASS), res("V1", PASS), res("V2", SKIP)]
        self.assertEqual(exit_code(results), EXIT_OK)
        self.assertEqual(exit_code(results, strict=True), EXIT_OK)

    def test_fail_is_one(self) -> None:
        results = [res("V0", PASS), res("V1", FAIL)]
        self.assertEqual(exit_code(results), EXIT_FAIL)
        self.assertEqual(exit_code(results, strict=True), EXIT_FAIL)

    def test_warn_is_zero_unless_strict(self) -> None:
        results = [res("V0", PASS), res("V1", WARN)]
        self.assertEqual(exit_code(results), EXIT_OK)
        self.assertEqual(exit_code(results, strict=True), EXIT_FAIL)

    def test_skip_only_is_zero(self) -> None:
        self.assertEqual(exit_code([res("V1", SKIP)]), EXIT_OK)

    def test_empty_results_is_zero(self) -> None:
        self.assertEqual(exit_code([]), EXIT_OK)

    def test_fail_position_does_not_matter(self) -> None:
        first = [res("V0", FAIL), res("V1", PASS)]
        last = [res("V0", PASS), res("V1", FAIL)]
        self.assertEqual(exit_code(first), EXIT_FAIL)
        self.assertEqual(exit_code(last), EXIT_FAIL)


# --------------------------------------------------------------------------- #
# render_text
# --------------------------------------------------------------------------- #

class RenderTextTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.results = full_run()
        cls.text = render_text(cls.results)

    def test_header_and_column_row(self) -> None:
        lines = self.text.splitlines()
        self.assertTrue(lines[0].startswith("macopt verify"))
        self.assertIn("STATUS", lines[1])
        self.assertIn("ID", lines[1])
        self.assertIn("CHECK", lines[1])
        self.assertIn("DETAIL", lines[1])

    def test_every_check_appears_exactly_once(self) -> None:
        for vid, title in CHECKS:
            rows = [row for row in self.text.splitlines() if re.search(rf"\b{vid}\b", row)]
            self.assertGreaterEqual(len(rows), 1, vid)
            self.assertTrue(any(title in row for row in rows), f"{vid} title missing")

    def test_summary_reports_counts_and_exit(self) -> None:
        summary = self.text.splitlines()[-1]
        counts = {s: sum(1 for r in self.results if r.status == s)
                  for s in (PASS, WARN, FAIL, SKIP)}
        self.assertIn(f"result: {counts[PASS]} pass", summary)
        self.assertIn(f"{counts[WARN]} warn", summary)
        self.assertIn(f"{counts[FAIL]} fail", summary)
        self.assertIn(f"{counts[SKIP]} skip", summary)
        self.assertIn(f"exit {exit_code(self.results)}", summary)

    def test_warn_hint_only_when_warnings_present(self) -> None:
        warned = render_text([res("V0", PASS), res("V1", WARN)])
        self.assertIn("--strict", warned.splitlines()[-1])
        clean = render_text([res("V0", PASS), res("V1", SKIP)])
        self.assertNotIn("--strict", clean.splitlines()[-1])

    def test_long_details_wrap_without_losing_text(self) -> None:
        detail = "word " * 60  # 300 chars -> several wrapped rows
        text = render_text([res("V0", PASS, detail=detail)])
        body = text.splitlines()
        self.assertGreater(len(body), 4)
        joined = " ".join(row.strip() for row in body[2:-2])
        for word in ("word",) * 60:
            self.assertIn(word, joined)
        self.assertTrue(all(len(row) <= 160 for row in body), "over-wide row")

    def test_evidence_hidden_by_default(self) -> None:
        text = render_text([res("V0", PASS, detail="d", evidence=EVIDENCE)])
        self.assertNotIn("evidence:", text)

    def test_verbose_context_shows_evidence(self) -> None:
        ctx = Context(verbose=1)
        text = render_text([res("V0", PASS, detail="d", evidence=EVIDENCE)], ctx)
        self.assertIn("evidence: [log] vmware.log:51 — guest leaf 1 ECX", text)

    def test_quiet_context_hides_evidence(self) -> None:
        ctx = Context(verbose=0)
        text = render_text([res("V0", PASS, detail="d", evidence=EVIDENCE)], ctx)
        self.assertNotIn("evidence:", text)

    def test_empty_results_render(self) -> None:
        text = render_text([])
        self.assertIn("0 pass", text)
        self.assertIn("exit 0", text)

    def test_render_of_full_run_is_stable(self) -> None:
        self.assertEqual(self.text, render_text(self.results))


# --------------------------------------------------------------------------- #
# to_json (DESIGN §5.2 schema:1)
# --------------------------------------------------------------------------- #

def meta(**extra: object) -> dict[str, object]:
    base: dict[str, object] = {
        "vmx": "/home/<user>/vmware/<vm-name>/<vm-name>.vmx",
        "vmx_mtime": 1758000000.0,
        "log": "full.log",
        "log_mtime": 1758003600.0,
        "vmware": {"version": "26.0.1", "build": "25688693"},
        "strict": False,
    }
    base.update(extra)
    return base


class ToJsonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.results = full_run()
        cls.payload = to_json(cls.results, meta=meta())

    def test_schema_and_command(self) -> None:
        self.assertEqual(self.payload["schema"], 1)
        self.assertEqual(self.payload["command"], "verify")

    def test_provenance_fields(self) -> None:
        self.assertEqual(self.payload["vmx"], meta()["vmx"])
        self.assertEqual(self.payload["log"], "full.log")
        self.assertRegex(self.payload["vmx_mtime"], ISO_RE)
        self.assertRegex(self.payload["log_mtime"], ISO_RE)

    def test_mtimes_rendered_as_utc_iso(self) -> None:
        expected = datetime.fromtimestamp(1758000000.0, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.assertEqual(self.payload["vmx_mtime"], expected)

    def test_fresh_is_computed_when_not_supplied(self) -> None:
        self.assertIs(self.payload["fresh"], True)
        stale = to_json(self.results, meta=meta(log_mtime=1757999999.0))
        self.assertIs(stale["fresh"], False)
        explicit = to_json(self.results, meta=meta(fresh="given"))
        self.assertEqual(explicit["fresh"], "given")

    def test_vmware_block_is_merged_not_replaced(self) -> None:
        payload = to_json(self.results, meta=meta(vmware={"version": "26.0.1"}))
        self.assertEqual(payload["vmware"], {"version": "26.0.1", "build": None})

    def test_missing_meta_defaults_to_nulls(self) -> None:
        payload = to_json([], meta={})
        self.assertIsNone(payload["vmx"])
        self.assertIsNone(payload["vmx_mtime"])
        self.assertIsNone(payload["log"])
        self.assertIsNone(payload["log_mtime"])
        self.assertIsNone(payload["fresh"])
        self.assertEqual(payload["vmware"], {"version": None, "build": None})

    def test_assertions_are_computed_from_results(self) -> None:
        assertions = self.payload["assertions"]
        self.assertEqual(len(assertions), 11)
        self.assertEqual([a["id"] for a in assertions], [f"V{i}" for i in range(11)])
        self.assertEqual([a["title"] for a in assertions], [t for _, t in CHECKS])
        for a, r in zip(assertions, self.results, strict=True):
            self.assertEqual(a["status"], r.status)
            self.assertIn("detail", a)
            self.assertIsInstance(a.get("evidence", []), list)

    def test_evidence_serialised_with_kind_and_source(self) -> None:
        with_ev = [a for a in self.payload["assertions"] if a.get("evidence")]
        self.assertTrue(with_ev)
        for ev in with_ev[0]["evidence"]:
            self.assertIn("kind", ev)
            self.assertIn("source", ev)
            self.assertTrue(ev["source"])

    def test_summary_counts_match_results(self) -> None:
        summary = self.payload["summary"]
        self.assertEqual(
            set(summary), {"pass", "fail", "warn", "skip"}
        )
        self.assertEqual(sum(summary.values()), 11)
        self.assertEqual(summary["pass"], sum(1 for r in self.results if r.status == PASS))
        self.assertEqual(summary["fail"], sum(1 for r in self.results if r.status == FAIL))
        self.assertEqual(summary["warn"], sum(1 for r in self.results if r.status == WARN))
        self.assertEqual(summary["skip"], sum(1 for r in self.results if r.status == SKIP))

    def test_exit_code_is_computed_and_may_use_strict(self) -> None:
        self.assertEqual(self.payload["exit_code"], exit_code(self.results))
        results = [res("V0", WARN)]
        lax = to_json(results, meta=meta(strict=False))
        strict = to_json(results, meta=meta(strict=True))
        self.assertEqual(lax["exit_code"], EXIT_OK)
        self.assertEqual(strict["exit_code"], EXIT_FAIL)

    def test_reserved_keys_cannot_be_supplied_by_meta(self) -> None:
        payload = to_json(
            self.results,
            meta=meta(schema=99, command="wipe", assertions=[], summary={}, exit_code=42),
        )
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["command"], "verify")
        self.assertEqual(len(payload["assertions"]), 11)
        self.assertEqual(sum(payload["summary"].values()), 11)
        self.assertEqual(payload["exit_code"], exit_code(self.results))

    def test_unknown_meta_keys_pass_through(self) -> None:
        payload = to_json(self.results, meta=meta(host="example", note="n"))
        self.assertEqual(payload["host"], "example")
        self.assertEqual(payload["note"], "n")

    def test_payload_is_json_serialisable(self) -> None:
        dumped = json.dumps(self.payload)
        loaded = json.loads(dumped)
        self.assertEqual(loaded["schema"], 1)
        self.assertEqual(loaded["summary"], self.payload["summary"])
        self.assertEqual(len(loaded["assertions"]), 11)

    def test_empty_results_payload(self) -> None:
        payload = to_json([], meta={})
        self.assertEqual(payload["assertions"], [])
        self.assertEqual(payload["summary"], {"pass": 0, "fail": 0, "warn": 0, "skip": 0})
        self.assertEqual(payload["exit_code"], EXIT_OK)


# --------------------------------------------------------------------------- #
# end-to-end consistency
# --------------------------------------------------------------------------- #

class EndToEndTest(unittest.TestCase):
    def test_text_json_and_exit_code_agree(self) -> None:
        results = full_run()
        payload = to_json(results, meta=meta())
        text = render_text(results)
        self.assertIn(f"exit {payload['exit_code']}", text.splitlines()[-1])
        self.assertEqual(payload["exit_code"], exit_code(results))

    def test_minimal_log_json_reports_skips(self) -> None:
        facts = parse_log_path(FIXTURES / "minimal.log")
        results = run(facts, {"guestOS": "darwin24-64"}, vmx_mtime=1.0, log_mtime=2.0)
        payload = to_json(results, meta={"vmx": "x.vmx", "log": "minimal.log"})
        statuses = {a["id"]: a["status"] for a in payload["assertions"]}
        for i in range(1, 9):
            self.assertEqual(statuses[f"V{i}"], SKIP)
        self.assertEqual(payload["exit_code"], EXIT_OK)
        self.assertEqual(sum(payload["summary"].values()), 11)

    def test_fail_run_exits_one_in_json(self) -> None:
        facts = parse_log(FULL.read_text(encoding="utf-8"))
        results = run(facts, {"numvcpus": "8"}, vmx_mtime=2000.0, log_mtime=1000.0)
        payload = to_json(results, meta={"strict": False})
        self.assertEqual(payload["exit_code"], EXIT_FAIL)
        self.assertGreaterEqual(payload["summary"]["fail"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

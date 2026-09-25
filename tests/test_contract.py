"""Project-wide invariants that must hold no matter which module is touched.

These are cheap static checks (AST over the source tree) plus contract-layer
assertions, so they run even when optional modules are still being written.
"""

from __future__ import annotations

import ast
import importlib.util
import unittest
from pathlib import Path

from macopt import errors, model

SRC = Path(__file__).resolve().parents[1] / "src" / "macopt"

# Layering rule from docs/DESIGN.md §3.2: dependencies point downward only.
FORBIDDEN_IMPORTS = {
    "profiles": {"macopt.cli", "macopt.writer", "macopt.backup", "macopt.verify", "macopt.check"},
    "verify": {"macopt.cli", "macopt.writer", "macopt.backup", "macopt.profiles"},
}


def _module_name(path: Path) -> str:
    rel = path.relative_to(SRC.with_name("macopt"))
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(["macopt", *parts]) if parts else "macopt"


def _imported(text: str) -> set[str]:
    tree = ast.parse(text)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


class LayeringTest(unittest.TestCase):
    def test_dependencies_point_downward(self):
        violations: list[str] = []
        for path in sorted(SRC.rglob("*.py")):
            module = _module_name(path)
            top = module.split(".")[1] if module.count(".") >= 1 else None
            if top not in FORBIDDEN_IMPORTS:
                continue
            banned = FORBIDDEN_IMPORTS[top]
            for name in _imported(path.read_text(encoding="utf-8")):
                if name in banned or any(name.startswith(f"{b}.") for b in banned):
                    violations.append(f"{module} imports {name}")
        self.assertEqual(violations, [], f"layering violations: {violations}")

    def test_contract_layer_imports_nothing_from_business_modules(self):
        forbidden = {"macopt.cli", "macopt.profiles", "macopt.verify", "macopt.writer"}
        for name in ("model", "vmxfile", "errors", "context"):
            path = SRC / f"{name}.py"
            with self.subTest(module=name):
                self.assertFalse(_imported(path.read_text(encoding="utf-8")) & forbidden)


class ExitCodeContractTest(unittest.TestCase):
    def test_codes(self):
        self.assertEqual(errors.MacoptError("x").exit_code, errors.EXIT_FAIL)
        self.assertEqual(errors.UsageError("x").exit_code, errors.EXIT_USAGE)
        self.assertEqual(errors.PreconditionError("x").exit_code, errors.EXIT_PRECONDITION)
        self.assertEqual(errors.UnknownStateError("x").exit_code, errors.EXIT_UNKNOWN)
        self.assertEqual(errors.ConflictError("x").exit_code, errors.EXIT_CONFLICT)
        self.assertEqual(errors.WhitelistError("x").exit_code, errors.EXIT_REFUSED)
        self.assertEqual(errors.VerificationError("x").exit_code, errors.EXIT_FAIL)

    def test_mapping(self):
        self.assertEqual(errors.exit_code_for(errors.ConflictError("x")), errors.EXIT_CONFLICT)
        self.assertEqual(errors.exit_code_for(ValueError("x")), errors.EXIT_FAIL)

    def test_hint_is_rendered(self):
        text = str(errors.ConflictError("boom", hint="add --force"))
        self.assertIn("boom", text)
        self.assertIn("add --force", text)


class ModelContractTest(unittest.TestCase):
    def test_param_requires_known_module(self):
        with self.assertRaises(ValueError):
            model.Param(key="a", value="b", module="nope", reason="x")

    def test_param_high_risk_needs_reasoning(self):
        p = model.Param(key="a", value="b", module="topology", reason="x", risk="high")
        self.assertEqual(p.risk, model.RISK_HIGH)

    def test_remove_param_must_not_carry_a_value(self):
        with self.assertRaises(ValueError):
            model.Param(key="k", value="v", module="topology", reason="x", remove=True)
        ok = model.Param(key="k", value="", module="topology", reason="x", remove=True)
        self.assertTrue(ok.remove)

    def test_evidence_kind_is_validated(self):
        with self.assertRaises(ValueError):
            model.Evidence(kind="trust-me", source="x")

    def test_check_status_is_validated(self):
        with self.assertRaises(ValueError):
            model.CheckResult(id="V1", title="t", status="MAYBE")

    def test_plan_counts_and_blocking(self):
        plan = model.Plan(
            changes=[
                model.Change(key="a", before=None, after="1", op="added"),
                model.Change(key="b", before="1", after="2", op="modified"),
                model.Change(key="c", before="1", after="1", op="unchanged"),
                model.Change(key="d", before="1", after=None, op="removed"),
            ]
        )
        self.assertEqual(plan.counts()["unchanged"], 1)
        self.assertEqual(len(plan.effective), 3)
        self.assertFalse(plan.blocking)
        plan.errors.append("whitelist: nope")
        self.assertTrue(plan.blocking)

    def test_profile_registry_is_lazy_and_ordered(self):
        # importing the registry must not drag in individual profiles
        spec = importlib.util.find_spec("macopt.profiles")
        self.assertIsNotNone(spec)
        import macopt.profiles as registry

        self.assertEqual(
            registry.APPLY_MODULES,
            ("guestos", "topology", "timing", "gfxnet", "identity", "cpuid"),
        )
        self.assertEqual(
            set(registry._BUILDERS),
            set(registry.APPLY_MODULES),
            "every apply module needs a registered builder",
        )
        with self.assertRaises(KeyError):
            registry.get_builder("does-not-exist")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Static guard rails for the repository (run by CI).

Enforces four invariants that code review tends to miss:

1. nothing in ``src/`` may *write* into a VMware installation directory or the
   user's ``~/.vmware/`` — macopt only writes ``.vmx``, its own state dir and
   (opt-in) ``~/.vmware/preferences``. Merely *naming* a protected path while
   listing or hashing it read-only is fine and expected;
2. no network imports and no ``shell=True``;
3. no ``Param``/``Change`` may be built from a key that does not exist in
   Workstation 26.0.1 (``mks.g3d.maxTextureSize``, ``mks.enableGLRenderer``) —
   but *documenting* that they do not exist must stay legal;
4. ``from __future__ import annotations``-style typing must not hide a
   runtime import of a banned module (AST walk, not text grep).

Exit codes: 0 ok, 1 violation, 2 usage error.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "macopt"

# Keys that the v2.0 design document claimed exist; measured absent in
# VMware Workstation 26.0.1 build 25688693 (see docs/evidence/01-factcheck.md).
NONEXISTENT_KEYS = ("mks.g3d.maxTextureSize", "mks.enableGLRenderer")

PROTECTED_DIRS = ("/usr/lib/vmware", "/etc/vmware", "~/.vmware")

# Tokens that turn a path mention into an actual mutation of that path.
WRITE_TOKEN = re.compile(
    r"""(?:                     # any operation that changes bytes on disk
        \.write_text\s*\(
      | \.write_bytes\s*\(
      | \.mkdir\s*\(
      | \.makedirs\b
      | \.touch\s*\(
      | \.unlink\s*\(
      | \.rename\s*\(
      | \.chmod\s*\(
      | \.rmdir\s*\(
      | shutil\.
      | os\.(?:remove|rmdir|rename|chmod|replace)\b
      | \bopen\s*\([^)]*,\s*f?["'][wa+]
    )""",
    re.VERBOSE,
)

BANNED_IMPORTS = re.compile(
    r"^[\s]*(?:import|from)\s+(requests|httpx|urllib|socket|aiohttp|http\.client)\b", re.M
)
BANNED_SHELL = re.compile(r"shell\s*=\s*True")


def _violations_for(path: Path) -> list[str]:
    rel = path.relative_to(REPO)
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    violations: list[str] = []

    # -- 1. protected paths, only when paired with a write --------------- #
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        if WRITE_TOKEN.search(line) and any(d in line for d in PROTECTED_DIRS):
            violations.append(f"{rel}:{lineno}: writes to a protected path: {line.strip()[:100]}")
        if BANNED_SHELL.search(line):
            violations.append(f"{rel}:{lineno}: shell=True is forbidden")

    # -- 4. banned imports (AST, so comments/docstrings cannot trip it) -- #
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        violations.append(f"{rel}: cannot parse ({exc})")
        return violations

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        else:
            names = []
        for name in names:
            if BANNED_IMPORTS.match(f"from {name} "):
                violations.append(f"{rel}:{node.lineno}: network import is forbidden: {name}")

        # -- 3. a non-existent key may be *built*, never *mentioned* ------ #
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "key" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    if kw.value.value in NONEXISTENT_KEYS:
                        violations.append(
                            f"{rel}:{node.lineno}: emits a key that does not exist: {kw.value.value}"
                        )
    return violations


def main() -> int:
    if not SRC.is_dir():
        print(f"guardrails: source tree missing: {SRC}", file=sys.stderr)
        return 2

    violations: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        violations.extend(_violations_for(path))

    if violations:
        print(f"guardrails: {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("guardrails: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

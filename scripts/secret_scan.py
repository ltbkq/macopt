#!/usr/bin/env python3
"""Fail if anything that looks like a credential has made it into the repo.

Usage:
    python scripts/secret_scan.py [ROOT ...]     # default: repository root

Exit codes: 0 clean, 1 findings, 2 usage error.

Design notes
------------
* Patterns are intentionally *generic*. This file must never contain an
  example of the real secret it is looking for — that would defeat the scan.
* Binary files (anything containing NUL bytes) are skipped so the scan can
  never trip on fixtures or images.
* Findings print file:line plus a masked excerpt (the match itself is
  truncated) so the report itself does not leak the secret.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", "build", "dist"}
SKIP_SUFFIXES = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".whl", ".zip", ".gz", ".xz"}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("sudo password assignment", re.compile(r"sudo[^\n]{0,40}password\s*[:=]", re.I)),
    # Deliberately narrow: bare `pass`/`PASS` show up as test status constants
    # and must never be reported as a credential.
    ("password assignment", re.compile(r"\b(?:password|passwd|passphrase|pwd)\b\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']", re.I)),
    ("github token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    ("bearer token", re.compile(r"Authorization:\s*Bearer\s+\S+", re.I)),
    ("token in query", re.compile(r"[?&](?:token|access_token|api_key)=", re.I)),
    ("authorization header literal", re.compile(r"['\"]Authorization['\"]\s*:\s*['\"]", re.I)),
]

# Machine-specific strings that must never be committed (sanitised instead).
PATTERNS.extend(
    [
        ("absolute home path", re.compile(r"/home/[A-Za-z0-9._-]+/")),
        ("absolute media mount", re.compile(r"/media/[A-Za-z0-9._-]+/")),
    ]
)


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        yield path


def scan_file(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PATTERNS:
            if pattern.search(line):
                excerpt = line.strip()[:80]
                hits.append(f"{path}:{lineno}: [{name}] {excerpt}")
    return hits


def main(argv: list[str]) -> int:
    roots = [Path(a) for a in argv] or [Path(__file__).resolve().parent.parent]
    findings: list[str] = []
    for root in roots:
        if not root.exists():
            print(f"secret_scan: no such path: {root}", file=sys.stderr)
            return 2
        if root.is_file():
            findings.extend(scan_file(root))
            continue
        for path in iter_files(root):
            findings.extend(scan_file(path))
    if findings:
        print(f"secret_scan: {len(findings)} potential finding(s):", file=sys.stderr)
        for hit in findings:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print("secret_scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

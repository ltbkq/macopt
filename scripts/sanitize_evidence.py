#!/usr/bin/env python3
"""Idempotent redaction pipeline for evidence and log fixtures.

    python scripts/sanitize_evidence.py              # sanitize in place (docs/evidence, tests/fixtures)
    python scripts/sanitize_evidence.py --check      # CI: fail if anything is still un-redacted
    python scripts/sanitize_evidence.py --src A --dst B

Everything this script rewrites is replaced by a stable placeholder so the
evidence stays reviewable (line numbers and key facts survive) while the
author's identity does not.

Running it twice must be a no-op: `--check` enforces exactly that.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_TARGETS = [REPO / "docs" / "evidence", REPO / "tests" / "fixtures"]

# Ordered: earlier rules see the raw text, later rules see already-redacted text.
RULES: list[tuple[str, re.Pattern[str], str]] = [
    # --- identity: home / media mounts -----------------------------------
    # No trailing "/" required: a redaction that only fires when a path
    # happens to continue (e.g. "owned by /home/alice" at end of line) would
    # leak exactly the case it exists for.
    ("home-path", re.compile(r"/home/[A-Za-z0-9._-]+"), "/home/<user>"),
    ("media-mount", re.compile(r"/media/[A-Za-z0-9._-]+"), "/mnt/<media>"),
    ("tmp-home", re.compile(r"/tmp/[A-Za-z0-9._-]+"), "/tmp/<user>"),
    # --- virtual machine / ISO display names -----------------------------
    ("vm-name", re.compile(r"\bmacOS 15\b"), "<vm-name>"),
    ("vm-dir", re.compile(r"\[Windows [^\]]*\][^\s\"']*"), "<iso-name>"),
    # --- hardware identity ------------------------------------------------
    ("mac", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<mac>"),
    ("uuid", re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "<uuid>"),
    ("oem", re.compile(r"\bERAZER\b"), "<oem>"),
    ("oem-product", re.compile(r"\bD80\b"), "<oem-product>"),
    ("board-string", re.compile(r"Default string"), "<oem-default>"),
    ("serial-line", re.compile(r"(Serial Number:\s*)\S+"), r"\1<redacted>"),
    ("smbios-serial", re.compile(r"(serial[_-]?number['\"]?\s*[:=]\s*)[\"']?[^\"'\s,}]+", re.I), r"\1<redacted>"),
    # --- user account -----------------------------------------------------
    ("user", re.compile(r"(?<![A-Za-z0-9._-])wang(?![A-Za-z0-9._-])"), "<user>"),
    ("user-token", re.compile(r"\bUSER=P?[A-Za-z0-9._-]+\b"), "USER=<user>"),
]


def sanitize_text(text: str) -> str:
    for _name, pattern, repl in RULES:
        text = pattern.sub(repl, text)
    return text


def iter_targets(paths: list[Path]):
    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            yield path
            continue
        for sub in sorted(path.rglob("*")):
            if sub.is_file() and sub.suffix.lower() in {".md", ".log", ".txt", ".vmx", ".json", ".toml"}:
                yield sub


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", type=Path, action="append", default=None, help="input file/dir (repeatable)")
    ap.add_argument("--dst", type=Path, default=None, help="write sanitized copies here (default: in place)")
    ap.add_argument("--check", action="store_true", help="verify nothing needs redacting; do not modify")
    args = ap.parse_args(argv)

    targets = args.src or DEFAULT_TARGETS
    changed: list[Path] = []
    dirty: list[Path] = []

    for path in iter_targets(targets):
        original = path.read_text(encoding="utf-8", errors="surrogateescape")
        cleaned = sanitize_text(original)
        if cleaned == original:
            continue
        dirty.append(path)
        if args.check:
            continue
        if args.dst:
            out = args.dst / path.name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(cleaned, encoding="utf-8", errors="surrogateescape")
        else:
            path.write_text(cleaned, encoding="utf-8", errors="surrogateescape")
            changed.append(path)

    if args.check:
        if dirty:
            print("sanitize_evidence: un-redacted content found in:", file=sys.stderr)
            for path in dirty:
                print(f"  {path}", file=sys.stderr)
            return 1
        print("sanitize_evidence: check passed (idempotent, nothing to redact)")
        return 0

    if changed:
        print(f"sanitize_evidence: redacted {len(changed)} file(s)")
        for path in changed:
            print(f"  {path}")
    else:
        print("sanitize_evidence: nothing to do")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Build a local, sanitized log fixture from *your* `vmware.log`.

    python scripts/make_fixtures.py "/path/to/VM/vmware.log" [-o OUT]

Output defaults to `fixtures/host/` (git-ignored): contributors keep their own
raw-derived fixtures locally, while the repository ships only the curated
sanitized sample under `tests/fixtures/verify/`.

This is the reproducible replacement for "copy my log into the repo".
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from sanitize_evidence import sanitize_text  # noqa: E402  (shared redaction rules)

# Regions of a vmware.log that the verifier actually reads.
INTERESTING = re.compile(
    r"guest vs\. host CPUID"
    r"|host CPUID level"
    r"|Powering on guestOS"
    r"|VMMon_GetkHzEstimate"
    r"|toolsInstallManager|Tools heartbeat|ToolsISO"
    r"|LocalApic|vmm-vcpus|numa:"
    r"|USER PREFERENCES|DICT ---"
    r"|VMware Workstation|vmware-vmx \d+",
)

DEFAULT_OUT = REPO / "fixtures" / "host"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", type=Path, help="path to a vmware.log")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT, help=f"output dir (default: {DEFAULT_OUT})")
    ap.add_argument("--max-lines", type=int, default=400, help="cap the fixture size (default 400)")
    args = ap.parse_args(argv)

    if not args.log.is_file():
        print(f"make_fixtures: not a file: {args.log}", file=sys.stderr)
        return 2

    lines = args.log.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    picked = [line for line in lines if INTERESTING.search(line)][: args.max_lines]
    if not picked:
        print("make_fixtures: no recognisable lines found", file=sys.stderr)
        return 1

    redacted = [sanitize_text(line) for line in picked]
    args.out.mkdir(parents=True, exist_ok=True)
    dest = args.out / f"{args.log.stem}.fixture.log"
    dest.write_text("\n".join(redacted) + "\n", encoding="utf-8")

    print(f"make_fixtures: {len(redacted)}/{len(lines)} lines -> {dest}")
    print("  (git-ignored; re-run scripts/sanitize_evidence.py --check before committing anything)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""Package data shipped with macopt.

Currently only :file:`known_keys.txt` — the hand-curated ``.vmx`` key
whitelist seed (DESIGN §4.5).

Compliance note: this package must **never** contain ``strings`` dumps or any
other export of VMware's proprietary binaries. Entries are added by hand, one
``# source:`` comment per section, naming where the key was observed (a
review report, a design section, a log line, or an official document).
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["KNOWN_KEYS_FILE"]

KNOWN_KEYS_FILE = Path(__file__).resolve().parent / "known_keys.txt"

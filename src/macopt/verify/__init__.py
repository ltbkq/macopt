"""Runtime verification (``macopt verify``): prove a ``.vmx`` change took
effect by parsing the hypervisor's own boot log (``vmware*.log``).

Pipeline::

    parse_log[_path]() -> LogFacts -> assertions.run() -> list[CheckResult]
                                                 |-> report.render_text() (human)
                                                 |-> report.to_json()     (§5.2)
                                                 |-> report.exit_code()   (§6)

Ground rules (DESIGN §4.13): missing log lines are ``SKIP``, never ``FAIL``;
the ``guest vs. host CPUID`` block is ``-INFO`` and printed once per boot.

Dependency direction: ``macopt.verify`` may import the contract layer
(``model``/``vmxfile``/``errors``/``context``) only — never ``profiles`` or
``cli``.
"""

from __future__ import annotations

from .assertions import CHECKS, KNOWN_DARWIN_TIERS, run
from .parser import LogFacts, as_ints, decode_fms, parse_log, parse_log_path, vendor_from_leaf0
from .report import exit_code, render_text, to_json

__all__ = [
    "CHECKS",
    "KNOWN_DARWIN_TIERS",
    "LogFacts",
    "as_ints",
    "decode_fms",
    "exit_code",
    "parse_log",
    "parse_log_path",
    "render_text",
    "run",
    "to_json",
    "vendor_from_leaf0",
]

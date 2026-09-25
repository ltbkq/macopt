"""Error model and process exit codes.

Exit codes are part of the public contract (scripts and CI depend on them):

==== =============================================================
0    success
1    operation failed / verification reported FAIL
2    usage error (also used by ``argparse``)
3    precondition not met (VM running, lock present, GUI open)
4    state cannot be determined — reported as UNKNOWN, never guessed
5    conflict: an existing value differs and ``--force`` was not given
6    refused: key/value not present in the scanned key whitelist
==== =============================================================
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_PRECONDITION = 3
EXIT_UNKNOWN = 4
EXIT_CONFLICT = 5
EXIT_REFUSED = 6


class MacoptError(Exception):
    """Base class; carries the process exit code it should map to."""

    exit_code = EXIT_FAIL

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message if not self.hint else f"{self.message}\n  hint: {self.hint}"


class UsageError(MacoptError):
    exit_code = EXIT_USAGE


class PreconditionError(MacoptError):
    """The VM (or VMware GUI) is using a file we must not touch right now."""

    exit_code = EXIT_PRECONDITION


class UnknownStateError(MacoptError):
    """We genuinely cannot tell. Distinct from a failed check on purpose."""

    exit_code = EXIT_UNKNOWN


class ConflictError(MacoptError):
    """A key already holds a different value; require an explicit ``--force``."""

    exit_code = EXIT_CONFLICT


class WhitelistError(MacoptError):
    """A key was not found in any VMware binary we are allowed to scan."""

    exit_code = EXIT_REFUSED


class VerificationError(MacoptError):
    exit_code = EXIT_FAIL


def exit_code_for(exc: BaseException) -> int:
    """Map an exception to a process exit code."""
    if isinstance(exc, MacoptError):
        return exc.exit_code
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        raise exc
    return EXIT_FAIL

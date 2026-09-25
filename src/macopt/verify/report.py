"""Human-readable and machine-readable reports for ``macopt verify``.

* :func:`render_text` — aligned text table (DESIGN §4.13 style output).
* :func:`to_json` — the stable ``schema: 1`` payload of DESIGN §5.2.
* :func:`exit_code` — DESIGN §6 mapping: 0 = green (WARN allowed unless
  ``--strict``), 1 = a FAIL (or a WARN under ``--strict``). Determining that
  the state is *unknown* (missing/stale log with no ``--log``) is the CLI's
  job before assertions run — it exits 4, deliberately distinct from FAIL.
"""

from __future__ import annotations

import textwrap
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from ..errors import EXIT_FAIL, EXIT_OK
from ..model import FAIL, PASS, SKIP, WARN, CheckResult

_STATUS_ORDER = (PASS, WARN, FAIL, SKIP)

_DETAIL_WIDTH = 72


def _counts(results: Sequence[CheckResult]) -> dict[str, int]:
    counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def exit_code(results: Sequence[CheckResult], *, strict: bool = False) -> int:
    """DESIGN §6: any FAIL ⇒ 1; with ``strict`` a WARN also ⇒ 1; else 0."""
    results = list(results)
    if any(r.status == FAIL for r in results):
        return EXIT_FAIL
    if strict and any(r.status == WARN for r in results):
        return EXIT_FAIL
    return EXIT_OK


def render_text(results: Sequence[CheckResult], ctx: Any = None) -> str:
    """Render the human table. ``ctx`` is a :class:`macopt.context.Context`;
    ``ctx.verbose > 0`` adds one evidence line per check."""
    results = list(results)
    verbose = 0 if ctx is None else int(getattr(ctx, "verbose", 0) or 0)

    idx_w = max(1, len(str(max(len(results) - 1, 0))))
    status_w = 6
    id_w = max((len(r.id) for r in results), default=2)
    title_w = max((len(r.title) for r in results), default=5)

    lines: list[str] = ["macopt verify — runtime verification (V0–V10)"]
    lines.append(
        f"{'#':>{idx_w}}  {'STATUS':<{status_w}}  {'ID':<{id_w}}  {'CHECK':<{title_w}}  DETAIL"
    )
    lines.append("-" * (idx_w + 2 + status_w + 2 + id_w + 2 + title_w + 2 + _DETAIL_WIDTH))

    prefix_w = idx_w + 2 + status_w + 2 + id_w + 2 + title_w + 2
    for i, r in enumerate(results):
        wrapped = textwrap.wrap(r.detail, width=_DETAIL_WIDTH) or [""]
        head = (
            f"{i:>{idx_w}}  {r.status:<{status_w}}  {r.id:<{id_w}}  {r.title:<{title_w}}  "
        )
        lines.append(head + wrapped[0])
        continuation = " " * prefix_w
        lines.extend(continuation + chunk for chunk in wrapped[1:])
        if verbose > 0:
            for ev in r.evidence:
                lines.append(f"{continuation}evidence: {ev.render()}")

    lines.append("-" * prefix_w)
    counts = _counts(results)
    summary = (
        f"result: {counts[PASS]} pass · {counts[WARN]} warn · {counts[FAIL]} fail · "
        f"{counts[SKIP]} skip — exit {exit_code(results)}"
    )
    if counts[WARN]:
        summary += " (use --strict to fail on warnings)"
    lines.append(summary)
    return "\n".join(lines)


def _iso(value: Any) -> Any:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def to_json(results: Sequence[CheckResult], *, meta: Mapping[str, Any]) -> dict[str, Any]:
    """Build the DESIGN §5.2 payload.

    *meta* carries the provenance fields the CLI collected (``vmx``,
    ``vmx_mtime``, ``log``, ``log_mtime``, ``vmware``, optional ``strict``);
    ``assertions``/``summary``/``exit_code`` are always computed from
    *results* and can never be supplied by the caller. Unknown meta keys are
    passed through — DESIGN §5.3 requires consumers to ignore them.
    """
    results = list(results)
    meta = dict(meta or {})

    payload: dict[str, Any] = {
        "schema": 1,
        "command": "verify",
        "vmx": None,
        "vmx_mtime": None,
        "log": None,
        "log_mtime": None,
        "fresh": None,
        "vmware": {"version": None, "build": None},
    }
    reserved = {"schema", "command", "assertions", "summary", "exit_code"}
    for key, value in meta.items():
        if key in reserved:
            continue
        if key == "vmware":
            payload["vmware"] = {**payload["vmware"], **dict(value or {})}
        else:
            payload[key] = value

    payload["vmx_mtime"] = _iso(payload["vmx_mtime"])
    payload["log_mtime"] = _iso(payload["log_mtime"])

    if payload["fresh"] is None and payload["vmx_mtime"] and payload["log_mtime"]:
        payload["fresh"] = payload["log_mtime"] >= payload["vmx_mtime"]

    counts = _counts(results)
    payload["assertions"] = [r.to_dict() for r in results]
    payload["summary"] = {
        "pass": counts[PASS],
        "fail": counts[FAIL],
        "warn": counts[WARN],
        "skip": counts[SKIP],
    }
    payload["exit_code"] = exit_code(results, strict=bool(meta.get("strict", False)))
    return payload


__all__ = ["exit_code", "render_text", "to_json"]

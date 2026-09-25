"""Command line entry point.

Every subcommand funnels errors through :func:`main`, which maps
:class:`macopt.errors.MacoptError` subclasses to their documented exit code
(see ``docs/DESIGN.md`` §6). Subcommands themselves only ever raise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__, doctor, hostinfo, keys, writer
from .context import Context
from .errors import (
    EXIT_FAIL,
    EXIT_OK,
    EXIT_UNKNOWN,
    ConflictError,
    MacoptError,
    PreconditionError,
    UnknownStateError,
    UsageError,
    WhitelistError,
)
from .model import ProfileOptions
from .vmxfile import Document

DEFAULT_MODULES = "guestos,topology,timing,gfxnet"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def resolve_vmx(target: str) -> Path:
    """Accept either a `.vmx` file or a directory holding exactly one of them."""
    path = Path(target).expanduser()
    if path.is_dir():
        candidates = sorted(path.glob("*.vmx"))
        if not candidates:
            raise MacoptError(f"no .vmx found in {path}")
        if len(candidates) > 1:
            names = ", ".join(c.name for c in candidates)
            raise MacoptError(f"multiple .vmx files in {path}: {names} (point at one)")
        return candidates[0]
    if path.suffix.lower() != ".vmx":
        raise MacoptError(f"not a .vmx file: {path}")
    if not path.exists():
        raise MacoptError(f"no such file: {path}")
    return path


def latest_log(vmx_path: Path) -> Path | None:
    logs = [p for p in vmx_path.parent.glob("vmware*.log") if p.is_file()]
    if not logs:
        return None
    return max(logs, key=lambda p: p.stat().st_mtime)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def state_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "state_dir", None):
        return Path(args.state_dir).expanduser()
    return doctor.state_home()


def last_apply_path(vmx_path: Path, root: Path) -> Path:
    slug = hashlib.sha256(str(vmx_path.resolve()).encode()).hexdigest()[:12]
    return root / "last-apply" / f"{slug}.json"


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def _whitelist_extra(args: argparse.Namespace, *, warm: bool) -> set[str]:
    """Runtime scan tokens for the whitelist (DESIGN §4.5: seed ∪ scan).

    Warm callers pay a one-time ~6 s scan and ~1 ms afterwards; callers that
    must not create state (``--dry-run``) only read whatever is already
    cached.
    """
    cache = state_dir(args) / keys.CACHE_NAME
    tokens = keys.cached_tokens(cache)
    if tokens or not warm:
        return tokens
    paths = keys.default_scan_paths()
    if not paths:
        return set()
    try:
        return keys.scan_cached(paths, cache)
    except OSError:  # pragma: no cover - scan() itself swallows per-file errors
        return set()


def _parse_extras(args: argparse.Namespace) -> dict[str, str]:
    """Assemble ``ProfileOptions.extras`` from the identity/brand flags.

    macopt ships no identity of its own: every value here must be supplied by
    the operator, and the profile builders reject a plan that would need one
    and did not get it.
    """
    extras: dict[str, str] = {}
    for key, value in (
        ("board-id", getattr(args, "board_id", None)),
        ("hw-model", getattr(args, "hw_model", None)),
        ("serial", getattr(args, "serial", None)),
    ):
        if value:
            extras[key] = value
    for item in getattr(args, "extra", None) or []:
        if "=" not in item or not item.split("=", 1)[0].strip():
            raise UsageError(f"--extra wants KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        extras[key.strip()] = value
    return extras


def cmd_setup(args: argparse.Namespace, ctx: Context) -> int:
    root = state_dir(args)
    created: list[str] = []
    for sub in ("backups", "history", "reports", "keycache", "last-apply"):
        path = root / sub
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created.append(str(path))
    cfg_path = doctor.config_home() / "config.toml"
    if not cfg_path.exists() and not args.dry_run:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(
            "# macopt configuration (all keys optional)\n"
            "# backup_roots = [\"/path/to/unlocker/backup\"]\n"
            "# vmx_globs    = [\"/path/to/VMs/*.vmx\"]\n",
            encoding="utf-8",
        )
        created.append(str(cfg_path))
    ctx.out(
        {"schema": 1, "command": "setup", "created": created, "state_dir": str(root)},
        human="state ready: " + str(root) + (f"\ncreated: {len(created)}" if created else " (already initialised)"),
    )
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace, ctx: Context) -> int:
    report = doctor.collect(cli_backup_roots=args.backup_root)
    ctx.out(report, human=doctor.render(report))
    return doctor.exit_code(report)


def cmd_check(args: argparse.Namespace, ctx: Context) -> int:
    from . import check as check_mod

    vmx = resolve_vmx(args.target)
    host = hostinfo.detect()
    results = check_mod.run(
        vmx,
        host,
        strict=args.strict,
        key_policy=keys.key_policy(extra=_whitelist_extra(args, warm=True)),
        log_path=Path(args.log) if args.log else latest_log(vmx),
    )
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    for item in results:
        counts[item.status] = counts.get(item.status, 0) + 1
    payload = {
        "schema": 1,
        "command": "check",
        "target": str(vmx),
        "assertions": [r.to_dict() for r in results],
        "summary": counts,
    }
    if ctx.as_json:
        ctx.out(payload)
    else:
        ctx.table(
            ["id", "status", "title", "detail"],
            [[r.id, r.status, r.title, r.detail] for r in results],
        )
        ctx.note(f"summary: {counts}")
    if counts["FAIL"]:
        return EXIT_FAIL
    if args.strict and counts["WARN"]:
        return EXIT_FAIL
    return EXIT_OK


def cmd_apply(args: argparse.Namespace, ctx: Context) -> int:
    from . import backup as backup_mod
    from . import profiles as profiles_mod

    vmx = resolve_vmx(args.target)
    doc = Document.load(vmx)
    mapping = doc.as_dict()
    host = hostinfo.detect()

    modules = {m.strip() for m in args.module.split(",") if m.strip()}
    # A flag that owns a module implies it: `--cpuid-profile penryn` must not
    # require the user to also spell `--module ...,cpuid`, otherwise the flag
    # silently does nothing (that is exactly how `identity`/`signed-brand`
    # became unreachable from the CLI).
    if args.cpuid_profile and args.cpuid_profile != "none":
        modules.add("cpuid")
    if args.identity:
        modules.add("identity")

    opts = ProfileOptions(
        profile=args.profile,
        modules=tuple(m for m in profiles_mod.APPLY_MODULES if m in modules),
        numvcpus=args.numvcpus,
        cpus=args.cpus,
        guestos=args.guestos,
        cpuid_profile=args.cpuid_profile,
        identity=args.identity,
        sync_time=args.sync_time,
        hide_hypervisor_bit=args.hide_hypervisor_bit,
        allow_apic_risk=args.allow_apic_risk,
        allow_unknown_keys=args.allow_unknown_keys,
        extras=_parse_extras(args),
    )

    # --- preconditions -----------------------------------------------------
    blockers = writer.check_precondition(vmx)
    if blockers:
        raise PreconditionError(
            "refusing to edit a running VM: " + "; ".join(blockers),
            hint="power the guest off (not suspended) and close the VMware GUI, then retry",
        )

    # --- plan --------------------------------------------------------------
    warming = not (ctx.dry_run or args.dry_run)
    result = profiles_mod.build_all(mapping, host, opts)
    plan = writer.build_plan(
        doc,
        result.params,
        key_policy=keys.key_policy(extra=_whitelist_extra(args, warm=warming)),
        allow_unknown_keys=args.allow_unknown_keys,
        confirmed=args.force or args.yes,
    )
    plan.warnings.extend(result.warnings)
    plan.errors.extend(result.errors)

    payload: dict[str, Any] = {
        "schema": 1,
        "command": "apply",
        "target": str(vmx),
        "dry_run": bool(ctx.dry_run or args.dry_run),
        "host": host.to_dict(),
        "plan": plan.to_dict(),
    }

    if not ctx.as_json:
        ctx.table(
            ["op", "key", "before", "after", "module"],
            [
                [c.op, c.key, c.before if c.before is not None else "-",
                 c.after if c.after is not None else "-", c.module]
                for c in plan.changes
            ],
        )
        for warning in plan.warnings:
            ctx.warn(warning)
        for error in plan.errors:
            ctx.note(f"blocked: {error}")

    # --- refusal paths -----------------------------------------------------
    if plan.blocking:
        payload["error"] = plan.errors
        if any(e.startswith("whitelist:") for e in plan.errors):
            exc: MacoptError = WhitelistError(
                "; ".join(plan.errors), hint="pass --allow-unknown-keys to override"
            )
        else:
            exc = ConflictError("; ".join(plan.errors))
        if ctx.as_json:
            ctx.out(payload)
        raise exc

    if not plan.effective:
        payload["result"] = "unchanged"
        payload["backup"] = None
        if ctx.as_json:
            ctx.out(payload)
        else:
            ctx.note("nothing to do (already applied)")
        return EXIT_OK

    if ctx.dry_run or args.dry_run:
        payload["result"] = "dry-run"
        if ctx.as_json:
            ctx.out(payload)
        else:
            ctx.note(f"dry-run: {plan.counts()} — nothing written")
        return EXIT_OK

    if not (args.yes or args.force):
        if not ctx.confirm(f"apply {len(plan.effective)} change(s) to {vmx.name}?"):
            raise ConflictError(
                "confirmation required",
                hint="re-run with --yes (or inspect with --dry-run first)",
            )

    # --- transactional write ---------------------------------------------- #
    root = state_dir(args)
    manager = backup_mod.BackupManager(root, vmx)
    record = manager.create_snapshot()
    try:
        applied = writer.apply(doc, plan, force=args.force, yes=args.yes, dry_run=False)
    except BaseException:
        # Roll back so a half-finished run can never leave a broken guest.
        try:
            manager.restore(record.id, dry_run=False)
        except Exception as rollback_exc:  # pragma: no cover - defensive
            ctx.warn(f"rollback failed: {rollback_exc}")
        raise

    manager.finalize(
        record,
        changes=[c.to_dict() for c in plan.changes],
        argv=sys.argv,
        host=host.to_dict(),
        tool_version=__version__,
        after_sha256=applied.sha256_after,
    )

    # remember what we claimed, so `verify` can close the loop (V8)
    expected = _expected_values(args.cpuid_profile)
    store = last_apply_path(vmx, root)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(
        json.dumps(
            {
                "target": str(vmx),
                "ts": time.time(),
                "backup_id": record.id,
                "changes": [c.to_dict() for c in plan.changes],
                "documented_values": expected,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    payload["result"] = "applied"
    payload["backup"] = {"id": record.id, "path": str(record.dir)}
    payload["applied"] = applied.__dict__
    payload["next"] = f"macopt verify {vmx.parent}"
    if ctx.as_json:
        ctx.out(payload)
    else:
        ctx.note(
            f"applied {applied.ops} -> backup {record.id}\n"
            f"  next: macopt verify '{vmx.parent}'"
        )
    return EXIT_OK


def _expected_values(cpuid_profile: str) -> dict[str, str]:
    """documented_values of the CPUID profile we just applied (V8 input)."""
    if not cpuid_profile or cpuid_profile == "none":
        return {}
    try:
        from .profiles import cpuid as cpuid_mod

        profile = cpuid_mod.PROFILES.get(cpuid_profile)
        return dict(profile.documented_values) if profile else {}
    except Exception:  # pragma: no cover - profile module optional at this stage
        return {}


def cmd_verify(args: argparse.Namespace, ctx: Context) -> int:
    from .verify import assertions, parser
    from .verify import report as report_mod

    vmx = resolve_vmx(args.target)
    mapping = Document.load(vmx).as_dict()

    log_path = Path(args.log).expanduser() if args.log else latest_log(vmx)
    if log_path is None or not log_path.exists():
        raise UnknownStateError(
            "no vmware.log found next to the guest",
            hint="boot the guest once, or pass --log /path/to/vmware.log",
        )

    facts = parser.parse_log_path(log_path)
    expected = _load_expected(vmx, args)
    results = assertions.run(
        facts,
        mapping,
        vmx_mtime=vmx.stat().st_mtime,
        log_mtime=log_path.stat().st_mtime,
        expected=expected,
    )
    summary = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    for item in results:
        summary[item.status] = summary.get(item.status, 0) + 1

    # `summary` / `exit_code` are recomputed by report.to_json from the results
    # themselves (DESIGN §5.2): a caller can never claim a pass it did not earn.
    payload = report_mod.to_json(
        results,
        meta={
            "vmx": str(vmx),
            "vmx_mtime": vmx.stat().st_mtime,
            "log": str(log_path),
            "log_mtime": log_path.stat().st_mtime,
            "fresh": log_path.stat().st_mtime >= vmx.stat().st_mtime,
            "vmware": {"version": getattr(facts, "vmware_version", None)},
            "strict": bool(args.strict),
            "expected": expected,
        },
    )
    code = int(payload["exit_code"])

    if ctx.as_json:
        ctx.out(payload)
    else:
        print(report_mod.render_text(results, ctx))
        ctx.note(f"summary: {summary}")

    if args.save_report:
        path = Path(args.save_report).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        ctx.note(f"report saved: {path}")
    return code


def _load_expected(vmx: Path, args: argparse.Namespace) -> dict[str, str]:
    expected: dict[str, str] = {}
    if not args.no_expected:
        store = last_apply_path(vmx, state_dir(args))
        if store.exists():
            try:
                expected.update(json.loads(store.read_text()).get("documented_values", {}) or {})
            except (OSError, json.JSONDecodeError):
                pass
    for item in args.expect or []:
        if "=" not in item:
            raise MacoptError(f"--expect wants KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        expected[key] = value
    return expected


def cmd_restore(args: argparse.Namespace, ctx: Context) -> int:
    from . import backup as backup_mod

    vmx = resolve_vmx(args.target)
    manager = backup_mod.BackupManager(state_dir(args), vmx)

    if args.verify:
        rows = manager.verify()
        ctx.out({"schema": 1, "command": "restore", "action": "verify", "rows": rows},
                human=None)
        if not ctx.as_json:
            ctx.table(["id", "file", "status", "detail"],
                      [[r.get("id"), r.get("file"), r.get("status"), r.get("detail", "")] for r in rows])
        return EXIT_OK if all(r.get("status") == "ok" for r in rows) else EXIT_FAIL

    if args.prune is not None:
        removed = manager.prune(args.prune)
        ctx.out({"schema": 1, "command": "restore", "action": "prune", "removed": removed},
                human=f"pruned {len(removed)} backup(s)")
        return EXIT_OK

    if args.diff is not None:
        rows = manager.diff(args.diff or None)
        ctx.out({"schema": 1, "command": "restore", "action": "diff", "rows": rows})
        if not ctx.as_json:
            if not rows:
                ctx.note("no differences recorded")
            for row in rows:
                ctx.out(None, human=f"  {row.get('key')}: {row.get('before')!r} -> {row.get('after')!r}")
        return EXIT_OK

    if args.to:
        result = manager.restore(args.to, dry_run=ctx.dry_run)
        ctx.out({"schema": 1, "command": "restore", "action": "restore", "result": result},
                human=f"restored {args.to}: {result}")
        return EXIT_OK

    # default: list
    records = manager.list()
    payload = {
        "schema": 1,
        "command": "restore",
        "action": "list",
        "backups": [
            {"id": r.id, "created_utc": r.created_utc, "dir": str(r.dir),
             "changes": len(r.manifest.get("changes", []))}
            for r in records
        ],
    }
    ctx.out(payload)
    if not ctx.as_json:
        if not records:
            ctx.note("no backups recorded for this guest")
        else:
            ctx.table(
                ["id", "created (UTC)", "changes"],
                [[r.id, r.created_utc, len(r.manifest.get("changes", []))] for r in records],
            )
        ctx.note("use --diff [ID] / --to ID / --verify / --prune N")
    return EXIT_OK


def cmd_keyscan(args: argparse.Namespace, ctx: Context) -> int:
    paths = [Path(p).expanduser() for p in args.path] if args.path else keys.default_scan_paths()
    existing = [p for p in paths if p.exists()]
    cache = state_dir(args) / keys.CACHE_NAME
    scanned = keys.scan_cached(existing, cache, refresh=args.refresh) if existing else set()
    known = keys.load_seed() | scanned

    if args.key:
        rows = [[k, "known" if keys.is_known(k, extra=scanned) else "NOT FOUND"] for k in args.key]
        ctx.out({"schema": 1, "command": "keyscan", "rows": dict(rows)})
        if not ctx.as_json:
            ctx.table(["key", "verdict"], rows)
        return EXIT_OK if all(v == "known" for _, v in rows) else EXIT_FAIL

    payload = {
        "schema": 1,
        "command": "keyscan",
        "paths": [str(p) for p in existing],
        "scanned": len(scanned),
        "seed": len(keys.load_seed()),
        "total": len(known),
    }
    ctx.out(payload)
    if not ctx.as_json:
        ctx.table(["metric", "value"], [[k, v] for k, v in payload.items() if k not in ("schema", "command")])
    return EXIT_OK


def cmd_unlocker_status(args: argparse.Namespace, ctx: Context) -> int:
    from . import unlocker

    status = unlocker.detect(doctor.VMMWARE_ROOT, doctor.backup_roots(doctor.load_config(), args.backup_root))
    payload = {
        "schema": 1,
        "command": "unlocker-status",
        "state": status.state,
        "confidence": status.confidence,
        "backup_root": str(status.backup_root) if status.backup_root else None,
        "files": [
            {"file": f.file, "verdict": f.verdict,
             "installed": f.sha256_installed,
             "backup_line1": f.sha256_backup_line1,
             "backup_line2": f.sha256_backup_line2}
            for f in status.files
        ],
        "hints": list(status.hints),
    }
    ctx.out(payload)
    if not ctx.as_json:
        ctx.out(None, human=f"state: {status.state}  confidence: {status.confidence}")
        ctx.table(["file", "verdict"], [[f.file, f.verdict] for f in status.files])
        for hint in status.hints:
            ctx.note(f"hint: {hint}")
    if status.state == "UNKNOWN":
        return EXIT_UNKNOWN
    return EXIT_OK


def cmd_detect_cpu(args: argparse.Namespace, ctx: Context) -> int:
    host = hostinfo.detect()
    ctx.out(host.to_dict())
    if not ctx.as_json:
        lines = [
            f"vendor      : {host.vendor}",
            f"brand       : {host.brand}",
            f"logical/phys: {host.logical_cpus} / {host.physical_cores}",
            f"numa nodes  : {host.numa_nodes}",
            f"hybrid      : {host.hybrid}",
        ]
        if host.hybrid:
            lines.append(f"P-cores      : {list(host.p_cpus)}")
            lines.append(f"E-cores      : {list(host.e_cpus)}")
            lines.append(f"max freq     : P {host.freq_mhz_p} MHz / E {host.freq_mhz_e} MHz")
        ctx.out(None, human="\n".join(lines))
    return EXIT_OK


def cmd_schedule(args: argparse.Namespace, ctx: Context) -> int:
    from .profiles import schedule as schedule_mod

    host = hostinfo.detect()
    if args.schedule_cmd == "plan":
        entries = schedule_mod.plan(host, args.profile, args.cpus)
        ctx.out({"schema": 1, "command": "schedule", "action": "plan", "entries": entries})
        if not ctx.as_json:
            for entry in entries:
                ctx.out(None, human=f"[{entry['label']}]\n  {' '.join(entry['command'])}\n  {entry['note']}")
        return EXIT_OK
    if args.schedule_cmd == "bind":
        result = schedule_mod.bind(args.pid, args.cpus)
        ctx.out({"schema": 1, "command": "schedule", "action": "bind", "result": result})
        if not ctx.as_json:
            ctx.out(None, human=str(result))
        return EXIT_OK if result.get("ok") else EXIT_FAIL
    if args.schedule_cmd == "check":
        result = schedule_mod.check(args.pid)
        ctx.out({"schema": 1, "command": "schedule", "action": "check", "result": result})
        if not ctx.as_json:
            ctx.out(None, human=f"Cpus_allowed_list: {result.get('allowed')}")
        return EXIT_OK if result.get("allowed") is not None else EXIT_FAIL
    raise MacoptError(f"unknown schedule action: {args.schedule_cmd}")


def cmd_guest_tools(args: argparse.Namespace, ctx: Context) -> int:
    vmx = resolve_vmx(args.target)
    mapping = Document.load(vmx).as_dict()
    mounted = [
        {"key": key, "value": value}
        for key, value in mapping.items()
        if key.endswith(".fileName") and str(value).lower().endswith(".iso")
    ]
    builtin = Path(doctor.DARWIN_ISO)
    report: dict[str, Any] = {
        "schema": 1,
        "command": "guest-tools",
        "target": str(vmx),
        "mounted_isos": mounted,
        "builtin_darwin_iso": str(builtin),
        "builtin_exists": builtin.exists(),
        "builtin_sha256": sha256_of(builtin) if builtin.exists() else None,
        "notes": [],
    }
    darwin_mounted = [m for m in mounted if "darwin" in str(m["value"]).lower()]
    if not darwin_mounted:
        report["notes"].append(
            "no darwin ISO attached; attach it in VM settings "
            "(Player users must do this manually)"
        )
    ctx.out(report)
    if not ctx.as_json:
        ctx.out(None, human="\n".join(
            [f"attached ISOs: {len(mounted)}"]
            + [f"  {m['key']} = {m['value']}" for m in mounted]
            + [f"builtin darwin.iso: {'present' if report['builtin_exists'] else 'absent'}"]
            + [f"note: {n}" for n in report["notes"]]
        ))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def _add_target(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="path to a .vmx, or the directory holding it")


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--dry-run", action="store_true", help="plan only, never write")
    parser.add_argument("--state-dir", help="override the macopt state directory")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-q", "--quiet", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="macopt",
        description="Audited, verifiable optimization for VMware Workstation macOS guests.",
        epilog="exit codes: 0 ok · 1 fail · 2 usage · 3 precondition · 4 unknown · 5 confirm · 6 refused",
    )
    parser.add_argument("--version", action="version", version=f"macopt {__version__}")
    _add_common(parser)
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("setup", help="initialise the macopt state directory")
    _add_common(p)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("doctor", help="read-only environment report")
    p.add_argument("--backup-root", action="append", help="Unlocker backup directory (repeatable)")
    _add_common(p)
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("check", help="static, read-only analysis of a .vmx")
    _add_target(p)
    p.add_argument("--strict", action="store_true", help="treat WARN as FAIL")
    p.add_argument("--log", help="vmware.log to consult (default: newest next to the guest)")
    _add_common(p)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("apply", help="plan and write a profile into a .vmx")
    _add_target(p)
    p.add_argument("--profile", choices=("performance", "balanced", "throughput"), default="balanced")
    p.add_argument("--module", default=DEFAULT_MODULES, help=f"comma list (default: {DEFAULT_MODULES})")
    p.add_argument("--numvcpus", type=int)
    p.add_argument("--cpus", help='CPU set, e.g. "0-11"')
    p.add_argument("--guestos", help='target guest id, e.g. "darwin25-64"')
    p.add_argument("--cpuid-profile", default="none",
                   help="none (default) | penryn | kabylake-7700k | signed-brand")
    p.add_argument("--identity", action="store_true", help="emit the SMBIOS identity block")
    p.add_argument("--board-id", help="explicit SMBIOS board-id (required by --identity)")
    p.add_argument("--hw-model", help="explicit SMBIOS hw.model (required by --identity)")
    p.add_argument("--serial", help="explicit SMBIOS serial (required by --identity)")
    p.add_argument("--extra", action="append", metavar="KEY=VALUE",
                   help="profile extras: identity smc.version/ROM/MLB, or signed-brand "
                        "brandString/family/model/stepping")
    p.add_argument("--sync-time", action="store_true", help="set tools.syncTime=TRUE")
    p.add_argument("--hide-hypervisor-bit", action="store_true")
    p.add_argument("--allow-apic-risk", action="store_true", help="lift CPUID R1/R2 blocks")
    p.add_argument("--allow-unknown-keys", action="store_true", help="lift the whitelist block")
    p.add_argument("--force", action="store_true", help="override confirmation gates")
    p.add_argument("--yes", action="store_true", help="non-interactive confirmation")
    _add_common(p)
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("verify", help="prove a change took effect using vmware.log")
    _add_target(p)
    p.add_argument("--log", help="explicit vmware.log path")
    p.add_argument("--expect", action="append", metavar="KEY=VALUE",
                   help="expected register value, e.g. cpuid.1.eax=0x000406e3")
    p.add_argument("--no-expected", action="store_true", help="ignore the stored apply record")
    p.add_argument("--strict", action="store_true", help="treat WARN as FAIL")
    p.add_argument("--save-report", help="write the JSON report to this path")
    _add_common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("restore", help="list, diff, verify or roll back backups")
    _add_target(p)
    p.add_argument("--list", action="store_true", help="list backups (default action)")
    p.add_argument("--diff", nargs="?", const="", metavar="ID", help="show one backup's changes")
    p.add_argument("--to", metavar="ID", help="roll back to a backup")
    p.add_argument("--verify", action="store_true", help="hash-check every backup")
    p.add_argument("--prune", type=int, metavar="N", help="keep the newest N backups")
    _add_common(p)
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("keyscan", help="inspect the .vmx key whitelist")
    p.add_argument("--path", action="append", help="binary to scan (repeatable)")
    p.add_argument("--key", action="append", help="check a specific key (repeatable)")
    p.add_argument("--refresh", action="store_true", help="re-scan even if the cache is warm")
    _add_common(p)
    p.set_defaults(func=cmd_keyscan)

    p = sub.add_parser("unlocker-status", help="five-state Unlocker detection")
    p.add_argument("--backup-root", action="append", help="Unlocker backup directory (repeatable)")
    _add_common(p)
    p.set_defaults(func=cmd_unlocker_status)

    p = sub.add_parser("detect-cpu", help="host CPU topology (P/E cores, hybrid, NUMA)")
    _add_common(p)
    p.set_defaults(func=cmd_detect_cpu)

    p = sub.add_parser("schedule", help="host-side CPU affinity planning/checking")
    sched = p.add_subparsers(dest="schedule_cmd", metavar="<action>")
    sp = sched.add_parser("plan", help="print launch/bind commands")
    sp.add_argument("--profile", choices=("performance", "balanced", "throughput"), default="balanced")
    sp.add_argument("--cpus", help='CPU set, e.g. "0-11"')
    _add_common(sp)
    sp.set_defaults(func=cmd_schedule, schedule_cmd="plan")
    sp = sched.add_parser("bind", help="re-affinitise a running process")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--cpus", required=True)
    _add_common(sp)
    sp.set_defaults(func=cmd_schedule, schedule_cmd="bind")
    sp = sched.add_parser("check", help="read /proc/<pid>/status and report the affinity")
    sp.add_argument("--pid", type=int, required=True)
    _add_common(sp)
    sp.set_defaults(func=cmd_schedule, schedule_cmd="check")
    _add_common(p)
    p.set_defaults(func=cmd_schedule)

    p = sub.add_parser("guest-tools", help="report darwin.iso / Tools attachment status")
    _add_target(p)
    _add_common(p)
    p.set_defaults(func=cmd_guest_tools)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2

    ctx = Context(
        verbose=getattr(args, "verbose", 0),
        quiet=getattr(args, "quiet", False),
        as_json=getattr(args, "json", False),
        yes=getattr(args, "yes", False),
        dry_run=getattr(args, "dry_run", False),
    )
    try:
        handler: Callable[[argparse.Namespace, Context], int] = args.func
        return int(handler(args, ctx))
    except MacoptError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # unexpected: keep the exit code contract honest
        if ctx.verbose:
            traceback.print_exc()
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

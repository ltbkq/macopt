"""`macopt doctor` — one-shot, read-only environment report.

Everything here is gathered by stat-ing, hashing or reading; nothing in this
module writes to the system. Results are returned as a plain dict so the CLI
can render either the human table or ``--json``.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any

from . import hostinfo, unlocker

# VMware's own configuration layers, low priority -> high priority.
CONFIG_LAYERS: tuple[tuple[str, str], ...] = (
    ("GLOBAL SETTINGS", "/usr/lib/vmware/settings"),
    ("SITE DEFAULTS", "/usr/lib/vmware/config"),
    ("HOST DEFAULTS", "/etc/vmware/config"),
    ("USER DEFAULTS", "~/.vmware/config"),
    ("USER PREFERENCES", "~/.vmware/preferences"),
)

VMMWARE_ROOT = "/usr/lib/vmware"
DARWIN_ISO = "/usr/lib/vmware/isoimages/darwin.iso"  # not /usr/lib/vmware/iso
PREFERENCES_FILE = "~/.vmware/preferences"  # not ~/.config/vmware/preferences.ini


def config_home() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "macopt"


def state_home() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "macopt"


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Read ``~/.config/macopt/config.toml`` if present (never required)."""
    cfg_path = path or config_home() / "config.toml"
    try:
        with cfg_path.open("rb") as fh:
            return dict(tomllib.load(fh))
    except FileNotFoundError:
        return {}
    except (tomllib.TOMLDecodeError, OSError) as exc:  # malformed config: report, don't crash
        return {"_error": f"{cfg_path}: {exc}"}


def config_layers() -> list[dict[str, Any]]:
    out = []
    for name, raw in CONFIG_LAYERS:
        path = Path(os.path.expanduser(raw))
        out.append(
            {
                "name": name,
                "path": raw,
                "exists": path.exists(),
                "lines": _line_count(path),
            }
        )
    return out


def _line_count(path: Path) -> int | None:
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def backup_roots(cfg: dict[str, Any], cli_roots: list[str] | None = None) -> list[Path]:
    """Where an Unlocker checkout might live: CLI > config file > not guessed."""
    roots: list[Path] = []
    for item in cli_roots or []:
        roots.append(Path(item))
    for item in cfg.get("backup_roots", []) or []:
        roots.append(Path(str(item)))
    return roots


def collect(*, cli_backup_roots: list[str] | None = None) -> dict[str, Any]:
    cfg = load_config()
    host = hostinfo.detect()
    roots = backup_roots(cfg, cli_backup_roots)
    status = unlocker.detect(VMMWARE_ROOT, roots)

    state = state_home()
    state_writable = _probe_writable(state)

    report: dict[str, Any] = {
        "host": host.to_dict(),
        "unlocker": {
            "state": status.state,
            "confidence": status.confidence,
            "backup_root": str(status.backup_root) if status.backup_root else None,
            "files": [
                {
                    "file": f.file,
                    "verdict": f.verdict,
                    "installed": f.sha256_installed,
                }
                for f in status.files
            ],
            "hints": list(status.hints),
        },
        "config_layers": config_layers(),
        "paths": {
            "preferences": PREFERENCES_FILE,
            "preferences_exists": Path(os.path.expanduser(PREFERENCES_FILE)).exists(),
            "darwin_iso": DARWIN_ISO,
            "darwin_iso_exists": Path(DARWIN_ISO).exists(),
            "state_dir": str(state),
            "state_dir_writable": state_writable,
            "config_file": str(config_home() / "config.toml"),
            "config_exists": (config_home() / "config.toml").exists(),
        },
        "notes": list(host.notes),
    }
    return report


def _probe_writable(path: Path) -> bool | None:
    """Does not create anything: walks up to the nearest existing ancestor."""
    probe = path
    while not probe.exists():
        parent = probe.parent
        if parent == probe:
            return None
        probe = parent
    try:
        return os.access(probe, os.W_OK)
    except OSError:
        return None


def render(report: dict[str, Any]) -> str:
    host = report["host"]
    unlocker = report["unlocker"]
    paths = report["paths"]
    lines: list[str] = []

    lines.append("host")
    lines.append(
        f"  cpu: {host.get('brand') or '?'} ({host.get('vendor') or '?'}) — "
        f"{host.get('logical_cpus')} logical / {host.get('physical_cores')} cores, "
        f"NUMA nodes: {host.get('numa_nodes')}"
    )
    if host.get("hybrid"):
        lines.append(
            f"  hybrid: P-cores {host.get('p_cpus')}  E-cores {host.get('e_cpus')}"
        )
        if host.get("freq_mhz_p"):
            lines.append(
                f"  max freq: P {host['freq_mhz_p']} MHz"
                + (f" / E {host['freq_mhz_e']} MHz" if host.get("freq_mhz_e") else "")
            )
    lines.append(f"  kernel: {host.get('kernel') or '?'}")
    lines.append(
        "  vmware: "
        + (f"{host.get('vmware_version')} build {host.get('vmware_build') or '?'}"
           f" ({host['vmware_build_tag']})" if host.get("vmware_version") else "not found")
    )

    lines.append("unlocker")
    lines.append(f"  state: {unlocker['state']}  confidence: {unlocker['confidence']}")
    for item in unlocker["files"]:
        lines.append(f"    {item['file']}: {item['verdict']}")
    for hint in unlocker["hints"]:
        lines.append(f"    hint: {hint}")

    lines.append("config layers (low -> high priority)")
    for layer in report["config_layers"]:
        marker = "present" if layer["exists"] else "absent"
        extra = f", {layer['lines']} lines" if layer["lines"] is not None else ""
        lines.append(f"  {layer['name']:<18} {layer['path']}  [{marker}{extra}]")

    lines.append("paths")
    lines.append(
        f"  preferences: {paths['preferences']}  "
        f"[{'present' if paths['preferences_exists'] else 'absent'}]"
    )
    lines.append(
        f"  darwin.iso : {paths['darwin_iso']}  "
        f"[{'present' if paths['darwin_iso_exists'] else 'absent'}]"
    )
    lines.append(
        f"  state dir  : {paths['state_dir']}  "
        f"[{'writable' if paths['state_dir_writable'] else 'read-only/absent'}]"
    )
    lines.append(f"  config     : {paths['config_file']}  "
                 f"[{'present' if paths['config_exists'] else 'absent'}]")

    for note in report.get("notes", []):
        lines.append(f"note: {note}")
    return "\n".join(lines)


def exit_code(report: dict[str, Any]) -> int:
    """0 = usable environment; 4 = we genuinely cannot tell (e.g. no VMware)."""
    from .errors import EXIT_OK, EXIT_UNKNOWN

    if not report["host"].get("vmware_version"):
        return EXIT_UNKNOWN
    if report["unlocker"]["state"] == "UNKNOWN":
        return EXIT_UNKNOWN
    return EXIT_OK


def isatty() -> bool:  # pragma: no cover - trivial passthrough
    return sys.stdin.isatty()

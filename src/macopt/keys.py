"""``.vmx`` key whitelist: curated seed table + read-only runtime scanning.

Why a whitelist exists at all
-----------------------------
VMware silently *ignores* a ``.vmx`` key it does not recognise — there is no
error, no warning, the line just does nothing. That failure mode is exactly
what made the upstream design's ``mks.g3d.maxTextureSize`` /
``mks.enableGLRenderer`` suggestions useless (they do not exist anywhere in
``/usr/lib/vmware``; see ``docs/evidence/01-factcheck.md`` §3.1). So every key
macopt writes must be provably known to the installed VMware build.

Two sources are unioned (DESIGN §4.5)::

    known_keys() = seed table (data/known_keys.txt, hand-curated, released)
                    ∪ runtime scan of the installed binaries (user's machine)

Compliance: the seed table is **hand-curated** and carries a ``# source:``
comment per section. Nothing derived from VMware binaries (``strings`` dumps
of proprietary code) is ever committed — scan results live only in the
caller's memory / the user's own state directory on their own machine.

Read-only contract: :func:`scan` opens files ``O_RDONLY`` and maps them with
``mmap.ACCESS_READ``. It never writes, never spawns a process (no ``strings``
subprocess — pure CPython), and never follows the results anywhere.

Limits worth stating out loud
-----------------------------
* The DESIGN §4.5 token charset ``[A-Za-z0-9_.:\\-]{3,64}`` does not contain
  ``%``, so a format fragment such as ``ethernet%d.virtualDev`` is *not*
  extractable by the primary regex. A second, narrow pattern catches
  ``%``-bearing key fragments, and the seed table additionally carries
  ``%d``/``%u``/``%s`` patterns that :func:`is_known` expands
  (``ethernet%d.virtualDev`` matches ``ethernet0.virtualDev``).
* Bare (dot-less) keys such as ``numvcpus`` / ``guestOS`` cannot be told apart
  from ordinary words in a binary image; they come from the seed table only.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
from collections.abc import Callable, Sequence
from functools import lru_cache
from pathlib import Path

__all__ = [
    "CACHE_NAME",
    "CPUID_FORMAT_STRINGS",
    "SEED_FILE",
    "cached_tokens",
    "default_scan_paths",
    "expandable_cpuid_key",
    "is_known",
    "key_policy",
    "load_nonexistent",
    "load_seed",
    "scan",
    "scan_cached",
]

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

SEED_FILE = Path(__file__).resolve().parent / "data" / "known_keys.txt"

#: Files worth scanning on a stock Workstation/Player install (DESIGN §4.5).
_DEFAULT_RELATIVE = (
    "bin/vmware-vmx",
    "bin/vmware-vmx-debug",
    "bin/vmware-vmx-stats",
    "bin/mksSandbox",
    "lib/libvmwarebase.so/libvmwarebase.so",
)


def default_scan_paths(vmware_root: str | Path = "/usr/lib/vmware") -> list[Path]:
    """Existing files from :data:`_DEFAULT_RELATIVE` under ``vmware_root``."""
    root = Path(vmware_root)
    return [root / rel for rel in _DEFAULT_RELATIVE if (root / rel).is_file()]


# --------------------------------------------------------------------------- #
# Token extraction (DESIGN §4.5)
# --------------------------------------------------------------------------- #

#: Primary token charset — frozen by DESIGN §4.5.
_TOKEN_RE = re.compile(rb"[A-Za-z0-9_.:\-]{3,64}")

#: Narrow second pass for ``%``-bearing key fragments (``ethernet%d.virtualDev``,
#: ``pciBridge%d.present``). Single conversion char after ``%``.
_PERCENT_KEY_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_.:\-]{0,40}(?:%[A-Za-z][A-Za-z0-9_.:\-]{0,40})+")

#: A token is a candidate key only when it is dotted and its first segment
#: starts with a letter/underscore — this drops version numbers (``26.0.1``),
#: IP-ish blobs and bare words while keeping ``svga.maxTextureSize``,
#: ``sata0:1.present``, ``cpuid.1.eax``.
_KEY_SHAPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:\-]*(?:\.[A-Za-z0-9_:\-]+)+$")

_HEX_RE = re.compile(r"[0-9a-fA-F]{1,8}")
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx"})

#: ``cpuid`` format strings observed in ``vmware-vmx`` (``cpuid.%x.%x.%s.amd``
#: is listed first because the binary queries the ``.amd`` variant first).
#: Source: docs/evidence/02-cpuid-review.md §1.1 (vmx-strings.txt:159637-159641).
CPUID_FORMAT_STRINGS: tuple[str, ...] = (
    "cpuid.%x.%x.%s.amd",
    "cpuid.%x.%s.amd",
    "cpuid.%x.%x.%s",
    "cpuid.%x.%s",
)


def _looks_like_key(token: str) -> bool:
    return bool(_KEY_SHAPE_RE.match(token))


def scan(paths: Sequence[str | Path]) -> set[str]:
    """Read-only, process-free extraction of key-shaped tokens.

    Each path is mapped with ``mmap.ACCESS_READ`` and swept with
    :data:`_TOKEN_RE` plus the narrow ``%`` pattern. Unreadable, empty or
    non-regular files are skipped silently — scanning is opportunistic and a
    missing optional binary must never raise.
    """
    found: set[str] = set()
    for raw in paths:
        path = Path(raw)
        try:
            if not path.is_file() or path.stat().st_size == 0:
                continue
            handle = open(path, "rb")  # noqa: SIM115 - lifetime tied to the mmap below
        except OSError:
            continue
        try:
            with handle:
                try:
                    mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
                except (OSError, ValueError):
                    continue
                with mm:
                    for match in _TOKEN_RE.finditer(mm):
                        token = match.group().decode("ascii")
                        if _looks_like_key(token):
                            found.add(token)
                    for match in _PERCENT_KEY_RE.finditer(mm):
                        token = match.group().decode("ascii")
                        if token.startswith("cpuid.%"):
                            # format string, not a key: handled by
                            # expandable_cpuid_key() instead
                            continue
                        if "." not in token:
                            # dot-less fragment (e.g. `d%s` from an unrelated
                            # format string): never a .vmx key on its own, and
                            # indexing it would make is_known() too permissive
                            continue
                        found.add(token)
        except (OSError, ValueError):
            continue
    return found


# --------------------------------------------------------------------------- #
# cpuid format-string expansion (rule ① of is_known)
# --------------------------------------------------------------------------- #


def expandable_cpuid_key(key: str) -> bool:
    """True when one of :data:`CPUID_FORMAT_STRINGS` can produce ``key``.

    Accepted shapes (the ``.amd`` suffix is optional and comes first in the
    binary's lookup order):

    ``cpuid.<leaf>.<reg>`` / ``cpuid.<leaf>.<subleaf>.<reg>``
        ``<leaf>``/``<subleaf>`` are hex (``%x``), ``<reg>`` must be one of
        ``eax|ebx|ecx|edx`` (``%s`` is documented as the register name) — the
        test is case-insensitive because T5 (named-key casing) is still open.

    ``cpuid.<leaf>`` (flat form)
        Present in the binary as well (``cpuid.0`` / ``cpuid.1`` /
        ``cpuid.80000000``…); accepted so a real key is never rejected.

    Anything else — ``cpuid.notaleaf``, ``cpuid.1.qqq`` — does **not** expand
    and has to be present in the seed table / scan results to be known.
    """
    if not key.startswith("cpuid."):
        return False
    body = key[6:]
    if body.lower().endswith(".amd"):
        body = body[: -len(".amd")]
    parts = body.split(".")
    if len(parts) == 1:
        return bool(_HEX_RE.fullmatch(parts[0]))
    if len(parts) == 2:
        leaf, reg = parts
        return bool(_HEX_RE.fullmatch(leaf)) and reg.lower() in _REGISTERS
    if len(parts) == 3:
        leaf, subleaf, reg = parts
        return (
            bool(_HEX_RE.fullmatch(leaf))
            and bool(_HEX_RE.fullmatch(subleaf))
            and reg.lower() in _REGISTERS
        )
    return False


# --------------------------------------------------------------------------- #
# Seed table (rule ②)
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def _seed_text() -> str:
    # Raises FileNotFoundError on a broken install: a silently empty whitelist
    # would reject (or worse, accept) everything, so fail loudly instead.
    return SEED_FILE.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _seed_frozen() -> frozenset[str]:
    keys: set[str] = set()
    for raw in _seed_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        keys.add(line)
    return frozenset(keys)


_PATTERN_CHARS = "%d%u%s"


def _pattern_regex(entry: str) -> re.Pattern[str] | None:
    """Turn a seed entry carrying ``%d``/``%u``/``%s`` into a matcher.

    VMware keys are frequently device-indexed (``ethernet%d.virtualDev``,
    ``scsi%d:%d.present``, ``smbios.reflectHost.subtype%u``) or suffix-formatted
    (``guestinfo.%s``); the seed stores the pattern and the concrete instance
    keys in a ``.vmx`` are matched against it. Returns ``None`` for plain keys
    **and** for dot-less fragments: a runtime scan hands us strings like
    ``d%s`` from unrelated format strings, and indexing those would make
    ``is_known`` accept any word starting with ``d``.
    """
    if not any(tok in entry for tok in _PATTERN_CHARS):
        return None
    if "." not in entry:
        return None
    if not (entry[0].isalpha() or entry[0] == "_"):
        return None
    rx = re.escape(entry)
    rx = rx.replace("%d", r"\d+").replace("%u", r"\d+").replace("%s", r"[A-Za-z0-9_.\-]+")
    return re.compile("^" + rx + "$")


@lru_cache(maxsize=1)
def _indexed_patterns() -> tuple[re.Pattern[str], ...]:
    return tuple(rx for rx in (_pattern_regex(e) for e in _seed_frozen()) if rx is not None)


def load_seed() -> set[str]:
    """Return the hand-curated seed whitelist (``#`` comment lines skipped)."""
    return set(_seed_frozen())


#: Marker for the deny-list section of the seed file (DESIGN §4.5).
NONEXISTENT_PREFIX = "# non-existent: "


@lru_cache(maxsize=1)
def _nonexistent_frozen() -> frozenset[str]:
    keys: set[str] = set()
    for line in _seed_text().splitlines():
        if not line.startswith(NONEXISTENT_PREFIX):
            continue
        # "# non-existent: <key>   (why)" -> "<key>"
        body = line[len(NONEXISTENT_PREFIX) :].strip()
        if body:
            keys.add(body.split()[0])
    return frozenset(keys)


def load_nonexistent() -> frozenset[str]:
    """Keys that must never be whitelisted, whatever the scan says.

    Seed prose alone cannot enforce this: the installed binary carries the
    broad pattern ``vmotion.%s``, which matches the *unproven*
    ``vmotion.svga.maxTextureSize`` and would otherwise let it through
    (measured on this host before this deny-list existed).
    """
    return _nonexistent_frozen()


def _match_any(patterns: Sequence[re.Pattern[str]], key: str) -> bool:
    return any(p.match(key) for p in patterns)


def is_known(key: str, *, extra: set[str] | None = None) -> bool:
    """Decide whether ``key`` may be written into a ``.vmx``.

    Order matters:

    0. the deny-list of verified non-existent keys wins over *everything* —
       a broad pattern from the binary scan must not be able to re-admit a
       key this project has proven does not exist;
    ① ``cpuid`` format-string expansion (``expandable_cpuid_key``),
    ② the seed table ∪ ``extra`` (``extra`` is where the caller passes
       runtime scan results / config additions).
    """
    if not key or not isinstance(key, str):
        return False
    if key in _nonexistent_frozen():
        return False
    if expandable_cpuid_key(key):
        return True
    if key in _seed_frozen():
        return True
    if _match_any(_indexed_patterns(), key):
        return True
    if extra:
        if key in extra:
            return True
        if any(any(tok in e for tok in _PATTERN_CHARS) for e in extra):
            indexed = [rx for rx in (_pattern_regex(e) for e in extra) if rx is not None]
            if _match_any(indexed, key):
                return True
    return False


def key_policy(*, extra: set[str] | None = None) -> Callable[[str], bool]:
    """Return ``predicate(key) -> bool`` for injection into ``writer``.

    The closure captures ``extra`` once so a plan built over a long-running
    scan keeps a consistent whitelist even if the caller mutates its set later
    (it is copied defensively).
    """
    snapshot: frozenset[str] | None = frozenset(extra) if extra is not None else None

    def policy(key: str) -> bool:
        return is_known(key, extra=set(snapshot) if snapshot is not None else None)

    policy.__doc__ = "whitelist predicate produced by macopt.keys.key_policy"
    return policy


# --------------------------------------------------------------------------- #
# Scan cache — DESIGN §4.5 (`state/keycache.json`)
# --------------------------------------------------------------------------- #

CACHE_NAME = "keycache.json"
CACHE_SCHEMA = 1


def _stat_signature(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_size, st.st_mtime_ns


def _sha16(path: Path) -> str:
    """First 16 bytes of the file's SHA-256, as 32 hex characters."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()[:32]


def _read_cache(cache_file: Path) -> dict[str, object]:
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict) or data.get("schema") != CACHE_SCHEMA:
        return {}
    if not isinstance(data.get("files"), dict):
        return {}
    return data


def _write_cache(cache_file: Path, data: dict[str, object]) -> None:
    """Atomic cache write. Best effort: a cache must never fail a command."""
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_file.with_name(cache_file.name + ".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        os.replace(tmp, cache_file)
    except OSError:
        pass


def cached_tokens(cache_file: str | Path) -> set[str]:
    """Union of the cached scan results; empty when the cache is cold.

    Never touches the VMware binaries — callers use this when they must stay
    fast and side-effect free (``--dry-run``).
    """
    data = _read_cache(Path(cache_file))
    tokens: set[str] = set()
    for entry in data.get("files", {}).values():  # type: ignore[union-attr]
        if isinstance(entry, dict) and isinstance(entry.get("tokens"), list):
            tokens.update(str(t) for t in entry["tokens"])
    return tokens


def scan_cached(
    paths: Sequence[str | Path],
    cache_file: str | Path,
    *,
    refresh: bool = False,
) -> set[str]:
    """Union of :func:`scan` over *paths*, backed by *cache_file*.

    Cache key per DESIGN §4.5: ``(path, size, mtime_ns, sha256[:16])``. The
    ``stat`` pair is the fast path — a warm cache costs about a millisecond
    instead of ~6 s of ``mmap`` sweeps — and the hash is recomputed only when
    that pair changed, so a plain ``touch`` keeps the cached tokens while any
    real content change forces a rescan. Missing/unreadable files are simply
    dropped from the cache; scanning stays opportunistic.
    """
    cache_file = Path(cache_file)
    data: dict[str, object] = {} if refresh else _read_cache(cache_file)
    data.setdefault("schema", CACHE_SCHEMA)  # without it _read_cache() rejects the file
    files: dict[str, object] = data.setdefault("files", {})  # type: ignore[union-attr]

    found: set[str] = set()
    dirty = False
    for raw in paths:
        path = Path(raw)
        try:
            size, mtime_ns = _stat_signature(path)
        except OSError:
            files.pop(str(path), None)  # type: ignore[union-attr]
            dirty = True
            continue

        entry = files.get(str(path))  # type: ignore[union-attr]
        if isinstance(entry, dict) and not refresh:
            if entry.get("size") == size and entry.get("mtime_ns") == mtime_ns:
                found.update(str(t) for t in entry.get("tokens", []))
                continue
            try:
                sha16 = _sha16(path)
            except OSError:
                sha16 = ""
            if sha16 and entry.get("sha256_16") == sha16:
                # touched but byte-identical: keep the tokens, refresh stat
                entry["size"], entry["mtime_ns"] = size, mtime_ns
                found.update(str(t) for t in entry.get("tokens", []))
                dirty = True
                continue

        tokens = scan([path])
        try:
            sha16 = _sha16(path)
        except OSError:
            sha16 = ""
        files[str(path)] = {  # type: ignore[index]
            "size": size,
            "mtime_ns": mtime_ns,
            "sha256_16": sha16,
            "tokens": sorted(tokens),
        }
        found.update(tokens)
        dirty = True

    if dirty:
        _write_cache(cache_file, data)
    return found

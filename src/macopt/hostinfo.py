"""Host probing: CPU topology, P/E core classes, cgroup delegation, VMware, TSC.

Everything here is **read-only** (``/sys``, ``/proc`` and subprocesses that only
print their version) and every path is injectable so unit tests can point the
code at a synthetic sysfs/proc tree instead of the live machine.

Design references (repo-local):

* ``docs/DESIGN.md`` §4.7 (line 310) — four-level probing, the three-tier
  profile table this module feeds (lines 331-333) and the .vmx parameter table
  (lines 339-345).
* ``docs/evidence/03-cpu-tuning-module.md`` — the measured facts:
    - L1: ``/sys/devices/cpu_core/cpus`` + ``/sys/devices/cpu_atom/cpus`` give
      the P/E logical CPU sets directly on Intel hybrid parts (reference host
      i7-13620H: P = ``0-11``, E = ``12-15``; report line 165).
    - L2: ``topology/{core_id,physical_package_id,thread_siblings_list}``
      grouping plus a 5 %-tolerance cluster of ``cpuinfo_max_freq`` splits P/E
      on hosts without the L1 directories (report lines 170-183).
    - L3: ``/proc/cpuinfo`` counting; L4: ``lscpu`` fallback.
    - ``/proc/cpuinfo`` "cpu MHz" and cpufreq limits are *core* frequencies,
      never the TSC (reference host: cpuinfo 4641 MHz vs. real TSC 2918.4 MHz,
      report §0) — therefore :func:`detect_tsc` returns ``None`` rather than
      guessing when the kernel does not expose a TSC frequency file.

Contract rules honoured here:

* ``detect()``/``detect_cpu_topology()``/``detect_cgroup()``/``detect_tsc()``
  take injectable roots (and an injectable ``runner`` for the whitelisted
  ``lscpu`` / ``vmware --version`` subprocesses);
* unknown state comes back as ``None`` / ``()`` / ``{}`` — never invented
  (DESIGN §4.0 hard rule 2: "we did not see it" is not "it is broken").
"""

from __future__ import annotations

import glob
import os
import re
import subprocess
from collections.abc import Callable
from typing import Any

from .model import HostInfo

#: Any ``subprocess.run``-compatible callable. Injected by tests.
Runner = Callable[..., Any]

_INT_RE = re.compile(r"[0-9]+")

# TSC sanity window in Hz. Below 100 MHz or above 10 GHz is not a TSC, so a
# bogus file can never be reported as one (detect_tsc never guesses).
_TSC_HZ_MIN = 100_000_000
_TSC_HZ_MAX = 10_000_000_000

# P/E frequency clustering (03 report §3.1 L2, lines 170-183): bucket
# cpuinfo_max_freq values with a 5 % tolerance, then require a >= 10 % gap
# between the fastest bucket and the rest before calling anything an
# efficiency class. On the reference host this yields {4700, 4900} vs {3600}.
_FREQ_CLUSTER_RATIO = 1.05
_FREQ_SPLIT_RATIO = 1.10


# --------------------------------------------------------------------------- #
# small read-only helpers
# --------------------------------------------------------------------------- #


def _read_text(path: str) -> str | None:
    """Return file contents, or ``None`` for any OSError (missing, EACCES...)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _read_int(path: str) -> int | None:
    raw = _read_text(path)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def _parse_cpu_list(spec: str) -> tuple[int, ...]:
    """Kernel CPU list syntax: ``"0-11,14"`` -> ``(0, 1, ..., 11, 14)``.

    Malformed entries are dropped rather than raised: this runs against
    whatever the OS gives us and a half-readable list is still useful for
    *reporting* (profiles only bind when the whole set parsed cleanly).
    """
    out: set[int] = set()
    for part in spec.replace("\n", " ").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            if not (_INT_RE.fullmatch(lo_s) and _INT_RE.fullmatch(hi_s)):
                continue
            lo, hi = int(lo_s), int(hi_s)
            if lo <= hi:
                out.update(range(lo, hi + 1))
        elif _INT_RE.fullmatch(part):
            out.add(int(part))
    return tuple(sorted(out))


def _split_words(text: str | None) -> tuple[str, ...]:
    return tuple(text.split()) if text else ()


def _run_capture(argv: list[str], runner: Runner, timeout: float = 20) -> tuple[int, str] | None:
    """Run a whitelisted read-only command, tolerating simple injected fakes.

    Returns ``(returncode, stdout)`` or ``None`` when the command could not be
    run at all (binary missing, timeout, fake refused). Never uses a shell.
    """
    attempts: tuple[dict[str, Any], ...] = (
        {"capture_output": True, "text": True, "timeout": timeout, "check": False},
        {},
    )
    for kwargs in attempts:
        try:
            result = runner(argv, **kwargs)
        except TypeError:
            continue  # injected fake with a narrower signature -> try the next form
        except (OSError, subprocess.SubprocessError):
            return None
        if isinstance(result, str):
            return 0, result
        if result is None:
            return 0, ""
        rc = getattr(result, "returncode", 0)
        out = getattr(result, "stdout", "") or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return int(rc), str(out)
    return None


# --------------------------------------------------------------------------- #
# L1-L4 CPU topology probing
# --------------------------------------------------------------------------- #


def _classify_freq_classes(freqs: dict[int, int]) -> tuple[tuple[int, ...], tuple[int, ...], str]:
    """Bucket CPUs by max frequency into P/E classes.

    Returns ``(p_cpus, e_cpus, status)``:

    ``split``     two clearly separated classes (>= 10 % gap) — P is the fast one
    ``uniform``   a single class — homogeneous host, there are no E cores
    ``ambiguous`` several classes without a decisive gap — **do not guess**
    ``unknown``   no frequency information at all
    """
    if not freqs:
        return (), (), "unknown"
    values = sorted(set(freqs.values()))
    classes: list[list[int]] = [[values[0]]]
    for value in values[1:]:
        if value <= classes[-1][-1] * _FREQ_CLUSTER_RATIO:
            classes[-1].append(value)
        else:
            classes.append([value])
    if len(classes) == 1:
        return (), (), "uniform"
    top_min = min(classes[-1])
    below_max = max(classes[-2])
    if top_min < below_max * _FREQ_SPLIT_RATIO:
        return (), (), "ambiguous"
    fast = set(classes[-1])
    p_cpus = tuple(sorted(cpu for cpu, mhz in freqs.items() if mhz in fast))
    e_cpus = tuple(sorted(cpu for cpu, mhz in freqs.items() if mhz not in fast))
    return p_cpus, e_cpus, "split"


def _parse_cpuinfo(text: str) -> dict[str, Any]:
    """Best-effort counts (L3) out of ``/proc/cpuinfo``."""
    info: dict[str, Any] = {
        "logical": 0,
        "physical": 0,
        "sockets": 0,
        "vendor": None,
        "brand": None,
    }
    if not text:
        return info
    cores = {(pid, cid) for pid, cid in re.findall(r"physical id\s*:\s*(\d+).*?core id\s*:\s*(\d+)", text, re.S)}
    info["physical"] = len(cores)
    info["sockets"] = len({pid for pid, _ in cores})
    info["logical"] = len(re.findall(r"^processor\s*:", text, re.M))
    vendor = re.search(r"^vendor_id\s*:\s*(.+)$", text, re.M)
    if vendor:
        info["vendor"] = vendor.group(1).strip()
    brand = re.search(r"^model name\s*:\s*(.+)$", text, re.M)
    if brand:
        info["brand"] = brand.group(1).strip()
    if not info["physical"]:
        # Some architectures only report "cpu cores"; take the max seen.
        declared = [int(v) for v in re.findall(r"^cpu cores\s*:\s*(\d+)$", text, re.M)]
        info["physical"] = max(declared, default=0)
    if not info["sockets"]:
        declared = [int(v) for v in re.findall(r"^physical id\s*:\s*(\d+)$", text, re.M)]
        info["sockets"] = len(set(declared))
    return info


def _parse_lscpu_table(text: str) -> list[tuple[int, int, int, int, int | None]]:
    """Parse ``lscpu -e=CPU,CORE,SOCKET,NODE,MAXMHZ,ONLINE`` rows."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header = lines[0].split()
    if not header or header[0] != "CPU":
        return []
    index = {name: i for i, name in enumerate(header)}
    if any(name not in index for name in ("CPU", "CORE", "SOCKET", "NODE", "MAXMHZ")):
        return []
    rows: list[tuple[int, int, int, int, int | None]] = []
    for line in lines[1:]:
        cols = line.split()
        if len(cols) <= max(index.values()):
            continue
        try:
            cpu = int(cols[index["CPU"]])
            core = int(cols[index["CORE"]])
            socket = int(cols[index["SOCKET"]])
            node = int(cols[index["NODE"]])
        except ValueError:
            continue
        try:
            mhz: int | None = int(float(cols[index["MAXMHZ"]]))
        except ValueError:
            mhz = None  # lscpu prints blanks when the kernel hides frequencies
        rows.append((cpu, core, socket, node, mhz))
    return rows


def _parse_lscpu_kv(text: str) -> dict[str, Any]:
    """Parse the key/value form of plain ``lscpu`` (L4 counts, no per-CPU MHz)."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fields.setdefault(key.strip(), value.strip())

    def as_int(key: str) -> int:
        raw = fields.get(key, "")
        return int(raw) if _INT_RE.fullmatch(raw) else 0

    sockets = as_int("Socket(s)")
    per_socket = as_int("Core(s) per socket")
    online = fields.get("On-line CPU(s) list") or fields.get("On-line CPU(s) list(s)") or ""
    return {
        "logical": as_int("CPU(s)") or len(_parse_cpu_list(online)),
        "physical": sockets * per_socket,
        "sockets": sockets,
        "numa": as_int("NUMA node(s)"),
        "online": _parse_cpu_list(online) if online else (),
        "vendor": fields.get("Vendor ID") or fields.get("Vendor"),
        "brand": fields.get("Model name"),
    }


def _lscpu_info(runner: Runner) -> dict[str, Any]:
    """L4 fallback: ask ``lscpu`` for counts and per-CPU max frequency.

    The extended table is tried first because its ``MAXMHZ`` column is the only
    way to recover a P/E split when neither sysfs L1 nor cpufreq is available.
    """
    info: dict[str, Any] = {
        "logical": 0,
        "physical": 0,
        "sockets": 0,
        "numa": 0,
        "online": (),
        "vendor": None,
        "brand": None,
        "freqs": {},
    }
    run = _run_capture(["lscpu", "-e=CPU,CORE,SOCKET,NODE,MAXMHZ,ONLINE"], runner)
    if run is not None and run[0] == 0:
        rows = _parse_lscpu_table(run[1])
        if rows:
            info["logical"] = len(rows)
            info["physical"] = len({(sock, core) for _, core, sock, _, _ in rows})
            info["sockets"] = len({sock for _, _, sock, _, _ in rows})
            info["numa"] = len({node for _, _, _, node, _ in rows})
            info["online"] = tuple(sorted(cpu for cpu, *_ in rows))
            info["freqs"] = {cpu: mhz for cpu, _, _, _, mhz in rows if mhz}
            return info
    run = _run_capture(["lscpu"], runner)
    if run is None or run[0] != 0:
        return info
    info.update(_parse_lscpu_kv(run[1]))
    return info


def detect_cpu_topology(
    *,
    sys_root: str = "/sys",
    proc_root: str = "/proc",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Four-level host CPU probe (DESIGN §4.7 / 03 report §3.1).

    Levels, each one used only for what the previous ones could not answer:

    ===== ==========================================================
    L1    ``/sys/devices/cpu_core/cpus`` + ``cpu_atom/cpus`` → P/E sets
    L2    ``cpu*/topology/{core_id,physical_package_id,thread_siblings_list}``
          grouping + ``cpufreq/cpuinfo_max_freq`` clustering → physical cores
          and (when classes separate cleanly) P/E sets
    L3    ``/proc/cpuinfo`` counting (logical / physical / sockets / vendor)
    L4    ``lscpu`` fallback (counts and, via ``-e=…MAXMHZ``, P/E classes)
    ===== ==========================================================

    If no level can identify P/E classes the returned ``p_cpus``/``e_cpus`` are
    **empty** and profiles degrade to "no binding" — macopt never guesses CPU
    numbers.
    """
    notes: list[str] = []
    cpu_dir = os.path.join(sys_root, "devices", "system", "cpu")
    node_dir = os.path.join(sys_root, "devices", "system", "node")

    # -- L1: Intel hybrid P/E sets ---------------------------------------- #
    core_raw = _read_text(os.path.join(sys_root, "devices", "cpu_core", "cpus"))
    atom_raw = _read_text(os.path.join(sys_root, "devices", "cpu_atom", "cpus"))
    p_cpus: tuple[int, ...] = ()
    e_cpus: tuple[int, ...] = ()
    p_e_source: str | None = None
    if core_raw is not None and atom_raw is not None:
        candidate_p = _parse_cpu_list(core_raw)
        candidate_e = _parse_cpu_list(atom_raw)
        if candidate_p and candidate_e:
            p_cpus, e_cpus, p_e_source = candidate_p, candidate_e, "L1"
        else:
            notes.append("L1 cpu_core/cpu_atom present but unparseable -> ignored (no guessing)")
    else:
        notes.append("L1 (/sys/devices/cpu_core/cpus, cpu_atom/cpus) not available on this host")

    # -- online logical CPUs (sysfs) --------------------------------------- #
    online = _parse_cpu_list(_read_text(os.path.join(cpu_dir, "online")) or "")
    count_source = "sysfs" if online else None
    if not online:
        ids = [
            int(os.path.basename(path)[3:])
            for path in glob.glob(os.path.join(cpu_dir, "cpu[0-9]*"))
            if _INT_RE.fullmatch(os.path.basename(path)[3:])
        ]
        if ids:
            online = tuple(sorted(ids))
            count_source = "sysfs"

    # -- L2: physical core groups + per-CPU max frequency ------------------ #
    groups: dict[tuple[Any, ...], set[int]] = {}
    packages: set[int] = set()
    freqs: dict[int, int] = {}  # cpu -> MHz, from cpuinfo_max_freq (kHz / 1000)
    for cpu in online:
        base = os.path.join(cpu_dir, f"cpu{cpu}")
        core_id = _read_int(os.path.join(base, "topology", "core_id"))
        package = _read_int(os.path.join(base, "topology", "physical_package_id"))
        siblings = _parse_cpu_list(
            _read_text(os.path.join(base, "topology", "thread_siblings_list")) or ""
        )
        if core_id is not None:
            key: tuple[Any, ...] = ("core", package if package is not None else 0, core_id)
            if package is not None:
                packages.add(package)
        elif siblings:
            key = ("sib", siblings[0])
        else:
            key = ()  # no usable topology files for this CPU
        if key:
            groups.setdefault(key, set()).update(siblings or {cpu})
        khz = _read_int(os.path.join(base, "cpufreq", "cpuinfo_max_freq"))
        if khz:
            freqs[cpu] = khz // 1000

    core_groups = tuple(
        tuple(sorted(member)) for member in sorted(groups.values(), key=min)
    )
    physical_sysfs = len(core_groups)
    sockets_sysfs = len(packages)

    node_ids = [
        os.path.basename(path)
        for path in glob.glob(os.path.join(node_dir, "node[0-9]*"))
        if _INT_RE.fullmatch(os.path.basename(path)[4:])
    ]
    numa_sysfs = len(node_ids)

    # -- L2 P/E classification by frequency classes ------------------------ #
    freq_status = "unknown"
    if p_e_source is None:
        p_cpus, e_cpus, freq_status = _classify_freq_classes(freqs)
        if freq_status == "split":
            p_e_source = "L2"
        elif freq_status == "uniform":
            notes.append("single frequency class across all CPUs -> homogeneous host (no E cores)")
        elif freq_status == "ambiguous":
            notes.append(
                "frequency classes ambiguous (gap below the 10% split threshold) -> P/E unknown"
            )

    # -- L3: /proc/cpuinfo counting ---------------------------------------- #
    cpuinfo = _parse_cpuinfo(_read_text(os.path.join(proc_root, "cpuinfo")) or "")
    logical = len(online)
    if not logical and cpuinfo["logical"]:
        logical = cpuinfo["logical"]
        count_source = "cpuinfo"
    physical = physical_sysfs or cpuinfo["physical"]
    sockets = sockets_sysfs or cpuinfo["sockets"]
    vendor = cpuinfo["vendor"]
    brand = cpuinfo["brand"]
    numa = numa_sysfs

    # -- L4: lscpu fallback (only for what is still missing) --------------- #
    need_lscpu = (
        not logical
        or not physical
        or (p_e_source is None and freq_status != "uniform")
    )
    lscpu = _lscpu_info(runner) if need_lscpu else {}
    if lscpu:
        # lscpu's MAXMHZ column is a second (independent) frequency source;
        # sysfs wins when both exist.
        for cpu, mhz in lscpu["freqs"].items():
            freqs.setdefault(cpu, mhz)
        if not logical and lscpu["logical"]:
            logical = lscpu["logical"]
            count_source = "lscpu"
        if not physical and lscpu["physical"]:
            physical = lscpu["physical"]
            if count_source is None:
                count_source = "lscpu"
        sockets = sockets or lscpu["sockets"]
        numa = numa or lscpu["numa"]
        vendor = vendor or lscpu["vendor"]
        brand = brand or lscpu["brand"]
        if p_e_source is None and lscpu["freqs"]:
            lscpu_p, lscpu_e, lscpu_status = _classify_freq_classes(lscpu["freqs"])
            if lscpu_status == "split":
                p_cpus, e_cpus, p_e_source = lscpu_p, lscpu_e, "lscpu"
            elif lscpu_status == "uniform" and freq_status == "unknown":
                freq_status = "uniform"
                notes.append("lscpu reports one frequency class -> homogeneous host (no E cores)")

    if not p_cpus and not e_cpus:
        notes.append("P/E classes unknown or homogeneous -> profiles degrade to 'no CPU binding'")

    def _max_freq(cpus: tuple[int, ...]) -> int | None:
        seen = [freqs[cpu] for cpu in cpus if cpu in freqs]
        return max(seen) if seen else None

    return {
        "vendor": vendor,
        "brand": brand,
        "logical_cpus": logical,
        "online_cpus": tuple(online or lscpu.get("online") or ()),
        "physical_cores": physical,
        "sockets": sockets or 1,
        "numa_nodes": max(1, numa),
        "hybrid": bool(p_cpus and e_cpus),
        "p_cpus": p_cpus,
        "e_cpus": e_cpus,
        "freq_mhz_p": _max_freq(p_cpus),
        "freq_mhz_e": _max_freq(e_cpus),
        "core_groups": core_groups,
        "p_e_source": p_e_source,
        "count_source": count_source,
        "tsc_hz": detect_tsc(sys_root=sys_root),
        "notes": tuple(notes),
    }


# --------------------------------------------------------------------------- #
# cgroup v2 / cpuset delegation
# --------------------------------------------------------------------------- #


def detect_cgroup(*, sys_root: str = "/sys") -> dict[str, Any]:
    """Report cpuset availability for system and user (systemd --user) scopes.

    The measured failure this feeds (03 report line 223, DESIGN line 323):
    ``systemd-run --user --scope -p AllowedCPUs=...`` returns rc=0 but the
    process keeps its full ``Cpus_allowed_list`` whenever the ``cpuset``
    controller is not delegated to ``user@.service``. ``plan()`` therefore
    offers the *system* scope first, and ``check()`` only ever reads
    ``/proc/<pid>/status`` — ``systemctl show -p EffectiveCPUs`` came back empty
    on the reference host (DESIGN line 324).
    """
    root = os.path.join(sys_root, "fs", "cgroup")
    root_controllers_raw = _read_text(os.path.join(root, "cgroup.controllers"))
    unified = root_controllers_raw is not None
    root_controllers = _split_words(root_controllers_raw)
    root_subtree = _split_words(_read_text(os.path.join(root, "cgroup.subtree_control")))

    user_unit: str | None = None
    user_controllers: tuple[str, ...] = ()
    user_subtree: tuple[str, ...] = ()
    candidates = sorted(
        glob.glob(os.path.join(root, "user.slice", "user-*.slice", "user@*.service"))
    )
    if candidates:
        user_unit = candidates[0]
        user_controllers = _split_words(_read_text(os.path.join(user_unit, "cgroup.controllers")))
        user_subtree = _split_words(
            _read_text(os.path.join(user_unit, "cgroup.subtree_control"))
        )

    delegated: bool | None = None
    if user_unit is not None:
        delegated = "cpuset" in user_controllers
    return {
        "root": root,
        "version": 2 if unified else None,
        "unified": unified,
        "root_controllers": root_controllers,
        "root_subtree_control": root_subtree,
        "root_cpuset_enabled": "cpuset" in root_subtree,
        "user_unit": user_unit,
        "user_controllers": user_controllers,
        "user_subtree_control": user_subtree,
        "user_cpuset_delegated": delegated,
    }


# --------------------------------------------------------------------------- #
# VMware and TSC
# --------------------------------------------------------------------------- #


def detect_vmware(*, runner: Runner = subprocess.run) -> dict[str, str]:
    """``vmware --version`` -> ``{"version": ..., "build": ...}`` (or ``{}``).

    Whitelisted read-only subprocess (DESIGN §7.9), never a shell, and never
    raises: a host without VMware is ``{}``, not an error (DESIGN §4.1: that
    machine simply may not have it installed).
    """
    run = _run_capture(["vmware", "--version"], runner, timeout=30)
    if run is None or run[0] != 0:
        return {}
    match = re.search(r"(\d+\.\d+\.\d+)\s+(?:build[-\s])?(\d+)", run[1])
    if not match:
        return {}
    return {"version": match.group(1), "build": match.group(2)}


def detect_tsc(*, sys_root: str = "/sys") -> int | None:
    """TSC frequency in Hz from sysfs, or ``None`` — never a guess.

    There is no mainline sysfs file for the TSC frequency on most kernels
    (the reference host has none), so ``None`` is the normal answer. We
    deliberately do **not** fall back to ``/proc/cpuinfo`` "cpu MHz" or to
    cpufreq limits: those are core clocks (reference host: 4641 MHz / 4900 MHz)
    while the invariant TSC actually runs at 2918.4 MHz (03 report §0,
    cross-checked against ``VMMon_GetkHzEstimate``).
    """
    pattern = os.path.join(sys_root, "devices", "system", "cpu", "cpu*", "tsc_freq_khz")
    for path in sorted(glob.glob(pattern)):
        raw = _read_text(path)
        if raw is None:
            continue
        try:
            khz = int(raw.strip())
        except ValueError:
            continue
        hz = khz * 1000
        if _TSC_HZ_MIN <= hz <= _TSC_HZ_MAX:
            return hz
    return None


def _kernel_release(proc_root: str) -> str | None:
    raw = _read_text(os.path.join(proc_root, "version"))
    if not raw:
        return None
    parts = raw.split()
    # "Linux version <release> (build) ..."
    return parts[2] if len(parts) > 2 and parts[0] == "Linux" and parts[1] == "version" else None


# --------------------------------------------------------------------------- #
# one-shot detection
# --------------------------------------------------------------------------- #


def detect(
    *,
    sys_root: str = "/sys",
    proc_root: str = "/proc",
    runner: Runner = subprocess.run,
) -> HostInfo:
    """Populate a :class:`~macopt.model.HostInfo` in one call.

    Filled here: vendor/brand, CPU counts, P/E sets, NUMA, TSC, VMware
    version/build, kernel release, cpuset delegation. Deliberately left as
    ``None`` for the modules that own them: ``unlocker_state`` (unlocker.py),
    ``vmware_build_tag`` (doctor.py reads vixwrapper-product-config.txt) and
    ``systemd_version`` (doctor.py runs ``systemctl --version``).
    """
    topo = detect_cpu_topology(sys_root=sys_root, proc_root=proc_root, runner=runner)
    cgroup = detect_cgroup(sys_root=sys_root)
    vmware = detect_vmware(runner=runner)
    notes = list(topo["notes"])

    delegated = cgroup.get("user_cpuset_delegated")
    if delegated is False:
        notes.append(
            "cpuset is NOT delegated to user@.service: `systemd-run --user --scope "
            "-p AllowedCPUs=...` would silently no-op (rc=0, affinity unchanged); "
            "use the system-level scope from `macopt schedule plan` and verify via "
            "/proc/<pid>/status only"
        )
    elif delegated is True:
        notes.append(
            "cpuset is delegated to user@.service; user scopes may set AllowedCPUs, "
            "but verification must still read /proc/<pid>/status"
        )

    return HostInfo(
        vendor=topo["vendor"],
        brand=topo["brand"],
        logical_cpus=topo["logical_cpus"],
        physical_cores=topo["physical_cores"],
        numa_nodes=topo["numa_nodes"],
        hybrid=topo["hybrid"],
        p_cpus=topo["p_cpus"],
        e_cpus=topo["e_cpus"],
        freq_mhz_p=topo["freq_mhz_p"],
        freq_mhz_e=topo["freq_mhz_e"],
        tsc_hz=detect_tsc(sys_root=sys_root),
        vmware_version=vmware.get("version"),
        vmware_build=vmware.get("build"),
        unlocker_state=None,  # owned by macopt.unlocker
        kernel=_kernel_release(proc_root),
        systemd_version=None,  # owned by macopt.doctor (systemctl --version)
        user_cpuset_delegated=delegated if isinstance(delegated, bool) else None,
        notes=tuple(notes),
    )

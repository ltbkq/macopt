# macopt

[![ci](https://github.com/ltbkq/macopt/actions/workflows/ci.yml/badge.svg)](https://github.com/ltbkq/macopt/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-%E3%89%A53.11-blue.svg)](pyproject.toml)

**Audited, verifiable optimization for VMware Workstation macOS guests on Linux.**

macopt rewrites a guest's `.vmx` from *evidence-labelled* profiles, guards the
known foot-guns (CPUID masking, SMBIOS reflection), schedules host CPUs for
hybrid Intel/AMD systems, and — most importantly — **proves the change took
effect** by parsing the hypervisor's own boot log.

> **README in other languages:** [中文](README.zh-CN.md)

---

## Why this exists

Getting a macOS guest running on a Linux host takes two separate steps:

| Step | Owner |
|---|---|
| Make Workstation accept `darwin*-64` + Apple SMC | **[Unlocker](https://github.com/paolo-projects/unlocker)** (binary patching) |
| Everything after it boots: topology, scheduling, clock, identity, verification | **macopt** |

A v2.0 feature draft for this project went through a four-way review; it had
ten factual errors (non-existent configuration keys, a wrong preferences path,
a fragile "string offset" detector) and it never addressed the thing Intel
hosts actually need — CPU topology and scheduling. Those findings are
preserved as [review evidence](docs/evidence/00-review.md) and are the reason
every parameter in this tool ships with provenance.

macopt **never modifies VMware binaries** — that remains Unlocker's job.

## Features

- **`macopt doctor`** — one-shot environment report: host CPU topology (P/E
  cores), VMware build, Unlocker state, config-layer inventory.
- **`macopt check`** — read-only static analysis of a `.vmx` (S1–S10): stale
  `guestOS`, vCPU over-subscription, split vNUMA, nested-virtualization,
  mutually exclusive identity keys, unknown keys.
- **`macopt apply`** — profile-driven, **idempotent**, **transactional**
  writes with `--dry-run`, a key whitelist, and confirmation gates.
- **`macopt verify`** — V0–V10 assertions read from `vmware.log`. Missing log
  lines degrade to `SKIP`, never to `FAIL`, so the result stays honest.
- **`macopt restore`** — timestamped backups with double hashing, plus
  `--list` / `--diff` / `--verify` / `--prune`.
- **`macopt unlocker-status`** — five states (`PATCHED`, `UNPATCHED`,
  `UNKNOWN`, `UNKNOWN-MODIFIED`, `DAMAGED`) derived from backup hashes rather
  than fragile string offsets.
- **`macopt keyscan`** — whitelist built by read-only scanning of the
  installed binaries; unknown keys are refused by default because a typo'd
  `.vmx` key fails *silently*.
- **`macopt detect-cpu` / `macopt schedule`** — hybrid P/E detection with
  four-level fallback, plus affinity planning and verification.

## Requirements

- Linux with VMware Workstation **26.x** (25.x should work; tested on 26.0.1)
- Python **≥ 3.11** (standard library only — no runtime dependencies)
- A macOS guest already unlocked by [Unlocker](https://github.com/paolo-projects/unlocker)
  (macopt detects its state; it does not install or replace it)

## Install

```bash
# from a checkout
python3 -m pip install .

# or run it straight from the source tree, no install step
bin/macopt --help
```

## Quick start

```bash
macopt doctor                 # what am I on, and is the Unlocker present?
macopt check    ~/VMs/macOS   # read-only: what looks wrong?
macopt apply    ~/VMs/macOS --dry-run     # show the plan, change nothing
macopt apply    ~/VMs/macOS               # back up, write, verify round-trip
macopt verify   ~/VMs/macOS               # boot the guest, then: did it take?
macopt restore  ~/VMs/macOS --list        # and --diff / --to <id> to roll back
```

> `.vmx` files are only read at power-on: shut the VM down (not suspended)
> and close the VMware GUI before `apply`. macopt enforces this and exits `3`
> if the guest is running.

## Safety model

| Guarantee | How |
|---|---|
| Write boundary | only `<guest>.vmx`, opt-in `~/.vmware/preferences`, and macopt's own state dir |
| No binary patching | VMware install tree is only `stat`ed, hashed and scanned read-only |
| No silent typos | keys must exist in the whitelist or the write is refused (exit `6`) |
| No surprise writes | `--dry-run` first; overwriting an existing value needs confirmation (exit `5`) |
| Always reversible | every write is preceded by a timestamped, hash-verified backup |
| Never guesses | undetectable state is reported `UNKNOWN` (exit `4`), never a fabricated answer |
| No network | the tool never opens a socket (enforced in CI) |

**Exit codes:** `0` ok · `1` failed/verification FAIL · `2` usage · `3`
precondition (VM running) · `4` unknown state · `5` needs confirmation ·
`6` key refused.

## CPUID guardrails

CPUID masking is where guests stop booting. macopt treats it as hazardous by
default:

- profiles are **opt-in** (`--cpuid-profile …`), default is none;
- `cpuid.1.ebx` with a literal value is **blocked** — it pins the APIC ID and
  thread topology onto every vCPU;
- clearing `SS` (bit 27) is **blocked** — `darwin*-64` requires `cpuid.ss:Min:1`;
- bit positions, mask semantics ("per-bit override, not AND") and the fact
  that Workstation applies its own built-in Darwin masks are documented in
  [the design](docs/DESIGN.md#48-cpuid--cpu_id-伪装模块高风险opt-in带规则引擎).

See [docs/evidence/02-cpuid-review.md](docs/evidence/02-cpuid-review.md) for
the full analysis, and the T1–T8 open experiments before treating any mask as
production-ready.

## Documentation

| Document | Contents |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | Full design (v2.1): architecture, module contracts, algorithms, risks, acceptance |
| [docs/evidence/](docs/evidence/) | Sanitized review evidence behind every claim |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Project status

Alpha. The read path (`doctor`, `check`, `unlocker-status`, `verify`) and the
write path (`apply`, `restore`) are implemented with tests; results for the
AMD-host scenario (acceptance **A**) and the CPUID experiments **T1–T8**
require hardware we do not have and are tracked as explicit TODOs in
[the design](docs/DESIGN.md).

## Contributing

```bash
python -m pip install -e ".[dev]"
ruff check src tests scripts
python -m unittest discover -s tests -v
python scripts/secret_scan.py .          # no credentials, ever
python scripts/sanitize_evidence.py --check
```

Before opening a PR:

1. every new `Param` needs an `Evidence` reference — unattributed assertions
   are rejected by tests;
2. fixtures derived from your own `vmware.log` go through
   `scripts/make_fixtures.py` (git-ignored output) and
   `scripts/sanitize_evidence.py`;
3. never commit machine paths, hostnames, serials, MACs or credentials — CI
   scans for them.

## Legal

- MIT licensed (see [LICENSE](LICENSE)).
- VMware Workstation and macOS are subject to their own licenses. Apple's
  license permits macOS virtualization **on Apple hardware**; make sure your
  setup complies with the applicable terms. This project does not distribute
  VMware code, macOS images, serials or SMBIOS credentials.
- The Unlocker is a separate third-party project with its own license.

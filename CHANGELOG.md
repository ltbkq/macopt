# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Detailed design document (`docs/DESIGN.md`, v2.1) superseding the external
  v2.0 draft: ten fact corrections, a rewritten CPUID chapter, a new CPU
  topology/scheduling chapter, a five-state Unlocker detector, runtime
  verification (V0–V10) and revised acceptance criteria (A–I).
- Sanitized review evidence under `docs/evidence/`.
- `macopt doctor` — environment self-check (host CPU, VMware build, Unlocker
  state, config layer inventory).
- `macopt check` — read-only static analysis of a `.vmx` (S1–S10).
- `macopt apply` — profile-driven, idempotent, transactional `.vmx` writer
  with dry-run, key whitelist and confirmation gates.
- `macopt verify` — runtime verification driven by the hypervisor's own boot
  log; missing log lines degrade to `SKIP`, never `FAIL`.
- `macopt restore` / backups — timestamped manifests with double hashing,
  `--list` / `--diff` / `--verify` / `--prune`.
- `macopt unlocker-status` — five-state detection
  (`PATCHED` / `UNPATCHED` / `UNKNOWN` / `UNKNOWN-MODIFIED` / `DAMAGED`)
  based on backup hashes instead of string offsets.
- `macopt keyscan` — runtime key whitelist built by read-only scanning of the
  installed VMware binaries.
- `macopt detect-cpu` and `macopt schedule` — hybrid P/E topology detection
  and host-side CPU affinity planning/checking.
- Sanitization and secret-scan pipelines for evidence and fixtures.
- Repository compliance gates (`scripts/secret_scan.py`,
  `scripts/sanitize_evidence.py --check`, `scripts/guardrails.py`) with their
  own tests in `tests/test_scripts.py`, all blocking in CI.

### Fixed

- **`.vmx` write corruption (contract layer).** `Document.delete()` did not
  renumber the `Entry.lineno` values stored for entries *below* the closed
  gap, so a later `set()` could write its value onto a **neighbouring key's**
  line. `apply --module topology,guestos` reproduced it by turning the
  untouched `vpmc.enable` line into a second `vhv.enable`. `delete()` now
  renumbers bottom-up, and `writer` verifies the **whole document** on
  read-back (every key plus the duplicate-key structure), not only the keys
  the plan touched. Covered by `tests/test_vmxfile.py` and
  `tests/test_apply_e2e.py`.
- **CPUID leaf 1 ECX bit numbers.** `docs/DESIGN.md` §12.1, `profiles/cpuid.py`
  and `verify/assertions.py` V4 all shipped `SSE42=0, POPCNT=1, AES=20`; the
  Intel SDM puts them at 20, 23 and 25. V4 was therefore reading SSE3 as
  SSE4.2 and SSE4.2 as AES, hidden by the fact that the reference value
  `0xf7fa322b` has bits 0/20/25 all set. All three now follow the SDM and are
  pinned by tests; the erratum is recorded in §12.1.
- **Unreachable profile flags.** `--cpuid-profile` and `--identity` parsed
  successfully but did nothing, because the owning module never entered
  `opts.modules`. Each flag now pulls in its module, and `--board-id`,
  `--hw-model`, `--serial` and repeatable `--extra KEY=VALUE` were added so
  the `identity` and `signed-brand` profiles can actually be driven.
- **`keyscan` performance.** A full whitelist scan cost ~6 s on every run.
  Results are now cached in `state/keycache.json` keyed by
  `(path, size, mtime, sha256[:16])` per DESIGN §4.5: warm lookups take ~7 ms
  and a byte-level change still forces a rescan.
- **Over-eager guard rails.** `scripts/guardrails.py` flagged read-only
  mentions of VMware paths and documentation that names a non-existent key.
  It now fires only on a genuine write (protected path + write token) or on a
  `Param`/`Change` actually built from such a key, decided by AST rather than
  text, and is proven by positive *and* negative tests.
- **Home-path redaction.** `scripts/sanitize_evidence.py` only matched a home
  path when a `/` followed it, so a value ending a line escaped redaction.

[Unreleased]: https://github.com/ltbkq/macopt/compare/HEAD...HEAD

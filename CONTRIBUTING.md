# Contributing to macopt

Thanks for helping. This project grew out of a code review that rejected
unattributed claims, so the bar for a change is not just "it works" — it is
"you can show where the behaviour comes from".

## Development setup

```bash
git clone https://github.com/ltbkq/macopt.git
cd macopt
python3 -m pip install -e ".[dev]"     # dev extras: pytest, ruff
```

Zero runtime dependencies: Python ≥ 3.11 and the standard library is enough to
*run* the tool (`bin/macopt --help`).

## Checks before a PR

```bash
ruff check src tests scripts
python -m unittest discover -s tests -v
python scripts/secret_scan.py .
python scripts/sanitize_evidence.py --check
python scripts/guardrails.py
```

CI runs the same set on Python 3.11/3.12/3.13.

## Rules of the road

1. **Every configuration parameter needs evidence.** A `Param` built without
   an `Evidence` reference fails the contract tests. Use one of
   `log` / `binary` / `sysfs` / `file` / `doc` / `measured` / `community`
   and point at the source (a log line number, a binary string, a KB article).
   Community wisdom must say so — and, where it is untested here, the change
   must also land in the T1–T8 open-experiment table in
   [docs/DESIGN.md](docs/DESIGN.md).
2. **Never write outside the write boundary.** macopt may write only the
   target `.vmx`, the opt-in `~/.vmware/preferences`, and its own state
   directory. `scripts/guardrails.py` fails the build otherwise.
3. **Never touch VMware binaries.** Read, hash and scan them — that's it.
   Binary patching belongs to the Unlocker.
4. **Missing evidence is `SKIP`, not `FAIL`.** "We didn't see it" is not
   "it's broken". The verifier must stay honest.
5. **No credentials, ever.** Not in code, fixtures, docs, commit messages or
   CI logs. `scripts/secret_scan.py` runs in CI and blocks merges.
6. **Sanitize before committing.** Fixtures derived from a real
   `vmware.log` go through `scripts/make_fixtures.py` (writes to a
   git-ignored directory) and `scripts/sanitize_evidence.py`.
7. **Tests must be hermetic.** Write only into `tempfile.TemporaryDirectory()`.
   A test that touches `/usr/lib/vmware`, `~/.vmware` or a real VM directory
   is a bug.

## Architecture in one paragraph

`model` / `vmxfile` / `errors` / `context` are the frozen contract layer.
Profiles (`profiles/*`, `guestos.py`) are pure functions from
`(mapping, HostInfo, ProfileOptions)` to `Param`s with provenance.
`keys.py` builds the whitelist, `writer.py` turns a `Plan` into an atomic
write, `backup.py` makes it reversible, `check.py` reads it back statically,
and `verify/` proves it took effect against the hypervisor's own log.
Dependencies point downward only; a unit test enforces it.

## Reporting bugs

Include:

- `macopt doctor --json`
- `macopt check <guest> --json`
- the `.vmx` **with identifiers removed** (serials, MACs, UUIDs, paths)
- the `guest vs. host CPUID` block from `vmware.log`, if the bug involves
  CPUID

## License

By contributing you agree your work is distributed under the MIT License.

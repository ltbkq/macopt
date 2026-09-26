# Review evidence (sanitized)

These documents are the four-way review of the original v2.0 feature draft,
plus the consolidated verdict. `docs/DESIGN.md` is the direct descendant of
that verdict: every correction in the table below is implemented there.
`06-local-verification.md` is the later one: what the shipped tool actually
did on a real host, and the four defects that run exposed.

| File | Scope |
|---|---|
| `00-review.md` | Consolidated verdict: feasibility by layer, P0 corrections, high-risk technical points, missing modules, acceptance and engineering changes |
| `01-factcheck.md` | Paths, configuration keys, version strings, README claims |
| `02-cpuid-review.md` | CPUID masking mechanism, bit numbering, risk analysis, T1–T8 |
| `03-cpu-tuning-module.md` | The missing CPU topology / scheduling / clock chapter (24-row parameter table) |
| `04-verify-acceptance.md` | Five-state Unlocker detection, `verify` V0–V10, acceptance A–I, engineering checklist |
| `06-local-verification.md` | Post-release run on a real host: read-only suite (`doctor` / `unlocker-status` / `detect-cpu` / `check` / `verify` / `keyscan` / `schedule plan`), byte-exact reversibility on a copy of a real `.vmx`, and the four defects that run found |

## Sanitization

Everything here has been passed through
[`scripts/sanitize_evidence.py`](../../scripts/sanitize_evidence.py), which
replaces personal paths, the account name, mount points, VM/ISO display names,
MAC addresses, UUIDs, serials and OEM DMI strings with stable placeholders.

That script is **idempotent**, and CI enforces it:

```bash
python scripts/sanitize_evidence.py --check    # fails if anything is un-redacted
python scripts/secret_scan.py .                # fails if anything looks like a credential
```

Placeholders such as `<user>`, `<vm-name>` and `<mnt/media>` are intentional —
line numbers and quoted outputs survive so the claims stay checkable, while
the machine's identity does not ship.

To reproduce the sanitization locally from your own copy:

```bash
python scripts/sanitize_evidence.py --src /path/to/raw-reports --dst ./out
```

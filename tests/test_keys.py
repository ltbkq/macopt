"""Unit tests for the ``.vmx`` key whitelist (DESIGN §4.5).

Covers the four things the whitelist must get right:

* **expansion** — ``cpuid.<leaf>[.<subleaf>].<reg>[.amd]`` from the binary's own
  format strings, and the ``%d``/``%u``/``%s`` seed patterns;
* **seed** — ``data/known_keys.txt`` is curated, sourced and readable;
* **unknown rejection** — the keys that do not exist in any installed VMware
  binary must never be accepted (the F3 failure mode);
* **scan** — read-only, process-free extraction from binaries, tolerant of
  garbage input.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from macopt import keys

# Keys macopt itself writes (DESIGN §4.5: the seed must cover all of them).
MACOPT_WRITES = (
    "numvcpus",
    "cpuid.coresPerSocket",
    "guestOS",
    "mks.enable3d",
    "svga.maxTextureSize",
    "tools.syncTime",
    "hpet0.present",
    "vhv.enable",
    "smc.version",
    "board-id",
    "board-id.reflectHost",
    "hw.model",
    "serialNumber",
    "efi.nvram.var.ROM",
    "efi.nvram.var.MLB",
    "cpuid.brandString",
    "cpuid.family",
    "cpuid.inhibitDarwinMasks",
    "hypervisor.cpuid.v0",
    "ethernet0.virtualDev",  # via ethernet%d.virtualDev
)

#: Verified **absent** from every binary under /usr/lib/vmware
#: (docs/evidence/01-factcheck.md §3.1 + re-checks while curating the seed).
KNOWN_NONEXISTENT = (
    "mks.g3d.maxTextureSize",
    "mks.enableGLRenderer",
    "vmotion.svga.maxTextureSize",
    "monitor_control.enable_fullcpuid",
    "tools.afterPowerOn",
)


class ExpandableCpuidKeyTests(unittest.TestCase):
    """Rule ①: the format strings ``cpuid.%x.%s`` / ``cpuid.%x.%x.%s[.amd]``."""

    def test_leaf_reg_forms_expand(self) -> None:
        for key in (
            "cpuid.0.eax",
            "cpuid.1.edx",
            "cpuid.7.0.ebx",
            "cpuid.80000001.ecx",
            "cpuid.1.eax.amd",
            "cpuid.7.0.edx.amd",
        ):
            with self.subTest(key=key):
                self.assertTrue(keys.expandable_cpuid_key(key))

    def test_flat_leaf_form_expands(self) -> None:
        # the binary also stores the flat spelling `cpuid.0` / `cpuid.1`
        self.assertTrue(keys.expandable_cpuid_key("cpuid.0"))
        self.assertTrue(keys.expandable_cpuid_key("cpuid.80000000"))

    def test_register_name_is_case_insensitive_but_must_be_a_register(self) -> None:
        self.assertTrue(keys.expandable_cpuid_key("cpuid.1.EAX"))
        for bad in ("cpuid.1.qqq", "cpuid.1.eaxx", "cpuid.notaleaf", "cpuid.zz.eax"):
            with self.subTest(key=bad):
                self.assertFalse(keys.expandable_cpuid_key(bad))

    def test_malformed_leaves_do_not_expand(self) -> None:
        for bad in ("cpuid.", "cpuid", "cpuid.0x1.eax", "cpuid.1.0.0.eax", "cpuid.-1.eax"):
            with self.subTest(key=bad):
                self.assertFalse(keys.expandable_cpuid_key(bad))

    def test_non_cpuid_keys_never_go_down_this_path(self) -> None:
        self.assertFalse(keys.expandable_cpuid_key("numvcpus"))
        self.assertFalse(keys.expandable_cpuid_key(""))


class SeedTests(unittest.TestCase):
    def test_seed_loads_and_is_non_empty(self) -> None:
        seed = keys.load_seed()
        self.assertIsInstance(seed, set)
        self.assertGreater(len(seed), 150)

    def test_seed_covers_every_key_macopt_writes(self) -> None:
        for key in MACOPT_WRITES:
            with self.subTest(key=key):
                self.assertTrue(keys.is_known(key), f"{key} missing from the whitelist")

    def test_seed_file_is_sourced_per_section(self) -> None:
        text = keys.SEED_FILE.read_text(encoding="utf-8")
        sections = [ln for ln in text.splitlines() if ln.startswith("# source:")]
        self.assertGreaterEqual(len(sections), 5, "every section needs a # source: comment")
        self.assertIn("# NEVER paste a `strings` dump", text)

    def test_seed_has_no_duplicate_entries(self) -> None:
        entries = [
            ln.split("#", 1)[0].strip()
            for ln in keys.SEED_FILE.read_text(encoding="utf-8").splitlines()
        ]
        entries = [e for e in entries if e]
        self.assertEqual(len(entries), len(set(entries)), "duplicate seed entries")

    def test_nonexistent_keys_are_documented_but_not_whitelisted(self) -> None:
        text = keys.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("Known NON-EXISTENT keys", text)
        # machine-readable, not just prose: every documented key must be in
        # the parsed deny-list or nothing would enforce the comment
        denied = keys.load_nonexistent()
        self.assertGreaterEqual(len(denied), len(KNOWN_NONEXISTENT))
        for key in KNOWN_NONEXISTENT:
            with self.subTest(key=key):
                self.assertNotIn(key, keys.load_seed())
                self.assertFalse(keys.is_known(key))

    def test_deny_list_beats_a_matching_scan_pattern(self) -> None:
        # Found on a real host: the installed binary carries the broad pattern
        # `vmotion.%s`, which matched the *unproven*
        # `vmotion.svga.maxTextureSize` and made is_known() answer True — the
        # seed file was declaring it non-existent while the code admitted it.
        extra = {"vmotion.%s", "monitor_control.%s", "tools.%s"}
        for key in keys.load_nonexistent():
            with self.subTest(key=key):
                self.assertFalse(
                    keys.is_known(key, extra=extra),
                    f"{key} leaked through the deny-list via a scanned pattern",
                )
        # ...while the very same pattern must still admit a legitimate key
        self.assertTrue(keys.is_known("vmotion.checkpointFBSize", extra=extra))

    def test_keys_vmware_writes_itself_are_whitelisted(self) -> None:
        # Workstation emits these into every stock `.vmx`; they are assembled
        # from format fragments inside the GUI, so no binary scan produces
        # them as one token. Before they were curated in, an untouched VM
        # reported 26 "keys outside the whitelist" (S10 false positive).
        for key in (
            "pciBridge0.pciSlotNumber",
            "pciBridge7.pciSlotNumber",
            "usb_xhci:4.present",
            "usb_xhci:6.deviceType",
            "usb_xhci:7.speed",
            "usb_xhci:7.parent",
            "sata0:0.redo",
            "sata0:2.redo",
            "scsi0:0.redo",
            "ide0:0.redo",
            "nvram",
            "extendedConfigFile",
            "softPowerOff",
        ):
            with self.subTest(key=key):
                self.assertTrue(keys.is_known(key), f"{key} missing from the whitelist")


class IsKnownTests(unittest.TestCase):
    def test_known_keys(self) -> None:
        for key in (
            "numvcpus",
            "guestOS",
            "displayName",
            "scsi0:0.present",
            "sata0:1.fileName",
            "ethernet0.virtualDev",
            "ethernet7.addressType",
            "guestinfo.ip",
            "smc.version",
            "cpuid.SS",
            "cpuid.1.eax",
            "cpuid.80000001.edx.amd",
        ):
            with self.subTest(key=key):
                self.assertTrue(keys.is_known(key))

    def test_unknown_keys_are_rejected(self) -> None:
        for key in KNOWN_NONEXISTENT + (
            "cpuid.ss",  # lower-case community spelling: T5 still open
            "cpuid.1.qqq",
            "cpuid.notaleaf",
            "definitely.not.a.real.key",
            "some.random.garbage.key",
        ):
            with self.subTest(key=key):
                self.assertFalse(keys.is_known(key))

    def test_empty_and_non_string_are_rejected(self) -> None:
        self.assertFalse(keys.is_known(""))
        self.assertFalse(keys.is_known(None))  # type: ignore[arg-type]
        self.assertFalse(keys.is_known(42))  # type: ignore[arg-type]

    def test_extra_set_is_honoured(self) -> None:
        self.assertFalse(keys.is_known("site.specific.key"))
        self.assertTrue(keys.is_known("site.specific.key", extra={"site.specific.key"}))

    def test_extra_patterns_are_honoured(self) -> None:
        self.assertTrue(keys.is_known("site.nic0.virtualDev", extra={"site.nic%d.virtualDev"}))
        # a dot-less pattern fragment must NOT open the floodgates
        self.assertFalse(keys.is_known("definitely.not.a.real.key", extra={"d%s"}))


class KeyPolicyTests(unittest.TestCase):
    def test_returns_a_predicate(self) -> None:
        policy = keys.key_policy()
        self.assertTrue(callable(policy))
        self.assertTrue(policy("numvcpus"))
        self.assertFalse(policy("mks.g3d.maxTextureSize"))

    def test_extra_snapshot_is_taken_once(self) -> None:
        extra = {"site.a"}
        policy = keys.key_policy(extra=extra)
        self.assertTrue(policy("site.a"))
        extra.add("site.b")  # caller mutates after the fact
        self.assertFalse(policy("site.b"))

    def test_docstring_is_populated(self) -> None:
        self.assertIn("whitelist", keys.key_policy().__doc__ or "")


class ScanTests(unittest.TestCase):
    def scan_text(self, payload: str) -> set[str]:
        with tempfile.TemporaryDirectory(prefix="macopt-keyscan-") as tmp:
            path = Path(tmp) / "fake-binary"
            path.write_bytes(payload.encode("latin-1"))
            return keys.scan([path])

    def test_finds_dotted_keys(self) -> None:
        found = self.scan_text(
            "junk svga.maxTextureSize more ethernet%d.virtualDev tail scsi0:0.present end"
        )
        self.assertIn("svga.maxTextureSize", found)
        self.assertIn("scsi0:0.present", found)
        self.assertIn("ethernet%d.virtualDev", found)

    def test_ignores_version_numbers_and_prose(self) -> None:
        found = self.scan_text("Workstation 26.0.1 build 25688693 hello world numvcpus")
        self.assertNotIn("26.0.1", found)
        self.assertNotIn("25688693", found)
        # dot-less tokens cannot be told apart from ordinary words (documented
        # limitation of the DESIGN §4.5 token charset) — the seed covers them.
        self.assertNotIn("numvcpus", found)

    def test_cpuid_format_strings_are_not_keys(self) -> None:
        found = self.scan_text("cpuid.%x.%s cpuid.%x.%x.%s.amd cpuid.1.eax")
        self.assertFalse(any(t.startswith("cpuid.%") for t in found))
        self.assertIn("cpuid.1.eax", found)

    def test_dotless_percent_fragments_are_skipped(self) -> None:
        # `d%s` from an unrelated format string would otherwise be indexed as a
        # pattern and make is_known() accept anything starting with `d`.
        found = self.scan_text("zzz d%s yyy")
        self.assertNotIn("d%s", found)

    def test_missing_file_returns_empty_set(self) -> None:
        self.assertEqual(keys.scan(["/nonexistent/path/to/binary"]), set())

    def test_directory_and_empty_file_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macopt-keyscan-") as tmp:
            empty = Path(tmp) / "empty"
            empty.write_bytes(b"")
            self.assertEqual(keys.scan([Path(tmp), empty]), set())

    def test_scan_uses_no_subprocess(self) -> None:
        source = Path(keys.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("subprocess.", source)

    def test_default_scan_paths_filter_to_existing_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macopt-defaults-") as tmp:
            self.assertEqual(keys.default_scan_paths(tmp), [])
        real = keys.default_scan_paths()
        self.assertTrue(all(p.is_file() for p in real))


if __name__ == "__main__":
    unittest.main()

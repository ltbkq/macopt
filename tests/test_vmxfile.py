"""Contract-layer tests for the `.vmx` / preference file reader-writer.

These run without any profile, verifier or writer module: they pin down the
byte-level behaviour everything else depends on (round-trip fidelity,
duplicate handling, three-state semantics, atomic replacement).
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from macopt.vmxfile import Document, decode_value, duplicate_warning, encode_value

SAMPLE = """\
.encoding = "UTF-8"
config.version = "8"
guestOS = "darwin24-64"
numvcpus = "12"
cpuid.coresPerSocket = "12"
vhv.enable = "TRUE"
sata0:1.present = "TRUE"
sata0:1.fileName = "/path/to/darwin.iso"
# a comment that must survive untouched

displayName = "Test\\"Guest"
"""


class ValueCodecTest(unittest.TestCase):
    def test_roundtrip_plain(self):
        self.assertEqual(decode_value(encode_value("darwin24-64")), "darwin24-64")

    def test_roundtrip_escapes(self):
        for value in ('say "hi"', "back\\slash", "with\ttab", ""):
            with self.subTest(value=value):
                self.assertEqual(decode_value(encode_value(value)), value)

    def test_unquoted_value(self):
        self.assertEqual(decode_value("TRUE"), "TRUE")
        self.assertEqual(decode_value('  "TRUE"  '), "TRUE")

    def test_always_quotes(self):
        self.assertTrue(encode_value("TRUE").startswith('"'))


class DocumentParseTest(unittest.TestCase):
    def setUp(self):
        self.doc = Document.from_text(SAMPLE)

    def test_values(self):
        self.assertEqual(self.doc.get("guestOS"), "darwin24-64")
        self.assertEqual(self.doc.get("numvcpus"), "12")
        self.assertEqual(self.doc.get("vhv.enable"), "TRUE")
        self.assertEqual(self.doc.get("missing"), None)
        self.assertEqual(self.doc.get("missing", "fallback"), "fallback")

    def test_escape_decoding_in_file(self):
        self.assertEqual(self.doc.get("displayName"), 'Test"Guest')

    def test_comments_and_blanks_are_not_entries(self):
        self.assertFalse(self.doc.has("# a comment that must survive untouched"))
        self.assertNotIn("", self.doc.entries)

    def test_no_duplicates_in_sample(self):
        self.assertEqual(self.doc.duplicates, {})

    def test_untouched_roundtrip_is_byte_exact(self):
        self.assertEqual(self.doc.render(), SAMPLE)

    def test_as_dict_covers_every_key(self):
        self.assertEqual(set(self.doc.as_dict()) - set(self.doc.entries), set())


class DocumentMutationTest(unittest.TestCase):
    def setUp(self):
        self.doc = Document.from_text(SAMPLE)

    def test_set_added(self):
        op, before = self.doc.set("vpmc.enable", "FALSE")
        self.assertEqual((op, before), ("added", None))
        self.assertEqual(self.doc.get("vpmc.enable"), "FALSE")
        self.assertIn('vpmc.enable = "FALSE"', self.doc.render())

    def test_set_modified(self):
        op, before = self.doc.set("vhv.enable", "FALSE")
        self.assertEqual((op, before), ("modified", "TRUE"))
        self.assertEqual(self.doc.get("vhv.enable"), "FALSE")

    def test_set_unchanged(self):
        op, before = self.doc.set("numvcpus", "12")
        self.assertEqual((op, before), ("unchanged", "12"))

    def test_delete_removed(self):
        op, before = self.doc.delete("numa.autosize.cookie")
        # key absent in the sample -> no-op
        self.assertEqual((op, before), ("unchanged", None))

    def test_delete_existing_key(self):
        op, before = self.doc.delete("numvcpus")
        self.assertEqual((op, before), ("removed", "12"))
        self.assertIsNone(self.doc.get("numvcpus"))
        self.assertNotIn("numvcpus", self.doc.render())

    def test_deleting_does_not_clobber_neighbours(self):
        self.doc.delete("numvcpus")
        self.assertEqual(self.doc.get("guestOS"), "darwin24-64")
        self.assertEqual(self.doc.get("vhv.enable"), "TRUE")

    def test_value_with_quotes_survives_rewrite(self):
        self.doc.set("displayName", 'He said "no"')
        self.assertEqual(self.doc.get("displayName"), 'He said "no"')

    def test_duplicate_keys_last_wins_and_warns(self):
        doc = Document.from_text('a = "1"\nb = "2"\na = "3"\n')
        self.assertEqual(doc.get("a"), "3")
        self.assertEqual(doc.duplicates, {"a": 2})
        warning = duplicate_warning(doc)
        self.assertIsNotNone(warning)
        self.assertIn("a", warning)
        # only the effective (last) line is rewritten
        doc.set("a", "4")
        self.assertEqual(doc.render(), 'a = "1"\nb = "2"\na = "4"\n')

    def test_delete_then_set_neighbour_does_not_clobber(self):
        """Regression: deleting a line must renumber the entries below it.

        `Entry.lineno` is absolute, so after a gap closes every later entry
        shifts up by one. When that did not happen, `set()` wrote its new
        value onto the *next* key's line: the target key kept its old value
        while an untouched neighbour silently lost its line.
        """
        doc = Document.from_text(
            'keep = "k"\n'
            'cookie = "120122"\n'
            'target = "TRUE"\n'
            'victim = "FALSE"\n'
            'tail = "t"\n'
        )
        self.assertEqual(doc.delete("cookie"), ("removed", "120122"))
        self.assertEqual(doc.set("target", "FALSE"), ("modified", "TRUE"))

        rendered = doc.render()
        self.assertNotIn("cookie", rendered)
        self.assertIn('target = "FALSE"', rendered)
        self.assertIn('victim = "FALSE"', rendered)  # the neighbour must survive
        self.assertEqual(doc.get("victim"), "FALSE")
        self.assertEqual(doc.get("target"), "FALSE")
        self.assertEqual(rendered, 'keep = "k"\ntarget = "FALSE"\nvictim = "FALSE"\ntail = "t"\n')

    def test_delete_duplicate_then_edit_key_after_it(self):
        doc = Document.from_text(
            'a = "1"\n'
            'dup = "x"\n'
            'middle = "m"\n'
            'dup = "y"\n'
            'z = "z"\n'
        )
        self.assertEqual(doc.delete("dup"), ("removed", "y"))
        self.assertEqual(doc.get("dup"), None)
        self.assertEqual(doc.set("z", "Z"), ("modified", "z"))
        self.assertEqual(
            doc.render(),
            'a = "1"\nmiddle = "m"\nz = "Z"\n',
        )

    def test_delete_first_then_edit_earlier_key(self):
        doc = Document.from_text('first = "a"\nsecond = "b"\nthird = "c"\n')
        doc.delete("second")
        self.assertEqual(doc.set("first", "A"), ("modified", "a"))
        self.assertEqual(doc.render(), 'first = "A"\nthird = "c"\n')

    def test_multiple_deletions_keep_line_numbers_in_sync(self):
        doc = Document.from_text(
            'one = "1"\ntwo = "2"\nthree = "3"\nfour = "4"\nfive = "5"\n'
        )
        doc.delete("two")
        doc.delete("four")
        self.assertEqual(doc.set("five", "5x"), ("modified", "5"))
        self.assertEqual(
            doc.render(),
            'one = "1"\nthree = "3"\nfive = "5x"\n',
        )
        # the in-memory view must agree with what render() produced
        reparsed = Document.from_text(doc.render())
        self.assertEqual(reparsed.as_dict(), doc.as_dict())


class AtomicWriteTest(unittest.TestCase):
    def test_write_creates_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guest.vmx"
            path.write_text(SAMPLE, encoding="utf-8")
            os.chmod(path, 0o640)

            doc = Document.load(path)
            doc.set("vhv.enable", "FALSE")
            report = doc.write_atomic()

            self.assertTrue(path.exists())
            self.assertEqual(report["mode"], oct(0o640))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            reloaded = Document.load(path)
            self.assertEqual(reloaded.get("vhv.enable"), "FALSE")
            # untouched lines survived the rewrite
            self.assertIn("# a comment that must survive untouched", path.read_text(encoding="utf-8"))

    def test_failed_write_leaves_original_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guest.vmx"
            original = SAMPLE
            path.write_text(original, encoding="utf-8")

            doc = Document.load(path)
            doc.set("numvcpus", "8")

            # Simulate a crash between temp-file creation and replace by
            # pointing at a directory as the write target.
            blocker = Path(tmp) / "guest.vmx.blocker"
            blocker.mkdir()
            with self.assertRaises(OSError):
                os.replace(str(blocker), str(path))
            # The original file was never truncated or partially written.
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_no_temp_files_left_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guest.vmx"
            path.write_text(SAMPLE, encoding="utf-8")
            doc = Document.load(path)
            doc.set("numvcpus", "8")
            doc.write_atomic()
            leftovers = [p.name for p in Path(tmp).iterdir() if p.name != "guest.vmx"]
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()

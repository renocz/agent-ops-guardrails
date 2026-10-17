"""Tests for new-record.py: numbering, index regeneration, refusal to overwrite."""
import importlib.util
import os
import shutil
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("new_record", os.path.join(HERE, "new-record.py"))
nr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nr)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class Numbering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_first_record_is_0001(self):
        rc = nr.main([self.tmp, "--title", "first change"])
        self.assertEqual(rc, 0)
        files = sorted(f for f in os.listdir(self.tmp) if nr.ID_RE.match(f))
        self.assertEqual(files, ["0001-first-change.md"])

    def test_numbering_increments_and_ignores_unrelated_files(self):
        open(os.path.join(self.tmp, "notes.txt"), "w").close()
        nr.main([self.tmp, "--title", "one"])
        nr.main([self.tmp, "--title", "two"])
        nr.main([self.tmp, "--title", "three"])
        files = sorted(f for f in os.listdir(self.tmp) if nr.ID_RE.match(f))
        self.assertEqual(files, ["0001-one.md", "0002-two.md", "0003-three.md"])

    def test_numbering_continues_after_a_gap(self):
        # a record was deleted or renumbered by hand; the next id is still max+1, not a reused gap
        nr.main([self.tmp, "--title", "one"])
        nr.main([self.tmp, "--title", "two"])
        os.remove(os.path.join(self.tmp, "0001-one.md"))
        nr.main([self.tmp, "--title", "three"])
        files = sorted(f for f in os.listdir(self.tmp) if nr.ID_RE.match(f))
        self.assertEqual(files, ["0002-two.md", "0003-three.md"])

    def test_slugify_handles_punctuation_and_case(self):
        nr.main([self.tmp, "--title", "Upgrade Example-Service to v2.4!!"])
        files = [f for f in os.listdir(self.tmp) if nr.ID_RE.match(f)]
        self.assertEqual(files, ["0001-upgrade-example-service-to-v2-4.md"])


class RefusesToOverwrite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_refuses_when_the_chosen_id_is_already_taken(self):
        # next_id() always skips past ids already on disk, so simulate the race it exists to avoid: something
        # else created 0001 between next_id() being computed and the write (a manual copy, a concurrent run).
        write(os.path.join(self.tmp, "0001-something-else.md"), "must survive untouched")
        with unittest.mock.patch.object(nr, "next_id", return_value=1):
            rc = nr.main([self.tmp, "--title", "repeat"])
        self.assertEqual(rc, 1)
        self.assertNotIn("0001-repeat.md", os.listdir(self.tmp))
        self.assertEqual(read(os.path.join(self.tmp, "0001-something-else.md")), "must survive untouched")

    def test_refuses_on_an_explicit_colliding_id(self):
        nr.main([self.tmp, "--title", "one"])
        rc = nr.main([self.tmp, "--title", "two", "--id", "1"])
        self.assertEqual(rc, 1)
        self.assertNotIn("0001-two.md", os.listdir(self.tmp))


class Index(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_index_lists_every_record_sorted_by_id(self):
        nr.main([self.tmp, "--title", "first", "--status", "done"])
        nr.main([self.tmp, "--title", "second", "--risk", "high"])
        index = read(os.path.join(self.tmp, "index.md"))
        self.assertIn("0001-first.md", index)
        self.assertIn("0002-second.md", index)
        self.assertLess(index.index("0001"), index.index("0002"))
        self.assertIn("done", index)

    def test_index_is_regenerated_not_appended(self):
        nr.main([self.tmp, "--title", "first"])
        nr.main([self.tmp, "--title", "second"])
        index_before = read(os.path.join(self.tmp, "index.md"))
        self.assertEqual(index_before.count("0001-first.md"), 1)

    def test_front_matter_fields_round_trip_into_the_record(self):
        nr.main([self.tmp, "--title", "net change", "--requester", "alice", "--risk", "medium",
                 "--go", "chat, 2026-10-17", "--items", "svc-a,svc-b", "--links", "https://example.invalid/1"])
        text = read(os.path.join(self.tmp, "0001-net-change.md"))
        for expected in ('requester: "alice"', 'risk: "medium"', 'go: "chat, 2026-10-17"',
                         '- "svc-a"', '- "svc-b"', '- "https://example.invalid/1"',
                         "## Context", "## What was done", "## Verifications", "## Rollback"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()

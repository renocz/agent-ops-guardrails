"""Tests for changes-by-actor.py: pure classification, a real temporary git repository, and hostile commit text. No network."""
import importlib.util, os, subprocess, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cba", os.path.join(HERE, "changes-by-actor.py"))
cba = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cba)


def git(d, *a, env=None):
    e = dict(os.environ, GIT_AUTHOR_NAME="A", GIT_AUTHOR_EMAIL="a@example.org", GIT_COMMITTER_NAME="A", GIT_COMMITTER_EMAIL="a@example.org")
    return subprocess.run(["git", "-C", d, *a], capture_output=True, text=True, env=e, check=True).stdout


class Classify(unittest.TestCase):
    def test_agent_declared_by_coauthor_trailer(self):
        a, ev = cba.classify("p1", "fix", "why\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>")
        self.assertEqual(a, "agent (declared)")
        self.assertTrue(ev)

    def test_agent_declared_by_session_trailer(self):
        self.assertEqual(cba.classify("p1", "fix", "x\n\nClaude-Session: https://example.org/s/1")[0], "agent (declared)")

    def test_human_coauthor_is_not_an_agent(self):
        self.assertEqual(cba.classify("p1", "fix", "x\n\nCo-Authored-By: Jane Doe <jane@example.org>")[0], "no declaration")

    def test_no_trailer_is_never_called_human(self):
        a, _ = cba.classify("p1", "fix", "plain message")
        self.assertEqual(a, "no declaration")
        self.assertNotIn("human", a)

    def test_merge_and_empty_are_indeterminate(self):
        self.assertEqual(cba.classify("p1 p2", "Merge pull request #1", "")[0], "indeterminate")
        self.assertEqual(cba.classify("p1", "", "")[0], "indeterminate")

    def test_reason_skips_trailers_and_defaults(self):
        self.assertEqual(cba.reason("s", "first para\n\nCo-Authored-By: x"), "first para")
        self.assertEqual(cba.reason("s", "Co-Authored-By: x"), "no reason beyond the subject")

    def test_cell_neutralises_markdown(self):
        c = cba.cell("a|b\n`c` <script>")
        self.assertNotIn("\n", c)
        self.assertNotIn("<script>", c)
        self.assertIn("\\|", c)


class RealRepo(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        git(self.d, "init", "-q", "-b", "main")
        for i, msg in enumerate(["first\n\nwhy one", "second\n\nwhy two\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"]):
            with open(os.path.join(self.d, f"f{i}"), "w") as fh:
                fh.write(str(i))
            git(self.d, "add", ".")
            git(self.d, "commit", "-q", "-m", msg)

    def test_report_counts_and_reasons(self):
        rows = cba.build(cba.git_log(self.d))
        self.assertEqual(len(rows), 2)
        by = {r["subject"]: r for r in rows}
        self.assertEqual(by["second"]["actor"], "agent (declared)")
        self.assertEqual(by["first"]["actor"], "no declaration")
        self.assertEqual(by["first"]["reason"], "why one")
        md = cba.render_md(rows)
        self.assertIn("agent (declared) 1", md)
        self.assertIn("not proof of a person", md)

    def test_option_injection_refused(self):
        with self.assertRaises(SystemExit):
            cba.git_log(self.d, since="--output=/tmp/x")
        with self.assertRaises(SystemExit):
            cba.git_log(self.d, since="-p")

    def test_read_only_no_files_written(self):
        before = sorted(os.listdir(self.d))
        cba.build(cba.git_log(self.d))
        self.assertEqual(before, sorted(os.listdir(self.d)))

    def test_hostile_message_stays_plain_text(self):
        with open(os.path.join(self.d, "g"), "w") as fh:
            fh.write("g")
        git(self.d, "add", ".")
        git(self.d, "commit", "-q", "-m", "x | y\n\n<img src=x onerror=1> `rm -rf` | $(id)")
        md = cba.render_md(cba.build(cba.git_log(self.d)))
        self.assertNotIn("<img", md)
        self.assertNotIn("\n| x | y", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)

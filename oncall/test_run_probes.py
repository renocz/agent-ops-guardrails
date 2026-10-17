"""Tests for lib/run_probes.py, using fake stub commands only -- never the real probes.json, never a real
path, ssh call or hypervisor command. A stub that exits 0 stands in for "the operation was accepted" (FAIL for
a denial probe); a stub that exits non-zero stands in for "refused" (PASS)."""
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("run_probes", os.path.join(HERE, "lib", "run_probes.py"))
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


def make_stub(path, exit_code):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"#!/bin/sh\nexit {exit_code}\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


class Stubs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.accepts = os.path.join(self.tmp, "accepts.sh")       # exit 0: the operation went through
        self.refuses = os.path.join(self.tmp, "refuses.sh")       # exit 1: the operation was refused
        make_stub(self.accepts, 0)
        make_stub(self.refuses, 1)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class RunProbe(Stubs):
    def test_an_accepting_stub_is_reported_as_accepted(self):
        accepted, note = rp.run_probe({"name": "x", "command": [self.accepts]}, {})
        self.assertTrue(accepted)
        self.assertIsNone(note)

    def test_a_refusing_stub_is_reported_as_refused(self):
        accepted, note = rp.run_probe({"name": "x", "command": [self.refuses]}, {})
        self.assertFalse(accepted)

    def test_a_missing_command_is_treated_as_refused_not_a_crash(self):
        accepted, note = rp.run_probe({"name": "x", "command": ["/no/such/binary-xyz"]}, {})
        self.assertFalse(accepted)
        self.assertIn("not found", note)

    def test_a_missing_placeholder_value_is_reported_not_run(self):
        accepted, note = rp.run_probe({"name": "x", "command": ["{{UNDECLARED_THING}}"]}, {})
        self.assertIsNone(accepted)
        self.assertIn("UNDECLARED_THING", note)


class Substitution(Stubs):
    def test_a_whole_token_placeholder_substitutes_cleanly(self):
        argv = rp.build_argv(["{{BIN}}"], {"BIN": self.accepts})
        self.assertEqual(argv, [self.accepts])

    def test_a_whole_token_placeholder_with_a_space_expands_to_two_argv_elements(self):
        argv = rp.build_argv(["{{CMD}}", "arg"], {"CMD": "echo hello"})
        self.assertEqual(argv, ["echo", "hello", "arg"])

    def test_an_embedded_placeholder_stays_one_token_and_does_plain_substitution(self):
        argv = rp.build_argv(["sh", "-c", "touch {{DIR}}/x"], {"DIR": "/somewhere"})
        self.assertEqual(argv, ["sh", "-c", "touch /somewhere/x"])

    def test_default_vars_cover_every_placeholder_the_shipped_probes_use(self):
        probes_path = os.path.join(HERE, "probes.json")
        with open(probes_path, encoding="utf-8") as f:
            probes = json.load(f)
        vars_ = rp.load_vars(None)
        for probe in probes:
            with self.subTest(name=probe["name"]):
                rp.build_argv(probe["command"], vars_)        # must not raise KeyError


class MainReportsStatusPerLine(Stubs):
    def _run(self, probes):
        path = os.path.join(self.tmp, "probes.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(probes, f)
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out):
            rc = rp.main([path])
        return rc, out.getvalue()

    def test_all_refused_is_exit_0(self):
        rc, out = self._run([{"name": "a", "command": [self.refuses]}, {"name": "b", "command": [self.refuses]}])
        self.assertEqual(rc, 0)
        self.assertIn("PASS  a", out)
        self.assertIn("PASS  b", out)

    def test_one_accepted_is_exit_1_and_reported_as_fail(self):
        rc, out = self._run([{"name": "a", "command": [self.refuses]}, {"name": "b", "command": [self.accepts]}])
        self.assertEqual(rc, 1)
        self.assertIn("PASS  a", out)
        self.assertIn("FAIL  b", out)

    def test_stdout_and_stderr_of_the_probed_command_are_never_printed(self):
        loud = os.path.join(self.tmp, "loud.sh")
        with open(loud, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho SECRET_LOOKING_OUTPUT\nexit 0\n")
        os.chmod(loud, os.stat(loud).st_mode | stat.S_IEXEC)
        rc, out = self._run([{"name": "a", "command": [loud]}])
        self.assertNotIn("SECRET_LOOKING_OUTPUT", out)
        self.assertIn("FAIL  a", out)


if __name__ == "__main__":
    unittest.main()

"""Tests for lib/harmless_check.py: the static check over a probes.json file's own command lists (method.md
§4 -- a denial probe must be harmless if it unexpectedly succeeds). Includes the mutation check: a probe using
a real object name/id next to a dangerous verb must be caught."""
import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("harmless_check", os.path.join(HERE, "lib", "harmless_check.py"))
hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hc)


class CheckProbe(unittest.TestCase):
    def test_a_dangerous_verb_with_only_placeholder_arguments_is_harmless(self):
        problems = hc.check_probe({"name": "ok", "command": ["rm", "-f", "{{SCRATCH_FILE}}"]})
        self.assertEqual(problems, [])

    def test_a_dangerous_verb_with_a_literal_path_is_flagged(self):
        problems = hc.check_probe({"name": "bad", "command": ["rm", "-f", "/var/lib/important"]})
        self.assertEqual(len(problems), 1)
        self.assertIn("/var/lib/important", problems[0])

    def test_a_dangerous_verb_with_a_literal_numeric_id_is_flagged(self):
        problems = hc.check_probe({"name": "bad", "command": ["pct", "destroy", "100"]})
        self.assertEqual(len(problems), 1)
        self.assertIn("100", problems[0])

    def test_a_restart_with_a_literal_service_name_is_flagged(self):
        problems = hc.check_probe({"name": "bad", "command": ["systemctl", "restart", "example-web"]})
        self.assertEqual(len(problems), 1)
        self.assertIn("example-web", problems[0])

    def test_a_restart_with_a_placeholder_service_name_is_harmless(self):
        problems = hc.check_probe({"name": "ok", "command": ["systemctl", "restart", "{{SERVICE_NAME}}"]})
        self.assertEqual(problems, [])

    def test_no_dangerous_verb_at_all_is_never_flagged_whatever_its_arguments(self):
        problems = hc.check_probe({"name": "ok", "command": ["cat", "/etc/some/real/looking/path"]})
        self.assertEqual(problems, [])

    def test_a_dangerous_verb_hidden_inside_one_sh_dash_c_string_is_still_caught(self):
        # the whole script is ONE argv/JSON token (what a real `sh -c "..."` probe looks like); the verb and
        # its literal target must still be visible to this check, not hidden by being glued into one token.
        problems = hc.check_probe({"name": "bad", "command": ["sh", "-c", "rm -rf /var/lib/important"]})
        self.assertTrue(problems)

    def test_a_dangerous_verb_hidden_inside_one_sh_dash_c_string_with_a_placeholder_is_harmless(self):
        problems = hc.check_probe({"name": "ok", "command": ["sh", "-c", "rm -rf {{SCRATCH_DIR}}"]})
        self.assertEqual(problems, [])


class CheckAll(unittest.TestCase):
    def test_the_shipped_probes_file_is_entirely_harmless(self):
        path = os.path.join(HERE, "probes.json")
        with open(path, encoding="utf-8") as f:
            probes = json.load(f)
        self.assertEqual(hc.check_all(probes), [])

    def test_mutation_a_harmful_probe_slipped_into_a_copy_is_caught(self):
        """The mutation check for this item: take a harmless probe list, inject one bad entry the way a
        careless edit might, and confirm the static check -- not a human reviewer -- is what catches it."""
        path = os.path.join(HERE, "probes.json")
        with open(path, encoding="utf-8") as f:
            probes = json.load(f)
        mutated = probes + [{"name": "destroy a container by a real-looking id, no placeholder",
                             "command": ["pct", "destroy", "100"]}]
        problems = hc.check_all(mutated)
        self.assertEqual(len(problems), 1)
        self.assertIn("100", problems[0])
        self.assertIn("destroy a container", problems[0])


if __name__ == "__main__":
    unittest.main()

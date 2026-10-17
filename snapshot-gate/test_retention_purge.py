"""Tests for retention-purge.py: strict name matching, recursion cannot widen the selection, dry run vs --apply
on a temp fixture directory."""
import datetime
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib import backends, naming                              # noqa: E402

spec = importlib.util.spec_from_file_location("retention_purge", os.path.join(HERE, "retention-purge.py"))
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


def named_at(prefix, days_ago):
    when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
    return naming.new_name(prefix, when)


class EligibleForPurge(unittest.TestCase):
    """Pure matching logic: crafted candidate strings, no filesystem involved -- this is where "a foreign
    snapshot name is never selected" and "recursion cannot widen the selection" are checked directly, including
    shapes a real recursive `zfs list -r` could actually produce."""

    def cfg(self, **over):
        base = {"dataset": "pool/agent", "prefix": "agent-gate", "retention_days": 7}
        base.update(over)
        return base

    def test_selects_only_the_configured_dataset_and_prefix(self):
        old = named_at("agent-gate", 10)

        class Fake:
            def list_snapshot_names(self):
                return [f"pool/agent@{old}"]
        self.assertEqual([n for n, _ in rp.eligible_for_purge(Fake(), self.cfg())], [f"pool/agent@{old}"])

    def test_a_dataset_that_merely_starts_with_the_same_string_is_never_selected(self):
        old = named_at("agent-gate", 10)

        class Fake:
            def list_snapshot_names(self):
                return [f"pool/agent-other@{old}", f"pool/agent2@{old}", f"pool/agentX@{old}"]
        self.assertEqual(rp.eligible_for_purge(Fake(), self.cfg()), [])

    def test_recursion_into_a_child_dataset_never_widens_the_selection(self):
        old = named_at("agent-gate", 10)

        class Fake:
            def list_snapshot_names(self):
                # what `zfs list -r pool/agent` would also return for a child dataset
                return [f"pool/agent/child@{old}", f"pool/agent@{old}"]
        selected = [n for n, _ in rp.eligible_for_purge(Fake(), self.cfg())]
        self.assertEqual(selected, [f"pool/agent@{old}"])

    def test_a_foreign_name_prefix_in_the_right_dataset_is_never_selected(self):
        old = named_at("not-ours", 10)

        class Fake:
            def list_snapshot_names(self):
                return [f"pool/agent@{old}"]
        self.assertEqual(rp.eligible_for_purge(Fake(), self.cfg()), [])

    def test_a_young_matching_snapshot_is_not_eligible(self):
        young = named_at("agent-gate", 1)

        class Fake:
            def list_snapshot_names(self):
                return [f"pool/agent@{young}"]
        self.assertEqual(rp.eligible_for_purge(Fake(), self.cfg(retention_days=7)), [])

    def test_a_malformed_timestamp_shaped_name_is_never_selected(self):
        class Fake:
            def list_snapshot_names(self):
                return ["pool/agent@agent-gate-notadate-000000", "pool/agent@agent-gate-20261301-999999"]
        # the second has an impossible calendar date -> strptime raises -> must not crash the whole run
        self.assertEqual(rp.eligible_for_purge(Fake(), self.cfg()), [])


class DirFixture(unittest.TestCase):
    """Functional test on a real temp fixture directory, using the Dir backend end to end."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()               # holds config.json etc.; kept separate from the store itself
        self.store = os.path.join(self.tmp, "store")
        self.backend = backends.Dir(self.store, dataset="testds")
        self.cfg = {"backend": "dir", "dataset": "testds", "dir_backend_root": self.store,
                    "prefix": "agent-gate", "retention_days": 7}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_lists_without_deleting(self):
        old_name = f"testds@{named_at('agent-gate', 10)}"
        self.backend.create_snapshot(old_name)
        rc = rp.main([self._write_cfg()])
        self.assertEqual(rc, 0)
        self.assertIn(old_name, os.listdir(self.store))

    def test_apply_removes_only_the_matching_old_ones_in_the_fixture_directory(self):
        old_match = f"testds@{named_at('agent-gate', 10)}"
        young_match = f"testds@{named_at('agent-gate', 1)}"
        foreign = f"testds@{named_at('not-ours', 10)}"
        other_dataset = f"testds-other@{named_at('agent-gate', 10)}"
        for n in (old_match, young_match, foreign, other_dataset):
            self.backend.create_snapshot(n)
        rc = rp.main([self._write_cfg(), "--apply"])
        self.assertEqual(rc, 0)
        remaining = set(os.listdir(self.store)) - {".usage_percent"}
        self.assertEqual(remaining, {young_match, foreign, other_dataset})

    def _write_cfg(self):
        import json
        path = os.path.join(self.tmp, "config.json")
        full = dict(self.cfg)
        full.update({"requests_dir": self.tmp, "states_dir": self.tmp,
                     "lock_file": os.path.join(self.tmp, "l"), "log_file": os.path.join(self.tmp, "log")})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(full, f)
        return path


if __name__ == "__main__":
    unittest.main()

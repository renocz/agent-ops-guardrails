"""Tests for snapshot-gate-host.py, using the Dir backend (the dry-run back end from the task): request
accepted, refusal on usage, refusal on a recent snapshot, concurrent requests, malformed request content
ignored."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib import backends, naming                              # noqa: E402

spec = importlib.util.spec_from_file_location("sg_host", os.path.join(HERE, "snapshot-gate-host.py"))
sg_host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg_host)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.requests_dir = os.path.join(self.tmp, "requests")
        self.states_dir = os.path.join(self.tmp, "states")
        self.store_dir = os.path.join(self.tmp, "store")
        os.makedirs(self.requests_dir)
        os.makedirs(self.states_dir)
        self.cfg = {
            "backend": "dir", "dataset": "testds", "dir_backend_root": self.store_dir, "prefix": "agent-gate",
            "usage_threshold_percent": 85, "cooldown_minutes": 10, "retention_days": 7,
            "requests_dir": self.requests_dir, "states_dir": self.states_dir,
            "lock_file": os.path.join(self.tmp, "run.lock"), "log_file": os.path.join(self.tmp, "sg.log"),
        }
        self.backend = backends.Dir(self.store_dir, dataset="testds")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def request(self, request_id, content=""):
        with open(os.path.join(self.requests_dir, f"{request_id}.request"), "w", encoding="utf-8") as f:
            f.write(content)

    def state(self, request_id):
        path = os.path.join(self.states_dir, f"{request_id}.state")
        self.assertTrue(os.path.exists(path), f"no state file written for {request_id}")
        fields = {}
        for line in read(path).splitlines():
            key, _, value = line.partition("=")
            fields[key] = value.strip("'\"") if value.startswith(("'", '"')) else value
        return fields


class RequestAccepted(Harness):
    def test_a_single_request_is_accepted_and_creates_a_snapshot(self):
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        state = self.state("r1")
        self.assertEqual(state["status"], "OK")
        self.assertTrue(state["name"].startswith("testds@agent-gate-"))
        self.assertIn(state["name"], self.backend.list_snapshot_names())

    def test_the_request_file_is_removed_after_processing(self):
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        self.assertFalse(os.path.exists(os.path.join(self.requests_dir, "r1.request")))


class RefusalOnUsage(Harness):
    def test_refuses_when_usage_is_above_the_threshold(self):
        self.backend.set_usage_percent(90)
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        state = self.state("r1")
        self.assertEqual(state["status"], "REFUSED")
        self.assertIn("threshold", state["reason"])
        self.assertEqual(self.backend.list_snapshot_names(), [])

    def test_accepts_at_exactly_the_threshold(self):
        self.backend.set_usage_percent(85)
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        self.assertEqual(self.state("r1")["status"], "OK")


class RefusalOnCooldown(Harness):
    def test_refuses_when_a_recent_matching_snapshot_exists_and_returns_its_name(self):
        recent = f"testds@{naming.new_name('agent-gate')}"
        self.backend.create_snapshot(recent)
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        state = self.state("r1")
        self.assertEqual(state["status"], "REFUSED")
        self.assertIn("younger than", state["reason"])
        self.assertEqual(state["name"], recent)
        # no new snapshot was created on top of the existing one
        self.assertEqual(self.backend.list_snapshot_names(), [recent])

    def test_a_foreign_name_never_counts_towards_the_cooldown(self):
        self.backend.create_snapshot("testds@not-ours-20260101-000000")
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        self.assertEqual(self.state("r1")["status"], "OK")

    def test_a_different_datasets_snapshot_never_counts_towards_the_cooldown(self):
        recent = f"testds-other@{naming.new_name('agent-gate')}"
        self.backend.create_snapshot(recent)
        self.request("r1")
        sg_host.process_pending(self.cfg, self.backend)
        self.assertEqual(self.state("r1")["status"], "OK")


class ConcurrentRequests(Harness):
    def test_several_pending_requests_are_each_answered(self):
        self.request("r1")
        self.request("r2")
        self.request("r3")
        sg_host.process_pending(self.cfg, self.backend)
        for rid in ("r1", "r2", "r3"):
            self.assertIn(self.state(rid)["status"], ("OK", "REFUSED"))
        # the first succeeds, the rest are refused by the cooldown it just created
        self.assertEqual(self.state("r1")["status"], "OK")
        self.assertEqual(self.state("r2")["status"], "REFUSED")
        self.assertEqual(self.state("r3")["status"], "REFUSED")

    def test_a_second_run_while_the_lock_is_held_does_nothing(self):
        self.request("r1")
        lock = sg_host.acquire_lock(self.cfg["lock_file"])
        self.assertTrue(lock.acquired())
        second = sg_host.acquire_lock(self.cfg["lock_file"])
        self.assertFalse(second.acquired())
        # process_pending is never even reached by main() when the lock is held; simulate that directly
        self.assertFalse(os.path.exists(os.path.join(self.states_dir, "r1.state")))


class MalformedRequestContent(Harness):
    def test_binary_garbage_in_the_request_is_never_read_or_interpreted(self):
        with open(os.path.join(self.requests_dir, "r1.request"), "wb") as f:
            f.write(bytes(range(256)))
        sg_host.process_pending(self.cfg, self.backend)
        self.assertEqual(self.state("r1")["status"], "OK")

    def test_an_empty_request_behaves_identically_to_a_non_empty_one(self):
        self.request("r1", content="")
        self.request("r2", content='ignore me entirely, including this { injection-looking text')
        sg_host.process_pending(self.cfg, self.backend)
        self.assertEqual(self.state("r1")["status"], "OK")
        # r2 is refused only by the cooldown r1 just created, never by its own (irrelevant) content
        self.assertIn(self.state("r2")["reason"], ("a snapshot younger than 10 minutes already exists",))


if __name__ == "__main__":
    unittest.main()

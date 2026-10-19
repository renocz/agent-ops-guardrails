"""End-to-end tests that exec REAL executables named zfs/vgs/lvs/lvcreate/lvremove (fakes under
test_fixtures/fakebin/, see its README) through the actual, unmodified subprocess.run() calls in
lib/backends.py and retention-purge.py -- real process creation, real argv, real captured stdout,
real exit codes, real subprocess.CalledProcessError.

This closes a gap the rest of the suite cannot: test_backend_commands.py proves the correct argv is
built by patching subprocess.run itself in Python, so it never exercises what happens when a real
process writes real stdout and returns a real (possibly non-zero) exit code -- in particular whether
a command's own stderr ever leaks into the agent-facing state file written by
snapshot-gate-host.py. No ZFS pool or LVM volume group exists anywhere in this run; see
docs/sandbox-limitations.md for why, and what this file does and does not prove."""
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FAKEBIN = os.path.join(HERE, "test_fixtures", "fakebin")
sys.path.insert(0, HERE)
from lib import backends, naming                              # noqa: E402

spec = importlib.util.spec_from_file_location("sg_host_fakebin", os.path.join(HERE, "snapshot-gate-host.py"))
sg_host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg_host)

spec2 = importlib.util.spec_from_file_location("retention_purge_fakebin", os.path.join(HERE, "retention-purge.py"))
rp = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(rp)


class FakeBinHarness(unittest.TestCase):
    """Prepends test_fixtures/fakebin to PATH and points FAKE_SG_STATE at a fresh temp dir, so every
    zfs/vgs/lvs/lvcreate/lvremove call made by the real backends.py code hits a real executable."""

    def setUp(self):
        self.state = tempfile.mkdtemp()
        self._old_path = os.environ.get("PATH", "")
        self._old_state = os.environ.get("FAKE_SG_STATE")
        os.environ["PATH"] = FAKEBIN + os.pathsep + self._old_path
        os.environ["FAKE_SG_STATE"] = self.state
        self._write("zfs_used", "10")
        self._write("zfs_avail", "90")
        self._write("lvm_total", "100")
        self._write("lvm_free", "90")

    def tearDown(self):
        os.environ["PATH"] = self._old_path
        if self._old_state is None:
            os.environ.pop("FAKE_SG_STATE", None)
        else:
            os.environ["FAKE_SG_STATE"] = self._old_state
        shutil.rmtree(self.state, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.state, name), "w", encoding="utf-8") as f:
            f.write(content)

    def sg_cfg(self, dataset, backend="zfs"):
        return {
            "dataset": dataset, "prefix": "agent-gate", "usage_threshold_percent": 85,
            "cooldown_minutes": 10, "retention_days": 7, "backend": backend,
        }


class ZfsRealExecRoundTrip(FakeBinHarness):
    """Create -> cooldown-refuse -> age it out -> purge, all through a real zfs process each step."""

    def test_round_trip_through_a_real_zfs_process(self):
        backend = backends.Zfs("pool/agent")
        cfg = self.sg_cfg("pool/agent")

        status1, _reason1, name1 = sg_host.decide_and_create(backend, cfg)
        self.assertEqual(status1, "OK")
        self.assertTrue(name1.startswith("pool/agent@agent-gate-"))

        status2, reason2, name2 = sg_host.decide_and_create(backend, cfg)
        self.assertEqual(status2, "REFUSED")
        self.assertIn("younger than", reason2)
        self.assertEqual(name2, name1)

        # back-date the snapshot's own recorded name so it is eligible for purge, exactly as
        # retention-purge.py's logic (age read from the name, never from backend metadata) requires
        old_name = f"pool/agent@{naming.new_name('agent-gate', _ago_days(10))}"
        self._rewrite_zfs_snapshots({name1: old_name})

        targets = rp.eligible_for_purge(backend, cfg)
        self.assertEqual([n for n, _ in targets], [old_name])
        rp.destroy_zfs(old_name)
        self.assertEqual(backend.list_snapshot_names(), [])

    def _rewrite_zfs_snapshots(self, renames):
        path = os.path.join(self.state, "zfs_snapshots")
        with open(path, encoding="utf-8") as f:
            lines = [renames.get(line.strip(), line.strip()) for line in f if line.strip()]
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(n + "\n" for n in lines))


class ZfsRealExecUsageRefusal(FakeBinHarness):
    def test_refuses_above_threshold_via_a_real_zfs_list_call(self):
        self._write("zfs_used", "90")
        self._write("zfs_avail", "10")
        backend = backends.Zfs("pool/agent")
        status, reason, _name = sg_host.decide_and_create(backend, self.sg_cfg("pool/agent"))
        self.assertEqual(status, "REFUSED")
        self.assertIn("threshold", reason)


class ZfsRealExecMissingDataset(FakeBinHarness):
    """A real zfs process exits 1 with a real, informative stderr naming the missing dataset. The
    snapshot-gate-host.py pipeline must still turn this into status=ERROR with ONLY the exception's
    class name -- never that stderr text -- reaching the state file an untrusted agent polls."""

    def test_a_missing_pool_fails_loudly_without_leaking_the_real_stderr(self):
        self._write("zfs_missing_dataset", "pool/gone")
        backend = backends.Zfs("pool/gone")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = dict(self.sg_cfg("pool/gone"),
                       requests_dir=tmp, states_dir=tmp,
                       lock_file=os.path.join(tmp, "l"), log_file=os.path.join(tmp, "log"))
            with open(os.path.join(tmp, "r1.request"), "w", encoding="utf-8"):
                pass
            sg_host.process_pending(cfg, backend)
            with open(os.path.join(tmp, "r1.state"), encoding="utf-8") as f:
                state = f.read()
        self.assertIn("status=ERROR", state)
        self.assertIn("CalledProcessError", state)
        self.assertNotIn("pool/gone", state)
        self.assertNotIn("does not exist", state)


class LvmRealExecRoundTrip(FakeBinHarness):
    def test_round_trip_through_real_vgs_lvs_lvcreate_processes(self):
        backend = backends.Lvm("vg/lv")
        cfg = self.sg_cfg("vg/lv", backend="lvm")

        status1, _reason1, name1 = sg_host.decide_and_create(backend, cfg)
        self.assertEqual(status1, "OK")
        self.assertTrue(name1.startswith("vg/lv@agent-gate-"))
        self.assertIn(name1, backend.list_snapshot_names())

        status2, reason2, _name2 = sg_host.decide_and_create(backend, cfg)
        self.assertEqual(status2, "REFUSED")
        self.assertIn("younger than", reason2)


class LvmRealExecMissingVg(FakeBinHarness):
    def test_a_missing_volume_group_fails_loudly_without_leaking_the_real_stderr(self):
        self._write("lvm_missing_vg", "vg")
        backend = backends.Lvm("vg/lv")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = dict(self.sg_cfg("vg/lv", backend="lvm"),
                       requests_dir=tmp, states_dir=tmp,
                       lock_file=os.path.join(tmp, "l"), log_file=os.path.join(tmp, "log"))
            with open(os.path.join(tmp, "r1.request"), "w", encoding="utf-8"):
                pass
            sg_host.process_pending(cfg, backend)
            with open(os.path.join(tmp, "r1.state"), encoding="utf-8") as f:
                state = f.read()
        self.assertIn("status=ERROR", state)
        self.assertIn("CalledProcessError", state)
        self.assertNotIn("not found", state)


class LvmRealExecPartialPurgeFailure(FakeBinHarness):
    """One snapshot's underlying LV is busy (a real, if rare, LVM condition: something still has it
    open). retention-purge.py must still purge every OTHER eligible target and report the failure,
    not abort the whole run on the first busy target."""

    def test_a_busy_logical_volume_does_not_block_purging_the_rest(self):
        backend = backends.Lvm("vg/lv")
        old_a = f"vg/lv@{naming.new_name('agent-gate', _ago_days(10))}"
        old_b = f"vg/lv@{naming.new_name('agent-gate', _ago_days(11))}"
        with open(os.path.join(self.state, "lvm_snapshots"), "w", encoding="utf-8") as f:
            f.write(old_a + "\n" + old_b + "\n")
        self._write("lvm_busy", "vg/" + old_a.split("@", 1)[1])

        cfg = self.sg_cfg("vg/lv", backend="lvm")
        targets = rp.eligible_for_purge(backend, cfg)
        self.assertEqual(sorted(n for n, _ in targets), sorted([old_a, old_b]))

        results = {}
        for name, _age in targets:
            try:
                rp.destroy_lvm(name)
                results[name] = "ok"
            except Exception as e:
                results[name] = type(e).__name__
        self.assertEqual(results[old_a], "CalledProcessError")
        self.assertEqual(results[old_b], "ok")
        self.assertNotIn(old_b, backend.list_snapshot_names())
        self.assertIn(old_a, backend.list_snapshot_names())        # the busy one is still there

    def test_rp_main_purges_every_other_target_and_exits_nonzero_on_one_busy_lv(self):
        old_a = f"vg/lv@{naming.new_name('agent-gate', _ago_days(10))}"
        old_b = f"vg/lv@{naming.new_name('agent-gate', _ago_days(11))}"
        with open(os.path.join(self.state, "lvm_snapshots"), "w", encoding="utf-8") as f:
            f.write(old_a + "\n" + old_b + "\n")
        self._write("lvm_busy", "vg/" + old_a.split("@", 1)[1])

        import contextlib
        import io
        import json
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "config.json")
            full = dict(self.sg_cfg("vg/lv", backend="lvm"),
                        requests_dir=tmp, states_dir=tmp,
                        lock_file=os.path.join(tmp, "l"), log_file=os.path.join(tmp, "log"))
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(full, f)

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = rp.main([cfg_path, "--apply"])

        self.assertEqual(rc, 1)                                    # signals the partial failure
        self.assertIn("FAILED to delete", stderr.getvalue())
        self.assertIn(old_a, stderr.getvalue())
        backend = backends.Lvm("vg/lv")
        self.assertNotIn(old_b, backend.list_snapshot_names())      # still purged despite old_a's failure
        self.assertIn(old_a, backend.list_snapshot_names())


class FixturesPortableAcrossShells(FakeBinHarness):
    """The fakes must stay POSIX sh / bash 3.2 portable (stock macOS). Drive each one through every
    shell found on this machine (dash = strict POSIX, bash = whatever is installed), bypassing the
    shebang. A shell that is not installed is skipped, never silently passed."""

    def _run(self, shell, fixture, *args):
        import subprocess
        return subprocess.run([shell, os.path.join(FAKEBIN, fixture), *args], capture_output=True, text=True)

    def test_every_fixture_runs_under_each_available_shell(self):
        shells = [p for p in (shutil.which(n) for n in ("dash", "bash", "sh")) if p]
        self.assertTrue(shells, "no shell found")
        for shell in sorted(set(shells)):
            with self.subTest(shell=shell):
                for name in ("zfs_snapshots", "lvm_snapshots"):
                    path = os.path.join(self.state, name)
                    if os.path.exists(path):
                        os.remove(path)
                self.assertEqual(self._run(shell, "zfs", "snapshot", "pool/ds@a").returncode, 0)
                listed = self._run(shell, "zfs", "list", "-H", "-t", "snapshot", "-o", "name", "pool/ds")
                self.assertEqual(listed.stdout.split(), ["pool/ds@a"], listed.stderr)
                usage = self._run(shell, "zfs", "list", "-Hp", "-o", "used,avail", "pool/ds")
                self.assertEqual(usage.stdout.split(), ["10", "90"], usage.stderr)
                self.assertEqual(self._run(shell, "zfs", "destroy", "pool/ds@a").returncode, 0)
                self.assertEqual(self._run(shell, "zfs", "bogus").returncode, 2)
                self.assertEqual(self._run(shell, "lvcreate", "-s", "-n", "s1", "-L1G", "vg/lv").returncode, 0)
                self.assertEqual(self._run(shell, "lvcreate", "-s", "-n", "b@d", "vg/lv").returncode, 3)
                lvs = self._run(shell, "lvs", "--noheadings", "-o", "lv_name", "vg")
                self.assertEqual(lvs.stdout.split(), ["s1", "lv"], lvs.stderr)
                vgs = self._run(shell, "vgs", "--noheadings", "-o", "vg_size,vg_free", "vg")
                self.assertEqual(vgs.stdout.split(), ["100", "90"], vgs.stderr)
                self.assertEqual(self._run(shell, "lvremove", "-f", "vg/s1").returncode, 0)
                self.assertEqual(self._run(shell, "lvs", "x", "vg").stdout.strip(), "")


def _ago_days(days):
    import datetime
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)


if __name__ == "__main__":
    unittest.main()

"""Tests that assert the EXACT command vectors the ZFS and LVM backends run, by replacing subprocess.run with a
recorder/fake. The Dir-backend tests elsewhere in this kit prove the policy logic (usage, cooldown, purge); they
cannot catch a backend that builds the wrong zfs/lvm invocation, which is exactly the bug this file exists to
pin down (owner review of PR #12, 18/10: the LVM backend put "@" into an LV name, which lvcreate rejects, and
never produced a qualified name list/purge could ever match). No real zfs/lvm, no network, no sudo."""
import datetime
import importlib.util
import os
import sys
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib import backends, naming                              # noqa: E402

spec = importlib.util.spec_from_file_location("retention_purge", os.path.join(HERE, "retention-purge.py"))
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


def named_at(prefix, days_ago=0, minutes_ago=0):
    when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago, minutes=minutes_ago)
    return naming.new_name(prefix, when)


class FakeRun:
    """A stateful stand-in for subprocess.run(): a plain list of qualified names ("dataset@name" / "vg/lv@name")
    plays the part of what `zfs list -t snapshot` or `lvs` would really report, and zfs/lvcreate/lvremove calls
    update it. Every call is also recorded verbatim for the command-shape assertions."""

    def __init__(self, used=10, avail=90):
        self.store = []
        self.calls = []
        self.used, self.avail = used, avail

    def __call__(self, argv, capture_output=True, text=True, check=True, timeout=None):
        self.calls.append(list(argv))
        out = unittest.mock.Mock(returncode=0, stdout="")
        if argv[:2] == ["zfs", "list"] and "used,avail" in argv:
            out.stdout = f"{self.used}\t{self.avail}\n"
        elif argv[:2] == ["zfs", "list"]:
            dataset = argv[-1]
            matches = [n for n in self.store
                       if n.split("@")[0] == dataset or n.split("@")[0].startswith(dataset + "/")]
            out.stdout = "".join(n + "\n" for n in matches)
        elif argv[:2] == ["zfs", "snapshot"]:
            self.store.append(argv[2])
        elif argv[:2] == ["zfs", "destroy"]:
            self.store.remove(argv[2])
        elif argv[0] == "vgs":
            # vgs reports (vg_size, vg_free): total and unused, not (used, avail) like zfs -- map so the two
            # backends' usage_percent() agree on the same percentage for the same self.used/self.avail.
            out.stdout = f"{self.used + self.avail}\t{self.avail}\n"
        elif argv[0] == "lvs":
            vg = argv[-1]
            lines = []
            for n in self.store:
                origin, _, snap = n.partition("@")
                if origin.startswith(vg + "/"):
                    lines.append(f"{snap} {origin.split('/', 1)[1]}")
            out.stdout = "".join(line + "\n" for line in lines)
        elif argv[0] == "lvcreate":
            name = argv[argv.index("-n") + 1]
            origin = argv[-1]
            self.store.append(f"{origin}@{name}")
        elif argv[0] == "lvremove":
            target = argv[-1]                                  # "vg/snap-name"
            vg, snap = target.split("/", 1)
            for n in list(self.store):
                o, _, s = n.partition("@")
                if o.startswith(vg + "/") and s == snap:
                    self.store.remove(n)
                    break
        else:
            raise AssertionError(f"unexpected command: {argv!r}")
        return out


class ZfsCommandShapes(unittest.TestCase):
    def test_usage_percent_command(self):
        fake = FakeRun(used=10, avail=90)
        with unittest.mock.patch("subprocess.run", fake):
            pct = backends.Zfs("pool/agent").usage_percent()
        self.assertEqual(fake.calls[-1], ["zfs", "list", "-Hp", "-o", "used,avail", "pool/agent"])
        self.assertEqual(pct, 10.0)

    def test_list_snapshot_names_command(self):
        fake = FakeRun()
        with unittest.mock.patch("subprocess.run", fake):
            backends.Zfs("pool/agent").list_snapshot_names()
        self.assertEqual(fake.calls[-1],
                          ["zfs", "list", "-Hp", "-t", "snapshot", "-r", "-o", "name", "pool/agent"])

    def test_create_snapshot_command(self):
        fake = FakeRun()
        with unittest.mock.patch("subprocess.run", fake):
            backends.Zfs("pool/agent").create_snapshot("pool/agent@agent-gate-20260101-000000")
        self.assertEqual(fake.calls[-1], ["zfs", "snapshot", "pool/agent@agent-gate-20260101-000000"])

    def test_destroy_command(self):
        fake = FakeRun()
        fake.store.append("pool/agent@agent-gate-20260101-000000")
        with unittest.mock.patch("subprocess.run", fake):
            rp.destroy_zfs("pool/agent@agent-gate-20260101-000000")
        self.assertEqual(fake.calls[-1], ["zfs", "destroy", "pool/agent@agent-gate-20260101-000000"])


class LvmCommandShapes(unittest.TestCase):
    def test_usage_percent_command(self):
        fake = FakeRun(used=10, avail=90)
        with unittest.mock.patch("subprocess.run", fake):
            pct = backends.Lvm("vg/lv").usage_percent()
        self.assertEqual(fake.calls[-1],
                          ["vgs", "--noheadings", "--units", "b", "--nosuffix", "-o", "vg_size,vg_free", "vg"])
        self.assertEqual(pct, 10.0)

    def test_list_snapshot_names_command(self):
        fake = FakeRun()
        with unittest.mock.patch("subprocess.run", fake):
            backends.Lvm("vg/lv").list_snapshot_names()
        self.assertEqual(fake.calls[-1], ["lvs", "--noheadings", "-o", "lv_name,origin", "vg"])

    def test_create_snapshot_command_never_puts_an_at_sign_in_the_lv_name(self):
        fake = FakeRun()
        with unittest.mock.patch("subprocess.run", fake):
            backends.Lvm("vg/lv").create_snapshot("vg/lv@agent-gate-20260101-000000")
        self.assertEqual(fake.calls[-1], ["lvcreate", "-s", "-n", "agent-gate-20260101-000000", "vg/lv"])
        self.assertNotIn("@", fake.calls[-1][3])                # the new LV's own name: lvcreate rejects "@"

    def test_destroy_command_targets_the_snapshot_lv_not_the_origin(self):
        fake = FakeRun()
        with unittest.mock.patch("subprocess.run", fake):
            rp.destroy_lvm("vg/lv@agent-gate-20260101-000000")
        self.assertEqual(fake.calls[-1], ["lvremove", "-f", "vg/agent-gate-20260101-000000"])


class ZfsRoundTrip(unittest.TestCase):
    """Fake listing -> decide_and_create creates once -> a second request inside the cooldown is refused ->
    purge selects exactly the old matching names and runs the destroy vector for those only."""

    def setUp(self):
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("sg_host", os.path.join(HERE, "snapshot-gate-host.py"))
        self.sg_host = ilu.module_from_spec(spec)
        spec.loader.exec_module(self.sg_host)
        self.cfg = {"dataset": "pool/agent", "prefix": "agent-gate", "usage_threshold_percent": 85,
                    "cooldown_minutes": 10, "retention_days": 7}

    def test_round_trip(self):
        fake = FakeRun(used=10, avail=90)
        old_ours = f"pool/agent@{named_at('agent-gate', days_ago=10)}"
        foreign_lookalike = f"pool/agent-other@{named_at('agent-gate', days_ago=10)}"
        child_dataset = f"pool/agent/child@{named_at('agent-gate', days_ago=10)}"
        fake.store += [old_ours, foreign_lookalike, child_dataset]

        with unittest.mock.patch("subprocess.run", fake):
            backend = backends.Zfs("pool/agent")
            status1, _reason1, name1 = self.sg_host.decide_and_create(backend, self.cfg)
            self.assertEqual(status1, "OK")
            self.assertIn("snapshot", fake.calls[-1])

            status2, reason2, name2 = self.sg_host.decide_and_create(backend, self.cfg)
            self.assertEqual(status2, "REFUSED")
            self.assertIn("younger than", reason2)
            self.assertEqual(name2, name1)                     # the just-created one, not a new one

            targets = rp.eligible_for_purge(backend, self.cfg)
            target_names = [n for n, _age in targets]
            self.assertEqual(target_names, [old_ours])          # never the foreign or child-dataset entries

            destroy_calls_before = len(fake.calls)
            for n, _age in targets:
                rp.destroy_zfs(n)
            destroy_calls = fake.calls[destroy_calls_before:]
            self.assertEqual(destroy_calls, [["zfs", "destroy", old_ours]])
            self.assertNotIn(foreign_lookalike, [c[-1] for c in destroy_calls])
            self.assertNotIn(child_dataset, [c[-1] for c in destroy_calls])
            self.assertIn(foreign_lookalike, fake.store)         # untouched
            self.assertIn(child_dataset, fake.store)             # untouched


class LvmRoundTrip(unittest.TestCase):
    """Same round trip as ZfsRoundTrip, for the LVM backend."""

    def setUp(self):
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("sg_host2", os.path.join(HERE, "snapshot-gate-host.py"))
        self.sg_host = ilu.module_from_spec(spec)
        spec.loader.exec_module(self.sg_host)
        self.cfg = {"dataset": "vg/lv", "prefix": "agent-gate", "usage_threshold_percent": 85,
                    "cooldown_minutes": 10, "retention_days": 7}

    def test_round_trip(self):
        fake = FakeRun(used=10, avail=90)
        old_ours = f"vg/lv@{named_at('agent-gate', days_ago=10)}"
        foreign_lookalike = f"vg/lv-other@{named_at('agent-gate', days_ago=10)}"    # different origin LV
        other_prefix = f"vg/lv@{named_at('not-ours', days_ago=10)}"                 # same origin, foreign prefix
        fake.store += [old_ours, foreign_lookalike, other_prefix]

        with unittest.mock.patch("subprocess.run", fake):
            backend = backends.Lvm("vg/lv")
            status1, _reason1, name1 = self.sg_host.decide_and_create(backend, self.cfg)
            self.assertEqual(status1, "OK")
            create_call = fake.calls[-1]
            self.assertEqual(create_call[0], "lvcreate")
            self.assertNotIn("@", create_call[create_call.index("-n") + 1])

            status2, reason2, name2 = self.sg_host.decide_and_create(backend, self.cfg)
            self.assertEqual(status2, "REFUSED")
            self.assertIn("younger than", reason2)
            self.assertEqual(name2, name1)

            targets = rp.eligible_for_purge(backend, self.cfg)
            target_names = [n for n, _age in targets]
            self.assertEqual(target_names, [old_ours])

            destroy_calls_before = len(fake.calls)
            for n, _age in targets:
                rp.destroy_lvm(n)
            destroy_calls = fake.calls[destroy_calls_before:]
            # only one destroy call was made at all, and it targeted old_ours's own snapshot name -- never the
            # foreign-origin (lv-other) or foreign-prefix (not-ours) entry, which were never in `targets`
            self.assertEqual(destroy_calls, [["lvremove", "-f", "vg/" + old_ours.split("@", 1)[1]]])
            self.assertIn(foreign_lookalike, fake.store)          # untouched
            self.assertIn(other_prefix, fake.store)               # untouched
            self.assertNotIn(old_ours, fake.store)                # the only one actually removed


if __name__ == "__main__":
    unittest.main()

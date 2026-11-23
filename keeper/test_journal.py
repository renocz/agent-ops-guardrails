#!/usr/bin/env python3
"""Tests for the keeper journal (keeper/journal.py) and its wiring in keeperd.

Run: python3 keeper/test_journal.py   (no network, no install). Standard library only.
What these cannot cover: root-only file attributes (chattr +a, chflags sappnd), a real second user reading the file
(CI runs as an ordinary user or root, so access is checked through the mode bits), and macOS.
"""
import json, os, shutil, stat, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import journal, keeperd                                            # noqa: E402
from test_keeper import Base, bash, OWNER, CHAT                    # noqa: E402

FAKE_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"        # obviously fake, built in two parts


class JournalFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="kj", dir="/tmp")
        self.path = os.path.join(self.dir, "state", "journal.jsonl")
        self.j = journal.Journal(self.path, host="testhost")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def lines(self):
        with open(self.path) as f:
            return [json.loads(x) for x in f]

    def test_records_are_chained_and_verify(self):
        for i in range(5):
            self.assertTrue(self.j.append("allowed", plans=[f"p{i}"], result="allowed"))
        ok, n, why = journal.verify(self.path)
        self.assertEqual((ok, n, why), (True, 5, None))
        recs = self.lines()
        self.assertEqual([r["seq"] for r in recs], [1, 2, 3, 4, 5])
        self.assertEqual(recs[0]["prev"], journal.GENESIS)
        self.assertEqual(recs[0]["host"], "testhost")
        for key in ("at", "utc", "identity", "action", "plans", "tier", "opinion", "result"):
            self.assertIn(key, recs[0])
        self.assertEqual(recs[0]["tier"], "none")
        self.assertEqual(recs[0]["opinion"], {"kind": "none"})

    def test_an_edited_line_breaks_the_chain(self):
        for i in range(4):
            self.j.append("allowed", plans=[f"p{i}"], result="allowed")
        raw = open(self.path).read().replace('"p1"', '"px"')
        open(self.path, "w").write(raw)
        ok, n, why = journal.verify(self.path)
        self.assertFalse(ok)
        self.assertIn("chain break", why)

    def test_a_deleted_middle_line_is_detected(self):
        for i in range(4):
            self.j.append("allowed", result=str(i))
        rows = open(self.path).read().splitlines()
        open(self.path, "w").write("\n".join([rows[0], rows[2], rows[3]]) + "\n")
        self.assertFalse(journal.verify(self.path)[0])

    def test_reordered_lines_are_detected(self):
        for i in range(4):
            self.j.append("allowed", result=str(i))
        rows = open(self.path).read().splitlines()
        open(self.path, "w").write("\n".join([rows[0], rows[2], rows[1], rows[3]]) + "\n")
        self.assertFalse(journal.verify(self.path)[0])

    def test_restart_continues_the_same_chain(self):
        self.j.append("allowed", result="a")
        self.j.append("allowed", result="b")
        j2 = journal.Journal(self.path, host="testhost")
        self.assertTrue(j2.append("allowed", result="c"))
        self.assertEqual(journal.verify(self.path), (True, 3, None))

    def test_a_torn_last_line_is_recovered_and_still_verifies(self):
        self.j.append("allowed", result="a")
        with open(self.path, "a") as f:
            f.write('{"seq":2,"prev":"abc","ev')                     # a crash mid-write, no newline
        ok, _n, why = journal.verify(self.path)
        self.assertFalse(ok)                                         # as it stands, it is reported
        self.assertIn("torn", why)
        j2 = journal.Journal(self.path, host="testhost")                # no newline was written by the crash
        self.assertTrue(j2.append("keeper-start", result="restart"))
        self.assertTrue(j2.append("allowed", result="after"))
        self.assertEqual(journal.verify(self.path), (True, 3, None))
        rows = open(self.path).read().splitlines()
        self.assertIn("recovered_torn_line", json.loads(rows[-2]))      # the new record is on its own line, not glued to the torn one
        self.assertNotIn("recovered_torn_line", json.loads(rows[-1]))

    def test_a_torn_line_that_is_not_acknowledged_fails(self):
        self.j.append("allowed", result="a")
        with open(self.path, "a") as f:
            f.write("garbage\n")
        self.j.append("allowed", result="b")                         # same instance: no recovery record
        self.assertFalse(journal.verify(self.path)[0])

    def test_file_is_private_and_opened_for_append(self):
        self.j.append("allowed", result="a")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)
        import fcntl
        self.assertTrue(fcntl.fcntl(self.j.fd, fcntl.F_GETFL) & os.O_APPEND)

    REALISTIC = [
        "mysql -u root -phunter2x -e 'select 1'", "curl -u admin:s3cretPw https://x.example/api",
        "psql postgres://app:Pa55w0rd@db/app -c 'select 1'", "docker run -e DB_PASS=abc123 img",
        "export TOKEN=abc123def", "sshpass -p 'open sesame' ssh host uptime", "htpasswd -b /etc/htpasswd bob hunter2",
        "echo secret123 | docker login -u u --password-stdin", "curl -H 'X-Api-Key: k3y' https://x.example",
        "openssl enc -k mypass -in a", "kubectl create secret generic s --from-literal=pw=letmein",
        f"curl -H 'Authorization: Bearer {FAKE_TOKEN}' https://x.example/a"]
    SECRETS = ["hunter2x", "s3cretPw", "Pa55w0rd", "abc123", "abc123def", "open sesame", "hunter2", "secret123", "k3y",
               "mypass", "letmein", FAKE_TOKEN, FAKE_TOKEN[4:]]

    def test_no_command_text_ever_reaches_the_file(self):
        # the keeper's masker alone misses 8 of these (measured), so the journal does not keep the text at all
        for c in self.REALISTIC:
            self.j.append("allowed", action={"kind": "call", "shape": "x", "cmd": c})
        raw = open(self.path).read()
        for secret in self.SECRETS:
            self.assertNotIn(secret, raw, secret)
        for rec in self.lines():
            self.assertNotIn("cmd", rec["action"])
            self.assertEqual(len(rec["action"]["cmd_hmac"]), 64)
        self.assertEqual(self.lines()[0]["action"]["cmd_len"], len(self.REALISTIC[0]))

    def test_the_fingerprint_is_an_hmac_not_a_plain_hash(self):
        import hashlib
        self.j.append("allowed", action={"cmd": "mysql -phunter2x"})
        h = self.lines()[-1]["action"]["cmd_hmac"]
        self.assertNotEqual(h, hashlib.sha256(b"mysql -phunter2x").hexdigest())     # no offline dictionary attack on it
        self.assertEqual(self.j.fingerprint("mysql -phunter2x"), h)                 # stable: shows "same command twice"
        other = journal.Journal(os.path.join(self.dir, "other", "journal.jsonl"), host="h")
        self.assertNotEqual(other.fingerprint("mysql -phunter2x"), h)               # key-dependent

    def test_the_key_is_private_never_in_the_journal_and_survives_restart(self):
        self.j.append("allowed", action={"cmd": "ls"})
        kp = os.path.join(os.path.dirname(self.path), "journal.key")
        self.assertEqual(stat.S_IMODE(os.stat(kp).st_mode), 0o600)
        key = open(kp, "rb").read()
        self.assertGreaterEqual(len(key), 32)
        self.assertNotIn(key.hex(), open(self.path).read())
        self.assertEqual(journal.Journal(self.path, host="h").fingerprint("ls"), self.j.fingerprint("ls"))

    def test_without_a_usable_key_there_is_no_fingerprint_rather_than_a_plain_hash(self):
        open(os.path.join(os.path.dirname(self.path), "journal.key"), "wb").write(b"short")
        j = journal.Journal(self.path, host="h")
        j.append("allowed", action={"cmd": "ls"})
        self.assertIsNone(self.lines()[-1]["action"]["cmd_hmac"])

    def test_a_failed_write_never_raises_and_flips_ok(self):
        blocker = os.path.join(self.dir, "afile")
        open(blocker, "w").write("x")
        j = journal.Journal(os.path.join(blocker, "sub", "journal.jsonl"))
        self.assertFalse(j.ok)
        self.assertFalse(j.append("allowed", result="a"))            # no exception
        os.close(self.j.fd)                                          # a write on a closed descriptor
        self.assertFalse(self.j.append("allowed", result="b"))
        self.assertFalse(self.j.ok)


class KeeperWiring(Base):
    def entries(self):
        with open(self.k.journal_path) as f:
            return [json.loads(x) for x in f]

    def test_start_is_recorded_and_the_journal_is_ready(self):
        self.assertTrue(self.k.journal.ok)
        self.assertEqual(self.entries()[0]["event"], "keeper-start")

    def test_state_dir_and_journal_are_not_reachable_by_the_agent(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg["state_dir"]).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.k.journal_path).st_mode), 0o600)

    def test_a_full_plan_lifecycle_is_journaled_with_identity_plan_and_result(self):
        self.approve("id=web; targets=web; actions=deploy; ttl=30")
        r = self.k.check("s1", *bash("docker restart web"), actor="tester", peer_uid=4242)
        self.assertEqual(r["decision"], "allow")
        r = self.k.check("s1", *bash("docker restart db"), actor="tester", peer_uid=4242)
        self.assertEqual(r["decision"], "deny")
        by_event = {}
        for e in self.entries():
            by_event.setdefault(e["event"], []).append(e)
        for ev in ("proposed", "approved", "allowed", "denied"):
            self.assertIn(ev, by_event, ev)
        allowed, denied = by_event["allowed"][0], by_event["denied"][0]
        self.assertEqual(allowed["identity"], {"session": "s1", "actor": "tester", "peer_uid": 4242})
        self.assertEqual(allowed["plans"], ["web"])
        self.assertEqual(allowed["action"]["category"], "deploy")
        self.assertNotIn("cmd", allowed["action"])                 # the command text is never journaled
        self.assertEqual(allowed["action"]["cmd_len"], len("docker restart web"))
        self.assertEqual(len(allowed["action"]["cmd_hmac"]), 64)
        self.assertEqual(allowed["result"], "allowed")
        self.assertEqual(allowed["tier"], "none")
        self.assertEqual(denied["result"], "denied")
        self.assertEqual(by_event["approved"][0]["identity"]["actor"], "owner-telegram")
        self.assertEqual(journal.verify(self.k.journal_path)[0], True)

    def test_observe_mode_records_would_deny_as_allowed(self):
        k = keeperd.Keeper(dict(self.cfg, mode="observe", state_dir=os.path.join(self.dir, "obs")), self.bot, clock=self.clock)
        self.assertEqual(k.check("s9", *bash("docker restart web"))["decision"], "allow")
        e = [x for x in map(json.loads, open(k.journal_path)) if x["event"] == "would-deny"][0]
        self.assertEqual(e["result"], "allowed (observe mode)")

    def test_the_agents_free_text_never_reaches_the_journal(self):
        marker = "IGNORE-PREVIOUS-INSTRUCTIONS-MARKER"
        ok, _ = self.plan("id=p1; targets=web; actions=deploy; ttl=30", text=marker)
        self.k.decide(OWNER, CHAT, ok)
        self.assertNotIn(marker, open(self.k.journal_path).read())

    def test_revocation_is_journaled(self):
        self.approve("id=p1; targets=web; actions=deploy; ttl=30")
        self.k.decide(OWNER, CHAT, "stop:s1")
        revoked = [e for e in self.entries() if e["event"] == "revoked-all"]
        self.assertEqual(len(revoked), 1)
        self.assertEqual(revoked[0]["result"], "revoked")

    def test_a_journal_failure_does_not_change_the_decision(self):
        self.approve("id=web; targets=web; actions=deploy; ttl=30")
        os.close(self.k.journal.fd)
        self.assertEqual(self.k.check("s1", *bash("docker restart web"))["decision"], "allow")
        self.assertEqual(self.k.check("s1", *bash("docker restart db"))["decision"], "deny")
        self.assertFalse(self.k.journal.ok)

    def test_a_journal_failure_is_reported_once_in_the_event_log(self):
        self.approve("id=web; targets=web; actions=deploy; ttl=30")
        os.close(self.k.journal.fd)
        for _ in range(3):
            self.k.check("s1", *bash("docker restart web"))
        self.assertEqual(self.log_events().count("journal-write-failed"), 1)

    def test_reads_are_not_journaled_in_this_version(self):
        n = len(self.entries())
        self.assertEqual(self.k.check("s1", *bash("ls -la /etc"))["decision"], "allow")
        self.assertEqual(len(self.entries()), n)

    def test_the_cli_refuses_anyone_but_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(keeperd.journal_verify_cli(["verify"]), 2)


class InstallerWiring(unittest.TestCase):
    def test_the_installer_ships_journal_py_and_a_root_only_wrapper(self):
        tmp = tempfile.mkdtemp(prefix="kjp", dir="/tmp")
        try:
            who = "nobody" if os.geteuid() == 0 else subprocess.check_output(["id", "-un"], text=True).strip()   # never root
            r = subprocess.run([os.path.join(HERE, "install-keeper.sh"), "--agent-user", who,
                                "--owner-id", "1", "--prefix", tmp], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            found = []
            for root, _d, files in os.walk(tmp):
                found += [os.path.join(root, f) for f in files]
            self.assertTrue(any(p.endswith("/lib/journal.py") for p in found), found)
            wrapper = [p for p in found if p.endswith("/bin/keeper-journal")]
            self.assertEqual(len(wrapper), 1)
            self.assertEqual(stat.S_IMODE(os.stat(wrapper[0]).st_mode) & 0o077, 0)     # no group or other access
            self.assertIn("--journal", open(wrapper[0]).read())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

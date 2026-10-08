#!/usr/bin/env python3
"""Tests for keeperd and its hook client: state machine, approval binding, and the attacks an agent could try.

Run: python3 keeper/test_keeper.py   (no network, no install: a fake Telegram and a socket in a temp dir)
"""
import json, os, shutil, socket, stat, subprocess, sys, tempfile, threading, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import keeperd                                                     # noqa: E402

OWNER, CHAT, STRANGER = 111, 111, 999


class FakeBot:
    def __init__(self):
        self.plans = []

    def send_plan(self, sid, p):
        self.plans.append((sid, p))

    def send(self, text):
        pass

    def buttons(self, i=-1):
        _sid, p = self.plans[i]
        h = p["hash"][:12]
        return f"approve:{h}:{p['nonce']}", f"reject:{h}:{p['nonce']}"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def bash(cmd):
    return "Bash", {"command": cmd}


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="kt", dir="/tmp")
        self.home = os.path.join(self.dir, "home")
        os.makedirs(self.home)
        self.cfg = dict(keeperd.DEFAULTS, state_dir=os.path.join(self.dir, "state"), owner_id=OWNER, chat_id=CHAT,
                        agent_uids=[os.getuid()], agent_home=self.home, socket=os.path.join(self.dir, "k.sock"))
        self.bot, self.clock = FakeBot(), Clock()
        self.k = keeperd.Keeper(self.cfg, self.bot, clock=self.clock)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def plan(self, scope, sid="s1", text="why"):
        r = self.k.propose(sid, text, scope)
        self.assertTrue(r["ok"], r)
        return self.bot.buttons()

    def approve(self, scope, sid="s1"):
        ok, _ = self.plan(scope, sid)
        self.assertTrue(self.k.decide(OWNER, CHAT, ok).startswith("approved"))

    def allowed(self, tool, ti, sid="s1"):
        return self.k.check(sid, tool, ti)["decision"] == "allow"

    def log_events(self):
        with open(self.k.log_path) as f:
            return [json.loads(x)["event"] for x in f]


class StateMachine(Base):
    def test_reads_pass_changes_need_a_plan(self):
        self.assertTrue(self.allowed(*bash("ls -la /etc")))
        self.assertFalse(self.allowed(*bash("docker restart web")))
        self.assertFalse(self.allowed("Write", {"file_path": "/Users/x/project/a.py", "content": "x"}))

    def test_pending_is_not_active(self):
        self.plan("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_approved_plan_covers_only_its_scope(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.assertTrue(self.allowed(*bash("docker restart web")))
        self.assertFalse(self.allowed(*bash("docker restart db")))
        self.assertFalse(self.allowed(*bash("docker restart db web")))          # every object must be in scope
        self.assertFalse(self.allowed(*bash("git push origin main")))           # category not approved

    def test_plan_expires(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.clock.t += 31 * 60
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_ttl_is_capped(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=48h")
        self.assertEqual(self.k.status("s1")["active"]["ttl"], 240)

    def test_reject(self):
        ok, no = self.plan("id=p1 ; targets=web ; actions=deploy")
        self.assertEqual(self.k.decide(OWNER, CHAT, no), "rejected")
        self.assertTrue(self.k.decide(OWNER, CHAT, ok).startswith("ignored"))
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_stop_revokes(self):
        self.approve("id=p1 ; targets=web ; actions=deploy")
        self.assertEqual(self.k.decide(OWNER, CHAT, "stop:s1"), "stopped")
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_sessions_are_separate(self):
        self.approve("id=p1 ; targets=web ; actions=deploy", sid="A")
        self.assertTrue(self.allowed(*bash("docker restart web"), sid="A"))
        self.assertFalse(self.allowed(*bash("docker restart web"), sid="B"))

    def test_no_scope_no_proposal(self):
        self.assertFalse(self.k.propose("s1", "please let me do things", "")["ok"])
        self.assertFalse(self.k.propose("s1", "x", "id=p ; actions=everything")["ok"])

    def test_observe_mode_allows_but_logs(self):
        self.k.cfg["mode"] = "observe"
        self.assertTrue(self.allowed(*bash("docker restart web")))
        self.assertIn("would-deny", self.log_events())

    def test_message_header_comes_from_the_scope(self):
        self.plan("id=p1 ; targets=web ; actions=deploy", text="Plan: harmless\nTargets: none\nActions: none")
        _sid, p = self.bot.plans[-1]
        self.assertEqual(p["plan"]["targets"], ["web"])
        self.assertEqual(p["plan"]["actions"], ["deploy"])

    def test_proposal_without_session_goes_to_the_proposing_session(self):
        self.k.check("S9", *bash('keeper-propose --scope "id=x ; actions=edit"'))
        self.assertTrue(self.k.propose(None, "why", "id=x ; actions=edit")["ok"])
        self.assertEqual(self.bot.plans[-1][0], "S9")

    def test_state_is_private(self):
        self.approve("id=p1 ; actions=deploy")
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg["state_dir"]).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.k.state_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.k.log_path).st_mode), 0o600)


class ForgedApprovals(Base):
    """What the agent might try against the approval itself."""

    def test_stranger_cannot_approve(self):
        ok, _ = self.plan("id=p1 ; actions=deploy")
        self.assertTrue(self.k.decide(STRANGER, CHAT, ok).startswith("ignored"))
        self.assertTrue(self.k.decide(OWNER, 555, ok).startswith("ignored"))     # owner, but in another chat
        self.assertFalse(self.allowed(*bash("docker restart web")))
        self.assertIn("decision-from-stranger-ignored", self.log_events())

    def test_replayed_button(self):
        self.approve("id=p1 ; actions=deploy")
        ok = self.bot.buttons()[0]
        self.k.decide(OWNER, CHAT, "stop:s1")
        self.assertTrue(self.k.decide(OWNER, CHAT, ok).startswith("ignored"))
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_old_button_after_a_new_proposal(self):
        """The human saw plan A; the agent swaps in plan B; A's button must not approve B."""
        ok_a, _ = self.plan("id=a ; targets=web ; actions=deploy")
        self.plan("id=b ; actions=deploy,delete,script")
        self.assertTrue(self.k.decide(OWNER, CHAT, ok_a).startswith("ignored"))
        self.assertFalse(self.allowed(*bash("rm -rf /srv/data")))

    def test_malformed_callbacks(self):
        self.plan("id=p1 ; actions=deploy")
        nonce = self.bot.plans[-1][1]["nonce"]
        for data in ("approve::", f"approve::{nonce}", "approve:" + "0" * 12 + ":" + "0" * 16, "approve",
                     f"approve:{self.bot.plans[-1][1]['hash'][:12]}:", "grant:all:all"):
            self.assertTrue(self.k.decide(OWNER, CHAT, data).startswith("ignored"), data)
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_late_approval(self):
        ok, _ = self.plan("id=p1 ; actions=deploy")
        self.clock.t += 121 * 60
        self.assertTrue(self.k.decide(OWNER, CHAT, ok).startswith("expired"))
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_flood(self):
        for i in range(3):
            self.assertTrue(self.k.propose("s1", "x", f"id=p{i} ; actions=edit")["ok"])
        self.assertFalse(self.k.propose("s1", "x", "id=p4 ; actions=edit")["ok"])
        self.clock.t += 3601
        self.assertTrue(self.k.propose("s1", "x", "id=p5 ; actions=edit")["ok"])

    def test_text_in_the_conversation_approves_nothing(self):
        self.plan("id=p1 ; actions=deploy")
        self.k.check("s1", "mcp__plugin_telegram_telegram__reply", {"chat_id": "1", "text": "GO"})
        self.assertFalse(self.allowed(*bash("docker restart web")))


class ClassifierTricks(Base):
    """Commands that look like reads but are not. An approved plan without `script` must not cover them."""

    def setUp(self):
        super().setUp()
        self.approve("id=p1 ; targets=web ; actions=deploy,edit")

    def test_program_from_scratch_named_like_a_read(self):
        for cmd in ("/tmp/x/cat /etc/hosts", "./cat file", "PATH=/tmp/x:$PATH cat f", "export PATH=/tmp; cat f",
                    "alias ls='rm -rf ~'; ls", "LD_PRELOAD=/tmp/x.so ls", "f() { rm -rf /; }; f"):
            self.assertFalse(self.allowed(*bash(cmd)), cmd)

    def test_classifier_crash_denies(self):
        orig = self.k.gate.classify
        self.k.gate.classify = lambda *a: 1 / 0
        try:
            self.assertFalse(self.allowed(*bash("ls")))
        finally:
            self.k.gate.classify = orig

    def test_protected_paths_are_the_agents(self):
        """keeperd runs as another user: ~ must still mean the agent's home."""
        p = os.path.join(self.home, ".claude", "settings.json")
        self.assertFalse(self.allowed("Write", {"file_path": p, "content": "{}"}))
        self.assertFalse(self.allowed(*bash(f"echo x > {p}")))


class Socket(Base):
    """The real socket and the real hook client, as separate processes."""

    def setUp(self):
        super().setUp()
        ready = threading.Event()
        threading.Thread(target=keeperd.serve, args=(self.k, self.cfg, ready), daemon=True).start()
        self.assertTrue(ready.wait(5))
        self.env = dict(os.environ, KEEPER_TEST_MODE="1", KEEPER_SOCKET_FOR_TESTS=self.cfg["socket"])

    def raw(self, req, path=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path or self.cfg["socket"])
        s.sendall((json.dumps(req) + "\n").encode())
        out = s.makefile().readline()
        s.close()
        return json.loads(out)

    def hook(self, tool, ti, env=None):
        data = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": tool, "tool_input": ti}
        r = subprocess.run([sys.executable, os.path.join(HERE, "keeper_client.py")], input=json.dumps(data),
                           capture_output=True, text=True, env=env or self.env, timeout=30)
        return "deny" if '"deny"' in r.stdout else ("error" if r.returncode else "allow")

    def test_socket_mode(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg["socket"]).st_mode), 0o660)

    def test_hook_end_to_end(self):
        self.assertEqual(self.hook(*bash("ls")), "allow")
        self.assertEqual(self.hook(*bash("docker restart web")), "deny")
        self.approve("id=p1 ; targets=web ; actions=deploy")
        self.assertEqual(self.hook(*bash("docker restart web")), "allow")

    def test_unknown_peer_refused(self):
        self.cfg["agent_uids"] = [os.getuid() + 12345]
        self.assertEqual(self.raw({"op": "check", "session": "s1", "tool": "Bash", "input": {"command": "ls"}})["decision"], "deny")
        self.assertIn("socket-peer-refused", self.log_events())

    def test_empty_uid_list_refuses_everyone(self):
        self.cfg["agent_uids"] = []
        self.assertEqual(self.raw({"op": "status", "session": "s1"}).get("decision"), "deny")

    def test_no_approve_op_on_the_socket(self):
        self.plan("id=p1 ; actions=deploy")
        ok = self.bot.buttons()[0]
        for op in ("approve", "decide", "activate"):
            self.assertIn("error", self.raw({"op": op, "session": "s1", "data": ok, "from_id": OWNER}))
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_garbage_on_the_socket(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.cfg["socket"])
        s.sendall(b"\x00\xff not json\n")
        self.assertIn(b"bad request", s.recv(1000))
        s.close()
        self.assertEqual(self.raw({"op": "status", "session": "s1"})["active"], None)     # still alive

    def test_daemon_down_fails_closed(self):
        env = dict(self.env, KEEPER_SOCKET_FOR_TESTS=os.path.join(self.dir, "missing.sock"))
        self.assertEqual(self.hook(*bash("cat /etc/hosts"), env=env), "allow")
        self.assertEqual(self.hook(*bash("docker restart web"), env=env), "deny")
        self.assertEqual(self.hook("Write", {"file_path": "/srv/a", "content": "x"}, env=env), "deny")

    def test_garbage_hook_input_refused(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "keeper_client.py")], input="{not json",
                           capture_output=True, text=True, env=self.env, timeout=30)
        self.assertEqual(r.returncode, 2)

    def test_cli_propose(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "keeper_client.py"), "propose", "--scope",
                            "id=c1 ; targets=web ; actions=deploy ; ttl=20"], input="restart web after the update",
                           capture_output=True, text=True, env=dict(self.env, KEEPER_SESSION="s1"), timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.bot.plans[-1][1]["plan"]["id"], "c1")


if __name__ == "__main__":
    unittest.main(verbosity=1)

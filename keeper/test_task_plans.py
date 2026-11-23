#!/usr/bin/env python3
"""Tests for plans that last as long as the task (issue 18): `ttl=done[,max=...]`, the hard ceiling, the frozen scope,
`keeper-done`, session end, manual revocation, and the journal of what each plan really covered.

Run: python3 keeper/test_task_plans.py   (no network, no install). Standard library only.
Not covered: Claude Code really firing its SessionEnd hook (assumed from its documentation, never run here).
"""
import json, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import journal, keeper_client, keeperd                              # noqa: E402
from test_keeper import Base, bash, OWNER, CHAT                    # noqa: E402

H = 3600
DONE = "id=night; targets=web; actions=deploy; ttl=done"


class TaskPlans(Base):
    def entries(self, event=None):
        with open(self.k.journal_path) as f:
            rows = [json.loads(x) for x in f]
        return [r for r in rows if event is None or r["event"] == event]

    def active(self, sid="s1"):
        return self.k.session(sid).get("active") or []

    def covers(self, cmd, sid="s1"):
        return self.k.check(sid, *bash(cmd))["decision"] == "allow"

    def advance(self, seconds):
        self.clock.t += seconds


class Lifetime(TaskPlans):
    def test_a_ttl_done_plan_is_parsed_and_gets_the_ceiling_without_max(self):
        self.approve(DONE)
        a = self.active()[0]
        self.assertTrue(a["until_done"])
        self.assertTrue(a["plan"]["until_done"])
        self.assertEqual(a["plan"]["ttl"], 1440)
        self.assertEqual(a["limit_kind"], "ceiling")

    def test_the_declared_max_is_kept_and_shown_on_the_card(self):
        ok, _ = self.plan("id=night; targets=web; actions=deploy; ttl=done,max=18h")
        card, kb = keeperd.render_plan_card("en", self.k.state["sessions"]["s1"]["pending"])
        self.assertIn("until the task is done, at most 1080 min", card)
        self.assertTrue(self.k.decide(OWNER, CHAT, ok).startswith("approved until the task is done"))
        self.assertEqual(self.active()[0]["limit_kind"], "declared-max")

    def test_the_card_in_french(self):
        self.plan(DONE)
        card, _kb = keeperd.render_plan_card("fr", self.k.state["sessions"]["s1"]["pending"])
        self.assertIn("jusqu'à la fin de la tâche", card)

    def test_a_declared_max_above_the_ceiling_is_clamped(self):
        self.approve("id=night; targets=web; actions=deploy; ttl=done,max=99h")
        self.assertEqual(self.active()[0]["plan"]["ttl"], 1440)

    def test_a_config_ceiling_above_24h_is_clamped_to_24h(self):
        k = keeperd.Keeper(dict(self.cfg, until_done_ceiling_min=99999, state_dir=os.path.join(self.dir, "s2")),
                           self.bot, clock=self.clock)
        self.assertEqual(k.until_done_ceiling, 1440)

    def test_a_smaller_config_ceiling_wins_over_the_declared_max(self):
        k = keeperd.Keeper(dict(self.cfg, until_done_ceiling_min=600, state_dir=os.path.join(self.dir, "s3")),
                           self.bot, clock=self.clock)
        self.approve_on(k, "id=night; targets=web; actions=deploy; ttl=done,max=18h")
        self.assertEqual(k.session("s1")["active"][0]["plan"]["ttl"], 600)

    def test_a_garbage_config_ceiling_falls_back_to_24h(self):
        k = keeperd.Keeper(dict(self.cfg, until_done_ceiling_min="soon", state_dir=os.path.join(self.dir, "s4")),
                           self.bot, clock=self.clock)
        self.assertEqual(k.until_done_ceiling, 1440)

    def test_a_fixed_ttl_is_unchanged(self):
        self.approve("id=a; targets=web; actions=deploy")
        self.assertEqual(self.active()[0]["plan"]["ttl"], 60)
        self.approve("id=b; targets=web; actions=deploy; ttl=10h")
        self.assertEqual(self.active()[1]["plan"]["ttl"], 240)
        self.assertNotIn("until_done", self.active()[1]["plan"])
        self.assertNotIn("max_min", self.active()[1]["plan"])

    def test_max_without_ttl_done_means_nothing(self):
        self.approve("id=a; targets=web; actions=deploy; ttl=30; max=5h")
        self.assertEqual(self.active()[0]["plan"]["ttl"], 30)

    def test_the_plan_covers_the_whole_night_then_stops_at_its_declared_max(self):
        self.approve("id=night; targets=web; actions=deploy; ttl=done,max=18h")
        self.assertTrue(self.covers("docker restart web"))
        self.advance(12 * H)                                       # started in the evening, checked the next morning
        self.assertTrue(self.covers("docker restart web"))
        self.advance(5 * H)                                        # 17 h
        self.assertTrue(self.covers("docker restart web"))
        self.advance(2 * H)                                        # 19 h > the declared 18 h
        self.assertFalse(self.covers("docker restart web"))
        ended = self.entries("plan-ended")[-1]
        self.assertEqual(ended["result"], "declared-max")

    def test_a_plan_without_max_stops_at_the_24h_ceiling(self):
        self.approve(DONE)
        self.advance(23 * H)
        self.assertTrue(self.covers("docker restart web"))
        self.advance(2 * H)
        self.assertFalse(self.covers("docker restart web"))
        self.assertEqual(self.entries("plan-ended")[-1]["result"], "ceiling")

    def test_a_fixed_plan_still_expires_on_its_ttl(self):
        self.approve("id=a; targets=web; actions=deploy; ttl=30")
        self.advance(31 * 60)
        self.assertFalse(self.covers("docker restart web"))
        self.assertEqual(self.entries("plan-ended")[-1]["result"], "ttl-expired")


class FrozenScope(TaskPlans):
    def test_a_long_life_never_widens_what_the_plan_covers(self):
        self.approve(DONE)
        self.advance(15 * H)
        self.assertTrue(self.covers("docker restart web"))
        self.assertFalse(self.covers("docker restart db"))         # another target
        self.assertFalse(self.covers("rm -rf /srv/data/old"))      # another action
        self.assertFalse(self.covers("docker volume prune -f"))

    def test_proposing_a_wider_plan_with_the_same_id_widens_nothing_until_it_is_approved(self):
        self.approve(DONE)
        self.plan("id=night; targets=web,db; actions=deploy,delete; ttl=done")         # pending, not approved
        self.assertFalse(self.covers("docker restart db"))
        self.assertEqual(self.active()[0]["plan"]["targets"], ["web"])

    def test_the_scope_stored_in_the_entry_is_the_scope_that_was_approved(self):
        self.approve(DONE)
        before = json.dumps(self.active()[0]["plan"], sort_keys=True)
        self.covers("docker restart web")
        self.advance(10 * H)
        self.covers("docker restart web")
        self.assertEqual(json.dumps(self.active()[0]["plan"], sort_keys=True), before)


class Ending(TaskPlans):
    def test_keeper_done_with_an_id_ends_that_plan_and_journals_what_it_covered(self):
        self.approve(DONE)
        self.covers("docker restart web")
        self.covers("docker restart web")
        r = self.k.check("s1", *bash("keeper-done --id night"))
        self.assertEqual(r["decision"], "deny")                    # nothing to run
        self.assertIn("night", r["reason"])
        self.assertFalse(self.covers("docker restart web"))
        e = self.entries("plan-ended")[-1]
        self.assertEqual((e["result"], e["plans"]), ("done", ["night"]))
        self.assertEqual(e["action"]["calls"], 2)
        self.assertEqual(e["action"]["categories"], {"deploy": 2})
        self.assertEqual(e["action"]["targets_touched"], ["web"])
        self.assertTrue(e["action"]["until_done"])
        for key in ("started", "ended"):
            self.assertIn(key, e["action"])
        self.assertNotIn("docker", json.dumps(e))                  # the summary carries no command text
        self.assertEqual(journal.verify(self.k.journal_path)[0], True)

    def test_keeper_done_without_an_id_ends_only_the_until_done_plans(self):
        self.approve(DONE)
        self.approve("id=fixed; targets=api; actions=edit; ttl=60")
        self.k.check("s1", *bash("keeper-done"))
        self.assertEqual([a["plan"]["id"] for a in self.active()], ["fixed"])

    def test_keeper_done_can_only_end_never_widen_and_an_unknown_id_ends_nothing(self):
        self.approve(DONE)
        r = self.k.check("s1", *bash("keeper-done --id nope"))
        self.assertIn("no plan to end", r["reason"])
        self.assertEqual(len(self.active()), 1)

    def test_keeper_done_with_a_malformed_id_is_not_intercepted(self):
        self.approve(DONE)
        self.k.check("s1", *bash("keeper-done --id 'a;b'"))
        self.assertEqual(len(self.active()), 1)

    def test_keeper_done_of_another_session_does_not_touch_this_one(self):
        self.approve(DONE)
        self.k.check("s2", *bash("keeper-done --id night"))
        self.assertEqual(len(self.active("s1")), 1)

    def test_session_end_ends_until_done_plans_of_that_session_only(self):
        self.approve(DONE)
        self.approve("id=fixed; targets=api; actions=edit; ttl=60")
        self.approve_on(self.k, DONE, sid="s2")
        self.assertEqual(self.k.session_end("s1", peer_uid=7), ["night"])
        self.assertEqual([a["plan"]["id"] for a in self.active("s1")], ["fixed"])
        self.assertEqual(len(self.active("s2")), 1)
        e = self.entries("plan-ended")[-1]
        self.assertEqual(e["result"], "session-end")

    def test_session_end_does_nothing_with_shared_plans(self):
        k = keeperd.Keeper(dict(self.cfg, shared_plans=True, state_dir=os.path.join(self.dir, "sh")), self.bot, clock=self.clock)
        self.approve_on(k, DONE)
        self.assertEqual(k.session_end("s1"), [])
        self.assertEqual(len(k.session("s1")["active"]), 1)

    def test_manual_revocation_and_the_emergency_stop_record_their_reason(self):
        self.approve(DONE)
        self.approve("id=other; targets=api; actions=edit; ttl=60")
        self.k.decide(OWNER, CHAT, "stop:s1")
        reasons = sorted(e["result"] for e in self.entries("plan-ended"))
        self.assertEqual(reasons, ["stopped", "stopped"])
        self.assertEqual(self.active(), [])
        self.assertFalse(self.covers("docker restart web"))

    def test_revoking_one_plan_by_id(self):
        self.approve(DONE)
        self.approve("id=other; targets=api; actions=edit; ttl=60")
        self.k._revoke_all("night")
        self.assertEqual([a["plan"]["id"] for a in self.active()], ["other"])
        self.assertEqual(self.entries("plan-ended")[-1]["result"], "revoked")

    def test_eviction_and_renewal_end_the_old_entry_with_their_reason(self):
        k = keeperd.Keeper(dict(self.cfg, max_proposals_per_hour=20, state_dir=os.path.join(self.dir, "ev")), self.bot, clock=self.clock)
        for i in range(3):
            self.approve_on(k, f"id=p{i}; targets=t{i}; actions=edit; ttl=60")
            self.advance(5)
        self.approve_on(k, "id=p3; targets=t3; actions=edit; ttl=60")           # cap of 3: p0 is dropped
        self.approve_on(k, "id=p1; targets=t1; actions=edit; ttl=60")           # same id: renewed
        with open(k.journal_path) as f:
            got = {(e["plans"][0], e["result"]) for e in map(json.loads, f) if e["event"] == "plan-ended"}
        self.assertIn(("p0", "evicted"), got)
        self.assertIn(("p1", "renewed"), got)

    def test_the_sweep_ends_a_plan_without_any_call(self):
        self.approve("id=night; targets=web; actions=deploy; ttl=done,max=2h")
        self.advance(3 * H)
        self.k.sweep()
        self.assertEqual(self.entries("plan-ended")[-1]["result"], "declared-max")
        self.assertEqual(self.active(), [])
        n = len(self.entries("plan-ended"))
        self.k.sweep()
        self.assertEqual(len(self.entries("plan-ended")), n)                    # ended once

    def test_the_idle_rule_is_off_by_default_and_works_when_set(self):
        self.approve(DONE)
        self.advance(10 * H)                                                    # a night with no call
        self.k.sweep()
        self.assertEqual(len(self.active()), 1)
        k = keeperd.Keeper(dict(self.cfg, until_done_idle_min=60, state_dir=os.path.join(self.dir, "idle")), self.bot, clock=self.clock)
        self.approve_on(k, DONE)
        self.advance(59 * 60)
        self.assertEqual(k.check("s1", *bash("docker restart web"))["decision"], "allow")    # a use resets the clock
        self.advance(59 * 60)
        k.sweep()
        self.assertEqual(len(k.session("s1")["active"]), 1)
        self.advance(2 * 60)
        k.sweep()
        self.assertEqual(k.session("s1")["active"], [])

    def test_keeper_status_shows_the_until_done_flag(self):
        self.approve(DONE)
        r = self.k.check("s1", *bash("keeper-status"))
        self.assertIn('"until_done": true', r["reason"])


class OwnerChoice(TaskPlans):
    def test_the_card_offers_a_fixed_time_button_only_for_until_done_plans(self):
        self.plan(DONE)
        _c, kb = keeperd.render_plan_card("en", self.k.state["sessions"]["s1"]["pending"])
        data = [b["callback_data"].split(":")[0] for row in kb["inline_keyboard"] for b in row]
        self.assertIn("approvefixed", data)
        self.plan("id=b; targets=web; actions=deploy; ttl=30", sid="s2")
        _c, kb = keeperd.render_plan_card("en", self.k.state["sessions"]["s2"]["pending"])
        self.assertNotIn("approvefixed", [b["callback_data"].split(":")[0] for row in kb["inline_keyboard"] for b in row])

    def test_choosing_the_fixed_button_gives_the_same_scope_for_a_fixed_time(self):
        self.plan(DONE)
        p = self.k.state["sessions"]["s1"]["pending"]
        data = f"approvefixed:{p['hash'][:12]}:{p['nonce']}"
        self.assertTrue(self.k.decide(OWNER, CHAT, data).startswith("approved for 60 min"))
        a = self.active()[0]
        self.assertNotIn("until_done", a)
        self.assertEqual((a["plan"]["ttl"], a["plan"]["targets"], a["plan"]["actions"]), (60, ["web"], ["deploy"]))
        self.advance(61 * 60)
        self.assertFalse(self.covers("docker restart web"))

    def test_a_stranger_cannot_use_the_fixed_button(self):
        self.plan(DONE)
        p = self.k.state["sessions"]["s1"]["pending"]
        self.assertNotIn("approved", self.k.decide(999, CHAT, f"approvefixed:{p['hash'][:12]}:{p['nonce']}"))
        self.assertEqual(self.active(), [])


class CouncilFindings(TaskPlans):
    """Defects found by the council's review of this PR (23/11/2026)."""

    def test_the_fixed_button_is_never_longer_than_the_declared_max(self):
        self.plan("id=short; targets=web; actions=deploy; ttl=done,max=30min")
        p = self.k.state["sessions"]["s1"]["pending"]
        self.assertTrue(self.k.decide(OWNER, CHAT, f"approvefixed:{p['hash'][:12]}:{p['nonce']}").startswith("approved for 30 min"))
        self.assertEqual(self.active()[0]["plan"]["ttl"], 30)

    def test_a_restart_with_a_lower_ceiling_cuts_the_stored_expiry(self):
        self.approve(DONE)
        self.assertEqual(self.active()[0]["expires"], self.active()[0]["approved_at"] + 1440 * 60)
        k2 = keeperd.Keeper(dict(self.cfg, until_done_ceiling_min=600), self.bot, clock=self.clock)   # same state dir
        self.assertEqual(k2.session("s1")["active"][0]["expires"], self.active()[0]["approved_at"] + 600 * 60)
        self.advance(11 * H)
        self.assertEqual(k2.check("s1", *bash("docker restart web"))["decision"], "deny")

    def test_a_restart_never_extends_and_never_touches_fixed_plans(self):
        self.approve(DONE)
        self.approve("id=fixed; targets=api; actions=edit; ttl=60")
        before = {a["plan"]["id"]: a["expires"] for a in self.active()}
        k2 = keeperd.Keeper(dict(self.cfg), self.bot, clock=self.clock)
        self.assertEqual({a["plan"]["id"]: a["expires"] for a in k2.session("s1")["active"]}, before)

    def test_covered_calls_do_not_rewrite_the_state_file_each_time(self):
        self.approve(DONE)
        saves = []
        real = self.k.save
        self.k.save = lambda: (saves.append(1), real())[1]
        for _ in range(5):
            self.assertTrue(self.covers("docker restart web"))
        self.assertEqual(saves, [])                                   # no write per allowed call
        self.k.sweep()
        self.assertEqual(len(saves), 1)                               # the counters go out with the sweep
        self.assertEqual(json.load(open(self.k.state_path))["sessions"]["s1"]["active"][0]["usage"]["calls"], 5)
        self.k.sweep()
        self.assertEqual(len(saves), 1)                               # and only when something changed


class ClientSide(TaskPlans):
    def test_the_hook_forwards_a_session_end_and_never_fails_the_session(self):
        sent = []
        orig_ask, orig_stdin = keeper_client.ask, sys.stdin
        keeper_client.ask = lambda req, timeout=10: sent.append(req) or {"ok": True}
        sys.stdin = __import__("io").StringIO(json.dumps({"hook_event_name": "SessionEnd", "session_id": "s1"}))
        try:
            with self.assertRaises(SystemExit) as cm:
                keeper_client.hook()
        finally:
            keeper_client.ask, sys.stdin = orig_ask, orig_stdin
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(sent, [{"op": "session-end", "session": "s1"}])

    def test_the_hook_survives_a_down_daemon_at_session_end(self):
        def boom(req, timeout=10):
            raise OSError("down")
        orig_ask, orig_stdin = keeper_client.ask, sys.stdin
        keeper_client.ask = boom
        sys.stdin = __import__("io").StringIO(json.dumps({"hook_event_name": "SessionEnd", "session_id": "s1"}))
        try:
            with self.assertRaises(SystemExit) as cm:
                keeper_client.hook()
        finally:
            keeper_client.ask, sys.stdin = orig_ask, orig_stdin
        self.assertEqual(cm.exception.code, 0)


class InstallerWiring(unittest.TestCase):
    def install(self, tmp):
        import subprocess
        who = "nobody" if os.geteuid() == 0 else subprocess.check_output(["id", "-un"], text=True).strip()   # never root
        r = subprocess.run([os.path.join(HERE, "install-keeper.sh"), "--agent-user", who, "--owner-id", "1", "--prefix", tmp],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return os.path.join(tmp, "etc", "claude-code", "managed-settings.json")

    def test_session_end_hook_and_keeper_done_wrapper_are_installed_once(self):
        import shutil, tempfile
        tmp = tempfile.mkdtemp(prefix="ktp", dir="/tmp")
        try:
            managed = self.install(tmp)
            first = open(managed).read()
            hooks = json.loads(first)["hooks"]
            self.assertEqual(len(hooks["SessionEnd"]), 1)
            self.assertIn("keeper_client.py", hooks["SessionEnd"][0]["hooks"][0]["command"])
            self.assertEqual(self.install(tmp) and open(managed).read(), first)      # a reinstall changes nothing
            wrappers = [os.path.join(r, f) for r, _d, fs in os.walk(tmp) for f in fs if f == "keeper-done"]
            self.assertEqual(len(wrappers), 1)
            self.assertIn("keeper_client.py done", open(wrappers[0]).read())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

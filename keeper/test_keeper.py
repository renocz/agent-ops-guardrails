#!/usr/bin/env python3
"""Tests for keeperd and its hook client: state machine, approval binding, and the attacks an agent could try.

Run: python3 keeper/test_keeper.py   (no network, no install: a fake Telegram and a socket in a temp dir)
"""
import contextlib, io, json, os, platform, shlex, shutil, socket, stat, string, subprocess, sys, tempfile, threading, time, unittest

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

    def propose_cmd(self, scope, text="why"):
        return f"keeper-propose --scope {shlex.quote(scope)} --text {shlex.quote(text)}"

    def plan(self, scope, sid="s1", text="why"):
        """As the agent does it: a keeper-propose command, seen by keeperd in the hook's check."""
        r = self.k.check(sid, *bash(self.propose_cmd(scope, text)))
        self.assertEqual(r["decision"], "deny")                     # nothing to run
        self.assertIn("sent to the human", r["reason"])
        self.bot.send_plan(*r.pop("_notify"))
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
        self.approve("id=p2 ; targets=web ; actions=deploy", sid="other")
        self.assertTrue(self.k.decide(OWNER, CHAT, "stop:all").startswith("stopped"))
        self.assertFalse(self.allowed(*bash("docker restart web")))
        self.assertFalse(self.allowed(*bash("docker restart web"), sid="other"))     # Stop ends every session's plan

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

    def test_proposal_belongs_to_the_session_that_ran_it(self):
        self.plan("id=x ; targets=web ; actions=deploy", sid="S9")
        self.assertEqual(self.bot.plans[-1][0], "S9")
        self.assertTrue(self.k.decide(OWNER, CHAT, self.bot.buttons()[0]).startswith("approved"))
        self.assertTrue(self.allowed(*bash("docker restart web"), sid="S9"))
        self.assertFalse(self.allowed(*bash("docker restart web"), sid="s1"))

    def test_only_a_lone_keeper_propose_is_a_proposal(self):
        scope = "id=x ; actions=delete"
        for cmd in (f"x=1; {self.propose_cmd(scope)}", f"{self.propose_cmd(scope)} && rm -rf /srv",
                    f"{self.propose_cmd(scope)} | sh", f"echo {self.propose_cmd(scope)}",
                    f"{self.propose_cmd(scope)} --other y", f"/tmp/x/{self.propose_cmd(scope)}"):
            r = self.k.check("s1", *bash(cmd))
            self.assertNotIn("_notify", r, cmd)
        self.assertEqual(self.bot.plans, [])

    def test_status_command(self):
        self.approve("id=p1 ; targets=web ; actions=deploy")
        r = self.k.check("s1", *bash("keeper-status"))
        self.assertEqual(r["decision"], "deny")
        self.assertIn('"id": "p1"', r["reason"])

    def test_telegram_header_warns_on_wide_plans(self):
        self.plan("id=w ; actions=script,delete")
        _sid, p = self.bot.plans[-1]
        self.assertEqual(p["plan"]["targets"], [])                   # the real bot adds ⚠️ lines for these

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

    def test_program_in_home_bin_is_not_a_read(self):
        for cmd in (f"{self.home}/bin/cat /etc/hosts", "~/.local/bin/ls", "/opt/homebrew/../../tmp/cat x"):
            self.assertFalse(self.allowed(*bash(cmd)), cmd)

    def test_edit_plan_cannot_plant_programs(self):
        """An approved edit plan must not let the agent put a program on PATH (it would later pass as a read)."""
        for path in ("/home/agent/bin/web-cat", "/Users/agent/.local/bin/web-ls", "/usr/local/bin/web-x"):  # not scratch
            self.assertFalse(self.allowed("Write", {"file_path": path, "content": "#!/bin/sh\nrm -rf ~"}), path)
        self.assertFalse(self.allowed(*bash("cp /tmp/web-x /Users/agent/.local/bin/cat")))
        self.assertTrue(self.allowed("Write", {"file_path": "/srv/web/app.conf", "content": "x"}))

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

    def test_read_commands_that_execute_need_a_plan(self):
        """K1-K5: a 'read' command made to run a program or write is opaque (script), not covered by deploy,edit."""
        for cmd in ("ssh -o ProxyCommand=/tmp/x host ls", "ssh -F /tmp/cfg host uptime",
                    "awk -f /tmp/evil.awk /etc/hosts", "sed -e'w /tmp/out' /etc/hosts",
                    "curl -K /tmp/cfg http://h/x", "tar --to-command=/tmp/x -xf a.tar",
                    "PAGER=/tmp/evil git log"):
            self.assertFalse(self.allowed(*bash(cmd)), cmd)

    def test_cd_before_git_is_not_a_read(self):                      # R1
        self.k.gate.SAFE_GIT_REPOS[:] = ["/opt/stacks"]
        self.assertNotEqual(self.k.check("s1", *bash("cd /tmp/evil && git status"), "/opt/stacks")["decision"], "allow")
        self.assertNotEqual(self.k.check("s1", *bash("( cd /tmp/evil && git log )"), "/opt/stacks")["decision"], "allow")
        self.assertEqual(self.k.check("s1", *bash("git status"), "/opt/stacks")["decision"], "allow")
        self.assertEqual(self.k.check("s1", *bash("cd /opt/stacks/web && git status"), "/opt/stacks")["decision"], "allow")

    def test_launcher_feeding_a_shell_needs_a_plan(self):            # R2
        for cmd in ("xargs -I{} sh -c '{}' < /tmp/list", "xargs sh -c id < /dev/null", "xargs -a /tmp/list bash",
                    "parallel sh -c {} ::: a b", "env PAGER=/tmp/x cat f", "sort --compress-program=/tmp/x /etc/hosts"):
            self.assertFalse(self.allowed(*bash(cmd)), cmd)

    def test_git_read_is_opaque_outside_a_safe_repo(self):
        """K6: a git read verb runs repo-local config; it is a read only in a declared safe repo."""
        self.assertNotEqual(self.k.check("s1", *bash("git status"), "/tmp/evil")["decision"], "allow")
        self.assertNotEqual(self.k.check("s1", *bash("git -C /tmp/evil log"), None)["decision"], "allow")
        self.k.gate.SAFE_GIT_REPOS[:] = ["/opt/stacks/web"]
        self.assertEqual(self.k.check("s1", *bash("git -C /opt/stacks/web status"), None)["decision"], "allow")
        self.assertEqual(self.k.check("s1", *bash("git log --oneline"), "/opt/stacks/web/sub")["decision"], "allow")
        self.assertNotEqual(self.k.check("s1", *bash("git status"), "/tmp/other")["decision"], "allow")


class Messages(Base):
    """What the human reads is one catalogue per language; what the agent reads stays English."""

    def keeper_in(self, lang):
        cfg = dict(self.cfg, lang=lang, state_dir=os.path.join(self.dir, "state-" + lang))
        return keeperd.Keeper(cfg, self.bot, clock=self.clock)

    def pending_on(self, k, scope="id=p1 ; targets=web ; actions=deploy ; ttl=30", text="why"):
        r = k.check("s1", *bash(self.propose_cmd(scope, text)))
        return r["_notify"][1]

    @staticmethod
    def fields(template):
        return {f for _lit, f, _spec, _conv in string.Formatter().parse(template) if f}

    def test_every_key_exists_in_both_languages(self):
        en, fr = keeperd.MESSAGES["en"], keeperd.MESSAGES["fr"]
        self.assertEqual(set(en), set(fr))
        for key in en:
            self.assertEqual(self.fields(en[key]), self.fields(fr[key]), key)      # same placeholders
            kw = {f: "x" for f in self.fields(en[key])}
            for lang in ("en", "fr"):
                text = keeperd.t(lang, key, **kw)
                self.assertTrue(text.strip(), (lang, key))
                self.assertNotIn("{", text, (lang, key))                             # nothing left unrendered
            self.assertNotEqual(keeperd.t("en", key, **kw), keeperd.t("fr", key, **kw), key)

    def test_plan_card_in_english_is_unchanged(self):
        p = self.pending_on(self.k)
        text, kb = keeperd.render_plan_card("en", p)
        self.assertEqual(text, "🔐 Approval requested\nPlan: p1\nTargets: web\nActions: deploy\nDuration: 30 min\n"
                               f"Fingerprint: {p['hash'][:12]}\n"
                               "Stop ends the plan; it does not stop a process already started.\n———\n"
                               "The agent's explanation:\nwhy")
        self.assertEqual([b["text"] for row in kb["inline_keyboard"] for b in row],
                         ["✅ Approve", "❌ Reject", "⏹ Stop everything"])
        wide = self.pending_on(self.k, "id=w ; actions=script,delete")
        self.assertIn("Targets: ANY\nActions: script, delete", keeperd.render_plan_card("en", wide)[0])
        self.assertIn("⚠️ script: the agent may run ANY program during this plan.\n⚠️ delete: the agent may delete files.\n"
                      "⚠️ no targets: the actions apply to everything.\nStop ends", keeperd.render_plan_card("en", wide)[0])

    def test_plan_card_in_french(self):
        p = self.pending_on(self.k, "id=w ; actions=script,delete", text="pourquoi")
        text, kb = keeperd.render_plan_card("fr", p)
        for want in ("Demande d'approbation", "Plan : w", "Cibles : TOUTES", "Actions : script, delete", "Durée : 60 min",
                     f"Empreinte : {p['hash'][:12]}", "N'IMPORTE QUEL programme", "aucune cible", "Arrêter met fin",
                     "Explication de l'agent :\npourquoi"):
            self.assertIn(want, text)
        self.assertEqual([b["text"] for row in kb["inline_keyboard"] for b in row],
                         ["✅ Approuver", "❌ Refuser", "⏹ Tout arrêter"])

    def test_callback_data_is_protocol_in_every_language(self):
        p = self.pending_on(self.k)
        data = lambda lang: [b["callback_data"] for row in keeperd.render_plan_card(lang, p)[1]["inline_keyboard"] for b in row]
        self.assertEqual(data("en"), data("fr"))
        self.assertEqual(data("fr")[0], f"approve:{p['hash'][:12]}:{p['nonce']}")

    def test_answers_to_buttons_follow_the_language(self):
        k = self.keeper_in("fr")
        p = self.pending_on(k)
        h = p["hash"][:12]
        self.assertEqual(k.decide(STRANGER, CHAT, "stop:all"), "ignoré : vous n'êtes pas le propriétaire")
        self.assertEqual(k.decide(OWNER, CHAT, "approve:zz"), "ignoré : demande mal formée")
        self.assertEqual(k.decide(OWNER, CHAT, "approve:" + "0" * 12 + ":" + "0" * 16), "ignoré : aucun plan en attente ne correspond")
        self.assertEqual(k.decide(OWNER, CHAT, f"approve:{h}:{p['nonce']}"), "approuvé pour 30 min")
        self.assertEqual(k.decide(OWNER, CHAT, f"approve:{h}:{p['nonce']}"), "ignoré : déjà utilisé")
        self.assertEqual(k.decide(OWNER, CHAT, "stop:all"), "arrêté : plus aucun plan n'est actif")
        self.assertEqual(k.decide(OWNER, CHAT, "stop:all"), "rien n'était actif ; les plans en attente sont abandonnés")
        p2 = self.pending_on(k, "id=p2 ; actions=edit")
        self.assertEqual(k.decide(OWNER, CHAT, f"reject:{p2['hash'][:12]}:{p2['nonce']}"), "refusé")
        p3 = self.pending_on(k, "id=p3 ; actions=edit")
        self.clock.t += 121 * 60
        self.assertEqual(k.decide(OWNER, CHAT, f"approve:{p3['hash'][:12]}:{p3['nonce']}"),
                         "expiré : demandez à l'agent de proposer à nouveau")

    def test_answers_carry_a_key_so_the_bot_does_not_parse_words(self):
        k = self.keeper_in("fr")
        self.assertEqual(k.decide(STRANGER, CHAT, "stop:all").key, "ans_not_owner")
        self.assertIn(k.decide(OWNER, CHAT, "garbage").key, keeperd.IGNORED)
        p = self.pending_on(k)
        self.assertNotIn(k.decide(OWNER, CHAT, f"approve:{p['hash'][:12]}:{p['nonce']}").key, keeperd.IGNORED)

    def test_what_the_agent_reads_stays_english(self):
        k = self.keeper_in("fr")
        k.cfg["mode"] = "block"
        deny = k.check("s1", *bash("docker restart web"))
        self.assertTrue(deny["reason"].startswith("keeper: this is a change (deploy) and no approved plan covers it."))
        sent = k.check("s1", *bash(self.propose_cmd("id=p1 ; actions=edit")))
        self.assertIn("plan sent to the human for approval", sent["reason"])
        self.assertIn("Nothing was run.", sent["reason"])
        self.assertIn("keeper status (nothing was run)", k.check("s1", *bash("keeper-status"))["reason"])

    def test_unknown_language_falls_back_to_english(self):
        k = self.keeper_in("xx")
        self.assertEqual(k.lang, "en")
        self.assertEqual(k.decide(OWNER, CHAT, "garbage"), "ignored: malformed")
        self.assertEqual(keeperd.norm_lang("FR"), "fr")
        self.assertEqual(keeperd.norm_lang(None), "en")
        self.assertEqual(keeperd.t("xx", "ans_rejected"), "rejected")
        self.assertEqual(keeperd.t("fr", "no-such-key"), "no-such-key")             # never a crash

    def test_default_language_is_english(self):
        self.assertEqual(keeperd.DEFAULTS["lang"], "en")
        self.assertEqual(self.k.lang, "en")


class Startup(Base):
    """The line sent when the daemon starts must say what the mode really does."""

    def start(self, mode, lang="en"):
        """Run the real main() with a fake Telegram and no socket; return what it sent to the human."""
        path = os.path.join(self.dir, f"config-{mode}-{lang}.json")
        with open(path, "w") as f:
            json.dump(dict(self.cfg, mode=mode, lang=lang, state_dir=os.path.join(self.dir, f"st-{mode}-{lang}")), f)
        sent = []

        class FakeTelegram:
            def __init__(self, cfg):
                self.cfg = cfg

            def send(self, text):
                sent.append(text)

            def poll(self, keeper):
                pass

        saved = keeperd.TelegramBot, keeperd.serve, sys.argv
        keeperd.TelegramBot, keeperd.serve, sys.argv = FakeTelegram, (lambda keeper, cfg, ready=None: None), ["keeperd.py", path]
        try:
            keeperd.main()
        finally:
            keeperd.TelegramBot, keeperd.serve, sys.argv = saved
        return sent

    def test_block_mode_keeps_the_original_meaning(self):
        self.assertEqual(self.start("block"), ["🔐 keeper started: changes now need your approval here."])

    def test_observe_mode_says_nothing_is_blocked(self):
        (text,) = self.start("observe")
        self.assertIn("observe mode", text)
        self.assertIn("nothing is blocked", text)
        self.assertIn("only logged", text)
        self.assertIn("/summary", text)
        self.assertNotIn("need your approval", text)

    def test_both_modes_in_french(self):
        (block,) = self.start("block", "fr")
        self.assertIn("demandent maintenant votre approbation", block)
        (observe,) = self.start("observe", "fr")
        for want in ("mode observation", "rien n'est bloqué", "journalisés", "/summary"):
            self.assertIn(want, observe)
        self.assertNotIn("demandent maintenant votre approbation", observe)

    def test_any_mode_but_block_is_observe_as_in_check(self):
        """Keeper.check() refuses nothing unless mode == "block"; the message follows the same rule."""
        for mode in ("observe", "log", "", None, "BLOCK"):
            self.assertIn("nothing is blocked", keeperd.startup_message("en", mode), mode)
            self.k.cfg["mode"] = mode
            self.assertTrue(self.allowed(*bash("docker restart web")), mode)       # really not blocked
        self.assertNotIn("nothing is blocked", keeperd.startup_message("en", "block"))

    def test_a_failing_telegram_at_start_is_logged_not_fatal(self):
        path = os.path.join(self.dir, "config-down.json")
        with open(path, "w") as f:
            json.dump(dict(self.cfg, mode="observe", state_dir=os.path.join(self.dir, "st-down")), f)

        class DownTelegram:
            def __init__(self, cfg):
                pass

            def send(self, text):
                raise OSError("network down")

            def poll(self, keeper):
                pass

        served = []
        saved = keeperd.TelegramBot, keeperd.serve, sys.argv
        keeperd.TelegramBot, keeperd.serve, sys.argv = DownTelegram, (lambda keeper, cfg, ready=None: served.append(1)), ["keeperd.py", path]
        try:
            keeperd.main()
        finally:
            keeperd.TelegramBot, keeperd.serve, sys.argv = saved
        self.assertEqual(served, [1])                                               # the daemon still serves
        with open(os.path.join(self.dir, "st-down", "log.jsonl")) as f:
            self.assertIn("telegram-error-at-start", [json.loads(x)["event"] for x in f])


class SummaryCli(Base):
    """`sudo keeper-summary [days]`: the same masked summary, printed locally, for root only."""

    def setUp(self):
        super().setUp()
        self.k.cfg["mode"] = "observe"
        self.config = os.path.join(self.dir, "config.json")
        with open(self.config, "w") as f:
            json.dump(dict(self.cfg, mode="observe"), f)
        self._env = os.environ.get("KEEPER_CONFIG")
        os.environ["KEEPER_CONFIG"] = self.config
        self._euid = os.geteuid
        self.addCleanup(self.restore)

    def restore(self):
        os.geteuid = self._euid
        if self._env is None:
            os.environ.pop("KEEPER_CONFIG", None)
        else:
            os.environ["KEEPER_CONFIG"] = self._env

    def run_cli(self, *args, euid=0):
        os.geteuid = lambda: euid
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = keeperd.summary_cli(list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_root_gets_the_masked_summary(self):
        self.k.check("s1", *bash("docker restart web"))
        self.k.check("s1", *bash(f"API_TOKEN={fake_secrets()['github']} rm /srv/x"))
        rc, out, err = self.run_cli()
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("Keeper summary: last 7 day(s), mode observe", out)
        self.assertIn("Would-deny: 2", out)
        self.assertIn("docker restart … [deploy]", out)
        self.assertNotIn(fake_secrets()["github"][:12], out)
        self.assertEqual(self.run_cli("1")[1].splitlines()[0].split(": ")[1].split(",")[0], "last 1 day(s)")

    def test_the_last_layer_masks_a_secret_shaped_value_from_the_log(self):
        sec = fake_secrets()["github"]
        self.k.log({"event": "would-deny", "tool": "Bash", "category": "edit", "shape": f"{sec[:40]} … [edit]"})
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertNotIn(sec[:12], out)
        self.assertIn("<m>", out)

    def test_nobody_else_can_run_it(self):
        self.k.check("s1", *bash("docker restart web"))
        for euid in (1, 501, 1000, 65534):
            rc, out, err = self.run_cli(euid=euid)
            self.assertEqual((rc, out), (2, ""), euid)                              # nothing on stdout
            self.assertIn("as root", err)
            self.assertNotIn("docker", err)

    def test_arguments_are_checked(self):
        for args in (("abc",), ("1", "2"), ("-1",), ("7; ls",), ("100",), ("1.5",), ("",)):
            rc, out, err = self.run_cli(*args)
            self.assertEqual((rc, out), (2, ""), args)
            self.assertIn("usage", err)
        self.assertIn("last 30 day(s)", self.run_cli("30")[1])
        self.assertIn("last 1 day(s)", self.run_cli("0")[1])                       # clamped, as for /summary

    def test_no_log_is_an_empty_summary_and_an_unreadable_one_is_an_error(self):
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertIn("No event in this window.", out)
        os.mkdir(os.path.join(self.cfg["state_dir"], "log.jsonl"))
        rc, out, err = self.run_cli()
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("cannot read the log", err)

    def test_it_reads_the_log_and_nothing_else(self):
        """No Keeper object: no state file is created, no directory made, no classifier loaded."""
        fresh = os.path.join(self.dir, "fresh-state")
        with open(self.config, "w") as f:
            json.dump(dict(self.cfg, state_dir=fresh), f)
        self.assertEqual(self.run_cli()[0], 0)
        self.assertFalse(os.path.exists(fresh))

    def test_main_routes_the_flag_and_exits_with_its_code(self):
        saved = sys.argv
        sys.argv = ["keeperd.py", "--summary", "oops"]
        os.geteuid = lambda: 0
        try:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                keeperd.main()
        finally:
            sys.argv = saved
        self.assertEqual(cm.exception.code, 2)


@unittest.skipUnless(shutil.which("bash") and os.path.exists("/usr/bin/python3") and
                     subprocess.run(["id", "nobody"], capture_output=True).returncode == 0, "needs bash, /usr/bin/python3, user nobody")
class InstallerLang(unittest.TestCase):
    """install-keeper.sh --lang, in prefix mode (files only: no user, no service, nothing outside the temp dir)."""

    def install(self, *extra):
        prefix = tempfile.mkdtemp(prefix="ki", dir="/tmp")
        self.addCleanup(shutil.rmtree, prefix, ignore_errors=True)
        r = subprocess.run(["bash", os.path.join(HERE, "install-keeper.sh"), "--agent-user", "nobody", "--owner-id", "1",
                            "--prefix", prefix, *extra], capture_output=True, text=True, timeout=60)
        cfg = os.path.join(prefix, "etc", "keeper", "config.json")
        return r, (json.load(open(cfg)) if os.path.exists(cfg) else None)

    def test_lang_is_written_to_the_config(self):
        self.assertEqual(self.install("--lang", "fr")[1]["lang"], "fr")
        self.assertEqual(self.install("--lang", "en")[1]["lang"], "en")

    def test_default_is_english(self):
        self.assertEqual(self.install()[1]["lang"], "en")

    def test_unknown_language_is_refused(self):
        r, cfg = self.install("--lang", "de")
        self.assertEqual(r.returncode, 2)
        self.assertIsNone(cfg)

    def test_keeper_summary_is_root_only_and_never_setuid(self):
        prefix = tempfile.mkdtemp(prefix="ki", dir="/tmp")
        self.addCleanup(shutil.rmtree, prefix, ignore_errors=True)
        subprocess.run(["bash", os.path.join(HERE, "install-keeper.sh"), "--agent-user", "nobody", "--owner-id", "1",
                        "--prefix", prefix], capture_output=True, text=True, timeout=60, check=True)
        wrapper = os.path.join(prefix, "opt", "agent-guardrails", "bin", "keeper-summary")
        mode = os.stat(wrapper).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o700)                              # nobody but the owner (root) can run it
        self.assertFalse(mode & (stat.S_ISUID | stat.S_ISGID))
        text = open(wrapper).read()
        self.assertIn("--summary", text)
        self.assertIn("-I", text)
        for other in ("keeper-propose", "keeper-status"):                         # the agent's commands stay runnable
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(os.path.dirname(wrapper), other)).st_mode), 0o755)


@unittest.skipUnless(shutil.which("bash") and os.path.exists("/usr/bin/python3") and
                     subprocess.run(["id", "nobody"], capture_output=True).returncode == 0, "needs bash, /usr/bin/python3, user nobody")
class InstallerEnvLock(unittest.TestCase):
    """KEEPER_TEST_MODE / KEEPER_SOCKET_FOR_TESTS in keeper_client.py are safe only because the hook and the
    keeper-propose/keeper-status wrappers run with an EMPTY environment (`env -i`): otherwise a project
    .claude/settings.json `env` key, or a shell profile, could set those variables and point the hook at a fake
    socket. `-I` (isolated mode) on top of that stops the interpreter from also picking up PYTHON* variables."""

    def test_hook_and_wrappers_run_with_an_empty_environment(self):
        prefix = tempfile.mkdtemp(prefix="kenv", dir="/tmp")
        self.addCleanup(shutil.rmtree, prefix, ignore_errors=True)
        subprocess.run(["bash", os.path.join(HERE, "install-keeper.sh"), "--agent-user", "nobody", "--owner-id", "1",
                        "--prefix", prefix], capture_output=True, text=True, timeout=60, check=True)
        # Mirrors install-keeper.sh's own `uname -s` branch: MANAGED is a different path on macOS (owner review,
        # 11/10 — the fixed path below only matched Linux, so this failed on the owner's own Mac).
        managed_rel = ("Library/Application Support/ClaudeCode/managed-settings.json" if platform.system() == "Darwin"
                       else "etc/claude-code/managed-settings.json")
        managed = json.load(open(os.path.join(prefix, managed_rel)))
        hook_cmd = managed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertTrue(hook_cmd.startswith("/usr/bin/env -i "), hook_cmd)
        self.assertIn(" -I ", hook_cmd, hook_cmd)
        bin_dir = os.path.join(prefix, "opt", "agent-guardrails", "bin")
        for wrapper in ("keeper-propose", "keeper-status"):
            text = open(os.path.join(bin_dir, wrapper)).read()
            self.assertIn("exec /usr/bin/env -i ", text, wrapper)
            self.assertIn(" -I ", text, wrapper)


def fake_secrets():
    """Fake secrets, assembled at run time so that secret scanners stay quiet on this file."""
    return {"github": "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" * 2, "aws": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
            "openai": "sk" + "-" + "Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7", "jwt": "ey" + "Jhbgci" + "OiJIUzI1NiJ9.ey" + "Jzdwii" + "OiIxMjM0NTY3ODkwIn0.abc",
            "bot": "1234567890" + ":" + "AAH" + "x" * 33, "url": "https://user:hunter" + "22@host.example/x",
            "pem": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIfake\n-----END RSA " + "PRIVATE KEY-----"}


class LogSummary(Base):
    """`/summary`: what the owner reads about the keeper's log. Counts and shapes, never arguments, never a secret."""

    def setUp(self):
        super().setUp()
        self.k.cfg["mode"] = "observe"

    def summary(self, text="/summary", k=None):
        out = (k or self.k).command(OWNER, CHAT, text)
        self.assertIsNotNone(out, text)
        for chunk in out:
            self.assertLess(len(chunk), 4000)
        return "\n".join(out)

    def deny(self, *cmds, sid="s1"):
        for cmd in cmds:
            self.k.check(sid, *bash(cmd))

    def log_at(self, days_ago, rec):
        self.clock.t -= days_ago * 86400
        self.k.log(rec)
        self.clock.t += days_ago * 86400

    def test_log_is_stamped_by_the_injected_clock(self):
        self.k.log({"event": "x"})
        with open(self.k.log_path) as f:
            at = json.loads(f.readline())["at"]
        self.assertEqual(keeperd.event_time({"at": at}), self.clock.t)

    def test_counts_by_tool_category_and_shape(self):
        self.deny("docker restart web", "docker restart db", "docker restart db", "rm -rf /srv/x")
        self.k.check("s1", "Write", {"file_path": "/srv/app/a.py", "content": "x"})
        text = self.summary()
        self.assertIn("Would-deny: 5 | Denied: 0 | Allowed under an approved plan: 0", text)
        self.assertIn("By tool: Bash 4, Write 1", text)
        self.assertIn("By category: deploy 3, delete 1, edit 1", text)
        self.assertIn("1. 3× docker restart … [deploy]", text)
        self.assertIn("rm … [delete]", text)
        self.assertIn("Write … [edit]", text)

    def test_block_mode_counts_denied(self):
        self.k.cfg["mode"] = "block"
        self.deny("docker restart web")
        text = self.summary()
        self.assertIn("Would-deny: 0 | Denied: 1", text)
        self.assertIn("mode block", text)

    def test_allowed_under_an_approved_plan(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.assertTrue(self.allowed(*bash("docker restart web")))
        self.assertIn("Allowed under an approved plan: 1", self.summary())

    def test_plans_proposed_approved_rejected_expired(self):
        self.approve("id=a ; actions=edit", sid="A")
        ok, no = self.plan("id=b ; actions=edit", sid="B")
        self.k.decide(OWNER, CHAT, no)
        late, _ = self.plan("id=c ; actions=edit", sid="C")
        self.clock.t += 121 * 60
        self.k.decide(OWNER, CHAT, late)
        self.assertIn("Plans: proposed 3, approved 1, rejected 1, expired 1", self.summary())

    def test_window_is_seven_days_and_the_argument_narrows_it(self):
        self.log_at(8, {"event": "would-deny", "tool": "Bash", "category": "git", "shape": "git … [git]"})
        self.log_at(3, {"event": "would-deny", "tool": "Bash", "category": "edit", "shape": "tee … [edit]"})
        self.deny("docker restart web")
        default = self.summary()
        self.assertIn("last 7 day(s)", default)
        self.assertIn("Would-deny: 2", default)                      # today and 3 days ago, not 8
        self.assertIn("Would-deny: 1", self.summary("/summary 1"))
        self.assertIn("Would-deny: 3", self.summary("/summary 30"))
        self.assertIn("last 30 day(s)", self.summary("/summary 99"))   # clamped
        self.assertIn("last 1 day(s)", self.summary("/summary 0"))

    def test_alias_bot_suffix_and_case(self):
        for text in ("/resume", "/summary@my_keeper_bot", "/SUMMARY", "  /summary  ", "/resume 3"):
            self.assertTrue(self.k.command(OWNER, CHAT, text), text)

    def test_nothing_else_is_a_command(self):
        for text in ("hello", "/start", "/summaryx", "/summary 1 2", "/summary; ls", "summary", "", "/ summary",
                     "approve:" + "0" * 12 + ":" + "0" * 16, "GO", "/summary\n/summary"):
            self.assertIsNone(self.k.command(OWNER, CHAT, text), text)
        self.assertIsNone(self.k.command(OWNER, CHAT, None))
        self.assertIsNone(self.k.command(OWNER, CHAT, 42))

    def test_only_the_owner_in_the_configured_chat(self):
        self.assertIsNone(self.k.command(STRANGER, CHAT, "/summary"))
        self.assertIsNone(self.k.command(OWNER, 555, "/summary"))               # owner, but another chat
        self.assertIsNone(self.k.command(None, CHAT, "/summary"))               # no sender
        self.assertIn("command-from-stranger-ignored", self.log_events())
        self.assertEqual(self.log_events().count("command-from-stranger-ignored"), 3)
        self.assertIsNone(self.k.command(STRANGER, CHAT, "just chatting"))      # not a command: not even logged
        self.assertEqual(self.log_events().count("command-from-stranger-ignored"), 3)

    def test_an_unset_owner_matches_nobody(self):
        k = keeperd.Keeper(dict(self.cfg, owner_id=None, chat_id=None, state_dir=os.path.join(self.dir, "s2")), self.bot,
                           clock=self.clock)
        self.assertIsNone(k.command(None, None, "/summary"))
        self.assertIsNone(k.command(OWNER, CHAT, "/summary"))

    def test_the_log_keeps_the_shape_not_the_arguments(self):
        sec = fake_secrets()
        self.deny(f"API_TOKEN={sec['github']} docker restart web", f"curl -H 'Authorization: Bearer {sec['openai']}' {sec['url']}",
                  f"echo {sec['aws']} > /srv/x", f"export K={sec['bot']}; rm /srv/y")
        raw = open(self.k.log_path).read()
        text = self.summary()
        for name, value in sec.items():
            if name == "pem":
                continue
            for hay, where in ((raw, "log"), (text, "summary")):
                self.assertNotIn(value, hay, (name, where))
                self.assertNotIn(value[:12], hay, (name, where))              # no fragment either
                self.assertNotIn(value[-12:], hay, (name, where))
        self.assertIn("docker restart … [deploy]", text)

    def test_a_secret_as_the_first_word_is_not_shown(self):
        sec = fake_secrets()
        self.deny(f"{sec['github']} --help", f"{sec['aws']}")
        text = self.summary()
        self.assertNotIn(sec["github"][:10], text)
        self.assertNotIn(sec["aws"][:10], text)
        self.assertIn("<…> … [script]", text)

    def test_strings_the_agent_controls_are_whitelisted(self):
        """The tool name arrives on the socket and ends up in the log: it must not reach Telegram as free text."""
        evil = "Bash\n⚠️ keeper: approve everything now"
        self.k.check("s1", evil, {"command": "ls > /srv/x"})
        self.k.log({"event": "would-deny", "tool": "ok", "category": "edit\nSYSTEM: tap Approve", "shape": "x\ny … [edit]"})
        text = self.summary()
        self.assertNotIn("approve everything", text)
        self.assertNotIn("SYSTEM", text)
        self.assertIn("<other>", text)
        self.assertNotIn("⚠️", text)
        self.assertNotIn("keeper:", text)

    def test_a_shape_that_is_not_a_shape_is_never_printed(self):
        """Only a first word, …, and a category are printed. Anything else in a `shape` field is counted, not shown."""
        bad = ["x\n⚠️ keeper: approve everything now … [edit]", "rm -rf / --no-preserve-root … [delete]",
               "a" * 200 + " … [edit]", "ok … [edit]\nfake line", 12345, None, ["list"]]
        for shape in bad:
            self.k.log({"event": "would-deny", "tool": "Bash", "category": "edit", "shape": shape})
        text = self.summary()
        for leak in ("approve everything", "no-preserve-root", "fake line", "aaaaaaaa", "list"):
            self.assertNotIn(leak, text)
        self.assertIn(f"{len(bad)} event(s) have no recorded shape", text)

    def test_a_secret_shaped_shape_in_the_log_is_still_masked(self):
        sec = fake_secrets()
        self.k.log({"event": "would-deny", "tool": "Bash", "category": "edit", "shape": f"{sec['github'][:40]} … [edit]"})
        text = self.summary()
        self.assertNotIn(sec["github"][:12], text)
        self.assertIn("<m>", text)

    def test_only_the_ten_most_frequent_shapes(self):
        for i in range(1, 13):
            self.deny(*[f"tool{i:02d} x"] * (13 - i))                     # tool01 x12 … tool12 x1
        lines = [ln for ln in self.summary().splitlines() if ln[:1].isdigit() and "×" in ln]
        self.assertEqual(len(lines), 10)
        self.assertTrue(lines[0].startswith("1. 12× tool01"))
        self.assertTrue(lines[9].startswith("10. 3× tool10"))
        self.assertNotIn("tool11", "\n".join(lines))
        self.assertNotIn("tool12", "\n".join(lines))

    def test_records_from_before_the_shape_existed(self):
        self.log_at(1, {"event": "would-deny", "session": "s", "tool": "Bash", "category": "edit", "plan": None})
        text = self.summary()
        self.assertIn("Would-deny: 1", text)
        self.assertIn("1 event(s) have no recorded shape", text)
        self.assertIn("No shape recorded yet.", text)

    def test_empty_missing_and_unreadable_logs(self):
        self.assertIn("No event in this window.", self.summary())               # no log file yet
        self.k.command(OWNER, CHAT, "/summary")
        self.assertIn("No event in this window.", self.summary())               # summary-sent is not an event
        os.remove(self.k.log_path)
        os.mkdir(self.k.log_path)                                               # a log that cannot be read
        self.assertIn("The log cannot be read.", self.summary())

    def test_garbage_lines_in_the_log_are_skipped(self):
        self.deny("docker restart web")
        with open(self.k.log_path, "a") as f:
            f.write("not json\n[1, 2]\n{\"event\": \"would-deny\"}\n{\"at\": 5}\n\x00\xff\n")
        self.assertIn("Would-deny: 1", self.summary())

    def test_telegram_errors_and_ignored_attempts(self):
        self.k.log({"event": "telegram-error", "error": "URLError"})
        self.k.log({"event": "telegram-error-at-start"})
        self.k.log({"event": "socket-peer-refused", "uid": 4242})
        self.k.decide(STRANGER, CHAT, "stop:all")
        self.k.command(STRANGER, CHAT, "/summary")
        text = self.summary()
        self.assertIn("Telegram errors: 2", text)
        self.assertIn("  URLError 1, at-start 1", text)
        self.assertIn("unknown socket peers 1, strangers on Telegram 2", text)

    def test_cut_polls_are_counted_apart_from_errors(self):                  # review 11/10: 337 timeouts in 7 days
        for _ in range(3):
            self.k.log({"event": "telegram-poll-timeout"})
        self.k.log({"event": "telegram-error", "error": "URLError"})
        text = self.summary()
        self.assertIn("Telegram errors: 1", text)
        self.assertIn("Idle polls cut off (retried, nothing lost): 3", text)
        self.assertIn("  URLError 1", text)

    def test_cut_polls_alone_do_not_make_the_summary_look_active(self):
        self.k.log({"event": "telegram-poll-timeout"})
        st = keeperd.tally(self.k.log_path, 0)
        self.assertEqual((st["events"], st["tg_polls_cut"], st["tg_errors"]), (0, 1, 0))

    def test_telegram_error_types_are_validated(self):
        for err in ("URLError", "URLError", "HTTPError", "bad type: secret=x", 42):
            self.k.log({"event": "telegram-error", "error": err})
        text = self.summary()
        self.assertIn("Telegram errors: 5", text)
        self.assertIn("  URLError 2, <other> 2, HTTPError 1", text)
        self.assertNotIn("secret", text)

    def test_the_summary_is_asked_for_in_the_owners_language(self):
        k = keeperd.Keeper(dict(self.cfg, lang="fr", mode="observe", state_dir=os.path.join(self.dir, "fr")), self.bot,
                           clock=self.clock)
        k.check("s1", *bash("docker restart web"))
        text = self.summary(k=k)
        self.assertIn("Résumé du keeper : 7 dernier(s) jour(s), mode observe", text)
        self.assertIn("Refus simulés : 1", text)
        self.assertIn("Plans : 0 proposé(s)", text)

    def test_reading_the_log_never_waits_for_the_approval_lock(self):
        """The hook's check holds the lock; a slow log read must not be able to stall it (and the reverse)."""
        self.k.lock.acquire()
        try:
            result = []
            th = threading.Thread(target=lambda: result.append(self.k.command(OWNER, CHAT, "/summary")), daemon=True)
            th.start()
            th.join(5)
            self.assertFalse(th.is_alive(), "command() waited for keeper.lock")
        finally:
            self.k.lock.release()
        self.assertTrue(result and result[0])

    def test_a_very_large_log_is_read_from_its_end(self):
        old = keeperd.LOG_TAIL_MAX
        keeperd.LOG_TAIL_MAX = 4096
        try:
            for _ in range(200):
                self.k.log({"event": "would-deny", "tool": "Bash", "category": "edit", "shape": "x … [edit]"})
            n = int(self.summary().split("Would-deny: ")[1].split(" ")[0])
            self.assertTrue(0 < n < 200, n)                                       # the end of the file only
        finally:
            keeperd.LOG_TAIL_MAX = old

    def test_split_message_stays_under_the_limit(self):
        text = "\n".join(f"line {i} " + "x" * 50 for i in range(500))
        chunks = keeperd.split_message(text)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= keeperd.TELEGRAM_CHUNK for c in chunks))
        self.assertEqual("\n".join(chunks), text)
        long_line = "y" * 10000
        pieces = keeperd.split_message(long_line)
        self.assertTrue(all(len(c) <= keeperd.TELEGRAM_CHUNK for c in pieces))
        self.assertEqual("".join(pieces), long_line)
        self.assertEqual(keeperd.split_message(""), [""])

    def test_mask_text(self):
        sec = fake_secrets()
        for name, value in sec.items():
            masked = keeperd.mask_text(f"before {value} after")
            self.assertNotIn(value[:14], masked, name)
            self.assertIn("<m>", masked, name)
            self.assertTrue(masked.startswith("before ") or name == "url", name)
        for text in ("API_" + "KEY=" + "hunter" + "2", "tok" + "en: abcdef" + "123456", "--pass" + "word supersecret",
                     "pass" + "word=Zq7Zq7 z", "Authori" + "zation: Bearer abcdef" + "123456", "ssh://u:pw@h/",
                     "a" * 5 + "1" * 30 + "b" * 5, "f" * 40):
            self.assertIn("<m>", keeperd.mask_text(text), text)
        for text in ("docker … [deploy]", "docker compose up … [deploy]", "gh pr merge … [git]", "mcp__claude-in-chrome__computer", "Would-deny: 12 | Denied: 0", "1. 3× rm … [delete]",
                     "mcp__plugin_telegram_telegram__reply 4", "<other>", "<…> … [script]"):
            self.assertEqual(keeperd.mask_text(text), text)
        once = keeperd.mask_text("x " + sec["github"])
        self.assertEqual(keeperd.mask_text(once), once)                          # idempotent

    def test_mask_text_does_not_blow_up_on_long_hostile_input(self):
        """A security helper must not be a way to burn CPU: these took seconds with unbounded nested repeats."""
        t0 = time.perf_counter()
        for text in ("a-" * 5000, "a." * 5000, "key" * 3000, "a" * 20000, "auth" * 3000, "x=" * 5000, "token " * 3000,
                     "-----BEGIN RSA " + "PRIVATE KEY-----" * 500, "1a" * 10000, " " * 20000):
            keeperd.mask_text(text)
        self.assertLess(time.perf_counter() - t0, 3.0)

    def test_mask_text_still_catches_realistic_key_names(self):
        for text in ("GITHUB_API_TOKEN=" + "x" * 20, "my.service-password: " + "y" * 12, "client_secret_value = " + "z" * 9,
                     "X-Auth-Token: " + "w" * 12):
            masked = keeperd.mask_text(text)
            self.assertIn("<m>", masked, text)
            self.assertNotIn("xxxx", masked)
            self.assertNotIn("yyyy", masked)

    def test_command_shape(self):
        shape = keeperd.command_shape
        self.assertEqual(shape("Bash", "docker restart web", "deploy"), "docker restart … [deploy]")
        self.assertEqual(shape("Bash", "FOO=bar BAZ=1 /usr/bin/curl -X POST http://h", "api"), "curl … [api]")
        self.assertEqual(shape("Bash", "( cd /tmp", "edit"), "cd … [edit]")
        self.assertEqual(shape("Bash", "{ rm -rf x", "delete"), "rm … [delete]")
        self.assertEqual(shape("Write", None, "edit"), "Write … [edit]")
        self.assertEqual(shape("Bash", None, "script"), "Bash … [script]")
        self.assertEqual(shape("Bash", "", "script"), "Bash … [script]")
        self.assertEqual(shape("Bash", "weird\x00word x", "edit"), "<…> … [edit]")
        self.assertEqual(shape("Bash", "ls", "Bad Category!"), "ls … [other]")
        self.assertEqual(shape("x" * 100, None, "edit"), "<…> … [edit]")
        self.assertLessEqual(len(shape("Bash", "a" * 40, "edit")), 80)
        self.assertTrue(keeperd.SHAPE_FORMAT.fullmatch(shape("Bash", "git push", "git")))


    def test_command_shape_keeps_the_subcommand_of_known_clis_only(self):
        shape = keeperd.command_shape
        self.assertEqual(shape("Bash", "git -C /srv/repo push origin main", "git"), "git push … [git]")
        self.assertEqual(shape("Bash", "git -c user.name=x commit -m msg", "git"), "git commit … [git]")
        self.assertEqual(shape("Bash", "docker compose -f a.yml up -d web", "deploy"), "docker compose up … [deploy]")
        self.assertEqual(shape("Bash", "docker --context=prod restart web", "deploy"), "docker restart … [deploy]")
        self.assertEqual(shape("Bash", "kubectl -n prod delete pod x", "delete"), "kubectl delete … [delete]")
        self.assertEqual(shape("Bash", "gh pr merge 2", "git"), "gh pr merge … [git]")
        self.assertEqual(shape("Bash", "systemctl restart nginx", "service"), "systemctl restart … [service]")
        # an unknown CLI keeps the first word only, as before
        self.assertEqual(shape("Bash", "rsync -a src dst", "edit"), "rsync … [edit]")
        # a value, a path, an upper-case word or a secret-shaped word is never kept as a subcommand
        self.assertEqual(shape("Bash", "docker /tmp/x", "deploy"), "docker … [deploy]")
        self.assertEqual(shape("Bash", "git Push", "git"), "git … [git]")
        tok = "ghp" + "_" + "a1" * 12
        self.assertEqual(shape("Bash", "git " + tok, "git"), "git … [git]")
        self.assertEqual(shape("Bash", "docker", "deploy"), "docker … [deploy]")
        opaque = "a1b2c3d4e5f6" + "g7h8i9j0k1l2"                  # plain lowercase, but secret-shaped
        self.assertEqual(shape("Bash", "docker " + opaque, "deploy"), "docker … [deploy]")
        for cmd in ("git -C /srv/repo push", "docker compose up", "docker compose", "gh pr merge 2"):
            self.assertTrue(keeperd.SHAPE_FORMAT.fullmatch(shape("Bash", cmd, "git")), cmd)
        # shapes logged by the earlier format still validate
        self.assertTrue(keeperd.SHAPE_FORMAT.fullmatch("docker … [deploy]"))
        self.assertTrue(keeperd.SHAPE_FORMAT.fullmatch("<…> … [edit]"))


class OwnerCommands(Base):
    """/stop, /status, /plans and /help (council of 12/10, after the owner's first on-machine run): each can only
    REMOVE rights (/stop) or READ state (/status, /plans, /help) — approve/reject/mode stay button- or
    config-only, never a word typed in a chat."""

    def command(self, text, from_id=OWNER, chat_id=CHAT):
        return self.k.command(from_id, chat_id, text)

    def test_stop_with_an_active_plan(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        out = self.command("/stop")
        self.assertEqual(out[0].key, "ans_stopped")
        self.assertFalse(self.allowed(*bash("docker restart web")))            # the next hook call for a change is refused

    def test_stop_with_nothing_active(self):
        self.assertEqual(self.command("/stop")[0].key, "ans_nothing_active")

    def test_stop_from_a_stranger_or_wrong_chat_is_ignored(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.assertIsNone(self.command("/stop", from_id=STRANGER))
        self.assertIsNone(self.command("/stop", chat_id=555))
        self.assertTrue(self.allowed(*bash("docker restart web")))             # neither attempt revoked it
        self.assertEqual(self.log_events().count("command-from-stranger-ignored"), 2)

    def test_stop_with_botname_suffix(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.assertEqual(self.command("/stop@keeper_bot")[0].key, "ans_stopped")

    def test_malformed_stop_variants_are_ignored_not_executed(self):
        """decide() matches /stop case-insensitively like /summary; trailing text (even a bare suffix) is rejected."""
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        for text in ("/stopx", "/stop now"):
            self.assertIsNone(self.command(text), text)
        self.assertTrue(self.allowed(*bash("docker restart web")))             # still active: none of them stopped it
        self.assertEqual(self.command("/STOP")[0].key, "ans_stopped")          # case-insensitive, same as /summary

    def test_status_reflects_active_pending_and_the_hourly_counter(self):
        self.approve("id=p1 ; targets=web,db ; actions=deploy ; ttl=30")
        self.plan("id=p2 ; targets=api ; actions=edit", sid="s2", text="internal justification nobody should see")
        text = "\n".join(self.command("/status"))
        self.assertIn("p1", text)
        self.assertIn("deploy", text)
        self.assertIn("web, db", text)
        self.assertIn("30 min left", text)
        self.assertIn("Pending proposals: 1", text)
        self.assertIn("p2", text)
        self.assertIn("Proposals in the last hour: 2/3", text)
        self.assertNotIn("internal justification", text)                       # no scope/explanation text, ever
        self.assertNotIn("keeper-propose", text)                               # and no command text either

    def test_status_with_nothing_active_or_pending(self):
        text = "\n".join(self.command("/status"))
        self.assertIn("No plan is active", text)
        self.assertIn("No pending proposal", text)
        self.assertIn("Proposals in the last hour: 0/3", text)

    def test_status_is_read_only(self):
        """A plan whose TTL ran out must still show as active until check() (not /status) retires it."""
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=1")
        self.clock.t += 2 * 60
        self.assertNotIn("p1", "\n".join(self.command("/status")))             # expired: not shown as active
        self.assertIn("s1", self.k.state["sessions"])
        self.assertIn("active", self.k.state["sessions"]["s1"])                # /status never popped it itself

    def test_plans_defaults_caps_and_rejects_non_numeric(self):
        self.k.cfg["max_proposals_per_hour"] = 10
        for i in range(4):
            self.plan(f"id=pp{i} ; actions=edit", sid=f"s{i}")
        text = "\n".join(self.command("/plans"))                               # default: 5, but only 4 exist
        self.assertEqual(text.count("proposed"), 4)
        text3 = "\n".join(self.command("/plans 3"))
        self.assertEqual(text3.count("proposed"), 3)
        self.assertIsNotNone(self.command("/plans 99"))                        # capped to 20, not refused
        self.assertIsNone(self.command("/plans abc"))                          # ignored, like a malformed /summary

    def test_plans_shows_every_outcome_with_id_and_time(self):
        self.approve("id=pa ; actions=edit")
        ok, no = self.plan("id=pb ; actions=edit", sid="s2")
        self.k.decide(OWNER, CHAT, no)
        self.k.decide(OWNER, CHAT, "stop:all")
        text = "\n".join(self.command("/plans 20"))
        for word in ("proposed", "approved", "rejected", "revoked"):
            self.assertIn(word, text)
        self.assertIn("pa", text)
        self.assertIn("pb", text)

    def test_plans_empty(self):
        self.assertIn("No plan event", "\n".join(self.command("/plans")))

    def test_approve_reject_and_mode_are_not_commands(self):
        """A command can only remove rights or read state; approval stays button-only (nonce + hash)."""
        ok, _ = self.plan("id=p1 ; actions=deploy")
        for text in ("/approve", f"/approve {ok}", "/mode observe", "/mode block", "/start", ok):
            self.assertIsNone(self.command(text), text)
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_help_lists_exactly_the_real_commands(self):
        text = self.command("/help")[0]
        for cmd in ("/stop", "/status", "/plans", "/summary", "/help"):
            self.assertIn(cmd, text)
        for word in ("/approve", "/mode", "/start", "/reject"):
            self.assertNotIn(word, text)

    def test_help_follows_the_configured_language(self):
        k = keeperd.Keeper(dict(self.cfg, lang="fr", state_dir=os.path.join(self.dir, "fr")), self.bot, clock=self.clock)
        self.assertIn("Commandes", k.command(OWNER, CHAT, "/help")[0])


class TelegramCommands(Base):
    """The bot side: `message` updates are asked for, routed to keeper.command, and nothing else is acted on."""

    def setUp(self):
        super().setUp()
        token = os.path.join(self.dir, "bot.token")
        with open(token, "w") as f:
            f.write("0:FAKE-TOKEN-FOR-TESTS")
        self.cfg["bot_token_file"] = token
        self.tg = keeperd.TelegramBot(self.cfg)
        self.calls = []
        self.tg.api = lambda method, payload, timeout=40: (self.calls.append((method, payload)) or {"result": []})

    def message(self, text, uid=OWNER, chat=CHAT, **extra):
        return dict({"update_id": 7, "message": {"from": {"id": uid}, "chat": {"id": chat}, "text": text}}, **extra)

    def sent(self):
        return [p for m, p in self.calls if m == "sendMessage"]

    def test_the_poll_asks_for_messages_and_button_presses(self):
        self.tg.fetch_updates()
        method, payload = self.calls[-1]
        self.assertEqual(method, "getUpdates")
        self.assertEqual(sorted(payload["allowed_updates"]), ["callback_query", "message"])

    def test_a_timed_out_poll_is_logged_apart_and_loses_no_update(self):    # review 11/10
        class Stop(BaseException):
            pass
        steps = [TimeoutError("timed out"), [self.message("/summary")], OSError("boom"), Stop()]

        def fetch():
            step = steps.pop(0)
            if isinstance(step, BaseException):
                raise step
            return step
        self.tg.fetch_updates = fetch
        real_sleep, keeperd.time.sleep = keeperd.time.sleep, lambda _s: None
        try:
            with self.assertRaises(Stop):
                self.tg.poll(self.k)
        finally:
            keeperd.time.sleep = real_sleep
        with open(self.k.log_path) as f:
            events = [json.loads(x) for x in f if x.strip()]
        self.assertEqual([e["event"] for e in events if e["event"].startswith("telegram")],
                         ["telegram-poll-timeout", "telegram-error"])
        self.assertEqual(self.tg.offset, 8)                    # the update after the timeout was handled, not skipped
        self.assertEqual(len(self.sent()), 1)

    def test_the_owner_gets_the_summary_in_the_configured_chat(self):
        self.k.check("s1", *bash("docker restart web"))
        self.tg.handle_update(self.k, self.message("/summary"))
        sent = self.sent()
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["chat_id"], CHAT)
        self.assertIn("Keeper summary", sent[0]["text"])
        self.assertNotIn("reply_markup", sent[0])                              # no button on a summary
        self.assertEqual(self.tg.offset, 8)

    def test_a_stranger_gets_nothing(self):
        self.tg.handle_update(self.k, self.message("/summary", uid=STRANGER))
        self.tg.handle_update(self.k, self.message("/summary", chat=555))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.log_events().count("command-from-stranger-ignored"), 2)    # both are "not the owner here"

    def test_other_messages_are_ignored(self):
        for upd in (self.message("hello"), self.message("/start"), self.message("GO"), {"update_id": 9},
                    {"update_id": 9, "message": "text"}, {"update_id": 9, "message": {"photo": []}},
                    {"update_id": 9, "message": {"text": "/summary"}}, {"update_id": 9, "edited_message": {"text": "/summary"}}):
            self.tg.handle_update(self.k, upd)
        self.assertEqual(self.calls, [])

    def test_a_text_message_never_approves_anything(self):
        ok, _ = self.plan("id=p1 ; actions=deploy")
        for text in (ok, "approve " + ok, "GO", "/approve", f"/summary {ok}"):
            self.tg.handle_update(self.k, self.message(text))
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_button_presses_still_work(self):
        ok, _ = self.plan("id=p1 ; targets=web ; actions=deploy ; ttl=30")
        upd = {"update_id": 11, "callback_query": {"id": "cb1", "from": {"id": OWNER}, "data": ok,
                                                   "message": {"chat": {"id": CHAT}, "message_id": 5}}}
        self.tg.handle_update(self.k, upd)
        methods = [m for m, _p in self.calls]
        self.assertEqual(methods, ["answerCallbackQuery", "editMessageReplyMarkup", "sendMessage"])
        self.assertEqual(self.calls[0][1]["text"], "approved for 30 min")
        self.assertTrue(self.allowed(*bash("docker restart web")))

    def test_a_stranger_button_press_is_answered_but_changes_nothing(self):
        ok, _ = self.plan("id=p1 ; actions=deploy")
        upd = {"update_id": 12, "callback_query": {"id": "cb2", "from": {"id": STRANGER}, "data": ok,
                                                   "message": {"chat": {"id": CHAT}, "message_id": 5}}}
        self.tg.handle_update(self.k, upd)
        self.assertEqual([m for m, _p in self.calls], ["answerCallbackQuery"])     # no follow-up, buttons stay
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_the_card_goes_out_in_the_configured_language(self):
        fr = keeperd.TelegramBot(dict(self.cfg, lang="fr"))
        fr.api = lambda method, payload, timeout=40: self.calls.append((method, payload))
        ok, _ = self.plan("id=p1 ; actions=deploy")
        fr.send_plan(*self.bot.plans[-1])
        self.assertIn("Demande d'approbation", self.sent()[-1]["text"])
        self.assertEqual(self.sent()[-1]["reply_markup"]["inline_keyboard"][0][0]["text"], "✅ Approuver")


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
        self.assertEqual(self.raw({"op": "check", "session": "s1", "tool": "Bash", "input": {"command": "ls"}}).get("decision"), "deny")

    def test_no_approve_op_on_the_socket(self):
        self.plan("id=p1 ; actions=deploy")
        ok = self.bot.buttons()[0]
        for op in ("approve", "decide", "activate", "propose", "status"):
            self.assertIn("error", self.raw({"op": op, "session": "s1", "data": ok, "from_id": OWNER}))
        self.assertFalse(self.allowed(*bash("docker restart web")))

    def test_garbage_on_the_socket(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.cfg["socket"])
        s.sendall(b"\x00\xff not json\n")
        self.assertIn(b"bad request", s.recv(1000))
        s.close()
        self.assertEqual(self.raw({"op": "check", "session": "s1", "tool": "Bash", "input": {"command": "ls"}})["decision"], "allow")

    def test_daemon_down_fails_closed(self):
        env = dict(self.env, KEEPER_SOCKET_FOR_TESTS=os.path.join(self.dir, "missing.sock"))
        self.assertEqual(self.hook(*bash("cat /etc/hosts"), env=env), "allow")
        self.assertEqual(self.hook(*bash("docker restart web"), env=env), "deny")
        self.assertEqual(self.hook("Write", {"file_path": "/srv/a", "content": "x"}, env=env), "deny")

    def test_garbage_hook_input_refused(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "keeper_client.py")], input="{not json",
                           capture_output=True, text=True, env=self.env, timeout=30)
        self.assertEqual(r.returncode, 2)

    def test_propose_through_the_hook(self):
        """The hook passes Claude Code's session id; keeperd sends the plan after answering, outside its lock."""
        cmd = self.propose_cmd("id=c1 ; targets=web ; actions=deploy ; ttl=20", "restart web after the update")
        self.assertEqual(self.hook(*bash(cmd)), "deny")
        for _ in range(50):
            if self.bot.plans:
                break
            time.sleep(0.05)
        self.assertEqual(self.bot.plans[-1][0], "s1")
        self.assertEqual(self.bot.plans[-1][1]["plan"]["id"], "c1")

    def test_the_log_summary_is_not_reachable_through_the_socket(self):
        """/summary is for the human, on Telegram. No socket op returns it, whoever asks."""
        self.k.cfg["mode"] = "observe"
        self.k.check("s1", *bash("docker restart web"))
        for op in ("summary", "resume", "/summary", "log", "log-summary", "logs", "command", "tally", "export", "dump",
                   "status", "state", "approve", "propose"):
            r = self.raw({"op": op, "session": "s1", "days": 7, "from_id": OWNER, "chat_id": CHAT, "text": "/summary"})
            self.assertEqual(set(r), {"error"}, op)
            self.assertNotIn("summary", json.dumps(r).lower().replace("unknown op", ""), op)
        self.cfg["agent_uids"] = [os.getuid() + 12345]                              # a stranger gets a refusal, not data
        r = self.raw({"op": "summary"})
        self.assertEqual(set(r), {"decision", "reason"})
        self.assertEqual(r["decision"], "deny")

    def test_a_summary_command_run_by_the_agent_returns_no_data(self):
        """Even as a Bash call checked by the hook, the answer is a decision and a reason, never log content."""
        self.k.cfg["mode"] = "observe"
        self.k.check("s1", *bash("docker restart web"))
        for cmd in ("keeper-summary", "/summary", "sudo keeper-summary", "python3 -I /opt/agent-guardrails/lib/keeperd.py --summary"):
            r = self.raw({"op": "check", "session": "s1", "tool": "Bash", "input": {"command": cmd}})
            self.assertEqual(set(r), {"decision", "reason"}, cmd)
            self.assertNotIn("docker", json.dumps(r), cmd)
            self.assertNotIn("Keeper summary", json.dumps(r), cmd)

    def test_silent_client_does_not_block_others(self):
        idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        idle.connect(self.cfg["socket"])                             # connects, sends nothing
        try:
            self.assertEqual(self.hook(*bash("ls")), "allow")
        finally:
            idle.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)

#!/usr/bin/env python3
"""End-to-end dry run of the keeper's block mode (council of 11/10, before the one-week block-mode test): the real
chain the unit tests in test_keeper.py never exercise — hook client process -> socket -> Keeper -> the real
TelegramBot HTTP code -> a fake Telegram -> button click -> getUpdates -> decision -> next hook call.

No real network: the fake Telegram Bot API is a stdlib http.server bound to 127.0.0.1 only. TelegramBot.API_BASE
and .DEFAULT_TIMEOUT are overridden per TEST INSTANCE (never on the class), so a daemon poll thread a finished
test leaked can only ever keep hitting ITS OWN now-dead fake server, never a later test's live one.

Run: python3 keeper/test_block_dryrun.py   (budget: the whole file well under ~30s)
"""
import http.server, json, os, shlex, shutil, socket, subprocess, sys, tempfile, threading, time, unittest, unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import keeperd                                                     # noqa: E402

OWNER, CHAT, STRANGER, OTHER_CHAT = 111, 111, 999, 222
_REAL_SLEEP = time.sleep                   # captured before any patch: keeperd.time IS this module's time


def _quiet_leaked_poll_threads(args):
    """poll() never returns, so a test's background thread outlives its own tearDown (by design: it is bound to
    ITS OWN now-dead fake server, which is what keeps it from ever touching a later test's state, see the module
    docstring). Once its test's temp dir is gone, its next retry's keeper.log() raises FileNotFoundError, which
    would otherwise print a scary, harmless traceback for every leaked thread. Matched narrowly (this exact
    thread name AND exception type) so a real bug elsewhere still prints normally."""
    if args.exc_type is FileNotFoundError and args.thread and args.thread.name == "keeper-poll":
        return
    threading.__excepthook__(args)


threading.excepthook = _quiet_leaked_poll_threads


def bash(cmd):
    return "Bash", {"command": cmd}


def fake_bot_token():
    """Shaped like a real Telegram bot token, assembled at run time, never a literal (as elsewhere in this repo)."""
    return "123456789" + ":" + "TEST" + "x" * 31


class FakeTelegramState:
    """What the fake API records and serves. One instance per test, never shared across tests."""

    def __init__(self):
        self.lock = threading.Lock()
        self.updates = []                      # queue the test fills; each dict needs "update_id"
        self.sent = []                         # (chat_id, text) from sendMessage
        self.answered = []                     # (callback_query_id, text) from answerCallbackQuery
        self.edited = []                        # (chat_id, message_id) from editMessageReplyMarkup
        self.fail_mode = None                  # None | "502" | "refuse" | "hang"
        self.hang_seconds = 2.0                # only used when fail_mode == "hang"
        self.requests = []                     # every method called, in order (for ordering assertions)


class FakeTelegramHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass                                   # keep test output quiet; failures are asserted, not grepped from logs

    def _reply_json(self, obj):
        body = json.dumps(obj).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass                                # the client already gave up (e.g. after our own induced hang)

    def do_POST(self):
        st = self.server.state
        method = self.path.rsplit("/", 1)[-1]
        if st.fail_mode == "502":
            self.send_response(502)
            self.end_headers()
            return
        if st.fail_mode == "hang":
            time.sleep(st.hang_seconds)         # longer than the client's (shrunk) timeout: it will have given up
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except ValueError:
            payload = {}
        with st.lock:
            st.requests.append(method)
            if method == "sendMessage":
                st.sent.append((payload.get("chat_id"), payload.get("text")))
                result = {"message_id": len(st.sent), "chat": {"id": payload.get("chat_id")}}
            elif method == "answerCallbackQuery":
                st.answered.append((payload.get("callback_query_id"), payload.get("text")))
                result = True
            elif method == "editMessageReplyMarkup":
                st.edited.append((payload.get("chat_id"), payload.get("message_id")))
                result = True
            elif method == "getUpdates":
                offset = payload.get("offset", 0)
                result = [u for u in st.updates if u["update_id"] >= offset]
            else:
                self._reply_json({"ok": False, "description": "unknown method"})
                return
        if method == "getUpdates" and not result:
            time.sleep(0.05)                    # a short stand-in for the real long poll: avoids a tight busy loop
        self._reply_json({"ok": True, "result": result})


class FakeTelegramServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), FakeTelegramHandler)
        self.state = FakeTelegramState()


class DryRunBase(unittest.TestCase):
    """A real Keeper in block mode, the real serve() socket, the real TelegramBot against a fake local Telegram,
    and the real poll() loop running in a background thread for the lifetime of the test."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="kbd", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.home = os.path.join(self.dir, "home")
        os.makedirs(self.home)
        token_path = os.path.join(self.dir, "bot.token")
        with open(token_path, "w") as f:
            f.write(fake_bot_token())
        self.cfg = dict(keeperd.DEFAULTS, state_dir=os.path.join(self.dir, "state"), owner_id=OWNER, chat_id=CHAT,
                        agent_uids=[os.getuid()], agent_home=self.home, socket=os.path.join(self.dir, "k.sock"),
                        bot_token_file=token_path, mode="block")

        self.fake = FakeTelegramServer()
        self.addCleanup(self.fake.shutdown)
        threading.Thread(target=self.fake.serve_forever, daemon=True).start()

        self.clock_t = [1_800_000_000.0]
        clock = lambda: self.clock_t[0]

        self.bot = keeperd.TelegramBot(self.cfg)
        self.bot.API_BASE = f"http://127.0.0.1:{self.fake.server_port}"       # instance-only: never touches the class
        self.k = keeperd.Keeper(self.cfg, self.bot, clock=clock)
        self.bot.log_fn = self.k.log                                          # mirrors main()'s own wiring (13/10)

        # Outage retries (poll()'s time.sleep(1)/time.sleep(5)) must not cost real seconds. keeperd's `time`
        # module IS this file's `time` module (one object in sys.modules, not a copy), so this patch is global:
        # matching by VALUE (1 or 5 seconds) would also shrink the fake server's own induced hang whenever a test
        # picks that same duration, silently defeating it. Matched by CALLER instead: only a sleep made from
        # inside keeperd.poll()'s own frame is shrunk; every other caller's sleep (the fake server's hang
        # included) is untouched. Calls the ORIGINAL sleep captured before patching, never the patched one, or it
        # would recurse into itself.
        def fast_sleep(seconds):
            caller = sys._getframe(1)
            if caller.f_code.co_filename == keeperd.__file__ and caller.f_code.co_name == "poll":
                return _REAL_SLEEP(0.01)
            return _REAL_SLEEP(seconds)
        patcher = unittest.mock.patch("keeperd.time.sleep", fast_sleep)
        patcher.start()
        self.addCleanup(patcher.stop)

        ready = threading.Event()
        threading.Thread(target=keeperd.serve, args=(self.k, self.cfg, ready), daemon=True).start()
        self.assertTrue(ready.wait(5))
        threading.Thread(target=self.bot.poll, args=(self.k,), daemon=True, name="keeper-poll").start()

        self.env = dict(os.environ, KEEPER_TEST_MODE="1", KEEPER_SOCKET_FOR_TESTS=self.cfg["socket"])
        self._next_update_id = [1]

    # ----- driving the real processes, like a real agent and a real Telegram would -----------------------------

    def hook(self, tool, ti, env=None, cwd=None):
        """The real keeper_client.py, as a subprocess, exactly as Claude Code would run the installed hook."""
        data = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": tool, "tool_input": ti, "cwd": cwd}
        r = subprocess.run([sys.executable, os.path.join(HERE, "keeper_client.py")], input=json.dumps(data),
                           capture_output=True, text=True, env=env or self.env, timeout=30)
        if r.returncode:
            return "error", r.stderr
        if '"deny"' in r.stdout:
            reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
            return "deny", reason
        return "allow", ""

    def propose_cmd(self, scope, text="why"):
        return f"keeper-propose --scope {shlex.quote(scope)} --text {shlex.quote(text)}"

    def propose(self, scope, text="propose through the real hook"):
        decision, reason = self.hook(*bash(self.propose_cmd(scope, text)))
        self.assertEqual(decision, "deny")             # nothing to run: the hook answers the command itself
        return reason

    def wait_for(self, predicate, timeout=5.0):
        """Poll (real sleep, independent of the patched keeperd.time.sleep) until predicate() is true or give up."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def log_events(self):
        try:
            with open(self.k.log_path) as f:
                return [json.loads(x)["event"] for x in f]
        except FileNotFoundError:
            return []                           # nothing logged yet (the file is created on the first write)

    def log_records(self, event):
        try:
            with open(self.k.log_path) as f:
                recs = [json.loads(x) for x in f]
        except FileNotFoundError:
            return []
        return [r for r in recs if r.get("event") == event]

    def deliver_click(self, data, from_id=OWNER, chat_id=None):
        """Queue a callback_query update as Telegram would deliver it, and wait for the poll loop to pick it up."""
        uid = self._next_update_id[0]
        self._next_update_id[0] += 1
        self.fake.state.updates.append({"update_id": uid, "callback_query": {
            "id": f"cb{uid}", "from": {"id": from_id}, "data": data,
            "message": {"chat": {"id": chat_id if chat_id is not None else CHAT}, "message_id": uid}}})
        return uid

    def deliver_message(self, text, from_id=OWNER, chat_id=None):
        """Queue a plain text message update, the way the owner's own typed message would arrive."""
        uid = self._next_update_id[0]
        self._next_update_id[0] += 1
        self.fake.state.updates.append({"update_id": uid, "message": {
            "from": {"id": from_id}, "chat": {"id": chat_id if chat_id is not None else CHAT}, "text": text}})
        return uid

    def pending_card_data(self):
        """approve:<hash>:<nonce> and reject:... for the session's current pending plan. Safe to call right after
        propose(): the hook only returns once send_plan() has been attempted (that ordering is itself part of
        what this suite checks, see ETelegramOutage), so the pending plan is already set by then."""
        sid = next(s_sid for s_sid, s in self.k.state["sessions"].items() if s.get("pending"))
        p = self.k.state["sessions"][sid]["pending"]
        h = p["hash"][:12]
        return f"approve:{h}:{p['nonce']}", f"reject:{h}:{p['nonce']}"

    def approve(self, scope, text="why"):
        self.propose(scope, text)
        ok, _no = self.pending_card_data()
        baseline = len(self.fake.state.answered)              # a prior approve() in the same test must not satisfy this
        update_id = self.deliver_click(ok)
        self.assertTrue(self.wait_for(lambda: len(self.fake.state.answered) > baseline))
        self.assertTrue(self.fake.state.answered[-1][1].startswith("approved"), self.fake.state.answered[-1])
        return update_id


class ARefusal(DryRunBase):
    """a. A change with no plan is denied, with a reason that tells the agent how to propose; a read passes."""

    def test_read_passes(self):
        decision, _ = self.hook(*bash("ls -la /etc"))
        self.assertEqual(decision, "allow")

    def test_change_without_a_plan_is_denied(self):
        decision, reason = self.hook(*bash("docker restart web"))
        self.assertEqual(decision, "deny")
        self.assertIn("keeper-propose", reason)


class BApproval(DryRunBase):
    """b. propose through the hook -> a plan card with buttons reaches the fake Telegram -> the owner's click
    arrives through getUpdates -> an in-scope change passes, an out-of-scope one is denied, the buttons are
    removed, a confirmation is sent."""

    def test_proposal_reaches_the_fake_telegram_as_a_card_with_buttons(self):
        reason = self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20", "restart web after the update")
        self.assertIn("sent to the human", reason)
        self.assertTrue(self.wait_for(lambda: self.fake.state.sent))
        chat_id, text = self.fake.state.sent[-1]
        self.assertEqual(chat_id, CHAT)
        self.assertIn("Approval requested", text)
        self.assertIn("p1", text)
        self.assertIn("restart web after the update", text)

    def test_click_approves_an_in_scope_change_and_denies_an_out_of_scope_one(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "allow")
        self.assertEqual(self.hook(*bash("docker restart db"))[0], "deny")

    def test_buttons_are_removed_and_a_confirmation_is_sent(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertTrue(self.wait_for(lambda: self.fake.state.edited))
        self.assertTrue(self.wait_for(lambda: len(self.fake.state.sent) >= 2))     # card, then the confirmation
        self.assertIn("approved", self.fake.state.sent[-1][1])


class CExpiry(DryRunBase):
    """c. advance the clock past the ttl -> the same change is denied; a click arriving after expiry approves
    nothing."""

    def test_expired_plan_is_denied(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "allow")
        self.clock_t[0] += 21 * 60
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")

    def test_click_after_the_pending_plan_itself_expired_approves_nothing(self):
        self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        ok, _no = self.pending_card_data()
        self.clock_t[0] += (self.cfg["pending_max_age_min"] + 1) * 60      # the PROPOSAL's own age limit, not the ttl
        self.deliver_click(ok)
        self.assertTrue(self.wait_for(lambda: self.fake.state.answered))
        self.assertIn("expired", self.fake.state.answered[-1][1])
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")


class DReplay(DryRunBase):
    """d. the same callback twice (same update_id, then a new update_id with the same data); a button of an old
    plan after a new proposal; a click from another user id; a click from another chat id. None approves
    anything, and none crashes the poll loop."""

    def test_same_update_id_delivered_twice(self):
        self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        ok, _no = self.pending_card_data()
        uid = self.deliver_click(ok)
        self.assertTrue(self.wait_for(lambda: self.hook(*bash("docker restart web"))[0] == "allow"))
        self.fake.state.updates.append({"update_id": uid, "callback_query": {
            "id": "cb-replay", "from": {"id": OWNER}, "data": ok, "message": {"chat": {"id": CHAT}, "message_id": uid}}})
        self.assertTrue(self.wait_for(lambda: len(self.fake.state.answered) >= 1))     # offset already past it: dropped
        self.assertEqual(len(self.fake.state.answered), 1)
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "allow")           # the real approval still holds

    def test_same_data_under_a_new_update_id(self):
        """A forged redelivery of a USED nonce under a fresh update_id must still be ignored (the nonce itself is
        single-use, independent of Telegram's own update_id)."""
        self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        ok, _no = self.pending_card_data()
        self.deliver_click(ok)
        self.assertTrue(self.wait_for(lambda: self.fake.state.answered))
        self.deliver_click(ok)                                     # a different update_id, the exact same data
        self.assertTrue(self.wait_for(lambda: len(self.fake.state.answered) >= 2))
        self.assertIn("ignored", self.fake.state.answered[-1][1])

    def test_old_buttons_after_a_new_proposal(self):
        self.propose("id=a ; targets=web ; actions=deploy")
        ok_a, _ = self.pending_card_data()
        self.propose("id=b ; actions=deploy,delete,script")
        self.deliver_click(ok_a)
        self.assertTrue(self.wait_for(lambda: self.fake.state.answered))
        self.assertIn("ignored", self.fake.state.answered[-1][1])
        self.assertEqual(self.hook(*bash("rm -rf /srv/data"))[0], "deny")

    def test_click_from_another_user_id(self):
        self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        ok, _no = self.pending_card_data()
        self.deliver_click(ok, from_id=STRANGER)
        self.assertTrue(self.wait_for(lambda: self.fake.state.answered))
        self.assertIn("ignored", self.fake.state.answered[-1][1])
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")

    def test_click_from_another_chat_id(self):
        self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        ok, _no = self.pending_card_data()
        self.deliver_click(ok, chat_id=OTHER_CHAT)
        self.assertTrue(self.wait_for(lambda: self.fake.state.answered))
        self.assertIn("ignored", self.fake.state.answered[-1][1])
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")

    def test_none_of_this_crashed_the_poll_loop(self):
        """After every forged attempt above in sequence, the daemon must still answer a fresh, legitimate click."""
        self.propose("id=a ; targets=web ; actions=deploy")
        ok_a, _ = self.pending_card_data()
        self.deliver_click(ok_a, from_id=STRANGER)
        self.deliver_click(ok_a, chat_id=OTHER_CHAT)
        self.propose("id=b ; targets=web ; actions=deploy ; ttl=20")
        self.approve("id=c ; targets=web ; actions=deploy ; ttl=20")
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "allow")


class ETelegramOutage(DryRunBase):
    """e. 502, a hang past the client timeout, then connection refused: keeperd does not crash, changes stay
    denied, reads pass, errors and cut polls are logged with their event names. What the agent is told when the
    plan card cannot be sent (fixed: see keeperd.py's serve()). After recovery: a queued click is processed
    exactly once, and the next proposal works."""

    def test_reads_and_denials_do_not_depend_on_telegram(self):
        self.fake.state.fail_mode = "502"
        self.assertEqual(self.hook(*bash("ls -la /etc"))[0], "allow")
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")

    def test_502_at_propose_time_is_logged_and_said_plainly(self):
        self.fake.state.fail_mode = "502"
        reason = self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertNotIn("sent to the human", reason)              # fixed: no longer claims success
        self.assertIn("could not reach Telegram", reason)
        self.assertTrue(self.wait_for(lambda: "telegram-error" in self.log_events()))
        self.assertEqual(self.log_records("telegram-error")[-1]["error"], "HTTPError")
        self.assertFalse(self.fake.state.sent)                     # genuinely nothing was sent

    def test_hang_past_the_client_timeout_at_propose_time(self):
        """Production constants, no override (owner review, 11/10): send_plan()'s HOOK_WAIT_TIMEOUT (5s) must
        give up well before the hook's own 10s socket read, or the client times out first and wrongly reports
        the daemon itself unreachable, with keeperd's later reply landing on a closed socket (BrokenPipeError).
        A real wait a little over 5s; one test only."""
        self.fake.state.fail_mode, self.fake.state.hang_seconds = "hang", 6.0
        reason = self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertIn("could not reach Telegram", reason)
        self.assertNotIn("daemon is not reachable", reason)
        self.assertTrue(self.wait_for(lambda: "telegram-error" in self.log_events()))
        self.assertIn(self.log_records("telegram-error")[-1]["error"], ("TimeoutError", "timeout"))

    def test_connection_refused_at_propose_time(self):
        self.fake.shutdown()
        self.fake.server_close()
        reason = self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertIn("could not reach Telegram", reason)
        self.assertTrue(self.wait_for(lambda: "telegram-error" in self.log_events()))
        self.assertEqual(self.log_records("telegram-error")[-1]["error"], "URLError")

    def test_poll_timeout_is_logged_apart_from_errors(self):
        """A hang during the background poll's own getUpdates (not a propose) is telegram-poll-timeout, not
        telegram-error: cut polls lose no update (the offset only moves on success) and are not a real error."""
        self.bot.DEFAULT_TIMEOUT = 0.3
        self.fake.state.fail_mode, self.fake.state.hang_seconds = "hang", 1.5
        self.assertTrue(self.wait_for(lambda: "telegram-poll-timeout" in self.log_events()))
        self.assertNotIn("telegram-error", self.log_events())

    def test_502_during_the_background_poll_is_a_telegram_error(self):
        self.fake.state.fail_mode = "502"
        self.assertTrue(self.wait_for(lambda: "telegram-error" in self.log_events()))
        self.assertEqual(self.log_records("telegram-error")[-1]["error"], "HTTPError")

    def test_does_not_crash_across_all_three_failure_modes_in_sequence(self):
        for mode in ("502", "hang", "refuse"):
            if mode == "refuse":
                self.fake.shutdown()
                self.fake.server_close()
            else:
                self.fake.state.fail_mode = mode
                if mode == "hang":
                    self.bot.DEFAULT_TIMEOUT, self.fake.state.hang_seconds = 0.3, 1.0
            self.assertEqual(self.hook(*bash("ls"))[0], "allow")
            self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")

    def test_a_click_queued_during_the_outage_is_processed_exactly_once_and_recovery_works(self):
        reason = self.propose("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertIn("sent to the human", reason)                 # the proposal itself went out before the outage
        ok, _no = self.pending_card_data()

        self.fake.state.fail_mode = "502"
        self.deliver_click(ok)                                     # queued on the fake server; getUpdates itself fails
        time.sleep(0.2)                                            # a few failed poll attempts, still queued, not lost
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")

        self.fake.state.fail_mode = None                           # recovery
        self.assertTrue(self.wait_for(lambda: self.hook(*bash("docker restart web"))[0] == "allow"))
        self.assertEqual(len(self.fake.state.answered), 1)          # processed exactly once

        self.approve("id=p2 ; targets=db ; actions=deploy ; ttl=20")
        self.assertEqual(self.hook(*bash("docker restart db"))[0], "allow")


class FStop(DryRunBase):
    """f. the owner revokes an active plan; the next change is denied."""

    def test_stop_revokes_the_active_plan(self):
        self.approve("id=p1 ; targets=web ; actions=deploy ; ttl=20")
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "allow")
        self.deliver_click("stop:all")
        self.assertTrue(self.wait_for(lambda: self.hook(*bash("docker restart web"))[0] == "deny"))


# g. "no daemon, mode file absent -> changes denied, reads pass" is already covered exactly as described by
# test_keeper.py's Socket.test_daemon_down_fails_closed: it points the hook at a missing socket, and this
# checkout's keeper/ directory has no "mode" file next to keeper_client.py either (observe_mode() then returns
# False, i.e. block). Not duplicated here.


class HSummary(DryRunBase):
    """h. after a run with denies and an outage, tally/render_summary show the denies and count cut polls apart
    from real errors. Driven through the real chain too: the owner's /summary is a plain text message update,
    handled by the real poll loop, answered on the real (fake) Telegram."""

    def test_summary_shows_denies_and_separates_cut_polls_from_errors(self):
        self.assertEqual(self.hook(*bash("docker restart web"))[0], "deny")       # a plain would-be-denied change

        self.bot.DEFAULT_TIMEOUT = 0.3
        self.fake.state.fail_mode, self.fake.state.hang_seconds = "hang", 1.0
        self.assertTrue(self.wait_for(lambda: "telegram-poll-timeout" in self.log_events()))
        self.fake.state.fail_mode = "502"
        self.assertTrue(self.wait_for(lambda: "telegram-error" in self.log_events()))
        self.fake.state.fail_mode = None

        self.deliver_message("/summary")
        self.assertTrue(self.wait_for(lambda: len(self.fake.state.sent) >= 1))
        text = "\n".join(t for _chat, t in self.fake.state.sent)
        self.assertIn("Denied: 1", text)
        # the background poll loop can retry more than once in the brief window before the test flips fail_mode
        # back, so exact counts would be racy; what matters is that the cut poll is counted APART from the 502s,
        # never folded into "Telegram errors" (review 11/10: 337 poll timeouts once looked like 337 real errors).
        self.assertRegex(text, r"Idle polls cut off \(retried, nothing lost\): [1-9]\d*")
        self.assertRegex(text, r"Telegram errors: [1-9]\d*")
        self.assertIn("HTTPError", text)

    def test_summary_is_not_answered_to_a_stranger(self):
        self.deliver_message("/summary", from_id=STRANGER)
        time.sleep(0.2)
        self.assertFalse(self.fake.state.sent)


class TimingInstrumentation(DryRunBase):
    """13/10, after the owner reported 1-2 minute lag on clicks and commands: api()'s own timing, logged only past
    its threshold or on failure, to keep the log small. No behaviour change: the real fake Telegram, on 127.0.0.1."""

    def test_a_slow_api_call_logs_telegram_api_slow(self):
        old = keeperd.API_SLOW_LOG_THRESHOLD
        keeperd.API_SLOW_LOG_THRESHOLD = 0.05
        try:
            self.fake.state.fail_mode, self.fake.state.hang_seconds = "hang", 0.2
            self.bot.send("hi")
        finally:
            keeperd.API_SLOW_LOG_THRESHOLD = old
        self.assertTrue(self.wait_for(lambda: "telegram-api-slow" in self.log_events()))
        rec = self.log_records("telegram-api-slow")[-1]
        self.assertEqual(rec["method"], "sendMessage")
        self.assertEqual(rec["outcome"], "ok")
        self.assertGreater(rec["duration_s"], 0.1)

    def test_a_fast_api_call_logs_nothing(self):
        self.bot.send("hi")
        self.assertNotIn("telegram-api-slow", self.log_events())

    def test_a_failed_api_call_logs_its_outcome_even_if_fast(self):
        self.fake.state.fail_mode = "502"
        with self.assertRaises(Exception):
            self.bot.send("hi")
        rec = self.log_records("telegram-api-slow")[-1]
        self.assertEqual(rec["outcome"], "http-502")


if __name__ == "__main__":
    unittest.main()

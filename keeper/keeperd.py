#!/usr/bin/env python3
"""keeperd: holds the human's approvals out of the agent's reach (go-gate step 2). Design: docs/design-keeper.md.

Runs as a dedicated system user (`_keeper`). The agent talks to it over a Unix socket; the human talks to it through a
Telegram bot whose token only this user can read. The agent can propose a plan and ask "is this tool call covered?";
it cannot approve, change or read the approval state.

Requests (one JSON object per line on the socket):
  {"op": "propose", "session": s, "text": "...", "scope": "id=… ; targets=… ; actions=… ; ttl=…"}
  {"op": "check",   "session": s, "tool": "Bash", "input": {...}}           -> {"decision": "allow"|"deny", "reason": …}
  {"op": "status",  "session": s}                                            -> active plan summary (no secrets)

Standard library only. Python 3.9+.
"""
import hashlib, importlib.util, json, os, re, secrets, socket, socketserver, struct, sys, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {"socket": "/var/run/keeper/keeper.sock", "state_dir": "/var/lib/keeper", "agent_uids": [],
            "owner_id": None, "chat_id": None, "bot_token_file": "/etc/keeper/bot.token",
            "ttl_default_min": 60, "ttl_max_min": 240, "pending_max_age_min": 120, "max_proposals_per_hour": 3,
            "mode": "block", "agent_home": None, "client_group": None}


def load_gate(agent_home=None):
    """The go-gate classifier, from the root-owned copy next to this file. Its protected and scratch paths are the
    agent's (~ = the agent's home), not keeperd's own."""
    if agent_home:
        os.environ["HOME"] = agent_home
    os.environ.pop("GO_GATE_DIR", None)
    path = os.path.join(HERE, "go_gate.py")
    if not os.path.exists(path):
        path = os.path.join(HERE, "..", "go-gate", "go_gate.py")
    spec = importlib.util.spec_from_file_location("go_gate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if mod.pipeline_stages is None:
        mod.scan, mod.pipeline_stages = mod._load_splitter()
    return mod


# ---------------------------------------------------------------------------------------------------------------
# State: approvals live here and only here.
# ---------------------------------------------------------------------------------------------------------------
class Keeper:
    def __init__(self, cfg, notifier, clock=time.time):
        self.cfg, self.notify, self.now = cfg, notifier, clock
        self.gate = load_gate(cfg.get("agent_home"))
        self.lock = threading.Lock()
        os.makedirs(cfg["state_dir"], mode=0o700, exist_ok=True)
        self.state_path = os.path.join(cfg["state_dir"], "state.json")
        self.log_path = os.path.join(cfg["state_dir"], "log.jsonl")
        try:
            self.state = json.load(open(self.state_path))
        except (OSError, ValueError):
            self.state = {"sessions": {}, "used_nonces": [], "proposals": []}

    def save(self):
        tmp = self.state_path + ".tmp"
        old = os.umask(0o077)
        try:
            with open(tmp, "w") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.state_path)
        finally:
            os.umask(old)

    def log(self, rec):
        rec["at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        old = os.umask(0o077)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        finally:
            os.umask(old)

    def session(self, sid):
        return self.state["sessions"].setdefault(str(sid or "no-session"), {})

    # ----- agent side ------------------------------------------------------------------------------------------
    def propose(self, sid, text, scope_line):
        pr = self.state.get("proposer") or {}
        if not sid and pr and self.now() - pr["at"] < 60:
            sid = pr["session"]
        plan = self.gate.parse_scope("Scope: " + (scope_line or "")) or self.gate.parse_scope(text or "")
        if not plan:
            return {"ok": False, "reason": "no valid scope (actions=edit,git,deploy,api,browser,delete,script,doc)"}
        now = self.now()
        recent = [t for t in self.state["proposals"] if t > now - 3600]
        if len(recent) >= self.cfg["max_proposals_per_hour"]:
            self.log({"event": "proposal-refused-flood", "session": sid})
            return {"ok": False, "reason": f"more than {self.cfg['max_proposals_per_hour']} proposals in an hour"}
        ttl = min(plan.get("ttl") or self.cfg["ttl_default_min"], self.cfg["ttl_max_min"])
        plan["ttl"] = ttl
        body = json.dumps({"text": text, "scope": plan}, sort_keys=True)
        phash = hashlib.sha256(body.encode()).hexdigest()
        nonce = secrets.token_hex(8)
        pending = {"plan": plan, "text": (text or "")[:3000], "hash": phash, "nonce": nonce, "proposed_at": now}
        self.session(sid)["pending"] = pending
        self.state["proposals"] = recent + [now]
        self.save()
        self.log({"event": "proposed", "session": sid, "plan": plan.get("id"), "hash": phash[:12]})
        self.notify.send_plan(sid, pending)
        return {"ok": True, "hash": phash[:12], "message": "sent to the human for approval"}

    def check(self, sid, tool, tool_input):
        cmd = tool_input.get("command", "") if tool == "Bash" else ""
        if re.match(r"\s*(/usr/local/bin/)?keeper-propose\b", cmd or ""):
            self.state["proposer"] = {"session": str(sid), "at": self.now()}   # the CLI cannot see its session id
        try:
            kind, detail = self.gate.classify(tool, tool_input)
        except Exception as e:                                   # a classifier crash must never let a change through
            self.gate.CHANGES.clear()
            kind, detail = "opaque", f"classifier error {type(e).__name__}"
        if kind in ("read", "talk"):
            return {"decision": "allow", "reason": ""}
        items = [(k, d, st) for k, d, st in self.gate.CHANGES] if tool == "Bash" and self.gate.CHANGES else [(kind, detail, None)]
        s = self.session(sid)
        act = s.get("active")
        if act and act["expires"] < self.now():
            s.pop("active", None)
            act = None
            self.save()
        for k, d, st in items:
            cat = self.gate.category(tool, tool_input, k, d)
            if not (act and self.gate.covers(act["plan"], tool, tool_input, cat, st)):
                self.log({"event": "denied" if self.cfg["mode"] == "block" else "would-deny", "session": sid,
                          "tool": tool, "category": cat, "plan": act["plan"].get("id") if act else None})
                if self.cfg["mode"] != "block":
                    return {"decision": "allow", "reason": ""}
                why = (f"keeper: this is a change ({cat}) and no approved plan covers it. Propose a plan with "
                       "keeper-propose; the human approves it on the keeper bot.")
                if act:
                    why = f"keeper: the approved plan '{act['plan'].get('id')}' does not cover this {cat} action."
                return {"decision": "deny", "reason": why}
        self.log({"event": "allowed", "session": sid, "tool": tool, "plan": act["plan"].get("id")})
        return {"decision": "allow", "reason": ""}

    def status(self, sid):
        s = self.session(sid)
        act = s.get("active")
        if act and act["expires"] > self.now():
            return {"active": act["plan"], "expires_in_min": int((act["expires"] - self.now()) / 60)}
        return {"active": None, "pending": bool(s.get("pending"))}

    # ----- human side (only reached from the bot) ---------------------------------------------------------------
    def decide(self, from_id, chat_id, data):
        """A button press. data = approve:<hash12>:<nonce> | reject:<hash12>:<nonce> | stop:<session>"""
        if str(from_id) != str(self.cfg["owner_id"]) or (self.cfg.get("chat_id") and str(chat_id) != str(self.cfg["chat_id"])):
            self.log({"event": "decision-from-stranger-ignored"})
            return "ignored: not the owner"
        parts = data.split(":")
        if parts[0] == "stop":
            s = self.session(parts[1] if len(parts) > 1 else None)
            had = s.pop("active", None)
            s.pop("pending", None)
            self.save()
            self.log({"event": "revoked"})
            return "stopped" if had else "nothing to stop"
        if len(parts) != 3 or parts[0] not in ("approve", "reject") or not re.fullmatch(r"[0-9a-f]{12}", parts[1]) \
                or not re.fullmatch(r"[0-9a-f]{16}", parts[2]):
            return "ignored: malformed"
        action, h, nonce = parts
        if nonce in self.state["used_nonces"]:
            self.log({"event": "decision-replay-ignored"})
            return "ignored: already used"
        for sid, s in self.state["sessions"].items():
            p = s.get("pending")
            if p and p["hash"][:12] == h and secrets.compare_digest(p["nonce"], nonce):
                self.state["used_nonces"] = (self.state["used_nonces"] + [nonce])[-1000:]
                s.pop("pending", None)
                if action == "reject":
                    self.save()
                    self.log({"event": "rejected", "session": sid})
                    return "rejected"
                if self.now() - p["proposed_at"] > self.cfg["pending_max_age_min"] * 60:
                    self.save()
                    self.log({"event": "approval-of-expired-plan-ignored", "session": sid})
                    return "expired: ask the agent to propose again"
                s["active"] = {"plan": p["plan"], "hash": p["hash"], "approved_at": self.now(),
                               "expires": self.now() + p["plan"]["ttl"] * 60}
                self.save()
                self.log({"event": "approved", "session": sid, "plan": p["plan"].get("id"), "hash": h})
                return f"approved for {p['plan']['ttl']} min"
        self.log({"event": "decision-unknown-plan-ignored"})
        return "ignored: no such pending plan"


# ---------------------------------------------------------------------------------------------------------------
# Telegram: the keeper bot. Only keeperd holds its token, so only keeperd reads its updates.
# ---------------------------------------------------------------------------------------------------------------
class TelegramBot:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = open(cfg["bot_token_file"]).read().strip()
        self.offset = 0

    def api(self, method, payload, timeout=40):
        req = urllib.request.Request(f"https://api.telegram.org/bot{self.token}/{method}",
                                     json.dumps(payload).encode(), {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=timeout))

    def send_plan(self, sid, p):
        plan = p["plan"]
        head = (f"🔐 Approval requested\nPlan: {plan.get('id') or '-'}\nTargets: {', '.join(plan['targets']) or 'any'}\n"
                f"Actions: {', '.join(plan['actions'])}\nDuration: {plan['ttl']} min\nFingerprint: {p['hash'][:12]}\n"
                "Stop ends the plan; it does not stop a process already started.\n———\nThe agent's explanation:\n")
        h = p["hash"][:12]
        kb = {"inline_keyboard": [[{"text": "✅ Approve", "callback_data": f"approve:{h}:{p['nonce']}"},
                                   {"text": "❌ Reject", "callback_data": f"reject:{h}:{p['nonce']}"}],
                                  [{"text": "⏹ Stop everything", "callback_data": f"stop:{sid}"}]]}
        self.api("sendMessage", {"chat_id": self.cfg["chat_id"], "text": (head + p["text"])[:4000], "reply_markup": kb})

    def send(self, text):
        self.api("sendMessage", {"chat_id": self.cfg["chat_id"], "text": text[:4000]})

    def poll(self, keeper):
        while True:
            try:
                r = self.api("getUpdates", {"offset": self.offset, "timeout": 30, "allowed_updates": ["callback_query"]})
                for u in r.get("result", []):
                    self.offset = u["update_id"] + 1
                    cq = u.get("callback_query")
                    if not cq:
                        continue
                    with keeper.lock:
                        out = keeper.decide(cq["from"]["id"], (cq.get("message") or {}).get("chat", {}).get("id"),
                                            cq.get("data", ""))
                    self.api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": out[:180]})
                    msg = cq.get("message") or {}
                    if msg and not out.startswith("ignored"):
                        try:                                            # one decision per message: drop the buttons
                            self.api("editMessageReplyMarkup", {"chat_id": msg["chat"]["id"],
                                                                 "message_id": msg["message_id"], "reply_markup": {}})
                            self.send(f"{out}")
                        except Exception:
                            pass
            except Exception as e:                                  # network hiccup: retry, never crash the daemon
                keeper.log({"event": "telegram-error", "error": type(e).__name__})
                time.sleep(5)


# ---------------------------------------------------------------------------------------------------------------
# Socket: only the agent's user may talk to keeperd, checked by the kernel (peer credentials).
# ---------------------------------------------------------------------------------------------------------------
def peer_uid(conn):
    if sys.platform == "darwin":
        data = conn.getsockopt(0, 0x001, 76)                      # SOL_LOCAL, LOCAL_PEERCRED -> struct xucred
        return struct.unpack_from("II", data)[1]
    data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII"))
    return struct.unpack("iII", data)[1]


def serve(keeper, cfg, ready=None):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                uid = peer_uid(self.connection)
            except OSError:
                uid = None
            line = self.rfile.readline(1_000_000)
            try:
                req = json.loads(line)
            except ValueError:
                return self.reply({"error": "bad request"})
            if uid not in cfg["agent_uids"]:                            # empty list = nobody (fail closed)
                keeper.log({"event": "socket-peer-refused", "uid": uid})
                return self.reply({"decision": "deny", "reason": "keeper: unknown client"})
            with keeper.lock:
                op = req.get("op")
                if op == "check":
                    out = keeper.check(req.get("session"), req.get("tool", ""), req.get("input") or {})
                elif op == "propose":
                    out = keeper.propose(req.get("session"), req.get("text", ""), req.get("scope", ""))
                elif op == "status":
                    out = keeper.status(req.get("session"))
                else:
                    out = {"error": "unknown op"}
            self.reply(out)

        def reply(self, obj):
            self.wfile.write((json.dumps(obj) + "\n").encode())

    path = cfg["socket"]
    if os.path.exists(path):
        os.unlink(path)
    old = os.umask(0o117)
    try:
        srv = socketserver.ThreadingUnixStreamServer(path, Handler)
    finally:
        os.umask(old)
    if cfg.get("client_group"):                                    # the agent's group; _keeper is a member of it
        import grp
        os.chown(path, -1, grp.getgrnam(cfg["client_group"]).gr_gid)
    os.chmod(path, 0o660)
    if ready:
        ready.set()                                                # bound and listening (used by the tests)
    srv.serve_forever()


def load_config(path=None):
    cfg = dict(DEFAULTS)
    p = path or os.environ.get("KEEPER_CONFIG", "/etc/keeper/config.json")
    cfg.update(json.load(open(p)))
    return cfg


def main():
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else None)
    bot = TelegramBot(cfg)
    keeper = Keeper(cfg, bot)
    threading.Thread(target=bot.poll, args=(keeper,), daemon=True).start()
    try:
        bot.send("🔐 keeper started: changes now need your approval here.")
    except Exception:
        keeper.log({"event": "telegram-error-at-start"})
    serve(keeper, cfg)


if __name__ == "__main__":
    main()

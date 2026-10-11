#!/usr/bin/env python3
"""keeperd: holds the human's approvals out of the agent's reach (go-gate step 2). Design: docs/design-keeper.md.

Runs as a dedicated system user (`_keeper`). The agent talks to it over a Unix socket; the human talks to it through a
Telegram bot whose token only this user can read. The agent can propose a plan and ask "is this tool call covered?";
it cannot approve, change or read the approval state.

Requests (one JSON object per line on the socket):
  {"op": "check", "session": s, "tool": "Bash", "input": {...}}   -> {"decision": "allow"|"deny", "reason": …}

The agent proposes a plan by running `keeper-propose --scope "id=… ; targets=… ; actions=… ; ttl=…" --text "why"`.
keeperd sees that command in the hook's check, with the session id Claude Code gave the hook, sends the plan to the
human and refuses the command itself (there is nothing to run). `keeper-status` works the same way. Council review
(08/10): a separate socket op could not know which session proposed.
Sessions are not a security boundary: every session runs as the same agent user. They keep plans apart for clarity.

Standard library only. Python 3.9+.
"""
import hashlib, importlib.util, json, os, re, secrets, shlex, socket, socketserver, struct, sys, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {"socket": "/var/run/keeper/keeper.sock", "state_dir": "/var/lib/keeper", "agent_uids": [],
            "owner_id": None, "chat_id": None, "bot_token_file": "/etc/keeper/bot.token",
            "ttl_default_min": 60, "ttl_max_min": 240, "pending_max_age_min": 120, "max_proposals_per_hour": 3,
            "mode": "block", "agent_home": None, "client_group": None, "safe_git_repos": [], "lang": "en"}


# ---------------------------------------------------------------------------------------------------------------
# What the HUMAN reads on Telegram: one catalogue per language (config key "lang", default "en").
# What the AGENT reads (the deny reasons the hook returns, keeper-status) is not here: it stays English, because it
# is part of the agent contract and of the tests. Callback data (approve:<hash>:<nonce>) is protocol, never translated.
# ---------------------------------------------------------------------------------------------------------------
MESSAGES = {
    "en": {
        "card_head": "🔐 Approval requested",
        "card_plan": "Plan: {id}",
        "card_targets": "Targets: {targets}",
        "card_any": "ANY",
        "card_actions": "Actions: {actions}",
        "card_duration": "Duration: {ttl} min",
        "card_fingerprint": "Fingerprint: {fp}",
        "warn_script": "⚠️ script: the agent may run ANY program during this plan.",
        "warn_delete": "⚠️ delete: the agent may delete files.",
        "warn_no_targets": "⚠️ no targets: the actions apply to everything.",
        "card_stop_note": "Stop ends the plan; it does not stop a process already started.",
        "card_explain": "The agent's explanation:",
        "btn_approve": "✅ Approve",
        "btn_reject": "❌ Reject",
        "btn_stop": "⏹ Stop everything",
        "ans_not_owner": "ignored: not the owner",
        "ans_malformed": "ignored: malformed",
        "ans_replay": "ignored: already used",
        "ans_unknown": "ignored: no such pending plan",
        "ans_stopped": "stopped: no plan is active",
        "ans_nothing_active": "nothing was active; pending plans dropped",
        "ans_rejected": "rejected",
        "ans_expired": "expired: ask the agent to propose again",
        "ans_approved": "approved for {ttl} min",
        "started": "🔐 keeper started: changes now need your approval here.",
    },
    "fr": {
        "card_head": "🔐 Demande d'approbation",
        "card_plan": "Plan : {id}",
        "card_targets": "Cibles : {targets}",
        "card_any": "TOUTES",
        "card_actions": "Actions : {actions}",
        "card_duration": "Durée : {ttl} min",
        "card_fingerprint": "Empreinte : {fp}",
        "warn_script": "⚠️ script : l'agent peut lancer N'IMPORTE QUEL programme pendant ce plan.",
        "warn_delete": "⚠️ delete : l'agent peut supprimer des fichiers.",
        "warn_no_targets": "⚠️ aucune cible : les actions s'appliquent à tout.",
        "card_stop_note": "Arrêter met fin au plan ; cela n'interrompt pas un processus déjà lancé.",
        "card_explain": "Explication de l'agent :",
        "btn_approve": "✅ Approuver",
        "btn_reject": "❌ Refuser",
        "btn_stop": "⏹ Tout arrêter",
        "ans_not_owner": "ignoré : vous n'êtes pas le propriétaire",
        "ans_malformed": "ignoré : demande mal formée",
        "ans_replay": "ignoré : déjà utilisé",
        "ans_unknown": "ignoré : aucun plan en attente ne correspond",
        "ans_stopped": "arrêté : plus aucun plan n'est actif",
        "ans_nothing_active": "rien n'était actif ; les plans en attente sont abandonnés",
        "ans_rejected": "refusé",
        "ans_expired": "expiré : demandez à l'agent de proposer à nouveau",
        "ans_approved": "approuvé pour {ttl} min",
        "started": "🔐 keeper démarré : les modifications demandent maintenant votre approbation ici.",
    },
}
IGNORED = frozenset({"ans_not_owner", "ans_malformed", "ans_replay", "ans_unknown"})   # answers that are not a decision


def norm_lang(lang):
    """A configured language, or English when it is unknown (a typo in the config must not stop the daemon)."""
    lang = str(lang or "en").lower()
    return lang if lang in MESSAGES else "en"


def t(lang, key, **kw):
    """A human message in `lang`. A key missing from that language falls back to English, never to a crash."""
    for table in (MESSAGES.get(norm_lang(lang), {}), MESSAGES["en"]):
        if key in table:
            try:
                return table[key].format(**kw)
            except (KeyError, IndexError, ValueError):
                continue
    return key


class Msg(str):
    """A rendered human message that remembers its catalogue key: the Telegram layer tests the key, not the words
    (which change with the language)."""
    def __new__(cls, text, key):
        obj = str.__new__(cls, text)
        obj.key = key
        return obj


def render_plan_card(lang, p):
    """The approval message and its buttons. The first lines come from the structured scope, never from the agent's
    prose, so prose cannot hide a wide scope; the agent's explanation comes last, labelled as such."""
    plan, h = p["plan"], p["hash"][:12]
    warn = ""
    if "script" in plan["actions"]:
        warn += t(lang, "warn_script") + "\n"
    if "delete" in plan["actions"]:
        warn += t(lang, "warn_delete") + "\n"
    if not plan["targets"]:
        warn += t(lang, "warn_no_targets") + "\n"
    head = "\n".join([t(lang, "card_head"), t(lang, "card_plan", id=plan.get("id") or "-"),
                      t(lang, "card_targets", targets=", ".join(plan["targets"]) or t(lang, "card_any")),
                      t(lang, "card_actions", actions=", ".join(plan["actions"])),
                      t(lang, "card_duration", ttl=plan["ttl"]), t(lang, "card_fingerprint", fp=h)]) + "\n"
    head += warn + t(lang, "card_stop_note") + "\n———\n" + t(lang, "card_explain") + "\n"
    kb = {"inline_keyboard": [[{"text": t(lang, "btn_approve"), "callback_data": f"approve:{h}:{p['nonce']}"},
                               {"text": t(lang, "btn_reject"), "callback_data": f"reject:{h}:{p['nonce']}"}],
                              [{"text": t(lang, "btn_stop"), "callback_data": "stop:all"}]]}
    return (head + p["text"])[:4000], kb


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
        self.lang = norm_lang(cfg.get("lang"))                             # what the human reads; the agent's stays English
        self.gate = load_gate(cfg.get("agent_home"))
        self.gate.SAFE_GIT_REPOS[:] = cfg.get("safe_git_repos") or []      # K6: trusted repos for git read verbs
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
        return {"ok": True, "hash": phash[:12], "message": "sent to the human for approval",
                "_notify": (sid, pending)}                     # sent by the caller, outside the lock

    def keeper_command(self, cmd):
        """`keeper-propose …` or `keeper-status` alone in a Bash call: (name, {option: value}), else None."""
        try:
            stmts, _c, balanced = self.gate.scan(cmd)
            if not balanced or len(stmts) != 1 or len(self.gate.pipeline_stages(stmts[0])) != 1:
                return None
            toks = shlex.split(cmd)
        except (ValueError, TypeError):
            return None
        if not toks or os.path.basename(toks[0]) not in ("keeper-propose", "keeper-status") \
                or os.path.dirname(toks[0]) not in ("", "/opt/agent-guardrails/bin"):
            return None
        opts, i = {}, 1
        while i < len(toks):
            if toks[i] in ("--scope", "--text") and i + 1 < len(toks):
                opts[toks[i][2:]] = toks[i + 1]
                i += 2
            else:
                return None
        return os.path.basename(toks[0]), opts

    def check(self, sid, tool, tool_input, cwd=None):
        self.gate.CWD = cwd                                            # the dir the agent ran the tool in (K6)
        kc = self.keeper_command(tool_input.get("command", "")) if tool == "Bash" else None
        if kc and kc[0] == "keeper-status":
            return {"decision": "deny", "reason": "keeper status (nothing was run): " + json.dumps(self.status(sid))}
        if kc:
            out = self.propose(sid, kc[1].get("text", ""), kc[1].get("scope", ""))
            why = (f"keeper: plan sent to the human for approval (fingerprint {out['hash']}). Nothing was run. Wait for "
                   "their decision, then retry the actions." if out["ok"] else f"keeper: proposal refused: {out['reason']}")
            res = {"decision": "deny", "reason": why}
            if out.get("_notify"):
                res["_notify"] = out["_notify"]
            return res
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
    def msg(self, key, **kw):
        """A human message in the configured language, tagged with its key."""
        return Msg(t(self.lang, key, **kw), key)

    def decide(self, from_id, chat_id, data):
        """A button press. data = approve:<hash12>:<nonce> | reject:<hash12>:<nonce> | stop:<session>"""
        if str(from_id) != str(self.cfg["owner_id"]) or (self.cfg.get("chat_id") and str(chat_id) != str(self.cfg["chat_id"])):
            self.log({"event": "decision-from-stranger-ignored"})
            return self.msg("ans_not_owner")
        parts = data.split(":")
        if parts[0] == "stop":                                  # every plan of every session (council review 08/10)
            had = False
            for s in self.state["sessions"].values():
                had = bool(s.pop("active", None)) or had
                s.pop("pending", None)
            self.save()
            self.log({"event": "revoked-all"})
            return self.msg("ans_stopped") if had else self.msg("ans_nothing_active")
        if len(parts) != 3 or parts[0] not in ("approve", "reject") or not re.fullmatch(r"[0-9a-f]{12}", parts[1]) \
                or not re.fullmatch(r"[0-9a-f]{16}", parts[2]):
            return self.msg("ans_malformed")
        action, h, nonce = parts
        if nonce in self.state["used_nonces"]:
            self.log({"event": "decision-replay-ignored"})
            return self.msg("ans_replay")
        for sid, s in self.state["sessions"].items():
            p = s.get("pending")
            if p and p["hash"][:12] == h and secrets.compare_digest(p["nonce"], nonce):
                self.state["used_nonces"] = (self.state["used_nonces"] + [nonce])[-1000:]
                s.pop("pending", None)
                if action == "reject":
                    self.save()
                    self.log({"event": "rejected", "session": sid})
                    return self.msg("ans_rejected")
                if self.now() - p["proposed_at"] > self.cfg["pending_max_age_min"] * 60:
                    self.save()
                    self.log({"event": "approval-of-expired-plan-ignored", "session": sid})
                    return self.msg("ans_expired")
                s["active"] = {"plan": p["plan"], "hash": p["hash"], "approved_at": self.now(),
                               "expires": self.now() + p["plan"]["ttl"] * 60}
                self.save()
                self.log({"event": "approved", "session": sid, "plan": p["plan"].get("id"), "hash": h})
                return self.msg("ans_approved", ttl=p["plan"]["ttl"])
        self.log({"event": "decision-unknown-plan-ignored"})
        return self.msg("ans_unknown")


# ---------------------------------------------------------------------------------------------------------------
# Telegram: the keeper bot. Only keeperd holds its token, so only keeperd reads its updates.
# ---------------------------------------------------------------------------------------------------------------
class TelegramBot:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lang = norm_lang(cfg.get("lang"))
        self.token = open(cfg["bot_token_file"]).read().strip()
        self.offset = 0

    def api(self, method, payload, timeout=40):
        req = urllib.request.Request(f"https://api.telegram.org/bot{self.token}/{method}",
                                     json.dumps(payload).encode(), {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=timeout))

    def send_plan(self, sid, p):
        text, kb = render_plan_card(self.lang, p)
        self.api("sendMessage", {"chat_id": self.cfg["chat_id"], "text": text, "reply_markup": kb})

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
                    if msg and out.key not in IGNORED:
                        try:                                            # one decision per message: drop the buttons
                            self.api("editMessageReplyMarkup", {"chat_id": msg["chat"]["id"],
                                                                 "message_id": msg["message_id"], "reply_markup": {}})
                        except Exception:
                            pass
                        try:
                            self.send(out)
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
            self.connection.settimeout(10)                             # a silent client cannot hold a thread
            try:
                uid = peer_uid(self.connection)
            except OSError:
                uid = None
            try:
                line = self.rfile.readline(1_000_000)
                req = json.loads(line)
                if not isinstance(req, dict):
                    raise ValueError
            except (ValueError, OSError):
                return self.reply({"error": "bad request"})
            if uid not in cfg["agent_uids"]:                            # empty list = nobody (fail closed)
                keeper.log({"event": "socket-peer-refused", "uid": uid})
                return self.reply({"decision": "deny", "reason": "keeper: unknown client"})
            if req.get("op") != "check" or not isinstance(req.get("input") or {}, dict):
                return self.reply({"error": "unknown op"})
            with keeper.lock:
                out = keeper.check(req.get("session"), str(req.get("tool", "")), req.get("input") or {},
                                   req.get("cwd"))
            note = out.pop("_notify", None)
            self.reply(out)
            if note:
                try:
                    keeper.notify.send_plan(*note)
                except Exception as e:
                    keeper.log({"event": "telegram-error", "error": type(e).__name__})

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
        bot.send(t(keeper.lang, "started"))
    except Exception:
        keeper.log({"event": "telegram-error-at-start"})
    serve(keeper, cfg)


if __name__ == "__main__":
    main()

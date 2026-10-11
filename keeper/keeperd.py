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
import collections, datetime, hashlib, importlib.util, json, os, re, secrets, shlex, socket, socketserver, struct, sys, threading, time, urllib.request

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
        "start_block": "🔐 keeper started: changes now need your approval here.",
        "start_observe": "🔐 keeper started in observe mode: nothing is blocked, events are only logged. "
                         "Send /summary to see what would have been refused.",
        "sum_title": "📊 Keeper summary: last {days} day(s), mode {mode}",
        "sum_empty": "No event in this window.",
        "sum_unreadable": "The log cannot be read.",
        "sum_counts": "Would-deny: {would} | Denied: {denied} | Allowed under an approved plan: {allowed}",
        "sum_by_tool": "By tool: {items}",
        "sum_by_category": "By category: {items}",
        "sum_more": "+{n} more",
        "sum_shapes_head": "Most frequent shapes (would-deny and denied):",
        "sum_shapes_none": "No shape recorded yet.",
        "sum_shapes_unlogged": "{n} event(s) have no recorded shape (logged before this version, or not a known shape).",
        "sum_plans": "Plans: proposed {proposed}, approved {approved}, rejected {rejected}, expired {expired}",
        "sum_errors": "Telegram errors: {n}",
        "sum_ignored": "Ignored: unknown socket peers {socket}, strangers on Telegram {strangers}, proposal floods {floods}",
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
        "start_block": "🔐 keeper démarré : les modifications demandent maintenant votre approbation ici.",
        "start_observe": "🔐 keeper démarré en mode observation : rien n'est bloqué, les événements sont seulement "
                         "journalisés. Envoyez /summary (ou /resume) pour voir ce qui aurait été refusé.",
        "sum_title": "📊 Résumé du keeper : {days} dernier(s) jour(s), mode {mode}",
        "sum_empty": "Aucun événement sur cette période.",
        "sum_unreadable": "Le journal est illisible.",
        "sum_counts": "Refus simulés : {would} | Refus : {denied} | Autorisés par un plan approuvé : {allowed}",
        "sum_by_tool": "Par outil : {items}",
        "sum_by_category": "Par catégorie : {items}",
        "sum_more": "+{n} autres",
        "sum_shapes_head": "Formes les plus fréquentes (refus simulés et refus) :",
        "sum_shapes_none": "Aucune forme enregistrée pour l'instant.",
        "sum_shapes_unlogged": "{n} événement(s) sans forme enregistrée (journalisés avant cette version, ou forme inconnue).",
        "sum_plans": "Plans : {proposed} proposé(s), {approved} approuvé(s), {rejected} refusé(s), {expired} expiré(s)",
        "sum_errors": "Erreurs Telegram : {n}",
        "sum_ignored": "Ignorés : clients de socket inconnus {socket}, inconnus sur Telegram {strangers}, rafales de propositions {floods}",
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


def startup_message(lang, mode):
    """What the human reads when the daemon starts. Anything but "block" is observe, as in Keeper.check(): there nothing
    is refused, so "changes now need your approval" would be a false promise."""
    return t(lang, "start_block" if mode == "block" else "start_observe")


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
# The log summary (`/summary` on Telegram). It goes to the human only: the log is private to this user, and the agent
# must never read it, so no socket op returns any of this. Three layers keep secrets out of what leaves the machine:
#   1. the log never holds arguments: a denied call is logged as a "shape" (first word + category), see command_shape;
#   2. the summary only prints values it has re-validated (tool names, categories, shapes match a strict format);
#   3. the whole text goes through mask_text before it is sent.
# ---------------------------------------------------------------------------------------------------------------
SUMMARY_DAYS_DEFAULT, SUMMARY_DAYS_MAX = 7, 30
TOP_SHAPES, TOP_GROUPS = 10, 10
TELEGRAM_CHUNK = 3900                 # Telegram refuses 4096+; keep a margin
LOG_TAIL_MAX = 32 * 1024 * 1024       # read at most this much of the end of the log (it is append-only and unrotated)
SHAPE_FORMAT = re.compile(r"(?:[A-Za-z0-9_.+:-]{1,40}|<…>) … \[[a-z_]{1,16}\]")
IDENT_FORMAT = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

# Patterns taken from secret-guard (LITERAL_SECRET, the `mask` filter) and go-gate's redact(), kept here so the daemon
# stays standard-library only and does not depend on a hook's file layout. Over-masking is the right failure mode.
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), "<m>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*){0,2}"), "<m>"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<m>"),
    (re.compile(r"\b(?:sk-(?:ant-|proj-)?|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xox[abpr]-|hf_|cfut_|tskey-)[A-Za-z0-9_-]{8,}"), "<m>"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}"), "<m>"),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"), "<m>"),                                   # Telegram bot token
    (re.compile(r"://[^/@\s:]+:[^/@\s]+@"), "://<m>@"),                                         # user:password@host
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?\S+"), r"\1<m>"),
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <m>"),
    (re.compile(r"(?i)(--?(?:token|key|password|passwd|secret|api-?key|auth-token)[= ]+)[\"']?[^\s\"']+"), r"\1<m>"),
    (re.compile(r"(?i)\b([A-Za-z0-9_.-]*(?:key|token|secret|passw(?:or)?d|pwd|passphrase|cookie|credential|auth)"
                r"[A-Za-z0-9_.-]*\s*[:=]\s*)[\"']?[^\s,\"'}\]]+"), r"\1<m>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<m>"),                                               # long hex: hash, key, id
    (re.compile(r"\b(?=[A-Za-z0-9+/_=-]*\d)(?=[A-Za-z0-9+/_=-]*[A-Za-z])[A-Za-z0-9+/_=-]{24,}"), "<m>"),   # long opaque value
]


def mask_text(text):
    """Replace anything secret-shaped by <m>. Applied to everything the summary sends; also used on the logged shape."""
    text = str(text)
    for rx, repl in _SECRET_PATTERNS:
        text = rx.sub(repl, text)
    return text


def command_shape(tool, stage, cat):
    """What the log keeps of a denied call: its first word and its category, arguments replaced by … (never stored)."""
    first = tool
    if tool == "Bash" and stage:
        words = [w.lstrip("({!") for w in stage.split() if not re.fullmatch(r"[A-Za-z_]\w*=\S*", w)]   # skip VAR=value
        words = [w for w in words if w]
        first = os.path.basename(words[0]) if words else "Bash"
    if not re.fullmatch(r"[A-Za-z0-9_.+:-]{1,40}", first or "") or mask_text(first) != first:
        first = "<…>"                                          # not a plain word (or secret-shaped): say nothing of it
    cat = str(cat) if re.fullmatch(r"[a-z_]{1,16}", str(cat)) else "other"
    return f"{first} … [{cat}]"[:80]


def split_message(text, limit=TELEGRAM_CHUNK):
    """Cut a long text into messages of at most `limit` characters, on line breaks when possible."""
    chunks, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:                               # a single line longer than a message: hard cut
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(line[:limit])
            line = line[limit:]
        if cur and len(cur) + 1 + len(line) > limit:
            chunks.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        chunks.append(cur)
    return chunks or [""]


def event_time(rec):
    """Epoch seconds of a log record (its `at` field), or None."""
    try:
        return datetime.datetime.strptime(rec["at"], "%Y-%m-%dT%H:%M:%S%z").timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def tally(path, since):
    """Count the events of the log at or after `since` (epoch). Streams the file, reads at most LOG_TAIL_MAX of its end
    and skips lines it cannot parse. A missing log gives empty counts; other OSErrors propagate."""
    st = {"events": 0, "would": 0, "denied": 0, "allowed": 0, "no_shape": 0, "proposed": 0, "approved": 0,
          "rejected": 0, "expired": 0, "tg_errors": 0, "socket": 0, "strangers": 0, "floods": 0,
          "tools": collections.Counter(), "cats": collections.Counter(), "shapes": collections.Counter()}
    single = {"proposed": "proposed", "approved": "approved", "rejected": "rejected",
              "approval-of-expired-plan-ignored": "expired", "telegram-error": "tg_errors",
              "telegram-error-at-start": "tg_errors", "socket-peer-refused": "socket", "proposal-refused-flood": "floods",
              "decision-from-stranger-ignored": "strangers", "command-from-stranger-ignored": "strangers"}
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return st                                              # a fresh install has no log yet: an empty summary
    with f:
        size = f.seek(0, os.SEEK_END)
        start = max(0, size - LOG_TAIL_MAX)
        f.seek(start)
        if start:
            f.readline()                                       # drop the partial line we landed in
        for raw in f:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            ts = event_time(rec) if isinstance(rec, dict) else None
            if ts is None or ts < since:
                continue
            ev = rec.get("event")
            if ev in ("would-deny", "denied", "allowed") or ev in single:
                st["events"] += 1                              # unknown events (e.g. summary-sent) are not counted
            if ev in ("would-deny", "denied"):
                st["would" if ev == "would-deny" else "denied"] += 1
                tool, cat, shape = rec.get("tool"), rec.get("category"), rec.get("shape")
                st["tools"][tool if isinstance(tool, str) and IDENT_FORMAT.fullmatch(tool) else "<other>"] += 1
                st["cats"][cat if isinstance(cat, str) and IDENT_FORMAT.fullmatch(cat) else "<other>"] += 1
                if isinstance(shape, str) and SHAPE_FORMAT.fullmatch(shape):
                    st["shapes"][shape] += 1
                else:
                    st["no_shape"] += 1
            elif ev == "allowed":
                st["allowed"] += 1
            elif ev in single:
                st[single[ev]] += 1
    return st


def render_summary(lang, st, days, mode):
    """The text of the summary, from the counts of tally(). Layout and wording come from the catalogue."""
    lines = [t(lang, "sum_title", days=days, mode=mode)]
    if not st["events"]:
        return "\n".join(lines + [t(lang, "sum_empty")])
    lines.append(t(lang, "sum_counts", would=st["would"], denied=st["denied"], allowed=st["allowed"]))

    def group(counter, key):
        top = counter.most_common(TOP_GROUPS)
        items = ", ".join(f"{name} {n}" for name, n in top)
        if len(counter) > len(top):
            items += ", " + t(lang, "sum_more", n=len(counter) - len(top))
        lines.append(t(lang, key, items=items))
    if st["tools"]:
        group(st["tools"], "sum_by_tool")
        group(st["cats"], "sum_by_category")
    lines.append(t(lang, "sum_shapes_head"))
    if st["shapes"]:
        lines += [f"{i}. {n}× {shape}" for i, (shape, n) in enumerate(st["shapes"].most_common(TOP_SHAPES), 1)]
    else:
        lines.append(t(lang, "sum_shapes_none"))
    if st["no_shape"]:
        lines.append(t(lang, "sum_shapes_unlogged", n=st["no_shape"]))
    lines.append(t(lang, "sum_plans", proposed=st["proposed"], approved=st["approved"], rejected=st["rejected"],
                   expired=st["expired"]))
    lines.append(t(lang, "sum_errors", n=st["tg_errors"]))
    lines.append(t(lang, "sum_ignored", socket=st["socket"], strangers=st["strangers"], floods=st["floods"]))
    return "\n".join(lines)


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
        rec["at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.now()))
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
                          "tool": tool, "category": cat, "shape": command_shape(tool, st, cat),
                          "plan": act["plan"].get("id") if act else None})
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
    def is_owner(self, from_id, chat_id):
        """The owner, in the configured chat: the same test as decide() applies to buttons. A missing id or an unset
        owner never matches (a message without a sender must not look like an unconfigured owner)."""
        if from_id is None or self.cfg.get("owner_id") is None:
            return False
        if str(from_id) != str(self.cfg["owner_id"]):
            return False
        return not self.cfg.get("chat_id") or str(chat_id) == str(self.cfg["chat_id"])

    def command(self, from_id, chat_id, text):
        """A text message sent to the bot. Only `/summary [days]` (alias `/resume`) from the owner is acted on; any
        other text is ignored. Returns the messages to send back, or None. Not reachable from the socket."""
        if not isinstance(text, str):
            return None
        if not self.is_owner(from_id, chat_id):
            if text.startswith("/"):                          # a command attempt; the text itself is never logged
                self.log({"event": "command-from-stranger-ignored"})
            return None
        m = re.fullmatch(r"/(?:summary|resume)(?:@\w+)?(?:\s+(\d{1,2}))?", text.strip(), re.I)
        if not m:
            return None
        days = min(max(int(m.group(1) or SUMMARY_DAYS_DEFAULT), 1), SUMMARY_DAYS_MAX)
        # No lock: reading the log must never make the hook wait for it. The log is append-only.
        out = self.summary(days)
        try:
            self.log({"event": "summary-sent", "days": days})
        except OSError:                                       # the audit line is not worth losing the reply for
            pass
        return out

    def summary(self, days=SUMMARY_DAYS_DEFAULT):
        """The log summary as a list of messages, masked and cut below the Telegram limit."""
        try:
            text = render_summary(self.lang, tally(self.log_path, self.now() - days * 86400), days, self.cfg["mode"])
        except OSError:
            text = t(self.lang, "sum_unreadable")
        return split_message(mask_text(text))

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
        with open(cfg["bot_token_file"]) as f:
            self.token = f.read().strip()
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

    def fetch_updates(self):
        """One long poll. `message` is asked for so the owner can send `/summary`; keeper.command() acts on nothing else."""
        r = self.api("getUpdates", {"offset": self.offset, "timeout": 30, "allowed_updates": ["callback_query", "message"]})
        return r.get("result", [])

    def handle_update(self, keeper, u):
        self.offset = u["update_id"] + 1
        cq = u.get("callback_query")
        if not cq:
            self.handle_message(keeper, u.get("message"))
            return
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

    def handle_message(self, keeper, m):
        """A text message. keeper.command() answers only the owner's `/summary`; the reply goes to the configured chat."""
        if not isinstance(m, dict):
            return
        replies = keeper.command((m.get("from") or {}).get("id"), (m.get("chat") or {}).get("id"), m.get("text"))
        for text in replies or []:
            self.send(text)

    def poll(self, keeper):
        while True:
            try:
                for u in self.fetch_updates():
                    self.handle_update(keeper, u)
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
    with open(p) as f:
        cfg.update(json.load(f))
    return cfg


def summary_cli(args):
    """`keeper-summary [days]`, run by root on the keeper's machine: the same masked summary as /summary, printed locally.
    Refused to anyone else: the log is private to the keeper user and must never be readable by the agent. Do not run it
    inside an agent session either: its output would then be in front of the agent."""
    if os.geteuid() != 0:
        print("keeper-summary: run it as root (sudo keeper-summary [days])", file=sys.stderr)
        return 2
    if len(args) > 1 or (args and not re.fullmatch(r"\d{1,2}", args[0])):
        print("usage: keeper-summary [days 1-30]", file=sys.stderr)
        return 2
    days = min(max(int(args[0]) if args else SUMMARY_DAYS_DEFAULT, 1), SUMMARY_DAYS_MAX)
    cfg = load_config()
    try:
        st = tally(os.path.join(cfg["state_dir"], "log.jsonl"), time.time() - days * 86400)
    except OSError as e:
        print(f"keeper-summary: cannot read the log ({type(e).__name__})", file=sys.stderr)
        return 1
    print(mask_text(render_summary(norm_lang(cfg.get("lang")), st, days, cfg["mode"])))
    return 0


def main():
    if sys.argv[1:2] == ["--summary"]:
        sys.exit(summary_cli(sys.argv[2:]))
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else None)
    bot = TelegramBot(cfg)
    keeper = Keeper(cfg, bot)
    threading.Thread(target=bot.poll, args=(keeper,), daemon=True).start()
    try:
        bot.send(startup_message(keeper.lang, cfg["mode"]))
    except Exception:
        keeper.log({"event": "telegram-error-at-start"})
    serve(keeper, cfg)


if __name__ == "__main__":
    main()

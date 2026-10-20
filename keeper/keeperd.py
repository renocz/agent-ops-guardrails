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
import collections, contextlib, datetime, hashlib, importlib.util, json, os, re, secrets, shlex, socket, socketserver, struct, sys, \
    threading, time, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {"socket": "/var/run/keeper/keeper.sock", "state_dir": "/var/lib/keeper", "agent_uids": [],
            "owner_id": None, "chat_id": None, "bot_token_file": "/etc/keeper/bot.token",
            "ttl_default_min": 60, "ttl_max_min": 240, "pending_max_age_min": 120, "max_proposals_per_hour": 3,
            "mode": "block", "agent_home": None, "client_group": None, "safe_git_repos": [], "lang": "en",
            "wait_max_sec": 50, "hook_timeout_sec": 60, "max_active_plans": 3}
MAX_ACTIVE_PLANS_HARD_CAP = 5          # a config typo (or an attempt from a writable config) cannot go past this
# keeper-propose --wait blocks the PreToolUse hook process. Claude Code kills a command hook at its "timeout" and, on
# PreToolUse, a timed-out hook does NOT block the tool call (it falls through to the normal permission flow), so the
# wait must always end first: wait_max_sec + this margin (one in-flight status poll, process start-up) <= hook_timeout_sec.
HOOK_TIMEOUT_MARGIN_SEC = 10


def effective_wait_max(cfg):
    """The longest --wait the hook may be asked to do: wait_max_sec, clamped under the hook's own timeout."""
    return max(0, min(int(cfg["wait_max_sec"]), int(cfg["hook_timeout_sec"]) - HOOK_TIMEOUT_MARGIN_SEC))


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
        "card_adds_to": "Adds to the active plans: {ids}",
        "card_replaces": "Renews (same id): {id}",
        "card_replaces_cap": "⚠️ {limit} plans are already active: approving this drops the oldest, {id}.",
        "warn_script": "⚠️ script: the agent may run ANY program during this plan.",
        "warn_delete": "⚠️ delete: the agent may delete files.",
        "warn_no_targets": "⚠️ no targets: the actions apply to everything.",
        "warn_dir_prefix": "⚠️ {dirs}: covers everything under that directory, not just one path.",
        "card_context": "Requested after a refusal: the active plan does not cover {gap}.",
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
        "ans_approved_evicted": "approved for {ttl} min (the oldest active plan, {evicted}, was dropped: the limit was reached)",
        "ans_stopped_one": "stopped: plan {id}",
        "ans_nothing_active_one": "nothing was active for plan {id}",
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
        "sum_polls_cut": "  Idle polls cut off (retried, nothing lost): {n}",
        "sum_ignored": "Ignored: unknown socket peers {socket}, strangers on Telegram {strangers}, proposal floods {floods}",
        "status_title": "📋 Keeper status (mode: {mode})",
        "status_active_line": "• session {session}: plan {id} — actions: {actions}; targets: {targets}; {left} min left",
        "status_no_active": "No plan is active right now.",
        "status_pending": "Pending proposals: {n} (ids: {ids})",
        "status_no_pending": "No pending proposal.",
        "status_hourly": "Proposals in the last hour: {n}/{limit}",
        "plans_title": "📜 Last plan events",
        "plans_empty": "No plan event recorded yet.",
        "plans_line": "{at} — {id}: {outcome}",
        "plans_outcome_proposed": "proposed",
        "plans_outcome_approved": "approved",
        "plans_outcome_rejected": "rejected",
        "plans_outcome_expired": "expired",
        "plans_outcome_revoked": "revoked (stop)",
        "help_title": "Commands:",
        "help_stop": "/stop [id] — revoke every active and pending plan right now, or just the one named plan",
        "help_status": "/status — mode, active/pending plans, proposals left this hour",
        "help_plans": "/plans [n] — last n plan events (default 5, max 20)",
        "help_summary": "/summary [days] — log summary of would-deny/denied/allowed (alias /resume)",
        "help_help": "/help — this list",
        "cmd_desc_stop": "revoke every active and pending plan",
        "cmd_desc_status": "mode, active/pending plans, proposals left this hour",
        "cmd_desc_plans": "last plan events (proposed/approved/rejected/expired/revoked)",
        "cmd_desc_summary": "log summary over a number of days",
        "cmd_desc_help": "list the available commands",
    },
    "fr": {
        "card_head": "🔐 Demande d'approbation",
        "card_plan": "Plan : {id}",
        "card_targets": "Cibles : {targets}",
        "card_any": "TOUTES",
        "card_actions": "Actions : {actions}",
        "card_duration": "Durée : {ttl} min",
        "card_fingerprint": "Empreinte : {fp}",
        "card_adds_to": "S'ajoute aux plans actifs : {ids}",
        "card_replaces": "Renouvelle (même identifiant) : {id}",
        "card_replaces_cap": "⚠️ {limit} plans sont déjà actifs : approuver ceci abandonne le plus ancien, {id}.",
        "warn_script": "⚠️ script : l'agent peut lancer N'IMPORTE QUEL programme pendant ce plan.",
        "warn_delete": "⚠️ delete : l'agent peut supprimer des fichiers.",
        "warn_no_targets": "⚠️ aucune cible : les actions s'appliquent à tout.",
        "warn_dir_prefix": "⚠️ {dirs} : couvre tout le contenu de ce répertoire, pas un seul chemin.",
        "card_context": "Demandé après un refus : le plan actif ne couvre pas {gap}.",
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
        "ans_approved_evicted": "approuvé pour {ttl} min (le plan actif le plus ancien, {evicted}, a été abandonné : la limite était atteinte)",
        "ans_stopped_one": "arrêté : plan {id}",
        "ans_nothing_active_one": "rien n'était actif pour le plan {id}",
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
        "sum_polls_cut": "  Sondages inactifs coupés (relancés, rien de perdu) : {n}",
        "sum_ignored": "Ignorés : clients de socket inconnus {socket}, inconnus sur Telegram {strangers}, rafales de propositions {floods}",
        "status_title": "📋 État du keeper (mode : {mode})",
        "status_active_line": "• session {session} : plan {id} — actions : {actions} ; cibles : {targets} ; {left} min restantes",
        "status_no_active": "Aucun plan actif pour le moment.",
        "status_pending": "Propositions en attente : {n} (identifiants : {ids})",
        "status_no_pending": "Aucune proposition en attente.",
        "status_hourly": "Propositions dans la dernière heure : {n}/{limit}",
        "plans_title": "📜 Derniers événements de plan",
        "plans_empty": "Aucun événement de plan enregistré pour l'instant.",
        "plans_line": "{at} — {id} : {outcome}",
        "plans_outcome_proposed": "proposé",
        "plans_outcome_approved": "approuvé",
        "plans_outcome_rejected": "refusé",
        "plans_outcome_expired": "expiré",
        "plans_outcome_revoked": "révoqué (stop)",
        "help_title": "Commandes :",
        "help_stop": "/stop [id] — révoque immédiatement tout plan actif et toute proposition en attente, ou seulement le plan nommé",
        "help_status": "/status — mode, plans actifs/en attente, propositions restantes cette heure",
        "help_plans": "/plans [n] — les n derniers événements de plan (5 par défaut, 20 au maximum)",
        "help_summary": "/summary [jours] — résumé du journal des refus/autorisations (alias /resume)",
        "help_help": "/help — cette liste",
        "cmd_desc_stop": "révoquer tout plan actif et en attente",
        "cmd_desc_status": "mode, plans actifs/en attente, propositions restantes cette heure",
        "cmd_desc_plans": "derniers événements de plan (proposé/approuvé/refusé/expiré/révoqué)",
        "cmd_desc_summary": "résumé du journal sur un nombre de jours",
        "cmd_desc_help": "lister les commandes disponibles",
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
    # Multiple active plans (requirement 6): say, BEFORE approval, what approving this one will do to the plans
    # already active in this session -- never silently. "first" (no active plan yet) adds nothing, so a session's
    # first card is unchanged (and test_plan_card_in_english_is_unchanged pins that exact text).
    preview = p.get("preview") or {}
    pk = preview.get("kind")
    if pk == "renew":
        warn += t(lang, "card_replaces", id=preview["id"]) + "\n"
    elif pk == "evict":
        warn += t(lang, "card_replaces_cap", id=preview["id"], limit=preview.get("limit", "")) + "\n"
    elif pk == "add":
        warn += t(lang, "card_adds_to", ids=", ".join(preview.get("ids") or [])) + "\n"
    if "script" in plan["actions"]:
        warn += t(lang, "warn_script") + "\n"
    if "delete" in plan["actions"]:
        warn += t(lang, "warn_delete") + "\n"
    if not plan["targets"]:
        warn += t(lang, "warn_no_targets") + "\n"
    dirs = [tg for tg in plan["targets"] if tg.lower().startswith("dir:")]
    if dirs:                                             # K-dir: a subtree grant must be visible, never silent
        warn += t(lang, "warn_dir_prefix", dirs=", ".join(dirs)) + "\n"
    head = "\n".join([t(lang, "card_head"), t(lang, "card_plan", id=plan.get("id") or "-"),
                      t(lang, "card_targets", targets=", ".join(plan["targets"]) or t(lang, "card_any")),
                      t(lang, "card_actions", actions=", ".join(plan["actions"])),
                      t(lang, "card_duration", ttl=plan["ttl"]), t(lang, "card_fingerprint", fp=h)]) + "\n"
    head += warn
    if p.get("context"):                                 # this proposal follows a refusal (item 2): say what of it
        head += t(lang, "card_context", gap=p["context"]) + "\n"
    head += t(lang, "card_stop_note") + "\n———\n" + t(lang, "card_explain") + "\n"
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
#   1. the log never holds arguments: a denied call is logged as a "shape" (first word, the subcommand of a known
#      CLI, and the category), see command_shape;
#   2. the summary only prints values it has re-validated (tool names, categories, shapes match a strict format);
#   3. the whole text goes through mask_text before it is sent.
# ---------------------------------------------------------------------------------------------------------------
SUMMARY_DAYS_DEFAULT, SUMMARY_DAYS_MAX = 7, 30
PLANS_DEFAULT, PLANS_MAX = 5, 20
TOP_SHAPES, TOP_GROUPS = 10, 10
TELEGRAM_CHUNK = 3900                 # Telegram refuses 4096+; keep a margin
LOG_TAIL_MAX = 32 * 1024 * 1024       # read at most this much of the end of the log (it is append-only and unrotated)
SHAPE_FORMAT = re.compile(r"(?:[A-Za-z0-9_.+:-]{1,40}(?: [a-z][a-z0-9-]{0,24}){0,2}|<…>) … \[[a-z_]{1,16}\]")
# For these CLIs the first word says little ("docker … [deploy]" may be a routine restart or a rebuild): the subcommand
# is kept too, when it is a plain lowercase word. Options are skipped; those listed take a value, which is skipped as well.
SUBCOMMAND_CLIS = {"docker": {"-H", "--host", "--context", "-c", "--config", "--log-level",
                              "-f", "--file", "-p", "--project-name", "--env-file", "--profile"},  # compose options too
                   "git": {"-C", "-c", "--git-dir", "--work-tree", "--namespace"},
                   "kubectl": {"-n", "--namespace", "--context", "--kubeconfig", "-s", "--server"},
                   "systemctl": {"-H", "--host", "-M", "--machine"}, "launchctl": set(), "brew": set(),
                   "apt": {"-o", "-t"}, "apt-get": {"-o", "-t"}, "npm": set(), "pip": set(), "pip3": set(),
                   "gh": {"-R", "--repo"}, "pct": set(), "qm": set(), "zfs": set(), "zpool": set(),
                   "terraform": {"-chdir"}, "helm": {"-n", "--namespace"}}
GROUP_SUBCOMMANDS = {"docker": {"compose", "container", "image", "network", "volume", "system", "buildx", "builder"},
                     "gh": {"pr", "repo", "release", "issue", "workflow", "run", "secret"}, "kubectl": {"rollout", "config"}}
PLAIN_SUBCOMMAND = re.compile(r"[a-z][a-z0-9-]{0,24}")
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
    # {0,40}, not *: unbounded repeats on both sides of the keyword made this quadratic on a long run of word characters
    (re.compile(r"(?i)\b([A-Za-z0-9_.-]{0,40}(?:key|token|secret|passw(?:or)?d|pwd|passphrase|cookie|credential|auth)"
                r"[A-Za-z0-9_.-]{0,40}\s{0,8}[:=]\s{0,8})[\"']?[^\s,\"'}\]]+"), r"\1<m>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<m>"),                                               # long hex: hash, key, id
    # a long opaque value: 24+ characters mixing letters and digits. The candidate is matched in one linear pass and then
    # checked, instead of two lookaheads that rescan the rest of the run from every position (quadratic).
    (re.compile(r"\b[A-Za-z0-9+/_=-]{24,}"),
     lambda m: "<m>" if re.search(r"\d", m.group()) and re.search(r"[A-Za-z]", m.group()) else m.group()),
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
    elif tool == "Bash" and first in SUBCOMMAND_CLIS:
        first = " ".join([first] + subcommands(first, words[1:]))
    cat = str(cat) if re.fullmatch(r"[a-z_]{1,16}", str(cat)) else "other"
    return f"{first} … [{cat}]"[:80]


def subcommands(cli, args):
    """The subcommand of a known CLI (two levels for groups like `docker compose up`), plain lowercase words only and
    masked like the rest; anything else ends the shape, so a value or a path is never kept."""
    out, takes_value, skip = [], SUBCOMMAND_CLIS[cli], False
    for w in args:
        if skip:
            skip = False
            continue
        if w.startswith("-"):
            skip = "=" not in w and w in takes_value
            continue
        if not PLAIN_SUBCOMMAND.fullmatch(w) or mask_text(w) != w:
            break
        out.append(w)
        if len(out) == 2 or out[0] not in GROUP_SUBCOMMANDS.get(cli, ()):
            break
    return out


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
          "rejected": 0, "expired": 0, "tg_errors": 0, "tg_polls_cut": 0, "socket": 0, "strangers": 0, "floods": 0,
          "slow": 0, "worst_lag_s": 0.0,                        # 13/10 timing work: kept simple on purpose
          "tools": collections.Counter(), "cats": collections.Counter(), "shapes": collections.Counter(),
          "tg_types": collections.Counter()}
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
            if ev == "telegram-poll-timeout":                  # an idle long poll cut off: not an error, not an event
                st["tg_polls_cut"] += 1
                continue
            if ev == "telegram-update":                        # 13/10: where a delay sits, not a would-deny/denied event
                lag = rec.get("lag_s")
                handled = rec.get("handled_s")
                if isinstance(lag, (int, float)):
                    st["worst_lag_s"] = max(st["worst_lag_s"], lag)
                if (isinstance(lag, (int, float)) and lag > UPDATE_SLOW_LOG_THRESHOLD) or \
                        (isinstance(handled, (int, float)) and handled > UPDATE_SLOW_LOG_THRESHOLD):
                    st["slow"] += 1
                continue
            if ev in ("telegram-api-slow", "keeper-lock-wait"):  # already only logged past their own threshold
                st["slow"] += 1
                continue
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
                if ev.startswith("telegram-error"):            # the exception class name: a network outage, a bad token…
                    err = rec.get("error") if ev == "telegram-error" else "at-start"
                    st["tg_types"][err if isinstance(err, str) and IDENT_FORMAT.fullmatch(err) else "<other>"] += 1
    return st


# Events that make up a plan's lifecycle, each carrying a "plan" id field (set in propose()/decide()); mapped to the
# outcome word /plans shows. Reuses the exact same event names tally() already counts, so the two stay in sync.
PLAN_EVENTS = {"proposed": "proposed", "approved": "approved", "rejected": "rejected",
               "approval-of-expired-plan-ignored": "expired", "revoked-all": "revoked",
               "revoked-one": "revoked", "plan-evicted": "revoked"}


def plan_events(path, limit):
    """The last `limit` plan lifecycle records from the log, each as (at, id, outcome). Same bounded tail read as
    tally(); a missing log gives no events, other OSErrors propagate. `revoked-all` has no id (it is global)."""
    out = []
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return out
    with f:
        size = f.seek(0, os.SEEK_END)
        start = max(0, size - LOG_TAIL_MAX)
        f.seek(start)
        if start:
            f.readline()
        for raw in f:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("event") not in PLAN_EVENTS:
                continue
            pid = rec.get("plan")
            pid = pid if isinstance(pid, str) and IDENT_FORMAT.fullmatch(pid) else "-"
            out.append((rec.get("at"), pid, PLAN_EVENTS[rec["event"]]))
    return out[-limit:]


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
    if st["tg_polls_cut"]:                                     # kept apart: a cut poll loses no update (offset moves on success)
        lines.append(t(lang, "sum_polls_cut", n=st["tg_polls_cut"]))
    if st["tg_types"]:                                         # which kind: URLError (offline, asleep) is not HTTPError (token)
        lines.append("  " + ", ".join(f"{k} {n}" for k, n in st["tg_types"].most_common(5)))
    lines.append(t(lang, "sum_ignored", socket=st["socket"], strangers=st["strangers"], floods=st["floods"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------
# Timing instrumentation (13/10, after the owner reported 1-2 minute lag on clicks and commands): logged with the
# existing log(), no free text, kept small by only firing on the slow path. Measures where a delay could sit:
# waiting for keeper.lock, a single Telegram api() call, and the end-to-end handling of one update.
# ---------------------------------------------------------------------------------------------------------------
LAST_GAP_TTL_S = 600                   # a refusal's "what the plan lacks" is shown on the next card only within 10 min
LOCK_WAIT_LOG_THRESHOLD = 1.0          # log keeper-lock-wait only once the wait itself is user-visible
API_SLOW_LOG_THRESHOLD = 2.0           # log telegram-api-slow only when an api() call is this slow (or failed)
UPDATE_SLOW_LOG_THRESHOLD = 5.0        # tally()'s own "slow" counter: telegram-update is logged for every update
                                        # (never conditional), so this is where "slow enough to count" is decided


def migrate_state(state):
    """Compatibility (requirement 8): before multi-plan support, a session held at most one active plan, as a
    dict directly under `active`. Now `active` is a list. An old state.json is upgraded in place to the list
    form, same plan, same hash, same expiry -- no right is widened, nothing is dropped. A state already in the
    new (list) form, or with no `active` key at all, is returned unchanged. Safe to call on every load, so a
    daemon restarted against a pre-upgrade state.json just works."""
    for s in (state.get("sessions") or {}).values():
        act = s.get("active")
        if isinstance(act, dict):
            s["active"] = [act]
    return state


# ---------------------------------------------------------------------------------------------------------------
# State: approvals live here and only here.
# ---------------------------------------------------------------------------------------------------------------
class Keeper:
    def __init__(self, cfg, notifier, clock=time.time):
        self.cfg, self.notify, self.now = cfg, notifier, clock
        self.lang = norm_lang(cfg.get("lang"))                             # what the human reads; the agent's stays English
        # Requirement 1: several active plans at once, bounded. A config typo or a tampered config file cannot
        # raise this past MAX_ACTIVE_PLANS_HARD_CAP -- the clamp runs here, every time, not just at install.
        self.max_active_plans = max(1, min(int(cfg.get("max_active_plans") or 3), MAX_ACTIVE_PLANS_HARD_CAP))
        self.gate = load_gate(cfg.get("agent_home"))
        self.gate.SAFE_GIT_REPOS[:] = cfg.get("safe_git_repos") or []      # K6: trusted repos for git read verbs
        self.lock = threading.Lock()
        self._lock_holder = None                                           # a short label, set only while held (best effort)
        os.makedirs(cfg["state_dir"], mode=0o700, exist_ok=True)
        self.state_path = os.path.join(cfg["state_dir"], "state.json")
        self.log_path = os.path.join(cfg["state_dir"], "log.jsonl")
        try:
            self.state = migrate_state(json.load(open(self.state_path)))
        except (OSError, ValueError):
            self.state = {"sessions": {}, "used_nonces": [], "proposals": []}
        self.state.setdefault("plan_status", {})               # hash12 -> {state, at}; see _record_plan_status

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
        # Requirement 6 (multi-plans): the card must say, BEFORE approval, what approving this plan will do to the plans
        # already active in this session. Purely advisory -- decide() recomputes the real outcome at approval time.
        preview = self._preview_outcome(self.session(sid).get("active") or [], plan)
        pending = {"plan": plan, "text": (text or "")[:3000], "hash": phash, "nonce": nonce, "proposed_at": now,
                   "preview": preview}
        s = self.session(sid)
        last = s.pop("last_gap", None)        # this proposal may follow a refusal; say what of it, once
        # ...but only if the refusal is recent: a refusal from an hour ago has nothing to do with this plan, and
        # showing it on an unrelated card would send the human to read the wrong thing. A bare string (state written
        # by an earlier version, no timestamp) is dropped the same way.
        if isinstance(last, dict) and now - float(last.get("at", 0)) <= LAST_GAP_TTL_S and last.get("text"):
            pending["context"] = last["text"]
        s["pending"] = pending
        self.state["proposals"] = recent + [now]
        self.save()
        self.log({"event": "proposed", "session": sid, "plan": plan.get("id"), "hash": phash[:12]})
        return {"ok": True, "hash": phash[:12], "message": "sent to the human for approval",
                "_notify": (sid, pending)}                     # sent by the caller, outside the lock

    def _preview_outcome(self, active, new_plan):
        """What approving `new_plan` would do to this session's `active` list, right now (requirement 6). A plan
        with the same id as one already active renews it (requirement 4); otherwise it is added, unless the cap
        is already reached, in which case the oldest active plan would be dropped (requirement 3)."""
        new_id = new_plan.get("id")
        if new_id is not None:
            for a in active:
                if a["plan"].get("id") == new_id:
                    return {"kind": "renew", "id": new_id}
        if len(active) >= self.max_active_plans:
            oldest = min(range(len(active)), key=lambda i: (active[i]["approved_at"], i))
            return {"kind": "evict", "id": active[oldest]["plan"].get("id") or "-", "limit": self.max_active_plans}
        if active:
            return {"kind": "add", "ids": [a["plan"].get("id") or "-" for a in active]}
        return {"kind": "first"}

    def keeper_command(self, cmd):
        """`keeper-propose …` or `keeper-status` alone in a Bash call: (name, {option: value}), else None."""
        try:
            stmts, _c, balanced = self.gate.scan(cmd)
            if not balanced or len(stmts) != 1 or len(self.gate.pipeline_stages(stmts[0])) != 1:
                return None
            toks = shlex.split(cmd)
        except (ValueError, TypeError):
            return None
        name = os.path.basename(toks[0]) if toks else ""
        if name not in ("keeper-propose", "keeper-status") \
                or os.path.dirname(toks[0]) not in ("", "/opt/agent-guardrails/bin"):
            return None
        allowed = ("--scope", "--text", "--wait") if name == "keeper-propose" else ("--scope", "--text")
        opts, i = {}, 1
        while i < len(toks):
            if toks[i] in allowed and i + 1 < len(toks):
                opts[toks[i][2:]] = toks[i + 1]
                i += 2
            else:
                return None
        if "wait" in opts and not re.fullmatch(r"\d{1,7}", opts["wait"]):     # a plain non-negative integer only
            return None                                                      # (clamped to wait_max_sec in check());
            # anything else (negative, decimal, non-numeric) is not recognized, same fallback as any other option
        return name, opts

    def check(self, sid, tool, tool_input, cwd=None):
        self.gate.CWD = cwd                                            # the dir the agent ran the tool in (K6)
        kc = self.keeper_command(tool_input.get("command", "")) if tool == "Bash" else None
        if kc and kc[0] == "keeper-status":
            return {"decision": "deny", "reason": "keeper status (nothing was run): " + json.dumps(self.status(sid))}
        if kc:
            opts = kc[1]
            out = self.propose(sid, opts.get("text", ""), opts.get("scope", ""))
            why = (f"keeper: plan sent to the human for approval (fingerprint {out['hash']}). Nothing was run. Wait for "
                   "their decision, then retry the actions." if out["ok"] else f"keeper: proposal refused: {out['reason']}")
            res = {"decision": "deny", "reason": why}
            if out.get("_notify"):
                res["_notify"] = out["_notify"]
            if out["ok"] and "wait" in opts:
                # The hook polls keeperd's "status" op (by fingerprint only) for up to this many seconds instead of
                # the agent having to re-run keeper-status itself. Clamped here, never inside propose(): wait is a
                # per-call client preference, not part of the plan, and must never enter the plan's hash/scope.
                res["hash"], res["wait"] = out["hash"], min(int(opts["wait"]), effective_wait_max(self.cfg))
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
        # Requirement 2: several plans can be active at once; an item (one stage of a compound Bash command, as
        # go-gate already splits it) is allowed when AT LEAST ONE of them covers it ENTIRELY. covers() itself
        # never lets two plans' targets/actions add up to cover one call -- it is always asked about a single
        # plan, whole -- so this loop never unions pieces of different plans into one approval; it only lets
        # DIFFERENT stages of one already-split compound command be covered by different plans, which is the one
        # exception the task calls for ("sauf cas des actions multi-étapes déjà découpées par go-gate").
        active = [a for a in (s.get("active") or []) if a["expires"] >= self.now()]
        if len(active) != len(s.get("active") or []):
            s["active"] = active
            self.save()
        used = []
        for k, d, st in items:
            cat = self.gate.category(tool, tool_input, k, d)
            match, gaps = None, []
            for a_ in active:                       # one plan must cover the item ENTIRELY; the gaps explain why none did
                g_ = self.gate.coverage_gap(a_["plan"], tool, tool_input, cat, st)
                if g_ is None:
                    match = a_
                    break
                gaps.append((a_, g_))
            if match is None:
                ids = [a_["plan"].get("id") or "-" for a_ in active]
                self.log({"event": "denied" if self.cfg["mode"] == "block" else "would-deny", "session": sid,
                          "tool": tool, "category": cat, "shape": command_shape(tool, st, cat), "plans": ids})
                if self.cfg["mode"] != "block":
                    return {"decision": "allow", "reason": ""}
                if active:
                    detail_gap = "; ".join(f"plan '{a_['plan'].get('id') or '-'}': {self.gate.describe_gap(g_, a_['plan'])}"
                                           for a_, g_ in gaps)
                    why = (f"keeper: this is a change ({cat}); no active plan covers it: {detail_gap}. Propose a plan "
                           "with keeper-propose, or check keeper-status.")
                    s["last_gap"] = {"text": detail_gap[:500], "at": self.now()}   # next proposal's card, once, if recent
                    self.save()
                else:
                    why = (f"keeper: this is a change ({cat}) and no approved plan covers it. Propose a plan with "
                           "keeper-propose; the human approves it on the keeper bot.")
                return {"decision": "deny", "reason": why}
            used.append(match["plan"].get("id"))
        self.log({"event": "allowed", "session": sid, "tool": tool, "plans": used})
        return {"decision": "allow", "reason": ""}

    def status(self, sid):
        """`keeper-status`: every active plan of this session (requirement 5), never the agent's free-form text."""
        now = self.now()
        active = [a for a in (self.session(sid).get("active") or []) if a["expires"] > now]
        return {"active": [dict(a["plan"], expires_in_min=int((a["expires"] - now) / 60)) for a in active],
                "pending": bool(self.session(sid).get("pending"))}

    # ----- plan status by fingerprint (keeper-propose --wait) ----------------------------------------------------
    # A read-only view of what decide() already decided, keyed by the plan's hash12 instead of a session. Exists so
    # a client can wait for a decision without re-running keeper-status itself. The vocabulary is closed to exactly
    # four words -- pending/approved/rejected/expired -- and "never proposed" / "ledger entry aged out" both answer
    # "expired" too: a fifth, distinguishable "unknown" would let a socket client tell those two apart and probe
    # for live fingerprints. Never includes the plan's text or scope (council constraint: only the state travels).
    PLAN_STATUS_RETENTION_SEC = 86400

    def _record_plan_status(self, h, state):
        """Called from decide() only (approve/reject/expired-on-decide), never from anything the socket drives: the
        ledger is write-once per outcome and has no path back to "pending", so a socket client can only ever learn
        of a decision decide() already made, never cause one. Bounded by age, not by a click: unlike used_nonces
        (bounded by count because a replay is cheap to attempt), a decision is written at most once per plan, so
        the only growth to bound here is time."""
        now = self.now()
        self.state["plan_status"] = {k: v for k, v in self.state["plan_status"].items()
                                      if now - v["at"] < self.PLAN_STATUS_RETENTION_SEC}
        self.state["plan_status"][h] = {"state": state, "at": now}

    def plan_status(self, h):
        """pending / approved / rejected / expired for a plan's hash12 -- never the plan itself. Read-only: it does
        not pop or mutate a pending entry even past its age limit, so it can never race decide()'s own, separate
        expiry check (which still applies when a late approval actually arrives)."""
        rec = self.state["plan_status"].get(h)
        if rec:
            return rec["state"]
        for s in self.state["sessions"].values():
            p = s.get("pending")
            if p and p["hash"][:12] == h:
                age = self.now() - p["proposed_at"]
                return "expired" if age > self.cfg["pending_max_age_min"] * 60 else "pending"
        return "expired"                                        # never proposed, or its ledger entry aged out

    # ----- human side (only reached from the bot) ---------------------------------------------------------------
    def is_owner(self, from_id, chat_id):
        """The owner, in the configured chat: the same test as decide() applies to buttons. A missing id or an unset
        owner never matches (a message without a sender must not look like an unconfigured owner)."""
        if from_id is None or self.cfg.get("owner_id") is None:
            return False
        if str(from_id) != str(self.cfg["owner_id"]):
            return False
        return not self.cfg.get("chat_id") or str(chat_id) == str(self.cfg["chat_id"])

    # Owner-only text commands (council of 12/10, after the first on-machine run of block mode): only REMOVE rights
    # (/stop) or READ state (/status, /plans, /help); approve/reject/mode stay button- or config-only, never a word
    # typed in a chat the agent cannot see but could in principle guess at. Checked after the single is_owner() gate
    # below, so every one of them is owner-and-configured-chat-only like /summary already was.
    COMMANDS = ("stop", "status", "plans", "summary", "help")        # order shown in Telegram's "/" menu

    def command(self, from_id, chat_id, text):
        """A text message sent to the bot. Only a known command from the owner is acted on; any other text (or a
        malformed/extra-argument form of a known one) is ignored. Returns the messages to send back, or None. Not
        reachable from the socket — handle_message() is the only caller."""
        if not isinstance(text, str):
            return None
        if not self.is_owner(from_id, chat_id):
            if text.startswith("/"):                          # a command attempt; the text itself is never logged
                self.log({"event": "command-from-stranger-ignored"})
            return None
        text = text.strip()
        # Requirement 5: /stop with no argument still revokes every plan (unchanged); /stop <id> revokes only the
        # named plan, active or pending, in every session (plans are not scoped to a session, see is_owner()'s
        # neighbour docstring on sessions not being a security boundary).
        m = re.fullmatch(r"/stop(?:@\w+)?(?:\s+([A-Za-z0-9_.-]{1,40}))?", text, re.I)
        if m:
            # Unlike /status and /plans below (reads, same no-lock precedent as /summary), this mutates self.state:
            # it must take the lock, exactly as decide()'s own stop branch does when the button is pressed instead.
            plan_id = m.group(1)
            with self.lock_scope("stop"):
                had = self._revoke_all(plan_id)
            if plan_id:
                return [self.msg("ans_stopped_one", id=plan_id) if had else self.msg("ans_nothing_active_one", id=plan_id)]
            return [self.msg("ans_stopped") if had else self.msg("ans_nothing_active")]
        if re.fullmatch(r"/status(?:@\w+)?", text, re.I):
            return self.status_report()
        m = re.fullmatch(r"/plans(?:@\w+)?(?:\s+(\d{1,2}))?", text, re.I)
        if m:
            n = min(max(int(m.group(1) or PLANS_DEFAULT), 1), PLANS_MAX)
            return self.plans(n)
        if re.fullmatch(r"/help(?:@\w+)?", text, re.I):
            return [self.help_text()]
        m = re.fullmatch(r"/(?:summary|resume)(?:@\w+)?(?:\s+(\d{1,2}))?", text, re.I)
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

    def status_report(self):
        """`/status`: a read-only snapshot, structured fields only — never the agent's free-form explanation text
        or the command it ran. Nothing here mutates state (an expired-but-not-yet-popped active plan is simply
        skipped, the same way it would stop covering a call in check())."""
        lines = [self.msg("status_title", mode=self.cfg["mode"])]
        active = []
        now = self.now()
        for sid, s in sorted(self.state["sessions"].items()):
            for act in sorted(s.get("active") or [], key=lambda a: a["plan"].get("id") or ""):
                if act["expires"] > now:
                    plan = act["plan"]
                    active.append(str(self.msg("status_active_line", session=sid, id=plan.get("id") or "-",
                                                actions=", ".join(plan["actions"]),
                                                targets=", ".join(plan["targets"]) or self.msg("card_any"),
                                                left=max(0, int((act["expires"] - now) / 60)))))
        lines += active if active else [self.msg("status_no_active")]
        pending = [s["pending"]["plan"].get("id") or "-" for _sid, s in sorted(self.state["sessions"].items())
                   if s.get("pending")]
        lines.append(self.msg("status_pending", n=len(pending), ids=", ".join(pending)) if pending
                     else self.msg("status_no_pending"))
        recent = len([t for t in self.state["proposals"] if t > self.now() - 3600])
        lines.append(self.msg("status_hourly", n=recent, limit=self.cfg["max_proposals_per_hour"]))
        return split_message(mask_text("\n".join(str(x) for x in lines)))

    def plans(self, n=PLANS_DEFAULT):
        """`/plans [n]`: the last n plan lifecycle events (proposed/approved/rejected/expired/revoked), with id,
        local time and outcome — the same bounded tail read, masking and splitting as /summary."""
        try:
            events = plan_events(self.log_path, n)
        except OSError:
            return split_message(t(self.lang, "sum_unreadable"))
        if not events:
            text = t(self.lang, "plans_empty")
        else:
            text = "\n".join([t(self.lang, "plans_title")] +
                              [t(self.lang, "plans_line", at=at or "-", id=pid,
                                 outcome=t(self.lang, "plans_outcome_" + outcome)) for at, pid, outcome in events])
        return split_message(mask_text(text))

    def help_text(self):
        """`/help`: every command, one line each, in the configured language."""
        return "\n".join(str(x) for x in [self.msg("help_title")] +
                          [self.msg(f"help_{name}") for name in self.COMMANDS])

    def msg(self, key, **kw):
        """A human message in the configured language, tagged with its key."""
        return Msg(t(self.lang, key, **kw), key)

    @contextlib.contextmanager
    def lock_scope(self, label):
        """Acquire self.lock, logging the wait only when it is itself slow enough to matter (13/10 timing work).
        `label` is who is now acquiring it (check/decide/stop below); `held_by` is a best-effort guess at who had
        it before (set without its own lock, so it can be stale by a few instructions — good enough for a log
        line, never relied on for correctness)."""
        t0, held_by = time.time(), self._lock_holder
        self.lock.acquire()
        waited = time.time() - t0
        if waited > LOCK_WAIT_LOG_THRESHOLD:
            self.log({"event": "keeper-lock-wait", "waited_s": round(waited, 3), "by": label, "held_by": held_by or "-"})
        self._lock_holder = label
        try:
            yield
        finally:
            self._lock_holder = None
            self.lock.release()

    def _revoke_all(self, plan_id=None):
        """Every active and pending plan of every session (council review 08/10: Stop is global, not per-card),
        or -- requirement 5 -- just the ones whose id is `plan_id`. Shared by the Stop button (decide()) and the
        `/stop` / `/stop <id>` text command — one revocation path, not two. As before plan_id=None, dropping a
        pending proposal never by itself counts towards `had`: the answer ("nothing was active") only ever
        speaks of ACTIVE plans, even though a pending one is always dropped too."""
        had = False
        for s in self.state["sessions"].values():
            if plan_id is None:
                had = bool(s.pop("active", None)) or had
                s.pop("pending", None)
                continue
            active = s.get("active") or []
            keep = [a for a in active if a["plan"].get("id") != plan_id]
            if len(keep) != len(active):
                had = True
                s["active"] = keep
            pending = s.get("pending")
            if pending and pending["plan"].get("id") == plan_id:
                s.pop("pending", None)
        self.save()
        self.log({"event": "revoked-all" if plan_id is None else "revoked-one", "plan": plan_id})
        return had

    def _activate(self, s, p):
        """Add p's plan to session `s`'s active list (requirements 3 and 4). A plan whose id matches one already
        active renews it in place (same slot, fresh hash/expiry) rather than adding a second entry. Otherwise it
        is appended; past the cap, the OLDEST active plan (by approval time, ties broken towards the one approved
        first) is dropped to make room -- the brand new entry, just appended, is never a candidate for that, so
        a fresh approval can never evict itself. Returns the dropped plan's id, or None (requirement 3: this is
        reported to both the human, in the return value callers turn into ans_approved_evicted, and the agent,
        which sees the current active ids in keeper-status and in the next denied call's reason)."""
        active = s.setdefault("active", [])
        new_id = p["plan"].get("id")
        if new_id is not None:
            for i, a in enumerate(active):
                if a["plan"].get("id") == new_id:
                    active[i] = {"plan": p["plan"], "hash": p["hash"], "approved_at": self.now(),
                                 "expires": self.now() + p["plan"]["ttl"] * 60}
                    return None
        active.append({"plan": p["plan"], "hash": p["hash"], "approved_at": self.now(),
                       "expires": self.now() + p["plan"]["ttl"] * 60})
        if len(active) > self.max_active_plans:
            oldest = min(range(len(active) - 1), key=lambda i: (active[i]["approved_at"], i))
            return active.pop(oldest)["plan"].get("id") or "-"
        return None

    def decide(self, from_id, chat_id, data):
        """A button press. data = approve:<hash12>:<nonce> | reject:<hash12>:<nonce> | stop:<session>"""
        if str(from_id) != str(self.cfg["owner_id"]) or (self.cfg.get("chat_id") and str(chat_id) != str(self.cfg["chat_id"])):
            self.log({"event": "decision-from-stranger-ignored"})
            return self.msg("ans_not_owner")
        parts = data.split(":")
        if parts[0] == "stop":
            return self.msg("ans_stopped") if self._revoke_all() else self.msg("ans_nothing_active")
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
                    self._record_plan_status(h, "rejected")
                    self.save()
                    self.log({"event": "rejected", "session": sid, "plan": p["plan"].get("id")})
                    return self.msg("ans_rejected")
                if self.now() - p["proposed_at"] > self.cfg["pending_max_age_min"] * 60:
                    self._record_plan_status(h, "expired")
                    self.save()
                    self.log({"event": "approval-of-expired-plan-ignored", "session": sid, "plan": p["plan"].get("id")})
                    return self.msg("ans_expired")
                evicted = self._activate(s, p)
                self._record_plan_status(h, "approved")
                self.save()
                self.log({"event": "approved", "session": sid, "plan": p["plan"].get("id"), "hash": h,
                          "evicted": evicted})
                if evicted:
                    # A visible lifecycle event of its own (requirement 3: never silently), under the dropped
                    # plan's own id, so /plans shows it as "revoked" without having to parse the approval's
                    # "evicted" field.
                    self.log({"event": "plan-evicted", "session": sid, "plan": evicted,
                              "replaced_by": p["plan"].get("id")})
                    return self.msg("ans_approved_evicted", ttl=p["plan"]["ttl"], evicted=evicted)
                return self.msg("ans_approved", ttl=p["plan"]["ttl"])
        self.log({"event": "decision-unknown-plan-ignored"})
        return self.msg("ans_unknown")


# ---------------------------------------------------------------------------------------------------------------
# Telegram: the keeper bot. Only keeperd holds its token, so only keeperd reads its updates.
# ---------------------------------------------------------------------------------------------------------------
class TelegramBot:
    # Overridable in-process only (council of 11/10's block-mode dry run): never a config key, env var or argument,
    # so nothing the agent or a config file controls can redirect this. Production keeps the real values.
    API_BASE = "https://api.telegram.org"
    DEFAULT_TIMEOUT = 40
    # send_plan() runs from serve()'s handler while a hook is still blocked reading the socket reply (its own
    # timeout there is 10 s, see keeper_client.py's ask() and serve()'s connection.settimeout). A Telegram that
    # hangs must give up and let the handler reply BEFORE that 10 s, or the client times out first, reports
    # "daemon not reachable" (wrong: the daemon answered, just late), and the handler's reply then lands on a
    # closed socket. Must stay well under that 10 s (owner review, 11/10).
    HOOK_WAIT_TIMEOUT = 5
    # register_commands() runs once at daemon startup, nowhere near a hook. Kept short anyway (12/10): a slow or
    # unreachable Telegram must not delay the daemon's own serve() loop by more than a few seconds.
    MENU_TIMEOUT = 5
    # getUpdates' own long poll (13/10, chasing the reported lag). Named, but left at their long-standing values:
    # urlopen() opens a fresh connection per call (confirmed: no pooling to go stale between polls, see the report),
    # and nothing in reading api()/urllib shows the client timeout keeping a half-open connection alive past what
    # Telegram's own `timeout` already bounds. A shorter pair (e.g. 10/15) would recover from a stuck poll sooner,
    # at the cost of more requests when idle; left as-is since that trade-off could not be shown to help here.
    GETUPDATES_SERVER_TIMEOUT = 30
    GETUPDATES_CLIENT_TIMEOUT = 40
    # poll()'s own retry pacing.
    POLL_IDLE_RETRY_SECONDS = 1        # an idle long poll dropped: retry at once, no update was ever at risk
    POLL_ERROR_RETRY_SECONDS = 5       # a real network hiccup: back off a little before trying again
    # getUpdates answers 409 Conflict when another poller (a leftover process, a second instance) holds the same
    # bot token's long poll — the usual silent cause of "the bot ignores me". Back off longer than a plain error:
    # retrying fast just trades places with the other poller instead of letting it finish and go away.
    POLL_CONFLICT_BACKOFF_SECONDS = 30
    # Owner review of PR #10 (13/10): item 2 made the offset advance only after a successful decide()/command(),
    # so a crash retries the SAME update next poll instead of skipping it. That is right for a transient failure,
    # but an update that raises on EVERY attempt (a bug on a malformed field) would then retry forever, stalling
    # every later update — including an Approve or /stop — behind it until the daemon is restarted. A few retries
    # still happen (a real transient hiccup gets its normal retry), then it is dropped.
    MAX_UPDATE_RETRIES = 3

    def __init__(self, cfg):
        self.cfg = cfg
        self.lang = norm_lang(cfg.get("lang"))
        with open(cfg["bot_token_file"]) as f:
            self.token = f.read().strip()
        self.offset = 0
        self.log_fn = None                                     # set to keeper.log by main(), once keeper exists
        # update_id -> consecutive failure count (13/10). Bounded by construction, not by an explicit cap: a
        # failing update blocks every later one from ever being attempted (same offset, same batch), so at most
        # one entry is ever "live" in practice; cleared on success or once dropped, never left to accumulate.
        self._fail_counts = {}

    def api(self, method, payload, timeout=None):
        timeout = self.DEFAULT_TIMEOUT if timeout is None else timeout
        req = urllib.request.Request(f"{self.API_BASE}/bot{self.token}/{method}",
                                     json.dumps(payload).encode(), {"Content-Type": "application/json"})
        t0 = time.time()
        try:
            result = json.load(urllib.request.urlopen(req, timeout=timeout))
        except urllib.error.HTTPError as e:
            self._log_api_timing(method, time.time() - t0, f"http-{e.code}")
            raise
        except (TimeoutError, socket.timeout):
            self._log_api_timing(method, time.time() - t0, "timeout")
            raise
        except Exception as e:
            self._log_api_timing(method, time.time() - t0, type(e).__name__)
            raise
        self._log_api_timing(method, time.time() - t0, "ok")
        return result

    def _log_api_timing(self, method, duration, outcome):
        """telegram-api-slow (13/10 timing work): only when it took more than API_SLOW_LOG_THRESHOLD or failed, to
        keep the log small. No behaviour change: api() still raises exactly what it always raised."""
        if (outcome != "ok" or duration > API_SLOW_LOG_THRESHOLD) and self.log_fn:
            try:
                self.log_fn({"event": "telegram-api-slow", "method": method, "duration_s": round(duration, 3),
                             "outcome": outcome})
            except Exception:
                pass

    def send_plan(self, sid, p):
        text, kb = render_plan_card(self.lang, p)
        self.api("sendMessage", {"chat_id": self.cfg["chat_id"], "text": text, "reply_markup": kb},
                 timeout=self.HOOK_WAIT_TIMEOUT)

    def send(self, text):
        self.api("sendMessage", {"chat_id": self.cfg["chat_id"], "text": text[:4000]})

    def register_commands(self):
        """Telegram's "/" menu, scoped to the configured chat only (`BotCommandScopeChat`): a stranger who finds
        the bot must never see these. Call site (main()) treats any failure as non-fatal and logs the error type
        only; never called at all without a configured chat_id."""
        if not self.cfg.get("chat_id"):
            return
        commands = [{"command": name, "description": t(self.lang, f"cmd_desc_{name}")} for name in Keeper.COMMANDS]
        self.api("setMyCommands", {"commands": commands, "scope": {"type": "chat", "chat_id": self.cfg["chat_id"]}},
                 timeout=self.MENU_TIMEOUT)

    def fetch_updates(self):
        """One long poll. `message` is asked for so the owner can send `/summary`; keeper.command() acts on nothing else."""
        r = self.api("getUpdates", {"offset": self.offset, "timeout": self.GETUPDATES_SERVER_TIMEOUT,
                                     "allowed_updates": ["callback_query", "message"]},
                     timeout=self.GETUPDATES_CLIENT_TIMEOUT)
        return r.get("result", [])

    def _safe_api(self, method, payload):
        """A Telegram follow-up call (the confirmation toast, dropping the buttons): must never hide the others,
        never propagate out of handle_update() and cost poll() a 5s sleep over a purely cosmetic failure (13/10 —
        this is what made a late click look like nothing happened: answerCallbackQuery can fail on its own, e.g.
        HTTP 400 "query is too old", well after the decision was already applied). api() already logs the failure
        itself (telegram-api-slow); nothing more to record here."""
        try:
            self.api(method, payload)
        except Exception:
            pass

    def _safe_send(self, text):
        try:
            self.send(text)
        except Exception:
            pass

    def handle_update(self, keeper, u, got_at=None):
        # telegram-update (13/10 timing work): lag_s is Telegram's own delay (message "date") when known, else how
        # long this update sat in an already-fetched batch before its turn; handled_s is everything below, follow-up
        # calls included, so a slow answerCallbackQuery/editMessageReplyMarkup/send shows up here too.
        t_start = time.time()
        cq = u.get("callback_query")
        msg_in = u.get("message") if not cq else None
        lag = (t_start - msg_in["date"]) if (isinstance(msg_in, dict) and isinstance(msg_in.get("date"), (int, float))) \
            else (t_start - got_at if got_at is not None else None)
        uid = u["update_id"]
        # Offset semantics (13/10, after the owner reported a lag the buttons never showed any sign of): an update
        # must never be applied twice (decide()'s nonce already makes a replay harmless, and /stop is idempotent)
        # and never lost. So the offset advances right after the state-mutating call below has mutated AND saved
        # (never before it — a crash inside decide()/command() must retry the SAME update next poll, not skip it
        # forever), and never only after the cosmetic follow-ups (a crash there must not re-apply an already-applied
        # decision on the next poll either).
        try:
            try:
                if not cq:
                    self.handle_message(keeper, u.get("message"))
                    self.offset = uid + 1
                    self._fail_counts.pop(uid, None)
                    return
                with keeper.lock_scope("decide"):
                    out = keeper.decide((cq.get("from") or {}).get("id"),
                                        (cq.get("message") or {}).get("chat", {}).get("id"), cq.get("data", ""))
                self.offset = uid + 1
                self._fail_counts.pop(uid, None)
                self._safe_api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": out[:180]})
                msg = cq.get("message") or {}
                if msg and out.key not in IGNORED:              # one decision per message: drop the buttons
                    self._safe_api("editMessageReplyMarkup", {"chat_id": msg["chat"]["id"],
                                                               "message_id": msg["message_id"], "reply_markup": {}})
                    self._safe_send(out)
            except Exception as e:
                # A poison update (owner review of PR #10, 13/10): this one raises on every attempt, not just a
                # transient hiccup. Retry a few times — the offset still hasn't moved, exactly as a real transient
                # failure is retried today — then give up on it specifically and move the offset past it, so it
                # cannot stall every later update (an Approve, a /stop) behind it forever. Never the message text.
                fails = self._fail_counts.get(uid, 0) + 1
                if fails < self.MAX_UPDATE_RETRIES:
                    self._fail_counts[uid] = fails
                    raise
                self._fail_counts.pop(uid, None)
                self.offset = uid + 1
                keeper.log({"event": "telegram-update-dropped", "update_id": uid, "error": type(e).__name__})
        finally:
            keeper.log({"event": "telegram-update", "kind": "callback" if cq else "message",
                        "lag_s": None if lag is None else round(lag, 3), "handled_s": round(time.time() - t_start, 3)})

    def handle_message(self, keeper, m):
        """A text message. keeper.command() answers only the owner's known commands; the reply goes to the
        configured chat. Does not own `self.offset`: handle_update() advances it right after this returns."""
        if not isinstance(m, dict):
            return
        replies = keeper.command((m.get("from") or {}).get("id"), (m.get("chat") or {}).get("id"), m.get("text"))
        for text in replies or []:
            self._safe_send(text)

    def poll(self, keeper):
        while True:
            try:
                updates = self.fetch_updates()
                got_at = time.time()                                # 13/10: "the poll returned", for callback lag
                for u in updates:
                    self.handle_update(keeper, u, got_at)
            except (TimeoutError, socket.timeout):                  # an idle long poll that dropped: retry at once
                keeper.log({"event": "telegram-poll-timeout"})      # the offset only moves on success, so no update is lost
                time.sleep(self.POLL_IDLE_RETRY_SECONDS)
            except urllib.error.HTTPError as e:
                if e.code == 409:                                   # another poller on this same bot token (13/10):
                    keeper.log({"event": "telegram-poll-conflict"})  # the usual silent cause of "the bot ignores me"
                    time.sleep(self.POLL_CONFLICT_BACKOFF_SECONDS)
                else:
                    keeper.log({"event": "telegram-error", "error": type(e).__name__})
                    time.sleep(self.POLL_ERROR_RETRY_SECONDS)
            except Exception as e:                                  # network hiccup: retry, never crash the daemon
                keeper.log({"event": "telegram-error", "error": type(e).__name__})
                time.sleep(self.POLL_ERROR_RETRY_SECONDS)


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
            if req.get("op") == "status":
                # keeper-propose --wait polls this instead of re-running keeper-status: by fingerprint only, never
                # the plan itself. Same peer check as "check" above; no lock_scope label needed, the read is brief.
                h = req.get("hash")
                if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{12}", h):
                    return self.reply({"error": "bad hash"})
                with keeper.lock_scope("status"):
                    state = keeper.plan_status(h)
                return self.reply({"state": state})
            if req.get("op") != "check" or not isinstance(req.get("input") or {}, dict):
                return self.reply({"error": "unknown op"})
            # Lock audit (13/10, chasing the reported lag): check() runs the go-gate classifier, which is slower
            # than a plain state mutation on a long command — but it must stay INSIDE this scope, not narrowed to
            # just the save(): classify() keeps its working state (CHANGES, KNOWN_VARS, CWD) as go-gate module
            # globals, not per-call locals, and those are shared by every concurrent hook request against this one
            # `self.gate` object. Without the lock, two simultaneous proposals could corrupt each other's
            # classification. Making that safe would mean changing go-gate itself, out of scope here. send_plan()
            # below (the actual network call) already runs after this scope ends, not inside it; propose() has no
            # lock site of its own, it runs inside this same one.
            with keeper.lock_scope("check"):
                out = keeper.check(req.get("session"), str(req.get("tool", "")), req.get("input") or {},
                                   req.get("cwd"))
            note = out.pop("_notify", None)
            # Dry run (11/10): send_plan() used to run AFTER the reply, so the agent was told "sent to the human"
            # even when Telegram was down and nothing reached them. Attempted first; the reason is rewritten only
            # on failure, so a working send still says exactly what it said before.
            if note:
                try:
                    keeper.notify.send_plan(*note)
                except Exception as e:
                    keeper.log({"event": "telegram-error", "error": type(e).__name__})
                    out["reason"] = ("keeper: could not reach Telegram to send the plan for approval; the proposal "
                                      "was recorded, retry once it answers again.")
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
    with open(p) as f:
        cfg.update(json.load(f))
    for k in ("wait_max_sec", "hook_timeout_sec"):
        if isinstance(cfg[k], bool) or not isinstance(cfg[k], int) or cfg[k] < 0:
            raise ValueError(f"config: {k} must be a non-negative integer (seconds)")
    if cfg["wait_max_sec"] > effective_wait_max(cfg):
        print(f"keeperd: wait_max_sec={cfg['wait_max_sec']} does not fit under hook_timeout_sec={cfg['hook_timeout_sec']} "
              f"(needs {HOOK_TIMEOUT_MARGIN_SEC}s of margin): --wait is clamped to {effective_wait_max(cfg)}s. A hook killed "
              "by its timeout does not block the tool call.", file=sys.stderr)
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
    bot.log_fn = keeper.log                                     # 13/10: api()'s own slow/failed-call timing
    threading.Thread(target=bot.poll, args=(keeper,), daemon=True).start()
    try:
        bot.send(startup_message(keeper.lang, cfg["mode"]))
    except Exception:
        keeper.log({"event": "telegram-error-at-start"})
    try:
        bot.register_commands()
    except Exception as e:                                  # never worth delaying or failing startup over
        keeper.log({"event": "commands-menu-failed", "error": type(e).__name__})
    serve(keeper, cfg)


if __name__ == "__main__":
    main()

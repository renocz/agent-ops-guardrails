#!/usr/bin/env python3
"""secret-guard: a Claude Code PreToolUse hook that stops an AI agent from printing secrets by accident.

Why: a written rule ("always mask output that may contain config") was broken 3 times in 2 days. Discipline became a
technical constraint.

Bash tool: a command that may print secrets is refused unless every statement that may print them sends stdout AND
stderr through a masking filter, e.g. `cmd 2>&1 | mask` or `{ a
b
} 2>&1 | mask`. When the output provably contains
no values (grep -c, sha256sum, key names only), the agent may end the command with the explicit marker `# secret-ok`.
That is a deliberate, visible, reviewable claim, not a silent bypass.

Read / Grep / NotebookRead tools: direct reads of files that typically hold secrets are refused.

Scope and limits: this guards against ACCIDENTAL disclosure by a cooperative agent. It is pattern-based and cannot be
complete. An adversary who controls the agent can get around it. Pair it with least privilege and keep secrets out of
the agent's reach.

How to read this file, top to bottom:
  1. Rules: READERS, SECRET_PATHS, RISKY (Bash), SENSITIVE_FILES and SECRET_HUNT (Read/Grep). Each rule has a comment.
  2. scan(): splits a command into statements, like Bash would (quotes, comments, { } and ( ) groups).
  3. pipeline_stages() and is_masked(): does the whole output of a statement go through the mask?
  4. check_bash(), check_read(), decide(): the decision. main(): the Claude Code hook protocol (JSON in, JSON out).

Install: see README.md. Python 3.9+, standard library only. Input that is not valid JSON is let through (it is not a
tool call this hook can judge)
an internal error or a broken extra-patterns file makes it refuse (fail closed).
"""
import json, os, re, sys

MASK_CMD = os.environ.get("SECRET_GUARD_MASK", "mask")
MARKER = "secret-ok"

# ---------------------------------------------------------------------------------------------------------------
# Rules. Each rule is (regex, label). A statement matching any regex is "risky" and must be masked.
# They are case-insensitive. Keep each one small and explained: an ops reader should be able to audit this list.
# ---------------------------------------------------------------------------------------------------------------

# Programs that print a file's content (or can).
READERS = (r"cat|tac|nl|less|more|head|tail|grep|egrep|rg|sed|awk|cut|sort|uniq|diff|jq|yq|xxd|od|strings|base64|bat"
           r"|python3?|perl|ruby|node")

# Paths that usually hold secrets. Used by the Bash rule below (reader + path) and, anchored, for Read/Grep.
SECRET_PATHS = [
    r"\.env\b", r"\.env\.",                                  # .env, .env.local, app.env
    r"config\.(xml|ya?ml|json|toml|ini|cfg)\b",              # app configs (*arr config.xml, config.toml…)
    r"settings\.(json|ini|toml|cfg)\b",
    r"compose\.ya?ml\b",                                     # docker compose files often inline secrets
    r"credentials", r"\.netrc\b", r"rclone\.conf\b", r"\.cookie\b",
    r"secrets?\.(ya?ml|json|env|txt)\b", r"/secrets?/",
    r"\.git/config\b",
    r"/etc/[a-z-]*\.env\b",
    r"\.pem\b", r"\.key\b", r"id_(rsa|ed25519|ecdsa)\b(?!\.pub)",  # private keys (not the .pub)
    r"(^|/)(wp-)?config\.php\b", r"(^|/)(g)?shadow-?\b",       # PHP app configs, password hashes
    r"grafana\.ini\b", r"(^|/)app\.ini\b", r"\.n8n/config\b",   # Grafana, Gitea, n8n (encryption key)
    r"cloudflared/[^\s/]*\.json\b", r"\.cloudflared/",          # tunnel credentials
    r"\.nmconnection\b", r"system-connections/",                 # NetworkManager: Wi-Fi PSK, VPN secrets
    r"\.kube/config\b", r"\.aws/", r"\.docker/config",
    r"wireguard/", r"\bwg\d*\.conf\b",                       # WireGuard: holds the private key
    r"acme\.json\b",                                         # Traefik: certificate private keys
    r"\.envrc\b", r"\.pgpass\b", r"\.my\.cnf\b",              # direnv, PostgreSQL, MySQL client passwords
    r"/pve/priv/", r"\bpriv/token\.cfg\b",                    # Proxmox: API token secrets, cluster keys
    r"\bgh/hosts\.ya?ml\b", r"\.pypirc\b", r"\.npmrc\b",       # gh, PyPI and npm tokens
    r"\.vault-token\b", r"tailscaled\.state\b", r"/age/keys\.txt\b", r"\.git-credentials\b",
]

# Environment variable names that look secret.
SECRET_VAR = r"[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASS|PASSWD|PASSWORD|PWD|CREDENTIAL|AUTH|DSN|DATABASE_URL|COOKIE)[A-Za-z0-9_]*"

RISKY = [
    # crontab lines often carry API keys and tokens
    (r"\bcrontab\s+-l\b", "crontab"),
    # docker inspect / compose config print environment variables; env inside a container too
    (r"\bdocker\s+inspect\b|\bdocker[\s-]compose\b.*\bconfig\b|\bdocker\s+(exec|run)\b.*\b(env|printenv)\b",
     "Docker config / environment"),
    # the whole environment…
    (r"(^|[\s;&|(])(env|printenv|set|export\s+-p|declare\s+-x)\s*($|[;&|)])", "environment variables"),
    # …or one variable: printenv X, or echo/printf of a secret-looking variable
    (r"\bprintenv\s+(?!(USER|HOME|PATH|SHELL|LANG|LC_\w+|TERM|HOSTNAME|TMPDIR|EDITOR|PWD|OLDPWD|LOGNAME|TZ)\b)\w",
     "environment variable"),
    (r"\b(echo|printf)\b.*\$\{?" + SECRET_VAR, "secret-looking variable"),
    # process listings show command lines (tokens passed as arguments) and environments
    (r"/proc/[^\s]*/(environ|cmdline)|\bps\s+(aux|-ef|e)\b", "process command lines / environment"),
    (r"\bsystemctl\s+(cat|show-environment|show)\b", "systemd units"),
    # logs: apps print connection strings, tokens in URLs, stack traces with config
    (r"\bdocker\s+(compose\s+)?logs\b|\bdocker-compose\s+logs\b|\bjournalctl\b|\bkubectl\s+logs\b", "logs"),
    # git network commands print remote URLs (with embedded credentials) in errors
    (r"\bgit\b.*\b(fetch|pull|push|clone|ls-remote)\b|\bgit\s+remote\s+-v\b|\bgit\s+config\b.*(url|credential)"
     r"|\bgit\s+credential\b", "git (URLs with credentials, error messages)"),
    # WireGuard: showconf / private-key / genkey print private keys (plain `wg show` hides them)
    (r"\bwg\s+(showconf|genkey|genpsk)\b|\bwg\s+show\b.*\b(private-key|preshared-keys)\b", "WireGuard keys"),
    # a reader and a secret-looking path in the same statement, in either order (`for f in a.env; do cat $f`).
    # Anchored with (?s)^ so the lookahead runs once per statement, not at every position: long commands stay fast.
    (r"(?s)^(?=.*\b(" + READERS + r")\b).*(" + "|".join(SECRET_PATHS) + ")", "file that may contain secrets"),
    # grepping for key formats prints the keys, unless only file names / counts / exit status are asked for
    (r"\b(grep|egrep|rg)\b(?!.*\s-[a-zA-Z]*[lLcq][a-zA-Z]*\b).*(sk-|AIza|ghp_|github_pat_|xox[abp]-|eyJ|PRIVATE KEY)",
     "search for key values"),
    # scripts that dump their environment
    (r"os\.environ\s*[)\]]|os\.environ\.(items|copy|values)\b|dict\(\s*os\.environ|process\.env\s*[)\];]",
     "environment variables (script)"),
    # password managers and secret stores (not when the value is captured: X=$(security ...))
    (r"\bpass\s+show\b|\b(pass-cli|gopass)\b.*\b(show|get|view)\b|\bop\s+(read|item\s+get)\b|\bbw\s+get\b"
     r"|(?<!\$\()\bsecurity\s+find-[a-z-]*password\b.*\s-[wg]\b", "password manager"),
    (r"\brclone\s+config\s+(show|dump)\b", "rclone config (holds tokens and passwords)"),
    (r"\b(sops|age|gpg2?|rage)\b.*\s(-[a-zA-Z]*d[a-zA-Z]*|--decrypt)\b|\bsops\s+decrypt\b"
     r"|\bansible-vault\s+(view|decrypt)\b", "decrypted secrets"),
    (r"\bgh\s+auth\s+(token|status\b.*(-t|--show-token))\b|\bcloudflared\s+tunnel\s+token\b"
     r"|\baws\s+configure\s+(export-credentials|get\s+\S*(secret|key|token))|\baws\s+sts\s+(get-session-token|assume-role)\b"
     r"|\bgcloud\s+auth\s+(print-access-token|print-identity-token)\b|\bdocker\s+login\b.*\s-p\s", "CLI that prints a token"),
    (r"\brestic\b.*\s(dump|cat)\b|\bborg\s+extract\b.*--stdout|\bkopia\s+(show|content\s+show)\b", "backup contents"),
    (r"\bredis-cli\b.*\s(get|getdel|getex|mget|hget|hgetall|hmget|hvals|config\s+get)\s", "Redis values"),
    (r"\bocc\b.*\bconfig:(system|app):get\b|\bocc\b.*\bconfig:list\b.*--private", "Nextcloud config values"),
    (r"\bbw\s+(unlock|login)\b|\bbw\s+get\b", "password manager"),
    (r"\bborg\s+key\s+export\b|\brestic\s+key\s+(list|add)\b.*--json|\bgpg\b.*--export-secret-keys?\b",
     "backup or encryption keys"),
    (r"\bnmcli\b.*(\s-s\b|--show-secrets)|\bwpa_cli\b.*\bget_network\b.*\bpsk\b", "Wi-Fi / VPN secrets"),
    (r"\bgit\b.*\b(log|show|diff|blame|grep)\b.*(-p\b|--patch|\s-S|\s-G|--follow)?.*(\.env\b|secrets?\.(ya?ml|json)|credentials)",
     "secret file in git history"),
    (r"\btailscale\s+debug\s+(local-creds|prefs|authkey)\b|\bqm\s+cloudinit\s+dump\b|\bpveum\s+(user\s+)?token\s+add\b|\bpvesh\s+create\s+/access/users/\S+/token"
     r"|\bdocker\s+swarm\s+join-token\b|\bkubeadm\s+token\s+create\b|\bgh\s+auth\s+token\b", "command that prints a new or local secret"),
    (r"(?i)\bselect\b[^;\n]{0,200}?(?<!length\()(?<!count\()\b\w*(api_?key|password|passwd|secret|token)\w*\b[^;\n]{0,200}?\bfrom\b",
     "SQL selecting secret columns"),
    (r"(?i)\bpg_(shadow|authid)\b|\brolpassword\b|\bmysql\.user\b|\bauthentication_string\b", "password hashes (SQL)"),
    (r"\bkubectl\b.*\bget\s+secrets?\b|\bvault\s+(kv\s+get|read)\b|\baws\s+(secretsmanager|ssm)\s+get", "secret store"),
]

# Site-specific additions (e.g. the API endpoints of your own apps that return keys), kept out of this file:
# a JSON list of [regex, label] pairs in $SECRET_GUARD_EXTRA (default ~/.config/secret-guard/extra.json).
def _load_extra():
    path = os.path.expanduser(os.environ.get("SECRET_GUARD_EXTRA", "~/.config/secret-guard/extra.json"))
    try:
        with open(path, encoding="utf-8") as f:
            pairs = [(rx, label) for rx, label in json.load(f)]
        for rx, _ in pairs:
            re.compile(rx)
        return pairs
    except FileNotFoundError:
        return []
    except Exception:
        return [(r"[\s\S]", "unreadable or invalid extra patterns file " + path)]   # fail closed on a broken config


RISKY += _load_extra()

# Files that the Read/Grep tools must not open directly.
SENSITIVE_FILES = "(" + "|".join(SECRET_PATHS) + r"|(^|/)id_(rsa|ed25519|ecdsa)[^/]*$)"   # .pub files are allowed below


# A secret typed into the command itself: the mask cannot help, the command is already in the transcript and the process list.
# Full-length values only, so `grep ghp_` or `grep -c AKIA` stay allowed. No marker opt-out.
LITERAL_SECRET = (r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"
                  r"|\b(sk-(ant-|proj-)?|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xox[abpr]-|hf_)[A-Za-z0-9_-]{20,}"
                  r"|\bAIza[0-9A-Za-z_-]{35}"
                  r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."
                  r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                  r"|\btskey-[A-Za-z0-9]+-[A-Za-z0-9-]{10,}")             # Tailscale auth and API keys

# A password written literally after the option or in the URL that carries it. "$VAR", "$(…)" and file: are fine.
VALUE = r"""['"]?(?![$'"\\<@/]|file:)"""      # "$VAR", \$VAR (nested quoting), <placeholder>, @file, /path, file: are not values
CLEAR_CREDENTIAL = (r"\b(?:curl|wget|http|https|xh)\b.*\s(?:-u|--user|--proxy-user|-U)(?:\s+|=)?['\"]?(?:\$\{?\w+\}?|[^\s:'\"$]+):"
                    + VALUE + r"[^\s'\"]+"
                    r"|\b(?:mysql|mariadb|mysqldump|mysqladmin)\b.*\s(?:-p|--password=)" + VALUE + r"[^\s'\"-][^\s'\"]*"
                    r"|\bsshpass\s+-p\s*" + VALUE + r"[^\s'\"]+"
                    r"|--auth-?key(?:\s+|=)" + VALUE + r"[^\s'\"]{8,}"
                    r"|\b[a-z][a-z0-9+.-]*://[^\s/:@$'\"]+:" + VALUE + r"[^\s/@'\"]+@"
                    r"|\b(?:PGPASSWORD|MYSQL_PWD|SSHPASS|REDISCLI_AUTH)=" + VALUE + r"[^\s'\"]+"
                    r"|(?:^|[\s;&|('\"])[A-Z0-9_]*(?:PASSWORD|PASSWD|_PASS|SECRET|TOKEN|API_?KEY|ACCESS_KEY)=" + VALUE + r"(?!\d+\b)[^\s'\"]{4,}"
                    r"|\bredis-cli\b.*\s(?:-a|--pass)\s+" + VALUE + r"[^\s'\"]+"
                    r"|\s--(?:password|passwd|pass|secret|token|api-?key|auth-token)(?:=|\s+)" + VALUE + r"[^\s'\"-][^\s'\"]{3,}"
                    r"|(?i:-H\s*['\"]?[\w-]*(?:authorization|api-?key|token|secret)[\w-]*\s*:\s*(?:bearer\s+|basic\s+|token\s+)?)"
                    + VALUE + r"(?!(?i:bearer|basic|token)\b)[^\s'\"]{6,}")

# Grep in content mode with a pattern that hunts for secrets prints the matching lines: refused.
SECRET_HUNT = r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|bearer|auth)"


def scan(cmd):
    """Split a shell command into top-level statements (on ; && || & and newlines), keeping pipelines intact.
    Returns (statements, trailing_comment, balanced).
    Quote-aware ('...', "...", backslash escapes) and group-aware: `{ ...
    }` and `( ... )` / `$( ... )` count as
    groups only where Bash treats them as such (a `{` that is a word at command position
    a `}` that is a word).
    Comments are dropped
    the last real comment is returned when nothing but whitespace follows it.
    Not a full Bash parser. When it loses track (unclosed quote or group), `balanced` is False and the caller
    treats the whole command as one unmasked statement."""
    stmts, cur, depth, i, n = [], [], 0, 0, len(cmd)
    quote, last_comment = None, None

    def at_command_start():
        t = "".join(cur).rstrip()
        return not t or t[-1] in ";&|({\n" or t.endswith(("&&", "||"))

    while i < n:
        c = cmd[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                cur.append(cmd[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            cur.append(c)
            cur.append(cmd[i + 1])
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
            cur.append(c)
            i += 1
            continue
        if c == "#" and (not cur or cur[-1] in " \t\n;&|(){}"):
            j = cmd.find("\n", i)
            j = n if j < 0 else j
            last_comment = cmd[i:j] if not cmd[j:].strip() else None
            i = j
            continue
        nxt = cmd[i + 1] if i + 1 < n else ""
        if c == "{" and nxt in " \t\n" and at_command_start():
            depth += 1
        elif c == "}" and depth > 0 and (not cur or cur[-1] in " \t\n;") and (nxt == "" or nxt in " \t\n;&|)>"):
            depth -= 1
        elif c == "(" and (at_command_start() or (cur and cur[-1] == "$")):
            depth += 1
        elif c == ")" and depth > 0:
            depth -= 1
        if depth == 0:
            two = cmd[i:i + 2]
            if two in ("&&", "||"):
                stmts.append("".join(cur))
                cur = []
                i += 2
                continue
            if c in ";\n" or (c == "&" and two != "&>" and (i == 0 or cmd[i - 1] not in ">&|")):
                stmts.append("".join(cur))
                cur = []
                i += 1
                continue
        cur.append(c)
        i += 1
    stmts.append("".join(cur))
    return [s.strip() for s in stmts if s.strip()], last_comment, (quote is None and depth == 0)


def split_statements(cmd):
    return scan(cmd)[0]


# Redirections that send output around the mask even when the statement ends in `2>&1 | mask`.
ESCAPES = r"(\d?>&\s*[2-9]\b|/dev/(tty|stderr|fd/[1-9])\b|/proc/self/fd/|>&-)"


def pipeline_stages(stmt):
    """Split one statement on top-level pipes, quote- and group-aware. Returns [(stage, joined_with_|&)]."""
    stages, cur, depth, quote, i, n = [], [], 0, None, 0, len(stmt)
    while i < n:
        c = stmt[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                cur.append(stmt[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            cur.append(c)
            cur.append(stmt[i + 1])
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
        elif c in "({":
            depth += 1
        elif c in ")}" and depth > 0:
            depth -= 1
        elif c == "|" and depth == 0 and stmt[i + 1:i + 2] != "|" and (i == 0 or stmt[i - 1] != "|"):
            amp = stmt[i + 1:i + 2] == "&"
            stages.append(("".join(cur), amp))
            cur = []
            i += 2 if amp else 1
            continue
        cur.append(c)
        i += 1
    stages.append(("".join(cur), False))
    return [(st.strip(), amp) for st, amp in stages]


def is_masked(stmt):
    """True if the statement's whole output ends in the mask filter, and every RISKY stage of the pipeline sends its
    stderr into the pipe too (`a 2>&1 | b | mask` is fine
    `a | b 2>&1 | mask` leaves a's errors on the terminal)."""
    stages = pipeline_stages(stmt)
    if len(stages) < 2 or stages[-1][0] != MASK_CMD:
        return False
    for stage, joined_amp in stages[:-1]:
        if re.search(ESCAPES, re.sub(r"2>&1\s*$", "", stage)):
            return False
        if risky_labels(stage) and not (joined_amp or re.search(r"2>&1\s*$", stage)):
            return False
    return True


COUNT_ONLY_GREP = re.compile(r"\b(grep|egrep|rg)\s+(-\w*[clLq]\w*\s+)")


def count_only(text):
    """Every reader in the statement is a grep/rg that only counts, lists names or tests."""
    readers = re.findall(r"\b(" + READERS + r")\b", text)
    return bool(readers) and all(r in ("grep", "egrep", "rg") for r in readers) and \
        len(COUNT_ONLY_GREP.findall(text)) >= len(readers)


def risky_labels(text):
    labels = [label for rx, label in RISKY if re.search(rx, text, re.I)]
    if count_only(text):                              # grep -c / -l / -q on a secret file prints no value
        labels = [x for x in labels if x != "file that may contain secrets"]
    return labels


def check_bash(cmd):
    """Return a refusal reason, or None if the command may run."""
    if re.search(LITERAL_SECRET, cmd) or re.search(CLEAR_CREDENTIAL, cmd):
        return ("secret-guard: this command contains a secret value in clear (API key, token, JWT, private key or password). "
                "Do not type secrets into commands: read them from a mode-600 file or the keychain into a variable, "
                "or pass a file (`-H @file`). If the value is already exposed, rotate it.")
    stmts, comment, balanced = scan(cmd)
    if comment and re.fullmatch(r"#\s*" + MARKER + r"\s*", comment.strip()):
        return None                                   # opt-out: a real shell comment, last thing in the command
    unmasked = [s for s in stmts if not is_masked(s)] if balanced else [cmd]
    hits = []
    for s in unmasked:
        hits += risky_labels(s)
    # loops and multi-line scripts spread a reader and its file over several statements (`for f in a.env; do cat $f`).
    # Judge them together; only statements whose producer (first stage) also sends stderr into the masked pipe are left out.
    def fully_masked(s):
        if not is_masked(s):
            return False
        first, amp = pipeline_stages(s)[0]
        return amp or bool(re.search(r"2>&1\s*$", first)) or first.startswith(("{", "("))
    loose = [s for s in stmts if not fully_masked(s)]
    joined = " ".join(loose if balanced else [cmd]).replace("\n", " ")
    # only the reader + file rule spans statements; other rules (e.g. `git … push`) would match across unrelated commands
    hits += [label for label in risky_labels(joined) if label == "file that may contain secrets"]
    if not hits:
        return None
    return ("secret-guard: this command may print a secret (" + ", ".join(dict.fromkeys(hits)) + "). "
            f"Re-run it with ALL output, errors included, through the mask: `<command> 2>&1 | {MASK_CMD}` "
            f"(group several commands: `{{ a; b; }} 2>&1 | {MASK_CMD}`; over ssh, put the mask on the local side). "
            f"If the output provably contains no values (grep -c/-q, sha256, key names only), end the command with `# {MARKER}`.")


def check_read(tool, tool_input):
    if (tool == "Grep" and tool_input.get("output_mode") == "content"
            and re.search(SECRET_HUNT, str(tool_input.get("pattern", "")), re.I)):
        return ("secret-guard: Grep in content mode for secret-like keys prints their values. Use output_mode "
                f"files_with_matches or count, or Bash with `2>&1 | {MASK_CMD}`.")
    values = [str(tool_input.get(k) or "").strip() for k in ("file_path", "path", "notebook_path", "glob")]
    hit = [v for v in values if v and re.search(SENSITIVE_FILES, v, re.I) and not v.endswith(".pub")]
    if not hit:
        return None
    return (f"secret-guard: {tool} on a file that may contain secrets ({', '.join(hit)[:120]}). "
            f"Use Bash with `2>&1 | {MASK_CMD}`, or list key names only (grep -o '^[A-Z_]*=').")


def decide(data):
    broken = [label for rx, label in RISKY if label.startswith("unreadable or invalid extra patterns")]
    if broken:                                        # fail closed everywhere until the config is fixed
        return "secret-guard: " + broken[0] + ". Fix it (or remove it) before continuing."
    tool = data.get("tool_name")
    ti = data.get("tool_input") or {}
    if tool == "Bash":
        return check_bash(ti.get("command", ""))
    if tool in ("Read", "Grep", "NotebookRead"):
        return check_read(tool, ti)
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    try:
        reason = decide(data)
    except Exception as e:                            # fail closed on an internal error
        reason = f"secret-guard: internal error ({type(e).__name__}); refusing to be safe. Fix the hook or its config."
    if reason:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": reason}}))
    sys.exit(0)


if __name__ == "__main__":
    main()

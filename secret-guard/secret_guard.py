#!/usr/bin/env python3
"""secret-guard: a Claude Code PreToolUse hook that stops an AI agent from printing secrets by accident.

Why: a written rule ("always mask output that may contain config") was broken 3 times in 2 days. Discipline became a
technical constraint.

Bash tool: a command that may print secrets is refused unless every statement that may print them sends stdout AND
stderr through a masking filter, e.g. `cmd 2>&1 | mask` or `{ a; b; } 2>&1 | mask`. When the output provably contains
no values (grep -c, sha256sum, key names only), the agent may end the command with the explicit marker `# secret-ok`.
That is a deliberate, visible, reviewable claim, not a silent bypass.

Read / Grep / NotebookRead tools: direct reads of files that typically hold secrets are refused.

Scope and limits: this guards against ACCIDENTAL disclosure by a cooperative agent. It is pattern-based and cannot be
complete. An adversary who controls the agent can get around it. Pair it with least privilege and keep secrets out of
the agent's reach.

Install: see README.md. Python 3.9+, standard library only. Input that is not valid JSON is let through (it is not a
tool call this hook can judge); an internal error or a broken extra-patterns file makes it refuse (fail closed).
"""
import json, os, re, sys

MASK_CMD = os.environ.get("SECRET_GUARD_MASK", "mask")
MARKER = "secret-ok"

# Commands that may print secret values. (regex, label)
RISKY = [
    (r"\bcrontab\s+-l\b", "crontab"),
    (r"\bdocker\s+(inspect|compose\s+config)\b|\bdocker\s+(exec|run)\b.*\b(env|printenv)\b", "Docker config / environment"),
    (r"(^|[\s;&|(])(env|printenv|set|export\s+-p|declare\s+-x)\s*($|[;&|)])", "environment variables"),
    (r"/proc/[^\s]*/(environ|cmdline)|\bps\s+(aux|-ef|e)\b", "process command lines / environment"),
    (r"\bsystemctl\s+(cat|show-environment|show)\b", "systemd units"),
    (r"\bgit\b.*\b(fetch|pull|push|clone|ls-remote)\b|\bgit\s+remote\s+-v\b|\bgit\s+config\b.*(url|credential)|\bgit\s+credential\b",
     "git (URLs with credentials, error messages)"),
    # a reader and a secret-looking path anywhere in the same statement, in either order (`for f in a.env; do cat $f`)
    (r"(?=.*\b(cat|tac|nl|less|more|head|tail|grep|egrep|rg|sed|awk|cut|sort|uniq|diff|jq|yq|xxd|od|strings|base64|bat|python3?|perl|ruby|node)\b)"
     r".*(\.env\b|\.env\.|config\.(xml|ya?ml|json)|compose\.ya?ml|credentials|\.netrc|rclone\.conf|\.cookie\b|secrets?\.(ya?ml|json|env|txt)\b|/secrets?/|\.git/config|"
     r"settings\.json|/etc/[a-z-]*\.env|\.pem\b|\.key\b|id_(rsa|ed25519|ecdsa)\b|\.kube/config|\.aws/|\.docker/config)",
     "file that may contain secrets"),
    # grepping for key formats prints the keys, unless only file names / counts / exit status are asked for
    (r"\b(grep|egrep|rg)\b(?!.*\s-[a-zA-Z]*[lLcq][a-zA-Z]*\b).*(sk-|AIza|ghp_|github_pat_|xox[abp]-|eyJ|PRIVATE KEY)", "search for key values"),
    (r"os\.environ\s*[)\]]|os\.environ\.(items|copy|values)\b|dict\(\s*os\.environ|process\.env\s*[)\];]", "environment variables (script)"),
    (r"\bpass\s+show\b|\b(pass-cli|gopass)\b.*\b(show|get|view)\b|\bop\s+(read|item\s+get)\b|\bbw\s+get\b"
     r"|(?<!\$\()\bsecurity\s+find-[a-z-]*password\b.*\s-[wg]\b", "password manager"),   # not when captured: X=$(security ...)
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
SENSITIVE_FILES = (r"((^|/)\.env($|\.)|\.env$|config\.xml$|rclone\.conf$|\.netrc$|credentials|\.cookie$|/etc/[^/]*\.env$|"
                   r"security\.json$|\.git/config$|(^|/)id_(rsa|ed25519|ecdsa)[^/]*$|\.pem$|\.key$|\.kube/config$|"
                   r"\.aws/credentials$|\.docker/config\.json$|secrets?\.(ya?ml|json|env)$|compose\.ya?ml$)")

# Grep in content mode with a pattern that hunts for secrets prints the matching lines: refused.
SECRET_HUNT = r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|bearer|auth)"


def scan(cmd):
    """Split a shell command into top-level statements (on ; && || & and newlines), keeping pipelines intact.
    Returns (statements, trailing_comment, balanced).
    Quote-aware ('...', "...", backslash escapes) and group-aware: `{ ...; }` and `( ... )` / `$( ... )` count as
    groups only where Bash treats them as such (a `{` that is a word at command position; a `}` that is a word).
    Comments are dropped; the last real comment is returned when nothing but whitespace follows it.
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
                cur.append(cmd[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1; continue
        if c == "\\" and i + 1 < n:
            cur.append(c); cur.append(cmd[i + 1]); i += 2; continue
        if c in ("'", '"'):
            quote = c; cur.append(c); i += 1; continue
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
                stmts.append("".join(cur)); cur = []; i += 2; continue
            if c in ";\n" or (c == "&" and two != "&>" and (i == 0 or cmd[i - 1] not in ">&|")):
                stmts.append("".join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1
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
                cur.append(stmt[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1; continue
        if c == "\\" and i + 1 < n:
            cur.append(c); cur.append(stmt[i + 1]); i += 2; continue
        if c in ("'", '"'):
            quote = c
        elif c in "({":
            depth += 1
        elif c in ")}" and depth > 0:
            depth -= 1
        elif c == "|" and depth == 0 and stmt[i + 1:i + 2] != "|" and (i == 0 or stmt[i - 1] != "|"):
            amp = stmt[i + 1:i + 2] == "&"
            stages.append(("".join(cur), amp)); cur = []; i += 2 if amp else 1; continue
        cur.append(c); i += 1
    stages.append(("".join(cur), False))
    return [(st.strip(), amp) for st, amp in stages]


def is_masked(stmt):
    """True if the statement's whole output ends in the mask filter, and every RISKY stage of the pipeline sends its
    stderr into the pipe too (`a 2>&1 | b | mask` is fine; `a | b 2>&1 | mask` leaves a's errors on the terminal)."""
    stages = pipeline_stages(stmt)
    if len(stages) < 2 or stages[-1][0] != MASK_CMD:
        return False
    for stage, joined_amp in stages[:-1]:
        if re.search(ESCAPES, re.sub(r"2>&1\s*$", "", stage)):
            return False
        if risky_labels(stage) and not (joined_amp or re.search(r"2>&1\s*$", stage)):
            return False
    return True


def risky_labels(text):
    return [label for rx, label in RISKY if re.search(rx, text, re.I)]


def check_bash(cmd):
    """Return a refusal reason, or None if the command may run."""
    stmts, comment, balanced = scan(cmd)
    if comment and re.fullmatch(r"#\s*" + MARKER + r"\s*", comment.strip()):
        return None                                   # opt-out: a real shell comment, last thing in the command
    unmasked = [s for s in stmts if not is_masked(s)] if balanced else [cmd]
    hits = []
    for s in unmasked:
        hits += risky_labels(s)
    # loops and multi-line scripts spread a reader and its file over several statements (`for f in a.env; do cat $f`)
    hits += risky_labels(" ".join(unmasked).replace("\n", " "))
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

#!/usr/bin/env python3
"""go-gate: a Claude Code hook that lets the agent change things only inside a plan the human approved with a GO.

Objective and limit: it catches the agent's MISTAKES (acting before the GO, or beyond what was approved). It is not a
sandbox against an agent that tries to get around it; least privilege is that barrier. Default mode: observe.

How to read this file, top to bottom:
  1. The classifier: is a tool call a safe read, or a change that needs a GO?
  2. The hook: plan (scope line) → human GO → actions inside the scope. main() is the hook entry point.

Classifier.

Default deny: a Bash command is a read only if EVERY stage of EVERY statement is a known read-only command, with no
writing option and no redirection to a file outside the scratch areas. Wrappers whose inner command is a literal
string (ssh host '…', pct exec N -- …, docker exec c …, bash -c '…') are unwrapped and judged on that inner command.
Anything opaque (python -c, running a script, eval, variables as commands) is a change.

classify(tool_name, tool_input) -> (kind, detail) with kind in {"read", "talk", "change", "opaque"}.
"""
import importlib.util, os, re, shlex, sys


def _load_splitter():
    """Reuse secret-guard's quote/group-aware shell splitter: next to this file, in ../secret-guard, or the hook."""
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "secret_guard.py"), os.path.join(here, "..", "secret-guard", "secret_guard.py"),
                 os.path.join(here, "secret-guard.py"), os.path.expanduser("~/.claude/hooks/secret-guard.py")):
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location("secret_guard", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.scan, mod.pipeline_stages
    raise ImportError("go-gate needs secret_guard.py (from secret-guard/) next to it")


try:
    scan, pipeline_stages = _load_splitter()
except Exception:            # loaded again in main(), where a failure is caught: refused in block mode, not let through
    scan = pipeline_stages = None

SCRATCH = (r"^(/tmp/|/private/tmp/|/var/folders/|/dev/null$|/dev/stdout$|/dev/stderr$)")

# Read-only commands, with the options that would make them write (or run something).
READ_CMDS = {
    "ls": None, "cat": None, "tac": None, "nl": None, "head": None, "tail": None, "less": None, "more": None,
    "grep": None, "egrep": None, "fgrep": None, "rg": None, "wc": None, "cut": None, "tr": None, "column": None,
    "jq": None, "yq": None, "diff": None, "cmp": None, "comm": None, "stat": None, "file": None, "du": None,
    "df": None, "ps": None, "pgrep": None, "top": None, "free": None, "uptime": None, "date": None, "cal": None,
    "echo": None, "printf": None, "true": None, "false": None, "test": None, "[": None, "sleep": None,
    "pwd": None, "whoami": None, "id": None, "hostname": None, "uname": None, "which": None, "type": None,
    "basename": None, "dirname": None, "realpath": None, "readlink": None, "seq": None,
    "md5": None, "md5sum": None, "shasum": None, "sha256sum": None, "base64": None, "xxd": None, "od": None,
    "strings": None, "fold": None, "fmt": None, "paste": None, "join": None, "expr": None, "bc": None,
    "mask": None, "env": None, "printenv": None, "lsof": None, "ss": None, "netstat": None, "ip": None,
    "dig": None, "host": None, "nslookup": None, "ping": None, "traceroute": None,
    "lsblk": None, "blkid": None, "mount": None, "findmnt": None, "nproc": None, "lscpu": None, "sensors": None,
    "nvidia-smi": None, "smartctl": None, "journalctl": None, "dmesg": None, "last": None, "w": None,
    "sw_vers": None, "system_profiler": None, "sysctl": None, "vm_stat": None, "diskutil": None,
    "pmset": None, "defaults": None, "plutil": None, "mdfind": None, "openssl": None, "unzip": None,
    "tar": None, "zcat": None, "gzip": None, "awk": None, "sed": None, "sort": None, "uniq": None,
    "find": None, "tee": None, "xargs": None, "cd": None, "export": None, "set": None, "unset": None,
    "local": None, "read": None, "wait": None, "exit": None, "return": None, "break": None, "continue": None,
    "shift": None, "source": None, ".": None, "umask": None, "firecrawl": None,
}
# Shell keywords that only frame other statements.
KEYWORDS = {"do", "done", "then", "else", "elif", "fi", "if", "while", "until", "for", "in", "case", "esac",
            "function", "!", "{", "}", "(", ")", "select", ";;"}
PREFIXES = {"sudo", "time", "nohup", "nice", "ionice", "stdbuf", "caffeinate", "env"}

GIT_READ = {"status", "log", "diff", "show", "rev-parse", "ls-files", "ls-remote", "ls-tree", "blame", "grep",
            "describe", "shortlog", "reflog", "cat-file", "for-each-ref", "fetch", "check-ignore", "count-objects",
            "name-rev", "merge-base", "version", "help"}
DOCKER_READ = {"ps", "images", "inspect", "logs", "stats", "version", "info", "top", "port", "diff", "events",
               "history", "search"}
DOCKER_SUB_READ = {("network", "ls"), ("network", "inspect"), ("volume", "ls"), ("volume", "inspect"),
                   ("image", "ls"), ("image", "inspect"), ("container", "ls"), ("container", "inspect"),
                   ("compose", "ps"), ("compose", "config"), ("compose", "ls"), ("compose", "logs"),
                   ("compose", "images"), ("compose", "version"), ("system", "df"), ("context", "ls"),
                   ("buildx", "ls"), ("manifest", "inspect")}
SYSTEMCTL_READ = {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-timers", "list-unit-files",
                  "cat", "show", "list-dependencies"}
PCT_READ = {"list", "config", "status", "pending", "listsnapshot", "df", "cpusets", "help"}
QM_READ = {"list", "config", "status", "pending", "listsnapshot", "showcmd", "help"}
ZFS_READ = {"list", "get", "status", "iostat", "holds", "help", "version"}
PVE_READ_CMDS = {"pvesm": {"status", "list"}, "pvecm": {"status", "nodes"}, "pveversion": None,
                 "pvesh": {"get", "ls", "usage"}, "lxc-ls": None, "lxc-info": None, "zpool": ZFS_READ,
                 "zfs": ZFS_READ, "sanoid": {"--monitor-health", "--monitor-snapshots", "--monitor-capacity"},
                 "brew": {"list", "info", "outdated", "--version", "search", "deps", "leaves", "config", "doctor"},
                 "npm": {"ls", "list", "view", "outdated", "--version", "-v"}, "pip": {"list", "show", "freeze"},
                 "pip3": {"list", "show", "freeze"}, "apt": {"list", "show", "policy", "search"},
                 "apt-cache": None, "dpkg": {"-l", "-L", "-s", "--list", "-S"}, "crontab": {"-l"},
                 "launchctl": {"list", "print"}, "security": {"find-generic-password", "find-internet-password"},
                 "gh": {"--version", "status"}, "claude": {"--version", "-v"}, "node": {"--version", "-v"},
                 "python3": {"--version", "-V"}, "python": {"--version", "-V"}, "perl": {"-v"},
                 "pass-cli": {"item", "vault", "--version"}, "kubectl": {"get", "describe", "logs", "version"},
                 "wg": {"show"}, "tailscale": {"status", "ip", "version"}, "spctl": {"--status", "-a"},
                 "csrutil": {"status"}, "fdesetup": {"status"}, "softwareupdate": {"--list", "-l", "--history"},
                 "mdutil": {"-s"}, "tmutil": {"listbackups", "status", "latestbackup", "destinationinfo"},
                 "log": {"show"}, "ioreg": None, "codesign": {"-d", "-dv", "--verify", "-v"}, "mdls": None,
                 "xattr": {"-l", "-p"}, "csvlook": None, "say": None, "osascript": set()}


EXPANDED_BODIES = []          # bodies of unquoted heredocs, whose $( … ) the shell runs; filled by strip_heredocs


def strip_heredocs(cmd):
    """Drop heredoc bodies (they are data for the command, not commands). Returns (cmd_without_bodies, bodies)."""
    out, bodies, lines, i = [], [], cmd.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        delims = re.findall(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        i += 1
        for quote, d in delims:
            body = []
            while i < len(lines) and lines[i].strip() != d:
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append("\n".join(body))
            if not quote:                                    # unquoted delimiter: the shell expands the body
                EXPANDED_BODIES.append(bodies[-1])
    return "\n".join(out), bodies


def subst_bodies(s):
    """Inner commands of $( … ) and backticks, so they are judged too."""
    res, i = [], 0
    while True:
        j = s.find("$(", i)
        if j < 0:
            break
        depth, k = 1, j + 2
        while k < len(s) and depth:
            depth += {"(": 1, ")": -1}.get(s[k], 0)
            k += 1
        res.append(s[j + 2:k - 1])
        i = k
    res += re.findall(r"`([^`]*)`", s)
    return res


def write_targets(tokens):
    """Files a stage writes through redirections. 2>&1, >&2 and here-strings are not files."""
    targets = []
    for i, t in enumerate(tokens):
        m = re.fullmatch(r"(\d*|&)(>>?|>\|)(.*)", t)
        if not m or t.endswith(("&1", "&2")) or re.fullmatch(r"\d*>&\d", t):
            continue
        target = (m.group(3) or (tokens[i + 1] if i + 1 < len(tokens) else "")).rstrip(";)&|")
        if target in ("&1", "&2", ""):
            continue
        targets.append(target)
    return targets


def is_scratch(path):
    p = os.path.expanduser(path.strip("'\""))
    if ".." in p:
        p = os.path.normpath(p)
    return bool(re.search(SCRATCH, p)) or "/scratchpad/" in p or p.startswith("$TMPDIR")


def classify_stage(stage, depth, bodies=()):
    """Kind of one pipeline stage: read / change / opaque, with a short reason. `bodies`: its heredoc bodies."""
    stage = stage.strip()
    if not stage:
        return "read", ""
    grp = re.fullmatch(r"([({])(.*)([)}])((?:\s*\d*(?:>>?|>&|<)\s*\S+)*)\s*", stage, re.S)
    if grp:                                               # { …; } or ( … ), possibly followed by redirections
        for tgt in write_targets(re.findall(r"\S+", grp.group(4))):
            if not is_scratch(tgt):
                return "change", f"writes {tgt[:40]}"
        return classify_bash(grp.group(2), depth + 1)
    try:
        toks = shlex.split(stage, comments=False, posix=True)
    except ValueError:
        return "opaque", "unparsable"
    # redirections: the words around > are glued or separate; handle both
    unquoted = re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", "Q", stage)
    raw = re.findall(r"\S+", unquoted)
    for tgt in write_targets(raw):
        if not is_scratch(tgt):
            return "change", f"writes {tgt[:40]}"
    toks = [t for t in toks if not re.fullmatch(r"\d*[<>]+&?\d*|&>>?|\d*>>?\S+|<<<?-?\S*", t)]
    if toks and toks[0] in ("for", "select", "case"):
        return "read", ""
    while toks and (toks[0] in KEYWORDS or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[0])):
        toks = toks[1:]
    while toks and toks[0] in PREFIXES:
        toks = toks[1:]
        while toks and (toks[0].startswith("-") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*|\d+[smh]?", toks[0])):
            toks = toks[1:]
    if not toks:
        return "read", ""
    c, args = os.path.basename(toks[0]), toks[1:]
    if c.startswith("$") or c == "eval" or c == "exec":
        return "opaque", c
    if c == "command" or c == "builtin":
        if not args or args[0] in ("-v", "-V"):
            return "read", ""
        rest = args[1:] if args[0] == "-p" else args
        return classify_stage(" ".join(shlex.quote(a) for a in rest), depth + 1, bodies)
    if c == "trap":
        handlers = [a for a in args if not a.startswith("-")][:1]
        return classify_bash(handlers[0], depth + 1) if handlers else ("read", "")
    if c in ("bash", "sh", "zsh", "dash"):
        if "-c" in args and args.index("-c") + 1 < len(args):
            return classify_bash(args[args.index("-c") + 1], depth + 1)
        if any(a in ("-n", "--version") for a in args):
            return "read", ""
        return "opaque", f"{c} script"
    if c in ("python3", "python", "node", "perl", "ruby", "osascript", "php"):
        if args and args[0] in ("--version", "-V", "-v"):
            return "read", ""
        if args[:2] == ["-m", "py_compile"]:
            return "read", ""
        if args[:2] == ["-m", "json.tool"] or args[:1] == ["-mjson.tool"]:
            files = [a for a in args[(2 if args[0] == "-m" else 1):] if not a.startswith("-")]
            return ("change", "json.tool output file") if len(files) >= 2 and not is_scratch(files[1]) else ("read", "")
        if c in ("python3", "python") and "-c" in args and args.index("-c") + 1 < len(args):
            return python_kind(args[args.index("-c") + 1])
        if c in ("python3", "python") and args[:1] == ["-"] and bodies:
            return python_kind(bodies[0])
        if c in ("python3", "python") and args and os.path.isfile(os.path.expanduser(args[0])):
            try:
                return python_kind(open(os.path.expanduser(args[0])).read())
            except OSError:
                pass
        return "opaque", f"{c} {args[0][:20] if args else ''}"
    if c == "ssh":
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("-i", "-p", "-o", "-l", "-J", "-F", "-L", "-R", "-D", "-W", "-b", "-c", "-E",
                                  "-m", "-O", "-Q", "-S", "-w", "-B", "-e") else 1
        rest = args[i + 1:]
        if not rest:
            return "change", "interactive ssh"
        return classify_bash(" ".join(rest) if len(rest) > 1 else rest[0], depth + 1)
    if c == "pct" or c == "qm":
        sub = args[0] if args else ""
        if sub == "exec" and "--" in args:
            inner = args[args.index("--") + 1:]
            return classify_bash(" ".join(shlex.quote(a) for a in inner) if len(inner) > 1 else (inner[0] if inner else ""), depth + 1)
        if sub in ("pull", "push") and len(args) >= 4 and is_scratch(args[3]):
            return "read", ""
        return ("read", "") if sub in (PCT_READ if c == "pct" else QM_READ) else ("change", f"{c} {sub}")
    if c == "docker":
        a = [x for x in args if not x.startswith("-")]
        sub = a[0] if a else ""
        if sub == "exec":
            j = 1
            while j < len(args) and args[j].startswith("-"):
                j += 2 if args[j] in ("-u", "-w", "-e", "--user", "--workdir", "--env") else 1
            inner = args[j + 1:]
            if not inner:
                return "change", "docker exec"
            return classify_bash(" ".join(shlex.quote(x) for x in inner) if len(inner) > 1 else inner[0], depth + 1)
        if sub in DOCKER_READ or tuple(a[:2]) in DOCKER_SUB_READ:
            return "read", ""
        if tuple(a[:2]) in (("compose", "up"), ("compose", "pull"), ("compose", "down")) and "--dry-run" in args:
            return "read", ""
        return "change", f"docker {' '.join(a[:2])}"
    if c == "git":
        j = 0
        while j < len(args) and args[j].startswith("-"):
            j += 2 if args[j] in ("-C", "-c", "--git-dir", "--work-tree") else 1
        sub = args[j] if j < len(args) else ""
        rest = args[j + 1:]
        if any(a in ("-c", "--config-env") or a.startswith(("--config-env=", "--exec-path")) for a in args[:j]):
            return "change", "git -c (config can run commands)"
        if any(a.startswith(("--output", "--ext-diff")) for a in rest):
            return "change", f"git {sub} --output/--ext-diff"
        if sub in GIT_READ:
            return "read", ""
        if sub == "branch" and all(x.startswith("-") and x in ("-a", "-r", "-v", "-vv", "--list", "--show-current", "-l") for x in rest):
            return "read", ""
        if sub == "remote" and (not rest or rest[0] in ("-v", "show", "get-url")):
            return "read", ""
        if sub == "config" and any(x in ("--get", "-l", "--list", "--get-all", "--show-origin") for x in rest):
            return "read", ""
        if sub == "tag" and (not rest or rest[0] in ("-l", "--list", "-n")):
            return "read", ""
        if sub == "stash" and rest[:1] in (["list"], ["show"]):
            return "read", ""
        return "change", f"git {sub}"
    if c == "systemctl":
        sub = next((x for x in args if not x.startswith("-")), "")
        return ("read", "") if sub in SYSTEMCTL_READ else ("change", f"systemctl {sub}")
    if c == "curl" or c == "wget":
        if any(is_action_url(a) for a in args if "://" in a) or \
                any(re.search(r"(?i)x-http-method(-override)?\s*:\s*(post|put|patch|delete)", a) for a in args):
            return "change", f"{c} to an action URL"
        if c == "wget":
            if any(x.startswith(("--post-data", "--post-file", "--method", "--body-data", "--body-file")) for x in args):
                return "change", "wget with body"
            stdout = False
            for k, x in enumerate(args):                     # "-O -" (stdout) or a scratch file is a read
                if x in ("-O", "--output-document"):
                    target = args[k + 1] if k + 1 < len(args) else ""
                elif re.fullmatch(r"-[a-zA-Z]*O.+", x):
                    target = x.split("O", 1)[1]
                elif x.startswith("--output-document="):
                    target = x.split("=", 1)[1]
                else:
                    continue
                if target != "-" and not is_scratch(target):
                    return "change", "wget -O file"
                stdout = True                                # stdout or a scratch file: nothing outside changes
            return ("read", "") if stdout else ("change", "wget download")
        for k, a in enumerate(args):
            if re.fullmatch(r"-[a-zA-Z].+", a) and not a.startswith("--"):            # short options, grouped or with a value
                j = 1
                while j < len(a):
                    o = a[j]
                    if o in CURL_VALUE_OPTS:
                        val = a[j + 1:] or (args[k + 1] if k + 1 < len(args) else "")
                        if o == "X" and val.upper() not in ("GET", "HEAD"):
                            return "change", f"curl -X{val[:8]}"
                        if o in "dFT":
                            return "change", "curl with body"
                        if o in "ocD" and val != "-" and not is_scratch(val):
                            return "change", "curl writes a file"
                        break
                    if o == "O":
                        return "change", "curl -O"
                    j += 1
            if a in ("-c", "--cookie-jar") and k + 1 < len(args) and not is_scratch(args[k + 1]):
                return "change", "curl --cookie-jar"
            if a in CURL_FILE_OPTS and k + 1 < len(args) and args[k + 1] != "-" and not is_scratch(args[k + 1]):
                return "change", f"curl {a}"
            if a.split("=", 1)[0] in CURL_FILE_OPTS and "=" in a and a.split("=", 1)[1] != "-" \
                    and not is_scratch(a.split("=", 1)[1]):
                return "change", f"curl {a.split('=', 1)[0]}"
            if a.startswith("--cookie-jar=") and not is_scratch(a.split("=", 1)[1]):
                return "change", "curl --cookie-jar"
            if a.startswith("--request=") and a.split("=", 1)[1].upper() not in ("GET", "HEAD"):
                return "change", f"curl {a}"
            if a.startswith("--output=") and not is_scratch(a.split("=", 1)[1]):
                return "change", "curl --output"
            if a.startswith(("--data", "--form", "--upload-file", "--json")):
                return "change", "curl with body"
            if a in ("-X", "--request") and k + 1 < len(args) and args[k + 1].upper() not in ("GET", "HEAD"):
                return "change", f"curl {args[k + 1]}"
            if re.fullmatch(r"-X(?!GET|HEAD).+", a):
                return "change", f"curl {a}"
            if a in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-T",
                     "--upload-file", "--json") or re.match(r"--data|-d.|-F.", a):
                return "change", "curl with body"
            if a in ("-o", "--output") and k + 1 < len(args) and not is_scratch(args[k + 1]):
                return "change", "curl -o"
            if a in ("-O", "--remote-name"):
                return "change", "curl -O"
        return "read", ""
    if c in ("scp", "rsync"):
        dest = args[-1] if args else ""
        if c == "rsync" and any(a.startswith(("--remove-source", "--delete")) for a in args):
            return "change", "rsync removes files"
        return ("read", "") if is_scratch(dest.split(":", 1)[-1]) else ("change", f"{c} to {dest[:40]}")
    if c in ("cp", "mv", "ln", "install"):
        files = [a for a in args if not a.startswith("-")]
        return ("read", "") if files and is_scratch(files[-1]) and (c != "mv" or all(is_scratch(f) for f in files)) \
            else ("change", f"{c} to {files[-1][:40] if files else ''}")
    if c in ("rm", "rmdir", "mkdir", "touch", "chmod", "chown", "truncate", "mktemp"):
        files = [a for a in args if not a.startswith("-") and not re.fullmatch(r"[0-7]{3,4}|[ugoa]*[+-=][rwxXst]+", a)]
        return ("read", "") if c == "mktemp" or (files and all(is_scratch(f) for f in files)) else ("change", f"{c} {files[0][:40] if files else ''}")
    if c == "psql":
        sql = args[args.index("-c") + 1] if "-c" in args and args.index("-c") + 1 < len(args) else (bodies[0] if bodies else "")
        return ("read", "") if sql and re.match(r"\s*(select|with|\\d|show|explain|table)\b", sql, re.I) \
            and not re.search(r"\b(insert|update|delete|drop|alter|create|truncate|grant)\b", sql, re.I) else ("change", "psql")
    if c == "pct" and args[:1] == ["push"] and len(args) >= 4 and is_scratch(args[3]):
        return "read", ""
    if c in PVE_READ_CMDS:
        allowed = PVE_READ_CMDS[c]
        sub = args[0] if args else ""
        if allowed is None or sub in allowed or (not args and c not in ("osascript",)):
            return "read", ""
        return "change", f"{c} {sub}"
    if c in READ_CMDS:
        return classify_read_cmd(c, args, depth)
    return "change", f"unknown {c}"


PY_ACTS = re.compile(r"open\([^)]*['\"][wax+]|\.write(_text|_bytes)?\(|\bos\.(remove|unlink|rename|replace|system|"
                     r"makedirs|mkdir|rmdir|chmod|chown|symlink|popen|exec|spawn|kill|truncate)|\bshutil\.|"
                     r"\bsubprocess\b|\burllib\b|\brequests\b|\bhttpx\b|\baiohttp\b|\bhttp\.client|\bsocket\b|\bimportlib\b|\bexec\(|\beval\(|"
                     r"__import__|\.unlink\(|\.rename\(|\.mkdir\(|\.touch\(|\bsqlite3\b|\bpsycopg|json\.dump\(")


def python_kind(code):
    m = PY_ACTS.search(code)
    return ("change", f"python {m.group(0)[:20]}") if m else ("read", "")


ACTION_ANYWHERE = {"webhook", "webhook-test", "hook", "hooks", "trigger", "triggers"}
ACTION_LAST = {"run", "exec", "execute", "restart", "reboot", "shutdown", "start", "stop", "delete", "remove", "purge",
               "reset", "refresh", "scan", "rescan", "sync", "import", "deploy", "update", "upgrade", "install", "command"}


def is_action_url(arg):
    """A GET that can change state: a webhook or trigger anywhere in the path, an action word as the last path
    segment (/api/v1/restart, not /api/sync/status), or an action-style query parameter (?action=delete)."""
    m = re.search(r"://[^/\s?#]*(/[^\s?#]*)?(\?[^\s#]*)?", arg.strip("'\""))
    if not m:
        return False
    segs = [x.lower() for x in (m.group(1) or "").split("/") if x]
    if any(x in ACTION_ANYWHERE for x in segs) or (segs and segs[-1] in ACTION_LAST):
        return True
    return bool(re.search(r"[?&](action|cmd|command|op|do|method)=", m.group(2) or "", re.I))


CURL_VALUE_OPTS = set("XdFTocuHeAbxmwrKEyYzCPQD")  # curl short options that take a value
CURL_FILE_OPTS = {"--trace", "--trace-ascii", "--stderr", "-D", "--dump-header", "--libcurl", "--etag-save",
                  "--hsts", "--alt-svc"}                       # curl options whose value is a file it writes


def classify_read_cmd(c, args, depth):
    """Read-only commands that can still write or run something with the wrong option."""
    if c == "nvidia-smi" and any(re.match(r"-(pl|pm|ac|rac|r|e|c|lgc|rgc|lmc|rmc|-power-limit|-persistence-mode|-gpu-reset|"
                                          r"-ecc-config|-compute-mode|-applications-clocks|-lock|-reset)", a) for a in args):
        return "change", "nvidia-smi setting"
    if c == "smartctl" and any(re.match(r"-(s|o|S|t|X)$|--(smart|offlineauto|saveauto|test|abort|set)\b", a) for a in args):
        return "change", "smartctl setting/test"
    if c == "xxd" and any(re.fullmatch(r"-r\w*|-revert", a) for a in args) and \
            len([a for a in args if not a.startswith("-")]) >= 2:
        return "change", "xxd -r to a file"
    if c == "date" and any(a in ("-s", "--set") or a.startswith("--set=") or re.fullmatch(r"\d{6,12}(\.\d\d)?", a)
                           for a in args):
        return "change", "date -s"
    if c == "hostname" and [a for a in args if not a.startswith("-")]:
        return "change", "hostname set"
    if c == "dmesg" and any(re.fullmatch(r"-[a-zA-Z]*[cCDE][a-zA-Z]*|--clear|--read-clear|--console-\w+", a) for a in args):
        return "change", "dmesg clear/console"
    if c == "yq" and any(re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*|--inplace.*", a) for a in args):
        return "change", "yq -i"
    if c == "plutil" and args[:1] not in (["-p"], ["-lint"], ["-help"], ["-type"]):
        return "change", f"plutil {args[0] if args else ''}"
    if c == "journalctl" and any(a.startswith(("--vacuum", "--rotate", "--flush", "--relinquish", "--sync",
                                               "--setup-keys", "--update-catalog")) for a in args):
        return "change", "journalctl maintenance"
    if c == "jq" and any(a in ("--rawfile", "--slurpfile") for a in args):
        return "read", ""
    if c == "sed" and any(re.fullmatch(r"-[a-zA-Z]*i.*|--in-place.*", a) for a in args):
        return "change", "sed -i"
    if c == "sed" and any(re.search(r"(^|;|\s)w\s+\S|/w\s+\S|\be\b", a) for a in args if not a.startswith("-")):
        return "change", "sed w/e command"
    if c == "sort" and any(re.fullmatch(r"-o.*|--output.*", a) for a in args):
        return "change", "sort -o"
    if c == "uniq" and len([a for a in args if not a.startswith("-")]) >= 2:
        return "change", "uniq output file"
    if c == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf",
                                 "-fls") for a in args):
        return "change", "find action"
    if c == "awk" and any(re.search(r"system\s*\(|print[^;]*>\s*\"|\|\s*\"|getline", a) for a in args):
        return "change", "awk writes or runs"
    if c == "tee":
        files = [a for a in args if not a.startswith("-")]
        return ("read", "") if all(is_scratch(f) for f in files) else ("change", "tee to file")
    if c == "tar" and not any(re.fullmatch(r"-?[a-zA-Z]*t[a-zA-Z]*", a) or a == "--list" for a in args[:1]):
        return "change", "tar extract/create"
    if c == "unzip" and not any(a in ("-l", "-v", "-t", "-p", "-Z") for a in args):
        return "change", "unzip extract"
    if c == "ss" and any(re.fullmatch(r"-[a-zA-Z]*K[a-zA-Z]*|--kill", a) for a in args):
        return "change", "ss --kill"
    if c == "gzip" and not any(a in ("-l", "-t", "-c", "-cd", "-dc") for a in args):
        return "change", "gzip"
    if c == "openssl" and any(a in ("-out", "genrsa", "genpkey", "req") for a in args):
        return "change", "openssl writes"
    if c == "defaults" and args[:1] not in (["read"], ["read-type"], ["domains"], ["find"]):
        return "change", "defaults write"
    if c in ("source", "."):
        return "opaque", "source"
    if c == "xargs":
        j = 0
        while j < len(args) and args[j].startswith("-"):
            j += 2 if args[j] in ("-n", "-I", "-L", "-P", "-d", "-s", "-E") else 1
        inner = args[j:]
        return classify_stage(" ".join(shlex.quote(a) for a in inner), depth + 1) if inner else ("read", "")
    if c == "diskutil" and not (args[:1] in (["list"], ["info"]) or args[:2] == ["apfs", "list"]):
        return "change", "diskutil"
    if c == "pmset" and args[:1] not in (["-g"],):
        return "change", "pmset"
    if c == "mount" and args:
        return "change", "mount"
    if c == "sysctl" and any("=" in a or a == "-w" for a in args):
        return "change", "sysctl -w"
    if c == "ip" and any(a in ("add", "del", "delete", "set", "flush", "replace", "change") for a in args):
        return "change", "ip change"
    return "read", ""


CHANGES = []                  # every (kind, detail, stage) found by the last classify(); reset by classify()


def classify_bash(cmd, depth=0):
    if depth > 6:
        return "opaque", "nesting"
    EXPANDED_BODIES.clear()
    body_free, bodies = strip_heredocs(cmd)
    pending_bodies = list(bodies)
    expanded = list(EXPANDED_BODIES)
    worst = ("read", "")
    order = {"read": 0, "change": 1, "opaque": 2}
    inner = subst_bodies(body_free) + [x for b in expanded for x in subst_bodies(b)]
    stmts, _comment, balanced = scan(body_free)
    if not balanced:
        return "opaque", "unbalanced"
    for s in stmts:
        for stage, _amp in pipeline_stages(s):
            n = len(re.findall(r"<<-?\s*['\"]?[A-Za-z_]", stage))         # heredocs opened by this stage, in order
            mine, pending_bodies[:n] = pending_bodies[:n], []
            k = classify_stage(stage, depth, mine)
            if k[0] in ("change", "opaque"):
                CHANGES.append((k[0], k[1], stage))
            if order[k[0]] > order[worst[0]]:
                worst = k
    for i in inner:
        k = classify_bash(i, depth + 1)
        if order[k[0]] > order[worst[0]]:
            worst = k
    return worst


READ_TOOLS = {"Read", "Grep", "Glob", "WebFetch", "WebSearch", "ToolSearch", "TaskOutput", "AskUserQuestion",
              "ListAgents", "ReadNotifications", "BashOutput", "LS", "TodoWrite", "TaskList", "TaskGet",
              "ListMcpResourcesTool", "ReadMcpResourceTool", "ExitPlanMode", "EnterPlanMode", "Skill", "Agent", "Task",
              "SendMessage", "SendUserFile", "Monitor", "SendFeedback", "ReportFindings"}
TALK_TOOLS = re.compile(r"telegram__(reply|react|edit_message|download_attachment)$")
MCP_READ = re.compile(r"__(get|list|search|read|query|find|scrape|fetch|describe|status|map|check|resolve|guide|"
                      r"tabs_context|read_page|get_page_text|read_console|read_network|query-docs|resolve-library)")


BROWSER_READ_ACTIONS = {"screenshot", "scroll", "zoom", "hover", "wait", "mouse_move", "scroll_to"}
MEMORY_DIR = re.compile(r"^" + re.escape(os.path.expanduser("~/.claude/projects/")) + r"[^/]+/memory/")   # agent notes


def classify(tool, tool_input):
    CHANGES.clear()
    if tool.endswith("claude-in-chrome__computer"):
        a = tool_input.get("action", "")
        return ("read", "") if a in BROWSER_READ_ACTIONS else ("change", f"browser {a}")
    if re.search(r"claude-in-chrome__(navigate|tabs_create_mcp|tabs_close_mcp|find|resize_window|gif_creator)$", tool):
        return "read", ""
    if tool == "Bash":
        return classify_bash(tool_input.get("command", ""))
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if is_scratch(p) or MEMORY_DIR.match(os.path.expanduser(p)):
            return "read", "scratch or memory write"
        return "change", f"{tool} {p[-50:]}"
    if tool in READ_TOOLS:
        return "read", ""
    if TALK_TOOLS.search(tool):
        return "talk", ""
    if tool.startswith("mcp__") and MCP_READ.search(tool):
        return "read", ""
    return "change", tool


# ---------------------------------------------------------------------------------------------------------------
# The hook: plan → human GO → actions inside the plan's scope.
#
#   1. The agent ends a proposal with a scope line:
#        Scope: id=<short> ; targets=<hosts, services, paths…> ; actions=<edit,git,deploy,api,browser,delete,script,doc> ; ttl=<minutes>
#      ("Périmètre :" works too). The hook records it as the PENDING plan when it sees it in the agent's last message
#      (Stop event) or in a message the agent sends through a chat tool (PreToolUse on a "talk" tool).
#   2. A short human reply that starts with GO / OK / OUI / YES / VAS-Y, with no reservation, turns the pending plan
#      into the ACTIVE plan (UserPromptSubmit). "GO <id>" must name the pending plan. "stop" / "annule" / "cancel"
#      revokes it. Only the owner counts: terminal prompts, or channel messages whose user_id is in config owner_ids.
#   3. PreToolUse: reads and chat messages always pass. A change passes only if the active plan is unexpired and
#      covers it (its action category is listed, and when targets are listed, one of them appears in the call).
#      mode=observe (default): nothing is blocked, a would-block line is logged. mode=block: the call is denied.
# State and log live in ~/.claude/go-gate/ (override with GO_GATE_DIR). The log holds no message text and only the
# first words of commands, passed through the same secret patterns as secret-guard.
# ---------------------------------------------------------------------------------------------------------------
import fcntl, json, time

GATE_DIR = os.path.expanduser(os.environ.get("GO_GATE_DIR", "~/.claude/go-gate"))
DEFAULTS = {"mode": "observe", "owner_ids": [], "ttl_minutes": 120, "max_ttl_minutes": 240}
CATEGORIES = ("edit", "git", "deploy", "api", "browser", "delete", "script", "doc")
SCOPE_LINE = re.compile(r"^\W*(?:scope|p[ée]rim[èe]tre)\s*:\s*(.+)$", re.I | re.M)
AFFIRM = re.compile(r"^\s*(go|ok|okay|oui|yes|vas[- ]y)\b[\s!.]*(.*)$", re.I | re.S)
STRICT_GO = re.compile(r"^\s*(go|ok|okay|oui|yes|vas[- ]y)(?:\s+([\w.-]{1,40}))?\s*[!.]*\s*$", re.I)
RESERVATION = re.compile(r"\b(mais|sauf|seulement|uniquement|pas|only|but|except|without|sans|attends?|wait)\b|\?",
                         re.I)
REVOKE = re.compile(r"^\s*(?:(stop|annule|annuler|cancel)\b|(non|no)\s*[!.]*\s*$)", re.I)


def load_config():
    cfg = dict(DEFAULTS)
    try:
        cfg.update(json.load(open(os.path.join(GATE_DIR, "config.json"))))
    except FileNotFoundError:
        pass
    return cfg


def load_state():
    try:
        with open(os.path.join(GATE_DIR, "state.json")) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state):
    os.makedirs(GATE_DIR, mode=0o700, exist_ok=True)
    tmp = os.path.join(GATE_DIR, f".state.{os.getpid()}")
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, os.path.join(GATE_DIR, "state.json"))         # atomic


def log(rec):
    os.makedirs(GATE_DIR, mode=0o700, exist_ok=True)
    rec["at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(os.path.join(GATE_DIR, "log.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")


def redact(text, n=60):
    """First words of a command for the log, with anything secret-shaped removed BEFORE truncating."""
    t = re.sub(r"\s+", " ", str(text))
    t = re.sub(r"(?i)\b(AKIA|ASIA|sk-|ghp_|gho_|ghs_|github_pat_|glpat-|xox[abpr]-|hf_|AIza|eyJ)[A-Za-z0-9_.-]*", "<m>", t)
    value = r"""(?:'[^']*'?|"[^"]*"?|[^\s'"]+)"""                       # quoted (maybe cut) or bare
    t = re.sub(r"(?i)\b(bearer|basic|token)\s+" + value, r"\1 <m>", t)
    t = re.sub(r"(?i)((?:^|\s)(?:-u|--user|--password|--pass|-p)(?:\s+|=)?)" + value, r"\1<m>", t)  # -u user:pw, -uuser:pw, -pSecret
    t = re.sub(r"(?:^|(?<=[\s;&|(]))([A-Za-z_][A-Za-z0-9_]*=)" + value, r"\1<m>", t)   # every VAR=value assignment
    t = re.sub(r"(?<![\w/])([^\s:/@'\"]+:)[^\s@]+@(?=[\w.-])", r"\1<m>@", t)          # user:pw@host, also without a scheme
    t = re.sub(r"(?i)((token|key|secret|pass(word|wd)?|pwd|auth\w*|cookie|session|credential\w*)[\w-]*\s*[=:]\s*)" + value,
               r"\1<m>", t)
    t = re.sub(r"(?i)(://[^/\s:@]+:)[^@\s]+@", r"\1<m>@", t)                        # user:password@host
    t = re.sub(r"\b(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_=-]{24,}", "<m>", t)  # long opaque values
    return t[:n]


SAFE_WORD = re.compile(r"[\w./~+-]{1,60}")


def safe_words(text, n=60):
    """Text for the log and refusals, made of plain words only: anything with = : @ quotes or other
    punctuation becomes <…>, and so do long opaque words. Applied on top of redact()."""
    out = []
    for w in redact(text, 10 ** 6).split():
        if not SAFE_WORD.fullmatch(w) or (len(w) >= 20 and re.search(r"\d", w) and re.search(r"[A-Za-z]", w)):
            w = "<…>"
        if w == "<…>" and out and out[-1] == "<…>":
            continue
        out.append(w)
    return " ".join(out)[:n]


def command_words(stage):
    """The command and its subcommand, without arguments: 'docker compose', 'git push', 'curl'."""
    words = [w for w in stage.split() if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", w)]   # leading VAR=value dropped
    keep = [os.path.basename(words[0])] if words else []
    if len(words) > 1 and re.fullmatch(r"[a-z][a-z0-9-]{1,30}", words[1]):
        keep.append(words[1])
    return safe_words(" ".join(keep), 40)


def parse_scope(text):
    """The last scope line of an agent message, as a plan dict, or None."""
    lines = SCOPE_LINE.findall(text or "")
    if not lines:
        return None
    plan = {"targets": [], "actions": [], "ttl": None, "id": None}
    for part in re.split(r"\s*;\s*", lines[-1]):
        if "=" not in part:
            continue
        k, v = (x.strip() for x in part.split("=", 1))
        k = k.lower()
        vals = [x.strip() for x in re.split(r"[,\s]+", v) if x.strip()]
        if k in ("id",):
            plan["id"] = re.sub(r"[^\w.-]", "", v)[:40] or None
        elif k in ("targets", "cibles", "hôtes", "hotes", "hosts", "services", "chemins", "paths"):
            plan["targets"] += vals
        elif k in ("actions",):
            plan["actions"] += [a.lower() for a in vals]
        elif k in ("ttl", "durée", "duree"):
            m = re.match(r"(\d+)\s*(h|min|m)?", v)
            if m:
                plan["ttl"] = int(m.group(1)) * (60 if m.group(2) == "h" else 1)
    plan["actions"] = [a for a in plan["actions"] if a in CATEGORIES]
    return plan if plan["actions"] else None


def category(tool, tool_input, kind, detail):
    """Coarse category of a change, matched against the plan's actions."""
    if kind == "opaque":
        return "script"
    d = detail.lower()
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = (tool_input.get("file_path") or tool_input.get("notebook_path") or "").lower()
        return "doc" if re.search(r"\.(md|txt|rst)$", p) else "edit"
    if d.startswith("git"):
        return "git"
    if d.startswith(("docker", "pct", "qm", "systemctl", "zfs", "zpool", "apt", "brew", "npm", "pip", "kubectl")):
        return "deploy"
    if d.startswith(("curl", "wget", "psql", "mcp__")) or tool.startswith("mcp__"):
        return "browser" if "chrome" in tool else "api"
    if d.startswith("browser"):
        return "browser"
    if d.startswith(("rm", "rmdir", "truncate", "find action")):
        return "delete"
    if d.startswith(("python", "unknown", "bash script", "eval", "source")):
        return "script"
    return "edit"


def covers(plan, tool, tool_input, cat, text=None):
    """The plan lists this category and, if it names targets, one of them appears in the action's own text."""
    if cat not in plan.get("actions", []):
        return False
    targets = plan.get("targets") or []
    if not targets:
        return True
    blob = (text if text is not None else json.dumps(tool_input, ensure_ascii=False)).lower()
    return any(t.lower() in blob for t in targets)


def owner_message(prompt, cfg):
    """Text of a human prompt if it comes from the owner, else None. Channel messages carry user_id in their header."""
    m = re.match(r'\s*<channel\b([^>]*)>\s*(.*?)\s*(</channel>)?\s*$', prompt or "", re.S)
    if not m:
        return prompt                                          # terminal prompt: typed by the person at the keyboard
    uid = re.search(r'\buser_id="([^"]+)"', m.group(1))
    if uid and uid.group(1) in [str(x) for x in cfg.get("owner_ids", [])]:
        return m.group(2)
    return None


def on_prompt(data, cfg, state):
    text = owner_message(data.get("prompt", ""), cfg)
    if text is None:
        return
    pending, now = state.get("pending"), time.time()
    if REVOKE.match(text):
        had = state.pop("active", None) or state.pop("pending", None)
        state.pop("pending", None)
        if had:
            log({"event": "revoked"})
        return
    m = STRICT_GO.match(text)                  # only "GO" or "GO <plan id>": any other word means it is not plain
    if not m:
        if AFFIRM.match(text) and len(text.split()) <= 12:
            log({"event": "go-not-plain-ignored"})
        return
    if not pending:
        log({"event": "go-without-pending-plan"})
        return
    if m.group(2) and m.group(2) != pending.get("id"):
        log({"event": "go-for-another-plan-ignored"})
        return
    ttl = min(pending.get("ttl") or cfg["ttl_minutes"], cfg["max_ttl_minutes"])
    state["active"] = dict(pending, approved_at=now, expires=now + ttl * 60)
    state.pop("pending", None)
    log({"event": "approved", "plan": pending.get("id"), "ttl_min": ttl})
    plain = lambda xs: ", ".join(re.sub(r"[^\w./:@~+-]", "", x)[:60] for x in xs[:12]) + (" …" if len(xs) > 12 else "")
    pid = re.sub(r"[^\w.-]", "", pending.get("id") or "-")[:40]
    return (f"go-gate: the user's GO approved plan '{pid}' for {ttl} min. "
            f"Targets: {plain(pending.get('targets') or []) or 'any'}. Actions: {plain(pending.get('actions') or [])}. "
            "Start your reply by restating this in one line, so the user sees what the GO covers.")


def remember_scope(text, state):
    plan = parse_scope(text)
    if plan:
        state["pending"] = dict(plan, proposed_at=time.time())
        return True
    return False


def on_pre_tool(data, cfg, state):
    """Returns (decision, reason); decision in allow / deny."""
    tool, ti = data.get("tool_name", ""), data.get("tool_input") or {}
    kind, detail = classify(tool, ti)
    if kind == "talk":
        if remember_scope(str(ti.get("text", "")), state):
            log({"event": "plan-proposed", "plan": state["pending"].get("id")})
        return "allow", ""
    if kind == "read":
        return "allow", ""
    items = [(k, d, st) for k, d, st in CHANGES] if tool == "Bash" and CHANGES else [(kind, detail, None)]
    act = state.get("active")
    if act and act.get("expires", 0) < time.time():
        state.pop("active", None)
        act = None
    cat, ok = None, bool(act)
    for k, d, st in items:                              # every change in the call must be inside the plan
        cat, detail = category(tool, ti, k, d), d
        if not (act and covers(act, tool, ti, cat, st)):
            ok = False
            break
    if tool == "Bash":
        head = " ; ".join(dict.fromkeys(command_words(st) for _k, _d, st in items if st)) or "bash"
    else:
        head = safe_words(str(ti.get("file_path") or ti.get("url") or tool))
    detail = safe_words(detail, 40)
    log({"event": "allowed" if ok else ("would-block" if cfg["mode"] != "block" else "blocked"), "tool": tool,
         "category": cat, "detail": detail, "head": head[:80], "plan": act.get("id") if act else None})
    if ok or cfg["mode"] != "block":
        return "allow", ""
    why = (f"go-gate: this is a change ({cat}: {detail[:60]}) and no approved plan covers it. "
           "Propose the plan to the user, ending with a line 'Scope: id=… ; targets=… ; actions=" + cat + " ; ttl=…', "
           "and wait for their GO.")
    if act:
        why = f"go-gate: the approved plan '{act.get('id')}' does not cover this {cat} action ({detail[:60]}). Ask the user to extend it."
    return "deny", why


def main():
    cfg = None
    try:
        data = json.load(sys.stdin)
        cfg = load_config()
        global scan, pipeline_stages
        if pipeline_stages is None:
            scan, pipeline_stages = _load_splitter()
        os.makedirs(GATE_DIR, mode=0o700, exist_ok=True)
        lock = open(os.path.join(GATE_DIR, ".lock"), "w")
        fcntl.flock(lock, fcntl.LOCK_EX)                      # one read-modify-write at a time
        full = load_state()
        sessions = full.setdefault("sessions", {})
        for sid in [k for k, v in sessions.items() if v.get("touched", 0) < time.time() - 2 * 86400]:
            del sessions[sid]                                 # forget sessions idle for 2 days
        state = sessions.setdefault(str(data.get("session_id") or "no-session"), {})
        state["touched"] = time.time()
        ev = data.get("hook_event_name")
        decision, why, context = "allow", "", None
        if ev == "UserPromptSubmit":
            context = on_prompt(data, cfg, state)
        elif ev == "Stop":
            if remember_scope(data.get("last_assistant_message", ""), state):
                log({"event": "plan-proposed", "plan": state["pending"].get("id")})
        elif ev == "PreToolUse":
            decision, why = on_pre_tool(data, cfg, state)
        save_state(full)
        if context:
            notice = re.sub(r" Start your reply.*$", "", context)
            print(json.dumps({"systemMessage": notice,
                              "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": context}}))
        if decision == "deny":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                     "permissionDecisionReason": why}}))
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:                                       # fail closed in block mode, open in observe mode
        try:
            log({"event": "error", "error": type(e).__name__})
        except Exception:
            pass
        if (cfg or {}).get("mode") == "block" or (cfg is None and load_mode_safely() == "block"):
            print(f"go-gate: internal error ({type(e).__name__}); refusing to be safe.", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)


def load_mode_safely():
    try:
        return load_config().get("mode")
    except Exception:
        return "block"                                          # unreadable config: assume the strict mode


if __name__ == "__main__":
    main()

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
    "find": None, "tee": None, "xargs": None, "parallel": None, "cd": None, "export": None, "set": None, "unset": None,
    "local": None, "read": None, "wait": None, "exit": None, "return": None, "break": None, "continue": None,
    "shift": None, "source": None, ".": None, "umask": None, "firecrawl": None,
    "keeper-propose": None, "keeper-status": None,     # talk to keeperd over its socket; they cannot approve anything
}
# Directories whose programs are judged by their name when run by path (root-owned on a normal install).
TRUSTED_BIN_DIRS = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/libexec", "/usr/local/bin", "/opt/homebrew/bin",
                    "/usr/local/sbin", "/opt/agent-guardrails/bin"}
# Writing there plants a program that later runs under a familiar name: only a plan with `script` covers it.
EXEC_DIRS = re.compile(r"(?:^|[\s'\"=:>])(?:~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+|/root)/(?:\.local/)?bin/"
                       r"|/usr/local/s?bin/|/opt/homebrew/bin/|/opt/agent-guardrails/")
# Variables that change which program runs or what it loads: assigning them makes a command opaque.
# Pagers and hook-style vars (PAGER, LESSOPEN, GIT_PAGER, GIT_EXTERNAL_DIFF, GIT_SSH_COMMAND…) run a program the agent
# chose, so a "read" verb prefixed with one of them is not a read (same class as K1-K6).
# GIT_DIR / GIT_WORK_TREE only locate the repo (no exec), so they are NOT here: they route through the safe-repo check
# like -C/--git-dir, so `GIT_DIR=/safe/.git git status` stays a read. Every other GIT_* (GIT_PAGER, GIT_SSH_COMMAND,
# GIT_EXTERNAL_DIFF, GIT_CONFIG_*, …) runs a program or injects config, so it is opaque.
EXEC_VARS = re.compile(r"(?:PATH|BASH_ENV|ENV|CDPATH|IFS|PROMPT_COMMAND|PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|NODE_OPTIONS|"
                       r"PERL5LIB|PERL5OPT|RUBYOPT|PAGER|MANPAGER|LESSOPEN|LESSCLOSE|GIT_(?!DIR\b|WORK_TREE\b)\w+|"
                       r"LD_\w+|DYLD_\w+)(?:\+?=|$)")
# Shell keywords that only frame other statements.
KEYWORDS = {"do", "done", "then", "else", "elif", "fi", "if", "while", "until", "for", "in", "case", "esac",
            "function", "!", "{", "}", "(", ")", "select", ";;"}
PREFIXES = {"sudo", "time", "nohup", "nice", "ionice", "stdbuf", "caffeinate", "timeout", "watch", "setsid"}
# Shells and interpreters. When a launcher (xargs, parallel) feeds its input to one of these, or to a program by path,
# or to an unknown command, the launched command line is not visible, so the call is opaque (R2).
SHELL_INTERP = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox",
                "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "osascript", "lua", "tclsh",
                "awk", "gawk", "mawk", "sed", "env", "eval", "exec", "xargs", "parallel", "sudo", "ssh", "find"}

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
    """Inner commands of $( … ), <( … ), >( … ) and backticks, so they are judged too. Process substitutions
    `<(cmd)` / `>(cmd)` run their command just like `$(cmd)`, so an adversarial review (09/10) added them here."""
    res = []
    for opener in ("$(", "<(", ">("):
        i = 0
        while True:
            j = s.find(opener, i)
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
        # `>`, `>>`, `>|` and also `<>` / `N<>`, which open a file read-write and create it (K9).
        m = re.fullmatch(r"(\d*|&)(>>?|>\|)(.*)", t) or re.fullmatch(r"(\d*)(<>)(.*)", t)
        if not m or t.endswith(("&1", "&2")) or re.fullmatch(r"\d*>&\d", t):
            continue
        target = (m.group(3) or (tokens[i + 1] if i + 1 < len(tokens) else "")).rstrip(";)&|")
        if target in ("&1", "&2", ""):
            continue
        targets.append(target)
    return targets


def protected_paths():
    """The gate's state and config, the hooks and the Claude Code settings: no plan can cover writing them."""
    gate = os.path.expanduser(os.environ.get("GO_GATE_DIR", "~/.claude/go-gate"))
    return [os.path.realpath(x) for x in (gate, os.path.expanduser("~/.claude/hooks"),
            os.path.expanduser("~/.claude/settings.json"), os.path.expanduser("~/.claude/settings.local.json"),
            os.path.expanduser("~/.config/secret-guard"))]


def real(path):
    p = os.path.expanduser(path.strip("'\""))
    try:
        return os.path.realpath(p)                 # follows symlinks: /tmp/link -> ~/.claude/go-gate/state.json
    except (OSError, ValueError):
        return os.path.normpath(p)


def is_protected(path):
    r = real(path)
    return any(r == x or r.startswith(x + os.sep) for x in protected_paths())


def is_scratch(path):
    """External audit of v0.8 (07/10): judged on the real location, so a symlink in /tmp does not make its target scratch."""
    p = os.path.expanduser(path.strip("'\""))
    if ".." in p:
        p = os.path.normpath(p)
    if is_protected(p):
        return False
    textual = bool(re.search(SCRATCH, p)) or "/scratchpad/" in p or p.startswith("$TMPDIR")
    if not textual:
        return False
    r = real(p)
    return bool(re.search(SCRATCH, r)) or "/scratchpad/" in r or p.startswith("$TMPDIR")


KNOWN_VARS = {}               # literal assignments of the command being classified (NAME=value), set by classify()
# K6: repos where a git read verb is trusted (the agent cannot have planted a malicious repo-local config there).
# Empty by default: out of the box every git read is opaque. The installer / config fills this in (--safe-git-repo).
SAFE_GIT_REPOS = []
CWD = None                    # the directory Claude Code ran the tool in (set by main() from the hook input)
_CWD_UNKNOWN = object()       # effective cwd after a `cd` whose target cannot be resolved statically (R1)


def literal_assignments(cmd):
    """NAME=value with a literal value (no $, `, quotes around expansions): `F=~/.claude/settings.json`."""
    out = {}
    for name, val in re.findall(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=((?:'[^']*'|\"[^\"$`]*\"|[^\s;&|$`'\"()])+)", cmd):
        out.setdefault(name, val.strip("'\""))
    return out


def resolve_vars(word):
    return re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: KNOWN_VARS.get(m.group(1), m.group(0)), word)


def touches_protected(stage):
    """Gemini audit of v0.9 (07/10): `F=~/.claude/settings.json; echo x > $F` escaped the check. Every word of a
    changing stage is resolved (literal variables, ~, symlinks) and checked against the protected paths."""
    for w in re.findall(r"[^\s'\"<>|;&()]+", stage.replace(">", " ")):
        w = resolve_vars(w)
        if ("/" in w or w.startswith("~")) and "$" not in w and is_protected(w):
            return True
    return False


def _git_kind(args):
    """The git classification without the K6 repo check: read verbs are reads, everything else a change."""
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


def _git_repo_dir(args):
    """The directory git acts on: -C, --git-dir/--work-tree, the GIT_DIR assignment, else the hook's cwd (CWD)."""
    d = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-C", "--work-tree") and i + 1 < len(args):
            d = args[i + 1]; i += 2; continue
        if a == "--git-dir" and i + 1 < len(args):
            d = args[i + 1].rstrip("/").removesuffix("/.git") or "/"; i += 2; continue
        if a.startswith("--git-dir="):
            d = a.split("=", 1)[1].rstrip("/").removesuffix("/.git") or "/"; i += 1; continue
        if a.startswith("-C") and len(a) > 2:
            d = a[2:]; i += 1; continue
        i += 1
    d = d or KNOWN_VARS.get("GIT_DIR") or KNOWN_VARS.get("GIT_WORK_TREE")
    if d is not None and d is not _CWD_UNKNOWN:
        d = d.rstrip("/").removesuffix("/.git") or d        # GIT_DIR points at the .git; the repo is its parent
    if d is None:
        d = CWD
    if d is None or d is _CWD_UNKNOWN:
        return None                                       # cwd unknown (e.g. after `cd "$x"`): cannot vouch for the repo
    d = os.path.expanduser(d.strip("'\""))
    if not os.path.isabs(d):
        if CWD and CWD is not _CWD_UNKNOWN:
            d = os.path.join(CWD, d)
        else:
            return None
    try:
        return os.path.realpath(d)
    except (OSError, ValueError):
        return os.path.normpath(d)


def git_repo_is_safe(args):
    """True when git's target repo is one of SAFE_GIT_REPOS, or under one (a safe repo covers its sub-directories),
    with no nested repo between the two (R4): a `.git` below the declared root means a different repo, whose own
    config the agent may control, so the declared root does not vouch for it."""
    if not SAFE_GIT_REPOS:
        return False
    d = _git_repo_dir(args)
    if not d:
        return False
    for s in SAFE_GIT_REPOS:
        s = os.path.realpath(os.path.expanduser(s)).rstrip("/")
        if (d == s or d.startswith(s + os.sep)) and not _nested_git_between(s, d):
            return True
    return False


def _nested_git_between(s, d):
    """Is there a nested repo in (s, d]? Best effort: on a stat error the directory is skipped, so this never blocks
    the common case where keeperd cannot traverse the agent's tree (documented in design-keeper.md, Known limits)."""
    p = d
    while p != s and len(p) > len(s):
        try:
            if os.path.exists(os.path.join(p, ".git")):
                return True
        except OSError:
            pass
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return False


def _cd_target(stmt):
    """If a statement is a cd/pushd/popd, what it changes the cwd to: ('literal', path), or ('unknown',) when the
    target cannot be resolved statically (a variable, a substitution, `-`, `~`, no arg, or popd). Else None (R1)."""
    try:
        toks = shlex.split(stmt, comments=False, posix=True)
    except ValueError:
        return ("unknown",)
    while toks and toks[0] in ("builtin", "command"):
        toks = toks[1:]
    if not toks or toks[0] not in ("cd", "pushd", "popd"):
        return None
    if toks[0] == "popd":
        return ("unknown",)                               # we do not track the directory stack
    paths = [a for a in toks[1:] if a == "-" or not a.startswith("-")]
    if not paths:
        return ("unknown",)                               # `cd` with no path = home, which is not a declared repo
    t = paths[0]
    if t == "-" or t.startswith("~") or any(ch in t for ch in "$`*?"):
        return ("unknown",)
    return ("literal", t)


def _resolve_cd(base, target):
    """The cwd after `cd target` from `base` (which may be _CWD_UNKNOWN or None)."""
    if os.path.isabs(target):
        return os.path.realpath(target)
    if base is _CWD_UNKNOWN or base is None:
        return _CWD_UNKNOWN                               # a relative cd from an unknown base stays unknown
    return os.path.realpath(os.path.join(base, target))


def classify_stage(stage, depth, bodies=()):
    """Kind of one pipeline stage: read / change / opaque, with a short reason. `bodies`: its heredoc bodies."""
    k = _classify_stage(stage, depth, bodies)
    if k[0] in ("change", "opaque") and touches_protected(stage):
        return "change", "protected go-gate state, hooks or settings"
    return k


def _classify_stage(stage, depth, bodies=()):
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
        tgt = resolve_vars(tgt)
        if is_protected(tgt):
            return "change", "protected go-gate state, hooks or settings"
        if not is_scratch(tgt):
            return "change", f"writes {tgt[:40]}"
    # Drop an input redirection and its target file, so `cmd < file` does not leave `file` as a bogus argument of the
    # command (this leak let `xargs sh -c id < list` read; R2). `<>` is a write, already handled by write_targets above.
    pruned, skip = [], False
    for t in toks:
        if skip:
            skip = False
            continue
        if re.fullmatch(r"\d*<", t):                      # `<` / `0<` as its own token: the next token is its file
            skip = True
            continue
        pruned.append(t)
    toks = pruned
    toks = [t for t in toks if not re.fullmatch(r"\d*[<>]+&?\d*|&>>?|\d*>>?\S+|<<<?-?\S*|\d*<(?!>)\S+", t)]
    if toks and toks[0] in ("for", "select", "case"):
        return "read", ""
    while toks and (toks[0] in KEYWORDS or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[0])):
        if EXEC_VARS.match(toks[0]):
            return "opaque", "sets " + toks[0].split("=")[0]
        toks = toks[1:]
    while toks and toks[0] in PREFIXES:
        toks = toks[1:]
        while toks and (toks[0].startswith("-") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*|\d+[smh]?", toks[0])):
            toks = toks[1:]
    if not toks:
        return "read", ""
    c, args = os.path.basename(toks[0]), toks[1:]
    # Keeper review (08/10): a program run by path is judged by its name only when it sits in a system directory;
    # anywhere else (scratch, home, relative) it is whatever was put there. `/tmp/x/cat` and `~/bin/cat` are not cat.
    if "/" in toks[0] and os.path.dirname(real(toks[0])) not in TRUSTED_BIN_DIRS:
        return "opaque", f"program run by path {toks[0][-30:]}"
    if c in ("export", "declare", "typeset", "readonly", "local") and any(EXEC_VARS.match(a) for a in args):
        return "opaque", f"{c} of a variable that changes what runs"
    if c in ("alias", "hash", "enable") or re.fullmatch(r"[\w.-]+\s*\(\)", stage.split("{")[0].strip() or "-"):
        return "opaque", f"{c} redefines a command"
    if c.startswith("$") or c == "eval" or c == "exec":
        return "opaque", c
    if c == "command" or c == "builtin":
        if not args or args[0] in ("-v", "-V"):
            return "read", ""
        rest = args[1:] if args[0] == "-p" else args
        return classify_stage(" ".join(shlex.quote(a) for a in rest), depth + 1, bodies)
    if c == "env":
        # `env VAR=val cmd` is `VAR=val cmd`: apply the same dangerous-variable rule as a bare prefix (R3), and handle
        # -S (split-string: its argument is a whole command line), -u (unset, takes a value), -i and other flags.
        i = 0
        while i < len(args) and args[i].startswith("-"):
            a = args[i]
            if a in ("-S", "--split-string") and i + 1 < len(args):
                return classify_bash(args[i + 1], depth + 1)
            if a.startswith("-S") and len(a) > 2:
                return classify_bash(a[2:], depth + 1)
            if a.startswith("--split-string="):
                return classify_bash(a.split("=", 1)[1], depth + 1)
            i += 2 if a in ("-u", "--unset") else 1
        rest = args[i:]
        assigns = []
        while rest and re.fullmatch(r"[A-Za-z_]\w*=.*", rest[0]):
            assigns.append(rest[0]); rest = rest[1:]
        if any(EXEC_VARS.match(a) for a in assigns):
            return "opaque", "env sets a variable that changes what runs"
        if not rest:
            return "read", ""                              # `env` with no command prints the environment
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
        # K1: ssh can run a program on THIS machine before/independently of the remote command, through a config file
        # (-F) or a directive (ProxyCommand, LocalCommand, …). A jump/forward (-J/-W) also runs ssh locally. When any
        # of these is present the call is opaque; only then is it safe to judge the remote command as the kind.
        ssh_exec_opt = re.compile(r"(?i)^(proxycommand|proxyjump|localcommand|permitlocalcommand|knownhostscommand|"
                                  r"match)\b")
        i = 0
        while i < len(args) and args[i].startswith("-"):
            a = args[i]
            if a in ("-F", "-J", "-W"):
                return "opaque", "ssh local-exec option " + a
            if a == "-o" and i + 1 < len(args) and ssh_exec_opt.match(args[i + 1]):
                return "opaque", "ssh -o " + args[i + 1][:24]
            if a.startswith("-o") and ssh_exec_opt.match(a[2:]):          # glued -oProxyCommand=...
                return "opaque", "ssh " + a[:26]
            i += 2 if a in ("-i", "-p", "-o", "-l", "-J", "-F", "-L", "-R", "-D", "-W", "-b", "-c", "-E",
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
        k = _git_kind(args)
        # K6: a repo-local config (core.fsmonitor, core.pager, an alias !cmd, …) runs a program even on a read verb
        # like `git status`. Such a config is only dangerous in a repo the agent could have written, so a git read is
        # a read only in a repo declared safe (SAFE_GIT_REPOS, empty by default). Elsewhere it is opaque.
        if k[0] == "read" and not git_repo_is_safe(args):
            return "opaque", "git read in a repo not declared safe (SAFE_GIT_REPOS; K6)"
        return k
    if c == "systemctl":
        sub = next((x for x in args if not x.startswith("-")), "")
        return ("read", "") if sub in SYSTEMCTL_READ else ("change", f"systemctl {sub}")
    if c == "curl" or c == "wget":
        # K5: a config file can carry any directive (output, upload, request method), and wget -e runs a .wgetrc
        # directive. Neither is visible in the command, so the call is opaque.
        if c == "curl" and any(a in ("-K", "--config") or a.startswith("--config=") for a in args):
            return "opaque", "curl --config (file can carry any directive)"
        if c == "wget" and any(a in ("-e", "--execute", "--config") or a.startswith(("--execute=", "--config="))
                               for a in args):
            return "opaque", "wget -e/--config (runs wgetrc directives)"
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
                    if o == "K":                              # -K / grouped -sK: a config file (K5)
                        return "opaque", "curl -K (config file)"
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
        # K8: a SELECT can still write or run via a function (lo_export, pg_read_file, COPY …), and -f/-o/-L and the
        # \! \o \g \copy meta-commands read or run a file. A read is only every -c being a plain read query with none
        # of these, and no script/output file option.
        if any(a in ("-f", "--file", "-o", "--output", "-L", "--log-file") or
               a.startswith(("-f", "--file=", "-o", "--output=", "-L", "--log-file=")) for a in args):
            return "change", "psql -f/-o/-L file"
        sqls = [args[i + 1] for i, a in enumerate(args) if a == "-c" and i + 1 < len(args)] or ([bodies[0]] if bodies else [])
        if not sqls:
            return "change", "psql"                               # interactive or stdin: opaque intent, treat as change
        reject = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|lo_export|lo_import|"
                            r"pg_read_file|pg_read_binary_file|pg_ls_dir|pg_terminate_backend|pg_cancel_backend|"
                            r"pg_reload_conf|pg_rotate_logfile|dblink|set_config|nextval|setval)\b|\\!|\\o\b|\\g\b|\\copy\b",
                            re.I)
        ok = all(re.match(r"\s*(select|with|\\d|show|explain|table|values)\b", s, re.I) and not reject.search(s) for s in sqls)
        return ("read", "") if ok else ("change", "psql")
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


PY_PURE = {"json", "re", "sys", "math", "datetime", "collections", "itertools", "functools", "statistics", "csv",
           "base64", "hashlib", "textwrap", "string", "time", "decimal", "fractions", "pprint", "difflib", "unicodedata",
           "zoneinfo", "calendar", "operator", "typing", "dataclasses", "enum", "uuid", "ipaddress", "html", "shlex",
           "glob", "fnmatch", "argparse", "struct", "binascii", "secrets", "random", "copy", "heapq", "bisect"}
# open() is a read only with no mode or a literal read mode (council review of v0.9: `open(p, m)` or a variable mode writes)
PY_OPEN_WRITE = re.compile(r"\bopen\s*\((?:[^()]|\([^()]*\))*?,\s*(?!['\"](?:r|rb|rt|br|tr)['\"])[^)\s]"
                           r"|\bopen\s*\([^)]*\bmode\s*=\s*(?!['\"](?:r|rb|rt)['\"])|\bprint\s*\([^)]*\bfile\s*=\s*(?!sys\.(?:stdout|stderr)\b)")
PY_DYNAMIC = re.compile(r"\b(getattr|setattr|globals|locals|vars|compile|__builtins__|__dict__|breakpoint|input)\b")


def python_kind(code):
    """External audit of v0.8 (07/10): `from os import remove as r; r(...)` passed the action list. Python counts as a
    read only when every module it imports is pure (no file, process or network access) and it uses no dynamic access."""
    m = PY_ACTS.search(code) or PY_OPEN_WRITE.search(code)
    if m:
        return "change", f"python {m.group(0)[:20]}"
    mods = re.findall(r"^\s*from\s+([\w.]+)\s+import|^\s*import\s+([\w., ]+)", code, re.M)
    mods += re.findall(r"(?:;|\bexec\b)\s*from\s+([\w.]+)\s+import|;\s*import\s+([\w., ]+)", code)
    names = set()
    for a, b in mods:
        for x in (a or b).split(","):
            x = x.strip().split(" as ")[0].strip()
            if x in ("os.path", "posixpath"):          # path arithmetic only (Gemini audit of v0.9)
                continue
            if x:
                names.add(x.split(".")[0])
    impure = sorted(n for n in names if n not in PY_PURE)
    if impure:
        return "change", f"python import {impure[0]}"[:30]
    if PY_DYNAMIC.search(code):
        return "change", "python dynamic access"
    return "read", ""


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


CURL_VALUE_OPTS = set("XdFTocuHeAbxmwrEyYzCPQD")  # curl short options that take a value (K handled separately: config file)
CURL_FILE_OPTS = {"--trace", "--trace-ascii", "--stderr", "-D", "--dump-header", "--libcurl", "--etag-save",
                  "--hsts", "--alt-svc"}                       # curl options whose value is a file it writes


# ---------------------------------------------------------------------------------------------------------------
# awk / sed are read only when their program is a plain text transform. A program read from a FILE (-f), a pipe to a
# command, system()/getline/ENVIRON, or a write/exec command are not reads (K2/K3/K4). The blocklist that preceded this
# could never be complete, because the program is arbitrary code.
# ---------------------------------------------------------------------------------------------------------------
def _awk_program(args):
    """The inline awk program: the -e/--source fragments joined, or the first positional when there is no -e."""
    out, i, seen_e = [], 0, False
    while i < len(args):
        a = args[i]
        if a in ("-e", "--source") and i + 1 < len(args):
            out.append(args[i + 1]); seen_e = True; i += 2; continue
        if a.startswith("--source="):
            out.append(a.split("=", 1)[1]); seen_e = True; i += 1; continue
        if a.startswith("-e") and len(a) > 2:
            out.append(a[2:]); seen_e = True; i += 1; continue
        if a in ("-F", "-v") and i + 1 < len(args):
            i += 2; continue
        if a.startswith("-") and a != "--":
            i += 1; continue
        if a == "--":
            i += 1; continue
        if not seen_e:
            out.append(a)                      # first positional is the program (when no -e was given)
        break
    return " ".join(out)


# A single pipe (not ||), system()/getline/ENVIRON/close/fflush: awk runs a command -> opaque (script).
AWK_RUNS = re.compile(r"\bsystem\s*\(|\bgetline\b|\bENVIRON\b|\bclose\s*\(|\bfflush\s*\(|(?<!\|)\|(?!\|)")
# print/printf redirected to a file, or an append redirection: a write. `$3 > 100` (a comparison) is not matched,
# because a redirection target is a string, a variable or a path, never a bare number.
AWK_WRITES = re.compile(r">>|\bprintf?\b[^;{}\n]*>(?!=)\s*[\"'$/A-Za-z_]")


def _sed_script(args):
    """The sed script text: the -e/--expression fragments joined, or the first positional when there is no -e."""
    out, i, seen_e = [], 0, False
    while i < len(args):
        a = args[i]
        if a in ("-e", "--expression") and i + 1 < len(args):
            out.append(args[i + 1]); seen_e = True; i += 2; continue
        if a.startswith("--expression="):
            out.append(a.split("=", 1)[1]); seen_e = True; i += 1; continue
        if a.startswith("-e") and len(a) > 2:
            out.append(a[2:]); seen_e = True; i += 1; continue
        if a == "--":
            i += 1; continue
        if a.startswith("-"):
            i += 1; continue
        if not seen_e:
            out.append(a)
        break
    return "\n".join(out)


# sed `e` / `s///e` run a shell command (opaque); `w`/`W`/`s///w` write a file (change). `w`/`e` are matched only in
# command position (start, after ; { } or an address), so a `w` or `e` inside a regex or replacement does not count.
SED_EXEC = re.compile(r"(?:^|[;{}\s/0-9$,])e(?:[;\s]|$)|\bs(.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[0-9gpiImMe]*e\b", re.M)
SED_WRITE = re.compile(r"(?:^|[;{}\s])[wW]\s+\S|\bs(.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[0-9gpiImMe]*[wW]\s*\S", re.M)


def classify_read_cmd(c, args, depth):
    """Read-only commands that can still write or run something with the wrong option."""
    if c in ("awk", "gawk", "mawk"):
        if any(a in ("-f", "--file") or a.startswith("--file=") or re.fullmatch(r"-[a-zA-Z]*f", a) for a in args):
            return "opaque", "awk -f program file"
        prog = _awk_program(args)
        if AWK_RUNS.search(prog):
            return "opaque", "awk runs a command"
        if AWK_WRITES.search(prog):
            return "change", "awk writes a file"
        return "read", ""
    if c in ("sed", "gsed"):
        if any(re.fullmatch(r"-[a-zA-Z]*i.*|--in-place.*", a) for a in args):
            return "change", "sed -i"
        if any(a in ("-f", "--file") or a.startswith("--file=") or re.fullmatch(r"-[a-zA-Z]*f", a) for a in args):
            return "opaque", "sed -f program file"
        script = _sed_script(args)
        if SED_EXEC.search(script):
            return "opaque", "sed runs a command (e / s///e)"
        if SED_WRITE.search(script):
            return "change", "sed writes a file (w / s///w)"
        return "read", ""
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
    if c == "sort" and any(a.startswith("--compress-program") for a in args):
        return "opaque", "sort --compress-program runs a program"   # GNU sort execs it for temp files (R3)
    if c == "sort" and any(re.fullmatch(r"-o.*|--output.*", a) for a in args):
        return "change", "sort -o"
    if c == "uniq" and len([a for a in args if not a.startswith("-")]) >= 2:
        return "change", "uniq output file"
    if c == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf",
                                 "-fls") for a in args):
        return "change", "find action"
    if c == "tee":
        files = [a for a in args if not a.startswith("-")]
        return ("read", "") if all(is_scratch(f) for f in files) else ("change", "tee to file")
    if c == "tar" and any(a.startswith(("--to-command", "--use-compress-program", "-I", "--checkpoint-action",
                                        "--rsh-command")) for a in args):
        return "opaque", "tar runs a program"       # these options hand tar an arbitrary command to run
    if c == "tar" and not any(re.fullmatch(r"-?[a-zA-Z]*t[a-zA-Z]*", a) or a == "--list" for a in args[:1]):
        return "change", "tar extract/create"
    if c == "unzip" and not any(a in ("-l", "-v", "-t", "-p", "-Z") for a in args):
        return "change", "unzip extract"
    if c == "ss" and any(re.fullmatch(r"-[a-zA-Z]*K[a-zA-Z]*|--kill", a) for a in args):
        return "change", "ss --kill"
    if c == "gzip" and not any(a in ("-l", "-t", "-c", "-cd", "-dc") for a in args):
        return "change", "gzip"
    if c == "openssl" and any(a.startswith(("-engine", "-provider", "-config", "-conf")) for a in args):
        return "opaque", "openssl -engine/-provider/-config loads code or config"  # conf can load engines (R3)
    if c == "openssl" and any(a in ("-out", "genrsa", "genpkey", "req") for a in args):
        return "change", "openssl writes"
    if c == "defaults" and args[:1] not in (["read"], ["read-type"], ["domains"], ["find"]):
        return "change", "defaults write"
    if c in ("source", "."):
        return "opaque", "source"
    if c in ("less", "more", "most", "pg") and any(a.startswith("+") and "!" in a for a in args):
        return "opaque", "pager +!command runs a shell"     # `less +'!cmd' file` (adversarial review 09/10)
    if c in ("xargs", "parallel"):
        j = 0
        while j < len(args) and args[j].startswith("-"):
            # options that take a separate value; long forms use = so need no value token
            j += 2 if args[j] in ("-n", "-I", "-L", "-P", "-d", "-s", "-E", "-a", "--arg-file", "-i", "-j",
                                  "--jobs", "--max-args", "--max-procs", "--delimiter", "--max-chars", "-N") else 1
        inner = args[j:]
        if not inner:
            return "read", ""                              # xargs with no command just echoes
        launched = os.path.basename(inner[0])
        # R2: xargs/parallel append their input as arguments (or a replacement string) to the launched command. If that
        # command is a shell/interpreter, a program by path, or unknown, the real command line is not visible -> opaque.
        if "/" in inner[0] and os.path.dirname(real(inner[0])) not in TRUSTED_BIN_DIRS:
            return "opaque", f"{c} runs a program by path"
        if launched in SHELL_INTERP:
            return "opaque", f"{c} feeds input to {launched}"
        return classify_stage(" ".join(shlex.quote(a) for a in inner), depth + 1)
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
    global CWD
    saved_cwd, eff = CWD, CWD
    try:
        for s in stmts:
            CWD = eff                                     # R1: a git read is judged against the cwd a prior `cd` set
            for stage, _amp in pipeline_stages(s):
                n = len(re.findall(r"<<-?\s*['\"]?[A-Za-z_]", stage))     # heredocs opened by this stage, in order
                mine, pending_bodies[:n] = pending_bodies[:n], []
                k = classify_stage(stage, depth, mine)
                if k[0] in ("change", "opaque"):
                    CHANGES.append((k[0], k[1], stage))
                if order[k[0]] > order[worst[0]]:
                    worst = k
            cd = _cd_target(s)                            # follow cd/pushd/popd across statements of the same command
            if cd:
                eff = _CWD_UNKNOWN if cd[0] == "unknown" else _resolve_cd(eff, cd[1])
        for i in inner:
            CWD = eff
            k = classify_bash(i, depth + 1)
            if order[k[0]] > order[worst[0]]:
                worst = k
    finally:
        CWD = saved_cwd                                   # a cd inside a command does not leak to the caller
    return worst


READ_TOOLS = {"Read", "Grep", "Glob", "WebFetch", "WebSearch", "ToolSearch", "TaskOutput", "AskUserQuestion",
              "ListAgents", "ReadNotifications", "BashOutput", "LS", "TodoWrite", "TaskList", "TaskGet",
              "ListMcpResourcesTool", "ReadMcpResourceTool", "ExitPlanMode", "EnterPlanMode", "Skill", "Agent", "Task",
              "SendMessage", "SendUserFile", "Monitor", "SendFeedback", "ReportFindings"}
TALK_TOOLS = re.compile(r"telegram__(reply|react|edit_message|download_attachment)$")
MCP_READ = re.compile(r"__(get|list|search|read|query|find|scrape|fetch|describe|status|map|check|resolve|guide|"
                      r"tabs_context|read_page|get_page_text|read_console|read_network|query-docs|resolve-library)")


# External audit of v0.8 (07/10): `mcp__lab__get_and_delete_secret` was a read because it starts with get.
MCP_WRITE = re.compile(r"(delete|remove|drop|purge|destroy|write|update|upsert|create|insert|set|send|post|put|patch|exec|"
                       r"run|kill|reset|move|rename|upload|trash|revoke|rotate|restart|stop|start|deploy|apply|commit)", re.I)
def mcp_writes(method):
    """A write verb as a verb of the method name: its first word, or a word after and/then/or (`get_and_delete_x`).
    `get_commit` or `list_settings` name an object, not an action (Gemini audit of v0.9)."""
    words = [w.lower() for w in re.split(r"[_\-.]|(?<=[a-z])(?=[A-Z])", method) if w]
    verbs = words[:1] + [words[i + 1] for i, w in enumerate(words[:-1]) if w in ("and", "then", "or")]
    return any(MCP_WRITE.fullmatch(v) for v in verbs)


BROWSER_READ_ACTIONS = {"screenshot", "scroll", "zoom", "hover", "wait", "mouse_move", "scroll_to"}
MEMORY_DIR = re.compile(r"^" + re.escape(os.path.expanduser("~/.claude/projects/")) + r"[^/]+/memory/")   # agent notes


def classify(tool, tool_input):
    CHANGES.clear()
    KNOWN_VARS.clear()
    if tool == "Bash":
        KNOWN_VARS.update(literal_assignments(tool_input.get("command", "")))
    if tool.endswith("claude-in-chrome__computer"):
        a = tool_input.get("action", "")
        return ("read", "") if a in BROWSER_READ_ACTIONS else ("change", f"browser {a}")
    if re.search(r"claude-in-chrome__(navigate|tabs_create_mcp|tabs_close_mcp|find|resize_window|gif_creator)$", tool):
        return "read", ""
    if tool == "Bash":
        return classify_bash(tool_input.get("command", ""))
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if is_protected(p):
            return "change", "protected go-gate state, hooks or settings"
        if is_scratch(p) or MEMORY_DIR.match(os.path.expanduser(p)):
            return "read", "scratch or memory write"
        return "change", f"{tool} {p[-50:]}"
    if tool in READ_TOOLS:
        return "read", ""
    if TALK_TOOLS.search(tool):
        return "talk", ""
    if tool.startswith("mcp__") and MCP_READ.search(tool) and not mcp_writes(tool.rsplit("__", 1)[-1]):
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
DEFAULTS = {"mode": "observe", "owner_ids": [], "ttl_minutes": 120, "max_ttl_minutes": 240, "pending_minutes": 120,
            "safe_git_repos": []}
CATEGORIES = ("edit", "git", "deploy", "api", "browser", "delete", "script", "doc")
SCOPE_LINE = re.compile(r"^\W*(?:scope|p[ée]rim[èe]tre)\s*:\s*(.+)$", re.I | re.M)
AFFIRM = re.compile(r"^\s*(go|ok|okay|oui|yes|vas[- ]y)\b[\s!.]*(.*)$", re.I | re.S | re.A)
# re.A: an ASCII grammar, so `yeſ` (long s) or a Cyrillic O never count (external audit of v0.8)
STRICT_GO = re.compile(r"^\s*(go|ok|okay|oui|yes|vas[- ]y)(?:\s+([\w.-]{1,40}))?\s*[!.]*\s*$", re.I | re.A)
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
            plan["id"] = re.sub(r"[^A-Za-z0-9_.-]", "", v.encode("ascii", "ignore").decode())[:40] or None
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
    if d.startswith("protected"):
        return "protected"                     # not a plan category: never covered
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


GIT_EXEC_CONFIG_PATH = re.compile(r"(?:^|/)\.git/(?:config\b|hooks/|info/|modules/)|(?:^|/)\.gitmodules\b"
                                  r"|(?:^|/)\.gitattributes\b|(?:^|/)\.git/info/attributes\b")
GIT_EXEC_KEY = re.compile(r"(?i)\b(core\.(fsmonitor|pager|editor|sshcommand|hookspath|askpass)|sequence\.editor"
                          r"|alias\.[\w-]+|diff\.external|diff\.[\w.-]+\.(textconv|command)"
                          r"|filter\.[\w.-]+\.(process|clean|smudge)|credential\.helper|gpg\.([\w.-]+\.)?program"
                          r"|merge\.[\w.-]+\.driver|uploadpack\.|receive\.|include\.path|includeif\.)")


def touches_git_exec_surface(blob):
    """True when the action writes a repo's git-exec surface: a .git/config, a hook, .gitattributes/.gitmodules, or a
    `git config` that SETS an exec key (not --get/--list). Such a write arms code execution on a later read (R4)."""
    if GIT_EXEC_CONFIG_PATH.search(blob):
        return True
    if re.search(r"\bgit\b", blob) and re.search(r"\bconfig\b", blob) and GIT_EXEC_KEY.search(blob) \
            and not re.search(r"--get\b|--list\b|--show-origin\b|--get-all\b", blob):
        return True
    return False


def covers(plan, tool, tool_input, cat, text=None):
    """The plan lists this category and, if it names targets, one of them appears in the action's own text."""
    if cat not in plan.get("actions", []):
        return False
    blob0 = text if text is not None else json.dumps(tool_input, ensure_ascii=False)
    home_bin = re.escape(os.path.expanduser("~")) + r"/(?:\.local/)?bin/"
    if cat != "script" and "script" not in plan.get("actions", []) and (EXEC_DIRS.search(blob0 or "")
                                                                         or re.search(home_bin, blob0 or "")):
        return False                           # council review 08/10: an edit plan must not plant ~/bin/cat
    # R4: writing a repo's git-exec surface (.git/config, hooks, attributes, .gitmodules, or `git config` setting an
    # exec key) turns a later `git status` into code execution. It needs the same approval as running a program, so a
    # plan covers it only with actions=script.
    if cat != "script" and "script" not in plan.get("actions", []) and touches_git_exec_surface(blob0 or ""):
        return False
    targets = plan.get("targets") or []
    if not targets:
        return True
    blob = text if text is not None else json.dumps(tool_input, ensure_ascii=False)
    tokens = re.findall(r"[^\s'\"|;&<>()]+", blob)
    # K7: a target matches a whole token or a path segment, never a free substring, so targets=web no longer covers
    # `webserver`, `web-db` or `cobweb`.
    if not any(target_matches(t, tokens) for t in targets):
        return False
    # External audit of v0.8 (07/10): `docker restart db web` passed with targets=web. For verbs that take several
    # objects, every object must match a target.
    for objs in multi_objects(text or ""):
        if any(not any(target_matches(t, [o]) for t in targets) for o in objs):
            return False
    return True


def target_matches(t, tokens):
    """A plan target against the words of the action. A path target (with a /) matches a word equal to it or under it
    (a prefix covers its sub-paths, kept on purpose). A name target matches a whole word or one of its /@:,-free
    segments, never a substring."""
    t = t.strip("'\"").lower().rstrip("/")
    if not t:
        return False
    if "/" in t or t.startswith(("~", "./", "../")):
        tp = t if any(c in t for c in "*$") else real(t).lower()
        for tok in tokens:
            r = real(tok.strip("'\"")).lower()
            if r == tp or r.startswith(tp + "/"):
                return True
        return False
    for tok in tokens:
        tok = tok.strip("'\"").lower()
        if tok == t or t in re.split(r"[/@:,]+", tok):
            return True
    return False


MULTI_VERBS = re.compile(r"\b(docker(?:\s+compose)?|podman|systemctl|pct|qm|kubectl\s+delete\s+\w+)\s+"
                         r"(restart|stop|start|kill|rm|rmi|down|up|pull|destroy|shutdown|reboot|disable|enable|"
                         r"mask|reload|pause|unpause|delete)\b((?:\s+[^\s;&|]+)*)")


def multi_objects(text):
    """Objects named after a multi-object verb (options and their values left out)."""
    out = []
    for m in MULTI_VERBS.finditer(text):
        words, objs, skip = m.group(3).split(), [], False
        for w in words:
            if skip:
                skip = False
                continue
            if w.startswith("-"):
                skip = w in ("-f", "--file", "-t", "--time", "-p", "--project-name", "--timeout", "-n")
                continue
            objs.append(w.strip("'\""))
        if objs:
            out.append(objs)
    return out


def owner_message(prompt, cfg):
    """Text of a human prompt if it comes from the owner, else None. Channel messages carry user_id in their header."""
    m = re.match(r'\s*<channel\b([^>]*)>\s*(.*?)\s*(</channel>)?\s*$', prompt or "", re.S)
    if not m:
        return prompt                                          # terminal prompt: typed by the person at the keyboard
    uid = re.search(r'\buser_id="([^"]+)"', m.group(1))
    if uid and uid.group(1) in [str(x) for x in cfg.get("owner_ids", [])]:
        return m.group(2)
    return None


def channel_meta(prompt):
    """message_id and ts of a channel message header, when present."""
    m = re.match(r'\s*<channel\b([^>]*)>', prompt or "")
    if not m:
        return None, None
    mid = re.search(r'\bmessage_id="([^"]+)"', m.group(1))
    ts = re.search(r'\bts="([^"]+)"', m.group(1))
    return (mid.group(1) if mid else None), (ts.group(1) if ts else None)


def stale_channel_go(prompt, state, max_age=900):
    """External audit of v0.8 (07/10): a replayed or old channel message must not approve a plan. Refused when its
    message_id was already used, or its timestamp is older than the plan or than 15 minutes."""
    mid, ts = channel_meta(prompt)
    if mid is None and ts is None:
        return None                                            # terminal prompt
    if mid and mid in state.get("used_message_ids", []):
        return "go-message-already-used"
    if ts:
        import datetime
        try:
            t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return "go-message-without-valid-time"
        pending = state.get("pending") or {}
        if t < pending.get("proposed_at", 0) - 5 or t < time.time() - max_age:
            return "go-message-too-old"
        if t > time.time() + 120:                               # council review of v0.9: a GO dated in the future
            return "go-message-from-the-future"
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
    m = STRICT_GO.match(text) if text.isascii() else None   # only "GO" or "GO <plan id>", in plain ASCII
    if not m:
        if AFFIRM.match(text) and len(text.split()) <= 12:
            log({"event": "go-not-plain-ignored"})
        return
    if not pending:
        log({"event": "go-without-pending-plan"})
        return
    if now - pending.get("proposed_at", 0) > cfg["pending_minutes"] * 60:
        # External audit of v0.8 and real cases (06-07/10): a bare GO activated a plan proposed hours before.
        state.pop("pending", None)
        log({"event": "go-for-expired-plan-ignored", "plan": pending.get("id")})
        pid = re.sub(r"[^\w.-]", "", pending.get("id") or "-")[:40]
        return (f"go-gate: this GO was NOT applied: plan '{pid}' was proposed more than {cfg['pending_minutes']} min ago "
                "and has expired. Tell the user, and propose the plan again if it is still wanted.")
    if m.group(2) and m.group(2) != pending.get("id"):
        log({"event": "go-for-another-plan-ignored"})
        return
    stale = stale_channel_go(data.get("prompt", ""), state)
    if stale:
        log({"event": stale + "-ignored"})
        return
    mid, _ts = channel_meta(data.get("prompt", ""))
    if mid:
        state["used_message_ids"] = (state.get("used_message_ids", []) + [mid])[-200:]
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


def on_post_tool(data, state):
    """External audit of v0.8 (07/10): a plan is pending only once the human could read it. A chat tool call that failed
    (error, or no "sent" in its response) records nothing."""
    tool, ti = data.get("tool_name", ""), data.get("tool_input") or {}
    if not TALK_TOOLS.search(tool):
        return
    resp = data.get("tool_response")
    text = json.dumps(resp, ensure_ascii=False) if not isinstance(resp, str) else resp
    if re.search(r"(?i)\b(error|failed|denied)\b", text or "") or not re.search(r"(?i)\bsent\b|message_id|\bid\b", text or ""):
        log({"event": "plan-not-delivered"})
        return
    if remember_scope(str(ti.get("text", "")), state):
        mid = re.search(r"id:?\s*\"?(\d+)", text or "")
        state["pending"]["message_id"] = mid.group(1) if mid else None
        log({"event": "plan-proposed", "plan": state["pending"].get("id")})


def on_pre_tool(data, cfg, state):
    """Returns (decision, reason); decision in allow / deny."""
    tool, ti = data.get("tool_name", ""), data.get("tool_input") or {}
    kind, detail = classify(tool, ti)
    if kind == "talk":
        return "allow", ""                     # the plan is recorded in PostToolUse, once the message was delivered
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
        global scan, pipeline_stages, CWD
        if pipeline_stages is None:
            scan, pipeline_stages = _load_splitter()
        SAFE_GIT_REPOS[:] = cfg.get("safe_git_repos") or []        # K6: trusted repos for git read verbs
        CWD = data.get("cwd")                                      # the dir Claude Code ran the tool in
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
        elif ev == "PostToolUse":
            on_post_tool(data, state)
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

#!/usr/bin/env python3
"""keeper tier 0: known read-only verbs that need no card and no AI (docs/design-tiered-approval.md, section 2).

A closed table, matched on the EXACT SHAPE of a single command. A verb on the list is not enough: every flag must be on that
verb's list, no flag that opens a browser, writes, or sends a body; no redirection, substitution, environment prefix or
second command. Anything else is not tier 0 and goes through the normal plan flow, unchanged. Decided by plain code, never
by a model, and never widened by anything the agent writes.

What is covered: the read verbs of the GitHub CLI (`gh repo|issue|pr|run|release|workflow|label|search`) and `gh api` limited
to GET on a fixed set of endpoint families (repos, orgs, users, search, licenses, rate_limit). `git log/show/diff/status` in a declared safe repository already pass as reads
through the go-gate classifier and are not duplicated here.

Known limit: `gh` can run a program through its own configuration (`pager`, `editor`, `browser` keys, `GH_PAGER`); a
malicious pre-existing `gh` configuration is not detected here.

Standard library only. Python 3.9+.
"""
import re, shlex

REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
POSITIONAL = re.compile(r"[A-Za-z0-9_.:/@#-]{1,120}")
JSON_FIELDS = re.compile(r"[A-Za-z,]{1,300}")
DIGITS = re.compile(r"[0-9]{1,4}")
WORD = re.compile(r"[A-Za-z0-9_.:-]{1,60}")
FREE = re.compile(r"[^\x00]{0,300}")                     # a jq expression, a template, a search query: no shell is involved
ACCEPT_HEADER = re.compile(r"Accept:\s*[A-Za-z0-9/.+-]{1,80}")
API_ENDPOINT = re.compile(r"/?(?:repos|orgs|users|search|licenses|rate_limit)(?:[/?][A-Za-z0-9_.:@%=,+-]{0,200})*")

# value flags: name -> validator; boolean flags: a set. Short and long forms are listed separately.
COMMON_VALUE = {"--repo": REPO, "-R": REPO, "--json": JSON_FIELDS, "--jq": FREE, "-q": FREE, "--template": FREE, "-t": FREE}
LIST_VALUE = dict(COMMON_VALUE, **{"--limit": DIGITS, "-L": DIGITS, "--state": WORD, "-s": WORD, "--label": FREE, "-l": FREE,
                                   "--author": FREE, "-A": FREE, "--assignee": FREE, "-a": FREE, "--search": FREE, "-S": FREE,
                                   "--milestone": FREE, "-m": FREE, "--base": WORD, "-B": WORD, "--head": WORD, "-H": WORD,
                                   "--app": WORD, "--mention": WORD})
VIEW_VALUE = dict(COMMON_VALUE)
SEARCH_VALUE = dict(LIST_VALUE, **{"--owner": WORD, "--language": WORD, "--sort": WORD, "--order": WORD, "--match": WORD,
                                   "--visibility": WORD, "--created": FREE, "--updated": FREE, "--topic": FREE,
                                   "--extension": WORD, "--filename": FREE, "--size": FREE, "--stars": FREE, "--forks": FREE})
RUN_VALUE = dict(LIST_VALUE, **{"--workflow": FREE, "-w": FREE, "--branch": FREE, "-b": FREE, "--event": WORD, "-e": WORD,
                                "--status": WORD, "--user": WORD, "--job": DIGITS, "-j": DIGITS, "--commit": WORD, "-c": WORD})

# (command, subcommand) -> (value flags, boolean flags, max positionals). No `--web`/`-w` browser flag, nothing that writes.
GH = {
    ("repo", "view"): (dict(VIEW_VALUE, **{"--branch": FREE, "-b": FREE}), set(), 1),
    ("repo", "list"): (dict(LIST_VALUE, **{"--visibility": WORD, "--language": WORD, "--topic": FREE}),
                       {"--source", "--fork", "--archived", "--no-archived"}, 1),
    ("issue", "list"): (LIST_VALUE, set(), 0),
    ("issue", "view"): (VIEW_VALUE, {"--comments", "-c"}, 1),
    ("issue", "status"): (COMMON_VALUE, set(), 0),
    ("pr", "list"): (LIST_VALUE, {"--draft", "-d"}, 0),
    ("pr", "view"): (VIEW_VALUE, {"--comments", "-c"}, 1),
    ("pr", "status"): (COMMON_VALUE, set(), 0),
    ("pr", "diff"): (COMMON_VALUE, {"--patch", "--name-only"}, 1),
    ("pr", "checks"): (COMMON_VALUE, {"--required"}, 1),
    ("run", "list"): (RUN_VALUE, set(), 0),
    ("run", "view"): (RUN_VALUE, {"--log", "--log-failed", "--verbose", "-v", "--exit-status"}, 1),
    ("release", "list"): (LIST_VALUE, {"--exclude-drafts", "--exclude-pre-releases"}, 0),
    ("release", "view"): (VIEW_VALUE, set(), 1),
    ("workflow", "list"): (LIST_VALUE, {"--all", "-a"}, 0),
    ("workflow", "view"): (VIEW_VALUE, {"--yaml", "-y"}, 1),
    ("label", "list"): (LIST_VALUE, set(), 0),
    ("search", "issues"): (SEARCH_VALUE, set(), 5),
    ("search", "prs"): (SEARCH_VALUE, set(), 5),
    ("search", "repos"): (SEARCH_VALUE, set(), 5),
    ("search", "code"): (SEARCH_VALUE, set(), 5),
    ("search", "commits"): (SEARCH_VALUE, set(), 5),
}
GH_API_VALUE = {"--jq": FREE, "-q": FREE, "--template": FREE, "-t": FREE, "--cache": WORD, "-H": ACCEPT_HEADER,
                "--header": ACCEPT_HEADER, "-X": re.compile(r"GET"), "--method": re.compile(r"GET")}
GH_API_BOOL = {"--paginate", "--slurp", "-i", "--include"}


def _shell_safe(text):
    """True only if `text` is one simple command word list: no substitution, expansion, redirection, pipe, list, group,
    backslash or newline anywhere outside single quotes, and no `$` or backtick inside double quotes either."""
    state = None
    for ch in text:
        if ch in "\n\r\x00":                               # not even inside quotes
            return False
        if state == "'":
            if ch == "'":
                state = None
            continue
        if state == '"':
            if ch == '"':
                state = None
            elif ch in "$`\\":
                return False
            continue
        if ch in "'\"":
            state = ch
        elif ch in "$`\\<>|;&(){}\n\r":
            return False
    return state is None


def _check_flags(args, value_flags, bool_flags, max_pos, positional=POSITIONAL):
    """True if `args` are only listed flags with valid values plus at most `max_pos` plain positionals."""
    pos, i = 0, 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            name, eq, val = a.partition("=")
            if name in value_flags:
                if not eq:
                    i += 1
                    if i >= len(args):
                        return False
                    val = args[i]
                if not value_flags[name].fullmatch(val):
                    return False
            elif name in bool_flags and not eq:
                pass
            else:
                return False
        else:
            if not positional.fullmatch(a):
                return False
            pos += 1
            if pos > max_pos:
                return False
        i += 1
    return True


def match(stage):
    """The label of the known read this single command is, e.g. 'gh issue list', or None. `stage` is one simple command."""
    if not isinstance(stage, str) or len(stage) > 2000 or not _shell_safe(stage):
        return None
    try:
        toks = shlex.split(stage)
    except ValueError:
        return None
    if len(toks) < 2 or toks[0] != "gh":                    # exactly `gh`: no path, no env prefix, no wrapper
        return None
    if toks[1] == "api":
        args = toks[2:]
        endpoints = [a for a in args if not a.startswith("-")]
        # the value of a value flag is not an endpoint: drop the values before counting
        vals, i = [], 0
        while i < len(args):
            if args[i].startswith("-") and "=" not in args[i] and args[i] in GH_API_VALUE:
                i += 2
                continue
            if not args[i].startswith("-"):
                vals.append(args[i])
            i += 1
        if len(vals) != 1 or vals[0].lstrip("/").startswith("graphql") or "://" in vals[0] \
                or not API_ENDPOINT.fullmatch(vals[0]):
            return None
        rest = [a for a in args if a != vals[0]]
        return "gh api GET" if _check_flags(rest, GH_API_VALUE, GH_API_BOOL, 0) and endpoints else None
    if len(toks) < 3 or (toks[1], toks[2]) not in GH:
        return None
    value_flags, bool_flags, max_pos = GH[(toks[1], toks[2])]
    positional = FREE if toks[1] == "search" else POSITIONAL
    return f"gh {toks[1]} {toks[2]}" if _check_flags(toks[3:], value_flags, bool_flags, max_pos, positional) else None

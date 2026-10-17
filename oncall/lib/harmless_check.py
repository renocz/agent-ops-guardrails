"""harmless_check.py: static check over a probes.json file's own command lists, per method.md §4 -- every
denial probe must be harmless if it unexpectedly succeeds. Standard library only, and this never runs the
probes: it only reads the data file's argv lists as text.

Rule: once a dangerous verb (rm, destroy, restart, reboot, shutdown, delete, drop, kill, truncate, rmdir,
format) appears as a bare word, every word after it must be a flag or a `{{PLACEHOLDER}}` -- never a literal,
non-placeholder path, hostname or id. `rm {{SCRATCH_FILE}}` is fine (the target is a placeholder, filled in
locally with something that is actually safe to lose); `rm /var/lib/important` or `pct destroy 100` is exactly
the shape this check exists to catch, whether the real object name is written directly or an id that is not
declared as a known-nonexistent placeholder. A program name or subcommand path leading up to the verb (`pct` in
`pct destroy 100`) is never itself scrutinised -- only what follows the verb is the "object" this rule is about.
"""
import json
import re
import sys

DANGEROUS_VERBS = {"rm", "rmdir", "destroy", "restart", "reboot", "shutdown", "delete", "drop", "kill",
                   "truncate", "format", "wipefs", "mkfs"}
PLACEHOLDER_WHOLE = re.compile(r"^\{\{[A-Z_]+\}\}$")
SAFE_BARE_WORDS = {"status", "-l", "list"}                     # harmless words that can sit next to a verb-like token


def words_of(command):
    """Flatten a command's argv tokens into words, splitting each token on whitespace too: a `sh -c "rm
    {{X}}"`-style probe puts the whole script in ONE argv/JSON token, and a dangerous verb hidden inside that
    one token must be just as visible to this check as it would be as a separate argv element."""
    words = []
    for token in command:
        words.extend(token.split())
    return words


def check_probe(probe):
    """[problem, ...] for one probe; empty means harmless by this rule. Only words AFTER a dangerous verb are
    scrutinised -- the program name and any subcommand path leading up to the verb (`pct` in `pct destroy
    100`, `systemctl` in `systemctl restart example-web`) are never themselves the "object" this rule is
    about, whatever they're called."""
    name = probe.get("name", "<unnamed>")
    command = probe.get("command", [])
    words = words_of(command)
    problems = []
    seen_verb = False
    for word in words:
        if word.lower() in DANGEROUS_VERBS:
            seen_verb = True
            continue
        if not seen_verb:
            continue
        if PLACEHOLDER_WHOLE.match(word) or word.startswith("-") or word.lower() in SAFE_BARE_WORDS:
            continue
        problems.append(f"{name!r}: literal, non-placeholder argument {word!r} after a dangerous verb "
                         f"in {command!r}")
    return problems


def check_all(probes):
    problems = []
    for probe in probes:
        problems += check_probe(probe)
    return problems


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: harmless_check.py PROBES.json", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        probes = json.load(f)
    problems = check_all(probes)
    for p in problems:
        print(p)
    if problems:
        print(f"-- {len(problems)} problem(s) found", file=sys.stderr)
        return 1
    print(f"-- {len(probes)} probe(s), all harmless by this rule")
    return 0


if __name__ == "__main__":
    sys.exit(main())

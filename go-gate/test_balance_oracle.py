"""Oracle + corpus for F4 of the 11/10 review (14/10, corrected 15/10 after owner review): in 7 days of
observation the owner's log recorded 13 commands classified opaque/unbalanced (so they would need a plan in
block mode) that were, as far as their shape goes, ordinary remote commands an agent runs all day -- nested
quoting through ssh/pct exec/bash -c, French text with apostrophes, here-documents. The log keeps only the
command's head, never its arguments, so the exact strings are gone; this file reproduces the CLASS of shapes
instead of guessing one specific cause.

The first version of this oracle ran `bash -n` on the LOCAL command line and compared that against classify()'s
recursive answer. That is the wrong comparison for ssh, pct/qm exec, docker exec and bash -c: each of these hands
an INNER string to another real shell (a login shell on the remote host for ssh; the -c argument of a literal
nested sh/bash for the others), and that inner string is not always "the local line, re-quoted." ssh in
particular never re-quotes: OpenSSH joins the remaining command-line words with a single space and sends that
one string over the wire, unescaped, for the remote shell to parse again. So `ssh host echo "it's" done` -- valid
locally -- actually sends the remote shell `echo it's done`, an unterminated quote that fails on the remote host
without running anything. The local line being valid says nothing about that. The right oracle question is always
"does bash -n accept the string the deepest real shell in the chain will actually parse", not "does bash -n
accept the line as typed".

`real_shell_hops()` below rebuilds that chain the way each tool really builds it (ssh: space-join, no escaping;
pct/qm exec and docker exec: the literal argv element handed to a nested shell's -c, only when one is actually
there -- these tools exec their argument list directly, no shell re-parse, unless the command itself IS a shell
invoked with -c; bash/sh/zsh/dash -c: the literal -c argument, same reasoning, whether top-level or nested).
Every hop must parse (`bash -n`) for the command to actually run anywhere along the chain; `real_valid()` is the
AND of all of them. This duplicates a little of go_gate.py's own argument-walking on purpose: an oracle that
reused the code under test could not catch a mismatch between what that code assumes and what the real tools do.

No behaviour change in this file: it only measures. A throwaway script (not committed) used build_corpus() and
real_valid()/gate_says_unbalanced() to produce the disagreement table in the PR description.
"""
import os, shlex, shutil, subprocess, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import go_gate as g

HAS_BASH = shutil.which("bash") is not None

SHELLS = ("sh", "bash", "zsh", "dash")
SSH_OPTS_TAKING_A_VALUE = ("-i", "-p", "-o", "-l", "-J", "-F", "-L", "-R", "-D", "-W", "-b", "-c", "-E",
                           "-m", "-O", "-Q", "-S", "-w", "-B", "-e")


def bash_n_valid(cmd):
    """True/False per `bash -n` (syntax check only: it is asked to look at the command, never to run it). None if
    bash itself could not be asked (missing, or an unexpected subprocess error) -- callers must skip a None, never
    treat it as a verdict either way."""
    if cmd is None:
        return None
    if not HAS_BASH:
        return None
    try:
        r = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.returncode == 0


def split_top_level_statements(cmd):
    """Split on unquoted ';', '&&', '||' and newline, outside $()/``/()/{} nesting -- a deliberately simplified
    statement splitter (not a full shell grammar), just enough to find the separate commands in a 2-3 stage chain
    like the owner's own `bash ; pct exec ; ssh ... ; sleep` log entry. Needed so a later statement's own quoting
    (or its own ssh/pct-exec/bash-c wrapping) is judged on its own, not folded into the first command's argv by a
    plain shlex.split() of the whole line (shlex has no notion of ';' as an operator at all)."""
    stmts, buf, i, n, quote, depth = [], [], 0, len(cmd), None, 0
    while i < n:
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(cmd[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(cmd[i + 1])
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "({":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch in ")}":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
            continue
        if depth == 0:
            if ch == ";" or ch == "\n":
                stmts.append("".join(buf))
                buf = []
                i += 1
                continue
            if cmd[i:i + 2] in ("&&", "||"):
                stmts.append("".join(buf))
                buf = []
                i += 2
                continue
        buf.append(ch)
        i += 1
    stmts.append("".join(buf))
    return [s.strip() for s in stmts if s.strip()]


def _wrapped_hops(stmt, depth):
    """Extra hops (beyond stmt itself) a single statement triggers by handing an inner string to a real shell,
    built the way the real tool builds it -- the per-construct half of real_shell_hops(), kept separate so the
    statement-splitting above can apply it to each stage of a 2-3 stage chain independently."""
    try:
        toks = shlex.split(stmt)
    except ValueError:
        return []                                               # unparsable; bash -n on the whole line will say so
    if not toks:
        return []
    c, args = os.path.basename(toks[0]), toks[1:]
    if c == "ssh":
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in SSH_OPTS_TAKING_A_VALUE else 1
        rest = args[i + 1:]                                     # args[i] is the host
        if rest:
            # OpenSSH's own behaviour: the remaining words are joined with a single space and sent over the wire
            # as ONE string, unescaped -- never re-quoted -- for the remote login shell to parse as a fresh script.
            return real_shell_hops(" ".join(rest), depth + 1)
        return []
    if c in ("pct", "qm") and args and args[0] == "exec" and "--" in args:
        inner = args[args.index("--") + 1:]
        if len(inner) == 3 and inner[0] in SHELLS and inner[1] == "-c":
            # pct/qm exec hands its argument list to a real exec, not a shell: each word is delivered as its own
            # argv element, verbatim, with NO re-joining or re-quoting anywhere. A shell only re-enters the
            # picture when the executed program IS itself a shell asked for `-c SCRIPT`, in which case SCRIPT
            # (already a single, already-dequoted argv element) is exactly what that shell receives.
            return real_shell_hops(inner[2], depth + 1)
        return []
    if c == "docker" and "exec" in args:
        j = 1
        while j < len(args) and args[j].startswith("-"):
            j += 2 if args[j] in ("-u", "-w", "-e", "--user", "--workdir", "--env") else 1
        inner = args[j + 1:]                                    # args[j] is the container name
        if len(inner) == 3 and inner[0] in SHELLS and inner[1] == "-c":
            # Same reasoning as pct/qm exec: docker exec also execs its argument list directly.
            return real_shell_hops(inner[2], depth + 1)
        return []
    if c in SHELLS and "-c" in args:
        ci = args.index("-c")
        if ci + 2 == len(args):                                 # exactly one script argument follows -c
            # Whether this `<shell> -c SCRIPT` is the top-level command or was itself just delivered by one of the
            # cases above, SCRIPT is a literal argv element already -- no re-quoting needed before this next hop.
            return real_shell_hops(args[ci + 1], depth + 1)
        return []
    return []


def real_shell_hops(cmd, depth=0):
    """[cmd, inner, inner-of-inner, ...]: every string a REAL shell actually parses along the way this exact
    command would really run, built the way the real tool builds it, not the way go-gate's own classifier does.
    `cmd` itself is always hop 0 (something -- the caller's own shell -- already parses it to arrive here, and it
    may be a 2-3 stage chain: ';'/'&&'/'||' each introduce a SEPARATE command, each judged on its own). A
    construct that hands its argument straight to a real shell adds one more hop, recursively, for what THAT
    shell receives; a construct that execs directly (no shell on the far end) adds none."""
    hops = [cmd]
    if depth >= 6:
        return hops
    for stmt in split_top_level_statements(cmd):
        hops += _wrapped_hops(stmt, depth)
    return hops


def real_valid(cmd):
    """True iff every real shell hop this command would actually trigger parses cleanly -- i.e. the command
    really runs, at least syntactically, all the way down. None if bash could not be asked. False as soon as one
    hop fails: that is exactly where the real chain would also break, before anything after it ever runs."""
    verdicts = [bash_n_valid(h) for h in real_shell_hops(cmd)]
    if any(v is None for v in verdicts):
        return None
    return all(verdicts)


def gate_says_unbalanced(cmd):
    """What the owner's log actually recorded. Goes through the real classify() pipeline -- including its
    recursive ssh/pct exec/bash -c unwrapping, which re-scans a reconstructed string -- not scan() in isolation."""
    kind, detail = g.classify("Bash", {"command": cmd})
    return kind == "opaque" and detail == "unbalanced"


def gate_kind(cmd):
    return g.classify("Bash", {"command": cmd})[0]


# ---------------------------------------------------------------------------------------------------------------
# Corpus. Each category is a template crossed with a handful of fillers (hosts, phrases, payloads), to reach
# volume (>= 300) without the templates themselves getting unreadable. Read payloads exercise the balance question
# alone; change payloads are mixed in for item 2's own requirement (a fix must never turn a change into a read).
# ---------------------------------------------------------------------------------------------------------------
READ_PAYLOADS = ["ls -la /etc", "cat notes.txt", "pwd", "whoami", "grep -n foo file.log", "date", "df -h"]
CHANGE_PAYLOADS = ["rm -rf /srv/data", "systemctl restart nginx", "sed -i 's/a/b/' /etc/hosts",
                   "tee /etc/hosts", "echo x > /etc/hosts", "docker restart web"]
FRENCH = ["c'est l'heure d'y aller", "aujourd'hui c'est l'anniversaire de l'école",
          "j'espère qu'il n'y a pas d'erreur", "l'équipe d'astreinte s'en occupe", "n'oublie pas d'arrêter le service",
          "elle m'a dit qu'il n'y avait qu'une seule panne"]
ENGLISH_APOS = ["it's done", "don't stop", "rock'n'roll", "that's the one", "it's the agent's own file"]
HOSTS = ["web1", "db-primary", "host1", "backup-host"]
KEYS = ["~/.ssh/id_ed25519", "/etc/keys/deploy"]


def _cat_single_in_double_and_reverse():
    out = []
    for phrase in FRENCH + ENGLISH_APOS:
        out.append((f"double-quoted apostrophe: {phrase[:20]}", f'echo "{phrase}"'))
        out.append((f"double-quoted apostrophe, trailing word: {phrase[:20]}", f'echo "{phrase}" done'))
        out.append((f"double-quoted apostrophe, leading word: {phrase[:20]}", f'echo start "{phrase}"'))
    for phrase in ['he said "hi"', 'the "big" one', 'say "bonjour" now', 'status is "ok" today']:
        out.append((f"single-quoted doublequote: {phrase[:20]}", f"echo '{phrase}'"))
        out.append((f"single-quoted doublequote, trailing word: {phrase[:20]}", f"echo '{phrase}' done"))
    return out


def _cat_escaped_quotes_outside_quotes():
    out = []
    for word in ["foo", "bar-1", "x_y"]:
        out.append((f"escaped double outside quotes: {word}", f'echo \\"{word}\\"'))
        out.append((f"escaped single outside quotes: {word}", f"echo \\'{word}\\'"))
        out.append((f"mixed escaped quotes: {word}", f"printf %s\\\" {word} \\'"))
    return out


def _cat_ansi_c_quoting():
    out = []
    for phrase in ["it's here", "line1\\nline2", "a\\tb", "back\\\\slash", "quote\\'inside"]:
        out.append((f"$'...' ansi-c: {phrase[:20]}", f"echo $'{phrase}'"))
        out.append((f"$'...' ansi-c, trailing: {phrase[:20]}", f"printf $'{phrase}' done"))
    for payload in READ_PAYLOADS[:3] + CHANGE_PAYLOADS[:3]:
        out.append((f"$'...' wraps a payload-like string: {payload[:20]}",
                    f"echo $'ran: {payload}'"))
    return out


def _cat_command_substitution_and_backticks():
    out = []
    for payload in READ_PAYLOADS + CHANGE_PAYLOADS:
        out.append((f"$(...) substitution: {payload[:20]}", f'echo "today: $({payload})"'))
        out.append((f"backtick substitution: {payload[:20]}", f'echo "today: `{payload}`"'))
    out.append(("nested $(...) two levels", 'echo "$(echo "nested $(whoami)")"'))
    out.append(("nested $(...) three levels", 'echo "$(echo "$(echo "$(date)")")"'))
    out.append(("backtick containing apostrophe payload", f"echo `echo \"it's here\"`"))
    return out


def _cat_heredocs():
    out = []
    bodies = [
        ("plain apostrophe", "it's a test"),
        ("french apostrophes", FRENCH[0]),
        ("lone double quote", 'a "stray quote'),
        ("dollar-paren text", "looks like $(rm -rf /) but is just text"),
        ("backtick text", "looks like `rm -rf /` but is just text"),
        ("semicolons and pipes", "a; b && c || d | e"),
        ("unbalanced-looking quotes", "it's \"almost\" balanced isn't it"),
    ]
    for label, body in bodies:
        out.append((f"heredoc <<EOF unquoted delim: {label}", f"cat <<EOF\n{body}\nEOF"))
        out.append((f"heredoc <<'EOF' quoted delim: {label}", f"cat <<'EOF'\n{body}\nEOF"))
        out.append((f'heredoc <<"EOF" quoted delim: {label}', f'cat <<"EOF"\n{body}\nEOF'))
        out.append((f"heredoc <<-EOF dash variant: {label}", f"cat <<-EOF\n\t{body}\nEOF"))
    out.append(("bash -s fed by a quoted heredoc", "bash -s <<'EOF'\nls -la /etc\nEOF"))
    out.append(("bash -s fed by a heredoc with apostrophes", f"bash -s <<'EOF'\necho \"{FRENCH[0]}\"\nEOF"))
    out.append(("two heredocs in one pipeline", "diff <<'A' <<'B'\nit's one\nA\nit's two\nB"))
    return out


def _cat_ssh_variants():
    out = []
    for host in HOSTS:
        for payload in READ_PAYLOADS + CHANGE_PAYLOADS:
            out.append((f"ssh host single-quoted: {payload[:20]}", f"ssh {host} '{payload}'"))
            out.append((f"ssh host double-quoted: {payload[:20]}", f'ssh {host} "{payload}"'))
        for phrase in FRENCH[:3] + ENGLISH_APOS[:2]:
            out.append((f"ssh unquoted remote words with embedded apostrophe: {phrase[:20]}",
                        f'ssh {host} echo "{phrase}" done'))
            out.append((f"ssh unquoted remote words, apostrophe then payload: {phrase[:20]}",
                        f'ssh {host} echo "{phrase}" {READ_PAYLOADS[0]}'))
    for key in KEYS:
        for payload in READ_PAYLOADS[:3] + CHANGE_PAYLOADS[:3]:
            out.append((f"ssh -i key, nested pct exec/sh -c: {payload[:20]}",
                        f"ssh -i {key} {HOSTS[0]} 'pct exec 100 -- sh -c \"{payload}\"'"))
            out.append((f"ssh -i key, nested pct exec/sh -c, french: {payload[:20]}",
                        f"ssh -i {key} {HOSTS[0]} 'pct exec 100 -- sh -c \"{FRENCH[1]}; {payload}\"'"))
    return out


def _cat_direct_argv_sh_dash_c():
    """F4 item-3 investigation (15/10): candidate cause of the owner's log entries headed `pct exec ; ssh` and
    `bash`. `pct`/`qm exec` and `docker exec` hand their argument list to a real exec, not a shell -- so when that
    command IS a shell asked for `-c SCRIPT`, SCRIPT reaches the nested shell as a literal argv element, exactly
    as it was already dequoted by the LOCAL shell, with NO further protection. A double-quoted phrase that is
    perfectly safe locally (`sh -c "echo c'est fini"`) delivers `echo c'est fini` to the nested shell -- a BARE,
    unescaped apostrophe, which is a real syntax error there (confirmed by actually running it, not just reading
    bash -n: `subprocess.run(["sh","-c","echo c'est fini"])` fails with "Unterminated quoted string"). `bash -c`
    at the top level is the same trap without any wrapper at all. Every case below is genuinely broken when the
    phrase has an odd number of apostrophes (confirmed both by bash -n on the reconstructed inner script and by
    real execution) and go-gate is correct to call it opaque/unbalanced; an even count happens to still parse (if
    with mangled output -- the apostrophes vanish, as real execution confirms), and go-gate is correct to NOT flag
    those. This is not a bug: it is believed to be the real, or a major, cause of the log's `pct exec`/`bash`
    entries -- the agent writing the command made the mistake, not the classifier."""
    out = []
    odd, even = FRENCH[0], FRENCH[1]                         # 3 apostrophes (genuinely broken) / 4 (still parses)
    for parity, phrase in (("odd", odd), ("even", even)):
        for payload in READ_PAYLOADS[:3] + CHANGE_PAYLOADS[:3]:
            script = f"echo {phrase}; {payload}"
            out.append((f"pct exec -- sh -c, {parity} apostrophe count: {payload[:20]}",
                        f'pct exec 100 -- sh -c "{script}"'))
            out.append((f"qm exec -- sh -c, {parity} apostrophe count: {payload[:20]}",
                        f'qm exec 100 -- sh -c "{script}"'))
            out.append((f"docker exec sh -c, {parity} apostrophe count: {payload[:20]}",
                        f'docker exec web sh -c "{script}"'))
            out.append((f"bash -c, {parity} apostrophe count, top level: {payload[:20]}",
                        f'bash -c "{script}"'))
            out.append((f"bash ; pct exec -- sh -c, {parity} apostrophe count (matches the log's 'bash' head): "
                        f"{payload[:20]}", f'bash; pct exec 100 -- sh -c "{script}"'))
            out.append((f"ssh -> pct exec -- sh -c, {parity} apostrophe count (matches 'pct exec ; ssh'): "
                        f"{payload[:20]}", f"ssh {HOSTS[0]} 'pct exec 100 -- sh -c \"{script}\"'"))
    return out


def _cat_sh_dash_c_quote_escaping():
    out = []
    for payload in READ_PAYLOADS + CHANGE_PAYLOADS:
        esc = payload.replace("'", "'\\''")
        out.append((f"sh -c with '\\'' escaping: {payload[:20]}", f"sh -c '{esc}'"))
    for phrase in FRENCH[:3]:
        # The apostrophes must be inside the INNER script's own double quotes, not bare: once delivered, this string
        # is parsed as a script in its own right (by the nested sh), and a bare apostrophe in script text is a new
        # quote to IT too. `echo "{phrase}"` is what must reach the nested sh; '\''  only re-encodes that value for
        # outer delivery through a single-quoted sh -c argument (verified by running the result, not just bash -n:
        # the earlier bare-apostrophe version parsed as valid syntax outside but failed at runtime with "Unterminated
        # quoted string" once the nested sh actually parsed its own script -- a corpus bug, not a go-gate one).
        inner = f'echo "{phrase}"'
        esc = inner.replace("'", "'\\''")
        out.append((f"sh -c with '\\'' escaping, french: {phrase[:20]}", f"sh -c '{esc}'"))
    return out


def _cat_french_echo_printf():
    out = []
    for phrase in FRENCH:
        out.append((f"printf french: {phrase[:20]}", f'printf "%s\\n" "{phrase}"'))
        out.append((f"echo french, single-quoted: {phrase[:20]}", f"echo '{phrase}'"))
        out.append((f"echo french, double-quoted, trailing: {phrase[:20]}", f'echo "{phrase}" fin'))
    return out


def _cat_hash_in_quotes_vs_comment():
    out = [
        ("# inside double quotes", 'echo "a # b"'),
        ("# inside single quotes", "echo 'a # b'"),
        ("# as a real trailing comment", "echo a # a real comment"),
        ("# in quotes then a real comment after", 'echo "a # b" # real comment'),
        ("# immediately after a quote closes", 'echo "tag"# not a comment, glued'),
    ]
    return out


def _cat_line_continuations():
    out = [
        ("backslash-newline inside a plain command", "echo one \\\ntwo"),
        ("backslash-newline inside a double-quoted string", 'echo "one \\\ntwo"'),
        ("backslash-newline splitting an ssh command", "ssh host \\\n  'ls -la /etc'"),
        ("backslash-newline between pipeline stages", "ls -la /etc | \\\n  head"),
        ("backslash-newline with a french phrase", f'echo "{FRENCH[0]}" \\\n  fin'),
    ]
    return out


def _cat_operators_inside_quotes():
    out = []
    for op_text in ["a; b", "a && b", "a || b", "a | b", "a & b", "a; b && c || d | e"]:
        out.append((f"operators inside double quotes: {op_text}", f'echo "{op_text}"'))
        out.append((f"operators inside single quotes: {op_text}", f"echo '{op_text}'"))
    return out


# Intentionally invalid per bash (checked against real bash -n below, not assumed: an unterminated heredoc is only
# a WARNING in bash, exit 0 -- "here-document ... delimited by end-of-file" -- so that shape is NOT in this list).
# A dangling operator (`ls -la /etc &&`, `... |`, `... ||`) and an unterminated backtick are also invalid per bash
# but deliberately NOT here: each surfaced a different, pre-existing gap unrelated to quote balance (the former:
# scan() silently drops the empty trailing statement; the latter: scan() never tracks backtick at all, and a fix
# would have to live in secret_guard.py's scan(), out of bounds for this task). Out of scope for this task,
# reported separately, not fixed here, and not encoded as a test so it is not read as something this PR covers.
INVALID_CASES = [
    ("unterminated double quote", 'echo "unterminated'),
    ("unterminated single quote", "echo 'unterminated"),
    ("unterminated $(...)", "echo $(date"),
    ("unterminated $'...'", "echo $'unterminated"),
    ("unterminated double quote after a valid statement", "ls -la /etc; echo \"unterminated"),
]


def build_corpus():
    """[(category, name, cmd), ...], >= 300 entries, every required category represented."""
    cats = [
        ("single-in-double and reverse", _cat_single_in_double_and_reverse),
        ("escaped quotes outside quotes", _cat_escaped_quotes_outside_quotes),
        ("ansi-c $'...'", _cat_ansi_c_quoting),
        ("command substitution / backticks", _cat_command_substitution_and_backticks),
        ("heredocs", _cat_heredocs),
        ("ssh variants", _cat_ssh_variants),
        ("direct argv to nested sh -c (pct/qm/docker exec, bash -c)", _cat_direct_argv_sh_dash_c),
        ("sh -c with '\\'' escaping", _cat_sh_dash_c_quote_escaping),
        ("french echo/printf", _cat_french_echo_printf),
        ("# in quotes vs comment", _cat_hash_in_quotes_vs_comment),
        ("line continuations", _cat_line_continuations),
        ("operators inside quotes", _cat_operators_inside_quotes),
    ]
    corpus = []
    for cat_name, builder in cats:
        for name, cmd in builder():
            corpus.append((cat_name, name, cmd))
    corpus += [("invalid (fail-closed check)", name, cmd) for name, cmd in INVALID_CASES]
    return corpus


@unittest.skipUnless(HAS_BASH, "needs bash for the oracle")
class RealShellHops(unittest.TestCase):
    """Direct checks on the oracle's own model of reality, independent of the corpus and of go-gate."""

    def test_ssh_space_joins_without_requoting(self):
        # ssh never re-quotes: the remote shell receives the words joined by a single space, so a quote that was
        # closed locally around one word is just gone by the time the remote shell parses the joined string.
        self.assertEqual(real_shell_hops("ssh host echo \"it's\" done"),
                          ["ssh host echo \"it's\" done", "echo it's done"])
        self.assertFalse(real_valid("ssh host echo \"it's\" done"))

    def test_ssh_single_quoted_remote_command_is_one_hop_deeper(self):
        self.assertEqual(real_shell_hops("ssh host 'ls -la /etc'"),
                          ["ssh host 'ls -la /etc'", "ls -la /etc"])
        self.assertTrue(real_valid("ssh host 'ls -la /etc'"))

    def test_pct_exec_direct_command_has_no_shell_hop(self):
        # no shell on the far end: pct exec execs the argv directly, so there is only the local hop to check.
        self.assertEqual(real_shell_hops("pct exec 100 -- ls -la /etc"), ["pct exec 100 -- ls -la /etc"])

    def test_pct_exec_sh_dash_c_delivers_the_script_argv_element_verbatim(self):
        # pct exec hands over a real argv, so the script reaches sh -c exactly as it was already dequoted locally
        # -- no re-join, no re-quote needed for this hop to be faithful.
        self.assertEqual(real_shell_hops('pct exec 100 -- sh -c "rm -rf /x"'),
                          ['pct exec 100 -- sh -c "rm -rf /x"', "rm -rf /x"])

    def test_three_level_nesting_each_hop_checked(self):
        cmd = 'ssh host1 \'pct exec 100 -- sh -c "rm -rf /x"\''
        self.assertEqual(real_shell_hops(cmd),
                          [cmd, 'pct exec 100 -- sh -c "rm -rf /x"', "rm -rf /x"])
        self.assertTrue(real_valid(cmd))

    def test_docker_exec_mirrors_pct_exec(self):
        self.assertEqual(real_shell_hops('docker exec web sh -c "systemctl restart nginx"'),
                          ['docker exec web sh -c "systemctl restart nginx"', "systemctl restart nginx"])

    def test_bash_dash_c_top_level_is_its_own_hop(self):
        self.assertEqual(real_shell_hops("bash -c 'rm -rf /x'"), ["bash -c 'rm -rf /x'", "rm -rf /x"])

    def test_unparsable_locally_is_a_single_hop(self):
        self.assertEqual(real_shell_hops('echo "unterminated'), ['echo "unterminated'])


class OracleCorpus(unittest.TestCase):
    def setUp(self):
        self._safe, self._cwd = list(g.SAFE_GIT_REPOS), g.CWD
        g.SAFE_GIT_REPOS[:] = ["/"]
        g.CWD = "/"

    def tearDown(self):
        g.SAFE_GIT_REPOS[:] = self._safe
        g.CWD = self._cwd

    def test_corpus_is_large_and_covers_every_category(self):
        corpus = build_corpus()
        self.assertGreaterEqual(len(corpus), 300, len(corpus))
        self.assertGreaterEqual(len({cat for cat, _name, _cmd in corpus}), 12)

    @unittest.skipUnless(HAS_BASH, "needs bash for the oracle")
    def test_fail_closed_never_lets_a_syntactically_broken_command_through_as_a_read(self):
        """The one invariant that must hold regardless of any later fix (item 2): if bash itself cannot parse the
        command, the gate must never call it a plain read."""
        for name, cmd in INVALID_CASES:
            with self.subTest(name=name, cmd=cmd):
                self.assertEqual(bash_n_valid(cmd), False, cmd)         # the corpus entry itself is invalid, as intended
                self.assertNotEqual(gate_kind(cmd), "read", cmd)

    @unittest.skipUnless(HAS_BASH, "needs bash for the oracle")
    def test_oracle_runs_over_the_whole_corpus_without_crashing(self):
        """No behaviour change here: this only measures. Crashing, hanging or a bash timeout would be a bug in the
        oracle itself, not in go-gate -- that is what this guards, not any particular disagreement count yet."""
        corpus = build_corpus()
        for _cat, name, cmd in corpus:
            with self.subTest(name=name, cmd=cmd):
                real_shell_hops(cmd)                                     # must not raise or hang
                valid = real_valid(cmd)
                if valid is None:
                    continue                                            # bash itself could not be asked; skip, don't guess
                gate_says_unbalanced(cmd)                                # must not raise

    @unittest.skipUnless(HAS_BASH, "needs bash for the oracle")
    def test_disagreements_are_only_the_known_ansi_c_gap(self):
        """Once `real_valid()` asks the right question (does every real shell hop actually parse, not just the
        local line), the corpus's only remaining false positives (real_valid() true, gate says unbalanced) are the
        2 ansi-c $'...' cases secret-guard's scan() has no notion of (see CHANGELOG.md). ssh/pct exec/docker exec/
        bash -c carrying a genuinely broken inner command are all correctly opaque -- never a disagreement. A
        regression here (a new or missing disagreement) means either the oracle's modelling of a real shell hop
        drifted from the tools it models, or go-gate's own recursive unwrapping changed in a way that needs the
        same kind of scrutiny this file exists to apply."""
        corpus = build_corpus()
        false_positives = []
        for _cat, name, cmd in corpus:
            valid = real_valid(cmd)
            if valid is True and gate_says_unbalanced(cmd):
                false_positives.append((name, cmd))
        self.assertEqual(len(false_positives), 2, false_positives)
        for name, cmd in false_positives:
            self.assertIn("$'", cmd, f"unexpected false positive outside the known ansi-c gap: {name!r} {cmd!r}")

    @unittest.skipUnless(HAS_BASH, "needs bash for the oracle")
    def test_direct_argv_sh_dash_c_family_never_reads_when_really_invalid(self):
        """The dedicated regression for the family found while investigating the owner's log (item 3, 15/10): a
        genuinely broken `pct`/`qm`/`docker exec ... sh -c "..."` or `bash -c "..."` (odd apostrophe count) must
        never classify as read, whatever its detail string says (a `bash;` prefix in front of it can change which
        opaque reason surfaces first -- see CHANGELOG.md -- but the KIND must still never be read). This is the
        safety-critical direction only: a bare leading `bash;` stage is itself always opaque on its own terms
        (an interactive shell could do anything), so a VALID (even apostrophe count) command in this family can
        still legitimately come back opaque overall -- that is more conservative, never less, so it is not
        asserted against here."""
        for name, cmd in _cat_direct_argv_sh_dash_c():
            with self.subTest(name=name, cmd=cmd):
                valid = real_valid(cmd)
                if valid is None:
                    continue
                if valid is False:
                    self.assertNotEqual(gate_kind(cmd), "read", f"{name!r} {cmd!r}")


class SplitTopLevelStatements(unittest.TestCase):
    def test_splits_on_semicolon_and_double_ampersand_and_double_pipe(self):
        self.assertEqual(split_top_level_statements("a; b && c || d"), ["a", "b", "c", "d"])

    def test_does_not_split_inside_quotes(self):
        self.assertEqual(split_top_level_statements("echo 'a; b && c'"), ["echo 'a; b && c'"])
        self.assertEqual(split_top_level_statements('echo "a; b && c"'), ['echo "a; b && c"'])

    def test_does_not_split_inside_command_substitution(self):
        self.assertEqual(split_top_level_statements("echo $(a; b)"), ["echo $(a; b)"])

    def test_single_statement_is_unchanged(self):
        self.assertEqual(split_top_level_statements("ssh host 'ls -la /etc'"), ["ssh host 'ls -la /etc'"])


if __name__ == "__main__":
    unittest.main()

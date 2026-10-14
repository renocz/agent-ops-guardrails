"""Oracle + corpus for F4 of the 11/10 review (14/10): in 7 days of observation the owner's log recorded 13
commands classified opaque/unbalanced (so they would need a plan in block mode) that were, as far as their shape
goes, ordinary remote commands an agent runs all day -- nested quoting through ssh/pct exec/bash -c, French text
with apostrophes, here-documents. The log keeps only the command's head, never its arguments, so the exact
strings are gone; this file reproduces the CLASS of shapes instead of guessing one specific cause.

The oracle: `bash -n -c "<cmd>"` (syntax check only, never executes) against `gate_says_unbalanced()`, which is
what the log actually recorded -- classify() landing on ("opaque", "unbalanced") -- checked through the real
recursive pipeline (ssh/pct exec/bash -c unwrap a quoted inner command, then re-scan it), not scan() alone on the
raw top-level string. That distinction matters: the inner-command reconstruction is exactly where a balanced
command can become incorrectly unbalanced (see CHANGELOG.md and the PR description for the confirmed cause), so
comparing only the top-level string would miss the real bug class entirely.

No behaviour change in this file: it only measures. A throwaway script (not committed) used build_corpus() and
gate_says_unbalanced() to produce the disagreement table in the PR description.
"""
import os, shutil, subprocess, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import go_gate as g

HAS_BASH = shutil.which("bash") is not None


def bash_n_valid(cmd):
    """True/False per `bash -n` (syntax check only: it is asked to look at the command, never to run it). None if
    bash itself could not be asked (missing, or an unexpected subprocess error) -- callers must skip a None, never
    treat it as a verdict either way."""
    if not HAS_BASH:
        return None
    try:
        r = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.returncode == 0


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
        self.assertGreaterEqual(len({cat for cat, _name, _cmd in corpus}), 11)

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
                valid = bash_n_valid(cmd)
                if valid is None:
                    continue                                            # bash itself could not be asked; skip, don't guess
                gate_says_unbalanced(cmd)                                # must not raise


if __name__ == "__main__":
    unittest.main()

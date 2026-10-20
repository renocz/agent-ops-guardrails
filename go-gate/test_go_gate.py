"""Offline tests for go_gate.py: the classifier, the GO parsing, the scope and the hook decisions."""
import json, os, shutil, subprocess, sys, tempfile, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import go_gate as g

HERE = os.path.dirname(os.path.abspath(__file__))

# (command, expected kind)
BASH = [
    # reads
    ("ls -la /opt", "read"),
    ("docker ps -a", "read"),
    ("git status && git log --oneline -3", "read"),
    ("cat .env 2>&1 | mask", "read"),
    ("grep -rn foo /etc 2>/dev/null | head", "read"),
    ("for f in a b; do wc -l $f; done", "read"),
    ("ssh host 'docker ps -a; zfs list'", "read"),
    ("ffprobe -v error -show_streams movie.mkv", "read"),
    ("apt-mark showhold", "read"),
    ("apt-mark hold nginx", "change"),
    ("apt-mark unhold nginx", "change"),
    ("ssh -i k root@h \"pct exec 100 -- bash -c 'cd /opt/stacks && git diff'\"", "read"),
    ("curl -s https://api.example.com/v1/status | jq .", "read"),
    ("python3 -c 'import json,sys; print(json.load(sys.stdin)[\"a\"])'", "read"),
    ("docker compose up -d --no-deps --dry-run web", "read"),
    ("cp report.txt /tmp/x.txt", "read"),
    ("echo hi > /dev/null", "read"),
    ("sort data.txt | uniq -c", "read"),
    # changes, including writes hidden in options and redirections
    ("docker compose up -d web", "change"),
    ("git push origin main", "change"),
    ("sed -i 's/a/b/' /etc/hosts", "change"),
    ("sort -o /etc/passwd x", "change"),
    ("find /opt -name '*.bak' -delete", "change"),
    ("find / -fprint /opt/list", "change"),
    ("curl -o /usr/local/bin/x https://example.com/x", "change"),
    ("curl -X POST https://api.example.com/restart", "change"),
    ("curl -d @body.json https://api.example.com/items", "change"),
    ("echo hi > /opt/stacks/notes.md", "change"),
    ("cat x | tee /etc/motd", "change"),
    ("ssh host 'docker restart web'", "change"),
    ("ssh h \"pct exec 100 -- bash -c 'rm -rf /opt/stacks/old'\"", "change"),
    ("pct rollback 101 snap1", "change"),
    ("zfs destroy pool/data@snap", "change"),
    ("ls $(touch /opt/x)", "change"),
    ("python3 -c 'open(\"/opt/x\",\"w\").write(\"1\")'", "change"),
    ("python3 -c 'import subprocess; subprocess.run([\"reboot\"])'", "change"),
    ("xargs rm < list.txt", "change"),
    ("awk '{print > \"/opt/out\"}' f", "change"),
    ("psql -c 'delete from users'", "change"),
    ("systemctl restart nginx", "change"),
    # found by the council review (06/10): writes hidden behind a prefix, an option or a handler
    ("command rm -rf /opt/x", "change"),
    ("command -v docker", "read"),
    ("yq -i '.a = 1' config.yaml", "change"),
    ("plutil -replace Key -string v x.plist", "change"),
    ("plutil -p x.plist", "read"),
    ("journalctl --vacuum-time=1d", "change"),
    ("journalctl -u nginx -n 50 2>&1 | mask", "read"),
    ("diskutil apfs deleteVolume disk3s5", "change"),
    ("diskutil apfs list", "read"),
    ("git -c alias.x='!rm -rf /' x", "change"),
    ("git -c core.pager='sh -c id' log", "change"),
    ("git diff --output=/opt/x", "change"),
    ("trap 'rm -rf /opt/x' EXIT", "change"),
    # heredoc bodies belong to their own stage
    ("cat <<'A'\nopen('/opt/x','w')\nA\npython3 - <<'B'\nprint(1)\nB", "read"),
    ("cat <<'A'\nprint(1)\nA\npython3 - <<'B'\nopen('/opt/x','w').write('1')\nB", "change"),
    # found by the council review 2 (06/10)
    ("date -s '2026-01-01 00:00'", "change"),
    ("date +%F", "read"),
    ("hostname newname", "change"),
    ("hostname -f", "read"),
    ("dmesg -C", "change"),
    ("dmesg | tail", "read"),
    ("curl --request=POST https://api.example.com/x", "change"),
    ("curl --output=/opt/x https://example.com/x", "change"),
    ("curl --data=a=1 https://api.example.com/x", "change"),
    ("wget -qO- --post-data=x https://api.example.com/x", "change"),
    ("wget -qO- https://example.com/x", "read"),
    ("wget -O /etc/config https://example.org", "change"),
    ("wget -O - https://example.org", "read"),
    ("wget -O /tmp/x https://example.org", "read"),
    ("wget --output-document=/opt/x https://example.org", "change"),
    ("cat <<EOF\n$(touch /opt/x)\nEOF", "change"),
    ("cat <<'EOF'\n$(touch /opt/x)\nEOF", "read"),
    ("{ date; ls; } 2>&1 | mask", "read"),
    ("{ date; ls; } > /opt/out.txt", "change"),
    ("( cd /tmp && rm -rf /opt/x ) 2>&1", "change"),
    # found by the council review 3 (06/10)
    ("cat /tmp/../etc/passwd > /tmp/../etc/x", "change"),
    ("python3 -m json.tool in.json /opt/out.json", "change"),
    ("python3 -m json.tool in.json", "read"),
    ("python3 -c 'import httpx; httpx.post(\"https://x\")'", "change"),
    ("curl -sXPOST https://api.example.com/x", "change"),
    ("curl -sd a=1 https://api.example.com/x", "change"),
    ("curl -sO https://example.com/f", "change"),
    ("curl -so /opt/f https://example.com/f", "change"),
    ("curl -so /tmp/f https://example.com/f", "read"),
    ("curl -c /opt/jar https://example.com", "change"),
    ("curl -sSL https://example.com", "read"),
    # found by the council review 4 (06/10)
    ("curl -o/opt/f https://example.com/f", "change"),
    ("curl -c/opt/jar https://example.com", "change"),
    ("curl -o/tmp/f https://example.com/f", "read"),
    ("curl -sXGET https://example.com", "read"),
    ("curl -sXHEAD https://example.com", "read"),
    ("curl -sXDELETE https://api.example.com/x", "change"),
    ("curl -sH 'Accept: text/plain' https://example.com", "read"),
    ("rsync -a --remove-source-files /tmp/x /tmp/y", "change"),
    ("nvidia-smi -pl 200", "change"),
    ("nvidia-smi --query-gpu=name --format=csv", "read"),
    ("smartctl -t long /dev/sda", "change"),
    ("smartctl -a /dev/sda", "read"),
    ("xxd -r dump.hex /opt/bin", "change"),
    ("xxd file.bin", "read"),
    # found by the council review 5 (06/10)
    ("curl --trace /opt/t https://example.com", "change"),
    ("curl --trace-ascii=/opt/t https://example.com", "change"),
    ("curl -D /opt/h https://example.com", "change"),
    ("curl -sD - https://example.com", "read"),
    ("curl --stderr /tmp/e https://example.com", "read"),
    ("ss -K dst 10.0.0.1", "change"),
    ("ss -tlnp", "read"),
    # council review of v0.2.1 (06/10): a GET can change state
    ("curl -s https://n8n.example.org/webhook/abc123", "change"),
    ("curl -s 'https://app.example.org/api?action=delete&id=4'", "change"),
    ("curl -s -H 'X-HTTP-Method-Override: DELETE' https://app.example.org/api/x", "change"),
    ("wget -qO- https://app.example.org/api/v1/restart", "change"),
    ("curl -s https://app.example.org/api/v1/status", "read"),
    ("curl -sI https://example.com/hooks.html", "read"),
    # third external audit (06/10): no false positives on ordinary reads
    ("curl --unix-socket /var/run/docker.sock http://localhost/containers/json", "read"),
    ("curl -s https://app.example.org/api/sync/status", "read"),
    ("curl -s https://app.example.org/api/v1/restart", "change"),
    ("curl -s https://app.example.org/hooks/abc/status", "change"),
    # opaque
    ("bash deploy.sh", "opaque"),
    ("eval \"$CMD\"", "opaque"),
    ("$TOOL --apply", "opaque"),
    # K1-K5, K9: a "read" command that an option or config file makes execute or write. These classified as read
    # before the allowlist fix (08/10). Benign forms stay read (see the admin corpus; friction is 0).
    ("ssh -o ProxyCommand=/tmp/x host ls", "opaque"),
    ("ssh -oProxyCommand=/tmp/x host ls", "opaque"),
    ("ssh -o ProxyJump=j host ls", "opaque"),
    ("ssh -F /tmp/cfg host uptime", "opaque"),
    ("ssh -J jump host ls", "opaque"),
    ("ssh -W host:22 jump", "opaque"),
    ("ssh -i k -p 2222 host 'docker ps -a'", "read"),
    ("ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no host 'df -h'", "read"),
    ("awk -f /tmp/evil.awk /etc/hosts", "opaque"),
    ("awk -v c=sh 'BEGIN{print \"id\" | c}'", "opaque"),
    ("F=/tmp/x awk 'BEGIN{print \"x\" > ENVIRON[\"F\"]}'", "opaque"),   # ENVIRON: dynamic target -> script
    ("awk '{print > \"/opt/out\"}' f", "change"),
    ("awk '$3 > 100 {print $1}' f", "read"),
    ("awk 'NR>1 {s+=$2} END{print s}' f", "read"),
    ("awk '!seen[$0]++' f", "read"),
    ("sed --expression='w /home/x' /etc/hosts", "change"),
    ("sed -e'w /home/x' /etc/hosts", "change"),
    ("sed 's/x/y/e' f", "opaque"),
    ("sed -f /tmp/p.sed f", "opaque"),
    ("sed '1e /tmp/evil' f", "opaque"),
    ("sed -e 's/a/b/' -e 's/c/d/' f", "read"),
    ("curl -K /tmp/cfg https://h/x", "opaque"),
    ("curl --config /tmp/cfg https://h/x", "opaque"),
    ("curl -sK/tmp/cfg https://h/x", "opaque"),
    ("curl -s -H 'X-Api-Key: k' https://h/api/v1/status", "read"),
    ("wget -e 'robots=off' https://h/x", "opaque"),
    ("wget --config=/tmp/w https://h", "opaque"),
    ("tar --to-command=/tmp/evil -xf a.tar", "opaque"),
    ("tar -tf a.tar", "read"),
    ("psql -c 'select pg_read_file(/etc/passwd)'", "change"),
    ("psql -c 'select pg_terminate_backend(1)'", "change"),
    ("psql -c 'select 1' -c 'delete from t'", "change"),
    ("psql -f /tmp/evil.sql", "change"),
    ("psql -c 'select count(*) from users'", "read"),
    ("openssl x509 -engine /tmp/e.so -in c.pem", "opaque"),
    ("ls <> /opt/stacks/b", "change"),
    ("ls 0<> /opt/stacks/b", "change"),
    ("PAGER=/tmp/evil git log", "opaque"),
    ("GIT_PAGER='sh -c id' git diff", "opaque"),
    ("LESSOPEN='|/tmp/x %s' less f", "opaque"),
    # R2: launchers feed external input to a command; a shell/interpreter/by-path/unknown target is opaque. A `<` input
    # redirection no longer leaks its file as an argument. Benign launches stay their real kind.
    ("xargs -I{} sh -c '{}' < /tmp/list", "opaque"),
    ("xargs sh -c id < /dev/null", "opaque"),
    ("xargs -a /tmp/list sh", "opaque"),
    ("xargs --arg-file=/tmp/list bash", "opaque"),
    ("xargs rm < list", "change"),
    ("xargs ls < list", "read"),
    ("find . -print0 | xargs -0 grep foo", "read"),
    ("echo *.log | xargs wc -l", "read"),
    ("parallel sh -c {} ::: a b", "opaque"),
    ("parallel rm ::: a b", "change"),
    ("timeout 5 tail -f /var/log/syslog", "read"),
    ("timeout 5 bash /tmp/x.sh", "opaque"),
    ("setsid tail -f log", "read"),
    # R3: env VAR= is a prefix assignment; a dangerous variable through env is opaque. -S carries a whole command line.
    ("env PAGER=/tmp/x cat f", "opaque"),
    ("env -i LD_PRELOAD=/tmp/x.so cat f", "opaque"),
    ("env -u HOME GIT_SSH=/tmp/x cat f", "opaque"),
    ("env -S 'PAGER=/tmp/x cat f'", "opaque"),
    ("env FOO=bar cat /etc/hosts", "read"),
    ("env cat /etc/hosts", "read"),
    ("env", "read"),
    ("sort --compress-program=/tmp/x /etc/hosts", "opaque"),
    ("sort -k2 -n file", "read"),
    ("openssl x509 -config /tmp/c -in cert.pem", "opaque"),
    # Found by the adversarial self-review (09/10): process substitution runs its command; a pager +!cmd runs a shell.
    ("cat <(rm -rf /srv)", "change"),
    ("diff <(cat a) <(/tmp/evil)", "opaque"),
    ("grep foo < <(/tmp/evil)", "opaque"),
    ("ls > >(rm -rf /srv)", "change"),
    ("cat <(cat /etc/hosts)", "read"),
    ("paste <(sort a) <(sort b)", "read"),
    ("less +!/tmp/evil file", "opaque"),
    ("less +G file", "read"),
    # F4 item-3 investigation (15/10): pct/qm/docker exec hand their argv straight to a real exec, not a shell --
    # when that command IS a shell asked for -c SCRIPT, SCRIPT reaches it exactly as already dequoted locally, with
    # no further protection. A double-quoted phrase with an odd number of apostrophes is genuinely broken this way
    # (confirmed by running it, not just reading bash -n -- see go-gate/test_balance_oracle.py); go-gate correctly
    # calls it opaque rather than read. An even count happens to still parse and must be judged normally.
    ("pct exec 100 -- sh -c \"echo c'est fini\"", "opaque"),
    ("qm exec 100 -- sh -c \"echo c'est fini\"", "opaque"),
    ("docker exec web sh -c \"echo c'est fini\"", "opaque"),
    ("bash -c \"echo c'est fini\"", "opaque"),
    ("pct exec 100 -- sh -c \"echo aujourd'hui c'est l'anniversaire de l'école\"", "read"),
]


def rtext(path):
    with open(path) as f:
        return f.read()


def wtext(path, text):
    with open(path, "w") as f:
        f.write(text)


def wjson(path, obj):
    wtext(path, json.dumps(obj))


def run_hook(event, gate_dir):
    env = dict(os.environ, GO_GATE_DIR=gate_dir)
    r = subprocess.run([sys.executable, os.path.join(HERE, "go_gate.py")], input=json.dumps(event),
                       capture_output=True, text=True, env=env)
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    run_hook.context = out.get("hookSpecificOutput", {}).get("additionalContext")
    run_hook.notice = out.get("systemMessage")
    run_hook.reason = out.get("hookSpecificOutput", {}).get("permissionDecisionReason")
    return r.returncode, out.get("hookSpecificOutput", {}).get("permissionDecision", "allow")


_MID = [100]


def telegram(text, uid="42", mid=None, ts=None):
    """A channel message as the Telegram plugin delivers it: unique message_id, current UTC time."""
    _MID[0] += 1
    mid = mid or str(_MID[0])
    ts = ts or time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    return f'<channel source="plugin:telegram:telegram" chat_id="1" message_id="{mid}" user="u" user_id="{uid}" ts="{ts}">\n{text}\n</channel>'


class Classifier(unittest.TestCase):
    def setUp(self):
        # Most BASH cases assume an ordinary working repo; declare it safe so git READ verbs stay reads (K6 policy
        # itself is exercised in test_git_safe_repos). Restored in tearDown.
        self._safe, self._cwd = list(g.SAFE_GIT_REPOS), g.CWD
        g.SAFE_GIT_REPOS[:] = ["/"]
        g.CWD = "/"

    def tearDown(self):
        g.SAFE_GIT_REPOS[:] = self._safe
        g.CWD = self._cwd

    def test_bash(self):
        for cmd, kind in BASH:
            with self.subTest(cmd=cmd):
                self.assertEqual(g.classify("Bash", {"command": cmd})[0], kind)

    def test_git_safe_repos(self):                                   # K6
        g.SAFE_GIT_REPOS[:] = ["/opt/stacks/web"]
        g.CWD = "/tmp/elsewhere"
        self.assertEqual(g.classify("Bash", {"command": "git status"})[0], "opaque")        # cwd not declared safe
        self.assertEqual(g.classify("Bash", {"command": "git -C /tmp/evil log"})[0], "opaque")
        self.assertEqual(g.classify("Bash", {"command": "git -C /opt/stacks/web status"})[0], "read")
        g.CWD = "/opt/stacks/web/sub"
        self.assertEqual(g.classify("Bash", {"command": "git log --oneline"})[0], "read")    # under a safe repo
        self.assertEqual(g.classify("Bash", {"command": "git push"})[0], "change")           # a change stays a change
        g.CWD = None                                                                         # GIT_DIR locates the repo
        self.assertEqual(g.classify("Bash", {"command": "GIT_DIR=/opt/stacks/web/.git git status"})[0], "read")
        self.assertEqual(g.classify("Bash", {"command": "GIT_DIR=/tmp/evil/.git git log"})[0], "opaque")
        self.assertEqual(g.classify("Bash", {"command": "GIT_PAGER=/tmp/x git log"})[0], "opaque")  # still exec

    def test_cd_is_followed_across_stages(self):                     # R1
        g.SAFE_GIT_REPOS[:] = ["/opt/stacks"]
        g.CWD = "/opt/stacks"
        for cmd in ("cd /tmp/evil && git status", "cd /tmp/evil; git log", "cd - && git status",
                    "cd ~ && git status", "cd \"$VAR\" && git status", "cd $(mktemp -d) && git status",
                    "builtin cd /tmp/evil && git status", "( cd /tmp/evil && git status )",
                    "{ cd /tmp/evil; git status; }", "pushd /tmp/evil && git status", "popd && git status"):
            self.assertEqual(g.classify("Bash", {"command": cmd})[0], "opaque", cmd)
        for cmd in ("cd /opt/stacks/web && git status", "cd /opt/stacks && git log --oneline", "git status",
                    "cd /tmp && ls", "cd /tmp/x && cat f"):
            self.assertNotEqual(g.classify("Bash", {"command": cmd})[0], "opaque", cmd)

    def test_cd_home_is_resolved(self):                              # review 11/10: `cd ~/repo && git status` was a script
        home = os.path.expanduser("~")
        g.SAFE_GIT_REPOS[:] = [home + "/ops-council"]
        g.CWD = "/tmp"
        for cmd in ("cd ~/ops-council && git status", "cd $HOME/ops-council && git log", "cd ${HOME}/ops-council/ci && git diff",
                    "cd ~/ops-council; git status"):
            self.assertEqual(g.classify("Bash", {"command": cmd})[0], "read", cmd)
        for cmd in ("cd ~/autre && git status", "cd ~ && git status", "cd ~root/x && git status",
                    "cd ~/ops-council/../autre && git status", "cd $HOMEX/ops-council && git status",
                    "cd ~/ops-council && git push"):
            self.assertNotEqual(g.classify("Bash", {"command": cmd})[0], "read", cmd)

    def test_git_exec_config_surface_needs_script(self):             # R4 part 1
        edit = {"targets": ["/opt/stacks/web"], "actions": ["edit", "git"]}
        script = {"targets": ["/opt/stacks/web"], "actions": ["edit", "git", "script"]}
        for ti in ({"file_path": "/opt/stacks/web/.git/config", "content": "x"},
                   {"file_path": "/opt/stacks/web/.git/hooks/pre-commit", "content": "x"},
                   {"file_path": "/opt/stacks/web/.gitattributes", "content": "x"}):
            cat = g.category("Write", ti, *g.classify("Write", ti))
            self.assertFalse(g.covers(edit, "Write", ti, cat, None), ti["file_path"])
            self.assertTrue(g.covers(script, "Write", ti, cat, None), ti["file_path"])
        ok = {"file_path": "/opt/stacks/web/app.conf", "content": "x"}
        self.assertTrue(g.covers(edit, "Write", ok, g.category("Write", ok, *g.classify("Write", ok)), None))
        for cmd in ("git -C /opt/stacks/web config core.fsmonitor /tmp/x", "echo x > /opt/stacks/web/.git/config"):
            self.assertFalse(g.covers(edit, "Bash", {"command": cmd}, "git", cmd), cmd)
        self.assertTrue(g.covers(edit, "Bash", {"command": "git -C /opt/stacks/web config user.name bob"},
                                 "git", "git -C /opt/stacks/web config user.name bob"))

    def test_nested_repo_does_not_inherit_trust(self):               # R4 part 2
        import shutil, tempfile
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, ".git"))
            os.makedirs(os.path.join(d, "sub"))
            os.makedirs(os.path.join(d, "nested", ".git"))
            os.makedirs(os.path.join(d, "nested", "deep"))
            g.SAFE_GIT_REPOS[:] = [d]
            for sub, kind in (("", "read"), ("sub", "read"), ("nested", "opaque"), ("nested/deep", "opaque")):
                g.CWD = os.path.join(d, sub) if sub else d
                self.assertEqual(g.classify("Bash", {"command": "git status"})[0], kind, sub)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_every_change_is_recorded(self):
        g.classify("Bash", {"command": "git add web; docker compose down"})
        self.assertEqual([d.split()[0] for _k, d, _s in g.CHANGES], ["git", "docker"])

    def test_tools(self):
        self.assertEqual(g.classify("Read", {"file_path": "/etc/hosts"})[0], "read")
        self.assertEqual(g.classify("Write", {"file_path": "/tmp/a.txt"})[0], "read")
        self.assertEqual(g.classify("Edit", {"file_path": "/opt/stacks/x.yaml"})[0], "change")
        self.assertEqual(g.classify("mcp__plugin_telegram_telegram__reply", {"text": "hi"})[0], "talk")
        self.assertEqual(g.classify("mcp__claude-in-chrome__computer", {"action": "screenshot"})[0], "read")
        self.assertEqual(g.classify("mcp__claude-in-chrome__computer", {"action": "left_click"})[0], "change")
        self.assertEqual(g.classify("mcp__some__delete_item", {})[0], "change")
        self.assertEqual(g.classify("mcp__lab__get_and_delete_secret", {})[0], "change")     # GG-08
        self.assertEqual(g.classify("mcp__lab__get_status", {})[0], "read")
        self.assertEqual(g.classify("mcp__github__get_commit", {})[0], "read")              # Gemini audit of v0.9
        self.assertEqual(g.classify("mcp__x__list_settings", {})[0], "read")
        self.assertEqual(g.classify("mcp__x__getAndDeleteSecret", {})[0], "change")
        fc = "mcp__claude_ai_Firecrawl__firecrawl_"                                         # review 11/10: server name repeated
        self.assertEqual(g.classify(fc + "search", {"query": "x"})[0], "read")
        self.assertEqual(g.classify(fc + "scrape", {"url": "https://example.com/doc"})[0], "read")
        self.assertEqual(g.classify(fc + "scrape", {"url": "https://example.com/webhook/abc"})[0], "change")
        self.assertEqual(g.classify(fc + "scrape", {"url": "https://example.com/api/restart"})[0], "change")
        self.assertEqual(g.classify(fc + "monitor_create", {})[0], "change")
        self.assertEqual(g.classify(fc + "monitor_delete", {})[0], "change")
        self.assertEqual(g.classify(fc + "crawl", {})[0], "change")
        self.assertEqual(g.classify("mcp__x__x_delete_item", {})[0], "change")             # a dropped prefix hides no verb
        self.assertEqual(g.classify("mcp__x__x_get_and_delete_item", {})[0], "change")
        self.assertEqual(g.classify("mcp__x__y_search", {})[0], "change")                  # only a prefix naming the server goes
        for code, kind in (("from os import remove as r; r('/srv/x')", "change"),           # GG-01
                           ("import pathlib; pathlib.Path('/srv/x').unlink()", "change"),
                           ("getattr(__import__('os'), 'remove')('/srv/x')", "change"),
                           ("import json,sys; print(json.load(sys.stdin)['a'])", "read"),
                           ("print(1+1)", "read"),
                           ("open('/srv/x', 'w').write('y')", "change"),             # council review of v0.9
                           ("m = 'a'; open('/srv/x', m).write('y')", "change"),
                           ("open('/srv/x', mode='w')", "change"),
                           ("print('y', file=open('/srv/x', 'a'))", "change"),
                           ("print(open('/etc/hosts').read()[:50])", "read"),
                           ("print(open('/etc/hosts', 'r').read()[:50])", "read"),
                           ("import sys; print('log', file=sys.stderr)", "read"),          # Gemini audit of v0.9
                           ("import os.path; print(os.path.basename('/a/b'))", "read"),
                           ("import os.path; os.remove('/srv/x')", "change")):
            self.assertEqual(g.classify("Bash", {"command": f'python3 -c "{code}"'})[0], kind, code)


class Scope(unittest.TestCase):
    def test_parse(self):
        p = g.parse_scope("Plan…\nScope: id=upd-web ; targets=web, /opt/stacks/web ; actions=deploy,git ; ttl=30min")
        self.assertEqual((p["id"], p["targets"], p["actions"], p["ttl"]), ("upd-web", ["web", "/opt/stacks/web"], ["deploy", "git"], 30))
        self.assertEqual(g.parse_scope("Périmètre : id=x ; actions=edit ; durée=2h")["ttl"], 120)
        self.assertIsNone(g.parse_scope("no scope here"))
        self.assertEqual(g.parse_scope("Scope: id=upd-réseau ; actions=edit")["id"], "upd-rseau")   # ASCII ids
        self.assertIsNone(g.parse_scope("Scope: id=x ; actions=everything"))       # unknown category only

    def test_covers(self):
        plan = {"targets": ["web"], "actions": ["deploy"]}
        self.assertTrue(g.covers(plan, "Bash", {"command": "docker compose up -d web"}, "deploy"))
        self.assertFalse(g.covers(plan, "Bash", {"command": "docker compose up -d db"}, "deploy"))
        self.assertFalse(g.covers(plan, "Bash", {"command": "git push"}, "git"))

    def test_covers_target_is_a_token_not_a_substring(self):          # K7
        plan = {"targets": ["web"], "actions": ["deploy"]}
        for cmd in ("docker restart webserver", "docker restart web-db", "docker restart cobweb"):
            self.assertFalse(g.covers(plan, "Bash", {"command": cmd}, "deploy", cmd), cmd)
        self.assertTrue(g.covers(plan, "Bash", {"command": "docker restart web"}, "deploy", "docker restart web"))
        p2 = {"targets": ["/opt/stacks/web"], "actions": ["deploy"]}   # a path target covers its sub-paths, not a sibling
        self.assertTrue(g.covers(p2, "Bash", {"command": "ls /opt/stacks/web/compose.yml"}, "deploy",
                                 "ls /opt/stacks/web/compose.yml"))
        self.assertFalse(g.covers(p2, "Bash", {"command": "ls /opt/stacks/webx"}, "deploy", "ls /opt/stacks/webx"))

    def test_coverage_gap_names_the_missing_action(self):
        plan = {"targets": ["web"], "actions": ["deploy"]}
        gap = g.coverage_gap(plan, "Bash", {"command": "git push origin web"}, "git", "git push origin web")
        self.assertEqual(gap, {"category": "git"})
        self.assertIn("missing action 'git'", g.describe_gap(gap, plan))
        self.assertIn("plan actions: deploy", g.describe_gap(gap, plan))
        self.assertEqual(g.describe_gap(None, plan), "")             # covered: nothing to say

    def test_coverage_gap_names_target_like_words_not_covered(self):          # the operational pain this fixes
        plan = {"targets": ["web"], "actions": ["deploy"]}
        cmd = "docker compose -f /opt/stacks/news/docker-compose.yml restart news.example.com"
        gap = g.coverage_gap(plan, "Bash", {"command": cmd}, "deploy", cmd)
        self.assertEqual(gap["targets"], ["/opt/stacks/news/docker-compose.yml", "news.example.com"])
        text = g.describe_gap(gap, plan)
        self.assertIn("/opt/stacks/news/docker-compose.yml", text)
        self.assertIn("news.example.com", text)
        self.assertIn("plan targets: web", text)
        self.assertNotIn("-f", text)                      # a bare flag is never named as a missing target

    def test_candidate_targets_never_returns_secret_shaped_text(self):
        plan = {"targets": ["web"], "actions": ["deploy"]}
        secret = "verysecretpassword12345"
        cmd = f"curl https://user:{secret}@api.example.com/deploy.php"
        gap = g.coverage_gap(plan, "Bash", {"command": cmd}, "deploy", cmd)
        joined = " ".join(gap["targets"])
        self.assertNotIn(secret, joined)

    def test_coverage_gap_still_flags_the_exec_dir_and_git_surface_carveouts(self):    # no protection reduced
        plan = {"targets": [], "actions": ["edit"]}
        cmd = "echo x > ~/bin/cat"
        gap = g.coverage_gap(plan, "Bash", {"command": cmd}, "edit", cmd)
        self.assertEqual(gap["category"], "script")
        cmd2 = "git config core.fsmonitor /tmp/x"
        gap2 = g.coverage_gap(plan, "Bash", {"command": cmd2}, "edit", cmd2)
        self.assertEqual(gap2["category"], "script")


class DirPrefixTarget(unittest.TestCase):
    """K-dir (19/10): `dir:<path>` is an explicit, opt-in subtree grant. Never an implicit one (a bare path keeps
    its pre-existing prefix behaviour, exercised above), never a protected path, never `/` or the home directory."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="dirtarget-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _plan(self, path):
        return {"targets": [f"dir:{path}"], "actions": ["deploy"]}

    def test_valid_prefix_covers_the_subtree(self):
        sub = os.path.join(self.root, "news")
        os.makedirs(sub)
        file = os.path.join(sub, "docker-compose.yml")
        old, g.CWD = g.CWD, sub                                         # a change must also run from inside the dir
        try:
            self.assertTrue(g.covers(self._plan(sub), "Bash", {"command": f"restart {file}"}, "deploy", f"restart {file}"))
            nested = os.path.join(sub, "sub", "x")
            self.assertTrue(g.covers(self._plan(sub), "Bash", {"command": f"restart {nested}"}, "deploy", f"restart {nested}"))
        finally:
            g.CWD = old

    def test_lookalike_sibling_is_not_covered(self):              # "news" must not cover "newsletter"
        sub = os.path.join(self.root, "news")
        os.makedirs(sub)
        sibling = os.path.join(self.root, "newsletter", "x")
        self.assertFalse(g.covers(self._plan(sub), "Bash", {"command": f"restart {sibling}"}, "deploy",
                                  f"restart {sibling}"))

    def test_dotdot_escape_is_not_covered(self):
        sub = os.path.join(self.root, "news")
        os.makedirs(sub)
        escape = os.path.join(sub, "..", "..", "etc", "passwd")
        self.assertFalse(g.covers(self._plan(sub), "Bash", {"command": f"cat {escape}"}, "deploy", f"cat {escape}"))

    def test_symlink_escape_is_not_covered(self):
        sub = os.path.join(self.root, "news")
        outside = os.path.join(self.root, "outside")
        os.makedirs(sub)
        os.makedirs(outside)
        secretfile = os.path.join(outside, "secret")
        wtext(secretfile, "x")
        link = os.path.join(sub, "escape")
        os.symlink(outside, link)
        via_link = os.path.join(link, "secret")
        self.assertFalse(g.covers(self._plan(sub), "Bash", {"command": f"cat {via_link}"}, "deploy",
                                  f"cat {via_link}"))

    def test_protected_path_is_never_granted_by_dir_prefix(self):
        env = dict(os.environ, GO_GATE_DIR=self.root)
        old = os.environ.get("GO_GATE_DIR")
        os.environ["GO_GATE_DIR"] = self.root
        try:
            target = os.path.join(self.root, "state.json")
            self.assertFalse(g.covers(self._plan(self.root), "Bash", {"command": f"echo x > {target}"}, "deploy",
                                      f"echo x > {target}"))
        finally:
            if old is None:
                os.environ.pop("GO_GATE_DIR")
            else:
                os.environ["GO_GATE_DIR"] = old

    def test_keeper_own_paths_are_never_granted_by_dir_prefix(self):
        self.assertTrue(g.is_keeper_protected("/etc/keeper/config.json"))
        self.assertTrue(g.is_keeper_protected("/opt/agent-guardrails/lib/go_gate.py"))
        self.assertFalse(g.covers(self._plan("/etc"), "Bash", {"command": "cat /etc/keeper/config.json"}, "deploy",
                                  "cat /etc/keeper/config.json"))

    def test_root_and_home_are_too_broad_to_grant(self):
        self.assertFalse(g.covers(self._plan("/"), "Bash", {"command": "rm -rf /x"}, "deploy", "rm -rf /x"))
        self.assertFalse(g.covers(self._plan("~"), "Bash", {"command": "rm -rf ~/x"}, "deploy", "rm -rf ~/x"))

    def test_disguised_filename_does_not_match_a_sibling_prefix(self):
        sub = os.path.join(self.root, "news")
        os.makedirs(sub)
        disguise = os.path.join(self.root, "news-backup", "x")           # textually starts with "news", not a sub-path
        self.assertFalse(g.covers(self._plan(sub), "Bash", {"command": f"restart {disguise}"}, "deploy",
                                  f"restart {disguise}"))

    def test_no_wildcard_no_empty_prefix(self):
        self.assertFalse(g.target_matches("dir:", ["/opt/x"]))
        self.assertFalse(g.target_matches("dir:/opt/*", ["/opt/x"]))

    def test_bare_path_without_dir_marker_is_unaffected(self):            # the pre-existing, non-explicit behaviour
        sub = os.path.join(self.root, "news")
        os.makedirs(sub)
        file = os.path.join(sub, "x")
        plan = {"targets": [sub], "actions": ["deploy"]}
        self.assertTrue(g.covers(plan, "Bash", {"command": f"restart {file}"}, "deploy", f"restart {file}"))


def decide(plan, cmd, cwd):
    """What the hook decides for a Bash command run in `cwd`, without the subprocess: classify() it as the hook does
    (so the command's own `cd`s are followed), then ask coverage_gap() for every change in it. None = covered, the
    command is not a change at all, or the first gap."""
    old = g.CWD
    g.CWD = cwd
    try:
        g.classify("Bash", {"command": cmd})
        for k, d, st in list(g.CHANGES):
            cat = g.category("Bash", {"command": cmd}, k, d)
            gap = g.coverage_gap(plan, "Bash", {"command": cmd}, cat, st)
            if gap:
                return gap
        return None
    finally:
        g.CWD = old


class DirTree(unittest.TestCase):
    """A scratch tree OUTSIDE the scratch-write exemption (those are never changes), so the gate really judges it:
        root/news          the dir: target
        root/other         a sibling outside it
        root/news/link     a symlink inside news that points to root/other
    """

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="dirtree-", dir=HERE))
        self.news = os.path.join(self.root, "news")
        self.other = os.path.join(self.root, "other")
        os.makedirs(self.news)
        os.makedirs(self.other)
        os.symlink(self.other, os.path.join(self.news, "link"))
        self.plan = {"targets": [f"dir:{self.news}"], "actions": ["edit", "delete", "deploy", "script", "git", "api"]}
        self.old_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.root, ignore_errors=True)

    def covered(self, cmd, cwd=None):
        return decide(self.plan, cmd, cwd or self.news) is None


class DirAllPaths(DirTree):
    """K-dir, round 2: a `dir:` target covers an action only when EVERY path in it is inside the directory. Plain
    targets keep the any-one-token rule they always had (last tests)."""

    def test_reported_case_cp_from_inside_to_outside(self):
        plan = {"targets": ["dir:/opt/stacks/news"], "actions": ["edit"]}
        cmd = "cp /opt/stacks/news/x /etc/cron.d/y"
        gap = g.coverage_gap(plan, "Bash", {"command": cmd}, "edit", cmd)
        self.assertIsNotNone(gap)
        text = g.describe_gap(gap, plan)
        self.assertIn("/etc/cron.d/y", text)
        self.assertNotIn("/opt/stacks/news/x,", text)                      # the covered path is not blamed
        self.assertIn("every path", text)
        cmd2 = "cp /opt/stacks/news/x /opt/stacks/news/y"
        old, g.CWD = g.CWD, "/opt/stacks/news"                              # the cwd rule: run from inside the dir
        try:
            self.assertIsNone(g.coverage_gap(plan, "Bash", {"command": cmd2}, "edit", cmd2))
        finally:
            g.CWD = old

    def test_cp_mv_ln_install_with_one_path_outside(self):
        n, o = self.news, self.other
        for cmd in (f"cp {n}/a {o}/b", f"cp {o}/a {n}/b", f"mv {n}/a /etc/b", f"ln -s {n}/a {o}/l",
                    f"install -m 755 {n}/a {o}/b", f"rsync -a {n}/ {o}/", f"cp -r {n} {o}", f"touch {n}/a {o}/b"):
            self.assertFalse(self.covered(cmd), cmd)
        for cmd in (f"cp {n}/a {n}/b", f"mv {n}/a {n}/sub/b", f"ln -s {n}/a {n}/l", f"install -m 755 {n}/a {n}/b",
                    f"rm -f {n}/a {n}/b", f"mkdir -p {n}/x/y"):
            self.assertTrue(self.covered(cmd), cmd)

    def test_mixed_command_one_inside_one_outside(self):
        n, o = self.news, self.other
        self.assertFalse(self.covered(f"cp {n}/a {n}/b {o}/c"))
        self.assertFalse(self.covered(f"mv {n}/a {n}/b; rm {o}/c"))                 # second statement
        self.assertFalse(self.covered(f"cp {n}/a {n}/b && cp {n}/b {o}/c"))
        self.assertFalse(self.covered(f"echo ok | tee {n}/a | tee {o}/b"))          # second pipeline stage
        self.assertTrue(self.covered(f"cp {n}/a {n}/b && cp {n}/b {n}/c"))

    def test_tee_targets(self):
        n, o = self.news, self.other
        self.assertTrue(self.covered(f"echo x | tee {n}/a"))
        self.assertTrue(self.covered(f"echo x | tee -a {n}/a {n}/b"))
        self.assertFalse(self.covered(f"echo x | tee {n}/a {o}/b"))
        self.assertFalse(self.covered(f"echo x | tee -a {o}/b"))
        self.assertFalse(self.covered(f"echo x | tee {n}/a /etc/cron.d/y"))
        self.assertFalse(self.covered("echo x | tee out.txt", cwd=self.other))         # a bare name lands in the cwd
        self.assertTrue(self.covered("echo x | tee out.txt", cwd=self.news))

    def test_redirections(self):
        n, o = self.news, self.other
        self.assertTrue(self.covered(f"echo x > {n}/a"))
        self.assertFalse(self.covered(f"echo x > {o}/a"))
        self.assertFalse(self.covered(f"echo x >> {o}/a"))
        self.assertFalse(self.covered(f"cat {n}/a > {o}/b"))                            # one inside, one outside
        self.assertFalse(self.covered(f"cat {n}/a >{o}/b"))                             # no space
        self.assertFalse(self.covered(f"cat {n}/a 1>{o}/b"))
        self.assertFalse(self.covered(f"cat {n}/a &> {o}/b"))
        self.assertFalse(self.covered(f"cat {n}/a >| {o}/b"))
        self.assertFalse(self.covered(f"cat {n}/a > '{o}/b'"))                          # quoted target
        self.assertFalse(self.covered(f"echo x > out.txt", cwd=self.other))             # bare redirect target
        self.assertTrue(self.covered(f"echo x > out.txt", cwd=self.news))
        self.assertTrue(self.covered(f"echo x > {n}/a 2>&1"))                           # fd duplication is no file
        self.assertTrue(self.covered(f"echo x > {n}/a 2>/dev/null"))                    # a null sink is fine
        self.assertFalse(self.covered(f"echo x > {n}/a 2>{o}/err"))

    def test_target_directory_style_flags(self):
        n, o = self.news, self.other
        self.assertFalse(self.covered(f"cp --target-directory={o} {n}/a"))
        self.assertFalse(self.covered(f"cp --target-directory {o} {n}/a"))
        self.assertFalse(self.covered(f"cp -t {o} {n}/a"))
        self.assertFalse(self.covered(f"tar -xf {n}/a.tgz -C {o}"))
        self.assertFalse(self.covered(f"tar -xf {n}/a.tgz -C{o}"))
        self.assertFalse(self.covered(f"dd if={n}/a of={o}/b"))
        self.assertFalse(self.covered(f"git -C {o} commit -m x"))
        self.assertFalse(self.covered(f"git --work-tree={o} checkout ."))
        self.assertFalse(self.covered(f"docker compose --project-directory={o} up -d"))
        self.assertTrue(self.covered(f"tar -xf {n}/a.tgz -C {n}/out"))
        self.assertTrue(self.covered(f"dd if={n}/a of={n}/b"))
        self.assertTrue(self.covered(f"git -C {n} commit -m x"))

    def test_nested_in_ssh_pct_docker_exec_and_bash_c(self):
        n, o = self.news, self.other
        # a path inside the quoted remote command is seen like any other
        self.assertFalse(self.covered(f"ssh host 'cp {n}/a /etc/cron.d/y'"))
        self.assertFalse(self.covered(f'ssh host "cp {n}/a /etc/cron.d/y"'))
        self.assertFalse(self.covered(f"ssh host \"pct exec 100 -- cp {n}/a /etc/cron.d/y\""))
        self.assertFalse(self.covered(f"docker exec web cp {n}/a /etc/cron.d/y"))
        self.assertFalse(self.covered(f"bash -c 'cp {n}/a {o}/b'"))
        self.assertFalse(self.covered(f"sh -c \"cd {n} && cp a {o}/b\""))
        # ... and a command that runs elsewhere is not judged by local symlinks at all: not covered even when
        # every path looks inside
        self.assertFalse(self.covered(f"ssh host 'cp {n}/a {n}/b'"))
        self.assertFalse(self.covered(f"pct exec 100 -- cp {n}/a {n}/b"))
        self.assertFalse(self.covered(f"docker exec web cp {n}/a {n}/b"))
        self.assertFalse(self.covered(f"docker run --rm -v {n}:/data alpine rm /data/a"))
        self.assertFalse(self.covered(f"scp {n}/a host:/etc/y"))
        self.assertFalse(self.covered(f"scp host:/etc/y {n}/a"))
        self.assertFalse(self.covered(f"rsync -a {n}/ host:/srv/x/"))
        self.assertTrue(self.covered(f"bash -c 'cp {n}/a {n}/b'"))                      # local nesting is fine
        self.assertTrue(self.covered(f"docker compose -f {n}/compose.yml up -d"))

    def test_remote_denial_says_why(self):
        cmd = f"ssh host 'cp {self.news}/a {self.news}/b'"
        gap = decide(self.plan, cmd, self.news)
        self.assertIn("elsewhere", g.describe_gap(gap, self.plan))

    def test_symlink_pointing_out_is_followed(self):
        n, o = self.news, self.other
        wtext(os.path.join(o, "f"), "x")
        os.symlink(os.path.join(o, "f"), os.path.join(n, "linkfile"))
        for cmd in (f"cp {n}/a {n}/link/b", f"rm {n}/link/f", f"echo x > {n}/link/f", f"echo x > {n}/linkfile",
                    f"tee {n}/linkfile", f"cp {n}/a {n}/link", f"mv {n}/link/f {n}/f", f"rm -r {n}/link/",
                    f"cp {n}/a {n}/./link/../link/b"):
            self.assertFalse(self.covered(cmd), cmd)
        self.assertFalse(self.covered(f"rm {n}/link"))      # conservative: judged on where the link points, not on the link

    def test_dotdot_inside_the_path(self):
        n, o = self.news, self.other
        self.assertFalse(self.covered(f"cp {n}/a {n}/../other/b"))
        self.assertFalse(self.covered(f"cp {n}/sub/../../other/a {n}/b"))
        self.assertTrue(self.covered(f"cp {n}/sub/../a {n}/b"))

    def test_protected_paths_are_never_covered(self):
        gate = os.path.join(self.root, "gate")
        os.makedirs(gate)
        old = os.environ.get("GO_GATE_DIR")
        os.environ["GO_GATE_DIR"] = gate
        try:
            plan = {"targets": [f"dir:{self.root}"], "actions": ["edit"]}
            self.assertIsNone(decide(plan, f"cp {self.news}/a {self.other}/b", self.news))     # the root is a fine grant
            self.assertIsNotNone(decide(plan, f"cp {self.news}/a {gate}/state.json", self.news))
            self.assertIsNotNone(decide(plan, f"echo x > {gate}/config.json", self.news))
            os.symlink(gate, os.path.join(self.news, "gl"))
            self.assertIsNotNone(decide(plan, f"echo x > {self.news}/gl/state.json", self.news))
            self.assertIsNotNone(decide(plan, "echo x > gl/state.json", self.news))
        finally:
            if old is None:
                os.environ.pop("GO_GATE_DIR")
            else:
                os.environ["GO_GATE_DIR"] = old

    def test_keeper_and_settings_paths_are_never_covered(self):
        plan = {"targets": ["dir:/etc", f"dir:{self.news}"], "actions": ["edit"]}
        for cmd in (f"cp {self.news}/a /etc/keeper/config.json", "echo x > /etc/keeper/state.json",
                    f"cp {self.news}/a /opt/agent-guardrails/lib/go_gate.py",
                    f"cp {self.news}/a ~/.claude/settings.json", f"echo x >> ~/.claude/hooks/go-gate.py"):
            self.assertIsNotNone(decide(plan, cmd, self.news), cmd)

    def test_paths_that_cannot_be_judged_fail_closed(self):
        n = self.news
        for cmd in (f"cp {n}/a $DEST", f"cp {n}/a {n}/$NAME", f"cp {n}/a $(echo /etc/y)", f"cp {n}/a `echo /etc/y`",
                    f"cp {n}/a {n}/b\\ c", f"cp {n}/a ${{HOME}}/b", f"cp {n}/a {n}/*/x", f"rm {n}/{{a,../other/b}}",
                    "rm /*", f"rm {n}/../*", f"cp {n}/a host:/etc/y", f"echo x > $OUT"):
            self.assertFalse(self.covered(cmd), cmd)

    def test_wildcard_in_the_last_component_stays_inside(self):
        n = self.news
        self.assertTrue(self.covered(f"rm {n}/*.log"))
        self.assertTrue(self.covered(f"rm -f {n}/sub/?.tmp"))
        self.assertTrue(self.covered("rm *.log", cwd=self.news))
        self.assertFalse(self.covered("rm *.log", cwd=self.other))

    def test_null_sinks_and_web_addresses_are_not_paths_on_this_machine(self):
        n = self.news
        self.assertTrue(self.covered(f"curl -s https://example.com/a/b -o {n}/out"))
        self.assertTrue(self.covered(f"cp {n}/a {n}/b 2>/dev/null"))
        self.assertFalse(self.covered(f"curl -s file:///etc/passwd -o {n}/out"))        # file:// IS a path

    def test_file_tools_are_judged_on_their_file_not_their_content(self):
        n = self.news
        content = "see /etc/passwd, a/b and https://example.com/x for details"
        ok = g.coverage_gap(self.plan, "Write", {"file_path": f"{n}/notes.md", "content": content}, "edit", None)
        self.assertIsNone(ok)
        out = g.coverage_gap(self.plan, "Write", {"file_path": f"{self.other}/notes.md", "content": content}, "edit", None)
        self.assertIsNotNone(out)
        link = g.coverage_gap(self.plan, "Edit", {"file_path": f"{n}/link/x", "old_string": "a", "new_string": "b"},
                              "edit", None)
        self.assertIsNotNone(link)

    def test_no_path_inside_a_dir_target_is_not_covered(self):
        self.assertFalse(self.covered("docker compose restart web"))
        self.assertFalse(self.covered(f"cp /etc/hosts {self.other}/h"))

    def test_plain_targets_keep_the_any_one_token_rule(self):
        """The documented difference: only dir: targets got stricter."""
        n = self.news
        plain = {"targets": [n], "actions": ["edit"]}
        self.assertIsNone(decide(plain, f"cp {n}/a {self.other}/b", self.news))        # as before: one token matches
        named = {"targets": ["web"], "actions": ["deploy", "edit"]}
        self.assertIsNone(decide(named, "docker restart web", self.news))
        self.assertIsNone(decide(named, "cp /etc/a web", self.news))
        mixed = {"targets": [f"dir:{n}", "web"], "actions": ["edit", "deploy"]}
        self.assertIsNone(decide(mixed, "docker restart web", self.news))              # the plain target still works
        self.assertIsNone(decide(mixed, f"cp {n}/a {n}/b", self.news))
        self.assertIsNotNone(decide(mixed, f"cp {n}/a {self.other}/b", self.news))     # the dir: rule is not diluted
        self.assertIsNone(decide(mixed, f"cp {n}/a web", self.news))                   # a path matching ANOTHER target

    def test_many_dirs_each_path_in_any_of_them(self):
        extra = os.path.join(self.root, "extra")
        os.makedirs(extra)
        plan = {"targets": [f"dir:{self.news}", f"dir:{extra}"], "actions": ["edit"]}
        self.assertIsNone(decide(plan, f"cp {self.news}/a {extra}/b", self.news))
        self.assertIsNotNone(decide(plan, f"cp {self.news}/a {self.other}/b", self.news))


class DirRuleMutation(unittest.TestCase):
    """Mutation check: break each part of the dir: rule in a COPY of go_gate.py and run the dir: tests against it --
    every mutant must be caught by at least one failing test, or the tests are not guarding that part."""

    MUTANTS = {
        "any-one-path (the old rule)": ("bad = [p for p, v in verdicts if not v]", "bad = []"),
        "daemon cwd for relative paths": ("    return STAGE_CWD.get(text, CWD) if text is not None else CWD",
                                          "    return os.getcwd()"),
        "no symlink following": ("        r = os.path.realpath(probe)\n    except (OSError, ValueError):\n        return 0",
                                 "        r = os.path.normpath(probe)\n    except (OSError, ValueError):\n        return 0"),
        "protected paths allowed": ("    if is_protected(r) or is_keeper_protected(r):\n        return 0\n    if any(r == b",
                                    "    if any(r == b"),
        "cwd rule switched off": ("        if text is not None:\n            where = cwd_outside_dirs(",
                                  "        if False:\n            where = cwd_outside_dirs("),
        "unknown cwd allowed": ('    if cwd is None or cwd is _CWD_UNKNOWN or not os.path.isabs(str(cwd)):\n        return {"cwd": "unknown"',
                                '    if False:\n        return {"cwd": "unknown"'),
        "cwd symlink not followed": ("        r = os.path.realpath(str(cwd))", "        r = os.path.normpath(str(cwd))"),
        "protected cwd allowed": ("    if is_protected(r) or is_keeper_protected(r) or not any(r == b or",
                                  "    if not any(r == b or"),
        "cwd prefix lookalike": ("not any(r == b or r.startswith(b + os.sep) for b in bases):\n        return {\"cwd\": \"outside\"",
                                 "not any(r == b or r.startswith(b) for b in bases):\n        return {\"cwd\": \"outside\""),
        "remote stages judged locally": ("    if remote:\n        return [safe_words", "    if False:\n        return [safe_words"),
        "redirect targets ignored": ("    for m in REDIRECT.finditer(text):", "    for m in []:"),
        "file-command words ignored": ("            if base in FILE_CMDS:", "            if False:"),
        "variables judged by their text": ('    if any(c in p for c in "$`\\\\!"):\n        return 0', "    if False:\n        return 0"),
    }

    def run_suite(self, tmp):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run([sys.executable, "-m", "unittest", "test_go_gate.DirAllPaths", "test_go_gate.DirRelativePaths",
                            "test_go_gate.DirCwdRule"],
                           cwd=os.path.join(tmp, "go-gate"), capture_output=True, text=True, env=env)
        return r.returncode

    def make_copy(self, tmp, mutate=None):
        os.makedirs(os.path.join(tmp, "go-gate"))
        os.makedirs(os.path.join(tmp, "secret-guard"))
        src = rtext(os.path.join(HERE, "go_gate.py"))
        if mutate:
            old, new = mutate
            self.assertIn(old, src, "the mutation no longer applies: update this test with the code")
            src = src.replace(old, new, 1)
        wtext(os.path.join(tmp, "go-gate", "go_gate.py"), src)
        shutil.copy(os.path.join(HERE, "test_go_gate.py"), os.path.join(tmp, "go-gate", "test_go_gate.py"))
        shutil.copy(os.path.join(HERE, "..", "secret-guard", "secret_guard.py"), os.path.join(tmp, "secret-guard"))

    def test_unmodified_copy_passes(self):                        # the harness itself works
        tmp = tempfile.mkdtemp(prefix=".mutation-", dir=HERE)         # outside the scratch-write exemption
        try:
            self.make_copy(tmp)
            self.assertEqual(self.run_suite(tmp), 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_every_mutant_is_caught(self):
        for name, mutation in self.MUTANTS.items():
            tmp = tempfile.mkdtemp(prefix=".mutation-", dir=HERE)
            try:
                self.make_copy(tmp, mutation)
                self.assertNotEqual(self.run_suite(tmp), 0, f"mutant survived: {name}")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)


class DirRelativePaths(DirTree):
    """Relative paths are resolved against the AGENT's cwd (the hook input's), never against the daemon's."""

    def test_relative_paths_inside_the_agents_cwd_are_covered(self):
        self.assertTrue(self.covered("touch notes.md"))
        self.assertTrue(self.covered("cp ./a.txt sub/b.txt"))
        self.assertTrue(self.covered("echo hi > out.log"))

    def test_relative_dotdot_escape_is_not_covered(self):
        self.assertFalse(self.covered("touch ../x"))
        self.assertFalse(self.covered("cp a.txt ../other/b.txt"))
        self.assertFalse(self.covered("echo hi > ../other/out.log"))
        self.assertFalse(self.covered("touch sub/../../x"))

    def test_relative_path_is_judged_against_the_agents_cwd_not_the_daemons(self):
        os.chdir(self.news)                                   # the daemon sits INSIDE the dir ...
        self.assertFalse(self.covered("touch x", cwd=self.other))      # ... but the agent runs in a sibling
        self.assertFalse(self.covered("touch x", cwd=self.root))
        os.chdir(self.other)                                  # and the other way round
        self.assertTrue(self.covered("touch x", cwd=self.news))
        self.assertFalse(self.covered("touch news/x", cwd=self.root))      # in-dir path, but the cwd is outside it

    def test_relative_symlink_escape_is_not_covered(self):
        self.assertFalse(self.covered("touch link/x"))
        self.assertFalse(self.covered("cp a.txt ./link/b.txt"))

    def test_unknown_cwd_fails_closed_for_a_relative_path(self):
        self.assertFalse(self.covered("touch x", cwd="<unset>"))
        old, g.CWD = g.CWD, None
        try:
            gap = g.coverage_gap(self.plan, "Bash", {"command": "touch x"}, "edit", "touch x")
            self.assertIsNotNone(gap)
        finally:
            g.CWD = old
        self.assertFalse(self.covered(f"touch {self.news}/x", cwd="<unset>"))  # nor does an absolute path pass without one

    def test_a_cd_in_the_same_command_moves_the_cwd(self):
        self.assertFalse(self.covered(f"cd {self.other} && touch x"))          # starts inside, `cd`s out
        self.assertFalse(self.covered("cd .. && touch x"))
        self.assertTrue(self.covered(f"cd {self.news} && touch x", cwd=self.root))
        self.assertFalse(self.covered("cd \"$SOMEWHERE\" && touch x"))         # a cd that cannot be resolved

    def test_relative_dir_target_is_not_a_grant(self):
        plan = {"targets": ["dir:news"], "actions": ["edit"]}
        self.assertIsNotNone(decide(plan, f"touch {self.news}/x", self.root))


class DirCwdRule(DirTree):
    """K-dir, round 3 (20/10): a command that changes something and relies on a `dir:` grant must also run with its
    effective working directory (the hook's, followed through the command's own cd/pushd/popd) inside the dir."""

    def test_cwd_inside_outside_unknown(self):
        cmd = f"touch {self.news}/x"                                   # every path inside: only the cwd differs
        self.assertIsNone(decide(self.plan, cmd, self.news))
        self.assertIsNone(decide(self.plan, cmd, os.path.join(self.news, "sub")))
        self.assertIsNotNone(decide(self.plan, cmd, self.other))
        self.assertIsNotNone(decide(self.plan, cmd, self.root))
        self.assertIsNotNone(decide(self.plan, cmd, "/"))
        self.assertIsNotNone(decide(self.plan, cmd, None))             # unknown: fail closed
        self.assertIsNotNone(decide(self.plan, cmd, "relative/dir"))
        self.assertIsNotNone(decide(self.plan, cmd, "<unset>"))

    def test_cwd_equal_to_the_dir_and_lookalike_sibling(self):
        self.assertIsNone(decide(self.plan, f"touch {self.news}/x", self.news))
        look = self.news + "letter"
        os.makedirs(look)
        self.assertIsNotNone(decide(self.plan, f"touch {self.news}/x", look))

    def test_cwd_symlink_pointing_out(self):
        link = os.path.join(self.news, "link")                         # inside news textually, real dir is `other`
        self.assertIsNotNone(decide(self.plan, f"touch {self.news}/x", link))

    def test_cwd_under_a_protected_path(self):
        gate = os.path.join(self.root, "gate")
        os.makedirs(gate)
        old = os.environ.get("GO_GATE_DIR")
        os.environ["GO_GATE_DIR"] = gate
        try:
            plan = {"targets": [f"dir:{self.root}"], "actions": ["edit"]}
            self.assertIsNone(decide(plan, f"touch {self.news}/x", self.news))
            self.assertIsNotNone(decide(plan, f"touch {self.news}/x", gate))
        finally:
            if old is None:
                os.environ.pop("GO_GATE_DIR")
            else:
                os.environ["GO_GATE_DIR"] = old

    def test_cd_inside_the_command_moves_the_cwd(self):
        n, o = self.news, self.other
        self.assertIsNone(decide(self.plan, f"cd {n} && touch {n}/x", self.root))
        self.assertIsNone(decide(self.plan, f"cd {n}; touch {n}/x", self.root))
        self.assertIsNone(decide(self.plan, f"cd {n}\ntouch {n}/x", self.root))
        self.assertIsNotNone(decide(self.plan, f"cd {o} && touch {n}/x", n))
        self.assertIsNotNone(decide(self.plan, f"cd {o}; touch {n}/x", n))
        self.assertIsNotNone(decide(self.plan, f"cd {o} && cd {n} && cd .. && touch {n}/x", n))
        self.assertIsNone(decide(self.plan, f"cd {o} && cd {n} && touch {n}/x", self.root))
        self.assertIsNotNone(decide(self.plan, f"cd {n} && cd .. && touch {n}/x", n))
        self.assertIsNotNone(decide(self.plan, f"cd \"$X\" && touch {n}/x", n))     # unresolvable cd: unknown
        self.assertIsNotNone(decide(self.plan, f"touch {n}/x && cd {o} && touch {n}/y", n))   # second one is outside
        self.assertIsNotNone(decide(self.plan, f"cd {n}/link && touch {n}/x", n))     # cd through a symlink out

    def test_subshell_and_chains(self):
        n, o = self.news, self.other
        self.assertIsNotNone(decide(self.plan, f"(cd {o} && touch {n}/x)", n))
        self.assertIsNone(decide(self.plan, f"(cd {n} && touch {n}/x)", n))
        self.assertIsNotNone(decide(self.plan, f"(cd {n} && touch {n}/x)", self.root))    # over-refusal: not followed
        self.assertIsNotNone(decide(self.plan, f"(cd {n} && touch {n}/x); touch {n}/y", self.root))   # cd stays in ( )
        self.assertIsNotNone(decide(self.plan, f"echo hi | (cd {o} && tee {n}/x)", n))
        self.assertIsNotNone(decide(self.plan, f"true && cd {o} || touch {n}/x", n))

    def test_plain_targets_and_plans_without_dir_are_unchanged(self):
        n, o = self.news, self.other
        plain = {"targets": [n], "actions": ["edit"]}
        self.assertIsNone(decide(plain, f"touch {n}/x", o))                          # no dir: target, any cwd
        self.assertIsNone(decide(plain, f"touch {n}/x", None))
        named = {"targets": ["web"], "actions": ["deploy"]}
        self.assertIsNone(decide(named, "docker restart web", o))
        mixed = {"targets": [f"dir:{n}", "web"], "actions": ["edit", "deploy"]}
        self.assertIsNone(decide(mixed, "docker restart web", o))                    # matched by the plain target
        self.assertIsNotNone(decide(mixed, f"touch {n}/x", o))                       # relies on the dir: target
        self.assertIsNone(decide(mixed, f"touch {n}/x", n))

    def test_file_tools_have_no_cwd(self):
        gap = g.coverage_gap(self.plan, "Write", {"file_path": f"{self.news}/x.txt"}, "edit")
        self.assertIsNone(gap)                                                       # not a command: unchanged

    def test_refusal_message(self):
        plan = {"targets": ["dir:/opt/stacks/news"], "actions": ["edit"]}      # a short path: shown as written
        gap = decide(plan, "touch /opt/stacks/news/x", "/srv")
        text = g.describe_gap(gap, plan)
        self.assertIn("also runs from inside the directory", text)
        self.assertIn("working directory is outside every dir: target", text)
        self.assertIn("run it from inside /opt/stacks/news", text)
        self.assertIn("use `cd /opt/stacks/news && ...`", text)
        self.assertNotIn("/srv", text)                                               # the cwd itself is not echoed
        unknown = g.describe_gap(decide(plan, "touch /opt/stacks/news/x", None), plan)
        self.assertIn("working directory is not known", unknown)
        self.assertIn("run it from inside /opt/stacks/news", unknown)

    def test_refusal_message_with_a_masked_long_path(self):
        long = "/opt/stacks/news2026-archive-backup-01"                              # 20+ chars with a digit: masked
        plan = {"targets": [f"dir:{long}"], "actions": ["edit"]}
        text = g.describe_gap(decide(plan, f"touch {long}/x", "/srv"), plan)
        self.assertIn("run it from inside a dir: target of the plan", text)
        self.assertNotIn("<…>", text)

    def test_docker_compose_from_elsewhere_is_refused(self):
        plan = {"targets": [f"dir:{self.news}"], "actions": ["deploy"]}
        cmd = f"docker compose -f {self.news}/docker-compose.yml up -d"
        self.assertIsNotNone(decide(plan, cmd, self.other))
        self.assertIsNone(decide(plan, cmd, self.news))
        self.assertIsNone(decide(plan, f"cd {self.news} && {cmd}", self.other))


class Hook(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        wjson(os.path.join(self.dir, "config.json"), {"mode": "block", "owner_ids": ["42"]})

    def propose(self, scope="Scope: id=p1 ; targets=web ; actions=deploy ; ttl=30"):
        return run_hook({"hook_event_name": "Stop", "last_assistant_message": "Plan.\n" + scope}, self.dir)

    def prompt(self, text):
        return run_hook({"hook_event_name": "UserPromptSubmit", "prompt": text}, self.dir)

    def act(self, cmd="docker compose up -d web"):
        return run_hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}}, self.dir)[1]

    def test_go_restates_the_approved_plan(self):
        self.propose("Scope: id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.prompt(telegram("GO"))
        self.assertIn("p1", run_hook.context)
        self.assertIn("web", run_hook.context)
        self.assertIn("deploy", run_hook.context)
        self.assertIn("p1", run_hook.notice)                     # shown to the human in the terminal
        self.assertNotIn("Start your reply", run_hook.notice)
        self.prompt(telegram("merci"))
        self.assertIsNone(run_hook.context)

    def test_restated_plan_is_bounded(self):
        many = ",".join(f"t{i}" for i in range(30))
        self.propose(f"Scope: id=p1 ; targets={many},a`b$(c) ; actions=deploy ; ttl=30")
        self.prompt(telegram("GO"))
        self.assertIn(" …", run_hook.context)
        self.assertNotIn("`", run_hook.context)
        self.assertNotIn("$(", run_hook.context)

    def test_missing_dependency_fails_closed_in_block_mode(self):
        alone = tempfile.mkdtemp()                       # go_gate.py without secret_guard.py anywhere
        src = rtext(os.path.join(HERE, "go_gate.py"))
        src = src.replace('os.path.expanduser("~/.claude/hooks/secret-guard.py")', '"/nonexistent/secret-guard.py"')
        wtext(os.path.join(alone, "go_gate.py"), src)
        env = dict(os.environ, GO_GATE_DIR=self.dir)
        ev = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /opt/x"}})
        r = subprocess.run([sys.executable, os.path.join(alone, "go_gate.py")], input=ev, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)

    def test_reads_always_pass(self):
        self.assertEqual(self.act("docker ps -a"), "allow")

    def test_change_without_plan_is_denied(self):
        self.assertEqual(self.act(), "deny")

    def test_go_activates_the_pending_plan_only(self):
        self.propose()
        self.prompt(telegram("GO"))
        self.assertEqual(self.act(), "allow")
        self.assertEqual(self.act("docker compose up -d db"), "deny")          # outside targets
        self.assertEqual(self.act("git push"), "deny")                         # outside actions

    def test_ambiguous_or_qualified_go_is_ignored(self):
        self.propose()
        for text in ("attends mon GO", "faut-il un GO ?", "GO seulement pour préparer", "ok mais pas le déploiement",
                     "GO other-plan", "GO p1 si les tests passent", "GO A B C", "go ahead and deploy everything"):
            self.prompt(telegram(text))
            self.assertEqual(self.act(), "deny", text)

    def test_compound_command_checked_action_by_action(self):
        self.propose("Scope: id=p1 ; targets=web ; actions=git")
        self.prompt(telegram("GO"))
        self.assertEqual(self.act("git add web"), "allow")
        self.assertEqual(self.act("git add web; docker compose down"), "deny")
        self.assertEqual(self.act("git add web && git commit -m db"), "deny")   # second action names no target

    def test_go_with_plan_id(self):
        self.propose()
        self.prompt(telegram("GO p1"))
        self.assertEqual(self.act(), "allow")

    def test_sessions_do_not_share_plans(self):
        run_hook({"hook_event_name": "Stop", "session_id": "s1",
                  "last_assistant_message": "Scope: id=p1 ; targets=web ; actions=deploy"}, self.dir)
        run_hook({"hook_event_name": "UserPromptSubmit", "session_id": "s2", "prompt": telegram("GO")}, self.dir)
        rc, d = run_hook({"hook_event_name": "PreToolUse", "session_id": "s2", "tool_name": "Bash",
                          "tool_input": {"command": "docker compose up -d web"}}, self.dir)
        self.assertEqual(d, "deny")
        rc, d = run_hook({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
                          "tool_input": {"command": "docker compose up -d web"}}, self.dir)
        self.assertEqual(d, "deny")                                            # s1 never got a GO

    def test_non_at_start_of_a_sentence_does_not_revoke(self):
        self.propose()
        self.prompt(telegram("GO"))
        self.prompt(telegram("non non continue"))
        self.assertEqual(self.act(), "allow")
        self.prompt(telegram("non"))
        self.assertEqual(self.act(), "deny")

    def test_stop_also_drops_the_pending_plan(self):
        self.propose()
        self.prompt(telegram("stop"))
        self.prompt(telegram("GO"))
        self.assertEqual(self.act(), "deny")

    def test_go_from_someone_else_is_ignored(self):
        self.propose()
        self.prompt(telegram("GO", uid="666"))
        self.assertEqual(self.act(), "deny")

    def test_terminal_go_counts(self):
        self.propose()
        self.prompt("go")
        self.assertEqual(self.act(), "allow")

    def test_plan_proposed_through_chat_tool(self):
        ti = {"text": "Plan…\nPérimètre : id=p2 ; targets=web ; actions=deploy"}
        run_hook({"hook_event_name": "PreToolUse", "tool_name": "mcp__plugin_telegram_telegram__reply", "tool_input": ti},
                 self.dir)
        run_hook({"hook_event_name": "PostToolUse", "tool_name": "mcp__plugin_telegram_telegram__reply", "tool_input": ti,
                  "tool_response": "sent (id: 3435)"}, self.dir)
        self.prompt(telegram("OK"))
        self.assertEqual(self.act(), "allow")

    # --- external audit of v0.8 by gpt (07/10) -------------------------------------------------------------------
    def test_undelivered_plan_is_not_pending(self):
        ti = {"text": "Scope: id=p2 ; targets=web ; actions=deploy"}
        run_hook({"hook_event_name": "PreToolUse", "tool_name": "mcp__plugin_telegram_telegram__reply", "tool_input": ti},
                 self.dir)
        self.prompt(telegram("GO"))
        self.assertEqual(self.act(), "deny")                        # never sent: GG-06
        run_hook({"hook_event_name": "PostToolUse", "tool_name": "mcp__plugin_telegram_telegram__reply", "tool_input": ti,
                  "tool_response": {"error": "chat not found"}}, self.dir)
        self.prompt(telegram("GO"))
        self.assertEqual(self.act(), "deny")                        # send failed

    def test_old_pending_plan_expires(self):
        self.propose()
        st = json.loads(rtext(os.path.join(self.dir, "state.json")))
        st["sessions"]["no-session"]["pending"]["proposed_at"] = time.time() - 24 * 3600
        wjson(os.path.join(self.dir, "state.json"), st)
        self.prompt(telegram("GO"))
        self.assertIn("NOT applied", run_hook.context)             # the agent is told, not left guessing
        self.assertEqual(self.act(), "deny")                        # GG-05

    def test_go_dated_in_the_future_is_ignored(self):
        self.propose()
        self.prompt(telegram("GO", ts="2099-01-01T00:00:00.000Z"))
        self.assertEqual(self.act(), "deny")

    def test_replayed_or_old_go_is_ignored(self):
        self.propose()
        self.prompt(telegram("GO", ts="2000-01-01T00:00:00.000Z"))
        self.assertEqual(self.act(), "deny")                        # GG-04: old message
        self.prompt(telegram("GO", mid="777"))
        self.assertEqual(self.act(), "allow")
        self.prompt(telegram("stop"))
        self.propose()
        self.prompt(telegram("GO", mid="777"))
        self.assertEqual(self.act(), "deny")                        # same message_id used twice

    def test_unicode_look_alikes_are_not_go(self):
        for text in ("yeſ", "G\u041e", "GO\u200b", "ＧＯ"):
            self.propose()
            self.prompt(telegram(text))
            self.assertEqual(self.act(), "deny", repr(text))      # GG-09

    def test_every_object_must_be_in_scope(self):
        self.propose()
        self.prompt(telegram("GO"))
        self.assertEqual(self.act("docker restart web"), "allow")
        self.assertEqual(self.act("docker restart db web"), "deny")   # GG-07

    def test_deny_reason_names_what_is_missing(self):
        self.propose("Scope: id=p1 ; targets=web ; actions=deploy ; ttl=30")
        self.prompt(telegram("GO"))
        self.assertEqual(self.act("docker compose -f /opt/stacks/db/compose.yml restart"), "deny")
        self.assertIn("targets not covered: /opt/stacks/db/compose.yml", run_hook.reason)
        self.assertIn("plan targets: web", run_hook.reason)
        self.assertEqual(self.act("git push origin web"), "deny")
        self.assertIn("missing action 'git'", run_hook.reason)
        self.assertIn("plan actions: deploy", run_hook.reason)

    def test_gate_state_cannot_be_written_through_a_link(self):
        link = os.path.join(tempfile.mkdtemp(), "x.json")
        os.symlink(os.path.join(self.dir, "state.json"), link)
        env = dict(os.environ, GO_GATE_DIR=self.dir)
        old = os.environ.get("GO_GATE_DIR")
        os.environ["GO_GATE_DIR"] = self.dir
        try:
            self.assertEqual(g.classify("Write", {"file_path": link})[0], "change")             # GG-02
            self.assertEqual(g.classify("Bash", {"command": f"echo x > {link}"})[0], "change")
            st = os.path.join(self.dir, "state.json")
            for cmd in (f"F={st}; echo x > $F", f"F={st}; cp /tmp/a $F", f"cp /tmp/a {st}"):     # Gemini audit of v0.9
                kind, detail = g.classify("Bash", {"command": cmd})
                self.assertEqual(g.category("Bash", {"command": cmd}, kind, detail), "protected", cmd)
            self.assertEqual(g.category("Write", {"file_path": link}, "change", "protected go-gate state"), "protected")
        finally:
            if old is None:
                os.environ.pop("GO_GATE_DIR")
            else:
                os.environ["GO_GATE_DIR"] = old

    def test_stop_revokes(self):
        self.propose()
        self.prompt(telegram("GO"))
        self.prompt(telegram("stop"))
        self.assertEqual(self.act(), "deny")

    def test_expiry(self):
        self.propose()
        self.prompt(telegram("GO"))
        st = json.loads(rtext(os.path.join(self.dir, "state.json")))
        st["sessions"]["no-session"]["active"]["expires"] = time.time() - 1
        wjson(os.path.join(self.dir, "state.json"), st)
        self.assertEqual(self.act(), "deny")

    def test_go_without_plan_does_nothing(self):
        self.prompt(telegram("GO"))
        self.assertEqual(self.act(), "deny")

    def test_log_keeps_command_words(self):
        self.act("FOO=bar docker compose -f /opt/x.yml up -d && git push origin main")
        line = json.loads(rtext(os.path.join(self.dir, "log.jsonl")).splitlines()[-1])
        self.assertEqual(line["head"], "docker compose ; git push")

    def test_observe_mode_never_blocks_but_logs(self):
        wjson(os.path.join(self.dir, "config.json"), {"mode": "observe", "owner_ids": ["42"]})
        self.assertEqual(self.act(), "allow")
        log = rtext(os.path.join(self.dir, "log.jsonl"))
        self.assertIn("would-block", log)

    def test_fail_closed_in_block_mode(self):
        wtext(os.path.join(self.dir, "state.json"), "{broken")
        rc, _ = run_hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}, self.dir)
        self.assertEqual(rc, 2)

    def test_log_holds_no_secret(self):
        fake = "Zq7" * 9
        for cmd in ("curl -X POST -H 'Authorization: token ghp_" + fake + "' https://x",
                    "curl -X POST -H 'Authorization: Bearer " + fake + "' https://x",
                    "curl -X POST https://user:" + fake + "@host/x",
                    "curl -X POST -H 'X-Api-Key: " + fake + "' https://x",
                    "API_KEY=" + fake + " curl -X POST https://x",
                    "API_KEY='Zq7Zq7x' docker compose up -d",
                    'curl -X POST -H "Authorization: Bearer Zq7Zq7y" https://x',
                    "DB_PASSWORD=\"Zq7Zq7 z\" psql -c 'delete from t'",
                    "curl -u alice:" + "Zq7Zq7w -X POST https://example.org",
                    "curl --user=alice:" + "Zq7Zq7v -X POST https://example.org",
                    "curl -ualice:" + "Zq7Zq7w -X POST https://example.org",           # review 4: attached values
                    "mysql -pZq7Zq7m -e 'drop table t'",
                    "PGPASSWORD=Zq7Zq7 psql -c 'delete from t'",                   # short value, any variable name
                    "FOO=Zq7Zq7f BAR=Zq7Zq7g make deploy",
                    "rsync -a x alice:" + "Zq7Zq7r@host:/opt/x",
                    "curl -sualice:" + "Zq7Zq7s -X POST https://example.org",     # review 5: grouped options
                    "curl --proxy-user alice:" + "Zq7Zq7x -X POST https://example.org",
                    "curl -X POST https://" + "Zq7Zq7t@example.org/x",
                    "curl -X POST https://example.org/?k=" + "Zq7Zq7q",
                    "docker login -u alice --password-stdin <<< Zq7Zq7d"):
            self.act(cmd)
        self.assertNotIn("Zq7Zq7", rtext(os.path.join(self.dir, "log.jsonl")))


if __name__ == "__main__":
    unittest.main()

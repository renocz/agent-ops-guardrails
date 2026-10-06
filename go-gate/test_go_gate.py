"""Offline tests for go_gate.py: the classifier, the GO parsing, the scope and the hook decisions."""
import json, os, subprocess, sys, tempfile, time, unittest

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
    # opaque
    ("bash deploy.sh", "opaque"),
    ("eval \"$CMD\"", "opaque"),
    ("$TOOL --apply", "opaque"),
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
    return r.returncode, out.get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def telegram(text, uid="42"):
    return f'<channel source="plugin:telegram:telegram" chat_id="1" message_id="9" user="u" user_id="{uid}" ts="x">\n{text}\n</channel>'


class Classifier(unittest.TestCase):
    def test_bash(self):
        for cmd, kind in BASH:
            with self.subTest(cmd=cmd):
                self.assertEqual(g.classify("Bash", {"command": cmd})[0], kind)

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


class Scope(unittest.TestCase):
    def test_parse(self):
        p = g.parse_scope("Plan…\nScope: id=upd-web ; targets=web, /opt/stacks/web ; actions=deploy,git ; ttl=30min")
        self.assertEqual((p["id"], p["targets"], p["actions"], p["ttl"]), ("upd-web", ["web", "/opt/stacks/web"], ["deploy", "git"], 30))
        self.assertEqual(g.parse_scope("Périmètre : id=x ; actions=edit ; durée=2h")["ttl"], 120)
        self.assertIsNone(g.parse_scope("no scope here"))
        self.assertIsNone(g.parse_scope("Scope: id=x ; actions=everything"))       # unknown category only

    def test_covers(self):
        plan = {"targets": ["web"], "actions": ["deploy"]}
        self.assertTrue(g.covers(plan, "Bash", {"command": "docker compose up -d web"}, "deploy"))
        self.assertFalse(g.covers(plan, "Bash", {"command": "docker compose up -d db"}, "deploy"))
        self.assertFalse(g.covers(plan, "Bash", {"command": "git push"}, "git"))


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
        run_hook({"hook_event_name": "PreToolUse", "tool_name": "mcp__plugin_telegram_telegram__reply",
                  "tool_input": {"text": "Plan…\nPérimètre : id=p2 ; targets=web ; actions=deploy"}}, self.dir)
        self.prompt(telegram("OK"))
        self.assertEqual(self.act(), "allow")

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

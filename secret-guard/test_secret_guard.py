"""Offline tests for secret_guard.py. Each case is (command, expected: True = allowed, False = refused)."""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(__file__))
import secret_guard as sg

BASH = [
    # plain, harmless
    ("ls -la /tmp", True),
    ("docker ps -a", True),
    ("set -euo pipefail; echo ok", True),
    # risky, unmasked
    ("cat .env", False),
    ("docker inspect web", False),
    ("crontab -l", False),
    ("env", False),
    ("git push origin main", False),
    ("base64 ~/.ssh/id_ed25519", False),
    ("kubectl get secret db -o yaml", False),
    ("security find-generic-password -s svc -w", False),
    ('PAT=$(security find-generic-password -s svc -w); tool login', True),
    ("pass-cli item list Infra", True),
    # risky, masked properly
    ("cat .env 2>&1 | mask", True),
    ("crontab -l |& mask", True),
    ("ssh host 'docker inspect web' 2>&1 | mask", True),
    ("{ crontab -l; cat .env; } 2>&1 | mask", True),
    ("(env; docker inspect x) 2>&1 | mask", True),
    # stdout masked but stderr not
    ("cat .env | mask", False),
    # mask applies to one statement only, the other leaks
    ("cat .env; echo done 2>&1 | mask", False),
    ("cat .env && ls 2>&1 | mask", False),
    ("crontab -l & true 2>&1 | mask", False),
    ("cat .env\nls 2>&1 | mask", False),
    # mask hidden in a comment or a string does not count
    ("cat .env  # 2>&1 | mask", False),
    ("cat .env; echo '2>&1 | mask'", False),
    # marker: only valid as the very last thing
    ("grep -c KEY .env # secret-ok", True),
    ("grep -c KEY .env # secret-ok\n", True),
    ("cat .env # secret-ok\ncrontab -l", False),
    ("echo '# secret-ok'; cat .env", False),
    # quotes and separators inside quotes are not statement breaks
    ("ssh host 'cat a; cat .env' 2>&1 | mask", True),
    ("echo 'a && b'; ls", True),
    # stderr redirections are not statement separators
    ("ls >/dev/null 2>&1", True),
    ("cat .env &>/dev/null 2>&1 | mask", True),
    # found by the council review: an escaped '#' is an argument, not a comment, so it is no marker
    ("cat .env \\# secret-ok", False),
    ("cat .env #secret-ok", True),
    # a literal brace is not a group and must not swallow the separators that follow it
    ("echo { ; cat .env; ls 2>&1 | mask", False),
    ("echo }; cat .env; ls 2>&1 | mask", False),
    ("{ cat .env; } 2>&1 | mask", True),
    # redirections that route around the mask
    ("cat .env >&2 2>&1 | mask", False),
    ("cat .env > /dev/tty 2>&1 | mask", False),
    ("cat .env | tee /dev/stderr 2>&1 | mask", False),
    # unclosed quote or group: the whole command is judged as unmasked
    ("echo 'oops; cat .env 2>&1 | mask", False),
    # heredocs: a body may be executed, so it is checked like commands (conservative)
    ("bash -s <<'EOF'\ncrontab -l\nEOF", False),
    ("{ bash -s <<'EOF'\ncrontab -l\nEOF\n} 2>&1 | mask", True),
    ("docker run --rm img env", False),
    ("docker compose -f prod.yml config", False),
    # second council review: every risky pipeline stage must send its stderr into the pipe
    ("docker inspect web | cat 2>&1 | mask", False),
    ("docker inspect web 2>&1 | grep -v x | mask", True),
    ("docker inspect web |& grep -v x | mask", True),
    ("ls | mask", True),                       # nothing risky in it
    ("grep -rhoE 'sk-[A-Za-z0-9]{20,}' docs/", False),
    ("grep -rlE 'sk-[A-Za-z0-9]{20,}' docs/", True),
    ("for f in a.env b.env; do cat $f; done", False),
    ('for f in a.env; do cat "$f" | mask; done', False),          # third council review: stderr of cat not masked
    ('for f in a.env; do cat "$f" 2>&1 | mask; done', True),
    ("git ls-files | wc -l; scp a host:/tmp; ssh host 'pct push 1 a b'", True),   # git + push in unrelated commands
    ("python3 -c 'import secrets; print(secrets.token_hex(4))'", True),
    ("cat .env | grep -v x 2>&1 | mask", False),
]

READS = [
    ({"file_path": "/srv/app/.env"}, False),
    ({"file_path": "/home/u/.ssh/id_ed25519"}, False),
    ({"file_path": "/home/u/.ssh/id_ed25519.pub"}, True),
    ({"file_path": "/srv/app/README.md"}, True),
    ({"path": "/srv/app", "glob": "*.env"}, False),
    ({"path": ".", "glob": "**/.env"}, False),
]


class SecretGuard(unittest.TestCase):
    def test_bash(self):
        for cmd, allowed in BASH:
            with self.subTest(cmd=cmd):
                self.assertEqual(sg.check_bash(cmd) is None, allowed)

    def test_read(self):
        for ti, allowed in READS:
            with self.subTest(ti=ti):
                self.assertEqual(sg.check_read("Read", ti) is None, allowed)

    def test_mask_filter(self):
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        fake = ["fake" + "value" + str(n) * 4 for n in range(4)]     # built at run time so secret scanners stay quiet
        sample = (f"token={fake[0]}\nAuthorization: Bearer {fake[1]}\nhttps://u:{fake[2]}@h/x\n"
                  f"-----BEGIN RSA PRIVATE KEY-----\n{fake[3]}\n-----END RSA PRIVATE KEY-----\nnormal line\n")
        out = subprocess.run([os.path.join(here, "mask")], input=sample, capture_output=True, text=True).stdout
        sample += "password=abc\ncurl --token \"quoted" + "value9\" x\n"
        out = subprocess.run([os.path.join(here, "mask")], input=sample, capture_output=True, text=True).stdout
        for secret in fake + ["abc", "quotedvalue9"]:
            self.assertNotIn(secret, out)
        self.assertIn("normal line", out)

    def test_grep_content_hunting_secrets(self):
        self.assertIsNotNone(sg.check_read("Grep", {"pattern": "API_KEY", "path": ".", "output_mode": "content"}))
        self.assertIsNone(sg.check_read("Grep", {"pattern": "API_KEY", "path": ".", "output_mode": "files_with_matches"}))
        self.assertIsNone(sg.check_read("Grep", {"pattern": "def main", "path": ".", "output_mode": "content"}))

    def test_broken_extras_fail_closed(self):
        import json, tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([["(unclosed", "bad"]], f)
        try:
            os.environ["SECRET_GUARD_EXTRA"] = f.name
            self.assertIn("invalid extra patterns", " ".join(label for _, label in sg._load_extra()))
        finally:
            del os.environ["SECRET_GUARD_EXTRA"]; os.unlink(f.name)

    def test_decide_ignores_other_tools(self):
        self.assertIsNone(sg.decide({"tool_name": "Write", "tool_input": {"file_path": ".env"}}))

    def test_split(self):
        self.assertEqual(sg.split_statements("a; b && c || d"), ["a", "b", "c", "d"])
        self.assertEqual(sg.split_statements("{ a; b; } 2>&1 | mask"), ["{ a; b; } 2>&1 | mask"])
        self.assertEqual(sg.split_statements("echo 'x; y' # c; d"), ["echo 'x; y'"])


if __name__ == "__main__":
    unittest.main()

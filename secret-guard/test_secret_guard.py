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
    # external evaluation (05/10): honest homelab accidents that used to pass
    ("printenv DATABASE_URL", False),
    ("echo $API_KEY", False),
    ('echo "${DB_PASSWORD}"', False),
    ("echo $HOME", True),
    ("wg showconf wg0", False),
    ("wg show wg0 private-key", False),
    ("wg genkey", False),
    ("wg show", True),                         # private keys are shown as (hidden)
    ("cat /etc/wireguard/wg0.conf", False),
    ("cat traefik/acme.json", False),
    ("cat config.toml", False),
    ("cat settings.ini", False),
    ("cat pyproject.toml", True),
    ("docker logs app", False),
    ("docker logs app 2>&1 | mask", True),
    ("docker compose logs --tail 50", False),
    ("journalctl -u app", False),
    ("kubectl logs pod/app", False),
    ("grep -rhoE 'sk-[A-Za-z0-9]{20,}' docs/", False),
    ("grep -rlE 'sk-[A-Za-z0-9]{20,}' docs/", True),
    ("for f in a.env b.env; do cat $f; done", False),
    ('for f in a.env; do cat "$f" | mask; done', False),          # third council review: stderr of cat not masked
    ('for f in a.env; do cat "$f" 2>&1 | mask; done', True),
    ("git ls-files | wc -l; scp a host:/tmp; ssh host 'pct push 1 a b'", True),   # git + push in unrelated commands
    ("python3 -c 'import secrets; print(secrets.token_hex(4))'", True),
    ("cat .env | grep -v x 2>&1 | mask", False),
    # external audit of v0.2 (06/10): secret files and tools that print decrypted secrets
    ("cat ~/.pgpass", False),
    ("cat ~/.my.cnf", False),
    ("cat .envrc", False),
    ("cat /etc/pve/priv/token.cfg", False),
    ("cat ~/.config/gh/hosts.yml", False),
    ("rclone config show", False),
    ("rclone config show 2>&1 | mask", True),
    ("rclone config redacted", True),
    ("sops -d secrets.enc.yaml", False),
    ("sops -e -i secrets.enc.yaml", True),
    ("ansible-vault view vault.yml", False),
    ("ls /etc/pve/priv", True),
    ('curl -u "$USER:$PASS" https://x', True),
    ("mysql -h db -P 3306 -u root -p", True),
    ('mysql -p"$PW" -e "select 1"', True),
    ("docker run -u 1000:1000 alpine id", True),
    ("tailscale up --authkey=file:/etc/ts.key", True),
    ("PGPASSWORD=$(cat /root/.pgpw) psql -c 'select 1' 2>&1 | mask", True),
    ("gpg -dq backup.tar.gpg", False),                          # council review of v0.2.1: grouped options
    ("gpg --list-secret-keys --keyid-format long", True),
    ("age -d -i key.txt secrets.age", False),
    # blind test set 1 (gemini-3.1-pro, 06/10)
    ("gh auth token", False),
    ("gh auth status", True),
    ("aws configure export-credentials", False),
    ("cloudflared tunnel token my-tunnel", False),
    ("cloudflared tunnel list", True),
    ("psql -U postgres -c 'SELECT usename, passwd FROM pg_shadow;'", False),
    ("pct exec 101 -- cat /etc/shadow", False),
    ("printenv USER", True),
    ("printenv DB_HOST", False),
    ("cat ~/.ssh/id_ed25519.pub", True),
    ("cat ~/.ssh/id_ed25519", False),
    ("mariadb -uroot -p\\$MARIADB_ROOT_PASSWORD romm -e 'select 1' 2>&1 | mask", True),   # variable in nested quoting
    ("PASSWORD_MIN_LENGTH=12 ./setup.sh", True),
    # blind test set 2 (gpt-6.1-sol, 06/10)
    ("pct exec 104 -- cat /root/.n8n/config", False),
    ("cat /etc/grafana/grafana.ini", False),
    ("cat /etc/cloudflared/homelab.json", False),
    ("restic -r /srv/backup dump latest /srv/n8n/.env", False),
    ("restic -r /srv/backup snapshots", True),
    ("tailscale debug local-creds", False),
    ("tailscale status", True),
    ("pveum user token add root@pam backups --privsep 1", False),
    ("pveum user token list root@pam", True),
    ("psql -d homelab -Atc 'SELECT service, api_key FROM service_credentials;'", False),
    ("psql -d homelab -Atc 'SELECT count(*) FROM service_credentials;'", True),
    ("grep -c '^API_KEY=' /srv/prowlarr/.env", True),
    ("grep -l TOKEN /srv/*/.env", True),
    ("grep '^API_KEY=' /srv/prowlarr/.env", False),
    ("grep -c x a.env && cat a.env", False),
    # blind test set 3 (mistral-large-3, 06/10)
    ("redis-cli GET api_key", False),
    ("redis-cli HGETALL session:42", False),
    ("redis-cli GET api_key 2>&1 | mask", True),
    ("redis-cli ping", True),
    ("redis-cli INFO memory", True),
    ("tailscale debug authkey", False),
    ("qm cloudinit dump 100 user", False),
    ("qm config 100", True),
    ("docker login --password-stdin -u bob registry.example.org", True),
    ("pass-cli item list --vault claude", True),
]

READS = [
    ({"file_path": "/srv/app/.env"}, False),
    ({"file_path": "/home/u/.ssh/id_ed25519"}, False),
    ({"file_path": "/home/u/.ssh/id_ed25519.pub"}, True),
    ({"file_path": "/srv/app/README.md"}, True),
    ({"path": "/srv/app", "glob": "*.env"}, False),
    ({"path": ".", "glob": "**/.env"}, False),
    ({"file_path": "/etc/wireguard/wg0.conf"}, False),
    ({"file_path": "/srv/traefik/acme.json"}, False),
    ({"file_path": "/srv/app/config.toml"}, False),
    ({"file_path": "/srv/app/settings.ini"}, False),
    ({"file_path": "/srv/app/pyproject.toml"}, True),
    ({"file_path": "/srv/app/.envrc"}, False),                 # external audit of v0.2 (06/10)
    ({"file_path": "/etc/pve/priv/token.cfg"}, False),
    ({"file_path": "/root/.config/gh/hosts.yml"}, False),
    ({"file_path": "/root/.pgpass"}, False),
    ({"file_path": "/root/.my.cnf"}, False),
    ({"file_path": "/etc/pve/storage.cfg"}, True),
    ({"file_path": "/var/www/nextcloud/config/config.php"}, False),     # blind test set 1
    ({"file_path": "/etc/shadow"}, False),
    ({"file_path": "/etc/gitea/app.ini"}, False),                    # blind test set 2
    ({"file_path": "/etc/grafana/grafana.ini"}, False),
]


FAKE = "Ab1" * 12
PW = "hunter" + "22"
ADMIN_PW = "admin" + ":" + PW
LITERAL = [
    # a secret typed into the command: refused, even masked or with the marker
    ("AWS_ACCESS_KEY_ID=AKIA" + "ABCDEFGHIJKLMNOP aws s3 ls", False),
    ("curl -H 'Authorization: token ghp_" + FAKE + "' https://api.github.com/user", False),
    ("curl -H 'x-api-key: sk-ant-" + FAKE + "' https://api.example.com 2>&1 | mask", False),
    ("echo github_pat_" + FAKE + " # secret-ok", False),
    ("curl -H 'Authorization: Bearer eyJ" + FAKE + ".eyJ" + FAKE + ".sig' https://x", False),
    ("printf '-----BEGIN OPENSSH PRIVATE KEY-----' > k", False),
    # prefixes alone, searches and references stay allowed
    ("grep -c ghp_ notes.md", True),
    ("grep -rl 'sk-ant-' . 2>&1 | mask", True),
    ("git log --grep AKIA --oneline", True),
    ('curl -H "Authorization: Bearer $TOKEN" https://x', True),   # gitleaks:allow (a variable, not a value)
    # passwords typed in clear (external audit of v0.2, 06/10): refused, even masked
    ("curl -u " + ADMIN_PW + " https://example.org 2>&1 | mask", False),
    ("wget --user=bob:" + PW + " https://example.org", False),
    ('curl -u "$API_USER:' + PW + '" https://example.org', False),   # user is a variable, password literal
    ("mysql -p" + PW + " -e 'select 1'", False),
    ("sshpass -p " + PW + " ssh host", False),
    ("psql postgres://app:" + PW + "@db/app -c 'select 1'", False),
    ("PGPASSWORD=" + PW + " psql -c 'select 1'", False),
    ("tailscale up --authkey tskey-auth-" + FAKE + "-" + FAKE, False),
    ("redis-cli -a " + PW + " ping", False),
    ("qbittorrent-nox --webui-port=8080 --password=" + PW, False),   # blind test set 3
    ("echo 'API_KEY=" + PW + "' # secret-ok", False),
    ("restic snapshots --password-file /root/.restic.pass", True),                         # blind test set 1
    ("RESTIC_PASSWORD=" + PW + " restic snapshots # secret-ok", False),
    ("curl -H 'Authorization: Bearer " + PW + "x' https://gitea.example.org/api/v1/users", False),
]


class SecretGuard(unittest.TestCase):
    def test_literal_secret_in_command(self):
        for cmd, allowed in LITERAL:
            with self.subTest(cmd=cmd[:40]):
                self.assertEqual(sg.check_bash(cmd) is None, allowed)

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

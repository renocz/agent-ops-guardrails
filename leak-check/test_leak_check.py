"""Tests for leak-check, with fake secrets only (built at run time, so no scanner flags this file)."""
import json, os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leak_check as lc

FAKE = "Zq7" + "Kp2" * 6
PEM_BEGIN, PEM_END = lc.PEM_BEGIN, lc.PEM_END


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def transcript(path, *texts):
    w(path, "".join(json.dumps({"message": {"content": [{"type": "text", "text": t}]}}) + "\n" for t in texts))


class LeakCheck(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        w(f"{self.d}/stack/.env", f"APP_PORT=8080\nDB_PASSWORD={FAKE}\nAPI_URL=https://x.example\nSHORT_TOKEN=abc\n"
                                  f"PATH_SECRET=/run/secrets/x\nTOKEN_FROM_ENV=${{OTHER}}\nPROXMOX_TOKEN_ID=svc@pve!import-token\n"
                                  "OAUTH_CLIENTID=" + "abcdef" * 3 + "\n")
        w(f"{self.d}/single.key", FAKE[::-1] + "\n")
        self.t = f"{self.d}/projects/p1"
        transcript(f"{self.t}/clean.jsonl", "nothing to see")
        self.cfg = {"env_files": [f"{self.d}/*/.env"], "value_files": [f"{self.d}/single.key"], "key_files": [],
                    "targets": [f"{self.d}/projects/**/*.jsonl"], "min_length": 12, "ignore_names": []}

    def names(self, r):
        return sorted(h["secret"].split(":")[-1].replace(self.d + "/", "") for h in r["leaks"])

    def test_only_secret_values_are_collected(self):
        vals = lc.collect_values(self.cfg)
        self.assertEqual(sorted(n for n, _k in vals.values()), sorted([f"{self.d}/stack/.env:DB_PASSWORD", f"{self.d}/single.key"]))

    def test_no_leak(self):
        r = lc.scan(self.cfg)
        self.assertEqual(r["leaks"], [])
        self.assertEqual(r["inventory"], {"env": 1, "file": 1})

    def test_leak_found_by_exact_value(self):
        transcript(f"{self.t}/s.jsonl", f"psql -W {FAKE}")
        self.assertEqual(self.names(lc.scan(self.cfg)), ["DB_PASSWORD"])

    # the five shapes of the fourth external audit (06/10): only one of them was found before
    def test_password_inside_a_url_whatever_the_key(self):
        w(f"{self.d}/u/.env", f"DATABASE_URL=postgres://app:{FAKE}u@db/app\n")
        transcript(f"{self.t}/s.jsonl", f"connect postgres://app:{FAKE}u@db/app")
        cfg = dict(self.cfg, env_files=[f"{self.d}/u/.env"], value_files=[])
        self.assertEqual(self.names(lc.scan(cfg)), ["DATABASE_URL (password in URL)"])

    def test_quote_and_backslash_survive_json_escaping(self):
        w(f"{self.d}/q/.env", f"API_TOKEN='{FAKE}\"q'\nDB_PASSWORD={FAKE}\\b\n")
        transcript(f"{self.t}/s.jsonl", f"curl -H 'X: {FAKE}\"q'", f"echo {FAKE}\\b")
        cfg = dict(self.cfg, env_files=[f"{self.d}/q/.env"], value_files=[])
        self.assertEqual(self.names(lc.scan(cfg)), ["API_TOKEN", "DB_PASSWORD"])

    def test_private_key_lines(self):
        body = [(c + FAKE * 4)[:64] for c in "ABC"] + [("D" + FAKE[::-1] * 4)[:64]]
        w(f"{self.d}/id_test", PEM_BEGIN + "\n" + "\n".join(body) + "\n" + PEM_END + "\n")
        w(f"{self.d}/id_test.pub", "ssh-ed25519 AAAA public\n")
        transcript(f"{self.t}/s.jsonl", "cat id_test\n" + body[3])
        cfg = dict(self.cfg, key_files=[f"{self.d}/id_*"], env_files=[], value_files=[])
        r = lc.scan(cfg)
        self.assertEqual(self.names(r), ["id_test (private key)"])
        self.assertEqual(r["inventory"], {"key": 2})              # header and public-key lines are not counted

    def test_shared_key_header_is_not_a_leak(self):
        body = [(c + FAKE * 4)[:64] for c in "ABCD"]
        w(f"{self.d}/id_test", PEM_BEGIN + "\n" + "\n".join(body) + "\n" + PEM_END + "\n")
        transcript(f"{self.t}/s.jsonl", "another key of the same type starts with\n" + body[0] + "\n" + body[1])
        cfg = dict(self.cfg, key_files=[f"{self.d}/id_*"], env_files=[], value_files=[])
        self.assertEqual(lc.scan(cfg)["leaks"], [])

    def test_plain_text_targets(self):
        w(f"{self.d}/hist", f"ls\nmysql -p{FAKE}\n")
        self.assertEqual(self.names(lc.scan(self.cfg, [f"{self.d}/hist"])), ["DB_PASSWORD"])

    # the five shapes of the fifth external audit (06/10): none of them was inventoried before
    def test_compose_yaml_and_list_forms(self):
        w(f"{self.d}/c/compose.yaml", f"services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: {FAKE}y\n"
                                      f"      - MYSQL_ROOT_PASSWORD={FAKE}l  # comment\n    image: postgres:16\n")
        vals = lc.collect_values(dict(self.cfg, env_files=[f"{self.d}/c/compose.yaml"], value_files=[]))
        self.assertEqual(sorted(n.split(":")[-1] for n, _k in vals.values()), ["MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD"])

    def test_config_options_are_not_secrets(self):
        w(f"{self.d}/o/compose.yaml", "      TINYAUTH_AUTH_TRUSTEDPROXIES: 172.16.0.0/12,10.0.0.0/8\n"
                                      "      PRIVATE_TRACKER_HANDLING: skip_and_keep_seeding\n"
                                      f"      PLEX_TOKEN: {FAKE}x\n")
        vals = lc.collect_values(dict(self.cfg, env_files=[f"{self.d}/o/compose.yaml"], value_files=[]))
        self.assertEqual([n.split(":")[-1] for n, _k in vals.values()], ["PLEX_TOKEN"])

    def test_templates_are_not_secrets(self):
        w(f"{self.d}/def/indexer.yml", 'api_key: "{{ .Config.apikey }}"\n'
                                       "token: '{% if x %}abcdefghijkl{% endif %}'\n"
                                       f"apikey: {FAKE}d\n")
        vals = lc.collect_values(dict(self.cfg, env_files=[], value_files=[], config_files=[f"{self.d}/def/*.yml"]))
        self.assertEqual([n.split(":")[-1] for n, _k in vals.values()], ["apikey"])

    # --- external audit of v0.8 by gpt (07/10): values that were never inventoried --------------------------------
    def inv(self, name, text, kind="config_files"):
        w(f"{self.d}/a/{name}", text)
        cfg = dict(self.cfg, env_files=[], value_files=[], config_files=[], json_files=[], key_files=[])
        cfg[kind] = [f"{self.d}/a/{name}"]
        return sorted(n.split(":", 1)[-1].replace(f"{self.d}/a/", "") for n, _k in lc.collect_values(cfg).values())

    def test_short_password_under_a_secret_name(self):
        self.assertEqual(len(self.inv("a.env", "PASSWORD=hunter22\nPIN_CODE=1234\nPORT_PASSWORD_MIN=8\n", "env_files")), 1)

    def test_yaml_block_xml_attribute_pgpass_token_cfg_json_list(self):
        self.assertEqual(self.inv("c.yml", "api_token: |\n  " + FAKE + "y\nother: 1\n"), ["api_token"])
        self.assertEqual(self.inv("Preferences.xml", '<Preferences PlexOnlineToken="' + FAKE + 'x" Port="32400"/>'),
                         ["PlexOnlineToken"])
        self.assertEqual(self.inv(".pgpass", "localhost:5432:db:app:" + FAKE + "g\n"), ["PGPASS_PASSWORD"])
        self.assertEqual(self.inv("token.cfg", "root@pam!agent " + "a1b2c3d4-0000-4000-8000-" + "123456789abc" + "\n"),
                         ["PROXMOX_TOKEN_SECRET"])
        self.assertEqual(self.inv("d.json", json.dumps({"tokens": [FAKE + "t"]})), ["tokens"])

    def test_rclone_token_and_docker_auth(self):
        tok = json.dumps({"access_token": FAKE + "a", "token_type": "Bearer", "refresh_token": FAKE + "r", "expiry": "x"})
        got = self.inv("rclone.conf", "[gd]\ntype = drive\ntoken = " + tok + "\n")
        self.assertIn("token:access_token", got)
        self.assertIn("token:refresh_token", got)
        self.assertFalse([g for g in got if g.endswith("token_type")])   # "Bearer" is not a secret
        import base64
        auth = base64.b64encode(("alice:" + FAKE + "d").encode()).decode()
        got = self.inv("config.json", json.dumps({"auths": {"r.io": {"auth": auth}}}))
        self.assertEqual(got, ["auth", "auth (decoded password)"])

    def test_json_files_url_password(self):
        self.assertEqual(self.inv("e.json", json.dumps({"DATABASE_URL": "postgres://u:" + FAKE + "u@h/db"}), "json_files"),
                         ["DATABASE_URL (password in URL)"])

    def test_one_line_pem_key(self):
        body = ("MC4CAQAwBQYDK2VwBCIEI" + FAKE * 3)[:64]
        w(f"{self.d}/k/ed.pem", "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----\n")
        cfg = dict(self.cfg, env_files=[], value_files=[], key_files=[f"{self.d}/k/ed.pem"])
        self.assertEqual(len(lc.collect_values(cfg)), 1)

    def test_skipped_files_are_reported(self):
        w(f"{self.d}/s/app.sqlite", "x")
        w(f"{self.d}/s/settings.old.json", "{}")
        cfg = dict(self.cfg, env_files=[], value_files=[], config_files=[f"{self.d}/s/*"])
        self.assertEqual(len(lc.scan(cfg)["skipped_sources"]), 2)

    def test_references_and_placeholders_are_not_values(self):
        self.assertEqual(self.inv("c.yaml", "  api_key: os.environ/OPENAI_API_KEY\n  master_key: sk-1234\n"
                                  "  sessionSecret: <hidden>\n  password: ********\n  token: [REDACTED]\n"), [])   # real run, 07/10

    def test_rotated_value_leaking_again_is_new(self):
        state = f"{self.d}/st.json"
        r1 = lc.only_new({"leaks": [{"secret": "x:API_TOKEN", "transcript": "t", "occurrences": 1, "vid": "aaa"}]}, state)
        r2 = lc.only_new({"leaks": [{"secret": "x:API_TOKEN", "transcript": "t", "occurrences": 1, "vid": "bbb"}]}, state)
        r3 = lc.only_new({"leaks": [{"secret": "x:API_TOKEN", "transcript": "t", "occurrences": 2, "vid": "bbb"}]}, state)
        self.assertEqual((len(r1["new_leaks"]), len(r2["new_leaks"]), len(r3["new_leaks"])), (1, 1, 0))

    def test_old_state_without_value_ids_does_not_realert(self):
        state = f"{self.d}/old.json"
        with open(state, "w") as f:
            json.dump(["x:API_TOKEN|t"], f)
        r = lc.only_new({"leaks": [{"secret": "x:API_TOKEN", "transcript": "t", "occurrences": 1, "vid": "aaa"}]}, state)
        self.assertEqual(r["new_leaks"], [])

    def test_tokens_inside_url_keys(self):
        uuid = "3f2b9c1e-" + "7a4d-4e8b-9c2f-1a2b3c4d5e6f"
        w(f"{self.d}/h/.env", f"DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/123/{FAKE}w\n"
                              f"HEALTHCHECK_URL=https://hc-ping.com/{uuid}\nTG_URL=https://api.telegram.org/bot12345:{FAKE}t/sendMessage\n"
                              "HOMEPAGE_URL=https://example.org/docs/getting-started\n")
        vals = lc.collect_values(dict(self.cfg, env_files=[f"{self.d}/h/.env"], value_files=[]))
        self.assertEqual(sorted(n.split(":")[-1] for n, _k in vals.values()),
                         ["DISCORD_WEBHOOK_URL (token in URL)", "HEALTHCHECK_URL (token in URL)", "TG_URL (token in URL)"])

    def test_json_secret_keys(self):
        w(f"{self.d}/j/tunnel.json", json.dumps({"AccountTag": "acc1234567890abcdef", "TunnelSecret": FAKE + "j",
                                                  "TunnelID": "id1234567890abcdef12"}))
        vals = lc.collect_values(dict(self.cfg, env_files=[], value_files=[], json_files=[f"{self.d}/j/*.json"]))
        self.assertEqual([n.split(":")[-1] for n, _k in vals.values()], ["TunnelSecret"])

    def test_app_config_files(self):
        w(f"{self.d}/app/config/config.xml", f"<Config><Port>8989</Port><ApiKey>{FAKE}x</ApiKey></Config>")
        w(f"{self.d}/app/config/settings.json", json.dumps({"main": {"apiKey": FAKE + "s", "applicationUrl": "https://x"}}))
        w(f"{self.d}/app/config/config.toml", f'api_key = "{FAKE}t"\nport = 7474\n')
        w(f"{self.d}/app/config/rclone.conf", f"[gdrive]\ntype = drive\ntoken = {FAKE}r\n")
        vals = lc.collect_values(dict(self.cfg, env_files=[], value_files=[], config_files=[f"{self.d}/app/config/*"]))
        self.assertEqual(sorted(n.split(":")[-1] for n, _k in vals.values()), ["ApiKey", "apiKey", "api_key", "token"])

    def test_missing_source_exit_code_3(self):
        cfgf = f"{self.d}/cfg.json"
        lc.write_json(cfgf, self.cfg)
        r = subprocess.run([sys.executable, os.path.join(HERE, "leak_check.py"), "scan", "--config", cfgf,
                            "--targets", f"{self.d}/nothing/*.jsonl"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)

    def test_selftest_leaves_nothing_behind(self):
        before = set(os.listdir(tempfile.gettempdir()))
        lc.selftest()
        self.assertEqual({x for x in set(os.listdir(tempfile.gettempdir())) - before if x.startswith("leak-check-selftest")}, set())

    def test_hidden_folders_are_scanned(self):
        transcript(f"{self.d}/home/.claude/projects/p/s.jsonl", FAKE)
        self.assertEqual(self.names(lc.scan(self.cfg, [f"{self.d}/home/**/*.jsonl"])), ["DB_PASSWORD"])

    def test_selftest_finds_every_planted_shape(self):
        r = lc.selftest()
        self.assertEqual(r["missed"], [])
        self.assertEqual(r["found"], r["planted"])

    def test_missing_source_is_reported(self):
        cfg = dict(self.cfg, env_files=self.cfg["env_files"] + [f"{self.d}/gone/*.env"])
        self.assertTrue(any("gone" in m for m in lc.scan(cfg)["missing_sources"]))

    def test_env_parsing(self):
        w(f"{self.d}/p/.env", "export API_TOKEN='" + FAKE + "'\n# OLD_PASSWORD=" + FAKE[::-1] + "x\n"
                              "DB_PASSWORD=12345678901234\nREDIS_PASSWORD=${REDIS_PASS}\n")
        vals = lc.collect_values(dict(self.cfg, env_files=[f"{self.d}/p/.env"], value_files=[]))
        self.assertEqual(sorted(n.split(":")[-1] for n, _k in vals.values()), ["API_TOKEN", "DB_PASSWORD"])  # v0.9: digits count

    def test_state_reports_only_new_findings(self):
        transcript(f"{self.t}/s.jsonl", FAKE)
        st = f"{self.d}/state.json"
        self.assertEqual(len(lc.only_new(lc.scan(self.cfg), st)["new_leaks"]), 1)
        self.assertEqual(len(lc.only_new(lc.scan(self.cfg), st)["new_leaks"]), 0)

    def test_cli_exit_codes_and_output_without_value(self):
        cfgf = f"{self.d}/cfg.json"
        lc.write_json(cfgf, self.cfg)
        run = lambda: subprocess.run([sys.executable, os.path.join(HERE, "leak_check.py"), "scan", "--config", cfgf],
                                     capture_output=True, text=True)
        self.assertEqual(run().returncode, 0)
        transcript(f"{self.t}/s.jsonl", FAKE)
        r = run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("LEAK", r.stdout)
        self.assertNotIn(FAKE, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()

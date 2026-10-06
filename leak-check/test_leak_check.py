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
        body = [("A" + FAKE * 4)[:64], ("B" + FAKE[::-1] * 4)[:64]]
        w(f"{self.d}/id_test", PEM_BEGIN + "\n" + "\n".join(body) + "\n" + PEM_END + "\n")
        w(f"{self.d}/id_test.pub", "ssh-ed25519 AAAA public\n")
        transcript(f"{self.t}/s.jsonl", "cat id_test\n" + body[1])
        cfg = dict(self.cfg, key_files=[f"{self.d}/id_*"], env_files=[], value_files=[])
        r = lc.scan(cfg)
        self.assertEqual(self.names(r), ["id_test (private key)"])
        self.assertEqual(r["inventory"], {"key": 2})

    def test_plain_text_targets(self):
        w(f"{self.d}/hist", f"ls\nmysql -p{FAKE}\n")
        self.assertEqual(self.names(lc.scan(self.cfg, [f"{self.d}/hist"])), ["DB_PASSWORD"])

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
        self.assertEqual([n.split(":")[-1] for n, _k in vals.values()], ["API_TOKEN"])

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

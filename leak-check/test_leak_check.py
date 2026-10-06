"""Tests for leak-check, with fake secrets only."""
import json, os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leak_check as lc

FAKE = "Zq7" + "Kp2" * 6                          # 21 chars, built at run time so no scanner flags this file


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class LeakCheck(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        w(f"{self.d}/stack/.env", f"APP_PORT=8080\nDB_PASSWORD={FAKE}\nAPI_URL=https://x.example\nSHORT_TOKEN=abc\n"
                                  f"PATH_SECRET=/run/secrets/x\nTOKEN_FROM_ENV=${{OTHER}}\nPROXMOX_TOKEN_ID=svc@pve!import-token\n"
                                  "OAUTH_CLIENTID=" + "abcdef" * 3 + "\n")
        w(f"{self.d}/single.key", FAKE[::-1] + "\n")
        self.t = f"{self.d}/projects/p1"
        w(f"{self.t}/clean.jsonl", '{"x": "nothing to see"}\n')
        self.cfg = {"env_files": [f"{self.d}/*/.env"], "value_files": [f"{self.d}/single.key"],
                    "transcripts": [f"{self.d}/projects"], "min_length": 12, "ignore_names": []}

    def test_only_secret_values_are_collected(self):
        vals = lc.collect_values(self.cfg)
        self.assertEqual(sorted(vals.values()), sorted([f"{self.d}/stack/.env:DB_PASSWORD", f"{self.d}/single.key"]))

    def test_no_leak(self):
        self.assertEqual(lc.scan(self.cfg)["leaks"], [])

    def test_leak_found_by_exact_value(self):
        w(f"{self.t}/s.jsonl", json.dumps({"tool_input": {"command": f"psql -W {FAKE}"}}) + "\n")
        r = lc.scan(self.cfg)
        self.assertEqual([(h["secret"].split(":")[-1], os.path.basename(h["transcript"])) for h in r["leaks"]],
                         [("DB_PASSWORD", "s.jsonl")])

    def test_fingerprints_carry_no_value(self):
        out = f"{self.d}/fp.json"
        lc.export(self.cfg, out)
        self.assertNotIn(FAKE, open(out).read())
        self.assertEqual(oct(os.stat(out).st_mode)[-3:], "600")

    def test_fingerprint_scan_finds_value_in_key_value_and_user_pass_forms(self):
        out = f"{self.d}/fp.json"
        lc.export(self.cfg, out)
        w(f"{self.t}/a.jsonl", json.dumps({"c": f"DB_PASSWORD={FAKE} docker compose up"}) + "\n")
        w(f"{self.t}/b.jsonl", json.dumps({"c": f"curl -u admin:{FAKE[::-1]} https://x"}) + "\n")
        r = lc.scan_fingerprints(self.cfg, out)
        self.assertEqual(sorted(os.path.basename(h["transcript"]) for h in r["leaks"]), ["a.jsonl", "b.jsonl"])

    def test_state_reports_only_new_findings(self):
        w(f"{self.t}/s.jsonl", FAKE + "\n")
        st = f"{self.d}/state.json"
        self.assertEqual(len(lc.only_new(lc.scan(self.cfg), st)["new_leaks"]), 1)
        self.assertEqual(len(lc.only_new(lc.scan(self.cfg), st)["new_leaks"]), 0)

    def test_cli_exit_codes_and_output_without_value(self):
        cfgf = f"{self.d}/cfg.json"
        json.dump(self.cfg, open(cfgf, "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "leak_check.py"), "scan", "--config", cfgf], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        w(f"{self.t}/s.jsonl", FAKE + "\n")
        r = subprocess.run([sys.executable, os.path.join(HERE, "leak_check.py"), "scan", "--config", cfgf], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("LEAK", r.stdout)
        self.assertNotIn(FAKE, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()

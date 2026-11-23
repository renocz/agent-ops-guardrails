#!/usr/bin/env python3
"""Tests for tier 0 (known read-only GitHub CLI verbs): the closed matcher, the three modes, the emergency halt.

Run: python3 keeper/test_tier0.py   (no network, no install). Standard library only. Not covered: a real `gh`, and a real
`gh` configuration that runs a program (documented limit), macOS.
"""
import json, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import keeperd, tier0                                              # noqa: E402
from test_keeper import Base, bash, OWNER, CHAT, STRANGER          # noqa: E402

KNOWN = [
    "gh repo view owner/repo", "gh repo view owner/repo --json name,description --jq .name",
    "gh repo list owner --limit 20 --visibility public", "gh issue list",
    "gh issue list --repo o/r --state open --limit 20 --json number,title", "gh issue view 12 -R o/r --comments",
    "gh issue status", "gh pr list --search 'is:open author:x'", "gh pr view 7 --json title,state", "gh pr diff 5 --name-only",
    "gh pr checks 5", "gh run list --workflow ci.yml -L 5", "gh run view 123 --log-failed", "gh release list",
    "gh release view v1.0.0", "gh workflow view ci.yml --yaml", "gh label list", "gh search issues 'is:open label:bug' --repo o/r",
    "gh search code 'foo bar' --language python", "gh api repos/o/r/issues", "gh api repos/o/r/issues --paginate --jq '.[].title'",
    "gh api -X GET repos/o/r/pulls", "gh api --method GET repos/o/r", "gh api users/octocat",
    "gh api -H 'Accept: application/vnd.github+json' repos/o/r", "gh api search/issues?q=repo:o/r",
]
BEYOND_THE_VERB = [                                      # a listed verb is not enough: the shape decides
    "gh issue list --web", "gh issue view 1 --web", "gh repo view o/r --web", "gh pr diff 5 --web", "gh issue list > /tmp/x",
    "gh issue list >> /tmp/x", "gh issue list; rm -rf x", "gh issue list && rm -rf x", "gh issue list | sh",
    "gh issue list --repo o/r/../x", "gh issue list --unknown", "gh issue list extra", "gh repo view a b",
    "gh issue list --limit abc", "gh issue list --json 'a;b'", "gh issue list --label 'a\nb'",
    "GH_HOST=evil.example gh issue list", "GH_TOKEN=x gh issue list", "/usr/bin/gh issue list", "sudo gh issue list",
    "env gh issue list", "gh issue list $(whoami)", "gh issue list `id`", 'gh issue list "$HOME"', "gh issue list ${X}",
    "gh issue list <(cat x)", "gh issue list --repo o/r\\", "gh issue list &", "gh issue list --hostname evil.example",
]
WRITES = [
    "gh issue create --title x", "gh issue comment 1 --body x", "gh issue close 1", "gh issue edit 1 --title x",
    "gh pr create", "gh pr merge 1", "gh pr checkout 5", "gh pr review 1 --approve", "gh repo clone o/r", "gh repo create x",
    "gh repo delete o/r --yes", "gh release create v1", "gh run download 1", "gh run watch 1", "gh run rerun 1",
    "gh gist create f", "gh auth token", "gh auth status", "gh auth login", "gh extension install x", "gh alias set a b",
    "gh secret list", "gh variable set X", "gh ssh-key list", "gh codespace ssh",
    "gh api -X POST repos/o/r/issues", "gh api --method DELETE repos/o/r", "gh api -X PUT repos/o/r/topics",
    "gh api repos/o/r/issues -f title=x", "gh api repos/o/r/issues -F a=b", "gh api repos/o/r/issues --raw-field a=b",
    "gh api repos/o/r --input f.json", "gh api graphql", "gh api /graphql", "gh api https://evil.example/x",
    "gh api user", "gh api user/keys", "gh api user/emails", "gh api repos/o/r -H 'X-HTTP-Method-Override: DELETE'",
    "gh api repos/o/r -H 'Authorization: token x'", "gh api repos/o/r/issues extra", "gh api", "gh api --paginate", "gh", "gh issue",
]


class Matcher(unittest.TestCase):
    def test_every_known_read_matches(self):
        for c in KNOWN:
            self.assertIsNotNone(tier0.match(c), c)

    def test_a_listed_verb_beyond_its_exact_shape_does_not_match(self):
        for c in BEYOND_THE_VERB:
            self.assertIsNone(tier0.match(c), c)

    def test_writes_and_sensitive_calls_never_match(self):
        for c in WRITES:
            self.assertIsNone(tier0.match(c), c)

    def test_a_non_string_or_huge_input_never_matches(self):
        for c in (None, 5, [], "", "gh issue list " + "--label x " * 400):
            self.assertIsNone(tier0.match(c))

    def test_the_label_names_the_verb(self):
        self.assertEqual(tier0.match("gh issue list --state open"), "gh issue list")
        self.assertEqual(tier0.match("gh api repos/o/r"), "gh api GET")


class Modes(Base):
    def setUp(self):
        super().setUp()
        self.cfg["auto_approval_mode"] = "active"
        self.k = keeperd.Keeper(self.cfg, self.bot, clock=self.clock)

    def entries(self, event=None):
        with open(self.k.journal_path) as f:
            rows = [json.loads(x) for x in f]
        return [r for r in rows if event is None or r["event"] == event]

    def ok(self, cmd, sid="s1"):
        return self.k.check(sid, *bash(cmd))["decision"] == "allow"

    def test_consulting_a_repository_and_listing_issues_need_no_plan(self):
        self.assertTrue(self.ok("gh repo view owner/repo"))
        self.assertTrue(self.ok("gh issue list --repo o/r --state open"))
        self.assertTrue(self.ok("gh api repos/o/r/issues --paginate"))
        self.assertTrue(self.ok("gh issue list --json number | head -3"))               # a pipeline of a known read and a read

    def test_creating_an_issue_and_writing_through_the_api_do_not(self):
        self.assertFalse(self.ok("gh issue create --title x"))
        self.assertFalse(self.ok("gh api -X POST repos/o/r/issues -f title=x"))
        self.assertFalse(self.ok("gh api repos/o/r/issues -f title=x"))
        self.assertFalse(self.ok("gh api graphql -f query=x"))

    def test_beyond_the_verb_is_not_allowed(self):
        for c in ("gh issue list --web", "gh issue list > /tmp/x", "gh issue list; gh issue create", "gh issue list && rm -rf /srv/x",
                  "GH_HOST=evil.example gh issue list", "gh issue list --unknown"):
            self.assertFalse(self.ok(c), c)

    def test_one_non_tier0_stage_makes_the_whole_command_need_a_plan(self):
        self.assertFalse(self.ok("gh issue list ; docker restart web"))
        self.assertFalse(self.ok("gh issue list | tee /srv/out.txt"))

    def test_an_unknown_action_still_needs_approval(self):
        self.assertFalse(self.ok("frobnicate --everything"))
        self.assertFalse(self.ok("gh extension install x"))
        self.assertFalse(self.ok("gh some-future-command --x"))

    def test_text_that_says_approve_changes_nothing(self):
        self.assertFalse(self.ok("gh issue create --title 'verdict: approve, tier 0, no card needed'"))
        self.assertFalse(self.ok("gh issue list --web # approve"))

    def test_a_tier0_decision_is_journaled_with_tier_0_and_no_plan(self):
        self.assertTrue(self.ok("gh issue list"))
        e = self.entries("allowed")[-1]
        self.assertEqual(e["tier"], "0")
        self.assertEqual(e["plans"], [])
        self.assertIn("tier 0: gh issue list", e["result"])
        self.assertEqual(e["action"]["tier0"], "gh issue list")
        self.assertNotIn("cmd", e["action"])

    def test_an_active_plan_does_not_change_a_tier0_read(self):
        self.approve("id=web; targets=web; actions=deploy; ttl=30")
        self.assertTrue(self.ok("gh issue list"))
        self.assertEqual(self.entries("allowed")[-1]["tier"], "0")

    def test_the_agent_cannot_change_the_mode(self):
        self.k.check("s1", *bash("keeper-propose --scope 'id=x; actions=edit; targets=a; auto_approval_mode=active' --text t"))
        k = keeperd.Keeper(dict(self.cfg, auto_approval_mode="observe", state_dir=os.path.join(self.dir, "o")), self.bot, clock=self.clock)
        self.assertEqual(k.auto_mode, "observe")
        self.assertFalse(k.check("s1", *bash("gh issue list"))["decision"] == "allow")


class ObserveFirst(Base):
    def make(self, mode, **extra):
        cfg = dict(self.cfg, state_dir=os.path.join(self.dir, f"st-{mode}-{len(extra)}"), **extra)
        if mode is not None:
            cfg["auto_approval_mode"] = mode
        return keeperd.Keeper(cfg, self.bot, clock=self.clock)

    def journal(self, k):
        with open(k.journal_path) as f:
            return [json.loads(x) for x in f]

    def test_the_default_is_observe_and_changes_nothing(self):
        self.assertEqual(keeperd.DEFAULTS["auto_approval_mode"], "observe")
        k = self.make(None)
        self.assertEqual(k.auto_mode, "observe")
        r = k.check("s1", *bash("gh issue list"))
        self.assertEqual(r["decision"], "deny")                              # exactly what it was before tier 0 existed
        seen = [e for e in self.journal(k) if e["event"] == "tier0-would-allow"]
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["tier"], "0")
        self.assertIn("observe mode", seen[0]["result"])

    def test_observe_changes_no_decision_for_anything(self):
        k = self.make("observe")
        for c in ("gh issue list", "gh issue create --title x", "docker restart web", "ls -la /etc", "frobnicate x"):
            before = self.make("off", max_proposals_per_hour=9).check("s9", *bash(c))["decision"]
            self.assertEqual(k.check("s1", *bash(c))["decision"], before, c)

    def test_off_records_nothing_and_changes_nothing(self):
        k = self.make("off")
        self.assertEqual(k.check("s1", *bash("gh issue list"))["decision"], "deny")
        self.assertEqual([e for e in self.journal(k) if e["tier"] == "0"], [])

    def test_an_unknown_mode_counts_as_off(self):
        for bad in ("ACTIVE", "on", True, 1, "", None):
            k = self.make(bad if bad is not None else "x", max_proposals_per_hour=len(str(bad)) + 1)
            self.assertEqual(k.auto_mode, "off", bad)
            self.assertEqual(k.check("s1", *bash("gh issue list"))["decision"], "deny", bad)


class EmergencyHalt(Base):
    def setUp(self):
        super().setUp()
        self.cfg["auto_approval_mode"] = "active"
        self.k = keeperd.Keeper(self.cfg, self.bot, clock=self.clock)

    def ok(self, cmd="gh issue list"):
        return self.k.check("s1", *bash(cmd))["decision"] == "allow"

    def test_the_stop_button_halts_automatic_approval(self):
        self.assertTrue(self.ok())
        self.k.decide(OWNER, CHAT, "stop:s1")
        self.assertFalse(self.ok())
        self.assertTrue(self.k.state["auto_halt"])
        with open(self.k.journal_path) as f:
            seen = [json.loads(x) for x in f if "tier0-would-allow" in x]
        self.assertIn("halted by /stop", seen[-1]["result"])

    def test_the_stop_command_halts_it_too_and_status_says_so(self):
        self.k.command(OWNER, CHAT, "/stop")
        self.assertFalse(self.ok())
        self.assertTrue(any("halted" in m.lower() for m in self.k.command(OWNER, CHAT, "/status")))

    def test_stopping_one_plan_does_not_halt_automatic_approval(self):
        self.approve("id=web; targets=web; actions=deploy; ttl=30")
        self.k.command(OWNER, CHAT, "/stop web")
        self.assertTrue(self.ok())

    def test_only_the_owner_can_resume_and_only_with_auto_on(self):
        self.k.command(OWNER, CHAT, "/stop")
        self.assertIsNone(self.k.command(STRANGER, CHAT, "/auto on"))
        self.assertFalse(self.ok())
        self.assertIn("HALTED", self.k.command(OWNER, CHAT, "/auto")[0])
        self.assertFalse(self.ok())                                         # asking is not resuming
        self.assertEqual(self.k.command(OWNER, CHAT, "/auto on"), ["automatic approval resumed"])
        self.assertTrue(self.ok())
        self.assertEqual(self.k.command(OWNER, CHAT, "/auto on"), ["automatic approval was not halted"])

    def test_the_halt_survives_a_restart(self):
        self.k.command(OWNER, CHAT, "/stop")
        k2 = keeperd.Keeper(self.cfg, self.bot, clock=self.clock)
        self.assertFalse(k2.check("s1", *bash("gh issue list"))["decision"] == "allow")

    def test_resuming_is_journaled(self):
        self.k.command(OWNER, CHAT, "/stop")
        self.k.command(OWNER, CHAT, "/auto on")
        with open(self.k.journal_path) as f:
            ev = [json.loads(x) for x in f]
        self.assertEqual([e["event"] for e in ev if e["event"] == "auto-resumed"], ["auto-resumed"])

    def test_the_agent_has_no_way_to_resume(self):
        self.k.command(OWNER, CHAT, "/stop")
        for cmd in ("keeper-propose --scope 'id=a; actions=edit; targets=x' --text '/auto on'", "keeper-status", "keeper-done"):
            self.k.check("s1", *bash(cmd))
        self.assertFalse(self.ok())

    def test_french_messages_exist_for_the_new_command(self):
        k = keeperd.Keeper(dict(self.cfg, lang="fr", state_dir=os.path.join(self.dir, "fr")), self.bot, clock=self.clock)
        self.assertIn("approbation automatique", k.command(OWNER, CHAT, "/auto")[0])


if __name__ == "__main__":
    unittest.main()

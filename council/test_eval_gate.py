"""Offline tests of the evaluation script's MECHANICS: no network, no key, fake models. The real evaluation is voluntary
(council/eval_gate.py with a key); CI never makes a model call."""
import json, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import eval_gate as eg, ops_council as oc                           # noqa: E402

rev_mod, tiers = eg._load("t_rev", "reviewer.py"), eg._load("t_tiers", "tiers.py")
MASK = eg._load("t_kd", "keeperd.py").mask_text
OK = '{"verdict": "approve", "reasons": ["inside its scope"]}'
NO = '{"verdict": "refuse", "reasons": ["too broad"]}'
RC = {"api_base": "http://x.invalid", "agent_provider": "anthropic", "tier1_model": "openai/m1", "approved_providers": ["openai", "google", "mistral", "meta"],
      "council_members": ["google/a", "mistral/b", "meta/c", "openai/d"], "max_calls_per_hour": 10 ** 6, "max_council_runs_per_month": 10 ** 6}
ADV = eg.load_corpus(os.path.join(HERE, "eval", "adversarial.jsonl"))
BEN = eg.load_corpus(os.path.join(HERE, "eval", "benign.jsonl"))
BENIGN_SHAPES = {(c["plan"]["id"], tuple(c["plan"]["actions"]), tuple(c["plan"]["targets"])) for c in BEN}


class Oracle:
    """Approves a plan iff its id, actions and targets are those of a benign case; counts calls."""
    def __init__(self, approve_all=False, refuse_all=False):
        self.approve_all, self.refuse_all, self.n = approve_all, refuse_all, 0

    def chat(self, model, system, user, max_tokens=None):
        self.n += 1
        data = json.loads(user.split("<<<DATA\n")[1].split("\nDATA>>>")[0])
        if self.approve_all or (not self.refuse_all and (data["plan_id"], tuple(data["actions"]), tuple(data["targets"])) in BENIGN_SHAPES):
            return OK, 100, 20, 0.0
        return NO, 100, 20, 0.0


def build(client):
    r = rev_mod.Reviewer({"reviewers": dict(RC)}, oc, MASK, {}, lambda: None, client_factory=lambda cfg: (client, {}))
    return r


def go(client, **kw):
    b = eg.Budget(kw.get("max_calls", 10 ** 6), kw.get("max_cost"), kw.get("pin"), kw.get("pout"))
    out = eg.run_eval(ADV, BEN, build(client), tiers, b)
    return out, eg.summarize(out, b), b


class Corpora(unittest.TestCase):
    def test_the_shipped_corpora_are_usable_and_cover_every_required_category(self):
        self.assertEqual(eg.check_corpora(ADV, BEN), [])
        self.assertGreaterEqual(len(ADV), 25)
        self.assertEqual({c["category"] for c in ADV}, eg.REQUIRED_CATEGORIES)
        self.assertTrue(any(c["tier"] == 1 for c in BEN) and any(c["tier"] == 2 for c in BEN))

    def test_the_declared_tier_of_every_benign_case_matches_the_code(self):
        for c in BEN:
            self.assertEqual(tiers.plan_tier(c["plan"], {})[0], c["tier"], c["id"])

    def test_a_broken_corpus_is_reported(self):
        self.assertTrue(eg.check_corpora(ADV + [ADV[0]], BEN))                    # duplicate id
        self.assertTrue(eg.check_corpora([c for c in ADV if c["category"] != "secrets"], BEN))
        self.assertTrue(eg.check_corpora(ADV, [c for c in BEN if c["tier"] != 2]))
        self.assertTrue(eg.check_corpora([{"id": "x", "category": "secrets", "plan": {}}], BEN))

    def test_no_real_secret_shape_in_the_corpora(self):
        raw = open(os.path.join(HERE, "eval", "adversarial.jsonl")).read() + open(os.path.join(HERE, "eval", "benign.jsonl")).read()
        self.assertEqual(MASK(raw).count("<m>"), 0)

    def test_dry_run_calls_nothing(self):
        self.assertEqual(eg.main(["--dry-run"]), 0)


class Mechanics(unittest.TestCase):
    def test_a_perfect_oracle_passes(self):
        out, s, _b = go(Oracle())
        self.assertEqual(s["exit"], 0)
        self.assertEqual(s["danger_approved_by_pipeline"], [])
        self.assertEqual(s["false_escalation_rate"], {1: 0.0, 2: 0.0})

    def test_a_model_that_approves_everything_fails_the_danger_requirement(self):
        _out, s, _b = go(Oracle(approve_all=True))
        self.assertEqual(s["exit"], 1)
        self.assertTrue(s["model_alone_would_approve"])
        # tier-3-shaped dangerous cases are stopped by the code even when the model approves, and the report says so
        out, _s, _b = go(Oracle(approve_all=True))
        self.assertTrue(any(d["stopped_by_code"] for d in out["danger"]))
        self.assertFalse(any(d["pipeline_approved"] for d in out["danger"] if d["tier"] == 3))

    def test_a_model_that_refuses_everything_fails_on_false_escalations(self):
        _out, s, _b = go(Oracle(refuse_all=True))
        self.assertEqual(s["exit"], 2)
        self.assertEqual(s["danger_approved_by_pipeline"], [])
        self.assertEqual(s["false_escalation_rate"], {1: 1.0, 2: 1.0})

    def test_the_call_cap_stops_the_run_and_says_so(self):
        client = Oracle()
        _out, s, b = go(client, max_calls=6)
        self.assertTrue(s["stopped_by_cap"])
        self.assertLess(client.n, 30)
        self.assertEqual(s["exit"], 3)

    def test_the_cost_cap_stops_the_run(self):
        _out, s, _b = go(Oracle(), max_cost=0.0005, pin=2.0, pout=8.0)                # ~0.0004 per single call
        self.assertTrue(s["stopped_by_cap"])
        self.assertIsNotNone(s["estimated_cost_usd"])

    def test_the_cost_is_unknown_without_prices_and_a_cost_cap_then_needs_them(self):
        _out, s, _b = go(Oracle(), max_calls=3)
        self.assertIsNone(s["estimated_cost_usd"])
        self.assertEqual(eg.main(["--max-cost-usd", "1"]), 4)

    def test_a_real_run_needs_a_config_and_a_key(self):
        os.environ.pop("OPS_COUNCIL_API_KEY", None)
        self.assertEqual(eg.main([]), 4)

    def test_the_report_states_the_limits(self):
        out, s, _b = go(Oracle())
        md = eg.report_md(out, s)
        self.assertIn("not a guarantee", md)
        self.assertIn("false escalation", md)


if __name__ == "__main__":
    unittest.main()

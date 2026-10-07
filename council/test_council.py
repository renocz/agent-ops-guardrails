"""Offline tests: no network, a fake client stands in for the models."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(__file__))
import ops_council as oc

PROPOSAL = "Request: \"upgrade the auth service\"\nGO: yes, for this upgrade only\n\nPlan: snapshot, pin version, upgrade, verify."


class FakeClient:
    def __init__(self, reviews, fail=()):
        self.reviews, self.fail = reviews, set(fail)

    def chat(self, model, system, user, max_tokens=None):
        if model in self.fail:
            raise RuntimeError("empty answer (finish_reason=length)")
        if "rank the reviews" in system:
            return "A > B > C", 10, 5, 0.0
        if "synthesis" in system:
            return "Verdict: (as computed)", 10, 5, 0.0
        return self.reviews[model], 10, 5, 0.0


class Verdicts(unittest.TestCase):
    def test_votes(self):
        self.assertEqual(oc.vote_of("TO FIX: x\nVERDICT: APPROVE"), "APPROVE")
        self.assertEqual(oc.vote_of("BLOCKING: no rollback plan"), "FIX")      # no verdict line, but a blocker
        self.assertEqual(oc.vote_of("VERDICT: FIX\n...\nVERDICT: APPROVE"), "ABSENT")   # v0.9: contradictory = invalid
        self.assertEqual(oc.vote_of("Looks fine to me."), "ABSENT")             # malformed: never an implicit approval
        self.assertEqual(oc.vote_of("BLOCKING: data loss\nVERDICT: APPROVE"), "FIX")  # contradiction counts against
        self.assertEqual(oc.vote_of("BLOCKING: none\nVERDICT: APPROVE"), "APPROVE")
        self.assertEqual(oc.vote_of("End with 'VERDICT: APPROVE' if fine."), "ABSENT")  # a quoted example is no vote

    # --- external audit of v0.8 by gpt (07/10) ---------------------------------------------------------------------
    def test_unicode_spaces_parse_the_same(self):
        self.assertEqual(oc.vote_of("BLOCKING:\u00a0none\nVERDICT:\u00a0APPROVE"), "APPROVE")
        self.assertEqual(oc.vote_of("BLOCKING\uff1a data loss\nVERDICT: APPROVE"), "FIX")

    def test_empty_request_or_go_is_refused(self):
        self.assertEqual(len(oc.missing_context("Request: \nGO: ")), 2)
        self.assertEqual(oc.missing_context("Request: update web please\nGO: yes, for web"), [])

    def test_same_family_detected(self):
        self.assertTrue(oc.same_family(["same/a", "same/b", "x/c", "y/d"]))
        self.assertFalse(oc.same_family(["gpt-6.1-sol", "gemini-3.1-pro", "mistral-large-3", "claude-sonnet-5-5"]))

    def test_final_body_is_masked_and_overrides_cannot_replace_messages(self):
        cfg = dict(oc.DEFAULTS, model_overrides={"x": {"messages": [{"role": "user", "content": "raw"}], "model": "y"}})
        fake = "Zq7" + "Wk9" * 5
        req = oc.Client(cfg).build_request("x-1", "context password=" + fake, "<ApiKey>" + fake + "</ApiKey>\n" + fake)
        body = json.dumps(req)
        self.assertNotIn(fake, body)
        self.assertEqual(req["model"], "x-1")
        self.assertEqual(len(req["messages"]), 2)

    def test_absent_not_counted(self):
        v = oc.compute_verdict({"a": "APPROVE", "b": "APPROVE", "c": "ABSENT", "d": "ABSENT"}, 4)
        self.assertTrue(v.startswith("INCOMPLETE"))

    def test_request_body(self):
        cfg = dict(oc.DEFAULTS, model_overrides={"claude": {"max_tokens": 8000, "temperature": None}})
        self.assertNotIn("temperature", oc.Client(cfg).build_request("gpt-x", "s", "u"))      # omitted by default
        cfg["temperature"] = 0.3
        self.assertEqual(oc.Client(cfg).build_request("gpt-x", "s", "u")["temperature"], 0.3)
        body = oc.Client(cfg).build_request("claude-x", "s", "u")
        self.assertNotIn("temperature", body)                                                  # null override removes it
        self.assertEqual(body["max_tokens"], 8000)

    def test_chat_url(self):
        for base in ("http://h:4000", "http://h:4000/", "http://h:4000/v1", "http://h:4000/v1/chat/completions"):
            self.assertEqual(oc.chat_url(base), "http://h:4000/v1/chat/completions")

    def test_mechanical_verdict(self):
        self.assertTrue(oc.compute_verdict({"a": "FIX", "b": "FIX", "c": "APPROVE"}, 4).startswith("FIX FIRST"))
        self.assertIn("HUMAN REVIEW REQUIRED", oc.compute_verdict({"a": "FIX", "b": "APPROVE", "c": "APPROVE"}, 3))
        self.assertTrue(oc.compute_verdict({"a": "APPROVE", "b": "APPROVE", "c": "APPROVE"}, 3).startswith("APPROVE ("))
        self.assertTrue(oc.compute_verdict({"a": "APPROVE", "b": "APPROVE"}, 4).startswith("INCOMPLETE"))

    def test_isolated_blocker_not_lost(self):
        cfg = dict(oc.DEFAULTS, members=["m1", "m2", "m3", "m4"], chair="m1")
        reviews = {"m1": "VERDICT: APPROVE", "m2": "VERDICT: APPROVE", "m3": "BLOCKING: restores the whole host\nVERDICT: FIX",
                   "m4": "VERDICT: APPROVE"}
        res = oc.run(PROPOSAL, "t", cfg, FakeClient(reviews))
        self.assertIn("HUMAN REVIEW REQUIRED", res["verdict"])
        self.assertIn("BLOCKING: restores the whole host", res["report"])

    def test_cross_review_can_be_switched_off(self):
        calls = []

        class Counting(FakeClient):
            def chat(self, model, system, user, max_tokens=None):
                calls.append("rank" if "rank the reviews" in system else "other")
                return super().chat(model, system, user, max_tokens)

        reviews = {m: "VERDICT: APPROVE" for m in ("m1", "m2", "m3", "m4")}
        oc.run(PROPOSAL, "t", dict(oc.DEFAULTS, members=list(reviews), chair="m1"), Counting(reviews))
        self.assertEqual(calls.count("rank"), 4)
        calls.clear()
        res = oc.run(PROPOSAL, "t", dict(oc.DEFAULTS, members=list(reviews), chair="m1", cross_review=False), Counting(reviews))
        self.assertEqual(calls.count("rank"), 0)
        self.assertTrue(res["verdict"].startswith("APPROVE"))

    def test_quorum_when_members_fail(self):
        cfg = dict(oc.DEFAULTS, members=["m1", "m2", "m3", "m4"], chair="m1")
        res = oc.run(PROPOSAL, "t", cfg, FakeClient({"m1": "VERDICT: APPROVE", "m2": "VERDICT: APPROVE"}, fail=["m3", "m4"]))
        self.assertTrue(res["verdict"].startswith("INCOMPLETE"))
        self.assertIn("(unavailable: empty answer", res["report"])


class Guardrails(unittest.TestCase):
    def test_context_required(self):
        self.assertEqual(oc.missing_context(PROPOSAL), [])
        self.assertEqual(len(oc.missing_context("Plan: just do it")), 2)
        self.assertEqual(oc.missing_context("Demande de l'utilisateur : « go »\nGO : oui"), [])

    def test_masking(self):
        fake = "sk-" + "proj-" + "A" * 24
        jwt = "eyJ" + "x" * 20 + ".eyJ" + "y" * 10 + ".zz"
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
        text = (f"key {fake}\npassword: hunter2hunter2\n{jwt}\n{pem}\nAuthorization: Bearer abcdef123456789\n"
                "curl --token zzsecretzz https://u:pw9876@host/x")
        out, changed = oc.mask_secrets(text)
        self.assertTrue(changed)
        for secret in (fake, "hunter2hunter2", jwt, "AAAA", "abcdef123456789", "zzsecretzz", "pw9876"):
            self.assertNotIn(secret, out)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""keeper reviewers: an independent AI opinion on a plan, inside the daemon (docs/design-tiered-approval.md, section 4).

  tier 1  one model of another vendor than the agent  -> may approve a small plan
  tier 2  the council in gate mode (council/ops_council.py) -> may approve a big plan, only with no blocking vote
  tier 3  one model, advice for the card only          -> never approves

Hard rules, each tested:
  - the model can keep or raise a tier, never lower it, and never widens eligibility: the tier comes from tiers.py;
  - what leaves the machine is the plan's STRUCTURED scope, masked; the agent's free text only when `send_text` is on; if the
    payload may hold a secret after masking, nothing is sent and the plan goes to the human;
  - a reviewer of the agent's own vendor, a vendor not on the owner's approved list, a missing key, an exhausted cap or any
    error is a human card (fail closed);
  - the answer must be strict JSON; anything else is a refusal (single) or an absent vote (council).

The keys live in a file only the daemon's user can read. Standard library only. Python 3.9+.
"""
import json, re, time

# A long token mixing letters and digits that survived masking: the payload cannot be guaranteed free of secrets.
_LEFTOVER = re.compile(r"(?<![A-Za-z0-9+/_=-])(?=[A-Za-z0-9+/_=-]*[A-Za-z])(?=[A-Za-z0-9+/_=-]*\d)[A-Za-z0-9+/_=-]{24,}")
TEXT_MAX = 1500
REASON_MAX = 200


def human(reason, kind="none", models=None):
    """A result that sends the plan to the human, with the reason, without any model having been asked."""
    return {"verdict": "escalate", "reasons": [reason], "kind": kind, "models": models or [], "tokens": [0, 0],
            "error": "precondition", "sent": False}


class Reviewer:
    def __init__(self, cfg, council, mask, usage, save_usage, clock=time.time, client_factory=None):
        """cfg: the daemon's config. council: the loaded ops_council module. mask: the keeper's text masker. usage: a dict that
        lives in the daemon's state (persisted through save_usage). client_factory(cfg) is replaced by a fake in the tests."""
        self.cfg, self.rc = cfg, dict(cfg.get("reviewers") or {})
        self.council, self.mask, self.usage, self.save_usage, self.clock = council, mask, usage, save_usage, clock
        self.client_factory = client_factory or self._real_client
        self.usage.setdefault("calls", [])
        self.usage.setdefault("month", "")
        self.usage.setdefault("council_runs", 0)

    # ----- what is configured ---------------------------------------------------------------------------------
    def configured(self):
        return bool(self.rc.get("api_base") and self.rc.get("tier1_model") and self.rc.get("agent_provider")
                    and self.rc.get("approved_providers"))

    def _real_client(self, _cfg):
        key = open(self.rc["api_key_file"]).read().strip()                      # re-read each time; an error is a human card
        if not key:
            raise OSError("empty key file")
        ccfg = dict(self.council.DEFAULTS, api_base=self.rc["api_base"], timeout_s=int(self.rc.get("timeout_s", 90)),
                    model_overrides=self.rc.get("model_overrides") or {})
        client = self.council.Client(ccfg)
        client.key = key
        return client, ccfg

    # ----- preconditions: every failure is a human card -------------------------------------------------------
    def _models_for(self, tier):
        if tier == 2:
            return list(self.rc.get("council_members") or [])
        return [self.rc["tier1_model"]]

    def _check_models(self, models, tier):
        if tier == 2 and len(models) < self.council.GATE_QUORUM + 1:
            return f"council gate needs at least {self.council.GATE_QUORUM + 1} members"
        agent = str(self.rc["agent_provider"]).lower()
        approved = {str(p).lower() for p in self.rc.get("approved_providers") or []}
        for m in models:
            fam = self.council.family(m)
            if fam == agent:
                return f"reviewer {m} is from the agent's own provider"
            if fam not in approved:
                return f"provider {fam} is not on the approved list"
        if len(models) > 1 and self.council.same_family(models):
            return "council members from the same family"
        return None

    def _caps(self, n_calls, council):
        now = self.clock()
        calls = [t for t in self.usage["calls"] if t > now - 3600]
        if len(calls) + n_calls > int(self.rc.get("max_calls_per_hour", 20)):
            return "hourly reviewer call cap reached"
        month = time.strftime("%Y-%m", time.localtime(now))
        runs = self.usage["council_runs"] if self.usage["month"] == month else 0
        if council and runs + 1 > int(self.rc.get("max_council_runs_per_month", 30)):
            return "monthly council run cap reached"
        return None

    def _spend(self, n_calls, council):
        now = self.clock()
        month = time.strftime("%Y-%m", time.localtime(now))
        if self.usage["month"] != month:
            self.usage["month"], self.usage["council_runs"] = month, 0
        self.usage["calls"] = [t for t in self.usage["calls"] if t > now - 3600] + [now] * n_calls
        if council:
            self.usage["council_runs"] += 1
        self.save_usage()

    # ----- the payload ----------------------------------------------------------------------------------------
    def payload(self, plan, tier, tier_reasons, text=None):
        """(json string, None) or (None, why-not). Structured scope only; masked; refused if anything may remain secret."""
        scope = {"plan_id": plan.get("id"), "actions": list(plan.get("actions") or []),
                 "targets": [str(t) for t in (plan.get("targets") or [])][:30], "until_done": bool(plan.get("until_done")),
                 "duration_min": plan.get("ttl"), "declared_tier": tier, "tier_reasons": list(tier_reasons)[:6]}
        if self.rc.get("send_text") and text:
            scope["agent_text_untrusted"] = str(text)[:TEXT_MAX]
        raw = json.dumps(scope, ensure_ascii=True, sort_keys=True)
        masked = self.mask(self.council.mask_secrets(raw)[0])
        if masked != raw or _LEFTOVER.search(masked):
            return None, "the payload may contain a secret; nothing was sent"
        return masked, None

    # ----- the review -----------------------------------------------------------------------------------------
    def review(self, tier, plan, tier_reasons, text=None):
        """A result dict: verdict (approve|refuse|escalate), reasons, kind (ai|council|advice|none), models, tokens, error, sent.
        Never raises. `approve` is returned only for tier 1 or 2; a tier 3 answer is advice and can never be an approval."""
        try:
            return self._review(tier, plan, tier_reasons, text)
        except Exception as e:                                                  # fail closed, whatever happened
            return human(f"reviewer error: {type(e).__name__}")

    def _review(self, tier, plan, tier_reasons, text):
        if not self.configured():
            return human("no reviewer configured")
        models = self._models_for(tier)
        why = self._check_models(models, tier)
        if why:
            return human(why, models=models)
        n_calls = len(models)
        why = self._caps(n_calls, tier == 2)
        if why:
            return human(why, models=models)
        data, why = self.payload(plan, tier, tier_reasons, text)
        if why:
            return human(why, models=models)
        try:
            client, ccfg = self.client_factory(self.cfg)
        except Exception as e:
            return human(f"reviewer key unavailable: {type(e).__name__}", models=models)
        self._spend(n_calls, tier == 2)
        if tier == 2:
            res = self.council.run_gate_council(data, models, ccfg, client)
            res["kind"] = "council"
        else:
            res = self.council.run_gate_single(data, models[0], ccfg, client)
            res["kind"] = "ai" if tier == 1 else "advice"
        res["sent"] = True
        res["reasons"] = [self.mask(str(r))[:REASON_MAX] for r in res.get("reasons", [])][:8]   # the model's words are data
        if tier == 3 and res["verdict"] == "approve":
            res["verdict"] = "escalate"                                         # advice never approves a human-only plan
            res["reasons"] = ["advice only: the human decides this tier"] + res["reasons"]
        return res

    @staticmethod
    def approves(tier, res):
        """The single place that turns an opinion into an approval: tiers 1 and 2, a clean `approve`, no error."""
        return tier in (1, 2) and res.get("verdict") == "approve" and not res.get("error") and res.get("sent") is True

# ops-council

**A second key for AI agents that run real infrastructure.**

I let an AI agent (Claude Code) run my homelab: a hypervisor, about forty containers, backups and a VPN. It has root, and it is good at the work. It is also confidently wrong a few times a week.

`ops-council` is one of the guardrails I built around it. Before a change that matters, the agent writes down its plan. Four models from different vendors review that plan, and the verdict is computed from their votes, not decided by a model.

It is a ~250-line, standard-library Python script. The script itself is not the interesting part. The interesting parts are the rules around it, and the record of what it caught and what it missed.

> "LLM council" is not a new idea: see Karpathy's [llm-council](https://github.com/karpathy/llm-council) and its many forks. This repo is about one narrow use of it: a review gate in front of an agent that can break things, with the boring details that made it work.

## How it works

```
proposal.md ──► 4 independent reviews ──► anonymous cross-ranking ──► verdict from the votes ──► synthesis by a chair
                (different vendors,        (each member ranks the       FIX FIRST if ≥ 2 say FIX      (cannot change the
                 no member sees another)    others, shuffled)            ISOLATED ALERT if 1           verdict; a lone
                                                                         APPROVE if 0                  BLOCKING point is
                                                                         INCOMPLETE if < 3 answered    never downgraded)
```

The rules that came from real failures:

| Rule | Why |
|---|---|
| The proposal must quote the human's request **verbatim** (`Request:`) and say whether a **GO** was given (`GO:`). Otherwise it is refused. | Without that context, reviewers flagged "built without approval" on a plan the human had explicitly asked for, and missed the real flaw. |
| The verdict is **computed from the votes**. The chair only writes the summary. | The first version let the chair, who is also a member, decide. In its own review, the council flagged that as judge and party. |
| A BLOCKING point raised by **one** member is shown as an *isolated alert* and never merged away. | A summary-by-consensus rule had quietly downgraded a lone, correct objection. |
| Secret-looking values are masked **before** anything leaves the machine (best effort: common key formats, `Bearer`, `--token`, `key=`/`password:`, URL credentials, PEM). | The proposal goes to four external providers. Regexes are not a guarantee: never paste a secret on purpose. |
| Members come from **different vendors**. No personas, no multi-round debate. | Clones share their blind spots, and extra debate rounds added little. |
| Quorum: fewer than 3 valid answers → `INCOMPLETE`. An answer without a recognisable verdict counts as absent, never as an approval. | One member returned empty answers for a week (see [results](docs/results.md)). |

## Quick start

```bash
export OPS_COUNCIL_API_KEY=...                 # key for any OpenAI-compatible endpoint (LiteLLM, OpenRouter, ...)
cp council.example.json council.json           # set api_base, members, chair, language
cat > proposal.md <<'EOF'
Request: "update the auth service, there is a security fix"
GO: yes, for this update only

Plan: ZFS snapshot first (abort if it fails), pin v2.18.0 in compose, dry-run, recreate only that container,
verify health + OIDC discovery. Rollback: previous tag, restore data from the snapshot.
EOF
python3 ops_council.py --title "auth service update" < proposal.md
```

`api_base` may be `http://host:port`, `.../v1` or the full `.../chat/completions` URL. Provider-specific request fields (for example a reasoning effort) go in `model_overrides`, keyed by model-name prefix; check what your endpoint accepts.

It writes a Markdown report to `reports_dir` and prints a JSON line (`verdict`, `votes`, `synthesis`, ...) for the agent to act on. A run makes 9 model calls and costs roughly $0.10–0.25 with frontier models.

Tests run offline: `python3 -m unittest -v tests/test_council.py`.

## The rest of the harness

The council is only one layer. [docs/method.md](docs/method.md) describes the full setup:
- the change procedure (analyse → plan → **GO** → dry-run → execute → verify → document);
- the secret-masking hook;
- an on-call agent that may **create** snapshots but never roll back;
- why "a test that should be refused" must be harmless if it isn't.

## Results, honestly

[docs/results.md](docs/results.md) gives the numbers so far:
- about 20 runs and about $3;
- a backtest on my agent's real past mistakes;
- what the council caught;
- its false alarms, and what it can't see (UX).

Short version: worth keeping, but it is a problem finder, not a judge. These are one person's anecdotal numbers, not a benchmark.

## License

MIT. Personal project by [renocz](https://github.com/renocz).

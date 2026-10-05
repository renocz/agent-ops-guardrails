# agent-ops-guardrails

**Guardrails for an AI agent that runs real infrastructure.**

I let an AI agent (Claude Code) run my homelab: a hypervisor, about forty containers, backups and a VPN. It has root, and it is good at the work. It is also confidently wrong a few times a week, and early on it printed secrets into its own transcript.

This repo collects the guardrails that grew around it. Each one exists because something went wrong once. The full story is in [docs/method.md](docs/method.md).

| Pillar | What it does | Status |
|---|---|---|
| [council/](council/) | Before a change that matters, four models from different vendors review the agent's plan. The verdict is computed from their votes, and a lone blocking objection is never merged away. | ✅ published |
| [secret-guard/](secret-guard/) | A Claude Code hook. It refuses commands that may print secrets unless their whole output goes through a masking filter, and blocks direct reads of secret files. | ✅ published |
| change procedure | Analyse → plan → explicit GO → dry-run → execute → verify with evidence → document. Packaged as an agent skill. | described in [method](docs/method.md), code to come |
| snapshot gate | An on-call agent may *request* a snapshot before an upgrade. The host takes it, and the agent can never roll back or delete. | described in [method](docs/method.md), code to come |
| on-call restrictions | A least-privilege role for the on-call agent. Denial tests must be harmless if they unexpectedly succeed. | described in [method](docs/method.md) |

## Results, honestly

[docs/results.md](docs/results.md) has the council numbers so far:
- about 20 runs for about $3;
- a backtest on my agent's real past mistakes;
- what it caught;
- its false alarms, and what it can't see (UX).

The [secret-guard README](secret-guard/README.md) explains how the hook was checked: about 5,600 real commands replayed through it before deployment.

These are one person's field notes, not a benchmark.

## License

MIT. Personal project by [renocz](https://github.com/renocz).

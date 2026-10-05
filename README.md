# agent-ops-guardrails

[![tests](https://github.com/renocz/agent-ops-guardrails/actions/workflows/tests.yml/badge.svg)](https://github.com/renocz/agent-ops-guardrails/actions/workflows/tests.yml)

**An operating model for an AI agent that runs real infrastructure: the guardrails, the method, and the field notes.**

I let an AI agent run my homelab: a hypervisor, about forty containers, backups and a VPN. The agent is Claude Code; the reviewers in the council come from four different vendors. It has root, and it is good at the work. It is also confidently wrong a few times a week, and early on it printed secrets into its own transcript.

This repo collects the guardrails that grew around it. Each one exists because something went wrong once.

## The principle in one picture

Each layer answers one way an AI ops agent fails. None of them is enough alone.

```mermaid
flowchart LR
    H(["👤 Human request"]) --> A["🤖 Agent analyses<br/>(read-only)"]
    A --> P["📝 Written plan:<br/>what, why, risk,<br/>dry-run, rollback"]
    P -->|"decision that matters"| C{{"🏛️ council<br/>4 models, 4 vendors"}}
    C -->|"FIX FIRST"| P
    C -->|"APPROVE<br/>(+ isolated alerts)"| G{"👤 Human GO?"}
    P -->|"routine change"| G
    G -->|"no"| P
    G -->|"yes"| S["📸 snapshot gate<br/>host takes a snapshot<br/>(agent can't roll back)"]
    S --> E["⚙️ Execute + verify<br/>with evidence"]
    E --> D["📚 Document<br/>(change record)"]
    SG["🔐 secret-guard<br/>every command and file read"] -.->|"watches"| A
    SG -.->|"watches"| E
```

| Failure mode of the agent | Guardrail | Status |
|---|---|---|
| Confidently wrong plan: a wrong diagnosis, an inconsistent threshold, a missed risk | [**council/**](council/): four models from different vendors review the written plan. The verdict is computed from their votes, and a lone blocking objection is never merged away. | ✅ code |
| Prints a secret by accident (`docker inspect`, `crontab -l`, an error message carrying a URL with credentials) | [**secret-guard/**](secret-guard/): a hook refuses commands that may print secrets unless their whole output goes through a masking filter, and blocks direct reads of secret files. | ✅ code |
| Acts without being asked, or skips checks | **Change procedure**: analyse → plan → explicit GO → dry-run → execute → verify with evidence → document. | 📄 [described](docs/method.md#1-the-change-procedure) |
| Breaks something during an upgrade | **Snapshot gate**: the agent *requests* a snapshot; the host takes it. The agent can never roll back or delete. | 📄 [described](docs/method.md#3-an-on-call-agent-that-cannot-undo) |
| Has too much power when working alone | **On-call restrictions**: a least-privilege role, and denial tests that are harmless if they unexpectedly succeed. | 📄 [described](docs/method.md#4-denial-tests-must-be-harmless) |

## Start here

- **See what you get:** a real [council report](examples/council-report.md) and the hook's real [refusals](examples/secret-guard-refusals.md).
- **Install secret-guard:** `./install.sh` (add `--write-settings` to register the hook in `~/.claude/settings.json`; a backup is made).
- **Questions?** The [FAQ](docs/faq.md) covers: why several LLMs, cost, use with other agents, false positives, limits, adapting it to your setup.
- **Review plans with several models:** [council/README.md](council/README.md). Works with any OpenAI-compatible endpoint.
- **Stop secret leaks in Claude Code:** [secret-guard/README.md](secret-guard/README.md). Two files to install, plus a settings snippet.
- **The whole method and the incidents behind it:** [docs/method.md](docs/method.md).

## Results, honestly

[docs/results.md](docs/results.md) has the council numbers so far:
- about 20 runs for about $3;
- a backtest on my agent's real past mistakes;
- what it caught;
- its false alarms, and what it can't see (UX).

The [secret-guard README](secret-guard/README.md#limits) explains how the hook was checked: about 5,700 real commands replayed through the old and new versions before deployment. That is a comparison between versions, not proof that nothing leaks.

These are one person's field notes, not a benchmark.

## License

MIT. Personal project by [renocz](https://github.com/renocz).

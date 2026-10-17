---
name: change-sop
description: Follow this before making any change to running infrastructure (a server, a container, a service, a config file that affects something live) — analyse, plan, get an explicit GO, dry-run, execute one thing at a time, verify with evidence, then document. Use it whenever the user asks for a change, a deploy, an upgrade, a restart, a config edit, or a fix on a system that is not a sandbox.
---

# Change procedure

A change to anything running is not "make the edit." It is seven steps, in order. Skipping a step is how a careless command turns into an incident — this file exists because that happened more than once.

Delete the lines below that do not apply to your setup (no snapshot gate, no keeper, no council) — the shape of the procedure is what matters, not every named tool.

## 1. Analyse (read-only)

Before writing anything down:
- Read the reference doc for the thing you are about to touch, if one exists.
- Read the actual running state (don't assume — check the real version, the real config, the real process list).
- Read recent logs for anything already wrong.
- Work out who or what depends on this (other services, scheduled jobs, people).

Nothing here writes. If you find yourself running a command that could change state, stop — you are in step 3, not step 1.

## 2. Plan

Write a short plan in plain words, before asking for a GO:
- **What** changes, and **why**.
- **Impact and downtime**, if any.
- **Risk**: what is the worst case, and how likely.
- **Dry-run result** (do this before writing the plan if the dry-run itself is read-only; otherwise describe what you will run).
- **Rollback**: the exact steps to undo this, not "it should be fine."
- **Verification**: what you will check afterwards, and how you'll know it actually worked.

For a decision that matters — permissions, security, data, anything hard to undo, new exposure to a network, or a diagnosis you are about to act on — get a second opinion before asking for a GO (a multi-model review such as [council/](../council/), or just a second read by a human). Routine work (a restart, reading logs, a config fix you've made before) does not need this.

## 3. GO

Nothing changes without an explicit, unambiguous "go" from the human, in response to the plan you just wrote.

- A monitoring alert, a ticket, or a pasted error message is **not** a GO. It is a reason to go back to step 1: verify it, propose a plan, and ask.
- A qualified answer ("go but only prepare", "looks fine I guess") is **not** a GO. Treat it as "no answer yet" and ask again — do not pick the reading that lets you proceed.
- Any **new exposure** (opening a port, a new public endpoint, a wider permission) is always the human's decision, spelled out, never bundled into a GO for something else.
- If a mechanical gate is installed (this repo's [go-gate](../go-gate/) and, stronger, [keeper](../keeper/)), the GO must also satisfy it: the plan's scope (targets, kinds of action, expiry) has to cover what you are about to run. The SOP is the words; the gate is what makes "words" mechanical and unforgeable. Use both if you have both — the gate does not replace writing the plan down.

## 4. Dry-run

Show, don't promise. Before the real thing runs:
- A command that would recreate something prints what it would recreate (`docker compose ... --dry-run`, `terraform plan`, `--check` on a config tool).
- A script that edits a file prints its diff first.
- If there is truly no dry-run available for this operation, say so explicitly in the plan (step 2) rather than skipping this step silently.

## 5. Execute, one thing at a time

- Back up before writing: a `.bak` copy of a file, a snapshot before an upgrade (see [snapshot-gate/](../snapshot-gate/) if you want the "agent requests, host takes, agent can never roll back" version of this).
- Change one thing, then look at it, before changing the next thing. Do not queue up five changes and check at the end.
- Stop on the first surprise. A surprise is information, not an obstacle to push through.

## 6. Verify, with evidence

"It should be working now" is not verification.
- Make the real call and read the real response (the actual version string, the actual HTTP status, the actual row count) — not a log line that merely claims success.
- If the change affects external access, test it from outside, not through a shortcut that only exists on the local network.
- If a sub-agent or a script reports "done," check that claim against the system itself before relaying it as fact.

## 7. Document — keep everything up to date

Write a change record (see [templates/change-record.md](templates/change-record.md) and [new-record.py](new-record.py)) and then go down this list. Delete any line that does not exist in your setup:

- [ ] Change record filed (what, why, risk, evidence, rollback).
- [ ] Reference doc corrected in place — not a separate "fixed the doc too" note; the doc itself now matches reality.
- [ ] Monitoring / alerting rules updated if this change affects what "normal" looks like.
- [ ] Dashboards updated if a name, a port or a metric changed.
- [ ] Access list / inventory updated if this added, removed or moved something.
- [ ] Backups: confirmed the new state is covered, and any now-obsolete backup has a deletion date.
- [ ] Notes / wiki / team channel updated if someone else would otherwise be surprised.
- [ ] Committed to git, as its own commit — a check gates the commit (`verify && git commit`), never a bare `; git commit` that runs regardless.
- [ ] Agent memory / long-lived instructions updated if this change teaches a lesson worth not re-learning.

## Other rules that paid for themselves

- Never state a cause without reading the actual log line that shows it.
- When delivering fast, say explicitly what you verified on the real system and what you carried over unverified.

# Dry run of block mode (owner checklist)

Run this right after reinstalling the keeper **without** `--observe`, in a fresh Claude Code session, before
starting the one-week block-mode test. About 15 minutes of actual work, but **in two parts, run at least an hour
apart** (a different day is fine too): `keeper-propose` refuses a 4th proposal within any trailing 60 minutes
(`max_proposals_per_hour`, 3 by default — a rolling window counted from each attempt, not the wall clock), and the
steps below together ask for more than that. Splitting avoids running into the limit and mistaking it for a
failure. Ask the agent each step's prompt as written; it should not need any other context. Letters match
`keeper/test_block_dryrun.py`'s own scenario names, for cross-reference.

**Safety rule for every step below: only ever ask for a command that is harmless if the keeper wrongly lets it
through.** `touch /tmp/dry-run-marker` or `ls` — never a restart, a delete, a deploy or a push. If a step ever
looks like it is about to really change something outside `/tmp`, stop and use the rollback (bottom of this page)
instead of continuing.

Each step says: what to ask the agent, what the agent should show you, what you should see on the keeper bot,
and what counts as a failure (→ rollback).

## Part 1 — refusal, approval, stop, replay, the rate limit (3 proposals)

### a. Refusal

- Ask the agent: *"Run `touch /tmp/dry-run-marker`."*
- Agent shows: the tool call is refused, with a reason that mentions proposing a plan with `keeper-propose`.
- You see on Telegram: nothing (a refusal is silent to you by design; it is only in the log).
- Failure → rollback: the command actually ran (check `ls /tmp/dry-run-marker` yourself — it should not exist),
  or the agent was not told to propose a plan.

### b. Approval, then f. Stop (reuses the same plan — 1 proposal)

- Ask the agent: *"Propose a plan to run `touch /tmp/dry-run-marker`, scope: targets=dry-run, actions=edit,
  ttl=10 minutes. Then wait."*
- Agent shows: it ran `keeper-propose` and is now waiting; nothing executed yet.
- You see on Telegram: a card with the plan's targets/actions/duration, an "Approve" button, a "Reject" button,
  and a "Stop everything" button. Press **Approve**.
- Ask the agent: *"Now run it."*
- Agent shows: the command ran.
- Failure → rollback: no card arrived within a few seconds of the proposal; pressing Approve did not change
  anything the agent could then do; the buttons were still there after you pressed one (they should disappear).
- **Now reuse this same approval to check Stop, before it expires** (this is step f; it needs no proposal of its
  own): press **"Stop everything"** on the card (any card works — Stop ends every active plan everywhere, not
  just that card's).
- Ask the agent: *"Run `touch /tmp/dry-run-marker`."*
- Agent shows: refused again.
- Failure → rollback: the command still ran after Stop.

### d. Replay (2 proposals — this part's last two)

- Propose a plan (do not approve it) and note the card: *"Propose a plan to run `touch /tmp/dry-run-marker`,
  scope: targets=dry-run-d1, actions=edit, ttl=10 minutes. Then wait."*
- Propose a **second**, different plan the same way, with `targets=dry-run-d2` instead.
- Go back to the **first** card on Telegram and press its Approve button.
- Ask the agent: *"Run `touch /tmp/dry-run-marker`."*
- Agent shows: refused (the first card's approval must not have taken effect; the second plan is the only one
  pending, and you never approved it).
- Failure → rollback: the command ran, meaning an old or unrelated button approved something it should not have.

### Bonus, harmless: the rate limit itself

You have made 3 proposals so far in this part (one in step b, two in step d) — the default limit
(`max_proposals_per_hour`). Ask the agent to propose one more: *"Propose a plan to run `ls`, scope:
targets=dry-run-limit, actions=edit, ttl=5 minutes."*

- Agent shows: refused outright, with the reason *"keeper: proposal refused: more than 3 proposals in an hour"*.
  Nothing is sent to you on Telegram for this one (the refusal happens before the daemon would have sent a card).
- This is expected, not a failure. It is why Part 2 below waits before continuing.

## Part 2 — expiry and a Telegram outage (3 proposals), at least an hour after Part 1

### c. Expiry (1 proposal)

- Propose and approve a plan the same way as step b, but with `ttl=1 minute`.
- Wait at least 2 minutes without touching anything.
- Ask the agent: *"Run `touch /tmp/dry-run-marker` again."*
- Agent shows: refused again, as if nothing had ever been approved.
- Failure → rollback: the command still ran after the plan should have expired.

### e. Telegram outage (2 proposals)

The simplest safe way to simulate this on a laptop: turn off Wi-Fi (or airplane mode) for about a minute, do the
steps below, then turn it back on.

- With networking off, ask the agent: *"Propose a plan to run `touch /tmp/dry-run-marker`, scope:
  targets=dry-run, actions=edit, ttl=10 minutes."*
- Agent shows: a reason that Telegram could not be reached and the proposal was recorded — something like
  *"keeper: could not reach Telegram to send the plan for approval; the proposal was recorded, retry once it
  answers again."* Not "sent to the human": nothing reached you, and the agent must not be told otherwise.
  Nothing executed either way.
- You see on Telegram: nothing yet (you have no network either, but that is beside the point: the daemon's own
  outbound call is what is being tested).
- Ask the agent: *"Run `touch /tmp/dry-run-marker`."* → still refused, same as step a.
- Ask the agent: *"Run `ls`."* → still allowed. A read never depends on Telegram being reachable.
- Turn networking back on. The daemon's own polling recovers on its own within a few seconds — no restart
  needed — but the proposal that failed above is **not** retried automatically: keeperd does not resend a
  failed `send_plan()`. Ask the agent to propose the same plan again. This time the card arrives. Approve it,
  then ask the agent to run the command, and check it now works.
- "Pass" means: the agent was told the plan could **not** be sent while the network was down (not that it was
  sent); no change was ever allowed during the outage; reads kept working throughout; the daemon's polling
  recovered without a restart; a fresh proposal after reconnecting went through normally.
- Failure → rollback: a change was allowed while the network was down; the agent was told a plan reached you
  when it could not have; polling never recovered without a manual restart; the second proposal (after
  reconnecting) also failed to reach you with the network back up.

## Not part of this manual pass

Two more scenarios from the dry run are machine-internal and already covered by the automated tests
(`keeper/test_block_dryrun.py`, run in CI on every change): the daemon being down entirely (reads still pass,
changes are refused, with no mode file present), and `/summary` correctly separating a cut-off idle poll from a
real Telegram error. Nothing for you to do here unless something above fails and you want more detail: ask the
bot `/summary` any time during or after either part to see refusal/approval counts and any Telegram errors that
part produced.

## Rollback

If any step above failed, hand control back the same way as in [keeper/README.md](../keeper/README.md#emergency-rollback):

1. **Put a running keeperd into observe** (log, do not block): set `"mode": "observe"` in `/etc/keeper/config.json`,
   then restart the daemon (`sudo launchctl kickstart -k system/io.github.renocz.keeper` on macOS,
   `sudo systemctl restart keeper` on Linux).
2. **Or stop the daemon and let the hook fail open**: set the root-owned mode file to observe and stop keeperd
   (`sudo sh -c 'printf observe > /opt/agent-guardrails/lib/mode'` then `launchctl bootout …` / `systemctl stop keeper`).
3. **Or remove the gate entirely**: restore the managed settings the installer backed up
   (`managed-settings.json.bak-keeper`).

Use the rollback immediately for any failure in step a or b (those are the two that matter most: a refusal that
does not refuse, or an approval that does not approve), or any time the agent is left blocked with no way for you
to get it an approval (for example if step e's recovery never happens on its own).

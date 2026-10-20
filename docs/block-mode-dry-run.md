# Dry run of block mode (owner checklist)

Run this right after reinstalling the keeper **without** `--observe`, in a fresh Claude Code session, before
starting the one-week block-mode test. About 15 minutes of actual work, but **in two parts, run at least an hour
apart** (a different day is fine too): `keeper-propose` refuses a 4th proposal within any trailing 60 minutes
(`max_proposals_per_hour`, 3 by default — a rolling window counted from each attempt, not the wall clock), and the
steps below together ask for more than that. Splitting avoids running into the limit and mistaking it for a
failure. Ask the agent each step's prompt as written; it should not need any other context. Letters match
`keeper/test_block_dryrun.py`'s own scenario names, for cross-reference.

**Every marker command below uses `~/dry-run-marker`, never a path under `/tmp`.** `/tmp` (and `/private/tmp`,
`/var/folders`, `$TMPDIR`) is scratch space by design (`SCRATCH` in `go-gate/go_gate.py`): a write there is always
classified as a read and never needs approval, so step a below could never actually be refused if it touched
`/tmp` — that is a real bug a run of this checklist found on 12/10, not a typo. `~/dry-run-marker` is an ordinary
home-directory file, so it is properly classified as a change and the checklist exercises the real gate.

If you ask the agent to run `keeper-status` directly (outside of what the steps below already do through
`keeper-propose`), note that keeperd only answers it when the command is run **alone**: `keeper-status` works,
but `keeper-status; ls` or `keeper-status && ls` does not — a chained command is classified normally instead,
so the agent sees an ordinary refusal reason, not the status report. This has no effect on `/status` or `/plans`
below: those are commands you send to the bot directly on Telegram, never through the agent.

**Safety rule for every step below: only ever ask for a command that is harmless if the keeper wrongly lets it
through.** `touch ~/dry-run-marker` or `ls` — never a restart, a delete outside this one marker file, a deploy or
a push. If a step ever looks like it is about to really change something else, stop and use the rollback (bottom
of this page) instead of continuing.

Each step says: what to ask the agent, what the agent should show you, what you should see on the keeper bot,
and what counts as a failure (→ rollback).

### 0. Restart your open sessions

If any Claude Code session was already open before you (re)installed or reinstalled the keeper, restart it before
starting below. A session keeps the hooks it had when it started; the installer edits the managed settings on
disk, but a session already running does not re-read them. A session started fresh after the install is fine.

## Part 1 — refusal, approval, stop/status, replay, the rate limit (3 proposals)

### a. Refusal

- Ask the agent: *"Run `touch ~/dry-run-marker`."*
- Agent shows: the tool call is refused, with a reason that mentions proposing a plan with `keeper-propose`.
- You see on Telegram: nothing (a refusal is silent to you by design; it is only in the log).
- Failure → rollback: the command actually ran (check `ls ~/dry-run-marker` yourself — it should not exist),
  or the agent was not told to propose a plan.

### b. Approval, then f. Status and Stop (reuses the same plan — 1 proposal)

- Ask the agent: *"Propose a plan to run `touch ~/dry-run-marker`, scope: targets=dry-run-marker, actions=edit,
  ttl=10 minutes. Then wait."* (`dry-run-marker` is the filename itself, so it matches as a whole path segment of
  `~/dry-run-marker`: a target only ever matches a whole token or path segment of the command, never a mere
  substring, so `targets=dry-run` would not have covered this file.)
- Agent shows: it ran `keeper-propose` and is now waiting; nothing executed yet.
- You see on Telegram: a card with the plan's targets/actions/duration, an "Approve" button, a "Reject" button,
  and a "Stop everything" button. Press **Approve**.
- Ask the agent: *"Now run it."*
- Agent shows: the command ran.
- Failure → rollback: no card arrived within a few seconds of the proposal; pressing Approve did not change
  anything the agent could then do; the buttons were still there after you pressed one (they should disappear).
- **Now reuse this same approval to check `/status` and `/stop`, before it expires** (this is step f; it needs no
  proposal of its own). Send the bot `/status`: it should show one active plan (this one), its targets/actions and
  the minutes left, and the proposal count for this hour. It must **not** show the agent's own explanation text or
  the raw command. Send `/stop`: it answers that the plan is now stopped.
- Ask the agent: *"Run `touch ~/dry-run-marker`."*
- Agent shows: refused again.
- Send `/status` again: it should now show no active plan.
- Failure → rollback: the command still ran after `/stop`, or `/status` kept showing the plan as active after it.

Pressing the card's own **"Stop everything"** button instead of `/stop` works the same way (they share the same
code) — use whichever you prefer; `/stop` has the advantage of still being reachable once the card's buttons are
gone (see step e for why you need that).

### d. Replay (2 proposals — this part's last two)

Neither of the two plans below is ever actually used to run anything — the point of this step is that approving
an old card no longer does anything once a new one has replaced it, not that the targets match. So `targets` only
needs to be a real token of the command (`dry-run-marker`, same as step b); what tells the two cards apart on
Telegram is their `id`, shown first on each card.

- Propose a plan (do not approve it) and note the card: *"Propose a plan to run `touch ~/dry-run-marker`, scope:
  id=d1, targets=dry-run-marker, actions=edit, ttl=10 minutes. Then wait."*
- Propose a **second**, different plan the same way, with `id=d2` instead of `id=d1`.
- Go back to the **first** card on Telegram (headed "Plan: d1") and press its Approve button.
- Ask the agent: *"Run `touch ~/dry-run-marker`."*
- Agent shows: refused (the first card's approval must not have taken effect; the second plan, d2, is the only
  one pending, and you never approved it).
- Failure → rollback: the command ran, meaning an old or unrelated button approved something it should not have.

### Bonus, harmless: the rate limit itself

You have made 3 proposals so far in this part (one in step b, two in step d) — the default limit
(`max_proposals_per_hour`). Ask the agent to propose one more: *"Propose a plan to run `ls`, scope:
targets=dry-run-limit, actions=edit, ttl=5 minutes."*

- Agent shows: refused outright, with the reason *"keeper: proposal refused: more than 3 proposals in an hour"*.
  Nothing is sent to you on Telegram for this one (the refusal happens before the daemon would have sent a card).
- This is expected, not a failure. It is why Part 2 below waits before continuing.

## Part 2 — expiry, a Telegram outage, and cleanup (3 proposals), at least an hour after Part 1

### c. Expiry (1 proposal)

- Propose and approve a plan the same way as step b, but with `ttl=1 minute`.
- Ask the agent to run it once, to confirm it still works while active.
- Wait at least 2 minutes without touching anything.
- Ask the agent: *"Run `touch ~/dry-run-marker` again."*
- Agent shows: refused again, as if nothing had ever been approved.
- Failure → rollback: the command still ran after the plan should have expired.

### e. Telegram outage, then cleanup (2 proposals — this checklist's last two)

The simplest safe way to simulate this on a laptop: turn off Wi-Fi (or airplane mode) for about a minute, do the
steps below, then turn it back on.

- With networking off, ask the agent: *"Propose a plan to run `touch ~/dry-run-marker`, scope:
  targets=dry-run-marker, actions=edit, ttl=10 minutes."*
- Agent shows: a reason that Telegram could not be reached and the proposal was recorded — something like
  *"keeper: could not reach Telegram to send the plan for approval; the proposal was recorded, retry once it
  answers again."* Not "sent to the human": nothing reached you, and the agent must not be told otherwise.
  Nothing executed either way.
- You see on Telegram: nothing yet (you have no network either, but that is beside the point: the daemon's own
  outbound call is what is being tested).
- Ask the agent: *"Run `touch ~/dry-run-marker`."* → still refused, same as step a.
- Ask the agent: *"Run `ls`."* → still allowed. A read never depends on Telegram being reachable.
- Turn networking back on. The daemon's own polling recovers on its own within a few seconds — no restart
  needed — but the proposal that failed above is **not** retried automatically: keeperd does not resend a
  failed `send_plan()`. Ask the agent to propose the same plan again, this time also covering this checklist's
  cleanup: *"Propose a plan to run `touch ~/dry-run-marker`, scope: targets=dry-run-marker, actions=edit,delete,
  ttl=10 minutes."* This time the card arrives. Approve it, then ask the agent to run the command, and check it
  now works.
- "Pass" means: the agent was told the plan could **not** be sent while the network was down (not that it was
  sent); no change was ever allowed during the outage; reads kept working throughout; the daemon's polling
  recovered without a restart; a fresh proposal after reconnecting went through normally.
- Failure → rollback: a change was allowed while the network was down; the agent was told a plan reached you
  when it could not have; polling never recovered without a manual restart; the second proposal (after
  reconnecting) also failed to reach you with the network back up.
- **Cleanup (same approval, no extra proposal):** ask the agent to run `rm ~/dry-run-marker`. It should succeed —
  the plan you just approved also covers `delete`, and `dry-run-marker` is the only file this whole checklist ever
  created: steps a and d never actually run the command, and every other step (b, c, this one) touches that same
  single path, never a new one.

## Part 3 — several plans at once (2 proposals), at least an hour after Part 2

### g. Approving a second plan does not throw away the first

This is the exact regression this feature fixes: before it, approving a new plan replaced whatever was already
active, so a parallel task relying on the first plan would suddenly start getting refused for no reason it caused.

- Propose and approve a plan: *"Propose a plan to run `touch ~/dry-run-marker`, scope: id=g1,
  targets=dry-run-marker, actions=edit,delete, ttl=10 minutes."*
- Ask the agent: *"Run `touch ~/dry-run-marker`."* → allowed.
- Propose a second, unrelated plan: *"Propose a plan to run `ls`, scope: id=g2, targets=dry-run-other,
  actions=edit, ttl=10 minutes."* Before you tap Approve, read the card: it should say it **adds to** the active
  plans (naming `g1`), not replace it. Approve it.
- Send `/status`: both `g1` and `g2` should be listed, each with its own targets and time left — never just one.
- Ask the agent: *"Run `touch ~/dry-run-marker`."* → still allowed. `g1` never stopped covering anything when
  `g2` was approved.
- **Cleanup, while `g1` is still active (no extra proposal):** ask the agent to run `rm ~/dry-run-marker`. It
  should succeed — `g1`'s scope covers `delete` too.
- Send `/stop g1`: answers "stopped: plan g1".
- Ask the agent: *"Run `touch ~/dry-run-marker`."* → refused (`g1` is gone).
- Send `/status`: `g2` should still be listed as active; `g1` should not.
- Send `/stop` (no id, no proposal needed): ends `g2` too, leaving nothing active for the next session.
- Failure → rollback: approving `g2` made `g1` stop covering its own scope; `/status` ever showed only one of the
  two while both were active; `/stop g1` also ended `g2`; the card for `g2` did not mention `g1` at all.

## Not part of this manual pass

Two more scenarios from the dry run are machine-internal and already covered by the automated tests
(`keeper/test_block_dryrun.py`, run in CI on every change): the daemon being down entirely (reads still pass,
changes are refused, with no mode file present), and `/summary` correctly separating a cut-off idle poll from a
real Telegram error. Nothing for you to do here unless something above fails and you want more detail: ask the
bot `/summary` any time during or after either part to see refusal/approval counts and any Telegram errors that
part produced, or `/plans` for the last few plan events with their outcome.

## Rollback

If any step above failed, hand control back the same way as in [keeper/README.md](../keeper/README.md#emergency-rollback):

1. **Put a running keeperd into observe** (log, do not block): set `"mode": "observe"` in `/etc/keeper/config.json`,
   then restart the daemon (`sudo launchctl kickstart -k system/io.github.renocz.keeper` on macOS,
   `sudo systemctl restart keeper` on Linux).
2. **Or stop the daemon and let the hook fail open**: set the root-owned mode file to observe and stop keeperd
   (`sudo sh -c 'printf observe > /opt/agent-guardrails/lib/mode'` then `launchctl bootout …` / `systemctl stop keeper`).
3. **Or remove the gate entirely**: restore the managed settings the installer backed up
   (`managed-settings.json.bak-keeper`).

Sending `/stop` on Telegram also revokes every active and pending plan immediately, without touching the gate
itself — try that first if the only problem is a plan you want gone right now; reach for the rollback above when
the gate itself is not doing what it should.

Use the rollback immediately for any failure in step a or b (those are the two that matter most: a refusal that
does not refuse, or an approval that does not approve), or any time the agent is left blocked with no way for you
to get it an approval (for example if step e's recovery never happens on its own).

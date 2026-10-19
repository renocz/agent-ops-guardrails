# keeper: approvals the agent cannot forge (go-gate step 2)

go-gate alone runs with the agent's rights and reads the text the agent writes, so a determined agent can write its
state, replay a GO or remove the hook. The keeper moves the approval out of the agent's reach. Design and threat model:
[docs/design-keeper.md](../docs/design-keeper.md).

**Precondition: the agent must not be root/admin on the machine where the keeper runs.**

## How it works

- `keeperd` runs as a dedicated user (`_keeper` on macOS, `keeper` on Linux). It owns the approval state
  (`/var/lib/keeper`, mode 700) and is the only one holding the token of a second Telegram bot, the *keeper bot*.
- The agent proposes a plan by running
  `/opt/agent-guardrails/bin/keeper-propose --scope "id=… ; targets=… ; actions=… ; ttl=…" --text "why"`.
  keeperd answers that command itself in the hook's check, with the session id Claude Code gave the hook, so the
  command never runs. keeperd then sends the plan to you on the keeper bot:
  - the first lines are generated from the scope;
  - ⚠️ lines appear for `script`, `delete` or a plan without targets;
  - the agent's text comes after.

  You get three buttons: Approve, Reject, and Stop, which ends every active plan.
- An approval is a button press, received by keeperd from Telegram. It is checked against the owner id and the chat,
  is bound to that plan's fingerprint, works once only, and must come within 2 h. The plan then stays active for its
  TTL: 1 h by default, 4 h at most. Anything the agent writes in its conversation approves nothing.
- Add `--wait SECONDS` to `keeper-propose` and the same Bash tool call blocks (up to `wait_max_sec`, 50 s by
  default, see "Hook timeout and `--wait`" below) until you decide, instead of the agent having to run `keeper-status` again to find out. The hook polls
  keeperd's `status` op on the same socket, by the plan's fingerprint only -- never the plan's text or scope, and
  never a new channel. The decision itself still comes only from a button press on the keeper bot, checked exactly
  as above; `--wait` only changes how soon the agent's own Bash call learns about it. Leaving `--wait` out behaves
  exactly as before. The tool call always ends up denied either way (there is nothing to run): the reason tells the
  agent the plan was approved, rejected, expired before you decided, or that the wait itself ran out while still
  pending (propose again to keep checking).
- The PreToolUse hook (`keeper_client.py`) only forwards the raw tool call to keeperd and applies its answer. keeperd
  classifies the call with the go-gate classifier (root-owned copy).
- The hook is registered in Claude Code's root-owned **managed settings**. Its code lives in
  `/opt/agent-guardrails/lib/` (root, 644) and runs as `/usr/bin/env -i /usr/bin/python3 -I`.
- If keeperd is down, the hook lets reads through and refuses changes.

## Install

```sh
./install-keeper.sh --agent-user you --owner-id <your Telegram id>                    # dry run (default)
./install-keeper.sh --agent-user you --owner-id <id> --prefix /tmp/kp                  # files only, to inspect
sudo ./install-keeper.sh --agent-user you --owner-id <id> --apply [--observe]          # real install
```

Options worth knowing: `--observe` (log only, block nothing), `--lang fr` (what you read on Telegram in French, default
`en`), `--safe-git-repo DIR` (repeatable, see the limits below).

Create the keeper bot with BotFather first. With `--apply`, the installer asks for its token on the terminal (hidden
input); the token is never passed as an argument. If managed settings already exist, the installer merges into them: it puts
the keeper hook first, adds the deny rules, shows the diff and keeps a `.bak-keeper` copy.

**After any (re)install, restart every Claude Code session that was already open.** A running session keeps the hooks
it started with; it will not pick up the keeper hook (or an updated one) until restarted. A session you start after
the install is fine.

## Commands on the keeper bot

Send these to the keeper bot from your own chat; only you (`owner_id`, in the configured chat) are answered — a command
attempt (text starting with `/`) from anyone else is ignored and logged without its text, and none of this is reachable
through the socket, so the agent can never see it. All five also show up in Telegram's "/" menu for this chat (never
in a global menu a stranger who finds the bot could see).

- **`/stop`** — revokes every active and pending plan right now, across every session, exactly like the card's own
  "Stop everything" button (they share the same code). Answers "stopped" or "nothing active".
- **`/status`** — mode (block/observe); for each session with an active plan, its id, actions, targets and the time
  left; how many proposals are pending; proposals made in the last rolling hour against `max_proposals_per_hour`.
  Read-only, and never the agent's free-form explanation or the raw command.
- **`/plans [n]`** — the last `n` plan events (default 5, max 20): proposed, approved, rejected, expired, revoked,
  each with its id, local time and outcome.
- **`/help`** — lists these commands, one line each, in your configured language.
- **`/summary [days]`** (alias `/resume`) — see below: the refusal/approval log, not the plans themselves.

### Review the log before switching to block mode: `/summary`

In observe mode nothing is blocked; every call that **would** have been refused is logged. That log belongs to the keeper
user, so you cannot (and the agent must not) read it. Ask the bot instead: send it `/summary` (alias `/resume`).

- `/summary` covers the last 7 days; `/summary 1` the last day (1 to 30 allowed).
- You get: would-deny / denied / allowed-under-an-approved-plan counts, grouped by tool and by category; the 10 most
  frequent **shapes**; plans proposed / approved / rejected / expired; Telegram errors; and what was ignored (unknown
  socket clients, strangers writing to the bot, proposal floods).
- A **shape** is the first word of the command, the subcommand for known CLIs (git, docker, kubectl, systemctl…),
  and its category, arguments replaced by `…`: `docker restart … [deploy]`, `git push … [git]`. The log
  does not store the arguments of a refused command, so there is nothing secret to show. Lines logged by an older version have no shape; the summary
  counts them ("no recorded shape") instead of guessing.
- On the machine, as root: `sudo keeper-summary [days]` prints the same text. Mode 700, not setuid, refuses non-root.
  **Do not run it inside an agent session**: the output would then be in front of the agent.

What to look at before blocking: which shapes dominate (a routine you forgot to cover with a plan?), anything in the
`script` category (it needs `actions=script`), and whether `Telegram errors` is zero (an approval you cannot receive is a
block you cannot lift).

## Hook timeout and `--wait`

`--wait` keeps the PreToolUse hook process alive while it polls, and Claude Code kills a command hook at its
`timeout` (seconds; its documented default is 600 for command hooks, and the installer does not rely on it). Per the
Claude Code hooks documentation, **a PreToolUse command hook that times out does not block the tool call**: the call
continues through the normal permission flow. A timeout is therefore a fail-open outcome, not a deny, and a wait must
never be allowed to reach it.

- `install-keeper.sh` writes an explicit `"timeout"` into the hook entry: 60 s by default (`--hook-timeout N`). A
  reinstall updates an existing keeper entry that has none (or another value) in place, and never adds a second one.
- `wait_max_sec` (config key, `--wait-max N` at install) defaults to 50 s. **Rule: `hook_timeout_sec` must be at
  least `wait_max_sec` + 10** (the margin covers one in-flight status poll and the hook's start-up). The installer
  refuses a combination that breaks it; keeperd, which also reads `hook_timeout_sec` from its config, clamps any
  `--wait` to `hook_timeout_sec - 10` anyway (and warns at start-up if `wait_max_sec` itself does not fit), so
  editing only one of the two numbers by hand cannot reopen the gap.
- To allow a longer wait, raise both: `install-keeper.sh ... --hook-timeout 1810 --wait-max 1800`. If you edit the
  keeper's config by hand instead, the hook entry in the managed settings must carry the same value as its
  `timeout`: keeperd cannot read the managed settings, so it trusts its own config.
- Without `--wait`, the hook answers in milliseconds and none of this applies.

## Language

The config key `lang` (`en` by default, or `fr`; `install-keeper.sh --lang fr` writes it) sets the language of everything
**you** read on Telegram: the approval card, the buttons, the answers, the startup line and the summary. What the **agent**
reads (the reasons the hook returns when it refuses a call) always stays English: it is part of the agent contract. An
unknown value falls back to English.

The startup line follows the mode: in observe it says that nothing is blocked and events are only logged (and points to
`/summary`); in block it says changes now need your approval.

## What the keeper does and does not guarantee (read these)

Two different things, and only the first is strong:

- **The approval cannot be forged by the agent.** It is a button press on a bot only `_keeper` can read, bound to the
  plan's fingerprint, single use, and the hook is root-owned in managed settings. An agent with the user's rights (not
  root) cannot create, replay or alter it. That is the point of the keeper.
- **The gate decides what counts as a change with a heuristic classifier.** That is not a proof. A review on 08/10 found
  a class of "read" commands that actually execute or write through an option or a config file; those are fixed and
  tested (ssh `ProxyCommand`/`-F`, `awk -f`, `sed -e 'w'`, `curl -K`, a `PAGER`/`GIT_*` prefix, git read verbs outside a
  declared safe repo, the `<>` redirection). The classifier stays heuristic, so a new "read" that can run a program is a
  bug to report, not a guarantee.

Still open:

- The keeper gates **tool calls**. A command approved under `actions=script` can do anything the agent's user can do.
  A process started under an approved plan keeps running after the plan ends or is stopped.
- Opaque commands always need `script`. So do: programs run by path outside system directories; commands that change
  `PATH`, `LD_*`/`DYLD_*` or aliases; writing into `~/bin`, `~/.local/bin`, `/usr/local/bin` or `/opt/homebrew/bin`.
- **git read verbs are trusted only in a declared safe repo.** A repo-local config (`core.fsmonitor`, `core.pager`, an
  alias `!cmd`) runs a program even on `git status`. List your repos at install time with `--safe-git-repo DIR`
  (repeatable); with none, every git read needs a plan. A safe repo the agent can itself write to voids this.
- Sessions are not a security boundary: every session runs as the same user. They keep plans apart for clarity.
- The installer refuses to install when a parent directory of the code is not root-owned or is writable by others.
- `python3 script.py` is judged on the script's content when keeperd reads it. The file can still change between that
  check and the run.
- Output filtering (secret-guard) still runs in the agent's process.
- A stronger design runs every change in an isolated executor under another user. That is the direction for v2.

## Emergency rollback

To hand control back fast (do this as a human with sudo; the agent cannot):

1. **Put a running keeperd into observe** (log, do not block): set `"mode": "observe"` in `/etc/keeper/config.json`,
   then restart the daemon (`sudo launchctl kickstart -k system/io.github.renocz.keeper` on macOS,
   `sudo systemctl restart keeper` on Linux). keeperd reads its mode at startup, so the restart is required.
2. **Or stop the daemon and let the hook fail open**: set the root-owned mode file to observe and stop keeperd
   (`sudo sh -c 'printf observe > /opt/agent-guardrails/lib/mode'` then `launchctl bootout …` / `systemctl stop keeper`).
   The mode file is consulted **only when keeperd is unreachable**; with it on `block` and the daemon stopped, every
   change is refused (reads still pass).
3. **Or remove the gate entirely**: restore the managed settings the installer backed up
   (`managed-settings.json.bak-keeper`).

## Tests

`python3 test_keeper.py`: no network and no install. The tests use a fake Telegram and a socket in a temp dir, and
cover:

- the state machine;
- forged, replayed, stale or stranger approvals;
- swapping in a new plan under an old button;
- flooding;
- an unknown socket peer;
- an `approve` op sent on the socket;
- a daemon that is down;
- classifier tricks;
- the `/summary` command: who may ask, that no socket op returns it, that no argument or secret reaches the text, the
  window, the split below the Telegram limit;
- `/stop`, `/status`, `/plans` and `/help`: who may ask (same gate as `/summary`), that `/status`/`/plans` never leak
  the agent's free-form text or the raw command, that `/stop` and the card's button revoke the same way, and that
  approve/reject/mode are never reachable as a typed command; the "/" menu registration (chat-scoped, non-fatal);
- the French and English messages (every key in both languages, the English card unchanged), the startup line by mode,
  and `keeper-summary`;
- `keeper-propose --wait`: the `status` op's closed vocabulary (pending/approved/rejected/expired, never the plan
  itself) and its peer-uid gate, two plans tracked independently, a late click still counted as expired, the
  ledger pruned by age, and the hook's own `wait_for_decision()` against a real socket (approved/rejected/expired
  while still waiting, the wait itself running out, a daemon that is down or stops answering mid-wait).

- the hook timeout (`InstallerHookTimeout`, `WaitClamp`): the installer writes the `timeout` into the entry, a
  reinstall is idempotent and upgrades an entry that has none, a `--wait-max` that does not fit under
  `--hook-timeout` is refused with nothing written, and keeperd clamps `--wait` under the timeout. Mutation-checked:
  the clamp removed, the installer's refusal removed, and the in-place upgrade removed, each makes tests fail.

`python3 test_block_dryrun.py` adds the same `--wait` scenarios end to end, through the real hook subprocess: the
Bash tool call stays blocked on the open socket while the card is still pending, and returns once the owner's
click (or the plan's own age limit) resolves it, or once the wait itself runs out.

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

Create the keeper bot with BotFather first. With `--apply`, the installer asks for its token on the terminal (hidden
input); the token is never passed as an argument. If managed settings already exist, the installer merges into them: it puts
the keeper hook first, adds the deny rules, shows the diff and keeps a `.bak-keeper` copy.

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
- classifier tricks.

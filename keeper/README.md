# keeper: approvals the agent cannot forge (go-gate step 2)

go-gate alone runs with the agent's rights and reads the text the agent writes, so a determined agent can write its
state, replay a GO or remove the hook. The keeper moves the approval out of the agent's reach. Design and threat model:
[docs/design-keeper.md](../docs/design-keeper.md).

**Precondition: the agent must not be root/admin on the machine where the keeper runs.**

## How it works

- `keeperd` runs as a dedicated user (`_keeper` on macOS, `keeper` on Linux). It owns the approval state
  (`/var/lib/keeper`, mode 700) and is the only one holding the token of a second Telegram bot, the *keeper bot*.
- The agent proposes a plan with `keeper-propose --scope "id=… ; targets=… ; actions=… ; ttl=…" < explanation`.
  keeperd sends it to you on the keeper bot. The first lines are generated from the scope, then comes the agent's text.
  You get three buttons: Approve, Reject and Stop.
- An approval is a button press, received by keeperd from Telegram. It is checked against the owner id and the chat,
  is bound to that plan's fingerprint, works once only, and must come within 2 h. The plan then stays active for its
  TTL: 1 h by default, 4 h at most. Anything the agent writes in its conversation approves nothing.
- The PreToolUse hook (`keeper_client.py`) only forwards the raw tool call to keeperd and applies its answer. keeperd
  classifies the call with the go-gate classifier (root-owned copy).
- The hook is registered in Claude Code's root-owned **managed settings**. Its code lives in
  `/usr/local/lib/agent-guardrails/` (root, 644) and runs as `/usr/bin/env -i /usr/bin/python3 -I`.
- If keeperd is down, the hook lets reads through and refuses changes.

## Install

```sh
./install-keeper.sh --agent-user you --owner-id <your Telegram id>                    # dry run (default)
./install-keeper.sh --agent-user you --owner-id <id> --prefix /tmp/kp                  # files only, to inspect
sudo ./install-keeper.sh --agent-user you --owner-id <id> --apply [--observe]          # real install
```

Create the keeper bot with BotFather first. With `--apply`, the installer asks for its token on the terminal (hidden
input); the token is never passed as an argument. If managed settings already exist, the installer does not touch them
and prints the snippet to merge.

## Limits (read these)

- The keeper gates **tool calls**. A command approved under `actions=script` can do anything the agent's user can do.
  A process started under an approved plan keeps running after the plan ends or is stopped.
- The classifier is heuristic. Opaque commands always need `script`, and so do programs run from a scratch path and
  commands that change `PATH`, `LD_*`/`DYLD_*` or aliases.
- `python3 script.py` is judged on the script's content when keeperd reads it. The file can still change between that
  check and the run.
- Output filtering (secret-guard) still runs in the agent's process.
- A stronger design runs every change in an isolated executor under another user. That is the direction for v2.

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

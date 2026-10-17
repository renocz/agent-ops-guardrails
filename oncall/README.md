# oncall

Least privilege for the agent that works alone, with no human watching every call in real time — plus denial
tests that stay harmless even when they turn out wrong. Generic: `{{VMID}}`, `example-host`, `oncall-agent` are
placeholders for your own names.

**Status: experimental.** The runner and the static harmlessness check are tested (21 tests across both). The
probes and templates themselves are examples to adapt, not verified against a real restricted identity.

## The model

[method.md §3](../docs/method.md#3-an-on-call-agent-that-cannot-undo) and
[§4](../docs/method.md#4-denial-tests-must-be-harmless) in one sentence: an agent working alone, with no human
approving each call as it happens, needs *fewer* rights than one a human is actively steering — and whatever
rights it does get need to be checked for real, with tests that cannot make things worse if the check itself
turns out to be wrong.

- **A dedicated, low-privilege role or user** for the on-call agent, never the same identity as the one a
  human drives interactively.
- **Create-only doors instead of rights**, wherever the real action is "ask a privileged process to do a
  narrow thing" rather than "do the thing directly" — [snapshot-gate/](../snapshot-gate/) is the worked
  example: the agent's own reachable capability is "write a request file," never "snapshot," and certainly
  never "rollback" or "destroy."
- **Forced-command SSH keys** (`command="...",restrict`, no tunnels, no pty) where an API role can't be scoped
  narrowly enough on its own — see `templates/sshd-forced-command.snippet`.
- **An explicit list of what the on-call agent must NOT be able to do.** Not a vague "least privilege," a
  written list you can actually test against — that list is `probes.json`.

## What the on-call agent must not be able to do (the shipped probes)

1. Read a root-only file (a dedicated canary, not a real secret — see below).
2. Write outside the directory it's actually allowed to write to.
3. List another user's secrets directory.
4. Run the hypervisor's destructive verb (restart/destroy/etc.) against a target id.
5. Open a tunnel through its forced-command SSH key.
6. Add itself to a sudoers-like capability.

Add your own to `probes.json` — it's a plain JSON list, each entry `{"name": ..., "command": [...]}`, where a
token can be `{{A_PLACEHOLDER}}` (substituted from `--vars`, or the runner's own safe defaults).

## Why every probe must be harmless if it unexpectedly succeeds

Learned the hard way (method.md §4): a "this must be refused" test was once accepted and actually ran. Since
then, every probe here targets a **non-existent object**, a **throwaway/placeholder path**, or a **read-only
check** — never a real id, a real service name, or `rm`/`restart`/`destroy` against something that matters.

`lib/harmless_check.py` enforces this mechanically on the data file itself, before anything ever runs: once a
dangerous verb (`rm`, `destroy`, `restart`, `reboot`, `shutdown`, `delete`, `drop`, `kill`, `truncate`, …)
appears as a bare word anywhere in a probe's command — including hidden inside one `sh -c "..."` string, not
just as its own argv element — every word after it must be a flag or a `{{PLACEHOLDER}}`, never a literal path,
hostname or id.

```sh
python3 lib/harmless_check.py probes.json
```

**One real, accepted limit:** probe 4 (a destructive verb against a non-existent id) cannot always tell
"refused" apart from "would have been allowed against a real target, but this one doesn't exist." Both outcomes
are safe — nothing gets destroyed either way — but only one of them tells you the permission itself is actually
narrow. Treat a FAIL there as "go read the role definition," not as final proof either way.

## Running the probes

```sh
./denial-probe.sh probes.json                       # against the shipped, safe-by-default placeholders
./denial-probe.sh probes.json --vars my-vars.json    # once you've pointed the placeholders at your own setup
```

Run this **as the restricted identity itself** (`su - oncall-agent -c '...'`, or over the forced-command key
with a throwaway override), not as yourself or as root — root can do everything, so running it as root only
tells you the probes themselves execute, not that anything is actually restricted. Each line is `PASS` (refused
— good) or `FAIL` (accepted — the restriction does not hold). The probed command's own output is never printed,
even on a FAIL: an unexpectedly-successful "list another user's secrets" probe should not then print the
secrets directory's real contents into your terminal.

## Templates

Examples to adapt, **not a hardened distribution**:

- `templates/proxmox-role.cfg` — a Proxmox-style role with the narrow privilege set this agent needs, and the
  list of what's deliberately left out.
- `templates/sshd-forced-command.snippet` — a forced-command `authorized_keys` line.
- `templates/sudoers-snapshot-door.sample` — a sudoers fragment for the create-only snapshot door, for setups
  where group membership (snapshot-gate's own default) isn't an option.

## Testing

```sh
python3 -m unittest test_run_probes test_harmless_check -v
```

21 tests: the runner against fake stub commands only (never a real path, ssh call or hypervisor command) —
accepted vs refused, a missing command treated as refused rather than a crash, a missing placeholder value
reported rather than guessed at, placeholder substitution (whole-token expansion to several argv elements,
and plain substitution when embedded in a larger string), probed output never printed; the harmlessness check
on crafted probes and on the shipped file itself, including the mutation check — a harmful probe
(`pct destroy 100`, no placeholder) injected into a copy of the real list is caught, not missed.

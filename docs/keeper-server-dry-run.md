# Server rollout: the owner's real-world trial, observe before block

This is the server equivalent of [docs/block-mode-dry-run.md](block-mode-dry-run.md) (the laptop's own checklist)
— run it after [docs/deploy-keeper-server.md](deploy-keeper-server.md)'s steps are all done and
`keeper/check-keeper-server.sh` is clean, and **before** turning off `--observe` on `lxc-agents` (or whatever you
named your real LXC). Nothing below can be done from a cloud session: every item needs the real host, a real
`claude -p`, and in one case a real container with a real healthcheck.

Mirror the design doc's own staged rollout (§5) and do these **in order**:

1. **Throwaway container first, never `lxc-agents` directly.** `sudo ./install-keeper.sh --agent-user <test-user>
   --owner-id <id> --apply --observe` in a disposable Debian LXC you can destroy, confirm the daemon starts, the
   hook answers, `/status` and `keeper-status` work, then destroy the container. Costs about the same half hour
   the laptop's own dry run already took.
2. **On the real host, `--observe` first.** Install with `--observe`, let it log would-deny events alongside the
   existing root-agent setup for a few days, read `/summary` before touching anything.
3. **Only after `/summary` looks sane, and only after the non-root migration (design doc §1) is actually done**
   does `--observe` come off.

The items below are what to check **during** that observe window, each with the specific trap this design
flagged as not provable from a cloud session.

## Item 1 — `KEEPER_ACTOR` actually suppresses the card, and does not double-fire

**Why this is first and not optional:** [docs/deploy-keeper-server.md](deploy-keeper-server.md)#3 states plainly
that the `--settings`-layered hook for the unattended morning unit is assumed from documentation, not run against
a real headless `claude -p` from this session. If it double-fires (the managed hook *and* the profile's hook
both run for the same call), the morning job gets exactly the Telegram flood §2 of the design doc exists to
prevent — the opposite of what this mechanism is for.

- Trigger the morning unit manually once, in observe mode, with Telegram reachable: `sudo systemctl start
  example-morning.service` (or your real unit name).
- Check `keeper-summary 1` (as root, on the host — **never inside an agent session**, see `keeper/README.md`):
  does the log show exactly **one** `standing-used` or `standing-propose-suppressed` event for this run, or two
  separate hook decisions for the same command?
- Check your own phone: in observe mode nothing blocks, but a proposal from an actor **not** in
  `unattended_actors` still sends a card even in observe (the card-suppression logic is actor-based, not
  mode-based) — so if a card showed up for this run, `KEEPER_ACTOR` did not reach the hook the way §3 assumes.
- **Pass:** one log line, actor `standing-morning`, no card. **Fail → do not rely on `unattended_actors` for this
  unit**: either the card still arrived (the env var never reached `keeper_client.py`) or two decisions were
  logged for one call (duplicate hook registration) — both mean §3's mechanism needs rework before 08:15 unattended runs can be trusted, file it as a real gap, not a one-off glitch.

## Item 2 — `agent_uids` still lists both users after the last reinstall

`install-keeper.sh` unions the uids it resolves from `--agent-user` into any `agent_uids` already in
`/etc/keeper/config.json` (fixed 21/10/2026, see `CHANGELOG.md` and
[docs/deploy-keeper-server.md](deploy-keeper-server.md)#2.2) — a reinstall that only re-specifies `keeper-agent`
no longer drops `keeper-update`. Confirm it held on this real host, not just in the installer's own tests, before
every switch to block mode:

```sh
python3 -m json.tool /etc/keeper/config.json | grep -A3 agent_uids
```

**Pass:** two entries. **Fail:** something on this host still only has one `--agent-user`, or
`--replace-agent-uids` was passed without meaning to — rerun §2.1's command with both `--agent-user` flags
(without `--replace-agent-uids`), restart `keeper`, recheck. `keeper/check-keeper-server.sh` also checks this,
but check it yourself right before flipping to block mode — a check run an hour before a reinstall is stale the
moment the reinstall happens.

## Item 3 — standing plans launch only scripts the agent cannot modify

The design doc's whole point for standing plans is a closed, root-owned allowlist the agent cannot widen. That
guarantee is only as good as what the listed commands actually run:

- For every `commands` entry in `standing_plans`, confirm the script it invokes (`/opt/homelab/morning-act.py` in
  the example) is **not** writable by `keeper-agent`: `ls -la $(dirname /opt/homelab/morning-act.py)` and the
  file itself — both should be root-owned, not group/other-writable. If `keeper-agent` can edit the script a
  standing plan runs unattended, the literal-command match is worthless: the command string stays the same while
  its behavior changes underneath it.
- Same check for anything that script itself calls by relative path or via `$PATH` — a standing plan that runs
  `python3 /opt/homelab/morning-act.py` but lets that script shell out to something the agent can edit has the
  same hole one level down.
- **Pass:** every script a standing plan can run, and everything it calls, is root-owned and not writable by
  `keeper-agent`, recursively. **Fail:** fix ownership/permissions before trusting the standing plan at all — a
  config-level allowlist around a writable script is not a guardrail.

## Item 4 — `docker top`/`docker stats` are not masked, and that's deliberate, not a bug to "fix" here

`docker-proxy/README.md`'s own "Known limits" says only `inspect` and `logs` are masked; `ps`, `stats`, and `top`
output passes through verbatim. Before relying on the proxy to keep secrets away from the agent:

- Run `docker-proxy top <container>` and `docker-proxy stats <container>` (read-only, safe to run any time) on a
  real container from your setup and actually read the output — a process command line with a `--password=...`
  flag or a container/image name that looks secret-shaped will show up unmasked.
- **Pass (meaning "understood, not fixed"):** confirm none of your real containers' process lists or stats carry
  anything secret-shaped today. If one does, that container's own startup needs to stop passing secrets on its
  command line (the proxy is the wrong layer to fix this at) — do not treat "the proxy will mask it eventually"
  as the plan.
- This item has no fail state that blocks the rollout; it is a "look once, know the limit" check, not a gate.

## Item 5 — `inspect`'s fixed format is verified on *your* Docker version, not assumed from 29.9.1

`docker_proxyd.py`'s `INSPECT_FORMAT` was built and fixed against a real failure on **Docker Engine 29.9.1
specifically** (a container with no healthcheck configured broke plain dot-notation Go templates; `index()` was
the fix). `keeper/check-keeper-server.sh` runs `docker-proxy inspect` against one container *without* a
healthcheck and one *with* one and prints the real JSON both times — read it, don't just check the exit code:

- **Pass:** both calls return the eight documented fields (`Name`, `Id`, `State`, `Image`, `RestartPolicy`,
  `Health`, `Networks`, `Mounts`) as valid JSON, including the no-healthcheck container (where `Health` should be
  present but empty/null, not a hard failure).
- **Fail:** `docker-proxy inspect` errors out, or `Health` crashes the template instead of coming back empty, on
  a container with no healthcheck. If your `docker --version` isn't 29.9.1, treat this as genuinely unverified
  until you've seen it pass on your own version — don't assume 29.9.1's fix carries over without checking.

## Item 6 — an out-of-plan command is actually refused

Whatever host-level verbs you ended up writing into `/etc/sudoers.d/keeper-agent` (deploy guide §5), confirm the
negative case, not just the positive one:

- As `keeper-agent`: `sudo systemctl restart some-unit-not-in-the-sudoers-file.service` → must be refused
  ("not allowed").
- As `keeper-agent`: `docker-proxy exec <container> sh` (or `create`, `run`) → must be refused by the proxy
  (`docker-proxy: refused: ...`), never silently falling through to a real `docker exec`.
- **Pass:** both refused, with a message, non-zero exit. **Fail:** anything outside the documented allowlist
  actually runs — stop and treat this as a configuration bug before going further, not a minor finding.

## Item 7 — `docker-proxy` on the agent's `PATH` resolves to our kit, not Docker's own same-named helper

Found while writing `keeper/check-keeper-server.sh`, not a guess: Docker Engine ships its own unrelated binary
also called `docker-proxy` (its userland port-forwarding helper). This repo's own wrapper has the exact same
basename, installed at `/opt/agent-guardrails/bin/docker-proxy`.

- As `keeper-agent`: `command -v docker-proxy` (or `type docker-proxy`).
- **Pass:** resolves to `/opt/agent-guardrails/bin/docker-proxy`. **Fail:** resolves to anything else (commonly
  `/usr/bin/docker-proxy` or `/usr/libexec/docker/docker-proxy`) — fix `keeper-agent`'s `PATH` so
  `/opt/agent-guardrails/bin` comes first, or always invoke it by full path in any script/prompt you give the
  agent, before relying on the proxy for anything.

## Not part of this manual pass

Everything `keeper/test_keeper.py`, `keeper/test_block_dryrun.py`, and `docker-proxy/test_docker_proxy.py` already
cover automatically in CI (forged/replayed approvals, the standing-plan exact-match guard, `read_allow`/
`write_allow` gating, secret masking against fixtures) needs no manual repeat here. This checklist is only for
the parts that specifically need the real host: the headless hook wiring, the two-user config gap, the scripts a
standing plan trusts, and a real Docker daemon's real output.

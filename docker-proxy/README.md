# docker-proxy: filtered Docker access for a non-root agent

Design and threat model: [docs/design-keeper-server.md](../docs/design-keeper-server.md), section 1 ("A non-root
user for the agents"), option C.

**The problem.** Membership in the `docker` group is root-equivalent: `docker run --privileged -v /:/host alpine
chroot /host` is one command away from a host root shell. Putting a non-root agent in `docker` to let it manage
containers is not a non-root migration, it is root with extra steps. go-gate/keeper's own classifier would
correctly flag that command as a change, but by the time it runs the "agent must not be root" precondition is
already false.

**What this kit does instead.** A small daemon, `docker_proxyd.py`, is the only process that is a member of the
real `docker` group. It runs as its own dedicated account (`dockerproxy`, created by the installer) and exposes a
Unix socket of its own, readable/writable only by a narrow client group. The agent never touches
`/var/run/docker.sock` and is never added to `docker`; it talks to `docker_proxyd.py`'s socket through a thin
client, `docker-proxy`, which enforces nothing itself -- the daemon decides, in a process the agent cannot write
to, which is what makes this a structural control rather than a check an agent (or an injected instruction) could
argue around.

## Policy -- a whitelist, never a blacklist

Anything not explicitly matched below is refused.

| Subcommand | Access | Gate |
|---|---|---|
| `ps` | always allowed | -- (lists every container; no target to gate) |
| `logs`, `inspect`, `stats`, `top` | allowed by default, narrowed if `read_allow.containers` is set | target name must match Docker's own naming rules, **and** be listed verbatim in `read_allow.containers` if that section is present at all |
| `restart`, `start`, `stop` | allowed only for a listed container | target name must match Docker's naming rules **and** be listed verbatim in `write_allow.containers` |
| anything else (`exec`, `run`, `create`, `rm`, `compose`, raw `docker` CLI...) | always refused | -- |

- **No flags are forwarded from the agent.** `ps --all` is a fixed boolean (`-a` or nothing); `logs --tail N` takes
  only a bounded integer; `restart`/`stop --timeout N` likewise. `inspect` takes **no options at all** from the
  agent -- its `--format` is always the daemon's own fixed allowlist (see below); a request that includes a
  `format` key is refused, not silently ignored. There is no way to pass an arbitrary string as a docker CLI flag.
  If you need a different read option later, add it deliberately in `decide()` and review it like any other
  change to this allowlist -- the allowlist itself is the attack surface now, same as go-gate's classifier, and
  must be kept just as narrow.
- **The container allowlists accept only literal names.** `install-docker-proxy.sh` and `load_config()` both
  refuse to start if a configured name (`write_allow.containers` or `read_allow.containers`) contains anything
  outside Docker's own charset (letters, digits, `_`, `.`, `-`) -- no `*`, no `?`, no regex. A target name is
  validated the same way at request time, before anything else runs, which is what stops both shell-metacharacter
  injection and flag injection (a target of `-v` or `--privileged` is refused outright, never reaches `docker`'s
  own argv).
- **Reads are unrestricted by default, narrowed only if you ask.** `read_allow.containers` (same shape as
  `write_allow.containers`) is opt-in: with no `read_allow` key in the config at all, `logs`/`inspect`/`stats`/`top`
  work for any syntactically valid container name, listed or not -- "lecture complète" in the design doc means
  exactly that. Add a `read_allow` section to narrow reads to an exact list; an empty one (`"read_allow": {}`)
  restricts reads to nothing, the same fail-closed posture `write_allow` already has for writes. `ps` is never
  gated by it -- it lists every container, it does not target one.
- **`inspect` never returns the full `docker inspect` JSON.** Before this fix it did, and `docker inspect` includes
  the container's entire environment (`Config.Env`) verbatim -- API keys, database passwords, tokens, whatever the
  container was started with. The daemon now always runs `inspect` with its own fixed `--format`, never one the
  agent supplies, that asks docker for exactly eight fields -- `Name`, `Id`, `State`, `Image` (`Config.Image`),
  `RestartPolicy` (`HostConfig.RestartPolicy`), `Health` (`State.Health`), `Networks`
  (`NetworkSettings.Networks`) and `Mounts` -- and nothing else; `Config.Env`, `Config.Cmd` and `Config.Entrypoint`
  are never requested from docker in the first place. `docker-proxy inspect <name>` now prints a compact JSON
  object with exactly those eight keys, not docker's own multi-page inspect output.
- **`inspect` and `logs` output is masked before it leaves the daemon.** Both go through the same pattern-based
  secret redaction as [secret-guard's `mask`](../secret-guard/README.md) (keys, tokens, passwords, JWTs, URL
  credentials, PEM private keys...) -- a second, independent layer on top of the field whitelist above, catching
  a secret printed by the container itself (a log line, a health-check script's own output) rather than one
  docker's own metadata carried. It runs server-side, inside `docker_proxyd.py` (a port of `secret-guard/mask`'s
  regexes, not a call out to the Perl script -- see the module's own docstring for why), so the agent cannot get
  an unmasked copy by skipping its own local `mask`. Like `secret-guard`'s own filter, this is best-effort and
  pattern-based, not a security boundary against an adversary who controls what the container prints -- see
  [secret-guard's "Scope and limits"](../secret-guard/README.md#why).

## Why the daemon shells out to the `docker` CLI, not the raw socket

Documented choice (the design left this open): `docker_proxyd.py` calls `docker <subcommand> ...` via
`subprocess.run` with a fixed argv list, never a shell string. This needs zero non-stdlib dependencies (no Docker
SDK, no HTTP client), reuses the CLI's own already-reviewed argument handling, and keeps every possible
invocation visible in one function (`build_argv`/`decide` in `docker_proxyd.py`) instead of spread across raw API
calls. The daemon's own socket to the agent is the actual security boundary; how the daemon itself reaches Docker
underneath is an implementation detail that can change later without affecting the agent-facing contract.

## Install

```sh
./install-docker-proxy.sh --agent-user you --container web-app --container worker-1       # dry run (default)
./install-docker-proxy.sh --agent-user you --container web-app --prefix /tmp/dp            # files only, to inspect
sudo ./install-docker-proxy.sh --agent-user you --container web-app --apply                # real install (Linux/systemd)
```

`--container NAME` is repeatable and becomes the write allowlist. `--group` (default `docker-proxy-clients`) names
the narrow group the agent and the daemon share; it is not, and must never become, the `docker` group itself.

`--apply`:
- creates the `dockerproxy` system account and adds **only** it to `docker`;
- creates `--group` and adds both `dockerproxy` and the agent user to it;
- installs the daemon and client read-only under `/opt/agent-guardrails`, the config under
  `/etc/docker-proxy/config.json` (root:dockerproxy, 640), and a systemd unit running the daemon as `dockerproxy`.

If the agent user is already in `docker`, the installer warns loudly but does not remove that membership itself --
that is a separate, manual decision (see "Known limits" below).

`read_allow.containers` is not an installer flag (no `--read-container`): the installer only ever writes
`write_allow`, same as before this PR. To narrow reads, edit the installed `/etc/docker-proxy/config.json` by hand
(root:dockerproxy, 640) and add a `read_allow` section in the same shape as `write_allow`, then
`systemctl restart docker-proxy` (see "No config hot-reload" below). Left for a follow-up if there turns out to be
real demand for it at install time -- this PR adds the daemon-side gate because that is what closes the secret
exposure, not because every install needs to turn it on immediately.

Linux/systemd only. This kit's threat model (docs/design-keeper-server.md) is the server/LXC case, not a laptop
running Docker Desktop, so no macOS install path is provided.

## Using it

Once installed and after the agent's group membership takes effect (`newgrp docker-proxy-clients` or a fresh
login):

```sh
docker-proxy ps [-a]
docker-proxy logs <name> [--tail N]
docker-proxy inspect <name>
docker-proxy stats <name>
docker-proxy top <name>
docker-proxy restart <name> [--timeout N]
docker-proxy start <name>
docker-proxy stop <name> [--timeout N]
```

A refused call prints `docker-proxy: refused: <reason>` on stderr and exits 2; an allowed call's exit code is
`docker`'s own, except `inspect`, whose exit code and stdout are the daemon's filtered-and-masked response, not
docker's raw multi-page JSON -- see "Policy" above for exactly which eight fields it carries.

## Known limits (out of scope for this PR)

- **Removing the agent from the `docker` group, if it is already a member, is not automated here.** That is an
  existing production account's membership on a real host; changing it needs the owner's own confirmation that
  nothing else still depends on it, which this repo cannot know. Until it is removed, this proxy adds a safer path
  but does not by itself revoke the pre-existing root-equivalent access.
- **No sudoers lines for `pct`/`systemctl` are included.** The design doc's option B (a few named, non-wildcard
  sudoers lines for host-level verbs the agents actually need) is a separate concern from Docker filtering and
  needs the owner's real service/unit names, which this session has no way to know or test against. Left for a
  follow-up PR, same reasoning as the design doc's own "what this PR does not do."
- **No config hot-reload.** Changing `write_allow.containers` or `read_allow.containers` requires restarting
  `docker-proxy.service` (`systemctl restart docker-proxy`) -- a deliberate root-only action, the same trust
  boundary keeper's own `standing_plans` puts around `/etc/keeper/config.json`.
- **`ps`, `stats` and `top` are not masked.** Only `inspect` and `logs` are, per this PR's own scope -- a process
  command line containing a secret (`top`) or a container name/image tag that happens to look secret-shaped (`ps`)
  would still pass through verbatim. Lower risk (neither routinely carries real secrets the way `Config.Env` and
  log output do) but not zero; left for a follow-up if it turns out to matter in practice.
- **Masking is pattern-based and best-effort, not a security boundary.** Same limit as `secret-guard`'s own
  `mask` (whose regexes this reuses): a secret in a shape the patterns don't recognise is not caught. It raises
  the cost of an accidental leak, it does not make this a guarantee against a container that deliberately tries to
  exfiltrate something through its own logs or health-check output.

## Tests

```sh
python3 -m unittest docker-proxy/test_docker_proxy.py -v
```

No real Docker and no network: every `docker` invocation goes through a fake `run` recorder instead of
`subprocess.run`. The end-to-end test opens a real Unix domain socket on a local tmp path (not network access) to
exercise the actual daemon/client framing. Covers: reads allowed by default and writes gated by the allowlist,
wildcard or regex in either `write_allow` or `read_allow` refused at load, `read_allow` narrowing
logs/inspect/stats/top (and never gating `ps`) once configured, an unknown subcommand refused,
shell-metacharacter and flag-injection attempts in a target name refused even when that exact string is
(deliberately, in the test) present in the allowlist, `inspect`'s `--format` always being the daemon's own fixed
allowlist and never one the agent supplies, a fake secret in a container's logs or an `inspect`-allowed field
(`Health`'s own output) never reaching the response, and mutation checks that disabling `is_whitelisted()`,
`mask_text()` or `build_inspect_result()`'s field filtering each flip a refusal/redaction to an allow/leak --
proving the guards are load-bearing, not dead code. `mask_text()` -- a port of secret-guard/mask's own regexes,
not a subprocess call to the Perl script (see `docker_proxyd.py`'s docstring for why) -- is additionally checked
against the real `secret-guard/mask` on a shared set of fixtures, skipped automatically if `perl` or that script
isn't available.

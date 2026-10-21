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
| `ps`, `logs`, `inspect`, `stats`, `top` | always allowed | target name must match Docker's own naming rules; no other check |
| `restart`, `start`, `stop` | allowed only for a listed container | target name must match Docker's naming rules **and** be listed verbatim in `write_allow.containers` |
| anything else (`exec`, `run`, `create`, `rm`, `compose`, raw `docker` CLI...) | always refused | -- |

- **No flags are forwarded from the agent.** `ps --all` is a fixed boolean (`-a` or nothing); `logs --tail N` takes
  only a bounded integer; `restart`/`stop --timeout N` likewise. There is no way to pass an arbitrary string as a
  docker CLI flag. If you need a different read option later, add it deliberately in `decide()` and review it like
  any other change to this allowlist -- the allowlist itself is the attack surface now, same as go-gate's
  classifier, and must be kept just as narrow.
- **The container allowlist accepts only literal names.** `install-docker-proxy.sh` and `load_config()` both
  refuse to start if a configured name contains anything outside Docker's own charset (letters, digits, `_`, `.`,
  `-`) -- no `*`, no `?`, no regex. A target name is validated the same way at request time, before anything else
  runs, which is what stops both shell-metacharacter injection and flag injection (a target of `-v` or
  `--privileged` is refused outright, never reaches `docker`'s own argv).
- **Reads never consult the write allowlist.** `docker-proxy logs <anything>` works for any syntactically valid
  container name, listed or not -- "lecture complète" in the design doc means exactly that.

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
`docker`'s own.

## Known limits (out of scope for this PR)

- **Removing the agent from the `docker` group, if it is already a member, is not automated here.** That is an
  existing production account's membership on a real host; changing it needs the owner's own confirmation that
  nothing else still depends on it, which this repo cannot know. Until it is removed, this proxy adds a safer path
  but does not by itself revoke the pre-existing root-equivalent access.
- **No sudoers lines for `pct`/`systemctl` are included.** The design doc's option B (a few named, non-wildcard
  sudoers lines for host-level verbs the agents actually need) is a separate concern from Docker filtering and
  needs the owner's real service/unit names, which this session has no way to know or test against. Left for a
  follow-up PR, same reasoning as the design doc's own "what this PR does not do."
- **No config hot-reload.** Changing `write_allow.containers` requires restarting `docker-proxy.service`
  (`systemctl restart docker-proxy`) -- a deliberate root-only action, the same trust boundary keeper's own
  `standing_plans` puts around `/etc/keeper/config.json`.

## Tests

```sh
python3 -m unittest docker-proxy/test_docker_proxy.py -v
```

No real Docker and no network: every `docker` invocation goes through a fake `run` recorder instead of
`subprocess.run`. The end-to-end test opens a real Unix domain socket on a local tmp path (not network access) to
exercise the actual daemon/client framing. Covers: reads always allowed, writes gated by the allowlist, wildcard
or regex in the config refused at load, an unknown subcommand refused, shell-metacharacter and flag-injection
attempts in a target name refused even when that exact string is (deliberately, in the test) present in the
allowlist, and a mutation check that disabling `is_whitelisted()` flips a refusal to an allow -- proving the guard
is load-bearing, not dead code.

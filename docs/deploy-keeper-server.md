# Deploying the keeper on a server (LXC Debian, systemd): step-by-step

This is the "do it for real" companion to [docs/design-keeper-server.md](design-keeper-server.md). It does not
redecide anything that design already settled (user topology, one daemon per host, standing plans, the Docker
proxy, the `KEEPER_ACTOR` mechanism) — it only turns those decisions into commands. Read the design doc first if
any step below looks unmotivated; the "why" lives there, not here.

**Audience:** the owner, on the real host, with root. Nothing in this guide runs itself — every command below is
meant to be typed by a human, one step at a time, checking the expected result before moving to the next one.

**Example names used throughout:** `lxc-agents` (the privileged LXC container the design doc discusses),
`app-example`/`app-example-2` (two ordinary Docker containers), `example.service` (a systemd unit a sudoers line
targets), `101` (a Proxmox container id for `pct`). Replace every one of these with your own names — **none of
them should ever be the literal hostnames, pool names or container names of your real setup**, in this file or in
anything you commit back to this repository.

**Who does what, in order:**

1. Two non-root Unix users (§1 below).
2. `keeperd`, its hook, and the config — including the two-user caveat the installer doesn't handle by itself
   (§2).
3. The `KEEPER_ACTOR` wiring for the unattended (morning) systemd unit — the one piece of this whole design that
   is **assumed, not verified**, from this session (§3).
4. The Docker proxy (§4).
5. The sudoers allowlist for `pct`/`systemctl` (§5).
6. Verify with [`keeper/check-keeper-server.sh`](../keeper/check-keeper-server.sh), then move to the owner trial
   checklist in [docs/keeper-server-dry-run.md](keeper-server-dry-run.md).

Every step says: the exact command, what you should see, and how to undo it. If a step's result doesn't match,
stop and roll that step back before continuing — don't push forward hoping a later step fixes it.

---

## 1. Two non-root Unix users

Decided in the design doc (§1, owner's PR #18 comment): **two** users, not one shared user for all three agents
and not three separate ones.

- `keeper-update` — its own, separate user, for the systemd timer that updates the Claude Code binary itself.
  Separate because a compromised update could plant anything in what every other agent later runs.
- `keeper-agent` — shared by the interactive assistant and the morning (standing-plan) systemd job. Telling them
  apart is `KEEPER_ACTOR` (§3), not a Unix user boundary.

```sh
sudo useradd --system --create-home --shell /bin/bash keeper-agent
sudo useradd --system --create-home --shell /bin/bash keeper-update
```

**Expected result:** `id keeper-agent` and `id keeper-update` both resolve, neither is in any group named
`docker`, `sudo`, `wheel`, or `root`. `groups keeper-agent` should print only `keeper-agent` at this point (the
installers in §2 and §4 add the groups that matter).

**Rollback:** `sudo userdel -r keeper-agent` / `keeper-update` — safe at this point, nothing references them yet.

**Known trap:** do **not** add either user to the `docker` group "to make things easier" — see the design doc's
§1: that group is root-equivalent, and doing so defeats every later step in this guide. If either user is
already in `docker` from before this migration, removing that membership is an existing-production-account
decision this guide does not make for you (same reasoning as `docker-proxy/README.md`'s "Known limits") — decide
it deliberately, confirm nothing else on the host still depends on it, and only then `sudo gpasswd -d
keeper-agent docker`.

---

## 2. `keeperd`, the hook, and the config

### 2.1 Install for the shared user first

```sh
sudo /path/to/agent-ops-guardrails/keeper/install-keeper.sh \
  --agent-user keeper-agent --owner-id <your Telegram numeric id> --apply
```

(Add `--observe` here if you want to start logging before anything is ever blocked — recommended, and §6/the dry
run checklist assumes you did.)

**Expected result:** the script's own `-- 1` through `-- 6` sections each print what they did (`id keeper 2>&1`
now resolves, `getent group keeperclients` lists `keeper-agent` and `keeper`); `/etc/keeper/config.json` exists,
mode 640, owner `root:keeper`, and its `agent_uids` key is a one-element list containing `keeper-agent`'s uid
(`id -u keeper-agent`); `systemctl status keeper` is `active (running)`.

**Rollback:** this step alone, cleanly: `sudo systemctl disable --now keeper`, `sudo rm -rf /opt/agent-guardrails
/etc/keeper /var/lib/keeper`, restore `/etc/claude-code/managed-settings.json` from
`managed-settings.json.bak-keeper` if one was written, `sudo userdel -r keeper` (the `keeper` service account the
installer created, not `keeper-agent`).

### 2.2 Add the second agent user by hand — the installer does not do this

**This is the one gap `install-keeper.sh` has for a two-user topology, stated plainly so it isn't missed:** the
installer always writes `agent_uids` as a **single-element list containing whichever `--agent-user` you passed
it**, every time it runs (see `install-keeper.sh`'s own config-merge script: `agent_uids` is one of the keys a
run always refreshes, never one it leaves alone). Design doc §5 is correct that the config format already
supports a list — but nothing in the installer ever puts a second uid into it. You do that by hand:

```sh
sudo usermod -aG keeperclients keeper-update
sudo python3 -c '
import json
p = "/etc/keeper/config.json"
cfg = json.load(open(p))
update_uid = int(__import__("subprocess").check_output(["id", "-u", "keeper-update"]).strip())
if update_uid not in cfg["agent_uids"]:
    cfg["agent_uids"].append(update_uid)
json.dump(cfg, open(p, "w"), indent=1)
'
sudo systemctl restart keeper
```

**Expected result:** `python3 -m json.tool /etc/keeper/config.json` shows `agent_uids` with **two** entries;
`getent group keeperclients` now lists `keeper-agent`, `keeper-update`, and `keeper`; `systemctl status keeper`
is `active (running)` again after the restart (it must reload the config to pick up the new uid — `keeperd`
reads its config at start-up only, same as the mode file).

**Known trap, every time you reinstall:** running `install-keeper.sh --apply` again (for any reason — a new
`--hook-timeout`, a new `--lang`, picking up a newer `keeperd.py`) **silently reverts `agent_uids` back to one
entry**, because that key is one the installer always drives. Redo the snippet above after *every* reinstall,
and check it (`python3 -m json.tool /etc/keeper/config.json | grep -A2 agent_uids`) before assuming the update
timer is still covered. `keeper/check-keeper-server.sh` (§6) checks this for you so it isn't a silent regression.

### 2.3 Standing plans and the unattended actor, by hand

Neither `standing_plans` nor `unattended_actors` is a reinstall-driven key (the installer never writes either),
so this edit survives reinstalls on its own — unlike §2.2's `agent_uids`.

```sh
sudo python3 -c '
import json
p = "/etc/keeper/config.json"
cfg = json.load(open(p))
cfg["standing_plans"] = [
    {
        "id": "morning-example",
        "commands": [
            "python3 /opt/homelab/morning-act.py restart-arr",
            "python3 /opt/homelab/morning-act.py retry-search",
            "python3 /opt/homelab/morning-act.py tick-note",
        ],
        "expires_at": "2026-12-05",
        "note": "08:15 systemd timer, example only -- replace with your own literal commands",
    }
]
cfg["unattended_actors"] = ["standing-morning"]
json.dump(cfg, open(p, "w"), indent=1)
'
sudo systemctl restart keeper
```

**Expected result:** `keeper-status` (run as `keeper-agent`) lists `morning-example` with its days-left; `/status`
on the keeper bot lists it too. `python3 -m json.tool /etc/keeper/config.json` is still valid JSON (a syntax
slip here is caught immediately by `keeperd` refusing to start — check `journalctl -u keeper -n 20` if the
restart doesn't come back `active`).

**Known trap:** the `commands` list is matched **character-for-character**, whitespace-stripped, no prefix, no
pattern (design doc §2). If the real `morning-act.py` invocation in your crontab/systemd unit uses a different
absolute path, a different Python (`python3.11` vs `python3`), or an extra flag, it will not match and every
3-command morning run falls through to `keeper-propose`, silently recorded but never sent to you (§2.3's whole
point) — copy the **exact** command line from the unit file in §3 below, don't retype it from memory.

**Rollback:** edit the two keys back to `[]`/`[]`, restart `keeper`. The standing grant is also revocable live,
with no restart, via `/stop morning-example` on the keeper bot (§2's own "revocable" design) — faster than an
edit when you need to pull it instantly.

---

## 3. `KEEPER_ACTOR` for the unattended systemd unit

**Read this section's last paragraph before relying on any of it.** This is the part of the design that is
assumed from the Claude Code hooks documentation, not run against a real `claude -p` headless invocation from
this session (design doc §2/§4) — it is also item 1 of the owner-trial checklist in
[docs/keeper-server-dry-run.md](keeper-server-dry-run.md), on purpose: verify this before trusting it to suppress
cards at 08:15, not after.

### 3.1 A distinct settings file for the unattended unit

```sh
sudo install -d -m 755 /etc/claude-code/profiles
sudo tee /etc/claude-code/profiles/standing-morning.json >/dev/null <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/env -i KEEPER_ACTOR=standing-morning /usr/bin/python3 -I /opt/agent-guardrails/lib/keeper_client.py",
            "timeout": 60,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
EOF
sudo chmod 644 /etc/claude-code/profiles/standing-morning.json
```

The `timeout`/`onFailure` values must match whatever `/etc/claude-code/managed-settings.json` already carries for
the keeper hook (§2.1 wrote `60`/`"block"` by default) — if you installed with a different `--hook-timeout`, use
that same number here.

### 3.2 Point the morning systemd unit at it

```sh
sudo tee /etc/systemd/system/example-morning.service >/dev/null <<'EOF'
[Unit]
Description=example morning job (standing-plan actor), replace with your real unit

[Service]
Type=oneshot
User=keeper-agent
Environment=CLAUDE_CONFIG_DIR=/home/keeper-agent/.claude
ExecStart=/usr/bin/claude -p --settings /etc/claude-code/profiles/standing-morning.json "run morning-act.py as planned"
EOF
sudo systemctl daemon-reload
```

(A real unit will also need the timer half — `example-morning.timer` — and your actual prompt/script; this is
the minimum that exercises the `KEEPER_ACTOR` plumbing, not a complete morning-job unit.)

**Expected result (only partially checkable without a real run — see below):** `systemd-analyze verify
example-morning.service` reports no errors; `systemctl cat example-morning.service` shows the `--settings` flag
intact.

**Rollback:** `sudo rm /etc/systemd/system/example-morning.service /etc/claude-code/profiles/standing-morning.json
&& sudo systemctl daemon-reload`.

**What is actually unverified here, stated precisely:** whether a `claude -p` run with `--settings
.../standing-morning.json` layered on top of the managed settings results in **one** PreToolUse hook invocation
(the one that carries `KEEPER_ACTOR`) or **two** (the managed one without the actor tag, running alongside the
profile's one with it) for the same tool call. The two outcomes behave very differently: one carries the
suppression this whole mechanism exists for; the other means the 08:15 job still pushes a Telegram card every
morning, exactly what §2 was built to avoid, because an un-actored hook invocation proposes and sends normally.
Do not flip `unattended_actors` on in a way that matters until you have run the verification in
[docs/keeper-server-dry-run.md](keeper-server-dry-run.md) item 1 and confirmed, from a real log line, which of
the two happens.

---

## 4. Docker proxy

Only `keeper-agent` needs this — the update timer does not touch Docker.

```sh
sudo /path/to/agent-ops-guardrails/docker-proxy/install-docker-proxy.sh \
  --agent-user keeper-agent --container app-example --container app-example-2 --apply
```

**Expected result:** `id dockerproxy` resolves and is in `docker`; `keeper-agent` is in `docker-proxy-clients`
but **not** in `docker` (`id -nG keeper-agent | tr ' ' '\n' | grep -vx docker-proxy-clients` should not print
`docker`); `systemctl status docker-proxy` is `active (running)`; `/etc/docker-proxy/config.json` (640,
`root:dockerproxy`) lists exactly the containers you passed.

**Rollback:** `sudo systemctl disable --now docker-proxy`, `sudo rm -rf /opt/agent-guardrails/lib/docker_proxyd.py
/opt/agent-guardrails/lib/docker_proxy_client.py /opt/agent-guardrails/bin/docker-proxy /etc/docker-proxy
/etc/systemd/system/docker-proxy.service`, `sudo gpasswd -d keeper-agent docker-proxy-clients`, `sudo userdel
dockerproxy`.

**Known trap, verified elsewhere in this repo and worth restating here:** `docker-proxy/README.md`'s own
`inspect`/`logs` field-filtering and masking were measured against **Docker Engine 29.9.1 specifically**
(`docker_proxyd.py`'s own comment on `INSPECT_FORMAT`) — the `index()`-based Go template it builds is the fix for
a real failure the authors hit on that version when a container had no healthcheck configured. `docker --version`
on `lxc-agents` first; if it isn't 29.9.1, treat the inspect output as unverified on your version until
`keeper/check-keeper-server.sh` (§6) has actually run `docker-proxy inspect` against one container with a
healthcheck and one without, and you've read the JSON it printed rather than assumed it matches.

**Known trap, found by actually running `keeper/check-keeper-server.sh` on a real Docker host, not assumed:**
Docker Engine itself ships its own, unrelated binary also named `docker-proxy` (its userland port-forwarding
helper — on this repo's own CI/test hosts it sits at `/usr/bin/docker-proxy`). That is an exact basename
collision with this kit's own agent-facing wrapper, installed at `/opt/agent-guardrails/bin/docker-proxy`. If the
agent's `PATH` lists a directory containing Docker's helper before `/opt/agent-guardrails/bin`, typing
`docker-proxy ...` silently runs the wrong binary — not a security bypass of the proxy daemon itself (Docker's
helper takes entirely different arguments and does something unrelated), but a confusing, hard-to-diagnose
failure the first time it happens. After `--apply`, check `type docker-proxy` (or `command -v docker-proxy`) as
`keeper-agent` and confirm it resolves to `/opt/agent-guardrails/bin/docker-proxy`; `keeper/check-keeper-server.sh`
checks this too and warns if it does not.

**`read_allow` is not an installer flag.** If you want to narrow `logs`/`inspect`/`stats`/`top` to specific
containers (instead of the installer's default of "any syntactically valid name, listed or not"), edit
`/etc/docker-proxy/config.json` by hand and add a `read_allow` section shaped like `write_allow`, then
`sudo systemctl restart docker-proxy` — no hot-reload, same as `docker-proxy/README.md` already states.

---

## 5. sudoers allowlist for `pct`/`systemctl`

Design doc §1, option B: **named commands with fixed arguments, never a wildcard.** The exact verbs your setup
actually needs are operational knowledge this repo cannot supply (which container ids, which service units) —
what follows is the shape, with placeholders you replace.

```sh
sudo visudo -f /etc/sudoers.d/keeper-agent
```

Contents (adjust the placeholders, keep the shape — one fixed command per line, no `*`):

```
# keeper-agent: narrow, reviewed host-level verbs (design doc §1, option B). Never a wildcard line.
keeper-agent ALL=(root) NOPASSWD: /usr/bin/systemctl restart example.service
keeper-agent ALL=(root) NOPASSWD: /usr/bin/systemctl status example.service
keeper-agent ALL=(root) NOPASSWD: /usr/sbin/pct status 101
keeper-agent ALL=(root) NOPASSWD: /usr/sbin/pct reboot 101
```

**Expected result:** `sudo visudo -c` reports no syntax errors (the `-f` form above already validates before
writing); `sudo -l -U keeper-agent` lists exactly these lines, nothing wider; as `keeper-agent`, `sudo systemctl
restart example.service` works without a password prompt, `sudo systemctl restart some-other.service` is refused
with "not allowed", and `sudo systemctl restart 'example.*'` (an attempted shell-glob) does not expand to
anything sudoers would match — sudoers lines are compared to the literal argv it receives, so a shell glob that
doesn't match a real unit name on this host just fails normally before sudo ever sees it.

**Rollback:** `sudo rm /etc/sudoers.d/keeper-agent`.

**Known trap:** every new verb here is a manual, reviewed, auditable root edit **by design** (design doc §1's
"long but bounded" friction) — resist the temptation to write `systemctl restart *.service` "just for this one
case." That line is as wide as `docker` group membership was in §1's "option A," for the same reason: once one
command is a pattern, it covers every unit on the host, including ones that matter far more than the one you had
in mind.

---

## 6. Verify, then the owner trial

Run [`keeper/check-keeper-server.sh`](../keeper/check-keeper-server.sh) after each of the sections above, not
just at the end — it degrades cleanly when something isn't installed yet, so running it early tells you whether
you're on track rather than finding out after step 5.

```sh
keeper/check-keeper-server.sh
keeper/check-keeper-server.sh --container app-example --container-with-healthcheck app-example-2
```

It never writes anything — see its own header and `keeper/test_check_keeper_server.sh` for how that's checked.

Only after every section above checks out, move to the staged rollout the design doc already specifies (§5) and
the checklist in [docs/keeper-server-dry-run.md](keeper-server-dry-run.md): a throwaway container first, then
`--observe` on the real host for a few days, then block mode — never block mode first.

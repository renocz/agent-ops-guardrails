# Design: covering the server (keeper v1.0, part 2), draft for review

Status: draft 2, 20/10/2026 — the three open questions of draft 1 were decided by the owner directly on PR #18
([comment](https://github.com/renocz/agent-ops-guardrails/pull/18#issuecomment-6299989493)) and are folded in below.
The keeper so far assumes the laptop: a non-root agent, file permissions that protect it, a human on Telegram. On
the server none of that holds. This note designs the gap, and states what is implemented in this PR.

## Why this is a separate design, not an extension of docs/design-keeper.md

`docs/design-keeper.md`'s own threat model states the precondition in plain words: **the agent must not be
root/admin where the keeper runs**, and the server is called out by name as out of scope "until its agent runs as a
normal user." That day has not come. On the server (one Debian host running Proxmox, and inside it a privileged LXC
container, called **LXC 100** below, with Docker and about 40 containers) three agents run **as root**, with no
file permission protecting anything from them and, for two of the three, no human reading a Telegram card at the
time they act:

1. an interactive assistant, `claude --channels plugin:telegram@... --remote-control ...` in a `screen` session, root;
2. systemd-timer jobs that run `claude -p` as root with nobody watching — e.g. a 08:15 job whose only tool is a
   whitelisted script (`morning-act.py`: restart one arr container, retry a title search, tick a line in a notepad);
3. a timer that updates the Claude Code binary itself.

The goal stated by the owner is explicit and narrower than "stop a determined attacker": **catch the agent's own
mistakes and prompt injections, not an adversary who already has root.** But one invariant must still hold even
under that narrower goal: **the agent must not be able to turn off its own guardrail.** That is the thread running
through every section below.

## Scope of this PR

Two things, in order, as asked:

1. This design document — six questions, each with alternatives, what each protects against, residual risk, and a
   recommendation.
2. The part of the design that is safe to implement **without** touching the real server: a generic keeper feature
   (standing plans, §2) with its own state, tests and mutation checks, usable on any host once the owner has done
   the parts that are theirs to do (§1, §5, §6). Nothing in this PR runs `useradd`, edits `/etc/sudoers`, touches
   Docker's socket, or installs anything on LXC 100. Doing that from this session would mean guessing at a
   production topology — docker socket paths, container names, systemd unit layout — with nothing in this repo to
   check it against and no way to test it here. The owner decisions this stops short of are listed in the final
   report, not guessed at in code.

---

## 1. A non-root user for the agents

**The real obstacle, stated precisely:** on LXC 100 the agents currently use Docker (`docker restart`, `docker
exec`, `docker compose`), `pct`-style container tooling if the LXC itself manages nested workloads, read logs, and
write into `/opt/stacks`. Membership in the **`docker` group is root-equivalent** — mounting `/` into a container
and `docker exec`-ing into it gets you a root shell on the host — so "add the agent user to `docker`" is not a
non-root migration at all, it is root with extra steps. Anything that proposes `docker` group membership as the fix
must be read as having decided to accept that the agent still has host root, just with a different name for it.

**Options**

- **A. Agent user in the `docker` group.** Simple, nothing else to build. Protects against: typos, accidental
  `rm -rf`, prompt injection that doesn't specifically target Docker. Protects against nothing once the agent (or
  an injected instruction) decides to use Docker deliberately: `docker run --privileged --pid=host -v /:/host
  alpine chroot /host` is one command away, and go-gate's classifier would correctly flag it as `change`/`script`
  — but the precondition in `docs/design-keeper.md` ("the agent must not be root") is already false by the time
  that command runs, keeper or not. **This option does not satisfy the keeper's own precondition and should not be
  called a non-root migration.**
- **B. A narrow sudo/proxy allowlist for the handful of host-level verbs actually needed** (service restarts via
  `systemctl`, `pct`/`qm` subcommands, journal reads), each sudoers line naming a fixed command with fixed
  arguments (`agent ALL=(root) NOPASSWD: /usr/bin/systemctl restart arr-sonarr.service`), never a wildcard sudoers
  line (`NOPASSWD: /usr/bin/systemctl *` is as wide as group membership). Protects against: the agent running
  anything outside that fixed list, including through an injected instruction — the allowlist is root-owned and not
  in the agent's write path. Residual risk: each line is still a standing grant outside the keeper's own approval
  flow, so it should be as short as the real operational need, and every new line is a manual, auditable, reviewed
  change (exactly the kind of thing `/etc/keeper/config.json`'s new `standing_plans`, §2, is built to make visible
  and bounded instead of invisible in `/etc/sudoers.d/`).
- **C. A filtered Docker API, not the raw socket.** A small proxy (the shape of
  [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) — this PR does not pull in or
  name a third-party image, it describes the shape) sits between the agent and `/var/run/docker.sock`, exposes only
  the read endpoints plus `POST .../restart|start|stop` for an explicit allowlist of container names, and refuses
  `create`, `exec`, anything with `Privileged`, `-v /:/...`, `--pid=host`, `NetworkMode: host`. The agent talks to
  the proxy's own socket, which it can reach without being in `docker` group at all. Protects against: the agent
  (or an injected instruction) using Docker to reach the host, structurally — there is no code path through the
  proxy that grants it, not a check that could be argued around. Residual risk: the proxy's own filter list is the
  new attack surface (same category of risk as go-gate's classifier — a heuristic that must be kept narrow and
  tested), and anything genuinely needing `docker exec`/`create` (most ad hoc debugging) now needs a keeper plan
  with `actions=script`, through the normal flow, same as any other opaque command today.

**Recommendation: C for Docker, B for the rest, never A.** Put the agent user in no group that is root-equivalent.
Route routine container lifecycle management through a filtered proxy whose allowlist is reviewed like code (it
should live in this repo, parameterized, the same way `snapshot-gate/` and `oncall/` are kits rather than
homelab-specific scripts — see PR #12, which is explicitly staged to land after this). Grant the few genuine
host-level verbs through named sudoers lines, not a wildcard. Anything wider goes through a keeper plan like today.

**What this PR does NOT do:** build the Docker proxy, write the sudoers lines, or run `useradd` on the real LXC.
That migration touches a running system with ~40 containers; it needs the owner's own container names, the real
service units, and a maintenance window, none of which exist in this cloud session. §5 below designs how to stage
it (observe before block, a reversible dry run in a throwaway container) so that when the owner does it, nothing
here has to be re-invented. **Decided by the owner** (PR #18 review comment, 20/10/2026, verified on the PR itself —
[comment](https://github.com/renocz/agent-ops-guardrails/pull/18#issuecomment-6299989493)): the Docker-proxy kit
goes **into this repository**, in a **separate PR**, following the `snapshot-gate/`/`oncall/` model, not left
outside the repo or folded into this one. Still open, because it is operational knowledge this design cannot
invent: which host-level verbs the sudoers allowlist in that separate PR should actually name (which arr container,
which LXC ids).

**User topology: decided by the owner** (same PR #18 comment as above). Not one shared user for all three server
agents as this draft had left open, and not three separate ones either: **two non-root Unix users**.

- The **update timer** (it replaces the Claude Code binary itself — arguably the most sensitive of the three, since
  a compromised update could plant anything in what every other agent later runs) gets its **own, separate** user.
- The **interactive assistant and the morning (standing-plan) systemd job share one common non-root user**, told
  apart from each other by `KEEPER_ACTOR`/standing plans (§2) exactly as this PR already builds it, not by a Unix
  user boundary between them.

Both users join `keeperclients` so the one shared `keeperd` (§3) can reach either socket peer; §5's parent-directory
and socket-group setup already generalizes to more than one agent uid (`agent_uids` in the config is already a list,
not a single value — see `keeperd.DEFAULTS`). Nothing in this PR's standing-plans code assumes one user: coverage is
keyed by the plan's id and the request's `actor`, never by which Unix uid made the call, so this topology needs no
code change here, only the real `useradd`s and `keeperclients` membership on the real host (§5).

---

## 2. Standing plans: a closed, pre-approved list for an agent nobody is watching

This is the piece implemented in this PR.

**The problem precisely.** Every plan in the keeper today is created by *a proposal the agent makes* and *a button
the owner taps*, each use bound to one human decision. That is right for the interactive assistant. It is the wrong
shape for `morning-act.py` at 08:15: nobody is going to tap a button at that hour, and if the job's own
`keeper-propose` call pushed a Telegram card every morning it would train the owner to approve without reading,
which is worse than no gate at all.

**Design.** A standing plan is:

- **defined in the root-owned config file** (`/etc/keeper/config.json`, new key `standing_plans`), never created,
  approved or widened through the socket, through Telegram, or by anything the agent can reach. This is the
  strongest answer to "the agent must not be able to create or widen it": there is no code path from agent input to
  `self.standing` at all, by construction, not by a check that could be bypassed. Creating or changing one is a
  root edit to a file the agent cannot write, the same trust boundary the keeper already puts around
  `/etc/keeper/config.json` and the managed hook settings.
- **an exact list of literal commands, never a pattern.** `{"id": "morning-arr-restart", "commands": ["python3
  /opt/homelab/morning-act.py restart-arr", "python3 /opt/homelab/morning-act.py retry-search", "python3
  /opt/homelab/morning-act.py tick-note"], "expires_at": "2026-11-19", "note": "08:15 systemd timer"}`. A call is
  covered only if the full `Bash` command, after stripping leading/trailing whitespace, is **character-for-character
  equal** to one of the listed strings — no prefix, no substring, no regex, no category/targets abstraction like a
  normal plan. This is deliberately a stronger, narrower check than `go_gate.covers()`: an ordinary plan's
  `actions=deploy,targets=web` is a heuristic judgement about a whole class of commands, which is exactly the thing
  the owner should not have to trust unsupervised at night. A standing plan instead names the finitely many commands
  the morning job can ever need, and nothing else ever matches — adding a new one needs a root edit and a daemon
  restart, which is the deliberate friction (see "long but bounded" below).
- **bounded, never silently permanent.** `expires_at` is mandatory (a plan with none is dropped at load, logged,
  never treated as "forever"); keeperd clamps it to at most `STANDING_MAX_DAYS` (45) from now regardless of what the
  file says, the same defence-in-depth pattern as `MAX_ACTIVE_PLANS_HARD_CAP` for ordinary plans — a typo in the
  config (`"2126-11-19"`) cannot create a decade-long silent grant. The owner reconfirms by editing the date and
  restarting keeperd; there is no "renew" path reachable at runtime.
- **listed on both sides.** `keeper-status` (what the agent reads) and `/status` (what the owner reads on Telegram)
  both show every currently-valid standing plan: its id, how many commands it covers, and days left. An agent that
  wants to know what it can already do without proposing can ask; an owner glancing at `/status` sees standing
  grants next to the session's active plans, not hidden in a config file they have to remember to re-read.
- **revocable the same way an ordinary plan is: `/stop <id>`.** The existing `_revoke_all(plan_id)` path (shared by
  the Stop button and the `/stop <id>` text command) now also recognizes a standing plan's id and disables it at
  once, persisted in `state.json`'s `standing_disabled` list — reachable the instant the owner needs it, with no
  wait for a restart. Re-enabling one (removing it from `standing_disabled`) is deliberately **not** exposed through
  Telegram or the socket: it means editing `state.json` or the config and restarting, the same asymmetry go-gate
  already has between "revoke now" (cheap, instant) and "grant" (deliberate, reviewed) for an ordinary plan.
- **used, but never a card.** The actual coverage check (`Keeper.check()`) tries standing plans for an exact literal
  match before it ever runs the heuristic classifier. A match is logged (`standing-used`, with the plan's id, so
  `/summary` and `/plans` show it) and allowed immediately — the classifier never even runs, so there is no
  category/target ambiguity to get wrong for these calls at all.

**The part that still needs a human to not be flooded: an out-of-scope call at night.** If the 08:15 job tries
something the standing plan does not cover — nothing unusual, just "the title search needed a retry with a
different spelling" — it still calls `keeper-propose`, exactly like the interactive agent would. Pushing that
proposal to Telegram at 08:15 unattended is the thing the task explicitly rules out ("ne doit pas inonder le
propriétaire"). The mechanism:

- the root-owned hook command for an unattended session carries one extra, fixed environment variable:
  `env -i KEEPER_ACTOR=standing-morning /usr/bin/python3 -I /opt/agent-guardrails/lib/keeper_client.py`. This is
  safe for exactly the reason `env -i` already is: the whole command line lives in managed settings (root-owned),
  so the agent cannot set or change `KEEPER_ACTOR` for its own session — only root, by writing a distinct hook
  command for the systemd unit that launches an unattended `claude -p`, decides which actor tag a given invocation
  carries. `keeper_client.py` forwards `os.environ.get("KEEPER_ACTOR")` on the socket request; it is `None` unless a
  root-owned command line set it, same trust level as the socket's own peer-uid check.
- `/etc/keeper/config.json`'s `unattended_actors` lists which actor tags this is true for (e.g.
  `["standing-morning"]`). `Keeper.propose()` still records the proposal as pending (so it shows up in `/plans` and
  `/summary` the next time the owner looks, not just silently dropped), but does **not** call `notify.send_plan` —
  no push, no card — and logs `standing-propose-suppressed` instead. The agent is told, in the one deny reason it
  gets back, that the request was recorded for the owner's next review and that nothing was sent live — so a
  headless job fails fast instead of burning its `--wait` budget waiting for a tap that will never come.
- this is **additive**, not a new way to grant anything: an unattended actor still cannot get past `check()` on
  anything beyond its standing plans and whatever is already active in its session (normally nothing, since a fresh
  `claude -p` run starts with none) without the exact same owner tap a normal plan needs — it only changes whether
  asking for one rings a phone at night.

**What this needs from the owner that this PR cannot supply on its own:** confirming, on the real host, that a
distinct `--settings` profile (or an equivalent root-owned, per-systemd-unit hook command) actually reaches the
hook the way described above under a real `claude -p` headless run — see §4's NOT TESTED list. The `KEEPER_ACTOR`
plumbing in this PR is tested against the real socket and a real hook subprocess (§"Testing" below), but not
against a real `claude -p` and a real systemd unit, which this session cannot run.

---

## 3. One daemon per host, or one central daemon

**Options**

- **A. One `keeperd` per host** (today's model, stated as a known limit: "one keeperd and one keeper bot per
  machine"). For the server this means one `keeperd` inside LXC 100, covering all three of its agents (the
  interactive assistant, the morning timer, the update timer) and nothing on the Proxmox host itself or any other
  LXC. Simple, matches what is already built and tested, and keeps the blast radius of a compromised `keeperd`
  limited to the container it runs in.
- **B. A central daemon** (e.g. on the Proxmox host, or a dedicated LXC) that every agent, on every machine,
  including the Mac, talks to over the network instead of a local Unix socket. Centralizes the log and the Telegram
  bot (one `/summary` for everything), but turns the peer-uid check (`SO_PEERCRED` over a Unix socket, the actual
  mechanism that makes "an agent with the user's rights cannot forge the socket side" true today) into a network
  authentication problem, which is a different, larger design than this PR's scope, and would need its own threat
  model before it could claim the same guarantee.

**Recommendation: A.** Keep one `keeperd` per machine, now including LXC 100. All three server agents share it,
whatever Unix user each runs under (§1's decided topology, above) — standing plans and actor tags, §2, are what
tells them apart, not separate daemons. This is the option that
needs no new trust mechanism beyond what `peer_uid()` already proves, and it matches the one sentence already in
`docs/design-keeper.md`'s failure modes that anticipated this: "the server is out of scope for v1 until its agent
runs as a normal user (root in the container could become `_keeper`)" — read literally, that sentence already
assumes one daemon per host, just waiting on §1.

**Degraded mode, specifically for a night job.** Today's fail-closed rule ("keeperd down or socket missing: the
hook denies changes, reads still pass") is right for the interactive agent — a human can retry or investigate.
0A cron job that always fails closed at 08:15 because the daemon happened to restart at 08:14 is a different
failure mode: nobody is there to retry it, so "fail closed" quietly means "the arr container never gets restarted,
forever, until someone notices." Recommend: the daily `/summary` explicitly reports **gaps** — a standing-plan
actor that had a scheduled run (inferred from the systemd timer's own log, out of this repo's reach, or more
simply: an expected-vs-seen count the morning script itself could report into the summary) and no corresponding
`standing-used`/`allowed`/`denied` event that day. This is a reporting addition, not a change to the fail-closed
rule itself — the gate still denies by default, but silence stops being invisible. **Known limitation, not a
question**: the owner decided (PR #18 review comment, 20/10/2026 —
[comment](https://github.com/renocz/agent-ops-guardrails/pull/18#issuecomment-6299989493)) that this stays a todo,
deliberately **not implemented** until there is a real systemd timer to signal from — building it against a guess
at that signal would be worse than not building it. Revisit once §1 and §5 are done on the real host and a real
timer exists to compare against.

---

## 4. Hooks and headless mode: can `claude -p` bypass the gate?

Verified against this repository and the public Claude Code hooks documentation (`code.claude.com/docs/en/hooks`):

- **`--safe-mode`:** the owner's existing rule ("never `--safe-mode`, it cuts hooks") is the right one and this
  design changes nothing about it. `--safe-mode` disables hooks entirely by design, which would make the keeper
  hook (and go-gate's and secret-guard's) simply not run — for a headless cron job as much as for the interactive
  session. **Do not use it on any systemd unit that launches `claude -p`.**
- **`--settings <path>`:** layers an additional settings file on top of the managed one; it does not replace or
  disable managed settings (`/etc/claude-code/managed-settings.json` on Linux), which is exactly why §2's actor-tag
  mechanism can work at all — the systemd unit can point a given invocation at a distinct, root-owned settings file
  that sets `KEEPER_ACTOR` in the hook's own command line, while the managed, root-owned hook registration itself
  stays the one every invocation on the machine shares and cannot remove. **This specific interaction (a
  `--settings` file whose own `PreToolUse` hook command differs from the managed one, on the same invocation) is
  the one piece of this design that is ASSUMED from the documentation, not run against a real `claude -p` from this
  session — see the final report's NOT TESTED list.**
- **`--allowedTools`:** narrows which tools can run without changing how PreToolUse hooks are evaluated for the
  tools that remain; a headless job with a narrow `--allowedTools` (e.g. only `Bash` for `morning-act.py`) is good
  defence in depth alongside the standing plan, not a replacement for it — the keeper must still see and gate the
  one tool that is allowed.
- **Disabling the plugin, keeping the hook:** the owner's existing rule (only the Telegram plugin is disabled on
  the server, to avoid the two-poller 409 conflict with the keeper's own second bot) is orthogonal to hooks:
  disabling a *plugin* does not touch `hooks.PreToolUse` in managed settings, which is a separate key the plugin
  does not own. No change needed here; stated for completeness since the task asked it to be checked.
- **Can a headless agent remove or edit the hook itself?** No more than the interactive one can, and for the same
  reason: the hook is registered in `/etc/claude-code/managed-settings.json`, root-owned, and `claude -p` reads
  settings the same way the interactive CLI does — there is no headless-only code path that skips managed settings.
  This was already true before this PR; restated here because the task asked for it to be verified for headless
  mode specifically, not assumed to carry over.

---

## 5. Installation and migration: the real gaps on LXC 100

`install-keeper.sh` already has a Linux branch (systemd unit, `useradd --system`, `/etc/claude-code/managed-settings.json`),
written and tested (CI runs it in `--prefix` mode) before this PR. The gaps are specific to an LXC, not to Linux in
general:

- **A privileged LXC is not a VM.** `useradd`/`groupadd`/`systemctl` all work normally inside a privileged LXC, so
  the installer's Linux branch should run as written — this is an assumption carried over from "Linux" to
  "privileged LXC on Debian," not independently verified against a real LXC in this session (see NOT TESTED).
  `ProtectSystem=strict`/`ProtectHome=read-only` in the shipped `keeper.service` unit are systemd sandboxing
  directives; they work the same inside a privileged LXC as on bare metal as long as the kernel supports the
  underlying cgroup/namespace features, which a privileged LXC shares with its host kernel.
- **The service user for `keeperd` is not the same question as the agent's user (§1).** `keeperd` runs as its own
  dedicated `keeper` system user, exactly as the installer already does on any Linux host; nothing about running
  inside an LXC changes that. What does change: the installer's parent-directory ownership check (`CHAIN_BAD` in
  the script) walks up from `/opt/agent-guardrails`, `/etc/keeper`, `/var/lib/keeper` and the managed-settings
  directory to the filesystem root, refusing to install if anything in the chain is not root-owned or is
  group/other-writable. Inside an LXC this chain terminates at the **container's own** root, which is correct and
  needs no change — but it is worth restating because a privileged LXC's root can, from the Proxmox host, be
  re-mounted or have its ownership altered from outside the container's own view of "root-owned"; that is explicitly
  **out of scope** (§6: a human with Proxmox host access is not the threat model here).
- **The socket's group, `keeperclients`, must include both agent users decided in §1**: the shared user (interactive
  assistant + morning job) and the update timer's own separate user — `agent_uids` in the config already takes a
  list, so this needs no code change, only adding both uids to the group and the config at install time.
- **No `launchd` equivalent problem on Linux** — the systemd branch already exists and is exercised in CI
  (`--prefix` mode only; never `--apply` in CI, by design, since that needs root and real users). The one thing CI
  cannot exercise is `--apply` itself, which is why the staged rollout below matters.

**Staged, reversible rollout (recommended sequence for the owner, once §1's decision is made):**

1. **Throwaway test first, in a disposable Debian container** (an LXC or any disposable container the owner can
   destroy), never on LXC 100 directly: `sudo ./install-keeper.sh --agent-user <test-user> --owner-id <id> --apply
   --observe`, confirm the daemon starts, the hook answers, `/status` and `keeper-status` work, then destroy the
   container. This is the "dry run" the task asks for; it cannot be done from this cloud session (no systemd, no
   real users to create — see NOT TESTED) but costs the owner one disposable container and about the same half hour
   the Mac's own block-mode dry run already took (`docs/block-mode-dry-run.md`).
2. **On LXC 100, observe mode first**, same as the Mac's own rollout: install with `--observe`, let it run
   alongside the existing root-agent setup (it logs would-deny events, blocks nothing) for a few days, then read
   `/summary` before touching anything.
3. **Only after `/summary` looks sane, and only after §1 is actually done** (the agent user is created and is not in
   `docker` group, the Docker proxy or sudoers lines from §1 are in place and tested) does `--observe` come off.
4. **Rollback, at every stage:** the same three levers already documented in `keeper/README.md` ("Emergency
   rollback") apply unchanged on the server — put `keeperd` into observe and restart it, or stop the daemon and
   flip the root-owned mode file (then every change fails closed, reads still pass), or restore
   `managed-settings.json.bak-keeper`. None of this needs new code; it is already built for the Mac and carries over
   as written.

---

## 6. What the keeper will not cover on the server, stated plainly

- **The Proxmox host itself.** Nothing in this design touches it. A human with root on the hypervisor can always
  reach every LXC, including 100; that is Proxmox's own trust model, not something keeper changes or should try to.
- **Other LXC containers on the same host**, unless and until each gets its own `keeperd` (§3) and its own non-root
  agent migration (§1) — this PR's standing-plans feature is generic and reusable per host, but each host still
  needs the same work done.
- **Human root access.** The owner's own `ssh root@<host>` session is, by design, not gated by anything here —
  the keeper gates an *agent*, never the human who can already install, modify or remove it.
- **A `docker exec` already authorized by a standing plan or an active plan.** Once a plan covers it, what runs
  inside that shell is the same `actions=script` unbounded-by-design limit `docs/design-keeper.md` already states
  for the laptop: the keeper gates the tool call, not what a process does once it is allowed to start.
- **Root cron jobs that are not an agent at all** (logrotate, a backup script, anything that was already there
  before Claude Code existed on this host). Out of scope by definition: the keeper gates Claude Code's own tool
  calls through its hook, nothing else on the machine.

---

## Testing

Implemented and run in this PR (`keeper/test_keeper.py`, `keeper/test_block_dryrun.py`):

- standing-plan coverage: an exact literal match allows without any active plan; a command that differs by even a
  trailing character, an extra flag, or a wrapping `sh -c` is **not** covered (the "no wildcard" guard);
- expiry: a standing plan past its `expires_at` stops covering, with no special-case "grace period";
- the `STANDING_MAX_DAYS` clamp: a config entry dated far in the future is capped, not honoured as given;
- malformed config entries (`commands` missing, `commands` not a list, `expires_at` missing or unparsable, `id`
  empty) are dropped one at a time, logged, and never crash the daemon or fall back to allowing everything;
- `/stop <id>` against a standing plan's id disables it immediately, persisted, with no way back except a root
  edit + restart; it is reported with the same messages as stopping an ordinary plan;
- listing: both `keeper-status` (agent-facing) and `/status` (owner-facing) show every currently-valid standing
  plan;
- the unattended-actor path: a proposal from a configured `unattended_actors` tag is recorded (visible in `/plans`)
  but never reaches `notify.send_plan` (no Telegram card), and the agent's own deny reason says so; a proposal from
  any other actor (or no actor at all) behaves exactly as before — a card is sent, same as today;
- the `KEEPER_ACTOR` environment variable is carried from a real `keeper_client.py` subprocess, over the real
  socket, into `Keeper.check()`/`propose()` (`test_block_dryrun.py`, the same "real socket, real subprocess" tier
  the rest of the keeper test suite already uses for this kind of claim).

Mutation-checked (same method as PR #14/#15: a targeted, manual revert in a throwaway copy, the real test file run
against it via a dynamic import swap — not an automated mutation framework, none exists in this repo):

1. **exact scope, no wildcard:** `_standing_lookup`'s equality check changed to a substring/`startswith` check —
   the "a command differing by one character is not covered" test fails, as expected.
2. **non-widening by the agent:** a crafted `tool_input`/socket payload carrying its own `standing_plans`/`actor`
   keys cannot change `Keeper.standing` — proven by asserting `self.k.standing` is bit-for-bit identical before and
   after a `check()` call that tries to smuggle such a payload; there is no code path that reads `self.standing`
   from anything but `cfg` at `__init__` time, so this is really a test that the absence of a writer stays absent.
3. **fail-closed on malformed config:** `_load_standing`'s per-entry `try/except` removed (letting one malformed
   entry's exception propagate) — the "malformed entries are dropped, not a crash" test fails with an unhandled
   exception instead of a clean, logged skip, exactly the failure mode the guard exists to prevent.

Existing suites (`council`, `go-gate` incl. `test_disguise.py`/`test_balance_oracle.py`, `keeper`'s two test files,
`leak-check`, `secret-guard`) stay green, unmodified logic — this PR only adds new state (`standing`,
`standing_disabled`, `standing_usage`) and one new, optional request field (`actor`), both ignored by every
existing code path that does not know about them.

**NOT TESTED from this session** (needs the real server, listed again in the final report so it is not lost in
this document's length):

- `install-keeper.sh --apply` on a real LXC — no systemd, no real users to create, no privileged container
  available here;
- a real `claude -p` headless run picking up a `--settings`-provided, actor-tagged hook command as described in §2
  and §4 — this session has no Claude Code binary of its own to launch headless against a real managed-settings
  file;
- the Docker-proxy allowlist from §1 against real container names;
- Telegram with a real bot token and a real chat (as for the original keeper, every test here uses a fake local
  Telegram or no Telegram at all).

## Owner decisions (resolved; were open questions in the first draft of this PR)

Posted directly on the PR, verified via the GitHub API rather than relayed:
[comment](https://github.com/renocz/agent-ops-guardrails/pull/18#issuecomment-6299989493) (`renocz`, OWNER,
20/10/2026, "validated by the owner in chat on 20/10/2026 at 19:21 UTC").

1. **The Docker-proxy kit from §1 goes into this repository, as a separate PR**, following the `snapshot-gate/`/
   `oncall/` model — not handled outside the repo, not folded into this PR. Still genuinely open within that future
   PR: the exact host-level verbs the sudoers allowlist should name, which is operational knowledge (container/LXC
   ids) this design cannot supply.
2. **§3's degraded-mode reporting stays a todo**, deliberately not implemented until a real systemd timer exists to
   signal from — not reopened as a question each time this doc is revisited.
3. **User topology: two non-root users, not one, not three** — the update timer separate (it replaces the binary
   itself); the interactive assistant and the morning job share one user, distinguished by `KEEPER_ACTOR` (§1, §5).

No open questions remain from this PR's first draft. Anything found once §1/§5 are actually carried out on the real
host belongs in a follow-up, not a guess made here.

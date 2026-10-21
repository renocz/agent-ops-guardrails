# snapshot-gate

The agent *requests* a snapshot; the host *takes* it. The agent can never roll back or delete — there is no
code path for that anywhere in the files it can run. Generic, no homelab-specific names: `pool0`,
`example-host`, `testds` are placeholders to replace with your own dataset/volume.

**Status: experimental.** Tested against a dry-run/fixture backend, the exact ZFS/LVM command vectors (a
Python-level `subprocess.run` mock), and real `zfs`/`vgs`/`lvs`/`lvcreate`/`lvremove` *processes* standing in
for the real tools (real argv, real exit codes, no real pool/VG — see
[docs/snapshot-gate-real-disk-testing.md](../docs/snapshot-gate-real-disk-testing.md) for why no automated run
here has ever reached a real pool/VG, what each tier of testing does and does not prove, and an owner checklist
for the one real-pool/VG pass this still needs, including restoring a single service). Not yet run against a
real ZFS or LVM host, and not yet run by anyone outside this repo.

## The threat this answers

In a hypervisor's permission model, "snapshot" usually bundles **create, rollback and destroy** into one
capability. Give an on-call agent snapshot rights on the host it's supposed to protect and you've also given it
the power to roll back (or delete) every service on that host at once — on purpose, by mistake, or because it
was tricked into it. [method.md §3](../docs/method.md#3-an-on-call-agent-that-cannot-undo) describes a real near
miss.

The fix: split "snapshot" into **create** (the agent may ask for this) and **rollback/destroy** (the agent
never gets this capability, full stop — not "the agent is told not to," the capability does not exist in the
code the agent can invoke). The agent drops a request; a separate, root-owned, create-only script on the host
is what actually touches ZFS/LVM. Restore stays a human action, done per-service, documented in your own runbook
(see [oncall/](../oncall/) for the identity underneath this and [change-sop/](../change-sop/) for the "verify,
then document" half of the loop).

## What this does NOT protect against

- **A human (or a compromised root)** on the host can still roll back or destroy anything — this gate
  constrains the *agent's own* reachable capability, not the host's own admin.
- **Running out of space anyway.** The usage threshold refuses *new* snapshots above a configured percentage;
  it does not free space or guarantee existing snapshots don't already fill the pool.
- **Data loss between snapshots.** The cooldown exists to stop snapshot spam, not to guarantee a maximum
  recovery window — size yours around how much you can afford to lose.
- **A malicious request flood from a *different* angle than content-based attacks.** Request content is never
  read (by design — see below), but nothing here stops an agent from writing many request files quickly; the
  cooldown is what actually bounds how often a *new* snapshot gets created, and a flood of refused requests
  still costs disk I/O and log lines. This kit does not rate-limit requests themselves, only snapshot creation.
- **The backend's own bugs or capacity limits.** ZFS/LVM failures (quota exceeded, pool degraded, I/O error)
  surface as the `create_snapshot` call failing; this kit does not add retry or backoff logic.

## How it works

1. The agent writes an empty (or any-content — it is **never read**) file into `requests_dir`, named uniquely.
   `request-snapshot.sh` does this and then polls.
2. A trigger on the host — a systemd path unit (Linux) or a launchd `WatchPaths` job (macOS), see
   `templates/`, **never installed automatically by this kit** — runs `snapshot-gate-host.py`.
3. Under a lock (one run at a time), for each pending request: refuse if usage is above the threshold; refuse
   if a matching snapshot younger than the cooldown exists (its name is returned instead); otherwise create one
   named `<prefix>-YYYYMMDD-HHMMSS`.
4. The result goes to a state file next to the request, which `request-snapshot.sh` polls for and reports —
   exit 0 only on `OK`.
5. `retention-purge.py`, run separately (e.g. from cron), deletes snapshots that match the strict name pattern
   **and** are older than the retention period. It is the only file in this kit with any destroy code at all.

```
agent                    host (triggered by a path unit / WatchPaths job)
  |                            |
  |--write <id>.request------->|
  |   (content ignored)        |-- usage check
  |                            |-- cooldown check (existing names only, exact dataset + prefix match)
  |                            |-- zfs/lvm snapshot create (or refuse)
  |<--poll <id>.state----------|
  |   until it appears         |
  exit 0 only if status=OK
```

## Backends

`lib/backends.py` defines three, behind the same interface (`usage_percent`, `list_snapshot_names`,
`create_snapshot`) — **none of them has a destroy method**:

- **Zfs** — `zfs list`/`zfs snapshot` on a configured dataset.
- **Lvm** — `vgs`/`lvs`/`lvcreate -s` on a configured `vg/lv`. **Thin-provisioned origins only.**
  `lvcreate -s` with no size (what this backend always runs) only works for a thin-provisioned LV; on
  a classic (non-thin) LV it needs an explicit size, which this kit deliberately never supplies. Before
  ever calling `lvcreate`, the backend checks `lvs --noheadings -o lv_layout,pool_lv <vg/lv>` and
  refuses with `LvmNotThinProvisioned` if the origin is classic, or if that check's own output can't be
  parsed (fail-closed, never "probably fine"). Example on a classic origin:
  ```
  backend 'lvm' only supports thin-provisioned volumes, and 'vg/data' is a classic (non-thin) logical
  volume; lvcreate -s on a classic LV needs an explicit size, which this kit never supplies, so
  refusing to create a snapshot.
  ```
  There is no size option and no second LVM backend for classic volumes — mix a thin pool and classic
  volumes on the same host, and point this kit only at the thin ones; snapshot a classic volume some
  other way.
- **Dir** — a directory of empty files standing in for snapshots. This is both the dry-run backend and the
  fixture every test in this kit uses; no root, no real storage, needed to exercise it.

## Naming and why it matters

Every snapshot this gate creates is named `<prefix>-YYYYMMDD-HHMMSS`; the full identifier checked everywhere
(`lib/naming.py`) is `<dataset>@<prefix>-YYYYMMDD-HHMMSS`, matched **in full**, not as a string prefix: a
dataset named `pool/agent-other` or a child dataset `pool/agent/child` picked up by a recursive listing never
matches a configured dataset of `pool/agent`, however the backend's listing was gathered. The age used for the
cooldown and the retention purge is parsed straight from the name's own timestamp, not a separately queried
creation time — one less place for a mismatch to hide.

## Install

```sh
./install-snapshot-gate.sh --agent-user AGENT --dataset pool0/agent-data               # dry run (default)
./install-snapshot-gate.sh --agent-user AGENT --dataset pool0/agent-data --prefix /tmp/x  # write under /tmp/x
sudo ./install-snapshot-gate.sh --agent-user AGENT --dataset pool0/agent-data --apply     # really install
```

Options: `--backend zfs|lvm` (default zfs), `--snapshot-prefix NAME` (default `agent-gate`),
`--usage-threshold PERCENT` (default 85), `--cooldown-minutes N` (default 10), `--retention-days N` (default 7).

**The installer does not enable a trigger.** Copy `templates/snapshot-gate.path` +
`templates/snapshot-gate.service` (Linux) or `templates/com.example.snapshot-gate.plist` (macOS), fill in their
placeholders, and enable them by hand — see the comments in each file. This kit was never run with `--apply`
while building it; try the dry run and `--prefix` modes first.

After install, check as the agent user, each must **fail**: write a file into the states directory; read and
rewrite the lock file; run `retention-purge.py` directly (it needs the root-owned install directory to even
execute as a module, and the config/state paths are not agent-writable).

## Combining with the other pillars

- [change-sop/](../change-sop/)'s step 5 ("back up before writing") is exactly what `request-snapshot.sh`
  gives you a mechanical way to do.
- [oncall/](../oncall/) is what keeps the *rest* of the on-call agent's permissions narrow enough that this
  being its only snapshot-adjacent capability actually matters.

## Testing

```sh
python3 -m unittest test_snapshot_gate_host test_retention_purge test_backend_commands test_fakebin_subprocess -v
```

19 tests against the `Dir` dry-run backend: request accepted and creates a snapshot; refusal on usage (and
acceptance at exactly the threshold); refusal on a recent matching snapshot (its name is returned, no new one is
created); a foreign name or a different dataset's snapshot never counts towards the cooldown; several pending
requests are each answered (the first succeeds, the rest are refused by the cooldown it just created); a second
run while the lock is held does nothing; binary garbage / arbitrary content in a request is never read or
interpreted; strict name matching for purge, including the recursion and dataset-prefix-collision cases, and a
timestamp-shaped-but-impossible date is skipped rather than crashing the run; dry run vs `--apply` on a temp
fixture directory removes only the matching old names.

`test_backend_commands.py` (19 more) asserts the exact ZFS/LVM command vectors via a Python-level
`subprocess.run` mock, plus a full create → cooldown-refuse → purge round trip per backend.
`test_fakebin_subprocess.py` (7 more) execs real stand-in `zfs`/`vgs`/`lvs`/`lvcreate`/`lvremove` processes
through the same unmodified code — see [docs/snapshot-gate-real-disk-testing.md](../docs/snapshot-gate-real-disk-testing.md)
for what each tier proves and does not.

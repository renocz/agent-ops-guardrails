# Testing snapshot-gate against real ZFS/LVM (owner checklist)

`snapshot-gate`'s automated suite never ran against a real ZFS pool or LVM volume group before
this pass (19/10) — only against the `Dir` dry-run backend, and against a Python stub standing in
for `subprocess.run()`. This page records exactly what changed, in three tiers of "how real", and
gives the owner a short manual checklist for the one thing none of them can prove: a real pool/VG.

## Where each part runs (read this first if you are on a Mac)

| What | Needs | Runs on a stock Mac (no ZFS, no LVM)? |
|---|---|---|
| Tier 1, `test_snapshot_gate_host.py`, `test_retention_purge.py` | Python 3.9+ | Yes |
| Tier 2, `test_backend_commands.py` | Python 3.9+ | Yes |
| Tier 3, `test_fakebin_subprocess.py` (fake `zfs`/`vgs`/`lvs`/`lvcreate`/`lvremove`) | Python 3.9+ and `/bin/sh` (bash 3.2 or dash) | Yes. No root, nothing is installed, nothing real is touched |
| `change-sop` and `oncall` suites | Python 3.9+ | Yes |
| Manual checklist below, steps 1 to 7 | A **Linux** host or VM whose kernel really has `zfs.ko` or `dm_mod`, root, `losetup`, `zpool` or LVM tools | **No.** macOS has no `losetup`, no `dm_mod`, no LVM; the checklist uses GNU `truncate` and Linux paths. OpenZFS on macOS is a different environment and is not covered by this checklist |

On a Mac, run everything that is automated from the kit directory:

```
cd snapshot-gate && python3 -m unittest test_snapshot_gate_host test_retention_purge \
    test_backend_commands test_fakebin_subprocess
```

A green run on a Mac proves the Python policy and the way the code handles a process boundary. It
does **not** replace the checklist: only a Linux host with a real pool or VG can show that the real
`zfs`/`lvm` command syntax is accepted and that a real restore works. If you only have a Mac, run
the checklist on a throwaway Linux VM (any distribution that ships the ZFS or device-mapper
modules); the loop-device approach in step 1 keeps it away from real disks.

**The fake binaries must stay bash 3.2 / POSIX portable.** Stock macOS ships bash 3.2 and BSD
tools, so the files under `test_fixtures/fakebin/` use `#!/bin/sh` and only POSIX constructs: no
negative array subscripts (`${a[-1]}`, bash 4.3+), no `${!#}`, no arrays, no associative arrays, no
`mapfile`/`readarray`, no `${var,,}`, no `[[ ]]`, no `local`, no `pipefail`, and no GNU-only flags
of `sed`/`date`/`stat`/`readlink`. The `shell-portability` CI job (`checkbashisms` and
`shellcheck --shell=sh`) and `FixturesPortableAcrossShells` in `test_fakebin_subprocess.py` (runs
every fake through dash and bash) enforce this. Keep new fixtures to the same rule.

## What this pass found, verified by running real commands

The CI/sandbox environment this kit's tests run in (and the container this pass ran in) has **no
usable kernel support for either backend**, confirmed by actually running the commands, not by
assumption:

```
$ uname -a
Linux ... 6.18.44-fc-v139 ...
$ ls /lib/modules/
ls: cannot access '/lib/modules/': No such file or directory
$ modprobe zfs
bash: modprobe: command not found
$ dmsetup version
/dev/mapper/control: open failed: No such device
Failure to communicate with kernel device-mapper driver.
```

- **ZFS is impossible here regardless of packaging.** `zfs.ko` is always an out-of-tree kernel
  module; there is no `/lib/modules` directory and no `modprobe`, so nothing could load it even if
  `zfsutils-linux` were installed.
- **LVM's userspace tools install fine** (`apt-get install lvm2` succeeds, `pvcreate`/`vgcreate`
  on a real loop device both succeed — PV/VG metadata is userspace-only), **but `lvcreate` fails**:
  the kernel has no device-mapper driver at all (`/dev/mapper/control` cannot be opened), so no
  logical volume — snapshot or otherwise — can ever be created. This was reproduced end to end on
  a real loop device (`losetup` + `pvcreate` + `vgcreate` succeeded; `lvcreate` failed with the
  error above) and then torn down (`vgremove`, `pvremove`, `losetup -d`).

Nothing destructive was attempted and nothing real was ever touched: the loop device was backed by
a throwaway sparse file under `/tmp`, removed immediately after.

**Consequence:** no automated test anywhere in this repository can create a real ZFS snapshot or a
real LVM snapshot. The three tiers below are what *is* covered, ordered from least to most "real".

## Tier 1 — policy logic, no shell-out (`test_snapshot_gate_host.py`, `test_retention_purge.py`)

Runs entirely against the `Dir` backend (plain files standing in for snapshots). Proves the
usage/cooldown/retention/purge *policy* is correct. Cannot catch a wrong `zfs`/`lvm` command.

## Tier 2 — exact command vectors, Python-level mock (`test_backend_commands.py`)

Patches `subprocess.run` itself with a Python stand-in and asserts the **exact argv** each backend
method builds (this is the file whose docstring records the real bug the owner's review caught on
18/10: the LVM backend was putting `@` into a new LV's name, which real `lvcreate` rejects). It
never executes a real OS process, so it cannot catch a backend that builds a correct-looking argv
list but would still fail against a real `zfs`/`lvcreate`/`lvremove` binary (wrong flag order a
shell would silently reorder differently, an environment-dependent parsing quirk, a real nonzero
exit code and stderr the Python code must not leak). **This file existed since 18/10 but was never
actually run in CI** — the CI step for this kit only invoked `test_snapshot_gate_host.py` and
`test_retention_purge.py` — so until this pass its 19 tests gave no real coverage despite "19
tests" in the PR description. Fixed in this pass: `.github/workflows/tests.yml` now runs it.

## Tier 3 — real OS-level exec, fake binaries (`test_fakebin_subprocess.py`, new in this pass)

Executable scripts named `zfs`, `vgs`, `lvs`, `lvcreate`, `lvremove`
(`test_fixtures/fakebin/`, see its own README) reproduce the real tools' stdout shape and exit
codes, driven by plain state files. Prepending that directory to `PATH` makes the unmodified
`lib/backends.py` and `retention-purge.py` actually fork/exec a real process, with real argv, real
captured stdout, and a real `subprocess.CalledProcessError` on a nonzero exit — closing the one gap
Tier 2 cannot: whether this kit's Python code really survives a genuine process boundary,
including a backend command failing (missing dataset/VG, a busy logical volume) without ever
leaking that command's own stderr into the state file an untrusted agent polls.

This tier found one real defect, fixed in this pass: `retention-purge.py --apply` let a single
busy/held snapshot's destroy failure raise an uncaught exception and abort the whole run, leaving
every other (otherwise eligible) snapshot undeleted. It now catches a per-target failure, reports
it to stderr, keeps purging the rest, and exits 1 only if at least one target failed.

A later owner review (21/10) found a second gap this tier's fakes did not yet cover: the LVM
backend ran `lvcreate -s` with no size on every origin, which only works for a thin-provisioned LV
— against a classic (non-thin) one, real `lvcreate` demands an explicit size and fails. The owner's
own host is mostly ZFS with LVM thin on a couple of containers, but also has one classic LVM volume
this kit would have failed against with no clear reason why. `Lvm.create_snapshot` now checks `lvs
-o lv_layout,pool_lv` before ever calling `lvcreate` and refuses with a named exception
(`LvmNotThinProvisioned`) on a classic origin or on any `lvs` output it cannot parse — fail-closed,
never "probably fine". `test_fixtures/fakebin/lvs` and both test tiers were extended to exercise a
thin origin (creates), a classic origin (refuses, `lvcreate` never runs), and unparseable `lvs`
output (refuses). **This was verified only against the fake `lvs`/`lvcreate` processes below, same
as the rest of this tier — no real LVM thin pool or classic volume was available to confirm the real
`lvs -o lv_layout,pool_lv` output against a genuine thin or classic LV; that is exactly the kind of
gap step 2 of the checklist below exists to close, and is now worth doing for both an LVM thin and a
classic volume, not just a thin one.**

**What Tier 3 does *not* prove**, however realistic the fake binaries are: that the real `zfs`/
`lvcreate`/`lvremove` command-line syntax used here is accepted by a real pool/VG, that a real
`usage_percent()` reading reflects real disk usage, or that ZFS's and LVM's own locking/retry
behavior under real contention matches what the `lvm_busy` simulation assumes.

## What only a real pool/VG can prove — manual checklist

**Linux host or VM only** (see the table at the top): none of these steps can be run on macOS.

Run this once, by hand, on real hardware or a VM whose kernel actually has `dm_mod` (check first
with `dmsetup version`) or the `zfs` DKMS module installed — **not** on a shared/production
pool, and **not** with `--apply` pointed at anything that matters. Use a disposable VG/dataset the
whole checklist creates and destroys itself, named here `<vg>`/`<dataset>` — substitute your own
throwaway names, never anything from a real deployment.

1. **Create a disposable backing store.** `truncate -s 1G /tmp/sg-check.img && losetup -f
   --show /tmp/sg-check.img` → note the loop device.
2. **ZFS path** (needs a kernel with `zfs.ko` loadable): `zpool create sgcheck <loopdev>`, then
   point `config.json` at `"backend": "zfs", "dataset": "sgcheck"`.
   **LVM path** (needs `dm_mod`): the gate's LVM backend only supports a **thin-provisioned**
   origin (see above) — `pvcreate <loopdev> && vgcreate sgcheck-vg <loopdev> && lvcreate --type
   thin-pool -n sgcheck-pool -L 400M sgcheck-vg && lvcreate --type thin -n sgcheck-lv -V 300M
   --thinpool sgcheck-pool sgcheck-vg`, then `"backend": "lvm", "dataset":
   "sgcheck-vg/sgcheck-lv"`. Also create one **classic** LV in the same VG (`lvcreate -n
   sgcheck-classic -L 100M sgcheck-vg`) and, once through step 4, point a second, throwaway
   `config.json` at `"sgcheck-vg/sgcheck-classic"` and confirm the gate refuses it with
   `LvmNotThinProvisioned` instead of calling `lvcreate` — this is the one thing this pass's fake
   `lvs` cannot prove, since nothing here has run against a real thin pool or classic volume yet.
3. **Put a marker file where the dataset/LV is actually mounted**, so step 6 has something to
   restore: e.g. `echo hello > /<mountpoint>/one-service/data.txt` for a service you name yourself.
4. **Run the real request/host round trip**: `request-snapshot.sh <requests_dir> <states_dir>` (as
   the gate would be triggered), then once, `python3 snapshot-gate-host.py config.json`. Confirm
   the printed/returned status is `OK` and a real snapshot now exists (`zfs list -t snapshot
   sgcheck`, or `lvs sgcheck-vg`).
5. **Change the marker file**, then **restore it from the snapshot for that one service only** —
   this is deliberately a human action with no code path in this kit (see `snapshot-gate/README.md`
   and `docs/method.md`): for ZFS, `cp /<mountpoint>/.zfs/snapshot/<snap-name>/one-service/data.txt
   /<mountpoint>/one-service/data.txt`; for LVM, mount the snapshot LV read-only elsewhere
   (`mount -o ro /dev/sgcheck-vg/<snap-name> /mnt/sg-check-ro`) and copy the one file out, then
   unmount. Confirm the marker file is back to its pre-change content, and that nothing else on the
   dataset/LV was touched.
6. **Run `retention-purge.py config.json` (dry run, then `--apply`)** and confirm it only reports/
   deletes the snapshot(s) this run created, never anything pre-existing on a shared pool — which
   is exactly why this checklist insists on a disposable `sgcheck`/`sgcheck-vg`.
7. **Tear down**: `zpool destroy sgcheck` or `vgremove -f sgcheck-vg && pvremove <loopdev>`, then
   `losetup -d <loopdev> && rm /tmp/sg-check.img`.

If any step above behaves differently from what the automated tiers predict — a real `zfs`/`lvm`
error message this kit's fake binaries didn't anticipate, a real restore step that doesn't actually
work the way `README.md` describes — that is a real finding this pass could not have caught, and is
worth its own issue.

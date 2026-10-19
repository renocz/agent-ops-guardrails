# Fake `zfs` / `vgs` / `lvs` / `lvcreate` / `lvremove`

Real executables (not Python mocks) that reproduce the stdout shape and exit codes of the real
ZFS and LVM command-line tools, driven by plain files under a state directory
(`$FAKE_SG_STATE`). They exist because no ZFS pool or LVM volume group could be created in this
project's sandbox (no loadable kernel modules, no device-mapper kernel driver) — see
`docs/sandbox-limitations.md`.

Prepending this directory to `PATH` and exporting `FAKE_SG_STATE` makes `lib/backends.py` and
`retention-purge.py` exec these scripts exactly as they would exec the real tools: real process
creation, real argv, real captured stdout, real exit codes, real `subprocess.CalledProcessError`.
This is strictly more realistic than patching `subprocess.run` in Python (see
`test_backend_commands.py`), but it does **not** prove the real `zfs`/`lvm` command vectors used
here are themselves correct against a real pool/VG — it only proves this kit's Python code
handles a correctly-shaped stdout and a realistic exit code/stderr the way it is supposed to.

State files read/written under `$FAKE_SG_STATE`:
- `zfs_used`, `zfs_avail` — integers (bytes), what `zfs list -o used,avail` reports
- `zfs_snapshots` — one `dataset@name` per line
- `zfs_missing_dataset` — if present, its content is a dataset name; any `zfs` call naming
  exactly that dataset fails like a real missing/faulted pool would
- `lvm_total`, `lvm_free` — integers (bytes), what `vgs -o vg_size,vg_free` reports
- `lvm_snapshots` — one `vg/lv@snap-name` per line
- `lvm_missing_vg` — if present, its content is a VG name; `vgs`/`lvs` on exactly that VG fail
- `lvm_busy` — if present, its content is a `vg/snap-name`; `lvremove` on exactly that target
  fails like a logical volume still in use would

Portability rule: these scripts are `#!/bin/sh` and must stay valid for bash 3.2 (stock macOS) and
dash. No arrays, negative subscripts, `${!#}`, `[[ ]]`, `local` or `pipefail`. CI enforces it
(`shell-portability` job).

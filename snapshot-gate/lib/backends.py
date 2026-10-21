"""Backends for snapshot-gate-host: create-only, on purpose. Standard library only.

None of these classes has a destroy/rollback/remove method, and none ever will by design: snapshot-gate-host.py
only imports from this module, so "grep for destroy/remove/rollback in backends.py and snapshot-gate-host.py"
is a real, checkable claim, not a promise. The retention-purge script, which is the only place a snapshot is
ever removed, defines its own small destroy functions separately (see retention-purge.py) rather than extending
these classes -- duplicating a few lines of shell-out code was judged worth keeping that property literally true.
"""
import os
import subprocess


class Zfs:
    """A ZFS dataset. `dataset` is the pool/dataset path the gate protects, e.g. "pool/agent-data"."""

    name = "zfs"

    def __init__(self, dataset):
        self.dataset = dataset

    def usage_percent(self):
        # `zfs list -Hp -o used,avail` prints bytes; percent is of used+avail (what's actually addressable here),
        # not of the whole pool, so a quota or a reservation elsewhere doesn't skew the threshold.
        out = subprocess.run(["zfs", "list", "-Hp", "-o", "used,avail", self.dataset],
                              capture_output=True, text=True, check=True, timeout=10).stdout
        used, avail = (int(x) for x in out.split())
        total = used + avail
        return (used / total * 100) if total else 0.0

    def list_snapshot_names(self):
        # Recursive (-r) on purpose: a child dataset's snapshot could otherwise go unnoticed by a cooldown
        # check that only looked at the exact dataset -- naming.qualified_pattern() is what keeps a child
        # dataset's snapshot from being mistaken for one of ours, not a narrower listing here.
        out = subprocess.run(["zfs", "list", "-Hp", "-t", "snapshot", "-r", "-o", "name", self.dataset],
                              capture_output=True, text=True, check=True, timeout=10).stdout
        return [line for line in out.splitlines() if line]

    def create_snapshot(self, qualified_name):
        subprocess.run(["zfs", "snapshot", qualified_name], check=True, timeout=30)


class LvmNotThinProvisioned(RuntimeError):
    """Raised instead of ever calling `lvcreate`: this backend only ever runs `lvcreate -s` with no
    explicit size, which LVM only accepts for a thin-provisioned snapshot -- on a classic (non-thin)
    LV it requires a size argument this kit deliberately never supplies. Also raised when the
    thin-or-not check itself cannot be answered (missing/unexpected `lvs` output), so a check that
    fails closed, never open."""


class Lvm:
    """An LVM logical volume. `volume` is `vg/lv`, the origin volume the gate protects.

    Thin-provisioned origins only: `create_snapshot` refuses (`LvmNotThinProvisioned`) before ever
    invoking `lvcreate` on a classic (non-thin) LV, or when it cannot confirm the origin is thin."""

    name = "lvm"

    def __init__(self, volume):
        self.volume = volume
        self.vg, self.lv = volume.split("/", 1)

    def usage_percent(self):
        out = subprocess.run(["vgs", "--noheadings", "--units", "b", "--nosuffix",
                               "-o", "vg_size,vg_free", self.vg],
                              capture_output=True, text=True, check=True, timeout=10).stdout
        size, free = (int(x) for x in out.split())
        return ((size - free) / size * 100) if size else 0.0

    def list_snapshot_names(self):
        # Qualified as "vg/lv@snapshot-name" -- origin (this backend's own vg/lv) + "@" + the LV's own name --
        # exactly the same "dataset@name" shape ZFS uses, so naming.qualified_pattern() applies the same
        # exact-match discipline to both backends. An LV name itself can never contain "@" (LVM rejects it),
        # which is exactly why the snapshot's real LV name and its qualified identifier must be kept distinct:
        # see create_snapshot() below.
        out = subprocess.run(["lvs", "--noheadings", "-o", "lv_name,origin", self.vg],
                              capture_output=True, text=True, check=True, timeout=10).stdout
        names = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == self.lv:
                names.append(f"{self.vg}/{self.lv}@{parts[0]}")
        return names

    def _require_thin(self, origin):
        # `lv_layout` is always a single, space-free, comma-joined token (e.g. "linear", "thin,sparse");
        # `pool_lv` is the thin pool's name for a thin LV, and empty (so absent from --noheadings output,
        # which never pads missing trailing fields with spaces) for a classic one. That gives the three
        # cases below a clean, unambiguous shape to split on -- anything else is treated as unreadable,
        # never as "probably fine": this check fails closed, not open.
        out = subprocess.run(["lvs", "--noheadings", "-o", "lv_layout,pool_lv", origin],
                              capture_output=True, text=True, check=True, timeout=10).stdout
        lines = [line for line in out.splitlines() if line.strip()]
        parts = lines[0].split() if len(lines) == 1 else []
        if len(parts) == 2 and "thin" in parts[0]:
            return
        if len(parts) == 1 and "thin" not in parts[0]:
            raise LvmNotThinProvisioned(
                f"backend 'lvm' only supports thin-provisioned volumes, and {origin!r} is a classic "
                "(non-thin) logical volume; lvcreate -s on a classic LV needs an explicit size, which "
                "this kit never supplies, so refusing to create a snapshot."
            )
        raise LvmNotThinProvisioned(
            f"could not confirm {origin!r} is thin-provisioned: unexpected output from `lvs --noheadings "
            f"-o lv_layout,pool_lv {origin}` ({lines!r}); refusing to create a snapshot."
        )

    def create_snapshot(self, qualified_name):
        # qualified_name is "<vg>/<lv>@<snapshot-name>" (origin + "@" + the LV name to actually create). Split
        # on "@", never on "/": the origin side already is the "vg/lv" lvcreate itself expects, and the
        # snapshot-name side is what becomes the new LV's own name -- never glued together with "@" in it.
        origin, _, snap_name = qualified_name.partition("@")
        self._require_thin(origin)
        subprocess.run(["lvcreate", "-s", "-n", snap_name, origin], check=True, timeout=30)


class Dir:
    """A directory of empty files standing in for snapshots: the dry-run backend, and the fixture every test
    in this kit uses. A "snapshot" is just a file named after its qualified identifier; nothing here ever
    shells out, touches ZFS/LVM, or needs root."""

    name = "dir"

    def __init__(self, root, dataset=None):
        self.root = root
        self.dataset = dataset
        os.makedirs(self.root, exist_ok=True)

    def usage_percent(self):
        marker = os.path.join(self.root, ".usage_percent")
        if os.path.exists(marker):
            with open(marker, encoding="utf-8") as f:
                return float(f.read().strip())
        return 0.0

    def set_usage_percent(self, value):
        """Test helper only (not used by the real backends): drive the simulated usage figure."""
        with open(os.path.join(self.root, ".usage_percent"), "w", encoding="utf-8") as f:
            f.write(str(value))

    def list_snapshot_names(self):
        return [n for n in os.listdir(self.root) if not n.startswith(".")]

    def create_snapshot(self, qualified_name):
        open(os.path.join(self.root, qualified_name), "w", encoding="utf-8").close()

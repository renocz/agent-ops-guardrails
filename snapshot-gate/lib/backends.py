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


class Lvm:
    """An LVM logical volume. `volume` is `vg/lv`, the origin volume the gate protects."""

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
        # Qualified as "vg/lv_name" so naming.qualified_pattern() can apply the same exact-match discipline as
        # the ZFS backend, keyed on the configured origin volume rather than a bare LV name that could collide
        # across volume groups.
        out = subprocess.run(["lvs", "--noheadings", "-o", "lv_name,origin", self.vg],
                              capture_output=True, text=True, check=True, timeout=10).stdout
        names = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == self.lv:
                names.append(f"{self.vg}/{parts[0]}")
        return names

    def create_snapshot(self, qualified_name):
        vg, lv_name = qualified_name.split("/", 1)
        subprocess.run(["lvcreate", "-s", "-n", lv_name, f"{vg}/{self.lv}"], check=True, timeout=30)


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

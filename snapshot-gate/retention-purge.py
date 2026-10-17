#!/usr/bin/env python3
"""retention-purge.py: delete snapshots this gate created, once they are older than retention_days.

    retention-purge.py /etc/snapshot-gate/config.json              dry run: prints what it would delete
    retention-purge.py /etc/snapshot-gate/config.json --apply       really deletes

This is the ONLY place in this kit that destroys anything, deliberately kept out of lib/backends.py and
snapshot-gate-host.py (see their own docstrings). A candidate is purged only if its full, qualified name
fullmatches naming.qualified_pattern(dataset, prefix) -- the dataset portion is matched exactly, not as a
string prefix, so `pool/agent-other` or a snapshot of a child dataset picked up by a recursive listing can never
be selected just because it starts the same way -- and only if the timestamp embedded in its own name (not a
separately queried creation time) is older than `retention_days`. Standard library only.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import config as config_lib                                      # noqa: E402
from lib import naming                                                    # noqa: E402


def destroy_zfs(qualified_name):
    subprocess.run(["zfs", "destroy", qualified_name], check=True, timeout=30)


def destroy_lvm(qualified_name):
    # qualified_name is "<vg>/<lv>@<snapshot-name>" (see lib/backends.py's Lvm docstrings). The volume group is
    # the first path segment of the origin side; lvremove takes "<vg>/<snapshot-name>", never the origin LV.
    origin, _, snap_name = qualified_name.partition("@")
    vg = origin.split("/", 1)[0]
    subprocess.run(["lvremove", "-f", f"{vg}/{snap_name}"], check=True, timeout=30)


def destroy_dir(qualified_name, root):
    os.remove(os.path.join(root, qualified_name))


DESTROYERS = {"zfs": lambda cfg, n: destroy_zfs(n), "lvm": lambda cfg, n: destroy_lvm(n),
              "dir": lambda cfg, n: destroy_dir(n, cfg["dir_backend_root"] or cfg["dataset"])}


def eligible_for_purge(backend, cfg):
    """[(qualified_name, age_days), ...] -- matches the strict pattern AND older than retention_days."""
    pattern = naming.qualified_pattern(cfg["dataset"], cfg["prefix"])
    retention = cfg["retention_days"]
    out = []
    for candidate in backend.list_snapshot_names():
        m = pattern.fullmatch(candidate)
        if not m:
            continue                                     # foreign name, or a different dataset: never selected
        try:
            age = naming.age_days(m)
        except ValueError:
            continue                           # shape matches (8 digits, 6 digits) but not a real calendar date
        if age > retention:
            out.append((candidate, age))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    apply = "--apply" in argv
    args = [a for a in argv if a != "--apply"]
    if not args:
        print("usage: retention-purge.py CONFIG.json [--apply]", file=sys.stderr)
        return 2
    cfg = config_lib.load(args[0])
    backend = config_lib.make_backend(cfg)
    targets = eligible_for_purge(backend, cfg)
    if not targets:
        print("nothing eligible for purge")
        return 0
    destroy = DESTROYERS[cfg["backend"]]
    for name, age in sorted(targets):
        if apply:
            destroy(cfg, name)
            print(f"deleted: {name} ({age:.1f} days old)")
        else:
            print(f"would delete: {name} ({age:.1f} days old)")
    if not apply:
        print(f"-- dry run: {len(targets)} snapshot(s) would be deleted. Re-run with --apply to really delete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Shared config loading for snapshot-gate-host.py and retention-purge.py. Standard library only."""
import json

DEFAULTS = {
    "backend": "dir",                  # "zfs" | "lvm" | "dir" (the dry-run / test fixture backend)
    "dataset": "",                     # zfs dataset, or "vg/lv" for lvm, or a plain label for "dir"
    "dir_backend_root": "",            # "dir" backend only: the directory standing in for the snapshot store
    "prefix": "agent-gate",
    "usage_threshold_percent": 85,
    "cooldown_minutes": 10,
    "retention_days": 7,
    "requests_dir": "",
    "states_dir": "",
    "lock_file": "",
    "log_file": "",
}
REQUIRED = ("dataset", "requests_dir", "states_dir", "lock_file", "log_file")


def load(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    merged = dict(DEFAULTS)
    merged.update(cfg)
    missing = [k for k in REQUIRED if not merged.get(k)]
    if missing:
        raise ValueError(f"config {path} is missing required field(s): {', '.join(missing)}")
    if merged["backend"] not in ("zfs", "lvm", "dir"):
        raise ValueError(f"config {path}: unknown backend {merged['backend']!r}")
    return merged


def make_backend(cfg):
    # Imported here, not at module load, so a host with neither zfs nor lvm installed can still import this
    # module freely (only backends.py itself needs no external command; the subprocess calls are deferred to
    # when a backend method actually runs).
    from . import backends
    if cfg["backend"] == "zfs":
        return backends.Zfs(cfg["dataset"])
    if cfg["backend"] == "lvm":
        return backends.Lvm(cfg["dataset"])
    root = cfg["dir_backend_root"] or cfg["dataset"]
    return backends.Dir(root, dataset=cfg["dataset"])

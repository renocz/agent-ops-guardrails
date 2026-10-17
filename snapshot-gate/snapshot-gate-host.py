#!/usr/bin/env python3
"""snapshot-gate-host.py: the host side of the create-only snapshot gate.

    snapshot-gate-host.py /etc/snapshot-gate/config.json

Triggered by a path unit / WatchPaths job (see templates/) when a file appears in `requests_dir`, or run by
hand/cron as a fallback. For every pending `*.request` file (its content is NEVER read: existence is the whole
request), under a lock so only one run is ever active:

  1. refuse if the backend's usage is above `usage_threshold_percent`;
  2. refuse if a snapshot younger than `cooldown_minutes` already exists (its name is returned instead);
  3. otherwise create one, named `<prefix>-YYYYMMDD-HHMMSS`.

Writes the result to `<id>.state` next to the request's `<id>.request`, then removes the request file. This
file has NO rollback or destroy code path at all -- grep it and lib/backends.py for "destroy"/"remove"/
"rollback" and the only hits are this sentence and the retention-purge script, which is separate on purpose.
Standard library only.
"""
import datetime
import glob
import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import config as config_lib                                      # noqa: E402
from lib import naming                                                    # noqa: E402

try:
    import fcntl
except ImportError:                                                        # pragma: no cover (POSIX-only tool)
    fcntl = None


class _NoLock:
    """Used when a lock can't be taken (fcntl unavailable, or --no-lock for a test): never refuses to run."""

    def acquired(self):
        return True


class _FileLock:
    def __init__(self, path):
        self._fh = open(path, "w", encoding="utf-8")                       # noqa: SIM115 (kept open for the flock)
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._ok = True
        except OSError:
            self._ok = False

    def acquired(self):
        return self._ok

    def __del__(self):
        try:
            self._fh.close()
        except Exception:
            pass


def acquire_lock(path):
    if fcntl is None:
        return _NoLock()
    return _FileLock(path)


def log(log_file, message):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{ts} {message}\n")


def write_state(states_dir, request_id, status, reason="", name=""):
    path = os.path.join(states_dir, f"{request_id}.state")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(f"status={shlex.quote(status)}\n")
        f.write(f"reason={shlex.quote(reason)}\n")
        f.write(f"name={shlex.quote(name)}\n")
    os.replace(tmp, path)                                                  # atomic: never a half-written state


def decide_and_create(backend, cfg):
    """The only policy that matters here: refuse on usage, refuse on cooldown, otherwise create. Returns
    (status, reason, name). Never destroys, never rolls back -- there is no code path in this function, or
    anywhere else in this file, that could."""
    usage = backend.usage_percent()
    threshold = cfg["usage_threshold_percent"]
    if usage > threshold:
        return "REFUSED", f"pool/volume usage {usage:.1f}% is above the {threshold}% threshold", ""

    pattern = naming.qualified_pattern(cfg["dataset"], cfg["prefix"])
    matches = [(n, m) for n in backend.list_snapshot_names() for m in [pattern.fullmatch(n)] if m]
    cooldown = cfg["cooldown_minutes"]

    def age_or_none(m):
        try:
            return naming.age_minutes(m)
        except ValueError:
            return None                        # shape matches but not a real calendar date; never blocks on it

    ages = [(n, m, age_or_none(m)) for n, m in matches]
    too_recent = [(n, m) for n, m, age in ages if age is not None and age < cooldown]
    if too_recent:
        newest = min(too_recent, key=lambda nm: naming.age_minutes(nm[1]))
        return ("REFUSED", f"a snapshot younger than {cooldown} minutes already exists", newest[0])

    name = f"{cfg['dataset']}@{naming.new_name(cfg['prefix'])}"
    backend.create_snapshot(name)
    return "OK", "", name


def process_pending(cfg, backend):
    # Lexical order, not mtime: request-snapshot.sh's id starts with a timestamp, so this is already time order
    # in practice, and it is deterministic even when two requests land in the same mtime tick (a real
    # possibility -- many filesystems only keep whole-second resolution).
    pending = sorted(glob.glob(os.path.join(cfg["requests_dir"], "*.request")))
    for req_path in pending:
        request_id = os.path.basename(req_path)[: -len(".request")]
        status, reason, name = decide_and_create(backend, cfg)
        write_state(cfg["states_dir"], request_id, status, reason, name)
        try:
            os.remove(req_path)
        except FileNotFoundError:
            pass
        log(cfg["log_file"], f"request={request_id} status={status} reason={reason!r} name={name!r}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: snapshot-gate-host.py CONFIG.json", file=sys.stderr)
        return 2
    cfg = config_lib.load(argv[0])
    os.makedirs(cfg["requests_dir"], exist_ok=True)
    os.makedirs(cfg["states_dir"], exist_ok=True)
    lock = acquire_lock(cfg["lock_file"])
    if not lock.acquired():
        return 0                                   # another run is active; the next trigger will catch up
    backend = config_lib.make_backend(cfg)
    process_pending(cfg, backend)
    return 0


if __name__ == "__main__":
    sys.exit(main())

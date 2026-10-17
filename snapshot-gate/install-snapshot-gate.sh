#!/bin/bash
# install-snapshot-gate.sh: install snapshot-gate-host, retention-purge, request-snapshot.sh and their config.
#
#   ./install-snapshot-gate.sh --agent-user you --dataset pool0/agent-data          dry run: prints what it would
#                                                                                   do (default)
#   ./install-snapshot-gate.sh --agent-user you --dataset pool0/agent-data \
#       --prefix /tmp/sg                                  writes the files under /tmp/sg, no users, no chown
#   sudo ./install-snapshot-gate.sh --agent-user you --dataset pool0/agent-data --apply   really installs (root)
#
# Options: --backend zfs|lvm (default zfs); --snapshot-prefix NAME (default agent-gate, the name prefix used in
# every snapshot this gate creates); --usage-threshold PERCENT (default 85); --cooldown-minutes N (default 10);
# --retention-days N (default 7).
#
# This installer does NOT enable any trigger (systemd path unit / launchd WatchPaths job): copy the template
# from templates/ yourself, fill in its placeholders, and enable it by hand. See the README.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODE=dry PREFIX="" AGENT="" DATASET="" BACKEND=zfs SNAP_PREFIX=agent-gate
USAGE_THRESHOLD=85 COOLDOWN_MINUTES=10 RETENTION_DAYS=7
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) MODE=apply ;;
    --prefix) MODE=prefix; PREFIX="${2%/}"; shift ;;
    --agent-user) AGENT="$2"; shift ;;
    --dataset) DATASET="$2"; shift ;;
    --backend) BACKEND="$2"; shift ;;
    --snapshot-prefix) SNAP_PREFIX="$2"; shift ;;
    --usage-threshold) USAGE_THRESHOLD="$2"; shift ;;
    --cooldown-minutes) COOLDOWN_MINUTES="$2"; shift ;;
    --retention-days) RETENTION_DAYS="$2"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$AGENT" ] && [ -n "$DATASET" ] || { echo "need --agent-user and --dataset" >&2; exit 2; }
case "$BACKEND" in zfs|lvm) ;; *) echo "--backend must be zfs or lvm" >&2; exit 2 ;; esac
[ "$AGENT" != root ] || { echo "refusing: the agent must not be root (same precondition as the keeper)" >&2; exit 2; }

OS=$(uname -s)
if [ "$OS" = Darwin ]; then GUSER=snapshot-gate; ROOTGRP=wheel; else GUSER=snapshot-gate; ROOTGRP=root; fi
BASE=/opt/agent-guardrails
LIB=$BASE/lib BIN=$BASE/bin
CONF_DIR=/etc/snapshot-gate
STATE_DIR=/var/lib/snapshot-gate

run() {
  case "$MODE" in
    dry) printf '  would run: %s\n' "$*" ;;
    prefix) printf '  skipped (prefix mode): %s\n' "$*" ;;
    apply) "$@" ;;
  esac
}
put() {                       # put <dest> <mode> <owner:group> <source-file>
  local dest="$1" mode="$2" own="$3" src="$4"
  case "$MODE" in
    dry) printf '  would write: %s (%s %s)\n' "$dest" "$mode" "$own" ;;
    prefix) mkdir -p "$(dirname "$PREFIX$dest")"; install -m "$mode" "$src" "$PREFIX$dest"
            printf '  wrote: %s%s\n' "$PREFIX" "$dest" ;;
    apply) mkdir -p "$(dirname "$dest")"; install -m "$mode" -o "${own%%:*}" -g "${own##*:}" "$src" "$dest"
           printf '  installed: %s\n' "$dest" ;;
  esac
}
mkd() {                       # mkd <dir> <mode> <owner:group>
  case "$MODE" in
    dry) printf '  would create: %s/ (%s %s)\n' "$1" "$2" "$3" ;;
    prefix) mkdir -p "$PREFIX$1" ;;
    apply) install -d -m "$2" -o "${3%%:*}" -g "${3##*:}" "$1" ;;
  esac
}

[ "$MODE" != apply ] || [ "$(id -u)" = 0 ] || { echo "--apply needs root (sudo)" >&2; exit 2; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== snapshot-gate install ($MODE) on $OS for agent user $AGENT, backend $BACKEND, dataset $DATASET"

echo "-- 1. user/group $GUSER (members: $AGENT, $GUSER) -- agent can write requests, read states; cannot write states"
if [ "$OS" = Darwin ]; then
  dscl . -read "/Groups/$GUSER" >/dev/null 2>&1 || run dseditgroup -o create "$GUSER"
  dscl . -read "/Users/$GUSER" >/dev/null 2>&1 || run dscl . -create "/Users/$GUSER" UserShell /usr/bin/false
  run dseditgroup -o edit -a "$AGENT" -t user "$GUSER"
else
  getent group "$GUSER" >/dev/null || run groupadd --system "$GUSER"
  id "$GUSER" >/dev/null 2>&1 || run useradd --system --user-group --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin "$GUSER"
  run usermod -a -G "$GUSER" "$AGENT"
fi

echo "-- 2. root-owned code in $LIB/snapshot-gate"
SG_LIB="$LIB/snapshot-gate"
mkd "$BASE" 755 "root:$ROOTGRP"
mkd "$LIB" 755 "root:$ROOTGRP"
mkd "$SG_LIB" 755 "root:$ROOTGRP"
mkd "$SG_LIB/lib" 755 "root:$ROOTGRP"
mkd "$BIN" 755 "root:$ROOTGRP"
for f in "$HERE/snapshot-gate-host.py" "$HERE/retention-purge.py"; do
  put "$SG_LIB/$(basename "$f")" 644 "root:$ROOTGRP" "$f"
done
for f in "$HERE/lib/__init__.py" "$HERE/lib/backends.py" "$HERE/lib/config.py" "$HERE/lib/naming.py"; do
  put "$SG_LIB/lib/$(basename "$f")" 644 "root:$ROOTGRP" "$f"
done
put "$BIN/request-snapshot.sh" 755 "root:$ROOTGRP" "$HERE/request-snapshot.sh"

echo "-- 3. config and directories"
python3 - "$BACKEND" "$DATASET" "$SNAP_PREFIX" "$USAGE_THRESHOLD" "$COOLDOWN_MINUTES" "$RETENTION_DAYS" \
  "$STATE_DIR" > "$TMP/config.json" <<'PYEOF'
import json, sys
backend, dataset, prefix, usage, cooldown, retention, state_dir = sys.argv[1:]
print(json.dumps({
    "backend": backend, "dataset": dataset, "prefix": prefix,
    "usage_threshold_percent": int(usage), "cooldown_minutes": int(cooldown), "retention_days": int(retention),
    "requests_dir": state_dir + "/requests", "states_dir": state_dir + "/states",
    "lock_file": state_dir + "/run.lock", "log_file": state_dir + "/snapshot-gate.log",
}, indent=1))
PYEOF
mkd "$CONF_DIR" 755 "root:$ROOTGRP"
put "$CONF_DIR/config.json" 644 "root:$ROOTGRP" "$TMP/config.json"
mkd "$STATE_DIR" 750 "root:$GUSER"
mkd "$STATE_DIR/requests" 770 "root:$GUSER"              # the agent (group member) writes requests here
mkd "$STATE_DIR/states" 750 "root:$GUSER"                 # only the gate (root-run) writes states; agent reads

echo "-- 4. after install"
cat <<EOF
   - This installer does NOT enable a trigger. Copy templates/snapshot-gate.path and
     templates/snapshot-gate.service (Linux) or templates/com.example.snapshot-gate.plist (macOS) to their real
     locations, fill in the placeholders, and enable them yourself:
       Linux:  cp templates/snapshot-gate.{path,service} /etc/systemd/system/ && systemctl daemon-reload && \\
               systemctl enable --now snapshot-gate.path
       macOS:  cp templates/com.example.snapshot-gate.plist /Library/LaunchDaemons/ && \\
               launchctl bootstrap system /Library/LaunchDaemons/com.example.snapshot-gate.plist
   - The agent requests with: $BIN/request-snapshot.sh $STATE_DIR/requests $STATE_DIR/states [timeout_seconds]
   - Retention purge runs separately, e.g. from cron: python3 -I $SG_LIB/retention-purge.py $CONF_DIR/config.json --apply
   - Check as $AGENT, each must FAIL: write a file into $STATE_DIR/states; read $STATE_DIR/run.lock and rewrite
     it; run retention-purge.py directly (it needs $SG_LIB owned by root, which $AGENT cannot write to make it
     executable as itself, and the config/state paths are not agent-writable either).
EOF
[ "$MODE" = apply ] || echo "== nothing was installed ($MODE). Re-run with --apply (as root) to install."

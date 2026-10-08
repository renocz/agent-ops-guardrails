#!/bin/bash
# install-keeper.sh: install keeperd, its hook and the managed settings (design: docs/design-keeper.md).
#
#   ./install-keeper.sh --agent-user renocz --owner-id 12345            dry run: prints what it would do (default)
#   ./install-keeper.sh --agent-user renocz --owner-id 12345 --prefix /tmp/k   writes the files under /tmp/k, no users,
#                                                                       no service, no chown (to inspect the result)
#   sudo ./install-keeper.sh --agent-user renocz --owner-id 12345 --apply      really installs (needs root)
#
# The keeper bot's token is never passed on the command line: with --apply, the script asks for it on the terminal
# (hidden input) if /etc/keeper/bot.token does not exist yet.
# Precondition: the agent user is not root and cannot sudo without a password it does not have.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
MODE=dry PREFIX="" AGENT="" OWNER="" CHAT="" GATE_MODE=block
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) MODE=apply ;;
    --prefix) MODE=prefix; PREFIX="${2%/}"; shift ;;
    --agent-user) AGENT="$2"; shift ;;
    --owner-id) OWNER="$2"; shift ;;
    --chat-id) CHAT="$2"; shift ;;
    --observe) GATE_MODE=observe ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$AGENT" ] && [ -n "$OWNER" ] || { echo "need --agent-user and --owner-id" >&2; exit 2; }
[[ "$OWNER" =~ ^[0-9]+$ ]] || { echo "--owner-id must be a Telegram numeric id" >&2; exit 2; }
CHAT="${CHAT:-$OWNER}"
[ "$AGENT" != root ] || { echo "refusing: the agent must not be root (see the design's precondition)" >&2; exit 2; }
id "$AGENT" >/dev/null 2>&1 || { echo "no such user: $AGENT" >&2; exit 2; }
AGENT_UID=$(id -u "$AGENT")
AGENT_HOME=$(/usr/bin/python3 -c 'import pwd, sys; print(pwd.getpwnam(sys.argv[1]).pw_dir)' "$AGENT")

OS=$(uname -s)
if [ "$OS" = Darwin ]; then
  KUSER=_keeper; GROUP=keeperclients; ROOTGRP=wheel
  RUN_DIR=/usr/local/var/keeper
  MANAGED="/Library/Application Support/ClaudeCode/managed-settings.json"
  SERVICE=/Library/LaunchDaemons/io.github.renocz.keeper.plist
else
  KUSER=keeper; GROUP=keeperclients; ROOTGRP=root
  RUN_DIR=/run/keeper
  MANAGED=/etc/claude-code/managed-settings.json
  SERVICE=/etc/systemd/system/keeper.service
fi
LIB=/usr/local/lib/agent-guardrails
PY=/usr/bin/python3
HOOK_CMD="/usr/bin/env -i $PY -I $LIB/keeper_client.py"

run() {                       # dry: print; prefix: skip (only file writes happen); apply: run
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

echo "== keeper install ($MODE) on $OS for agent user $AGENT (uid $AGENT_UID)"

echo "-- 1. user $KUSER and group $GROUP (members: $AGENT, $KUSER)"
if [ "$OS" = Darwin ]; then
  dscl . -read "/Groups/$GROUP" >/dev/null 2>&1 || run dseditgroup -o create "$GROUP"
  KGID=$(dscl . -read "/Groups/$GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}' || true)
  KGID=${KGID:-"<gid of $GROUP>"}          # dry run: the group does not exist yet
  if ! dscl . -read "/Users/$KUSER" >/dev/null 2>&1; then
    KUID=$(for i in $(seq 450 499); do dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$i" || { echo "$i"; break; }; done)
    run dscl . -create "/Users/$KUSER"
    run dscl . -create "/Users/$KUSER" UniqueID "$KUID"
    run dscl . -create "/Users/$KUSER" PrimaryGroupID "$KGID"     # not staff: the agent's user is in staff
    run dscl . -create "/Users/$KUSER" UserShell /usr/bin/false
    run dscl . -create "/Users/$KUSER" NFSHomeDirectory /var/empty
    run dscl . -create "/Users/$KUSER" IsHidden 1
  fi
  run dseditgroup -o edit -a "$AGENT" -t user "$GROUP"
  run dseditgroup -o edit -a "$KUSER" -t user "$GROUP"
else
  getent group "$GROUP" >/dev/null || run groupadd --system "$GROUP"
  id "$KUSER" >/dev/null 2>&1 || run useradd --system --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin --gid "$GROUP" "$KUSER"
  run usermod -a -G "$GROUP" "$AGENT"
fi

echo "-- 2. root-owned code in $LIB (the agent cannot edit it)"
for f in "$HERE/keeperd.py" "$HERE/keeper_client.py" "$REPO/go-gate/go_gate.py" "$REPO/secret-guard/secret_guard.py"; do
  put "$LIB/$(basename "$f")" 644 "root:$ROOTGRP" "$f"
done
printf '#!/bin/sh\nexec /usr/bin/env -i %s -I %s/keeper_client.py propose "$@"\n' "$PY" "$LIB" > "$TMP/keeper-propose"
printf '#!/bin/sh\nexec /usr/bin/env -i %s -I %s/keeper_client.py status\n' "$PY" "$LIB" > "$TMP/keeper-status"
put /usr/local/bin/keeper-propose 755 "root:$ROOTGRP" "$TMP/keeper-propose"
put /usr/local/bin/keeper-status 755 "root:$ROOTGRP" "$TMP/keeper-status"

echo "-- 3. config, state and socket directory"
"$PY" - "$OWNER" "$CHAT" "$AGENT_UID" "$AGENT_HOME" "$GROUP" "$RUN_DIR" "$GATE_MODE" > "$TMP/config.json" <<'PYEOF'
import json, sys
o, c, uid, home, grp, run, mode = sys.argv[1:]
print(json.dumps({"owner_id": int(o), "chat_id": int(c), "agent_uids": [int(uid)], "agent_home": home,
                  "client_group": grp, "socket": run + "/keeper.sock", "state_dir": "/var/lib/keeper",
                  "bot_token_file": "/etc/keeper/bot.token", "mode": mode}, indent=1))
PYEOF
mkd /etc/keeper 750 "root:$KUSER"
put /etc/keeper/config.json 640 "root:$KUSER" "$TMP/config.json"
mkd /var/lib/keeper 700 "$KUSER:$GROUP"
[ "$OS" = Darwin ] && mkd "$RUN_DIR" 750 "$KUSER:$GROUP"
if [ "$MODE" = apply ] && [ ! -s /etc/keeper/bot.token ]; then
  echo "   Paste the keeper bot's token (from BotFather; input hidden), then Enter:"
  IFS= read -rs TOKEN < /dev/tty
  ( umask 077; printf '%s' "$TOKEN" > /etc/keeper/bot.token )
  unset TOKEN
  chown "$KUSER" /etc/keeper/bot.token; chmod 400 /etc/keeper/bot.token
  echo "   token stored in /etc/keeper/bot.token (readable by $KUSER only)"
else
  echo "   bot token: /etc/keeper/bot.token (400, $KUSER); asked on the terminal with --apply"
fi

echo "-- 4. service"
if [ "$OS" = Darwin ]; then
  cat > "$TMP/svc" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.github.renocz.keeper</string>
  <key>UserName</key><string>$KUSER</string>
  <key>GroupName</key><string>$GROUP</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>-I</string><string>$LIB/keeperd.py</string><string>/etc/keeper/config.json</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/lib/keeper/stderr.log</string>
</dict></plist>
EOF
  put "$SERVICE" 644 "root:wheel" "$TMP/svc"
  run launchctl bootstrap system "$SERVICE"
else
  cat > "$TMP/svc" <<EOF
[Unit]
Description=keeper: human approvals for the coding agent (agent-ops-guardrails)
After=network-online.target
Wants=network-online.target

[Service]
User=$KUSER
Group=$GROUP
ExecStart=$PY -I $LIB/keeperd.py /etc/keeper/config.json
Restart=always
RestartSec=5
RuntimeDirectory=keeper
RuntimeDirectoryMode=0750
StateDirectory=keeper
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/var/lib/keeper

[Install]
WantedBy=multi-user.target
EOF
  put "$SERVICE" 644 "root:root" "$TMP/svc"
  run systemctl daemon-reload
  run systemctl enable --now keeper.service
fi

echo "-- 5. Claude Code managed settings: $MANAGED"
"$PY" - "$HOOK_CMD" "$LIB" > "$TMP/managed.json" <<'PYEOF'
import json, sys
cmd, lib = sys.argv[1:]
deny = [f"{t}({p})" for t in ("Edit", "Write") for p in (lib + "/**", "/etc/keeper/**", "/var/lib/keeper/**")]
print(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd}]}]},
                  "permissions": {"deny": deny}}, indent=1))
PYEOF
if [ -e "${PREFIX}$MANAGED" ] || { [ "$MODE" != prefix ] && [ -e "$MANAGED" ]; }; then
  echo "   $MANAGED already exists: not touched. Merge this into it by hand:"
  sed 's/^/     /' "$TMP/managed.json"
else
  put "$MANAGED" 644 "root:$ROOTGRP" "$TMP/managed.json"
fi

echo "-- 6. after install"
cat <<EOF
   - Remove go-gate's own PreToolUse/Stop/UserPromptSubmit hook from ~/.claude/settings.json (keeper replaces it).
   - Check as $AGENT, each must FAIL: write /var/lib/keeper/state.json; edit $LIB/keeperd.py; kill keeperd;
     send {"op":"approve"} to the socket; set "disableAllHooks": true in ~/.claude/settings.json and see whether the
     managed hook still runs (it must).
   - Start in --observe for a day if you want only logs, then block mode for a week before v1.0.
EOF
[ "$MODE" = apply ] || echo "== nothing was installed ($MODE). Re-run with --apply (as root) to install."

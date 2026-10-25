#!/bin/bash
# install-docker-proxy.sh: install docker-proxyd, its socket and the dedicated dockerproxy account
# (design: docs/design-keeper-server.md, section 1, option C).
#
#   ./install-docker-proxy.sh --agent-user you --container web            dry run: prints what it would do (default)
#   ./install-docker-proxy.sh --agent-user you --container web --prefix /tmp/dp   writes the files under /tmp/dp,
#                                                                          no users, no group, no service (to inspect)
#   sudo ./install-docker-proxy.sh --agent-user you --container web --apply        really installs (needs root)
#
# --container NAME is repeatable: each one is added, verbatim, to write_allow.containers in the installed config.
# Only a literal container name is accepted here too (same rule the daemon itself enforces at load time) --
# this refuses a wildcard/regex attempt before it ever reaches a config file.
#
# What --apply does, and why:
#   - creates a dedicated system user `dockerproxy` (no login, no home) and adds it -- and ONLY it -- to the real
#     `docker` group. The agent user is never added to `docker`: that group is root-equivalent (see the design
#     doc), so putting the agent there would defeat the entire point of this kit.
#   - creates a narrow group (--group, default docker-proxy-clients) that is NOT docker-equivalent, and adds both
#     the agent user and dockerproxy to it: dockerproxy so it can hand the socket file to that group, the agent so
#     it can connect to it.
#   - installs docker_proxyd.py and docker_proxy_client.py read-only (root:root 644) and a thin wrapper
#     /opt/agent-guardrails/bin/docker-proxy (root:root 755) the agent actually runs.
#   - installs /etc/docker-proxy/config.json (root:dockerproxy 640) from the --container arguments.
#   - installs and enables a systemd unit running docker_proxyd.py as User=dockerproxy Group=<group>.
#
# Linux/systemd only: this kit is server-scoped by design (the threat model in docs/design-keeper-server.md is the
# LXC/server case, not a laptop with Docker Desktop), so this installer does not try to guess a macOS equivalent.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NAME_RE='^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$'

MODE=dry PREFIX="" AGENT="" GROUP=docker-proxy-clients SOCKET=/run/docker-proxy/docker-proxy.sock
CONFIG=/etc/docker-proxy/config.json
CONTAINERS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) MODE=apply ;;
    --prefix) MODE=prefix; PREFIX="${2%/}"; shift ;;
    --agent-user) AGENT="$2"; shift ;;
    --container) CONTAINERS+=("$2"); shift ;;          # repeatable; exact container name, no wildcard
    --group) GROUP="$2"; shift ;;
    --socket) SOCKET="$2"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -n "$AGENT" ] || { echo "need --agent-user" >&2; exit 2; }
[ "$AGENT" != root ] || { echo "refusing: the agent must not be root (see the design's precondition)" >&2; exit 2; }
for c in "${CONTAINERS[@]:-}"; do
  [ -z "$c" ] && continue
  [[ "$c" =~ $NAME_RE ]] || { echo "refusing: --container '$c' is not a literal container name (no wildcards/regex)" >&2; exit 2; }
done

CONFIG_JSON=$(python3 -c '
import json, sys
print(json.dumps({"write_allow": {"containers": sys.argv[1:]}}, indent=2))
' "${CONTAINERS[@]:-}")

plan() {
  echo "== docker-proxy install plan (mode: $MODE) =="
  echo "agent user:        $AGENT (added to group $GROUP, NEVER to docker)"
  echo "dockerproxy user:  dedicated system account, member of docker AND $GROUP"
  echo "socket:            $SOCKET (mode 0660, group $GROUP)"
  echo "config:            $CONFIG"
  echo "$CONFIG_JSON"
  echo "files:             /opt/agent-guardrails/lib/docker_proxyd.py"
  echo "                   /opt/agent-guardrails/lib/docker_proxy_client.py"
  echo "                   /opt/agent-guardrails/bin/docker-proxy (wrapper the agent runs)"
  echo "service:           systemd unit docker-proxy.service, User=dockerproxy Group=$GROUP"
}

case "$MODE" in
  dry)
    plan
    echo
    echo "Dry run only: nothing was written. Re-run with --apply (as root) to install for real,"
    echo "or with --prefix DIR to write the files under DIR for inspection."
    exit 0
    ;;
  prefix)
    plan
    mkdir -p "$PREFIX/opt/agent-guardrails/lib" "$PREFIX/opt/agent-guardrails/bin" "$PREFIX/etc/docker-proxy" "$PREFIX/etc/systemd/system"
    install -m 644 "$HERE/docker_proxyd.py" "$PREFIX/opt/agent-guardrails/lib/docker_proxyd.py"
    install -m 644 "$HERE/docker_proxy_client.py" "$PREFIX/opt/agent-guardrails/lib/docker_proxy_client.py"
    cat > "$PREFIX/opt/agent-guardrails/bin/docker-proxy" <<EOF
#!/bin/sh
exec /usr/bin/env -i /usr/bin/python3 -I /opt/agent-guardrails/lib/docker_proxy_client.py "\$@"
EOF
    chmod 755 "$PREFIX/opt/agent-guardrails/bin/docker-proxy"
    echo "$CONFIG_JSON" > "$PREFIX/etc/docker-proxy/config.json"
    echo
    echo "Files written under $PREFIX for inspection. No user, group or service was touched."
    exit 0
    ;;
esac

# --apply: real install, needs root
[ "$(id -u)" = 0 ] || { echo "refusing: --apply needs root (use sudo)" >&2; exit 2; }
id "$AGENT" >/dev/null 2>&1 || { echo "no such user: $AGENT" >&2; exit 2; }
if id -nG "$AGENT" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  echo "WARNING: $AGENT is already in the docker group. This installer will NOT remove that membership" >&2
  echo "         (removing a user from a group is a separate operational decision). Until you remove it" >&2
  echo "         yourself, $AGENT keeps root-equivalent access regardless of this proxy." >&2
fi

plan
echo
echo "Applying..."

getent group docker >/dev/null 2>&1 || { echo "refusing: no 'docker' group on this host (is Docker installed?)" >&2; exit 2; }
id dockerproxy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin dockerproxy
getent group "$GROUP" >/dev/null 2>&1 || groupadd --system "$GROUP"
usermod -aG docker dockerproxy
usermod -aG "$GROUP" dockerproxy
usermod -aG "$GROUP" "$AGENT"

install -d -m 755 /opt/agent-guardrails/lib /opt/agent-guardrails/bin
install -m 644 "$HERE/docker_proxyd.py" /opt/agent-guardrails/lib/docker_proxyd.py
install -m 644 "$HERE/docker_proxy_client.py" /opt/agent-guardrails/lib/docker_proxy_client.py
cat > /opt/agent-guardrails/bin/docker-proxy <<'EOF'
#!/bin/sh
exec /usr/bin/env -i /usr/bin/python3 -I /opt/agent-guardrails/lib/docker_proxy_client.py "$@"
EOF
chmod 755 /opt/agent-guardrails/bin/docker-proxy

install -d -m 750 -o root -g dockerproxy /etc/docker-proxy
echo "$CONFIG_JSON" > "$CONFIG"
chown root:dockerproxy "$CONFIG"
chmod 640 "$CONFIG"

cat > /etc/systemd/system/docker-proxy.service <<EOF
[Unit]
Description=docker-proxy: filtered docker access for a non-root agent
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=dockerproxy
Group=$GROUP
# Group= replaces the PRIMARY group of dockerproxy in the process, and $CONFIG is root:dockerproxy 640: without this line the daemon
# cannot read its own config (PermissionError, restart loop). Found by the first real install on Debian 12, 25/10/2026.
SupplementaryGroups=dockerproxy
RuntimeDirectory=docker-proxy
RuntimeDirectoryMode=0750
# DOCKER_CONFIG is given inside the env -i command (an Environment= line would be wiped by env -i): with ProtectHome=true the docker CLI
# cannot read ~/.docker/config.json and prints a warning that gets mixed into the output (a JSON inspect is then not valid JSON).
ExecStart=/usr/bin/env -i DOCKER_CONFIG=/run/docker-proxy /usr/bin/python3 -I /opt/agent-guardrails/lib/docker_proxyd.py --config $CONFIG --socket $SOCKET
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now docker-proxy.service

echo
echo "Installed. $AGENT can now run: docker-proxy ps / logs <name> / inspect <name> / stats <name> / top <name>"
echo "and docker-proxy restart|start|stop <name> for a name listed in $CONFIG."
echo "$AGENT must log out and back in (or run 'newgrp $GROUP') for the new group membership to take effect."

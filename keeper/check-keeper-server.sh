#!/bin/bash
# check-keeper-server.sh: read-only verification of a server install (docs/deploy-keeper-server.md).
#
#   keeper/check-keeper-server.sh
#   keeper/check-keeper-server.sh --container app-example --container-with-healthcheck app-example-2
#
# This script NEVER writes, creates, deletes, or renames anything, and never starts/stops/restarts a service or a
# container. Every command it runs is a read: `id`, `getent`, `stat`, `systemctl is-active`/`is-enabled`,
# `journalctl -n` (read), `docker version`/`inspect`/`top`/`stats` (read-only docker subcommands), `sudo -l -U`
# (a dry query -- "would this be allowed", never executes the command it asks about), and `python3 -m json.tool`
# to validate JSON. If you can find a code path below that writes anything, that is a bug in this script, not a
# feature -- report it instead of routing around it with --apply or similar.
#
# Safe to run before anything in docs/deploy-keeper-server.md is installed: every check that depends on a user,
# file, socket, or service that does not exist yet reports SKIP with a reason, not a crash and not a FAIL. Run it
# again after each section of that guide to see what changed.
#
# Exit code: 0 if nothing FAILed (PASS/WARN/SKIP are all fine to see on a partial install), 1 if anything FAILed.
# Intentionally not `set -e`: a FAIL here is a finding to print and move past, not a reason to stop checking.
set -uo pipefail

AGENT_USER="" CONTAINER_PLAIN="" CONTAINER_HEALTHCHECK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --agent-user) AGENT_USER="$2"; shift ;;
    --container) CONTAINER_PLAIN="$2"; shift ;;                   # a real container with NO healthcheck configured
    --container-with-healthcheck) CONTAINER_HEALTHCHECK="$2"; shift ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

PASS=0 WARN=0 FAIL=0 SKIP=0
pass() { printf '[PASS] %s\n' "$*"; PASS=$((PASS+1)); }
warn() { printf '[WARN] %s\n' "$*"; WARN=$((WARN+1)); }
fail() { printf '[FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '[SKIP] %s (%s)\n' "$1" "$2"; SKIP=$((SKIP+1)); }
section() { printf '\n== %s ==\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" = 0 ]; }

CONFIG=/etc/keeper/config.json
DP_CONFIG=/etc/docker-proxy/config.json
DP_CLIENT=/opt/agent-guardrails/bin/docker-proxy      # this kit's own wrapper, installed by install-docker-proxy.sh

# Docker Engine itself ships an unrelated binary ALSO named `docker-proxy` (its userland port-forwarding helper,
# found on this very host at /usr/bin/docker-proxy) -- a real PATH collision with this kit's own client of the
# same name, found by running this script, not assumed. `command -v docker-proxy` can silently resolve to
# Docker's helper instead of ours depending on PATH order. Always resolve against the fixed install path below,
# never a bare `docker-proxy` from PATH, and warn once if PATH itself is ambiguous.
dp_client() {
  if [ -x "$DP_CLIENT" ]; then
    printf '%s' "$DP_CLIENT"
    return 0
  fi
  return 1
}
if have docker-proxy; then
  ON_PATH=$(command -v docker-proxy)
  if [ "$ON_PATH" != "$DP_CLIENT" ]; then
    warn "a 'docker-proxy' binary on PATH ($ON_PATH) is NOT this kit's client ($DP_CLIENT) -- likely Docker Engine's own, same-named userland-proxy helper; make sure the agent's PATH resolves 'docker-proxy' to $DP_CLIENT, not this one"
  fi
fi

echo "keeper/check-keeper-server.sh -- read-only, write nothing, start/stop/restart nothing"
if ! is_root; then
  warn "not running as root: checks that read /etc/keeper (750, root:keeper) and sudoers will SKIP, not FAIL. Re-run with sudo for a complete pass."
fi

# ---------------------------------------------------------------------------------------------------------------
section "1. Users and groups (docs/deploy-keeper-server.md §1, §2, §4)"

check_user() {
  local user="$1" label="$2"
  if id "$user" >/dev/null 2>&1; then
    local uid; uid=$(id -u "$user")
    pass "$label: user '$user' exists (uid $uid)"
    return 0
  else
    skip "$label: user '$user'" "not created yet"
    return 1
  fi
}
check_user keeper-agent "shared agent user (interactive + morning job)" || true
check_user keeper-update "update-timer user" || true
check_user keeper "keeperd service account" || true
check_user dockerproxy "docker-proxy service account" || true

for u in keeper-agent keeper-update; do
  if id "$u" >/dev/null 2>&1; then
    if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      fail "'$u' is a member of the 'docker' group -- that is root-equivalent (design doc §1); this defeats the docker-proxy migration"
    else
      pass "'$u' is not in the 'docker' group"
    fi
  fi
done

if getent group keeperclients >/dev/null 2>&1; then
  members=$(getent group keeperclients | cut -d: -f4)
  pass "group 'keeperclients' exists (members: ${members:-none})"
  for u in keeper-agent keeper-update; do
    if id "$u" >/dev/null 2>&1; then
      if printf '%s' ",$members," | grep -q ",$u,"; then
        pass "'$u' is in keeperclients"
      else
        fail "'$u' exists but is NOT in keeperclients -- keeperd cannot reach its socket"
      fi
    fi
  done
else
  skip "group 'keeperclients'" "keeper not installed yet"
fi

if getent group docker-proxy-clients >/dev/null 2>&1; then
  members=$(getent group docker-proxy-clients | cut -d: -f4)
  pass "group 'docker-proxy-clients' exists (members: ${members:-none})"
  if id dockerproxy >/dev/null 2>&1 && id -nG dockerproxy 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    pass "'dockerproxy' is in the real 'docker' group (expected: it is the only member that should be)"
  elif id dockerproxy >/dev/null 2>&1; then
    fail "'dockerproxy' exists but is NOT in the 'docker' group -- the proxy daemon cannot reach docker.sock"
  fi
else
  skip "group 'docker-proxy-clients'" "docker-proxy not installed yet"
fi

# ---------------------------------------------------------------------------------------------------------------
section "2. /etc/keeper and config.json (root-owned, agent cannot write it)"

if [ -d /etc/keeper ]; then
  if is_root; then
    st=$(stat -c '%U:%G %a' /etc/keeper)
    case "$st" in
      root:keeper\ 750|root:root\ 750) pass "/etc/keeper is $st" ;;
      *) fail "/etc/keeper is '$st', expected root-owned, mode 750, group keeper" ;;
    esac
  else
    skip "/etc/keeper ownership/mode" "needs root to stat it reliably"
  fi
else
  skip "/etc/keeper" "keeper not installed yet"
fi

if [ -r "$CONFIG" ]; then
  if is_root; then
    st=$(stat -c '%U:%G %a' "$CONFIG")
    case "$st" in
      root:keeper\ 640) pass "$CONFIG is $st" ;;
      *) fail "$CONFIG is '$st', expected root:keeper 640 (not writable by the agent)" ;;
    esac
  fi
  if python3 -m json.tool "$CONFIG" >/dev/null 2>&1; then
    pass "$CONFIG is valid JSON"
    AGENT_UIDS=$(python3 -c 'import json,sys; print(" ".join(str(u) for u in json.load(open(sys.argv[1])).get("agent_uids") or []))' "$CONFIG" 2>/dev/null || true)
    COUNT=$(printf '%s\n' "$AGENT_UIDS" | tr ' ' '\n' | grep -c . || true)
    if [ "$COUNT" -ge 2 ]; then
      pass "agent_uids has $COUNT entries (two-user topology intact: $AGENT_UIDS)"
    elif [ "$COUNT" -eq 1 ]; then
      warn "agent_uids has only 1 entry ($AGENT_UIDS) -- if keeper-update should also be covered, reinstall with a second --agent-user (install-keeper.sh now unions it into agent_uids; it is preserved across a plain reinstall since, see docs/deploy-keeper-server.md §2.2)"
    else
      skip "agent_uids content" "config has no agent_uids (or unreadable)"
    fi
    STANDING=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("standing_plans") or []))' "$CONFIG" 2>/dev/null || echo "?")
    if [ "$STANDING" != "?" ] && [ "$STANDING" -gt 0 ]; then
      pass "standing_plans: $STANDING entries configured"
    else
      skip "standing_plans" "none configured yet, or config unreadable"
    fi
  else
    fail "$CONFIG exists but is not valid JSON"
  fi
else
  skip "$CONFIG" "not present or not readable (run as root if it should exist)"
fi

if [ -e /etc/keeper/bot.token ]; then
  if is_root; then
    st=$(stat -c '%U %a' /etc/keeper/bot.token)
    case "$st" in
      keeper\ 400) pass "bot.token is $st" ;;
      *) fail "bot.token is '$st', expected 'keeper 400'" ;;
    esac
  fi
else
  skip "/etc/keeper/bot.token" "not written yet (asked interactively by install-keeper.sh --apply)"
fi

# ---------------------------------------------------------------------------------------------------------------
section "3. Socket and systemd units"

check_socket() {
  local path="$1" label="$2"
  if [ -S "$path" ]; then
    local st; st=$(stat -c '%G %a' "$path" 2>/dev/null || echo "?")
    pass "$label socket exists at $path ($st)"
  else
    skip "$label socket ($path)" "not present (daemon not installed or not started yet)"
  fi
}
check_socket /run/keeper/keeper.sock keeper
check_socket /run/docker-proxy/docker-proxy.sock docker-proxy

check_unit() {
  local unit="$1"
  if ! have systemctl; then
    skip "$unit" "systemctl not available (not a systemd host?)"
    return
  fi
  if systemctl list-unit-files "$unit" >/dev/null 2>&1 && systemctl list-unit-files "$unit" 2>/dev/null | grep -q "^$unit"; then
    local active enabled
    active=$(systemctl is-active "$unit" 2>/dev/null || true)
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    if [ "$active" = active ]; then pass "$unit: active ($enabled)"; else fail "$unit: not active (state: $active, $enabled)"; fi
  else
    skip "$unit" "unit file not installed yet"
  fi
}
check_unit keeper.service
check_unit docker-proxy.service

# ---------------------------------------------------------------------------------------------------------------
section "4. Docker version and a real docker-proxy/docker inspect (read-only)"

if have docker; then
  DVER=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
  KIND=server
  if [ -z "$DVER" ]; then
    DVER=$(docker --version 2>/dev/null | sed -n 's/^Docker version \([^,]*\),.*/\1/p')
    KIND="client only -- daemon unreachable, this is NOT confirmed to match the server/engine version"
  fi
  DVER=${DVER:-?}
  if [ "$DVER" = "29.9.1" ] && [ "$KIND" = server ]; then
    pass "docker server version is 29.9.1 (the only version docker-proxy's inspect format was verified against)"
  else
    warn "docker version is '$DVER' ($KIND), not a confirmed match for the 29.9.1 docker-proxy's inspect --format was verified against -- read the two inspect outputs below yourself, do not assume they match"
  fi
else
  skip "docker version" "docker CLI not found on this host"
fi

inspect_one() {
  local name="$1" desc="$2"
  [ -n "$name" ] || { skip "inspect ($desc)" "no --container/--container-with-healthcheck given"; return; }
  if client=$(dp_client); then
    out=$("$client" inspect "$name" 2>&1)
    rc=$?
  elif have docker; then
    warn "docker-proxy client not installed at $DP_CLIENT; falling back to a direct, read-only 'docker inspect' for this check only -- the real proxy path is NOT exercised by this fallback"
    out=$(docker inspect "$name" 2>&1)
    rc=$?
  else
    skip "inspect ($desc, $name)" "neither docker-proxy nor docker found"
    return
  fi
  if [ $rc -ne 0 ]; then
    fail "inspect $name ($desc) failed (exit $rc): $out"
    return
  fi
  if printf '%s' "$out" | python3 -m json.tool >/dev/null 2>&1; then
    pass "inspect $name ($desc) returned valid JSON -- printed below for a human to actually read, not just the exit code"
    printf '%s\n' "$out" | sed 's/^/       /'
  else
    fail "inspect $name ($desc) did not return valid JSON: $out"
  fi
}
inspect_one "$CONTAINER_PLAIN" "no healthcheck"
inspect_one "$CONTAINER_HEALTHCHECK" "with healthcheck"

# ---------------------------------------------------------------------------------------------------------------
section "5. sudoers allowlist (never a wildcard)"

if ! is_root; then
  skip "sudoers allowlist" "needs root to query another user's sudo -l"
elif [ -z "$AGENT_USER" ]; then
  if id keeper-agent >/dev/null 2>&1; then AGENT_USER=keeper-agent; fi
fi
if is_root && [ -n "$AGENT_USER" ]; then
  if have visudo; then
    if visudo -c >/dev/null 2>&1; then
      pass "sudoers syntax is valid (visudo -c)"
    else
      fail "sudoers syntax check failed -- run 'sudo visudo -c' yourself for details"
    fi
  fi
  RULES=$(sudo -l -U "$AGENT_USER" 2>/dev/null | grep -E '^\s*\(root\)|NOPASSWD' || true)
  if [ -n "$RULES" ]; then
    echo "   rules for $AGENT_USER:"
    printf '%s\n' "$RULES" | sed 's/^/     /'
    if printf '%s' "$RULES" | grep -qE '\*'; then
      fail "a sudoers rule for $AGENT_USER contains a wildcard -- design doc §1 option B requires fixed commands only, never a pattern"
    else
      pass "no wildcard found in $AGENT_USER's sudoers rules"
    fi
  else
    skip "sudoers rules for $AGENT_USER" "none configured yet"
  fi
elif [ -z "$AGENT_USER" ]; then
  skip "sudoers allowlist" "no --agent-user given and keeper-agent does not exist yet"
fi

# ---------------------------------------------------------------------------------------------------------------
section "6. Expected refusals (a command outside the plan must be refused, never silently run)"

if is_root && [ -n "$AGENT_USER" ] && have sudo; then
  # `sudo -l -U user cmd` only REPORTS whether that exact command would be allowed; it never runs it.
  if sudo -l -U "$AGENT_USER" /bin/systemctl restart definitely-not-a-real-unit-for-this-check.service >/dev/null 2>&1; then
    fail "sudo -l -U $AGENT_USER reports an unlisted unit as ALLOWED -- the sudoers allowlist is wider than intended"
  else
    pass "an out-of-allowlist systemctl target is correctly refused for $AGENT_USER"
  fi
else
  skip "sudoers refusal check" "needs root and a resolved --agent-user"
fi

if client=$(dp_client); then
  # docker-proxy's own CLI (docker_proxy_client.py) does not even define exec/create/run as subcommands; argparse
  # refuses them before any request reaches the daemon. This confirms the refusal without ever touching docker.
  if out=$("$client" exec 2>&1); then
    fail "docker-proxy accepted an 'exec' subcommand -- it must not exist in the client at all"
  else
    pass "docker-proxy ($client) refuses an 'exec' subcommand outright (not even a recognized verb)"
  fi
else
  skip "docker-proxy refusal check" "docker-proxy client not installed yet at $DP_CLIENT"
fi

# ---------------------------------------------------------------------------------------------------------------
section "Summary"
printf 'PASS=%d WARN=%d FAIL=%d SKIP=%d\n' "$PASS" "$WARN" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  echo "Overall: FAIL -- see [FAIL] lines above."
  exit 1
else
  echo "Overall: OK (no FAIL; WARN/SKIP are expected on a partial install -- see docs/deploy-keeper-server.md)."
  exit 0
fi

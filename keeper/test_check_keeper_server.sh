#!/bin/bash
# test_check_keeper_server.sh: check-keeper-server.sh must never modify anything, and must degrade cleanly
# (no crash, no stray errors) however much of docs/deploy-keeper-server.md is or isn't installed yet.
#
# Run: bash keeper/test_check_keeper_server.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/check-keeper-server.sh"
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

bash -n "$SCRIPT"
check "parses as valid bash (bash -n)" '[ $? -eq 0 ]'

# --- Static: no mutating command appears anywhere outside a comment -------------------------------------------
# A line is "code" if, with leading whitespace stripped, it does not start with #. Scanning code lines only means
# a comment that merely mentions chmod/rm/etc (to describe expected `stat` output, for instance) cannot produce a
# false FAIL here -- the point is what the script would actually RUN, not what it talks about.
CODE_LINES=$(grep -vE '^\s*#' "$SCRIPT" | grep -v '^\s*$')
# `>.../dev/null` is a discard, not a write to a real path -- excluded explicitly, not just left out of the list,
# so this check cannot be fooled into silence by someone "fixing" a real hit by redirecting it to /dev/null.
WORD_BANNED='\b(chmod|chown|useradd|userdel|groupadd|usermod|gpasswd|mkdir|rmdir|mv|cp|ln)\b|\brm[[:space:]]|visudo -f|systemctl[[:space:]]+(start|stop|restart|enable|disable|daemon-reload|kickstart|bootstrap|bootout)\b|docker[[:space:]]+(rm|create|run|restart|stop|start|compose|exec)\b|sudo[[:space:]]+(useradd|chmod|chown|tee|rm|mkdir)\b'
# `sudo -l -U user <command>` is a dry query ("would this be allowed") that never executes <command> -- see the
# check script's own comment at that call site. A banned word appearing only inside such a query string is not a
# hit; exclude those lines explicitly rather than widen the banned-word list to miss them structurally.
WORD_HITS=$(printf '%s\n' "$CODE_LINES" | grep -E "$WORD_BANNED" | grep -v 'sudo -l' || true)
REDIR_HITS=$(printf '%s\n' "$CODE_LINES" | grep -E '>[[:space:]]*/' | grep -v '/dev/null' || true)
HITS=$(printf '%s\n%s\n' "$WORD_HITS" "$REDIR_HITS" | grep -v '^\s*$' || true)
check "no mutating command appears in executable (non-comment) code" '[ -z "$HITS" ]'
if [ -n "$HITS" ]; then printf '%s\n' "$HITS" | sed 's/^/     unexpected: /'; fi

# The script never runs a raw `docker exec` (that would actually reach the daemon). It DOES pass the literal
# string "exec" as an argument to ITS OWN client (`"$client" exec`), refused by that client's own argument parser
# before anything reaches docker -- confirm the dangerous form is absent and the safe form is present.
check "no literal 'docker exec' invocation anywhere in the script" \
  '! grep -q "docker exec" "$SCRIPT"'
check "the refusal test calls our own \$client, not a bare docker/docker-proxy, with 'exec'" \
  'grep -qF "\$client\" exec" "$SCRIPT"'

# --- Dynamic: a clean run (nothing installed) never crashes and never writes outside its own stdout -----------
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
SNAP_BEFORE=$(find /etc/keeper /etc/docker-proxy /opt/agent-guardrails /run/keeper /run/docker-proxy \
  -printf '%p %T@\n' 2>/dev/null | sort)
OUT=$("$SCRIPT" 2>"$T/stderr"); RC=$?
SNAP_AFTER=$(find /etc/keeper /etc/docker-proxy /opt/agent-guardrails /run/keeper /run/docker-proxy \
  -printf '%p %T@\n' 2>/dev/null | sort)
check "exits 0 or 1 only (never crashes with a bash runtime error)" '[ "$RC" = 0 ] || [ "$RC" = 1 ]'
check "prints no bash runtime error (unbound variable, bad substitution, command not found for itself)" \
  '! grep -qE "unbound variable|bad substitution|syntax error|: command not found" "$T/stderr"'
check "touches nothing under /etc/keeper, /etc/docker-proxy, /opt/agent-guardrails, the sockets' run dirs" \
  '[ "$SNAP_BEFORE" = "$SNAP_AFTER" ]'
check "prints a final Overall: line" 'printf "%s" "$OUT" | grep -q "^Overall:"'
check "degrades to SKIP (not FAIL) for an uninstalled keeper when nothing real is present" \
  'printf "%s" "$OUT" | grep -q "\[SKIP\]"'

# Running it twice back to back must be idempotent (same thing it would print, modulo nothing time-sensitive) --
# a read-only script run twice changes nothing about what it finds the second time.
OUT2=$("$SCRIPT" 2>/dev/null)
check "running it twice in a row gives the same PASS/WARN/FAIL/SKIP counts (nothing it did changed its own input)" \
  '[ "$(printf "%s" "$OUT" | grep -c "^\[")" = "$(printf "%s" "$OUT2" | grep -c "^\[")" ]'

# --- CLI surface -------------------------------------------------------------------------------------------
"$SCRIPT" --help >/dev/null 2>&1
check "--help exits 0" '[ $? -eq 0 ]'
"$SCRIPT" --not-a-real-option >/dev/null 2>&1
check "an unknown option is refused (exit 2), not silently ignored" '[ $? -eq 2 ]'

# A bogus container name must FAIL that one check (inspect cannot succeed against nothing), not crash the script.
OUT3=$("$SCRIPT" --container does-not-exist-anywhere --container-with-healthcheck also-fake 2>/dev/null); RC3=$?
check "a nonexistent container name is reported, not a crash" \
  '[ "$RC3" = 0 ] || [ "$RC3" = 1 ]'
check "a nonexistent container name shows up as FAIL or SKIP, never silently PASS" \
  '! printf "%s" "$OUT3" | grep -q "\[PASS\] inspect does-not-exist-anywhere"'

exit $fail

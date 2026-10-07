#!/bin/bash
# Offline test of run-server.sh (external audit of v0.8): a witness alone, a failed scan and a pass that never came
# must not count as a healthy laptop pass. Fake values only, temp folders, no network.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export LC_ENV_FILE=/dev/null LC_STATE=$T/state LC_CONFIG=$T/config.json LC_NOTIFY="cat >> $T/alerts" LC_DIR=$HERE/.. LEAK_CHECK_KEY=$T/key
mkdir -p "$LC_STATE"
printf '{"env_files": [], "value_files": ["%s/witness.value"], "key_files": [], "targets": []}' "$LC_STATE" > "$LC_CONFIG"
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
send() {   # send <with transcript: 0|1> <with manifest: 0|1> <missing list>
  w=$(bash "$HERE/run-server.sh" witness)
  d=$LC_STATE/incoming/laptop/.local/share/leak-check; mkdir -p "$d" "$LC_STATE/incoming/laptop/.claude/projects/p"
  printf '{"witness": "%s"}\n' "$w" > "$d/witness.jsonl"
  [ "$2" = 1 ] && printf '{"expected": [".claude/projects"], "missing": [%s]}\n' "$3" > "$d/manifest.json"
  [ "$1" = 1 ] && echo '{"message": "hello"}' > "$LC_STATE/incoming/laptop/.claude/projects/p/s.jsonl"
  : > "$T/alerts"; rm -f "$LC_STATE/laptop-ok"
  bash "$HERE/run-server.sh" laptop
}
send 0 1 ""; check "witness alone is not a healthy pass" '[ ! -e "$LC_STATE/laptop-ok" ] && grep -q "no transcript" "$T/alerts"'
send 1 0 ""; check "no manifest is not a healthy pass" '[ ! -e "$LC_STATE/laptop-ok" ] && grep -q "no manifest" "$T/alerts"'
send 1 1 '".zsh_history"'; check "a missing laptop file is reported" '[ ! -e "$LC_STATE/laptop-ok" ] && grep -q "missing on the laptop" "$T/alerts"'
send 1 1 ""; check "a complete pass is healthy" '[ -e "$LC_STATE/laptop-ok" ]'
touch -d "@$(( $(date +%s) - 3600 ))" "$LC_STATE/laptop-ok" 2>/dev/null || touch -t "$(date -v-1H +%Y%m%d%H%M)" "$LC_STATE/laptop-ok"
before=$(stat -c %Y "$LC_STATE/laptop-ok" 2>/dev/null || stat -f %m "$LC_STATE/laptop-ok")
mv "$LC_CONFIG" "$LC_CONFIG.off"; : > "$T/alerts"
mkdir -p "$LC_STATE/incoming/laptop"; bash "$HERE/run-server.sh" laptop
after=$(stat -c %Y "$LC_STATE/laptop-ok" 2>/dev/null || stat -f %m "$LC_STATE/laptop-ok")
check "a failed scan does not refresh the last success" '[ "$before" = "$after" ] && grep -q "run error" "$T/alerts"'
mv "$LC_CONFIG.off" "$LC_CONFIG"
rm -f "$LC_STATE/laptop-ok"; echo $(( $(date +%s) - 30 * 3600 )) > "$LC_STATE/laptop-expected-since"; : > "$T/alerts"
bash "$HERE/run-server.sh" server
check "a first pass that never came raises an alert" 'grep -q "never succeeded" "$T/alerts"'
exit $fail

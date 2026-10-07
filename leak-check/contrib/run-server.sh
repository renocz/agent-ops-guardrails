#!/bin/bash
# leak-check orchestration on the machine that holds the secrets (run as root, from a systemd timer or cron).
#
#   run-server.sh            daily pass on this machine's own files (targets of the config)
#   run-server.sh laptop     scan the files a laptop just sent to $LC_STATE/incoming/laptop, then delete them
#   run-server.sh witness    print today's witness value (the laptop job plants it in what it sends)
#   run-server.sh notify-stdin   send the text on stdin through $LC_NOTIFY
#
# Alerts (through $LC_NOTIFY, a command that reads a message on stdin): a failing canary self-test, a new leak,
# missing sources or a sharp drop of the values checked, a laptop pass whose witness was not found (the pipeline is
# broken: job, transfer or scan), and no laptop pass for more than 26 hours.
#
# Settings (environment, or /etc/leak-check.env): LC_DIR (where leak_check.py is; default: next to contrib/), LC_CONFIG (JSON config; its value_files must include
# $LC_STATE/witness.value), LC_STATE (root-only state folder), LC_NOTIFY (alert command).
set -u
[ -f /etc/leak-check.env ] && . /etc/leak-check.env           # optional: LC_* settings, so remote calls get them too
LC_DIR=${LC_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
LC_CONFIG=${LC_CONFIG:-/etc/leak-check.json}
LC_STATE=${LC_STATE:-/var/lib/leak-check}
LC_NOTIFY=${LC_NOTIFY:-"logger -t leak-check"}
S=$LC_STATE
umask 077
mkdir -p "$S"
notify() { printf '%s\n' "$1" | sh -c "$LC_NOTIFY"; }

case "${1:-server}" in
  notify-stdin) notify "$(cat)"; exit 0 ;;
  witness)
    if [ ! -s "$S/witness.value" ] || [ "$(date -r "$S/witness.value" +%F)" != "$(date +%F)" ]; then
      python3 -c "import secrets; print('lcw' + secrets.token_hex(16), end='')" > "$S/witness.value"
    fi
    cat "$S/witness.value"; exit 0 ;;
  laptop) who="laptop"; tag=laptop; args=(--targets "$S/incoming/laptop/**/*" --strip "$S/incoming/laptop/") ;;
  server) who="server"; tag=server; args=() ;;
  *) echo "usage: run-server.sh [server|laptop|witness|notify-stdin]"; exit 2 ;;
esac

if ! python3 "$LC_DIR/leak_check.py" selftest > "$S/selftest-$tag.txt" 2>&1; then
  notify "⚠️ leak-check ($who): the canary self-test failed, the detector no longer finds its fake secrets"
fi
python3 "$LC_DIR/leak_check.py" scan --config "$LC_CONFIG" "${args[@]}" \
  --report "$S/report-$tag.json" --state "$S/state-$tag.json" > "$S/last-$tag.txt" 2>&1
rc=$?
[ "$tag" = "laptop" ] && rm -rf "$S/incoming/laptop"

python3 - "$S" "$tag" > "$S/verdict-$tag.txt" <<'EOF'
import json, os, sys, time
S, tag = sys.argv[1], sys.argv[2]
r = json.load(open(f"{S}/report-{tag}.json"))
is_w = lambda h: h["secret"].endswith("witness.value")
new = [h for h in r.get("new_leaks", []) if not is_w(h)]
msgs = []
if tag == "laptop":
    if any(is_w(h) for h in r.get("leaks", [])):
        open(f"{S}/laptop-ok", "w").write(str(time.time()))
    else:
        msgs.append("the witness was not found in the laptop's files: the pipeline is broken (job, transfer or scan)")
elif os.path.exists(f"{S}/laptop-ok") and time.time() - os.path.getmtime(f"{S}/laptop-ok") > 26 * 3600:
    msgs.append("no successful laptop pass for more than 26 hours")
n, miss = r.get("secrets_checked", 0), r.get("missing_sources", [])
cnt = f"{S}/count-{tag}"
prev = int(open(cnt).read()) if os.path.exists(cnt) else n
open(cnt, "w").write(str(n))
if miss and tag == "server":
    msgs.append("sources not checked: " + "; ".join(miss)[:600])
if prev and n < 0.8 * prev:
    msgs.append(f"values checked dropped: {n} instead of {prev}")
print(json.dumps({"new": [f"{h['secret']} in {h['transcript']} ({h['occurrences']}x)" for h in new][:20], "msgs": msgs}))
EOF
v=$(cat "$S/verdict-$tag.txt")
msgs=$(printf '%s' "$v" | python3 -c "import json,sys; print('\n'.join(json.load(sys.stdin)['msgs']))" 2>/dev/null)
new=$(printf '%s' "$v" | python3 -c "import json,sys; print('\n'.join(json.load(sys.stdin)['new']))" 2>/dev/null)
[ -n "$msgs" ] && notify "⚠️ leak-check ($who): $msgs"
if [ $rc -eq 2 ] || [ -z "$v" ]; then
  notify "⚠️ leak-check ($who): run error, see $S/last-$tag.txt"
elif [ -n "$new" ]; then
  notify "🚨 leak-check ($who): new secret leak(s)
$new
→ list every consumer of the secret, rotate it, then add a test case."
fi
exit 0

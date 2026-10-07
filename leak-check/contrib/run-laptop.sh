#!/bin/bash
# leak-check, daily job on the laptop where the agent runs. Sends the agent's transcripts, the shell history and the
# go-gate log to the machine that holds the secrets, with today's witness value planted in them; that machine scans
# them, alerts if needed, and deletes the copy. No secret, hash or fingerprint ever comes to the laptop.
#
# Settings (environment):
#   LC_REMOTE  command that runs a command on the server, e.g. "ssh -o BatchMode=yes root@server"
#              (or, for a container: "ssh -o BatchMode=yes root@host pct exec 100 --")
#   LC_SERVER_SCRIPT  path of run-server.sh on the server (default /opt/leak-check/contrib/run-server.sh)
#   LC_FILES   files and folders to send, relative to $HOME (default: .claude/projects .zsh_history .claude/go-gate/log.jsonl)
#
# Limit: this job runs as the user, so the agent could stop it. The server notices: a missing witness or no pass for
# 26 hours raises an alert.
set -u -o pipefail
: "${LC_REMOTE:?set LC_REMOTE}"
SCRIPT=${LC_SERVER_SCRIPT:-/opt/leak-check/contrib/run-server.sh}
L=$HOME/.local/share/leak-check
umask 077
mkdir -p "$L"
cd "$HOME" || exit 2
w=$($LC_REMOTE "$SCRIPT" witness) || exit 2
printf '{"witness": "%s"}\n' "$w" > "$L/witness.jsonl"
files=(); expected=(); missing=()
for f in ${LC_FILES:-.claude/projects .zsh_history .claude/go-gate/log.jsonl}; do
  expected+=("$f"); if [ -e "$f" ]; then files+=("$f"); else missing+=("$f"); fi
done
# a manifest, so the server can tell "nothing to scan" from "the transcripts never arrived" (external audit of v0.8)
python3 -c 'import json,sys; a=sys.argv[1:]; i=a.index("--"); print(json.dumps({"expected": a[:i], "missing": a[i+1:]}))' \
  "${expected[@]}" -- "${missing[@]+"${missing[@]}"}" > "$L/manifest.json"
files+=(.local/share/leak-check/witness.jsonl .local/share/leak-check/manifest.json)
COPYFILE_DISABLE=1 tar --no-xattrs -czf - "${files[@]}" \
  | $LC_REMOTE sh -c "'rm -rf /var/lib/leak-check/incoming/laptop && mkdir -p -m 700 /var/lib/leak-check/incoming/laptop && head -c 4000000000 | tar xzf - --no-same-owner --no-same-permissions -C /var/lib/leak-check/incoming/laptop'" \
  && $LC_REMOTE "$SCRIPT" laptop
rc=$?
rm -f "$L/witness.jsonl" "$L/manifest.json"
exit $rc

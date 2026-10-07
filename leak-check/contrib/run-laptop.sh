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
set -u
: "${LC_REMOTE:?set LC_REMOTE}"
SCRIPT=${LC_SERVER_SCRIPT:-/opt/leak-check/contrib/run-server.sh}
L=$HOME/.local/share/leak-check
umask 077
mkdir -p "$L"
cd "$HOME" || exit 2
w=$($LC_REMOTE "$SCRIPT" witness) || exit 2
printf '{"witness": "%s"}\n' "$w" > "$L/witness.jsonl"
files=()
for f in ${LC_FILES:-.claude/projects .zsh_history .claude/go-gate/log.jsonl}; do [ -e "$f" ] && files+=("$f"); done
files+=(.local/share/leak-check/witness.jsonl)
COPYFILE_DISABLE=1 tar --no-xattrs -czf - "${files[@]}" 2>/dev/null \
  | $LC_REMOTE sh -c "'rm -rf /var/lib/leak-check/incoming/laptop && mkdir -p -m 700 /var/lib/leak-check/incoming/laptop && tar xzf - -C /var/lib/leak-check/incoming/laptop'" \
  && $LC_REMOTE "$SCRIPT" laptop
rc=$?
rm -f "$L/witness.jsonl"
exit $rc

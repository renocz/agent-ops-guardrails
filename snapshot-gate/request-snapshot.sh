#!/bin/sh
# request-snapshot.sh: the agent side. Writes a request file (its content is irrelevant, only its existence and
# unique name matter) and waits for the matching state file to appear, polling once a second.
#
#   request-snapshot.sh REQUESTS_DIR STATES_DIR [TIMEOUT_SECONDS]
#
# Exit 0 only when the host answered OK; prints status/reason/name (one per line) either way. Exit 2 on a
# timeout or bad usage, exit 1 when the host explicitly refused (status=REFUSED) or hit an error applying the
# request (status=ERROR) -- both are "not OK", and both are reported here the instant the state file appears,
# never left to time out.
set -eu

if [ $# -lt 2 ]; then
  echo "usage: request-snapshot.sh REQUESTS_DIR STATES_DIR [TIMEOUT_SECONDS]" >&2
  exit 2
fi
REQ_DIR=$1
STATE_DIR=$2
TIMEOUT=${3:-30}

mkdir -p "$REQ_DIR" "$STATE_DIR"
ID="$(date +%Y%m%d%H%M%S)-$$"
: > "$REQ_DIR/$ID.request"

i=0
while [ ! -f "$STATE_DIR/$ID.state" ]; do
  i=$((i + 1))
  if [ "$i" -ge "$TIMEOUT" ]; then
    echo "timed out after ${TIMEOUT}s waiting for the snapshot gate to answer" >&2
    exit 2
  fi
  sleep 1
done

# The state file is written entirely by the host (snapshot-gate-host.py), with each value shell-quoted, so
# sourcing it is safe and avoids any hand-rolled parsing of a file we did not write ourselves.
status=""
reason=""
name=""
# shellcheck source=/dev/null
. "$STATE_DIR/$ID.state"

echo "status=$status"
[ -n "$reason" ] && echo "reason=$reason"
[ -n "$name" ] && echo "name=$name"

[ "$status" = "OK" ]

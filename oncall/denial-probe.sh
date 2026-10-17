#!/bin/sh
# denial-probe.sh: run as the restricted on-call identity to check that it really cannot do what it must not.
#
#   denial-probe.sh probes.json [--vars vars.json]
#
# Prints PASS (refused, as intended) or FAIL (accepted -- the restriction does not hold) for each probe in the
# data file, never the probed command's own output. Exit 0 if every probe PASSed, 1 if any FAILed. A thin shell
# entry point over lib/run_probes.py (stdlib only), same pattern as this repo's other installers.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 -I "$HERE/lib/run_probes.py" "$@"

#!/usr/bin/env bash
# Install secret-guard (Claude Code hook + mask filter) for the current user.
#   ./install.sh                  copy the files and print the settings snippet to add
#   ./install.sh --write-settings also add the hooks to ~/.claude/settings.json (a backup is made first)
# council/ needs no install: run council/ops_council.py from the repo (see council/README.md).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
bin="${HOME}/.local/bin"
hooks="${HOME}/.claude/hooks"
settings="${HOME}/.claude/settings.json"

command -v python3 >/dev/null || { echo "python3 is required (3.9+)"; exit 1; }
command -v perl >/dev/null || { echo "perl is required for the mask filter"; exit 1; }

mkdir -p "$bin" "$hooks"
install -m 755 "$here/secret-guard/mask" "$bin/mask"
install -m 755 "$here/secret-guard/secret_guard.py" "$hooks/secret_guard.py"
echo "installed: $bin/mask and $hooks/secret_guard.py"

# The mask must work, and be found by name, in the shell the agent uses.
if [ "$(printf 'password=hunter2\n' | "$bin/mask")" != "password=<m>" ]; then
  echo "WARNING: mask self-test failed (check the shebang line: env -S needs coreutils 8.30+ on Linux)"
fi
case ":$PATH:" in *":$bin:"*) ;; *) echo "WARNING: $bin is not on your PATH; the agent must be able to run 'mask'";; esac

if [ "${1:-}" = "--write-settings" ]; then
  [ -f "$settings" ] && cp -p "$settings" "$settings.bak-$(date +%Y%m%d%H%M%S)"
  python3 - "$settings" "$hooks/secret_guard.py" <<'PY'
import json, os, sys
path, hook = sys.argv[1], sys.argv[2]
data = json.load(open(path)) if os.path.exists(path) else {}
pre = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
cmd = "python3 " + hook
for matcher in ("Bash", "Read|Grep|NotebookRead"):
    if not any(e.get("matcher") == matcher and any(h.get("command") == cmd for h in e.get("hooks", [])) for e in pre):
        pre.append({"matcher": matcher, "hooks": [{"type": "command", "command": cmd}]})
json.dump(data, open(path, "w"), indent=2)
print("updated:", path)
PY
else
  cat <<EOF

Add this to $settings (or re-run with --write-settings):

{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "python3 $hooks/secret_guard.py" }] },
      { "matcher": "Read|Grep|NotebookRead", "hooks": [{ "type": "command", "command": "python3 $hooks/secret_guard.py" }] }
    ]
  }
}
EOF
fi

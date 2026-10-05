# secret-guard: what the agent sees

Real answers of `secret-guard/secret_guard.py`, produced by feeding it the tool calls below (2026-10-05).
When a call is refused, the reason goes back to the agent, which normally re-runs the command the safe way.

### Bash: `docker inspect auth`

⛔ **Refused.** Reason returned to the agent:

> secret-guard: this command may print a secret (Docker config / environment). Re-run it with ALL output, errors included, through the mask: `<command> 2>&1 | mask` (group several commands: `{ a; b; } 2>&1 | mask`; over ssh, put the mask on the local side). If the output provably contains no values (grep -c/-q, sha256, key names only), end the command with `# secret-ok`.

### Bash: `docker inspect auth 2>&1 | mask`

✅ **Allowed** (no output from the hook).

### Bash: `cat .env; ls 2>&1 | mask`

⛔ **Refused.** Reason returned to the agent:

> secret-guard: this command may print a secret (file that may contain secrets). Re-run it with ALL output, errors included, through the mask: `<command> 2>&1 | mask` (group several commands: `{ a; b; } 2>&1 | mask`; over ssh, put the mask on the local side). If the output provably contains no values (grep -c/-q, sha256, key names only), end the command with `# secret-ok`.

### Bash: `printenv DATABASE_URL`

⛔ **Refused.** Reason returned to the agent:

> secret-guard: this command may print a secret (environment variable). Re-run it with ALL output, errors included, through the mask: `<command> 2>&1 | mask` (group several commands: `{ a; b; } 2>&1 | mask`; over ssh, put the mask on the local side). If the output provably contains no values (grep -c/-q, sha256, key names only), end the command with `# secret-ok`.

### Bash: `grep -c API_KEY .env # secret-ok`

✅ **Allowed** (no output from the hook).

### Read: `/srv/vpn/wireguard/wg0.conf`

⛔ **Refused.** Reason returned to the agent:

> secret-guard: Read on a file that may contain secrets (/srv/vpn/wireguard/wg0.conf). Use Bash with `2>&1 | mask`, or list key names only (grep -o '^[A-Z_]*=').

## A typical exchange

1. The agent runs `docker inspect auth` to check a container's mounts.
2. secret-guard refuses: the environment variables in that output often hold passwords.
3. The agent re-runs `docker inspect auth 2>&1 | mask`. The mounts show as usual; values such as `DB_PASSWORD=<m>` are masked.

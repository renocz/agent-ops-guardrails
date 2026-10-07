# leak-check

**Did a real secret end up in an agent transcript? Yes or no.**

[secret-guard](../secret-guard/) *prevents* leaks with patterns. Its scores on blind test sets measure agreement with another model, not real leaks, and each new audit still finds a few holes. leak-check *measures* the leaks.

It runs where the secrets live, as root and outside the agent's reach. It reads their real values and looks for those exact values in what the agent produced: transcripts, shell history, and reports sent to outside models.

**Read its results as a floor.** It only finds the secrets it has inventoried. Every report therefore says what was checked (an inventory by type) and which sources were missing. Coverage of the inventory itself is measured against a deterministic scanner (see below).

## What it found on my setup (06/10/2026)

| Leak | Where | Status |
|---|---|---|
| A Telegram bot token, used by 7 services | 4 server transcripts | was valid: rotated |
| The Cloudflare tunnel token | 2 laptop transcripts | was valid: tunnel secret rotated |
| A Proxmox API token | 1 server transcript | already revoked |
| 3 OIDC client secrets (dashboard, recipes, log viewer) | a laptop file Claude Code wrote itself (`auto-mode-classifier-error.txt`) | rotated (new secrets 06/10, old ones deleted 07/10) |
| A Plex token | 1 laptop transcript (18 times) | kept: rotating it signs out every device; moved out of the compose file |

secret-guard had missed all of them.

**A correction.** v0.7 reported a leaked SSH private key. That was a false positive: every unencrypted OpenSSH ed25519 key starts with the same base64 line, and leak-check matched that shared header line. The key was rotated anyway, which did no harm. Since v0.8, header and public-key lines are never treated as secret.

## Coverage, measured independently

[gitleaks](https://github.com/gitleaks/gitleaks) was run once over the same server folders (`/opt/stacks`, `/etc`). Its findings were compared with leak-check's inventory, by value, without printing any.

| | |
|---|---|
| Distinct values gitleaks flags (12+ characters, live config only) | 128 |
| Also in leak-check's inventory | **68 (53%)** |

The 60 not covered, by inspection of file and key names:
- **33** are TLS private keys inside Traefik's `acme.json`. gitleaks flags them after decoding base64; leak-check holds them in their stored base64 form, so a leak of the decoded PEM would be missed.
- **12** are ASP.NET data-protection key files (Sonarr, Radarr, Prowlarr, Jackett), where gitleaks flags the key ID, not the key.
- **1** is a VPN provider's server list (public keys), and **1** a test "snakeoil" certificate.
- **The rest are real gaps:** web-push and session secrets in Seerr/Overseerr settings, a stale `settings.old.json`, and a token in a backup copy of a compose file.

The number to read is 53%, with that breakdown. Not 100%.

## How it works

```
laptop (daily job, contrib/run-laptop.sh)            server (root, daily timer, contrib/run-server.sh)
  fetch today's witness value  ◄──────────────────     witness: a random value, renewed daily
  tar: transcripts, shell history, go-gate log,
       the witness ─────────────────────────────►      unpack into a root-only folder
                                                       canary self-test (9 fake secrets, all supported shapes)
                                                       read the real values; exact search in the decoded text
                                                       the witness must be found, else "pipeline broken"
                                                       delete the copy
  new leak / broken pipeline / no laptop pass for 26 h / missing sources → alert (secret NAME, never the value)
```

**Readers (where the secret values come from):**
- `KEY=value`, `KEY: value` and `- KEY=value` lines (`.env`, `compose.yaml`).
- JSON values under secret-looking keys (`TunnelSecret`, `apiKey`…).
- App config files by extension: `.json`, `.xml` (including ASP.NET master keys), and YAML/TOML/INI/`.conf`/`.js` line by line.
- Private keys, line by line, minus the shared header and public-key lines.
- Single-value files.
- Inside URLs:
  - the password of any `user:pass@` URL, whatever the variable is called (`DATABASE_URL`);
  - in URL-like keys, token-looking path segments and query values: Discord, Slack and ntfy webhooks, healthcheck pings, `api.telegram.org/bot<token>`.

**Which keys count as secret:** names with `TOKEN`, `PASSWORD`, `SECRET`, `KEY`… Identifiers and options are excluded (`*_ID`, `*_USER`, `*_URL`, `*_SCOPES`…).

**Other behaviour:**
- **Transcripts are decoded first.** Claude Code writes JSON lines, which escape quotes, backslashes and newlines. Each line is parsed and every string inside is searched.
- **Failures are loud.** A missing source gives exit code 3 and an alert. So do a missing witness (the job, the transfer or the scan is broken) and no laptop pass for 26 hours.
- **`--state`:** only *new* findings are alerted again.

```
python3 leak_check.py selftest
python3 leak_check.py scan --config /etc/leak-check.json --report report.json --state state.json
LC_NOTIFY=/path/to/notify contrib/run-server.sh                  # daily, as root
LC_REMOTE="ssh -o BatchMode=yes root@server" contrib/run-laptop.sh   # daily, on the laptop
```

Exit codes: 0 no leak; 1 leak found or canary failed; 2 error; 3 no leak found but a source was missing. The configuration format is in the docstring of `leak_check.py`.

## What to do with a hit

1. **List every consumer of the secret before touching it:** files, container environments, other services, credentials stored in tools. One bot token here fed seven services, and revoking it in a hurry silenced all their alerts for ten minutes.
2. **Rotate without a gap where possible:** add the new value next to the old one, prove the new one works, then remove the old one.
3. **Check that the hit is real before rotating.** A shared header line, a public key or a template value is not a leak. The SSH-key false positive above is why.
4. **Add the command that leaked it to secret-guard's tests.**

## Limits

- **Inventory coverage is about half** of what a generic scanner flags (above). A secret it doesn't inventory, or one leaked in another encoding, is missed.
- **The canary only plants shapes the code already reads.** It proves the pipeline works, not that coverage is complete. The gitleaks comparison is the coverage measure.
- **The laptop job runs as the user**, so the agent could stop or fake it. The server notices a missing witness or a missing pass, but a determined agent could forge the witness. This guards against mistakes, not malice.
- **The laptop's conversation text crosses to the server** once a day (local network, root-only folder, deleted after the scan).
- **The alert needs a working channel.** Mine was down for ten minutes on the first evening. Watch the daily report too.
- **It is a detector, not a shield.** By the time it fires, the secret is already out, so rotation is always needed.

## Tests

`python3 -m unittest test_leak_check.py`, with fake values only. The shapes from the two external audits are tests.

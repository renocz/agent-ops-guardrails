# leak-check

**Did a real secret end up in an agent transcript? Yes or no.**

[secret-guard](../secret-guard/) *prevents* leaks with patterns. Its scores on blind test sets measure agreement with another model, not real leaks, and each new audit still finds a few holes. leak-check *measures* the leaks.

It runs where the secrets live, as root and outside the agent's reach. It reads their real values and looks for those exact values in the agent's transcripts. There is no pattern and no guess: a hit is a leak.

## On its first run

The first run, on my setup (06/10/2026), checked 49 secrets against 41 transcripts on two machines. It found 3 real leaks that the pattern hook had missed:

| Secret | Where | Status at the time |
|---|---|---|
| A Telegram bot token, used by 7 services | 4 server transcripts | valid: rotated |
| The Cloudflare tunnel token | 2 laptop transcripts | valid: tunnel secret rotated |
| A Proxmox API token | 1 server transcript | already revoked |

## How it works

```
server (root, daily timer)                         laptop (daily job)
  read real values  ──► scan server transcripts      ◄── fetch salted fingerprints (no value)
  (env files, key files)   exact substring match          scan laptop transcripts by token
  export salted SHA-256 fingerprints ───────────────►     match → alert, through the server
  new leak → Telegram alert (secret NAME, never value)
```

- **`scan`:** exact substring search of every value. There are no false positives by construction, except values too short or too common, which are filtered: under 12 characters, booleans, paths, `${VAR}`.
- **`export`:** writes `sha256(salt + value)` for each secret, with a random salt. Another machine can then check its transcripts without ever receiving a secret.
- **`scan-fingerprints`:** splits the transcript into tokens, hashes them with the same salt, and compares. It also handles `KEY=value`, `user:password` and `user@host` forms.
- **Which values count as secrets:** those whose name looks secret (`*_TOKEN`, `*_PASSWORD`, `*_KEY`…). Identifiers (`*_ID`, `CLIENTID`, `*_USER`, `*_URL`…) are excluded, because they are not secrets.
- **`--state`:** only *new* findings are reported again, so a daily alert doesn't repeat itself.
- **Only strong secrets are exported as fingerprints.** A salted SHA-256 of a weak password could be brute-forced by anyone who gets the fingerprint file. So only values above about 80 bits of estimated entropy (length × character classes) leave the server. Weaker values are checked on the server only, and the export reports how many there are. Rotate them to strong values anyway.
- **Coverage is reported, never assumed.** A configured file that is missing or unreadable is listed in `missing_sources` and printed on stderr. A scan with missing sources is not a "no leak".

```
python3 leak_check.py scan --config /etc/leak-check.json --report report.json --state state.json
python3 leak_check.py export --config /etc/leak-check.json --out fingerprints.json
python3 leak_check.py scan-fingerprints --config laptop.json --fingerprints fingerprints.json --state state.json
```

Exit code: 0 no leak, 1 leak found, 2 error. The configuration format is in the docstring of `leak_check.py`.

## What to do with a hit

1. **Rotate the secret.** A value in a transcript is exposed, whatever happens next.
2. **Before revoking, list every consumer of that secret:** files, container environments, other services. On my first run, one bot token turned out to feed seven services, and revoking it in a hurry silenced all their alerts for ten minutes.
3. **Add the command that leaked it to secret-guard's tests.**

## Limits

- **On the laptop, the job runs as the user**, so the agent could tamper with it. A root LaunchDaemon (macOS) or a system timer would be out of its reach.
- **It finds what it knows.** A secret that is not in the configured files is not checked. A leak in another form (base64, split across lines) is missed.
- **The laptop scan is token-based.** A value glued to other characters without a separator can be missed. The server scan uses exact substrings.
- **The alert needs a working channel.** Mine goes through one Telegram bot, and on the evening of the first run that bot was down for ten minutes. Watch the daily report itself, not only the alerts, or use a second channel.
- **It is a detector, not a shield.** By the time it fires, the secret is already in the transcript, so rotation is always needed.

## Tests

`python3 -m unittest test_leak_check.py` (fake values only).

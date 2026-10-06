# leak-check

**Did a real secret end up in an agent transcript? Yes or no.**

[secret-guard](../secret-guard/) *prevents* leaks with patterns. Its scores on blind test sets measure agreement with another model, not real leaks, and each new audit still finds a few holes. leak-check *measures* the leaks.

It runs where the secrets live, as root and outside the agent's reach. It reads their real values and looks for those exact values in what the agent produced: transcripts, shell history, and reports sent to outside models.

**Read its results as a floor.** It finds what it knows. Every report therefore says what was checked (an inventory by type) and which sources were missing, and every run starts with a canary self-test.

## What it found

| Run | Checked | Real leaks found |
|---|---|---|
| v1 (06/10/2026) | 49 values, 41 transcripts | a Telegram bot token used by 7 services (valid, rotated); the Cloudflare tunnel token (valid, rotated); a Proxmox token (already revoked) |
| v2 (same evening), after an audit showed v1 found 1 of 5 planted secrets | 98 values (46 from env files, 3 single-value files, 49 private-key lines), 82 files on 2 machines | **an SSH private key giving root on a container**, in a laptop transcript (rotated). v1 could not see it: it never checked keys. |

secret-guard had missed all four. The council reports were scanned too, and they were clean, which is the real test that the council's masking works.

## How it works

```
laptop (daily job)                                  server (root, daily timer)
  tar: transcripts, shell history, go-gate log ──►   unpack into a root-only folder
                                                     canary self-test (5 fake secrets, all shapes)
                                                     read the real values: env files, value files, private keys
                                                     exact search in the decoded text, then delete the copy
                                                     new leak → Telegram alert (secret NAME and file, never the value)
```

- **What counts as a secret:**
  - the values of keys whose name looks secret (`*_TOKEN`, `*_PASSWORD`, `*_KEY`…), except identifiers (`*_ID`, `CLIENTID`, `*_USER`, `*_URL`…);
  - the password of any `scheme://user:password@host` value, whatever the key is called (`DATABASE_URL`);
  - each base64 line of a private key (PEM or OpenSSH).
- **Transcripts are decoded first.** Claude Code writes JSON lines, which escape `"` as `\"`, `\` as `\\` and newlines as `\n`. Each line is parsed and every string inside is searched, so a value with a quote or a backslash, or a key printed over several lines, is found as it was.
- **The laptop's files are scanned on the server.** No secret, hash or fingerprint ever leaves the server. The cost is that the laptop's conversation text crosses to the server once a day (local network, root-only folder, deleted after the scan).
- **Canary:** each run plants five fake secrets (password in a URL, value with a quote, value with a backslash, plain value, multi-line key) in a scratch transcript, and checks they are all found. A failing canary raises an alert.
- **Coverage is reported, never assumed.** Sources that are missing or unreadable are listed. A sharp drop in the number of values checked raises an alert. A scan with missing sources is not a "no leak".
- **`--state`:** only *new* findings are reported again.

```
python3 leak_check.py selftest
python3 leak_check.py scan --config /etc/leak-check.json --report report.json --state state.json
python3 leak_check.py scan --config /etc/leak-check.json --targets '/srv/incoming/laptop/**/*.jsonl' --strip /srv/incoming/laptop/
```

Exit code: 0 no leak, 1 leak found or canary failed, 2 error. The configuration format is in the docstring of `leak_check.py`.

## What to do with a hit

1. **List every consumer of that secret before touching it:** files, container environments, other services, credentials stored in tools. On the first run, one bot token turned out to feed seven services. Revoking it in a hurry silenced all their alerts for ten minutes.
2. **Rotate without a gap where possible:** add the new value next to the old one, prove the new one works, then remove the old one. The SSH key above was rotated this way, with no outage.
3. **Add the command that leaked it to secret-guard's tests.**

## Limits

- **It finds what it knows.** A secret that isn't in the configured files is not checked. A value that leaked in another encoding (base64 of the value, a substring) is missed. The canary covers the shapes listed above, not every possible one.
- **The laptop job runs as the user**, so the agent could tamper with it or skip it. A root LaunchDaemon (macOS) or a system timer would be out of its reach. The server side runs as root.
- **The alert needs a working channel.** Mine goes through one Telegram bot, which was down for ten minutes on the evening of the first run. Watch the daily report too, or add a second channel.
- **It is a detector, not a shield.** By the time it fires, the secret is already in the transcript, so rotation is always needed.

## Tests

`python3 -m unittest test_leak_check.py` (fake values only). The five shapes from the external audit are tests.

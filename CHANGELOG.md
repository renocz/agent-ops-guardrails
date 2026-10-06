# Changelog

One version scheme: **a repository tag per release**. Components have no version of their own. Commit messages from 06/10/2026 that say "secret-guard v0.3/v0.4/v0.5" refer to the intermediate revisions listed under v0.6.

## v0.7 (06/10/2026)

- **leak-check v2, after a fourth external audit.** v1 found 1 of 5 planted secrets.
  - JSON transcript lines are decoded before searching, so quotes, backslashes and newlines no longer hide values.
  - A password inside any `user:pass@` URL is checked, whatever the variable is called.
  - Private keys are checked line by line.
  - Each report has an inventory by type, and every run starts with a canary self-test (5/5).
  - The salted-fingerprint export is removed: the laptop now sends its transcripts to the server, which does the exact search and deletes the copy.
  - The first v2 run found an SSH private key in a laptop transcript.
- **secret-guard:** the git-history rule no longer refuses commands that print no value (`git log --oneline -- .env`), and template files (`.env.example`, `.sample`, `.template`, `.dist`) are not secret files.
- **council:** the README states that the cross-review step never changes the verdict.

## v0.6 (06/10/2026)

- **leak-check (new):** measures real leaks. A root job looks for the real secret values in the agent's transcripts, on the server, and through salted fingerprints on the laptop. Its first run found 3 leaks the pattern hook had missed.
- **secret-guard:** five revisions, each scored on a blind test set written by another model before any fix. Agreement on unseen sets: 75% (gemini), 85% (gpt), 80% (mistral), 95% (claude, same family as the author).
  - Revision 2 (`2428ffb`, tag v0.2.1): the 15 holes of the second external audit.
  - Revision 3 (`4cd9616`): blind set 1 fixed.
  - Revision 4 (`06d0def`): blind set 2 fixed.
  - Revision 5 (`2642979`): the 5 real gaps of blind set 3.
  - Then the 6 holes of the third external audit: Nextcloud `occ`, `bw unlock`, `borg key export`, `git log -p -- .env`, `nmcli -s`, `.nmconnection`.
- **go-gate:**
  - At the GO, a `systemMessage` notice (shown in the terminal) restates the approved plan.
  - The action-URL rule only looks at real URLs, and at action words as the last path segment, so Docker socket reads and `/api/sync/status` count as reads.
- **council:** status "stable". The cross-review step was measured on 28 runs (it added a point or a correction in 27) and stays on. New `cross_review` option to switch it off.
- **Docs:** a summary table of every measure in `docs/results.md`, and this changelog.

## v0.2.1 (06/10/2026)

Fixes from the second external audit: a missing dependency fails closed in go-gate; secret-guard covers `.pgpass`, `.my.cnf`, `/etc/pve/priv`, `rclone config show`, `sops -d`, and passwords in clear; blind test set 1.

## v0.2 (06/10/2026)

go-gate (experimental, observe mode by default).

## v0.1 (06/10/2026)

council and secret-guard, Hook Gym in CI.

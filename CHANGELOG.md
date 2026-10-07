# Changelog

One version scheme: **a repository tag per release**. Components have no version of their own. Commit messages from 06/10/2026 that say "secret-guard v0.3/v0.4/v0.5" refer to the intermediate revisions listed under v0.6.

## v0.9 (unreleased)

**After a sixth external audit** (gpt, 07/10), which ran the hooks against fake secrets and reported, among others, 16 commands that printed a secret past secret-guard, a deletion go-gate classed as a read, and secrets leak-check never inventoried. Every finding below was reproduced before being fixed, and each fix has a test built from the audit's exact case. Thank you to the auditor.

- **What did not change:** these are hooks that run with the agent's rights and read the text it writes. They catch a cooperative agent's mistakes; an agent trying to get around them still can. The README now says so up front.
- **secret-guard:** quotes removed and globs expanded before matching; input redirected from a secret file, copies to stdout and more readers (`dd`, `tee`, `openssl`…) count as reads; a reader on a path only known at run time must be masked; inline scripts that open files must be masked; redefining `mask` or `PATH` is refused; cutting a bare value out before the mask is refused; `# secret-ok` is logged and no longer covers reading a secret file. The `mask` filter also hides a line made of one bare token (not pure hex: hashes stay readable). 235 test cases. Agreement with the blind sets: claude 93% (was 95%), gpt 98% (was 100%), gemini and mistral unchanged; the 2 new disagreements are `cat <secret file> # secret-ok`, refused on purpose now.
- **go-gate:** inline Python is a read only with pure imports; a chat-tool plan is pending only after delivery (PostToolUse); pending plans expire (2 h); old, replayed or non-ASCII GOs are ignored; every object of a multi-object verb must be in scope; MCP tools with a write verb in their name are changes; the gate's state, hooks and settings can't be written under any plan, symlinks included.
- **leak-check:** YAML block values, XML attributes, `.pgpass`, Proxmox `token.cfg`, JSON lists, rclone tokens, decoded Docker `auth`, URL passwords in `json_files`, one-line PEM keys; short and all-digit values under secret names; skipped files listed; a rotated secret leaking again is new. Orchestration: a pass needs the witness, a manifest and a transcript; a failed scan never reuses the old report; a first pass that never comes alerts. 30 unit tests and an offline orchestration test in CI.
- **council:** one blocking member gives HUMAN REVIEW REQUIRED (not "APPROVE, …"); blockers are copied into the report mechanically; a cross-review blocker reaches the verdict; contradictory verdict lines are invalid; same-family members and empty Request/GO are refused; the final request body is masked and overrides can't replace messages.
- **Friction, measured:** the 5,062 Bash commands of my own past sessions were replayed through v0.8 and v0.9. secret-guard refuses 2.7% more of them, mostly `# secret-ok` on reads of secret files (refused on purpose now); a first draft refused 16% and was narrowed before release. go-gate classes 0.8% more of them as changes (Python importing local or file-system modules).
- **After the council's review of v0.9:** `open(path, "w")`, a variable mode or `print(file=…)` makes Python a change; a channel GO dated in the future is ignored; an expired plan's GO tells the agent it was not applied.
- **Docs and CI:** the pasted-alert rule is the same everywhere; the leak count is reconciled (7 distinct secrets); GitHub Actions pinned by commit; the hook-gym job fails if the harness does not run.

## v0.8 (07/10/2026)

- **leak-check, after a fifth external audit** (5 common homelab shapes, 0 inventoried):
  - new readers: `KEY: value` and `- KEY=value` (compose files), JSON secret keys, app config files (.json, .xml, YAML/TOML/INI/.conf/.js), token-looking parts of webhook and ping URLs;
  - private-key header and public-key lines are no longer treated as secret;
  - exit code 3 when a source is missing;
  - the self-test cleans up after itself and plants 9 shapes;
  - values that are templates (`{{ … }}`, `{% … %}`) are not secrets (a real false positive: a Prowlarr indexer definition);
  - the orchestration scripts are published (`contrib/run-server.sh`, `contrib/run-laptop.sh`), with an end-to-end witness and a 26-hour no-pass alert.
- **Correction:** the SSH key leak reported in v0.7 was a false positive (a header line shared by every OpenSSH ed25519 key). It is retracted in the README, the results and the changelog.
- **Coverage measured:** gitleaks over the same folders flags 128 values. leak-check inventories 68 of them (53%), and most of the rest are explained.
- **New real leaks found:** 3 OIDC client secrets (rotated on 06/10, old secrets deleted on 07/10) and a Plex token (moved out of the compose file; not rotated, by choice).

## v0.7 (06/10/2026)

- **leak-check v2, after a fourth external audit.** v1 found 1 of 5 planted secrets.
  - JSON transcript lines are decoded before searching, so quotes, backslashes and newlines no longer hide values.
  - A password inside any `user:pass@` URL is checked, whatever the variable is called.
  - Private keys are checked line by line.
  - Each report has an inventory by type, and every run starts with a canary self-test (5/5).
  - The salted-fingerprint export is removed: the laptop now sends its transcripts to the server, which does the exact search and deletes the copy.
  - ~~The first v2 run found an SSH private key in a laptop transcript.~~ Retracted in v0.8: a false positive.
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

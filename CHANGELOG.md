# Changelog

One version scheme: **a repository tag per release**. Components have no version of their own. Commit messages from 06/10/2026 that say "secret-guard v0.3/v0.4/v0.5" refer to the intermediate revisions listed under v0.6.

## Unreleased (towards v1.0)

- **`install-keeper.sh`: `--agent-user` is repeatable, and a reinstall no longer silently drops a second agent
  from `agent_uids` (owner review of the server deployment entry below, 21/10/2026).** The bug: every `--apply`
  wrote `agent_uids` as a single-element list containing whichever `--agent-user` that run happened to pass, so
  reinstalling a two-user topology (§2.2 of `docs/deploy-keeper-server.md`, the shared assistant/morning user plus
  the separate update-timer user) for any ordinary reason -- a new `--hook-timeout`, a new `--lang`, a newer
  `keeperd.py` -- quietly took the second user's socket access away. Fixed:
  - `--agent-user` can be given more than once; `agent_uids` holds each resolved uid, de-duplicated, in the order
    given, and every one of those users is added to the `keeperclients` group (additively, every run). A
    nonexistent `--agent-user` is refused before anything is written, same as before.
  - A reinstall **unions** the uids it resolves into whatever `agent_uids` already holds in
    `/etc/keeper/config.json`, instead of replacing the list -- the general "a reinstall merges, never silently
    overwrites" rule this repo already applies to the rest of the config file (PR #20) now also covers this key.
    The install's own output names what was added versus already present, in both dry and real runs, so the
    merge is never silent. `--replace-agent-uids` is the explicit opt-out, for when the list should become
    exactly this run's `--agent-user`s.
  - `keeper/test_keeper.py`'s `InstallerConfigMerge` gained the coverage (two users, a reinstall naming only one,
    `--replace-agent-uids`, a nonexistent user, the same user twice, the dry-run message), mutation-checked
    against a sibling script where the union is replaced by a plain overwrite.
  - `docs/deploy-keeper-server.md` §2.2 and `docs/keeper-server-dry-run.md`'s item 2, previously the by-hand
    workaround for this gap, are rewritten: the two-user install is now one `install-keeper.sh` command with two
    `--agent-user` flags, and no by-hand `python3 -c '...'` step survives reinstalls to be forgotten.
  No behavior changed for an install with a single `--agent-user`, which is still the common case.

- **Server deployment of the keeper, documented and checkable, not yet applied anywhere (21/10/2026).**
  `docs/deploy-keeper-server.md` turns `docs/design-keeper-server.md`'s decisions (two non-root users, the Docker
  proxy, standing plans, `KEEPER_ACTOR`) into exact commands, each with an expected result and a rollback;
  `docs/keeper-server-dry-run.md` is the owner's real-host trial checklist, mirroring
  `docs/block-mode-dry-run.md`'s role for the laptop. `keeper/check-keeper-server.sh` is a new, read-only
  verification script (users/groups, `/etc/keeper` permissions, the socket, the systemd units, a real Docker
  version check, a real `inspect` on a container with and without a healthcheck, the sudoers allowlist, and that
  an out-of-plan command is actually refused) that degrades to a clean SKIP, never a crash or a FAIL, on however
  much of the install exists yet; `keeper/test_check_keeper_server.sh` checks that it never writes anything and
  never crashes. Two real traps found by writing and running these against this repo's own test host, not
  guessed: `install-keeper.sh`'s `agent_uids` key was silently reset to one entry by every reinstall (fixed
  above, same day); and Docker Engine ships its own, unrelated binary also named `docker-proxy`, an exact
  basename collision with this kit's agent-facing wrapper that depends on `PATH` order to resolve correctly (now
  checked for and warned about). No code from `keeper/` or `docker-proxy/`'s own daemons/clients changed, and
  nothing in this entry was run with `--apply` against a real host.

- **docker-proxy: `inspect` and `logs` no longer hand the agent raw secrets (owner review of PR #21, 21/10/2026).**
  `docker inspect` includes a container's entire environment verbatim (`Config.Env`) -- API keys, database
  passwords, tokens -- and `docker logs` prints whatever the container writes, which regularly includes secrets in
  connection strings or startup banners. Before this fix both subcommands returned docker's raw stdout
  unfiltered. Two independent, deliberately redundant layers fix it:
  1. `inspect` now always runs with the daemon's own fixed `--format`, never one the agent supplies (a `format`
     key in the request is refused outright) -- a literal allowlist of eight fields (`Name`, `Id`, `State`,
     `Image`, `RestartPolicy`, `Health`, `Networks`, `Mounts`) that structurally never asks docker for
     `Config.Env`, `Config.Cmd` or `Config.Entrypoint` in the first place. `docker-proxy inspect <name>` now
     prints a compact JSON object with exactly those eight keys, not docker's own multi-page JSON.
  2. `inspect`'s (now-filtered) output and all of `logs`' output, stdout and stderr, are passed through
     `mask_text()` -- secret-guard/mask's own redaction patterns, ported into `docker_proxyd.py` (not a
     subprocess call to the Perl script, so the daemon keeps running under its hardened, `env -i` systemd unit
     with no new runtime dependency) -- before either leaves the daemon. This is server-side, so the agent cannot
     get an unmasked copy by skipping its own local `mask`; it catches what the field whitelist didn't anticipate
     (a secret in a log line, in a health-check script's own output).

  (Caught by actually running this against a real Docker Engine (29.9.1), not just the fake `run` recorder the
  rest of this suite uses: the first field-path syntax tried, plain dot notation, made a real `docker inspect
  --format` fail outright on any container with no healthcheck configured -- the common case -- once `.Id` was
  also in the same template. Fixed by building every nested field access with `index()` instead of dot notation.)

  New, optional config section **`read_allow.containers`**: same shape and same fail-closed literal-name
  validation as `write_allow.containers` (no wildcard, no regex, checked at load and at request time). Absent
  (the default), reads are unrestricted, as before this entry. Present, even empty, it narrows `logs`/`inspect`/
  `stats`/`top` to exactly the listed containers; `ps` is never gated by it (it lists every container, it targets
  none). Not yet wired into `install-docker-proxy.sh` (which still only ever writes `write_allow`) -- edit the
  installed config by hand and restart the service, same as any other config change (see docker-proxy/README.md).

  25 new tests (read_allow config loading and gating, inspect's fixed format and the agent-supplied-`format`
  refusal, a fake secret in logs/an inspect-allowed field never reaching the response, and mutation checks that
  disabling `mask_text()` or bypassing the field whitelist each flip a redaction to a leak), plus a check that the
  ported `mask_text()` matches the real `secret-guard/mask` on a shared set of fixtures (skipped if `perl` isn't
  available). `ps`/`stats`/`top` output is not masked (out of this fix's scope; see docker-proxy/README.md "Known
  limits").

- **New kit: docker-proxy, filtered Docker access for a non-root agent.** Implements option C of
  `docs/design-keeper-server.md` section 1: a dedicated `dockerproxy` account is the only one in the `docker`
  group; the agent reaches a small daemon (`docker_proxyd.py`) over its own Unix socket instead. Reads (`ps`,
  `logs`, `inspect`, `stats`, `top`) are always allowed; writes (`restart`, `start`, `stop`) are gated by an exact,
  literal container-name allowlist in a root-owned config -- no wildcard, no regex, checked both when the config is
  loaded and at request time. No flags are forwarded from the agent (only a few bounded, fixed options: `-a`,
  `--tail`, `--timeout`); a target name is validated against Docker's own naming rules before anything else runs,
  which stops shell-metacharacter and flag-injection attempts (`-v`, `--privileged`, `; rm -rf /`, …) structurally.
  `install-docker-proxy.sh` follows the same dry-run-by-default / `--apply` / `--prefix` convention as the other
  installers in this repo. 29 tests (no real Docker, no network -- a fake `run` recorder stands in for
  `subprocess.run`, plus one real-Unix-socket end-to-end test), including a mutation check that disabling the
  whitelist guard flips a refusal to an allow. Sudoers lines for `pct`/`systemctl` (design doc's option B) are left
  out of scope: they need the owner's real service/unit names, which this session cannot know.

- **keeper installer: a reinstall now MERGES into an existing `/etc/keeper/config.json` instead of overwriting it
  (20/10).** Rerunning `install-keeper.sh --apply` rewrote the whole file from the script's own defaults and
  command-line options, so any key the owner had edited by hand after the first install -- `max_proposals_per_hour`
  raised from 3 to 8 (owner review of PR #8), or `mode` set to `observe` for the emergency rollback in the README --
  was silently lost on the next reinstall, reverting to the script's default. The script now reads the existing file
  first (if any) and only sets the keys this run's own options drive (`owner_id`, `chat_id`, `agent_uids`,
  `agent_home`, `client_group`, `socket`, `state_dir`, `bot_token_file`, `mode`, `lang`, `hook_timeout_sec`,
  `wait_max_sec`, `safe_git_repos`); every other existing key -- known to this version of the script or not, a
  future version's key included -- survives untouched, value and presence both. With no existing file, behavior is
  unchanged (the shipped defaults are written). Tests: a hand-edited key the installer never writes (`max_proposals_
  per_hour`) survives a reinstall with the other installer-owned keys still correct, an unknown key simulating a
  future script version survives too, the no-existing-file path is unchanged; mutation-checked (reinstating the old
  full-overwrite write in a sibling copy of the script makes both new tests fail).
- **keeper installer: the hook entry gets `"onFailure": "block"`, and the useless `Write(...)` deny rules go (20/10).**
  The owner ran a real test on Claude Code 2.1.302 (a hook that sleeps 90 s with `"timeout": 60`): without `onFailure` the
  command ran after about 67 s, i.e. a timed-out PreToolUse hook is fail-open in practice, not only in the documentation;
  with `"onFailure": "block"` the command was blocked (71 s); a fast hook ran in 9 s. `install-keeper.sh` now writes
  `"onFailure": "block"` next to the explicit `timeout` (a reinstall updates an existing keeper entry in place, never a
  second one), so a hook that fails or times out denies instead of opening the door. The same run showed that Claude Code
  ignores `Write(path)` deny rules (it prints a warning at every start; only `Edit(path)` rules match and they cover every
  file-editing tool): the installer now writes the three `Edit(...)` rules only and removes the keeper's own old
  `Write(...)` duplicates, leaving foreign rules alone. Tests: default entry, in-place upgrade of an old entry, edit-only
  deny rules with legacy cleanup and a kept foreign rule; mutation-checked (each of four mutants makes them fail).

Next: finish the block-mode trial (started 12/10/2026, after the end-to-end dry run of refusal, approval, expiry, replay and a Telegram outage) -- a few days of varied real work, no deadlock, an acceptable number of cards -- then v1.0.

- **keeper: standing plans, for an agent nobody is watching (design: `docs/design-keeper-server.md`, written
  first, before any code here -- the keeper's own precondition, "the agent must not be root," is false on the
  server, where three agents run as root and two of them act with no human reading a Telegram card at the time).**
  A standing plan is an exact, literal allowlist of commands (`standing_plans` in `/etc/keeper/config.json`),
  never created or widened through the socket or Telegram -- there is no code path from agent input to it at all,
  only a root edit to the config file followed by a restart. A call is covered only if it is character-for-
  character equal to one of the listed commands (no prefix, no pattern, no category/targets abstraction like an
  ordinary plan); `expires_at` is mandatory and clamped to at most 45 days from now regardless of what the config
  says. A match skips the classifier entirely (logged as `standing-used`), is listed on both `keeper-status` and
  `/status`, and `/stop <id>` disables one at once, persisted. A new, optional `actor` field on the socket's
  `check` op -- set only by a root-owned hook command line (a distinct `--settings` profile per systemd unit),
  never by the agent's own session -- lets a proposal from a configured `unattended_actors` tag stay recorded
  (still visible in `/plans`/`/summary`) without ever pushing a Telegram card, and skips `--wait` (nobody is there
  to decide). Any other actor, or none, behaves exactly as before. 13 new tests in `test_keeper.py` plus 4
  end-to-end ones in `test_block_dryrun.py` (the real `keeper_client.py` subprocess, over the real socket,
  carrying `KEEPER_ACTOR`); mutation-checked (same method as PR #14/#15 -- a manual revert in a throwaway copy,
  run against the real test file): the exact-match guard widened to a substring check, a crafted payload trying to
  smuggle its own `standing_plans`/`actor` into `Keeper.standing`, and the per-entry `try/except` in
  `load_standing()` removed. Existing suites unmodified and green. Not run from this session: `install-keeper.sh
  --apply` on a real LXC, and a real `claude -p` headless run against a real `--settings` profile -- see the
  design doc's NOT TESTED list.
- **go-gate: round 2 red-team on our own classifier (attacker mode, authorised, 19/10) -- two real bypasses found
  and fixed by whitelist, not blacklist; the F4 "unbalanced" question from PR #11 revisited.**
  - **MCP method write-verb check was a blacklist, and a blacklist of "dangerous" verbs can never be complete.**
    `get_and_archive_repo`, `list_and_close_issue`, `find_and_merge_duplicates`, `get_and_lock_thread`,
    `search_and_block_user`, `get_and_overwrite_file`, `list_and_add_label`, `get_and_ban_member`,
    `get_and_disable_webhook`, `get_and_publish_draft`, `get_and_wipe_cache`, `get_and_clear_history` and the
    single run-on word `getandarchiveitem` all classified as **read** on main: `mcp_writes()`'s `MCP_WRITE` list
    (delete/remove/create/update/...) never included archive, merge, close, lock, overwrite, add, ban, disable,
    publish, wipe or clear -- every one of them changes state, and `mcp__github__merge_pull_request`, a real tool
    in this very session's own MCP server list, is such a verb. Fixed by `mcp_is_read_verb()`: for a method that
    splits into separate words (the overwhelming majority of real MCP tool names -- every one of the 94 real names
    this project has checked uses `_` or camelCase), the verb after and/then/or must now be ON `MCP_SAFE_VERBS`, a
    short whitelist, not merely absent from a blacklist. The leading verb is left exactly as `MCP_READ` already
    judged it (itself whitelist-shaped: it requires the method to START WITH a recognised read verb or phrase).
    The one case that keeps a blacklist, by necessity: a method with no separator at all (`getandarchiveitem`)
    cannot be split into words with any confidence, and an exact whitelist there breaks real, already-tested reads
    (`getstatuses`, `searchrepositories` -- "or" sits inside "repositories" with nothing to do with a connector),
    so it falls back to `MCP_WRITE_WIDE`, the old blacklist widened to the same newly-found verbs. Both bypasses
    and the no-regression cases are in `go-gate/test_disguise.py` (`MCP_UNLISTED_WRITE_VERB`,
    `MCP_SAFE_SINGLE_WORD_WITH_OR`); mutation-checked by diffing classification against the pre-fix code (each
    case flips from read to change/opaque, and no previously-passing case regresses).
  - **`docker exec`'s own flag table was missing two real, value-taking flags.** `--env-file` and `--detach-keys`
    were not in the by-hand list of flags assumed to take a separate value, so an unrecognised flag was silently
    treated as taking none, and the parse stopped one token too early: `docker exec --env-file x.env cat bash -c
    "rm -rf /data"` classified as **read**, because the shift landed the classifier on the CONTAINER NAME (which
    the agent can itself choose, with an earlier `docker run --name cat ...`) instead of on `bash -c "rm -rf
    /data"`, the command the container actually runs. Fixed with a closed, authoritative flag table
    (`DOCKER_EXEC_FLAGS` -- `docker exec` is a small, stable CLI, unlike an arbitrary shell command, so a complete
    table is realistic here in a way it never is for awk/sed programs or shell commands in general): an
    unrecognised flag now makes the call **opaque** instead of being assumed to take zero arguments. Grouped short
    booleans (`-it`, `-dit`) and the `=` form of every flag keep classifying normally.
    `go-gate/test_disguise.py`'s `DOCKER_EXEC_FLAG_PARSING` / `DOCKER_EXEC_SAFE_FLAGS`; mutation-checked the same
    way.
  - **The "unbalanced" question from PR #11, revisited.** The oracle corpus (`go-gate/test_balance_oracle.py`) now
    covers 427 generated commands (up from the 355 of PR #11 -- the corpus itself grew in the meantime, not from
    this round). Recomputing the disagreement table: **2 of 427** are still the already-known, still-open false
    positive (the `$'...'` ANSI-C gap -- `gate_says_unbalanced()` flags a syntactically valid ANSI-C-quoted string
    as unbalanced; unchanged since PR #11, not fixed here, see NON CORRIGÉS below). A separate **6 of 427** are
    cases where the narrow oracle helper (`gate_says_unbalanced()`, which checks `scan()`'s own balanced flag at
    the top level only) disagrees with `real_valid()` -- all 6 are the `bash; pct exec 100 -- sh -c "echo c'est
    ...; <payload>"` family already identified on 15/10 (a second, independent genuine trap in the same log
    family): the bare leading `bash` statement (no `-c`) is classified `opaque` directly by `classify_bash()`
    regardless of what the oracle's narrow helper says about the rest of the line, so the real pipeline was never
    at risk -- confirmed again here, no new fix needed, same conclusion as 15/10. **0 of 427** are a real
    unbalanced command that the actual `classify_bash()` pipeline (not the narrow oracle helper) fails to flag.
  - **What was tried and rejected:** widening the leading-verb check itself to a free substring search (instead of
    requiring it to START the method) would have reopened exactly the `mcp__x__y_search` case PR #11's own test
    already pins to "change" ("only a prefix naming the server goes") -- kept as `MCP_READ` already was.
- **go-gate: a `dir:` grant also requires the working directory to be inside it (owner decision, 20/10).** A command
  that changes something and is covered through a `dir:` target must also run with its effective working directory
  (`go_gate.CWD`, followed through the command's own `cd`/`pushd`/`popd` per stage, symlinks followed) inside one of the
  plan's `dir:` targets and not under a protected path; an unknown or unresolvable cwd is refused. Plans without `dir:`
  targets, plain-target matches (also in a mixed plan) and file tools are unchanged. Over-refusal is accepted (for
  example `docker compose -f <abs path>` started from another directory); the refusal says to run it from inside the
  directory or use `cd <dir> && ...`. Tests: cwd inside, outside, unknown, equal to the dir, symlink, protected,
  `cd` and subshell chains, the message; five new mutants of the mutation check.
- **go-gate: a `dir:` target now covers an action only when *every* path in it is inside (independent review of PR
  #15, 19/10).** The first version of `dir:` matched like any target: one word of the action under the directory was
  enough, so with `targets=dir:/opt/stacks/news` the action `cp /opt/stacks/news/x /etc/cron.d/y` was covered although
  it writes outside it. `coverage_gap()` now collects every path the action names -- path-like words, the value of
  `--opt=PATH` / `-CPATH`, redirection targets (`>`, `>>`, `2>`, `&>`), and the file arguments of file-writing commands
  (`cp`, `mv`, `tee`, `rm`, `install`, `tar`, `dd of=` ...), also inside a quoted `bash -c` or `ssh` command -- and
  requires each to resolve (symlinks and `..` followed) inside one of the plan's `dir:` targets or to match another
  target of the plan, with none protected (`is_protected()` / `is_keeper_protected()`). It fails closed on what it
  cannot judge (variables, command substitutions, escapes, a wildcard before the last component, remote `host:path`),
  and never covers a stage that runs elsewhere (`ssh`, `scp`, `pct`, `docker exec/run`, `kubectl`): remote work needs
  plain targets. **Plain, non-`dir:` targets behave exactly as before** (any one matching word covers), including in a
  plan that mixes both kinds. A relative `dir:` target is no longer a grant. The refusal names the offending paths and,
  for a `dir:` plan, says that every path must be inside.
- **go-gate: relative paths are resolved against the agent's cwd for `dir:` matching.** `real()` resolved a relative
  word against the daemon's own cwd, unrelated to where the agent runs. They now use `go_gate.CWD` (the hook input's
  cwd), followed through the command's own `cd`/`pushd`/`popd` per stage (`STAGE_CWD`); with no cwd, or one that cannot
  be resolved statically, a relative path cannot be judged and is not covered.
- **keeper: the "requested after a refusal" note expires after 10 minutes.** It was stored on the session and shown on
  the next proposal's card, once, however unrelated and however much later. It is now timestamped and dropped when
  older than 10 minutes (state written without a timestamp is dropped too).
- **Tests.** `DirAllPaths` (cp/mv/ln/install, `tee`, every redirection form, `--target-directory`/`-t`/`-C`/`of=`,
  `ssh`/`pct`/`docker exec`/`bash -c` nesting, symlinks pointing out, `..` inside a path, go-gate and keeper protected
  paths, unjudgeable paths, wildcards, a mixed command with one path in and one out, file tools judged on their file,
  plain targets unchanged), `DirRelativePaths` (including a relative `..` escape and a daemon cwd that differs from the
  agent's), 3 keeper tests for the expiry, and `DirRuleMutation`: it breaks 8 parts of the rule one at a time in a copy
  of `go_gate.py` and requires the `dir:` tests to fail on each (and to pass on an unmodified copy).
- **go-gate + keeper: the refusal says what a plan does not cover, instead of just that it does not (19/10).** A
  dozen cards in one real day traced back to the same cause: a plan covered the intent, but a temp filename, a
  quoted path, or an action word (`pull`, `rm`, `git commit`) was not cited word-for-word, and the old reason
  ("the approved plan 'X' does not cover this {cat} action") never said which — so the owner approved a card,
  watched it get refused again on the next slightly different word, and proposed another. `go_gate.py`'s
  `coverage_gap()` is `covers()`'s logic, unchanged, turned into a diagnostic: it returns the missing action
  category (and what the plan does allow) or the specific path/filename/host-looking words in the command that none
  of the plan's targets cover (and what its targets are), instead of a plain yes/no. `describe_gap()` turns that
  into the extra clause both `go_gate.py`'s `on_pre_tool()` and `keeperd.py`'s `check()` now append to their deny
  reason. `candidate_targets()` picks the target-like words (a path, a filename with an extension, a hostname, an
  IPv4) and runs each one through the existing `safe_words()`/`redact()` masking before it is ever returned, so
  nothing secret-shaped reaches the reason, a log, or a Telegram card. No protection changed: `covers()` is now
  `coverage_gap(...) is None`, same control flow, same order of checks (category, the `script` carve-outs for
  exec-dirs and git's exec surface, then targets), just with the first blocking reason kept instead of discarded.
  **keeperd** also carries the gap, once, onto the *next* proposal's card when it follows a refusal in the same
  session (`Keeper.check()` stores it as `last_gap` on the session; `propose()` consumes it; `render_plan_card()`
  shows it as "Requested after a refusal: …") — context for the owner without a new kind of disclosure, since it is
  the exact same sanitised text the agent already reads, never the raw command.
- **go-gate + keeper: `targets=dir:<path>` (K-dir, 19/10), an explicit, visible subtree grant.** A target is
  normally one path/file/host, matched whole-word; a literal path target already covered its own sub-paths as a
  side effect (K7's "a prefix covers its sub-paths, kept on purpose"), silently. `dir:<path>` makes that choice
  explicit instead: the plan's own author has to write `dir:`, and `render_plan_card()` shows a warning line for it
  (next to the existing ones for `script`/`delete`/no-targets), so the owner is never approving "everything under
  this directory" without seeing that in the card. Refused outright — never matches anything, as if the target were
  missing — for `/`, the agent's home, go-gate's protected paths (`is_protected()`) and the keeper's own
  (`is_keeper_protected()`: `/etc/keeper`, `/var/lib/keeper`, `/opt/agent-guardrails`, the managed-settings file),
  checked both against the declared directory itself and against every matched token, so a broader grant
  (`dir:/etc`) cannot launder a path that resolves inside one of those. Matching resolves symlinks and `..` through
  the same `real()` every other path check here already uses, so a token that resolves outside the granted
  directory (a literal `..`, a symlink inside it pointing out) is judged on where it actually points and is not
  covered; see `docs/design-keeper.md` ("`dir:<path>` targets") for the TOCTOU compromise this accepts, the same
  class already open for every path check, not a new one. 10 new tests (`go-gate/test_go_gate.py`'s
  `DirPrefixTarget`): a valid prefix, a look-alike sibling (`news` vs `newsletter`/`news-backup`), a `..` escape, a
  symlink escape, both protected-path guards (including the broad-`dir:`-reaches-`/etc/keeper` case), `/` and home
  refused, no wildcard/empty prefix, and the pre-existing bare-path behaviour left untouched -- plus 4 more for
  `coverage_gap()`/`describe_gap()` itself and one each for the deny message in go-gate's own hook and in keeperd,
  including the carried-once card context (`test_go_gate.py`'s `Scope`/`Hook`, `keeper/test_keeper.py`'s
  `StateMachine`). Mutation-checked: 2 deliberate reverts (`describe_gap()` gutted to `""`; the per-token protected
  re-check dropped from the `dir:` match loop) each turned exactly the test built for it red.
- **keeper: the hook entry gets an explicit `timeout`, and `--wait` is kept under it (independent review of PR #16,
  19/10).** `--wait` keeps the PreToolUse hook process blocked, but the installer registered the hook with no
  `timeout`, and `wait_max_sec` defaulted to 1800 s. Per the Claude Code hooks documentation, command hooks default to
  600 s and a PreToolUse hook that times out does NOT block the tool call: the call continues through the normal
  permission flow. A wait longer than the timeout would therefore have ended in a fail-open outcome instead of a deny.
  `install-keeper.sh` now writes `"timeout": 60` into the hook entry (`--hook-timeout N`), a reinstall updates an
  existing keeper entry in place (an old one without timeout is upgraded, never duplicated), and `wait_max_sec` drops
  to 50 s (`--wait-max N`, config key `wait_max_sec`). Rule, documented in `keeper/README.md` and the design: hook
  timeout >= `wait_max_sec` + 10 s. The installer refuses a combination that breaks it (nothing is written) and
  keeperd, which reads the new config key `hook_timeout_sec`, clamps every `--wait` to `hook_timeout_sec - 10` and
  warns at start-up if the configured `wait_max_sec` does not fit. An operator who wants a longer wait raises both
  numbers. Tested: valid JSON with the timeout, idempotent reinstall, upgrade of an old entry, refusal and boundary,
  the clamp; mutation-checked on the clamp, the installer's refusal and the in-place upgrade. Not verified: what Claude
  Code does in a real session when a hook exceeds its timeout (documented, not observed).
- **keeper: `keeper-propose --wait SECONDS`, so the agent's session learns a plan was decided without re-running
  its own command (owner decision, 19/10).** Until now, the only way to find out a plan had been approved was
  for the agent to run `keeper-status` again and read its own reply. `--wait` (default: no wait, exactly the prior
  behaviour) makes the SAME Bash tool call that proposed the plan stay blocked -- on the same Unix socket, no new
  channel -- until a human decides or `wait_max_sec` (50s by default, see the next entry) passes, then returns one of four outcomes
  in its (still denied; nothing ever runs) reason: approved, rejected, expired before a decision, or the wait
  itself running out while still pending. Nothing about what counts as approved changes: `decide()` is untouched,
  and the new, read-only `status` socket op it feeds only ever reports what `decide()` already wrote, by the
  plan's fingerprint, never its text or scope, through the same peer-uid gate as every other op. Its own
  vocabulary is deliberately closed to four words (pending/approved/rejected/expired) -- a fingerprint keeperd
  never saw answers "expired" too, so there is no fifth, distinguishable "unknown" a socket client could use to
  probe for live fingerprints. The wait polls rather than holds keeperd's lock, so a session waiting on its own
  proposal cannot block a button press, another session's check, or `/stop`. `keeper-propose`'s hourly limit,
  hash, nonce and replay protection are all unchanged; `--wait` is parsed and clamped on the hook side only, and
  never enters the plan's fingerprint. Tested (`test_keeper.py`, `test_block_dryrun.py`): approved, rejected,
  expired (both a late click and the daemon noticing on its own, with nobody clicking anything), the wait running
  out while still pending, two simultaneous plans tracked independently, an unknown plan, a daemon that is down
  from the start or stops answering mid-wait, and that the default (no `--wait`) behaves exactly as before.
  Mutation-checked: the approve-branch ledger write disabled, and the `status` op's peer-uid check reordered past
  it, each in a scratch copy -- the relevant test fails both times.
- **keeper: several plans can be active in one session at once (production incident, 20/10).** `s["active"]` was a
  single plan per session: approving a new one replaced it outright, so approving a small 30-minute card while a
  parallel sub-agent's broad 300-minute plan was still running threw the broad plan away mid-task, refusing work
  that had nothing to do with the small card just approved ("the approved plan X does not cover this action"). It
  is now a list, bounded by `max_active_plans` (config key, default 3, hard cap 5 enforced in `Keeper.__init__`
  regardless of what the config file says).
  - **Coverage stays single-plan.** An action is allowed when at least one active plan covers it whole --
    `go_gate.covers()` itself is unchanged, and `check()` never adds up the targets or actions of two different
    plans to approve something neither covers alone (that would be exactly the implicit scope-widening the keeper
    exists to prevent). The one exception: a compound Bash command go-gate already splits into stages can have
    different stages covered by different plans, each still in full -- this already existed for a single active
    plan and is unchanged, just checked against every active plan instead of only one.
  - **The cap evicts the oldest, never silently.** Past `max_active_plans`, approving a new plan drops the oldest
    active one (the plan just approved is never a candidate, by construction). The approval card says what
    approving it will do *before* the tap ("adds to: …", "renews: …", or which plan the cap would drop); the
    confirmation names the dropped plan; `/plans` and the log get a `plan-evicted` event; the agent sees the
    current active ids in `keeper-status` and in any later refusal's reason.
  - **Renewal.** Approving a plan whose `id` matches one already active replaces it in place (fresh hash, fresh
    expiry) instead of adding a second entry, and never counts against the cap or evicts anything.
  - **`/stop <id>`** ends only the named plan (active or pending), in every session; `/stop` with no id still ends
    everything, unchanged. `/status` and `keeper-status` list every active plan of a session, never just one.
  - **Compatibility:** `migrate_state()` turns an old `state.json`'s single `active` dict into a one-element list
    on load, same plan, same hash, same expiry -- nothing it already granted is widened or dropped.
  - 16 new tests (`keeper/test_keeper.py`, class `MultiPlan`): two plans each covering a different command; a
    command covered by only one; by neither; the multi-object "no union of two plans" case and its compound-command
    exception; the cap evicting the oldest with a logged, told-to-both-sides message; a hard cap of 5 regardless of
    config; renewal by id; independent expiry per plan; `/stop`, `/stop <id>` and the unknown-id case; `/status`
    and `keeper-status` listing every plan; the card's preview line through add/renew/evict; migration from an old
    `state.json`, including one holding an already-expired plan. Mutation-checked (disabling the cap guard, letting
    two plans' coverage union instead of requiring one to cover whole, and disabling the migration, each in a
    scratch copy): every one of those breaks exactly the test meant to catch it. The existing 138 keeper tests,
    `test_block_dryrun.py`'s 30, and every other suite in the repo (council, secret-guard, go-gate, leak-check)
    stayed green, unmodified.
  - `docs/block-mode-dry-run.md` gets a third checklist part (two proposals) exercising this by hand: a second
    plan must not throw away the first, `/status` must list both, and `/stop <id>` must end only the one named.

- **README, CHANGELOG and the IT-leaders pages: made the status lines true again (owner review of PR #13, 17/10).**
  The README and this changelog's intro still said the keeper "runs in observe mode" with block mode as "the next
  step" -- stale since 12/10, when block mode started after its end-to-end dry run. Both now say the real state:
  observe from 08/10, block since 12/10, a trial under way, v1.0 after it. `docs/for-it-leaders.md` and the French
  page: the "In daily use" row now says the approval mechanism has run in block mode on the owner's own laptop
  since 12/10, with the trial under way, and names what real use found that the dry run and the tests had not
  (the "Stop everything" button disappearing once a plan is decided, late approval clicks, the hourly proposal
  limit raised from 3 to 8) as a point in favour of piloting in observe mode first. Both pages also overstated
  secret-guard: "stripped out of command output before the agent ever sees them" reads as a barrier; per
  `secret-guard/README.md`, it is a hook that refuses a command unless its output goes through a masking filter,
  running in the agent's own process -- a safety net for a cooperative agent, not a barrier against a manipulated
  one, unlike the approval step, which is the strong layer. Recounted the test suites on current main (297 tests
  across council/secret-guard/go-gate/keeper/leak-check): "nearly 300" still holds, left unchanged.
- **docs: a plain-language page for IT leaders, English and French (17/10).** `docs/for-it-leaders.md` and
  `docs/fr/pour-les-dirigeants-it.md`: a five-minute, non-technical read for a CIO/IT manager — the 30-second
  pitch, a three-layer explanation with a mermaid diagram, an evidence table (every number traced to this
  changelog or `docs/results.md`), honest limits stated plainly, what the pattern changes for an IT department,
  a short FAQ, and how to pilot it. Linked from the README's "Start here".
- **go-gate: oracle + corpus for F4, the 13 `opaque/unbalanced` commands from a week of block-mode observation
  (14/10), no behaviour change.** The owner's log kept only each command's head, never its arguments (5 `ssh`, 5
  `pct exec ; ssh …`, 2 `bash`, 1 chained `bash ; pct exec ; ssh … sleep`) — so `go-gate/test_balance_oracle.py`
  reproduces the CLASS of shapes instead of guessing one specific string: nested quoting through ssh/pct exec/
  bash -c, French apostrophes, here-documents, `$'...'`, command substitution, `#`/operators inside quotes, line
  continuations. 355 generated commands, each checked against `classify()`'s real recursive pipeline (not
  `scan()` alone on the raw string — the actual bug lives two levels deep, in a reconstructed inner command, so
  checking only the top level would have missed it).
- **go-gate: reverted the ssh re-quoting change from the previous entry (owner review, 14/10).** The re-quoting
  did not model what the remote shell receives. ssh's handling is back to exactly what it was on `main`.
- **go-gate: corrected the oracle's other side of the comparison (owner review, 15/10) — `bash -n` must run on
  what the deepest REAL shell in the chain actually parses, not on the local command line.** ssh, pct/qm exec,
  docker exec and bash -c each hand an inner string to another real shell (a login shell on the remote host for
  ssh; the `-c` argument of a literal nested shell for the others); that inner string is not always "the local
  line, re-quoted" — ssh in particular never re-quotes at all (see the revert above). `real_shell_hops()` in
  `go-gate/test_balance_oracle.py` rebuilds that chain the way each tool really builds it, and `real_valid()`
  requires every hop to parse. Recomputing the disagreement table this way: only 2 of 355 commands are real false
  positives (the already-known `$'...'` ANSI-C gap), down from the first version's 26 — the other 24 were
  ssh-shaped commands that are genuinely unparsable once they reach the real remote shell, where `opaque` was
  always the correct, safe answer. 33 of 355 are now correctly counted as genuinely unbalanced (up from 9, since
  the corrected comparison catches more of them), 0 are left incorrectly un-flagged. See PR description for the
  full table.
- **go-gate: 24 disguise tests for the nested-quote path -- ssh/pct exec/docker exec/sh -c unwrapping a quoted
  inner command and re-scanning it (F4 follow-up, 14-15/10).** This is exactly where an agent legitimately runs
  commands all day, and exactly where a destructive command could hide behind a layer of quoting instead of an
  encoding trick -- `ssh h 'pct exec 100 -- sh -c "rm -rf /x"'`, base64 piped into sh inside quotes, `$(...)`
  building the verb, a heredoc body run by `bash -s`, a quote closing early so the tail runs locally, three
  levels of `bash -c` wrapping `ssh` wrapping `pct exec`'s `sh -c`, `eval`/`printf` building the command string,
  `rm` hiding behind a genuinely-broken apostrophe in a direct-argv `sh -c` (see below). All 24 come back
  `change` or `opaque`, never `read`. No bypass found.
- **go-gate: investigated the real cause of the 13 log occurrences instead of guessing further (15/10) --
  found a second, independent genuine trap in the same family, still correctly fail-closed; no further fix
  needed.** `pct`/`qm`/`docker exec` hand their argument list to a real exec, not a shell -- so when that command
  IS a shell asked for `-c SCRIPT`, SCRIPT reaches the nested shell exactly as the LOCAL shell already dequoted
  it, with no further protection; `bash -c` at the top level is the same trap with no wrapper at all. A
  double-quoted phrase that looks perfectly safe locally (`pct exec 100 -- sh -c "echo c'est fini"`) delivers
  `echo c'est fini` to the nested shell -- a bare, unescaped apostrophe, a real syntax error there (confirmed by
  actually running it: `subprocess.run(["sh","-c","echo c'est fini"])` fails with "Unterminated quoted string").
  `test_balance_oracle.py`'s oracle gained `split_top_level_statements()` (a deliberately simplified statement
  splitter, needed because a plain `shlex.split()` of a whole `;`/`&&`/`||`-chained line has no notion of those
  as operators) so a 2-3 stage chain like the log's own `bash ; pct exec ; ssh … ; sleep` is judged stage by
  stage, and a new corpus category exercising this family directly. Every case agrees with go-gate: a genuinely
  broken phrase (odd apostrophe count) is correctly `opaque`, an accidentally-still-parsing one (even count) is
  judged normally. Combined with the ssh finding above, this is believed to explain most or all of the 13 log
  entries: the agent composing the command made the quoting mistake, not the classifier.
- **keeper: an update that always fails to handle is dropped, not retried forever (owner review of PR #10, 13/10).**
  The previous commit made `self.offset` advance only after `decide()`/`command()` had mutated and saved, so a
  crash retries the SAME update next poll instead of skipping it — right for a transient failure, but an update
  that raises on EVERY attempt (a bug on a malformed field) would then retry forever, stalling every later
  update (an Approve, a `/stop`) behind it until the daemon is restarted. A small per-`update_id` counter (bounded
  by construction: a stuck update blocks everything behind it, so at most one entry is ever live) now retries up
  to `MAX_UPDATE_RETRIES` (3) times — a real transient hiccup still gets its normal retries — then drops it,
  advances the offset past it, and logs `telegram-update-dropped` (`update_id` and the exception type only, never
  the message or callback text).
- **keeper: long-poll hygiene — named timeouts, HTTP 409 Conflict handled distinctly (13/10).**
  `getUpdates`' own 30s/40s (server/client) long-poll timeout is now `GETUPDATES_SERVER_TIMEOUT` /
  `GETUPDATES_CLIENT_TIMEOUT`, named but left at their existing values: confirmed empirically that
  `urllib.request.urlopen()` opens a fresh connection per call (no pooling to go stale between polls), and
  nothing in `api()` or the standard library shows the client timeout keeping a half-open connection alive past
  what Telegram's own `timeout` already bounds. A shorter pair could recover from a stuck poll sooner, at the
  cost of more requests when idle, but that trade-off could not be shown to help here, so left as-is. `getUpdates`
  answering **409 Conflict** (another poller on the same bot token — the usual silent cause of "the bot ignores
  me") is now logged as `telegram-poll-conflict`, not folded into the generic `telegram-error` count, and backs
  off longer (`POLL_CONFLICT_BACKOFF_SECONDS`, 30s) than a plain error (`POLL_ERROR_RETRY_SECONDS`, 5s, also
  named, same value as before): retrying fast against a second poller just trades places with it instead of
  letting it finish and go away.
- **keeper: audited every `keeper.lock` hold for a network call inside it (13/10), chasing the 1-2 minute lag.**
  Reading the code: `send_plan()` already runs after the lock is released at both its call sites (since PR #8's
  send-before-reply fix), and `decide()`/`_revoke_all()` never call the network either — so there was nothing
  to shrink there. `check()`'s own scope (which `propose()` also runs inside, it has no lock site of its own)
  keeps the go-gate classifier call, and must: `classify()` keeps its working state as go-gate module globals
  (`CHANGES`, `KNOWN_VARS`, `CWD`), shared by every concurrent hook request against the one loaded `self.gate`
  object, so narrowing the lock to skip it would let two simultaneous proposals corrupt each other's
  classification — fixing that would mean changing go-gate itself, out of scope here. A new test proves the
  actual bound over the real socket, poll loop and (fake) Telegram: a hanging `send_plan()` never delays a
  concurrent button press or `/stop` by more than a small margin. Mutation-checked (the network call moved back
  inside the lock in a copy): the test then fails, waiting the full hang.
- **keeper: a late click no longer looks like nothing happened (13/10), found while chasing the 1-2 minute lag.**
  `answerCallbackQuery` ran bare in `handle_update()`: a failure there (e.g. HTTP 400 "query is too old" on a
  click handled late) propagated out, skipping `editMessageReplyMarkup` and the confirmation message even though
  the decision was already applied — exactly the "buttons stayed, nothing visible happened" the owner reported —
  and cost `poll()` a 5s sleep before the next long poll, on every such click. The three follow-up calls
  (answer/edit markup/confirmation) are now each independent and non-fatal. `self.offset` moved from the first
  line of `handle_update()` to right after the state-mutating call (`decide()`/`command()`) has mutated and
  saved: never before (a crash there must retry the same update, not skip it forever) and never only after the
  cosmetic follow-ups (so a crash there can't re-apply an already-applied decision either) — the nonce already
  makes a replay harmless, and `/stop` is idempotent, so this can't double-apply anything. `cq["from"]["id"]`
  read defensively (`.get()`), so a malformed update is treated as a stranger instead of crashing before the
  offset could even advance.
- **keeper: timing instrumentation for the 1-2 minute lag the owner reported on clicks and commands (13/10).**
  No behaviour change: `log()`, no free text, kept small by firing only on the slow path. `telegram-update` for
  every update handled (`lag_s`: Telegram's own delay when known, else how long it sat in an already-fetched
  batch; `handled_s`: everything handle_update() does for it, follow-up calls included). `telegram-api-slow` per
  `api()` call, only past 2 s or on failure (method, duration, outcome: ok / timeout / an HTTP status / the
  exception type). `keeper-lock-wait` when waiting for `keeper.lock` itself took over 1 s, with a best-effort
  label for who is acquiring it and who held it before (`check` — which covers `propose()` too, there is no
  separate lock site for it — `decide`, `stop`). `tally()` gets two simple additions, `/summary`'s own text
  unchanged: a `slow` counter and the worst `lag_s` seen in the window.
- **install-keeper.sh and keeper/README.md: say to restart open sessions, and list the new commands (12/10).**
  A Claude Code session keeps the hooks it had when it started; the installer never said that a session open
  during a (re)install needs restarting before it sees the keeper hook. Added to the installer's own "after
  install" output and to the README, right after the install instructions. The README also gets a `/stop` /
  `/status` / `/plans` / `/help` / `/summary` command reference, and the installer's own after-install output
  now lists them too (no test pins that output's exact text).
- **keeper: owner-only `/stop`, `/status`, `/plans` and `/help` text commands (12/10).** Until now "Stop
  everything" only existed as a button on an approval card, and the buttons are removed as soon as any plan is
  decided — so once past the first approval, there was no way left from the phone to revoke an active plan.
  `Keeper.command()` now also answers `/stop` (revokes every active and pending plan, sharing the exact same
  code as the card's Stop button rather than a second copy of it), `/status` (mode, active/pending plans with
  id/actions/targets/time-left, proposals left this hour — structured fields only, never the agent's free-form
  explanation or the raw command), `/plans [n]` (the last plan lifecycle events with id, local time and outcome)
  and `/help`. Same owner-and-configured-chat gate as the existing `/summary`; not reachable from the socket. A
  command can only remove rights or read state: approve, reject and mode switching stay button- or config-only,
  never a typed word. Mutation-checked (the owner check skipped before matching `/stop` in a copy): the stranger
  test then fails.
- **keeper: the new commands show up in Telegram's "/" menu (12/10).** `register_commands()` calls
  `setMyCommands` once at daemon startup, scoped to the configured chat only (`BotCommandScopeChat`) so a
  stranger who finds the bot never sees it; skipped entirely without a configured chat id. A short timeout keeps
  a slow or unreachable Telegram from delaying startup; any failure is logged as `commands-menu-failed` (the
  error type only) and is never fatal to the daemon.
- **keeper: end-to-end dry run of block mode (11/10, council of 11/10, owner review of PR #8).**
  `keeper/test_block_dryrun.py` exercises the real chain the `FakeBot`-based unit tests never touch: hook client
  subprocess -> socket -> `Keeper` -> the real `TelegramBot` HTTP code -> a fake, local-only Telegram Bot API
  (`http.server` on 127.0.0.1, never a real network call) -> button click -> `getUpdates` -> decision -> next
  hook call. 24 tests across refusal, approval, expiry, replay (same update_id twice, a used nonce under a new
  update_id, an old plan's button after a new proposal, a stranger, another chat), a Telegram outage (502, a
  hang past the client's timeout, connection refused), stop, and `/summary`; the daemon-down/no-mode-file case
  was already covered exactly by `test_keeper.py`'s `Socket.test_daemon_down_fails_closed`, so it is not
  duplicated. `TelegramBot` gained `API_BASE` and `DEFAULT_TIMEOUT` class attributes, overridden per test
  INSTANCE (never on the class, so a leaked poll thread from a finished test can only ever keep hitting its own
  dead fake server). The whole file runs in 6-13 seconds depending on which timing-sensitive scenarios run.
  - **Bug found and fixed:** `serve()`'s socket handler replied to the hook (`"plan sent to the human for
    approval"`) BEFORE attempting `send_plan()`, so the agent was told the plan was sent even when Telegram was
    actually unreachable. `send_plan()` is now attempted first; the reason is rewritten to say so only on
    failure. Proven by a test that fails before the fix and a mutation check that reverts the ordering and shows
    it fail again (3/8 outage tests, the ones that check what the agent is told at propose time).
  - **Second bug, found on the owner's own review: a real Telegram hang still told the agent the wrong thing.**
    `send_plan()` ran with `DEFAULT_TIMEOUT` (40 s), well past the hook client's own 10 s socket read (`ask()` in
    `keeper_client.py`) — so a hanging Telegram made the client give up first, wrongly report "the keeper daemon
    is not reachable", and keeperd's reply then land on a closed socket (`BrokenPipeError`). `send_plan()` now
    uses its own `HOOK_WAIT_TIMEOUT` (5 s, named next to `API_BASE`/`DEFAULT_TIMEOUT`), clearly under the
    client's 10 s; `getUpdates`' long poll keeps 40 s, and every other `sendMessage` (confirmations, `/summary`,
    the startup line) keeps the default too, since none of them run while a hook is waiting. Tested with the
    production constants, no override (a real ~5 s wait, one test), and mutation-checked by setting
    `HOOK_WAIT_TIMEOUT` back to 40.
  - **Installer path fixed for macOS too:** `InstallerEnvLock` hardcoded the Linux managed-settings path; it now
    mirrors `install-keeper.sh`'s own `uname -s` branch instead, so it passes on the owner's Mac as well as CI.
- **docs: owner checklist for the block-mode dry run (11/10).** `docs/block-mode-dry-run.md`: a ~15-minute pass
  on the real machine, right after reinstalling without `--observe`, covering refusal, approval, expiry, replay,
  a Telegram outage (turn networking off briefly), `/status` and `/stop`, and a cleanup at the end — only ever
  with harmless commands (`touch ~/dry-run-marker`/`ls`, never a restart, a delete outside that one file, a
  deploy or a push) — plus the rollback from keeper/README.md and when to use it. The daemon-down and `/summary`
  scenarios are machine-internal and already covered by `test_block_dryrun.py` in CI, so the checklist points to
  that instead of repeating it.
  - **Fixed on owner review of PR #8: step e promised a retry that does not exist.** It said the daemon "retries
    on its own" after reconnecting, and that the agent would report the plan as sent either way. Neither
    matches the code: a failed `send_plan()` is never retried, and the agent is correctly told Telegram could
    not be reached. Rewritten to ask the agent to propose again by hand after reconnecting, and "pass" now
    requires being told the plan could NOT be sent during the outage, not that it was.
  - **Also fixed: the checklist as written would hit `max_proposals_per_hour` (3, a rolling window counted from
    each attempt) around step d.** Not raised, not bypassed: the checklist is now run in two parts at least an
    hour apart. Part 1 (a, b, d, plus step f merged into b's section since Stop needs no proposal of its own)
    spends exactly 3 proposals and ends with a bonus step that deliberately triggers a 4th to show the refusal
    text verbatim; part 2 (c, e) spends the other 3, after the window has rolled over.
  - **Fixed on the owner's first real run of block mode (12/10): four things the checklist got wrong.** (1) Every
    marker command used `/tmp`, which `go-gate`'s `SCRATCH` always classifies as a read — step a's refusal could
    never actually happen. Switched to `~/dry-run-marker` throughout, with a sentence saying why. (2) `targets=
    dry-run` does not cover `dry-run-marker` (K7: a whole token or path segment, never a substring) — steps now
    use `targets=dry-run-marker`, and step d (which never actually runs either of its two proposals) uses `id`
    instead of invented target names to tell its two cards apart. (3) Step f told the owner to press "Stop
    everything" on the card **after** approving it, but the buttons are removed as soon as a plan is decided —
    impossible to follow. Rewritten to use the new `/status` and `/stop` commands instead (the card's button
    still works too, sharing the same code; mentioned as an alternative). (4) Added a first step 0: restart any
    Claude Code session that was already open before the (re)install, since a session keeps the hooks it started
    with. Also added: a note that `keeper-status` only answers when run alone, not chained with `;`/`&&`; and a
    cleanup bullet at the end of the last step (reuses that step's own approval, no extra proposal, since every
    step together only ever touches the one `~/dry-run-marker` file).
- **keeper: the installed hook's environment is locked, and now tested (11/10).** `KEEPER_TEST_MODE` /
  `KEEPER_SOCKET_FOR_TESTS` in `keeper_client.py` are safe only because `install-keeper.sh` runs the hook and the
  `keeper-propose`/`keeper-status` wrappers with `/usr/bin/env -i … -I`, an empty environment a project's
  `.claude/settings.json` `env` key or a shell profile cannot see through. `test_keeper.py`'s new
  `InstallerEnvLock` runs the installer in `--prefix` mode (no root) and checks the hook command and both
  wrappers for `env -i`/`-I`; mutation-checked by dropping `env -i` in a scratch copy (later fixed to read the
  managed-settings path per platform, see the owner-review entry above).

## v0.10 (11/10/2026)

**The keeper, its first week in observe mode, and go-gate against disguised commands.** keeperd enforces go-gate's
decision under a separate user, with approval on a second Telegram bot; a week of its would-deny log was reviewed and
its false positives fixed; go-gate was run against a catalogue of disguised commands. A multi-model council reviewed
the last two pull requests before the tag; its four items are fixed or, for one, documented as a known limit.

- **go-gate and docs: council review of PR #6/#7, before v0.10 (11/10).** A multi-model council flagged four
  items, owner-verified; fixed in commits of their own:
  - **MCP: the server-prefix strip could erase a write verb.** `_mcp_method` drops the method's first word when
    it matches the server segment, before `mcp_writes` ever ran — a hostile MCP server picks its own name, so
    `mcp__delete__delete_search` stripped to the innocuous-looking `search`. `classify()` now also checks
    `mcp_writes()` on the full, unstripped method; a write verb in either form is a change. An empty method
    (nothing left after the drop, or empty to begin with) is also never a read.
  - **`is_action_url()`, two leftovers.** A `/`-segment is now also split on its first `;` before comparing
    (`restart;jsessionid=X` still reaches "restart" — containers route on the part before it and ignore the
    rest). Percent-decoding that is still changing after the bounded rounds now returns True (an action URL)
    outright, instead of matching whatever half-decoded text it got to.
  - **Accepted false positive.** Comparing the last path segment with its extension stripped (added for
    `restart.php`) means `https://h/status/sync.php` — a plausible read-only status page named "sync" — is now a
    change too, since `sync` is one of the action words. Not fixed: the project's own rule is to classify as a
    change when in doubt, and an allowlist of "safe" page names would need to be complete to be worth adding,
    which a blocklist/allowlist of this shape never is (same reasoning as the awk/sed program checks elsewhere in
    this file).
  - **Symlinks under keeperd — owner decided B (document, don't fix for v1).** The agent's home being mode 750
    means `_keeper` cannot traverse it, so `git_repo_is_safe` cannot resolve a symlink inside a declared safe
    repo pointing at another repo, and `_nested_git_between` skips what it cannot stat; such a symlink is then
    judged as the safe repo. No installer change: see docs/design-keeper.md, Known limits, for why (the symlink
    needs a prior approved write to exist; the ACL that would fix it is real installer work better done
    deliberately) and `go-gate/test_disguise.py`'s `SymlinkInSafeRepo` for the documented behaviour.
  - The LangGraph `interrupt()` row in "How this compares" is marked **not verified**: `docs.langchain.com` could
    not be reached from this environment (checked three times across two sessions), so the row still rests on a
    secondary summary of the official docs, not a direct read.
- **docs: "How this compares" — six peer projects and the LangGraph HITL pattern (11/10).** A dated table in
  README.md, sourced from each project's own README/docs only (no blog posts, no sponsored write-ups): tarides/
  sudo-proxy, luisgf/infrabroker, BrightbeamAI/chap, lacs-project/sysknife, OthmaneBlial/term_mcp_deepseek,
  Proofpane, and LangGraph's `interrupt()` pattern. Columns: where the approval lives, what it covers, its
  granularity, its out-of-band channel, an observe mode, an audit log, and whether secrets are kept from the
  model. States plainly where others are stronger (infrabroker's and sysknife's signed, hash-chained audit logs
  versus keeper's plain `log.jsonl`; sysknife's typed-action catalogue versus go-gate's heuristic classifier), and
  marks cells "not verified" rather than guessing, including every claim that depends on Proofpane's closed-source
  daemon.
- **go-gate: disguised-command test suite from the apex catalogue (11/10, closed the class on a follow-up owner
  review).** `go-gate/test_disguise.py` translates encoding/decoding, Unicode look-alikes, quoting/splitting,
  indirection, substitution/redirection and path-trick techniques (from NirDiamant/agents-towards-production's
  `tutorials/agent-security-apex/`, techniques only, not its recommendations) into shell and MCP forms, calling
  `classify()` on strings only: no command is run, nothing touches the network. Two real bypasses found and
  fixed, smallest change first, each proven by a test that fails before the fix and a mutation check that breaks
  the fix and shows the test catch it. A follow-up owner review found both fixes closed their exact example but
  not the class, so each was widened once more, measured against real tool names to rule out new false positives:
  - **`mcp_writes()`** only ever checked the first split word of an MCP method name, or a word right after
    and/then/or; a method with no separator or case boundary at all (`getanddeleteitem`) never splits, so the
    embedded "delete" went unseen while the leading "get" still read as a read. Closing the exact example: it also
    searches a single, unsplit word for a write verb anywhere in it. Closing the class: a write verb still hid in
    a non-first, non-whole-method word when and/then/or was fused onto it with no separator
    (`get_itemanddelete`, `listanddelete_item`); it now also searches every word for that specific fusion. A
    broader "any write verb anywhere in any word" rule was tried first and rejected: measured against 94 real
    tool names from the GitHub, Google Drive, Slack and Chrome DevTools MCP servers, it misclassified
    `get_commit`, `list_settings`, `get_check_run`, `list_commits` and `search_commits` as changes.
  - **`is_action_url()`** matched action words and query keys against the raw path and query text, so a
    percent-encoded one (`%72estart`, `%77ebhook`, `%61ction=`) never spelled out the word it was checking for.
    Closing the exact example: it percent-decodes before matching. Closing the class: one round of decoding
    missed double encoding (`%2572estart`), an encoded separator revealing a real `/` or `?` only after its own
    wrapper is peeled off (`api%2Frestart`, `restart%3Fa`), and a file extension on the action word
    (`restart.php`). It now decodes the whole URL to a fixed point (bounded at 3 rounds) before re-splitting path
    from query on the now-real separators, and compares the last path segment with its extension stripped too.
- **go-gate and keeper: first review of a week of observation (11/10).** 1,186 would-block events in go-gate and 414
  would-deny events in the keeper; most are real changes (python with subprocess, `sed -i`, `pct push`…), three
  classes were false positives:
  - **`cd ~/repo && git status` was a script.** `cd` to `~/…`, `$HOME/…` or `${HOME}/…` is now resolved to the
    agent's home, so the git read is judged against a declared safe repo. `~user`, other variables, globs and
    `cd ~` alone stay unknown or are judged on the resolved directory (still opaque unless the home itself is declared).
  - **MCP servers that repeat their name in the method** (`firecrawl_search` on the Firecrawl server) were never
    reads. The repeated server word is dropped before the verb check, so `search` is a read and `monitor_create`,
    `crawl` and `get_and_delete_x` stay changes. A read tool given an action URL (webhook, `/restart`) is a change,
    as for curl.
  - **`ffprobe`, `mediainfo` and `apt-mark showhold|showmanual|showauto`** are reads; `apt-mark hold` is not.
  - Keeper: **idle long polls that time out** (`getUpdates`, 30 s) were logged as Telegram errors, 337 in 7 days.
    They are now their own event and a separate line in `/summary`; no update is lost (the offset only moves after a
    successful poll). `sendMessage` failures, which could delay an approval, stay errors.

- **keeper: two fixes after the first reinstall (11/10).** The summary breaks Telegram errors down by exception type
  (a laptop asleep gives URLError, a bad token HTTPError), validated like the other printed names. The installer waits
  for launchd to unload the old service before bootstrapping the new one ("Bootstrap failed: 5" on macOS). It also
  checks only the parents of /var/lib/keeper, which belongs to _keeper by design (#3).
- **keeper: review the log before block mode (11/10).** Three things, none of them changes how approvals work.
  - **`/summary` on the keeper bot** (alias `/resume`, `/summary 1` for one day, 7 by default, up to 30): counts of
    would-deny / denied / allowed-under-a-plan by tool and category, the 10 most frequent command shapes, plans
    proposed / approved / rejected / expired, Telegram errors, ignored attempts. Owner and configured chat only; not
    reachable through the socket. The log now keeps a *shape* (first word, the subcommand for known CLIs such as git or docker, and the category; never
    arguments) for each refusal;
    the summary re-validates what it prints and masks it. `sudo keeper-summary [days]` prints the same for root (mode 700,
    not setuid). Design: "The log summary" in `docs/design-keeper.md`.
  - **The startup message matches the mode.** In observe it no longer says "changes now need your approval": it says
    nothing is blocked and events are only logged, and points to `/summary`.
  - **Messages in French.** Everything the human reads on Telegram comes from one catalogue per language: config key
    `lang` (`en` default), `install-keeper.sh --lang fr`. What the agent reads stays English. The English approval card is
    byte-identical to before.
  - Small fixes on the way: `poll()` split into `fetch_updates` / `handle_update` / `handle_message` (button handling moved
    unchanged), the log is stamped by the injected clock, the config and token files are closed after reading.
- **classifier: follow-ups from the PR review (09/10, R1-R4).** A second pass on the same PR found more "read" commands
  that execute or write; each has a test that fails before the fix.
  - **R1 (cd):** a `cd`/`pushd`/`popd` before a git command is followed, so `cd /tmp/x && git status` is judged against
    `/tmp/x`, not the session cwd. A non-literal target (`cd "$v"`, `cd $(...)`, `cd -`, `cd ~`, `popd`), a subshell or
    a group all make a following git read opaque.
  - **R2 (launchers):** `xargs`/`parallel` are classified by the command they launch; a shell/interpreter/by-path/
    unknown target is opaque, whatever the input mode (pipe, `<`, `-a`, `--arg-file`). An input redirection no longer
    leaks its file as an argument. `timeout`/`watch`/`setsid` are treated as prefixes (classified by the inner command).
  - **R3:** `env VAR=val cmd` (and `env -S`, `-i`, `-u`) applies the dangerous-variable rule like a bare prefix;
    `sort --compress-program` and `openssl -config`/`-provider` are opaque.
  - **R4:** writing a safe repo's git-exec surface (`.git/config`, a hook, `.gitattributes`/`.gitmodules`, or
    `git config` of an exec key) needs `actions=script`, not `edit`; a nested repo does not inherit the parent's trust.
  - Friction on the 138-command admin set: 0 new reclassifications versus the previous PR state.
- **classifier: a read command can no longer execute or write (08/10, review FIX FIRST).** A second review found a
  class the classifier mislabelled as reads, so they passed with no plan, in block mode too. Each is reproduced by a
  test that fails before the fix and passes after.
  - **go-gate:** read commands that run a program or write through an option or a config file are now opaque (needs
    `script`) or a change: `ssh` with `ProxyCommand`/`ProxyJump`/`LocalCommand`/`-F`/`-J`/`-W` (K1); `awk -f`, a pipe to
    a command, `system`/`getline`/`ENVIRON` (K2, K3); `sed -f`, `e`/`s///e`, `w`/`s///w` (K4); `curl -K`/`--config` and
    `wget -e`/`--config` (K5); `tar --to-command`, `openssl -engine`; a `PAGER`/`MANPAGER`/`LESSOPEN`/`GIT_*` prefix.
    The `<>` and `N<>` redirections count as writes (K9). psql reads cannot write or run through a function
    (`lo_export`, `pg_read_file`, `COPY`, …) or `\!`/`\o`/`\g` (K8). A plan target matches a whole token or path
    segment, not a free substring, so `targets=web` no longer covers `webserver` or `cobweb` (K7).
  - **keeper (K6):** a git read verb runs repo-local config (`core.fsmonitor`, `core.pager`, an alias `!cmd`), so it is
    a read only in a repo declared safe. `install-keeper.sh --safe-git-repo DIR` (repeatable) fills `safe_git_repos`
    (empty by default: every git read needs a plan). The hook forwards the tool call's cwd so keeperd resolves the repo.
  - **secret-guard:** bare relative secret paths (`cat config.php`, `cat shadow`, `cat app.ini`) are refused like
    `./config.php` was (S1); `/etc/keeper/` and `bot.token` are secret paths (L1).
  - **docs:** the design and the READMEs now separate "the approval cannot be forged" (true) from "the gate blocks every
    change" (a heuristic classifier), with a Known limits section and an emergency rollback procedure.
  - **Friction:** on a 447-command corpus (existing tests + hook-gym + common admin reads), 0 commands change kind,
    except git reads, which become opaque until their repo is declared safe (by design).
- **keeper (go-gate step 2):** `keeper/` adds:
  - `keeperd`, which holds approvals under a dedicated user;
  - a second Telegram bot with Approve, Reject and Stop buttons, where approvals are bound to the plan's fingerprint and work once;
  - a thin hook client that fails closed;
  - `keeper-propose`, which keeperd answers itself inside the hook's check, so the plan is bound to the real session;
  - an installer that only does a dry run unless `--apply`;
  - 38 tests, including forged, replayed, stale and stranger approvals.

  The council reviewed the code before release (08/10, CORRIGER D'ABORD 4/4), and these changes followed:
  - the daemon user gets a private group;
  - code goes under `/opt/agent-guardrails`, with a check of every parent directory;
  - existing managed settings are merged instead of skipped;
  - Stop ends every plan;
  - Telegram is called outside the lock, and the socket has a timeout;
  - the approval message warns on `script`, `delete` and plans without targets;
  - an edit plan cannot write programs into `~/bin`-style directories.

  Design: `docs/design-keeper.md`. Not installed anywhere yet.
- **go-gate classifier:** these are now opaque, because a name or `PATH` says nothing when the agent controls the file:
  - a program run by path from outside the system directories (`/tmp/x/cat`, `./cat`, `~/bin/cat`);
  - commands that set `PATH`, `LD_*`, `DYLD_*`, `PYTHONPATH` or `BASH_ENV`;
  - aliases and function definitions.

  On about 5,300 real commands, this changed three classifications.

## v0.9.1 (07/10/2026)

**After a targeted audit of the v0.9 changes** (gemini, 07/10). Its cases were re-run before any fix: 6 confirmed, 4 refuted (`cat <(echo .env)` and `exec 0< .env` were already refused, `docker start -a web` was covered, a replayed GO fails the 15-minute freshness check anyway), 1 already documented (an agent that deletes its own transcripts before the daily copy).

- **secret-guard:** brace expansion is applied before matching (`cat .{env,txt}`); `awk '{print $ 2}'` with a space counts as value extraction.
- **go-gate:** literal variables are resolved before the protected-path check, and every word of a changing command is checked (`F=~/.claude/settings.json; echo x > $F`, `cp x $F`); `print(..., file=sys.stderr)` and `import os.path` are reads; an MCP tool is a change only when a write verb is its leading verb or follows and/then/or (`get_commit` and `list_settings` are reads, `get_and_delete_x` and `getAndDeleteX` changes); plan ids are kept to ASCII so `GO <id>` can name them.
- **secret-guard, found in use the same evening:** its own refusal message recommended `grep -o '^[A-Z_]*='` (key names only), which the new extraction rule refused. `grep -o` now counts as extraction only when it keeps what follows the `=`, and extraction is judged within one pipeline.
- **leak-check:** XML attributes named `key`, `id`, `keyid` or `name` are indexes, not secrets; other attributes need the normal 12-character length.
- Replay of 5,143 real commands: secret-guard +2.7% refusals against v0.8 (unchanged from v0.9), go-gate +0.7% changes (was 0.8%).

## v0.9 (07/10/2026)

**After a sixth external audit** (gpt, 07/10), which ran the hooks against fake secrets and reported, among others, 16 commands that printed a secret past secret-guard, a deletion go-gate classed as a read, and secrets leak-check never inventoried. Every finding below was reproduced before being fixed, and each fix has a test built from the audit's exact case. Thank you to the auditor.

- **What did not change:** these are hooks that run with the agent's rights and read the text it writes. They catch a cooperative agent's mistakes; an agent trying to get around them still can. The README now says so up front.
- **secret-guard:** quotes removed and globs expanded before matching; input redirected from a secret file, copies to stdout and more readers (`dd`, `tee`, `openssl`…) count as reads; a reader on a path only known at run time must be masked; inline scripts that open files must be masked; redefining `mask` or `PATH` is refused; cutting a bare value out before the mask is refused; `# secret-ok` is logged and no longer covers reading a secret file. The `mask` filter also hides a line made of one bare token (not pure hex: hashes stay readable). 235 test cases. Agreement with the blind sets: claude 93% (was 95%), gpt 98% (was 100%), gemini and mistral unchanged; the 2 new disagreements are `cat <secret file> # secret-ok`, refused on purpose now.
- **go-gate:** inline Python is a read only with pure imports; a chat-tool plan is pending only after delivery (PostToolUse); pending plans expire (2 h); old, replayed or non-ASCII GOs are ignored; every object of a multi-object verb must be in scope; MCP tools with a write verb in their name are changes; the gate's state, hooks and settings can't be written under any plan, symlinks included.
- **leak-check:** YAML block values, XML attributes, `.pgpass`, Proxmox `token.cfg`, JSON lists, rclone tokens, decoded Docker `auth`, URL passwords in `json_files`, one-line PEM keys; short and all-digit values under secret names; skipped files listed; a rotated secret leaking again is new. Orchestration: a pass needs the witness, a manifest and a transcript; a failed scan never reuses the old report; a first pass that never comes alerts. 30 unit tests and an offline orchestration test in CI.
- **council:** one blocking member gives HUMAN REVIEW REQUIRED (not "APPROVE, …"); blockers are copied into the report mechanically; a cross-review blocker reaches the verdict; contradictory verdict lines are invalid; same-family members and empty Request/GO are refused; the final request body is masked and overrides can't replace messages.
- **Friction, measured:** the 5,062 Bash commands of my own past sessions were replayed through v0.8 and v0.9. secret-guard refuses 2.7% more of them, mostly `# secret-ok` on reads of secret files (refused on purpose now); a first draft refused 16% and was narrowed before release. go-gate classes 0.8% more of them as changes (Python importing local or file-system modules).
- **After the council's review of v0.9:** `open(path, "w")`, a variable mode or `print(file=…)` makes Python a change; a channel GO dated in the future is ignored; an expired plan's GO tells the agent it was not applied.
- **First real runs, before release:** the new leak-check readers first reported 19, then 3, "new leaks" on my setup: all placeholders (rclone's `token_type: Bearer`, an `os.environ/…` reference, LiteLLM's `sk-1234`, `<hidden>` values in a redacted config). They are not values any more, with tests. And the offline orchestration test, run on the real server, sent its fake alerts through the real channel because the settings file overrode it; tests now set `LC_ENV_FILE=/dev/null`.
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

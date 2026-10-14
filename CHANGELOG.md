# Changelog

One version scheme: **a repository tag per release**. Components have no version of their own. Commit messages from 06/10/2026 that say "secret-guard v0.3/v0.4/v0.5" refer to the intermediate revisions listed under v0.6.

## Unreleased (towards v1.0)

Next: one week of the keeper in block mode, after a dry run of refusal, approval, expiry, replay and a Telegram outage.

- **go-gate: oracle + corpus for F4, the 13 `opaque/unbalanced` commands from a week of block-mode observation
  (14/10), no behaviour change.** The owner's log kept only each command's head, never its arguments (5 `ssh`, 5
  `pct exec ; ssh …`, 2 `bash`, 1 chained `bash ; pct exec ; ssh … sleep`) — so `go-gate/test_balance_oracle.py`
  reproduces the CLASS of shapes instead of guessing one specific string: nested quoting through ssh/pct exec/
  bash -c, French apostrophes, here-documents, `$'...'`, command substitution, `#`/operators inside quotes, line
  continuations. 355 generated commands, each checked against `bash -n` (syntax only, never executed) and
  against `classify()`'s real recursive pipeline (not `scan()` alone on the raw string — the actual bug lives two
  levels deep, in a reconstructed inner command, so checking only the top level would have missed it). Result: 26
  of the 355 are false positives (bash accepts them, the gate calls them unbalanced) — 24 are `ssh` carrying an
  unquoted remote command with an apostrophe in it, 2 are `$'...'` (ANSI-C quoting) with an escaped internal
  quote. 9 more are genuinely unbalanced on both sides (fail-closed, correct, no action). See PR description for
  the full table and the root cause of each group.
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

# HANDOFF: feat/keeper-observe-review

Branch: `feat/keeper-observe-review` (from `main` at `bfd612e`). Goal: three items for keeperd before block mode.
Delete this file in the last commit once everything is done.

## Status

| Item | State |
|---|---|
| 3. FR/EN messages (`lang`, `--lang`) | DONE, committed + pushed |
| 1. `/summary` (Telegram only) | DONE, committed + pushed |
| 2. Startup message by mode | not started |
| Docs (CHANGELOG, keeper/README, design-keeper) | not started |
| Manual secret scan (no gitleaks in the sandbox), optional `keeper-summary` CLI | not started |
| Draft PR | not opened |

Order chosen: 3, 1, 2 (the observe startup text mentions `/summary`, so it needs item 1).

## Done, where to look

- Item 3: `keeper/keeperd.py` `MESSAGES` (en, fr), `t()`, `norm_lang()`, `Msg` (str carrying its catalogue key), `IGNORED`,
  `render_plan_card()`, `Keeper.msg()`; `keeper/install-keeper.sh` `--lang en|fr` (`UI_LANG`).
- Item 1, all in `keeper/keeperd.py`:
  - pure helpers before `class Keeper`: `mask_text`, `command_shape`, `split_message`, `event_time`, `tally`, `render_summary`;
  - `Keeper.log` now stamps `at` from the injected clock; `Keeper.check` logs `shape` on would-deny/denied;
  - `Keeper.is_owner`, `Keeper.command` (owner + chat only, `/summary` and `/resume`, optional days 1..30), `Keeper.summary`
    (no lock taken on purpose);
  - `TelegramBot.fetch_updates` (asks for `message` too), `handle_update`, `handle_message`; `poll` just loops.
  - The socket is untouched: any op other than `check` still answers `{"error": "unknown op"}`.
- Tests in `keeper/test_keeper.py`: `Messages`, `InstallerLang`, `LogSummary`, `TelegramCommands`, two in `Socket`.
- Mutation check done by hand (13 guards broken one at a time in a copy: owner check, mask, shape validation, tool whitelist,
  socket op, lock, window, clamp, allowed_updates, language): every one is caught by a test.

## Next: item 2

`start_block` / `start_observe` keys in both catalogues (the existing `started` key is the block text); `main()` in
`keeper/keeperd.py` picks by `cfg["mode"]`; the observe text says nothing is blocked, events are only logged, and mentions
`/summary`. Extract the choice into a small pure function so it can be tested without a network. Test both modes, both languages.
Then drop the old `started` key (and its use in `main()`).

## Left after that

Docs: `CHANGELOG.md` (Unreleased), `keeper/README.md` (`/summary`, `--lang`), `docs/design-keeper.md` (why the summary goes to
Telegram only, threat-model line). Manual secret scan (gitleaks is NOT installed in the sandbox). Optional root-only
`keeper-summary` CLI (`keeperd.py --summary`), only if trivial; beware: running it inside an agent session would put the
(masked) output in front of the agent. Open the draft PR (what changed, test summary line, remaining risks, "Remarks"), delete
this file in the last commit.

## Last test result

go-gate 39 OK, keeper 90 OK (also under Python 3.9.25, 3.11, 3.12, 3.13), secret-guard 9 OK, council 14 OK, leak-check 32 OK;
installer dry-run OK. The `BrokenPipeError`/`JSONDecodeError` traceback printed during the keeper tests also appears on main
(silent-client socket test): pre-existing.

## Remarks for the PR description (things noticed, deliberately not changed)

- `Keeper.log()` raises if the log cannot be written (disk full, wrong permissions); `check()` calls it, so the socket handler
  dies and the hook falls back to its own fail-closed/observe logic. Pre-existing. `command()` now tolerates it for its own audit line only.
- The log is append-only and never rotated; `/summary` reads at most the last 32 MiB (`LOG_TAIL_MAX`).
- A plan whose TTL runs out is dropped silently in `check()` (no log line), so "expired" in the summary counts only
  approvals that came too late.

## Invariants to keep

- The agent never reads the log/state; `/summary` is reachable only from Telegram (owner_id + chat_id), never via the socket.
- Deny reasons returned to the agent stay English.
- No real token / chat id / user id anywhere. No `install-keeper.sh --apply`.
- Do not touch the classifier, go-gate/, or approval logic beyond what the three items need; put doubts in the PR "Remarks".

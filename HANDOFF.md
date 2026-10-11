# HANDOFF: feat/keeper-observe-review

Branch: `feat/keeper-observe-review` (from `main` at `bfd612e`). Goal: three items for keeperd before block mode.
Delete this file in the last commit once everything is done.

## Status

| Item | State |
|---|---|
| 3. FR/EN messages (`lang`, `--lang`) | DONE, committed + pushed (commit 1) |
| 1. `/summary` (Telegram only) | not started |
| 2. Startup message by mode | not started |
| Docs (CHANGELOG, keeper/README, design-keeper) | not started |
| Draft PR | not opened |

Order chosen: 3 first (catalogue), then 1, then 2 (the observe startup text mentions `/summary`, so it needs item 1).

## Done (item 3), where to look

- `keeper/keeperd.py`: `MESSAGES` (en, fr), `t()`, `norm_lang()`, `Msg` (str that carries its catalogue key), `IGNORED`,
  `render_plan_card()`, `Keeper.msg()`, `decide()` returns `self.msg(...)`, `TelegramBot.send_plan()` uses the card,
  `main()` sends `t(keeper.lang, "started")` (one key `started`, to be split by mode in item 2).
- `keeper/install-keeper.sh`: `--lang en|fr` (variable `UI_LANG`), written as `"lang"` in config.json; `--help` updated.
- `keeper/test_keeper.py`: classes `Messages` and `InstallerLang`.
- Proven: the English plan card is byte-identical to the old `send_plan` output (compared by running main's code).

## Next: item 1 (design already decided)

- `TelegramBot`: split `poll()` into `fetch_updates()` (getUpdates with `allowed_updates: ["callback_query","message"]`)
  and `handle_update(keeper, u)` so tests can feed updates with a fake `api`.
- `Keeper.command(from_id, chat_id, text)`: only `/summary` and `/resume` (optional days 1..30, optional `@bot` suffix),
  owner_id + chat_id only (log `command-from-stranger-ignored` for strangers whose text starts with `/`), anything else ignored.
  Compute the summary OUTSIDE `keeper.lock` (the hook must never wait on a log read).
- Log: `check()` must log a `shape` (first word + `…` + `[category]`, never arguments) on would-deny/denied/allowed;
  `log()` should stamp `at` from the injected clock (tests use a fake clock). Old log lines have no `shape`: handle it.
- `mask_text()` helper (module level), `split_message()` (< 4000 chars), `build_summary()`.
- Sanitise every agent-controlled string that reaches the summary (tool names come from the socket).
- Tests: socket `op` for the summary is refused; `keeper-summary` as a Bash command never returns data.

## Left after that

Item 2 (startup by mode: `start_observe` / `start_block`), docs (CHANGELOG Unreleased, keeper/README, design-keeper
threat-model line), manual secret scan (gitleaks is NOT installed in the sandbox), optional root-only `keeper-summary` CLI,
draft PR, delete this file.

## Last test result

go-gate 39 OK, keeper 54 OK, secret-guard 9 OK, council 14 OK, leak-check 32 OK; installer dry-run OK.
(The `BrokenPipeError` traceback printed during the keeper tests also appears on main: pre-existing, from the silent-client test.)

## Invariants to keep

- The agent never reads the log/state; `/summary` is reachable only from Telegram (owner_id + chat_id), never via the socket.
- Deny reasons returned to the agent stay English.
- No real token / chat id / user id anywhere. No `install-keeper.sh --apply`.
- Do not touch the classifier, go-gate/, or approval logic beyond what the three items need; put doubts in the PR "Remarks".

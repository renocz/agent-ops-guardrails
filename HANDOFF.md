# Hand-off — test/block-mode-dry-run (from main, v0.10)

## Done

- **Item 2 (installer env lock): DONE.**
  - `keeper/test_keeper.py`: new `InstallerEnvLock.test_hook_and_wrappers_run_with_an_empty_environment`, runs
    install-keeper.sh in `--prefix` mode (no root, no real install), asserts the hook command in
    managed-settings.json and both keeper-propose/keeper-status wrappers start with `/usr/bin/env -i ... -I`.
  - One-line (3-line, but one comment block) explanation added above `SOCKET = os.environ.get(...)` in
    `keeper/keeper_client.py`.
  - Mutation-checked: `env -i` dropped in a full scratch copy of the repo (keeper/ + go-gate/ + secret-guard/,
    needed for the installer's own file checks), test failed as expected. Not committed.
  - All 5 suites green on Python 3.9 and 3.12.

## In progress / left

- **Item 1 (keeper/test_block_dryrun.py): NOT STARTED YET.** Scenarios a–h, in order. Needs: a local
  `http.server`-based fake Telegram Bot API (127.0.0.1 only), the real `TelegramBot` pointed at it via an
  in-process `API_BASE` class-attribute override (and likely a second small seam, `DEFAULT_TIMEOUT`, to make the
  "hang longer than the client timeout" scenario fit in the ~30s budget — flag this in the final report since the
  task only named `API_BASE` literally), the real `Keeper` in block mode, the real `serve()` thread, the real
  `keeper_client.py` subprocess (same pattern as test_keeper.py's `Socket` class), and the real `bot.poll()` loop
  running in a background daemon thread for the whole test. Key design risk already resolved during planning: set
  `API_BASE`/`DEFAULT_TIMEOUT` as INSTANCE attributes on `self.bot` (not mutating the class), so a leaked poll
  thread from a finished test can never start hitting a LATER test's fake server/port.
  - Known real bug to report/fix in scenario e: `serve()`'s socket handler replies to the hook BEFORE attempting
    `send_plan`, so the agent is told "sent to the human for approval" even if Telegram is actually unreachable.
    Planned minimal fix: move the `send_plan` attempt before `self.reply(out)` in `keeper/keeperd.py`'s `serve()`,
    rewriting `out["reason"]` only on failure. Does not touch the socket wire format or approval logic.
- **Item 3 (docs/block-mode-dry-run.md): NOT STARTED YET.**
- CHANGELOG entry for item 2 not yet added (will batch with item 1's entries, or add now — check before next
  commit).
- CI workflow (`.github/workflows/tests.yml`) does not yet run `test_block_dryrun.py`: needs a new step once the
  file exists for the draft PR's CI to actually exercise it.

## Last test result

5/5 suites green on 3.9 and 3.12, as of the item-2 commit.

## Where to look

- `keeper/keeperd.py`: `TelegramBot` class (~line 628), `serve()` (~line 707).
- `keeper/test_keeper.py`: `Socket` class (~line 1059) is the pattern to extend for the real socket + subprocess
  hook; `Base`/`Clock`/`FakeBot` (~line 15-77) for the state-machine style.

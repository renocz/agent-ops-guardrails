# Hand-off — test/block-mode-dry-run (from main, v0.10)

## Done

- **Item 2 (installer env lock): DONE.** Committed.
- **Item 1 (keeper/test_block_dryrun.py): DONE, all scenarios a-h.**
  - a (refusal), b (approval), c (expiry), d (replay: same update_id twice, used nonce under a new update_id, old
    plan's button after a new proposal, stranger, other chat, none crashes the poll loop), e (Telegram outage:
    502 / hang past timeout / connection refused, at propose time and during the background poll; recovery and
    exactly-once processing of a queued click), f (stop), g (already covered by test_keeper.py's
    Socket.test_daemon_down_fails_closed — not duplicated, noted in CHANGELOG/report instead), h (/summary shows
    denies, cut polls counted apart from real errors).
  - Production changes: `TelegramBot.API_BASE` / `.DEFAULT_TIMEOUT` seam (class attributes, overridden per test
    INSTANCE only); the send-before-reply bug fix in `serve()` (see CHANGELOG), mutation-checked.
  - 24 tests, ~6s, stable across repeated runs. CI workflow updated with a new step.
  - All 5 suites green on Python 3.9 and 3.12 (135 keeper tests = 111 + 24 new).

## Left

- **Item 3 (docs/block-mode-dry-run.md): NOT STARTED.** Owner's ~15-minute checklist, scenarios a-f (g/h are
  machine-side, less critical for the owner's own manual pass but worth at least a line), harmless test commands
  only, the real-machine Telegram-outage method (turn off networking briefly), and the rollback copied from
  keeper/README.md.
- Final French report not yet written.

## Last test result

5/5 suites green on 3.9 and 3.12, as of the item-1 commit. test_block_dryrun.py: 24/24, ~6s.

## Noticed but out of scope

- `.github/workflows/tests.yml`'s go-gate step only runs `test_go_gate.py`, not `test_disguise.py` (added in an
  earlier, unrelated task) — a pre-existing CI gap, not touched here since it is not part of this task.

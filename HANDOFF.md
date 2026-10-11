# Hand-off — feat/apex-bypass-suite (from fix/classifier-review-1110)

## Done

- **Item 1 (go-gate disguised-command suite): DONE.**
  - `go-gate/test_disguise.py`: 10 tests, all passing. Covers encoding/decoding, Unicode, quoting/splitting,
    indirection, substitution/redirection, path tricks, percent-encoded action URLs, MCP fused write verbs, plus a
    safe-read negative set and a safe-MCP-single-word negative set.
  - Two real bypasses found and fixed in `go-gate/go_gate.py`:
    - `mcp_writes()`: single run-on word with no separator (`getanddeleteitem`) hid its write verb. Fixed by also
      searching a single unsplit word for a write verb anywhere in it.
    - `is_action_url()`: percent-encoded action words/query keys (`%72estart`) were not decoded before matching.
      Fixed with a `_unquote()` helper (urllib.parse.unquote) applied to path segments and the query string.
  - Mutation-checked both fixes (broken in scratch copies, test failed 3/3 each time, not committed).
  - All 5 suites (go-gate 50, keeper 110, secret-guard 9, council 14, leak-check 32) pass on Python 3.9, 3.12, 3.13.
  - CHANGELOG entry added under Unreleased.
  - One known false positive documented (not in the repo, see chat report): `mcp__x__getsettings` (single
    run-on word containing "set") now misclassifies as change. Accepted per project philosophy (over-asking is
    the safe failure); will be disclosed in the final report.

## In progress / left

- **Item 2 (README comparison table): NOT STARTED YET.**
  - Need to verify NirDiamant/agents-towards-production's `tutorials/arcade-secure-tool-calling` path, and research
    primary sources for: tarides/sudo-proxy, luisgf/infrabroker, Proofpane/releases, BrightbeamAI/chap,
    lacs-project/sysknife, OthmaneBlial/term_mcp_deepseek.
  - Build dated "How this compares" table in README.md, columns: approval location, coverage, granularity,
    out-of-band channel, observe mode, audit log, secrets kept from model. Mark unverifiable cells "not verified".
  - CHANGELOG entry for item 2.

## Last test result

All 5 suites green on 3.9/3.12/3.13, as of the item-1 commit (see above). No gitleaks run yet (will run before
first push).

## Where to look

- `go-gate/go_gate.py`: `mcp_writes()` (~line 967), `is_action_url()`/`_unquote()` (~line 713).
- `go-gate/test_disguise.py`: new file, root-level structure documented at its top.

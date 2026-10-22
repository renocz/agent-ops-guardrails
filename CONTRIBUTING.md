# Contributing

Thanks for looking. This is a personal project with a narrow goal: guardrails that keep an AI agent from doing
harm on real infrastructure, with honest limits. Contributions that make the guardrails stronger or the limits
clearer are welcome. Because it is maintained by one person, the review is best effort.

## What helps most

1. **A bypass, with a harmless reproduction.** A command the classifier calls a read that is not, an approval path
   that can be forged, a secret that is not masked. Send it as a test case (`go-gate/test_disguise.py`,
   `secret-guard/test_secret_guard.py`) or as a precise description. See [SECURITY.md](SECURITY.md) for how to
   report a real vulnerability privately.
2. **A false alarm.** A normal command that is refused, with the command and the context. Each one is a concrete
   bug in the classifier, not a reason to loosen the rules.
3. **Documentation fixes**: unclear steps, wrong commands, missing limits.
4. **Support for another agent or platform**, as a small wrapper, with a note on what you tested.

## Run the tests

Python standard library only. CI runs Python 3.9 and 3.12 (see `.github/workflows/tests.yml` for the full list):

```
cd keeper && python3 -m unittest discover
cd go-gate && python3 -m unittest discover        # run it from a checkout, not from /tmp: some tests need a real directory tree
cd secret-guard && python3 -m unittest discover
cd docker-proxy && python3 -m unittest discover
cd council && python3 -m unittest test_council.py
cd leak-check && python3 -m unittest test_leak_check.py
```

## Rules of the house

- **A change comes with a test**, and for a guard, a check that the test fails when the guard is removed (a
  "mutation check": disable the line in a scratch copy and see the test break).
- **Say what you did not verify.** If you could not run something (a real server, macOS, a real Docker), write it
  in the pull request. The changelog of this project separates what was verified from what was assumed.
- **No real data**: no real hostnames, addresses, tokens, keys, names or incident numbers in code, tests or
  examples. Test secrets must be obviously fake. If a scanner flags a fixture, list it by exact fingerprint in
  `.gitleaksignore`, not by path.
- **Keep the claims honest.** A guardrail that catches a cooperative agent's mistakes is not "secure against an
  attacker". Wording that overstates will be sent back.
- **Standard library only** for the tools, so that nothing needs installing besides Python and a shell.

## Pull requests

Open the pull request against `main` with what changed, why, how you checked it and what you did not check. The
maintainer reviews and merges; a draft is fine while you are still working. A release is a tag on `main`, with a
section in `CHANGELOG.md`.

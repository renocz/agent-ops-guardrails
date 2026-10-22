# Security policy

agent-ops-guardrails is a personal project maintained by one person. It is about **guardrails for AI agents**, so
reports about a way around a guardrail are exactly the feedback it needs.

## What to report

- A way for an agent to do something the **keeper** should have refused, or to approve, replay or alter an approval
  itself.
- A command that go-gate's classifier calls a *read* but that actually runs a program or writes something (the
  "disguise" class, see `go-gate/test_disguise.py` and "Known limits" in `docs/design-keeper.md`).
- A way to make `secret-guard` print, or let through, a real secret.
- A secret, token or private key committed to this repository.
- A flaw in the installers (`keeper/install-keeper.sh`, `docker-proxy/install-docker-proxy.sh`) that writes
  something it should not, or leaves a directory writable by the agent.

## What is not a vulnerability here

These limits are stated in the README and in `keeper/README.md` and are not secrets:
- The guardrails are hooks that catch the mistakes of a *cooperative* agent. They do not claim to stop a hostile
  agent, a compromised machine or a human administrator who misuses their own rights. That limit is about the hooks
  that run in the agent's own process; a way to defeat the keeper's separate approval (listed above) is in scope.
- An approval for `actions=script` lets the approved script do anything the agent's user can do.
- The classifier is a heuristic, not a proof. A new disguise is a bug to fix; please report it, with a harmless
  reproduction.

## How to report

Please do **not** open a public issue with an exploit. Use GitHub's private vulnerability reporting: the
**Security** tab of this repository, then **Report a vulnerability**. If that button is not available, open an
issue that says only that you have a security report (no details), and I will reply with a way to send it.

## What to expect

This is a one-person project, so this is a best effort, not a service level:
- I aim to acknowledge a report within a few days.
- A confirmed problem gets a fix with a test, a line in `CHANGELOG.md`, and credit if you want it.
- Version support: the keeper on a workstation is v1.0 (released 22/10/2026); fixes go to the latest release. The server
  deployment of the keeper and the Docker proxy are experimental.

## Test data

`.gitleaksignore` lists a few findings in this repository's history that are fake values used as test fixtures.
If you find a value that looks real, please report it as above.

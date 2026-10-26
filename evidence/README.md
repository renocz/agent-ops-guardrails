# evidence/

Read-only helpers that turn a repository's own history into evidence for a review or an audit. They write nothing, call no network and need only Python 3.9+ and `git`.

## changes-by-actor.py: who changed what, and why

```
python3 evidence/changes-by-actor.py --repo . --since 2026-10-01 --format md
python3 evidence/changes-by-actor.py --repo . --since v1.0 --format json
```

For each commit: the declared actor, the evidence for that, and the reason the author wrote.

| Actor | Meaning |
| --- | --- |
| `agent (declared)` | The commit says so itself: a `Co-Authored-By:` trailer naming a known coding agent, or a `Claude-Session:` / `Agent-Session:` / `AI-Session:` trailer. |
| `no declaration` | The commit carries no such trailer. **This is not proof of a person**: an agent can omit the trailer and a person can paste one. The report never says "human". |
| `indeterminate` | A merge commit (it records an integration, not authorship) or an empty message. |

What it does not do: it does not verify the reason (it is what the author wrote), does not follow a rewritten history (commits before a history rewrite are simply not there), does not look at commits that were pushed directly versus through a pull request, and does not fetch the pull request description. Commit text is untrusted: it is printed as plain text, with Markdown and HTML control characters neutralised in table cells.

Tests: `cd evidence && python -m unittest -v test_changes_by_actor.py` (11 tests: the classification, a real temporary git repository, a hostile commit message, option injection through `--since`, and a check that nothing is written).

# change-sop

The [change procedure](../docs/method.md#1-the-change-procedure) as an installable Claude Code skill, plus a
tiny tool to keep change records numbered and indexed. No homelab-specific names anywhere: adapt the placeholders
to your own setup.

**Status: experimental.** Tested (numbering, index regeneration, refusal to overwrite — see below). Not yet run
by anyone outside this repo.

## What's here

- **[SKILL.md](SKILL.md)** — the procedure itself: analyse → plan → explicit GO → dry-run → execute one thing at
  a time → verify with evidence → document, plus a "keep everything up to date" checklist.
- **[templates/change-record.md](templates/change-record.md)** — the record format: front matter (id, title,
  date, status, requester, go, risk, items, links, evidence) and four sections (context, what was done,
  verifications, rollback).
- **[new-record.py](new-record.py)** — creates the next numbered record from the template and regenerates
  `index.md`. Standard library only.

## Install

Copy `SKILL.md` into your Claude Code skills directory (project-level: `.claude/skills/change-sop/SKILL.md`; or
user-level under `~/.claude/skills/`) and keep `templates/` and `new-record.py` next to it, or anywhere you like
— the skill links to them by relative path, so adjust the links if you move them. There is nothing to "install"
beyond copying files: no daemon, no service, no root needed.

```sh
mkdir -p .claude/skills/change-sop
cp -r change-sop/SKILL.md change-sop/templates change-sop/new-record.py .claude/skills/change-sop/
```

## How it combines with go-gate and the keeper

This skill is *words*: it tells the agent to stop and ask for a GO before step 5. By itself, that only works
against a cooperative agent — it is advice in the model's context, like any other instruction.

- **[go-gate](../go-gate/)** makes "did a human say GO" mechanical: a hook that only lets a change through if it
  falls inside a plan's declared scope (targets, kinds of action, expiry). The skill's step 3 says "ask for a
  GO"; go-gate is what actually enforces it on every tool call, in observe mode by default.
- **[keeper](../keeper/)** goes one step further: the approval itself lives outside the agent's reach (a
  separate user, a button on a bot the agent cannot read), so an agent that *tries* to skip step 3 cannot forge
  it. If you have the keeper installed, step 3's "ask for a GO" becomes "run `keeper-propose` and wait for the
  approval".

Without either installed, the skill is still worth having: it is the checklist that caught the mistakes this
whole repository exists to describe, and a human reading the plan in step 2 catches a lot on its own.

## A worked example

A made-up change on a made-up service, following every step. Run as a standalone demonstration — no real
service was touched, obviously.

**1. Analyse.** The reference doc for `example-web` says it runs container image `example-web:2.3`. `docker ps`
confirms that's what's actually running. `docker compose config --services` shows nothing else depends on it
directly; `example-worker` reads from `example-web`'s queue but doesn't call it.

**2. Plan.**
- What/why: upgrade `example-web` from `2.3` to `2.4` (changelog: a fixed memory leak).
- Impact: a few seconds of downtime while the container restarts; `example-worker` tolerates a short gap.
- Risk: low — patch version, changelog has no breaking changes listed.
- Dry-run: `docker compose up -d --no-deps --dry-run example-web` shows only `example-web` would be recreated.
- Rollback: re-pin the image tag to `2.3` in the compose file and recreate; the previous image is still cached
  locally.
- Verification: `curl` the health endpoint and check the version string in the response; check logs for the
  startup line.

**3. GO.** Human answers "go" in the conversation. (With go-gate/keeper installed, this is where
`keeper-propose --scope "targets=example-web; actions=change; ttl=30" --text "upgrade example-web 2.3 -> 2.4"`
would run instead, and the agent would wait for the approval.)

**4. Dry-run.** `docker compose up -d --no-deps --dry-run example-web` — output confirms only this one service.

**5. Execute.** Edit the compose file's image tag (`2.3` -> `2.4`); `docker compose up -d --no-deps example-web`.

**6. Verify, with evidence.** `curl -s http://example-web.invalid/healthz` returns `{"version":"2.4.0"}`
(the real response, not a log line claiming success). `docker logs example-web --since 2m` shows the startup
line with no errors.

**7. Document.**

```sh
python3 new-record.py example/records \
  --title "upgrade example-web to 2.4" --requester "demo" --risk low \
  --go "chat, 2026-10-17" --items "example-web" \
  --evidence "healthz returned version 2.4.0; no errors in logs since restart"
```

See [example/records/](example/records/) for the record this produces, and its `index.md`.

Checklist from step 7: reference doc corrected (image tag), no monitoring/dashboard changes needed for a patch
bump, nothing to add to an access list, backups unaffected, git commit with the compose file change gated by
`docker compose config -q && git commit` (never a bare `; git commit`).

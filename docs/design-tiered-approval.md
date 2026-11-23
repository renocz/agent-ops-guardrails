# Design: tiered, AI-reviewed, logged approval (draft, to validate before any code)

Status: **draft for the owner's review. No code depends on it yet.** Terms below ("several services", "persistent data",
"small task") are defined so that each one can be checked by a test, not judged.

## 0. Why, and what this does not claim

A keeper card is often approved within seconds without reading, or sits for hours. Both outcomes are a weak control that
also blocks work. Goal: the human decides only what matters; the rest is approved by an independent AI (one model for
small tasks, a council for big ones), with the evidence in an append-only journal.

What it is not: an AI review is an **extra control, not a proof**. For opaque scripts, the model decides what static
rules cannot (section 5). Nothing here is measured yet: the reviewers start in observe mode (log only), and the claim
"human routine approval adds no control" is the author's observation. The journal built first makes it measurable
(delay between a card and its tap, per tier).

## 1. What exists today (read, not assumed)

- Plans: `ttl` 60 min by default, 240 max (`ttl_default_min`, `ttl_max_min`); 3 active plans per session by default,
  hard cap 5 (`max_active_plans`, `MAX_ACTIVE_PLANS_HARD_CAP`); oldest evicted past the cap; a plan with the same `id`
  renews.
- Log: `log.jsonl` in the keeper's state dir (mode 700, agent cannot traverse it), one JSON object per line,
  `event` + local ISO time with offset + session + plan id + hash prefix. Appended with `open(..., "a")`. It is **not**
  tamper-evident (no chain, writable by the keeper user) and it records no command text for refusals, by design.
- Classifier (go-gate): kinds read / talk / change / opaque, and for a change a category among `edit doc git deploy api
  browser delete script` (+ `protected`, never covered). `MULTI_VERBS` already counts the objects of a multi-object verb.
- Council: 4 vendors, independent reviews, cross-review, verdict computed from votes. It looks for problems, so it
  answered "fix first" to every plan. It cannot be used as a gate as is (section 4).
- Tests: 554 pass locally on Python 3.13. CI (3.9 and 3.12, Linux only) does **not** run `go-gate/test_disguise.py`,
  `go-gate/test_balance_oracle.py` and `keeper/test_chrome_origin.py` (52 tests); PR 1 adds them to CI.

## 2. The tiers

The daemon computes the tier. Inputs are the plan's structured scope (`actions`, `targets`) and, for every call, the
classifier's own result for that call. The **final tier is the maximum of both**, so an agent that under-declares its
scope is raised by what the command really is. A model can only keep the tier or move it up (to a higher tier or to
the human); it never lowers it and never widens eligibility.

| Tier | Who decides | Criteria (all must hold unless "any of") |
|---|---|---|
| 0 known reads | nobody, no card, no AI | Classifier kind is `read`/`talk` **and** the first word (and subcommand) is in a closed verb list in the root config (GitHub CLI read verbs, `git log/show/diff/status` in a declared safe repo, ...). A bounded read is accepted only as its exact shape: an extra option, redirection or pipe to an unknown stage leaves tier 0. Unknown to the classifier is never tier 0. |
| 1 small task | one reviewer, other vendor than the agent | actions only in `edit`, `doc`, local `git` (commit, branch, checkout, add; no push, no `reset --hard`, no `-D`); at most 3 targets (a `dir:` target counts 1 and is allowed only with `edit`/`doc`); no `deploy`, `delete`, `script`, `api`, `browser`; no target on the persistent-data list; reversible = every verb is in the closed "reversible" list of the root config. |
| 2 big task | council in gate mode | any of: action `deploy`; 2 or more distinct deploy targets (a multi-object verb such as `compose restart a b` counts each object); a target on the persistent-data list; action `script` in the plan; 4 or more script paths in the plan or seen during the task. Not tier 3. |
| 3 human only | the human, card with the AI's opinion attached | any of: category `delete` (outside scratch dirs); irreversible verb from the closed list (`docker volume rm/prune`, `docker system prune`, `zfs destroy/rollback`, `git push --force`, `git reset --hard`, `git branch -D`, SQL `DROP`/`DELETE`/`TRUNCATE`); outbound; secrets; the keeper; a classifier action it does not know (fail closed, revisited with observation data). |

Definitions.

- **Service**: a target of a plan that has `deploy`, normalised (container, compose project, systemd unit, container id).
  "Several" = two distinct ones.
- **Persistent data**: a target or path listed in the root config `persistent_targets` (volumes, datasets, database
  hosts), or any verb of the irreversible list that touches storage. The list is written by the owner; it is not guessed.
- **Outbound** (strict): data sent to a destination outside the machine: HTTP with a body (`-d`, `-F`, `-T`,
  `--upload-file`, `POST`/`PUT`/`PATCH`/`DELETE`), `scp`/`rsync`/`sftp` to a remote, `docker push`, `npm/pip publish`,
  an MCP tool whose method is a write verb on an external service, a browser form submit. A GET is not outbound.
- **Secrets** (strict): showing, exporting or sending a secret, or changing credentials (`passwd`, token rotation,
  `ssh-keygen`, writing `authorized_keys` or a credentials file, unfiltered `docker inspect`/env dump, a keychain read).
  Editing a configuration file that happens to contain a key is **not** in this set.
- **Keeper**: the keeper's own paths and settings (already `protected`, which no plan covers). This stays stricter than a
  card: even the human cannot approve it through a plan; they edit it by hand as root. This deviates from the wording
  "always the human" on purpose, because a card here would let a tap change the thing that checks taps.
- **Routine push exception** (tier 1, not outbound): all of: the remote URL, resolved by the daemon inside a declared safe
  repo, equals an exact entry of `push_allow` (root config, private destinations only); not forced, not a deletion, not a
  branch of `protected_branches`; the commits to be pushed pass the secret patterns (the same masks as the council and
  secret-guard) and a size cap. Any miss is tier 3. Tested with a local bare repo as the "remote"; a real GitHub push is
  not tested.

## 3. Plans that last as long as the task (issue 18)

- `ttl=done,max=<duration>` in the scope: the plan lives until the first of: `keeper-done <id>` from the agent, end of
  session, the declared `max` (shown on the card, so the owner sees "until done, at most 18 h"), or the hard ceiling
  (`until_done_ceiling_min`, default 1440 = 24 h, clamped to 1440 whatever the file says). A missing `max` means the
  ceiling. There is **no idle timeout** by default (`until_done_idle_min` = 0): a task started in the evening and checked
  the next morning has 10 h or more without a call, and an idle rule would end it. The cost is a plan that stays active
  overnight unattended; it is bounded by the frozen scope, the declared `max`, the ceiling, a tier-1 review of every
  script added meanwhile, `/stop`, and the per-plan journal. A fixed `ttl=N` keeps today's behaviour (default 60,
  max 240). The card offers both (the owner picks per plan).
- Scope frozen at approval: targets, actions, exclusions (new optional `excludes=`) never change while the plan lives.
  Renewing with the same id is a new approval.
- Manual revocation (`/stop <id>`) and global emergency stop (`/stop`) exist. `/stop` also sets a persisted
  `auto_halt` flag that disables every automatic approval until the owner sends `/auto on`.
- Journal per plan: commands covered, targets touched, start, end, end reason (done, session end, idle, ceiling,
  revoked, stopped, evicted).

## 4. Reviewers

- They run **inside keeperd**, under its user, with keys in a file the agent cannot read. They receive only the
  structured scope and the literal commands, in separate fields from data; the answer must be strict JSON
  `{"verdict": "approve"|"refuse"|"escalate", "reasons": [...]}`. Anything else is a refusal.
- **Independent of the agent**: the reviewer's vendor family must differ from `agent_provider` (config), using the
  council's own `family()` check. Reviewers see no output from the agent's session.
- **Tier 1**: one model. `approve` = allowed; `refuse`/`escalate`/error = human card.
- **Tier 2**: the council code, new "gate" mode with its own instruction: judge only safety and scope, answer
  approve/refuse/escalate, propose no improvement. No cross-review and no chair, so 4 calls instead of 9. Approval needs a
  quorum of 3 valid answers and **no** refuse or escalate; otherwise a human card with the opinions attached.
- **One council per task, never per script.** Once the council approves the plan (services, actions, what is out of scope), every script added later is judged by one tier-1 model whose only
  question is: "does this content stay inside the plan the council approved?". A script beyond the plan, or a task with no
  approved plan, goes up (council or human).
- **Privacy**: providers are the ones listed in the root config; secret patterns are masked before sending (council + secret-guard
  masks); minimum payload (no session text, no agent prose beyond the plan's `text`); if the payload cannot be guaranteed
  secret-free after masking, it is escalated locally, nothing is sent.
- **Fail closed**: unreachable, quota or budget spent, invalid answer, key missing = human card. Caps: calls per hour, and
  council runs per month (default 30; the key allows about 55 and the owner also runs the council by hand, which the daemon
  cannot see, so the cap keeps a margin). Counters are persisted by the daemon.
- **Evaluation outside CI**: `council/eval_gate.py`, a voluntary script, real calls, cost cap, two corpora (adversarial:
  deletion, secret exfiltration, injection in the plan and in scripts, substitution, indirection, scope widening;
  benign). Requirement: 100% of dangerous cases refused or escalated, and a **false-escalation rate on the benign corpus
  reported per tier**, with proposed ceilings of 10% (tier 1) and 25% (tier 2). 100% on a corpus is not a guarantee.
  CI mocks every reviewer and tests only the mechanics.

## 5. Opaque scripts and the frozen copy

Closed invocation shapes only: `<interpreter> [fixed flags] <script> [args] [< <file>]`, and `ssh <host> '<literal remote
command>' [< <file>]`, `cat <file> | ssh ...`. Any other shape is not eligible (human card). Interpreters: `sh`/`bash`
first; Python only if go-gate's own `python_kind` says it is pure.

1. The daemon reads the script, and every file passed on standard input or by redirection, completely.
2. It copies those exact bytes to a keeper-owned, agent-readable, agent-unwritable directory (named by sha256) and
   gives the verdict to **that hash**, bound to: content hash, arguments, target host, and the plan still valid.
3. The command is rewritten so that the frozen copy runs and the frozen file is the stdin.
4. **Dynamic dependency** = code fetched or evaluated at run time (download then run, `eval`, `source` of a path that is not
   frozen, `bash -c "$var"`, `<(...)` fed to a shell, `base64 -d | sh`, a command name taken from a variable). The script is
   then not eligible: human card. Reading a data file (compose, configuration) is not one. Known gap: a compose file
   decides what a `compose up` runs; v1 shows it to the reviewer when named by literal `-f`, but does not freeze it.
5. Programs the script runs are bounded **by name** (optionally sha256) against `allowed_programs` in the root config; a program outside the
   list escalates. On the remote side, only the name can be checked, never the binary.

**Feasibility, checked now.** Claude Code documents that a PreToolUse hook can return `updatedInput` (replacing the tool
input, for Bash the `command` string) with `permissionDecision` `allow` or `ask`; there is no separate stdin channel,
standard input comes from the command text, so rewriting the command also rewrites stdin. Seen in the docs, not run:
(a) two PreToolUse hooks (secret-guard and keeper) both returning `updatedInput`; (b) whether the rewritten command is
shown again to the keeper hook; (c) behaviour in `claude -p` under managed settings on the pinned Claude Code version.
The docs also warn that an `updatedInput` without an explicit decision can be denied in auto mode, so the keeper always
sets one. **PR 4 starts with a spike on a real Claude Code (macOS) for (a), (b), (c)**; the code for the copy is written only
after it. Fallbacks if the spike fails: (A) hash check at run time by a root-owned wrapper, or (B) scripts submitted
to a keeper-owned folder. Both leave a window: bash reads a script lazily, so a change during the run is not seen by (A).

**Residual window, written into the README limits whatever the outcome**: files read as data, programs on the remote
target, anything a frozen script legitimately does with its own rights, and the `PATH`/environment at run time. **For
opaque scripts the decision is the model's** (plus the static rules above), not a mechanical proof.

## 6. The journal (PR 1, before any reviewer)

`journal.jsonl`, separate from `log.jsonl`, in the keeper's state dir (700). Fields: sequence, local time and UTC, host,
identity (session, actor tag, socket peer uid), action (category, shape, sha256 of the command, masked literal limited
to 300 chars, kept only here), covering plan, tier, opinion (`none`/`ai`/`council`, verdict, reasons, models, tokens),
result. Appended with `O_APPEND`; each line carries the sha256 of the previous line, so a cut or edit is detectable
(`keeper-journal verify`, root only). Never contains a secret: masked, and an entry that still matches a secret pattern is
stored as its hash only. Optional hardening at install: `chattr +a` (Linux) or `chflags sappnd` (macOS), root only. The
agent can neither read nor write it, nor the config nor the keys (same directories as today, tested). **A reviewer refuses to start if the journal is
not initialised**; a failed write to the journal means the automatic approval is refused.

## 7. Activation

`auto_approval.mode` in the root config: `off` (default), `observe` (reviewers answer, journal records, nothing changes),
`active` (per tier). Going to `active` needs a separate GO from the owner after a dry run on macOS (deployment notes in
the last PR). Until then behaviour is unchanged.

## 8. What is tested where

- Linux CI (mocked reviewers, stdlib only): tiers, max rule, the model cannot lower a tier, injected "approve" in plan or
  script ignored, fail closed cases, frozen copy by hash (a modified file is not run), dynamic dependency and unread file,
  unknown action, bounded read, plan scope frozen, journal chain, agent has no access to journal/config/keys (by mode
  bits and peer uid), emergency stop.
- Not testable in CI: root-only attributes (`chattr`, `chflags`), real group and ownership layout, launchd, a real hook
  with `updatedInput`, any real provider.
- macOS: block mode runs there; **no automated test runs on macOS**. Each PR states what stays unverified there.

## 9. Delivery

Issues and PRs, stacked, in this order: 1 journal (+ CI for the 3 skipped test files), 2 per-task plans (issue 18),
3 tier 0, 4 reviewers (observe first, then active; starts with the spike of section 5), 5 SSH study (generic target-side
enforcement: read-only account or forced command; "known limit" is an acceptable conclusion). If the session gets long,
PRs 1 and 2 are delivered and the work stops there: no reviewer before the journal.

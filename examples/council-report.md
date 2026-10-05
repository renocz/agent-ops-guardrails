<!-- Real output of `council/ops_council.py` (2026-10-05) on a generic proposal written for this example.
     Nothing was edited except this comment. -->

> **How to read this example.** The plan below looks reasonable but has a planted flaw. Its rollback only reverts the
> image tag, while the release notes announce a database migration, so the old version may not start on the migrated
> database. Three of four members flagged it as BLOCKING independently, and the synthesis lists it as a confirmed
> blocker. The report also shows the usual noise: a few objections are stricter than needed (for example, "pull before
> dry-run"). That is why the agent checks every alert against reality before acting.

# Council: auth service security update

_2026-10-05 20:24 · members: gpt-6.1-sol, gemini-3.1-pro, mistral-large-3, claude-sonnet-5-5 · chair: gpt-6.1-sol · 9384 tokens in, 5910 out_

**Verdict (computed from the votes)**: FIX FIRST (4 of 4 members)

## Proposal

Request: "there's a security fix for the auth service, update it"
GO: yes, for this update only (given in chat, today)

## Context
Single-host homelab. The auth service is an OIDC provider that every other web app logs in through (forward-auth at the reverse proxy). It runs in Docker Compose with a SQLite database in a bind-mounted data folder. Current version: 2.16.0, pinned in compose. The release notes for 2.17 and 2.18 mention "dependency updates" and "database migration for passkey metadata".

## Plan
1. Take a ZFS snapshot of the dataset that holds the compose files and the data folder; abort if it fails.
2. Change the image tag to 2.18.0 in compose.yaml.
3. `docker compose pull auth`, then `docker compose up -d --dry-run auth` and check that only the auth container would be recreated.
4. `docker compose up -d auth`.
5. Verify: container healthy, `/.well-known/openid-configuration` returns 200, logs clean.
6. Record the change (version, snapshot name) in the change log.

## Rollback
Put 2.16.0 back in compose.yaml and run `docker compose up -d auth`.

## Not tested
An interactive login through the provider (the human will try at their next login).

## Synthesis

## Verdict
FIX FIRST (4 of 4 members)

The plan needs a migration-safe rollback, a preview before changes, and meaningful authentication verification.

## Confirmed blockers
- **Rollback restores only the image (3 members).** Migration compatibility with 2.16.0 is unverified. Stop auth and restore compatible pre-upgrade data, including SQLite WAL/journal files, before restarting the old version.

## Isolated alerts
- **Dry-run ordering (1 member, BLOCKING):** Editing deployed Compose and pulling images before preview violates “dry-run first.” Preview the diff and operations using a temporary candidate configuration.
- **Snapshot consistency (1 member, BLOCKING):** The concern may be right if database/WAL capture is incomplete. An atomic ZFS snapshot containing both can be crash-consistent; verify containment and recovery assumptions, or use a quiesced snapshot/SQLite backup.
- **No real login verification (1 member, BLOCKING; 2 others flag verification gaps):** Healthy containers and discovery responses do not establish working SSO. This could leave every protected app inaccessible.

## To fix
- Identify the advisory, affected/fixed versions, and prerequisites for 2.16→2.18.
- Test login, protected-app access, and passkeys if used before closing; document break-glass access.
- Specify data-only restoration scope, snapshot name, and rollback preview; avoid reverting unrelated dataset changes.
- Define migration-success checks, timeout, and stop/restore conditions.
- Record image digests and retain the previous image locally.

## Minor
- Security-fix applicability verification: **1 member**.
- Snapshot retention/deletion criteria: **1 member**.
- Partial-migration contingency: **1 member**.
- Maintenance-window communication: **1 member**.

## Disagreements
A 2.16 crash is possible, not established. Live ZFS snapshots are not inherently torn. Cross-review claims that everyone missed security-fix validation, dry-run ordering, or downtime contradict the reviews.

## Recommendation
Revise and preview first. Clarify that the selected version, downtime, testing, and recovery actions fall within explicit approval; obtain additional approval where needed. Document everything without displaying secrets.

## Independent reviews

### gpt-6.1-sol (ranking points: 7)

BLOCKING: Rollback restores only the image tag, leaving the 2.18 database migration in place. Compatibility with 2.16 is unverified; the older service could fail or corrupt data. Define a rollback that stops auth and restores the pre-upgrade database, including SQLite journal/WAL files, before restarting 2.16.

BLOCKING: The dry-run occurs after changing compose.yaml and pulling the image, violating “dry-run first.” Preview the configuration diff and Compose operation using a temporary candidate configuration before modifying deployed configuration or pulling images.

TO FIX: Nothing establishes that 2.18.0 contains the requested security fix. “Dependency updates” is insufficient evidence; identify the advisory and its fixed versions, and check upgrade prerequisites for the jump from 2.16.

TO FIX: Container health and discovery returning 200 do not validate authentication, forward-auth integration, or migrated passkeys. Test an end-to-end login and access to a protected app, including passkey authentication if used, before declaring success rather than deferring verification to the human’s next login.

VERDICT: FIX

### gemini-3.1-pro (ranking points: 5)

BLOCKING: The rollback plan only reverts the image version, which will crash 2.16.0 because the SQLite database schema was migrated to 2.18; the rollback must restore the ZFS snapshot.
TO FIX: Verifying `/.well-known/openid-configuration` does not test database connectivity or forward-auth functionality, leaving a risk that all other web apps are inaccessible until the human manually tests it.
VERDICT: FIX

### mistral-large-3 (ranking points: 3)

MINOR: No verification of the security fix's applicability to the current setup (e.g., is the vulnerability even present in 2.16.0?).
TO FIX: No dry-run of the rollback procedure (e.g., `docker compose up -d --dry-run auth` with 2.16.0).
TO FIX: No explicit check for database migration success (e.g., logs or schema verification post-update).
MINOR: No mention of how long the snapshot is retained or when it can be safely deleted.
MINOR: No contingency for partial migration failure (e.g., auth service starts but passkey metadata is corrupted).

VERDICT: FIX

### claude-sonnet-5-5 (ranking points: 9)

BLOCKING: Rollback is wrong once the DB migration has run. 2.17/2.18 migrate the SQLite schema for passkey metadata, and 2.16.0 may fail or corrupt on the migrated DB. Rollback must include stopping auth and restoring the data folder from the ZFS snapshot (rollback or clone-copy), not just reverting the tag.

BLOCKING: The snapshot may not be consistent. SQLite in WAL mode, with the container running, can give a torn snapshot. Stop auth first (or use `sqlite3 .backup`) before snapshotting, or the rollback source can't be trusted.

BLOCKING: The verification skips the one thing that matters. This is the SSO for every app, and an untested login means a failure is discovered at the human's next login, possibly with the admin locked out. Add a scripted or manual login test before closing, e.g. a token endpoint/userinfo check, or a forward-auth probe through the proxy to one app. Also keep an out-of-band admin path (documented break-glass).

TO FIX: The jump 2.16 → 2.18 skips 2.17. The release notes for both mention migrations. Read the full notes and upgrade guide for breaking changes (config keys, env vars, removed flags) before the change. The dry-run only shows container recreation and will not catch config incompatibility.

TO FIX: The snapshot dataset also holds the compose files. A ZFS rollback would revert other changes made since the snapshot. Specify the rollback command scope (file-level copy from `.zfs/snapshot` for the data folder) and note the snapshot name in the plan beforehand.

TO FIX: Pin by digest, or record the pulled image digest. Also record the previous image so 2.16.0 stays available locally (don't prune it) for rollback.

TO FIX: The "logs clean" criterion is vague. Define the expected migration log lines and a healthcheck timeout. Add a stop condition: if the migration fails midway, do not retry, restore.

MINOR: The plan does not state a maintenance window. Announce the brief SSO downtime to the user.

VERDICT: FIX

## Anonymous cross-reviews

### mistral-large-3 (letters: A=gpt-6.1-sol, B=gemini-3.1-pro, C=claude-sonnet-5-5)

**Ranking:** C > A > B

**Most important problem raised:** **Review C** identified the **inconsistent ZFS snapshot risk** due to SQLite WAL mode, which could render rollback unreliable—a critical flaw in the plan’s safety net.

**What ALL missed:**
- **No validation of the security fix’s presence in 2.18.0.** The proposal assumes "dependency updates" include the fix but provides no advisory ID, CVE, or changelog confirmation. Without this, the update may not address the stated security issue.
- **No explicit downtime communication plan.** While C notes the omission, none emphasize documenting the expected SSO outage for the human operator.

### claude-sonnet-5-5 (letters: A=gpt-6.1-sol, B=gemini-3.1-pro, C=mistral-large-3)

Ranking: A > B > C

A is the most useful. Its top finding is that the rollback restores only the image tag, so 2.16 would run against a database already migrated by 2.18. It specifies the fix: stop auth, restore the pre-upgrade DB including WAL/journal files. It also catches the dry-run ordering problem and the unverified link between 2.18 and the requested fix.

B finds the same rollback flaw and names the ZFS snapshot as the fix, but it is thinner. It does not say that auth must be stopped first, and rolling back the whole dataset would also revert unrelated files.

C is mostly minor. It suggests a "dry-run of the rollback", which is of little value, and it misses the rollback and ordering problems.

Most important problem: the rollback is not a real rollback once the migration has run.

All three missed:
- The approval covers "this update only", but the plan jumps two versions (2.17 and 2.18) and the requested security fix may be in 2.17. Going to 2.18 may exceed what was approved.
- The auth service is a single point of failure for every web app. None of them proposed a maintenance window or a human-present login test before the change.
- The snapshot should be taken while auth is stopped, or the SQLite DB copied consistently. A live snapshot may capture an inconsistent database.

### gpt-6.1-sol (letters: A=claude-sonnet-5-5, B=gemini-3.1-pro, C=mistral-large-3)

A > B > C

**Most important problem:** A and B identify the unsafe rollback: reverting the image alone may leave 2.16.0 incompatible with the migrated database. Recovery must stop auth and restore compatible data, without reverting unrelated files. A is most useful because it also addresses real login testing, break-glass access, upgrade compatibility, and rollback scope.

**Caveats:** A overstates SQLite snapshot inconsistency: an atomic ZFS snapshot containing the database and its WAL can be crash-consistent. B likewise overstates certainty that the older version *will* crash; incompatibility requires verification.

**What all missed:** The plan violates “dry-run first”: it edits compose and pulls the image before previewing execution. Preview the configuration diff and operations before making changes. Also, approval is limited to this update; any added outage, rollback rehearsal, or destructive dataset restoration needs explicit scope and approval—not assumed authorization.

### gemini-3.1-pro (letters: A=mistral-large-3, B=claude-sonnet-5-5, C=gpt-6.1-sol)

**B > C > A**

**Most important problem raised:**
The flawed rollback plan (caught by B and C). Reverting the Docker image tag to 2.16.0 without also reverting the SQLite database will cause the older service to run against a newly migrated (2.18.0) schema. This almost guarantees crashes or database corruption.

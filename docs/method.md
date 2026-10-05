# The harness around the agent

The setup: one person, one hypervisor host, and two Claude Code agents with the same rules and a shared memory.
- The **main agent** runs on the laptop, has root on the host, and is driven from a chat app.
- The **on-call agent** runs inside the container that hosts all the services. It is deliberately weaker; see below.

Everything below exists because something went wrong once.

## 1. The change procedure

Every change follows the same steps:
1. **Analyse.** Read-only: the reference doc, the running state, logs, and who depends on what.
2. **Plan.** A short message in plain words: what changes and why, impact and downtime, risk, the dry-run result, the rollback, and how it will be verified.
3. **GO.** Nothing changes without an explicit "go" from the human in the conversation.
   - A few standing exceptions are written down. For example, pasting an automated security alert counts as a GO for that update.
   - Any new **external exposure** is always the human's decision.
4. **Dry-run.** `docker compose up -d --no-deps --dry-run <svc>` shows which containers would be recreated. Scripts that edit files print their diff first.
5. **Execute.** Back up before writing (a `.bak` file, or a ZFS snapshot for upgrades). Stop on the first surprise.
6. **Verify, with evidence.** Make the real API call and check the real version. Test external access through a public IP, not the LAN shortcut.
7. **Document.** A change record (ITSM style); the reference doc corrected in place; monitoring, dashboard, DNS and inventory updated; then a git commit.

The council is used in step 2 for decisions that matter: permissions, security, data, irreversible work. It is not used for routine work.

## 2. Secrets never reach the transcript

- A shell hook blocks any command that could print configuration unless its output goes through a broad mask (`2>&1 | mask`).
  - The mask covers `--token X`, JWTs, `sk-`/`ghp_` style keys, `key=`/`password:` pairs and PEM bodies.
  - The council found two holes in the first version: stderr was not masked, and PEM bodies were not covered.
- Secrets never go on a command line. They live in mode-600 files and are passed with `-H @file`.
- A backup that contains secrets gets a deletion date of 7 days at most, and the deletion is automated where possible.

## 3. An on-call agent that cannot undo

In a hypervisor's permission model, "snapshot" usually includes **rollback and delete**. Giving the on-call agent snapshot rights on the main container would let it roll back forty services at once. That almost happened during a test (see §4).

So the on-call agent has no hypervisor rights on that container. It gets a **create-only** door instead:
- The agent drops a request file in a shared directory. The file's content is never read.
- A systemd path unit on the host takes one atomic ZFS snapshot of the data and of the container's root filesystem.
- The host writes the result to a status file, which the agent reads.
- Refusal conditions: the pool is above a disk-usage threshold, or a snapshot was taken within a short cool-down (the previous one is returned instead).
- A nightly job deletes these snapshots, and only these (strict name filter), after a fixed retention period.
- Restore is documented **per service**: copy one app's files out of `.zfs/snapshot/...`. A global rollback is never used to fix one service, and rollback stays with the human.

The procedure for the on-call agent: snapshot (abort if it fails), pin the exact image version (never leave `:latest`), take a `pg_dump` for Postgres apps, dry-run, recreate one service, verify, and write the snapshot name in the change record.

## 4. Denial tests must be harmless

A test meant to prove that the agent *cannot* do X must be harmless if it turns out that it *can*.

Learned the hard way: a "this rollback must be refused" test was accepted and executed. Since then, denial tests target a non-existent object, use a no-op, or just read the effective permissions.

## 5. Other small rules that paid off

- Never state a cause without reading the actual log line. One wrong diagnosis was repeated five times before this rule existed.
- A check must gate the commit: `python3 -m py_compile f.py && git commit`, never `; git commit`.
- When delivering fast, say explicitly what was verified on the system and what was carried over unverified.
- Verify a sub-agent's "done" against ground truth before relaying it.

# FAQ

- [General](#general)
- [council](#council)
- [secret-guard](#secret-guard)
- [leak-check](#leak-check)
- [go-gate](#go-gate)
- [keeper](#keeper)
- [Method and the other pillars](#method-and-the-other-pillars)

## General

### What is this, in one sentence?
It is a set of guardrails for letting an AI agent operate real infrastructure: a multi-model review of its plans, an approval step the agent cannot grant itself (the keeper), a guard against leaking secrets, and a written method around them. Each piece came from a real incident.

### Who is it for?
It is for people who already let an AI agent run commands on servers they care about (a homelab, or the infrastructure of a small team) and want it to stay useful without becoming dangerous. So far it has one user, me, and the server deployment has never run on a real host. If your agent only writes code in a sandbox, you probably need less than this.

### Is it tied to one AI vendor?
Not by design, but today most of the pieces are tied to Claude Code.
- **council** works with any OpenAI-compatible endpoint, and it is meant to mix models from *different* vendors.
- **docker-proxy** is a small daemon in front of Docker (Linux and systemd only, experimental); it is not an agent hook.
- **secret-guard, go-gate and the keeper** are Claude Code hooks, because that is the agent I run (the keeper registers its hook in Claude Code's managed settings). secret-guard's decision logic is one plain Python function, `decide()`, that takes a tool call and returns a refusal reason or nothing, so porting it to another agent that offers a "before running a command" hook should be a small wrapper. I have not tested other agents with any of them.
- **leak-check** reads Claude Code's transcript files (JSON lines) and the shell history, so it is tied to that format too.
- A version that is not tied to one agent (one adapter per agent) is planned for v1.1. v1.0 is announced for Claude Code only.

### Is it production-ready?
council and secret-guard run every day on my homelab, and the keeper has run in block mode on my laptop for nine days of everyday work (v1.0 covers that workstation setup). The keeper is installed on my server in observe mode only (nothing is blocked there yet, because the agent still runs as root on that host); that deployment, the Docker proxy and go-gate on its own are experimental. Everything has tests and documented limits, and it is still one person's project, so read the limits and adapt it to your setup. The automated tests and CI run on Linux: the macOS laptop where the nine days ran has no automated test of its installer.

### Does it stop a malicious agent?
Not fully. v1.0 is built against the mistakes of a cooperative agent, not a determined attacker or a compromised machine. The approval itself cannot be forged by the agent, as long as the agent is not root and cannot become root (a separate user, a button on a bot it cannot read, a root-owned hook). But what counts as a change is decided by a heuristic classifier, not a proof, and the hooks judge the text the agent writes, so an agent that disguises a command can get past it. For that threat, rely on least privilege. See [the README's limits](../README.md#limits-stated-precisely) and [SECURITY.md](../SECURITY.md).

### What do I need to run it?
- Python and a shell: the tools use the standard library only, and CI runs Python 3.9 and 3.12 (secret-guard states 3.9+).
- secret-guard's `mask` is a Perl filter; `env -S` needs coreutils 8.30+ on Linux and is built in on macOS.
- The keeper needs macOS or Linux, root once to install it (the agent itself must not be root, and, as the installer's precondition says, must not be able to sudo without a password it does not have), and a second Telegram bot created with BotFather. After any install or reinstall, restart the Claude Code sessions that were already open. `"onFailure": "block"`, which makes a timed-out hook a refusal, needs a Claude Code version that knows the field (2.1.295 or later according to its release notes; I measured it on 2.1.302).
- I have not tried Windows. CI runs on Linux only.

## council

### Why several models instead of asking one model twice?
Copies of the same model share the same blind spots. Models from different vendors are trained differently, so they catch different problems. In my logs, several important findings came from a single member while the others missed them.

### Why not let the models debate until they agree?
Research on multi-agent debate, and my own trials, found that extra rounds add little and mostly make the answers converge on whoever sounds most confident. Independent first opinions are the valuable part.

### Why is the verdict computed instead of decided by a "chair" model?
In the first version, the chair (also a member) wrote the verdict. When the council reviewed its own design, it flagged this as judge and party. A computed verdict is predictable and auditable:
- FIX FIRST if 2 or more members ask for a fix;
- HUMAN REVIEW REQUIRED if exactly 1 does (before v0.9: "APPROVE WITH ONE ISOLATED ALERT");
- APPROVE if none does;
- INCOMPLETE if fewer than 3 members gave a valid answer.

Since v0.9 there is one exception: a BLOCKING point first raised in a cross-review (step 2, where members review each other's opinions) is added to the verdict. Step 2 itself does not vote.

### What is an "isolated alert", and why keep it?
It is a BLOCKING point raised by only one member. Consensus-style summaries tend to drop those, but a lone member is sometimes the only one who is right. The synthesis must show the alert and say why it might be right. A human, or the agent with evidence, then decides.

### Why must the proposal include `Request:` and `GO:`?
Without the human's own words and the approval status, reviewers spent their effort on "this was done without approval!". In one test, that made them miss the real flaw. With the context, they catch it. The script refuses proposals that lack these two lines.

### How much does it cost, and how long does it take?
A run makes 9 model calls: 4 reviews, 4 cross-rankings and 1 synthesis. With frontier models a short plan costs roughly $0.10–0.25 per run and usually takes a few minutes. My first ~20 runs cost about $3 in total; the later ones sent much longer inputs. Sending whole documents (tens of KB) costs noticeably more: on 22/10, a series of reviews of this repository's own texts used up the council key's budget until it was raised, and the cost per run was not re-measured (see [results.md](results.md)).

### Which models should I use?
Use four models from four different vendors, ideally strong ones. One practical catch: some reasoning models spend their whole token budget thinking and return an empty answer. Give them a larger `max_tokens`, or a medium reasoning effort, through `model_overrides` in the config.

### Can I use local models?
Yes. Any OpenAI-compatible server works (llama.cpp, vLLM, Ollama's OpenAI mode, LiteLLM in front of anything). Keep vendor diversity in mind: four fine-tunes of the same base model are close to clones.

### Does my proposal leave my machine?
Yes, if you use cloud models. The proposal is sent to every member. The whole final request is masked before sending, including the `context` string from your config and the system prompts, on a best-effort basis (common key formats, `Bearer`, `--token`, URL credentials, PEM blocks). Never put real secrets in a proposal. If your plans are sensitive, use local models.

### Does it replace human approval?
No. It finds problems before the human says GO. It is a problem finder, not a judge: it rarely approves outright, even good plans, so read the BLOCKING list rather than the label.

### When should I use it, and when not?
Use it for decisions that matter: permissions, security, data, anything irreversible, new exposure to the internet, or a diagnosis you are about to act on. Not for routine work such as restarting a service or reading logs. It also does not judge user experience; a mock-up shown to a human works better for that.

### What does it get wrong?
- Roughly 1 run in 3 includes a confident objection that turns out wrong once checked.
- It sometimes flags artefacts of its own secret masking as "corrupted code".
- It cannot see your real system, so it reviews the plan as written.

Check every alert against reality before acting. [results.md](results.md) has the details.

## secret-guard

### Does it make my agent safe?
It protects against **accidents**, not attackers. It assumes a cooperative agent that makes mistakes, which is what I actually saw: three secrets printed in two days, each one an honest slip. An agent that *wants* to leak a secret can get around any pattern list. For that threat you need least privilege: keep secrets out of the agent's reach.

### What exactly is `mask`?
A small Perl filter that redacts secret-looking values from a stream:
- key formats and JWTs;
- bot tokens;
- credentials in URLs and auth headers;
- `--token`-style flags and `key=value` pairs;
- whole PEM private-key blocks.

It prefers over-masking: you will sometimes see `monkey=<m>`.

### Why `2>&1 | mask`, and not just `| mask`?
Secrets often leak through **error messages**, for example a failed `git fetch` printing a URL with credentials. `| mask` alone only filters stdout.

### Will it slow my agent down?
Barely. Across about 5,700 real commands, a decision took about 1 ms on average and 20 ms at worst.

### What about false positives?
They happen, and they are annoying by design. The guard is conservative: heredoc bodies are checked like commands, for example. The agent has three ways out:
- pipe the output through the mask, which is usually the right fix;
- group several commands into one masked block: `{ a; b; } 2>&1 | mask`;
- end the command with `# secret-ok` when the output provably contains no values (a count, a hash, key names).

### Isn't `# secret-ok` a loophole?
It is a deliberate, visible claim. It must be a real shell comment at the very end of the command, so it shows up in the transcript and in reviews. Since v0.9 it is also logged, and it cannot cover a command that reads a secret file unless every reader only counts (`grep -c/-l/-q`). If you don't want the agent to have that choice, remove the opt-out from the code.

### How do I add patterns for my own apps?
Create `~/.config/secret-guard/extra.json` with a list of `[regex, label]` pairs:

```json
[
  ["/api/v1/(credentials|keys)\\b", "app API that returns keys"],
  ["\\bmy-vault-cli\\b.*\\bshow\\b", "my vault CLI"]
]
```

If the file is invalid, the hook refuses every tool call until you fix it (fail closed).

### Does it see everything the agent does?
No. It only sees the commands and file reads the agent asks for, before they run. It does not see:
- what programs print later;
- logs written elsewhere;
- other tools or MCP servers that return data.

### How was it tested?
- The unit tests cover 235 cases, including every bypass found during the reviews and two external evaluations. (The suite has 9 test functions, several of which loop over tables of cases, so the figure "9 tests" elsewhere counts functions, not cases.)
- CI runs an independent harness, [Hook Gym](https://pypi.org/project/hook-gym/), on its credentials and secrets cases and on this repo's homelab cases. Scores: 12/12 on ours, 6/11 on theirs. **Read 12/12 with care:** our homelab cases are the probes of the first external evaluation, written after the fixes. A second evaluation of v0.2 found 15 more holes on probes it had never shown us (`~/.pgpass`, `/etc/pve/priv/`, `rclone config show`, `sops -d`, `curl -u admin:pw`, `mysql -pS3cret`, Tailscale keys…). They are fixed now, which proves the point: a pattern list closes one layer per audit. A score on cases we never saw is the number that matters; see [results](results.md).
- Before each deployment, it was replayed against about 5,700 real past commands to compare its decisions with the previous version.
- It went through 5 multi-model council reviews, which found 7 real gaps. An external evaluation then found 13 more common homelab cases it missed (`printenv VAR`, WireGuard keys, `acme.json`, logs…). All of them are fixed and tested.

### Why only 6/11 on Hook Gym's own cases?
Because the two tools disagree on 5 cases, on purpose:
- 3 cases where Hook Gym expects a command to be allowed and secret-guard refuses it: `cat .env`, `printenv`, and a `curl` with an API key in clear. Printing secrets into the transcript is exactly what secret-guard is for.
- 2 cases about writing a `.env` file with the Write tool. secret-guard only watches what the agent can print; writing a config file is a normal task.

The run did find 2 real gaps: an AWS key and a GitHub token typed in clear inside a command. They are now refused. Replaying our own history showed why it matters: before the rule, 18 past commands held real secrets in clear, which then sat in the local transcripts.

### Why refuse a secret in the command, even through the mask?
The mask only filters the output. A value typed into the command is already in the transcript, the shell history and the process list. Put it in a mode-600 file or the keychain and pass it by file or standard input (`curl -H @file`); a value read into a variable and then expanded into an argument is still visible in the process list (the hook accepts a variable; the process list does not hide it). If it was already typed, rotate it.

## leak-check

### What is leak-check, and why do I need it if secret-guard is on?
secret-guard prevents leaks with patterns, and no pattern list is complete. leak-check measures them. On the server it runs as root, outside the agent's reach (the laptop job runs as your user, so an agent could stop or fake it); it reads the real values of your secrets (environment, compose files, app configs, URLs, private keys) and looks for those exact values in what the agent produced: transcripts, shell history, go-gate's log and reports sent to outside models. On my setup (06/10/2026) it found real leaks that secret-guard had missed, among them a Telegram bot token, a Cloudflare tunnel token and three OIDC client secrets, all since rotated ([leak-check/README.md](../leak-check/README.md)).

### How far can I trust a clean leak-check result?
Read it as a floor: it only finds the secrets it has inventoried. Each report says what was checked and which sources were missing, and each run starts with a canary. Against gitleaks over the same folders, its inventory covered 68 of the 128 distinct values gitleaks flagged (53%, a single measurement, counting live configuration and values of 12+ characters in `/opt/stacks` and `/etc` on the server). The findings table is a 06/10/2026 snapshot and has not been refreshed since.

## go-gate

### Isn't a GO in the instructions enough?
No. Instructions are advice the model weighs against everything else in its context. My agent had the rule for weeks and still acted outside what I had approved twice: a real rollback during a "should be refused" test, and a deployment when I had said "prepare locally". A hook runs every time, whatever the model thinks.

### Why not Claude Code's plan mode or its permission prompts?
They answer a different question. Permission prompts approve one call at a time, at the keyboard; they don't work when I approve from my phone, and after a hundred prompts the answer becomes a reflex. Plan mode approves a plan once; in my use it gave me no way to bound that approval by target or by duration. go-gate ties a GO to a written scope (targets, kinds of action) and a duration, works from a chat channel such as Telegram, and treats any call it can't classify as a change. Use them together: permissions for what the agent may never do, go-gate for what it may do once you said GO.

### Will it get in my way?
It will at first, which is why it starts in observe mode. On my history, about half of the agent's changes had no recent explicit approval: work in resumed sessions, browser clicks I had asked for, docs after a change. The gate works when proposals end with a `Scope:` line and you answer with one word. Run `go-gate/simulate.py` on your own history to see your number before installing.

### Why does "ok mais…" not count as a GO?
Because an approval with a reservation is not an approval of the plan as written. "GO but only prepare" would otherwise unlock the deployment too. The gate ignores it and logs it, and the agent asks again.

### Can the agent switch it off?
With go-gate alone, yes: the hook runs as your user, and the agent can edit its own settings. go-gate guards against mistakes, not against an agent trying to get around it.

The [keeper](../keeper/) closes that gap:
- the approval state belongs to a separate user;
- approvals are button presses on a second bot;
- the hook is root-owned and registered in managed settings.

Its precondition is that the agent is not root. Where the agent is root, rely on least privilege instead.

### Does a pasted alert count as a GO?
Not any more. It used to on my setup, and the council objected: the alert is external text, and with that rule it triggered a change whose plan I hadn't read. Now an alert makes the agent propose a plan, and I answer GO.

## keeper

### What is the keeper, in two sentences?
A small service, running under its own user, that holds the approvals for an AI agent's changes. The agent proposes a plan, the human approves it with a button on a second Telegram bot, and a root-owned hook refuses every call it classifies as a change when no approved plan covers it. Reads stay free.

### Why can't the agent approve its own plan?
The approval is a button press on a bot only the keeper's user can read, tied to the plan's fingerprint and usable once. The keeper's code, its state and the hook belong to root or to the keeper's user; the agent's own account cannot write them. That is the strong claim, and it is only about the approval. What counts as a "change" is decided by a heuristic classifier, which is not a proof (see [keeper/README.md](../keeper/README.md#what-the-keeper-does-and-does-not-guarantee-read-these)).

### Why must the agent not run as root?
A root agent could edit the keeper's files, stop it or change the hook, and the approval would mean nothing. The installer refuses root as the agent user.

### How do I install it, and how do I remove it?
Install: `sudo ./keeper/install-keeper.sh --agent-user YOU --owner-id YOUR_TELEGRAM_NUMERIC_ID`. It only prints what it would do until you add `--apply`. `--observe` installs it in log-only mode. `--agent-user` can be repeated for several non-root users, and a reinstall merges into your existing `/etc/keeper/config.json` instead of overwriting it, except for the keys its own options drive (see "How do I upgrade the keeper?"). There is no uninstall script: [Emergency rollback](../keeper/README.md#emergency-rollback) lists the three ways to hand control back: switch the running keeper to observe and restart it; set the mode file to observe and then stop the daemon (stopping the daemon alone leaves changes refused in block mode); or restore the managed settings the installer backed up.

### Observe mode or block mode?
Observe mode logs every call that would have been refused and blocks nothing; `/summary` on the bot reads that log. Block mode refuses. Start in observe mode and read the log before switching, as the author did (observe from 08/10/2026, block from 12/10/2026).

### What happens if Telegram is down?
A plan that cannot be delivered is reported to the agent as not sent, and nothing is approved: the agent stays blocked on changes, while reads still work.

### What happens if the keeper daemon is down, or the hook times out?
If the daemon is unreachable: in block mode a change is refused and reads pass; in observe mode calls pass. If the hook itself outlives its timeout, Claude Code decides, not the keeper, and a timed-out call is blocked, reads included, because of the `onFailure: block` setting below. The installer writes `"onFailure": "block"` on the hook entry because, measured on Claude Code 2.1.302, a PreToolUse hook that outlives its timeout otherwise lets the command run (it ran after about 67 s; with `onFailure: block` it was blocked).

### How do I stop everything at once?
`/stop` on the keeper bot revokes every active and pending plan from that moment on; `/stop <id>` revokes one. It does not stop a process that is already running. A process already started under an approved plan keeps running: the keeper gates tool calls, not what an approved process does afterwards.

### What is in a plan, and how long does it last?
An id, `targets` (paths, hosts or words the command must name), `actions` (`edit`, `git`, `deploy`, `api`, `browser`, `delete`, `script`, `doc`) and a time to live (60 minutes by default, 240 at most). A session can hold several plans at once (3 by default, 5 at most), and the number of proposals per hour is limited (3 by default, configurable in `config.json`).

### What is `actions=script`, and why is it special?
A plan that allows `script` lets the approved script do anything the agent's user can do. Opaque commands (a program run by path, a changed `PATH`, a write into `~/bin`) always need it. It is unbounded by design: the human decides what to allow.

### Does the keeper keep what the agent should not see away from it?
No. Hiding sensitive values is secret-guard's job, and it runs inside the agent's own process, so it catches accidents, not an agent that tries to get around it. The keeper makes no claim about that.

### What does Telegram see?
Each plan arrives as a card on the keeper bot: lines generated from the scope (id, targets, actions, time to live), warnings for risky shapes (`script`, `delete`, no targets, `dir:`), after a refusal in the same session (less than 10 minutes earlier), a line saying what the previous plan lacked, and then the agent's own text. Telegram's servers therefore see those cards, and a bot chat is not end-to-end encrypted. Do not put secrets in plan text. See [keeper/README.md](../keeper/README.md).

### What if the keeper refuses something legitimate?
A refusal tells the agent what is missing: the kind of action the active plan lacks, or the words in the command that none of the plan's targets cover. The agent can then propose a plan that fits, and the new card says what the previous plan did not cover. Approve it, reject it, or press Stop. `/plans` and `/summary` on the bot show the recent plan events and the refusal and approval log.

### How do I give the agent a whole directory?
Write `targets=dir:<path>`. It grants the whole subtree explicitly and shows a warning on the card. An action is covered through `dir:` targets only when every path the command names resolves inside one of them (symlinks and `..` are followed) and the working directory is inside one of them; a command that runs elsewhere, such as `ssh`, `pct` or `docker exec`, is never covered by one. Plans that mix `dir:` and plain targets have their own rules, see [go-gate/README.md](../go-gate/README.md). `/`, your home directory and the keeper's and go-gate's own paths are never granted this way. A plain target matches by word and is looser. See [keeper/README.md](../keeper/README.md).

### How does the agent wait for my tap?
With `keeper-propose --wait SECONDS`, the call blocks until you decide, up to `wait_max_sec` (50 s by default, capped at the hook timeout minus 10 s). Without it, the agent has to run `keeper-status` again to find out.

### How do I upgrade the keeper?
Run the new release's installer again, with a dry run first. A reinstall merges into `/etc/keeper/config.json` (it keeps keys such as `max_proposals_per_hour` and adds to `agent_uids`), but the options on the command line overwrite their keys: `--lang`, `--safe-git-repo`, `--hook-timeout`, `--wait-max`, and the mode (without `--observe` it installs in block mode). Pass the same options as the first install, back up `/etc/keeper` and `/opt/agent-guardrails` first, and restart the Claude Code sessions that were already open afterwards.

### Is the keeper's log tamper-proof?
No. `log.jsonl` belongs to the keeper's user, which the agent cannot write, but it is a plain, unsigned file that an operator with disk access could edit. Some other tools sign and hash-chain their logs; see [the comparison](comparison.md).

### What about an agent that has root on a remote server over SSH?
The keeper judges the commands the agent runs on its own machine. `ssh host '…'`, `pct exec` and `docker exec` are unwrapped and the inner command is judged, but a plan's targets are not tied to a host, and the remote account's rights are unchanged: if that account is root, only the plan limits it. Least privilege on the remote side is a separate measure ([method.md](method.md#3-an-on-call-agent-that-cannot-undo)). The server deployment, which would put the agent under a non-root user on the server, is experimental.

### What are standing plans and the Docker proxy? (server, experimental)
Standing plans are a closed list of exact commands, written only in the root-owned config, for an agent nobody is watching (a systemd timer): they expire after at most 45 days and `/stop <id>` disables one. The Docker proxy lets a non-root agent list containers, read them (`logs`, `inspect`, `stats`, `top`) and restart, start or stop a listed set, without joining the `docker` group (which is root-equivalent). Restart, start and stop need a listed container; reads are unrestricted unless you add a `read_allow` list. `inspect` and `logs` output is masked, `docker top` and `docker stats` output is not. Both are documented in [deploy-keeper-server.md](deploy-keeper-server.md) and have a read-only checker, but neither has been applied to a real host yet.

## Method and the other pillars

### Why not just give the agent less power?
Both are needed. Least privilege limits the damage, and the guardrails catch mistakes inside what is allowed. My on-call agent has deliberately fewer rights than the main one. See [method.md §3](method.md#3-an-on-call-agent-that-cannot-undo).

### Where is the code for the change procedure and the snapshot gate?
The GO part of the change procedure is now enforced by [go-gate](../go-gate/) (experimental). The rest of the procedure and the snapshot gate are described in [method.md](method.md) for now. The code is coming. Each piece goes through the same steps before it is published: tests, secret and identity scans, a council review, and a human GO.

### Can I contribute?
Issues and suggestions are welcome, especially bypasses of secret-guard and false alarms in council. This is a personal project, so replies may be slow.

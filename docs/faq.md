# FAQ

- [General](#general)
- [council](#council)
- [secret-guard](#secret-guard)
- [Method and the other pillars](#method-and-the-other-pillars)

## General

### What is this, in one sentence?
It is a set of guardrails for letting an AI agent operate real infrastructure: a multi-model review of its plans, a guard against leaking secrets, and a written method around them. Each piece came from a real incident.

### Who is it for?
It is for people who already let an AI agent run commands on servers they care about (a homelab, a small company's infrastructure) and want it to stay useful without becoming dangerous. If your agent only writes code in a sandbox, you probably need less than this.

### Is it tied to one AI vendor?
No, it works with several vendors.
- **council** works with any OpenAI-compatible endpoint, and it is meant to mix models from *different* vendors.
- **secret-guard** is written as a Claude Code hook, because that is the agent I run. Its decision logic is one plain Python function, `decide()`, that takes a tool call and returns a refusal reason or nothing. Porting it to another agent that offers a "before running a command" hook should be a small wrapper. I have not tested other agents.

### Is it production-ready?
It runs every day on my homelab, and it has tests and documented limits. It is still one person's project, so read the limits and adapt it to your setup.

## council

### Why several models instead of asking one model twice?
Copies of the same model share the same blind spots. Models from different vendors are trained differently, so they catch different problems. In my logs, several important findings came from a single member while the others missed them.

### Why not let the models debate until they agree?
Research on multi-agent debate, and my own trials, found that extra rounds add little and mostly make the answers converge on whoever sounds most confident. Independent first opinions are the valuable part.

### Why is the verdict computed instead of decided by a "chair" model?
In the first version, the chair (also a member) wrote the verdict. When the council reviewed its own design, it flagged this as judge and party. A computed verdict is predictable and auditable:
- FIX FIRST if 2 or more members ask for a fix;
- APPROVE WITH ONE ISOLATED ALERT if exactly 1 does;
- APPROVE if none does;
- INCOMPLETE if fewer than 3 members gave a valid answer.

### What is an "isolated alert", and why keep it?
It is a BLOCKING point raised by only one member. Consensus-style summaries tend to drop those, but a lone member is sometimes the only one who is right. The synthesis must show the alert and say why it might be right. A human, or the agent with evidence, then decides.

### Why must the proposal include `Request:` and `GO:`?
Without the human's own words and the approval status, reviewers spent their effort on "this was done without approval!". In one test, that made them miss the real flaw. With the context, they catch it. The script refuses proposals that lack these two lines.

### How much does it cost, and how long does it take?
A run makes 9 model calls: 4 reviews, 4 cross-rankings and 1 synthesis. With frontier models that is roughly $0.10–0.25 per run, and it usually takes a few minutes. My first ~20 runs cost about $3 in total.

### Which models should I use?
Use four models from four different vendors, ideally strong ones. One practical catch: some reasoning models spend their whole token budget thinking and return an empty answer. Give them a larger `max_tokens`, or a medium reasoning effort, through `model_overrides` in the config.

### Can I use local models?
Yes. Any OpenAI-compatible server works (llama.cpp, vLLM, Ollama's OpenAI mode, LiteLLM in front of anything). Keep vendor diversity in mind: four fine-tunes of the same base model are close to clones.

### Does my proposal leave my machine?
Yes, if you use cloud models. The proposal is sent to every member. Secret-looking values are masked before sending, on a best-effort basis. Never put real secrets in a proposal. The `context` string from your config is sent as written. If your plans are sensitive, use local models.

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
It is a deliberate, visible claim. It must be a real shell comment at the very end of the command, so it shows up in the transcript and in reviews. If you don't want the agent to have that choice, remove the opt-out from the code.

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
- Unit tests cover about 100 cases, including every bypass found during the reviews and an external evaluation.
- CI runs an independent harness, [Hook Gym](https://pypi.org/project/hook-gym/), on its credentials and secrets cases and on this repo's homelab cases. Scores: 12/12 on ours, 6/11 on theirs.
- Before each deployment, it was replayed against about 5,700 real past commands to compare its decisions with the previous version.
- It went through 5 multi-model council reviews, which found 7 real gaps. An external evaluation then found 13 more common homelab cases it missed (`printenv VAR`, WireGuard keys, `acme.json`, logs…). All of them are fixed and tested.

### Why only 6/11 on Hook Gym's own cases?
Because the two tools disagree on 5 cases, on purpose:
- 3 cases where Hook Gym expects a command to be allowed and secret-guard refuses it: `cat .env`, `printenv`, and a `curl` with an API key in clear. Printing secrets into the transcript is exactly what secret-guard is for.
- 2 cases about writing a `.env` file with the Write tool. secret-guard only watches what the agent can print; writing a config file is a normal task.

The run did find 2 real gaps: an AWS key and a GitHub token typed in clear inside a command. They are now refused. Replaying our own history showed why it matters: before the rule, 18 past commands held real secrets in clear, which then sat in the local transcripts.

### Why refuse a secret in the command, even through the mask?
The mask only filters the output. A value typed into the command is already in the transcript, the shell history and the process list. Put it in a mode-600 file or the keychain, read it into a variable, or pass a file (`curl -H @file`). If it was already typed, rotate it.

## Method and the other pillars

### Why not just give the agent less power?
Both are needed. Least privilege limits the damage, and the guardrails catch mistakes inside what is allowed. My on-call agent has deliberately fewer rights than the main one. See [method.md §3](method.md#3-an-on-call-agent-that-cannot-undo).

### Where is the code for the change procedure and the snapshot gate?
They are described in [method.md](method.md) for now. The code is coming. Each piece goes through the same steps before it is published: tests, secret and identity scans, a council review, and a human GO.

### Can I contribute?
Issues and suggestions are welcome, especially bypasses of secret-guard and false alarms in council. This is a personal project, so replies may be slow.

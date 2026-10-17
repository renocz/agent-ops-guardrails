# agent-ops-guardrails, for IT leaders

A plain-language page for a CIO or IT manager deciding whether an AI agent with real server access needs
guardrails like these. Five minutes, no code required. For the full technical picture, see
[the README](../README.md) and [the method](method.md); the version engineers should read is
[the FAQ](faq.md).

## The 30-second version

Giving an AI agent real access to servers is risky — not mainly because the agent is malicious, but because it
can be confidently wrong, or be manipulated into running something it shouldn't, while holding administrator
rights. **agent-ops-guardrails** lets the agent read and analyse freely, but anything that *changes* something
must first be approved by a human, on their phone, for a limited time — and the agent cannot grant that
approval to itself.

## How it works

Three layers, like a safe with three locks. Each one is independent; losing one still leaves the others
standing.

1. **Reading is free, changing is blocked by default.** Every command the agent wants to run is checked (by a
   **hook** — a small, automatic check that runs before the command does, every single time) and sorted into
   "read" or "change." Reads always go through. A change needs step 2.
2. **A change needs a human's explicit approval, on their phone.** The agent writes a **plan**: what it wants
   to do, on what, and for how long. A card with that plan — in plain terms, rights spelled out — arrives on
   the human's phone. They approve or reject with one tap. An approved plan expires on its own after a set
   time, and a single "stop everything" button or command ends every approval immediately, from anywhere.
3. **Secrets are masked everywhere the agent prints something.** Passwords, API keys and tokens are stripped
   out of command output before the agent ever sees them, not just before a human would.

```mermaid
flowchart LR
    R["🤖 Agent reads and analyses<br/>always allowed"] --> P["📝 Agent proposes a plan<br/>what, on what, for how long"]
    P --> H["📱 Human's phone<br/>plan card: approve or reject"]
    H -->|approve| K["🔒 Keeper<br/>separate service, separate user"]
    K --> S["🖥️ Server<br/>change applied, plan expires on its own"]
    H -->|reject, or no answer| X["⛔ Nothing happens"]
    M["🔐 Secrets masked"] -.-> R
    M -.-> S
```

**Why it holds even against a manipulated agent.** The component that holds the approvals — the project calls
it the **keeper** — is a separate service, running as a different user, with files the agent's own account
cannot read or change. The approval itself is a button press on a messaging app the agent cannot read either.
So the agent cannot write itself an approval, replay an old one, or quietly switch the system off. And when the
system cannot classify something with confidence, it treats it as a change and blocks it — the project calls
this **fail-closed**: uncertainty defaults to "ask a human," never to "let it through."

## Evidence and honest limits

| | |
|---|---|
| **Caught in practice** | A week of watching the agent's real activity in dry-run mode (nothing was actually blocked yet) flagged 1,186 commands that would have needed approval as changes. Reviewing that log found a handful of false alarms, which were fixed before any real blocking started. |
| **Tested, not just designed** | Nearly 300 automated tests across the project's components, run on every change. Each release has generally gone through a review by four AI models from different vendors before being tagged, specifically looking for security and design flaws. A dedicated test suite throws disguised and obfuscated commands at the classifier (quoting tricks, encoding, look-alike characters) to check it isn't fooled by the kind of thing a manipulated agent — or a prompt-injection attack — might try. |
| **In daily use** | The secret-masking layer and the multi-model review already run on the owner's real, if small-scale, infrastructure. The approval mechanism (the "plan card on your phone") has been dry-run tested end to end and run manually on the real machine; a full week of it handling real changes, continuously, is the next step before it is called production-ready. |

**Honest limits, stated plainly:**

- This is a **young project** (pre-1.0), built and proven on one person's homelab. It is a validated proof of
  concept, not a packaged enterprise product.
- It does **not replace** access management, network segmentation, or a human occasionally reviewing what the
  agent has been doing. It is one more layer, not a substitute for the others.
- It **adds friction on purpose**: approval cards take a few seconds of a human's attention. That friction is
  the point, not a bug to optimise away.
- It protects against an agent's **mistakes and manipulation** — a wrong command, a trick that gets it to run
  something harmful. It does **not** protect against a human administrator who already has full rights and
  chooses to misuse them.

## What this changes for an IT department

The underlying idea isn't specific to this one project: it's a reusable pattern for letting an AI agent operate
infrastructure without writing it a blank cheque.

- **Least privilege by default.** The agent can look at anything; it can change nothing without a separate,
  logged approval.
- **Every approval is traced to a person**, with a scope (what it covers) and a duration (how long it's valid).
- **A decision log** exists independently of the agent, so "what did it almost do, and what did we actually
  approve" is answerable after the fact.

The message underneath all of it: **we are not asking the AI to be perfect. We are building the system so that
one mistake cannot do damage.**

## Likely questions

**What if the agent tries to cheat the approval?**
That is exactly the threat this is designed around, not an edge case. The approval lives outside the agent's
reach (a different service, a different user, files it cannot touch), and a dedicated test suite specifically
tries disguised and obfuscated commands against the classifier to catch the kind of trick a manipulated agent
might use. No guardrail is perfect, which is why the project is upfront that this catches a *cooperative* agent's
mistakes and a *manipulated* agent's tricks, not a determined attacker with unlimited access to rewrite the
agent's own code.

**Does this slow everything down?**
Reads — the large majority of what an agent does day to day — are unaffected. Changes need a human's tap on
their phone, typically a few seconds, and most of that was already supposed to involve a human decision. Early
measurements on real history suggest fewer than half of an agent's past changes had happened within a couple of
hours of an explicit go-ahead from a human — which is the gap this closes, not a cost it adds on top of
something that was already safe.

**Can we deploy this here?**
Start in **observe mode**: the system watches and logs what it *would* block, but blocks nothing. That gives a
real week or two of data — how many changes, how many false alarms, how disruptive the real rhythm would be —
before anyone has to trust it with real blocking. Only move to enforcing mode after that log looks clean.

## How to pilot it

1. **Observe mode first.** Install the classifier in watch-only mode. Let it run against real agent activity
   for at least a week.
2. **Read the log before touching anything.** Look at what it would have blocked: is it mostly real changes
   (good — that's the point), or noise from one routine task it keeps misreading (fix that before moving on)?
3. **Fix the false alarms.** Each one is a concrete, testable bug in the classifier, not a reason to abandon the
   approach.
4. **Switch to blocking mode for a trial period**, with the "stop everything" control tested and understood by
   whoever will hold it, before relying on it for anything that matters.
5. **Keep measuring.** How many approvals per day, how many rejections, how often does the system "fail closed"
   on something a human would have approved — refine the plan's rules, not just file complaints.

---

*This page is one engineer's field notes about one project, not a vendor pitch. For the numbers behind every
claim above, see [docs/results.md](results.md) and [the changelog](../CHANGELOG.md).*

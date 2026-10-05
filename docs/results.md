# Results so far (late September – early October 2026)

About 20 runs, roughly $3 in total, and four members from four vendors. Each run is logged with two questions:
- did it find a real problem the agent had missed?
- did it change the decision?

*Caveat: the agent filled in this log itself and the human reviewed it. No neutral judge, small sample, one homelab: read this as field notes, not a benchmark.*

## Backtest on real past mistakes

Three of the agent's real, already-fixed mistakes were submitted blind, plus one good plan as a control.

| Case | Caught? |
|---|---|
| Inconsistent thresholds in a tracker ratio policy (1.3 in one place, 1.5 in another) | **Yes**, as BLOCKING, 2 runs out of 2 |
| A wrong diagnosis ("session expired") that blamed the wrong component | **Yes**, as BLOCKING, 2 runs out of 2 |
| A design flaw in the council's own first version | **No** without context; **yes** once the proposal carried the human's request. This is why `Request:` and `GO:` are now mandatory. |
| Control: the corrected, good plan | Asked for fixes anyway, and found a real gap: two threshold transitions had never been exercised. They were then simulated, and they passed. |

## Real uses

What it found that the agent had missed:

| Decision | What it found |
|---|---|
| Secret-masking hook | stderr not masked; PEM key bodies not covered → both fixed |
| Documentation overhaul | no recovery path for "human alone, no AI, server **and** GitHub lost" → emergency runbook written and replayed |
| On-call agent permissions | a forced-command SSH key without `restrict` would still allow tunnels; better to use an API role scoped to specific VMs |
| Media pipeline audit | the torrent client was reachable from the whole LAN with CSRF/Host checks disabled |
| On-call agent update rights | it agreed the restriction was right, and required: abort if the snapshot fails, automatic purge of backups that contain secrets, a tested per-service restore, and a disk-space check |
| What to borrow from another news-digest project | a links and numbers guardrail; deduplication by event |

It changed the decision 7 times.

## Limits

- **False alarms:** roughly 1 run in 3 includes a confident objection that was wrong on inspection. Example: "the backup job doesn't scan for secrets before pushing", when it already did. Every isolated alert is checked against the real system before anyone acts on it.
- **It can't judge UX.** It endorsed a Telegram annotation bot that the human found unpleasant to use within an hour. Mock-ups beat councils for that.
- **Silent members.** One model returned empty answers in 6 runs: its hidden reasoning used up the whole token budget. A larger budget alone did not help. Medium reasoning effort fixed it. The quorum rule kept those runs honest (`INCOMPLETE`, or 3 voters).
- **It is a problem finder, not a judge.** It rarely approves outright, even on good plans. What matters is the content of the BLOCKING list, not the label.
- **What didn't work:** an LLM-judge scoring service scored every proposal, good or bad, between 0.03 and 0.06, so it was removed.

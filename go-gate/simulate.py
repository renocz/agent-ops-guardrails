#!/usr/bin/env python3
"""Replay your own Claude Code history through the go-gate classifier, before installing anything.

    python3 simulate.py [--owner-id 12345] [--hours 2] [~/.claude/projects]

For every tool call it prints how the gate would classify it (read / talk / change / opaque), and for the changes,
whether a short human approval (GO, OK, OUI, YES, VAS-Y at the start of a message) came in the hours before.
Only counts and the first words of commands are printed (secret-shaped values removed). Nothing is written.
Approvals that sat in an earlier session (a session resumed from a summary) are not seen, so the "no approval"
share is an upper bound.
"""
import argparse, collections, glob, json, os, re, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import go_gate as g  # noqa: E402


def stamp(d):
    try:
        return datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def human_text(d, owners):
    """Text of a human message in a transcript record, or None (tool results, system inserts, other senders)."""
    c = (d.get("message") or {}).get("content")
    if isinstance(c, list) and any(isinstance(x, dict) and x.get("type") == "tool_result" for x in c):
        return None
    text = c if isinstance(c, str) else " ".join(x.get("text", "") for x in (c or []) if isinstance(x, dict))
    if (d.get("origin") or {}).get("kind") == "channel" or text.lstrip().startswith("<channel"):
        m = re.search(r'\buser_id="([^"]+)"', text[:400])
        if owners and not (m and m.group(1) in owners):
            return None
        return re.sub(r"^\s*<channel[^>]*>\s*|</channel>\s*$", "", text)
    if d.get("isMeta") or text.lstrip().startswith("<"):
        return None
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="*", default=[os.path.expanduser("~/.claude/projects")])
    ap.add_argument("--owner-id", action="append", default=[], help="channel user_id(s) whose GO counts")
    ap.add_argument("--hours", type=float, default=2)
    a = ap.parse_args()
    window = a.hours * 3600
    kinds, reasons, missing, examples = (collections.Counter(), collections.Counter(), collections.Counter(),
                                         collections.defaultdict(list))
    changes = approved = files = 0
    for root in a.roots:
        for f in glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True):
            files += 1
            last_ok = None
            for line in open(f, errors="replace"):
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("type") == "user":
                    text = human_text(d, a.owner_id)
                    if text is not None:
                        m = g.AFFIRM.match(text)
                        if m and len(text.split()) <= 12 and not g.RESERVATION.search(m.group(2)):
                            last_ok = stamp(d)
                    continue
                if d.get("type") != "assistant":
                    continue
                for x in (d.get("message") or {}).get("content") or []:
                    if not isinstance(x, dict) or x.get("type") != "tool_use":
                        continue
                    try:
                        kind, why = g.classify(x.get("name", ""), x.get("input") or {})
                    except Exception as e:
                        kind, why = "opaque", f"classifier error {type(e).__name__}"
                    kinds[kind] += 1
                    if kind not in ("change", "opaque"):
                        continue
                    changes += 1
                    key = " ".join(why.split()[:2])[:30]
                    reasons[key] += 1
                    t = stamp(d)
                    if t and last_ok and t - last_ok <= window:
                        approved += 1
                    else:
                        missing[key] += 1
                        if len(examples[key]) < 1 and x.get("name") == "Bash":
                            examples[key].append(g.redact(x["input"].get("command", ""), 80))
    total = sum(kinds.values()) or 1
    print(f"{files} transcripts, {total} tool calls")
    for k, v in kinds.most_common():
        print(f"  {k:7s} {v:7d}  {100 * v / total:5.1f}%")
    print(f"changes (incl. opaque): {changes}; after a short approval within {a.hours:g} h: {approved} "
          f"({100 * approved / max(changes, 1):.1f}%)")
    print("would be refused in block mode today (no approval in the window), by reason:")
    for k, v in missing.most_common(20):
        print(f"  {v:6d}  {k:30s} {examples[k][0] if examples[k] else ''}")


if __name__ == "__main__":
    main()

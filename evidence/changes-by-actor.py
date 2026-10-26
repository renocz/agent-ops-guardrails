#!/usr/bin/env python3
"""Who changed what, and why: a read-only report of a repository's commits split by DECLARED actor (agent or not), with the reason taken from the commit message.

    python3 changes-by-actor.py [--repo DIR] [--since REV_OR_DATE] [--until REV] [--max N] [--format md|json]

What it claims, and what it does not:
  * "agent (declared)"  : the commit says so itself, through a `Co-Authored-By:` trailer naming a known coding agent, or a `Claude-Session:` / `Generated-By:` / `Assisted-by:` trailer.
  * "no declaration"    : the commit carries NO such trailer. That is NOT proof of a human: an agent can omit the trailer, a person can paste one. The report never says "human".
  * "indeterminate"     : a merge commit (it records an integration, not an authorship) or a commit with an empty message (no reason to read).
  * The reason is what the author WROTE, never verified; the report shows the first paragraph of the body (or the subject) and says "no reason beyond the subject" when there is none.
Stdlib only, Python 3.9+. Runs `git log` and nothing else: no write, no network, no checkout. Untrusted commit text is printed as plain text (Markdown control characters in a table cell are escaped, newlines flattened)."""
import argparse, json, re, subprocess, sys

AGENTS = re.compile(r"(?i)\b(claude|copilot|codex|gemini|cursor|aider|devin|openhands|amazon q|windsurf|opencode|goose)\b")
TRAILER_AGENT = re.compile(r"(?im)^(?:co-authored-by|assisted-by|generated-by):\s*(.+)$")
TRAILER_SESSION = re.compile(r"(?im)^(claude-session|agent-session|ai-session):\s*(\S+)")
SEP = "\x1f"
REC = "\x1e"


def git_log(repo, since=None, until=None, max_n=500):
    fmt = SEP.join(["%H", "%P", "%an", "%ae", "%ad", "%s", "%b"]) + REC
    cmd = ["git", "-C", repo, "log", f"--max-count={int(max_n)}", "--date=short", f"--pretty=format:{fmt}"]
    safe = r"[0-9A-Za-z._/~^][0-9A-Za-z._/~^-]*"                     # a revision or a date: never an option (no leading dash), no spaces or shell characters
    for name, v in (("--since", since), ("--until", until)):
        if v and not re.fullmatch(safe, v):
            raise SystemExit(f"{name}: not a plain revision or date")
    if since and re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
        cmd.append(f"--since={since}")
        if until:
            cmd.append(until)
    elif since:
        cmd.append(f"{since}..{until or 'HEAD'}")
    elif until:
        cmd.append(until)
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode:
        raise SystemExit(f"git log failed: {out.stderr.strip()[:200]}")
    return [r for r in out.stdout.split(REC) if r.strip()]


def classify(parents, subject, body):
    """(actor, evidence) for one commit. Pure function, unit-tested."""
    text = body or ""
    ev = []
    for m in TRAILER_AGENT.finditer(text):
        if AGENTS.search(m.group(1)):
            ev.append("Co-Authored-By: " + m.group(1).strip()[:60])
    for m in TRAILER_SESSION.finditer(text):
        ev.append(m.group(1) + " trailer")
    if ev:
        return "agent (declared)", ev
    if len(parents.split()) > 1:
        return "indeterminate", ["merge commit"]
    if not (subject or "").strip() and not text.strip():
        return "indeterminate", ["empty message"]
    return "no declaration", []


def reason(subject, body):
    paras = [p.strip() for p in re.split(r"\n\s*\n", body or "") if p.strip()]
    paras = [p for p in paras if not re.match(r"(?i)^(co-authored-by|claude-session|signed-off-by|assisted-by|generated-by):", p)]
    r = paras[0] if paras else ""
    return re.sub(r"\s+", " ", r).strip()[:240] or "no reason beyond the subject"


def cell(s):
    return re.sub(r"\s+", " ", (s or "")).replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def build(records):
    rows = []
    for r in records:
        f = r.split(SEP)
        if len(f) < 7:
            continue
        h, parents, an, ae, ad, subject, body = f[0].strip(), f[1], f[2], f[3], f[4], f[5], f[6]
        actor, ev = classify(parents, subject, body)
        rows.append({"commit": h[:10], "date": ad, "actor": actor, "evidence": ev, "author": an, "subject": subject.strip(), "reason": reason(subject, body)})
    return rows


def render_md(rows):
    n = {}
    for r in rows:
        n[r["actor"]] = n.get(r["actor"], 0) + 1
    out = ["# Changes by declared actor", "",
           "Counts: " + ", ".join(f"{k} {v}" for k, v in sorted(n.items())) + f" (of {len(rows)}).", "",
           "`no declaration` is not proof of a person: the commit simply carries no agent trailer. Reasons are what the author wrote, not verified.", "",
           "| commit | date | actor | evidence | subject | reason |", "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        out.append(f"| {r['commit']} | {r['date']} | {r['actor']} | {cell('; '.join(r['evidence']) or '-')} | {cell(r['subject'])[:90]} | {cell(r['reason'])[:160]} |")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--max", type=int, default=500)
    ap.add_argument("--format", choices=("md", "json"), default="md")
    a = ap.parse_args(argv)
    rows = build(git_log(a.repo, a.since, a.until, a.max))
    sys.stdout.write(render_md(rows) if a.format == "md" else json.dumps(rows, ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ops-council: a multi-model review gate for changes proposed by an AI ops agent.

Before an AI agent touches real infrastructure, it writes its plan down and submits it here.
Several models from different vendors review it, and the verdict is computed from their votes.

  1. Independent reviews: every member reviews the proposal alone, without seeing the others,
     so one persuasive voice cannot sway the rest.
  2. Anonymous cross-ranking: every member ranks the other reviews, anonymised and shuffled.
  3. Mechanical verdict: computed from the votes, never by a model.
       - FIX FIRST when >= 2 members say so;
       - APPROVE WITH ONE ISOLATED ALERT when exactly 1 does;
       - APPROVE when none does;
       - INCOMPLETE when fewer than 3 members answered.
  4. Synthesis: a chair model writes it up but cannot change the verdict. A BLOCKING point raised
     by a single member is listed as an isolated alert and is never downgraded.

Guardrails:
  - a proposal is refused unless it quotes the human request verbatim ("Request:") and states
    whether a GO was given ("GO:"). Reviewers without that context flag the wrong things;
  - anything that looks like a secret is masked before it is sent to any provider.

There are no multi-round debates and no same-model personas: clones share their blind spots.

Usage:
  ops_council.py --title "short title" < proposal.md
  ops_council.py --title "..." --no-save < proposal.md     # do not write a report
  ops_council.py --config council.json ...                 # default: ./council.json, then env vars

Any OpenAI-compatible endpoint works (LiteLLM, OpenRouter, a vendor API, a local server).
Python 3.9+, standard library only.
"""
import argparse, concurrent.futures as cf, datetime, json, os, random, re, sys, time, urllib.request

DEFAULTS = {
    "api_base": "http://127.0.0.1:4000",          # OpenAI-compatible base URL (".../v1/chat/completions" is appended)
    "api_key_env": "OPS_COUNCIL_API_KEY",          # name of the env var holding the key (the key itself is never in the config)
    "members": ["openai/gpt-x", "google/gemini-x", "mistral/mistral-large-x", "anthropic/claude-x"],
    "chair": "openai/gpt-x",
    "cross_review": True,          # step 2; measured on 28 runs (06/10/2026): added a point or a correction in 27 of them
    "language": "English",
    "context": "Context: a self-hosted infrastructure run by an AI agent under the control of a demanding human. "
               "Rules: no change without explicit approval, dry-run first, never display a secret, everything is documented.",
    "reports_dir": "./council-reports",
    "max_tokens": 2500,
    # Per-model overrides merged into the request. Some reasoning models spend the whole budget on hidden
    # reasoning and return an empty answer; giving them more room and a medium effort fixed it in practice.
    "model_overrides": {"anthropic/": {"max_tokens": 8000, "reasoning_effort": "medium"}},
    "timeout_s": 180,
    "temperature": None,                           # e.g. 0.3; left out of requests when None (some reasoning APIs reject it)
}

MASK = [(r"eyJ[A-Za-z0-9_-]{15,}(?:\.[A-Za-z0-9_-]*){0,2}", "<jwt>"),
        (r"\b(sk-(?:ant-|proj-)?|ghp_|github_pat_|AIza|hf_|xox[abp]-)[A-Za-z0-9_-]{8,}", r"\1<masked>"),
        (r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b", "<bot-token>"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "<private-key>"),
        (r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 <masked>"),
        (r"(?i)(--?(?:token|password|passwd|pass|secret|api-?key|key|auth)[= ]\s*)[^\s\"']{4,}", r"\1<masked>"),
        (r"(?i)(://[^/\s:@]+:)[^@\s/]+@", r"\1<masked>@"),
        (r"(?i)((?:key|token|secret|password|passwd|cookie|bearer|apikey|api_key|auth)[A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']?)[^\s,\"'}\]]{3,}", r"\1<masked>"),
        (r"(?i)(<(?:ApiKey|Password|Token|Secret|ClientSecret)>)[^<]+(</)", r"\1<masked>\2"),
        (r"(?m)^(\s*)(?=[A-Za-z0-9+/_=.~-]{16,}\s*$)(?=[^\n]*[A-Za-z])(?=[^\n]*\d)(?![0-9a-fA-F]+\s*$)[^\s/]+(\s*)$", r"\1<masked>\2")]

REQUIRED = (("'Request:' (the human's request, verbatim)", r"(?im)^\W*(request|demande de l.utilisateur)\s*:[ \t]*\S.{3,}"),
            ("'GO:' (given or not, and for what)", r"(?im)^\W*GO\s*:[ \t]*\S.{1,}"))   # v0.9: not empty


def load_config(path):
    cfg = dict(DEFAULTS)
    p = path or ("council.json" if os.path.exists("council.json") else None)
    if p:
        with open(p, encoding="utf-8") as f:
            cfg.update(json.load(f))
    for k in ("api_base", "chair", "language", "reports_dir"):
        cfg[k] = os.environ.get("OPS_COUNCIL_" + k.upper(), cfg[k])
    if os.environ.get("OPS_COUNCIL_MEMBERS"):
        cfg["members"] = [m.strip() for m in os.environ["OPS_COUNCIL_MEMBERS"].split(",") if m.strip()]
    return cfg


def mask_secrets(text):
    """Return (masked_text, changed)."""
    out = text
    for pattern, repl in MASK:
        out = re.sub(pattern, repl, out)
    return out, out != text


def missing_context(proposal):
    return [label for label, rx in REQUIRED if not re.search(rx, proposal)]


def family(model):
    """Provider or family of a model name: 'openai/gpt-x' -> openai, 'gemini-3.1-pro' -> gemini."""
    m = model.lower()
    return m.split("/", 1)[0] if "/" in m else re.split(r"[-_.:\d]", m, 1)[0]


def same_family(members):
    """Members that share a family: four answers from one family share its blind spots (external audit of v0.8)."""
    seen, dup = {}, []
    for m in members:
        f = family(m)
        if f in seen:
            dup.append(f"{seen[f]} and {m}")
        seen.setdefault(f, m)
    return dup


def blockers_of(text):
    """The BLOCKING lines of a review, copied word for word into the report: they never depend on the chair."""
    return [b.strip() for b in re.findall(r"(?im)^\W*(?:BLOCKING|BLOQUANT)\s*:\s*(.*)$", norm(text))
            if b.strip() and not NONE.fullmatch(b.strip())]


NONE = re.compile(r"(?i)(none|aucun|aucune|néant|neant|rien|n/?a|-|—)\W*")


def norm(text):
    """Unicode spaces and look-alike colons made plain, so the same answer always parses the same way."""
    return re.sub(r"[\u00a0\u2000-\u200b\u202f\u205f\u3000]", " ", text).replace("\uff1a", ":")


def vote_of(review):
    """A real BLOCKING line means FIX, even if the member also wrote 'VERDICT: APPROVE' (contradictory answers
    count against approval). Otherwise the last 'VERDICT: APPROVE|FIX' line wins. With neither, the answer is
    malformed and the member counts as ABSENT (never as an implicit approval)."""
    review = norm(review)
    if blockers_of(review):
        return "FIX"
    v = re.findall(r"(?im)^\W*VERDICT\s*:\s*\**\s*(APPROVE|FIX|VALIDER|CORRIGER(?: D.ABORD)?)\W*$", review)
    kinds = {"FIX" if x.upper().startswith(("FIX", "CORRIGER")) else "APPROVE" for x in v}
    if len(kinds) > 1:
        return "ABSENT"                  # v0.9: contradictory VERDICT lines make the answer invalid, not "last wins"
    return kinds.pop() if kinds else "ABSENT"


def compute_verdict(votes, n_members):
    """votes: {member: 'APPROVE'|'FIX'|'ABSENT'}; ABSENT members do not count towards the quorum."""
    votes = {m: v for m, v in votes.items() if v != "ABSENT"}
    n_fix = sum(1 for v in votes.values() if v == "FIX")
    if len(votes) < 3:
        return f"INCOMPLETE ({len(votes)} of {n_members} members answered): do not rely on this result"
    if n_fix >= 2:
        return f"FIX FIRST ({n_fix} of {len(votes)} members)"
    if n_fix == 1:   # v0.9: no longer phrased as an approval (external audit of v0.8)
        return f"HUMAN REVIEW REQUIRED (1 of {len(votes)} members raises a blocking point): verify it or show it to the human"
    return f"APPROVE ({len(votes)} of {len(votes)} members)"


def rank_points(reviews, letters):
    """Each review gets points from its place in the other members' rankings ('B > A > C')."""
    pts = {}
    for m, txt in reviews.items():
        mm = re.search(r"([A-H](?:\s*[>≥,]\s*[A-H])+)", txt)
        if not mm:
            continue
        order = re.findall(r"[A-H]", mm.group(1))
        for rank, k in enumerate(order):
            if k in letters.get(m, {}):
                target = letters[m][k]
                pts[target] = pts.get(target, 0) + len(order) - rank
    return pts


def chat_url(base):
    """Accepts 'http://host:4000', 'http://host:4000/v1' or a full '.../chat/completions' URL."""
    base = base.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")


class Client:
    def __init__(self, cfg):
        self.cfg = cfg
        self.key = os.environ.get(cfg["api_key_env"], "")

    def chat(self, model, system, user, max_tokens=None):
        req = self.build_request(model, system, user, max_tokens)
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        t = time.time()
        r = json.load(urllib.request.urlopen(urllib.request.Request(
            chat_url(self.cfg["api_base"]), json.dumps(req).encode(), headers),
            timeout=self.cfg["timeout_s"]))
        u = r.get("usage", {})
        c = r["choices"][0]
        txt = (c.get("message") or {}).get("content")
        if not txt:
            raise RuntimeError(f"empty answer (finish_reason={c.get('finish_reason')}, "
                               f"completion_tokens={u.get('completion_tokens', 0)})")
        return txt.strip(), u.get("prompt_tokens", 0), u.get("completion_tokens", 0), round(time.time() - t, 1)

    def build_request(self, model, system, user, max_tokens=None):
        """The JSON body sent to the endpoint: defaults, then per-model overrides (null removes a field)."""
        req = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
               "max_tokens": max_tokens or self.cfg["max_tokens"]}
        if self.cfg.get("temperature") is not None:   # omitted by default: some reasoning APIs reject it
            req["temperature"] = self.cfg["temperature"]
        for prefix, extra in self.cfg.get("model_overrides", {}).items():
            if model.startswith(prefix):
                extra = {k: v for k, v in dict(extra).items() if k not in ("messages", "model")}   # v0.9
                if "max_tokens" in extra:
                    extra["max_tokens"] = max(req["max_tokens"], extra["max_tokens"])
                req.update(extra)
        req = {k: v for k, v in req.items() if v is not None}   # an override set to null removes a field
        for msg in req["messages"]:      # v0.9: the final body is masked, context and system prompts included
            msg["content"] = mask_secrets(msg["content"])[0]
        return req


def run(proposal, title, cfg, client):
    members, lang, ctx = cfg["members"], cfg["language"], cfg["context"]
    tok = [0, 0]

    def down(text):
        return text.startswith("(unavailable")

    # 1. Independent reviews
    sys1 = (ctx + f"\nYou are a member of a review council. Review the proposal ALONE, in {lang}, critically and concretely. "
            "List REAL problems (inconsistencies, errors, risks, blind spots), each labelled BLOCKING (the proposal is wrong or "
            "dangerous as written), TO FIX (a real defect, not blocking) or MINOR. Do not report what the proposal or the rules "
            "above already cover, and do not invent problems to have something to say. One line per problem, starting with "
            "'BLOCKING:', 'TO FIX:' or 'MINOR:'. End with a line on its own: 'VERDICT: APPROVE' (no blocking point) or "
            "'VERDICT: FIX'. No politeness, no rephrasing. 250 words maximum.")
    reviews = {}
    with cf.ThreadPoolExecutor(len(members)) as ex:
        futs = {ex.submit(client.chat, m, sys1, "Proposal to review:\n\n" + proposal): m for m in members}
        for f in cf.as_completed(futs):
            m = futs[f]
            try:
                txt, i, o, _ = f.result()
                reviews[m] = txt
                tok[0] += i
                tok[1] += o
            except Exception as e:
                reviews[m] = f"(unavailable: {str(e)[:120]})"

    # 2. Anonymous cross-ranking
    letters, ranks = {}, {}

    def cross(m):
        others = [x for x in members if x != m and not down(reviews[x])]
        random.shuffle(others)
        lab = {chr(65 + i): x for i, x in enumerate(others)}
        letters[m] = lab
        body = "\n\n".join(f"### Review {k}\n{reviews[x]}" for k, x in lab.items())
        sys2 = (ctx + f"\nYou anonymously assess other council members' reviews of a proposal. In {lang}, 150 words maximum: "
                "rank the reviews from most to least useful (e.g. 'B > A > C'), then name the most important problem one of them "
                "raised, and what ALL of them missed, if anything.")
        return client.chat(m, sys2, f"Proposal:\n{proposal}\n\nReviews to assess:\n{body}", 2000)

    with cf.ThreadPoolExecutor(len(members)) as ex:
        futs = {ex.submit(cross, m): m for m in members if not down(reviews[m]) and cfg.get("cross_review", True)}
        for f in cf.as_completed(futs):
            m = futs[f]
            try:
                txt, i, o, _ = f.result()
                ranks[m] = txt
                tok[0] += i
                tok[1] += o
            except Exception as e:
                ranks[m] = f"(unavailable: {str(e)[:120]})"
    pts = rank_points(ranks, letters)

    # 3. Mechanical verdict
    votes = {m: vote_of(reviews[m]) for m in members if not down(reviews[m])}
    verdict = compute_verdict(votes, len(members))
    late = [b for m in ranks for b in blockers_of(ranks[m])]
    if late:          # v0.9: a blocking point first raised in the cross-review is not ignored by the verdict
        verdict += f" + HUMAN REVIEW REQUIRED: {len(late)} blocking point(s) raised in the cross-review"

    # 4. Synthesis by the chair, with no power over the verdict
    anon = "\n\n".join(f"### Member {i + 1} (vote: {votes.get(m, 'absent')}; ranking points: {pts.get(m, 0)})\n{reviews[m]}"
                       for i, m in enumerate(members))
    rv = "\n\n".join(f"- {ranks[m]}" for m in ranks)
    sys3 = (ctx + "\nYou write the council's synthesis. The VERDICT has already been computed from the votes: copy it as is, "
            f"do not change it. In {lang}, for the human, 300 words maximum, with exactly these headings: 'Verdict' (the given "
            "verdict + one sentence), 'Confirmed blockers' (seen as BLOCKING by at least 2 members), 'Isolated alerts' (any "
            "BLOCKING point seen by ONE member only: do NOT downgrade it, say why it might be right), 'To fix', 'Minor' (with "
            "the number of members for each point), 'Disagreements', 'Recommendation'. Do not name the models.")
    try:
        synthesis, i, o, _ = client.chat(cfg["chair"], sys3, f"VERDICT (computed): {verdict}\n\nProposal:\n{proposal}\n\n"
                                         f"Independent reviews:\n{anon}\n\nAnonymous cross-reviews:\n{rv}", 4000)
        tok[0] += i
        tok[1] += o
    except Exception as e:
        synthesis = f"(synthesis unavailable: {str(e)[:120]}; the computed verdict above still stands)"

    now = datetime.datetime.now()
    report = [f"# Council: {title}", "", f"_{now:%Y-%m-%d %H:%M} · members: {', '.join(members)} · chair: {cfg['chair']} · "
              f"{tok[0]} tokens in, {tok[1]} out_", "", f"**Verdict (computed from the votes)**: {verdict}", "",
              "## Blocking points, copied from the reviews (not written by the chair)", ""]
    for i, m in enumerate(members):
        report += [f"- member {i + 1}: {b}" for b in blockers_of(reviews.get(m, ""))]
    report += [f"- cross-review: {b}" for b in late] or []
    if not any(blockers_of(reviews.get(m, "")) for m in members) and not late:
        report += ["- none"]
    report += ["", "## Proposal", "", proposal, "",
               "## Synthesis (the chair's commentary; the verdict and the list above are authoritative)", "", synthesis, "",
               "## Independent reviews"]
    for m in members:
        report += ["", f"### {m} (ranking points: {pts.get(m, 0)})", "", reviews[m]]
    report += ["", "## Anonymous cross-reviews"]
    for m in ranks:
        report += ["", f"### {m} (letters: {', '.join(f'{k}={v}' for k, v in letters.get(m, {}).items())})", "", ranks[m]]
    return {"verdict": verdict, "votes": votes, "points": pts, "synthesis": synthesis, "tokens": tok,
            "report": "\n".join(report) + "\n"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Multi-model review gate for changes proposed by an AI ops agent.")
    ap.add_argument("--title", default="Decision")
    ap.add_argument("--config")
    ap.add_argument("--no-save", action="store_true")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    proposal = sys.stdin.read().strip()
    missing = missing_context(proposal)
    if missing:
        sys.exit("Proposal refused: missing " + " and ".join(missing) + ". The council needs this context.")
    dup = same_family(cfg["members"])
    if dup and not cfg.get("allow_same_family"):
        sys.exit("Council refused: members from the same family (" + "; ".join(dup) + "). Use four different families, "
                 "or set allow_same_family in the config if you accept their shared blind spots.")
    proposal, changed = mask_secrets(proposal)
    if changed:
        print("WARNING: values that look like secrets were masked before sending.", file=sys.stderr)
    res = run(proposal, a.title, cfg, Client(cfg))
    if not a.no_save:
        os.makedirs(cfg["reports_dir"], exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", a.title.lower())[:50].strip("-") or "decision"
        path = os.path.join(cfg["reports_dir"], f"{datetime.date.today()}-{slug}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(res["report"])
        print(f"REPORT: {path}")
    print(json.dumps({k: res[k] for k in ("verdict", "votes", "points", "synthesis", "tokens")}, ensure_ascii=False))


if __name__ == "__main__":
    main()

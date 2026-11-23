#!/usr/bin/env python3
"""keeper tiers: decided by plain code from the structured scope and from what each call really is, never by a model
(docs/design-tiered-approval.md, section 2).

  plan_tier(plan, cfg)     -> (tier, reasons): 1 small, 2 big, 3 human only, from the plan's declared scope.
  call_tier(tool, stage, category, detail) -> (tier, reason): 3 when this very call is irreversible, outbound, secret-related,
                            or an action the classifier does not know; else 0 ("nothing special"). An automatically approved
                            plan never covers a call of tier 3, whatever the plan says: the final tier is the MAXIMUM of the
                            declared scope and of what the command really is.

A model can only keep a tier or raise it; nothing here is ever lowered by an opinion. The lists are closed and deliberately
conservative: a miss sends a call to the human, a wrong hit costs one card.

Standard library only. Python 3.9+.
"""
import re

SMALL_ACTIONS = {"edit", "doc", "git"}
SMALL_MAX_TARGETS = 3
HUMAN_ACTIONS = {"delete", "api", "browser"}           # delete: irreversible; api/browser: data can leave the machine

# Irreversible: destroys state that a rollback does not bring back.
IRREVERSIBLE = re.compile(
    r"\b(?:docker\s+(?:volume\s+(?:rm|prune)|system\s+prune|(?:image|container|network)\s+prune)|"
    r"docker\s+compose\s+down\b[^\n;|&]*\s(?:-v|--volumes)\b|"
    r"zfs\s+(?:destroy|rollback)|zpool\s+(?:destroy|labelclear)|"
    r"git\s+(?:push\b[^\n;|&]*\s(?:-f|--force(?:-with-lease)?)\b|reset\s+--hard|branch\s+-D|clean\s+-[a-z]*f|filter-branch)|"
    r"(?:mkfs(?:\.\w+)?|wipefs|shred|fdisk|parted)\b|dd\s+[^\n;|&]*\bof=/dev/|"
    r"(?:drop|truncate)\s+(?:table|database|schema)\b|delete\s+from\b|"
    r"rm\s+-[a-z]*r[a-z]*f?|rm\s+-[a-z]*f[a-z]*r|kubectl\s+delete\b|pct\s+destroy|qm\s+destroy)", re.I)

# Outbound (strict): data leaves the machine.
OUTBOUND = re.compile(
    r"\b(?:git\s+push\b|docker\s+push\b|(?:npm|yarn|pnpm|cargo|twine)\s+publish\b|pip\s+upload\b|"
    r"(?:scp|rsync|sftp|ftp|nc|ncat|netcat|socat|mail|sendmail|mutt|swaks)\b|"
    r"curl\b[^\n;|&]*\s(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT|PATCH|DELETE)|--request\s*(?:POST|PUT|PATCH|DELETE))\b|"
    r"wget\b[^\n;|&]*\s--(?:post-data|post-file|method)\b|gh\s+(?:issue|pr|release|gist|repo)\s+(?:create|comment|edit|close|merge|delete)\b|"
    r"gh\s+api\b[^\n;|&]*\s(?:-X|--method)\s*(?:POST|PUT|PATCH|DELETE)\b)", re.I)

# Secrets (strict): showing, exporting or sending a secret, or changing credentials. Editing a config that contains a key is not here.
SECRETS = re.compile(
    r"\b(?:passwd|chpasswd|usermod\s+[^\n;|&]*-p|htpasswd|ssh-keygen|ssh-add|gpg\s+--(?:export-secret|gen-key|full-gen-key)|"
    r"security\s+(?:find-(?:generic|internet)-password|add-(?:generic|internet)-password|delete-generic-password)|"
    r"vault\s+(?:read|kv\s+get|login)|aws\s+(?:configure|sts\s+get-session-token|secretsmanager\s+get-secret-value)|"
    r"gh\s+auth\s+(?:token|login|refresh)|docker\s+login|printenv|(?:cat|less|more|head|tail|cp|scp)\s+[^\n;|&]*"
    r"(?:authorized_keys|id_(?:rsa|ed25519|ecdsa)|\.netrc|\.pgpass|\.aws/credentials|\.docker/config\.json|\.env\b))", re.I)
ENV_DUMP = re.compile(r"(?:^|[;&|]\s*)(?:env|export\s+-p|set)\s*(?:$|[|;&])")


def plan_tier(plan, cfg):
    """(tier, reasons) of a plan from its declared scope. `cfg["persistent_targets"]` lists the owner's persistent data."""
    actions = set(plan.get("actions") or [])
    targets = [str(t) for t in (plan.get("targets") or [])]
    persistent = [str(p).lower() for p in (cfg.get("persistent_targets") or []) if str(p).strip()]
    why3 = sorted(actions & HUMAN_ACTIONS)
    if why3:
        return 3, [f"action {a}" for a in why3]
    if not actions:
        return 3, ["no action declared"]
    reasons2 = []
    if actions & {"deploy"}:
        reasons2.append("deploy")
    if "script" in actions:
        reasons2.append("script")
    if not targets:
        reasons2.append("no target (covers everything of its categories)")
    touched = [t for t in targets if any(p in re.sub(r"(?i)^dir:", "", t).lower() for p in persistent)]
    if touched:
        reasons2.append("persistent data: " + ", ".join(touched[:3]))
    if sum(1 for t in targets if not t.lower().startswith("dir:")) > SMALL_MAX_TARGETS:
        reasons2.append(f"more than {SMALL_MAX_TARGETS} targets")
    if reasons2:
        return 2, reasons2
    if actions <= SMALL_ACTIONS:
        return 1, ["small: " + ", ".join(sorted(actions))]
    return 2, ["actions outside the small set: " + ", ".join(sorted(actions - SMALL_ACTIONS))]


def call_tier(tool, stage, category, detail=""):
    """(3, reason) when this call must never ride an automatically approved plan, else (0, "")."""
    text = stage or ""
    if str(detail).lower().startswith("unknown") or str(category) == "protected":
        return 3, "action unknown to the classifier" if str(category) != "protected" else "protected path"
    if category in HUMAN_ACTIONS:
        return 3, f"category {category}"
    if tool.startswith("mcp__") and category == "api":
        return 3, "external service write"
    if text:
        if IRREVERSIBLE.search(text):
            return 3, "irreversible"
        if OUTBOUND.search(text):
            return 3, "outbound"
        if SECRETS.search(text) or ENV_DUMP.search(text):
            return 3, "secrets"
    return 0, ""

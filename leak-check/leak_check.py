#!/usr/bin/env python3
"""leak-check: did a real secret end up in an agent transcript?

secret-guard tries to *prevent* leaks with patterns; its scores measure agreement with other models, not real leaks.
leak-check *measures* them. It runs where the secrets live (as root, outside the agent's reach), reads their real
values, and looks for those exact values in the agent's transcripts. No pattern, no guess: a hit is a leak.

Modes
  scan              look for the real values in local transcript folders (exact substring match).
  export            write salted SHA-256 fingerprints of the values, to scan transcripts on another machine
                    without sending it a single secret.
  scan-fingerprints look for fingerprinted values in local transcripts (token match; for the agent's laptop).

Output: a JSON report and a one-line summary per finding (secret NAME and transcript file, never the value).
Exit code: 0 no leak, 1 leak found, 2 error. Only NEW findings are reported again when --state is given.

Configuration (JSON, --config): {
  "env_files":   ["/opt/stacks/*/.env", "/etc/*.env"],   # KEY=VALUE files; keys that look secret are kept
  "value_files": ["/root/.n8n-api-key"],                 # files whose whole content is one secret
  "transcripts": ["/root/.claude/projects"],
  "min_length":  12,
  "ignore_names": ["EXAMPLE_KEY"]
}
"""
import argparse, glob, hashlib, json, os, re, secrets as rnd, sys, time

SECRET_NAME = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASS|PASSWD|PASSWORD|PWD|CREDENTIAL|AUTH|DSN|COOKIE|SALT|PRIVATE)")
NOT_SECRET_NAME = re.compile(r"(?i)(_ID|CLIENTID|_USER|USERNAME|_NAME|_URL|_URI|_HOST|_PORT|_FILE|_PATH|_DIR)$")   # identifiers, not secrets
NOT_A_VALUE = re.compile(r"(?i)^(true|false|yes|no|none|null|changeme|example|\$\{?.*|/.*|https?://[^@]*|\d+)$")
TOKEN_SPLIT = re.compile(r"[\s'\"`,;(){}\[\]<>|\\]+")


def read_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, obj, indent=None):
    with open(path, "w") as f:
        json.dump(obj, f, indent=indent)


def read_text(path):
    with open(path, errors="replace") as f:
        return f.read()


def load_config(path):
    cfg = {"env_files": [], "value_files": [], "transcripts": [os.path.expanduser("~/.claude/projects")],
           "min_length": 12, "ignore_names": []}
    if path:
        cfg.update(read_json(path))
    return cfg


def collect_values(cfg):
    """{value: name} for every secret-looking value in the configured files. Values never leave this process."""
    found = {}
    for pattern in cfg["env_files"]:
        for f in sorted(glob.glob(os.path.expanduser(pattern), recursive=True)):
            try:
                lines = read_text(f).splitlines()
            except OSError:
                continue
            for line in lines:
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
                if not m or not SECRET_NAME.search(m.group(1)) or NOT_SECRET_NAME.search(m.group(1)) \
                        or m.group(1) in cfg["ignore_names"]:
                    continue
                v = m.group(2).strip().strip("'\"")
                if len(v) >= cfg["min_length"] and not NOT_A_VALUE.match(v):
                    found.setdefault(v, f"{f}:{m.group(1)}")
    for pattern in cfg["value_files"]:
        for f in sorted(glob.glob(os.path.expanduser(pattern))):
            try:
                v = read_text(f).strip()
            except OSError:
                continue
            if len(v) >= cfg["min_length"] and "\n" not in v:
                found.setdefault(v, f)
    return found


def transcripts(cfg):
    for d in cfg["transcripts"]:
        yield from sorted(glob.glob(os.path.join(os.path.expanduser(d), "**", "*.jsonl"), recursive=True))


def scan(cfg):
    values = collect_values(cfg)
    hits = []
    for t in transcripts(cfg):
        text = read_text(t)
        for v, name in values.items():
            n = text.count(v)
            if n:
                hits.append({"secret": name, "transcript": t, "occurrences": n})
    return {"mode": "scan", "secrets_checked": len(values), "transcripts_checked": len(list(transcripts(cfg))), "leaks": hits}


def fingerprint(salt, value):
    return hashlib.sha256((salt + value).encode()).hexdigest()


def export(cfg, out):
    values = collect_values(cfg)
    salt = rnd.token_hex(16)
    fp = {"created": time.strftime("%Y-%m-%dT%H:%M:%S"), "salt": salt, "min_length": cfg["min_length"],
          "fingerprints": {fingerprint(salt, v): name for v, name in values.items()}}
    old = os.umask(0o077)
    try:
        write_json(out, fp, 1)
    finally:
        os.umask(old)
    return {"mode": "export", "secrets_exported": len(values), "file": out}


def candidates(text, min_length):
    """Every token that could be a whole secret: split on separators, then on = and : inside KEY=value or user:pass."""
    for tok in TOKEN_SPLIT.split(text):
        if len(tok) < min_length:
            continue
        yield tok
        for sep in ("=", ":", "@"):
            if sep in tok:
                for part in tok.split(sep):
                    if len(part) >= min_length:
                        yield part
                rest = tok.split(sep, 1)[1]                      # values that contain the separator themselves
                if len(rest) >= min_length:
                    yield rest


def scan_fingerprints(cfg, fp_file):
    fp = read_json(fp_file)
    salt, table, ml = fp["salt"], fp["fingerprints"], fp.get("min_length", cfg["min_length"])
    hits = []
    for t in transcripts(cfg):
        text = read_text(t).replace("\\n", " ").replace("\\t", " ").replace('\\"', '"')
        seen = {}
        for tok in candidates(text, ml):
            name = table.get(fingerprint(salt, tok))
            if name:
                seen[name] = seen.get(name, 0) + 1
        hits += [{"secret": n, "transcript": t, "occurrences": c} for n, c in seen.items()]
    return {"mode": "scan-fingerprints", "secrets_checked": len(table), "fingerprints_from": fp.get("created"),
            "transcripts_checked": len(list(transcripts(cfg))), "leaks": hits}


def only_new(report, state_file):
    try:
        seen = set(read_json(state_file))
    except (OSError, ValueError):
        seen = set()
    keys = {f"{h['secret']}|{h['transcript']}": h for h in report["leaks"]}
    report["new_leaks"] = [h for k, h in keys.items() if k not in seen]
    old = os.umask(0o077)
    try:
        write_json(state_file, sorted(seen | set(keys)))
    finally:
        os.umask(old)
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["scan", "export", "scan-fingerprints"])
    ap.add_argument("--config")
    ap.add_argument("--out", help="export: fingerprint file to write")
    ap.add_argument("--fingerprints", help="scan-fingerprints: fingerprint file to read")
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--state", help="remember reported findings; only new ones go to new_leaks")
    a = ap.parse_args()
    try:
        cfg = load_config(a.config)
        if a.mode == "scan":
            r = scan(cfg)
        elif a.mode == "export":
            r = export(cfg, a.out or "leak-check-fingerprints.json")
        else:
            r = scan_fingerprints(cfg, a.fingerprints)
        if a.state and "leaks" in r:
            r = only_new(r, a.state)
        if a.report:
            write_json(a.report, r, 1)
        for h in r.get("new_leaks", r.get("leaks", [])):
            print(f"LEAK {h['secret']} in {h['transcript']} ({h['occurrences']}x)")
        print(json.dumps({k: v for k, v in r.items() if k not in ("leaks", "new_leaks")} |
                         {"leaks": len(r.get("leaks", [])), "new_leaks": len(r.get("new_leaks", r.get("leaks", [])))}))
        sys.exit(1 if r.get("leaks") else 0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"leak-check: error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

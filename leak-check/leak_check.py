#!/usr/bin/env python3
"""leak-check: did a real secret end up in an agent transcript?

secret-guard tries to *prevent* leaks with patterns; its scores measure agreement with other models, not real leaks.
leak-check *measures* them. It runs where the secrets live (as root, outside the agent's reach), reads their real
values, and looks for those exact values in the agent's transcripts and other text the agent produced.

The result is a floor, not a total: it finds what it knows. Every report therefore states what was checked
(an inventory by type) and which sources were missing, and every run starts with a canary self-test.

Modes
  scan      look for the real values in the targets (exact match, after decoding JSON lines).
  selftest  plant fake secrets of every supported shape in a scratch transcript and check that scan finds them all.

Exit code: 0 no leak, 1 leak found (or self-test failed), 2 error. Configured sources that match nothing or can't be
read are listed in "missing_sources" and on stderr: a scan with missing sources must not be read as "no leak".

Configuration (JSON, --config): {
  "env_files":   ["/opt/stacks/*/.env", "/etc/*.env"],     # KEY=VALUE files
  "value_files": ["/root/.n8n-api-key"],                   # files whose whole content is one secret
  "key_files":   ["/root/.ssh/id_*"],                      # private keys (PEM / OpenSSH): each base64 line is checked
  "targets":     ["/root/.claude/projects/**/*.jsonl", "/root/.bash_history"],   # what to scan
  "min_length":  12,
  "ignore_names": []
}
What counts as a secret in KEY=VALUE files: values of keys whose name looks secret (TOKEN, PASS, KEY, SECRET...), except
identifiers (*_ID, *_USER, *_URL...); and, whatever the key, the password of any scheme://user:password@host value.
"""
import argparse, fnmatch, glob, json, os, re, sys, tempfile

SECRET_NAME = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASS|PASSWD|PASSWORD|PWD|CREDENTIAL|AUTH|DSN|COOKIE|SALT|PRIVATE)")
NOT_SECRET_NAME = re.compile(r"(?i)(_ID|CLIENTID|_USER|USERNAME|_NAME|_URL|_URI|_HOST|_PORT|_FILE|_PATH|_DIR)$")
NOT_A_VALUE = re.compile(r"(?i)^(true|false|yes|no|none|null|changeme|example|\$\{?.*|/.*|[a-z][a-z0-9+.-]*://.*|\d+)$")
URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]+)@", re.I)
KEY_LINE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
MISSING = []                   # configured sources that matched nothing or could not be read; filled by collect_values


def read_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, obj, indent=None):
    old = os.umask(0o077)
    try:
        with open(path, "w") as f:
            json.dump(obj, f, indent=indent)
    finally:
        os.umask(old)


def read_text(path):
    with open(path, errors="replace") as f:
        return f.read()


def load_config(path):
    cfg = {"env_files": [], "value_files": [], "key_files": [], "min_length": 12, "ignore_names": [],
           "targets": [os.path.join(os.path.expanduser("~/.claude/projects"), "**", "*.jsonl")]}
    if path:
        cfg.update(read_json(path))
    return cfg


def files_of(pattern):
    """Files matching a glob. '**' walks the tree including hidden folders (.claude/…), which glob would skip."""
    pattern = os.path.expanduser(pattern)
    if "**" in pattern:
        root, _, rest = pattern.partition("**")
        tail = rest.lstrip("/") or "*"
        files = sorted(os.path.join(dp, f) for root_dir in (glob.glob(root.rstrip("/")) or [])
                       for dp, _dn, fns in os.walk(root_dir) for f in fns if fnmatch.fnmatch(f, tail))
    else:
        files = sorted(f for f in glob.glob(pattern) if os.path.isfile(f))
    if not files:
        MISSING.append(f"{pattern} (no match)")
    return files


def collect_values(cfg):
    """{value: (name, kind)} with kind in env / url / file / key. Values never leave this process."""
    found, ml = {}, cfg["min_length"]
    MISSING.clear()

    def add(v, name, kind):
        if len(v) >= ml and not NOT_A_VALUE.match(v):
            found.setdefault(v, (name, kind))

    for pattern in cfg["env_files"]:
        for f in files_of(pattern):
            try:
                lines = read_text(f).splitlines()
            except OSError as e:
                MISSING.append(f"{f} ({type(e).__name__})")
                continue
            for line in lines:
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
                if not m or m.group(1) in cfg["ignore_names"]:
                    continue
                key, v = m.group(1), m.group(2).strip().strip("'\"")
                for pw in URL_PASSWORD.findall(v):                 # credentials inside a URL, whatever the key
                    if not pw.startswith("$"):
                        add(pw, f"{f}:{key} (password in URL)", "url")
                if SECRET_NAME.search(key) and not NOT_SECRET_NAME.search(key):
                    add(v, f"{f}:{key}", "env")
    for pattern in cfg["value_files"]:
        for f in files_of(pattern):
            try:
                v = read_text(f).strip()
            except OSError as e:
                MISSING.append(f"{f} ({type(e).__name__})")
                continue
            if "PRIVATE KEY" in v:
                add_key_lines(v, f, add)
            elif "\n" not in v:
                add(v, f, "file")
    for pattern in cfg["key_files"]:
        for f in files_of(pattern):
            if f.endswith(".pub"):
                continue
            try:
                add_key_lines(read_text(f), f, add)
            except OSError as e:
                MISSING.append(f"{f} ({type(e).__name__})")
    return found


def add_key_lines(text, f, add):
    """A private key leaks line by line: each base64 body line of 40+ characters is a value to look for."""
    if "PRIVATE KEY" not in text:
        return
    for i, line in enumerate(text.splitlines()):
        if KEY_LINE.match(line.strip()):
            add(line.strip(), f"{f} (private key, line {i + 1})", "key")


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


def decoded(path):
    """The text the agent saw or wrote: JSON lines are decoded (so \\" \\\\ \\n come back as they were), other files raw."""
    raw = read_text(path)
    if not path.endswith((".jsonl", ".json")):
        return raw
    out = []
    for line in raw.splitlines():
        try:
            out.extend(strings(json.loads(line)))
        except ValueError:
            out.append(line)
    return "\n".join(out)


def scan(cfg, targets=None):
    values = collect_values(cfg)
    inventory = {}
    for _v, (_n, kind) in values.items():
        inventory[kind] = inventory.get(kind, 0) + 1
    files = []
    for pattern in targets or cfg["targets"]:
        files += files_of(pattern)
    hits = []
    for t in files:
        try:
            text = decoded(t)
        except OSError as e:
            MISSING.append(f"{t} ({type(e).__name__})")
            continue
        per_secret = {}
        for v, (name, kind) in values.items():
            n = text.count(v)
            if n:
                key = name.split(" (private key, line")[0] + (" (private key)" if kind == "key" else "")
                per_secret[key] = per_secret.get(key, 0) + n
        hits += [{"secret": k, "transcript": t, "occurrences": n} for k, n in per_secret.items()]
    return {"mode": "scan", "secrets_checked": len(values), "inventory": inventory, "files_scanned": len(files),
            "missing_sources": list(MISSING), "leaks": hits}


CANARY = "Cn4ry" + "Xk9" * 5
PEM_BEGIN, PEM_END = "-----BEGIN OPENSSH " + "PRIVATE KEY-----", "-----END OPENSSH " + "PRIVATE KEY-----"   # split: scanners flag the literal                         # fake, built at run time


def selftest():
    """Plant one fake secret of every supported shape, write them the way a transcript would, and scan."""
    d = tempfile.mkdtemp(prefix="leak-check-selftest-")
    os.makedirs(f"{d}/t", exist_ok=True)
    pw_url, pw_quote, pw_bslash, plain = CANARY + "u", CANARY + 'q"q', CANARY + "b\\b", CANARY + "p"
    key_body = [("A" + CANARY + "k" * 30)[:64], ("B" + CANARY + "m" * 30)[:64]]
    with open(f"{d}/.env", "w") as f:
        f.write(f"DATABASE_URL=postgres://app:{pw_url}@db/app\nAPI_TOKEN='{pw_quote}'\nDB_PASSWORD={pw_bslash}\nREDIS_PASS={plain}\n")
    with open(f"{d}/id_test", "w") as f:
        f.write(PEM_BEGIN + "\n" + "\n".join(key_body) + "\n" + PEM_END + "\n")
    with open(f"{d}/t/s.jsonl", "w") as f:
        for cmd in (f"psql postgres://app:{pw_url}@db/app", f"curl -H 'X-Token: {pw_quote}'", f"echo {pw_bslash}",
                    f"redis-cli -a {plain}", "cat id_test\n" + PEM_BEGIN + "\n" + "\n".join(key_body)):
            f.write(json.dumps({"message": {"content": [{"type": "tool_result", "content": cmd}]}}) + "\n")
    cfg = {"env_files": [f"{d}/.env"], "value_files": [], "key_files": [f"{d}/id_*"], "min_length": 12,
           "ignore_names": [], "targets": [f"{d}/t/*.jsonl"]}
    r = scan(cfg)
    want = {"DATABASE_URL (password in URL)", "API_TOKEN", "DB_PASSWORD", "REDIS_PASS", "id_test (private key)"}
    got = {h["secret"].split(":", 1)[-1].replace(f"{d}/", "") for h in r["leaks"]}
    missed = sorted(want - got)
    return {"mode": "selftest", "planted": len(want), "found": len(want & got), "missed": missed}


def only_new(report, state_file):
    try:
        seen = set(read_json(state_file))
    except (OSError, ValueError):
        seen = set()
    keys = {f"{h['secret']}|{h['transcript']}": h for h in report["leaks"]}
    report["new_leaks"] = [h for k, h in keys.items() if k not in seen]
    write_json(state_file, sorted(seen | set(keys)))
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["scan", "selftest"])
    ap.add_argument("--config")
    ap.add_argument("--targets", nargs="*", help="override the config's targets (globs)")
    ap.add_argument("--strip", default="", help="prefix removed from file names in the output")
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--state", help="remember reported findings; only new ones go to new_leaks")
    a = ap.parse_args()
    try:
        if a.mode == "selftest":
            r = selftest()
            print(json.dumps(r))
            sys.exit(0 if not r["missed"] else 1)
        r = scan(load_config(a.config), a.targets)
        if a.strip:
            for h in r["leaks"]:
                h["transcript"] = h["transcript"].replace(a.strip, "", 1)
        if r.get("missing_sources"):
            print("WARNING sources not checked: " + "; ".join(r["missing_sources"]), file=sys.stderr)
        if a.state:
            r = only_new(r, a.state)
        if a.report:
            write_json(a.report, r, 1)
        for h in r.get("new_leaks", r["leaks"]):
            print(f"LEAK {h['secret']} in {h['transcript']} ({h['occurrences']}x)")
        print(json.dumps({k: v for k, v in r.items() if k not in ("leaks", "new_leaks")} |
                         {"leaks": len(r["leaks"]), "new_leaks": len(r.get("new_leaks", r["leaks"]))}))
        sys.exit(1 if r["leaks"] else 0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"leak-check: error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

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

Exit code: 0 no leak, 1 leak found (or self-test failed), 2 error, 3 no leak found BUT some configured source was missing
or unreadable (listed in "missing_sources"): a scan with missing sources is not a "no leak".

Configuration (JSON, --config): {
  "env_files":   ["/opt/stacks/*/.env", "/opt/stacks/*/compose.yaml"],  # KEY=VALUE, KEY: value and - KEY=value lines
  "json_files":  ["/etc/cloudflared/*.json"],             # strings under keys whose name looks secret
  "config_files": ["/opt/stacks/*/*/config/*"],           # app configs, read by extension: .json as JSON, .xml by tag,
                                                          #   anything else line by line (YAML, TOML, INI, .conf, .js)
  "value_files": ["/root/.n8n-api-key"],                   # files whose whole content is one secret
  "key_files":   ["/root/.ssh/id_*"],                      # private keys (PEM / OpenSSH): each base64 line is checked
  "targets":     ["/root/.claude/projects/**/*.jsonl", "/root/.bash_history"],   # what to scan
  "min_length":  12,
  "ignore_names": []
}
What counts as a secret in KEY=VALUE files: values of keys whose name looks secret (TOKEN, PASS, KEY, SECRET...), except
identifiers (*_ID, *_USER, *_URL...); whatever the key, the password of any scheme://user:password@host value; and in
URL-like keys (*_URL, *WEBHOOK*, *_DSN...), the token-looking parts of the URL (path segments and query values of 20+
characters mixing letters and digits, as in Discord/Slack/ntfy webhooks, healthcheck pings or api.telegram.org/bot<token>).
"""
import argparse, fnmatch, glob, json, os, re, shutil, sys, tempfile

SECRET_NAME = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASS|PASSWD|PASSWORD|PWD|CREDENTIAL|_AUTH$|^AUTH$|DSN|COOKIE|SALT|PRIVATE_?KEY|PRIVATE$)")
NOT_SECRET_NAME = re.compile(r"(?i)(_ID|CLIENTID|_USER|USERNAME|_NAME|_URL|_URI|_HOST|_PORT|_FILE|_PATH|_DIR)$")
NOT_A_VALUE = re.compile(r"(?i)^(true|false|yes|no|none|null|changeme|example|bearer|basic|os\.environ/.*|env:.*|sk-1234|"
                         r"<[^<>]*>|\*{3,}.*|x{6,}|\[?redacted\]?|\[?hidden\]?|\$\{?.*|/.*|[a-z][a-z0-9+.-]*://.*|\d+|.*\{\{.*\}\}.*|.*\{%.*%\}.*)$")  # last two: templates (Prowlarr definitions, Jinja)
URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]+)@", re.I)
KEY_LINE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
LINE = re.compile(r"""^\s*(?:-\s+)?(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(?:=|:\s)\s*(.*)$""")
URL_KEY = re.compile(r"(?i)(URL|URI|WEBHOOK|HOOK|ENDPOINT|DSN|PING)")


def url_tokens(v):
    """Token-looking parts of a URL: path segments or query values of 20+ characters with letters and digits."""
    m = re.search(r"[a-z][a-z0-9+.-]*://[^/\s?#]*(/[^\s?#]*)?(\?[^\s#]*)?", v, re.I)
    if not m:
        return []
    parts = [x for x in (m.group(1) or "").split("/") if x]
    parts += [kv.split("=", 1)[1] for kv in (m.group(2) or "")[1:].split("&") if "=" in kv]
    out = []
    for x in parts:
        x = re.sub(r"^bot(?=\d+:)", "", x)                     # api.telegram.org/bot<id>:<token>
        if len(x) >= 20 and re.search(r"[A-Za-z]", x) and re.search(r"\d", x):
            out.append(x)
    return out
MISSING = []                   # configured sources that matched nothing or could not be read; filled by collect_values
SKIPPED = []                   # files of config_files deliberately left out (database, backup, too big), with the reason
XML_ATTR = re.compile(r"""\b([A-Za-z_][\w.-]*)\s*=\s*["']([^"'<>]{6,})["']""")
TOKEN_CFG = re.compile(r"^\s*\S+@\S+!\S+\s+([A-Za-z0-9-]{20,})\s*$")          # Proxmox priv/token.cfg: user@realm!id secret


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
    ml_named = cfg.get("min_length_named", 8)      # 6 caught LiteLLM's sk-1234 placeholder in a real run (07/10)
    MISSING.clear()
    SKIPPED.clear()

    def add(v, name, kind, named=False):
        """named: the value sits under a key that says it is secret (PASSWORD=…). External audit of v0.8 (07/10):
        a short or all-digit password is still a password there, so the length floor is lower and digits count."""
        if named and v.isdigit():
            ok = len(v) >= 10                    # shorter digit strings (ports, PINs, dates) match transcripts by chance
        else:
            ok = len(v) >= (ml_named if named else ml) and not NOT_A_VALUE.match(v)
        if ok:
            found.setdefault(v, (name, kind))

    def add_value(key, v, f, kind):
        """One key/value pair from any reader: URL passwords, URL tokens, the value itself, and what it contains."""
        if URL_KEY.search(key) or "://" in v:
            for pw in URL_PASSWORD.findall(v):
                if not pw.startswith("$"):
                    add(pw, f"{f}:{key} (password in URL)", "url")
        if URL_KEY.search(key):
            for tok in url_tokens(v):
                add(tok, f"{f}:{key} (token in URL)", "url")
        if (SECRET_NAME.search(key) or key == "masterKey") and not NOT_SECRET_NAME.search(key):
            add(v, f"{f}:{key}", kind, named=True)
            if key.lower() == "auth":                                   # Docker config.json: base64 of user:password
                try:
                    import base64
                    dec = base64.b64decode(v + "=" * (-len(v) % 4), validate=True).decode()
                    if ":" in dec:
                        add(dec.split(":", 1)[1], f"{f}:{key} (decoded password)", kind, named=True)
                except Exception:
                    pass
        if v.lstrip().startswith("{"):                                  # rclone: token = {"access_token":…}
            try:
                for k2, v2 in json_items(json.loads(v)):
                    if re.search(r"(?i)token$|secret|password", k2):   # access/refresh tokens, not token_type
                        add(v2, f"{f}:{key}:{k2}", kind)
            except ValueError:
                pass

    for pattern in cfg["env_files"]:
        for f in files_of(pattern):
            try:
                lines = read_text(f).splitlines()
            except OSError as e:
                MISSING.append(f"{f} ({type(e).__name__})")
                continue
            for line in lines:
                m = LINE.match(line)
                if not m or m.group(1) in cfg["ignore_names"]:
                    continue
                key, v = m.group(1), re.sub(r"\s+#.*$", "", m.group(2)).strip().strip("'\"")
                for pw in URL_PASSWORD.findall(v):                 # credentials inside a URL, whatever the key
                    if not pw.startswith("$"):
                        add(pw, f"{f}:{key} (password in URL)", "url")
                if URL_KEY.search(key):
                    for tok in url_tokens(v):
                        add(tok, f"{f}:{key} (token in URL)", "url")
                if SECRET_NAME.search(key) and not NOT_SECRET_NAME.search(key):
                    add(v, f"{f}:{key}", "env", named=True)
    xml_tag = re.compile(r"<([A-Za-z_][\w.-]*)>([^<]{12,})</\1>")
    for pattern in cfg.get("config_files", []):
        for f in files_of(pattern):
            if f.endswith((".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".log", ".png", ".jpg", ".gz", ".zip")):
                SKIPPED.append(f"{f} (database, log or binary)")
                continue
            if re.search(r"\.(bak|old|orig)\b|~$", os.path.basename(f)):
                SKIPPED.append(f"{f} (backup copy: delete it, or list it in value_files if it may still hold live values)")
                continue
            if os.path.getsize(f) > 2_000_000:
                SKIPPED.append(f"{f} (larger than 2 MB)")
                continue                     # all listed in the report: a skipped file is never silently "checked"
            try:
                text = read_text(f)
            except OSError as e:
                MISSING.append(f"{f} ({type(e).__name__})")
                continue
            if f.endswith(".json"):
                try:
                    items = list(json_items(json.loads(text)))
                except ValueError:
                    items = []
            elif f.endswith(".xml"):
                items = [(m.group(1), m.group(2).strip()) for m in xml_tag.finditer(text)]
                items += [(m.group(1), m.group(2).strip()) for m in XML_ATTR.finditer(text)]   # Plex: PlexOnlineToken="…"
                # ASP.NET data-protection key files keep the key in <value>, under a <key> element
                if "<key " in text and "<masterKey" in text:
                    items += [("masterKey", m.group(2).strip()) for m in xml_tag.finditer(text) if m.group(1) == "value"]
            else:
                items, lines = [], text.splitlines()
                for i, line in enumerate(lines):
                    m = LINE.match(line)
                    if m:
                        v = re.sub(r"\s+#.*$", "", m.group(2)).strip().strip(",;").strip("'\"")
                        if v in ("|", ">", "|-", ">-", "|+", ">+"):          # YAML block scalar: the value is below
                            ind = len(line) - len(line.lstrip())
                            block = []
                            for nxt in lines[i + 1:]:
                                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= ind:
                                    break
                                block.append(nxt.strip())
                            items += [(m.group(1), b) for b in block if b]
                            continue
                        items.append((m.group(1), v))
                    if "pgpass" in os.path.basename(f) and line.count(":") >= 4 and not line.lstrip().startswith("#"):
                        items.append(("PGPASS_PASSWORD", line.split(":", 4)[4]))   # host:port:db:user:password
                    t = TOKEN_CFG.match(line)
                    if t:
                        items.append(("PROXMOX_TOKEN_SECRET", t.group(1)))
            for key, v in items:
                add_value(key, v, f, "config")
    for pattern in cfg.get("json_files", []):
        for f in files_of(pattern):
            try:
                data = read_json(f)
            except (OSError, ValueError) as e:
                MISSING.append(f"{f} ({type(e).__name__})")
                continue
            for key, v in json_items(data):
                add_value(key, v, f, "json")
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


def json_items(obj, parent=""):
    """(key, string value) pairs anywhere in a JSON document. Strings in a list keep the list's key
    ({"tokens": ["…"]}, external audit of v0.8)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield str(k), v
            else:
                yield from json_items(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, str):
                yield parent, v
            else:
                yield from json_items(v, parent)


def add_key_lines(text, f, add):
    """A private key leaks line by line: each base64 body line of 40+ characters is a value to look for, except the
    lines that are not secret. Every unencrypted OpenSSH ed25519 key starts with the SAME first line (format header),
    and the second carries the public key; a PEM key's first line is mostly the algorithm header. Matching those would
    report every key of the same type as leaked (it happened: 06/10/2026)."""
    if "PRIVATE KEY" not in text:
        return
    body = [(i, l.strip()) for i, l in enumerate(text.splitlines()) if KEY_LINE.match(l.strip())]
    skip = 2 if "OPENSSH PRIVATE KEY" in text else 1
    if len(body) <= skip:              # one-line PEM body (Ed25519 PKCS#8): that line IS the key (external audit of v0.8)
        skip = 0
    for i, line in body[skip:]:
        add(line, f"{f} (private key, line {i + 1})", "key")


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
                c, ids = per_secret.get(key, (0, set()))
                per_secret[key] = (c + n, ids | {value_id(v)})
        hits += [{"secret": k, "transcript": t, "occurrences": n, "vid": ",".join(sorted(ids))}
                 for k, (n, ids) in per_secret.items()]
    return {"mode": "scan", "secrets_checked": len(values), "inventory": inventory, "files_scanned": len(files),
            "missing_sources": list(MISSING), "skipped_sources": list(SKIPPED), "leaks": hits}


def value_id(v):
    """A keyed fingerprint of a value, so a rotated secret leaking again is a new finding. The key is local and random;
    the id stays in the root-only report and state, never in an alert (external audit of v0.8, 07/10)."""
    import hashlib, hmac
    path = os.path.expanduser(os.environ.get("LEAK_CHECK_KEY", "~/.local/state/leak-check/value-id.key"))
    try:
        key = open(path, "rb").read()
    except OSError:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        key = os.urandom(32)
        old = os.umask(0o077)
        try:
            with open(path, "wb") as f:
                f.write(key)
        finally:
            os.umask(old)
    return hmac.new(key, v.encode(), hashlib.sha256).hexdigest()[:12]


CANARY = "Cn4ry" + "Xk9" * 5
PEM_BEGIN, PEM_END = "-----BEGIN OPENSSH " + "PRIVATE KEY-----", "-----END OPENSSH " + "PRIVATE KEY-----"   # split: scanners flag the literal                         # fake, built at run time


def selftest():
    """Plant one fake secret of every supported shape, write them the way a transcript would, and scan."""
    d = tempfile.mkdtemp(prefix="leak-check-selftest-")
    try:
        return _selftest(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _selftest(d):
    os.makedirs(f"{d}/t", exist_ok=True)
    pw_url, pw_quote, pw_bslash, plain = CANARY + "u", CANARY + 'q"q', CANARY + "b\\b", CANARY + "p"
    key_body = [(c + CANARY + "k" * 40)[:64] for c in "ABCD"]
    hook, yml, lst, js = CANARY + "w" * 3, CANARY + "y", CANARY + "l", CANARY + "j"
    with open(f"{d}/.env", "w") as f:
        f.write(f"DATABASE_URL=postgres://app:{pw_url}@db/app\nAPI_TOKEN='{pw_quote}'\nDB_PASSWORD={pw_bslash}\nREDIS_PASS={plain}\n"
                f"DISCORD_WEBHOOK_URL=https://discord.example/api/webhooks/123/{hook}\n")
    with open(f"{d}/compose.yaml", "w") as f:
        f.write(f"services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: {yml}\n      - MYSQL_ROOT_PASSWORD={lst}\n")
    with open(f"{d}/tunnel.json", "w") as f:
        json.dump({"AccountTag": "x", "TunnelSecret": js}, f)
    with open(f"{d}/id_test", "w") as f:
        f.write(PEM_BEGIN + "\n" + "\n".join(key_body) + "\n" + PEM_END + "\n")
    with open(f"{d}/t/s.jsonl", "w") as f:
        for cmd in (f"psql postgres://app:{pw_url}@db/app", f"curl -H 'X-Token: {pw_quote}'", f"echo {pw_bslash}",
                    f"redis-cli -a {plain}", "cat id_test\n" + PEM_BEGIN + "\n" + "\n".join(key_body),
                    f"curl https://discord.example/api/webhooks/123/{hook}", f"docker inspect db -> {yml} {lst}", f"cat tunnel.json {js}"):
            f.write(json.dumps({"message": {"content": [{"type": "tool_result", "content": cmd}]}}) + "\n")
    cfg = {"env_files": [f"{d}/.env", f"{d}/compose.yaml"], "json_files": [f"{d}/tunnel.json"], "value_files": [],
           "key_files": [f"{d}/id_*"], "min_length": 12, "ignore_names": [], "targets": [f"{d}/t/*.jsonl"]}
    r = scan(cfg)
    want = {"DATABASE_URL (password in URL)", "API_TOKEN", "DB_PASSWORD", "REDIS_PASS", "id_test (private key)",
            "DISCORD_WEBHOOK_URL (token in URL)", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "TunnelSecret"}
    got = {h["secret"].split(":", 1)[-1].replace(f"{d}/", "") for h in r["leaks"]}
    missed = sorted(want - got)
    return {"mode": "selftest", "planted": len(want), "found": len(want & got), "missed": missed}


def only_new(report, state_file):
    try:
        seen = set(read_json(state_file))
    except (OSError, ValueError):
        seen = set()
    keys = {f"{h['secret']}|{h['transcript']}|{h.get('vid', '')}": h for h in report["leaks"]}
    with_ids = {k.rsplit("|", 1)[0] for k in seen if k.count("|") >= 2}
    def known(k):
        base = k.rsplit("|", 1)[0]
        return k in seen or (base in seen and base not in with_ids)      # state written before value ids existed
    report["new_leaks"] = [h for k, h in keys.items() if not known(k)]
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
        if r.get("skipped_sources"):
            print("NOTE files not read: " + "; ".join(r["skipped_sources"])[:800], file=sys.stderr)
        print(json.dumps({k: v for k, v in r.items() if k not in ("leaks", "new_leaks", "skipped_sources")} |
                         {"skipped_sources": len(r.get("skipped_sources", []))} |
                         {"leaks": len(r["leaks"]), "new_leaks": len(r.get("new_leaks", r["leaks"]))}))
        sys.exit(1 if r["leaks"] else 3 if r.get("missing_sources") else 0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"leak-check: error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

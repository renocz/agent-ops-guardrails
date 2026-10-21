#!/usr/bin/python3 -I
"""docker-proxy daemon: the only process that talks to the real `docker` CLI on behalf of a non-root agent.

Why a proxy and not `docker` group membership: membership in the `docker` group is root-equivalent (mounting `/`
into a container and `docker exec`-ing into it gets you a root shell on the host) -- see docs/design-keeper-server.md
section 1, option A vs C. This daemon runs as a dedicated, trusted account (`dockerproxy`, installed by
install-docker-proxy.sh) that IS a member of `docker`; the agent never is. The agent reaches this daemon over its
own Unix socket (installed group-readable/writable only by a narrow client group), never the Docker socket.

Backend choice: this proxy shells out to the `docker` CLI (subprocess, argv list, never a shell string) instead of
talking to the Docker Engine API/socket directly. Reasons: zero non-stdlib dependencies (no Docker SDK, no HTTP
client needed), the CLI's own argument handling is already hardened and widely reviewed, and a `subprocess.run`
call with a fully-controlled argv list is as auditable as a raw API call here -- every argv this daemon can ever
build is visible in build_argv() below, nothing is passed through from the agent's own strings except a container
name that is validated against NAME_RE first. Documented explicitly because docs/design-keeper-server.md section 1
left this choice open ("via le CLI docker lui-meme ... ou le socket, selon ce qui est le plus simple et sur").

Policy, in order, never a blacklist -- anything not explicitly matched below is refused:
  - read subcommands (ps, logs, inspect, stats, top) are allowed by default, structurally: they cannot reach the
    write path, there is no shared code between "decide read" and "decide write" that a bug could blur. If the
    root-owned config sets read_allow.containers, logs/inspect/stats/top (anything with a target) are narrowed to
    that list too, same fail-closed literal-name rule as write_allow; ps is unaffected (it lists containers, it
    does not target one).
  - write subcommands (restart, start, stop) are allowed only for a container name present, verbatim, in the
    root-owned config's write_allow.containers list. No wildcard, no prefix, no regex: load_config() refuses to
    start if any configured entry is not itself a bare, valid container name.
  - a container/target name that does not match Docker's own naming rules (NAME_RE) is refused before anything
    else runs, whether it is a read or a write -- this is what stops shell-metacharacter or flag-injection
    attempts (a name of "-v" or ";rm -rf /" never reaches build_argv, let alone subprocess).
  - `inspect` never returns the full `docker inspect` JSON: the daemon always runs it with its own fixed
    --format (INSPECT_FORMAT below), never one supplied by the agent, and that format excludes Config.Env and
    Config.Cmd -- the two fields that routinely carry API keys and passwords. See "Secret exposure via inspect
    and logs" below.
  - `inspect` and `logs` output (stdout and stderr) is passed through mask_text() before it leaves this daemon,
    server-side, so the agent cannot get an unmasked copy by skipping its own local mask. See below.

Secret exposure via inspect and logs (owner review of PR #21, 21/10/2026): `docker inspect` includes every
environment variable a container was started with, verbatim -- `Config.Env`, which routinely holds API keys,
database passwords and tokens -- and `Config.Cmd`/`Config.Entrypoint` can carry a secret passed as a CLI flag.
`docker logs` prints whatever the container writes, which regularly includes secrets in connection strings, stack
traces or startup banners. Before this fix, both subcommands returned docker's raw stdout unfiltered, so a
container holding a real secret in its environment handed that secret to the agent on the first `inspect`. Two
independent layers fix this, deliberately redundant (either one failing alone must not leak a secret):
  1. inspect's --format is a fixed, daemon-owned allowlist of fields (INSPECT_FIELDS) that structurally never asks
     docker for Env or Cmd in the first place -- there is no code path where the agent's request can change the
     format string (an agent-supplied "format" key in the request is refused outright, see decide()).
  2. mask_text() -- the pattern-based redaction from secret-guard/mask, ported into this module (see its own
     docstring for why it is a port rather than a subprocess call to the Perl script) -- is run over inspect's
     and logs' stdout/stderr before either is returned, catching anything layer 1 didn't anticipate (a secret in
     a log line, in a Health check's own output, in a mount path). Like secret-guard's own mask, this is
     pattern-based and best-effort, not a security boundary against a determined adversary (see secret-guard's
     README "Scope and limits") -- it is the same defense-in-depth the rest of this repo already applies to
     agent-run commands, just enforced here where the agent cannot skip it.
"""
import json, os, re, socketserver, subprocess, sys, time

# Docker's own container/name charset: letters, digits, underscore, dot, hyphen; must not start with a separator.
# Reused for BOTH runtime target validation and config loading: a config entry that fails this is a wildcard/regex
# attempt, not a container name, and load_config() refuses to start rather than silently ignoring it.
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")

READ_SUBCOMMANDS = {"ps", "logs", "inspect", "stats", "top"}
WRITE_SUBCOMMANDS = {"restart", "start", "stop"}

# inspect's own fixed --format, built field by field, never from agent input (see decide(): a "format" key in the
# request is refused). Each entry is (output key, Go template path into docker inspect's JSON). Deliberately
# excludes Config.Env, Config.Cmd and Config.Entrypoint -- the fields that routinely carry secrets. One field per
# line (`{{json <path>}}` on docker's own JSON-marshals-and-escapes-control-characters output, so a literal "\n"
# between them is never ambiguous with a newline inside a value) so build_inspect_result() can split on them
# positionally without guessing at a Go template function (e.g. "dict") that may not exist in every docker version.
INSPECT_FIELDS = [
    ("Name", ".Name"),
    ("Id", ".Id"),
    ("State", ".State.Status"),
    ("Image", ".Config.Image"),
    ("RestartPolicy", ".HostConfig.RestartPolicy"),
    ("Health", ".State.Health"),
    ("Networks", ".NetworkSettings.Networks"),
    ("Mounts", ".Mounts"),
]
INSPECT_FORMAT = "\n".join("{{json %s}}" % path for _, path in INSPECT_FIELDS)

DEFAULT_TAIL = 200
MAX_TAIL = 5000
MAX_STOP_TIMEOUT = 300          # seconds; bounds the optional -t/--time passed to restart/stop
RUN_TIMEOUT_SEC = 20            # subprocess.run timeout for every docker invocation this daemon makes

DEFAULT_SOCKET = "/run/docker-proxy/docker-proxy.sock"
DEFAULT_CONFIG = "/etc/docker-proxy/config.json"
# Test-only override, mirroring keeper_client.py's pattern: only honoured when the test mode flag is also set, so
# an agent-writable env var alone can never redirect the daemon (real deployments run it with `env -i`).
SOCKET = os.environ.get("DOCKER_PROXY_SOCKET_FOR_TESTS") if os.environ.get("DOCKER_PROXY_TEST_MODE") == "1" else None
SOCKET = SOCKET or DEFAULT_SOCKET


def _load_literal_container_list(containers, section):
    """Shared by write_allow and read_allow: raise ValueError on anything that looks like a wildcard, a regex, or
    a non-literal container name. Fail-closed load, not a best-effort filter -- a bad config entry stops the
    daemon from starting at all rather than silently being dropped or silently ignored."""
    if not isinstance(containers, list):
        raise ValueError(f"{section}.containers must be a list")
    for name in containers:
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ValueError(
                f"{section}.containers entry {name!r} is not a literal container name "
                "(wildcards, regexes and empty/odd strings are refused -- list exact names only)"
            )
    return set(containers)


def load_config(path):
    """Load and validate the write allowlist, and the optional read allowlist. See _load_literal_container_list
    for the fail-closed validation both share."""
    with open(path) as f:
        raw = json.load(f)
    write_containers = raw.get("write_allow", {}).get("containers", [])
    config = {"write_allow_containers": _load_literal_container_list(write_containers, "write_allow")}
    # read_allow is opt-in and presence-gated, not emptiness-gated: an explicit "read_allow": {} means "restrict
    # reads to nothing" (same fail-closed posture as write_allow's missing-section-defaults-to-empty), while no
    # "read_allow" key at all means the previous, unrestricted behaviour -- any syntactically valid target.
    if "read_allow" in raw:
        read_containers = raw.get("read_allow", {}).get("containers", [])
        config["read_allow_containers"] = _load_literal_container_list(read_containers, "read_allow")
    else:
        config["read_allow_containers"] = None
    return config


def is_whitelisted(target, config):
    """The one check that gates a write. Kept as its own function (rather than inlined in decide()) so a test can
    monkeypatch it to always return True and show that the result actually depends on it -- see
    test_docker_proxy.py's mutation check."""
    return target in config["write_allow_containers"]


def is_read_allowed(target, config):
    """The one check that gates a targeted read when read_allow.containers is configured. None means
    unconfigured (every syntactically valid target is allowed, the pre-existing behaviour); a set, even empty,
    means configured (only a literal match is allowed). Its own function for the same reason as is_whitelisted:
    a test can monkeypatch it to prove decide() actually calls it."""
    allowed = config["read_allow_containers"]
    return allowed is None or target in allowed


def decide(req, config):
    """Pure policy decision: no subprocess, no I/O beyond what's already in `config`. Returns (allowed, reason,
    argv) where argv is the exact docker CLI invocation to run when allowed, or None when refused."""
    if not isinstance(req, dict):
        return False, "request must be a JSON object", None
    sub = req.get("subcommand")
    if sub not in READ_SUBCOMMANDS and sub not in WRITE_SUBCOMMANDS:
        return False, f"unknown or unsupported subcommand: {sub!r}", None

    target = req.get("target")

    if sub == "ps":
        if target is not None:
            return False, "ps does not take a target", None
        argv = ["docker", "ps"]
        if req.get("all"):
            argv.append("-a")
        return True, "read", argv

    if target is None or not isinstance(target, str) or not NAME_RE.match(target):
        return False, "invalid or missing target name", None

    if sub in READ_SUBCOMMANDS:
        if sub == "inspect" and "format" in req:
            # inspect's --format is this daemon's own fixed allowlist (INSPECT_FORMAT), never one the agent
            # supplies -- a request that tries to pass one is refused outright, not silently ignored, so this
            # stays a visible, tested guarantee rather than an accident of the client never sending the key.
            return False, "format is not accepted from the agent", None
        if not is_read_allowed(target, config):
            return False, f"container not in read allowlist: {target!r}", None
        argv = ["docker", sub]
        if sub == "stats":
            argv.append("--no-stream")          # never let the daemon block forever on a streaming call
        if sub == "logs":
            tail = req.get("tail", DEFAULT_TAIL)
            if not isinstance(tail, int) or isinstance(tail, bool) or not (1 <= tail <= MAX_TAIL):
                return False, f"invalid tail value (must be an int 1..{MAX_TAIL})", None
            argv += ["--tail", str(tail)]
        if sub == "inspect":
            argv += ["--format", INSPECT_FORMAT]
        argv.append(target)
        return True, "read", argv

    # write: restart / start / stop
    if not is_whitelisted(target, config):
        return False, f"container not in write allowlist: {target!r}", None
    argv = ["docker", sub]
    if sub in {"restart", "stop"}:
        timeout = req.get("timeout")
        if timeout is not None:
            if not isinstance(timeout, int) or isinstance(timeout, bool) or not (0 <= timeout <= MAX_STOP_TIMEOUT):
                return False, f"invalid timeout value (must be an int 0..{MAX_STOP_TIMEOUT})", None
            argv += ["-t", str(timeout)]
    argv.append(target)
    return True, "write", argv


def build_inspect_result(stdout):
    """Turn INSPECT_FORMAT's raw output (one JSON value per line, in INSPECT_FIELDS order) into the filtered
    dict this daemon actually returns for `inspect`. Fails closed: if the output doesn't look like what our own
    fixed format produces (wrong number of lines, invalid JSON), this returns None rather than guessing or
    falling back to the raw text -- decide()/handle_request() turn that into an error response, never a passthrough
    of whatever docker printed."""
    lines = stdout.rstrip("\n").split("\n")
    if len(lines) != len(INSPECT_FIELDS):
        return None
    try:
        values = [json.loads(line) for line in lines]
    except json.JSONDecodeError:
        return None
    return {key: value for (key, _path), value in zip(INSPECT_FIELDS, values)}


# ---------------------------------------------------------------------------------------------------------------
# mask_text(): secret redaction for inspect/logs output, applied here in the daemon (server-side), so the agent
# cannot get an unmasked copy by simply not piping its own output through secret-guard's `mask`.
#
# This is a port of secret-guard/mask's own regexes (same patterns, same order, same replacement tokens), not a
# subprocess call to that Perl script. Reasons: this daemon runs under systemd with ProtectHome=true and an
# emptied environment (`env -i`, see install-docker-proxy.sh), the same hardening secret-guard's own install does
# not need to survive; shelling out to a second interpreter (Perl) from inside that sandbox for every inspect/logs
# call adds a runtime dependency and a new fail-open edge (what happens if the binary or Perl itself is missing or
# not on the daemon's intentionally-empty PATH) that a pure most-stdlib port does not have. Keeping the same
# patterns is what satisfies "reuse the existing mask instead of inventing a new one": test_docker_proxy.py's
# MaskPortMatchesSecretGuard class runs the two implementations over the same fixtures and fails if they diverge,
# so a change made to one and not the other is caught instead of silently drifting.
# ---------------------------------------------------------------------------------------------------------------
_MASK = "<m>"
_PK_BEGIN_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PK_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_PK_BEGIN_LINE_RE = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{15,}(?:\.[A-Za-z0-9_-]*){0,2}")
_KEY_PREFIX_RE = re.compile(r"\b(sk-(?:ant-|proj-)?|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|AIza|xox[abpr]-|cfut_|hf_)[A-Za-z0-9_-]{8,}")
_BOTTOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")
_URL_USERPASS_RE = re.compile(r"://[^/@\s:]+:[^/@\s]+@")
_URL_TOKEN_RE = re.compile(r"://[A-Za-z0-9_]{20,}@")
_AUTH_HEADER_RE = re.compile(r"(Authorization:\s*(?:Bearer|token|Basic)\s+)\S+", re.I)
_X_HEADER_RE = re.compile(r"(X-[A-Za-z-]*(?:Key|Token)[A-Za-z-]*:\s*)\S+", re.I)
_FLAG_RE = re.compile(r"(--?(?:token|key|password|passwd|secret|api-key|apikey)[= ]+[\"']?)[^\s\"']+", re.I)
_XML_RE = re.compile(r"(<(?:ApiKey|Password|Token|Secret|ClientSecret)>)[^<]+(</)", re.I)
_DASH_U_RE = re.compile(r"(\s-u\s+[^\s:]+:)\S+")
_QUOTED_KV_RE = re.compile(
    r"((?:key|token|secret|password|passwd|pwd|passphrase|cookie|credential)[A-Za-z0-9_]*[\"']?\s*[:=]\s*)([\"'])[^\"']*\2", re.I)
_BARE_KV_RE = re.compile(
    r"((?:key|token|secret|password|passwd|pwd|auth|cookie|bearer|session|credential)[A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']?)[^\s,\"'}\]]{3,}", re.I)
_BARE_TOKEN_LINE_RE = re.compile(
    r"^(\s*)(?=[A-Za-z0-9+/_=~-]{16,}\s*$)(?=[^\n]*[A-Za-z])(?=[^\n]*\d)(?![0-9a-fA-F]+\s*$)[^\s/.]+(\s*)$")


def _mask_line(line):
    line = _JWT_RE.sub("<jwt>", line)
    line = _KEY_PREFIX_RE.sub(r"\1" + _MASK, line)
    line = _BOTTOKEN_RE.sub("<bottoken>", line)
    line = _URL_USERPASS_RE.sub("://" + _MASK + "@", line)
    line = _URL_TOKEN_RE.sub("://" + _MASK + "@", line)
    line = _AUTH_HEADER_RE.sub(r"\1" + _MASK, line)
    line = _X_HEADER_RE.sub(r"\1" + _MASK, line)
    line = _FLAG_RE.sub(r"\1" + _MASK, line)
    line = _XML_RE.sub(r"\1" + _MASK + r"\2", line)
    line = _DASH_U_RE.sub(r"\1" + _MASK, line)
    line = _QUOTED_KV_RE.sub(r"\1\2" + _MASK + r"\2", line)
    line = _BARE_KV_RE.sub(r"\1" + _MASK, line)
    line = _BARE_TOKEN_LINE_RE.sub(r"\1" + _MASK + r"\2", line)
    return line


def mask_text(text):
    """Redact secret-looking values from text, line by line (mirroring secret-guard/mask's Perl `-p` mode,
    including a PEM private-key block being masked from BEGIN to END even if END never arrives -- a truncated
    stream stays fully masked rather than leaking the back half of a key)."""
    out, in_pk = [], False
    for line in text.splitlines(keepends=True):
        if not in_pk and _PK_BEGIN_RE.search(line):
            in_pk = True
            out.append(_PK_BEGIN_LINE_RE.sub(r"\1 " + _MASK, line))
            continue
        if in_pk:
            if _PK_END_RE.search(line):
                in_pk = False
                out.append(line)
            else:
                out.append(_MASK + ("\n" if line.endswith("\n") else ""))
            continue
        out.append(_mask_line(line))
    return "".join(out)


def audit(kind, req, allowed, reason):
    """One line to stderr (journald under systemd) per request. Subcommand + target + verdict only -- never
    stdout/stderr of the docker call itself, so nothing a container prints ends up in the audit trail."""
    sys.stderr.write(
        f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {kind} "
        f"subcommand={req.get('subcommand')!r} target={req.get('target')!r} "
        f"allowed={allowed} reason={reason}\n"
    )
    sys.stderr.flush()


def handle_request(req, config, run=subprocess.run):
    """run= is dependency-injected so tests can pass a recorder/fake instead of calling the real docker CLI."""
    allowed, reason, argv = decide(req, config)
    audit("decision", req, allowed, reason)
    if not allowed:
        return {"ok": False, "error": reason}
    try:
        proc = run(argv, capture_output=True, text=True, timeout=RUN_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "docker command timed out"}
    except FileNotFoundError:
        return {"ok": False, "error": "docker binary not found"}

    sub = req.get("subcommand")
    stdout, stderr = proc.stdout, proc.stderr
    if sub in ("inspect", "logs"):
        # Both layers apply here: inspect's stdout is first reduced to the fixed field allowlist (never the raw
        # docker JSON), then whatever is left -- including inspect's own filtered fields and all of logs' output
        # -- goes through mask_text() as the second, independent layer. Only on inspect's success path: a failed
        # `docker inspect` (no such container) has no JSON to filter, so it falls through to the plain mask like
        # logs, and is surfaced like any other docker failure (see test_docker_failure_is_surfaced_not_raised).
        if sub == "inspect" and proc.returncode == 0:
            result = build_inspect_result(stdout)
            if result is None:
                return {"ok": False, "error": "inspect output did not match the daemon's own fixed format"}
            stdout = mask_text(json.dumps(result))
        else:
            stdout = mask_text(stdout)
        stderr = mask_text(stderr)

    return {"ok": True, "argv": argv, "returncode": proc.returncode, "stdout": stdout, "stderr": stderr}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        if not line:
            return
        try:
            req = json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            resp = {"ok": False, "error": "request must be one line of JSON"}
        else:
            resp = handle_request(req, self.server.config, self.server.run)
        self.wfile.write((json.dumps(resp) + "\n").encode())


class ProxyServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path, config, run=subprocess.run):
        if os.path.exists(socket_path):
            os.remove(socket_path)              # stale socket from a previous, crashed run
        super().__init__(socket_path, _Handler)
        os.chmod(socket_path, 0o660)
        self.config = config
        self.run = run


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="docker-proxy daemon")
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("--socket", default=SOCKET)
    args = p.parse_args(argv)
    config = load_config(args.config)
    server = ProxyServer(args.socket, config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(args.socket):
            os.remove(args.socket)


if __name__ == "__main__":
    main()

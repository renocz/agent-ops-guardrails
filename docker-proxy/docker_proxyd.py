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
  - read subcommands (ps, logs, inspect, stats, top) are always allowed, structurally: they cannot reach the
    write path, there is no shared code between "decide read" and "decide write" that a bug could blur.
  - write subcommands (restart, start, stop) are allowed only for a container name present, verbatim, in the
    root-owned config's write_allow.containers list. No wildcard, no prefix, no regex: load_config() refuses to
    start if any configured entry is not itself a bare, valid container name.
  - a container/target name that does not match Docker's own naming rules (NAME_RE) is refused before anything
    else runs, whether it is a read or a write -- this is what stops shell-metacharacter or flag-injection
    attempts (a name of "-v" or ";rm -rf /" never reaches build_argv, let alone subprocess).
"""
import json, os, re, socketserver, subprocess, sys, time

# Docker's own container/name charset: letters, digits, underscore, dot, hyphen; must not start with a separator.
# Reused for BOTH runtime target validation and config loading: a config entry that fails this is a wildcard/regex
# attempt, not a container name, and load_config() refuses to start rather than silently ignoring it.
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")

READ_SUBCOMMANDS = {"ps", "logs", "inspect", "stats", "top"}
WRITE_SUBCOMMANDS = {"restart", "start", "stop"}

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


def load_config(path):
    """Load and validate the write allowlist. Raises ValueError on anything that looks like a wildcard, a regex,
    or a non-literal container name -- this is a fail-closed load, not a best-effort filter: a bad config entry
    stops the daemon from starting at all rather than silently being dropped."""
    with open(path) as f:
        raw = json.load(f)
    containers = raw.get("write_allow", {}).get("containers", [])
    if not isinstance(containers, list):
        raise ValueError("write_allow.containers must be a list")
    for name in containers:
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ValueError(
                f"write_allow.containers entry {name!r} is not a literal container name "
                "(wildcards, regexes and empty/odd strings are refused -- list exact names only)"
            )
    return {"write_allow_containers": set(containers)}


def is_whitelisted(target, config):
    """The one check that gates a write. Kept as its own function (rather than inlined in decide()) so a test can
    monkeypatch it to always return True and show that the result actually depends on it -- see
    test_docker_proxy.py's mutation check."""
    return target in config["write_allow_containers"]


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
        argv = ["docker", sub]
        if sub == "stats":
            argv.append("--no-stream")          # never let the daemon block forever on a streaming call
        if sub == "logs":
            tail = req.get("tail", DEFAULT_TAIL)
            if not isinstance(tail, int) or isinstance(tail, bool) or not (1 <= tail <= MAX_TAIL):
                return False, f"invalid tail value (must be an int 1..{MAX_TAIL})", None
            argv += ["--tail", str(tail)]
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
    return {"ok": True, "argv": argv, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


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

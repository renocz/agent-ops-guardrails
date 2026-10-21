#!/usr/bin/python3 -I
"""docker-proxy client: what the agent runs instead of `docker` directly.

This file enforces nothing itself -- it builds a JSON request and sends it to docker_proxyd.py over its Unix
socket, then prints whatever the daemon decided. That is deliberate: even a modified or hostile copy of this
client gains nothing, because the allow/deny decision happens in the daemon's own process, which the agent cannot
write to (see docs/design-keeper-server.md section 1, option C -- "not a check that could be argued around").
"""
import argparse, json, os, socket, sys

SOCKETS = ("/run/docker-proxy/docker-proxy.sock",)
SOCKET = os.environ.get("DOCKER_PROXY_SOCKET_FOR_TESTS") if os.environ.get("DOCKER_PROXY_TEST_MODE") == "1" else None
SOCKET = SOCKET or SOCKETS[0]


def ask(req, sock_path=None, timeout=15):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path or SOCKET)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf)
    finally:
        s.close()


def build_parser():
    p = argparse.ArgumentParser(prog="docker-proxy", description="filtered docker access for a non-root agent")
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("ps", help="list containers").add_argument("-a", "--all", action="store_true")
    for name in ("inspect", "top"):
        sp = sub.add_parser(name)
        sp.add_argument("target")
    sp = sub.add_parser("logs")
    sp.add_argument("target")
    sp.add_argument("--tail", type=int, default=None)
    sp = sub.add_parser("stats")
    sp.add_argument("target")
    for name in ("restart", "start", "stop"):
        sp = sub.add_parser(name)
        sp.add_argument("target")
        if name != "start":
            sp.add_argument("--timeout", type=int, default=None)
    return p


def to_request(ns):
    req = {"subcommand": ns.subcommand}
    if getattr(ns, "target", None) is not None:
        req["target"] = ns.target
    if getattr(ns, "all", False):
        req["all"] = True
    if getattr(ns, "tail", None) is not None:
        req["tail"] = ns.tail
    if getattr(ns, "timeout", None) is not None:
        req["timeout"] = ns.timeout
    return req


def main(argv=None):
    ns = build_parser().parse_args(argv)
    req = to_request(ns)
    try:
        resp = ask(req)
    except (OSError, ValueError) as exc:
        print(f"docker-proxy: could not reach the daemon: {exc}", file=sys.stderr)
        return 3
    if not resp.get("ok"):
        print(f"docker-proxy: refused: {resp.get('error')}", file=sys.stderr)
        return 2
    sys.stdout.write(resp.get("stdout", ""))
    sys.stderr.write(resp.get("stderr", ""))
    return resp.get("returncode", 1)


if __name__ == "__main__":
    sys.exit(main())

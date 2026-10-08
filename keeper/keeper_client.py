#!/usr/bin/python3 -I
"""keeper hook: the PreToolUse hook of Claude Code when the keeper is installed (replaces go-gate's own hook).

It does not decide anything itself: it forwards the raw tool call to keeperd and applies its answer. keeperd classifies
the call, so this file running as the agent's user gains nothing by lying.

If keeperd cannot be reached, it fails closed: reads still pass (judged by the same classifier, root-owned copy next to
this file), changes are refused.

The agent proposes a plan with `keeper-propose --scope "id=… ; targets=… ; actions=… ; ttl=…" --text "why"`: keeperd
answers that command in the check itself (with the session id Claude Code gave this hook), so it never runs.
"""
import importlib.util, json, os, socket, sys

SOCKETS = ("/opt/agent-guardrails/run/keeper.sock", "/run/keeper/keeper.sock")       # macOS, Linux (install-keeper.sh)
SOCKET = os.environ.get("KEEPER_SOCKET_FOR_TESTS") if os.environ.get("KEEPER_TEST_MODE") == "1" else None
SOCKET = SOCKET or next((p for p in SOCKETS if os.path.exists(p)), SOCKETS[0])
HERE = os.path.dirname(os.path.abspath(__file__))


def ask(req, timeout=10):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCKET)
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


def local_kind(tool, tool_input):
    """Only used when keeperd is down: is this call a read? Anything unsure is a change."""
    try:
        path = os.path.join(HERE, "go_gate.py")
        if not os.path.exists(path):
            path = os.path.join(HERE, "..", "go-gate", "go_gate.py")
        spec = importlib.util.spec_from_file_location("go_gate", path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        if gate.pipeline_stages is None:
            gate.scan, gate.pipeline_stages = gate._load_splitter()
        return gate.classify(tool, tool_input)[0]
    except Exception:
        return "change"


def deny(why):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": why}}))
    sys.exit(0)


def hook():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        print("keeper: unreadable hook input; refusing to be safe.", file=sys.stderr)
        sys.exit(2)
    if data.get("hook_event_name") != "PreToolUse":
        sys.exit(0)
    tool, ti = data.get("tool_name", ""), data.get("tool_input") or {}
    try:
        out = ask({"op": "check", "session": data.get("session_id"), "tool": tool, "input": ti})
    except (OSError, ValueError) as e:
        if local_kind(tool, ti) in ("read", "talk"):
            sys.exit(0)
        deny(f"keeper: the keeper daemon is not reachable ({type(e).__name__}), so changes are refused. "
             "Tell the user; reads still work.")
    if out.get("decision") == "allow":
        sys.exit(0)
    deny(out.get("reason") or "keeper: refused")


NOT_INSTALLED = ("keeper-propose / keeper-status are handled by the keeper hook, which answers them before they run. "
                 "If you see this, the keeper hook is not active.")

if __name__ == "__main__":
    if sys.argv[1:2] in (["propose"], ["status"]):
        print(NOT_INSTALLED, file=sys.stderr)
        sys.exit(1)
    hook()

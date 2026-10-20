#!/usr/bin/python3 -I
"""keeper hook: the PreToolUse hook of Claude Code when the keeper is installed (replaces go-gate's own hook).

It does not decide anything itself: it forwards the raw tool call to keeperd and applies its answer. keeperd classifies
the call, so this file running as the agent's user gains nothing by lying.

If keeperd cannot be reached, it fails closed: reads still pass (judged by the same classifier, root-owned copy next to
this file), changes are refused.

The agent proposes a plan with `keeper-propose --scope "id=… ; targets=… ; actions=… ; ttl=…" --text "why"`: keeperd
answers that command in the check itself (with the session id Claude Code gave this hook), so it never runs.
"""
import importlib.util, json, os, socket, sys, time

SOCKETS = ("/opt/agent-guardrails/run/keeper.sock", "/run/keeper/keeper.sock")       # macOS, Linux (install-keeper.sh)
# Safe only because install-keeper.sh runs this file (and the keeper-propose/keeper-status wrappers) with
# `env -i`: an agent-writable .claude/settings.json `env` key or shell profile cannot set these two variables to
# point the hook at a fake socket (guarded by test_keeper.py's InstallerEnvLock).
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


STATUS_POLL_INTERVAL = 2       # how often "status" is re-asked while waiting
STATUS_ASK_TIMEOUT = 5         # per-poll socket timeout; independent of the total wait budget

# keeper-propose --wait exit codes (used by wait_for_decision's return value; see hook()'s deny() reasons for what
# the agent reads). 1 and 2 are left alone: hook() already uses 2 for "unreadable hook input".
WAIT_APPROVED, WAIT_REJECTED, WAIT_EXPIRED, WAIT_STILL_PENDING = 0, 3, 4, 5


def wait_for_decision(hash12, wait_seconds):
    """Poll keeperd's "status" op (same socket, by fingerprint only) until the plan `hash12` is decided or
    `wait_seconds` elapses. Never approves or rejects anything itself -- it only reads what decide() already
    decided on the daemon side, the same way a human re-running keeper-status would have. Raises (OSError,
    ValueError) exactly like ask() if keeperd becomes unreachable mid-wait; the caller handles that the same way
    it already handles a daemon that was down from the start."""
    deadline = time.monotonic() + max(0, wait_seconds)
    while True:
        resp = ask({"op": "status", "hash": hash12}, timeout=STATUS_ASK_TIMEOUT)
        if "state" not in resp:                                 # e.g. {"error": "bad hash"}: never guess a state
            raise ValueError(resp.get("error") or "status: no state in the daemon's reply")
        state = resp["state"]
        if state != "pending":
            return {"approved": WAIT_APPROVED, "rejected": WAIT_REJECTED,
                     "expired": WAIT_EXPIRED}.get(state, WAIT_EXPIRED), state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return WAIT_STILL_PENDING, "pending"
        time.sleep(min(STATUS_POLL_INTERVAL, remaining))


def local_kind(tool, tool_input, cwd=None):
    """Only used when keeperd is down: is this call a read? Anything unsure is a change. SAFE_GIT_REPOS stays empty
    here (no daemon config to read), so git read verbs are opaque -> refused, which is the fail-closed behaviour."""
    try:
        path = os.path.join(HERE, "go_gate.py")
        if not os.path.exists(path):
            path = os.path.join(HERE, "..", "go-gate", "go_gate.py")
        spec = importlib.util.spec_from_file_location("go_gate", path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        if gate.pipeline_stages is None:
            gate.scan, gate.pipeline_stages = gate._load_splitter()
        gate.CWD = cwd
        return gate.classify(tool, tool_input)[0]
    except Exception:
        return "change"


def observe_mode():
    """Observe install (first days): a daemon that is down must not block the agent. Read from a root-owned file
    written by the installer next to this one; anything else means block."""
    try:
        p = os.path.join(HERE, "mode")
        st = os.stat(p)
        return st.st_uid == 0 and not st.st_mode & 0o022 and open(p).read().strip() == "observe"
    except OSError:
        return False


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
    cwd = data.get("cwd")
    try:
        out = ask({"op": "check", "session": data.get("session_id"), "tool": tool, "input": ti, "cwd": cwd})
    except (OSError, ValueError) as e:
        if local_kind(tool, ti, cwd) in ("read", "talk") or observe_mode():
            sys.exit(0)
        deny(f"keeper: the keeper daemon is not reachable ({type(e).__name__}), so changes are refused. "
             "Tell the user; reads still work.")
    if out.get("decision") == "allow":
        sys.exit(0)
    wait_s, h = out.get("wait"), out.get("hash")
    if wait_s and h:
        try:
            code, state = wait_for_decision(h, wait_s)
        except (OSError, ValueError) as e:
            deny(f"keeper: plan sent to the human for approval (fingerprint {h}), but the keeper daemon became "
                 f"unreachable while waiting ({type(e).__name__}). Nothing was run; check again once it answers.")
        reason = {
            WAIT_APPROVED: f"keeper: plan {h} was approved. Nothing was run; retry the actions now.",
            WAIT_REJECTED: f"keeper: plan {h} was rejected. Nothing was run.",
            WAIT_EXPIRED: f"keeper: plan {h} expired before a decision was made. Nothing was run; propose again.",
            WAIT_STILL_PENDING: (f"keeper: still waiting for a decision on plan {h} after {wait_s}s. Nothing was "
                                  "run; check again or propose again with a longer --wait."),
        }[code]
        deny(reason)
    deny(out.get("reason") or "keeper: refused")


NOT_INSTALLED = ("keeper-propose / keeper-status are handled by the keeper hook, which answers them before they run. "
                 "If you see this, the keeper hook is not active.")

if __name__ == "__main__":
    if sys.argv[1:2] in (["propose"], ["status"]):
        print(NOT_INSTALLED, file=sys.stderr)
        sys.exit(1)
    hook()

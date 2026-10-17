"""run_probes.py: run a list of denial probes AS the identity the script is invoked under, report PASS (the
operation was refused -- good) or FAIL (it was accepted -- the restriction does not hold) per line. Standard
library only. Never prints a probed command's own stdout/stderr: even an unexpectedly-accepted probe should not
leak whatever that command printed (a directory listing, a file's content) into this tool's own output.
"""
import json
import re
import shlex
import subprocess
import sys

PLACEHOLDER_WHOLE = re.compile(r"^\{\{([A-Z_]+)\}\}$")        # a token that IS a placeholder, nothing else
PLACEHOLDER_ANY = re.compile(r"\{\{([A-Z_]+)\}\}")            # a placeholder embedded in a larger string

# Defaults so the shipped probes.json runs out of the box against obviously-fake targets; override any of these
# with a local vars file (see --vars) once you have adapted the probes to your own setup.
DEFAULT_VARS = {
    "CANARY_FILE": "/etc/oncall-probe/canary",
    "OUTSIDE_WRITE_DIR": "/etc",
    "OTHER_USER_SECRETS_DIR": "/home/other-user/.secrets",
    "NONEXISTENT_ID": "999999999",
    "HYPERVISOR_DESTROY_CMD": "pct destroy",
    "FORCED_COMMAND_KEY": "/home/oncall/.ssh/forced_command_key",
    "FORCED_COMMAND_HOST": "example-host",
    "SUDOERS_PROBE_FILE": "/etc/sudoers.d/oncall-probe-test",
}


def load_probes(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_vars(path):
    merged = dict(DEFAULT_VARS)
    if path:
        with open(path, encoding="utf-8") as f:
            merged.update(json.load(f))
    return merged


def substitute_token(token, vars_):
    """A token that IS a placeholder, in full, can expand to several argv elements if its value contains a
    space (e.g. HYPERVISOR_DESTROY_CMD="pct destroy" -> two argv tokens). A placeholder embedded inside a
    longer string (e.g. inside a `sh -c "..."` script) is a plain substring substitution instead and always
    stays one token -- expanding it there would not make sense."""
    def value_of(name):
        if name not in vars_:
            raise KeyError(f"no value configured for placeholder {{{{{name}}}}}")
        return vars_[name]

    m = PLACEHOLDER_WHOLE.match(token)
    if m:
        value = value_of(m.group(1))
        return shlex.split(value) if " " in value else [value]
    return [PLACEHOLDER_ANY.sub(lambda mo: value_of(mo.group(1)), token)]


def build_argv(command, vars_):
    argv = []
    for token in command:
        argv.extend(substitute_token(token, vars_))
    return argv


def run_probe(probe, vars_, timeout=10):
    """True if the operation was ACCEPTED (ran, exit 0) -- a FAIL for a denial probe. False (refused, missing,
    or timed out) is a PASS: in every one of those cases the restricted identity did not get to do the thing."""
    try:
        argv = build_argv(probe["command"], vars_)
    except KeyError as e:
        return None, str(e)                                   # can't even build the command: reported, not run
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
        return (r.returncode == 0), None
    except FileNotFoundError as e:
        return False, f"command not found ({e.filename}) -- treated as refused"
    except subprocess.TimeoutExpired:
        return False, "timed out -- treated as refused"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: run_probes.py PROBES.json [--vars VARS.json]", file=sys.stderr)
        return 2
    vars_path = None
    if "--vars" in argv:
        i = argv.index("--vars")
        vars_path = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    probes = load_probes(argv[0])
    vars_ = load_vars(vars_path)

    failures = 0
    for probe in probes:
        accepted, note = run_probe(probe, vars_)
        if accepted is None:
            print(f"SKIP  {probe['name']} ({note})")
            continue
        status = "FAIL" if accepted else "PASS"
        failures += 1 if accepted else 0
        suffix = f"  ({note})" if note else ""
        print(f"{status}  {probe['name']}{suffix}")
    print(f"-- {len(probes) - failures}/{len(probes)} refused as expected" + (f", {failures} FAILED" if failures
                                                                               else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

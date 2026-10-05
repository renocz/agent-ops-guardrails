# secret-guard

A [Claude Code hook](https://docs.claude.com/en/docs/claude-code/hooks) that stops an AI agent from **printing secrets by accident** in the output of the commands and file reads it runs. That output is the only thing it filters.

## Why

The rule "always mask output that may contain configuration" was written down, and the agent broke it 3 times in 2 days. Each time it was an honest mistake: a `docker inspect`, an error message carrying a URL with credentials, a `crontab -l`. The fix was to turn the rule into a technical check.

## What it does

| Tool | Behaviour |
|---|---|
| **Bash** | A command that may print secrets is refused unless its whole output, **stdout and stderr**, goes through `mask`. |
| **Read / Grep / NotebookRead** | Direct reads (and Grep in any mode) of files that typically hold secrets (`.env`, private keys, `.netrc`, cloud credentials, compose files…) are refused. A Grep in content mode whose pattern hunts for secrets (`password`, `token`, `api_key`…) is refused too; listing matching files is allowed. |

For Bash, commands such as `crontab -l`, `docker inspect`, `env`, git network commands, or reading a config file count as risky. To pass, the command must look like this:
- `cmd 2>&1 | mask`, or
- `{ cmd1; cmd2; } 2>&1 | mask` to cover several statements.

**Every** statement is checked:
- `cat .env; ls 2>&1 | mask` is refused, because only `ls` is masked;
- a `mask` that sits in a comment or a quoted string does not count.

When the output provably holds no values, for example `grep -c`, a hash, or key names only, the agent may end the command with `# secret-ok`. This is a visible claim that a reviewer can check. It only counts as the very last thing in the command.

`mask` is a small Perl filter. It redacts:
- common key formats and JWTs;
- bot tokens;
- credentials in URLs and auth headers;
- `--token`-style flags and `key=value` pairs;
- whole PEM private-key blocks.

## Install

Requirements: Python 3.9+, and Perl for `mask`. `mask` starts with `#!/usr/bin/env -S perl`; `env -S` needs coreutils 8.30+ on Linux and is built in on macOS. Elsewhere, change that line to `#!/usr/bin/perl -p`.

From a clone of this repo:

```bash
cd secret-guard
mkdir -p ~/.local/bin ~/.claude/hooks
install -m 755 mask ~/.local/bin/mask            # must be on the PATH of the shell the agent uses
install -m 755 secret_guard.py ~/.claude/hooks/secret_guard.py
printf 'password=hunter2\n' | mask              # should print: password=<m>
```

Then add the hook to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/secret_guard.py" }] },
      { "matcher": "Read|Grep|NotebookRead", "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/secret_guard.py" }] }
    ]
  }
}
```

Site-specific patterns, such as the API endpoints of your own apps that return keys, go in `~/.config/secret-guard/extra.json` as a list of `[regex, label]` pairs. That way they stay out of a shared copy.

Failure behaviour:
- a broken or invalid extras file, or any internal error, makes the hook **refuse** (fail closed);
- input that is not a valid tool call (not JSON) is let through, because there is nothing to judge.

Run the tests with `python3 -m unittest test_secret_guard.py`.

## Limits

Read these before relying on it:
- **It targets accidents, not attackers.** It assumes a cooperative agent that makes mistakes. An agent that wants to leak a secret can do it in ways no pattern list will catch.
- **It is pattern-based, so it is incomplete.** Expect both misses and false alarms, and tune them to your environment. Before this version replaced the previous one, I replayed about 5,700 real commands from my agent through both. The new one refused about 550 more, mostly real gaps (config files read without the mask, errors left outside the mask) and some over-caution. It allowed 7 the old one had wrongly refused.
- **It is not a shell parser.** It splits commands on `;`, `&&`, `||`, `&` and newlines. It understands quotes, real comments and `{ }` / `( )` groups the way Bash does. When it loses track (an unclosed quote or group), it judges the whole command as unmasked. Unusual constructs may still be misread.
- **It is conservative with heredocs.** A heredoc body may be executed (`bash -s`, `python3 -`), so it is checked like commands. A heredoc that only writes a file can be refused; group the command with `{ …; } 2>&1 | mask` instead.
- **It only sees what the agent asks to run.** It does not see what programs print by themselves later, logs written elsewhere, or other tools and MCP servers.

Pair it with least privilege: secrets in mode-600 files, never on command lines, and out of the agent's reach where possible.

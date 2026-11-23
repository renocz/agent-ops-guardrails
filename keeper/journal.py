#!/usr/bin/env python3
"""keeper journal: an append-only, hash-chained record of approval decisions (docs/design-tiered-approval.md section 6).

Not the event log (`log.jsonl`, a counter for /summary). This is the evidence: who, where, what, when, under which plan,
at which tier, with whose opinion, and the result. It lives in the keeper's state directory (mode 700), so the agent
cannot read it; the file is mode 600 and opened O_APPEND.

Each line carries `prev`, the sha256 of the previous line, so an edited, deleted-in-the-middle or reordered line is
detected by `verify()`. Known limits (also in the README): the chain does not detect truncation of the tail, and it
does not stop whoever is the keeper user or root. `chattr +a` (Linux) or `chflags sappnd` (macOS), set by root, hardens
the file against the keeper user; it is not applied by the code and not tested in CI.

Never contains a command's text. A masker cannot be exhaustive (measured 23/11/2026: 8 of 12 realistic commands kept their
secret through the keeper's own masker: `mysql -p...`, `curl -u user:pw`, `DB_PASS=...`, `sshpass -p`, `htpasswd -b`,
`openssl -k`, `--from-literal=pw=...`, `docker run -e`), so the journal keeps the shape (first word, subcommand, category),
the length, and an HMAC-SHA256 of the command under a key that only lives in the keeper's directory (a plain hash of a
short secret can be brute-forced; the HMAC cannot without the key). The HMAC still shows that two decisions concerned the
same command.

Standard library only. Python 3.9+.
"""
import hashlib, hmac, json, os, socket, threading, time

GENESIS = "0" * 64
TAIL_READ = 256 * 1024


def _sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


class Journal:
    def __init__(self, path, host=None, clock=time.time):
        self.path, self.clock = path, clock
        self.key = None
        self.need_newline = False
        self.host = host or socket.gethostname()
        self.lock = threading.Lock()
        self.ok = False                       # True only once the file is writable and the chain head is known
        self.seq, self.prev = 0, GENESIS
        self.recovered_from = None
        self._open()

    def _open(self):
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            old = os.umask(0o077)
            try:
                self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            finally:
                os.umask(old)
            self._load_key()
            self._read_head()
            self.ok = True
        except OSError:
            self.fd, self.ok = None, False

    def _load_key(self):
        """The HMAC key of the command fingerprints: 32 random bytes, 600, created once, never logged. Without a usable key
        the fingerprint is simply left out (never replaced by a plain hash)."""
        kp = os.path.join(os.path.dirname(self.path), "journal.key")
        try:
            fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, os.urandom(32))
            finally:
                os.close(fd)
        except FileExistsError:
            pass
        with open(kp, "rb") as f:
            key = f.read()
        self.key = key if len(key) >= 32 else None

    def fingerprint(self, cmd):
        if cmd is None or self.key is None:
            return None
        return hmac.new(self.key, str(cmd).encode("utf-8", "replace"), hashlib.sha256).hexdigest()

    def _read_head(self):
        size = os.path.getsize(self.path)
        if not size:
            return
        with open(self.path, "rb") as f:
            f.seek(max(0, size - TAIL_READ))
            data = f.read()
        self.need_newline = not data.endswith(b"\n")          # a crash mid-write: the next record must start on its own line
        lines = [x for x in data.split(b"\n") if x.strip()]
        if not lines:
            return
        last = lines[-1]
        self.prev = _sha(last)
        for raw in reversed(lines):                       # the last line that parses gives the sequence number
            try:
                self.seq = int(json.loads(raw)["seq"])
                break
            except (ValueError, KeyError, TypeError):
                continue
        if not self._parses(last):
            self.recovered_from = _sha(last)              # a torn last line (crash mid-write): say so in the next record

    @staticmethod
    def _parses(raw):
        try:
            rec = json.loads(raw)
            return isinstance(rec, dict) and "seq" in rec
        except ValueError:
            return False

    def append(self, event, identity=None, action=None, plans=None, tier="none", opinion=None, result=None):
        """Write one record. Never raises: a failure sets `ok` to False and returns False (the caller's decision stands)."""
        if self.fd is None:
            self._open()
            if self.fd is None:
                return False
        with self.lock:
            try:
                now = self.clock()
                act = dict(action or {})
                cmd = act.pop("cmd", None)
                if cmd is not None:                       # the text itself is never written, only its HMAC and length
                    act["cmd_hmac"] = self.fingerprint(cmd)
                    act["cmd_len"] = len(str(cmd))
                rec = {"seq": self.seq + 1, "prev": self.prev, "event": event,
                       "at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
                       "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), "host": self.host,
                       "identity": identity or {}, "action": act, "plans": list(plans or []), "tier": tier,
                       "opinion": opinion or {"kind": "none"}, "result": result}
                if self.recovered_from:
                    rec["recovered_torn_line"] = self.recovered_from
                line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                os.write(self.fd, (("\n" if self.need_newline else "") + line + "\n").encode("ascii"))
                os.fsync(self.fd)
            except (OSError, ValueError, TypeError):
                self.ok = False
                return False
            self.seq, self.prev, self.recovered_from, self.ok, self.need_newline = rec["seq"], _sha(line), None, True, False
            return True


def verify(path):
    """(True, n_records, None) or (False, n_records_ok, 'reason at line N'). Reads the whole file. A torn line (a crash
    mid-write) is accepted only when the next record says it recovered from exactly that line."""
    prev, n, torn = GENESIS, 0, None
    try:
        with open(path, "rb") as f:
            for i, raw in enumerate(f, 1):
                raw = raw.rstrip(b"\n")
                if not raw.strip():
                    return False, n, f"empty line {i}"
                try:
                    rec = json.loads(raw)
                    if not isinstance(rec, dict):
                        raise ValueError
                except ValueError:
                    if torn:
                        return False, n, f"line {i} is not valid JSON"
                    torn = (i, _sha(raw))
                    prev = torn[1]
                    continue
                if rec.get("seq") != n + 1:
                    return False, n, f"line {i}: sequence break (expected {n + 1})"
                if rec.get("prev") != prev:
                    return False, n, f"line {i}: chain break (the previous line was changed, removed or reordered)"
                if torn and rec.get("recovered_torn_line") != torn[1]:
                    return False, n, f"line {torn[0]} is not valid JSON"
                torn = None
                prev, n = _sha(raw), n + 1
    except OSError as e:
        return False, n, f"cannot read the journal ({type(e).__name__})"
    if torn:
        return False, n, f"line {torn[0]} is torn (the keeper stopped mid-write; the next start records the recovery)"
    return True, n, None

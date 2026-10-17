"""Snapshot naming: the strict pattern everything else keys off. Standard library only.

A snapshot's name is `<prefix>-YYYYMMDD-HHMMSS`, and its qualified identifier (what a backend's listing returns)
is `<dataset>@<prefix>-YYYYMMDD-HHMMSS` for ZFS-style backends, or just the name for one that has no separate
dataset notion. The timestamp is the single source of truth for a snapshot's age: nothing here calls back into
the backend for a separate creation time, so there's one less place (and one less unit, filesystem mtime vs
backend metadata) for a mismatch to hide in.
"""
import datetime
import re

_TS = r"\d{8}-\d{6}"
_TS_FMT = "%Y%m%d-%H%M%S"


def name_pattern(prefix):
    """Matches a bare snapshot name, no dataset: `<prefix>-YYYYMMDD-HHMMSS`, nothing more, nothing less."""
    return re.compile(r"^" + re.escape(prefix) + r"-(" + _TS + r")$")


def qualified_pattern(dataset, prefix):
    """Matches a full `<dataset>@<prefix>-YYYYMMDD-HHMMSS`. The dataset is matched in full, not as a string
    prefix: `pool/agent-other` and `pool/agent/child` must never match when the configured dataset is
    `pool/agent`, however a listing was gathered (including a recursive one that widened it to child
    datasets) -- re.escape() plus anchoring with ^...$ makes the dataset portion an exact match, character for
    character, not merely a shared prefix."""
    return re.compile(r"^" + re.escape(dataset) + r"@" + re.escape(prefix) + r"-(" + _TS + r")$")


def new_name(prefix, when=None):
    when = when or datetime.datetime.now(datetime.timezone.utc)
    return f"{prefix}-{when.strftime(_TS_FMT)}"


def parse_timestamp(match):
    """`match`: a re.Match from name_pattern()/qualified_pattern(). Returns the embedded UTC datetime."""
    return datetime.datetime.strptime(match.group(1), _TS_FMT).replace(tzinfo=datetime.timezone.utc)


def age_minutes(match, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return (now - parse_timestamp(match)).total_seconds() / 60


def age_days(match, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return (now - parse_timestamp(match)).total_seconds() / 86400

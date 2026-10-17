#!/usr/bin/env python3
"""new-record.py: create the next numbered change record in a directory, and regenerate its index.

    new-record.py RECORDS_DIR --title "upgrade the example service to 2.4"
    new-record.py RECORDS_DIR --title "..." --requester alice --risk medium --go "chat, 2026-10-17" \
                   --items "example-service,example-db" --links "https://example.invalid/ticket/1"

Standard library only. Never overwrites an existing record: if the computed id already has a file, it refuses
and exits non-zero, so a stray pre-existing file (a race, a manual copy) is never silently clobbered.
"""
import argparse
import datetime
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "templates", "change-record.md")
ID_RE = re.compile(r"^(\d{4})-.*\.md$")


def slugify(title):
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s or "untitled"


def existing_ids(records_dir):
    ids = []
    for name in os.listdir(records_dir):
        m = ID_RE.match(name)
        if m:
            ids.append(int(m.group(1)))
    return ids


def next_id(records_dir):
    ids = existing_ids(records_dir)
    return (max(ids) + 1) if ids else 1


def body_template():
    with open(TEMPLATE, encoding="utf-8") as f:
        text = f.read()
    parts = text.split("---\n")
    if len(parts) < 3:
        raise SystemExit(f"malformed template (expected two '---' front-matter delimiters): {TEMPLATE}")
    return "---\n".join(parts[2:])                           # everything after the closing '---'


def yaml_str(value):
    return '"' + str(value).replace('"', '\\"') + '"'


def yaml_list(items):
    if not items:
        return " []"
    return "\n" + "\n".join(f'  - "{i}"' for i in items)


def render(record_id, args):
    front = (
        "---\n"
        f"id: {yaml_str(f'{record_id:04d}')}\n"
        f"title: {yaml_str(args.title)}\n"
        f"date: {yaml_str(args.date)}\n"
        f"status: {yaml_str(args.status)}\n"
        f"requester: {yaml_str(args.requester or '<unfilled>')}\n"
        f"go: {yaml_str(args.go or '<unfilled>')}\n"
        f"risk: {yaml_str(args.risk)}\n"
        f"items:{yaml_list(args.items)}\n"
        f"links:{yaml_list(args.links)}\n"
        f"evidence:{yaml_list(args.evidence)}\n"
        "---\n"
    )
    return front + body_template()


def write_index(records_dir):
    """Regenerate index.md: every <id>-*.md record, sorted by id, with its title/date/status."""
    rows = []
    for name in sorted(os.listdir(records_dir)):
        if not ID_RE.match(name) or name == "index.md":
            continue
        with open(os.path.join(records_dir, name), encoding="utf-8") as f:
            text = f.read()
        title_m = re.search(r'^title: *"(.*)"', text, re.MULTILINE)
        date_m = re.search(r'^date: *"(.*)"', text, re.MULTILINE)
        status_m = re.search(r'^status: *"(.*)"', text, re.MULTILINE)
        id_m = re.search(r'^id: *"(.*)"', text, re.MULTILINE)
        rows.append((id_m.group(1) if id_m else name[:4], title_m.group(1) if title_m else "",
                     date_m.group(1) if date_m else "", status_m.group(1) if status_m else "", name))
    rows.sort(key=lambda r: r[0])
    lines = ["# Change records\n", "\n", "| id | title | date | status |\n", "|---|---|---|---|\n"]
    for rec_id, title, date, status, name in rows:
        lines.append(f"| {rec_id} | [{title}]({name}) | {date} | {status} |\n")
    with open(os.path.join(records_dir, "index.md"), "w", encoding="utf-8") as f:
        f.writelines(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("records_dir")
    p.add_argument("--title", required=True)
    p.add_argument("--date", default=datetime.date.today().isoformat())
    p.add_argument("--status", default="proposed", choices=["proposed", "approved", "done", "rolled-back"])
    p.add_argument("--requester", default="")
    p.add_argument("--go", default="")
    p.add_argument("--risk", default="low", choices=["low", "medium", "high"])
    p.add_argument("--items", default="", help="comma-separated")
    p.add_argument("--links", default="", help="comma-separated")
    p.add_argument("--evidence", default="", help="comma-separated")
    p.add_argument("--id", type=int, default=None, help="use this id instead of auto-incrementing (still refuses "
                                                          "if a file with that id already exists)")
    args = p.parse_args(argv)
    for attr in ("items", "links", "evidence"):
        setattr(args, attr, [x.strip() for x in getattr(args, attr).split(",") if x.strip()])

    os.makedirs(args.records_dir, exist_ok=True)
    record_id = args.id if args.id is not None else next_id(args.records_dir)
    filename = f"{record_id:04d}-{slugify(args.title)}.md"
    path = os.path.join(args.records_dir, filename)
    # Refuse on a used id even if the slug differs (two records must never share a number), and on the exact
    # path as a second, independent check.
    if record_id in existing_ids(args.records_dir) or os.path.exists(path):
        print(f"refusing to overwrite existing record: id {record_id:04d} is already used in {args.records_dir}",
              file=sys.stderr)
        return 1

    with open(path, "w", encoding="utf-8") as f:
        f.write(render(record_id, args))
    write_index(args.records_dir)
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

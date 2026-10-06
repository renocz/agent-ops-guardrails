#!/usr/bin/env python3
"""Score secret-guard on a test set it was never tuned on.

The cases in blind/ were written by another model from a description of the stack and of the hook's contract, without
seeing this code or its tests. Expected answers are the generator's, not ours. Run, publish the score, and only then fix.

Usage: python3 blind_eval.py blind/2026-10-06-gemini.json [--show]   (--show prints the misses, through `| mask`)
"""
import importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("secret_guard", os.path.join(HERE, "secret_guard.py"))
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)

data = json.load(open(sys.argv[1], encoding="utf-8"))
rows = []
for c in data["cases"]:
    tool = c["tool"]
    ti = {"command": c["input"]} if tool == "Bash" else {"file_path": c["input"]}
    got = "REFUSE" if sg.decide({"tool_name": tool, "tool_input": ti}) else "ALLOW"
    rows.append((c, got))

ok = sum(c["expected"] == got for c, got in rows)
missed = [(c, g) for c, g in rows if c["expected"] == "REFUSE" and g == "ALLOW"]      # a secret could leak
extra = [(c, g) for c, g in rows if c["expected"] == "ALLOW" and g == "REFUSE"]       # friction only
print(f"generator: {data['generator']}, {data['date']}")
print(f"agree: {ok}/{len(rows)} ({100 * ok / len(rows):.0f}%)")
print(f"expected REFUSE but allowed (possible leaks): {len(missed)}")
print(f"expected ALLOW but refused (friction): {len(extra)}")
if "--show" in sys.argv:
    for title, items in (("possible leaks", missed), ("friction", extra)):
        print(f"\n## {title}")
        for c, _g in items:
            print(f"- [{c['tool']}] {c['input']}  -- {c['why']}")

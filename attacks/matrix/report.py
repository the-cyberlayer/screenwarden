"""Summarise a matrix run as Markdown.

    python -m attacks.matrix.report results/matrix/matrix-*.jsonl > results/matrix/REPORT.md

Later files win: a case re-run after an invalid run replaces the earlier row.
"""

from __future__ import annotations

import json
import sys


def yes(value) -> str:
    return {True: "yes", False: "no", None: "-"}.get(value, str(value))


def main(paths: list[str]) -> None:
    by_id: dict[str, dict] = {}
    for path in sorted(paths):
        for line in open(path, encoding="utf-8"):
            row = json.loads(line)
            by_id[row["id"]] = row
    rows = list(by_id.values())
    valid = [r for r in rows if "error" not in r and r["page_loaded"] and r["visible_text_kept"]]
    invalid = [r["id"] for r in rows if r not in valid]
    attacks = [r for r in valid if r["kind"] == "attack"]
    normal = [r for r in valid if r["kind"] == "normal"]

    reached = [r for r in attacks if r["reaches_agent_unguarded"]]
    cleaned = [r for r in reached if not r["reaches_agent_guarded"]]
    acting = [r for r in attacks if r.get("verdict")]
    stopped = [r for r in acting if r["verdict"] != "ALLOW"]
    print("# Attack matrix\n")
    print(f"{len(rows)} pages, {len(valid)} valid runs. Every page opened in Chrome on an "
          f"Android 15 emulator. No model involved: the runner measures the guard itself.\n")
    print(f"- Planted instruction reached the agent without the guard: "
          f"{len(reached)} of {len(attacks)} attack pages")
    print(f"- Removed by the guard before the agent saw it: {len(cleaned)} of {len(reached)}")
    print(f"- Hijacked action stopped (BLOCK or ASK_HUMAN): {len(stopped)} of {len(acting)}")
    false_alarms = [r for r in normal if r.get("verdict") not in (None, "ALLOW")
                    or r["instructions_removed"]]
    print(f"- Normal pages with a false alarm: {len(false_alarms)} of {len(normal)}\n")
    if invalid:
        print(f"Invalid runs (page did not load or screenshot unusable): {', '.join(invalid)}\n")

    print("## Attack pages\n")
    print("| Page | OWASP | Technique | Reaches agent, guard off | Reaches agent, guard on "
          "| Hijacked action | Verdict | Rule |")
    print("|---|---|---|---|---|---|---|---|")
    for r in attacks:
        print(f"| {r['id']} | {r['owasp']} | {r['technique']} | "
              f"{yes(r['reaches_agent_unguarded'])} | {yes(r['reaches_agent_guarded'])} | "
              f"{r.get('action') or 'none (words only)'} | {r.get('verdict', '-')} | "
              f"{r.get('rule') or '-'} |")
    print("\n## Normal pages\n")
    print("| Page | Text removed as instruction | Screen flags | Action asked by user | Verdict "
          "| Rule |")
    print("|---|---|---|---|---|---|")
    for r in normal:
        print(f"| {r['id']} | {r['instructions_removed']} | {', '.join(r['screen_flags']) or '-'}"
              f" | {r.get('action') or '-'} | {r.get('verdict', '-')} | {r.get('rule') or '-'} |")


if __name__ == "__main__":
    main(sys.argv[1:])

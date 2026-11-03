"""Run the attack matrix on a real emulator and measure the guard on every page.

    python -m attacks.matrix.make && python -m attacks.matrix.run [--only ID_PREFIX]

No model is involved. For each page the runner does what any agent's first step does:
opens the URL from the user's goal. It then reads the screen and asks:
  1. Without the guard, would the planted instruction reach the agent? (raw UI tree)
  2. With the guard, does it still reach the agent? (cleaned screen)
  3. Would the guard let the hijacked action through?
A run is valid only if the page's ordinary text survived cleaning. A broken screenshot
can make every line look invisible, which would fake a perfect result.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from screenwarden import Guard
from screenwarden.device import AdbError, Device

HERE = Path(__file__).parent
ROOT = HERE.parent  # attacks/, served at port 8000
OUT = HERE.parent.parent / "results" / "matrix"
CHROME = "com.android.chrome"


def marker(text: str) -> str:
    """A slice of the planted text that only the planted text contains."""
    return text[:40]


def capture(device: Device, wait: float) -> tuple[str, str, bytes | None]:
    time.sleep(wait)
    for attempt in range(3):  # dumps fail now and then on a loaded emulator
        try:
            xml = device.dump_ui()
            break
        except AdbError:
            if attempt == 2:
                raise
            time.sleep(5)
    try:
        png = device.screenshot()
    except AdbError:
        png = None
    return xml, device.foreground(), png


def resolve(action: dict | None, screen) -> dict | None:
    if not action or action.get("target") != "password":
        return action
    field = next((e for e in screen.elements if e.password), None)
    return {**action, "target": field.id if field else None}


def run_case(device: Device, case: dict, first_line: str, log: Path, wait: float) -> dict:
    device.open_url(case["url"])
    page = case["url"].rsplit("/", 1)[-1]
    for _ in range(5):  # wait until this page, not the previous one, is on screen
        xml, package, png = capture(device, wait)
        if first_line in xml and page in xml:
            break
    guard = Guard(case["goal"], log_path=log, model="none (matrix runner)")
    screen = guard.observe(xml, package, png)
    visible_kept = first_line in screen.text
    row = {"id": case["id"], "kind": case["kind"], "owasp": case["owasp"],
           "attacker_goal": case["attacker_goal"], "technique": case["technique"],
           "page_loaded": first_line in xml, "visible_text_kept": visible_kept,
           "screen_flags": sorted(screen.flags),
           "instructions_removed": len(screen.instructions),
           "warnings": sorted({w.code for w in screen.warnings})}
    if case["planted"]:
        m = marker(case["planted"])
        row["reaches_agent_unguarded"] = m in xml
        row["reaches_agent_guarded"] = m in screen.text
    if case["later_screen"]:  # the attack must survive into a later, unrelated screen
        device.key("KEYCODE_HOME")
        xml2, package2, png2 = capture(device, 2)
        guard.observe(xml2, package2, png2)
    action = resolve(case["action"], screen)
    if action:
        decision = guard.check(action)
        row.update(action=action["type"], verdict=decision.verdict.value,
                   rule=decision.rule, reason_owasp=decision.owasp)
    return row


def first_visible_line(case_id: str) -> str:
    html = (HERE / "pages" / f"{case_id}.html").read_text(encoding="utf-8")
    start = html.index("<h1>") + 4
    return html[start:html.index("</h1>", start)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--ids", default="", help="comma-separated case ids to re-run")
    parser.add_argument("--wait", type=float, default=6)
    args = parser.parse_args()
    ids = set(filter(None, args.ids.split(",")))
    cases = [c for c in json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
             if c["id"].startswith(args.only) and (not ids or c["id"] in ids)]
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    rows_path, log = OUT / f"matrix-{stamp}.jsonl", OUT / f"decisions-{stamp}.jsonl"
    device = Device()
    device.run("reverse", "tcp:8000", "tcp:8000")
    server = subprocess.Popen([sys.executable, "-m", "http.server", "8000", "--bind",
                               "127.0.0.1"], cwd=ROOT, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        for i, case in enumerate(cases, 1):
            try:
                row = run_case(device, case, first_visible_line(case["id"]), log, args.wait)
            except AdbError as exc:
                row = {"id": case["id"], "error": str(exc)[:200]}
            with rows_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            print(f"[{i}/{len(cases)}] {json.dumps(row)}", flush=True)
            device.key("KEYCODE_HOME")
    finally:
        server.terminate()
    print(f"Rows: {rows_path}")


if __name__ == "__main__":
    main()

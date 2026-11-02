"""Phone agent loop: dump UI, ask the LLM, act. Usage: python -m reference_agent --goal "..." """

from __future__ import annotations

import argparse
import json
import sys
import time

from . import ui
from .adb import Device
from .llm import get_llm
from screenwarden.decision_log import write_decision
from screenwarden.policy import load_policy

SYSTEM = """You operate an Android phone for the user. Each turn you get the user's goal, \
the actions so far, and the elements on the current screen. Reply with one JSON object only:
{"thought": "<brief>", "type": "<action>", ...}

Actions:
{"type": "tap", "target": <element id>}
{"type": "type", "target": <element id>, "text": "..."}  (taps the field, then types)
{"type": "send_sms", "recipient": "+44...", "text": "..."}
{"type": "open_url", "url": "..."}
{"type": "open_app", "package": "com.android.chrome"}
{"type": "scroll", "direction": "down"|"up"}
{"type": "back"} {"type": "home"} {"type": "wait"}
{"type": "done", "text": "<result for the user>"}

Package names: Messages is com.google.android.apps.messaging, Chrome is com.android.chrome."""


def describe(action: dict) -> str:
    return json.dumps({k: v for k, v in action.items() if k != "thought"}, ensure_ascii=False)


def execute(device: Device, action: dict, nodes: list) -> str:
    kind = action.get("type")
    node = next((n for n in nodes if n.id == action.get("target")), None)
    if kind in ("tap", "type") and node is None:
        return f"error: no element {action.get('target')}"
    if kind == "tap":
        device.tap(*node.center)
    elif kind == "type":
        device.tap(*node.center)
        time.sleep(1)
        device.type_text(action.get("text", ""))
    elif kind == "send_sms":
        device.compose_sms(action.get("recipient", ""), action.get("text", ""))
        time.sleep(3)
        send = next((n for n in ui.parse(device.dump_ui()) if n.label.lower().startswith("send")),
                    None)
        if send is None:
            return "error: send button not found"
        device.tap(*send.center)
    elif kind == "open_url":
        device.open_url(action.get("url", ""))
    elif kind == "open_app":
        device.open_app(action.get("package", ""))
    elif kind == "scroll":
        down = action.get("direction", "down") == "down"
        device.swipe(540, 1800 if down else 600, 540, 600 if down else 1800)
    elif kind == "back":
        device.key("KEYCODE_BACK")
    elif kind == "home":
        device.key("KEYCODE_HOME")
    elif kind == "wait":
        time.sleep(2)
    else:
        return f"error: unknown action {kind!r}"
    return "ok"


def approve(decision) -> bool:
    if not sys.stdin.isatty():
        return False
    return input(f"  Allow? {decision.reason} [y/N] ").strip().lower() == "y"


def run(args: argparse.Namespace) -> int:
    device = Device(args.device)
    llm = get_llm()
    policy = load_policy()
    guard = None
    if args.guard == "on":
        from screenwarden import Guard
        guard = Guard(args.goal, policy=policy, log_path=args.log, model=llm.model)
    print(f"Goal: {args.goal}\nGuard: {args.guard}")

    history: list[str] = []
    blocked_in_a_row = 0
    for step in range(1, args.max_steps + 1):
        xml = device.dump_ui()
        foreground = device.foreground()
        if guard:
            screen = guard.observe(xml, foreground, device.screenshot())
            nodes, view = screen.elements, screen.text
            for warning in screen.warnings:
                if warning.severity == "high":
                    print(f"  ScreenWarden sanitize: {warning.code} [{warning.owasp}] "
                          f"{warning.text[:90]!r}")
        else:
            nodes = ui.parse(xml)
            view = ui.render(nodes)

        prompt = (f"Goal: {args.goal}\n\nActions so far:\n" + ("\n".join(history) or "none")
                  + f"\n\nForeground app: {foreground}\nScreen:\n{view}")
        action = llm.next_action(SYSTEM, prompt, nodes)
        write_decision({"event": "agent_step", "model": llm.model, "guard": args.guard,
                        "step": step, "goal": args.goal, "action": action}, policy, args.log)
        if guard:
            guard.model = llm.model
        print(f"[{step}] {describe(action)}")
        if action.get("thought"):
            print(f"    thought: {action['thought']}")

        if guard:
            decision = guard.check(action)
            if not decision.allowed:
                tag = f" [{decision.owasp}]" if decision.owasp else ""
                print(f"  ScreenWarden {decision.verdict.value}{tag} {decision.rule}: "
                      f"{decision.reason}")
                if not (decision.verdict.value == "ASK_HUMAN" and approve(decision)):
                    history.append(f"{describe(action)} -> refused: {decision.reason}")
                    blocked_in_a_row += 1
                    if blocked_in_a_row >= args.max_blocks:
                        print("Stopping: too many refused actions")
                        return 3
                    continue
            blocked_in_a_row = 0

        if action.get("type") == "done":
            print(f"Done: {action.get('text', '')}")
            return 0
        result = execute(device, action, nodes)
        if result != "ok":
            print(f"    {result}")
        history.append(f"{describe(action)} -> {result}")
        time.sleep(args.settle)
    print("Stopping: step limit reached")
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(prog="reference_agent", description=__doc__)
    parser.add_argument("--goal", required=True)
    parser.add_argument("--guard", choices=["on", "off"], default="on")
    parser.add_argument("--device", help="adb serial, default $ANDROID_SERIAL")
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--max-blocks", type=int, default=3)
    parser.add_argument("--settle", type=float, default=2.0, help="seconds to wait after acting")
    parser.add_argument("--log", help="decision log path")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

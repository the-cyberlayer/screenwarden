"""MCP server: guarded Android phone control for any MCP client.

    python -m screenwarden.mcp_server [--goal "..."] [--learn] [--log decisions.jsonl]

The client (Claude Desktop, Claude Code, Cursor, ...) gets phone tools. Every screen it
reads is cleaned first, and every action is checked against the user's goal before adb
runs it. Refused actions are not run; the reason and OWASP tag come back as a tool error.

The goal is fixed before the agent reads anything: from --goal, or from the first
start_task call, which is refused once a screen has been read. Text on the phone can
therefore never set or change the goal. ASK_HUMAN is refused, because a tool cannot tell
whether a person answered; the client should ask the user to do that step themselves.

With --learn, screens of apps the policy does not know are labelled by Claude
(ANTHROPIC_API_KEY, model from $SCREENWARDEN_PROFILE_MODEL). Only the screen's structure
is sent, never its text. Without --learn the server makes no network calls.
Speaks MCP over stdio (JSON-RPC 2.0, one message per line). No dependencies beyond pyyaml.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Callable

from .decision_log import write_decision
from .device import AdbError, Device
from .guard import Guard
from .policy import load_policy

PROTOCOL = "2025-06-18"
VERSION = "0.1.0"


def _tool(name: str, description: str, **props: Any) -> dict:
    required = [k for k, v in props.items() if not v.pop("optional", False)]
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": props, "required": required,
                            "additionalProperties": False}}


_ID = {"type": "integer", "description": "element id from read_screen"}
_TEXT = {"type": "string"}
TOOLS = [
    _tool("start_task", "Set the user's goal for this session. Must be called before "
          "read_screen; it cannot be changed afterwards.", goal=_TEXT),
    _tool("read_screen", "Return the current screen, cleaned: instruction-like or hidden "
          "text from apps and web pages is removed and outside text is marked as data."),
    _tool("tap", "Tap an element.", element=_ID),
    _tool("type_text", "Tap a field and type text into it.", element=_ID, text=_TEXT),
    _tool("send_sms", "Send an SMS with the default messaging app.",
          recipient=_TEXT, text=_TEXT),
    _tool("open_url", "Open a URL.", url=_TEXT),
    _tool("open_app", "Open an app by package name.", package=_TEXT),
    _tool("scroll", "Scroll the screen.",
          direction={"type": "string", "enum": ["up", "down"], "optional": True}),
    _tool("back", "Press Back."),
    _tool("home", "Press Home."),
]


class ToolError(Exception):
    pass


class PhoneSession:
    """One user goal, one Guard, one phone."""

    def __init__(self, device: Any, goal: str | None = None, log_path=None,
                 guard_factory: Callable[[str], Guard] | None = None):
        self.device = device
        self.log_path = log_path
        self.policy = load_policy()
        self.guard_factory = guard_factory or (
            lambda g: Guard(g, policy=self.policy, log_path=log_path, model="mcp-client"))
        self.guard: Guard | None = self.guard_factory(goal) if goal else None
        self.read_once = False

    # tools --------------------------------------------------------------------------

    def start_task(self, goal: str) -> str:
        if self.read_once:
            raise ToolError("The goal is fixed once a screen has been read; restart the "
                            "server for a new task.")
        if not goal.strip():
            raise ToolError("Empty goal.")
        self.guard = self.guard_factory(goal.strip())
        return f"Goal set: {goal.strip()}"

    def read_screen(self) -> str:
        guard = self._guard()
        self.read_once = True
        screen = guard.observe(self.device.dump_ui(), self.device.foreground(),
                               self._screenshot())
        notes = [f"- {w.code} [{w.owasp}]" for w in screen.warnings if w.severity == "high"]
        head = f"Foreground app: {screen.foreground}"
        if notes:
            head += "\nScreenWarden removed or flagged:\n" + "\n".join(sorted(set(notes)))
        return f"{head}\n\n{screen.text}"

    def act(self, name: str, args: dict) -> str:
        guard = self._guard()
        if not self.read_once and name in ("tap", "type_text"):
            raise ToolError("Call read_screen first: element ids come from it.")
        action = self._action(name, args)
        decision = guard.check(action)
        if not decision.allowed:
            tag = f" [{decision.owasp}]" if decision.owasp else ""
            hint = (" Ask the user to do this step themselves if they want it."
                    if decision.verdict.value == "ASK_HUMAN" else "")
            raise ToolError(f"ScreenWarden {decision.verdict.value}{tag} {decision.rule}: "
                            f"{decision.reason}.{hint}")
        try:
            return self._run(action)
        except AdbError as exc:
            raise ToolError(f"adb failed: {exc}") from exc

    # helpers ------------------------------------------------------------------------

    def _guard(self) -> Guard:
        if self.guard is None:
            raise ToolError("Call start_task with the user's goal first.")
        return self.guard

    def _screenshot(self) -> bytes | None:
        try:
            return self.device.screenshot()
        except Exception:
            return None

    def _action(self, name: str, args: dict) -> dict:
        if name == "tap":
            return {"type": "tap", "target": args["element"]}
        if name == "type_text":
            return {"type": "type", "target": args["element"], "text": args["text"]}
        if name == "send_sms":
            return {"type": "send_sms", "recipient": args["recipient"], "text": args["text"]}
        if name == "open_url":
            return {"type": "open_url", "url": args["url"]}
        if name == "open_app":
            return {"type": "open_app", "package": args["package"]}
        if name == "scroll":
            return {"type": "scroll", "direction": args.get("direction", "down")}
        return {"type": name}

    def _element(self, action: dict):
        element = self.guard.screen.element(action["target"])
        if element is None:
            raise ToolError(f"No element {action['target']} on the last screen read.")
        return element

    def _run(self, action: dict) -> str:
        d, kind = self.device, action["type"]
        if kind == "tap":
            d.tap(*self._element(action).center)
        elif kind == "type":
            d.tap(*self._element(action).center)
            time.sleep(1)
            d.type_text(action["text"])
        elif kind == "send_sms":
            d.compose_sms(action["recipient"], action["text"])
            for _ in range(5):
                time.sleep(3)
                screen = self.guard.observe(d.dump_ui(), d.foreground())
                send = next((e for e in screen.elements
                             if e.label.lower().startswith("send")), None)
                if send:
                    d.tap(*send.center)
                    break
            else:
                raise ToolError("Send button not found; the message was not sent.")
        elif kind == "open_url":
            d.open_url(action["url"])
        elif kind == "open_app":
            d.open_app(action["package"])
        elif kind == "scroll":
            down = action["direction"] == "down"
            d.swipe(540, 1800 if down else 600, 540, 600 if down else 1800)
        elif kind == "back":
            d.key("KEYCODE_BACK")
        elif kind == "home":
            d.key("KEYCODE_HOME")
        return "ok: read_screen to see the result"

    def call(self, name: str, args: dict) -> str:
        if name == "start_task":
            return self.start_task(str(args.get("goal", "")))
        if name == "read_screen":
            return self.read_screen()
        if name in {t["name"] for t in TOOLS}:
            return self.act(name, args)
        raise ToolError(f"Unknown tool {name!r}")


class Server:
    def __init__(self, session: PhoneSession):
        self.session = session

    def handle(self, message: dict) -> dict | None:
        method, mid = message.get("method"), message.get("id")
        if mid is None:  # notification
            return None
        try:
            result = self._dispatch(method, message.get("params") or {})
        except KeyError as exc:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": f"missing parameter {exc}"}}
        if result is None:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"unknown method {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _dispatch(self, method: str, params: dict) -> dict | None:
        if method == "initialize":
            return {"protocolVersion": params.get("protocolVersion", PROTOCOL),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "screenwarden", "version": VERSION}}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            name, args = params["name"], params.get("arguments") or {}
            try:
                text, error = self.session.call(name, args), False
            except ToolError as exc:
                text, error = str(exc), True
            except KeyError as exc:
                text, error = f"Missing argument {exc}", True
            except Exception as exc:  # fail closed: report, never act
                text, error = f"ScreenWarden error: {exc!r}", True
            write_decision({"event": "mcp_tool", "model": "mcp-client", "tool": name,
                            "error": error}, self.session.policy, self.session.log_path)
            return {"content": [{"type": "text", "text": text}], "isError": error}
        return None

    def serve(self, stdin=sys.stdin, stdout=sys.stdout) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                reply = self.handle(json.loads(line))
            except json.JSONDecodeError:
                reply = {"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32700, "message": "parse error"}}
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(prog="screenwarden.mcp_server", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--goal", help="the user's goal; otherwise set by start_task")
    parser.add_argument("--device", help="adb serial, default $ANDROID_SERIAL")
    parser.add_argument("--log", help="decision log path (JSON lines)")
    parser.add_argument("--learn", action="store_true",
                        help="label unknown app screens with Claude; needs ANTHROPIC_API_KEY")
    args = parser.parse_args()
    factory = None
    if args.learn:
        from .profiler import ClaudeProfiler, ProfileGuard

        profiler = ClaudeProfiler()
        factory = lambda g: ProfileGuard(g, log_path=args.log, model="mcp-client",  # noqa: E731
                                         profiler=profiler)
    session = PhoneSession(Device(args.device), args.goal, args.log, factory)
    Server(session).serve()


if __name__ == "__main__":
    main()

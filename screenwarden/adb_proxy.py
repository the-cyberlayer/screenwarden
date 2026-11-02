"""adb proxy: enforce the policy below the agent, for every agent on the phone.

Agents point at the proxy instead of the adb server:

    python -m screenwarden.adb_proxy --goal "Read my messages" --listen 5038
    ANDROID_ADB_SERVER_PORT=5038 adb shell input tap 100 200

It reads the adb host protocol, turns device commands into actions and refuses what
the policy does not allow. It learns the screen from the UI dumps agents read, and
there is no human to ask here, so ASK_HUMAN is refused. Anything it cannot classify
is refused too. An agent that can still reach the real adb server bypasses it.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import shlex

from .profiler import ClaudeProfiler, ProfileGuard
from .session import SharedSession
from .types import Decision, Element, Verdict

_READ_ONLY = {"uiautomator", "screencap", "dumpsys", "getprop", "sleep", "grep", "wm"}
_OPERATORS = set("();<>&")
_DUMP = re.compile(r"\A(?:cat )?/sdcard/[\w.-]+\.xml\Z")
_XML = re.compile(rb"<\?xml.*</hierarchy>", re.DOTALL)


def _tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _option(argv: list[str], name: str, width: int = 1) -> str | None:
    if name not in argv:
        return None
    index = argv.index(name) + width
    return argv[index] if index < len(argv) else None


def _input_action(argv: list[str]) -> dict:
    verb = argv[1] if len(argv) > 1 else ""
    if verb == "tap" and len(argv) == 4:
        return {"type": "tap", "xy": (int(argv[2]), int(argv[3]))}
    if verb == "text" and len(argv) == 3:
        return {"type": "type", "text": re.sub(r"\\(.)", r"\1", argv[2]).replace("%s", " ")}
    if verb == "swipe":
        return {"type": "swipe"}
    if verb == "keyevent" and len(argv) == 3:
        known = {"KEYCODE_BACK": "back", "KEYCODE_HOME": "home"}
        return {"type": known.get(argv[2], "key")}
    return {"type": "shell:input"}


def _am_action(argv: list[str]) -> dict:
    data = _option(argv, "-d")
    if data and data.lower().startswith(("sms:", "smsto:", "mms:", "mmsto:")):
        return {"type": "send_sms", "recipient": data.split(":", 1)[1],
                "text": _option(argv, "sms_body") or ""}
    if data:
        return {"type": "open_url", "url": data}
    component = _option(argv, "-n")
    if component:
        return {"type": "open_app", "package": component.split("/")[0]}
    return {"type": "shell:am"}


def classify(command: str) -> dict | None:
    """Map a device shell command to an action, or None if it only reads."""
    if "`" in command or "$(" in command:
        return {"type": "shell:substitution"}
    try:
        tokens = _tokens(command)
        if any(set(t) <= _OPERATORS for t in tokens if t):
            return {"type": "shell:chain"}
        segments: list[list[str]] = [[]]
        for token in tokens:
            if token == "|":
                segments.append([])
            else:
                segments[-1].append(token)
        if not all(segments):
            return {"type": "shell:empty"}
        if all(s[0] in _READ_ONLY or _is_dump_io(s) for s in segments):
            return None
        if len(segments) > 1:
            return {"type": "shell:chain"}
        argv = segments[0]
        if argv[0] == "input":
            return _input_action(argv)
        if argv[:2] == ["am", "start"]:
            return _am_action(argv)
        if argv[0] == "monkey":
            return {"type": "open_app", "package": _option(argv, "-p") or ""}
        if argv[0] == "pm" or argv[:2] == ["cmd", "package"]:
            if "install" in " ".join(argv):
                return {"type": "install", "package": argv[-1]}
        return {"type": f"shell:{argv[0]}"}
    except ValueError:
        return {"type": "shell:unparsable"}


def _is_dump_io(argv: list[str]) -> bool:
    """The agent's own screen dump file: reading it, or clearing it first."""
    if argv[0] == "cat" and len(argv) == 2:
        return bool(_DUMP.match(argv[1]))
    return argv[:2] == ["rm", "-f"] and len(argv) == 3 and bool(_DUMP.match(argv[2]))


def _shell_command(service: str) -> str | None:
    """`shell:ls`, `shell,v2,raw:ls`, `exec:ls` -> `ls`."""
    kind, _, command = service.partition(":")
    return command if kind.split(",")[0] in ("shell", "exec") else None


class Gate:
    """Decide on device services for all connected agents."""

    def __init__(self, session: SharedSession, profiler=None):
        if profiler:
            self.guard = session.guard("adb_proxy", ProfileGuard, profiler=profiler)
        else:
            self.guard = session.guard(model="adb_proxy")
        self.field: Element | None = None  # last tapped element, the target of typing

    def _element_at(self, x: int, y: int) -> Element | None:
        hits = [e for e in self.guard.screen.elements
                if e.bounds[0] <= x < e.bounds[2] and e.bounds[1] <= y < e.bounds[3]]
        return min(hits, key=lambda e: (e.bounds[2] - e.bounds[0]) * (e.bounds[3] - e.bounds[1]),
                   default=None)

    def decide(self, service: str) -> Decision | None:
        """Return the Decision for an action, or None if the service only reads."""
        if service.startswith(("reverse:", "framebuffer:")):
            return None
        command = _shell_command(service)
        action = {"type": service.split(":")[0]} if command is None else classify(command)
        if action is None:
            return None
        xy = action.pop("xy", None)
        if xy:
            self.field = action["target"] = self._element_at(*xy)
        elif action["type"] == "type":
            action["target"] = self.field
        return self.guard.check(action)

    def refusal(self, service: str) -> str | None:
        try:
            decision = self.decide(service)
        except Exception as exc:  # fail closed
            return f"ScreenWarden: guard error {exc!r}"
        if decision is None or decision.verdict is Verdict.ALLOW:
            return None
        return f"ScreenWarden {decision.verdict.value} {decision.owasp}: {decision.reason}"

    def is_dump(self, service: str) -> bool:
        command = _shell_command(service) or ""
        return command.startswith("cat ") and bool(_DUMP.match(command))

    def observe(self, output: bytes) -> None:
        match = _XML.search(output)
        if match:
            self.guard.observe(match.group(0))


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                seen: bytearray | None = None) -> None:
    try:
        while data := await reader.read(65536):
            if seen is not None:
                seen.extend(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        if writer.can_write_eof():
            writer.write_eof()


async def _relay(client, server, seen: bytearray | None = None) -> None:
    await asyncio.gather(_pump(client[0], server[1]), _pump(server[0], client[1], seen))


async def _handle(reader, writer, gate: Gate, upstream: tuple[str, int]) -> None:
    client = (reader, writer)
    server = await asyncio.open_connection(*upstream)
    try:
        while True:
            frame = await reader.readexactly(4)
            body = await reader.readexactly(int(frame, 16))
            service = body.decode("utf-8", "replace")
            if service.startswith(("host:transport", "host:tport:")):
                server[1].write(frame + body)
                await server[1].drain()
                status = await server[0].readexactly(4)
                if status == b"OKAY" and service.startswith("host:tport:"):
                    status += await server[0].readexactly(8)
                writer.write(status)
                await writer.drain()
                if not status.startswith(b"OKAY"):
                    return await _relay(client, server)
                continue
            refusal = None if service.startswith("host") else gate.refusal(service)
            if refusal:
                print(f"refused {service[:120]!r}: {refusal}", flush=True)
                message = refusal.encode()
                writer.write(b"FAIL" + f"{len(message):04x}".encode() + message)
                await writer.drain()
                return None
            server[1].write(frame + body)
            await server[1].drain()
            seen = bytearray() if gate.is_dump(service) else None
            await _relay(client, server, seen)
            if seen:
                gate.observe(bytes(seen))
            return None
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        return None
    finally:
        for stream in (writer, server[1]):
            stream.close()


async def serve(gate: Gate, listen: int, upstream: tuple[str, int]) -> asyncio.Server:
    return await asyncio.start_server(lambda r, w: _handle(r, w, gate, upstream),
                                      "127.0.0.1", listen)


def main() -> None:
    parser = argparse.ArgumentParser(prog="screenwarden.adb_proxy", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--goal", required=True, help="the user's goal, shared by all agents")
    parser.add_argument("--listen", type=int, default=5038)
    parser.add_argument("--upstream", default="127.0.0.1:5037", help="the real adb server")
    parser.add_argument("--log", help="decision log path")
    parser.add_argument("--learn", action="store_true",
                        help="label unknown screens with Claude; needs ANTHROPIC_API_KEY")
    args = parser.parse_args()
    host, port = args.upstream.rsplit(":", 1)
    profiler = ClaudeProfiler() if args.learn else None
    gate = Gate(SharedSession(args.goal, log_path=args.log), profiler)

    async def run() -> None:
        server = await serve(gate, args.listen, (host, int(port)))
        print(f"ScreenWarden adb proxy on 127.0.0.1:{args.listen}", flush=True)
        await server.serve_forever()

    asyncio.run(run())


if __name__ == "__main__":
    main()

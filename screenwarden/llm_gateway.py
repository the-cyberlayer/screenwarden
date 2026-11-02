"""LLM gateway: guard any agent that lets you change its model URL, with no code change.

The agent talks to the gateway as if it were Ollama:

    python -m screenwarden.llm_gateway --listen 11435 --upstream http://127.0.0.1:11434
    (agent setting) Ollama URL = http://<gateway host>:11435

Tool output on its way to the model is cleaned and tainted. The model's plan on its way
back is checked, and refused whole if any step is not allowed. Nobody can be asked here,
so ASK_HUMAN is refused. Images pass through unchecked, and an agent running its model
on the device never reaches the gateway. Reading a plan needs an adapter per agent.
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .decision_log import write_decision
from .guard import Guard
from .session import SharedSession
from .types import Decision, Verdict

_PLACEHOLDER = re.compile(r"\{\{.*?\}\}|\$\{.*?\}|<<.*?>>")
_REMOVED = "[removed by ScreenWarden: instruction-like text in tool output]"
Message = dict[str, Any]


def _first_json(text: str) -> Any:
    start = text.find("{")
    end = text.rfind("}")
    return json.loads(text[start:end + 1]) if start >= 0 and end > start else None


class OpenDroid:
    """Plan format of OpenDroid (github.com/JMAN730/opendroid)."""

    READS = ("READ_", "GET_", "LIST_", "CHECK_", "SEARCH_", "RECALL_", "QUERY_", "ANALYZE_")
    SAFE = {"CHAT", "ASK_USER", "WAIT", "SCROLL", "PRESS_ENTER", "CALCULATE", "TRANSLATE",
            "DEFINE_WORD", "CONVERT_UNITS", "CURRENCY_CONVERT", "WEB_SEARCH", "SUMMARIZE_URL",
            "SET_ALARM", "SET_TIMER"}
    PAYMENTS = {"PAY_UPI", "SPLIT_BILL", "ORDER_FOOD", "ORDER_GROCERY", "BOOK_UBER", "BOOK_OLA",
                "ADD_TO_CART"}
    RECIPIENT = ("contact", "to", "recipient", "number", "phone", "group")
    BODY = ("message", "body", "text", "content")

    def is_tool_output(self, messages: list[Message]) -> bool:
        return any(m.get("role") == "system" and "Re-Evaluation Engine" in str(m.get("content"))
                   for m in messages)

    def goal(self, messages: list[Message]) -> str | None:
        users = [m for m in messages if m.get("role") == "user"]
        text = str(users[-1].get("content", "")) if users else ""
        return text if text and not text.startswith("Merge the plan") else None

    def steps(self, content: str) -> list[dict] | None:
        """Plan steps in a model reply: [] if it holds no plan, None if it cannot be read."""
        try:
            root = _first_json(content)
        except ValueError:
            root = None
        if not isinstance(root, dict):
            return None if '"action"' in content or '"steps"' in content else []
        plan = root.get("updatedPlan") or root.get("plan") or root
        if isinstance(plan, dict) and isinstance(plan.get("steps"), list):
            return [s for s in plan["steps"] if isinstance(s, dict)]
        return [root] if root.get("action") else []

    def _step(self, action: str, params: dict) -> dict:
        value = lambda keys: next((str(params[k]) for k in keys if params.get(k)), "")
        name = action.upper()
        if name in self.PAYMENTS:
            return {"type": "pay"}
        if name.startswith("INSTALL"):
            return {"type": "install", "package": value(("appName", "package", "name"))}
        if name in ("OPEN_URL", "OPEN_BROWSER"):
            return {"type": "open_url", "url": value(("url",))}
        if name.startswith(("SEND_", "MAKE_", "SOCIAL_CREATE")) or name == "CLICK_COORDINATES":
            body = value(self.BODY)
            result = {"type": "send_sms", "recipient": value(self.RECIPIENT), "text": body}
            if _PLACEHOLDER.search(body):
                result["origin"] = "untrusted"
            return result
        if name in self.SAFE or name.startswith(self.READS):
            return {"type": "read"}
        return {"type": "type", "text": " ".join(str(v) for v in params.values())}

    def actions(self, content: str) -> list[dict] | None:
        steps = self.steps(content)
        if steps is None:
            return None
        found = []
        for step in steps:
            params = step.get("params") if isinstance(step.get("params"), dict) else {}
            for name in (step.get("action"), step.get("fallback")):
                if isinstance(name, str) and name.strip():
                    found.append(self._step(name.strip(), params))
        return found

    def refusal(self, reason: str, tool_output: bool) -> str:
        text = f"ScreenWarden stopped this plan: {reason}"
        if tool_output:
            return json.dumps({"speech": text, "decision": "ABANDON"})
        return json.dumps({"action": "CHAT", "params": {"response": text}})


def clean_tool_output(text: str, guard: Guard) -> str:
    """Taint outside text, record codes in it, and drop lines that read as instructions."""
    policy = guard.policy
    kept = []
    for line in text.splitlines():
        if line.strip() and line not in guard.untrusted_text:
            guard.untrusted_text.append(line)
        if policy.matches("otp_context", line):
            guard.sensitive_codes.extend(
                v for v in policy.find("otp_value", line) if v not in guard.sensitive_codes)
        if policy.matches("instruction", line):
            if line not in guard.instructions:
                guard.instructions.append(line)
            kept.append(_REMOVED)
        else:
            kept.append(line)
    return "\n".join(kept)


class Gateway:
    def __init__(self, upstream: str, adapter: Any = None, log_path=None):
        self.upstream = upstream.rstrip("/")
        self.adapter = adapter or OpenDroid()
        self.log_path = log_path
        self.session: SharedSession | None = None
        self.guard: Guard | None = None
        self.lock = threading.Lock()

    def _start_task(self, goal: str) -> None:
        if self.session is None or self.session.user_goal != goal:
            self.session = SharedSession(goal, log_path=self.log_path)
            self.guard = self.session.guard()

    def prepare(self, request: dict) -> bool:
        """Clean the outgoing request. Return True if it carries tool output."""
        messages = request.get("messages") or []
        tool_output = self.adapter.is_tool_output(messages)
        if not tool_output:
            goal = self.adapter.goal(messages)
            if goal:
                self._start_task(goal)
        if tool_output and self.guard:
            for message in messages:
                if message.get("role") == "user" and isinstance(message.get("content"), str):
                    message["content"] = clean_tool_output(message["content"], self.guard)
        return tool_output

    def _decisions(self, content: str) -> list[Decision]:
        if self.guard is None:
            return [Decision(Verdict.BLOCK, "No user goal seen yet", None, "no_goal")]
        actions = self.adapter.actions(content)
        if actions is None:
            return [Decision(Verdict.BLOCK, "Model plan could not be read", None, "unreadable_plan")]
        return [self.guard.check(action) for action in actions]

    def review(self, content: str, model: str, tool_output: bool) -> str:
        """Return the model's reply, or a refusal if any step is not allowed."""
        if self.guard:
            self.guard.model = model
        write_decision({"event": "model_reply", "model": model, "reply": content[:2000]},
                       (self.guard.policy if self.guard else _policy()), self.log_path)
        try:
            refused = [d for d in self._decisions(content) if not d.allowed]
        except Exception as exc:  # fail closed
            refused = [Decision(Verdict.BLOCK, f"Guard error: {exc!r}", None, "internal_error")]
        if not refused:
            return content
        worst = next((d for d in refused if d.verdict is Verdict.BLOCK), refused[0])
        tag = f" [{worst.owasp}]" if worst.owasp else ""
        return self.adapter.refusal(f"{worst.reason}{tag}", tool_output)

    def chat(self, body: bytes) -> bytes:
        request = json.loads(body)
        request["stream"] = False  # a plan must be whole before it can be judged
        with self.lock:
            tool_output = self.prepare(request)
        reply = self._forward("/api/chat", json.dumps(request).encode())
        answer = json.loads(reply)
        with self.lock:
            answer["message"]["content"] = self.review(
                answer["message"]["content"], answer.get("model", ""), tool_output)
        return json.dumps(answer).encode()

    def _forward(self, path: str, body: bytes | None) -> bytes:
        request = urllib.request.Request(f"{self.upstream}{path}", body,
                                         {"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=600) as reply:
            return reply.read()

    def passthrough(self, path: str, body: bytes | None) -> bytes:
        return self._forward(path, body)


def _policy():
    from .policy import load_policy

    return load_policy()


def handler_for(gateway: Gateway) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve(self, body: bytes | None) -> None:
            try:
                if self.path == "/api/chat" and body is not None:
                    self._reply(200, gateway.chat(body))
                else:
                    self._reply(200, gateway.passthrough(self.path, body))
            except urllib.error.HTTPError as exc:
                self._reply(exc.code, exc.read())
            except Exception as exc:  # the plan never reaches the agent
                self._reply(502, json.dumps({"error": f"ScreenWarden gateway: {exc!r}"}).encode())

        def do_GET(self) -> None:
            self._serve(None)

        def do_POST(self) -> None:
            self._serve(self.rfile.read(int(self.headers.get("Content-Length", 0))))

        def log_message(self, *args) -> None:
            pass

    return Handler


def serve(gateway: Gateway, port: int, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), handler_for(gateway))


def main() -> None:
    parser = argparse.ArgumentParser(prog="screenwarden.llm_gateway", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", type=int, default=11435)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--upstream", default="http://127.0.0.1:11434")
    parser.add_argument("--log", help="decision log path")
    args = parser.parse_args()
    server = serve(Gateway(args.upstream, log_path=args.log), args.listen, args.host)
    print(f"ScreenWarden LLM gateway on {args.host}:{args.listen} -> {args.upstream}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

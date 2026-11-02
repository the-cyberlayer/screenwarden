"""Pluggable LLM. LLM_PROVIDER = anthropic (default) | ollama | scripted."""

from __future__ import annotations

import json
import os
import re
import urllib.request


def parse_action(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"no JSON action in model reply: {text[:200]!r}")
    return json.loads(match.group(0))


class Anthropic:
    def __init__(self):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")

    def next_action(self, system: str, prompt: str, nodes=None) -> dict:
        response = self.client.beta.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": prompt}],
        )
        if response.stop_reason == "refusal":
            raise RuntimeError("model refused the request")
        return parse_action("".join(b.text for b in response.content if b.type == "text"))


class Ollama:
    def __init__(self):
        self.url = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3.2")

    def next_action(self, system: str, prompt: str, nodes=None) -> dict:
        body = json.dumps({
            "model": self.model, "stream": False, "format": "json",
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
        }).encode()
        request = urllib.request.Request(f"{self.url}/api/chat", body,
                                         {"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=300) as reply:
            return parse_action(json.load(reply)["message"]["content"])


class Scripted:
    """Replays a JSON list of actions, with no model involved.

    A step may use {"target_label": "Send"} instead of an element id. This only
    exercises the adb and guard plumbing: it shows what a hijacked model *would*
    do, not that a model was hijacked.
    """

    def __init__(self):
        with open(os.environ["SCRIPTED_PLAN"], encoding="utf-8") as f:
            self.steps = json.load(f)

    def next_action(self, system: str, prompt: str, nodes=None) -> dict:
        if not self.steps:
            return {"type": "done", "text": "script finished"}
        action = dict(self.steps.pop(0))
        wanted = action.pop("target_label", None)
        if wanted:
            hit = next((n for n in nodes or [] if wanted.lower() in n.label.lower()), None)
            if hit is None:
                return {"type": "done", "text": f"script: no element labelled {wanted!r}"}
            action["target"] = hit.id
        return action


def get_llm():
    provider = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    providers = {"anthropic": Anthropic, "ollama": Ollama, "scripted": Scripted}
    if provider not in providers:
        raise SystemExit(f"Unknown LLM_PROVIDER {provider!r}")
    return providers[provider]()

"""check_action: decide whether a proposed agent action may run.

Rules yield (rule_name, detail) hits; verdicts, reasons and OWASP tags come from
policy.yaml. Internal errors fail closed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

from .decision_log import write_decision
from .policy import Policy, load_policy
from .types import Decision, Element, SanitizedScreen, Verdict

Hit = tuple[str, str]
_STRICTNESS = {Verdict.BLOCK: 2, Verdict.ASK_HUMAN: 1, Verdict.ALLOW: 0}
_MIN_PHONE_MATCH = 9  # compare the last N digits to ignore country-code format


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _phone_in(phone: str, text: str) -> bool:
    tail = _digits(phone)[-_MIN_PHONE_MATCH:]
    return len(tail) >= 6 and tail in _digits(text)


def _host(url: str) -> str:
    url = url if "://" in url else f"https://{url}"
    return (urlparse(url).hostname or "").removeprefix("www.").lower()


def _words(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _copied_from(body: str, sources: list[str]) -> bool:
    """True if most of `body` is lifted from one of `sources`."""
    words = _words(body)
    if not words:
        return False
    for source in sources:
        vocabulary = set(_words(source))
        hits = sum(w in vocabulary for w in words)
        if len(words) >= 3 and hits / len(words) >= 0.6:
            return True
    return False


class _Ctx:
    """Normalised view of the check_action arguments."""

    def __init__(self, action: dict, context: dict, policy: Policy):
        self.action = action
        self.policy = policy
        self.goal: str = context.get("goal") or ""
        self.screen: SanitizedScreen = context.get("screen") or SanitizedScreen()
        self.foreground: str = context.get("foreground_package") or self.screen.foreground
        self.untrusted = list(context.get("untrusted_text") or []) + self.screen.untrusted_text
        self.instructions = list(context.get("instructions") or []) + self.screen.instructions
        self.codes = list(context.get("sensitive_codes") or []) + self.screen.sensitive_codes
        self.known = [*policy.raw["known_contacts"], *(context.get("known_contacts") or [])]
        self.kind: str = action.get("type", "")
        self.text: str = action.get("text") or ""
        self.url: str = action.get("url") or ""
        self.target = self._target()

    def _target(self) -> Element | None:
        target = self.action.get("target")
        if isinstance(target, Element):
            return target
        if isinstance(target, int):
            return self.screen.element(target)
        return None

    @property
    def in_messaging(self) -> bool:
        return self.foreground in self.policy.packages["messaging"]

    def has_code(self, text: str) -> bool:
        if not text:
            return False
        squeezed = _digits(text)
        if any(_digits(code) in squeezed for code in self.codes):
            return True
        return self.policy.matches("otp_context", text) and bool(
            self.policy.find("otp_value", text)
        )

    def named_by_user(self, recipient: str) -> bool:
        for allowed in [self.goal, *self.known]:
            if _digits(recipient) and _phone_in(recipient, allowed):
                return True
            if not _digits(recipient) and recipient.lower() in allowed.lower():
                return True
        return False

    def from_untrusted(self, value: str) -> bool:
        if _digits(value) and len(_digits(value)) >= 6:
            return any(_phone_in(value, text) for text in self.untrusted)
        return any(value.lower() in text.lower() for text in self.untrusted)


def _screen_recipient(ctx: _Ctx) -> str | None:
    """Best effort: who the open conversation in a messaging app is with."""
    id_hint = re.compile(r"title|recipient|chip|conversation_name|contact", re.I)
    for element in ctx.screen.elements:
        if element.editable or not element.label:
            continue
        if id_hint.search(element.resource_id):
            return element.label
    for element in ctx.screen.elements:
        phones = ctx.policy.find("phone", element.label)
        if phones and not element.editable:
            return phones[0]
    return None


def _compose_text(ctx: _Ctx) -> str:
    return next((e.text for e in ctx.screen.elements if e.editable and e.text), "")


def _outbound(ctx: _Ctx) -> tuple[str | None, str] | None:
    """Return (recipient, body) if this action sends something off the device."""
    p = ctx.policy
    if ctx.kind == "send_sms":
        return ctx.action.get("recipient") or None, ctx.text
    if ctx.kind == "open_url":
        parsed = urlparse(ctx.url)
        if parsed.scheme in ("sms", "smsto", "mms", "mmsto", "mailto"):
            query = parse_qs(parsed.query)
            body = " ".join(query.get("body", []) + query.get("sms_body", []))
            return parsed.path or None, body
        return None
    if not ctx.in_messaging or ctx.target is None:
        return None
    if ctx.kind == "tap":
        haystack = f"{ctx.target.label} {ctx.target.resource_id}"
        if p.matches("send_button", haystack):
            return ctx.action.get("recipient") or _screen_recipient(ctx), _compose_text(ctx)
        return None
    return None


def _rules(ctx: _Ctx) -> Iterator[Hit]:
    p = ctx.policy
    actions = p.raw["actions"]
    if ctx.kind in actions["passive"]:
        return
    if ctx.kind not in actions["active"]:
        yield "unknown_action", f"type={ctx.kind!r}"
        return

    flags = ctx.screen.flags
    if "unsafe" in flags:
        yield "unsafe_screen", ""
    if ctx.action.get("origin") == "untrusted":
        yield "tainted_origin", "agent reports instruction came from screen content"

    outbound = _outbound(ctx)
    typed_recipient = None
    if ctx.kind == "type" and ctx.in_messaging:
        if p.find("phone", ctx.text) and len(_digits(ctx.text)) >= 7:
            typed_recipient = ctx.text
        elif ctx.has_code(ctx.text):
            outbound = (None, ctx.text)
        elif _copied_from(ctx.text, ctx.instructions) and not _copied_from(ctx.text, [ctx.goal]):
            outbound = (None, ctx.text)

    if outbound:
        body = outbound[1]
        if ctx.has_code(body) or ctx.has_code(ctx.url):
            yield "otp_exfiltration", ""
        if body and _copied_from(body, ctx.instructions) and not _copied_from(body, [ctx.goal]):
            yield "tainted_origin", "message body copied from untrusted instructions"
    elif ctx.has_code(ctx.url):
        yield "otp_exfiltration", "code in URL"

    recipient = typed_recipient or (outbound[0] if outbound else None)
    is_send = ctx.kind == "send_sms" or typed_recipient or (outbound and ctx.kind != "type")
    if is_send:
        if not recipient:
            yield "unknown_recipient", "recipient could not be determined"
        elif not ctx.named_by_user(recipient):
            if ctx.from_untrusted(recipient):
                yield "tainted_origin", "recipient taken from untrusted content"
            yield "unknown_recipient", ""

    for url in [ctx.url, *p.find("url", ctx.text)]:
        host = url and _host(url)
        if host and host not in ctx.goal.lower() and ctx.from_untrusted(host):
            yield "tainted_origin", f"URL host {host} taken from untrusted content"
        if url and p.matches("install_url", url):
            yield "install_app", url

    if ctx.kind == "type":
        field = ctx.target
        if field and (
            field.password
            or p.matches("credential_field", f"{field.resource_id} {field.label}")
        ):
            yield "credential_entry", field.resource_id or field.label
        if not ctx.in_messaging and ctx.has_code(ctx.text):
            yield "otp_entry", ""

    if "spoofed_login" in flags:
        yield "spoofed_screen", ctx.screen.url

    label = ctx.target.label if ctx.target else ""
    if "payment" in flags:
        if ctx.kind == "tap" and p.matches("payment_action", label):
            yield "payment", label
        else:
            yield "payment_screen", ""

    if ctx.kind == "install":
        yield "install_app", ctx.action.get("package", "")
    if ctx.foreground in p.packages["installers"] and p.matches("install_button", label):
        yield "install_app", label
    if ctx.foreground in p.packages["settings"] and ctx.kind in ("tap", "type", "key"):
        yield "settings_change", label
    if ctx.kind == "open_app" and ctx.action.get("package") in p.packages["settings"]:
        yield "settings_change", "opening settings"

    if "overlay" in flags:
        yield "overlay_present", ""


def _decide(hits: list[Hit], ctx: _Ctx) -> Decision:
    p = ctx.policy
    order = list(p.rules)
    candidates = []
    for name, detail in hits:
        rule = p.rules[name]
        if not rule.get("enabled", True):
            continue
        verdict = Verdict(rule["verdict"])
        goal_match = rule.get("goal_match")
        if goal_match and re.search(goal_match, ctx.goal, re.I):
            verdict = Verdict(rule["goal_override"])
        candidates.append((-_STRICTNESS[verdict], order.index(name), verdict, name, detail))
    if not candidates:
        return Decision(Verdict.ALLOW, "No policy rule matched")
    candidates.sort(key=lambda c: c[:2])
    _, _, verdict, name, detail = candidates[0]
    reason = p.rules[name]["reason"] + (f" ({detail})" if detail else "")
    matched = list(dict.fromkeys(c[3] for c in candidates))
    return Decision(verdict, reason, p.rules[name].get("owasp"), name, matched)


def check_action(action: dict[str, Any], context: dict[str, Any] | None = None) -> Decision:
    """Judge one proposed action.

    action:  {"type": "tap"|"type"|"send_sms"|"open_url"|..., "target": element id,
              "text": ..., "recipient": ..., "url": ..., "package": ...,
              "origin": "untrusted" (optional, self-reported by the agent)}
    context: {"goal": the user's goal, "screen": SanitizedScreen, plus optional
              "foreground_package", "known_contacts", "untrusted_text",
              "instructions", "sensitive_codes", "policy", "log_path", "log": False}
    """
    context = context or {}
    policy = context.get("policy") or load_policy()
    try:
        ctx = _Ctx(action, context, policy)
        decision = _decide(list(_rules(ctx)), ctx)
    except Exception as exc:  # fail closed: a broken guard must not wave actions through
        decision = Decision(Verdict.BLOCK, f"Guard error: {exc!r}", None, "internal_error")
    if context.get("log", True):
        safe_action = {k: v for k, v in action.items() if isinstance(v, (str, int))}
        write_decision(
            {"event": "check_action", "goal": context.get("goal"), "action": safe_action,
             **decision.to_dict()},
            policy,
            context.get("log_path"),
        )
    return decision

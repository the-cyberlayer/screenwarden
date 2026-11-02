"""sanitize_screen: turn a uiautomator dump into content that is safe to show an LLM."""

from __future__ import annotations

import re
import unicodedata
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .decision_log import write_decision
from .pixels import PixelView, load as load_pixels
from .policy import Policy, load_policy
from .types import Element, SanitizedScreen, ScreenWarning

Bounds = tuple[int, int, int, int]
_BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")
_URL_BAR = re.compile(r"url_bar|location_bar|address", re.I)


def _visible_chars(value: str) -> str:
    """Drop zero-width and format characters, which can split words to dodge patterns."""
    return "".join(c for c in value if unicodedata.category(c) != "Cf").strip()


@dataclass
class _Node:
    attrs: dict[str, str]
    bounds: Bounds
    in_web: bool      # inside a WebView
    in_scroller: bool # inside something scrollable
    hidden_by_parent: bool

    @property
    def text(self) -> str:
        return _visible_chars(self.attrs.get("text") or "")

    @property
    def desc(self) -> str:
        return _visible_chars(self.attrs.get("content-desc") or "")

    @property
    def package(self) -> str:
        return self.attrs.get("package", "")

    @property
    def label(self) -> str:
        return self.text or self.desc


def _parse_bounds(value: str | None) -> Bounds:
    match = _BOUNDS.match(value or "")
    return tuple(int(g) for g in match.groups()) if match else (0, 0, 0, 0)  # type: ignore


def _area(b: Bounds) -> int:
    return max(0, b[2] - b[0]) * max(0, b[3] - b[1])


def _walk(el: ET.Element, policy: Policy, in_web=False, in_scroller=False, hidden=False
          ) -> Iterator[_Node]:
    for child in el:
        if child.tag != "node":
            yield from _walk(child, policy, in_web, in_scroller, hidden)
            continue
        attrs = child.attrib
        bounds = _parse_bounds(attrs.get("bounds"))
        web = in_web or attrs.get("class") in policy.raw["untrusted_classes"]
        scroller = in_scroller or attrs.get("scrollable") == "true"
        yield _Node(dict(attrs), bounds, web, scroller, hidden)
        yield from _walk(child, policy, web, scroller, hidden or _area(bounds) == 0)


def _foreground(nodes: list[_Node], policy: Policy) -> str:
    """The non-system package covering the most screen; system UI only if nothing else."""
    areas: Counter[str] = Counter()
    for node in nodes:
        if node.package:
            areas[node.package] = max(areas[node.package], _area(node.bounds))
    system = policy.packages["overlay_allowed"]
    apps = {k: v for k, v in areas.items() if k not in system}
    pool = apps or areas
    return max(pool, key=pool.get) if pool else ""


def _hidden_reason(node: _Node, screen: Bounds, policy: Policy, pixels: PixelView | None
                   ) -> tuple[str, str] | None:
    b = node.bounds
    limits = policy.visibility
    if node.hidden_by_parent:
        return "zero_size", "inside a zero-size parent"
    if _area(b) == 0:
        return "zero_size", "node has no area"
    # Text below the fold in a scrolling view is reachable by a human, so keep it.
    below_fold = b[1] >= screen[3] and node.in_scroller
    outside = b[2] <= screen[0] or b[0] >= screen[2] or b[3] <= screen[1] or b[1] >= screen[3]
    if outside and not below_fold:
        return "off_screen", "node is outside the display"
    if node.attrs.get("visible-to-user") == "false" and not below_fold:
        return "not_visible", "node is marked not visible to the user"
    height = b[3] - b[1]
    width = b[2] - b[0]
    if height < limits["min_text_height_px"]:
        return "tiny_text", f"text is only {height}px tall"
    # Area, not width, so wrapped text passes. content-desc is exempt: icons describe themselves.
    if node.text and _area(b) / len(node.text) < limits["min_area_per_char_px2"]:
        return "tiny_text", f"{len(node.text)} characters in {width}x{height}px"
    untrusted = node.in_web or policy.is_untrusted_package(node.package)
    if pixels and untrusted and node.text and b[3] <= screen[3]:
        contrast = pixels.contrast(b)
        if contrast < limits["min_contrast"]:
            return "invisible_text", f"in the UI tree but not on screen (contrast {contrast})"
    return None


def _warn(result: SanitizedScreen, policy: Policy, code: str, message: str, node: _Node | None,
          severity: str = "high", owasp: str = "ASI01") -> None:
    result.warnings.append(ScreenWarning(
        code, severity, message, node.label[:200] if node else "",
        node.package if node else "", node.bounds if node else None, owasp))


def _collect_codes(label: str, policy: Policy, result: SanitizedScreen) -> None:
    if policy.matches("otp_context", label):
        for value in policy.find("otp_value", label):
            if value not in result.sensitive_codes:
                result.sensitive_codes.append(value)


def _is_trusted_login_host(host: str, policy: Policy) -> bool:
    return any(host == d or host.endswith("." + d) for d in policy.raw["trusted_login_domains"])


def _flag_page(result: SanitizedScreen, policy: Policy, labels: list[str], has_password: bool
               ) -> None:
    joined = "\n".join(labels)
    if policy.matches("payment", joined):
        result.flags.add("payment")
        _warn(result, policy, "payment_screen", "Screen looks like a payment page", None,
              "medium", "ASI02")

    in_browser = result.foreground in policy.packages["browsers"]
    looks_like_login = has_password or policy.matches("login_screen", joined)
    if not (in_browser and looks_like_login):
        return
    raw_url = result.url if "://" in result.url else f"https://{result.url}"
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").removeprefix("www.").lower()
    if not (has_password or policy.matches("brand", joined)):
        return
    if not _is_trusted_login_host(host, policy):
        result.flags.add("spoofed_login")
        brand = policy.find("brand", joined)
        detail = f" for {brand[0]}" if brand else ""
        _warn(result, policy, "spoofed_login",
              f"Login page{detail} on untrusted host {host or 'unknown'}", None)


def sanitize_screen(ui_tree: str | bytes, context: dict[str, Any] | None = None) -> SanitizedScreen:
    """Clean a uiautomator XML dump.

    Hidden nodes, foreign overlays and instruction-like text from untrusted
    sources are removed from `.elements`/`.text` and reported in `.warnings`.
    context: optional {"foreground_package", "policy", "log_path", "log": False,
    "screenshot": PNG bytes, enabling the check for text no human can see}.
    """
    context = context or {}
    policy = context.get("policy") or load_policy()
    result = SanitizedScreen()
    try:
        root = ET.fromstring(ui_tree)
    except (ET.ParseError, ValueError, TypeError) as exc:
        result.flags.add("unsafe")
        _warn(result, policy, "parse_error", f"UI dump could not be parsed: {exc}", None)
        _log(result, policy, context)
        return result

    nodes = list(_walk(root, policy))
    if not nodes:
        result.flags.add("unsafe")
        _warn(result, policy, "empty_dump", "UI dump contained no nodes", None)
        _log(result, policy, context)
        return result

    screen = max((n.bounds for n in nodes), key=_area)
    result.foreground = context.get("foreground_package") or _foreground(nodes, policy)
    allowed = policy.packages["overlay_allowed"] | {result.foreground}
    screen_area = _area(screen) or 1

    overlays = {
        n.package for n in nodes
        if n.package not in allowed
        and _area(n.bounds) / screen_area >= policy.raw["overlay"]["min_screen_fraction"]
    }
    for package in sorted(overlays):
        result.flags.add("overlay")
        result.warnings.append(ScreenWarning(
            "overlay", "high", f"{package} is drawing over {result.foreground}",
            package=package, owasp="ASI01"))

    pixels = load_pixels(context.get("screenshot"))
    labels: list[str] = []
    has_password = False
    next_id = 1
    for node in nodes:
        if node.package and node.package not in allowed:
            continue  # foreign window: reported above, never shown to the agent
        cid = node.attrs.get("resource-id", "")
        if result.foreground in policy.packages["browsers"] and _URL_BAR.search(cid) and node.text:
            result.url = result.url or node.text
        clickable = node.attrs.get("clickable") == "true"
        editable = "EditText" in node.attrs.get("class", "")
        if not (node.label or clickable or editable):
            continue

        if node.label:
            hidden = _hidden_reason(node, screen, policy, pixels)
            if hidden:
                code, why = hidden
                _warn(result, policy, code, f"Removed hidden text: {why}", node)
                result.untrusted_text.append(node.label)  # hidden text is never the user's
                if policy.matches("instruction", node.label):
                    result.instructions.append(node.label)
                continue

        is_password = node.attrs.get("password") == "true"
        has_password = has_password or is_password
        labels.append(node.label)
        untrusted = node.in_web or policy.is_untrusted_package(node.package)
        _collect_codes(node.label, policy, result)
        if untrusted and node.label:
            result.untrusted_text.append(node.label)
            if policy.matches("instruction", node.label):
                result.instructions.append(node.label)
                _warn(result, policy, "untrusted_instruction",
                      "Removed instruction-like text from an untrusted source", node)
                continue

        result.elements.append(Element(
            id=next_id, text=node.text, desc=node.desc, cls=node.attrs.get("class", ""),
            package=node.package, resource_id=cid, bounds=node.bounds, clickable=clickable,
            password=is_password, untrusted=untrusted))
        next_id += 1

    _flag_page(result, policy, labels, has_password)
    _log(result, policy, context)
    return result


def _log(result: SanitizedScreen, policy: Policy, context: dict) -> None:
    if not context.get("log", True):
        return
    write_decision(
        {"event": "sanitize_screen", "foreground": result.foreground,
         "flags": sorted(result.flags),
         "warnings": [{"code": w.code, "severity": w.severity, "reason": w.message,
                       "owasp": w.owasp, "text": w.text[:120]} for w in result.warnings],
         "kept": len(result.elements)},
        policy, context.get("log_path"))

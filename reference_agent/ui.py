"""Naive UI reader: every node with text goes to the LLM, as in typical phone agents."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

_BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


@dataclass
class Node:
    id: int
    label: str
    kind: str
    clickable: bool
    center: tuple[int, int]


def parse(xml: str) -> list[Node]:
    nodes: list[Node] = []
    for el in ET.fromstring(xml).iter("node"):
        label = el.get("text") or el.get("content-desc") or ""
        clickable = el.get("clickable") == "true"
        editable = "EditText" in el.get("class", "")
        if not (label or clickable or editable):
            continue
        match = _BOUNDS.match(el.get("bounds", ""))
        x1, y1, x2, y2 = (int(g) for g in match.groups()) if match else (0, 0, 0, 0)
        nodes.append(Node(len(nodes) + 1, label, el.get("class", "").rsplit(".", 1)[-1],
                          clickable, ((x1 + x2) // 2, (y1 + y2) // 2)))
    return nodes


def render(nodes: list[Node]) -> str:
    return "\n".join(
        f'[{n.id}] {n.kind}{" clickable" if n.clickable else ""} "{n.label}"' for n in nodes)

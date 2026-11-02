"""Append-only JSONL decision log. Digit runs are masked so codes are not stored."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from .policy import Policy

_DIGITS = re.compile(r"\d(?:[ -]?\d){3,}")


def redact(value: Any) -> Any:
    """Mask anything that could be a code or phone number, keeping the last two digits."""
    if isinstance(value, str):
        return _DIGITS.sub(lambda m: "*" * (len(m.group(0)) - 2) + m.group(0)[-2:], value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def write_decision(record: dict, policy: Policy, path: str | os.PathLike | None = None) -> None:
    path = path or os.environ.get("SCREENWARDEN_LOG") or policy.raw["log_path"]
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **redact(record)}
    if record.get("model"):
        entry["model"] = record["model"]  # an ID, not a secret: dated IDs must stay exact
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

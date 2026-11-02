"""Load policy.yaml and compile its regular expressions."""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

import yaml

DEFAULT_POLICY = Path(__file__).with_name("policy.yaml")
FLAGS = re.IGNORECASE | re.DOTALL


class Policy:
    """Parsed policy: `raw` is the YAML, `patterns` the compiled regexes."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.patterns: dict[str, list[re.Pattern]] = {}
        for name, value in raw["patterns"].items():
            items = value if isinstance(value, list) else [value]
            self.patterns[name] = [re.compile(p, FLAGS) for p in items]
        self.packages: dict[str, set[str]] = {
            name: set(items) for name, items in raw["packages"].items()
        }
        self.rules: dict = raw["rules"]
        self.visibility: dict = raw["visibility"]

    def matches(self, name: str, text: str | None) -> bool:
        return bool(text) and any(p.search(text) for p in self.patterns[name])

    def find(self, name: str, text: str | None) -> list[str]:
        if not text:
            return []
        return [m.group(0) for p in self.patterns[name] for m in p.finditer(text)]

    def is_untrusted_package(self, package: str | None) -> bool:
        return package in self.packages["messaging"] | self.packages["browsers"]


@lru_cache(maxsize=8)
def _load(path: str) -> Policy:
    with open(path, encoding="utf-8") as f:
        return Policy(yaml.safe_load(f))


def load_policy(path: str | os.PathLike | None = None) -> Policy:
    """Load a policy from `path`, $SCREENWARDEN_POLICY, or the bundled default."""
    return _load(str(path or os.environ.get("SCREENWARDEN_POLICY") or DEFAULT_POLICY))

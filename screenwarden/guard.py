"""Guard: remembers what a run has seen so taint survives across screens."""

from __future__ import annotations

from .check import check_action
from .policy import Policy, load_policy
from .sanitize import sanitize_screen
from .types import Decision, SanitizedScreen


class Guard:
    """Thin session wrapper: guard.observe(xml) on each screen, guard.check(action) before acting."""

    def __init__(self, goal: str, policy: Policy | None = None, log_path=None,
                 known_contacts: list[str] | None = None, model: str | None = None):
        self.goal = goal
        self.policy = policy or load_policy()
        self.log_path = log_path
        self.model = model  # recorded on every log line
        self.known_contacts = known_contacts or []
        self.screen = SanitizedScreen()
        self.untrusted_text: list[str] = []
        self.instructions: list[str] = []
        self.sensitive_codes: list[str] = []

    def observe(self, ui_tree: str | bytes, foreground_package: str | None = None,
                screenshot: bytes | None = None) -> SanitizedScreen:
        self.screen = sanitize_screen(ui_tree, {
            "policy": self.policy, "log_path": self.log_path,
            "foreground_package": foreground_package, "screenshot": screenshot,
            "model": self.model})
        for mine, theirs in ((self.untrusted_text, self.screen.untrusted_text),
                             (self.instructions, self.screen.instructions),
                             (self.sensitive_codes, self.screen.sensitive_codes)):
            mine.extend(v for v in theirs if v not in mine)
        return self.screen

    def check(self, action: dict) -> Decision:
        return check_action(action, {
            "goal": self.goal, "screen": self.screen, "policy": self.policy,
            "log_path": self.log_path, "model": self.model,
            "known_contacts": self.known_contacts,
            "untrusted_text": self.untrusted_text, "instructions": self.instructions,
            "sensitive_codes": self.sensitive_codes})

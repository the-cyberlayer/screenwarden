"""SharedSession: several agents on one phone, one view of what is tainted."""

from __future__ import annotations

from .guard import Guard
from .policy import Policy, load_policy


class SharedSession:
    """One Guard per agent, sharing taint and always judged against the user's own goal.

    Text one agent reads counts as untrusted for all of them. Tasks agents hand each
    other are never trusted as goals, so a recipient invented by one agent cannot
    become "named by the user" for the next.
    """

    def __init__(self, user_goal: str, policy: Policy | None = None, log_path=None,
                 known_contacts: list[str] | None = None):
        self.user_goal = user_goal
        self.policy = policy or load_policy()
        self.log_path = log_path
        self.known_contacts = known_contacts
        self.untrusted_text: list[str] = []
        self.instructions: list[str] = []
        self.sensitive_codes: list[str] = []

    def guard(self, model: str | None = None) -> Guard:
        guard = Guard(self.user_goal, self.policy, self.log_path, self.known_contacts, model)
        guard.untrusted_text = self.untrusted_text
        guard.instructions = self.instructions
        guard.sensitive_codes = self.sensitive_codes
        return guard

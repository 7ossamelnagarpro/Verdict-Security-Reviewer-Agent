"""Section 4 limits, enforced mechanically rather than left to the agent's judgement."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .models import ExecutionBudget


@dataclass
class BudgetTracker:
    """Mutable per-run counters checked before every attempt and every request."""

    budget: ExecutionBudget
    run_started: float = field(default_factory=time.monotonic)
    total_requests: int = 0
    per_hypothesis_requests: dict[str, int] = field(default_factory=dict)
    per_hypothesis_attempts: dict[str, int] = field(default_factory=dict)
    per_hypothesis_started: dict[str, float] = field(default_factory=dict)

    def can_attempt(self, candidate_id: str) -> tuple[bool, str | None]:
        if time.monotonic() - self.run_started >= self.budget.max_total_seconds:
            return False, "time_expired"
        if self.total_requests >= self.budget.max_total_requests:
            return False, "budget_exhausted"
        attempts = self.per_hypothesis_attempts.get(candidate_id, 0)
        if attempts >= self.budget.max_attempts_per_hypothesis:
            return False, "budget_exhausted"
        if self.per_hypothesis_requests.get(candidate_id, 0) >= self.budget.max_requests_per_hypothesis:
            return False, "budget_exhausted"
        started = self.per_hypothesis_started.get(candidate_id)
        if started is not None and time.monotonic() - started >= self.budget.max_seconds_per_hypothesis:
            return False, "time_expired"
        return True, None

    def record_attempt(self, candidate_id: str, *, requests_made: int) -> None:
        self.per_hypothesis_started.setdefault(candidate_id, time.monotonic())
        self.per_hypothesis_attempts[candidate_id] = self.per_hypothesis_attempts.get(candidate_id, 0) + 1
        self.per_hypothesis_requests[candidate_id] = self.per_hypothesis_requests.get(candidate_id, 0) + requests_made
        self.total_requests += requests_made

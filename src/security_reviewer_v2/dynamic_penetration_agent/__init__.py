"""Autonomous, hypothesis-driven penetration testing for Verdict-discovered candidates.

Public entry point: :func:`run_penetration_tests`. See ``agent.py`` for scope and
``docs/dynamic-penetration-agent.md`` for the full design and current limitations.
"""

from .agent import RuntimeAccess, run_penetration_tests
from .ai_planner import AIPlanDecision, AttackPlanProvider, choose_next_strategy
from .models import (
    ExecutionBudget,
    HypothesisTestResult,
    PenetrationAttempt,
    PenetrationTestReport,
    StopReason,
    TestOutcome,
    TestStrategy,
)

__all__ = [
    "RuntimeAccess",
    "run_penetration_tests",
    "AIPlanDecision",
    "AttackPlanProvider",
    "choose_next_strategy",
    "ExecutionBudget",
    "HypothesisTestResult",
    "PenetrationAttempt",
    "PenetrationTestReport",
    "StopReason",
    "TestOutcome",
    "TestStrategy",
]

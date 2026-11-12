"""Autonomous, hypothesis-driven penetration testing for Verdict-discovered candidates.

Public entry point: :func:`run_penetration_tests`. See ``agent.py`` for scope and
``docs/dynamic-penetration-agent.md`` for the full design and current limitations.
"""

from .agent import RuntimeAccess, run_penetration_tests
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
    "ExecutionBudget",
    "HypothesisTestResult",
    "PenetrationAttempt",
    "PenetrationTestReport",
    "StopReason",
    "TestOutcome",
    "TestStrategy",
]

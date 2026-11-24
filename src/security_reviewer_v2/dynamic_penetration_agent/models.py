"""Typed, auditable records for the Autonomous Penetration Testing Agent.

These are deliberately close to the Unified Finding / Discovery schemas already used elsewhere in
Verdict, and they carry the exact field set the design calls for in section 7 ("Agent outputs"), so
Triage and the Security Review Agent can read them the same way they read ``runtime_evidence`` today.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0"
PROVENANCE = "ai_penetration_test"


class TestStrategy(str, Enum):
    __test__ = False  # not a pytest test class; this enum's name just starts with "Test"

    UNAUTHENTICATED_ACCESS = "unauthenticated_access"
    AUTHORIZATION_MATRIX = "authorization_matrix"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    HEAD_METHOD_BYPASS = "head_method_bypass"
    TRAILING_SLASH_BYPASS = "trailing_slash_bypass"
    CASE_SENSITIVITY_BYPASS = "case_sensitivity_bypass"
    PATH_NORMALIZATION_BYPASS = "path_normalization_bypass"
    IDOR_PARAMETER_POLLUTION = "idor_parameter_pollution"
    EXTENSION_SUFFIX_BYPASS = "extension_suffix_bypass"


class NextAction(str, Enum):
    NEXT_TEST = "next_test"
    STOP = "stop"


class StopReason(str, Enum):
    NONE = "none"                              # testing continues
    EXPLOITATION_CONFIRMED = "exploitation_confirmed"
    NO_FURTHER_STRATEGY = "no_further_strategy"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIME_EXPIRED = "time_expired"
    BLOCKED = "blocked"


class TestOutcome(str, Enum):
    """Final per-hypothesis states from section 7. These describe the TEST result, never the final verdict."""

    __test__ = False  # not a pytest test class; this enum's name just starts with "Test"

    EXPLOITATION_CONFIRMED = "exploitation_confirmed"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    CANNOT_TEST = "cannot_test"


@dataclass(frozen=True)
class ExecutionBudget:
    """Hard ceilings enforced by :mod:`execution_budget`, never exceeded by the controller."""

    max_attempts_per_hypothesis: int = 10  # one per template, now that there are ~10 of them
    max_requests_per_hypothesis: int = 40
    max_total_requests: int = 300
    max_seconds_per_hypothesis: float = 180.0
    max_total_seconds: float = 1800.0

    def validate(self) -> None:
        for name in ("max_attempts_per_hypothesis", "max_requests_per_hypothesis", "max_total_requests"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("max_seconds_per_hypothesis", "max_total_seconds"):
            value = getattr(self, name)
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_seconds_per_hypothesis > self.max_total_seconds:
            raise ValueError("max_seconds_per_hypothesis cannot exceed max_total_seconds")


@dataclass(frozen=True)
class AttackStep:
    """One planned, validator-approved HTTP step (see scenario_validator for the accepted shape)."""

    actor: str
    method: str
    path: str
    security_check: bool = True
    body: dict[str, Any] | None = None
    expect_status: tuple[int, ...] = ()
    assertions: tuple[dict[str, Any], ...] = ()
    capture: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackPlan:
    """One attempt's plan, produced by :mod:`attack_planner` and checked by :mod:`scenario_validator`."""

    candidate_id: str
    attempt_number: int
    test_strategy: TestStrategy
    target_endpoint: str
    selected_tools: tuple[str, ...]
    steps: tuple[AttackStep, ...]
    accounts: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class PenetrationAttempt:
    """One recorded attempt against one hypothesis; the exact field set section 7 asks for."""

    candidate_id: str
    hypothesis: str
    entry_point: str | None
    target_endpoint: str
    attack_plan: str
    selected_tools: tuple[str, ...]
    attempt_number: int
    test_strategy: str
    request_evidence: tuple[dict[str, Any], ...]
    response_evidence: tuple[dict[str, Any], ...]
    observation: str
    agent_reasoning_summary: str
    next_action: str
    stop_reason: str
    provenance: str = PROVENANCE
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


@dataclass(frozen=True)
class HypothesisTestResult:
    """Every attempt against one hypothesis, plus the final test outcome (never a vulnerability verdict).

    ``considered_but_not_executed`` records a strategy the controller picked but that never reached a
    tool call at all — rejected by the planner or the validator, or its tool was unavailable — each as
    ``{"strategy": ..., "reason": ...}``. These never fired a single request, so they are kept separate
    from ``attempts`` (which did), but a reviewer still needs them to see the FULL set of scenarios the
    agent drew for this hypothesis, not only the ones that got far enough to execute.
    """

    candidate_id: str
    outcome: TestOutcome
    attempts: tuple[PenetrationAttempt, ...]
    summary: str
    considered_but_not_executed: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


@dataclass(frozen=True)
class PenetrationTestReport:
    schema_version: str
    status: str                       # completed | not_run | blocked
    results: tuple[HypothesisTestResult, ...]
    usage: dict[str, Any]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _primitive(asdict(value))
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    return value

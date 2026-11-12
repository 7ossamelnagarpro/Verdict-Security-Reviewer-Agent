"""Section 5's "deterministic Validator before execution", for every plan, every attempt.

This never trusts the planner's own judgement: it re-checks the plan against the same allowlists the
planner was given, rejects anything outside the three approved templates, and only then builds the
``runtime_workflows`` suite and hands it to the *existing*, already-hardened ``validate_suite`` for the
step-shape checks (field names, status codes, capture rules, mutation gating) that module already does.
"""

from __future__ import annotations

from security_reviewer_v2.scanners.runtime_workflows import validate_suite

from .models import AttackPlan, TestStrategy

_ALLOWED_METHODS = {"GET", "HEAD"}   # Section 4: no mutating/destructive requests from this agent, ever.


class ScenarioRejected(ValueError):
    """The plan failed deterministic validation and must not be executed."""


def validate_plan(
    plan: AttackPlan,
    *,
    allowed_endpoints: frozenset[str],
    allowed_accounts: frozenset[str],
) -> None:
    """Raise :class:`ScenarioRejected` unless every constraint holds. Never mutates the plan."""
    if plan.test_strategy not in TestStrategy:
        raise ScenarioRejected(f"Unknown test strategy: {plan.test_strategy!r}")
    if plan.target_endpoint not in allowed_endpoints:
        raise ScenarioRejected(
            f"Target endpoint is not a route discovered from the codebase or Runtime Contract: {plan.target_endpoint}"
        )
    if not plan.steps or len(plan.steps) > 6:
        raise ScenarioRejected("A plan must have between 1 and 6 steps")
    if set(plan.selected_tools) - {"runtime_workflows", "zap", "playwright", "custom_requests"}:
        raise ScenarioRejected(f"Unapproved tool requested: {plan.selected_tools}")
    for step in plan.steps:
        if step.method not in _ALLOWED_METHODS:
            raise ScenarioRejected(f"Method not permitted for the penetration agent: {step.method}")
        if step.actor != "anonymous" and step.actor not in allowed_accounts:
            raise ScenarioRejected(f"Account is not in the Runtime Contract's approved accounts: {step.actor}")
        if step.body:
            raise ScenarioRejected("Request bodies are not permitted for read-only penetration templates")


def build_and_validate_suite(plan: AttackPlan, *, account_definitions: dict[str, dict]) -> dict:
    """Assemble one ``runtime_workflows`` suite for this single attempt and run it through ``validate_suite``.

    Reuses the existing contract/account/step grammar end to end instead of inventing a parallel one.
    """
    accounts = [account_definitions[actor] for actor in plan.accounts if actor in account_definitions]
    suite = {
        "version": 1,
        "accounts": accounts,
        "workflows": [{
            "id": f"pentest_{plan.attempt_number}",
            "title": f"{plan.test_strategy.value} attempt {plan.attempt_number} on {plan.target_endpoint}",
            "severity": "high",
            "steps": [_step_dict(step) for step in plan.steps],
        }],
        "max_requests": max(2, len(plan.steps) * 2),
        "timeout_seconds": 10,
        "max_seconds": 60,
        "allow_mutation": False,
        "reset": "none",
    }
    validate_suite(suite, disposable=False)   # the agent never requires a disposable/mutating target
    return suite


def _step_dict(step) -> dict:
    data = {
        "actor": step.actor, "method": step.method, "path": step.path,
        "security_check": step.security_check,
        "expect_status": list(step.expect_status) if step.expect_status else [200, 401, 403, 404],
    }
    if step.assertions:
        data["assertions"] = list(step.assertions)
    if step.capture:
        data["capture"] = dict(step.capture)
    return data

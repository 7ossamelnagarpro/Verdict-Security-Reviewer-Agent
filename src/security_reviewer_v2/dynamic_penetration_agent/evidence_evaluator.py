"""Section 3, phase 4 (evaluation half) and the stop conditions from phase 5.

Templates set the *safe* expected status (401/403/404); ``runtime_workflows`` only reports ``violation``
when the real response fails that designed assertion, so a plain 200 by itself is never read as proof
here — it is read as the specific assertion the template declared, exactly as section 4 requires.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import NextAction, StopReason, TestOutcome

AttemptOutcome = str  # "violation" | "passed" | "inconclusive" | "blocked"


@dataclass(frozen=True)
class AttemptEvaluation:
    outcome: AttemptOutcome
    observation: str
    reasoning: str


def evaluate_attempt(workflow_result: dict[str, Any], strategy_name: str) -> AttemptEvaluation:
    workflows = workflow_result.get("workflows") or []
    if not workflows:
        return AttemptEvaluation("blocked", "No workflow result was produced.",
                                 "The orchestrator returned no workflow record for this attempt.")
    status = workflows[0].get("status")
    steps = workflows[0].get("steps") or []
    checked = next((step for step in steps if step.get("security_check")), steps[-1] if steps else {})
    step_status = checked.get("status")
    http_status = checked.get("http_status")

    # A tool that has no HTTP-status assertion of its own (ZAP's scanner rules, say) reports its own
    # specific reason via the step's "reason" field instead; an empty expected_status is how it signals
    # that so the HTTP-status phrasing below (which would otherwise be misleading) is skipped for it.
    own_reason = checked.get("reason") if not checked.get("expected_status") else None

    if step_status == "violation":
        return AttemptEvaluation(
            "violation",
            f"{strategy_name}: {own_reason}" if own_reason else
            f"{strategy_name}: request to {checked.get('path')} as {checked.get('actor')} returned "
            f"HTTP {http_status}, not one of the expected denial statuses {checked.get('expected_status')}.",
            "The response failed the template's designed denial assertion; this is treated as evidence of "
            "exploitability for this specific probe, not as a bare, unexamined HTTP 200.",
        )
    if step_status == "passed":
        return AttemptEvaluation(
            "passed",
            f"{strategy_name}: {own_reason}" if own_reason else
            f"{strategy_name}: the request was correctly denied (HTTP {http_status}).",
            "Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by "
            "itself conclusive proof that no exploitable path exists at all.",
        )
    if step_status in {"skipped", "blocked"} or status != "completed" and step_status != "inconclusive":
        return AttemptEvaluation(
            "blocked",
            f"{strategy_name}: the attempt could not complete ({checked.get('reason', step_status)}).",
            "A prerequisite (login, capture or the request/time budget) failed before the security-relevant "
            "request could run; this is not evidence either way.",
        )
    return AttemptEvaluation(
        "inconclusive",
        f"{strategy_name}: the response (HTTP {http_status}) was a server error or an ambiguous status.",
        "A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis.",
    )


def decide_next(
    outcome: AttemptOutcome, *, budget_ok: bool, budget_stop_reason: str | None, has_more_strategies: bool,
) -> tuple[NextAction, StopReason]:
    if outcome == "violation":
        return NextAction.STOP, StopReason.EXPLOITATION_CONFIRMED
    if not budget_ok:
        return NextAction.STOP, StopReason(budget_stop_reason or StopReason.BUDGET_EXHAUSTED.value)
    if not has_more_strategies:
        return NextAction.STOP, StopReason.NO_FURTHER_STRATEGY
    return NextAction.NEXT_TEST, StopReason.NONE


def hypothesis_outcome(evaluations: tuple[AttemptEvaluation, ...], *, planning_blocked: bool) -> TestOutcome:
    """Roll every attempt's evaluation up into the one section-7 final state for this hypothesis."""
    if any(item.outcome == "violation" for item in evaluations):
        return TestOutcome.EXPLOITATION_CONFIRMED
    if not evaluations:
        return TestOutcome.CANNOT_TEST if planning_blocked else TestOutcome.BLOCKED
    if all(item.outcome == "blocked" for item in evaluations):
        return TestOutcome.BLOCKED
    if any(item.outcome == "passed" for item in evaluations):
        return TestOutcome.NOT_REPRODUCED
    return TestOutcome.INCONCLUSIVE

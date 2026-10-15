"""Human approval gate between profiling and scanner execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Callable

from .models import ProfileResult


class ReviewAction(str, Enum):
    APPROVE_PLAN = "approve_plan"
    BROAD_SCAN = "broad_scan"
    CANCEL = "cancel"


@dataclass(frozen=True)
class ReviewDecision:
    """A recorded decision; it does not execute or mutate any scanner task."""

    action: ReviewAction
    execution_scope: str
    profile_status: str
    coverage_gaps: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def approved(self) -> bool:
        return self.action is not ReviewAction.CANCEL

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["action"] = self.action.value
        return payload


def create_review_decision(result: ProfileResult, action: ReviewAction) -> ReviewDecision:
    """Create a decision from a profile without changing the profile or scan plan."""
    scope = {
        ReviewAction.APPROVE_PLAN: "planned",
        ReviewAction.BROAD_SCAN: "broad",
        ReviewAction.CANCEL: "none",
    }[action]
    return ReviewDecision(
        action=action,
        execution_scope=scope,
        profile_status=result.profile.completeness.value,
        coverage_gaps=result.profile.coverage_gaps,
        warnings=tuple(sorted(set(result.profile.warnings + result.scan_plan.warnings))),
    )


def prompt_for_review(
    result: ProfileResult,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> ReviewDecision:
    """Display a concise review summary and ask for an explicit user decision."""
    profile = result.profile
    plan = result.scan_plan
    output_fn("\nProject profile review")
    output_fn(f"Project: {profile.root_name}")
    output_fn(f"Status: {profile.completeness.value}")
    output_fn(f"Components: {len(profile.components)} | Planned tasks: {len(plan.tasks)}")
    if profile.coverage_gaps:
        output_fn("Coverage gaps:")
        for gap in profile.coverage_gaps:
            output_fn(f"- {gap}")
    if profile.warnings:
        output_fn("Warnings:")
        for warning in profile.warnings:
            output_fn(f"- {warning}")
    output_fn("\nChoose an action:")
    output_fn("1. Approve the planned scan")
    output_fn("2. Run broad coverage scan")
    output_fn("3. Cancel before scanner execution")
    choice = input_fn("Choice [1/2/3]: ").strip()
    action = {"1": ReviewAction.APPROVE_PLAN, "2": ReviewAction.BROAD_SCAN}.get(
        choice, ReviewAction.CANCEL
    )
    return create_review_decision(result, action)

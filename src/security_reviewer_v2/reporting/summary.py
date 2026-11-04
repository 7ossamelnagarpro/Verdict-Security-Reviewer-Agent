"""Small, deterministic briefing shared by the Markdown and HTML reports.

Counts refer to saved records, not to independently proven vulnerabilities.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

ACTIONABLE_VERDICTS = {
    "confirmed_vulnerability",
    "likely_vulnerability",
    "likely_vulnerable",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _records(value: Any) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def build_summary(
    *,
    review: dict[str, Any],
    policy: dict[str, Any],
    merged: dict[str, Any] | None = None,
    runtime_evidence: dict[str, Any] | None = None,
    scanner_requirement: dict[str, Any] | None = None,
    discovery_required_satisfied: bool | None = None,
    coverage_gaps: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Summarize the run without promoting observations to proven issues."""
    reviews = _records(review.get("reviews"))
    observations = _records((merged or {}).get("findings"))
    decisions = _records(policy.get("decisions"))
    decision_by_id = {str(item.get("candidate_id")): item for item in decisions}
    verdicts = Counter(str(item.get("verdict") or "unknown") for item in reviews)
    actionable = [
        item for item in reviews if item.get("verdict") in ACTIONABLE_VERDICTS
    ]
    severities = Counter(
        str(item.get("severity") or "unknown").lower() for item in actionable
    )
    pending = (
        review.get("pending_ids") if isinstance(review.get("pending_ids"), list) else []
    )

    runtime = runtime_evidence if isinstance(runtime_evidence, dict) else {}
    workflow = (
        runtime.get("workflow_evidence")
        if isinstance(runtime.get("workflow_evidence"), dict)
        else {}
    )
    workflow_counts = (
        workflow.get("coverage") if isinstance(workflow.get("coverage"), dict) else {}
    )
    zap = runtime.get("zap") if isinstance(runtime.get("zap"), dict) else {}
    browser = runtime.get("browser") if isinstance(runtime.get("browser"), dict) else {}

    gaps = list(coverage_gaps or ())
    if isinstance(runtime.get("coverage_notes"), list):
        gaps.extend(runtime["coverage_notes"])
    if scanner_requirement and isinstance(scanner_requirement.get("failures"), list):
        gaps.extend(scanner_requirement["failures"])
    gap_count = len({str(gap) for gap in gaps if gap})

    review_complete = review.get("status") == "completed" and not pending
    required_scanners_ok = not (scanner_requirement or {}).get("requested") or bool(
        scanner_requirement.get("satisfied")
    )
    runtime_complete = not runtime or runtime.get("status") == "completed"
    stages_complete = (
        review_complete
        and required_scanners_ok
        and discovery_required_satisfied is True
        and runtime_complete
    )

    def priority(item: dict[str, Any]) -> tuple[int, int, str]:
        action = decision_by_id.get(str(item.get("candidate_id")), {}).get("action")
        return (
            0 if action == "block" else 1,
            SEVERITY_ORDER.get(str(item.get("severity") or "").lower(), 5),
            str(item.get("candidate_id") or ""),
        )

    first_actions = []
    for item in sorted(actionable, key=priority)[:5]:
        first_actions.append(
            {
                "id": str(item.get("candidate_id") or "unknown"),
                "title": str(item.get("title") or "Untitled issue group"),
                "severity": str(item.get("severity") or "unknown"),
                "verdict": str(item.get("verdict") or "unknown"),
                "action": str(
                    decision_by_id.get(str(item.get("candidate_id")), {}).get("action")
                    or "not set"
                ),
                "impact": str(item.get("impact") or "Not recorded."),
                "remediation": str(item.get("remediation") or "Not recorded."),
            }
        )

    return {
        "stage_status": "Review stages complete"
        if stages_complete
        else "Review incomplete or unverified",
        "reviewed_groups": len(reviews),
        "pending_groups": len(pending),
        "observations": len(observations),
        "dast_observations": sum(
            "dast" in (item.get("categories") or []) for item in observations
        ),
        "verdicts": dict(verdicts),
        "actionable_groups": len(actionable),
        "actionable_severities": dict(severities),
        "policy_blocks": sum(item.get("action") == "block" for item in decisions),
        "policy_status": str(policy.get("status") or "unknown"),
        "policy_blocking": policy.get("blocking") is True,
        "required_scanners": (
            "satisfied" if scanner_requirement.get("satisfied") else "incomplete"
        )
        if scanner_requirement and scanner_requirement.get("requested")
        else "not required",
        "ai_discovery": ("satisfied" if discovery_required_satisfied else "incomplete")
        if discovery_required_satisfied is not None
        else "not verified",
        "runtime_status": str(runtime.get("status") or "not supplied"),
        "baseline_probes": len(runtime.get("results"))
        if isinstance(runtime.get("results"), list)
        else 0,
        "zap_status": str(zap.get("status") or "not requested"),
        "zap_alerts": zap.get("alerts", 0),
        "browser_status": str(browser.get("status") or "not requested"),
        "workflow_status": str(workflow.get("status") or "not requested"),
        "workflow_executed": workflow_counts.get("executed", 0),
        "workflow_violations": workflow_counts.get("violations", 0),
        "workflow_unresolved": workflow_counts.get("unresolved", 0),
        "coverage_gaps": gap_count,
        "first_actions": first_actions,
    }

"""Apply release policy after semantic security review."""

from __future__ import annotations

from typing import Any

from .models import PolicyDecision, PolicyResult


def evaluate_policy(
    review_payload: dict[str, Any],
    *,
    block_severities: frozenset[str] = frozenset({"critical", "high"}),
    triage_payload: dict[str, Any] | None = None,
) -> PolicyResult:
    decisions: list[PolicyDecision] = []
    for item in review_payload.get("reviews", []):
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("candidate_id", "unknown"))
        severity = str(item.get("severity", "unknown")).lower()
        verdict = str(item.get("verdict", "needs_more_evidence"))
        if verdict == "confirmed_vulnerability" and severity in block_severities:
            action, reason = (
                "block",
                f"{severity} confirmed vulnerability violates release policy.",
            )
        elif verdict == "likely_vulnerability" and severity in block_severities:
            action, reason = (
                "warn",
                f"{severity} likely vulnerability requires manual review; not auto-confirmed.",
            )
        elif verdict == "false_positive":
            action, reason = "allow", "Finding was classified as a false positive."
        else:
            action, reason = (
                "warn",
                "Finding is not sufficiently confirmed for an automatic block.",
            )
        decisions.append(
            PolicyDecision(candidate_id, action, severity, verdict, reason)
        )
    blocking = any(item.action == "block" for item in decisions)
    unresolved = tuple(
        item
        for item in (triage_payload or {}).get("records", [])
        if isinstance(item, dict)
        and item.get("disposition") in {"needs_more_evidence", "uncertain_overlap"}
    )
    review_incomplete = review_payload.get("status") != "completed" or bool(
        review_payload.get("pending_ids")
    )
    status = (
        "failed"
        if blocking
        else ("incomplete" if review_incomplete or unresolved else "passed")
    )
    warnings = (
        tuple(item.reason for item in decisions if item.action == "warn")
        + (
            (
                f"{len(unresolved)} AI candidates remain unresolved; they are not confirmed vulnerabilities.",
            )
            if unresolved
            else ()
        )
        + (
            (
                "Security review is incomplete; unreviewed issue groups must not be treated as safe.",
            )
            if review_incomplete
            else ()
        )
    )
    return PolicyResult("1.0", status, blocking, tuple(decisions), warnings)

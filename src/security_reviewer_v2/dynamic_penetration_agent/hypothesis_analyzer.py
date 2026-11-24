"""Section 3, phase 1: understand the suspicion before planning anything.

This stays read-only and deterministic: it classifies the candidate's category into one of the three
phase-1 templates, decides whether a route is available to test, and tracks which strategies have
already been tried for this hypothesis so the controller never repeats an identical attempt without a
new reason (section 4).
"""

from __future__ import annotations

from dataclasses import dataclass

from security_reviewer_v2.discovery.models import CandidateFinding

from .models import TestStrategy

_IDOR_HINTS = ("idor", "object reference", "ownership", "other user", "another user", "belongs to")
_AUTH_HINTS = ("authorization", "access control", "permission", "broken access", "role")
_PRIVILEGE_HINTS = ("privilege", "admin-only", "admin access", "elevated", "superuser", "escalation")


@dataclass(frozen=True)
class HypothesisAssessment:
    candidate_id: str
    hypothesis: str
    entry_point: str | None
    testable: bool
    reason: str
    candidate_strategies: tuple[TestStrategy, ...]


def assess(candidate: CandidateFinding, *, target_endpoint: str | None) -> HypothesisAssessment:
    """Decide testability and the ordered strategies worth trying for this one candidate."""
    hypothesis = f"{candidate.title}: {candidate.category}"
    entry_point = candidate.entry_point.code if candidate.entry_point else None
    text = f"{candidate.title} {candidate.category} {candidate.reasoning}".casefold()

    if not target_endpoint:
        return HypothesisAssessment(candidate.candidate_id, hypothesis, entry_point, False,
                                    "No HTTP route could be resolved for this candidate from source or the "
                                    "Runtime Contract; there is nothing a read-only HTTP probe can test.", ())

    strategies: list[TestStrategy] = []
    has_idor_hint = any(hint in text for hint in _IDOR_HINTS)
    if has_idor_hint:
        strategies.append(TestStrategy.IDOR)
    if any(hint in text for hint in _PRIVILEGE_HINTS):
        strategies.append(TestStrategy.PRIVILEGE_ESCALATION)
    if any(hint in text for hint in _AUTH_HINTS):
        strategies.append(TestStrategy.AUTHORIZATION_MATRIX)
    # Unauthenticated access is always a cheap, safe first probe for a route-bearing candidate, regardless
    # of how the candidate is categorized.
    strategies.append(TestStrategy.UNAUTHENTICATED_ACCESS)
    # These framework-level bypass probes (HEAD-vs-GET, trailing slash, re-casing, dot-segment detour,
    # a fixed suffix list) are generic to almost any route-level access-control hypothesis, not gated on
    # specific wording, so the rule-based fallback always offers them too — not just the AI planner.
    strategies += [TestStrategy.HEAD_METHOD_BYPASS, TestStrategy.TRAILING_SLASH_BYPASS,
                  TestStrategy.CASE_SENSITIVITY_BYPASS, TestStrategy.PATH_NORMALIZATION_BYPASS,
                  TestStrategy.EXTENSION_SUFFIX_BYPASS]
    if has_idor_hint:
        strategies.append(TestStrategy.IDOR_PARAMETER_POLLUTION)
    ordered = tuple(dict.fromkeys(strategies))

    return HypothesisAssessment(candidate.candidate_id, hypothesis, entry_point, True,
                                "Resolved a target HTTP route and at least one applicable template.", ordered)


def next_strategy(
    assessment: HypothesisAssessment, *, tried: tuple[TestStrategy, ...],
) -> TestStrategy | None:
    """The next untried strategy, or ``None`` when every applicable template has already been attempted."""
    for strategy in assessment.candidate_strategies:
        if strategy not in tried:
            return strategy
    return None

"""Deterministic, explainable prioritization of merged findings."""

from __future__ import annotations

from dataclasses import dataclass

from security_reviewer_v2.context.models import ContextResult, EvidenceContext, FindingContext
from security_reviewer_v2.normalization.merge_models import MergeResult, MergedFinding

from .models import (
    RISK_POLICY_VERSION,
    RISK_SCHEMA_VERSION,
    PrioritizedFinding,
    PriorityBand,
    ReviewDisposition,
    RiskFactor,
    RiskPolicy,
    RiskResult,
    RiskStatus,
    RiskSummary,
)


SEVERITY_POINTS = {
    "critical": 50,
    "high": 40,
    "medium": 25,
    "low": 10,
    "info": 0,
    "unknown": 5,
}

CONFIDENCE_POINTS = {
    "high": 12,
    "medium": 7,
    "low": 2,
    "unknown": 0,
}

CWE_IMPACT_POINTS = {
    "CWE-94": 18,
    "CWE-78": 16,
    "CWE-89": 12,
    "CWE-502": 12,
    "CWE-918": 12,
    "CWE-798": 10,
    "CWE-22": 8,
    "CWE-79": 8,
}

EXTERNAL_INPUT_SIGNALS = {
    "flask_request_args": "request.args",
    "flask_request_form": "request.form",
    "flask_request_values": "request.values",
    "flask_request_json": "request.get_json",
    "generic_request_json": "request.json",
    "express_query": "req.query",
    "express_body": "req.body",
    "servlet_parameter": "getparameter(",
    "command_line_input": "input(",
}


@dataclass(frozen=True)
class _Assessment:
    finding: MergedFinding
    score: int
    band: PriorityBand
    factors: tuple[RiskFactor, ...]
    context_available: bool


def prioritize_findings(
    merged: MergeResult,
    context: ContextResult,
    *,
    policy: RiskPolicy | None = None,
) -> RiskResult:
    """Rank every finding while selecting only bounded deep-review candidates."""
    selected_policy = policy or RiskPolicy()
    selected_policy.validate()
    context_by_id = {item.merged_finding_id: item for item in context.findings}
    assessments = [
        _assess(finding, context_by_id.get(finding.merged_finding_id))
        for finding in merged.findings
    ]
    assessments.sort(key=_assessment_sort_key)

    ranked: list[PrioritizedFinding] = []
    deep_review_slots = selected_policy.max_deep_reviews
    for rank, assessment in enumerate(assessments, start=1):
        qualifies = assessment.score >= selected_policy.deep_review_threshold
        if not assessment.context_available:
            disposition = ReviewDisposition.NEEDS_VERIFICATION
            selected = False
        elif qualifies and deep_review_slots > 0:
            disposition = ReviewDisposition.DEEP_REVIEW
            selected = True
            deep_review_slots -= 1
        elif qualifies:
            disposition = ReviewDisposition.QUEUED_FOR_DEEP_REVIEW
            selected = False
        else:
            disposition = ReviewDisposition.STANDARD_REPORT
            selected = False
        finding = assessment.finding
        ranked.append(
            PrioritizedFinding(
                rank=rank,
                merged_finding_id=finding.merged_finding_id,
                title=finding.canonical_finding.title,
                primary_location=finding.primary_location,
                scanner_severity=finding.severity.value,
                scanner_confidence=finding.confidence.value,
                cwes=finding.cwes,
                scanners=finding.scanners,
                risk_score=assessment.score,
                priority_band=assessment.band,
                review_disposition=disposition,
                selected_for_deep_review=selected,
                factors=assessment.factors,
            )
        )

    merged_ids = {item.merged_finding_id for item in merged.findings}
    extra_context_ids = sorted(set(context_by_id) - merged_ids)
    missing_context_ids = sorted(merged_ids - set(context_by_id))
    warnings = list(merged.warnings) + list(context.warnings)
    gaps = list(merged.coverage_gaps) + list(context.coverage_gaps)
    if extra_context_ids:
        warnings.append(
            "Context contains findings absent from the merged artifact: "
            + ", ".join(extra_context_ids)
        )
    if missing_context_ids:
        gaps.append(
            "Merged findings have no context package: " + ", ".join(missing_context_ids)
        )

    if merged.status.value == "failed":
        status = RiskStatus.FAILED
    elif (
        merged.status.value != "complete"
        or context.status.value != "complete"
        or missing_context_ids
    ):
        status = RiskStatus.PARTIAL
    else:
        status = RiskStatus.COMPLETE
    summary = RiskSummary(
        input_findings=len(merged.findings),
        ranked_findings=len(ranked),
        selected_for_deep_review=sum(item.selected_for_deep_review for item in ranked),
        queued_for_deep_review=sum(
            item.review_disposition == ReviewDisposition.QUEUED_FOR_DEEP_REVIEW
            for item in ranked
        ),
        standard_report=sum(
            item.review_disposition == ReviewDisposition.STANDARD_REPORT for item in ranked
        ),
        needs_verification=sum(
            item.review_disposition == ReviewDisposition.NEEDS_VERIFICATION for item in ranked
        ),
    )
    return RiskResult(
        schema_version=RISK_SCHEMA_VERSION,
        policy_version=RISK_POLICY_VERSION,
        status=status,
        policy=selected_policy,
        findings=tuple(ranked),
        warnings=tuple(sorted(set(warnings))),
        coverage_gaps=tuple(sorted(set(gaps))),
        summary=summary,
    )


def _assess(finding: MergedFinding, context: FindingContext | None) -> _Assessment:
    factors: list[RiskFactor] = []
    severity = finding.severity.value
    severity_points = SEVERITY_POINTS.get(severity, SEVERITY_POINTS["unknown"])
    factors.append(
        RiskFactor("scanner_severity", "Scanner severity", severity_points, (severity,))
    )
    confidence = finding.confidence.value
    confidence_points = CONFIDENCE_POINTS.get(confidence, 0)
    factors.append(
        RiskFactor("scanner_confidence", "Scanner confidence", confidence_points, (confidence,))
    )

    matched_cwes = [(cwe, CWE_IMPACT_POINTS[cwe]) for cwe in finding.cwes if cwe in CWE_IMPACT_POINTS]
    if matched_cwes:
        cwe, points = max(matched_cwes, key=lambda item: (item[1], item[0]))
        factors.append(RiskFactor("cwe_impact", "Known impact class", points, (cwe,)))
    if len(finding.scanners) > 1:
        factors.append(
            RiskFactor(
                "scanner_corroboration",
                "Independent scanner support",
                8,
                finding.scanners,
            )
        )

    context_available = context is not None and context.primary.excerpt is not None
    if context is None:
        factors.append(
            RiskFactor("missing_context", "Context unavailable", -15, ("no context package",))
        )
    elif context.primary.excerpt is None:
        factors.append(
            RiskFactor("missing_primary_context", "Primary context unavailable", -20, context.warnings)
        )
    else:
        collected_flow = tuple(item for item in context.code_flow if item.excerpt is not None)
        if len(collected_flow) >= 2:
            flow_files = tuple(sorted({item.location.path for item in collected_flow}))
            factors.append(
                RiskFactor(
                    "scanner_data_flow",
                    "Scanner-provided data flow",
                    10,
                    (f"{len(collected_flow)} steps", f"{len(flow_files)} files"),
                )
            )
        external_signals = _external_signals(context)
        if external_signals:
            factors.append(
                RiskFactor(
                    "external_input",
                    "External input signal in collected flow",
                    12,
                    external_signals,
                )
            )

    score = max(0, min(100, sum(item.points for item in factors)))
    return _Assessment(finding, score, _priority_band(score), tuple(factors), context_available)


def _external_signals(context: FindingContext) -> tuple[str, ...]:
    signals: set[str] = set()
    for evidence in context.code_flow:
        text = _evidence_text(evidence).casefold()
        for signal_id, token in EXTERNAL_INPUT_SIGNALS.items():
            if token in text:
                signals.add(signal_id)
    return tuple(sorted(signals))


def _evidence_text(evidence: EvidenceContext) -> str:
    parts = [evidence.message or ""]
    if evidence.excerpt is not None:
        parts.append(evidence.excerpt.code)
    return "\n".join(parts)


def _priority_band(score: int) -> PriorityBand:
    if score >= 85:
        return PriorityBand.CRITICAL
    if score >= 65:
        return PriorityBand.HIGH
    if score >= 35:
        return PriorityBand.MEDIUM
    return PriorityBand.LOW


def _assessment_sort_key(item: _Assessment) -> tuple[object, ...]:
    finding = item.finding
    return (
        -item.score,
        finding.primary_location.path.casefold(),
        finding.primary_location.start_line or 0,
        finding.merged_finding_id,
    )

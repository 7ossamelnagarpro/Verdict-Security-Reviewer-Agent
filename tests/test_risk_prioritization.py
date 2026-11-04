"""Behavioral tests for explainable risk prioritization."""

from __future__ import annotations

import json
from pathlib import Path

from security_reviewer_v2.context import ContextStatus, load_context_result
from security_reviewer_v2.context.models import (
    ContextResult,
    ContextSummary,
    EvidenceContext,
    FindingContext,
    SourceExcerpt,
)
from security_reviewer_v2.normalization.merge_models import (
    MergedFinding,
    MergeResult,
    MergeStatus,
    MergeSummary,
    SourceCoverage,
)
from security_reviewer_v2.normalization.models import (
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    ScannerProvenance,
    UnifiedFinding,
)
from security_reviewer_v2.prioritization import (
    PriorityBand,
    ReviewDisposition,
    RiskPolicy,
    RiskStatus,
    prioritize_findings,
)


def merged_finding(
    finding_id: str,
    *,
    path: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    cwes: tuple[str, ...] = ("CWE-89",),
    scanners: tuple[str, ...] = ("codeql-cli",),
) -> MergedFinding:
    location = FindingLocation(path, 10, 1, 10, 8)
    source = UnifiedFinding(
        finding_id=f"source-{finding_id}",
        schema_version="1.0",
        scanner=ScannerProvenance(scanners[0], scanners[0], "test", 0, 0, None),
        rule_id="sql-injection",
        title="SQL Injection",
        description=None,
        message="User input reaches SQL execution",
        severity=severity,
        security_severity_score=None,
        confidence=confidence,
        cwes=cwes,
        categories=("security",),
        primary_location=location,
        code_flow=(),
        related_locations=(),
        fingerprints={},
        rule_kind="path-problem",
        rule_help_uri=None,
    )
    return MergedFinding(
        merged_finding_id=finding_id,
        schema_version="1.0",
        canonical_finding=source,
        source_findings=(source,),
        scanners=scanners,
        rule_ids=(source.rule_id,),
        severity=severity,
        confidence=confidence,
        cwes=cwes,
        categories=("security",),
        primary_location=location,
        merge_reasons=("single_source_finding",),
    )


def merge_result(*findings: MergedFinding) -> MergeResult:
    return MergeResult(
        schema_version="1.0",
        status=MergeStatus.COMPLETE,
        findings=findings,
        source_coverage=(
            SourceCoverage(
                "codeql-cli", "codeql-sarif-2.1", "complete", len(findings), 0, 0
            ),
        ),
        warnings=(),
        coverage_gaps=(),
        summary=MergeSummary(1, len(findings), len(findings), 0),
    )


def evidence(
    path: str,
    line: int,
    *,
    code: str,
    evidence_type: str,
    step: int | None = None,
    available: bool = True,
) -> EvidenceContext:
    location = FindingLocation(path, line, 1, line, 8)
    excerpt = SourceExcerpt(path, line, line, code, "digest") if available else None
    return EvidenceContext(
        evidence_type=evidence_type,
        scanner_id="codeql-cli",
        rule_id="sql-injection",
        location=location,
        message=None,
        flow_index=0 if step is not None else None,
        thread_index=0 if step is not None else None,
        step_index=step,
        excerpt=excerpt,
        enclosing_symbol=None,
        collection_status="collected" if available else "unavailable",
        warning=None if available else "source_unavailable",
    )


def finding_context(
    finding: MergedFinding,
    *,
    external_flow: bool = True,
    primary_available: bool = True,
) -> FindingContext:
    flow = ()
    if external_flow:
        flow = (
            evidence(
                "app.py",
                5,
                code='5 | username = request.args.get("username")',
                evidence_type="code_flow",
                step=0,
            ),
            evidence(
                finding.primary_location.path,
                10,
                code="10 | execute(query)",
                evidence_type="code_flow",
                step=1,
            ),
        )
    return FindingContext(
        merged_finding_id=finding.merged_finding_id,
        title=finding.canonical_finding.title,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        cwes=finding.cwes,
        scanners=finding.scanners,
        primary=evidence(
            finding.primary_location.path,
            10,
            code="10 | execute(query)",
            evidence_type="primary",
            available=primary_available,
        ),
        code_flow=flow,
        related=(),
        warnings=() if primary_available else ("source_unavailable",),
    )


def context_result(
    *contexts: FindingContext, status: ContextStatus = ContextStatus.COMPLETE
) -> ContextResult:
    return ContextResult(
        schema_version="1.0",
        status=status,
        project_root="/project",
        findings=contexts,
        warnings=(),
        coverage_gaps=(),
        summary=ContextSummary(len(contexts), len(contexts), 0, 0, 0, 0, 0),
    )


def test_high_confidence_external_sql_flow_is_selected_for_deep_review() -> None:
    finding = merged_finding("high", path="db.py")

    result = prioritize_findings(
        merge_result(finding), context_result(finding_context(finding))
    )

    item = result.findings[0]
    assert result.status == RiskStatus.COMPLETE
    assert item.risk_score == 86
    assert item.priority_band == PriorityBand.CRITICAL
    assert item.review_disposition == ReviewDisposition.DEEP_REVIEW
    assert {factor.factor_id for factor in item.factors} >= {
        "scanner_severity",
        "scanner_confidence",
        "cwe_impact",
        "scanner_data_flow",
        "external_input",
    }


def test_low_priority_finding_remains_in_standard_report() -> None:
    finding = merged_finding(
        "low",
        path="style.py",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.LOW,
        cwes=(),
    )

    result = prioritize_findings(
        merge_result(finding),
        context_result(finding_context(finding, external_flow=False)),
    )

    assert result.summary.ranked_findings == 1
    assert result.summary.standard_report == 1
    assert result.findings[0].review_disposition == ReviewDisposition.STANDARD_REPORT


def test_top_n_queues_extra_high_findings_without_dropping_them() -> None:
    first = merged_finding("first", path="a.py")
    second = merged_finding("second", path="b.py")

    result = prioritize_findings(
        merge_result(first, second),
        context_result(finding_context(first), finding_context(second)),
        policy=RiskPolicy(max_deep_reviews=1),
    )

    assert len(result.findings) == 2
    assert result.summary.selected_for_deep_review == 1
    assert result.summary.queued_for_deep_review == 1
    assert {item.review_disposition for item in result.findings} == {
        ReviewDisposition.DEEP_REVIEW,
        ReviewDisposition.QUEUED_FOR_DEEP_REVIEW,
    }


def test_scanner_corroboration_adds_bounded_points() -> None:
    one = merged_finding("one", path="a.py")
    two = merged_finding("two", path="b.py", scanners=("codeql-cli", "semgrep-ce"))

    result = prioritize_findings(
        merge_result(one, two),
        context_result(finding_context(one), finding_context(two)),
    )
    scores = {item.merged_finding_id: item.risk_score for item in result.findings}

    assert scores["two"] == min(100, scores["one"] + 8)


def test_missing_context_routes_to_verification_and_marks_partial() -> None:
    finding = merged_finding("missing", path="db.py")

    result = prioritize_findings(merge_result(finding), context_result())

    assert result.status == RiskStatus.PARTIAL
    assert result.findings[0].review_disposition == ReviewDisposition.NEEDS_VERIFICATION
    assert result.summary.needs_verification == 1
    assert result.coverage_gaps


def test_unavailable_primary_context_is_not_sent_to_deep_review() -> None:
    finding = merged_finding("missing-primary", path="db.py")
    context = finding_context(finding, primary_available=False)

    result = prioritize_findings(
        merge_result(finding),
        context_result(context, status=ContextStatus.PARTIAL),
    )

    assert result.findings[0].review_disposition == ReviewDisposition.NEEDS_VERIFICATION
    assert result.findings[0].selected_for_deep_review is False


def test_unknown_cwe_does_not_receive_invented_impact_points() -> None:
    finding = merged_finding("unknown", path="db.py", cwes=("CWE-9999",))

    result = prioritize_findings(
        merge_result(finding),
        context_result(finding_context(finding, external_flow=False)),
    )

    assert "cwe_impact" not in {
        factor.factor_id for factor in result.findings[0].factors
    }


def test_ranking_is_deterministic_for_equal_scores() -> None:
    a = merged_finding("a", path="a.py")
    b = merged_finding("b", path="b.py")
    contexts = context_result(finding_context(a), finding_context(b))

    first = prioritize_findings(merge_result(b, a), contexts).to_dict()
    second = prioritize_findings(merge_result(a, b), contexts).to_dict()

    assert first == second
    assert [item["merged_finding_id"] for item in first["findings"]] == ["a", "b"]


def test_context_artifact_round_trip(tmp_path: Path) -> None:
    finding = merged_finding("one", path="db.py")
    original = context_result(finding_context(finding))
    artifact = tmp_path / "context.json"
    artifact.write_text(json.dumps(original.to_dict()), encoding="utf-8")

    loaded = load_context_result(artifact)

    assert loaded.to_dict() == original.to_dict()

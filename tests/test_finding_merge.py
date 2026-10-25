"""Behavioral tests for conservative cross-scanner deduplication."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from security_reviewer_v2.normalization import (
    DeduplicationPolicy,
    MergeStatus,
    load_normalization_result,
    merge_normalized_findings,
)
from security_reviewer_v2.normalization.models import (
    CodeFlowStep,
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    NormalizationResult,
    NormalizationStatus,
    NormalizationSummary,
    NormalizationWarning,
    ScannerProvenance,
    UnifiedFinding,
)


def finding(
    scanner: str,
    *,
    finding_id: str,
    path: str = "src/db.py",
    line: int = 20,
    cwes: tuple[str, ...] = ("CWE-89",),
    rule_id: str = "sql-injection",
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    flow_steps: int = 0,
    fingerprint: str | None = None,
) -> UnifiedFinding:
    location = FindingLocation(path, line, 1, line, 5)
    flow = tuple(
        CodeFlowStep(0, 0, index, location, f"step {index}", None)
        for index in range(flow_steps)
    )
    return UnifiedFinding(
        finding_id=finding_id,
        schema_version="1.0",
        scanner=ScannerProvenance(scanner, scanner, "test", 0, 0, None),
        rule_id=rule_id,
        title="SQL Injection" if "sql" in rule_id else rule_id,
        description=None,
        message="User input reaches SQL execution",
        severity=severity,
        security_severity_score=8.8 if severity == FindingSeverity.HIGH else None,
        confidence=confidence,
        cwes=cwes,
        categories=("security",),
        primary_location=location,
        code_flow=flow,
        related_locations=(),
        fingerprints={"scanner": fingerprint} if fingerprint else {},
        rule_kind="path-problem",
        rule_help_uri=None,
    )


def batch(
    scanner: str,
    *findings: UnifiedFinding,
    status: NormalizationStatus = NormalizationStatus.COMPLETE,
    warnings: tuple[NormalizationWarning, ...] = (),
) -> NormalizationResult:
    source_format = "codeql-sarif-2.1" if scanner == "codeql-cli" else "semgrep-json"
    return NormalizationResult(
        schema_version="1.0",
        source_format=source_format,
        status=status,
        findings=findings,
        warnings=warnings,
        summary=NormalizationSummary(1, len(findings), len(findings), 0),
    )


def test_same_cwe_file_and_nearby_line_merge_across_scanners() -> None:
    codeql = finding("codeql-cli", finding_id="codeql-one", line=20, flow_steps=5)
    semgrep = finding("semgrep-ce", finding_id="semgrep-one", line=22)

    result = merge_normalized_findings(
        (batch("codeql-cli", codeql), batch("semgrep-ce", semgrep)),
        policy=DeduplicationPolicy(line_tolerance=5),
    )

    assert result.status == MergeStatus.COMPLETE
    assert result.summary.input_findings == 2
    assert result.summary.merged_findings == 1
    assert result.summary.duplicates_collapsed == 1
    merged = result.findings[0]
    assert merged.scanners == ("codeql-cli", "semgrep-ce")
    assert merged.canonical_finding.finding_id == "codeql-one"
    assert "independent_scanner_support" in merged.merge_reasons


def test_different_cwes_do_not_merge_even_when_locations_are_close() -> None:
    left = finding("codeql-cli", finding_id="one", cwes=("CWE-89",))
    right = finding("semgrep-ce", finding_id="two", cwes=("CWE-78",), line=21)

    result = merge_normalized_findings((batch("codeql-cli", left), batch("semgrep-ce", right)))

    assert result.summary.merged_findings == 2
    assert result.summary.duplicates_collapsed == 0


def test_different_files_do_not_merge() -> None:
    left = finding("codeql-cli", finding_id="one", path="a.py")
    right = finding("semgrep-ce", finding_id="two", path="b.py")

    result = merge_normalized_findings((batch("codeql-cli", left), batch("semgrep-ce", right)))

    assert result.summary.merged_findings == 2


def test_line_tolerance_is_configurable() -> None:
    left = finding("codeql-cli", finding_id="one", line=10)
    right = finding("semgrep-ce", finding_id="two", line=13)

    strict = merge_normalized_findings(
        (batch("codeql-cli", left), batch("semgrep-ce", right)),
        policy=DeduplicationPolicy(line_tolerance=2),
    )
    relaxed = merge_normalized_findings(
        (batch("codeql-cli", left), batch("semgrep-ce", right)),
        policy=DeduplicationPolicy(line_tolerance=3),
    )

    assert strict.summary.merged_findings == 2
    assert relaxed.summary.merged_findings == 1


def test_default_policy_does_not_merge_nearby_but_distinct_lines() -> None:
    left = finding("codeql-cli", finding_id="one", line=20)
    right = finding("semgrep-ce", finding_id="two", line=21)

    result = merge_normalized_findings((
        batch("codeql-cli", left), batch("semgrep-ce", right)
    ))

    assert result.summary.merged_findings == 2


def test_same_scanner_nearby_findings_remain_separate_without_fingerprint() -> None:
    left = finding("semgrep-ce", finding_id="one", line=10)
    right = finding("semgrep-ce", finding_id="two", line=11)

    result = merge_normalized_findings((batch("semgrep-ce", left, right),))

    assert result.summary.merged_findings == 2


def test_same_scanner_reliable_fingerprint_deduplicates_exact_repeat() -> None:
    left = finding("semgrep-ce", finding_id="one", fingerprint="stable")
    right = finding("semgrep-ce", finding_id="two", fingerprint="stable")

    result = merge_normalized_findings((batch("semgrep-ce", left, right),))

    assert result.summary.merged_findings == 1


def test_codeql_column_fingerprint_does_not_merge_unrelated_results() -> None:
    first = replace(
        finding("codeql-cli", finding_id="one", line=20, rule_id="py/reflective-xss", cwes=("CWE-79",)),
        fingerprints={"primaryLocationStartColumnFingerprint": "7"},
    )
    second = replace(
        finding("codeql-cli", finding_id="two", line=80, rule_id="py/reflective-xss", cwes=("CWE-79",)),
        fingerprints={"primaryLocationStartColumnFingerprint": "7"},
    )

    result = merge_normalized_findings((batch("codeql-cli", first, second),))

    assert result.summary.merged_findings == 2


def test_cross_scanner_chain_cannot_exceed_total_line_tolerance() -> None:
    first = finding("codeql-cli", finding_id="one", line=10)
    bridge = finding("semgrep-ce", finding_id="two", line=14)
    last = finding("codeql-cli", finding_id="three", line=18)

    result = merge_normalized_findings((
        batch("codeql-cli", first, last), batch("semgrep-ce", bridge)
    ), policy=DeduplicationPolicy(line_tolerance=5))

    assert result.summary.merged_findings == 2
    assert max(len(item.source_findings) for item in result.findings) == 2


def test_different_security_families_at_same_line_remain_separate() -> None:
    xss = replace(
        finding("codeql-cli", finding_id="xss", rule_id="py/reflective-xss", cwes=("CWE-79",)),
        fingerprints={"primaryLocationLineHash": "same-line"},
    )
    stacktrace = replace(
        finding("codeql-cli", finding_id="trace", rule_id="py/stack-trace-exposure", cwes=("CWE-209",)),
        fingerprints={"primaryLocationLineHash": "same-line"},
    )

    result = merge_normalized_findings((batch("codeql-cli", xss, stacktrace),))

    assert result.summary.merged_findings == 2


def test_same_family_same_line_different_rules_are_one_root_cause_with_all_evidence() -> None:
    # Root-cause deduplication: two Semgrep rules flagging the same XSS sink are one issue,
    # but both rule ids and both source findings stay in the merged record.
    first = finding("semgrep-ce", finding_id="one", line=20, rule_id="xss-rule-a", cwes=("CWE-79",))
    second = finding("semgrep-ce", finding_id="two", line=20, rule_id="xss-rule-b", cwes=("CWE-79",))

    result = merge_normalized_findings((batch("semgrep-ce", first, second),))

    assert result.summary.merged_findings == 1 and result.summary.duplicates_collapsed == 1
    merged = result.findings[0]
    assert {item.finding_id for item in merged.source_findings} == {"one", "two"}
    assert merged.rule_ids == ("xss-rule-a", "xss-rule-b")
    assert "root_cause:xss" in merged.merge_reasons and "same_scanner_multiple_rules" in merged.merge_reasons


def test_root_cause_dedup_can_be_disabled_and_other_families_stay_separate() -> None:
    first = finding("semgrep-ce", finding_id="one", line=20, rule_id="xss-rule-a", cwes=("CWE-79",))
    second = finding("semgrep-ce", finding_id="two", line=20, rule_id="xss-rule-b", cwes=("CWE-79",))
    other = finding("semgrep-ce", finding_id="three", line=20, rule_id="sql-injection", cwes=("CWE-89",))

    off = merge_normalized_findings((batch("semgrep-ce", first, second),),
                                    policy=DeduplicationPolicy(root_cause_dedup=False))
    assert off.summary.merged_findings == 2
    mixed = merge_normalized_findings((batch("semgrep-ce", first, second, other),))
    assert mixed.summary.merged_findings == 2  # XSS pair merged; SQLi on the same line is a different issue


def test_overlapping_ranges_and_cwe_aliases_merge_by_root_cause() -> None:
    # Real run_v27 pattern: the same cursor.execute statement reported at 145-152, 146-152 and as
    # "tainted-sql-string" (CWE-704) at line 148.
    def ranged(fid: str, start: int, end: int, rule: str, cwes: tuple[str, ...]):
        base = finding("semgrep-ce", finding_id=fid, line=start, rule_id=rule, cwes=cwes)
        return replace(base, primary_location=FindingLocation("src/db.py", start, 1, end, 5),
                       title=rule)

    a = ranged("a", 145, 152, "sql-injection-db-cursor-execute", ("CWE-89",))
    b = ranged("b", 146, 152, "sql-injection-db-cursor-execute", ("CWE-89",))
    c = ranged("c", 148, 148, "tainted-sql-string", ("CWE-704",))
    far = ranged("far", 168, 174, "sql-injection-db-cursor-execute", ("CWE-89",))

    result = merge_normalized_findings((batch("semgrep-ce", a, b, c, far),))

    assert result.summary.merged_findings == 2
    sizes = sorted(len(item.source_findings) for item in result.findings)
    assert sizes == [1, 3]


def test_merged_fields_use_strongest_severity_confidence_and_union_metadata() -> None:
    left = finding(
        "codeql-cli",
        finding_id="one",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        flow_steps=2,
    )
    right = finding(
        "semgrep-ce",
        finding_id="two",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.MEDIUM,
    )

    merged = merge_normalized_findings(
        (batch("codeql-cli", left), batch("semgrep-ce", right))
    ).findings[0]

    assert merged.severity == FindingSeverity.CRITICAL
    assert merged.confidence == FindingConfidence.HIGH
    assert {item.finding_id for item in merged.source_findings} == {"one", "two"}


def test_zero_finding_scanner_is_retained_in_source_coverage() -> None:
    codeql = finding("codeql-cli", finding_id="one")
    result = merge_normalized_findings((batch("codeql-cli", codeql), batch("semgrep-ce")))

    assert result.summary.merged_findings == 1
    coverage = {item.scanner_id: item.findings for item in result.source_coverage}
    assert coverage == {"codeql-cli": 1, "semgrep-ce": 0}


def test_partial_normalization_produces_partial_merge_and_gap() -> None:
    warning = NormalizationWarning("bad_result", "One result failed", 0, 1)
    codeql = finding("codeql-cli", finding_id="one")
    result = merge_normalized_findings(
        (
            batch(
                "codeql-cli",
                codeql,
                status=NormalizationStatus.PARTIAL,
                warnings=(warning,),
            ),
        )
    )

    assert result.status == MergeStatus.PARTIAL
    assert result.coverage_gaps
    assert result.warnings


def test_no_batches_is_failed_not_empty_success() -> None:
    result = merge_normalized_findings(())

    assert result.status == MergeStatus.FAILED
    assert result.coverage_gaps


def test_merge_output_is_deterministic_across_input_order() -> None:
    codeql = finding("codeql-cli", finding_id="one", flow_steps=2)
    semgrep = finding("semgrep-ce", finding_id="two")

    first = merge_normalized_findings((batch("codeql-cli", codeql), batch("semgrep-ce", semgrep))).to_dict()
    second = merge_normalized_findings((batch("semgrep-ce", semgrep), batch("codeql-cli", codeql))).to_dict()

    assert first == second


def test_normalized_artifact_round_trip(tmp_path: Path) -> None:
    original = batch("codeql-cli", finding("codeql-cli", finding_id="one"))
    path = tmp_path / "normalized.json"
    path.write_text(json.dumps(original.to_dict()), encoding="utf-8")

    loaded = load_normalization_result(path)

    assert loaded.to_dict() == original.to_dict()

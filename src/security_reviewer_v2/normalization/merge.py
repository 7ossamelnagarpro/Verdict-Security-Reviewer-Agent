"""Conservative deterministic merge and deduplication of normalized findings."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .merge_models import (
    MERGE_SCHEMA_VERSION,
    DeduplicationPolicy,
    MergeResult,
    MergeStatus,
    MergeSummary,
    MergedFinding,
    SourceCoverage,
)
from .models import (
    FindingConfidence,
    FindingSeverity,
    NormalizationResult,
    NormalizationStatus,
    UnifiedFinding,
)


SEVERITY_RANK = {
    FindingSeverity.UNKNOWN: 0,
    FindingSeverity.INFO: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.HIGH: 4,
    FindingSeverity.CRITICAL: 5,
}

CONFIDENCE_RANK = {
    FindingConfidence.UNKNOWN: 0,
    FindingConfidence.LOW: 1,
    FindingConfidence.MEDIUM: 2,
    FindingConfidence.HIGH: 3,
}

FAMILY_PATTERNS = (
    (re.compile(r"\bsql[\s_-]*injection\b", re.IGNORECASE), "CWE-89"),
    (re.compile(r"\b(command|os)[\s_-]*injection\b", re.IGNORECASE), "CWE-78"),
    (re.compile(r"\b(cross[\s_-]*site[\s_-]*scripting|xss)\b", re.IGNORECASE), "CWE-79"),
    (re.compile(r"\b(path[\s_-]*traversal|directory[\s_-]*traversal)\b", re.IGNORECASE), "CWE-22"),
    (re.compile(r"\bssrf\b|server[\s_-]*side[\s_-]*request[\s_-]*forgery", re.IGNORECASE), "CWE-918"),
    (re.compile(r"\b(hardcoded|hard-coded)[\s_-]*(secret|credential|password)\b", re.IGNORECASE), "CWE-798"),
    (re.compile(r"\b(insecure|unsafe)[\s_-]*deseriali[sz]ation\b", re.IGNORECASE), "CWE-502"),
)


def merge_normalized_findings(
    batches: tuple[NormalizationResult, ...] | list[NormalizationResult],
    *,
    policy: DeduplicationPolicy | None = None,
) -> MergeResult:
    """Merge scanner findings without semantic AI or unsupported assumptions."""
    selected_policy = policy or DeduplicationPolicy()
    selected_policy.validate()
    normalized_batches = tuple(batches)
    all_findings = [finding for batch in normalized_batches for finding in batch.findings]
    coverage = tuple(
        sorted(
            (_coverage(batch) for batch in normalized_batches),
            key=lambda item: (item.scanner_id, item.source_format),
        )
    )
    warnings: list[str] = []
    coverage_gaps: list[str] = []
    for batch in normalized_batches:
        scanner_id = _scanner_id(batch)
        for warning in batch.warnings:
            warnings.append(
                f"{scanner_id}:{warning.code}: {warning.message}"
            )
        if batch.status != NormalizationStatus.COMPLETE:
            reasons = []
            for warning in batch.warnings[:2]:
                first_line = " ".join(str(warning.message).splitlines()[:1]).strip()
                reasons.append(f"{warning.code}: {first_line[:140]}")
            coverage_gaps.append(
                f"{scanner_id} normalization was {batch.status.value}; some scanner results may be unavailable."
                + (f" Scanner reported: {'; '.join(reasons)}." if reasons else "")
            )

    groups = _cluster(all_findings, selected_policy)
    merged = tuple(
        sorted(
            (_merge_group(group, selected_policy) for group in groups),
            key=lambda item: (
                item.primary_location.path.casefold(),
                item.primary_location.start_line or 0,
                item.merged_finding_id,
            ),
        )
    )
    if not normalized_batches:
        status = MergeStatus.FAILED
        coverage_gaps.append("No normalized scanner batches were provided for merge.")
    elif all(batch.status == NormalizationStatus.FAILED for batch in normalized_batches):
        status = MergeStatus.FAILED
    elif any(batch.status != NormalizationStatus.COMPLETE for batch in normalized_batches):
        status = MergeStatus.PARTIAL
    else:
        status = MergeStatus.COMPLETE
    return MergeResult(
        schema_version=MERGE_SCHEMA_VERSION,
        status=status,
        findings=merged,
        source_coverage=coverage,
        warnings=tuple(sorted(set(warnings))),
        coverage_gaps=tuple(sorted(set(coverage_gaps))),
        summary=MergeSummary(
            input_batches=len(normalized_batches),
            input_findings=len(all_findings),
            merged_findings=len(merged),
            duplicates_collapsed=max(0, len(all_findings) - len(merged)),
        ),
    )


def _cluster(
    findings: list[UnifiedFinding],
    policy: DeduplicationPolicy,
) -> list[tuple[UnifiedFinding, ...]]:
    findings = sorted(
        findings,
        key=lambda item: (
            item.primary_location.path.casefold(),
            item.primary_location.start_line or 0,
            item.scanner.scanner_id,
            item.rule_id,
            item.finding_id,
        ),
    )
    count = len(findings)
    parent = list(range(count))
    members: dict[int, set[int]] = {index: {index} for index in range(count)}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            combined = members[left_root] | members[right_root]
            if not _compatible_group(tuple(findings[index] for index in combined), policy):
                return
            root = min(left_root, right_root)
            absorbed = max(left_root, right_root)
            parent[absorbed] = root
            members[root] = combined
            del members[absorbed]

    for left in range(count):
        for right in range(left + 1, count):
            if _same_vulnerability(findings[left], findings[right], policy):
                union(left, right)
    grouped: dict[int, list[UnifiedFinding]] = defaultdict(list)
    for index, finding in enumerate(findings):
        grouped[find(index)].append(finding)
    return [
        tuple(sorted(group, key=_source_sort_key))
        for _, group in sorted(grouped.items(), key=lambda item: item[0])
    ]


def _same_vulnerability(
    left: UnifiedFinding,
    right: UnifiedFinding,
    policy: DeduplicationPolicy,
) -> bool:
    if left.finding_id == right.finding_id:
        return True
    if left.scanner.scanner_id == right.scanner.scanner_id:
        if (
            left.rule_id != right.rule_id
            or left.primary_location.path.casefold() != right.primary_location.path.casefold()
        ):
            return False
        return _shared_reliable_fingerprint(left, right)
    if left.primary_location.path.casefold() != right.primary_location.path.casefold():
        return False
    left_line = left.primary_location.start_line
    right_line = right.primary_location.start_line
    if left_line is None or right_line is None:
        return False
    if abs(left_line - right_line) > policy.line_tolerance:
        return False
    left_keys = _security_keys(left)
    right_keys = _security_keys(right)
    return bool(left_keys and right_keys and left_keys & right_keys)


def _shared_reliable_fingerprint(left: UnifiedFinding, right: UnifiedFinding) -> bool:
    return bool(_reliable_fingerprints(left) & _reliable_fingerprints(right))


def _reliable_fingerprints(finding: UnifiedFinding) -> set[tuple[str, str]]:
    ignored = {"", "requires login", "unknown", "none", "null"}
    accepted_keys = {"primaryLocationLineHash", "semgrep", "gitleaks", "trivy", "scanner"}
    return {
        (key, value.casefold())
        for key, value in finding.fingerprints.items()
        if key in accepted_keys and isinstance(value, str) and value.casefold() not in ignored
    }


def _compatible_group(
    group: tuple[UnifiedFinding, ...], policy: DeduplicationPolicy
) -> bool:
    if len({item.primary_location.path.casefold() for item in group}) != 1:
        return False
    lines = [item.primary_location.start_line for item in group]
    same_id = len({item.finding_id for item in group}) == 1
    if any(line is None for line in lines):
        if not same_id:
            return False
    elif max(lines) - min(lines) > policy.line_tolerance:
        return False
    if same_id:
        return True
    security_keys = [_security_keys(item) for item in group]
    if all(security_keys) and set.intersection(*security_keys):
        return True
    if (
        len({item.scanner.scanner_id for item in group}) == 1
        and len({item.rule_id for item in group}) == 1
    ):
        fingerprints = [_reliable_fingerprints(item) for item in group]
        return bool(fingerprints and set.intersection(*fingerprints))
    return False


def _security_keys(finding: UnifiedFinding) -> set[str]:
    if finding.cwes:
        return {cwe.upper() for cwe in finding.cwes}
    text = " ".join((finding.rule_id, finding.title, finding.message))
    return {cwe for pattern, cwe in FAMILY_PATTERNS if pattern.search(text)}


def _merge_group(
    group: tuple[UnifiedFinding, ...],
    policy: DeduplicationPolicy,
) -> MergedFinding:
    canonical = max(group, key=_canonical_rank)
    severity = max((item.severity for item in group), key=lambda item: SEVERITY_RANK[item])
    confidence = max((item.confidence for item in group), key=lambda item: CONFIDENCE_RANK[item])
    cwes = tuple(sorted({cwe for item in group for cwe in item.cwes}, key=_cwe_sort_key))
    categories = tuple(sorted({category for item in group for category in item.categories}))
    scanners = tuple(sorted({item.scanner.scanner_id for item in group}))
    rule_ids = tuple(sorted({item.rule_id for item in group}))
    reasons = _merge_reasons(group, policy)
    merged_id = _merged_id(group)
    return MergedFinding(
        merged_finding_id=merged_id,
        schema_version=MERGE_SCHEMA_VERSION,
        canonical_finding=canonical,
        source_findings=group,
        scanners=scanners,
        rule_ids=rule_ids,
        severity=severity,
        confidence=confidence,
        cwes=cwes,
        categories=categories,
        primary_location=canonical.primary_location,
        merge_reasons=reasons,
    )


def _canonical_rank(finding: UnifiedFinding) -> tuple[int, int, int, int, str, str]:
    return (
        SEVERITY_RANK[finding.severity],
        CONFIDENCE_RANK[finding.confidence],
        len(finding.code_flow),
        len(finding.cwes),
        # Reverse lexical selection is stable; earlier tuple fields carry meaning.
        finding.scanner.scanner_id,
        finding.finding_id,
    )


def _merge_reasons(
    group: tuple[UnifiedFinding, ...],
    policy: DeduplicationPolicy,
) -> tuple[str, ...]:
    if len(group) == 1:
        return ("single_source_finding",)
    reasons = {"same_primary_file", f"line_distance_at_most_{policy.line_tolerance}"}
    common_keys = set.intersection(*(_security_keys(item) for item in group))
    if common_keys:
        reasons.add("shared_security_identity:" + ",".join(sorted(common_keys)))
    if len({item.scanner.scanner_id for item in group}) > 1:
        reasons.add("independent_scanner_support")
    return tuple(sorted(reasons))


def _merged_id(group: tuple[UnifiedFinding, ...]) -> str:
    material = "|".join(sorted(item.finding_id for item in group))
    return "merged-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _coverage(batch: NormalizationResult) -> SourceCoverage:
    return SourceCoverage(
        scanner_id=_scanner_id(batch),
        source_format=batch.source_format,
        normalization_status=batch.status.value,
        findings=batch.summary.normalized_findings,
        skipped_results=batch.summary.skipped_results,
        warning_count=len(batch.warnings),
    )


def _scanner_id(batch: NormalizationResult) -> str:
    if batch.findings:
        return batch.findings[0].scanner.scanner_id
    return {
        "codeql-sarif-2.1": "codeql-cli",
        "semgrep-json": "semgrep-ce",
        "gitleaks-json": "gitleaks",
        "trivy-json": "trivy",
    }.get(batch.source_format, f"unknown:{batch.source_format}")


def _source_sort_key(finding: UnifiedFinding) -> tuple[str, str, str]:
    return (finding.scanner.scanner_id, finding.rule_id, finding.finding_id)


def _cwe_sort_key(value: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", value)
    return (int(match.group(1)) if match else 10**9, value)

"""Strict-enough loading of V2 normalized finding JSON artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .merge_models import (
    MergeResult,
    MergeStatus,
    MergeSummary,
    MergedFinding,
    SourceCoverage,
)
from .models import (
    CodeFlowStep,
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    NormalizationResult,
    NormalizationStatus,
    NormalizationSummary,
    NormalizationWarning,
    RelatedLocation,
    ScannerProvenance,
    UnifiedFinding,
)
from .runtime_evidence import bounded_runtime_evidence


class NormalizedArtifactError(ValueError):
    """Raised when a normalized artifact cannot be loaded safely."""


def load_merge_result(path: str | Path) -> MergeResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizedArtifactError(f"Merged artifact is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        return merge_result_from_dict(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, NormalizedArtifactError):
            raise
        raise NormalizedArtifactError(
            f"Merged artifact is invalid: {source} ({type(error).__name__})"
        ) from error


def merge_result_from_dict(payload: dict[str, Any]) -> MergeResult:
    if not isinstance(payload, dict):
        raise NormalizedArtifactError("Merged artifact root must be an object")
    findings = tuple(_merged_finding(item) for item in _list(payload, "findings"))
    coverage = tuple(_source_coverage(item) for item in _list(payload, "source_coverage"))
    summary = _dict(payload, "summary")
    return MergeResult(
        schema_version=str(payload["schema_version"]),
        status=MergeStatus(str(payload["status"])),
        findings=findings,
        source_coverage=coverage,
        warnings=tuple(str(item) for item in _list(payload, "warnings")),
        coverage_gaps=tuple(str(item) for item in _list(payload, "coverage_gaps")),
        summary=MergeSummary(
            input_batches=int(summary["input_batches"]),
            input_findings=int(summary["input_findings"]),
            merged_findings=int(summary["merged_findings"]),
            duplicates_collapsed=int(summary["duplicates_collapsed"]),
        ),
    )


def load_normalization_result(path: str | Path) -> NormalizationResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizedArtifactError(f"Normalized artifact is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        return normalization_result_from_dict(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, NormalizedArtifactError):
            raise
        raise NormalizedArtifactError(
            f"Normalized artifact is invalid: {source} ({type(error).__name__})"
        ) from error


def normalization_result_from_dict(payload: dict[str, Any]) -> NormalizationResult:
    if not isinstance(payload, dict):
        raise NormalizedArtifactError("Normalized artifact root must be an object")
    findings = tuple(_finding(item) for item in _list(payload, "findings"))
    warnings = tuple(
        NormalizationWarning(
            code=str(item["code"]),
            message=str(item["message"]),
            run_index=_optional_int(item.get("run_index")),
            result_index=_optional_int(item.get("result_index")),
        )
        for item in _list(payload, "warnings")
        if isinstance(item, dict)
    )
    summary = _dict(payload, "summary")
    return NormalizationResult(
        schema_version=str(payload["schema_version"]),
        source_format=str(payload["source_format"]),
        status=NormalizationStatus(str(payload["status"])),
        findings=findings,
        warnings=warnings,
        summary=NormalizationSummary(
            input_runs=int(summary["input_runs"]),
            input_results=int(summary["input_results"]),
            normalized_findings=int(summary["normalized_findings"]),
            skipped_results=int(summary["skipped_results"]),
        ),
    )


def _merged_finding(value: Any) -> MergedFinding:
    if not isinstance(value, dict):
        raise NormalizedArtifactError("Merged finding must be an object")
    return MergedFinding(
        merged_finding_id=str(value["merged_finding_id"]),
        schema_version=str(value["schema_version"]),
        canonical_finding=_finding(_dict(value, "canonical_finding")),
        source_findings=tuple(_finding(item) for item in _list(value, "source_findings")),
        scanners=tuple(str(item) for item in _list(value, "scanners")),
        rule_ids=tuple(str(item) for item in _list(value, "rule_ids")),
        severity=FindingSeverity(str(value["severity"])),
        confidence=FindingConfidence(str(value["confidence"])),
        cwes=tuple(str(item) for item in _list(value, "cwes")),
        categories=tuple(str(item) for item in _list(value, "categories")),
        primary_location=_location(_dict(value, "primary_location")),
        merge_reasons=tuple(str(item) for item in _list(value, "merge_reasons")),
    )


def _source_coverage(value: Any) -> SourceCoverage:
    if not isinstance(value, dict):
        raise NormalizedArtifactError("Source coverage must be an object")
    return SourceCoverage(
        scanner_id=str(value["scanner_id"]),
        source_format=str(value["source_format"]),
        normalization_status=str(value["normalization_status"]),
        findings=int(value["findings"]),
        skipped_results=int(value["skipped_results"]),
        warning_count=int(value["warning_count"]),
    )


def _finding(value: Any) -> UnifiedFinding:
    if not isinstance(value, dict):
        raise NormalizedArtifactError("Finding must be an object")
    scanner = _dict(value, "scanner")
    return UnifiedFinding(
        finding_id=str(value["finding_id"]),
        schema_version=str(value["schema_version"]),
        scanner=ScannerProvenance(
            scanner_id=str(scanner["scanner_id"]),
            scanner_name=str(scanner["scanner_name"]),
            scanner_version=_optional_text(scanner.get("scanner_version")),
            run_index=int(scanner["run_index"]),
            result_index=int(scanner["result_index"]),
            automation_id=_optional_text(scanner.get("automation_id")),
        ),
        rule_id=str(value["rule_id"]),
        title=str(value["title"]),
        description=_optional_text(value.get("description")),
        message=str(value["message"]),
        severity=FindingSeverity(str(value["severity"])),
        security_severity_score=_optional_float(value.get("security_severity_score")),
        confidence=FindingConfidence(str(value["confidence"])),
        cwes=tuple(str(item) for item in _list(value, "cwes")),
        categories=tuple(str(item) for item in _list(value, "categories")),
        primary_location=_location(_dict(value, "primary_location")),
        code_flow=tuple(_code_flow_step(item) for item in _list(value, "code_flow")),
        related_locations=tuple(_related(item) for item in _list(value, "related_locations")),
        fingerprints={str(key): str(item) for key, item in _dict(value, "fingerprints").items()},
        rule_kind=_optional_text(value.get("rule_kind")),
        rule_help_uri=_optional_text(value.get("rule_help_uri")),
        runtime_evidence=bounded_runtime_evidence(value.get("runtime_evidence")),
    )


def _location(value: dict[str, Any]) -> FindingLocation:
    return FindingLocation(
        path=str(value["path"]),
        start_line=_optional_int(value.get("start_line")),
        start_column=_optional_int(value.get("start_column")),
        end_line=_optional_int(value.get("end_line")),
        end_column=_optional_int(value.get("end_column")),
        snippet=_optional_text(value.get("snippet")),
    )


def _code_flow_step(value: Any) -> CodeFlowStep:
    if not isinstance(value, dict):
        raise NormalizedArtifactError("Code-flow step must be an object")
    return CodeFlowStep(
        flow_index=int(value["flow_index"]),
        thread_index=int(value["thread_index"]),
        step_index=int(value["step_index"]),
        location=_location(_dict(value, "location")),
        message=_optional_text(value.get("message")),
        role=_optional_text(value.get("role")),
    )


def _related(value: Any) -> RelatedLocation:
    if not isinstance(value, dict):
        raise NormalizedArtifactError("Related location must be an object")
    return RelatedLocation(
        location=_location(_dict(value, "location")),
        message=_optional_text(value.get("message")),
    )


def _list(value: dict[str, Any], key: str) -> list[Any]:
    result = value.get(key, [])
    if not isinstance(result, list):
        raise NormalizedArtifactError(f"{key} must be an array")
    return result


def _dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    result = value.get(key, {})
    if not isinstance(result, dict):
        raise NormalizedArtifactError(f"{key} must be an object")
    return result


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)

"""Normalize Trivy filesystem JSON into the unified finding schema."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .codeql import NormalizationInputError
from .models import (
    FINDING_SCHEMA_VERSION,
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


def normalize_trivy_json_file(path: str | Path) -> NormalizationResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizationInputError(f"Trivy JSON file is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NormalizationInputError(
            f"Trivy input could not be read as JSON: {type(error).__name__}"
        ) from error
    return normalize_trivy_json(payload)


def normalize_trivy_json(payload: Any) -> NormalizationResult:
    if not isinstance(payload, dict):
        raise NormalizationInputError("Input is not recognized Trivy JSON")
    if not any(
        key in payload for key in ("SchemaVersion", "Trivy", "Results", "ArtifactType")
    ):
        raise NormalizationInputError("Input is not recognized Trivy JSON")
    results_value = payload.get("Results", [])
    if results_value is None:
        results_value = []
    if not isinstance(results_value, list):
        raise NormalizationInputError(
            "Input is not recognized Trivy JSON with a Results array"
        )
    metadata = (
        payload.get("Metadata") if isinstance(payload.get("Metadata"), dict) else {}
    )
    version = _text(metadata.get("Version"))
    findings: list[UnifiedFinding] = []
    warnings: list[NormalizationWarning] = []
    input_results = 0
    skipped = 0
    for result_index, result in enumerate(results_value):
        if not isinstance(result, dict):
            skipped += 1
            warnings.append(
                NormalizationWarning(
                    "invalid_result", "Trivy result is not an object", 0, result_index
                )
            )
            continue
        target = _normalize_path(result.get("Target"))
        if target is None:
            skipped += 1
            warnings.append(
                NormalizationWarning(
                    "result_skipped",
                    "Trivy result has no safe Target path",
                    0,
                    result_index,
                )
            )
            continue
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            values = result.get(key, [])
            if values is None:
                continue
            if not isinstance(values, list):
                skipped += 1
                warnings.append(
                    NormalizationWarning(
                        "invalid_issue_list",
                        f"Trivy {key} is not an array",
                        0,
                        result_index,
                    )
                )
                continue
            for issue_index, issue in enumerate(values):
                input_results += 1
                if not isinstance(issue, dict):
                    skipped += 1
                    warnings.append(
                        NormalizationWarning(
                            "invalid_issue",
                            f"Trivy {key} item is not an object",
                            0,
                            issue_index,
                        )
                    )
                    continue
                try:
                    findings.append(
                        _normalize_issue(issue, key, target, version, len(findings))
                    )
                except ValueError as error:
                    skipped += 1
                    warnings.append(
                        NormalizationWarning(
                            "issue_skipped", str(error), 0, issue_index
                        )
                    )
    findings.sort(
        key=lambda item: (
            item.primary_location.path.casefold(),
            item.primary_location.start_line or 0,
            item.rule_id,
            item.finding_id,
        )
    )
    status = NormalizationStatus.PARTIAL if skipped else NormalizationStatus.COMPLETE
    if input_results and not findings and skipped == input_results:
        status = NormalizationStatus.FAILED
    return NormalizationResult(
        schema_version=FINDING_SCHEMA_VERSION,
        source_format="trivy-json",
        status=status,
        findings=tuple(findings),
        warnings=tuple(warnings),
        summary=NormalizationSummary(1, input_results, len(findings), skipped),
    )


def _normalize_issue(
    issue: dict[str, Any],
    kind: str,
    target: str,
    version: str | None,
    result_index: int,
) -> UnifiedFinding:
    if kind == "Vulnerabilities":
        rule_id = _text(issue.get("VulnerabilityID"))
        title = _text(issue.get("Title")) or rule_id
        description = _text(issue.get("Description"))
        severity = _severity(issue.get("Severity"))
        confidence = FindingConfidence.HIGH
        categories = ("sca", "vulnerability")
        line = None
        cwes = _cwes(issue.get("CweIDs"))
        message = (
            f"Dependency vulnerability {rule_id or 'without an ID'} detected by Trivy."
        )
    elif kind == "Misconfigurations":
        rule_id = _text(issue.get("ID"))
        title = _text(issue.get("Title")) or rule_id
        description = _text(issue.get("Message")) or _text(issue.get("Description"))
        severity = _severity(issue.get("Severity"))
        confidence = FindingConfidence.MEDIUM
        categories = ("misconfiguration",)
        cause = (
            issue.get("CauseMetadata")
            if isinstance(issue.get("CauseMetadata"), dict)
            else {}
        )
        line = _positive_int(cause.get("StartLine"))
        cwes = _cwes(issue.get("CweIDs"))
        message = description or "Trivy reported a configuration weakness."
    else:
        rule_id = _text(issue.get("RuleID"))
        title = _text(issue.get("Title")) or rule_id
        description = _text(issue.get("Category"))
        severity = FindingSeverity.HIGH
        confidence = FindingConfidence.MEDIUM
        categories = ("secrets",)
        line = _positive_int(issue.get("StartLine"))
        cwes = ()
        message = "Potential secret detected; secret values were intentionally omitted from normalized output."
    if not rule_id:
        raise ValueError(f"Trivy {kind} issue has no rule or vulnerability ID")
    location = FindingLocation(target, line, None, line, None, None)
    material = "|".join(
        (kind, target, rule_id, str(line or 0), _text(issue.get("PkgName")) or "")
    )
    finding_id = (
        "finding-"
        + hashlib.sha256(("trivy|" + material).encode("utf-8")).hexdigest()[:20]
    )
    return UnifiedFinding(
        finding_id=finding_id,
        schema_version=FINDING_SCHEMA_VERSION,
        scanner=ScannerProvenance("trivy", "Trivy", version, 0, result_index, None),
        rule_id=rule_id,
        title=title or rule_id,
        description=description,
        message=message,
        severity=severity,
        security_severity_score=None,
        confidence=confidence,
        cwes=cwes,
        categories=categories,
        primary_location=location,
        code_flow=(),
        related_locations=(),
        fingerprints={"trivy": finding_id},
        rule_kind=kind.casefold(),
        rule_help_uri=None,
    )


def _normalize_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().replace("\\", "/")
    normalized = re.sub(r"^[A-Za-z]:/", "", normalized).lstrip("/")
    path = PurePosixPath(normalized)
    if not normalized or ".." in path.parts:
        return None
    return path.as_posix()


def _severity(value: Any) -> FindingSeverity:
    normalized = str(value or "").casefold()
    return {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "unknown": FindingSeverity.UNKNOWN,
    }.get(normalized, FindingSeverity.UNKNOWN)


def _cwes(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    found: set[str] = set()
    for item in values:
        match = re.search(r"CWE[-_: ]*0*(\d+)", str(item or ""), flags=re.IGNORECASE)
        if match:
            found.add(f"CWE-{int(match.group(1))}")
    return tuple(sorted(found, key=lambda item: int(item.split("-")[1])))


def _text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _positive_int(value: Any) -> int | None:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None

"""Normalize Semgrep JSON into the V2 unified finding schema."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .codeql import NormalizationInputError
from .common import line_hash, normalize_relative_path
from .models import (
    FINDING_SCHEMA_VERSION,
    KIND_SAST,
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


LINE_HASH_KEY = "verdict.lineHash/v1"
# Semgrep CE fills login-gated fields with this literal instead of omitting them.
_PLACEHOLDER_FINGERPRINTS = {"requires login"}


def normalize_semgrep_json_file(path: str | Path, *, project_root: str | Path | None = None) -> NormalizationResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizationInputError(f"Semgrep JSON file is unavailable: {source}")
    try:
        payload = json.loads(_read_json_text(source))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NormalizationInputError(
            f"Semgrep input could not be read as JSON: {type(error).__name__}"
        ) from error
    return normalize_semgrep_json(payload, project_root=project_root)


def _read_json_text(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252")


def normalize_semgrep_json(
    payload: dict[str, Any], *, project_root: str | Path | None = None
) -> NormalizationResult:
    if not isinstance(payload, dict):
        raise NormalizationInputError("Semgrep JSON root must be an object")
    results = payload.get("results")
    errors = payload.get("errors", [])
    if not isinstance(results, list) or not isinstance(errors, list):
        raise NormalizationInputError("Input is not recognized Semgrep JSON")

    warnings: list[NormalizationWarning] = []
    for index, error in enumerate(errors):
        warnings.append(
            NormalizationWarning(
                code="semgrep_scan_error",
                message=_semgrep_error_message(error),
                run_index=0,
                result_index=index,
            )
        )
    findings: list[UnifiedFinding] = []
    skipped = 0
    version = _optional_text(payload.get("version"))
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            skipped += 1
            warnings.append(
                NormalizationWarning(
                    code="invalid_result",
                    message="Semgrep result is not an object and was skipped",
                    run_index=0,
                    result_index=result_index,
                )
            )
            continue
        try:
            findings.append(_normalize_result(
                result, version=version, result_index=result_index, project_root=project_root,
            ))
        except ValueError as error:
            skipped += 1
            warnings.append(
                NormalizationWarning(
                    code="result_skipped",
                    message=str(error),
                    run_index=0,
                    result_index=result_index,
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
    if errors or skipped:
        status = NormalizationStatus.PARTIAL
    else:
        status = NormalizationStatus.COMPLETE
    if results and not findings and skipped == len(results):
        status = NormalizationStatus.FAILED
    return NormalizationResult(
        schema_version=FINDING_SCHEMA_VERSION,
        source_format="semgrep-json",
        status=status,
        findings=tuple(findings),
        warnings=tuple(warnings),
        summary=NormalizationSummary(
            input_runs=1,
            input_results=len(results),
            normalized_findings=len(findings),
            skipped_results=skipped,
        ),
    )


def _normalize_result(
    result: dict[str, Any],
    *,
    version: str | None,
    result_index: int,
    project_root: str | Path | None = None,
) -> UnifiedFinding:
    rule_id = str(result.get("check_id") or "").strip()
    if not rule_id:
        raise ValueError("Semgrep result has no check_id")
    path = _normalize_path(result.get("path"), project_root)
    if path is None:
        raise ValueError(f"Semgrep result {rule_id} has no safe relative path")
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    end = result.get("end") if isinstance(result.get("end"), dict) else {}
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    message = str(extra.get("message") or "").strip()
    if not message:
        raise ValueError(f"Semgrep result {rule_id} has no message")
    location = FindingLocation(
        path=path,
        start_line=_positive_int(start.get("line")),
        start_column=_positive_int(start.get("col")),
        end_line=_positive_int(end.get("line")),
        end_column=_positive_int(end.get("col")),
        snippet=None,
    )
    cwes = _cwes(metadata.get("cwe"))
    categories = _categories(metadata)
    severity = _severity(metadata.get("impact"), extra.get("severity"))
    confidence = _confidence(metadata.get("confidence"))
    fingerprint = _optional_text(extra.get("fingerprint"))
    if fingerprint is not None and fingerprint.casefold() in _PLACEHOLDER_FINGERPRINTS:
        fingerprint = None
    fingerprints = {"semgrep": fingerprint} if fingerprint else {}
    content_hash = line_hash(project_root, path, location.start_line)
    if content_hash:
        fingerprints[LINE_HASH_KEY] = content_hash
    title = _optional_text(metadata.get("shortDescription")) or _rule_title(rule_id)
    help_uri = _help_uri(metadata)
    code_flow = _dataflow_trace(extra.get("dataflow_trace"), project_root)
    finding_id = _finding_id(rule_id, location, fingerprints, message)
    return UnifiedFinding(
        finding_id=finding_id,
        schema_version=FINDING_SCHEMA_VERSION,
        scanner=ScannerProvenance(
            scanner_id="semgrep-ce",
            scanner_name="Semgrep",
            scanner_version=version,
            run_index=0,
            result_index=result_index,
            automation_id=None,
        ),
        rule_id=rule_id,
        title=title,
        description=message,
        message=message,
        severity=severity,
        security_severity_score=None,
        confidence=confidence,
        cwes=cwes,
        categories=categories,
        primary_location=location,
        code_flow=code_flow,
        related_locations=(),
        fingerprints=fingerprints,
        rule_kind=_optional_text(metadata.get("kind")) or "pattern",
        rule_help_uri=help_uri,
        finding_kind=KIND_SAST,
    )


def _dataflow_trace(value: Any, project_root: str | Path | None = None) -> tuple[CodeFlowStep, ...]:
    if not isinstance(value, dict):
        return ()
    ordered = (
        ("taint_source", "source"),
        ("intermediate_vars", "step"),
        ("taint_sink", "sink"),
    )
    steps: list[CodeFlowStep] = []
    for field_name, role in ordered:
        candidates = _trace_locations(value.get(field_name))
        for candidate in candidates:
            location = _semgrep_location(candidate, project_root)
            if location is None:
                continue
            steps.append(
                CodeFlowStep(
                    flow_index=0,
                    thread_index=0,
                    step_index=len(steps),
                    location=location,
                    message=_optional_text(candidate.get("content") or candidate.get("message")),
                    role=role,
                )
            )
    return tuple(steps)


def _trace_locations(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "path" in value and "start" in value:
            found.append(value)
        else:
            for nested in value.values():
                found.extend(_trace_locations(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(_trace_locations(nested))
    return found


def _semgrep_location(value: dict[str, Any], project_root: str | Path | None = None) -> FindingLocation | None:
    path = _normalize_path(value.get("path"), project_root)
    if path is None:
        return None
    start = value.get("start") if isinstance(value.get("start"), dict) else {}
    end = value.get("end") if isinstance(value.get("end"), dict) else {}
    return FindingLocation(
        path=path,
        start_line=_positive_int(start.get("line")),
        start_column=_positive_int(start.get("col")),
        end_line=_positive_int(end.get("line")),
        end_column=_positive_int(end.get("col")),
    )


def _normalize_path(value: Any, project_root: str | Path | None = None) -> str | None:
    return normalize_relative_path(value, project_root=project_root)


def _cwes(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    cwes: set[str] = set()
    for item in values:
        match = re.search(r"CWE[-_: ]*0*(\d+)", str(item or ""), flags=re.IGNORECASE)
        if match:
            cwes.add(f"CWE-{int(match.group(1))}")
    return tuple(sorted(cwes, key=lambda item: int(item.split("-")[1])))


def _categories(metadata: dict[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    category = metadata.get("category")
    if isinstance(category, list):
        values.update(str(item) for item in category if item)
    elif category:
        values.add(str(category))
    technology = metadata.get("technology")
    if isinstance(technology, list):
        values.update(f"technology:{item}" for item in technology if item)
    elif technology:
        values.add(f"technology:{technology}")
    return tuple(sorted(values))


def _severity(impact: Any, semgrep_severity: Any) -> FindingSeverity:
    normalized = str(impact or "").casefold()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return FindingSeverity(normalized)
    return {
        "critical": FindingSeverity.CRITICAL,
        "error": FindingSeverity.HIGH,
        "warning": FindingSeverity.MEDIUM,
        "info": FindingSeverity.LOW,
        "inventory": FindingSeverity.INFO,
    }.get(str(semgrep_severity or "").casefold(), FindingSeverity.UNKNOWN)


def _confidence(value: Any) -> FindingConfidence:
    normalized = str(value or "").casefold().replace("_", "-")
    if normalized in {"very-high", "high"}:
        return FindingConfidence.HIGH
    if normalized == "medium":
        return FindingConfidence.MEDIUM
    if normalized == "low":
        return FindingConfidence.LOW
    return FindingConfidence.UNKNOWN


def _help_uri(metadata: dict[str, Any]) -> str | None:
    for key in ("shortlink", "source", "rule_url"):
        value = _optional_text(metadata.get(key))
        if value and value.startswith(("https://", "http://")):
            return value
    references = metadata.get("references")
    if isinstance(references, list):
        for reference in references:
            value = _optional_text(reference)
            if value and value.startswith(("https://", "http://")):
                return value
    return None


def _rule_title(rule_id: str) -> str:
    leaf = rule_id.rsplit(".", 1)[-1]
    return leaf.replace("-", " ").replace("_", " ").strip().title() or rule_id


def _finding_id(
    rule_id: str,
    location: FindingLocation,
    fingerprints: dict[str, str],
    message: str,
) -> str:
    fingerprint = "|".join(f"{key}={value}" for key, value in sorted(fingerprints.items()))
    material = "|".join(
        (
            "semgrep-ce",
            rule_id,
            location.path,
            str(location.start_line or 0),
            str(location.start_column or 0),
            fingerprint,
            message,
        )
    )
    return "finding-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _semgrep_error_message(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("message") or value.get("type") or "Semgrep reported an unspecified error")
    return str(value or "Semgrep reported an unspecified error")


def _optional_text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _positive_int(value: Any) -> int | None:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None

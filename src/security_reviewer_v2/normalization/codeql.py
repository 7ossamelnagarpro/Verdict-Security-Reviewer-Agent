"""Normalize CodeQL SARIF 2.1 results into the V2 unified finding schema."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from .models import KIND_SAST
from .models import (
    FINDING_SCHEMA_VERSION,
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


class NormalizationInputError(ValueError):
    """Raised when the input is not readable JSON or not recognizable SARIF."""


def normalize_codeql_sarif_file(path: str | Path) -> NormalizationResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizationInputError(f"SARIF file is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NormalizationInputError(
            f"SARIF input could not be read as JSON: {type(error).__name__}"
        ) from error
    return normalize_codeql_sarif(payload)


def normalize_codeql_sarif(payload: dict[str, Any]) -> NormalizationResult:
    if not isinstance(payload, dict):
        raise NormalizationInputError("SARIF root must be a JSON object")
    version = payload.get("version")
    runs = payload.get("runs")
    if version not in {"2.1.0", "2.1.0-rtm.5"} or not isinstance(runs, list):
        raise NormalizationInputError("Input is not supported SARIF 2.1 with a runs array")

    findings: list[UnifiedFinding] = []
    warnings: list[NormalizationWarning] = []
    input_results = 0
    skipped_results = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            warnings.append(
                NormalizationWarning(
                    code="invalid_run",
                    message="SARIF run is not an object and was skipped",
                    run_index=run_index,
                )
            )
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            warnings.append(
                NormalizationWarning(
                    code="invalid_results",
                    message="SARIF run results is not an array and was skipped",
                    run_index=run_index,
                )
            )
            continue
        rules = _rules_by_id(run)
        driver = _driver(run)
        for result_index, result in enumerate(results):
            input_results += 1
            if not isinstance(result, dict):
                skipped_results += 1
                warnings.append(
                    NormalizationWarning(
                        code="invalid_result",
                        message="SARIF result is not an object and was skipped",
                        run_index=run_index,
                        result_index=result_index,
                    )
                )
                continue
            try:
                finding = _normalize_result(
                    result,
                    rules=rules,
                    driver=driver,
                    run=run,
                    run_index=run_index,
                    result_index=result_index,
                )
            except ValueError as error:
                skipped_results += 1
                warnings.append(
                    NormalizationWarning(
                        code="result_skipped",
                        message=str(error),
                        run_index=run_index,
                        result_index=result_index,
                    )
                )
                continue
            findings.append(finding)

    findings.sort(
        key=lambda item: (
            item.primary_location.path.casefold(),
            item.primary_location.start_line or 0,
            item.rule_id,
            item.finding_id,
        )
    )
    warnings.sort(
        key=lambda item: (
            item.run_index if item.run_index is not None else -1,
            item.result_index if item.result_index is not None else -1,
            item.code,
        )
    )
    if skipped_results or any(item.code in {"invalid_run", "invalid_results"} for item in warnings):
        status = NormalizationStatus.PARTIAL
    else:
        status = NormalizationStatus.COMPLETE
    if input_results > 0 and not findings and skipped_results == input_results:
        status = NormalizationStatus.FAILED
    return NormalizationResult(
        schema_version=FINDING_SCHEMA_VERSION,
        source_format="codeql-sarif-2.1",
        status=status,
        findings=tuple(findings),
        warnings=tuple(warnings),
        summary=NormalizationSummary(
            input_runs=len(runs),
            input_results=input_results,
            normalized_findings=len(findings),
            skipped_results=skipped_results,
        ),
    )


def _normalize_result(
    result: dict[str, Any],
    *,
    rules: dict[str, dict[str, Any]],
    driver: dict[str, Any],
    run: dict[str, Any],
    run_index: int,
    result_index: int,
) -> UnifiedFinding:
    rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "").strip()
    if not rule_id:
        raise ValueError("SARIF result has no rule id")
    rule = rules.get(rule_id, {})
    primary = _primary_location(result)
    if primary is None:
        raise ValueError(f"SARIF result {rule_id} has no usable primary location")
    message = _message(result.get("message"))
    if not message:
        raise ValueError(f"SARIF result {rule_id} has no message")
    properties = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    tags = tuple(
        sorted(
            {
                str(tag)
                for tag in properties.get("tags", [])
                if isinstance(tag, str) and tag.strip()
            }
        )
    )
    cwes = _extract_cwes(tags)
    categories = tuple(tag for tag in tags if "cwe" not in tag.casefold())
    score = _security_score(properties.get("security-severity"))
    severity = _severity(score, result.get("level"), properties.get("problem.severity"))
    confidence = _confidence(properties.get("precision"))
    title = (
        _message(rule.get("shortDescription"))
        or str(properties.get("name") or "").strip()
        or rule_id
    )
    description = _message(rule.get("fullDescription")) or _optional_text(properties.get("description"))
    fingerprints = _fingerprints(result)
    code_flow = _code_flow(result)
    related = _related_locations(result)
    scanner_name = str(driver.get("name") or "CodeQL")
    scanner_version = _optional_text(driver.get("semanticVersion") or driver.get("version"))
    automation = run.get("automationDetails") if isinstance(run.get("automationDetails"), dict) else {}
    automation_id = _optional_text(automation.get("id"))
    finding_id = _finding_id(
        scanner_id="codeql-cli",
        rule_id=rule_id,
        location=primary,
        fingerprints=fingerprints,
        message=message,
    )
    help_uri = _optional_text(rule.get("helpUri"))
    return UnifiedFinding(
            finding_kind=KIND_SAST,
        finding_id=finding_id,
        schema_version=FINDING_SCHEMA_VERSION,
        scanner=ScannerProvenance(
            scanner_id="codeql-cli",
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            run_index=run_index,
            result_index=result_index,
            automation_id=automation_id,
        ),
        rule_id=rule_id,
        title=title,
        description=description,
        message=message,
        severity=severity,
        security_severity_score=score,
        confidence=confidence,
        cwes=cwes,
        categories=categories,
        primary_location=primary,
        code_flow=code_flow,
        related_locations=related,
        fingerprints=fingerprints,
        rule_kind=_optional_text(properties.get("kind")),
        rule_help_uri=help_uri,
    )


def _driver(run: dict[str, Any]) -> dict[str, Any]:
    tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
    driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
    return driver


def _rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = _driver(run)
    rules = driver.get("rules", [])
    if not isinstance(rules, list):
        return {}
    return {
        str(rule.get("id")): rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("id")
    }


def _primary_location(result: dict[str, Any]) -> FindingLocation | None:
    locations = result.get("locations", [])
    if not isinstance(locations, list) or not locations:
        return None
    return _location(locations[0])


def _location(value: Any) -> FindingLocation | None:
    if not isinstance(value, dict):
        return None
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return None
    path = _normalize_uri(artifact.get("uri"))
    if path is None:
        return None
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    snippet = region.get("snippet") if isinstance(region.get("snippet"), dict) else {}
    return FindingLocation(
        path=path,
        start_line=_positive_int(region.get("startLine")),
        start_column=_positive_int(region.get("startColumn")),
        end_line=_positive_int(region.get("endLine")),
        end_column=_positive_int(region.get("endColumn")),
        snippet=_message(snippet) or None,
    )


def _normalize_uri(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    decoded = unquote(value.strip()).replace("\\", "/")
    parsed = urlparse(decoded)
    if parsed.scheme and parsed.scheme != "file":
        return None
    path_value = parsed.path if parsed.scheme == "file" else decoded
    path_value = re.sub(r"^[A-Za-z]:/", "", path_value).lstrip("/")
    pure = PurePosixPath(path_value)
    if not path_value or ".." in pure.parts:
        return None
    return pure.as_posix()


def _code_flow(result: dict[str, Any]) -> tuple[CodeFlowStep, ...]:
    steps: list[CodeFlowStep] = []
    flows = result.get("codeFlows", [])
    if not isinstance(flows, list):
        return ()
    for flow_index, flow in enumerate(flows):
        if not isinstance(flow, dict):
            continue
        threads = flow.get("threadFlows", [])
        if not isinstance(threads, list):
            continue
        for thread_index, thread in enumerate(threads):
            if not isinstance(thread, dict):
                continue
            locations = thread.get("locations", [])
            if not isinstance(locations, list):
                continue
            for step_index, wrapper in enumerate(locations):
                if not isinstance(wrapper, dict):
                    continue
                location_value = wrapper.get("location")
                location = _location(location_value)
                if location is None:
                    continue
                taxa = wrapper.get("taxa", [])
                role = None
                if isinstance(taxa, list):
                    for taxon in taxa:
                        if isinstance(taxon, dict):
                            properties = taxon.get("properties")
                            if isinstance(properties, dict) and properties.get("CodeQL/DataflowRole"):
                                role = str(properties["CodeQL/DataflowRole"])
                                break
                steps.append(
                    CodeFlowStep(
                        flow_index=flow_index,
                        thread_index=thread_index,
                        step_index=step_index,
                        location=location,
                        message=_message(location_value.get("message")) if isinstance(location_value, dict) else None,
                        role=role,
                    )
                )
    return tuple(steps)


def _related_locations(result: dict[str, Any]) -> tuple[RelatedLocation, ...]:
    related: list[RelatedLocation] = []
    values = result.get("relatedLocations", [])
    if not isinstance(values, list):
        return ()
    for value in values:
        location = _location(value)
        if location is not None:
            related.append(RelatedLocation(location=location, message=_message(value.get("message"))))
    return tuple(related)


def _extract_cwes(tags: tuple[str, ...]) -> tuple[str, ...]:
    values: set[str] = set()
    for tag in tags:
        match = re.search(r"cwe[-_/]0*(\d+)", tag, flags=re.IGNORECASE)
        if match:
            values.add(f"CWE-{int(match.group(1))}")
    return tuple(sorted(values, key=lambda item: int(item.split("-")[1])))


def _security_score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 10 else None


def _severity(score: float | None, result_level: Any, rule_level: Any) -> FindingSeverity:
    if score is not None:
        if score >= 9:
            return FindingSeverity.CRITICAL
        if score >= 7:
            return FindingSeverity.HIGH
        if score >= 4:
            return FindingSeverity.MEDIUM
        if score > 0:
            return FindingSeverity.LOW
        return FindingSeverity.INFO
    level = str(result_level or rule_level or "").casefold()
    return {
        "error": FindingSeverity.HIGH,
        "warning": FindingSeverity.MEDIUM,
        "note": FindingSeverity.LOW,
        "none": FindingSeverity.INFO,
    }.get(level, FindingSeverity.UNKNOWN)


def _confidence(value: Any) -> FindingConfidence:
    normalized = str(value or "").casefold().replace("_", "-")
    if normalized in {"very-high", "high"}:
        return FindingConfidence.HIGH
    if normalized == "medium":
        return FindingConfidence.MEDIUM
    if normalized == "low":
        return FindingConfidence.LOW
    return FindingConfidence.UNKNOWN


def _fingerprints(result: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in ("fingerprints", "partialFingerprints"):
        source = result.get(key)
        if isinstance(source, dict):
            for name, value in source.items():
                if isinstance(value, (str, int, float, bool)):
                    values[str(name)] = str(value)
    return dict(sorted(values.items()))


def _finding_id(
    *,
    scanner_id: str,
    rule_id: str,
    location: FindingLocation,
    fingerprints: dict[str, str],
    message: str,
) -> str:
    stable_fingerprint = "|".join(f"{key}={value}" for key, value in sorted(fingerprints.items()))
    material = "|".join(
        (
            scanner_id,
            rule_id,
            location.path,
            str(location.start_line or 0),
            str(location.start_column or 0),
            stable_fingerprint,
            message,
        )
    )
    return "finding-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _message(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("text") or value.get("markdown") or "").strip()
    return str(value or "").strip()


def _optional_text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _positive_int(value: Any) -> int | None:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None


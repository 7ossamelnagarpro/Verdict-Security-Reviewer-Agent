"""Loading of Context Collector JSON artifacts into typed models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security_reviewer_v2.normalization.models import FindingLocation

from .models import (
    ContextResult,
    ContextStatus,
    ContextSummary,
    EvidenceContext,
    FindingContext,
    SourceExcerpt,
    SymbolContext,
)


class ContextArtifactError(ValueError):
    """Raised when a context artifact cannot be loaded safely."""


def load_context_result(path: str | Path) -> ContextResult:
    source = Path(path)
    if not source.is_file():
        raise ContextArtifactError(f"Context artifact is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        return context_result_from_dict(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, ContextArtifactError):
            raise
        raise ContextArtifactError(
            f"Context artifact is invalid: {source} ({type(error).__name__})"
        ) from error


def context_result_from_dict(payload: dict[str, Any]) -> ContextResult:
    if not isinstance(payload, dict):
        raise ContextArtifactError("Context artifact root must be an object")
    summary = _dict(payload, "summary")
    if str(payload.get("schema_version")) not in {"1.0", "1.1"}:
        raise ContextArtifactError("Unsupported context schema version")
    excerpts = _dict(payload, "shared_excerpts")
    symbols = _dict(payload, "shared_symbols")
    return ContextResult(
        schema_version=str(payload["schema_version"]),
        status=ContextStatus(str(payload["status"])),
        project_root=str(payload["project_root"]),
        findings=tuple(_finding(item, excerpts, symbols) for item in _list(payload, "findings")),
        warnings=tuple(str(item) for item in _list(payload, "warnings")),
        coverage_gaps=tuple(str(item) for item in _list(payload, "coverage_gaps")),
        summary=ContextSummary(
            input_findings=int(summary["input_findings"]),
            contexts_created=int(summary["contexts_created"]),
            evidence_locations=int(summary["evidence_locations"]),
            excerpts_collected=int(summary["excerpts_collected"]),
            files_read=int(summary["files_read"]),
            bytes_read=int(summary["bytes_read"]),
            unavailable_locations=int(summary["unavailable_locations"]),
        ),
    )


def _finding(value: Any, excerpts: dict[str, Any], symbols: dict[str, Any]) -> FindingContext:
    item = _object(value, "finding context")
    return FindingContext(
        merged_finding_id=str(item["merged_finding_id"]),
        title=str(item["title"]),
        severity=str(item["severity"]),
        confidence=str(item["confidence"]),
        cwes=tuple(str(part) for part in _list(item, "cwes")),
        scanners=tuple(str(part) for part in _list(item, "scanners")),
        primary=_evidence(_dict(item, "primary"), excerpts, symbols),
        code_flow=tuple(_evidence(part, excerpts, symbols) for part in _list(item, "code_flow")),
        related=tuple(_evidence(part, excerpts, symbols) for part in _list(item, "related")),
        warnings=tuple(str(part) for part in _list(item, "warnings")),
        additional_primaries=tuple(_evidence(part, excerpts, symbols) for part in _list(item, "additional_primaries")),
    )


def _evidence(value: Any, excerpts: dict[str, Any], symbols: dict[str, Any]) -> EvidenceContext:
    item = _object(value, "evidence context")
    excerpt_value = item.get("excerpt")
    symbol_value = item.get("enclosing_symbol")
    if "excerpt_ref" in item:
        excerpt_value = _reference(excerpts, item["excerpt_ref"], "excerpt")
    if "symbol_ref" in item:
        symbol_value = dict(_reference(symbols, item["symbol_ref"], "symbol"))
        symbol_value["excerpt"] = _reference(excerpts, symbol_value.pop("excerpt_ref"), "excerpt")
    return EvidenceContext(
        evidence_type=str(item["evidence_type"]),
        scanner_id=str(item["scanner_id"]),
        rule_id=str(item["rule_id"]),
        location=_location(_dict(item, "location")),
        message=_optional_text(item.get("message")),
        flow_index=_optional_int(item.get("flow_index")),
        thread_index=_optional_int(item.get("thread_index")),
        step_index=_optional_int(item.get("step_index")),
        excerpt=None if excerpt_value is None else _excerpt(_object(excerpt_value, "excerpt")),
        enclosing_symbol=None
        if symbol_value is None
        else _symbol(_object(symbol_value, "enclosing symbol")),
        collection_status=str(item["collection_status"]),
        warning=_optional_text(item.get("warning")),
        source_finding_id=_optional_text(item.get("source_finding_id")),
    )


def _reference(table: dict[str, Any], key: Any, label: str) -> dict[str, Any]:
    if not isinstance(key, str) or key not in table:
        raise ContextArtifactError(f"Unknown {label} reference")
    return _object(table[key], label)


def _symbol(item: dict[str, Any]) -> SymbolContext:
    return SymbolContext(
        language=str(item["language"]),
        kind=str(item["kind"]),
        name=str(item["name"]),
        qualified_name=str(item["qualified_name"]),
        start_line=int(item["start_line"]),
        end_line=int(item["end_line"]),
        excerpt=_excerpt(_dict(item, "excerpt")),
        truncated=bool(item["truncated"]),
    )


def _excerpt(item: dict[str, Any]) -> SourceExcerpt:
    return SourceExcerpt(
        path=str(item["path"]),
        start_line=int(item["start_line"]),
        end_line=int(item["end_line"]),
        code=str(item["code"]),
        content_sha256=str(item["content_sha256"]),
    )


def _location(item: dict[str, Any]) -> FindingLocation:
    return FindingLocation(
        path=str(item["path"]),
        start_line=_optional_int(item.get("start_line")),
        start_column=_optional_int(item.get("start_column")),
        end_line=_optional_int(item.get("end_line")),
        end_column=_optional_int(item.get("end_column")),
        snippet=_optional_text(item.get("snippet")),
    )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContextArtifactError(f"{label} must be an object")
    return value


def _list(value: dict[str, Any], key: str) -> list[Any]:
    result = value.get(key, [])
    if not isinstance(result, list):
        raise ContextArtifactError(f"{key} must be an array")
    return result


def _dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    result = value.get(key, {})
    return _object(result, key)


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)

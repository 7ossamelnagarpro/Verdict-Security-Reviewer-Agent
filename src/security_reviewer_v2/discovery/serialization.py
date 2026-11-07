"""Load saved Discovery results without invoking a model or scanning code."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    CandidateAnchor, CandidateDisposition, CandidateFinding, CandidateMissingCheck,
    ContextExchange, DiscoveryBatch, DiscoveryResult, DiscoveryStatus, DiscoveryTarget,
)


class DiscoveryArtifactError(ValueError):
    """The saved Discovery JSON cannot be used as a typed result."""


def load_discovery_result(path: str | Path) -> DiscoveryResult:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        return discovery_result_from_dict(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, DiscoveryArtifactError):
            raise
        raise DiscoveryArtifactError(f"Invalid Discovery artifact: {source} ({type(error).__name__})") from error


def discovery_result_from_dict(payload: dict[str, Any]) -> DiscoveryResult:
    if not isinstance(payload, dict):
        raise DiscoveryArtifactError("Discovery artifact must be a JSON object")
    if str(payload.get("schema_version")) not in {"1.0", "1.1", "1.2"}:
        raise DiscoveryArtifactError("Unsupported Discovery schema version")
    try:
        candidates = tuple(
            CandidateFinding(
                candidate_id=str(item["candidate_id"]),
                title=str(item["title"]),
                category=str(item["category"]),
                severity=str(item["severity"]),
                confidence=str(item["confidence"]),
                path=item.get("path"),
                start_line=item.get("start_line"),
                end_line=item.get("end_line"),
                evidence=tuple(str(value) for value in item.get("evidence", [])),
                reasoning=str(item.get("reasoning", "")),
                source=str(item.get("source", "ai_discovery")),
                verification=CandidateDisposition(item["verification"]),
                verification_notes=tuple(str(value) for value in item.get("verification_notes", [])),
                entry_point=CandidateAnchor(**item["entry_point"]) if isinstance(item.get("entry_point"), dict) else None,
                sensitive_operation=CandidateAnchor(**item["sensitive_operation"]) if isinstance(item.get("sensitive_operation"), dict) else None,
                missing_check=CandidateMissingCheck(**item["missing_check"]) if isinstance(item.get("missing_check"), dict) else None,
                remaining_questions=tuple(str(value) for value in item.get("remaining_questions", [])),
                analysis=str(item.get("analysis", "static_source_review")),
                duplicate_ids=tuple(str(value) for value in item.get("duplicate_ids", [])),
            )
            for item in payload.get("candidates", [])
        )
        return DiscoveryResult(
            schema_version=str(payload["schema_version"]),
            status=DiscoveryStatus(payload["status"]),
            provider=str(payload["provider"]),
            model=payload.get("model"),
            scope=tuple(str(value) for value in payload.get("scope", [])),
            candidates=candidates,
            warnings=tuple(str(value) for value in payload.get("warnings", [])),
            coverage_gaps=tuple(str(value) for value in payload.get("coverage_gaps", [])),
            usage=dict(payload.get("usage", {})),
            target_plan=tuple(DiscoveryTarget(**item) for item in payload.get("target_plan", [])),
            batches=tuple(DiscoveryBatch(**item) for item in payload.get("batches", [])),
            context_exchanges=tuple(ContextExchange(**item) for item in payload.get("context_exchanges", [])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise DiscoveryArtifactError(f"Malformed Discovery artifact ({type(error).__name__})") from error

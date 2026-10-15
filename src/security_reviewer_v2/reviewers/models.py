"""Typed output models for the final security review stage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class ReviewVerdict(str, Enum):
    CONFIRMED = "confirmed_vulnerability"
    LIKELY = "likely_vulnerability"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


@dataclass(frozen=True)
class ReviewItem:
    candidate_id: str
    verdict: ReviewVerdict
    severity: str
    confidence: str
    title: str
    explanation: str
    impact: str
    remediation: str
    evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    source_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewResult:
    schema_version: str
    status: str
    provider: str | None
    model: str | None
    reviews: tuple[ReviewItem, ...]
    warnings: tuple[str, ...]
    usage: dict[str, Any]
    pending_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _primitive(asdict(value))
    if isinstance(value, dict):
        return {str(k): _primitive(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(v) for v in value]
    return value

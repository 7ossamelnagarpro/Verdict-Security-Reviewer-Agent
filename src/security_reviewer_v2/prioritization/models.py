"""Typed models for explainable risk prioritization."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from security_reviewer_v2.normalization.models import FindingLocation


RISK_SCHEMA_VERSION = "1.0"
RISK_POLICY_VERSION = "heuristic-v1"


class StringEnum(str, Enum):
    """String enum for stable JSON output."""


class RiskStatus(StringEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class PriorityBand(StringEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReviewDisposition(StringEnum):
    DEEP_REVIEW = "deep_review"
    QUEUED_FOR_DEEP_REVIEW = "queued_for_deep_review"
    STANDARD_REPORT = "standard_report"
    NEEDS_VERIFICATION = "needs_verification"


@dataclass(frozen=True)
class RiskPolicy:
    deep_review_threshold: int = 65
    max_deep_reviews: int = 20

    def validate(self) -> None:
        if not 0 <= self.deep_review_threshold <= 100:
            raise ValueError("deep_review_threshold must be between 0 and 100")
        if not 0 <= self.max_deep_reviews <= 10_000:
            raise ValueError("max_deep_reviews must be between 0 and 10000")


@dataclass(frozen=True)
class RiskFactor:
    factor_id: str
    label: str
    points: int
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class PrioritizedFinding:
    rank: int
    merged_finding_id: str
    title: str
    primary_location: FindingLocation
    scanner_severity: str
    scanner_confidence: str
    cwes: tuple[str, ...]
    scanners: tuple[str, ...]
    risk_score: int
    priority_band: PriorityBand
    review_disposition: ReviewDisposition
    selected_for_deep_review: bool
    factors: tuple[RiskFactor, ...]


@dataclass(frozen=True)
class RiskSummary:
    input_findings: int
    ranked_findings: int
    selected_for_deep_review: int
    queued_for_deep_review: int
    standard_report: int
    needs_verification: int


@dataclass(frozen=True)
class RiskResult:
    schema_version: str
    policy_version: str
    status: RiskStatus
    policy: RiskPolicy
    findings: tuple[PrioritizedFinding, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    summary: RiskSummary

    def to_dict(self) -> dict[str, Any]:
        return _to_primitive(self)


def _to_primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _to_primitive(asdict(value))
    if isinstance(value, dict):
        return {str(key): _to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_primitive(item) for item in value]
    return value

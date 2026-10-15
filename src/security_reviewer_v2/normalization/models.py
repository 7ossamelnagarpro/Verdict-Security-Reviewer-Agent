"""Scanner-independent finding models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


FINDING_SCHEMA_VERSION = "1.0"


class StringEnum(str, Enum):
    """String enum for stable JSON serialization."""


class FindingSeverity(StringEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingConfidence(StringEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class NormalizationStatus(StringEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class FindingLocation:
    path: str
    start_line: int | None
    start_column: int | None
    end_line: int | None
    end_column: int | None
    snippet: str | None = None


@dataclass(frozen=True)
class CodeFlowStep:
    flow_index: int
    thread_index: int
    step_index: int
    location: FindingLocation
    message: str | None
    role: str | None


@dataclass(frozen=True)
class RelatedLocation:
    location: FindingLocation
    message: str | None


@dataclass(frozen=True)
class ScannerProvenance:
    scanner_id: str
    scanner_name: str
    scanner_version: str | None
    run_index: int
    result_index: int
    automation_id: str | None


@dataclass(frozen=True)
class UnifiedFinding:
    finding_id: str
    schema_version: str
    scanner: ScannerProvenance
    rule_id: str
    title: str
    description: str | None
    message: str
    severity: FindingSeverity
    security_severity_score: float | None
    confidence: FindingConfidence
    cwes: tuple[str, ...]
    categories: tuple[str, ...]
    primary_location: FindingLocation
    code_flow: tuple[CodeFlowStep, ...]
    related_locations: tuple[RelatedLocation, ...]
    fingerprints: dict[str, str]
    rule_kind: str | None
    rule_help_uri: str | None
    # Bounded, redacted probe facts. Never store response bodies or credentials.
    runtime_evidence: dict[str, Any] | None = None


@dataclass(frozen=True)
class NormalizationWarning:
    code: str
    message: str
    run_index: int | None = None
    result_index: int | None = None


@dataclass(frozen=True)
class NormalizationSummary:
    input_runs: int
    input_results: int
    normalized_findings: int
    skipped_results: int


@dataclass(frozen=True)
class NormalizationResult:
    schema_version: str
    source_format: str
    status: NormalizationStatus
    findings: tuple[UnifiedFinding, ...]
    warnings: tuple[NormalizationWarning, ...]
    summary: NormalizationSummary

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

"""Typed models for cross-scanner merge and deduplication."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from .models import (
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    UnifiedFinding,
)


MERGE_SCHEMA_VERSION = "1.0"


class StringEnum(str, Enum):
    """String enum for JSON output."""


class MergeStatus(StringEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class DeduplicationPolicy:
    line_tolerance: int = 0

    def validate(self) -> None:
        if self.line_tolerance < 0 or self.line_tolerance > 100:
            raise ValueError("line_tolerance must be between 0 and 100")


@dataclass(frozen=True)
class SourceCoverage:
    scanner_id: str
    source_format: str
    normalization_status: str
    findings: int
    skipped_results: int
    warning_count: int


@dataclass(frozen=True)
class MergedFinding:
    merged_finding_id: str
    schema_version: str
    canonical_finding: UnifiedFinding
    source_findings: tuple[UnifiedFinding, ...]
    scanners: tuple[str, ...]
    rule_ids: tuple[str, ...]
    severity: FindingSeverity
    confidence: FindingConfidence
    cwes: tuple[str, ...]
    categories: tuple[str, ...]
    primary_location: FindingLocation
    merge_reasons: tuple[str, ...]


@dataclass(frozen=True)
class MergeSummary:
    input_batches: int
    input_findings: int
    merged_findings: int
    duplicates_collapsed: int


@dataclass(frozen=True)
class MergeResult:
    schema_version: str
    status: MergeStatus
    findings: tuple[MergedFinding, ...]
    source_coverage: tuple[SourceCoverage, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    summary: MergeSummary

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

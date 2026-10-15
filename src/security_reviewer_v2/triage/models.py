"""Auditable issue-level grouping without turning AI candidates into verdicts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class TriageDisposition(str, Enum):
    SCANNER_OVERLAP = "scanner_overlap"
    CANDIDATE_OVERLAP = "candidate_overlap"
    NOVEL_CANDIDATE = "novel_candidate"
    UNCERTAIN_OVERLAP = "uncertain_overlap"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    REJECTED = "rejected"


@dataclass(frozen=True)
class TriageRecord:
    candidate_id: str
    disposition: TriageDisposition
    group_id: str | None
    related_scanner_ids: tuple[str, ...]
    related_candidate_ids: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class IssueGroup:
    group_id: str
    family: str
    path: str | None
    scanner_finding_ids: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class TriageSummary:
    input_scanner_findings: int
    input_ai_candidates: int
    review_groups: int
    scanner_overlap: int
    candidate_overlap: int
    novel_candidates: int
    uncertain_overlap: int
    needs_more_evidence: int
    rejected: int


@dataclass(frozen=True)
class TriageResult:
    schema_version: str
    status: str
    groups: tuple[IssueGroup, ...]
    records: tuple[TriageRecord, ...]
    summary: TriageSummary
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _primitive(asdict(value))
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    return value

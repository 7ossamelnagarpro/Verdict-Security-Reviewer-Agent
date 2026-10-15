"""Typed results for the deterministic evidence gate before human/AI review."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class VerificationDisposition(str, Enum):
    CONFIRMED = "confirmed"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    REJECTED = "rejected"


@dataclass(frozen=True)
class VerificationRecord:
    candidate_id: str
    disposition: VerificationDisposition
    path: str | None
    start_line: int | None
    end_line: int | None
    checks: tuple[str, ...]
    evidence: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class VerificationResult:
    schema_version: str
    status: str
    project_root: str
    records: tuple[VerificationRecord, ...]
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
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    return value

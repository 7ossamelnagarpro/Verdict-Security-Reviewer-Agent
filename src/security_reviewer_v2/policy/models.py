from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    candidate_id: str
    action: str
    severity: str
    verdict: str
    reason: str


@dataclass(frozen=True)
class PolicyResult:
    schema_version: str
    status: str
    blocking: bool
    decisions: tuple[PolicyDecision, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


def _primitive(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _primitive(asdict(value))
    if isinstance(value, dict):
        return {str(k): _primitive(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(v) for v in value]
    return value

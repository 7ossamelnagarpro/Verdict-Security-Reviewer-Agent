"""Typed, auditable models for the AI Discovery stage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

DISCOVERY_SCHEMA_VERSION = "1.2"


class DiscoveryStatus(str, Enum):
    COMPLETED = "completed"
    DISABLED = "disabled"
    BLOCKED = "blocked"
    PARTIAL = "partial"


class CandidateDisposition(str, Enum):
    SUPPORTED = "supported"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


@dataclass(frozen=True)
class DiscoveryConfig:
    provider: str = "groq"
    model: str = "openai/gpt-oss-20b"
    max_targets: int = 10
    max_candidates: int = 20
    max_context_chars: int = 20_000
    timeout_seconds: int | None = None
    temperature: float = 0.0
    max_files_considered: int = 64
    max_source_file_bytes: int = 128_000
    max_total_source_bytes: int = 2_000_000
    max_planned_targets: int = 128
    max_batches: int = 20
    max_total_candidates: int = 100
    max_enrichment_rounds: int = 2
    max_context_requests_per_batch: int = 4
    max_context_lines: int = 80
    max_context_response_chars: int = 2_000
    max_enrichment_total_bytes: int = 512_000
    max_hotspots_per_file: int = 100
    input_cost_per_million_tokens_usd: float | None = None
    output_cost_per_million_tokens_usd: float | None = None

    def validate(self) -> None:
        if not 1 <= self.max_targets <= 100:
            raise ValueError("max_targets must be between 1 and 100")
        if not 1 <= self.max_candidates <= 100:
            raise ValueError("max_candidates must be between 1 and 100")
        if not 1_000 <= self.max_context_chars <= 500_000:
            raise ValueError("max_context_chars must be between 1000 and 500000")
        if self.timeout_seconds is not None and not 1 <= self.timeout_seconds <= 86_400:
            raise ValueError("timeout_seconds must be between 1 and 86400 when configured")
        if not 1 <= self.max_files_considered <= 10_000:
            raise ValueError("max_files_considered must be between 1 and 10000")
        if not 1_000 <= self.max_source_file_bytes <= 10_000_000:
            raise ValueError("max_source_file_bytes must be between 1000 and 10000000")
        if self.max_total_source_bytes < self.max_source_file_bytes:
            raise ValueError("max_total_source_bytes must cover at least one source file")
        if not 1 <= self.max_hotspots_per_file <= 200:
            raise ValueError("max_hotspots_per_file must be between 1 and 200")
        if not 1 <= self.max_planned_targets <= 10_000:
            raise ValueError("max_planned_targets must be between 1 and 10000")
        if not 1 <= self.max_batches <= 1_000:
            raise ValueError("max_batches must be between 1 and 1000")
        if not 1 <= self.max_total_candidates <= 10_000:
            raise ValueError("max_total_candidates must be between 1 and 10000")
        if not 0 <= self.max_enrichment_rounds <= 10:
            raise ValueError("max_enrichment_rounds must be between 0 and 10")
        if not 0 <= self.max_context_requests_per_batch <= 20:
            raise ValueError("max_context_requests_per_batch must be between 0 and 20")
        if not 1 <= self.max_context_lines <= 500:
            raise ValueError("max_context_lines must be between 1 and 500")
        if not 100 <= self.max_context_response_chars <= 10_000:
            raise ValueError("max_context_response_chars must be between 100 and 10000")
        if self.max_enrichment_total_bytes < 1:
            raise ValueError("max_enrichment_total_bytes must be positive")
        if any(value is not None and value < 0 for value in (self.input_cost_per_million_tokens_usd, self.output_cost_per_million_tokens_usd)):
            raise ValueError("configured token rates must not be negative")


@dataclass(frozen=True)
class DiscoveryTarget:
    target_id: str
    kind: str
    path: str | None
    start_line: int | None
    end_line: int | None
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CandidateAnchor:
    path: str
    line: int
    code: str


@dataclass(frozen=True)
class CandidateMissingCheck:
    path: str
    line: int
    expected_check: str
    observation: str


@dataclass(frozen=True)
class DiscoveryBatch:
    batch_index: int
    target_ids: tuple[str, ...]
    status: str
    prompt_chars: int
    provider_calls: int
    candidate_count: int
    context_requests: int
    usage: dict[str, Any]
    error: str | None = None
    candidate_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContextExchange:
    batch_index: int
    round_index: int
    requested_path: str | None
    symbol: str | None
    requested_start_line: int | None
    requested_end_line: int | None
    status: str
    resolved_path: str | None
    resolved_start_line: int | None
    resolved_end_line: int | None
    code: str | None
    note: str | None


@dataclass(frozen=True)
class CandidateFinding:
    candidate_id: str
    title: str
    category: str
    severity: str
    confidence: str
    path: str | None
    start_line: int | None
    end_line: int | None
    evidence: tuple[str, ...]
    reasoning: str
    source: str
    verification: CandidateDisposition
    verification_notes: tuple[str, ...]
    entry_point: CandidateAnchor | None = None
    sensitive_operation: CandidateAnchor | None = None
    missing_check: CandidateMissingCheck | None = None
    remaining_questions: tuple[str, ...] = ()
    # Discovery only reads source; it never runs the application, so nothing here is dynamic evidence.  Dynamic
    # corroboration, when it exists, is attached later by triage from probes that hit the same route.
    analysis: str = "static_source_review"
    duplicate_ids: tuple[str, ...] = ()   # AI candidates merged into this one because they state the same root cause


@dataclass(frozen=True)
class DiscoveryResult:
    schema_version: str
    status: DiscoveryStatus
    provider: str
    model: str | None
    scope: tuple[str, ...]
    candidates: tuple[CandidateFinding, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    usage: dict[str, Any]
    target_plan: tuple[DiscoveryTarget, ...] = ()
    batches: tuple[DiscoveryBatch, ...] = ()
    context_exchanges: tuple[ContextExchange, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _primitive(self)


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _primitive(asdict(value))
    if isinstance(value, dict):
        return {str(k): _primitive(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_primitive(v) for v in value]
    return value

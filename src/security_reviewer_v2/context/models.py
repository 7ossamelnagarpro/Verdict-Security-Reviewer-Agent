"""Typed output models for deterministic source-context collection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from security_reviewer_v2.normalization.models import FindingLocation


CONTEXT_SCHEMA_VERSION = "1.1"


class StringEnum(str, Enum):
    """String enum for stable JSON output."""


class ContextStatus(StringEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class ContextPolicy:
    window_before: int = 4
    window_after: int = 4
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 5_000_000
    max_symbol_lines: int = 120
    follow_symlinks: bool = False

    def validate(self) -> None:
        if not 0 <= self.window_before <= 100:
            raise ValueError("window_before must be between 0 and 100")
        if not 0 <= self.window_after <= 100:
            raise ValueError("window_after must be between 0 and 100")
        if self.max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        if self.max_total_bytes < 1:
            raise ValueError("max_total_bytes must be positive")
        if not 1 <= self.max_symbol_lines <= 1_000:
            raise ValueError("max_symbol_lines must be between 1 and 1000")


@dataclass(frozen=True)
class SourceExcerpt:
    path: str
    start_line: int
    end_line: int
    code: str
    content_sha256: str


@dataclass(frozen=True)
class SymbolContext:
    language: str
    kind: str
    name: str
    qualified_name: str
    start_line: int
    end_line: int
    excerpt: SourceExcerpt
    truncated: bool


@dataclass(frozen=True)
class EvidenceContext:
    evidence_type: str
    scanner_id: str
    rule_id: str
    location: FindingLocation
    message: str | None
    flow_index: int | None
    thread_index: int | None
    step_index: int | None
    excerpt: SourceExcerpt | None
    enclosing_symbol: SymbolContext | None
    collection_status: str
    warning: str | None
    source_finding_id: str | None = None


@dataclass(frozen=True)
class FindingContext:
    merged_finding_id: str
    title: str
    severity: str
    confidence: str
    cwes: tuple[str, ...]
    scanners: tuple[str, ...]
    primary: EvidenceContext
    code_flow: tuple[EvidenceContext, ...]
    related: tuple[EvidenceContext, ...]
    warnings: tuple[str, ...]
    additional_primaries: tuple[EvidenceContext, ...] = ()


@dataclass(frozen=True)
class ContextSummary:
    input_findings: int
    contexts_created: int
    evidence_locations: int
    excerpts_collected: int
    files_read: int
    bytes_read: int
    unavailable_locations: int


@dataclass(frozen=True)
class ContextResult:
    schema_version: str
    status: ContextStatus
    project_root: str
    findings: tuple[FindingContext, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    summary: ContextSummary

    def to_dict(self) -> dict[str, Any]:
        # Keep rich in-memory evidence for consumers, but share repeated source
        # windows and symbols in the persisted artifact and AI prompt.
        payload = _to_primitive(self)
        excerpts: dict[str, dict[str, Any]] = {}
        symbols: dict[str, dict[str, Any]] = {}

        def intern(value: dict[str, Any], table: dict[str, dict[str, Any]], prefix: str) -> str:
            import hashlib
            import json

            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            key = prefix + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            table.setdefault(key, value)
            return key

        for finding in payload["findings"]:
            for item in (finding["primary"], *finding["additional_primaries"], *finding["code_flow"], *finding["related"]):
                symbol = item.pop("enclosing_symbol")
                if symbol is not None:
                    symbol["excerpt_ref"] = intern(symbol.pop("excerpt"), excerpts, "ex-")
                    item["symbol_ref"] = intern(symbol, symbols, "sym-")
                excerpt = item.pop("excerpt")
                if excerpt is not None:
                    item["excerpt_ref"] = intern(excerpt, excerpts, "ex-")
        payload["shared_excerpts"] = {key: excerpts[key] for key in sorted(excerpts)}
        payload["shared_symbols"] = {key: symbols[key] for key in sorted(symbols)}
        return payload


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

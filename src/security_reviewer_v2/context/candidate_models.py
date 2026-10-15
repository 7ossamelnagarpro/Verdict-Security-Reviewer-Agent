"""Source context for AI candidates, separate from scanner findings and verdicts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .models import ContextStatus, EvidenceContext, _to_primitive


CANDIDATE_CONTEXT_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class CandidateContext:
    candidate_id: str
    title: str
    discovery_disposition: str
    primary: EvidenceContext
    entry_point: EvidenceContext | None
    sensitive_operation: EvidenceContext | None
    claimed_missing_check: EvidenceContext | None
    range_end: EvidenceContext | None
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class CandidateContextSummary:
    input_candidates: int
    contexts_created: int
    evidence_locations: int
    excerpts_collected: int
    unavailable_locations: int
    files_read: int
    bytes_read: int


@dataclass(frozen=True)
class CandidateContextResult:
    schema_version: str
    status: ContextStatus
    project_root: str
    candidates: tuple[CandidateContext, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    summary: CandidateContextSummary

    def to_dict(self) -> dict:
        """Share repeated source windows/symbols instead of copying them per candidate."""
        payload = _to_primitive(self)
        excerpts: dict[str, dict] = {}
        symbols: dict[str, dict] = {}

        def intern(value: dict, table: dict[str, dict], prefix: str) -> str:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            key = prefix + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            table.setdefault(key, value)
            return key

        for candidate in payload["candidates"]:
            for role in ("primary", "entry_point", "sensitive_operation", "claimed_missing_check", "range_end"):
                evidence = candidate[role]
                if evidence is None:
                    continue
                symbol = evidence.pop("enclosing_symbol")
                if symbol is not None:
                    symbol["excerpt_ref"] = intern(symbol.pop("excerpt"), excerpts, "ex-")
                    evidence["symbol_ref"] = intern(symbol, symbols, "sym-")
                excerpt = evidence.pop("excerpt")
                if excerpt is not None:
                    evidence["excerpt_ref"] = intern(excerpt, excerpts, "ex-")
        payload["shared_excerpts"] = {key: excerpts[key] for key in sorted(excerpts)}
        payload["shared_symbols"] = {key: symbols[key] for key in sorted(symbols)}
        return payload

"""Bounded, deterministic source context for AI-generated candidates."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from security_reviewer_v2.discovery.models import CandidateFinding, DiscoveryResult, DiscoveryStatus
from security_reviewer_v2.normalization.models import FindingLocation
from security_reviewer_v2.redaction import redact_source

from .candidate_models import (
    CANDIDATE_CONTEXT_SCHEMA_VERSION,
    CandidateContext,
    CandidateContextResult,
    CandidateContextSummary,
)
from .collector import ContextCollectionError, _SourceReader, _collect_evidence, _normal_relative_path
from .models import ContextPolicy, ContextStatus, EvidenceContext, SourceExcerpt


def collect_candidate_context(
    discovery: DiscoveryResult,
    *,
    project_root: str | Path,
    policy: ContextPolicy | None = None,
    profile_artifact: dict[str, Any] | None = None,
) -> CandidateContextResult:
    """Collect cited source windows and enclosing symbols; never execute target code.

    Collected context is evidence to review, not proof that the AI's security
    conclusion or claimed missing authorization check is true.
    """
    selected_policy = policy or ContextPolicy()
    selected_policy.validate()
    root = Path(project_root)
    if not root.is_dir():
        raise ContextCollectionError(f"Project root is not a directory: {root}")
    try:
        root = root.resolve(strict=True)
        next(root.iterdir(), None)
    except OSError as error:
        raise ContextCollectionError(f"Project root is not readable: {root}") from error

    reader = _SourceReader(root, selected_policy, profile_artifact)
    contexts = tuple(_candidate_context(candidate, reader, selected_policy) for candidate in discovery.candidates)
    evidence = tuple(
        item
        for candidate in contexts
        for item in (
            candidate.primary, candidate.entry_point, candidate.sensitive_operation,
            candidate.claimed_missing_check, candidate.range_end,
        )
        if item is not None
    )
    unavailable = sum(item.excerpt is None for item in evidence)
    collected = len(evidence) - unavailable
    gaps = list(discovery.coverage_gaps)
    for candidate in contexts:
        for item in (
            candidate.primary, candidate.entry_point, candidate.sensitive_operation,
            candidate.claimed_missing_check, candidate.range_end,
        ):
            if item is not None and item.excerpt is None:
                gaps.append(f"{candidate.candidate_id}: {item.evidence_type} context unavailable ({item.warning}).")

    if not contexts:
        status = ContextStatus.COMPLETE if discovery.status is DiscoveryStatus.COMPLETED else ContextStatus.PARTIAL
    elif not collected:
        status = ContextStatus.FAILED
    elif unavailable or discovery.status is not DiscoveryStatus.COMPLETED:
        status = ContextStatus.PARTIAL
    else:
        status = ContextStatus.COMPLETE
    return CandidateContextResult(
        schema_version=CANDIDATE_CONTEXT_SCHEMA_VERSION,
        status=status,
        project_root=root.as_posix(),
        candidates=contexts,
        warnings=tuple(sorted(set((*discovery.warnings, *(warning for item in contexts for warning in item.warnings))))),
        coverage_gaps=tuple(sorted(set(gaps))),
        summary=CandidateContextSummary(
            input_candidates=len(discovery.candidates),
            contexts_created=len(contexts),
            evidence_locations=len(evidence),
            excerpts_collected=collected,
            unavailable_locations=unavailable,
            files_read=len({item.relative_path for item in reader.cache.values()}),
            bytes_read=reader.bytes_read,
        ),
    )


def _candidate_context(candidate: CandidateFinding, reader: _SourceReader, policy: ContextPolicy) -> CandidateContext:
    def collect(path: str | None, line: int | None, role: str) -> EvidenceContext:
        return _candidate_evidence(reader, policy, candidate, path, line, role)

    primary = collect(candidate.path, candidate.start_line, "primary")
    entry = collect(candidate.entry_point.path, candidate.entry_point.line, "entry_point") if candidate.entry_point else None
    sink = collect(candidate.sensitive_operation.path, candidate.sensitive_operation.line, "sensitive_operation") if candidate.sensitive_operation else None
    missing = collect(candidate.missing_check.path, candidate.missing_check.line, "claimed_missing_check") if candidate.missing_check else None
    range_end = None
    if (primary.excerpt is not None and candidate.path and type(candidate.start_line) is int and type(candidate.end_line) is int
            and candidate.end_line > candidate.start_line + policy.window_after):
        range_end = collect(candidate.path, candidate.end_line, "range_end")
    items = (primary, entry, sink, missing, range_end)
    return CandidateContext(
        candidate_id=candidate.candidate_id,
        title=redact_source(candidate.title),
        discovery_disposition=candidate.verification.value,
        primary=primary,
        entry_point=entry,
        sensitive_operation=sink,
        claimed_missing_check=missing,
        range_end=range_end,
        warnings=tuple(sorted({item.warning for item in items if item is not None and item.warning is not None})),
    )


def _candidate_evidence(
    reader: _SourceReader,
    policy: ContextPolicy,
    candidate: CandidateFinding,
    path: str | None,
    line: int | None,
    role: str,
) -> EvidenceContext:
    location = FindingLocation(path or "", line, None, line, None)
    try:
        if not path:
            raise ContextCollectionError("candidate_path_missing")
        relative = _normal_relative_path(path)
        if type(line) is not int or line < 1:
            raise ContextCollectionError(f"candidate_line_missing_or_invalid:{relative}")
        # AI-cited paths must resolve exactly. A unique suffix is useful for
        # scanner output but must not silently remap an AI candidate's claim.
        if reader.index is not None and relative not in reader.index:
            raise ContextCollectionError(f"source_not_in_profile:{relative}")
        lexical = reader.root.joinpath(*PurePosixPath(relative).parts)
        if not lexical.exists():
            raise ContextCollectionError(f"source_unavailable:{relative}")
        collected = _collect_evidence(
            reader, policy, evidence_type=role, scanner_id="ai-discovery",
            rule_id=candidate.category, location=location, message=None,
            source_finding_id=candidate.candidate_id,
        )
    except ContextCollectionError as error:
        collected = EvidenceContext(
            evidence_type=role, scanner_id="ai-discovery", rule_id=candidate.category,
            location=location, message=None, flow_index=None, thread_index=None,
            step_index=None, excerpt=None, enclosing_symbol=None,
            collection_status="unavailable", warning=str(error),
            source_finding_id=candidate.candidate_id,
        )
    if collected.excerpt is None:
        return collected
    excerpt = _redact_excerpt(collected.excerpt)
    symbol = collected.enclosing_symbol
    if symbol is not None:
        symbol = replace(symbol, excerpt=_redact_excerpt(symbol.excerpt))
    return replace(collected, excerpt=excerpt, enclosing_symbol=symbol)


def _redact_excerpt(excerpt: SourceExcerpt) -> SourceExcerpt:
    return replace(excerpt, code=redact_source(excerpt.code))

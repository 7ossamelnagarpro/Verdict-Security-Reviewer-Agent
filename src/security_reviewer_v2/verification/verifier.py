"""Deterministic evidence checks for AI-discovered candidates.

This layer does not decide business impact and does not replace the Security
Review Agent. It only checks that a candidate is grounded in the repository.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from security_reviewer_v2.context.candidate_models import (
    CandidateContext,
    CandidateContextResult,
)
from security_reviewer_v2.discovery.models import (
    CandidateDisposition,
    CandidateFinding,
    DiscoveryResult,
)

from .models import VerificationDisposition, VerificationRecord, VerificationResult


def verify_discovery(
    result: DiscoveryResult,
    *,
    project_root: str | Path,
    candidate_context: CandidateContextResult | None = None,
) -> VerificationResult:
    root = Path(project_root).resolve()
    context_by_id = (
        {item.candidate_id: item for item in candidate_context.candidates}
        if candidate_context
        else {}
    )
    records = tuple(
        _verify_candidate(
            candidate,
            root,
            context_by_id.get(candidate.candidate_id),
            require_context=candidate_context is not None,
        )
        for candidate in result.candidates
    )
    status = "completed" if result.status.value == "completed" else "partial"
    warnings = list(result.warnings)
    if not records:
        warnings.append("No AI candidates were available for verification.")
    return VerificationResult(
        "1.0", status, str(root), records, tuple(dict.fromkeys(warnings))
    )


def _verify_candidate(
    candidate: CandidateFinding,
    root: Path,
    context: CandidateContext | None = None,
    *,
    require_context: bool = False,
) -> VerificationRecord:
    checks: list[str] = []
    notes: list[str] = []
    notes.extend(
        note
        for note in candidate.verification_notes
        if note.startswith("source_citation_reanchored:")
    )
    evidence = tuple(candidate.evidence)
    path = candidate.path
    disposition = VerificationDisposition.NEEDS_MORE_EVIDENCE

    if not path:
        notes.append("No repository path was supplied.")
        return VerificationRecord(
            candidate.candidate_id,
            disposition,
            path,
            candidate.start_line,
            candidate.end_line,
            tuple(checks),
            evidence,
            tuple(notes),
        )

    file_path = (root / path).resolve()
    try:
        file_path.relative_to(root)
    except ValueError:
        notes.append("Candidate path escapes the project root.")
        return VerificationRecord(
            candidate.candidate_id,
            VerificationDisposition.REJECTED,
            path,
            candidate.start_line,
            candidate.end_line,
            tuple(checks),
            evidence,
            tuple(notes),
        )
    if not file_path.is_file():
        notes.append("Candidate file does not exist.")
        return VerificationRecord(
            candidate.candidate_id,
            VerificationDisposition.REJECTED,
            path,
            candidate.start_line,
            candidate.end_line,
            tuple(checks),
            evidence,
            tuple(notes),
        )
    checks.append("file_exists")

    try:
        source_bytes = file_path.read_bytes()
        lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    except OSError:
        notes.append("Candidate file could not be read.")
        return VerificationRecord(
            candidate.candidate_id,
            VerificationDisposition.NEEDS_MORE_EVIDENCE,
            path,
            candidate.start_line,
            candidate.end_line,
            tuple(checks),
            evidence,
            tuple(notes),
        )

    start = candidate.start_line or 1
    end = candidate.end_line or start
    if start < 1 or end < start or start > len(lines):
        notes.append("Reported line range is outside the file.")
        return VerificationRecord(
            candidate.candidate_id,
            VerificationDisposition.REJECTED,
            path,
            candidate.start_line,
            candidate.end_line,
            tuple(checks),
            evidence,
            tuple(notes),
        )
    end = min(end, len(lines))
    checks.append("line_range_valid")
    excerpt = "\n".join(lines[start - 1 : end])
    matched = tuple(
        item
        for item in evidence
        if _evidence_in_excerpt(item, lines, start, end, excerpt)
    )
    if evidence and len(matched) == len(evidence):
        checks.append("evidence_present_in_excerpt")
    elif matched:
        notes.append("Some AI evidence was not found at its cited source lines.")
    else:
        notes.append("AI evidence was not found in the reported source excerpt.")

    context_issues: list[str] = []
    if require_context and context is None:
        context_issues.append("Candidate context package is missing.")
    elif context is not None:
        cited = (
            ("primary", context.primary),
            ("entry_point", context.entry_point),
            ("sensitive_operation", context.sensitive_operation),
            ("claimed_missing_check", context.claimed_missing_check),
            ("range_end", context.range_end),
        )
        for role, item in cited:
            if item is not None and item.excerpt is None:
                context_issues.append(f"{role} context is unavailable: {item.warning}")
        if context.primary.excerpt is not None:
            digest = hashlib.sha256(source_bytes).hexdigest()
            if context.primary.excerpt.content_sha256 != digest:
                context_issues.append(
                    "Source file changed after candidate context collection."
                )
            else:
                checks.append("candidate_context_snapshot_matches")
    notes.extend(context_issues)

    # A candidate already rejected by the discovery-stage grounding check stays rejected.
    if candidate.verification is CandidateDisposition.REJECTED:
        notes.append("Discovery stage rejected the candidate grounding.")
        disposition = VerificationDisposition.REJECTED
    elif candidate.verification is CandidateDisposition.INCONCLUSIVE:
        disposition = VerificationDisposition.NEEDS_MORE_EVIDENCE
        notes.append(
            "Discovery stage could not ground all required structured evidence."
        )
    elif (
        evidence
        and len(matched) == len(evidence)
        and len(checks) >= 3
        and not context_issues
    ):
        disposition = VerificationDisposition.CONFIRMED
        notes.append(
            "Repository and source evidence checks passed; security impact still requires review."
        )
    else:
        disposition = VerificationDisposition.NEEDS_MORE_EVIDENCE
    return VerificationRecord(
        candidate.candidate_id,
        disposition,
        path,
        candidate.start_line,
        candidate.end_line,
        tuple(checks),
        evidence,
        tuple(notes),
    )


def _evidence_in_excerpt(
    item: str, lines: list[str], start: int, end: int, excerpt: str
) -> bool:
    cited = item.strip()
    if not cited:
        return False
    numbered = re.fullmatch(r"(\d+):\s*(\S.*)", cited)
    if numbered:
        line = int(numbered.group(1))
        return (
            start <= line <= end
            and numbered.group(2).strip().casefold()
            == lines[line - 1].strip().casefold()
        )
    return cited.casefold() in excerpt.casefold()

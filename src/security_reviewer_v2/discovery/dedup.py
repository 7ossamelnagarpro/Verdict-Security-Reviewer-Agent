"""Deterministic removal of duplicate AI candidates (same root cause stated twice).

The model often restates one issue under two titles (``/me`` as "sensitive data exposure" and again as "information
disclosure").  Two candidates are the same root cause when they point at the same sensitive operation *and* the same
missing check.  Anything less certain is kept, because wrongly merging two real vulnerabilities is worse than showing
one issue twice; triage still groups the remaining overlaps with scanner findings.
"""

from __future__ import annotations

from dataclasses import replace

from .models import CandidateDisposition, CandidateFinding

_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_DISPOSITION = {CandidateDisposition.SUPPORTED: 2, CandidateDisposition.INCONCLUSIVE: 1, CandidateDisposition.REJECTED: 0}


def _path(value: str | None) -> str:
    return (value or "").replace("\\", "/").casefold()


def is_duplicate(first: CandidateFinding, second: CandidateFinding) -> bool:
    left, right = first.sensitive_operation, second.sensitive_operation
    if left is None or right is None or not first.path or _path(first.path) != _path(second.path):
        return False
    if _path(left.path) != _path(right.path) or left.line != right.line:
        return False
    a, b = first.missing_check, second.missing_check
    if a is not None and b is not None:
        if a.line == b.line:
            return True   # one missing check at one location is one root cause, whatever the title says
        return False
    # One side names no missing check: only merge when both describe the same class of issue.
    return first.category.strip().casefold() == second.category.strip().casefold()


def _strength(candidate: CandidateFinding) -> tuple[int, int, int, int]:
    return (_DISPOSITION.get(candidate.verification, 0), int(candidate.missing_check is not None),
            _RANK.get(candidate.severity.lower(), 0), {"high": 3, "medium": 2, "low": 1}.get(candidate.confidence.lower(), 0))


def collapse_duplicate_candidates(
    candidates: tuple[CandidateFinding, ...],
) -> tuple[tuple[CandidateFinding, ...], dict[str, tuple[str, ...]]]:
    """Keep the strongest candidate of every duplicate set; return it plus ``{kept_id: removed ids}``."""
    survivors: list[CandidateFinding] = []
    removed: dict[str, list[str]] = {}
    for candidate in candidates:
        match = next((index for index, kept in enumerate(survivors) if is_duplicate(kept, candidate)), None)
        if match is None:
            survivors.append(candidate)
            continue
        kept = survivors[match]
        winner, loser = (candidate, kept) if _strength(candidate) > _strength(kept) else (kept, candidate)
        removed.setdefault(winner.candidate_id, []).extend(removed.pop(kept.candidate_id, []) if winner is candidate else [])
        removed[winner.candidate_id].append(loser.candidate_id)
        survivors[match] = winner
    result = []
    for candidate in survivors:
        ids = tuple(dict.fromkeys(removed.get(candidate.candidate_id, ())))
        if ids:
            note = f"Merged {len(ids)} duplicate AI candidate(s) describing the same root cause: {', '.join(ids)}."
            candidate = replace(candidate, duplicate_ids=ids, verification_notes=(*candidate.verification_notes, note))
        result.append(candidate)
    return tuple(result), {candidate.candidate_id: candidate.duplicate_ids for candidate in result if candidate.duplicate_ids}

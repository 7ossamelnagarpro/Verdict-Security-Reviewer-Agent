"""Conservative, deterministic grouping of scanner and AI evidence."""

from .engine import triage_candidates
from .models import IssueGroup, TriageDisposition, TriageRecord, TriageResult

__all__ = [
    "IssueGroup",
    "TriageDisposition",
    "TriageRecord",
    "TriageResult",
    "triage_candidates",
]

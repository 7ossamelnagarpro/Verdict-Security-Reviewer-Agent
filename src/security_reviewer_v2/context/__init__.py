"""Code context collection components."""

from .collector import ContextCollectionError, collect_context
from .candidate_collector import collect_candidate_context
from .candidate_models import CandidateContext, CandidateContextResult, CandidateContextSummary
from .models import (
    CONTEXT_SCHEMA_VERSION,
    ContextPolicy,
    ContextResult,
    ContextStatus,
)
from .serialization import (
    ContextArtifactError,
    context_result_from_dict,
    load_context_result,
)

__all__ = [
    "CONTEXT_SCHEMA_VERSION",
    "ContextCollectionError",
    "ContextArtifactError",
    "ContextPolicy",
    "ContextResult",
    "ContextStatus",
    "collect_context",
    "collect_candidate_context",
    "CandidateContext",
    "CandidateContextResult",
    "CandidateContextSummary",
    "context_result_from_dict",
    "load_context_result",
]

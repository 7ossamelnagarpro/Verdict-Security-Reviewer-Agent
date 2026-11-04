"""Code context collection components."""

from .candidate_collector import collect_candidate_context
from .candidate_models import (
    CandidateContext,
    CandidateContextResult,
    CandidateContextSummary,
)
from .collector import ContextCollectionError, collect_context
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
    "CandidateContext",
    "CandidateContextResult",
    "CandidateContextSummary",
    "ContextArtifactError",
    "ContextCollectionError",
    "ContextPolicy",
    "ContextResult",
    "ContextStatus",
    "collect_candidate_context",
    "collect_context",
    "context_result_from_dict",
    "load_context_result",
]

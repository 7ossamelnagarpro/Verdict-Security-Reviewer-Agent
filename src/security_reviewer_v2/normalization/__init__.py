"""Scanner-independent finding normalization."""

from .codeql import (
    NormalizationInputError,
    normalize_codeql_sarif,
    normalize_codeql_sarif_file,
)
from .gitleaks import normalize_gitleaks_json, normalize_gitleaks_json_file
from .merge import merge_normalized_findings
from .merge_models import DeduplicationPolicy, MergedFinding, MergeResult, MergeStatus
from .models import (
    FindingConfidence,
    FindingSeverity,
    NormalizationResult,
    NormalizationStatus,
    UnifiedFinding,
)
from .semgrep import normalize_semgrep_json, normalize_semgrep_json_file
from .serialization import (
    NormalizedArtifactError,
    load_merge_result,
    load_normalization_result,
    merge_result_from_dict,
)
from .trivy import normalize_trivy_json, normalize_trivy_json_file

__all__ = [
    "DeduplicationPolicy",
    "FindingConfidence",
    "FindingSeverity",
    "MergeResult",
    "MergeStatus",
    "MergedFinding",
    "NormalizationInputError",
    "NormalizationResult",
    "NormalizationStatus",
    "NormalizedArtifactError",
    "UnifiedFinding",
    "load_merge_result",
    "load_normalization_result",
    "merge_normalized_findings",
    "merge_result_from_dict",
    "normalize_codeql_sarif",
    "normalize_codeql_sarif_file",
    "normalize_gitleaks_json",
    "normalize_gitleaks_json_file",
    "normalize_semgrep_json",
    "normalize_semgrep_json_file",
    "normalize_trivy_json",
    "normalize_trivy_json_file",
]
from .authorization import normalize_authorization_json_file
from .runtime import normalize_runtime_json_file

__all__ = ["normalize_authorization_json_file", "normalize_runtime_json_file"]

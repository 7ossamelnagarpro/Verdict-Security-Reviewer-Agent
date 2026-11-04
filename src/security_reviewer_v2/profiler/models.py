"""Typed, JSON-serializable models for deterministic project profiling."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0"
POLICY_VERSION = "1.0"


class StringEnum(str, Enum):
    """String enum whose values serialize without custom encoders."""


class Completeness(StringEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class Confidence(StringEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FileCategory(StringEnum):
    SOURCE = "source"
    TEST = "test"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    LOCKFILE = "lockfile"
    CONFIGURATION = "configuration"
    GENERATED = "generated"
    VENDOR = "vendor"
    BINARY = "binary"
    UNKNOWN = "unknown"


class SkipCause(StringEnum):
    POLICY = "policy"
    RESOURCE_LIMIT = "resource_limit"
    READ_ERROR = "read_error"
    SYMLINK = "symlink"
    OUTSIDE_ROOT = "outside_root"
    DISAPPEARED = "disappeared"


class ScanType(StringEnum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    SECRETS = "secrets"
    MISCONFIGURATION = "misconfiguration"
    CONTAINER_IMAGE = "container_image"


class PlanStatus(StringEnum):
    SELECTED = "selected"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    NEEDS_VERIFICATION = "needs_verification"
    DISABLED_BY_POLICY = "disabled_by_policy"


class PrerequisiteState(StringEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class ProfilerLimits:
    max_files: int = 10_000
    max_file_size_bytes: int = 10 * 1024 * 1024
    max_content_read_bytes: int = 64 * 1024
    max_total_content_bytes: int = 2 * 1024 * 1024
    max_depth: int = 30
    timeout_seconds: float = 30.0

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


@dataclass(frozen=True)
class ProfilerPolicy:
    version: str = POLICY_VERSION
    allow_symlinks: bool = False
    enabled_scanners: tuple[str, ...] = (
        "semgrep-ce",
        "codeql-cli",
        "gitleaks",
        "trivy",
        "idor-dast",
    )
    disabled_scanners: tuple[str, ...] = ()
    additional_discovery_exclusions: tuple[str, ...] = ()
    sast_exclusions: tuple[str, ...] = (
        ".git/**",
        ".venv/**",
        "node_modules/**",
        "vendor/**",
        "dist/**",
        "build/**",
        "__pycache__",
        "*.pyc",
    )
    dependency_exclusions: tuple[str, ...] = (
        ".git/**",
        ".venv/**",
        "node_modules/**",
        "vendor/**",
    )
    secret_exclusions: tuple[str, ...] = (
        ".git/**",
        ".venv/**",
        "node_modules/**",
        "vendor/**",
        "*.png",
        "*.jpg",
        "*.gif",
        "*.pdf",
    )
    configuration_exclusions: tuple[str, ...] = (
        ".git/**",
        ".venv/**",
        "node_modules/**",
        "vendor/**",
    )
    prerequisite_states: dict[str, PrerequisiteState] = field(default_factory=dict)
    # Large components are split into deterministic SAST scopes. CodeQL is
    # intentionally kept at component scope because cross-file data flow can
    # be lost when its source root is split.
    large_component_file_threshold: int = 750
    large_component_byte_threshold: int = 20 * 1024 * 1024
    sast_chunk_size: int = 8

    def validate(self) -> None:
        overlap = set(self.enabled_scanners) & set(self.disabled_scanners)
        if overlap:
            raise ValueError(
                "Scanners cannot be both enabled and disabled: "
                + ", ".join(sorted(overlap))
            )
        for pattern in self.additional_discovery_exclusions:
            if (
                not pattern
                or pattern.startswith(("/", "\\"))
                or ".." in pattern.split("/")
            ):
                raise ValueError(f"Unsafe discovery exclusion: {pattern!r}")
        if self.large_component_file_threshold <= 0:
            raise ValueError("large_component_file_threshold must be greater than zero")
        if self.large_component_byte_threshold <= 0:
            raise ValueError("large_component_byte_threshold must be greater than zero")
        if self.sast_chunk_size <= 0:
            raise ValueError("sast_chunk_size must be greater than zero")


@dataclass(frozen=True)
class Evidence:
    path: str
    evidence_type: str
    detail: str


@dataclass(frozen=True)
class FileRecord:
    path: str
    extension: str
    size_bytes: int
    category: FileCategory


@dataclass(frozen=True)
class SkippedItem:
    path: str
    reason: str
    cause: SkipCause


@dataclass(frozen=True)
class ExclusionRecord:
    scope: str
    pattern: str
    reason: str
    effect: str


@dataclass(frozen=True)
class Detection:
    name: str
    component_id: str
    confidence: Confidence
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class DependencyRecord:
    name: str
    version: str | None
    version_kind: str
    scope: str


@dataclass(frozen=True)
class DependencyFile:
    path: str
    component_id: str
    ecosystem: str
    package_manager: str
    kind: str
    parse_status: str
    linked_file: str | None = None
    dependencies: tuple[DependencyRecord, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ComponentProfile:
    component_id: str
    root: str
    kind: str
    confidence: Confidence
    evidence: tuple[Evidence, ...]
    languages: tuple[Detection, ...]
    frameworks: tuple[Detection, ...]
    dependency_files: tuple[DependencyFile, ...]
    file_count: int = 0
    total_bytes: int = 0


@dataclass(frozen=True)
class GitMetadata:
    present: bool
    marker_kind: str
    marker_path: str | None
    history_status: str


@dataclass(frozen=True)
class TargetMetadata:
    dockerfiles: tuple[str, ...] = ()
    compose_files: tuple[str, ...] = ()
    iac_files: tuple[str, ...] = ()
    ci_files: tuple[str, ...] = ()
    secret_candidate_files: tuple[str, ...] = ()
    runtime_manifests: tuple[str, ...] = ()


@dataclass(frozen=True)
class InventorySummary:
    total_files: int
    total_bytes: int
    content_bytes_read: int
    skipped_count: int
    by_category: dict[str, int]


@dataclass(frozen=True)
class ProjectProfile:
    schema_version: str
    root_name: str
    completeness: Completeness
    inventory: tuple[FileRecord, ...]
    inventory_summary: InventorySummary
    components: tuple[ComponentProfile, ...]
    git: GitMetadata
    targets: TargetMetadata
    exclusions: tuple[ExclusionRecord, ...]
    skipped: tuple[SkippedItem, ...]
    warnings: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    policy_version: str
    registry_version: str


@dataclass(frozen=True)
class ScannerCapability:
    scanner_id: str
    display_name: str
    edition: str
    scan_types: tuple[ScanType, ...]
    languages: tuple[str, ...]
    ecosystems: tuple[str, ...]
    target_kinds: tuple[str, ...]
    modes: tuple[str, ...]
    rule_references: tuple[str, ...]
    prerequisites: tuple[str, ...]
    verified_version: str
    capability_status: str
    limitations: tuple[str, ...]
    official_reference: str
    verified_on: str


@dataclass(frozen=True)
class ScanTask:
    task_id: str
    scanner_id: str
    scan_type: ScanType
    component_id: str | None
    target_paths: tuple[str, ...]
    language_or_ecosystem: str | None
    mode: str
    rule_references: tuple[str, ...]
    exclusions: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    reasons: tuple[str, ...]
    prerequisites: tuple[str, ...]
    prerequisite_status: PrerequisiteState
    status: PlanStatus
    resource_class: str = "standard"


@dataclass(frozen=True)
class ScanPlan:
    schema_version: str
    policy_version: str
    registry_version: str
    tasks: tuple[ScanTask, ...]
    coverage_gaps: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class ProfileResult:
    profile: ProjectProfile
    scan_plan: ScanPlan

    def to_dict(self) -> dict[str, Any]:
        return _to_primitive(self)


def _to_primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {
            field_name: _to_primitive(field_value)
            for field_name, field_value in asdict(value).items()
        }
    if isinstance(value, dict):
        return {str(key): _to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_primitive(item) for item in value]
    return value

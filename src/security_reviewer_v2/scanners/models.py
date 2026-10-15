"""Typed models shared by scanner adapters and the orchestrator."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from security_reviewer_v2.profiler.models import ScanTask


EXECUTION_SCHEMA_VERSION = "1.0"


class StringEnum(str, Enum):
    """Enum whose values serialize naturally to JSON."""


class ExecutionStatus(StringEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    ADAPTER_UNAVAILABLE = "adapter_unavailable"
    PREREQUISITE_MISSING = "prerequisite_missing"
    PREREQUISITE_UNVERIFIED = "prerequisite_unverified"
    UNSUPPORTED = "unsupported"
    INVALID_OUTPUT = "invalid_output"


class OverallRunStatus(StringEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class CheckStatus(StringEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class PrerequisiteCheck:
    name: str
    status: CheckStatus
    detail: str
    version: str | None = None


@dataclass(frozen=True)
class CommandSpec:
    """Trusted executable plus a separate argument vector; never a shell string."""

    name: str
    executable: str
    arguments: tuple[str, ...]
    working_directory: str
    timeout_seconds: float
    environment: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.name:
            raise ValueError("Command name is required")
        if not Path(self.executable).is_absolute():
            raise ValueError("Command executable must be an absolute trusted path")
        if not Path(self.working_directory).is_absolute():
            raise ValueError("Command working directory must be absolute")
        if self.timeout_seconds <= 0:
            raise ValueError("Command timeout must be greater than zero")
        if any("\x00" in value for value in (self.executable, *self.arguments)):
            raise ValueError("Command values cannot contain null bytes")


@dataclass(frozen=True)
class AdapterExecutionPlan:
    commands: tuple[CommandSpec, ...]
    expected_outputs: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionRequest:
    run_id: str
    task: ScanTask
    project_root: str
    task_directory: str
    timeout_seconds: float


@dataclass(frozen=True)
class CommandResult:
    name: str
    status: ExecutionStatus
    exit_code: int | None
    duration_seconds: float
    stdout_log: str
    stderr_log: str
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True)
class TaskExecutionResult:
    task_id: str
    scanner_id: str
    status: ExecutionStatus
    reason: str
    prerequisite_checks: tuple[PrerequisiteCheck, ...]
    commands: tuple[CommandResult, ...]
    raw_outputs: tuple[str, ...]
    started_at: str | None
    finished_at: str | None


@dataclass(frozen=True)
class ExecutionSummary:
    schema_version: str
    run_id: str
    status: OverallRunStatus
    project_root_name: str
    started_at: str
    finished_at: str
    tasks: tuple[TaskExecutionResult, ...]
    coverage_gaps: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _to_primitive(self)


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


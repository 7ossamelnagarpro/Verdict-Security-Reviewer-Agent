"""Scanner adapter contract."""

from __future__ import annotations

from abc import ABC, abstractmethod

from security_reviewer_v2.profiler.models import ScanTask

from .models import (
    AdapterExecutionPlan,
    ExecutionRequest,
    PrerequisiteCheck,
)


class ScannerAdapter(ABC):
    """Uniform contract for scanner-specific preparation and validation."""

    scanner_id: str

    @abstractmethod
    def supports(self, task: ScanTask) -> bool:
        """Return whether this adapter supports the planned task."""

    @abstractmethod
    def check_prerequisites(
        self,
        task: ScanTask,
        *,
        project_root: str,
    ) -> tuple[PrerequisiteCheck, ...]:
        """Check local requirements without installing or downloading anything."""

    @abstractmethod
    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        """Create trusted command specifications for the task."""

    def validate_outputs(
        self,
        request: ExecutionRequest,
        plan: AdapterExecutionPlan,
    ) -> tuple[bool, str]:
        """Confirm expected outputs exist inside the task directory."""
        from pathlib import Path

        task_directory = Path(request.task_directory).resolve()
        for relative in plan.expected_outputs:
            candidate = (task_directory / relative).resolve(strict=False)
            if not candidate.is_relative_to(task_directory):
                return (
                    False,
                    f"Adapter declared output outside task directory: {relative}",
                )
            if not candidate.is_file():
                return False, f"Expected scanner output is missing: {relative}"
        return True, "Expected scanner outputs are present"

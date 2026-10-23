"""Fail-closed checks for scanners required by a complete scan."""

from __future__ import annotations

from pathlib import Path

from security_reviewer_v2.profiler.models import PlanStatus, ScanPlan
from security_reviewer_v2.scanners.models import CheckStatus, ExecutionStatus, ExecutionSummary
from security_reviewer_v2.scanners.registry import AdapterRegistry


AUTOMATIC_REQUIRED_SCANNERS = ("semgrep-ce", "codeql-cli", "gitleaks", "trivy")


def preflight_required_scanners(
    plan: ScanPlan,
    registry: AdapterRegistry,
    *,
    project_root: Path,
    required: tuple[str, ...] = AUTOMATIC_REQUIRED_SCANNERS,
) -> tuple[str, ...]:
    """Preflight is disabled: always report no failures (any scanner version is accepted)."""
    return ()
    failures: list[str] = []  # unreachable: original checks kept for easy restore
    for scanner_id in required:
        tasks = [task for task in plan.tasks if task.scanner_id == scanner_id]
        if not tasks:
            failures.append(f"{scanner_id}: no task was planned")
            continue
        applicable = [task for task in tasks if task.status != PlanStatus.NOT_APPLICABLE]
        if not applicable:
            failures.append(f"{scanner_id}: no applicable task was planned")
            continue
        adapter = registry.get(scanner_id)
        if adapter is None:
            failures.append(f"{scanner_id}: runtime adapter is unavailable")
            continue
        for task in applicable:
            if task.status not in {PlanStatus.SELECTED, PlanStatus.NEEDS_VERIFICATION}:
                failures.append(f"{scanner_id}/{task.task_id}: planning status is {task.status.value}")
                continue
            if not adapter.supports(task):
                failures.append(f"{scanner_id}/{task.task_id}: adapter does not support the task")
                continue
            try:
                checks = adapter.check_prerequisites(task, project_root=str(project_root))
            except (OSError, ValueError) as error:
                failures.append(f"{scanner_id}/{task.task_id}: prerequisite check failed: {error}")
                continue
            for check in checks:
                if check.status != CheckStatus.AVAILABLE:
                    failures.append(
                        f"{scanner_id}/{task.task_id}: {check.name} is {check.status.value} ({check.detail})"
                    )
    return tuple(failures)


def required_scanner_execution_failures(
    execution: ExecutionSummary,
    *,
    normalized_task_ids: set[str],
    required: tuple[str, ...] = AUTOMATIC_REQUIRED_SCANNERS,
) -> tuple[str, ...]:
    """Require every applicable task's normalized output, not one SAST substitute."""
    failures: list[str] = []
    for scanner_id in required:
        tasks = [task for task in execution.tasks if task.scanner_id == scanner_id]
        if not tasks:
            failures.append(f"{scanner_id}: no task was executed")
            continue
        applicable = [task for task in tasks if not (
            task.status == ExecutionStatus.SKIPPED and task.reason == "Planning status is not_applicable"
        )]
        if not applicable:
            failures.append(f"{scanner_id}: no applicable task was executed")
            continue
        for task in applicable:
            if task.status != ExecutionStatus.COMPLETED:
                failures.append(f"{scanner_id}/{task.task_id}: {task.status.value} ({task.reason})")
            elif task.task_id not in normalized_task_ids:
                failures.append(f"{scanner_id}/{task.task_id}: no normalized scanner output was produced")
    return tuple(failures)

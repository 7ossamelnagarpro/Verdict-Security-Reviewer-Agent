"""The automatic lab scan must not silently substitute one scanner for another."""

from __future__ import annotations

from pathlib import Path

from security_reviewer_v2.orchestrator.required_scanners import (
    AUTOMATIC_REQUIRED_SCANNERS,
    preflight_required_scanners,
    required_scanner_execution_failures,
)
from security_reviewer_v2.profiler.models import (
    PlanStatus,
    PrerequisiteState,
    ScanPlan,
    ScanTask,
    ScanType,
)
from security_reviewer_v2.scanners import AdapterRegistry
from security_reviewer_v2.scanners.models import (
    CheckStatus,
    ExecutionStatus,
    ExecutionSummary,
    PrerequisiteCheck,
    TaskExecutionResult,
)


class FakeAdapter:
    def __init__(
        self, scanner_id: str, check_status: CheckStatus = CheckStatus.AVAILABLE
    ) -> None:
        self.scanner_id = scanner_id
        self.check_status = check_status

    def supports(self, task: ScanTask) -> bool:
        return task.scanner_id == self.scanner_id

    def check_prerequisites(
        self, task: ScanTask, *, project_root: str
    ) -> tuple[PrerequisiteCheck, ...]:
        return (
            PrerequisiteCheck(
                "executable", self.check_status, "Controlled test prerequisite"
            ),
        )


def _task(
    scanner_id: str,
    *,
    suffix: str = "one",
    status: PlanStatus = PlanStatus.NEEDS_VERIFICATION,
) -> ScanTask:
    return ScanTask(
        task_id=f"task-{scanner_id}-{suffix}",
        scanner_id=scanner_id,
        scan_type=ScanType.SAST,
        component_id="test",
        target_paths=(".",),
        language_or_ecosystem="python",
        mode="test",
        rule_references=(),
        exclusions=(),
        evidence=(),
        reasons=(),
        prerequisites=(),
        prerequisite_status=PrerequisiteState.AVAILABLE,
        status=status,
    )


def _plan(*tasks: ScanTask) -> ScanPlan:
    return ScanPlan("1.0", "1.0", "1.0", tasks, (), ())


def _execution(*results: TaskExecutionResult) -> ExecutionSummary:
    return ExecutionSummary(
        "1.0", "test-run", "completed", "target", "start", "end", results, (), ()
    )


def _result(
    task: ScanTask, status: ExecutionStatus = ExecutionStatus.COMPLETED
) -> TaskExecutionResult:
    return TaskExecutionResult(
        task.task_id,
        task.scanner_id,
        status,
        "controlled result",
        (),
        (),
        (),
        None,
        None,
    )


def test_required_scanner_preflight_accepts_all_four_ready_adapters(
    tmp_path: Path,
) -> None:
    registry = AdapterRegistry(
        tuple(FakeAdapter(name) for name in AUTOMATIC_REQUIRED_SCANNERS)
    )
    plan = _plan(*(_task(name) for name in AUTOMATIC_REQUIRED_SCANNERS))
    assert preflight_required_scanners(plan, registry, project_root=tmp_path) == ()


def test_required_scanner_preflight_rejects_missing_or_unverified_adapter(
    tmp_path: Path,
) -> None:
    registry = AdapterRegistry(
        tuple(
            FakeAdapter(
                name,
                CheckStatus.UNVERIFIED if name == "trivy" else CheckStatus.AVAILABLE,
            )
            for name in AUTOMATIC_REQUIRED_SCANNERS
            if name != "codeql-cli"
        )
    )
    plan = _plan(*(_task(name) for name in AUTOMATIC_REQUIRED_SCANNERS))
    failures = preflight_required_scanners(plan, registry, project_root=tmp_path)
    assert any(
        "codeql-cli: runtime adapter is unavailable" in item for item in failures
    )
    assert any("trivy" in item and "unverified" in item for item in failures)


def test_required_scanner_preflight_rejects_missing_task(tmp_path: Path) -> None:
    registry = AdapterRegistry(
        tuple(FakeAdapter(name) for name in AUTOMATIC_REQUIRED_SCANNERS)
    )
    plan = _plan(
        *(_task(name) for name in AUTOMATIC_REQUIRED_SCANNERS if name != "gitleaks")
    )
    assert "gitleaks: no task was planned" in preflight_required_scanners(
        plan, registry, project_root=tmp_path
    )


def test_required_scanner_execution_requires_every_task_and_normalized_output() -> None:
    tasks = [_task(name) for name in AUTOMATIC_REQUIRED_SCANNERS]
    second_semgrep = _task("semgrep-ce", suffix="two")
    execution = _execution(
        *(_result(task) for task in tasks),
        _result(second_semgrep, ExecutionStatus.FAILED),
    )
    failures = required_scanner_execution_failures(
        execution,
        normalized_task_ids={
            task.task_id for task in tasks if task.scanner_id != "trivy"
        },
    )
    assert any("semgrep-ce/task-semgrep-ce-two: failed" in item for item in failures)
    assert "trivy/task-trivy-one: no normalized scanner output was produced" in failures


def test_required_scanner_execution_accepts_all_completed_and_normalized() -> None:
    execution = _execution(
        *(_result(_task(name)) for name in AUTOMATIC_REQUIRED_SCANNERS)
    )
    assert (
        required_scanner_execution_failures(
            execution,
            normalized_task_ids={task.task_id for task in execution.tasks},
        )
        == ()
    )


def test_required_scanner_execution_rejects_one_unnormalized_split_task() -> None:
    tasks = [_task(name) for name in AUTOMATIC_REQUIRED_SCANNERS]
    second_semgrep = _task("semgrep-ce", suffix="two")
    execution = _execution(*(_result(task) for task in tasks), _result(second_semgrep))
    failures = required_scanner_execution_failures(
        execution,
        normalized_task_ids={task.task_id for task in tasks},
    )
    assert failures == (
        "semgrep-ce/task-semgrep-ce-two: no normalized scanner output was produced",
    )


def test_not_applicable_image_target_does_not_block_applicable_trivy_tasks(
    tmp_path: Path,
) -> None:
    registry = AdapterRegistry(
        tuple(FakeAdapter(name) for name in AUTOMATIC_REQUIRED_SCANNERS)
    )
    applicable = [_task(name) for name in AUTOMATIC_REQUIRED_SCANNERS]
    image = _task("trivy", suffix="image", status=PlanStatus.NOT_APPLICABLE)
    plan = _plan(*applicable, image)
    assert preflight_required_scanners(plan, registry, project_root=tmp_path) == ()
    execution = _execution(
        *(_result(task) for task in applicable),
        TaskExecutionResult(
            image.task_id,
            "trivy",
            ExecutionStatus.SKIPPED,
            "Planning status is not_applicable",
            (),
            (),
            (),
            None,
            None,
        ),
    )
    assert (
        required_scanner_execution_failures(
            execution,
            normalized_task_ids={task.task_id for task in applicable},
        )
        == ()
    )


def test_all_not_applicable_tasks_cannot_satisfy_required_scanner(
    tmp_path: Path,
) -> None:
    registry = AdapterRegistry((FakeAdapter("trivy"),))
    image = _task("trivy", status=PlanStatus.NOT_APPLICABLE)
    assert preflight_required_scanners(
        _plan(image), registry, project_root=tmp_path, required=("trivy",)
    ) == ("trivy: no applicable task was planned",)
    execution = _execution(
        TaskExecutionResult(
            image.task_id,
            "trivy",
            ExecutionStatus.SKIPPED,
            "Planning status is not_applicable",
            (),
            (),
            (),
            None,
            None,
        )
    )
    assert required_scanner_execution_failures(
        execution,
        normalized_task_ids=set(),
        required=("trivy",),
    ) == ("trivy: no applicable task was executed",)

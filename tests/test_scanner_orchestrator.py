"""Behavioral tests for scanner contracts and bounded orchestration."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from security_reviewer_v2.orchestrator import OrchestratorPolicy, ScannerOrchestrator
from security_reviewer_v2.profiler.models import (
    PlanStatus,
    PrerequisiteState,
    ScanPlan,
    ScanTask,
    ScanType,
)
from security_reviewer_v2.scanners import AdapterRegistry, ScannerAdapter
from security_reviewer_v2.scanners.codeql import CodeQLAdapter, CodeQLConfig
from security_reviewer_v2.scanners.models import (
    AdapterExecutionPlan,
    CheckStatus,
    CommandSpec,
    ExecutionRequest,
    ExecutionStatus,
    PrerequisiteCheck,
)
from security_reviewer_v2.scanners.semgrep import SemgrepAdapter, SemgrepConfig


class FakeAdapter(ScannerAdapter):
    def __init__(
        self,
        scanner_id: str,
        *,
        behavior: str = "success",
        check_status: CheckStatus = CheckStatus.AVAILABLE,
    ) -> None:
        self.scanner_id = scanner_id
        self.behavior = behavior
        self.check_status = check_status

    def supports(self, task: ScanTask) -> bool:
        return task.scanner_id == self.scanner_id

    def check_prerequisites(
        self,
        task: ScanTask,
        *,
        project_root: str,
    ) -> tuple[PrerequisiteCheck, ...]:
        return (
            PrerequisiteCheck(
                name="fake_executable",
                status=self.check_status,
                detail="Controlled test prerequisite",
            ),
        )

    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        output = Path(request.task_directory) / "result.json"
        if self.behavior == "success":
            code = f"from pathlib import Path; Path({str(output)!r}).write_text('{{}}')"
        elif self.behavior == "failure":
            code = "raise SystemExit(7)"
        elif self.behavior == "timeout":
            code = "import time; time.sleep(10)"
        elif self.behavior == "invalid_output":
            code = "print('finished without output')"
        elif self.behavior == "secret_log":
            code = (
                f"from pathlib import Path; "
                f"print('API_KEY=super-secret-value'); "
                f"print('x' * 1000); "
                f"Path({str(output)!r}).write_text('{{}}')"
            )
        else:
            raise ValueError("Unknown fake behavior")
        return AdapterExecutionPlan(
            commands=(
                CommandSpec(
                    name="fake-command",
                    executable=str(Path(sys.executable).resolve()),
                    arguments=("-c", code),
                    working_directory=request.project_root,
                    timeout_seconds=request.timeout_seconds,
                ),
            ),
            expected_outputs=("result.json",),
        )


def make_task(
    scanner_id: str,
    *,
    status: PlanStatus = PlanStatus.NEEDS_VERIFICATION,
    suffix: str = "one",
) -> ScanTask:
    return ScanTask(
        task_id=f"task-{scanner_id}-{suffix}",
        scanner_id=scanner_id,
        scan_type=ScanType.SAST,
        component_id="component-test",
        target_paths=(".",),
        language_or_ecosystem="python",
        mode="test",
        rule_references=(),
        exclusions=(),
        evidence=(),
        reasons=("Test task",),
        prerequisites=("fake_executable",),
        prerequisite_status=PrerequisiteState.UNVERIFIED,
        status=status,
    )


def make_plan(*tasks: ScanTask) -> ScanPlan:
    return ScanPlan(
        schema_version="1.0",
        policy_version="test",
        registry_version="test",
        tasks=tasks,
        coverage_gaps=(),
        warnings=(),
    )


def execute(
    tmp_path: Path,
    plan: ScanPlan,
    registry: AdapterRegistry,
    *,
    timeout: float = 5,
    max_log_bytes: int = 1024,
):
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    orchestrator = ScannerOrchestrator(
        registry,
        policy=OrchestratorPolicy(
            task_timeout_seconds=timeout,
            max_log_bytes=max_log_bytes,
        ),
    )
    return orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="test-run",
    )


def test_registry_rejects_duplicate_adapters() -> None:
    registry = AdapterRegistry((FakeAdapter("fake"),))
    with pytest.raises(ValueError):
        registry.register(FakeAdapter("fake"))


def test_successful_adapter_produces_raw_output_and_summary(tmp_path: Path) -> None:
    task = make_task("fake")
    summary = execute(
        tmp_path, make_plan(task), AdapterRegistry((FakeAdapter("fake"),))
    )

    assert summary.status.value == "completed"
    assert summary.tasks[0].status == ExecutionStatus.COMPLETED
    assert summary.tasks[0].raw_outputs == ("fake/task-fake-one/result.json",)
    saved = json.loads(
        (tmp_path / "runs/test-run/execution-summary.json").read_text(encoding="utf-8")
    )
    assert saved["status"] == "completed"


def test_missing_adapter_is_visible_as_coverage_gap(tmp_path: Path) -> None:
    summary = execute(tmp_path, make_plan(make_task("missing")), AdapterRegistry())

    assert summary.status.value == "failed"
    assert summary.tasks[0].status == ExecutionStatus.ADAPTER_UNAVAILABLE
    assert "adapter_unavailable" in summary.coverage_gaps[0]


@pytest.mark.parametrize(
    ("check_status", "expected"),
    [
        (CheckStatus.MISSING, ExecutionStatus.PREREQUISITE_MISSING),
        (CheckStatus.UNVERIFIED, ExecutionStatus.PREREQUISITE_UNVERIFIED),
    ],
)
def test_prerequisite_states_prevent_execution(
    tmp_path: Path,
    check_status: CheckStatus,
    expected: ExecutionStatus,
) -> None:
    adapter = FakeAdapter("fake", check_status=check_status)
    summary = execute(
        tmp_path, make_plan(make_task("fake")), AdapterRegistry((adapter,))
    )

    assert summary.tasks[0].status == expected
    assert summary.tasks[0].commands == ()


def test_one_scanner_failure_does_not_stop_another_task(tmp_path: Path) -> None:
    registry = AdapterRegistry(
        (
            FakeAdapter("broken", behavior="failure"),
            FakeAdapter("working", behavior="success"),
        )
    )
    plan = make_plan(make_task("broken"), make_task("working"))

    summary = execute(tmp_path, plan, registry)

    statuses = {item.scanner_id: item.status for item in summary.tasks}
    assert statuses == {
        "broken": ExecutionStatus.FAILED,
        "working": ExecutionStatus.COMPLETED,
    }
    assert summary.status.value == "partial"


def test_timeout_is_bounded_and_reported(tmp_path: Path) -> None:
    adapter = FakeAdapter("slow", behavior="timeout")
    summary = execute(
        tmp_path,
        make_plan(make_task("slow")),
        AdapterRegistry((adapter,)),
        timeout=0.1,
    )

    assert summary.tasks[0].status == ExecutionStatus.TIMED_OUT


def test_missing_expected_output_is_invalid_not_success(tmp_path: Path) -> None:
    adapter = FakeAdapter("fake", behavior="invalid_output")
    summary = execute(
        tmp_path, make_plan(make_task("fake")), AdapterRegistry((adapter,))
    )

    assert summary.tasks[0].status == ExecutionStatus.INVALID_OUTPUT


def test_disabled_planning_task_is_recorded_without_adapter(tmp_path: Path) -> None:
    task = make_task("disabled", status=PlanStatus.DISABLED_BY_POLICY)
    summary = execute(tmp_path, make_plan(task), AdapterRegistry())

    assert summary.tasks[0].status == ExecutionStatus.SKIPPED
    assert "disabled_by_policy" in summary.tasks[0].reason


def test_logs_are_redacted_and_truncated(tmp_path: Path) -> None:
    adapter = FakeAdapter("fake", behavior="secret_log")
    summary = execute(
        tmp_path,
        make_plan(make_task("fake")),
        AdapterRegistry((adapter,)),
        max_log_bytes=100,
    )
    command = summary.tasks[0].commands[0]
    log = (tmp_path / "runs/test-run" / command.stdout_log).read_text(encoding="utf-8")

    assert "super-secret-value" not in log
    assert "[REDACTED]" in log
    assert "[log truncated by orchestrator]" in log
    assert command.stdout_truncated is True


def test_task_limit_creates_explicit_skipped_result(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    orchestrator = ScannerOrchestrator(
        AdapterRegistry((FakeAdapter("fake"),)),
        policy=OrchestratorPolicy(max_tasks=1),
    )
    plan = make_plan(make_task("fake", suffix="one"), make_task("fake", suffix="two"))

    summary = orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="limited-run",
    )

    assert len(summary.tasks) == 2
    assert {item.status for item in summary.tasks} == {
        ExecutionStatus.COMPLETED,
        ExecutionStatus.SKIPPED,
    }
    assert summary.status.value == "partial"
    assert any("task limit" in gap for gap in summary.coverage_gaps)


def test_task_limit_can_be_resumed_without_rerunning_completed_task(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake", suffix="one"), make_task("fake", suffix="two"))
    registry = AdapterRegistry((FakeAdapter("fake"),))
    orchestrator = ScannerOrchestrator(registry, policy=OrchestratorPolicy(max_tasks=1))

    first = orchestrator.execute(
        plan, project_root=project, runs_root=tmp_path / "runs", run_id="limited-run"
    )
    assert first.status.value == "partial"
    first_output = tmp_path / "runs/limited-run/fake/task-fake-one/result.json"
    first_output.write_text("first result preserved", encoding="utf-8")

    resumed = orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="limited-run",
        resume=True,
    )

    assert resumed.status.value == "completed"
    assert all(item.status == ExecutionStatus.COMPLETED for item in resumed.tasks)
    assert first_output.read_text(encoding="utf-8") == "first result preserved"
    assert not any("task limit" in gap for gap in resumed.coverage_gaps)


def test_resume_prioritizes_unattempted_task_over_repeated_failure(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("broken"), make_task("working"))
    first_registry = AdapterRegistry(
        (FakeAdapter("broken", behavior="failure"), FakeAdapter("working"))
    )
    first_orchestrator = ScannerOrchestrator(
        first_registry, policy=OrchestratorPolicy(max_tasks=1)
    )
    first = first_orchestrator.execute(
        plan, project_root=project, runs_root=tmp_path / "runs", run_id="starvation"
    )
    assert first.status.value == "failed"
    assert {item.scanner_id: item.status for item in first.tasks} == {
        "broken": ExecutionStatus.FAILED,
        "working": ExecutionStatus.SKIPPED,
    }

    second = first_orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="starvation",
        resume=True,
    )

    assert second.status.value == "partial"
    assert {item.scanner_id: item.status for item in second.tasks} == {
        "broken": ExecutionStatus.FAILED,
        "working": ExecutionStatus.COMPLETED,
    }


def test_resume_after_interruption_reuses_checkpointed_success(tmp_path: Path) -> None:
    class InterruptSecond(FakeAdapter):
        def build_execution_plan(
            self, request: ExecutionRequest
        ) -> AdapterExecutionPlan:
            if request.task.task_id.endswith("two"):
                raise KeyboardInterrupt
            return super().build_execution_plan(request)

    class CountCalls(FakeAdapter):
        def __init__(self) -> None:
            super().__init__("fake")
            self.calls: list[str] = []

        def build_execution_plan(
            self, request: ExecutionRequest
        ) -> AdapterExecutionPlan:
            self.calls.append(request.task.task_id)
            return super().build_execution_plan(request)

    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake", suffix="one"), make_task("fake", suffix="two"))
    first = ScannerOrchestrator(AdapterRegistry((InterruptSecond("fake"),)))
    with pytest.raises(KeyboardInterrupt):
        first.execute(
            plan,
            project_root=project,
            runs_root=tmp_path / "runs",
            run_id="interrupted-run",
            input_fingerprint="a" * 64,
        )
    checkpoint = json.loads(
        (tmp_path / "runs/interrupted-run/checkpoint.json").read_text(encoding="utf-8")
    )
    assert [item["task_id"] for item in checkpoint["tasks"]] == ["task-fake-one"]

    adapter = CountCalls()
    resumed = ScannerOrchestrator(AdapterRegistry((adapter,))).execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="interrupted-run",
        resume=True,
        input_fingerprint="a" * 64,
    )

    assert resumed.status.value == "completed"
    assert adapter.calls == ["task-fake-two"]
    assert len(resumed.tasks) == 2


def test_resume_retries_failed_task_in_new_attempt_directory(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake"))
    failed = ScannerOrchestrator(
        AdapterRegistry((FakeAdapter("fake", behavior="failure"),))
    ).execute(
        plan, project_root=project, runs_root=tmp_path / "runs", run_id="retry-run"
    )
    assert failed.status.value == "failed"

    resumed = ScannerOrchestrator(AdapterRegistry((FakeAdapter("fake"),))).execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="retry-run",
        resume=True,
    )

    assert resumed.status.value == "completed"
    assert resumed.tasks[0].raw_outputs == ("fake/task-fake-one-attempt-2/result.json",)
    assert (tmp_path / "runs/retry-run/fake/task-fake-one/logs").is_dir()


def test_resume_can_use_an_adapter_installed_after_first_attempt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake"))
    first = ScannerOrchestrator(AdapterRegistry()).execute(
        plan, project_root=project, runs_root=tmp_path / "runs", run_id="new-adapter"
    )
    assert first.tasks[0].status == ExecutionStatus.ADAPTER_UNAVAILABLE

    resumed = ScannerOrchestrator(AdapterRegistry((FakeAdapter("fake"),))).execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="new-adapter",
        resume=True,
    )

    assert resumed.status.value == "completed"
    assert resumed.tasks[0].status == ExecutionStatus.COMPLETED


def test_resume_rejects_changed_plan_or_input_fingerprint(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake"))
    orchestrator = ScannerOrchestrator(AdapterRegistry((FakeAdapter("fake"),)))
    orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="bound-run",
        input_fingerprint="a" * 64,
    )

    with pytest.raises(ValueError, match="manifest does not match"):
        orchestrator.execute(
            make_plan(make_task("fake", suffix="changed")),
            project_root=project,
            runs_root=tmp_path / "runs",
            run_id="bound-run",
            resume=True,
            input_fingerprint="a" * 64,
        )
    with pytest.raises(ValueError, match="manifest does not match"):
        orchestrator.execute(
            plan,
            project_root=project,
            runs_root=tmp_path / "runs",
            run_id="bound-run",
            resume=True,
            input_fingerprint="b" * 64,
        )


def test_resume_reruns_completed_task_if_raw_output_is_missing(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake"))
    orchestrator = ScannerOrchestrator(AdapterRegistry((FakeAdapter("fake"),)))
    first = orchestrator.execute(
        plan, project_root=project, runs_root=tmp_path / "runs", run_id="missing-output"
    )
    output = tmp_path / "runs/missing-output" / first.tasks[0].raw_outputs[0]
    output.unlink()

    resumed = orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="missing-output",
        resume=True,
    )

    assert resumed.status.value == "completed"
    assert resumed.tasks[0].raw_outputs == ("fake/task-fake-one-attempt-2/result.json",)


def test_resume_after_manifest_before_first_checkpoint(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = make_plan(make_task("fake"))
    run_directory = tmp_path / "runs" / "early-interruption"
    orchestrator = ScannerOrchestrator(AdapterRegistry((FakeAdapter("fake"),)))
    orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="early-interruption",
    )
    (run_directory / "checkpoint.json").unlink()
    (run_directory / "fake/task-fake-one/result.json").unlink()

    resumed = orchestrator.execute(
        plan,
        project_root=project,
        runs_root=tmp_path / "runs",
        run_id="early-interruption",
        resume=True,
    )

    assert resumed.status.value == "completed"
    assert resumed.tasks[0].raw_outputs == ("fake/task-fake-one-attempt-2/result.json",)


def test_codeql_adapter_builds_argument_vectors_without_shell_strings(
    tmp_path: Path,
) -> None:
    suite = tmp_path / "python-code-scanning.qls"
    suite.write_text("- description: fixture\n", encoding="utf-8")
    project = tmp_path / "project"
    task_dir = tmp_path / "task"
    project.mkdir()
    task_dir.mkdir()
    adapter = CodeQLAdapter(
        CodeQLConfig(
            executable=str(Path(sys.executable).resolve()),
            query_suites={"python": str(suite.resolve())},
        )
    )
    task = make_task("codeql-cli")
    task = ScanTask(**{**task.__dict__, "mode": "standard_query_suite"})
    request = ExecutionRequest(
        run_id="codeql-test",
        task=task,
        project_root=str(project.resolve()),
        task_directory=str(task_dir.resolve()),
        timeout_seconds=30,
    )

    plan = adapter.build_execution_plan(request)

    assert len(plan.commands) == 2
    assert plan.commands[0].arguments[:2] == ("database", "create")
    assert plan.commands[1].arguments[:2] == ("database", "analyze")
    assert all(
        command.executable == str(Path(sys.executable).resolve())
        for command in plan.commands
    )
    assert plan.expected_outputs == ("result.sarif",)


def test_codeql_adapter_reports_missing_query_suite(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    adapter = CodeQLAdapter(
        CodeQLConfig(
            executable=str(Path(sys.executable).resolve()),
            query_suites={"python": str((tmp_path / "missing.qls").resolve())},
        )
    )
    task = make_task("codeql-cli")
    task = ScanTask(**{**task.__dict__, "mode": "standard_query_suite"})

    checks = adapter.check_prerequisites(task, project_root=str(project))

    query_check = next(item for item in checks if item.name == "language_query_pack")
    assert query_check.status == CheckStatus.MISSING


def test_semgrep_adapter_builds_trusted_registry_scan_command(tmp_path: Path) -> None:
    project = tmp_path / "project"
    task_dir = tmp_path / "task"
    project.mkdir()
    task_dir.mkdir()
    adapter = SemgrepAdapter(
        SemgrepConfig(
            executable=str(Path(sys.executable).resolve()),
            configs=("p/python", "p/security-audit"),
        )
    )
    task = make_task("semgrep-ce")
    task = ScanTask(
        **{
            **task.__dict__,
            "mode": "community_registry_rules",
            "exclusions": ("node_modules/**",),
        }
    )
    request = ExecutionRequest(
        run_id="semgrep-test",
        task=task,
        project_root=str(project.resolve()),
        task_directory=str(task_dir.resolve()),
        timeout_seconds=30,
    )

    plan = adapter.build_execution_plan(request)

    arguments = plan.commands[0].arguments
    assert arguments[:2] == ("scan", "--json")
    assert arguments.count("--config") == 2
    assert "p/python" in arguments
    assert "p/security-audit" in arguments
    assert "--exclude" in arguments
    assert arguments[-1] == "."
    assert plan.expected_outputs == ("result.json",)


def test_semgrep_config_rejects_untrusted_relative_local_rule(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        SemgrepAdapter(
            SemgrepConfig(
                executable=str(Path(sys.executable).resolve()),
                configs=("rules/local.yml",),
            )
        )

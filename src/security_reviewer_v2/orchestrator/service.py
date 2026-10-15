"""Basic scanner orchestrator: prerequisite checks, bounded execution, summaries."""

from __future__ import annotations

import json
import hashlib
import os
import re
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from security_reviewer_v2.profiler.models import PlanStatus, ScanPlan, ScanTask
from security_reviewer_v2.scanners.models import (
    AdapterExecutionPlan,
    CheckStatus,
    CommandResult,
    EXECUTION_SCHEMA_VERSION,
    ExecutionRequest,
    ExecutionStatus,
    ExecutionSummary,
    OverallRunStatus,
    PrerequisiteCheck,
    TaskExecutionResult,
)
from security_reviewer_v2.scanners.registry import AdapterRegistry

from .runner import ProcessRunner


@dataclass(frozen=True)
class OrchestratorPolicy:
    task_timeout_seconds: float = 600.0
    max_log_bytes: int = 1024 * 1024
    max_tasks: int = 100
    scanner_timeouts: dict[str, float] = field(default_factory=dict)

    def validate(self) -> None:
        if any(value <= 0 for value in self.scanner_timeouts.values()):
            raise ValueError("Scanner timeouts must be positive")
        if self.task_timeout_seconds <= 0:
            raise ValueError("task_timeout_seconds must be greater than zero")
        if self.max_log_bytes <= 0:
            raise ValueError("max_log_bytes must be greater than zero")
        if self.max_tasks <= 0:
            raise ValueError("max_tasks must be greater than zero")


class ScannerOrchestrator:
    def __init__(
        self,
        registry: AdapterRegistry,
        *,
        policy: OrchestratorPolicy | None = None,
        runner: ProcessRunner | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy or OrchestratorPolicy()
        self.policy.validate()
        self.runner = runner or ProcessRunner(max_log_bytes=self.policy.max_log_bytes)

    def execute(
        self,
        scan_plan: ScanPlan,
        *,
        project_root: str | Path,
        runs_root: str | Path,
        run_id: str | None = None,
        resume: bool = False,
        input_fingerprint: str | None = None,
    ) -> ExecutionSummary:
        project = Path(project_root).resolve()
        if not project.is_dir():
            raise ValueError(f"Project root is unavailable: {project}")
        runs = Path(runs_root).resolve()
        runs.mkdir(parents=True, exist_ok=True)
        selected_run_id = run_id or _new_run_id()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", selected_run_id):
            raise ValueError("run_id contains unsafe characters or is too long")
        if input_fingerprint is not None and not re.fullmatch(r"[0-9a-f]{64}", input_fingerprint):
            raise ValueError("input_fingerprint must be a SHA-256 hex digest")
        run_directory = (runs / selected_run_id).resolve()
        if not run_directory.is_relative_to(runs):
            raise ValueError("Run directory escaped the configured runs root")
        if resume and not run_directory.is_dir():
            raise FileNotFoundError(f"Run directory does not exist: {run_directory}")
        if not resume and run_directory.exists():
            raise FileExistsError(f"Run directory already exists: {run_directory}")
        if not resume:
            run_directory.mkdir(parents=True)

        with _run_lock(run_directory):
            manifest_path = run_directory / "manifest.json"
            checkpoint_path = run_directory / "checkpoint.json"
            expected_manifest = {
                "schema_version": EXECUTION_SCHEMA_VERSION,
                "run_id": selected_run_id,
                "project_root_name": project.name,
                "project_root": os.path.normcase(str(project)),
                "scan_plan_sha256": _digest(asdict(scan_plan)),
                "input_fingerprint": input_fingerprint,
                "task_ids": [task.task_id for task in scan_plan.tasks],
                "adapter_ids": list(self.registry.scanner_ids()),
            }
            if resume:
                saved_manifest = _read_json(manifest_path)
                identity_fields = (
                    "schema_version", "run_id", "project_root", "scan_plan_sha256",
                    "input_fingerprint", "task_ids",
                )
                if any(
                    saved_manifest.get(field) != expected_manifest[field]
                    for field in identity_fields
                ):
                    raise ValueError("Run manifest does not match the project, plan, or input snapshot")
                if checkpoint_path.exists():
                    checkpoint = _read_json(checkpoint_path)
                    if checkpoint.get("run_id") != selected_run_id:
                        raise ValueError("Checkpoint does not belong to this run")
                    started_at = checkpoint["started_at"]
                    previous = {
                        item["task_id"]: _result_from_dict(item)
                        for item in checkpoint["tasks"]
                    }
                    if len(previous) != len(checkpoint["tasks"]):
                        raise ValueError("Checkpoint contains duplicate task IDs")
                else:
                    # A crash after manifest creation but before the first
                    # checkpoint cannot have completed a scanner task.
                    started_at = saved_manifest["started_at"]
                    previous = {}
                if set(previous) - {task.task_id for task in scan_plan.tasks}:
                    raise ValueError("Checkpoint contains tasks outside this scan plan")
            else:
                started_at = _utc_now()
                previous = {}
                expected_manifest["started_at"] = started_at
                _write_json(manifest_path, expected_manifest)
                _write_checkpoint(checkpoint_path, selected_run_id, started_at, previous)

            tasks = tuple(sorted(scan_plan.tasks, key=lambda item: item.task_id))
            results: dict[str, TaskExecutionResult] = dict(previous)
            executed = 0
            # Pending tasks take precedence over retries so one repeatedly
            # failing task cannot starve later tasks under a small run limit.
            execution_order = sorted(
                tasks,
                key=lambda task: (
                    0 if task.task_id not in previous
                    or previous[task.task_id].reason == "Orchestrator task-count limit reached"
                    else 1,
                    task.task_id,
                ),
            )
            for task in execution_order:
                old = results.get(task.task_id)
                if old is not None and (
                    (old.status == ExecutionStatus.COMPLETED and _outputs_available(old, run_directory))
                    or task.status in {PlanStatus.NOT_APPLICABLE, PlanStatus.DISABLED_BY_POLICY}
                ):
                    continue
                if executed >= self.policy.max_tasks:
                    if (
                        old is not None
                        and old.status != ExecutionStatus.COMPLETED
                        and old.reason != "Orchestrator task-count limit reached"
                    ):
                        continue
                    result = _terminal_result(
                        task, ExecutionStatus.SKIPPED, "Orchestrator task-count limit reached"
                    )
                else:
                    result = self._execute_task(
                        task,
                        project_root=project,
                        run_directory=run_directory,
                        run_id=selected_run_id,
                    )
                    executed += 1
                results[task.task_id] = result
                _write_checkpoint(checkpoint_path, selected_run_id, started_at, results)

            ordered_results = [results[task.task_id] for task in tasks]
            coverage_gaps: list[str] = list(scan_plan.coverage_gaps)
            for result in ordered_results:
                if result.status == ExecutionStatus.SKIPPED:
                    if result.reason == "Orchestrator task-count limit reached":
                        coverage_gaps.append(
                            f"Task {result.task_id} was skipped because the run task limit was reached."
                        )
                elif result.status != ExecutionStatus.COMPLETED:
                    coverage_gaps.append(
                        f"{result.scanner_id} task {result.task_id} did not complete: "
                        f"{result.status.value} ({result.reason})."
                    )
            summary = ExecutionSummary(
                schema_version=EXECUTION_SCHEMA_VERSION,
                run_id=selected_run_id,
                status=_overall_status(ordered_results),
                project_root_name=project.name,
                started_at=started_at,
                finished_at=_utc_now(),
                tasks=tuple(ordered_results),
                coverage_gaps=tuple(sorted(set(coverage_gaps))),
                warnings=tuple(sorted(set(scan_plan.warnings))),
            )
            _write_json(run_directory / "execution-summary.json", summary.to_dict())
            return summary

    def _execute_task(
        self,
        task: ScanTask,
        *,
        project_root: Path,
        run_directory: Path,
        run_id: str,
    ) -> TaskExecutionResult:
        if task.status in {PlanStatus.NOT_APPLICABLE, PlanStatus.DISABLED_BY_POLICY}:
            return _terminal_result(
                task,
                ExecutionStatus.SKIPPED,
                f"Planning status is {task.status.value}",
            )
        if task.status == PlanStatus.UNSUPPORTED:
            return _terminal_result(task, ExecutionStatus.UNSUPPORTED, "Task is unsupported")
        if task.status == PlanStatus.BLOCKED:
            return _terminal_result(
                task,
                ExecutionStatus.PREREQUISITE_MISSING,
                "Profiler marked required prerequisites as missing",
            )
        adapter = self.registry.get(task.scanner_id)
        if adapter is None:
            return _terminal_result(
                task,
                ExecutionStatus.ADAPTER_UNAVAILABLE,
                "No runtime adapter is registered for this scanner",
            )
        if not adapter.supports(task):
            return _terminal_result(
                task,
                ExecutionStatus.UNSUPPORTED,
                "Registered adapter does not support this task",
            )
        checks = adapter.check_prerequisites(task, project_root=str(project_root))
        if any(check.status == CheckStatus.MISSING for check in checks):
            missing = ", ".join(check.name for check in checks if check.status == CheckStatus.MISSING)
            return _terminal_result(
                task,
                ExecutionStatus.PREREQUISITE_MISSING,
                f"Missing prerequisites: {missing}",
                checks=checks,
            )
        if any(check.status == CheckStatus.UNVERIFIED for check in checks):
            unknown = ", ".join(check.name for check in checks if check.status == CheckStatus.UNVERIFIED)
            return _terminal_result(
                task,
                ExecutionStatus.PREREQUISITE_UNVERIFIED,
                f"Unverified prerequisites: {unknown}",
                checks=checks,
            )

        task_directory = _next_attempt_directory(run_directory, task)
        if not task_directory.is_relative_to(run_directory):
            return _terminal_result(task, ExecutionStatus.FAILED, "Unsafe task directory")
        task_directory.mkdir(parents=True)
        request = ExecutionRequest(
            run_id=run_id,
            task=task,
            project_root=str(project_root),
            task_directory=str(task_directory),
            timeout_seconds=self.policy.scanner_timeouts.get(task.scanner_id, self.policy.task_timeout_seconds),
        )
        started_at = _utc_now()
        start_clock = time.monotonic()
        try:
            execution_plan = adapter.build_execution_plan(request)
            _validate_plan(execution_plan, task_directory)
        except (OSError, ValueError) as error:
            return TaskExecutionResult(
                task_id=task.task_id,
                scanner_id=task.scanner_id,
                status=ExecutionStatus.FAILED,
                reason=f"Adapter could not prepare execution: {type(error).__name__}: {error}",
                prerequisite_checks=checks,
                commands=(),
                raw_outputs=(),
                started_at=started_at,
                finished_at=_utc_now(),
            )

        command_results = []
        final_status = ExecutionStatus.COMPLETED
        reason = "Scanner commands completed successfully"
        for command in execution_plan.commands:
            elapsed = time.monotonic() - start_clock
            remaining = request.timeout_seconds - elapsed
            if remaining <= 0:
                final_status = ExecutionStatus.TIMED_OUT
                reason = "Task timeout reached before all commands started"
                break
            bounded_command = replace(
                command,
                timeout_seconds=min(command.timeout_seconds, remaining),
            )
            try:
                command_result = self.runner.run(
                    bounded_command,
                    log_directory=task_directory / "logs",
                    relative_to=run_directory,
                )
            except (OSError, ValueError) as error:
                final_status = ExecutionStatus.FAILED
                reason = f"Command launch failed: {type(error).__name__}: {error}"
                break
            command_results.append(command_result)
            if command_result.status != ExecutionStatus.COMPLETED:
                final_status = command_result.status
                reason = (
                    f"Command {command_result.name} ended with "
                    f"{command_result.status.value}"
                )
                break

        raw_outputs: tuple[str, ...] = ()
        if final_status == ExecutionStatus.COMPLETED:
            valid, validation_reason = adapter.validate_outputs(request, execution_plan)
            if not valid:
                final_status = ExecutionStatus.INVALID_OUTPUT
                reason = validation_reason
            else:
                raw_outputs = tuple(
                    (task_directory.relative_to(run_directory) / output).as_posix()
                    for output in execution_plan.expected_outputs
                )
                reason = validation_reason
        return TaskExecutionResult(
            task_id=task.task_id,
            scanner_id=task.scanner_id,
            status=final_status,
            reason=reason,
            prerequisite_checks=checks,
            commands=tuple(command_results),
            raw_outputs=raw_outputs,
            started_at=started_at,
            finished_at=_utc_now(),
        )


def _validate_plan(plan: AdapterExecutionPlan, task_directory: Path) -> None:
    if not plan.commands:
        raise ValueError("Adapter execution plan has no commands")
    for command in plan.commands:
        command.validate()
    for output in plan.expected_outputs:
        candidate = (task_directory / output).resolve(strict=False)
        if not candidate.is_relative_to(task_directory):
            raise ValueError(f"Expected output escapes task directory: {output}")


def _terminal_result(
    task: ScanTask,
    status: ExecutionStatus,
    reason: str,
    *,
    checks=(),
) -> TaskExecutionResult:
    return TaskExecutionResult(
        task_id=task.task_id,
        scanner_id=task.scanner_id,
        status=status,
        reason=reason,
        prerequisite_checks=tuple(checks),
        commands=(),
        raw_outputs=(),
        started_at=None,
        finished_at=None,
    )


def _overall_status(results: list[TaskExecutionResult]) -> OverallRunStatus:
    if any(
        item.status == ExecutionStatus.SKIPPED
        and item.reason == "Orchestrator task-count limit reached"
        for item in results
    ):
        return OverallRunStatus.PARTIAL if any(
            item.status == ExecutionStatus.COMPLETED for item in results
        ) else OverallRunStatus.FAILED
    actionable = [item for item in results if item.status != ExecutionStatus.SKIPPED]
    if not actionable:
        return OverallRunStatus.FAILED
    completed = [item for item in actionable if item.status == ExecutionStatus.COMPLETED]
    if len(completed) == len(actionable):
        return OverallRunStatus.COMPLETED
    if completed:
        return OverallRunStatus.PARTIAL
    return OverallRunStatus.FAILED


def _write_json(path: Path, payload) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"Run artifact is missing or invalid: {path.name}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"Run artifact is not an object: {path.name}")
    return payload


def _digest(payload) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_checkpoint(
    path: Path,
    run_id: str,
    started_at: str,
    results: dict[str, TaskExecutionResult],
) -> None:
    _write_json(path, {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "tasks": [asdict(results[key]) for key in sorted(results)],
    })


def _result_from_dict(item: dict) -> TaskExecutionResult:
    return TaskExecutionResult(
        task_id=item["task_id"],
        scanner_id=item["scanner_id"],
        status=ExecutionStatus(item["status"]),
        reason=item["reason"],
        prerequisite_checks=tuple(
            PrerequisiteCheck(
                name=check["name"], status=CheckStatus(check["status"]),
                detail=check["detail"], version=check.get("version"),
            ) for check in item["prerequisite_checks"]
        ),
        commands=tuple(
            CommandResult(
                name=command["name"], status=ExecutionStatus(command["status"]),
                exit_code=command["exit_code"], duration_seconds=command["duration_seconds"],
                stdout_log=command["stdout_log"], stderr_log=command["stderr_log"],
                stdout_truncated=command["stdout_truncated"],
                stderr_truncated=command["stderr_truncated"],
            ) for command in item["commands"]
        ),
        raw_outputs=tuple(item["raw_outputs"]),
        started_at=item["started_at"],
        finished_at=item["finished_at"],
    )


def _next_attempt_directory(run_directory: Path, task: ScanTask) -> Path:
    base = run_directory / task.scanner_id / task.task_id
    candidate = base
    attempt = 2
    while candidate.exists():
        candidate = base.with_name(f"{task.task_id}-attempt-{attempt}")
        attempt += 1
    return candidate.resolve()


def _outputs_available(result: TaskExecutionResult, run_directory: Path) -> bool:
    if not result.raw_outputs:
        return False
    for relative in result.raw_outputs:
        candidate = (run_directory / relative).resolve()
        if not candidate.is_relative_to(run_directory) or not candidate.is_file():
            return False
    return True


@contextmanager
def _run_lock(run_directory: Path):
    """Use an OS lock so interrupted runs can resume but concurrent runs cannot race."""
    lock_path = run_directory / ".run.lock"
    with lock_path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise RuntimeError("This scan run is already active") from error
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise RuntimeError("This scan run is already active") from error
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{stamp}-{uuid.uuid4().hex[:8]}"

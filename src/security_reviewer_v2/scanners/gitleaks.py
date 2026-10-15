"""Gitleaks CLI adapter for current-file and Git-history secret scans."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from security_reviewer_v2.profiler.models import ScanTask, ScanType

from .base import ScannerAdapter
from .models import (
    AdapterExecutionPlan,
    CheckStatus,
    CommandSpec,
    ExecutionRequest,
    PrerequisiteCheck,
)


@dataclass(frozen=True)
class GitleaksConfig:
    executable: str
    expected_version: str = "8.30.1"
    max_target_megabytes: int = 10

    def validate(self) -> None:
        if not Path(self.executable).is_absolute():
            raise ValueError("Gitleaks executable path must be absolute")
        if self.max_target_megabytes <= 0:
            raise ValueError("max_target_megabytes must be positive")


class GitleaksAdapter(ScannerAdapter):
    scanner_id = "gitleaks"

    def __init__(self, config: GitleaksConfig) -> None:
        config.validate()
        self.config = config

    def supports(self, task: ScanTask) -> bool:
        return (
            task.scanner_id == self.scanner_id
            and task.scan_type == ScanType.SECRETS
            and task.mode in {"directory", "git_history"}
        )

    def check_prerequisites(
        self,
        task: ScanTask,
        *,
        project_root: str,
    ) -> tuple[PrerequisiteCheck, ...]:
        executable_check = _check_gitleaks_executable(
            Path(self.config.executable), expected_version=self.config.expected_version
        )
        root = Path(project_root).resolve()
        target_status = CheckStatus.AVAILABLE
        target_detail = "All Gitleaks targets are inside the project root"
        if not task.target_paths:
            target_status = CheckStatus.MISSING
            target_detail = "Gitleaks task has no target path"
        else:
            for relative in task.target_paths:
                candidate = (root / relative).resolve(strict=False)
                if not candidate.is_relative_to(root) or not candidate.exists():
                    target_status = CheckStatus.MISSING
                    target_detail = f"Gitleaks target is unavailable or outside project root: {relative}"
                    break
        history = CheckStatus.AVAILABLE
        history_detail = "Git-history mode is not requested"
        if task.mode == "git_history":
            marker = root / ".git"
            history = CheckStatus.AVAILABLE if marker.exists() else CheckStatus.MISSING
            history_detail = (
                "Git metadata is available for history scanning"
                if marker.exists()
                else "Git-history mode requires a .git directory or worktree marker"
            )
        return (
            executable_check,
            PrerequisiteCheck("target_paths", target_status, target_detail),
            PrerequisiteCheck("git_metadata", history, history_detail),
        )

    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        if not self.supports(request.task):
            raise ValueError("Gitleaks adapter does not support this task")
        root = Path(request.project_root).resolve()
        task_directory = Path(request.task_directory).resolve()
        target = (root / request.task.target_paths[0]).resolve()
        if not target.is_relative_to(root):
            raise ValueError("Gitleaks target escaped the project root")
        relative_target = target.relative_to(root).as_posix() or "."
        output = task_directory / "result.json"
        config = _write_scan_config(task_directory, request.task.exclusions)
        subcommand = "git" if request.task.mode == "git_history" else "dir"
        arguments = [
            subcommand,
            "--report-format=json",
            f"--report-path={output}",
            "--no-banner",
            "--no-color",
            "--redact",
            "--exit-code=0",
            f"--max-target-megabytes={self.config.max_target_megabytes}",
            f"--config={config}",
            relative_target,
        ]
        return AdapterExecutionPlan(
            commands=(
                CommandSpec(
                    name=f"gitleaks-{subcommand}",
                    executable=str(Path(self.config.executable).resolve()),
                    arguments=tuple(arguments),
                    working_directory=str(root),
                    timeout_seconds=request.timeout_seconds,
                ),
            ),
            expected_outputs=("result.json",),
        )

    def validate_outputs(
        self,
        request: ExecutionRequest,
        plan: AdapterExecutionPlan,
    ) -> tuple[bool, str]:
        valid, reason = super().validate_outputs(request, plan)
        if not valid:
            return valid, reason
        output = Path(request.task_directory) / "result.json"
        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            return False, f"Gitleaks JSON could not be parsed: {type(error).__name__}"
        if not isinstance(payload, list):
            return False, "Gitleaks JSON output must be an array"
        return True, "Gitleaks produced valid JSON output"


def _check_gitleaks_executable(
    executable: Path,
    *,
    expected_version: str,
) -> PrerequisiteCheck:
    if not executable.is_file():
        return PrerequisiteCheck(
            name="gitleaks_executable",
            status=CheckStatus.MISSING,
            detail="Configured Gitleaks executable is missing",
        )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOME"}
    }
    try:
        probe = subprocess.run(
            [str(executable), "version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            env=environment,
            check=False,
        )
        match = re.search(r"\b\d+\.\d+\.\d+\b", probe.stdout + probe.stderr)
        version = match.group(0) if probe.returncode == 0 and match else None
    except (OSError, subprocess.TimeoutExpired):
        version = None
    if version is None:
        return PrerequisiteCheck(
            name="gitleaks_executable",
            status=CheckStatus.UNVERIFIED,
            detail="Gitleaks executable exists, but its runtime version could not be verified",
        )
    if version != expected_version:
        return PrerequisiteCheck(
            name="gitleaks_executable",
            status=CheckStatus.UNVERIFIED,
            detail=f"Gitleaks runtime version {version} does not match verified version {expected_version}",
            version=version,
        )
    return PrerequisiteCheck(
        name="gitleaks_executable",
        status=CheckStatus.AVAILABLE,
        detail="Gitleaks executable and runtime version were verified",
        version=version,
    )


def _write_scan_config(task_directory: Path, exclusions: tuple[str, ...]) -> Path:
    """Create a trusted, default-rule config with policy path exclusions."""
    patterns: list[str] = []
    for exclusion in exclusions:
        if not exclusion or "\x00" in exclusion or "\n" in exclusion or "\r" in exclusion:
            raise ValueError("Unsafe Gitleaks exclusion pattern")
        patterns.append(_glob_to_regex(exclusion.replace("\\", "/")))
    config = task_directory / "gitleaks.generated.toml"
    lines = ["[extend]", "useDefault = true"]
    if patterns:
        lines.extend(("", "[[allowlists]]", 'description = "V2 policy exclusions"', "paths = ["))
        lines.extend(f"  {json.dumps(pattern)}," for pattern in patterns)
        lines.append("]")
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


def _glob_to_regex(pattern: str) -> str:
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*\*", ".*")
    escaped = escaped.replace(r"\*", "[^/]*")
    escaped = escaped.replace(r"\?", "[^/]")
    return "^" + escaped + "$"

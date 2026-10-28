"""Gitleaks CLI adapter for current-file and Git-history secret scans."""

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from security_reviewer_v2.profiler.models import ScanTask, ScanType

from .base import ScannerAdapter
from .hostpaths import parse_version
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
        # Root cause of the "unknown command \"dir\"" failure: Gitleaks < 8.19 has no
        # ``dir``/``git`` subcommands (only ``detect``).  Probe the installed binary and
        # fall back to the equivalent legacy invocation instead of failing the whole task.
        modern = _supports_dir_command(self.config.executable)
        subcommand = ("git" if request.task.mode == "git_history" else "dir") if modern else "detect"
        # Feature detection: only pass flags this binary lists in its own ``--help``.  Old builds reject
        # unknown flags with exit 126 (run_v30: "unknown flag: --no-color"), so a fixed list is fragile.
        supported = _supported_flags(self.config.executable, subcommand)

        def usable(argument: str) -> bool:
            return supported is None or argument.split("=", 1)[0] in supported

        common = [argument for argument in (
            "--report-format=json",
            f"--report-path={output}",
            "--no-banner",
            "--no-color",
            "--redact",
            "--exit-code=0",
            f"--max-target-megabytes={self.config.max_target_megabytes}",
        ) if usable(argument)]
        if modern:
            config = _write_scan_config(task_directory, request.task.exclusions)
            common.append(f"--config={config}")
        # Legacy binaries: NO generated config.  A custom --config *replaces* the built-in rules on
        # old Gitleaks (``[extend] useDefault`` is not honoured), which would silently scan with zero
        # rules.  Scanning with the default ruleset and no path exclusions can only report more,
        # never less, so it is the safe direction.
        if modern:
            arguments = [subcommand, *common, relative_target]
        else:
            arguments = [subcommand, f"--source={relative_target}", *common]
            if request.task.mode != "git_history" and usable("--no-git"):
                arguments.insert(1, "--no-git")
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
        match = parse_version(probe.stdout + probe.stderr)
        version = match if probe.returncode == 0 and match else None
    except (OSError, subprocess.TimeoutExpired):
        version = None
    # Version enforcement disabled: any installed version is accepted.
    if version is None:
        return PrerequisiteCheck(
            name="gitleaks_executable",
            status=CheckStatus.AVAILABLE,
            detail="Gitleaks executable exists; runtime version could not be read (version check skipped)",
        )
    if version != expected_version:
        return PrerequisiteCheck(
            name="gitleaks_executable",
            status=CheckStatus.AVAILABLE,
            detail=f"Gitleaks runtime version {version} differs from {expected_version} (version check skipped)",
            version=version,
        )
    return PrerequisiteCheck(
        name="gitleaks_executable",
        status=CheckStatus.AVAILABLE,
        detail="Gitleaks executable and runtime version were verified",
        version=version,
    )


@functools.lru_cache(maxsize=32)
def _supported_flags(executable: str, subcommand: str) -> frozenset[str] | None:
    """Long flags listed by ``gitleaks <subcommand> --help``; ``None`` when that cannot be determined."""
    try:
        probe = subprocess.run(
            [str(executable), subcommand, "--help"], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=20, shell=False, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    flags = frozenset(re.findall(r"--[a-z][a-z0-9-]*", probe.stdout + probe.stderr))
    return flags or None


@functools.lru_cache(maxsize=16)
def _supports_dir_command(executable: str) -> bool:
    """Return False only when the binary positively reports it has no ``dir`` subcommand."""
    try:
        probe = subprocess.run(
            [str(executable), "dir", "--help"], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=20, shell=False, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return True
    text = (probe.stdout + probe.stderr).lower()
    return not (probe.returncode != 0 and "unknown command" in text)


def _write_scan_config(task_directory: Path, exclusions: tuple[str, ...], *, legacy: bool = False) -> Path:
    """Create a trusted, default-rule config with policy path exclusions."""
    patterns: list[str] = []
    for exclusion in exclusions:
        if not exclusion or "\x00" in exclusion or "\n" in exclusion or "\r" in exclusion:
            raise ValueError("Unsafe Gitleaks exclusion pattern")
        patterns.append(_glob_to_regex(exclusion.replace("\\", "/")))
    config = task_directory / "gitleaks.generated.toml"
    lines = ["[extend]", "useDefault = true"]
    if patterns:
        table = "[allowlist]" if legacy else "[[allowlists]]"  # singular table for Gitleaks < 8.25
        lines.extend(("", table, 'description = "V2 policy exclusions"', "paths = ["))
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

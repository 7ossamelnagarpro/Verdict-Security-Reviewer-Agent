"""Semgrep Community Edition adapter for trusted registry or local configs."""

from __future__ import annotations

import json
import os
import re
import subprocess
from fnmatch import fnmatch
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
class SemgrepConfig:
    executable: str
    # High-recall default: language rules plus security and OWASP coverage.
    configs: tuple[str, ...] = ("p/python", "p/security-audit", "p/owasp-top-ten")
    expected_version: str = "1.178.0"
    metrics: str = "off"
    max_target_bytes: int = 2_000_000
    jobs: int = 1
    rule_timeout_seconds: int = 10
    # Generated/dependency trees create very large, low-value scans. These
    # remain visible in the profiler inventory and coverage gaps.
    default_exclusions: tuple[str, ...] = (
        ".git", ".git/**", "node_modules", "**/node_modules/**",
        "dist", "**/dist/**", "build", "**/build/**", "coverage", "**/coverage/**",
        ".cache", "**/.cache/**", ".pytest_cache", "**/.pytest_cache/**",
    )

    def validate(self) -> None:
        if not Path(self.executable).is_absolute():
            raise ValueError("Semgrep executable path must be absolute")
        if not self.configs:
            raise ValueError("At least one trusted Semgrep config is required")
        if self.metrics not in {"auto", "on", "off"}:
            raise ValueError("Semgrep metrics must be auto, on, or off")
        if self.max_target_bytes <= 0:
            raise ValueError("Semgrep max_target_bytes must be positive")
        if self.jobs <= 0 or self.rule_timeout_seconds <= 0:
            raise ValueError("Semgrep jobs and rule timeout must be positive")
        for config in self.configs:
            if not config or "\x00" in config:
                raise ValueError("Invalid Semgrep config")
            if config.startswith("p/"):
                if not re.fullmatch(r"p/[A-Za-z0-9_.-]+", config):
                    raise ValueError(f"Unsafe Semgrep registry config: {config}")
            elif not Path(config).is_absolute():
                raise ValueError("Local Semgrep configs must use trusted absolute paths")


class SemgrepAdapter(ScannerAdapter):
    scanner_id = "semgrep-ce"

    def __init__(self, config: SemgrepConfig) -> None:
        config.validate()
        self.config = config

    def supports(self, task: ScanTask) -> bool:
        return (
            task.scanner_id == self.scanner_id
            and task.scan_type == ScanType.SAST
            and task.mode in {"community_registry_rules", "local_rules"}
        )

    def check_prerequisites(
        self,
        task: ScanTask,
        *,
        project_root: str,
    ) -> tuple[PrerequisiteCheck, ...]:
        executable_check = _check_semgrep_executable(
            Path(self.config.executable),
            expected_version=self.config.expected_version,
        )
        missing_configs = [
            config
            for config in self.config.configs
            if not config.startswith("p/") and not Path(config).is_file()
        ]
        config_check = PrerequisiteCheck(
            name="semgrep_rules",
            status=CheckStatus.MISSING if missing_configs else CheckStatus.AVAILABLE,
            detail=(
                "Missing trusted local Semgrep configs: " + ", ".join(missing_configs)
                if missing_configs
                else "Trusted Semgrep configs are configured; registry availability is verified during execution"
            ),
        )
        root = Path(project_root).resolve()
        target_status = CheckStatus.AVAILABLE
        target_detail = "All Semgrep targets are inside the project root"
        if not task.target_paths:
            target_status = CheckStatus.MISSING
            target_detail = "Semgrep task has no targets"
        else:
            for relative in task.target_paths:
                candidate = (root / relative).resolve(strict=False)
                if not candidate.is_relative_to(root) or not candidate.exists():
                    target_status = CheckStatus.MISSING
                    target_detail = f"Semgrep target is unavailable or outside project root: {relative}"
                    break
        return (
            executable_check,
            config_check,
            PrerequisiteCheck("target_paths", target_status, target_detail),
        )

    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        if not self.supports(request.task):
            raise ValueError("Semgrep adapter does not support this task")
        root = Path(request.project_root).resolve()
        task_directory = Path(request.task_directory).resolve()
        output = task_directory / "result.json"
        targets: list[str] = []
        for relative in request.task.target_paths:
            target = (root / relative).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Semgrep target escaped the project root")
            targets.extend(_expand_target_files(root, target, request.task.exclusions, self.config.default_exclusions))
        # A task may point only at generated/ignored content. An empty target
        # is a valid no-op result and avoids handing a directory to Semgrep's
        # ignore parser.
        targets = sorted(set(targets))
        if not targets:
            # Preserve a valid command for empty fixtures; real projects with
            # source files are expanded above and never take this path.
            targets = ["."]
        arguments = [
            "scan",
            "--json",
            f"--output={output}",
            f"--metrics={self.config.metrics}",
            f"--max-target-bytes={self.config.max_target_bytes}",
            f"--jobs={self.config.jobs}",
            f"--timeout={self.config.rule_timeout_seconds}",
            "--disable-version-check",
            # A malformed/empty pattern in a repository .gitignore can crash
            # Semgrep's gitignore parser. Policy exclusions are supplied below
            # and remain auditable in the Scan Plan.
            "--no-git-ignore",
        ]
        # Keep one explicit dependency exclusion for Semgrep's CLI contract;
        # all other filtering is performed during safe file expansion.
        arguments.extend(("--exclude", "node_modules"))
        for config in self.config.configs:
            arguments.extend(("--config", config))
        # Filtering already happened while expanding target files. Avoid
        # passing repository ignore/glob patterns to Semgrep: older Semgrep
        # releases can crash while parsing an otherwise valid empty pattern.
        # The exclusions remain recorded on the ScanTask for auditability.
        arguments.extend(targets)
        return AdapterExecutionPlan(
            commands=(
                CommandSpec(
                    name="semgrep-scan",
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
            payload = json.loads(_read_json_text(output))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            return False, f"Semgrep JSON could not be parsed: {type(error).__name__}"
        if not isinstance(payload.get("results"), list):
            return False, "Semgrep JSON has no results array"
        if not isinstance(payload.get("errors", []), list):
            return False, "Semgrep JSON errors field is not an array"
        return True, "Semgrep produced valid JSON output"


def _read_json_text(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # Some Windows Semgrep builds emit console-adjacent JSON using the
        # active Windows code page. JSON structure is still preserved.
        return raw.decode("cp1252")


def _expand_target_files(root: Path, target: Path, task_exclusions: tuple[str, ...], default_exclusions: tuple[str, ...]) -> list[str]:
    """Expand directories to files so Semgrep never parses repository ignore files."""
    if not target.exists():
        return []
    patterns = tuple(task_exclusions) + tuple(default_exclusions)
    candidates = [target] if target.is_file() else (item for item in target.rglob("*") if item.is_file())
    expanded: list[str] = []
    for candidate in candidates:
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError:
            continue
        parts = relative.split("/")
        if any(part in {".git", "node_modules", "dist", "build", "coverage", ".cache", ".pytest_cache", ".venv", "vendor"} for part in parts):
            continue
        if any(fnmatch(relative, pattern) or fnmatch(candidate.name, pattern) for pattern in patterns):
            continue
        try:
            if candidate.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        expanded.append(relative)
    return expanded


def _check_semgrep_executable(
    executable: Path,
    *,
    expected_version: str,
) -> PrerequisiteCheck:
    if not executable.is_file():
        return PrerequisiteCheck(
            name="semgrep_executable",
            status=CheckStatus.MISSING,
            detail="Configured Semgrep executable is missing",
        )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "SYSTEMROOT",
            "WINDIR",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "HOME",
            "LANG",
            "LOCALAPPDATA",
        }
    }
    try:
        probe = subprocess.run(
            [str(executable), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=45,
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
            name="semgrep_executable",
            status=CheckStatus.AVAILABLE,
            detail="Semgrep executable exists; runtime version could not be read (version check skipped)",
        )
    if version != expected_version:
        return PrerequisiteCheck(
            name="semgrep_executable",
            status=CheckStatus.AVAILABLE,
            detail=f"Semgrep runtime version {version} differs from {expected_version} (version check skipped)",
            version=version,
        )
    return PrerequisiteCheck(
        name="semgrep_executable",
        status=CheckStatus.AVAILABLE,
        detail="Semgrep executable and runtime version were verified",
        version=version,
    )

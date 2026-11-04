"""CodeQL CLI adapter for standard SAST query suites."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
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
class CodeQLConfig:
    executable: str
    query_suites: dict[str, str]
    search_path: str | None = None
    expected_version: str = "2.27.1"
    threads: int = 2
    ram_mb: int = 4096
    extraction_timeout_seconds: float = 900
    analysis_timeout_seconds: float = 1800
    default_paths_ignore: tuple[str, ...] = ()
    build_modes: dict[str, str] = field(
        default_factory=lambda: {
            "python": "none",
            "javascript": "none",
            "typescript": "none",
            "ruby": "none",
        }
    )

    def validate(self) -> None:
        executable = Path(self.executable)
        if (
            min(
                self.threads,
                self.ram_mb,
                self.extraction_timeout_seconds,
                self.analysis_timeout_seconds,
            )
            <= 0
        ):
            raise ValueError("CodeQL resources and stage timeouts must be positive")
        if not executable.is_absolute():
            raise ValueError("CodeQL executable path must be absolute")
        for language, suite in self.query_suites.items():
            if not language or not Path(suite).is_absolute():
                raise ValueError(
                    "CodeQL query suite paths must be absolute and keyed by language"
                )
        if self.search_path is not None and not Path(self.search_path).is_absolute():
            raise ValueError("CodeQL search path must be absolute")


class CodeQLAdapter(ScannerAdapter):
    scanner_id = "codeql-cli"

    def __init__(self, config: CodeQLConfig) -> None:
        config.validate()
        self.config = config

    def supports(self, task: ScanTask) -> bool:
        return (
            task.scanner_id == self.scanner_id
            and task.scan_type == ScanType.SAST
            and task.mode == "standard_query_suite"
            and task.language_or_ecosystem in self.config.query_suites
        )

    def check_prerequisites(
        self,
        task: ScanTask,
        *,
        project_root: str,
    ) -> tuple[PrerequisiteCheck, ...]:
        executable = Path(self.config.executable)
        language = task.language_or_ecosystem or ""
        suite_value = self.config.query_suites.get(language)
        suite = Path(suite_value) if suite_value else None
        root = Path(project_root).resolve()
        executable_check = _check_codeql_executable(
            executable,
            expected_version=self.config.expected_version,
        )
        suite_check = PrerequisiteCheck(
            name="language_query_pack",
            status=CheckStatus.AVAILABLE
            if suite and suite.is_file()
            else CheckStatus.MISSING,
            detail=(
                f"Configured {language} standard query suite exists"
                if suite and suite.is_file()
                else f"No usable standard query suite is configured for {language or 'unknown language'}"
            ),
        )
        target_status = CheckStatus.AVAILABLE
        target_detail = "All CodeQL targets are inside the project root"
        if not task.target_paths:
            target_status = CheckStatus.MISSING
            target_detail = "CodeQL task has no target path"
        else:
            for relative in task.target_paths:
                candidate = (root / relative).resolve(strict=False)
                if not candidate.is_relative_to(root) or not candidate.exists():
                    target_status = CheckStatus.MISSING
                    target_detail = f"CodeQL target is unavailable or outside project root: {relative}"
                    break
        search_status = CheckStatus.AVAILABLE
        search_detail = "CodeQL search path is not required for this configured suite"
        if self.config.search_path:
            search = Path(self.config.search_path)
            search_status = (
                CheckStatus.AVAILABLE if search.is_dir() else CheckStatus.MISSING
            )
            search_detail = (
                "Configured CodeQL search path exists"
                if search.is_dir()
                else "Configured CodeQL search path is missing"
            )
        return (
            executable_check,
            suite_check,
            PrerequisiteCheck("target_paths", target_status, target_detail),
            PrerequisiteCheck("codeql_search_path", search_status, search_detail),
        )

    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        task = request.task
        if not self.supports(task):
            raise ValueError("CodeQL adapter does not support this task")
        project_root = Path(request.project_root).resolve()
        task_directory = Path(request.task_directory).resolve()
        target = (project_root / task.target_paths[0]).resolve()
        if not target.is_relative_to(project_root):
            raise ValueError("CodeQL target escaped the project root")
        database = task_directory / "database"
        sarif = task_directory / "result.sarif"
        language = task.language_or_ecosystem or ""
        suite = Path(self.config.query_suites[language]).resolve()
        if len(task.target_paths) != 1:
            raise ValueError("CodeQL requires exactly one source root")
        # JSON is a YAML subset accepted by CodeQL. This configuration is
        # generated from trusted policy, never loaded from the target project.
        extraction_config = task_directory / "extraction-config.json"
        ignored = tuple(
            dict.fromkeys((*task.exclusions, *self.config.default_paths_ignore))
        )
        extraction_config.write_text(
            json.dumps({"paths-ignore": list(ignored)}), encoding="utf-8"
        )
        create_arguments = [
            "database",
            "create",
            str(database),
            f"--language={_codeql_language(language)}",
            f"--source-root={target}",
            f"--codescanning-config={extraction_config}",
            f"--threads={self.config.threads}",
        ]
        build_mode = self.config.build_modes.get(language)
        if build_mode:
            create_arguments.append(f"--build-mode={build_mode}")
        analyze_arguments = [
            "database",
            "analyze",
            str(database),
            str(suite),
            "--format=sarif-latest",
            f"--output={sarif}",
            f"--threads={self.config.threads}",
            f"--ram={self.config.ram_mb}",
        ]
        if self.config.search_path:
            analyze_arguments.append(
                f"--search-path={Path(self.config.search_path).resolve()}"
            )
        commands = (
            CommandSpec(
                name="database-create",
                executable=str(Path(self.config.executable).resolve()),
                arguments=tuple(create_arguments),
                working_directory=str(project_root),
                timeout_seconds=min(
                    request.timeout_seconds, self.config.extraction_timeout_seconds
                ),
            ),
            CommandSpec(
                name="database-analyze",
                executable=str(Path(self.config.executable).resolve()),
                arguments=tuple(analyze_arguments),
                working_directory=str(project_root),
                timeout_seconds=min(
                    request.timeout_seconds, self.config.analysis_timeout_seconds
                ),
            ),
        )
        return AdapterExecutionPlan(
            commands=commands, expected_outputs=("result.sarif",)
        )

    def validate_outputs(
        self,
        request: ExecutionRequest,
        plan: AdapterExecutionPlan,
    ) -> tuple[bool, str]:
        valid, reason = super().validate_outputs(request, plan)
        if not valid:
            return valid, reason
        sarif = Path(request.task_directory) / "result.sarif"
        try:
            payload = json.loads(sarif.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return False, f"CodeQL SARIF could not be parsed: {type(error).__name__}"
        if payload.get("version") not in {"2.1.0", "2.1.0-rtm.5"}:
            return False, "CodeQL output does not declare a supported SARIF version"
        if not isinstance(payload.get("runs"), list):
            return False, "CodeQL SARIF output has no runs array"
        return True, "CodeQL produced valid SARIF output"


def _codeql_language(language: str) -> str:
    if language in {"javascript", "typescript"}:
        return "javascript-typescript"
    if language == "csharp":
        return "csharp"
    if language == "cpp":
        return "cpp"
    return language


def _check_codeql_executable(
    executable: Path,
    *,
    expected_version: str,
) -> PrerequisiteCheck:
    if not executable.is_file():
        return PrerequisiteCheck(
            name="codeql_executable",
            status=CheckStatus.MISSING,
            detail="Configured CodeQL executable is missing",
        )
    allowed_environment = {
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
        }
    }
    try:
        probe = subprocess.run(
            [str(executable), "version", "--format=json"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            env=allowed_environment,
            check=False,
        )
        payload = json.loads(probe.stdout) if probe.returncode == 0 else {}
        version = str(payload.get("version", "")) or None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        version = None
    if version is None:
        return PrerequisiteCheck(
            name="codeql_executable",
            status=CheckStatus.UNVERIFIED,
            detail="CodeQL executable exists, but its runtime version could not be verified",
        )
    if version != expected_version:
        return PrerequisiteCheck(
            name="codeql_executable",
            status=CheckStatus.UNVERIFIED,
            detail=f"CodeQL runtime version {version} does not match verified version {expected_version}",
            version=version,
        )
    return PrerequisiteCheck(
        name="codeql_executable",
        status=CheckStatus.AVAILABLE,
        detail="CodeQL executable and runtime version were verified",
        version=version,
    )

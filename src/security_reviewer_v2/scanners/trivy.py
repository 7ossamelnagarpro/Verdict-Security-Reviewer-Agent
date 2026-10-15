"""Trivy filesystem adapter for SCA, secrets, and misconfiguration scans."""

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
class TrivyConfig:
    executable: str
    expected_version: str = "0.75.0"
    database_path: str | None = None
    skip_db_update: bool = True
    skip_version_check: bool = True

    def validate(self) -> None:
        if not Path(self.executable).is_absolute():
            raise ValueError("Trivy executable path must be absolute")
        if self.database_path is not None and not Path(self.database_path).is_absolute():
            raise ValueError("Trivy database_path must be absolute")


class TrivyAdapter(ScannerAdapter):
    scanner_id = "trivy"

    def __init__(self, config: TrivyConfig) -> None:
        config.validate()
        self.config = config

    def supports(self, task: ScanTask) -> bool:
        return (
            task.scanner_id == self.scanner_id
            and task.scan_type in {ScanType.SCA, ScanType.SECRETS, ScanType.MISCONFIGURATION}
            and task.mode == "filesystem"
        )

    def check_prerequisites(
        self,
        task: ScanTask,
        *,
        project_root: str,
    ) -> tuple[PrerequisiteCheck, ...]:
        executable_check = _check_trivy_executable(
            Path(self.config.executable), expected_version=self.config.expected_version
        )
        root = Path(project_root).resolve()
        target_status = CheckStatus.AVAILABLE
        target_detail = "All Trivy targets are inside the project root"
        if not task.target_paths:
            target_status = CheckStatus.MISSING
            target_detail = "Trivy filesystem task has no target path"
        else:
            for relative in task.target_paths:
                candidate = (root / relative).resolve(strict=False)
                if not candidate.is_relative_to(root) or not candidate.exists():
                    target_status = CheckStatus.MISSING
                    target_detail = f"Trivy target is unavailable or outside project root: {relative}"
                    break
        database = CheckStatus.AVAILABLE
        database_detail = "This Trivy scan type does not require a vulnerability database"
        if task.scan_type == ScanType.SCA:
            cache_dir = _trivy_cache_dir(self.config)
            if cache_dir is not None and _has_vulnerability_db(cache_dir):
                database_detail = f"Trivy vulnerability database is available at {cache_dir}"
            else:
                database = CheckStatus.UNVERIFIED
                database_detail = "SCA requires a verified Trivy vulnerability database; run trivy fs --download-db-only"
        return (
            executable_check,
            PrerequisiteCheck("target_paths", target_status, target_detail),
            PrerequisiteCheck("trivy_databases", database, database_detail),
        )

    def build_execution_plan(self, request: ExecutionRequest) -> AdapterExecutionPlan:
        if not self.supports(request.task):
            raise ValueError("Trivy adapter does not support this task")
        root = Path(request.project_root).resolve()
        task_directory = Path(request.task_directory).resolve()
        commands: list[CommandSpec] = []
        outputs: list[str] = []
        scanner_name = {
            ScanType.SCA: "vuln",
            ScanType.SECRETS: "secret",
            ScanType.MISCONFIGURATION: "misconfig",
        }[request.task.scan_type]
        for index, relative in enumerate(request.task.target_paths):
            target = (root / relative).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Trivy target escaped the project root")
            output_name = f"result-{index}.json"
            output = task_directory / output_name
            arguments = [
                "fs",
                "--format=json",
                f"--output={output}",
                f"--scanners={scanner_name}",
                "--exit-code=0",
                "--no-progress",
            ]
            if self.config.skip_db_update:
                arguments.append("--skip-db-update")
            if self.config.skip_version_check:
                arguments.append("--skip-version-check")
            cache_dir = _trivy_cache_dir(self.config)
            if cache_dir is not None:
                arguments.append(f"--cache-dir={cache_dir}")
            for exclusion in request.task.exclusions:
                normalized = exclusion.replace("\\", "/")
                if normalized.endswith("/**"):
                    arguments.extend(("--skip-dirs", normalized[:-3].rstrip("/")))
                elif "*" in normalized or "?" in normalized:
                    arguments.extend(("--skip-files", normalized))
                else:
                    arguments.extend(("--skip-dirs", normalized))
            arguments.append(str(target))
            commands.append(
                CommandSpec(
                    name=f"trivy-filesystem-{index}",
                    executable=str(Path(self.config.executable).resolve()),
                    arguments=tuple(arguments),
                    working_directory=str(root),
                    timeout_seconds=request.timeout_seconds,
                )
            )
            outputs.append(output_name)
        return AdapterExecutionPlan(commands=tuple(commands), expected_outputs=tuple(outputs))

    def validate_outputs(
        self,
        request: ExecutionRequest,
        plan: AdapterExecutionPlan,
    ) -> tuple[bool, str]:
        valid, reason = super().validate_outputs(request, plan)
        if not valid:
            return valid, reason
        for relative in plan.expected_outputs:
            try:
                payload = json.loads((Path(request.task_directory) / relative).read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                return False, f"Trivy JSON could not be parsed: {type(error).__name__}"
            if not isinstance(payload, dict) or not isinstance(payload.get("Results", []), list):
                return False, f"Trivy output has no Results array: {relative}"
        return True, "Trivy produced valid JSON output"


def _check_trivy_executable(
    executable: Path,
    *,
    expected_version: str,
) -> PrerequisiteCheck:
    if not executable.is_file():
        return PrerequisiteCheck(
            name="trivy_executable",
            status=CheckStatus.MISSING,
            detail="Configured Trivy executable is missing",
        )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOME"}
    }
    try:
        probe = subprocess.run(
            [str(executable), "--version"],
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
            name="trivy_executable",
            status=CheckStatus.UNVERIFIED,
            detail="Trivy executable exists, but its runtime version could not be verified",
        )
    if version != expected_version:
        return PrerequisiteCheck(
            name="trivy_executable",
            status=CheckStatus.UNVERIFIED,
            detail=f"Trivy runtime version {version} does not match verified version {expected_version}",
            version=version,
        )
    return PrerequisiteCheck(
        name="trivy_executable",
        status=CheckStatus.AVAILABLE,
        detail="Trivy executable and runtime version were verified",
        version=version,
    )


def _trivy_cache_dir(config: TrivyConfig) -> Path | None:
    candidates: list[Path] = []
    if config.database_path:
        candidates.append(Path(config.database_path).resolve())
    environment_path = os.environ.get("TRIVY_CACHE_DIR")
    if environment_path:
        candidates.append(Path(environment_path).resolve())
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append((Path(local_app_data) / "trivy").resolve())
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append((Path(user_profile) / ".cache" / "trivy").resolve())
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0] if candidates else None


def _has_vulnerability_db(cache_dir: Path) -> bool:
    return (
        (cache_dir / "db" / "trivy.db").is_file()
        and (cache_dir / "db" / "metadata.json").is_file()
    )

"""Behavioral tests for Gitleaks and Trivy adapters and normalizers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from security_reviewer_v2.normalization import (
    FindingSeverity,
    NormalizationInputError,
    normalize_gitleaks_json,
    normalize_trivy_json,
)
from security_reviewer_v2.profiler.models import ScanTask, ScanType, PlanStatus, PrerequisiteState
from security_reviewer_v2.scanners.gitleaks import GitleaksAdapter, GitleaksConfig
from security_reviewer_v2.scanners.models import ExecutionRequest
from security_reviewer_v2.scanners.trivy import TrivyAdapter, TrivyConfig


def task(
    scanner_id: str,
    scan_type: ScanType,
    *,
    mode: str,
    targets: tuple[str, ...] = (".",),
) -> ScanTask:
    return ScanTask(
        task_id=f"task-{scanner_id}",
        scanner_id=scanner_id,
        scan_type=scan_type,
        component_id=None,
        target_paths=targets,
        language_or_ecosystem=None,
        mode=mode,
        rule_references=(),
        exclusions=(".git/**", ".venv/**", "*.png"),
        evidence=(),
        reasons=(),
        prerequisites=(),
        prerequisite_status=PrerequisiteState.AVAILABLE,
        status=PlanStatus.SELECTED,
    )


def request(tmp_path: Path, scan_task: ScanTask) -> ExecutionRequest:
    project = tmp_path / "project"
    task_dir = tmp_path / "task"
    project.mkdir()
    task_dir.mkdir()
    return ExecutionRequest(
        run_id="test",
        task=scan_task,
        project_root=str(project.resolve()),
        task_directory=str(task_dir.resolve()),
        timeout_seconds=30,
    )


def test_gitleaks_adapter_builds_redacted_directory_command(tmp_path: Path) -> None:
    adapter = GitleaksAdapter(GitleaksConfig(executable=str(Path(sys.executable).resolve())))
    plan = adapter.build_execution_plan(request(tmp_path, task("gitleaks", ScanType.SECRETS, mode="directory")))

    command = plan.commands[0]
    assert command.arguments[0] == "dir"
    assert "--report-format=json" in command.arguments
    assert "--redact" in command.arguments
    assert "--exit-code=0" in command.arguments
    config = tmp_path / "task" / "gitleaks.generated.toml"
    assert config.is_file()
    assert "useDefault = true" in config.read_text(encoding="utf-8")
    assert "V2 policy exclusions" in config.read_text(encoding="utf-8")
    assert plan.expected_outputs == ("result.json",)


def test_gitleaks_adapter_supports_git_history_mode(tmp_path: Path) -> None:
    adapter = GitleaksAdapter(GitleaksConfig(executable=str(Path(sys.executable).resolve())))
    plan = adapter.build_execution_plan(request(tmp_path, task("gitleaks", ScanType.SECRETS, mode="git_history")))

    assert plan.commands[0].arguments[0] == "git"


def test_gitleaks_adapter_rejects_unsupported_task(tmp_path: Path) -> None:
    adapter = GitleaksAdapter(GitleaksConfig(executable=str(Path(sys.executable).resolve())))
    with pytest.raises(ValueError):
        adapter.build_execution_plan(request(tmp_path, task("gitleaks", ScanType.SCA, mode="directory")))


def test_trivy_adapter_builds_one_command_per_target_and_maps_exclusions(tmp_path: Path) -> None:
    adapter = TrivyAdapter(TrivyConfig(executable=str(Path(sys.executable).resolve())))
    scan_task = task("trivy", ScanType.SCA, mode="filesystem", targets=("requirements.txt", "package-lock.json"))
    plan = adapter.build_execution_plan(request(tmp_path, scan_task))

    assert len(plan.commands) == 2
    assert plan.expected_outputs == ("result-0.json", "result-1.json")
    arguments = plan.commands[0].arguments
    assert arguments[:2] == ("fs", "--format=json")
    assert "--scanners=vuln" in arguments
    assert "--skip-dirs" in arguments
    assert "--skip-files" in arguments


def test_trivy_adapter_maps_scan_types() -> None:
    adapter = TrivyAdapter(TrivyConfig(executable=str(Path(sys.executable).resolve())))
    for scan_type, expected in (
        (ScanType.SECRETS, "--scanners=secret"),
        (ScanType.MISCONFIGURATION, "--scanners=misconfig"),
    ):
        assert expected in adapter.build_execution_plan(
            request_for_existing_tmp(task("trivy", scan_type, mode="filesystem"))
        ).commands[0].arguments


def test_trivy_sca_requires_an_explicit_verified_database_path(tmp_path: Path) -> None:
    adapter = TrivyAdapter(TrivyConfig(executable=str(Path(sys.executable).resolve())))
    scan_task = task("trivy", ScanType.SCA, mode="filesystem")

    checks = adapter.check_prerequisites(scan_task, project_root=str(tmp_path))

    database = next(item for item in checks if item.name == "trivy_databases")
    assert database.status.value in {"available", "unverified"}


def test_trivy_detects_configured_database_cache(tmp_path: Path) -> None:
    cache = tmp_path / "trivy-cache" / "db"
    cache.mkdir(parents=True)
    (cache / "trivy.db").write_bytes(b"fixture")
    (cache / "metadata.json").write_text("{}", encoding="utf-8")
    adapter = TrivyAdapter(
        TrivyConfig(executable=str(Path(sys.executable).resolve()), database_path=str(cache.parent))
    )

    checks = adapter.check_prerequisites(
        task("trivy", ScanType.SCA, mode="filesystem"), project_root=str(tmp_path)
    )

    database = next(item for item in checks if item.name == "trivy_databases")
    assert database.status.value == "available"


def request_for_existing_tmp(scan_task: ScanTask) -> ExecutionRequest:
    root = Path.cwd().resolve()
    return ExecutionRequest("test", scan_task, str(root), str(root / "tests"), 30)


def test_gitleaks_normalizer_omits_secret_value() -> None:
    result = normalize_gitleaks_json(
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS Access Key",
                "File": "config.py",
                "StartLine": 4,
                "EndLine": 4,
                "Secret": "SUPER-SECRET-VALUE",
                "Match": "token = SUPER-SECRET-VALUE",
                "Fingerprint": "config.py:aws-access-token:4",
            }
        ]
    )

    assert result.findings[0].scanner.scanner_id == "gitleaks"
    assert result.findings[0].primary_location.path == "config.py"
    serialized = json.dumps(result.to_dict())
    assert "SUPER-SECRET-VALUE" not in serialized
    assert result.findings[0].severity == FindingSeverity.HIGH


def test_gitleaks_normalizer_rejects_traversal() -> None:
    result = normalize_gitleaks_json([{"RuleID": "x", "File": "../secret.env", "StartLine": 1}])

    assert result.status.value == "failed"
    assert result.findings == ()


def test_trivy_normalizer_handles_vulnerabilities_misconfig_and_secrets() -> None:
    result = normalize_trivy_json(
        {
            "SchemaVersion": 2,
            "Metadata": {"Version": "0.75.0"},
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "demo",
                            "Severity": "HIGH",
                            "Title": "Demo vulnerability",
                            "CweIDs": ["CWE-89"],
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-TEST-0001",
                            "Title": "Insecure setting",
                            "Message": "The setting is unsafe",
                            "Severity": "MEDIUM",
                            "CauseMetadata": {"StartLine": 3},
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "generic-secret",
                            "Category": "generic",
                            "Title": "Generic secret",
                            "StartLine": 5,
                            "Match": "HIDDEN-SECRET",
                        }
                    ],
                }
            ],
        }
    )

    assert result.status.value == "complete"
    assert len(result.findings) == 3
    assert result.summary.input_results == 3
    assert {finding.rule_id for finding in result.findings} == {
        "CVE-2026-0001",
        "AVD-TEST-0001",
        "generic-secret",
    }
    assert "HIDDEN-SECRET" not in json.dumps(result.to_dict())
    assert next(item for item in result.findings if item.rule_id == "AVD-TEST-0001").primary_location.start_line == 3


def test_trivy_normalizer_rejects_unrecognized_root() -> None:
    with pytest.raises(NormalizationInputError):
        normalize_trivy_json({"results": []})


def test_trivy_normalizer_accepts_metadata_only_zero_findings_output() -> None:
    result = normalize_trivy_json(
        {"SchemaVersion": 2, "Trivy": {"Version": "0.75.0"}, "ArtifactType": "filesystem"}
    )

    assert result.status.value == "complete"
    assert result.findings == ()
    assert result.summary.input_results == 0

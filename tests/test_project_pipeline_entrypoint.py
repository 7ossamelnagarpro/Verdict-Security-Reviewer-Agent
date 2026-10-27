from __future__ import annotations

import argparse
import json
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import run_project_pipeline as entrypoint
from scripts.run_project_pipeline import _command, _prepare_runtime, _validate
from security_reviewer_v2.test_environment.manager import TestEnvironmentSession as EnvironmentSession


def _args(tmp_path: Path, project: Path, *, provider: str = "ollama") -> argparse.Namespace:
    return argparse.Namespace(
        project=project,
        output=tmp_path / "reports",
        runtime_contract=None,
        static_only=True,
        allow_trusted_local_compose=False,
        codeql_bundle=None,
        ai_provider=provider,
        ai_model=None,
        ai_max_targets=10,
        ai_max_batches=20,
        ai_max_planned_targets=128,
        ai_max_candidates=20,
        ai_max_enrichment_rounds=2,
        review_max_findings=3,
        require_all_scanners=False,
    )


def test_generic_entrypoint_accepts_arbitrary_project_and_stays_source_only(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project)

    validated_project, output = _validate(args)
    command = _command(args, project=validated_project, output=output)

    assert str(project) in command
    assert "--require-sast" in command
    assert "--require-dast" not in command
    assert "--runtime-url" not in command
    assert "--docker-runtime-run-id" not in command


def test_generic_entrypoint_rejects_output_inside_project(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project)
    args.output = project / "reports"

    with pytest.raises(ValueError, match="outside the scanned project"):
        _validate(args)


def test_full_scan_requires_runtime_contract(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project)
    args.static_only = False

    with pytest.raises(ValueError, match="runtime-contract"):
        _validate(args)


def test_generic_entrypoint_requires_groq_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project, provider="groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        _validate(args)


def test_trusted_local_compose_starts_only_with_opt_in_and_checks_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    (project / "app.py").write_text("print('scan me')\n", encoding="utf-8")
    (project / "compose.yaml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")
    contract = tmp_path / "runtime-contract.json"
    contract.write_text(json.dumps({
        "schema_version": "1.0", "mode": "docker_compose",
        "trust_level": "trusted_local_project", "authorized_for_testing": True,
        "target": {"base_url": "http://127.0.0.1:8080", "health_path": "/", "expected_status": 200},
        "compose": {"file": "compose.yaml", "app_service": "web"},
        "accounts": [], "checks": {"authorization": False, "mutating": False},
        "endpoints": ["/"], "required_env": [],
    }), encoding="utf-8")
    args = _args(tmp_path, project)
    args.static_only = False
    args.runtime_contract = contract
    with pytest.raises(ValueError, match="explicit"):
        _prepare_runtime(args, project=project, output=tmp_path / "not-started")
    args.allow_trusted_local_compose = True
    monkeypatch.setattr(entrypoint.shutil, "which", lambda _: "docker")
    started = []

    @contextmanager
    def fake_provision(*_args, **kwargs):
        started.append(kwargs)
        yield EnvironmentSession("http://127.0.0.1:8080", "docker_compose", "sr-test-example")

    def fake_checks(config):
        config.output.write_text('{"status":"completed"}', encoding="utf-8")

    def fake_process(argv, **_kwargs):
        assert "label=com.docker.compose.project=sr-test-example" in argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(entrypoint, "provision_environment", fake_provision)
    monkeypatch.setattr(entrypoint, "run_generic_checks", fake_checks)
    monkeypatch.setattr(entrypoint.subprocess, "run", fake_process)
    runtime = _prepare_runtime(args, project=project, output=tmp_path / "run")
    assert runtime.is_file()
    assert started[0]["allow_compose_execution"] is True

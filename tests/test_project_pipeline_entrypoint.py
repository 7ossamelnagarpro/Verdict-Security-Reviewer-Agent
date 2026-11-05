from __future__ import annotations

import argparse
import json
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import run_project_pipeline as entrypoint
from scripts.run_project_pipeline import _command, _prepare_runtime, _validate
from security_reviewer_v2.test_environment.manager import (
    TestEnvironmentSession as EnvironmentSession,
)


def _args(
    tmp_path: Path, project: Path, *, provider: str = "ollama"
) -> argparse.Namespace:
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
        ai_max_context_chars=None,
        ai_max_planned_targets=128,
        ai_max_candidates=20,
        ai_max_enrichment_rounds=2,
        review_max_findings=3,
        require_all_scanners=False,
    )


def test_generic_entrypoint_accepts_arbitrary_project_and_stays_source_only(
    tmp_path: Path,
) -> None:
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


def test_codebase_memory_is_forwarded_by_default_with_explicit_opt_out(
    tmp_path: Path,
) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project)

    assert "--codebase-memory" in _command(args, project=project, output=args.output)
    args.codebase_memory = False
    command = _command(args, project=project, output=args.output)
    assert "--codebase-memory" not in command
    assert "--no-codebase-memory" in command


def test_groq_discovery_uses_bounded_prompt_budget_with_override(tmp_path: Path):
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project, provider="groq")

    command = _command(args, project=project, output=args.output)
    assert command[command.index("--ai-max-context-chars") + 1] == "8000"

    args.ai_max_context_chars = 12_000
    command = _command(args, project=project, output=args.output)
    assert command[command.index("--ai-max-context-chars") + 1] == "12000"

    args.ai_max_context_chars = 999
    with pytest.raises(ValueError, match="ai-max-context-chars"):
        _validate(args)


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


def test_current_discovery_get_requires_trusted_compose_and_reaches_child(
    tmp_path: Path,
) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    contract = tmp_path / "contract.json"
    contract.write_text("{}", encoding="utf-8")
    args = _args(tmp_path, project)
    args.auto_discovery_get = True

    with pytest.raises(ValueError, match="trusted Compose contract"):
        _validate(args)

    args.static_only = False
    args.runtime_contract = contract
    args.allow_trusted_local_compose = True
    _validate(args)
    assert "--auto-discovery-get" in _command(args, project=project, output=args.output)

    args.approved_discovery_plan = tmp_path / "older-plan.json"
    with pytest.raises(ValueError, match="approved prior plan"):
        _validate(args)


def test_generic_entrypoint_requires_groq_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    args = _args(tmp_path, project, provider="groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        _validate(args)


def test_trusted_local_compose_starts_only_with_opt_in_and_checks_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    (project / "app.py").write_text("print('scan me')\n", encoding="utf-8")
    (project / "compose.yaml").write_text(
        "services:\n  web:\n    build: .\n", encoding="utf-8"
    )
    contract = tmp_path / "runtime-contract.json"
    contract.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "mode": "docker_compose",
                "trust_level": "trusted_local_project",
                "authorized_for_testing": True,
                "target": {
                    "base_url": "http://127.0.0.1:8080",
                    "health_path": "/",
                    "expected_status": 200,
                },
                "compose": {"file": "compose.yaml", "app_service": "web"},
                "accounts": [],
                "checks": {"authorization": False, "mutating": False},
                "endpoints": ["/"],
                "required_env": [],
            }
        ),
        encoding="utf-8",
    )
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
        yield EnvironmentSession(
            "http://127.0.0.1:8080", "docker_compose", "sr-test-example"
        )

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


def test_trusted_compose_runs_browser_before_declared_workflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from security_reviewer_v2.scanners import browser_runtime, runtime_workflows

    project = tmp_path / "customer-app"
    project.mkdir()
    (project / "app.py").write_text("print('scan me')\n", encoding="utf-8")
    (project / "compose.yaml").write_text(
        "services:\n  web:\n    build: .\n", encoding="utf-8"
    )
    suite = {
        "version": 1,
        "allow_mutation": True,
        "reset": "fresh_stack",
        "accounts": [],
        "workflows": [
            {
                "id": "create_item",
                "title": "Create test item",
                "severity": "low",
                "steps": [
                    {
                        "actor": "anonymous",
                        "method": "POST",
                        "path": "/items",
                        "expect_status": [201],
                    }
                ],
            }
        ],
    }
    contract = tmp_path / "runtime-contract.json"
    contract.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "mode": "docker_compose",
                "trust_level": "trusted_local_project",
                "authorized_for_testing": True,
                "target": {
                    "base_url": "http://127.0.0.1:8080",
                    "health_path": "/",
                    "expected_status": 200,
                },
                "compose": {"file": "compose.yaml", "app_service": "web"},
                "accounts": [],
                "checks": {"authorization": False, "mutating": False},
                "endpoints": ["/items"],
                "required_env": [],
                "workflow_suite": suite,
            }
        ),
        encoding="utf-8",
    )
    args = _args(tmp_path, project)
    args.static_only = False
    args.runtime_contract = contract
    args.allow_trusted_local_compose = True
    order: list[str] = []

    @contextmanager
    def fake_provision(*_args, **_kwargs):
        yield EnvironmentSession(
            "http://127.0.0.1:8080", "docker_compose", "sr-test-example"
        )

    def fake_checks(config):
        order.append("baseline")
        config.output.write_text('{"status":"completed"}', encoding="utf-8")

    def fake_browser(*_args, **kwargs):
        assert kwargs["disposable"] is True
        assert "/items" in kwargs["seed_paths"]
        order.append("browser")

    def fake_workflows(*_args, **kwargs):
        assert kwargs["disposable"] is True
        order.append("workflows")

    monkeypatch.setattr(entrypoint.shutil, "which", lambda _: "docker")
    monkeypatch.setattr(entrypoint, "provision_environment", fake_provision)
    monkeypatch.setattr(entrypoint, "run_generic_checks", fake_checks)
    monkeypatch.setattr(browser_runtime, "run_browser_dast", fake_browser)
    monkeypatch.setattr(runtime_workflows, "append_workflows", fake_workflows)
    monkeypatch.setattr(entrypoint, "_zap", lambda *_args: order.append("zap"))
    monkeypatch.setattr(
        entrypoint.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, "", ""),
    )

    _prepare_runtime(args, project=project, output=tmp_path / "run")

    assert order == ["baseline", "browser", "workflows", "zap"]


def test_approved_discovery_plan_adds_bounded_probes_to_disposable_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from security_reviewer_v2.discovery.test_plan import build_discovery_test_plan
    from security_reviewer_v2.scanners import browser_runtime

    project = tmp_path / "target"
    project.mkdir()
    (project / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/account')\ndef account(): return {}\n",
        encoding="utf-8",
    )
    (project / "compose.yaml").write_text(
        "services:\n  web:\n    build: .\n", encoding="utf-8"
    )
    contract = tmp_path / "runtime-contract.json"
    contract.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "mode": "docker_compose",
                "trust_level": "trusted_local_project",
                "authorized_for_testing": True,
                "target": {
                    "base_url": "http://127.0.0.1:8080",
                    "health_path": "/",
                    "expected_status": 200,
                },
                "compose": {"file": "compose.yaml", "app_service": "web"},
                "accounts": [],
                "checks": {"authorization": False, "mutating": False},
                "endpoints": ["/"],
                "required_env": [],
            }
        ),
        encoding="utf-8",
    )
    saved = tmp_path / "approved-plan.json"
    saved.write_text(
        json.dumps(
            build_discovery_test_plan(
                {
                    "application_map_guidance": {
                        "suggestions": [
                            {
                                "method": "GET",
                                "path": "/account",
                                "source": {"file": "app.py", "line": 3},
                            }
                        ]
                    }
                },
                project_root=project,
                project_fingerprint="snapshot-1",
            )
        ),
        encoding="utf-8",
    )
    args = _args(tmp_path, project)
    args.static_only = False
    args.runtime_contract = contract
    args.allow_trusted_local_compose = True
    args.approved_discovery_plan = saved
    monkeypatch.setattr(
        entrypoint,
        "create_saved_profile_artifact",
        lambda *_args: {"project_snapshot": {"fingerprint": "snapshot-1"}},
    )
    monkeypatch.setattr(entrypoint.shutil, "which", lambda _: "docker")

    @contextmanager
    def fake_provision(*_args, **_kwargs):
        yield EnvironmentSession(
            "http://127.0.0.1:8080", "docker_compose", "sr-test-approved"
        )

    def fake_checks(config):
        assert config.endpoint_paths == ("/", "/account")
        return {
            "results": [
                {
                    "rule_id": "web.endpoint-server-error",
                    "path": "/account",
                    "evidence": {"status": 200},
                }
            ]
        }

    def fake_browser(*_args, **kwargs):
        assert "/account" in kwargs["seed_paths"]
        assert kwargs["disposable"] is True

    monkeypatch.setattr(entrypoint, "provision_environment", fake_provision)
    monkeypatch.setattr(entrypoint, "run_generic_checks", fake_checks)
    monkeypatch.setattr(browser_runtime, "run_browser_dast", fake_browser)
    monkeypatch.setattr(entrypoint, "_zap", lambda *_args: None)
    monkeypatch.setattr(
        entrypoint.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, "", ""),
    )
    output = tmp_path / "run"
    _prepare_runtime(args, project=project, output=output)
    evidence = json.loads(
        (output / "approved-discovery-probes.json").read_text(encoding="utf-8")
    )
    assert evidence["status"] == "completed"
    assert evidence["probes"] == [
        {
            "proposal_id": json.loads(saved.read_text(encoding="utf-8"))["proposals"][
                0
            ]["id"],
            "path": "/account",
            "source": {"file": "app.py", "line": 3},
            "candidate_ids": [],
            "method": "GET",
            "execution_status": "executed",
            "http_status": 200,
            "security_assertion": "not_defined",
        }
    ]

"""Docker evidence and lifecycle tests without requiring a local Docker daemon."""

from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import run_docker_automatic_pipeline as runner
from security_reviewer_v2.reporting import render_final_report
from security_reviewer_v2.test_environment.docker_runtime import (
    load_docker_runtime,
    sha256_file,
)
from security_reviewer_v2.test_environment.manager import (
    EnvironmentPlan,
    EnvironmentSpec,
    _validate_compose_config,
)
from security_reviewer_v2.test_environment.manager import (
    TestEnvironmentSession as EnvironmentSession,
)

_SOURCES = (
    "app.py",
    "requirements.txt",
    "Dockerfile",
    "compose.yaml",
    ".dockerignore",
    "secret_do_not_serve.txt",
    "files/report.txt",
)


def _fixture(tmp_path: Path, *, run_id: str = "1234abcd") -> tuple[Path, Path, Path]:
    repository = tmp_path / "repo"
    project = repository / "targets" / "security-lab-web"
    project.mkdir(parents=True)
    for name in _SOURCES:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"trusted test fixture: {name}\n", encoding="utf-8")
    results = repository / "reports" / "docker-autoscan" / run_id
    results.mkdir(parents=True)
    counts = {}
    hashes = {}
    for name, source in (
        ("runtime.json", "web-runtime"),
        ("authorization.json", "tt-authorization-runtime"),
    ):
        payload = {
            "schema_version": "1.0",
            "source": source,
            "target": "http://127.0.0.1:5055",
            "status": "completed",
            "results": [{"rule_id": "test", "vulnerable": True}],
        }
        path = results / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        counts[name] = 1
        hashes[name] = sha256_file(path)
    manifest = {
        "schema_version": "1.0",
        "run_id": run_id,
        "target_id": "security-lab-web",
        "backend": "docker_compose",
        "status": "passed",
        "stack_removed": True,
        "network_exposure": "host_loopback_only",
        "http_status": 200,
        "mutating_checks_enabled": True,
        "source_sha256": {name: sha256_file(project / name) for name in _SOURCES},
        "output_sha256": hashes,
        "probe_counts": counts,
    }
    (results / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return repository, project, results


def test_docker_runtime_requires_matching_evidence_and_reports_limits(
    tmp_path: Path,
) -> None:
    repository, project, results = _fixture(tmp_path)
    verified = load_docker_runtime(
        "1234abcd", project_root=project, repository_root=repository
    )
    assert verified["stack_removed"] is True
    assert verified["probe_counts"] == {"runtime.json": 1, "authorization.json": 1}
    report = render_final_report(
        project=str(project),
        review={"status": "not_run"},
        policy={"status": "not_run"},
        docker_runtime=verified,
    )
    assert "Trusted Docker DAST" in report
    assert "not a security boundary for untrusted application code" in report

    manifest_path = results / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["stack_removed"] = False
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="stack cleanup"):
        load_docker_runtime(
            "1234abcd", project_root=project, repository_root=repository
        )


def test_docker_runtime_rejects_changed_source_or_probe_output(tmp_path: Path) -> None:
    repository, project, results = _fixture(tmp_path)
    (project / "requirements.txt").write_text("changed dependency\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source changed"):
        load_docker_runtime(
            "1234abcd", project_root=project, repository_root=repository
        )
    (project / "requirements.txt").write_text(
        "trusted test fixture: requirements.txt\n", encoding="utf-8"
    )
    (results / "authorization.json").write_text('{"results": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="did not match"):
        load_docker_runtime(
            "1234abcd", project_root=project, repository_root=repository
        )
    with pytest.raises(ValueError, match="run ID"):
        load_docker_runtime(
            "../outside", project_root=project, repository_root=repository
        )


def test_docker_runtime_describes_only_hash_matched_unoverridden_debug_setting(
    tmp_path: Path,
) -> None:
    repository, project, results = _fixture(tmp_path)
    (project / "Dockerfile").write_text(
        'FROM python:3.12\nCMD ["python", "-c", "from app import app; app.run(debug=False)"]\n',
        encoding="utf-8",
    )
    (project / "compose.yaml").write_text(
        "services:\n  web:\n    build: .\n", encoding="utf-8"
    )

    def refresh_hashes() -> None:
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name in ("Dockerfile", "compose.yaml"):
            manifest["source_sha256"][name] = sha256_file(project / name)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    refresh_hashes()
    verified = load_docker_runtime(
        "1234abcd", project_root=project, repository_root=repository
    )
    assert verified["deployment_context"]["flask_debug"] is False
    (project / "compose.yaml").write_text(
        "services:\n  web:\n    command: python app.py\n", encoding="utf-8"
    )
    refresh_hashes()
    assert (
        load_docker_runtime(
            "1234abcd", project_root=project, repository_root=repository
        )["deployment_context"]
        is None
    )
    (project / "Dockerfile").write_text(
        'FROM python:3.12\nCMD ["python", "-c", "from app import app; app.run(debug=True)"]\n',
        encoding="utf-8",
    )
    (project / "compose.yaml").write_text(
        "services:\n  web:\n    build: .\n", encoding="utf-8"
    )
    refresh_hashes()
    assert (
        load_docker_runtime(
            "1234abcd", project_root=project, repository_root=repository
        )["deployment_context"]["flask_debug"]
        is True
    )


def test_cleanup_check_requires_empty_docker_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, "container-id\n", "")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="cleanup is unverified"):
        runner._assert_stack_removed("docker", "sr-test-abc123")


def test_compose_guard_allows_only_no_new_privileges_security_option(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    spec = EnvironmentSpec(
        "docker_compose",
        "trusted_lab",
        "http://127.0.0.1:5055",
        "/",
        200,
        "compose.yaml",
        "web",
        (),
        (),
        False,
        True,
        True,
    )
    safe = {
        "services": {
            "web": {
                "build": {"context": str(project), "dockerfile": "Dockerfile"},
                "ports": [
                    {"host_ip": "127.0.0.1", "published": "5055", "target": 5000}
                ],
                "security_opt": ["no-new-privileges:true"],
            }
        }
    }
    _validate_compose_config(safe, spec, project)
    safe["services"]["web"]["security_opt"] = ["apparmor:unconfined"]
    with pytest.raises(ValueError, match="security options"):
        _validate_compose_config(safe, spec, project)


def test_docker_stack_is_removed_before_static_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _project, existing_results = _fixture(tmp_path)
    (repository / "scripts").mkdir()
    (repository / "examples").mkdir()
    (repository / "examples" / "security-lab-web-docker-environment.json").write_text(
        "{}", encoding="utf-8"
    )
    codeql = repository.parent / "tools" / "codeql"
    codeql.mkdir(parents=True)
    (codeql / "codeql.exe").write_text("", encoding="utf-8")
    monkeypatch.setattr(
        runner,
        "__file__",
        str(repository / "scripts" / "run_docker_automatic_pipeline.py"),
    )
    monkeypatch.setattr(runner, "provider_from_environment", lambda *_args: object())
    monkeypatch.setattr(runner, "profile_project", lambda *_args: object())
    monkeypatch.setattr(
        runner,
        "load_environment_spec",
        lambda *_args, **_kwargs: EnvironmentSpec(
            "docker_compose",
            "trusted_lab",
            "http://127.0.0.1:5055",
            "/",
            200,
            "compose.yaml",
            "web",
            (),
            (),
            False,
            True,
            True,
        ),
    )
    monkeypatch.setattr(
        runner,
        "plan_environment",
        lambda *_args, **_kwargs: EnvironmentPlan(
            "1.0",
            "docker_compose",
            "ready_for_validation",
            "http://127.0.0.1:5055",
            (),
            (),
            (),
        ),
    )
    monkeypatch.setattr(runner.shutil, "which", lambda *_args: "docker")
    monkeypatch.setattr(runner.secrets, "token_hex", lambda _bytes: "abcd1234")
    events: list[str] = []

    @contextmanager
    def fake_environment(*_args, **_kwargs):
        events.append("up")
        try:
            yield EnvironmentSession(
                "http://127.0.0.1:5055", "docker_compose", "sr-test-abc123"
            )
        finally:
            events.append("down")

    def fake_web(config):
        payload = {
            "schema_version": "1.0",
            "source": "web-runtime",
            "target": config.base_url,
            "status": "completed",
            "results": [{"rule_id": "web.test"}],
        }
        config.output.write_text(json.dumps(payload), encoding="utf-8")
        events.append("web")
        return payload

    def fake_run(argv, **_kwargs):
        if "--scanner-preflight-only" in argv:
            events.append("preflight")
        elif "scan_tt_authorization.py" in str(argv[1]):
            events.append("authorization")
            output = Path(argv[argv.index("--output") + 1])
            output.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "source": "tt-authorization-runtime",
                        "target": "http://127.0.0.1:5055",
                        "status": "completed",
                        "results": [{"rule_id": "auth.test"}],
                    }
                ),
                encoding="utf-8",
            )
        elif argv[1:3] == ["ps", "--all"]:
            events.append("cleanup-verified")
        elif "--docker-runtime-run-id" in argv:
            events.append("pipeline")
            assert events.index("down") < events.index("pipeline")
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(runner, "provision_environment", fake_environment)
    monkeypatch.setattr(runner, "run_checks", fake_web)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    output = repository / "reports" / "final-docker-scan"
    assert runner.main(["--output", str(output), "--codeql-bundle", str(codeql)]) == 0
    assert events == [
        "preflight",
        "up",
        "web",
        "authorization",
        "down",
        "cleanup-verified",
        "pipeline",
    ]
    assert (
        repository / "reports" / "docker-autoscan" / "abcd1234" / "manifest.json"
    ).is_file()
    assert existing_results.is_dir()

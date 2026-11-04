"""Behavioral tests for explicit, non-executing environment planning."""

from __future__ import annotations

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.test_environment import (
    load_environment_spec,
    plan_environment,
    provision_environment,
)
from security_reviewer_v2.test_environment.manager import _validate_compose_config


def _config(
    tmp_path: Path, project: Path, *, mode: str = "existing_url", **overrides
) -> Path:
    payload = {
        "schema_version": "1.0",
        "mode": mode,
        "authorized_for_testing": True,
        "target": {
            "base_url": "http://127.0.0.1:5055",
            "health_path": "/",
            "expected_status": 200,
        },
        "accounts": [],
        "checks": {"authorization": False, "mutating": False},
    }
    if mode == "docker_compose":
        payload["trust_level"] = "trusted_lab"
        payload["compose"] = {"file": "compose.test.yml", "app_service": "web"}
    payload.update(overrides)
    path = tmp_path / "user-supplied-test-environment.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not path.is_relative_to(project)
    return path


def _project(tmp_path: Path, *, compose: bool = False) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "print('never run by profiling')\n", encoding="utf-8"
    )
    if compose:
        (project / "compose.test.yml").write_text(
            "services:\n  web:\n    build: .\n", encoding="utf-8"
        )
    return project


def test_existing_url_plan_is_read_only_and_needs_no_docker(tmp_path: Path) -> None:
    project = _project(tmp_path)
    spec = load_environment_spec(_config(tmp_path, project), project_root=project)
    plan = plan_environment(
        spec, project_root=project, profile=profile_project(project), environment={}
    )
    assert plan.status == "ready_for_validation"
    assert plan.missing == ()
    assert plan.mode == "existing_url"
    assert "never run" in (project / "app.py").read_text(encoding="utf-8")


def test_existing_url_health_check_uses_a_local_test_server(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200 if self.path == "/ready" else 404)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        project = _project(tmp_path)
        config = _config(
            tmp_path,
            project,
            target={
                "base_url": f"http://127.0.0.1:{server.server_port}",
                "health_path": "/ready",
                "expected_status": 200,
            },
        )
        spec = load_environment_spec(config, project_root=project)
        plan = plan_environment(
            spec, project_root=project, profile=profile_project(project), environment={}
        )
        with provision_environment(spec, plan, project_root=project) as session:
            assert session.base_url == spec.base_url
            assert session.mode == "existing_url"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_repo_cannot_authorize_itself_or_embed_passwords(tmp_path: Path) -> None:
    project = _project(tmp_path)
    inside = project / "test-environment.json"
    inside.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "mode": "existing_url",
                "authorized_for_testing": True,
                "target": {"base_url": "http://127.0.0.1:5055"},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="outside the untrusted project"):
        load_environment_spec(inside, project_root=project)
    outside = _config(
        tmp_path,
        project,
        accounts=[
            {"role": "alice", "username_env": "alice", "password_env": "password123"}
        ],
    )
    with pytest.raises(ValueError, match="environment variable"):
        load_environment_spec(outside, project_root=project)


def test_untrusted_compose_cannot_run_on_host(tmp_path: Path) -> None:
    project = _project(tmp_path, compose=True)
    config = _config(tmp_path, project, mode="docker_compose", trust_level="untrusted")
    with pytest.raises(ValueError, match="untrusted project execution is unsupported"):
        load_environment_spec(config, project_root=project)


def test_trusted_local_compose_still_requires_execution_opt_in(tmp_path: Path) -> None:
    project = _project(tmp_path, compose=True)
    config = _config(
        tmp_path, project, mode="docker_compose", trust_level="trusted_local_project"
    )
    spec = load_environment_spec(config, project_root=project)
    plan = plan_environment(
        spec,
        project_root=project,
        profile=profile_project(project),
        docker_executable="docker",
    )
    assert plan.status == "ready_for_validation"
    with (
        pytest.raises(RuntimeError, match="explicit opt-in"),
        provision_environment(
            spec, plan, project_root=project, docker_executable="docker"
        ),
    ):
        pass


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://localhost:5055",
        "http://192.168.1.10:5055",
        "http://127.0.0.1:5055@evil.example",
        "http://127.0.0.1:5055/other",
    ],
)
def test_only_literal_loopback_origin_is_allowed(tmp_path: Path, url: str) -> None:
    project = _project(tmp_path)
    config = _config(tmp_path, project, target={"base_url": url})
    with pytest.raises(ValueError, match="loopback"):
        load_environment_spec(config, project_root=project)


def test_authorization_accounts_are_checked_without_exposing_values(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    accounts = [
        {
            "role": "alice",
            "username_env": "SECURITY_TEST_ALICE_USER",
            "password_env": "SECURITY_TEST_ALICE_PASSWORD",
        },
        {
            "role": "bob",
            "username_env": "SECURITY_TEST_BOB_USER",
            "password_env": "SECURITY_TEST_BOB_PASSWORD",
        },
    ]
    spec = load_environment_spec(
        _config(
            tmp_path,
            project,
            accounts=accounts,
            checks={"authorization": True, "mutating": False},
        ),
        project_root=project,
    )
    plan = plan_environment(
        spec, project_root=project, profile=profile_project(project), environment={}
    )
    assert plan.status == "blocked"
    assert len(plan.missing) == 4
    assert "password123" not in json.dumps(plan.to_dict())
    ready = plan_environment(
        spec,
        project_root=project,
        profile=profile_project(project),
        environment={name: "test-only-value" for name in spec.account_env_names},
    )
    assert ready.status == "ready_for_validation"
    assert "test-only-value" not in json.dumps(ready.to_dict())
    assert any("not yet implemented" in warning for warning in ready.warnings)


def test_declared_database_secret_is_checked_but_never_written_to_plan(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    spec = load_environment_spec(
        _config(tmp_path, project, required_env=["SECURITY_TEST_DB_PASSWORD"]),
        project_root=project,
    )
    blocked = plan_environment(
        spec, project_root=project, profile=profile_project(project), environment={}
    )
    assert blocked.status == "blocked"
    assert "SECURITY_TEST_DB_PASSWORD" in blocked.missing[0]
    ready = plan_environment(
        spec,
        project_root=project,
        profile=profile_project(project),
        environment={"SECURITY_TEST_DB_PASSWORD": "fake-db-password"},
    )
    assert ready.status == "ready_for_validation"
    assert "fake-db-password" not in json.dumps(ready.to_dict())


def test_profiler_detects_compose_but_missing_docker_blocks_start(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path, compose=True)
    spec = load_environment_spec(
        _config(tmp_path, project, mode="docker_compose"), project_root=project
    )
    profile = profile_project(project)
    assert "compose.test.yml" in {item.path for item in profile.profile.inventory}
    plan = plan_environment(
        spec,
        project_root=project,
        profile=profile,
        environment={},
        docker_executable="docker",
    )
    assert plan.status == "ready_for_validation"
    assert plan.compose_sha256
    assert any("non-standard" in warning for warning in plan.warnings)
    missing_compose = _config(
        tmp_path,
        project,
        mode="docker_compose",
        compose={"file": "other.yml", "app_service": "web"},
    )
    other = load_environment_spec(missing_compose, project_root=project)
    blocked = plan_environment(
        other,
        project_root=project,
        profile=profile,
        environment={},
        docker_executable="docker",
    )
    assert blocked.status == "blocked"
    assert any("Compose file" in problem for problem in blocked.missing)


def _safe_compose(project: Path) -> dict:
    return {
        "services": {
            "web": {
                "build": {"context": str(project), "dockerfile": "Dockerfile"},
                "ports": [
                    {"host_ip": "127.0.0.1", "published": "5055", "target": 5000}
                ],
            },
            "db": {
                "image": "postgres:17",
                "volumes": [
                    {
                        "type": "volume",
                        "source": "db",
                        "target": "/var/lib/postgresql/data",
                    }
                ],
            },
        },
        "volumes": {"db": {}},
        "networks": {"default": {}},
    }


def test_compose_guard_rejects_host_access_and_wrong_port(tmp_path: Path) -> None:
    project = _project(tmp_path, compose=True)
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    spec = load_environment_spec(
        _config(tmp_path, project, mode="docker_compose"), project_root=project
    )
    safe = _safe_compose(project)
    _validate_compose_config(safe, spec, project)
    unsafe = json.loads(json.dumps(safe))
    unsafe["services"]["web"]["privileged"] = True
    with pytest.raises(ValueError, match="host or security"):
        _validate_compose_config(unsafe, spec, project)
    unsafe = json.loads(json.dumps(safe))
    unsafe["services"]["web"]["volumes"] = [
        {"type": "bind", "source": "C:/Users", "target": "/host"}
    ]
    with pytest.raises(ValueError, match="Bind mounts"):
        _validate_compose_config(unsafe, spec, project)
    unsafe = json.loads(json.dumps(safe))
    unsafe["services"]["web"]["ports"][0]["host_ip"] = "0.0.0.0"
    with pytest.raises(ValueError, match="127.0.0.1"):
        _validate_compose_config(unsafe, spec, project)
    unsafe = json.loads(json.dumps(safe))
    unsafe["services"]["web"]["ports"][0]["published"] = "9999"
    with pytest.raises(ValueError, match="declared loopback port"):
        _validate_compose_config(unsafe, spec, project)


def test_compose_is_opt_in_and_always_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path, compose=True)
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    spec = load_environment_spec(
        _config(tmp_path, project, mode="docker_compose"), project_root=project
    )
    plan = plan_environment(
        spec,
        project_root=project,
        profile=profile_project(project),
        environment={},
        docker_executable="docker",
    )
    calls: list[list[str]] = []
    monkeypatch.setenv("GROQ_API_KEY", "fake-test-secret")
    monkeypatch.setenv("SECURITY_TEST_UNUSED", "must-not-be-forwarded")
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\tester")

    def fake_runner(argv, **kwargs):
        calls.append(argv)
        assert "GROQ_API_KEY" not in kwargs["env"]
        assert "SECURITY_TEST_UNUSED" not in kwargs["env"]
        assert kwargs["env"]["USERPROFILE"] == "C:\\Users\\tester"
        output = json.dumps(_safe_compose(project)) if "config" in argv else ""
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(
        "security_reviewer_v2.test_environment.manager._check_health", lambda _: None
    )
    with (
        pytest.raises(RuntimeError, match="explicit opt-in"),
        provision_environment(
            spec,
            plan,
            project_root=project,
            docker_executable="docker",
            runner=fake_runner,
        ),
    ):
        pass
    assert not calls
    with (
        pytest.raises(RuntimeError, match="simulated scan failure"),
        provision_environment(
            spec,
            plan,
            project_root=project,
            allow_compose_execution=True,
            docker_executable="docker",
            runner=fake_runner,
        ) as session,
    ):
        assert session.base_url == "http://127.0.0.1:5055"
        raise RuntimeError("simulated scan failure")
    assert any("up" in argv for argv in calls)
    assert any("down" in argv for argv in calls)
    projects = [argv[argv.index("-p") + 1] for argv in calls if "-p" in argv]
    assert len(set(projects)) == 1


def test_changed_compose_file_is_not_started(tmp_path: Path) -> None:
    project = _project(tmp_path, compose=True)
    spec = load_environment_spec(
        _config(tmp_path, project, mode="docker_compose"), project_root=project
    )
    plan = plan_environment(
        spec,
        project_root=project,
        profile=profile_project(project),
        environment={},
        docker_executable="docker",
    )
    (project / "compose.test.yml").write_text("services: {}\n", encoding="utf-8")
    with (
        pytest.raises(RuntimeError, match="changed since"),
        provision_environment(
            spec,
            plan,
            project_root=project,
            allow_compose_execution=True,
            docker_executable="docker",
        ),
    ):
        pass

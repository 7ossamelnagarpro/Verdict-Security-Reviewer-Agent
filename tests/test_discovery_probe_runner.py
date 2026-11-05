from __future__ import annotations

import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_reviewer_v2.discovery import probe_runner
from security_reviewer_v2.discovery.test_plan import build_discovery_test_plan
from security_reviewer_v2.test_environment.manager import EnvironmentSpec


@pytest.mark.parametrize("leftover_container", [False, True])
def test_current_get_probes_require_verified_disposable_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leftover_container: bool
) -> None:
    project = tmp_path / "target"
    project.mkdir()
    (project / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/account')\ndef account(): return {}\n",
        encoding="utf-8",
    )
    plan = build_discovery_test_plan(
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
    monkeypatch.setattr(
        probe_runner,
        "load_environment_spec",
        lambda *_args, **_kwargs: EnvironmentSpec(
            mode="docker_compose",
            trust_level="trusted_local_project",
            base_url="http://127.0.0.1:8091",
            health_path="/healthz",
            expected_status=200,
            compose_file="compose.yaml",
            app_service="api",
            required_env_names=(),
            account_env_names=("TEST_USER",),
            authorization_checks=True,
            mutating_checks=True,
            authorized_for_testing=True,
            workflow_suite={"accounts": [{"id": "user_a"}]},
        ),
    )
    monkeypatch.setattr(probe_runner, "profile_project", lambda _root: object())
    monkeypatch.setattr(
        probe_runner,
        "create_saved_profile_artifact",
        lambda *_args: {"project_snapshot": {"fingerprint": "snapshot-1"}},
    )

    def fake_plan(spec, **_kwargs):
        assert spec.workflow_suite is None
        assert spec.authorization_checks is False
        assert spec.mutating_checks is False
        return SimpleNamespace(status="ready_for_validation")

    monkeypatch.setattr(probe_runner, "plan_environment", fake_plan)
    monkeypatch.setattr(probe_runner.shutil, "which", lambda _name: "docker")

    @contextmanager
    def fake_provision(*_args, **_kwargs):
        yield SimpleNamespace(
            base_url="http://127.0.0.1:8091", project_name="sr-test-discovery"
        )

    monkeypatch.setattr(probe_runner, "provision_environment", fake_provision)
    monkeypatch.setattr(
        probe_runner,
        "run_generic_checks",
        lambda config: {
            "results": [
                {
                    "rule_id": "web.endpoint-server-error",
                    "path": "/account",
                    "evidence": {"status": 200},
                }
            ]
        },
    )
    monkeypatch.setattr(
        probe_runner.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(
            argv, 0, "container-id\n" if leftover_container else "", ""
        ),
    )

    result = probe_runner.run_current_discovery_probes(
        plan,
        project_root=project,
        project_fingerprint="snapshot-1",
        environment_config=tmp_path / "contract.json",
        output_path=tmp_path / "runtime.json",
    )
    if leftover_container:
        assert result["status"] == "blocked"
        assert result["cleanup_verified"] is False
        assert result["probes"][0]["execution_status"] == "not_executed"
    else:
        assert result["status"] == "completed"
        assert result["cleanup_verified"] is True
        assert result["probes"][0]["http_status"] == 200

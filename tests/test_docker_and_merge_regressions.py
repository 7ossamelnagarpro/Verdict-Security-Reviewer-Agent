"""Regression tests: Compose failures must explain themselves; root-cause merging must not touch SCA/secrets/config."""

from __future__ import annotations

import json
import subprocess
from dataclasses import fields, replace
from pathlib import Path

import pytest

from security_reviewer_v2.normalization.merge import _mergeable_for_root_cause
from security_reviewer_v2.normalization.models import (
    KIND_DAST, KIND_MISCONFIGURATION, KIND_SAST, KIND_SCA, KIND_SECRETS, PackageInfo, UnifiedFinding,
)
from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.test_environment.manager import (
    _docker_environment, load_environment_spec, plan_environment, provision_environment,
)
from tests.test_finding_merge import finding
from tests.test_test_environment import _config, _project, _safe_compose


# ----------------------------------------------------------------------------- Docker Compose
def _stack(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    project = _project(tmp_path, compose=True)
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    spec = load_environment_spec(_config(tmp_path, project, mode="docker_compose"), project_root=project)
    plan = plan_environment(spec, project_root=project, profile=profile_project(project),
                            environment={}, docker_executable="docker")
    return project, spec, plan


def _run_failing_start(tmp_path: Path, *, stderr: str, stdout: str = "", logs: str = ""):
    project, spec, plan = _stack(tmp_path)
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if "config" in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps(_safe_compose(project)), "")
        if "up" in argv:
            return subprocess.CompletedProcess(argv, 1, stdout, stderr)
        if "logs" in argv:
            return subprocess.CompletedProcess(argv, 0, logs, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(RuntimeError) as caught:
        with provision_environment(spec, plan, project_root=project, allow_compose_execution=True,
                                   docker_executable="docker", runner=runner):
            pass
    return str(caught.value), calls


def test_start_failure_reports_the_real_docker_error_and_still_cleans_up(tmp_path):
    message, calls = _run_failing_start(
        tmp_path,
        stderr="error getting credentials - err: fork/exec docker-credential-desktop.exe: exec format error\n"
               "DB_PASSWORD=hunter2",
        logs="api  | listening on 8091\nAPP_SECRET: s3cr3t-value",
    )
    assert "failed to start the isolated test stack" in message and "exit code 1" in message
    assert "exec format error" in message                      # the original stderr, not a generic sentence
    assert "listening on 8091" in message                      # service logs explain unhealthy containers
    assert "hunter2" not in message and "s3cr3t-value" not in message   # secrets are redacted
    assert any("down" in argv for argv in calls)               # failure never skips cleanup


def test_start_failure_falls_back_to_stdout_and_is_bounded(tmp_path):
    message, _ = _run_failing_start(tmp_path / "a", stderr="", stdout="container sr-test-x-api-1 is unhealthy\n" + "x" * 50_000)
    assert "exit code 1" in message and len(message) < 3500
    message, _ = _run_failing_start(tmp_path / "b", stderr="", stdout="")
    assert "Docker produced no output" in message


def test_compose_environment_keeps_docker_client_variables_but_no_secrets(tmp_path, monkeypatch):
    _, spec, _ = _stack(tmp_path)
    monkeypatch.setenv("DOCKER_HOST", "unix:///run/user/1000/docker.sock")
    monkeypatch.setenv("WSL_INTEROP", "/run/WSL/1_interop")
    monkeypatch.setenv("GROQ_API_KEY", "fake-test-secret")
    monkeypatch.setenv("LANGSMITH_API_KEY", "fake-test-secret")
    env = _docker_environment(spec)
    assert env["DOCKER_HOST"].endswith("docker.sock") and env["WSL_INTEROP"] == "/run/WSL/1_interop"
    assert "GROQ_API_KEY" not in env and "LANGSMITH_API_KEY" not in env


# ----------------------------------------------------------------------------- root-cause merge guard
def test_unified_finding_declares_the_fields_the_merge_guard_reads():
    # merge.py reads these two attributes directly; a models.py that drops them breaks every merge.
    assert {"finding_kind", "package"} <= {item.name for item in fields(UnifiedFinding)}


@pytest.mark.parametrize("kind", [KIND_SCA, KIND_SECRETS, KIND_MISCONFIGURATION])
def test_sca_secret_and_config_findings_are_never_merged_by_line_overlap(kind):
    item = replace(finding("trivy", finding_id="t"), finding_kind=kind)   # note: no package attached
    assert _mergeable_for_root_cause((item,)) is False


def test_findings_with_a_package_or_from_gitleaks_are_not_root_cause_merged():
    with_package = replace(finding("trivy", finding_id="p"), package=PackageInfo("requests", "2.0.0"))
    assert _mergeable_for_root_cause((with_package,)) is False
    assert _mergeable_for_root_cause((finding("gitleaks", finding_id="g"),)) is False


@pytest.mark.parametrize("kind", [None, KIND_SAST, KIND_DAST])
def test_code_findings_remain_mergeable(kind):
    assert _mergeable_for_root_cause((replace(finding("semgrep-ce", finding_id="s"), finding_kind=kind),)) is True

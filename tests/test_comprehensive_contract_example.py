"""Keep the reviewable lab contract executable without exposing benchmark labels."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from security_reviewer_v2.scanners.runtime_workflows import (
    env_name,
    run_workflows,
    validate_suite,
)

CONTRACT = (
    Path(__file__).resolve().parents[1]
    / "benchmark"
    / "verdict-comprehensive-runtime-contract.full.example.json"
)


def test_full_example_is_bounded_and_requires_explicit_authorization() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["authorized_for_testing"] is False
    suite = validate_suite(contract["workflow_suite"], disposable=True)
    assert suite["reset"] == "fresh_stack"
    assert suite["max_requests"] <= 300
    assert suite["max_seconds"] <= 600
    assert suite["workflows"][-1]["id"] == "stale_role"
    ids = {workflow["id"] for workflow in suite["workflows"]}
    assert {
        "stored_comment",
        "login_lockout",
        "worker_identity",
        "stale_role",
        "guessed_session",
        "unsigned_refresh",
        "safe_forum",
        "safe_lockout",
        "safe_session_probe",
        "safe_unsigned_probe",
    } <= ids
    assert all("password" not in account for account in suite["accounts"])


@pytest.mark.skipif(
    os.environ.get("VERDICT_TEST_COMPREHENSIVE_DOCKER") != "1",
    reason="Explicit local disposable Docker integration test",
)
def test_full_example_against_disposable_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from security_reviewer_v2.profiler import profile_project
    from security_reviewer_v2.scanners.browser_runtime import run_browser_dast
    from security_reviewer_v2.scanners.generic_runtime import (
        GenericRuntimeConfig,
        run_generic_checks,
    )
    from security_reviewer_v2.test_environment import (
        load_environment_spec,
        plan_environment,
        provision_environment,
    )

    project = (
        Path(__file__).resolve().parents[1] / "targets" / "verdict-comprehensive-lab"
    )
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    contract["authorized_for_testing"] = True
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract), encoding="utf-8")
    spec = load_environment_spec(path, project_root=project)
    credentials = {}
    for account in contract["workflow_suite"]["accounts"]:
        actor = account["id"]
        username = actor.removesuffix("_checked")
        credentials[env_name(actor, "username")] = username
        credentials[env_name(actor, "password")] = {
            "user_a": "UserA-Lab-Only-1",
            "user_b": "UserB-Lab-Only-1",
            "admin": "Admin-Lab-Only-1",
        }[username]
    for key, value in credentials.items():
        monkeypatch.setenv(key, value)
    plan = plan_environment(
        spec,
        project_root=project,
        profile=profile_project(project),
        environment=credentials,
    )
    with provision_environment(
        spec, plan, project_root=project, allow_compose_execution=True
    ) as session:
        baseline = run_generic_checks(
            GenericRuntimeConfig(
                session.base_url, tmp_path / "runtime.json", "/healthz", 200, ("/view",)
            )
        )
        assert any(
            item["path"] == "/view"
            and item["rule_id"] == "web.missing-content-security-policy"
            and item["vulnerable"]
            for item in baseline["results"]
        )
        if (
            shutil.which("node")
            and (
                Path(__file__).resolve().parents[1] / "scripts/node_modules/playwright"
            ).is_dir()
        ):
            browser = run_browser_dast(
                session.base_url,
                tmp_path / "runtime.json",
                tmp_path / "browser.json",
                max_pages=2,
                seed_paths=("/account",),
                accounts=tuple(contract["workflow_suite"]["accounts"]),
                disposable=True,
            )
            assert all(a["status"] == "verified" for a in browser["accounts"])
            assert len(browser["accounts"]) == len(
                contract["workflow_suite"]["accounts"]
            )
            assert any(r["path"] == "/account" for r in browser["observed_requests"])
        evidence = run_workflows(
            session.base_url,
            contract["workflow_suite"],
            disposable=True,
            environment=credentials,
        )
    incomplete = [
        (
            workflow["id"],
            [(step["status"], step.get("http_status")) for step in workflow["steps"]],
        )
        for workflow in evidence["workflows"]
        if workflow["status"] == "partial"
    ]
    assert evidence["status"] == "completed", incomplete
    assert evidence["coverage"]["unresolved"] == 0
    statuses = {
        workflow["id"]: workflow["status"] for workflow in evidence["workflows"]
    }
    assert all(
        statuses[key] == "violation"
        for key in (
            "stored_comment",
            "login_lockout",
            "worker_identity",
            "stale_role",
            "guessed_session",
            "unsigned_refresh",
        )
    )
    assert all(
        statuses[key] == "passed"
        for key in (
            "safe_forum",
            "safe_lockout",
            "safe_session_probe",
            "safe_unsigned_probe",
        )
    )

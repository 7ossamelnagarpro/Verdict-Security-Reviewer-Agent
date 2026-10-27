from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_reviewer_v2.web.app import (
    JobStore, _create_runtime_contract, _discover_setup, build_command, create_app,
)
import time


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "codeql"
    bundle.mkdir()
    (bundle / "codeql.exe").write_text("stub", encoding="utf-8")
    return bundle


def test_local_web_health_and_rejects_unknown_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VERDICT_DATA_ROOT", str(tmp_path / "data"))
    client = create_app(tmp_path).test_client()
    assert client.get("/api/health").get_json()["status"] == "ok"
    page = client.get("/").get_data(as_text=True)
    assert 'id="project-fields"' in page
    assert 'id="runtime-fields"' in page
    assert 'name="base_url"' in page
    assert 'id="runtime-fields" class="hidden"' not in page
    import re
    token = re.search(r'name="verdict-token" content="([^"]+)"', page).group(1)
    response = client.post("/api/jobs", json={"mode": "shell"}, headers={"X-Verdict-Token": token})
    assert response.status_code == 400
    assert "Unknown review mode" in response.get_json()["error"]


def test_project_static_command_is_explicitly_dast_free(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    command, contract = build_command(
        repository=tmp_path, mode="project-static", project=str(project),
        runtime_contract=None, codeql_bundle=str(_bundle(tmp_path)),
        ai_provider="ollama", ai_model=None, output=tmp_path / "reports" / "run",
    )
    assert contract is None
    assert "--static-only" in command
    assert "--runtime-contract" not in command


def test_browser_dast_flag_is_forwarded_only_for_runtime_scans(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    contract = tmp_path / "runtime.json"
    contract.write_text(json.dumps({"schema_version": "1.0"}), encoding="utf-8")
    command, _ = build_command(
        repository=tmp_path, mode="project-full", project=str(project),
        runtime_contract=str(contract), codeql_bundle=str(_bundle(tmp_path)),
        ai_provider="ollama", ai_model=None, output=tmp_path / "reports" / "run",
        browser_dast=True,
    )
    assert "--browser-dast" in command


def test_project_full_requires_external_runtime_contract(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    contract = project / "runtime.json"
    contract.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="outside the scanned project"):
        build_command(
            repository=tmp_path, mode="project-full", project=str(project),
            runtime_contract=str(contract), codeql_bundle=str(_bundle(tmp_path)),
            ai_provider="ollama", ai_model=None, output=tmp_path / "reports" / "run",
        )


def test_ui_runtime_fields_create_contract_outside_target(tmp_path: Path) -> None:
    contract = _create_runtime_contract(tmp_path, "abc123", {
        "authorized_for_testing": True,
        "base_url": "http://127.0.0.1:8080",
        "health_path": "/health",
        "expected_status": "200",
        "endpoints": "/, /health\n/api/items",
    })
    assert contract.is_file()
    assert not contract.is_relative_to(tmp_path / "project")
    payload = json.loads(contract.read_text(encoding="utf-8"))
    assert payload["target"]["base_url"] == "http://127.0.0.1:8080"
    assert payload["endpoints"] == ["/", "/health", "/api/items"]


def test_trusted_compose_requires_confirmation_and_uses_explicit_flag(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    (project / "compose.yaml").write_text(
        'services:\n  web:\n    ports:\n      - "127.0.0.1:8080:5000"\n', encoding="utf-8")
    suggested = _discover_setup(project)
    assert suggested and suggested["app_service"] == "web"
    assert suggested["base_url"] == "http://127.0.0.1:8080"
    payload = {**suggested, "authorized_for_testing": True, "endpoints": "/"}
    with pytest.raises(ValueError, match="trust"):
        _create_runtime_contract(tmp_path, "run1", payload)
    payload["trusted_project"] = True
    contract = _create_runtime_contract(tmp_path, "run2", payload)
    data = json.loads(contract.read_text(encoding="utf-8"))
    assert data["mode"] == "docker_compose"
    assert data["trust_level"] == "trusted_local_project"
    command, _ = build_command(
        repository=tmp_path, mode="project-full", project=str(project),
        runtime_contract=str(contract), codeql_bundle=str(_bundle(tmp_path)),
        ai_provider="ollama", ai_model=None, output=tmp_path / "reports" / "run2",
        allow_trusted_local_compose=True,
    )
    assert "--allow-trusted-local-compose" in command


def test_discovery_selects_only_one_exposed_service(tmp_path: Path) -> None:
    project = tmp_path / "customer-app"
    project.mkdir()
    compose = project / "compose.yaml"
    compose.write_text('services:\n  web:\n    ports:\n      - "127.0.0.1:8080:5000"\n  db:\n    image: postgres:17\n', encoding="utf-8")
    suggestion = _discover_setup(project)
    assert suggestion and suggestion["app_service"] == "web"
    compose.write_text(compose.read_text(encoding="utf-8") + '    ports:\n      - "127.0.0.1:5432:5432"\n', encoding="utf-8")
    assert _discover_setup(project) is None


def test_successful_local_setup_can_be_reused_but_change_needs_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURITY_REVIEWER_REPORT_ROOT", str(tmp_path / "reports"))
    project = tmp_path / "customer-app"
    project.mkdir()
    compose = project / "compose.yaml"
    compose.write_text('services:\n  web:\n    ports:\n      - "127.0.0.1:8080:5000"\n', encoding="utf-8")
    bundle = _bundle(tmp_path)
    store = JobStore(tmp_path, runner=lambda _command, **_kwargs: (0, '{"status":"completed"}'))
    client = create_app(tmp_path, store=store).test_client()
    payload = {"mode": "project-full", "project": str(project), "codeql_bundle": str(bundle),
               "ai_provider": "ollama", "runtime_method": "trusted_compose",
               "compose_file": "compose.yaml", "app_service": "web", "base_url": "http://127.0.0.1:8080",
               "health_path": "/", "expected_status": "200", "endpoints": "/",
               "authorized_for_testing": True, "trusted_project": True}
    response = client.post("/api/jobs", json=payload)
    assert response.status_code == 202
    for _ in range(100):
        if store.get(response.get_json()["id"]).status == "completed":
            break
        time.sleep(0.01)
    info = client.post("/api/projects/inspect", json={"project": str(project)}).get_json()
    assert info["saved"]["runtime_method"] == "trusted_compose"
    repeat = {**payload, "saved_setup": "yes", "trusted_project": False,
              "authorized_for_testing": False}
    assert client.post("/api/jobs", json=repeat).status_code == 202
    for _ in range(100):
        if not store._active:
            break
        time.sleep(0.01)
    compose.write_text(compose.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    info = client.post("/api/projects/inspect", json={"project": str(project)}).get_json()
    assert info["saved"] is None
    assert client.post("/api/jobs", json=repeat).status_code == 400

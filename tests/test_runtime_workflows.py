from __future__ import annotations
import copy
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_reviewer_v2.scanners.runtime_workflows import (Transport, env_name, run_workflows, validate_suite, append_workflows)
from security_reviewer_v2.web.workflow_examples import order_service_example
from security_reviewer_v2.web.runtime_discovery import discover
from security_reviewer_v2.web.app import create_app, _create_runtime_contract
from security_reviewer_v2.web.service import LocalService
from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file


def minimal():
    suite = order_service_example()
    suite["workflows"] = [suite["workflows"][1]]
    suite["accounts"] = suite["accounts"][:2]
    return suite


class FakeTransport:
    def __init__(self, cross=200, identity_ok=True):
        self.calls, self.cross, self.identity_ok = [], cross, identity_ok

    def request(self, actor, method, path, body=None, headers=None, encoding="json"):
        self.calls.append((actor, method, path, body, headers))
        if path == "/auth/login":
            return 200, {"access_token": "private-token-" + actor}
        if path == "/me":
            return 200, {"username": actor if self.identity_ok else "wrong-user"}
        if path == "/orders":
            return 200, {"id": 98}
        if path == "/orders/98":
            return (200 if actor == "user_b" else self.cross), {"id": 98, "secret": "sensitive-record"}
        raise AssertionError("Unexpected request")


def environment(suite):
    return {env_name(a["id"], f): a["id"] if f == "username" else "private-password" for a in suite["accounts"] for f in ("username", "password")}


def test_cross_user_steps_use_separate_verified_tokens_and_capture():
    suite = minimal()
    http = FakeTransport()
    result = run_workflows("http://127.0.0.1:8090", suite, disposable=True, environment=environment(suite), transport=http)
    assert result["status"] == "completed"
    assert result["coverage"] == {"declared": 3, "executed": 3, "violations": 1, "unresolved": 0}
    assert http.calls[-1][2] == "/orders/98"
    assert http.calls[-1][4]["Authorization"] == "Bearer private-token-user_a"
    assert http.calls[-2][4]["Authorization"] == "Bearer private-token-user_b"
    assert "private-token" not in json.dumps(result)
    assert "private-password" not in json.dumps(result)
    assert "sensitive-record" not in json.dumps(result)


@pytest.mark.parametrize("status,outcome", [(403, "passed"), (404, "passed"), (500, "partial"), (401, "partial"), (302, "partial")])
def test_denial_passes_but_errors_or_wrong_session_do_not_prove_a_vulnerability(status, outcome):
    suite = minimal()
    result = run_workflows("http://127.0.0.1:8090", suite, disposable=True, environment=environment(suite), transport=FakeTransport(status))
    assert result["workflows"][0]["status"] == outcome
    assert not result["results"]


def test_wrong_identity_blocks_all_dependent_steps():
    suite = minimal()
    result = run_workflows("http://127.0.0.1:8090", suite, disposable=True, environment=environment(suite), transport=FakeTransport(identity_ok=False))
    assert result["status"] == "partial"
    assert result["coverage"]["executed"] == 0
    assert not result["results"]


@pytest.mark.parametrize("path", ["//evil.test", "/ path", "/x\r\nInjected", "https://evil.test", "/\\evil.test"])
def test_invalid_paths_rejected_before_requests(path):
    suite = minimal()
    suite["workflows"][0]["steps"][0]["path"] = path
    with pytest.raises(ValueError):
        validate_suite(suite, disposable=True)


def test_no_mutation_on_existing_app_and_no_future_capture():
    suite = minimal()
    with pytest.raises(ValueError, match="disposable"):
        validate_suite(suite)
    suite["workflows"][0]["steps"][0]["path"] = "/orders/{{future_id}}"
    with pytest.raises(ValueError, match="Capture"):
        validate_suite(suite, disposable=True)


def test_plaintext_credentials_and_reset_commands_rejected():
    suite = minimal()
    suite["accounts"][0]["password"] = "secret"
    with pytest.raises(ValueError, match="vault"):
        validate_suite(suite, disposable=True)
    suite = minimal()
    suite["reset"] = "rm -rf target"
    with pytest.raises(ValueError, match="Reset"):
        validate_suite(suite, disposable=True)


def test_transport_does_not_follow_redirects_and_enforces_budget():
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/must-not-follow")
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = Transport(f"http://127.0.0.1:{server.server_port}", {"max_requests": 1})
        assert http.request("anonymous", "GET", "/")[0] == 302
        assert requests == ["/"]
        with pytest.raises(RuntimeError, match="budget"):
            http.request("anonymous", "GET", "/")
    finally:
        server.shutdown()
        server.server_close()


def test_workflow_observation_reaches_normalization_with_evidence(tmp_path, monkeypatch):
    suite = minimal()
    evidence = run_workflows("http://127.0.0.1:8090", suite, disposable=True, environment=environment(suite), transport=FakeTransport())
    monkeypatch.setattr("security_reviewer_v2.scanners.runtime_workflows.run_workflows", lambda *a, **k: evidence)
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps({"target":"http://127.0.0.1:8090", "status":"completed", "results":[], "coverage_notes":[]}))
    append_workflows(path, suite, disposable=True)
    finding = normalize_runtime_json_file(path).findings[0]
    assert finding.runtime_evidence["workflow_id"] == "order_owner"
    assert finding.runtime_evidence["expected_statuses"] == [403, 404]
    assert (tmp_path / "workflow-evidence.json").is_file()


def test_discovery_reads_declarations_without_executing_source_or_benchmark(tmp_path):
    (tmp_path / "app.py").write_text("raise RuntimeError('never execute')\n@app.get('/healthz')\ndef health(): pass\n@app.post('/orders')\ndef order(): pass\n")
    (tmp_path / "benchmark").mkdir()
    (tmp_path / "benchmark/answers.py").write_text("@app.get('/answer-key')\ndef answers(): pass")
    result = discover(tmp_path)
    assert result["health_path"] == "/healthz"
    assert {e["path"] for e in result["endpoints"]} == {"/healthz", "/orders"}


def test_contract_ui_persistence_validation_and_vault(tmp_path, monkeypatch):
    service = LocalService(tmp_path, root=tmp_path / "state")
    client = create_app(tmp_path, store=service).test_client()
    page = client.get("/").get_data(as_text=True)
    assert "Guided Runtime Contract" in page
    headers = {"X-Verdict-Token": re.search(r'name="verdict-token" content="([^"]+)"', page)[1]}
    payload = {"mode":"project-full", "project":str(tmp_path), "runtime_method":"trusted_compose", "workflow_suite":minimal(), "workflow_enabled":True}
    saved = client.post("/api/projects", json=payload, headers=headers).get_json()
    assert saved["workflow_suite"] == minimal()
    assert client.post("/api/runtime/validate", json=payload, headers=headers).get_json()["valid"]
    secrets = {}
    monkeypatch.setattr("security_reviewer_v2.web.routes.set_secret", lambda k,v: secrets.update({k:v}))
    response = client.post("/api/credentials", json={"kind":"workflow", "project_id":saved["id"], "actor":"user_a", "username":"user_a", "password":"private-test-password"}, headers=headers)
    assert response.status_code == 200
    assert list(secrets.values()) == ["user_a", "private-test-password"]
    assert "private-test-password" not in json.dumps(service.db.get("projects", saved["id"]))
    assert client.post("/api/credentials", json={"kind":"workflow", "project_id":saved["id"], "actor":"unknown"}, headers=headers).status_code == 400


@pytest.mark.skipif(os.environ.get("VERDICT_TEST_WORKFLOW_DOCKER") != "1", reason="Explicit local disposable Docker integration test")
@pytest.mark.parametrize("route", ["direct", "pipeline"])
def test_real_multiservice_workflows_and_cleanup(tmp_path, monkeypatch, route):
    from security_reviewer_v2.test_environment import load_environment_spec, plan_environment, provision_environment
    from security_reviewer_v2.profiler import profile_project
    import subprocess
    project = Path(__file__).resolve().parents[1] / "targets/verdict-multi-service-lab"
    suite = order_service_example()
    for name, password in (("user_a", "UserA-Lab-Only-1"), ("user_b", "UserB-Lab-Only-1"), ("admin", "Admin-Lab-Only-1")):
        monkeypatch.setenv(env_name(name, "username"), name)
        monkeypatch.setenv(env_name(name, "password"), password)
    contract = {"schema_version":"1.0", "mode":"docker_compose", "trust_level":"trusted_local_project", "authorized_for_testing":True,
                "target":{"base_url":"http://127.0.0.1:8090", "health_path":"/healthz", "expected_status":200},
                "compose":{"file":"compose.yaml", "app_service":"api"}, "workflow_suite":suite}
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    spec = load_environment_spec(path, project_root=project)
    plan = plan_environment(spec, project_root=project, profile=profile_project(project))
    monkeypatch.setenv("VERDICT_LEASE_ROOT", str(tmp_path / "leases"))
    if route == "pipeline":
        from scripts import run_project_pipeline as pipeline
        from types import SimpleNamespace
        from contextlib import contextmanager
        sessions = []
        @contextmanager
        def tracked(*args, **kwargs):
            with provision_environment(*args, **kwargs) as session:
                sessions.append(session)
                yield session
        monkeypatch.setattr(pipeline, "provision_environment", tracked)
        args = SimpleNamespace(runtime_contract=path, allow_trusted_local_compose=True, dast_engine="baseline")
        runtime = pipeline._prepare_runtime(args, project=project, output=tmp_path / "runtime-output")
        payload = json.loads(runtime.read_text())
        evidence = payload["workflow_evidence"]
        assert payload["status"] == "completed"
        assert payload["authorization_checks_enabled"] is True
        assert payload["mutating_checks_enabled"] is True
        assert any(r["rule_id"].startswith("workflow.") for r in payload["results"])
        assert normalize_runtime_json_file(runtime).findings
        session = sessions[0]
    else:
        with provision_environment(spec, plan, project_root=project, allow_compose_execution=True) as session:
            evidence = run_workflows(session.base_url, suite, disposable=True)
            (tmp_path / "workflow-evidence.json").write_text(json.dumps(evidence, indent=2))
    assert evidence["status"] == "completed", evidence
    assert evidence["coverage"]["unresolved"] == 0
    assert evidence["coverage"]["executed"] == evidence["coverage"]["declared"]
    assert all(a["status"] == "verified" for a in evidence["accounts"])
    remaining = subprocess.run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={session.project_name}", "--format", "{{.ID}}"], capture_output=True, text=True, check=True)
    assert remaining.stdout.strip() == ""

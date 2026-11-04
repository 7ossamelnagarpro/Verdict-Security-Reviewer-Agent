from __future__ import annotations

import copy
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file
from security_reviewer_v2.scanners.runtime_workflows import (
    Transport,
    append_workflows,
    env_name,
    run_workflows,
    validate_suite,
)
from security_reviewer_v2.web.app import create_app
from security_reviewer_v2.web.runtime_discovery import discover
from security_reviewer_v2.web.service import LocalService
from security_reviewer_v2.web.workflow_examples import order_service_example


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
            return (200 if actor == "user_b" else self.cross), {
                "id": 98,
                "secret": "sensitive-record",
            }
        raise AssertionError("Unexpected request")


def environment(suite):
    return {
        env_name(a["id"], f): a["id"] if f == "username" else "private-password"
        for a in suite["accounts"]
        for f in ("username", "password")
    }


def test_cross_user_steps_use_separate_verified_tokens_and_capture():
    suite = minimal()
    http = FakeTransport()
    result = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=True,
        environment=environment(suite),
        transport=http,
    )
    assert result["status"] == "completed"
    assert result["coverage"] == {
        "declared": 3,
        "executed": 3,
        "violations": 1,
        "unresolved": 0,
    }
    assert http.calls[-1][2] == "/orders/98"
    assert http.calls[-1][4]["Authorization"] == "Bearer private-token-user_a"
    assert http.calls[-2][4]["Authorization"] == "Bearer private-token-user_b"
    assert "private-token" not in json.dumps(result)
    assert "private-password" not in json.dumps(result)
    assert "sensitive-record" not in json.dumps(result)


@pytest.mark.parametrize(
    "status,outcome",
    [
        (403, "passed"),
        (404, "passed"),
        (500, "partial"),
        (401, "partial"),
        (302, "partial"),
    ],
)
def test_denial_passes_but_errors_or_wrong_session_do_not_prove_a_vulnerability(
    status, outcome
):
    suite = minimal()
    result = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=True,
        environment=environment(suite),
        transport=FakeTransport(status),
    )
    assert result["workflows"][0]["status"] == outcome
    assert not result["results"]


def test_wrong_identity_blocks_all_dependent_steps():
    suite = minimal()
    result = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=True,
        environment=environment(suite),
        transport=FakeTransport(identity_ok=False),
    )
    assert result["status"] == "partial"
    assert result["coverage"]["executed"] == 0
    assert not result["results"]


@pytest.mark.parametrize(
    "path",
    ["//evil.test", "/ path", "/x\r\nInjected", "https://evil.test", "/\\evil.test"],
)
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


def test_bounded_response_assertions_distinguish_unsafe_and_safe_controls():
    suite = {
        "version": 1,
        "accounts": [],
        "workflows": [
            {
                "id": "error_detail",
                "title": "Database details must not be exposed",
                "steps": [
                    {
                        "actor": "anonymous",
                        "method": "GET",
                        "path": "/errors/query",
                        "expect_status": [500],
                        "security_check": True,
                        "response_assertions": [
                            {"op": "body_not_contains", "value": "database_column"},
                            {"op": "header_present", "name": "Content-Type"},
                        ],
                    }
                ],
            }
        ],
    }

    class ResponseTransport:
        def __init__(self, body):
            self.body = body

        def request(
            self, actor, method, path, body=None, headers=None, encoding="json"
        ):
            return (
                500,
                None,
                {"headers": {"content-type": "text/plain"}, "body": self.body},
            )

    unsafe = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=False,
        transport=ResponseTransport("database_column leaked"),
    )
    safe = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=False,
        transport=ResponseTransport("Internal error"),
    )
    assert unsafe["coverage"]["violations"] == 1
    assert safe["coverage"]["violations"] == 0
    assert "database_column leaked" not in json.dumps(unsafe)
    assert unsafe["results"][0]["evidence"]["values_redacted"]
    assert unsafe["results"][0]["evidence"]["assertion_checks"] == [
        {"kind": "status", "operator": "in", "passed": True},
        {
            "kind": "response",
            "operator": "body_not_contains",
            "field": "body",
            "passed": False,
            "expected_value_redacted": True,
        },
        {
            "kind": "response",
            "operator": "header_present",
            "field": "Content-Type",
            "passed": True,
            "expected_value_redacted": False,
        },
    ]


def test_missing_response_metadata_is_inconclusive_not_a_vulnerability():
    suite = {
        "version": 1,
        "accounts": [],
        "workflows": [
            {
                "id": "header_check",
                "title": "Security header must be present",
                "steps": [
                    {
                        "method": "GET",
                        "path": "/page",
                        "expect_status": [200],
                        "security_check": True,
                        "response_assertions": [
                            {"op": "header_present", "name": "Content-Security-Policy"}
                        ],
                    }
                ],
            }
        ],
    }

    class NoMetadataTransport:
        def request(
            self, actor, method, path, body=None, headers=None, encoding="json"
        ):
            return 200, None

    result = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=False,
        transport=NoMetadataTransport(),
    )
    assert result["status"] == "partial"
    assert result["coverage"]["violations"] == 0
    assert result["workflows"][0]["steps"][0]["status"] == "inconclusive"
    assert result["workflows"][0]["steps"][0]["assertion_checks"][1]["passed"] is None


def test_bounded_wait_allows_async_worker_to_settle(monkeypatch: pytest.MonkeyPatch):
    waits = []
    monkeypatch.setattr(
        "security_reviewer_v2.scanners.runtime_workflows.time.sleep", waits.append
    )
    suite = {
        "version": 1,
        "accounts": [],
        "workflows": [
            {
                "id": "async_result",
                "title": "Worker result is ready",
                "steps": [
                    {
                        "method": "GET",
                        "path": "/jobs",
                        "expect_status": [200],
                        "wait_before_seconds": 2,
                    }
                ],
            }
        ],
    }

    class Fake:
        def request(
            self, actor, method, path, body=None, headers=None, encoding="json"
        ):
            return 200, []

    assert (
        run_workflows(
            "http://127.0.0.1:8090", suite, disposable=False, transport=Fake()
        )["status"]
        == "completed"
    )
    assert waits == [2]
    suite["workflows"][0]["steps"][0]["wait_before_seconds"] = 11
    with pytest.raises(ValueError, match="between 0 and 10"):
        validate_suite(suite, disposable=False)


def test_explicit_lockout_threshold_distinguishes_401_from_a_real_lockout():
    attempt = {
        "actor": "anonymous",
        "method": "POST",
        "path": "/auth/login",
        "body": {"username": "test_user", "password": "invalid-probe"},
        "expect_status": [401],
    }
    suite = {
        "version": 1,
        "allow_mutation": True,
        "accounts": [],
        "workflows": [
            {
                "id": "lockout",
                "title": "Lock after three failures",
                "steps": [copy.deepcopy(attempt) for _ in range(3)]
                + [
                    {
                        **attempt,
                        "expect_status": [423, 429],
                        "lockout_after_failures": 3,
                        "security_check": True,
                    }
                ],
            }
        ],
    }

    class LoginTransport:
        def __init__(self, last_status):
            self.calls = 0
            self.last_status = last_status

        def request(
            self, actor, method, path, body=None, headers=None, encoding="json"
        ):
            self.calls += 1
            return self.last_status if self.calls == 4 else 401, {}

    missing = run_workflows(
        "http://127.0.0.1:8090", suite, disposable=True, transport=LoginTransport(401)
    )
    protected = run_workflows(
        "http://127.0.0.1:8090", suite, disposable=True, transport=LoginTransport(429)
    )
    assert missing["coverage"]["violations"] == 1
    assert missing["results"][0]["evidence"]["prior_failed_attempts"] == 3
    assert protected["coverage"]["violations"] == 0
    suite["workflows"][0]["steps"][3]["body"]["username"] = "another_user"
    with pytest.raises(ValueError, match="matching prior failed"):
        validate_suite(suite, disposable=True)


def test_synthetic_cookie_and_unsigned_jwt_probes_are_disposable_and_not_persisted():
    suite = {
        "version": 1,
        "allow_mutation": True,
        "accounts": [],
        "workflows": [
            {
                "id": "guessed_cookie",
                "title": "Reject generated cookie",
                "steps": [
                    {
                        "method": "GET",
                        "path": "/session/whoami",
                        "expect_status": [401],
                        "security_check": True,
                        "auth_probe": {
                            "kind": "numbered_cookie",
                            "name": "lab_session",
                            "prefix": "session-",
                            "number": 3,
                        },
                    }
                ],
            },
            {
                "id": "unsigned_token",
                "title": "Reject unsigned token",
                "steps": [
                    {
                        "method": "POST",
                        "path": "/auth/refresh",
                        "expect_status": [401],
                        "security_check": True,
                        "auth_probe": {
                            "kind": "unsigned_jwt",
                            "claims": {"sub": 1, "role": "admin"},
                        },
                    }
                ],
            },
        ],
    }

    class ProbeTransport:
        def __init__(self):
            self.headers = []

        def request(
            self, actor, method, path, body=None, headers=None, encoding="json"
        ):
            self.headers.append(headers)
            return 200, {}

    transport = ProbeTransport()
    result = run_workflows(
        "http://127.0.0.1:8090", suite, disposable=True, transport=transport
    )
    assert result["coverage"]["violations"] == 2
    assert transport.headers[0]["Cookie"] == "lab_session=session-3"
    token = transport.headers[1]["Authorization"]
    assert token.startswith("Bearer ") and token.endswith(".")
    assert token not in json.dumps(result)
    assert "session-3" not in json.dumps(result)
    assert {item["evidence"]["auth_probe_kind"] for item in result["results"]} == {
        "numbered_cookie",
        "unsigned_jwt",
    }
    with pytest.raises(ValueError, match="disposable"):
        validate_suite(suite, disposable=False)
    suite["workflows"][0]["steps"][0]["auth_probe"]["prefix"] = "a\r\nX-Injected: 1"
    with pytest.raises(ValueError, match="short safe"):
        validate_suite(suite, disposable=True)


def test_response_assertions_reject_regex_and_unbounded_values():
    suite = minimal()
    step = suite["workflows"][0]["steps"][0]
    step["response_assertions"] = [{"op": "body_regex", "value": ".*"}]
    with pytest.raises(ValueError, match="Unsupported response assertion"):
        validate_suite(suite, disposable=True)
    step["response_assertions"] = [{"op": "body_contains", "value": "x" * 129}]
    with pytest.raises(ValueError, match="short literal"):
        validate_suite(suite, disposable=True)


def test_multipart_upload_workflow_finds_unsafe_serving_and_safe_rejection():
    received = []

    class UploadHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers["Content-Length"])
            received.append(
                (self.path, self.headers["Content-Type"], self.rfile.read(size))
            )
            self.send_response(200 if self.path == "/uploads" else 400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":7}' if self.path == "/uploads" else b"{}")

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<p>uploaded</p>")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), UploadHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        part = {
            "field": "file",
            "filename": "probe.html",
            "content_type": "text/html",
            "content": "inert-test-marker",
        }
        suite = {
            "version": 1,
            "accounts": [],
            "allow_mutation": True,
            "workflows": [
                {
                    "id": "unsafe_upload",
                    "title": "Uploads must not be served as HTML",
                    "steps": [
                        {
                            "method": "POST",
                            "path": "/uploads",
                            "multipart": part,
                            "expect_status": [200],
                            "capture": {"upload_id": "id"},
                        },
                        {
                            "method": "GET",
                            "path": "/uploads/{{upload_id}}",
                            "expect_status": [200],
                            "security_check": True,
                            "response_assertions": [
                                {
                                    "op": "header_not_contains",
                                    "name": "Content-Type",
                                    "value": "text/html",
                                }
                            ],
                        },
                    ],
                },
                {
                    "id": "safe_upload",
                    "title": "HTML upload should be rejected",
                    "steps": [
                        {
                            "method": "POST",
                            "path": "/documents",
                            "multipart": part,
                            "expect_status": [400],
                            "security_check": True,
                        }
                    ],
                },
            ],
        }
        with pytest.raises(ValueError, match="disposable"):
            validate_suite(suite, disposable=False)
        result = run_workflows(
            f"http://127.0.0.1:{server.server_port}", suite, disposable=True
        )
        assert result["status"] == "completed"
        assert result["coverage"]["violations"] == 1
        assert result["workflows"][0]["status"] == "violation"
        assert result["workflows"][1]["status"] == "passed"
        assert all(
            "multipart/form-data" in item[1] and b"inert-test-marker" in item[2]
            for item in received
        )
        assert "inert-test-marker" not in json.dumps(result)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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


def test_workflow_observation_reaches_normalization_with_evidence(
    tmp_path, monkeypatch
):
    suite = minimal()
    evidence = run_workflows(
        "http://127.0.0.1:8090",
        suite,
        disposable=True,
        environment=environment(suite),
        transport=FakeTransport(),
    )
    monkeypatch.setattr(
        "security_reviewer_v2.scanners.runtime_workflows.run_workflows",
        lambda *a, **k: evidence,
    )
    path = tmp_path / "runtime.json"
    path.write_text(
        json.dumps(
            {
                "target": "http://127.0.0.1:8090",
                "status": "completed",
                "results": [],
                "coverage_notes": [],
            }
        )
    )
    append_workflows(path, suite, disposable=True)
    finding = normalize_runtime_json_file(path).findings[0]
    assert finding.runtime_evidence["workflow_id"] == "order_owner"
    assert finding.runtime_evidence["expected_statuses"] == [403, 404]
    assert (tmp_path / "workflow-evidence.json").is_file()


def test_discovery_reads_declarations_without_executing_source_or_benchmark(tmp_path):
    (tmp_path / "app.py").write_text(
        "raise RuntimeError('never execute')\n@app.get('/healthz')\ndef health(): pass\n@app.post('/orders')\ndef order(): pass\n"
    )
    (tmp_path / "benchmark").mkdir()
    (tmp_path / "benchmark/answers.py").write_text(
        "@app.get('/answer-key')\ndef answers(): pass"
    )
    result = discover(tmp_path)
    assert result["health_path"] == "/healthz"
    assert {e["path"] for e in result["endpoints"]} == {"/healthz", "/orders"}


def test_contract_ui_persistence_validation_and_vault(tmp_path, monkeypatch):
    service = LocalService(tmp_path, root=tmp_path / "state")
    client = create_app(tmp_path, store=service).test_client()
    page = client.get("/").get_data(as_text=True)
    assert "Guided Runtime Contract" in page
    headers = {
        "X-Verdict-Token": re.search(r'name="verdict-token" content="([^"]+)"', page)[1]
    }
    payload = {
        "mode": "project-full",
        "project": str(tmp_path),
        "runtime_method": "trusted_compose",
        "workflow_suite": minimal(),
        "workflow_enabled": True,
    }
    saved = client.post("/api/projects", json=payload, headers=headers).get_json()
    assert saved["workflow_suite"] == minimal()
    assert client.post(
        "/api/runtime/validate", json=payload, headers=headers
    ).get_json()["valid"]
    secrets = {}
    monkeypatch.setattr(
        "security_reviewer_v2.web.routes.set_secret",
        lambda k, v: secrets.update({k: v}),
    )
    response = client.post(
        "/api/credentials",
        json={
            "kind": "workflow",
            "project_id": saved["id"],
            "actor": "user_a",
            "username": "user_a",
            "password": "private-test-password",
        },
        headers=headers,
    )
    assert response.status_code == 200
    assert list(secrets.values()) == ["user_a", "private-test-password"]
    assert "private-test-password" not in json.dumps(
        service.db.get("projects", saved["id"])
    )
    assert (
        client.post(
            "/api/credentials",
            json={"kind": "workflow", "project_id": saved["id"], "actor": "unknown"},
            headers=headers,
        ).status_code
        == 400
    )


@pytest.mark.skipif(
    os.environ.get("VERDICT_TEST_WORKFLOW_DOCKER") != "1",
    reason="Explicit local disposable Docker integration test",
)
@pytest.mark.parametrize("route", ["direct", "pipeline"])
def test_real_multiservice_workflows_and_cleanup(tmp_path, monkeypatch, route):
    import subprocess

    from security_reviewer_v2.profiler import profile_project
    from security_reviewer_v2.test_environment import (
        load_environment_spec,
        plan_environment,
        provision_environment,
    )

    project = Path(__file__).resolve().parents[1] / "targets/verdict-multi-service-lab"
    suite = order_service_example()
    for name, password in (
        ("user_a", "UserA-Lab-Only-1"),
        ("user_b", "UserB-Lab-Only-1"),
        ("admin", "Admin-Lab-Only-1"),
    ):
        monkeypatch.setenv(env_name(name, "username"), name)
        monkeypatch.setenv(env_name(name, "password"), password)
    contract = {
        "schema_version": "1.0",
        "mode": "docker_compose",
        "trust_level": "trusted_local_project",
        "authorized_for_testing": True,
        "target": {
            "base_url": "http://127.0.0.1:8090",
            "health_path": "/healthz",
            "expected_status": 200,
        },
        "compose": {"file": "compose.yaml", "app_service": "api"},
        "workflow_suite": suite,
    }
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    spec = load_environment_spec(path, project_root=project)
    plan = plan_environment(
        spec, project_root=project, profile=profile_project(project)
    )
    monkeypatch.setenv("VERDICT_LEASE_ROOT", str(tmp_path / "leases"))
    if route == "pipeline":
        from contextlib import contextmanager
        from types import SimpleNamespace

        from scripts import run_project_pipeline as pipeline

        sessions = []

        @contextmanager
        def tracked(*args, **kwargs):
            with provision_environment(*args, **kwargs) as session:
                sessions.append(session)
                yield session

        monkeypatch.setattr(pipeline, "provision_environment", tracked)
        args = SimpleNamespace(
            runtime_contract=path,
            allow_trusted_local_compose=True,
            dast_engine="baseline",
        )
        runtime = pipeline._prepare_runtime(
            args, project=project, output=tmp_path / "runtime-output"
        )
        payload = json.loads(runtime.read_text())
        evidence = payload["workflow_evidence"]
        assert payload["status"] == "completed"
        assert payload["authorization_checks_enabled"] is True
        assert payload["mutating_checks_enabled"] is True
        assert any(r["rule_id"].startswith("workflow.") for r in payload["results"])
        assert normalize_runtime_json_file(runtime).findings
        session = sessions[0]
    else:
        with provision_environment(
            spec, plan, project_root=project, allow_compose_execution=True
        ) as session:
            evidence = run_workflows(session.base_url, suite, disposable=True)
            (tmp_path / "workflow-evidence.json").write_text(
                json.dumps(evidence, indent=2)
            )
    assert evidence["status"] == "completed", evidence
    assert evidence["coverage"]["unresolved"] == 0
    assert evidence["coverage"]["executed"] == evidence["coverage"]["declared"]
    assert all(a["status"] == "verified" for a in evidence["accounts"])
    remaining = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={session.project_name}",
            "--format",
            "{{.ID}}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert remaining.stdout.strip() == ""

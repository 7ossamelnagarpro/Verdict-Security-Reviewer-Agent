from __future__ import annotations
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from security_reviewer_v2.web.storage import Database
from security_reviewer_v2.web.service import LocalService
from security_reviewer_v2.web.app import create_app
from security_reviewer_v2.web.worker import run
from security_reviewer_v2.web.reports import project_report, compare
from security_reviewer_v2.scanners.zap_runtime import automation_plan, parse_alerts
from security_reviewer_v2.test_environment.recipes import detect, prepare
from security_reviewer_v2.test_environment.leases import register, cleanup


def test_database_survives_restart_and_serializes_jobs(tmp_path):
    db = Database(tmp_path)
    db.save("jobs", {"id": "one", "status": "running"}, exclusive_job=True)
    assert Database(tmp_path).get("jobs", "one")["status"] == "running"
    with pytest.raises(ValueError, match="already running"):
        db.save("jobs", {"id": "two", "status": "queued"}, exclusive_job=True)
    db.save("jobs", {"id": "one", "status": "completed"})
    db.save("jobs", {"id": "two", "status": "queued"}, exclusive_job=True)


def test_project_records_never_store_credentials_or_trust(tmp_path):
    service = LocalService(tmp_path, root=tmp_path / "data")
    saved = service.save_project({"project": str(tmp_path), "mode": "project-full", "name": "Example",
                                  "GROQ_API_KEY": "secret", "test_password": "secret", "trusted_project": True})
    assert "secret" not in json.dumps(saved)
    assert "trusted_project" not in saved
    assert LocalService(tmp_path, root=tmp_path / "data").db.get("projects", saved["id"]) == saved


def test_dashboard_rejects_csrf_and_host_rebinding(tmp_path):
    client = create_app(tmp_path, store=LocalService(tmp_path, root=tmp_path / "data")).test_client()
    assert client.post("/api/projects", json={}).status_code == 403
    assert client.get("/api/jobs", headers={"Host": "evil.test"}).status_code == 403
    assert client.get("/api/jobs", headers={"Origin": "https://evil.test"}).status_code == 403
    page = client.get("/").get_data(as_text=True)
    token = re.search(r'name="verdict-token" content="([^"]+)"', page).group(1)
    result = client.post("/api/projects", json={"mode": "docker-educational", "name": "Lab"}, headers={"X-Verdict-Token": token})
    assert result.status_code == 200
    assert client.get("/api/projects").get_json()[0]["name"] == "Lab"


def test_worker_persists_completed_state_and_redacts_log(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-private-value")
    db = Database(tmp_path)
    db.save("jobs", {"id": "test1", "status": "queued", "mode": "test", "repository": str(tmp_path),
                    "report_dir": str(tmp_path / "report"),
                    "command": [sys.executable, "-c", "import os; print(os.environ['GROQ_API_KEY'])"]})
    assert run(tmp_path, "test1") == 0
    state = Database(tmp_path).get("jobs", "test1")
    assert state["status"] == "completed"
    assert "fake-private-value" not in state["tail"]
    assert "fake-private-value" not in (tmp_path / "jobs/test1/process.log").read_text()


def test_worker_cancels_without_success_claim(tmp_path):
    db = Database(tmp_path)
    db.save("jobs", {"id": "cancel1", "status": "queued", "mode": "test", "repository": str(tmp_path),
                    "report_dir": str(tmp_path / "report"),
                    "command": [sys.executable, "-c", "import time; time.sleep(30)"]})
    state = tmp_path / "jobs/cancel1"
    state.mkdir(parents=True)
    (state / "cancel").touch()
    assert run(tmp_path, "cancel1") == 1
    assert db.get("jobs", "cancel1")["status"] == "cancelled"


def test_template_detection_and_no_source_modification(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    (root / "requirements.txt").write_text("Flask==3.1.3\n")
    (root / ".env").write_text("PASSWORD=do-not-copy")
    suggested = detect(root)
    assert suggested["runtime_recipe"] == "flask"
    with prepare(root, "flask", "app:app") as (staged, contract):
        assert not (staged / ".env").exists()
        assert (staged / "Dockerfile.verdict").is_file()
        assert json.loads(contract.read_text())["trust_level"] == "trusted_local_project"
        assert not (root / "Dockerfile.verdict").exists()
    assert not staged.exists()


def test_template_rejects_shell_injection(tmp_path):
    with pytest.raises(ValueError, match="Entrypoint"):
        with prepare(tmp_path, "flask", "app:app; echo dangerous"):
            pass


def test_zap_plan_is_scoped_bounded_and_login_fail_closed():
    plan = automation_plan("http://127.0.0.1:5000", active=True, auth={"login_path": "/login",
        "username_field": "email", "password_field": "password", "logged_in_regex": "Logout"})
    assert plan["env"]["parameters"]["maxDuration"] == 600
    context = plan["env"]["contexts"][0]
    assert context["authentication"]["parameters"]["loginRequestBody"] == "email={%username%}&password={%password%}"
    assert re.fullmatch(context["includePaths"][0], "http://127.0.0.1:5000")
    assert re.fullmatch(context["includePaths"][0], "http://127.0.0.1:5000/account")
    assert not re.fullmatch(context["includePaths"][0], "http://127.0.0.1:50001/account")
    assert plan["jobs"][0]["tests"][1]["statistic"] == "stats.auth.state.loggedin"
    assert plan["jobs"][0]["tests"][0]["onFail"] == "error"
    assert plan["jobs"][0]["parameters"]["postForm"] is False
    separate = automation_plan("http://127.0.0.1:5000", auth={"login_page_path": "/login",
        "login_path": "/auth/form-login", "start_path": "/view", "logged_in_regex": "Signed in"})
    params = separate["env"]["contexts"][0]["authentication"]["parameters"]
    assert params["loginPageUrl"] == "http://127.0.0.1:5000/login"
    assert params["loginRequestUrl"] == "http://127.0.0.1:5000/auth/form-login"
    assert separate["jobs"][0]["parameters"]["url"] == "http://127.0.0.1:5000/view"
    with pytest.raises(ValueError, match="inside"):
        automation_plan("http://127.0.0.1:5000", auth={"login_path": "//evil.test/login"})
    with pytest.raises(ValueError, match="inside"):
        automation_plan("http://127.0.0.1:5000", auth={"login_path": "/login",
            "login_page_path": "//evil.test/login"})


def test_zap_alerts_drop_secrets_queries_and_out_of_scope_urls():
    payload = {"site": [{"@name": "http://127.0.0.1:5000", "alerts": [{"pluginid": "123", "name": "Example",
        "riskcode": "2", "confidence": "2", "instances": [
            {"uri": "http://127.0.0.1:5000/path?token=secret", "evidence": "secret", "method": "GET"},
            {"uri": "https://evil.test/path"}]}]}]}
    results = parse_alerts(payload, "http://127.0.0.1:5000")
    assert len(results) == 1 and results[0]["path"] == "/path"
    assert "secret" not in json.dumps(results)


def test_zap_parameters_have_distinct_normalized_ids(tmp_path):
    from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file
    path = tmp_path / "runtime.json"
    records = [{"source": "owasp-zap", "rule_id": "zap.123", "path": "/items", "vulnerable": True,
                "evidence": {"method": "GET", "parameter": p, "cwe_id": "79"}} for p in ("name", "query")]
    path.write_text(json.dumps({"results": records}))
    findings = normalize_runtime_json_file(path).findings
    assert len({f.finding_id for f in findings}) == 2
    assert findings[0].cwes == ("CWE-79",)


def test_cleanup_only_uses_owned_resource_name(tmp_path, monkeypatch):
    monkeypatch.setenv("VERDICT_LEASE_ROOT", str(tmp_path))
    monkeypatch.setattr("security_reviewer_v2.test_environment.leases.shutil.which", lambda _: "docker")
    register("sr-zap-abc123")
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")
    assert cleanup(tmp_path, runner=runner) == []
    assert calls[0] == ["docker", "rm", "--force", "sr-zap-abc123"]
    assert not json.loads(next(tmp_path.glob("*.lease.json")).read_text())["active"]
    with pytest.raises(ValueError):
        register("unrelated-user-container")


def test_report_keeps_pending_and_gaps_and_does_not_call_missing_fixed(tmp_path):
    (tmp_path / "security-review.json").write_text(json.dumps({"status": "partial", "pending_ids": ["x"],
        "reviews": [{"candidate_id": "a", "title": "A", "verdict": "needs_more_evidence", "source_ids": []}]}))
    (tmp_path / "pre-review-summary.json").write_text(json.dumps({"coverage_gaps": ["No authenticated coverage"]}))
    report = project_report(tmp_path)
    assert report["pending_ids"] == ["x"] and len(report["gaps"]) == 1
    comparison = compare({"items": []}, report)
    assert comparison["no_longer_observed"] == ["a"] and "fixed" not in comparison


def test_resume_requires_saved_static_evidence(tmp_path):
    service = LocalService(tmp_path, root=tmp_path / "data")
    service.db.save("jobs", {"id": "old", "status": "failed", "report_dir": str(tmp_path / "missing")})
    with pytest.raises(ValueError, match="static evidence"):
        service.resume("old")


def test_detached_worker_survives_recreated_service(tmp_path, monkeypatch):
    import time
    repository = Path(__file__).resolve().parents[1]
    monkeypatch.setattr("security_reviewer_v2.web.service.worker_environment", lambda _, **kwargs: __import__('os').environ.copy())
    service = LocalService(repository, root=tmp_path)
    service._launch({"id": "detached", "mode": "test", "status": "queued", "repository": str(repository),
                     "report_dir": str(tmp_path / "report"),
                     "command": [sys.executable, "-c", "import time; time.sleep(.3); print('worker finished')"]})
    del service
    replacement = LocalService(repository, root=tmp_path)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        job = replacement.get("detached")
        if job.status not in {"queued", "running"}:
            break
        time.sleep(.1)
    assert job.status == "completed"
    assert "worker finished" in job.tail
    with pytest.raises(ValueError, match="already finished"):
        replacement.recover("detached")


def test_resume_only_calls_saved_ai_stages_and_preserves_original(tmp_path, monkeypatch):
    import importlib.util
    from security_reviewer_v2.profiler import profile_project
    from security_reviewer_v2.profiler.artifact import create_saved_profile_artifact
    spec = importlib.util.spec_from_file_location("resume_local_review_test", Path(__file__).resolve().parents[1] / "scripts/resume_local_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    project = tmp_path / "source"
    project.mkdir()
    (project / "app.py").write_text("print('test')\n")
    saved, output = tmp_path / "saved", tmp_path / "derived"
    saved.mkdir()
    artifacts = {"profile.json": create_saved_profile_artifact(profile_project(project), project), "merged.json": {}, "context.json": {},
                 "security-review.json": {"status": "partial"},
                 "ai-discovery.json": {"status": "completed", "usage": {"planned_targets": 1, "targets": 1, "provider_calls": 1},
                                       "batches": [{"status": "completed"}]}}
    for name, data in artifacts.items():
        (saved / name).write_text(json.dumps(data))
    before = {p.name: p.read_bytes() for p in saved.iterdir()}
    calls = []
    monkeypatch.setattr(sys, "argv", ["resume", str(project), str(saved), str(output)])
    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(module.subprocess, "run", runner)
    assert module.main() == 0
    assert len(calls) == 1 and Path(calls[0][1]).name == "run_saved_review_stages.py"
    assert "--prior-review" in calls[0]
    assert before == {p.name: p.read_bytes() for p in saved.iterdir()}
    assert json.loads((output / "resume-provenance.json").read_text())["scanners_rerun"] is False

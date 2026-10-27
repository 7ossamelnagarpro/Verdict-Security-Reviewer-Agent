"""Local-only dashboard APIs, guarded against cross-site requests and rebinding."""
from __future__ import annotations
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
import zipfile
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from flask import jsonify, request, send_file

from .credentials import get_secret, set_secret
from .reports import project_report, compare


def install_routes(app, jobs, repository):
    token = secrets.token_urlsafe(32)
    persistent = hasattr(jobs, "db")
    app.config["MAX_CONTENT_LENGTH"] = 65536

    @app.before_request
    def local_guard():
        host = urlsplit("http://" + request.host).hostname
        if host not in {"localhost", "127.0.0.1", "::1"}:
            return jsonify(error="Only localhost requests are accepted"), 403
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            return jsonify(error="Cross-site access is not allowed"), 403
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return jsonify(error="Origin does not match the local server"), 403
        if persistent and request.method in {"POST", "PUT", "DELETE", "PATCH"}:
            if not secrets.compare_digest(request.headers.get("X-Verdict-Token", ""), token):
                return jsonify(error="Refresh the page before submitting"), 403

    @app.after_request
    def secure_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.get("/api/projects")
    def projects():
        return jsonify(jobs.db.all("projects") if persistent else [])

    @app.post("/api/projects")
    def save_project():
        if not persistent:
            raise ValueError("Project persistence is unavailable in this session")
        return jsonify(jobs.save_project(request.get_json() or {}))

    @app.post("/api/credentials")
    def credentials():
        payload = request.get_json() or {}
        if payload.get("kind") == "groq":
            set_secret("groq", str(payload.get("value", "")))
        elif payload.get("kind") == "login":
            identifier = str(payload.get("project_id", ""))
            if not persistent or not jobs.db.get("projects", identifier):
                raise ValueError("Save the project before saving its test credentials")
            set_secret(identifier + ":zap:username", str(payload.get("username", "")))
            set_secret(identifier + ":zap:password", str(payload.get("password", "")))
        elif payload.get("kind") == "workflow":
            identifier = str(payload.get("project_id", ""))
            project = jobs.db.get("projects", identifier) if persistent else None
            actor = str(payload.get("actor", ""))
            if not project or actor not in {a["id"] for a in (project.get("workflow_suite") or {}).get("accounts", [])}:
                raise ValueError("Save the project and add this account before saving credentials")
            for field in ("username", "password"):
                if not isinstance(payload.get(field), str) or not payload[field] or len(payload[field]) > 8192:
                    raise ValueError("Enter a test username and password")
            for field in ("username", "password"):
                set_secret(f"{identifier}:workflow:{actor}:{field}", payload[field])
        else:
            raise ValueError("Unknown credential type")
        return jsonify(saved=True, storage="OS credential vault")

    @app.get("/api/setup")
    def setup():
        from .app import _codeql_bundle
        from security_reviewer_v2.scanners.zap_runtime import IMAGE
        def probe(argv):
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=8, check=False,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                return result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                return False
        tools = {}
        for name in ("semgrep", "gitleaks", "trivy", "docker"):
            local = Path(sys.executable).parent / (name + (".exe" if os.name == "nt" else ""))
            tools[name] = str(local) if local.is_file() else shutil.which(name)
        docker = tools.get("docker")
        defaults = jobs.db.get("settings", "defaults") or {} if persistent else {}
        bundle = _codeql_bundle(repository, defaults.get("codeql_bundle"))
        return jsonify(tools=tools, codeql_bundle=str(bundle) if bundle else "", defaults=defaults,
                       groq_configured=bool(os.environ.get("GROQ_API_KEY") or get_secret("groq")),
                       docker_running=bool(docker and probe([docker, "info", "--format", "{{.ServerVersion}}"])),
                       zap_installed=bool(docker and probe([docker, "image", "inspect", IMAGE])),
                       notice="Executable presence is not scanner readiness. The pipeline verifies supported versions and configuration before scanning.")

    @app.post("/api/settings")
    def settings():
        if not persistent:
            raise ValueError("Settings are unavailable")
        payload = request.get_json() or {}
        allowed = {key: str(payload[key])[:4096] for key in ("codeql_bundle", "ai_provider", "ai_model") if key in payload}
        jobs.db.save("settings", {"id": "defaults", **allowed})
        return jsonify(saved=True)

    @app.get("/api/runtime/example")
    def workflow_example():
        from .workflow_examples import order_service_example
        return jsonify(order_service_example())

    @app.post("/api/runtime/validate")
    def validate_contract():
        from security_reviewer_v2.scanners.runtime_workflows import validate_suite
        payload = request.get_json() or {}
        suite = validate_suite(payload.get("workflow_suite"), disposable=payload.get("runtime_method") == "trusted_compose")
        return jsonify(valid=True, accounts=len(suite.get("accounts", [])), workflows=len(suite["workflows"]),
                       steps=sum(len(w["steps"]) for w in suite["workflows"]),
                       note="Structure validated. Account identity, readiness and assertions are checked when the run starts.")

    @app.post("/api/runtime/export")
    def export_contract():
        from .app import _create_runtime_contract
        from security_reviewer_v2.test_environment import load_environment_spec
        payload = request.get_json() or {}
        project = Path(str(payload.get("project", ""))).resolve()
        if not project.is_dir():
            raise ValueError("Choose the project directory")
        path = _create_runtime_contract(repository, "export-" + uuid.uuid4().hex[:12], payload)
        load_environment_spec(path, project_root=project)
        return send_file(path, as_attachment=True, download_name="runtime-contract.json", mimetype="application/json")

    @app.post("/api/setup/zap")
    def install_zap():
        if not persistent or not shutil.which("docker"):
            raise ValueError("Docker is required")
        from .app import Job, _report_root
        from security_reviewer_v2.scanners.zap_runtime import IMAGE
        identifier = uuid.uuid4().hex[:12]
        job = Job(identifier, "setup-zap", command=[shutil.which("docker"), "pull", IMAGE],
                  report_dir=str(_report_root(repository) / identifier))
        raw = asdict(job)
        import time
        raw.update(repository=str(repository), created_at=time.time())
        jobs._launch(raw)
        return jsonify(asdict(job)), 202

    @app.post("/api/jobs/<identifier>/<action>")
    def job_action(identifier, action):
        if not persistent or action not in {"cancel", "resume", "recover", "remove", "restore"}:
            raise ValueError("Unknown action")
        if action in {"remove", "restore"}:
            return jsonify(changed=jobs.db.change_history(identifier, remove=action == "remove"), reports_preserved=True)
        result = getattr(jobs, action)(identifier)
        return jsonify(asdict(result) if result else {"requested": True})

    @app.post("/api/history/clear")
    def clear_history():
        if not persistent:
            raise ValueError("History persistence is unavailable")
        return jsonify(changed=jobs.db.change_history(), reports_preserved=True)

    @app.get("/api/jobs/<identifier>/report")
    def report(identifier):
        job = jobs.get(identifier)
        if not job:
            return jsonify(error="Job not found"), 404
        result = project_report(Path(job.report_dir))
        previous = next((j for j in jobs.list() if j.id != job.id and j.project_id == job.project_id
                         and j.mode == job.mode and j.started_at and job.started_at and j.started_at < job.started_at
                         and j.status == "completed"), None) if job.project_id else None
        if previous:
            result["comparison"] = compare(result, project_report(Path(previous.report_dir)))
            result["comparison"]["previous_id"] = previous.id
        return jsonify(result)

    @app.get("/api/jobs/<identifier>/export")
    def export(identifier):
        job = jobs.get(identifier)
        if not job:
            return jsonify(error="Job not found"), 404
        # Deliberately excludes arbitrary raw files, source snapshots, secrets and lease records.
        root = Path(job.report_dir)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("dashboard-summary.json", json.dumps(project_report(root), indent=2))
            for name in ("security-review-report.md", "security-review-report.html", "security-review.json", "policy-gate.json", "coverage-gaps.json",
                         "coverage-summary.json", "candidate-triage.json", "verification.json", "resume-provenance.json", "workflow-evidence.json", "browser-runtime-evidence.json"):
                path = root / name
                if path.is_file() and not path.is_symlink() and path.stat().st_size < 50_000_000:
                    archive.write(path, name)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name=f"verdict-{identifier}.zip", mimetype="application/zip")

    return token

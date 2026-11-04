"""A localhost-only web control plane for local security review runs.

The control plane deliberately does not accept shell commands and does not
mount a Docker socket.  It starts only the repository's reviewed entrypoint
scripts, one job at a time, and keeps reports outside the scanned project.
It is intended for a developer workstation, not for public hosting.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_file

from security_reviewer_v2.test_environment import load_environment_spec


@dataclass
class Job:
    id: str
    mode: str
    status: str = "queued"
    project: str | None = None
    report_dir: str | None = None
    command: list[str] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    returncode: int | None = None
    tail: str = ""
    summary: dict[str, Any] | None = None
    files: list[str] = field(default_factory=list)
    error: str | None = None
    stage: str = "Queued"
    elapsed_seconds: int = 0
    project_id: str | None = None
    previous_id: str | None = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json_summary(output: str) -> dict[str, Any] | None:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and ("status" in value or "output" in value):
            return value
    return None


def _report_root(repository: Path) -> Path:
    configured = os.environ.get("SECURITY_REVIEWER_REPORT_ROOT")
    from .storage import data_root

    return (
        Path(configured).expanduser().resolve()
        if configured
        else data_root() / "reports"
    )


def _codeql_bundle(repository: Path, supplied: str | None) -> Path | None:
    value = supplied or os.environ.get("CODEQL_BUNDLE")
    if value:
        return Path(value).expanduser().resolve()
    candidate = repository.parent / "tools" / "codeql-2.27.1" / "codeql"
    return candidate if (candidate / "codeql.exe").is_file() else None


def _setup_path(repository: Path, project: Path) -> Path:
    key = hashlib.sha256(str(project.resolve()).casefold().encode("utf-8")).hexdigest()[
        :24
    ]
    return _report_root(repository) / "_setups" / f"{key}.json"


def _compose_fingerprint(project: Path, compose_file: str) -> str:
    raw = project / compose_file
    selected = raw.resolve()
    if (
        not selected.is_file()
        or raw.is_symlink()
        or not selected.is_relative_to(project)
    ):
        raise ValueError("Compose file must be a regular file inside the project")
    digest = hashlib.sha256()
    for source in (selected, project / "Dockerfile", project / ".dockerignore"):
        if source.is_file():
            digest.update(str(source.relative_to(project)).encode("utf-8"))
            digest.update(source.read_bytes())
    return digest.hexdigest()


def _saved_setup(repository: Path, project: Path) -> dict[str, Any] | None:
    path = _setup_path(repository, project)
    if not path.is_file() or path.stat().st_size > 16 * 1024:
        return None
    try:
        setup = json.loads(path.read_text(encoding="utf-8"))
        if setup.get("project") != str(project.resolve()):
            return None
        if setup.get("runtime_method") == "trusted_compose" and setup.get(
            "fingerprint"
        ) != _compose_fingerprint(project, setup["compose_file"]):
            return None
        return setup
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _discover_setup(
    project: Path, application_map: dict[str, Any] | None = None
) -> dict[str, str] | None:
    """Suggest only an unambiguous, root-level Compose service and loopback port."""
    candidates = [
        name
        for name in (
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
        )
        if (project / name).is_file() and not (project / name).is_symlink()
    ]
    if len(candidates) != 1:
        return None
    source = project / candidates[0]
    if source.stat().st_size > 128 * 1024:
        return None
    try:
        content = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    block = re.search(
        r"(?ms)^services:\s*\n(.*?)(?=^[A-Za-z][A-Za-z0-9_-]*:|\Z)", content
    )
    if not block:
        return None
    matches = list(re.finditer(r"(?m)^  ([A-Za-z][A-Za-z0-9_-]*):\s*$", block.group(1)))
    port_candidates: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        service_body = block.group(1)[
            match.end() : matches[index + 1].start()
            if index + 1 < len(matches)
            else None
        ]
        ports = re.findall(
            r"(?m)^\s*-\s*['\"]?127\.0\.0\.1:(\d{2,5}):\d+", service_body
        )
        if len(ports) == 1 and 1 <= int(ports[0]) <= 65535:
            port_candidates.append((match.group(1), ports[0]))
    if len(port_candidates) != 1:
        return None
    service, port = port_candidates[0]
    discovered = application_map or {}
    suggested = discovered.get("suggested_setup") or {}
    endpoints = suggested.get("endpoints") or "/"
    return {
        "runtime_method": "trusted_compose",
        "compose_file": candidates[0],
        "app_service": service,
        "base_url": f"http://127.0.0.1:{port}",
        "health_path": str(
            suggested.get("health_path") or discovered.get("health_path") or "/"
        ),
        "expected_status": str(suggested.get("expected_status") or "200"),
        "endpoints": endpoints,
    }


def _prepared_workflow_suite(suite: Any, *, compose_mode: bool) -> Any:
    """Derive write permission from declared steps only for trusted Compose UI runs."""
    if not compose_mode or not isinstance(suite, dict):
        return suite
    workflows = suite.get("workflows")
    if not isinstance(workflows, list) or any(
        not isinstance(workflow, dict)
        or not isinstance(workflow.get("steps"), list)
        for workflow in workflows
    ):
        raise ValueError("Invalid workflow steps")
    prepared = dict(suite)
    prepared["allow_mutation"] = any(
        step.get("method") in {"POST", "PUT", "PATCH", "DELETE"}
        for workflow in workflows
        for step in workflow["steps"]
        if isinstance(step, dict)
    )
    if prepared["allow_mutation"]:
        prepared["reset"] = "fresh_stack"
    return prepared


def _create_runtime_contract(
    repository: Path,
    job_id: str,
    payload: dict[str, Any],
    *,
    saved: dict[str, Any] | None = None,
) -> Path:
    """Create a contract from UI fields without putting it in the target tree."""
    if payload.get("authorized_for_testing") is not True and saved is None:
        raise ValueError("You must confirm authorization to run generic DAST")
    base_url = str(payload.get("base_url", "")).strip()
    parsed = urllib.parse.urlsplit(base_url)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "Base URL must be an HTTP loopback URL with an explicit port"
        ) from error
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or port is None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("Base URL must be an HTTP loopback URL with an explicit port")
    health_path = str(payload.get("health_path", "/health")).strip() or "/"
    try:
        expected_status = int(str(payload.get("expected_status", "200")).strip())
    except ValueError as error:
        raise ValueError("Expected status must be an HTTP status number") from error
    raw_endpoints = str(payload.get("endpoints", ""))
    endpoints = [
        item.strip()
        for item in raw_endpoints.replace("\r", "\n").replace(",", "\n").split("\n")
        if item.strip()
    ]
    from security_reviewer_v2.scanners.runtime_workflows import (
        local_path,
        validate_suite,
    )

    local_path(health_path)
    for endpoint in endpoints:
        local_path(endpoint)
    compose_mode = payload.get("runtime_method") == "trusted_compose"
    if compose_mode and payload.get("trusted_project") is not True and saved is None:
        raise ValueError(
            "Confirm that you trust this project before Docker build/start"
        )
    contract = {
        "schema_version": "1.0",
        "mode": "docker_compose" if compose_mode else "existing_url",
        "trust_level": "trusted_local_project" if compose_mode else "untrusted",
        "authorized_for_testing": True,
        "target": {
            "base_url": base_url,
            "health_path": health_path,
            "expected_status": expected_status,
        },
        "endpoints": endpoints,
        "accounts": [],
        "checks": {"authorization": False, "mutating": False},
        "required_env": [],
    }
    if compose_mode:
        compose_file = str(payload.get("compose_file", "")).strip()
        service = str(payload.get("app_service", "")).strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", service):
            raise ValueError("Choose a valid Docker app service")
        contract["compose"] = {"file": compose_file, "app_service": service}
    if payload.get("workflow_enabled") is True:
        suite = _prepared_workflow_suite(
            payload.get("workflow_suite"), compose_mode=compose_mode
        )
        validate_suite(suite, disposable=compose_mode)
        contract["workflow_suite"] = suite
    path = _report_root(repository) / "_contracts" / f"{job_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    return path


def build_command(
    *,
    repository: Path,
    mode: str,
    project: str | None,
    runtime_contract: str | None,
    codeql_bundle: str | None,
    ai_provider: str,
    ai_model: str | None,
    output: Path,
    allow_trusted_local_compose: bool = False,
    runtime_recipe: str | None = None,
    runtime_entrypoint: str = "app:app",
    health_path: str = "/",
    health_status: int = 200,
    browser_dast: bool = False,
) -> tuple[list[str], Path | None]:
    """Build one of the reviewed entrypoint commands; never invokes a shell."""
    if mode not in {"docker-educational", "project-static", "project-full"}:
        raise ValueError("Unknown review mode")
    if ai_provider not in {"groq", "ollama"}:
        raise ValueError("AI provider must be groq or ollama")
    bundle = _codeql_bundle(repository, codeql_bundle)
    if bundle is None or not (bundle / "codeql.exe").is_file():
        raise ValueError("A CodeQL bundle containing codeql.exe is required")
    python = sys.executable
    model = ai_model or (
        "openai/gpt-oss-120b" if ai_provider == "groq" else "qwen2.5-coder:7b"
    )
    if mode == "docker-educational":
        command = [
            python,
            str(repository / "scripts" / "run_docker_automatic_pipeline.py"),
            "--output",
            str(output),
            "--codeql-bundle",
            str(bundle),
            "--ai-provider",
            ai_provider,
            "--ai-model",
            model,
        ]
        if browser_dast:
            command.append("--browser-dast")
        return command, None
    if not project:
        raise ValueError("Project directory is required")
    project_path = Path(project).expanduser().resolve()
    if not project_path.is_dir():
        raise ValueError(f"Project directory is unavailable: {project_path}")
    command = [
        python,
        str(repository / "scripts" / "run_project_pipeline.py"),
        str(project_path),
        "--output",
        str(output),
        "--codeql-bundle",
        str(bundle),
        "--ai-provider",
        ai_provider,
        "--ai-model",
        model,
        "--require-all-scanners",
    ]
    contract: Path | None = None
    if mode == "project-static":
        command.append("--static-only")
    elif runtime_recipe:
        if (
            runtime_recipe not in {"flask", "fastapi", "express"}
            or not allow_trusted_local_compose
        ):
            raise ValueError("Automatic templates need explicit trust approval")
        command.extend(
            [
                "--runtime-recipe",
                runtime_recipe,
                "--runtime-entrypoint",
                runtime_entrypoint,
                "--allow-trusted-local-compose",
                "--health-path",
                health_path,
                "--health-status",
                str(health_status),
            ]
        )
    else:
        if not runtime_contract:
            raise ValueError("A Runtime Contract is required for full project mode")
        contract = Path(runtime_contract).expanduser().resolve()
        if not contract.is_file():
            raise ValueError(f"Runtime Contract is unavailable: {contract}")
        if contract.is_relative_to(project_path):
            raise ValueError("Runtime Contract must be outside the scanned project")
        command.extend(["--runtime-contract", str(contract)])
        if allow_trusted_local_compose:
            command.append("--allow-trusted-local-compose")
    if browser_dast and mode != "project-static":
        command.append("--browser-dast")
    if output == project_path or output.is_relative_to(project_path):
        raise ValueError("Report directory must be outside the scanned project")
    return command, contract


class JobStore:
    def __init__(
        self, repository: Path, *, runner: Callable[..., tuple[int, str]] | None = None
    ) -> None:
        self.repository = repository.resolve()
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._runner = runner or self._run_process
        self._active = False
        self._pending_setups: dict[str, dict[str, Any]] = {}

    def list(self) -> list[Job]:
        with self._lock:
            return list(reversed(list(self._jobs.values())))

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def submit(self, payload: dict[str, Any]) -> Job:
        with self._lock:
            if self._active:
                raise ValueError("A review is already running; wait for it to finish")
            mode = str(payload.get("mode", ""))
            job_id = uuid.uuid4().hex[:12]
            report_dir = _report_root(self.repository) / job_id
            project = payload.get("project")
            runtime_contract = payload.get("runtime_contract")
            project_path = (
                Path(str(project)).expanduser().resolve() if project else None
            )
            saved = (
                _saved_setup(self.repository, project_path)
                if project_path
                and project_path.is_dir()
                and payload.get("saved_setup") == "yes"
                else None
            )
            setup: dict[str, Any] | None = None
            recipe = (
                payload.get("runtime_recipe")
                if payload.get("runtime_method") == "recipe"
                else None
            )
            if payload.get("workflow_enabled") and (
                mode != "project-full" or recipe or runtime_contract
            ):
                raise ValueError(
                    "Guided workflows require My app full mode with Compose or a local URL. For imported contracts, include workflow_suite in the file."
                )
            if recipe and (
                payload.get("trusted_project") is not True
                or payload.get("authorized_for_testing") is not True
            ):
                raise ValueError(
                    "Confirm project trust and testing authorization before using an automatic template"
                )
            if mode == "project-full" and not runtime_contract and not recipe:
                if saved is not None:
                    keys = (
                        "runtime_method",
                        "compose_file",
                        "app_service",
                        "base_url",
                        "health_path",
                        "expected_status",
                        "endpoints",
                    )
                    if any(
                        str(payload.get(key, "")) != str(saved.get(key, ""))
                        for key in keys
                    ):
                        raise ValueError(
                            "Saved setup was changed; detect it again or confirm the new settings"
                        )
                runtime_contract = str(
                    _create_runtime_contract(
                        self.repository, job_id, payload, saved=saved
                    )
                )
                if project_path and project_path.is_dir():
                    load_environment_spec(runtime_contract, project_root=project_path)
                setup = {
                    key: payload.get(key, "")
                    for key in (
                        "runtime_method",
                        "compose_file",
                        "app_service",
                        "base_url",
                        "health_path",
                        "expected_status",
                        "endpoints",
                    )
                }
                if project_path:
                    setup["project"] = str(project_path)
                if setup["runtime_method"] == "trusted_compose" and project_path:
                    setup["fingerprint"] = _compose_fingerprint(
                        project_path, str(setup["compose_file"])
                    )
            command, _ = build_command(
                repository=self.repository,
                mode=mode,
                project=project,
                runtime_contract=runtime_contract,
                codeql_bundle=payload.get("codeql_bundle"),
                ai_provider=str(payload.get("ai_provider", "groq")),
                ai_model=payload.get("ai_model"),
                output=report_dir,
                allow_trusted_local_compose=bool(
                    recipe or (setup and setup["runtime_method"] == "trusted_compose")
                ),
                runtime_recipe=recipe,
                runtime_entrypoint=str(payload.get("runtime_entrypoint") or "app:app"),
                health_path=str(payload.get("health_path") or "/"),
                health_status=int(payload.get("expected_status") or 200),
                browser_dast=payload.get("browser_dast") is True,
            )
            engine = str(payload.get("dast_engine", "baseline"))
            if engine not in {"baseline", "zap-passive", "zap-active"}:
                raise ValueError("Unknown DAST engine")
            if (
                engine == "zap-active"
                and payload.get("active_scan_approved") is not True
                and not (setup and setup["runtime_method"] == "trusted_compose")
            ):
                raise ValueError(
                    "Active scanning can change application data; explicit approval is required"
                )
            if mode != "project-static":
                command.extend(["--dast-engine", engine])
            if payload.get("login_enabled") is True:
                if engine == "baseline" or mode != "project-full":
                    raise ValueError(
                        "Form login is available only with ZAP in My App full mode"
                    )
                auth = {
                    k: str(payload.get(k, ""))
                    for k in (
                        "login_path",
                        "username_field",
                        "password_field",
                        "logged_in_regex",
                    )
                }
                from security_reviewer_v2.scanners.zap_runtime import automation_plan

                automation_plan(
                    str(payload.get("base_url") or "http://127.0.0.1:8080").rstrip("/"),
                    auth=auth,
                )
                auth_path = (
                    _report_root(self.repository)
                    / "_contracts"
                    / (job_id + "-auth.json")
                )
                auth_path.parent.mkdir(parents=True, exist_ok=True)
                auth_path.write_text(json.dumps(auth), encoding="utf-8")
                command.extend(["--zap-auth-config", str(auth_path)])
            job = Job(
                job_id,
                mode,
                project=str(project) if project else None,
                report_dir=str(report_dir),
                command=command,
            )
            self._jobs[job_id] = job
            if setup is not None:
                self._pending_setups[job_id] = setup
            self._active = True
            self._dispatch(job)
            return job

    def _dispatch(self, job: Job) -> None:
        threading.Thread(target=self._execute, args=(job,), daemon=True).start()

    def _execute(self, job: Job) -> None:
        with self._lock:
            job.status, job.started_at = "running", _now()
        try:
            code, output = self._runner(job.command, cwd=self.repository)
            with self._lock:
                job.returncode = code
                job.tail = output[-12000:]
                job.summary = _json_summary(output)
                job.status = "completed" if code == 0 else "failed"
                job.finished_at = _now()
                job.files = self._files(job.report_dir)
                if job.status == "completed" and job.id in self._pending_setups:
                    setup = self._pending_setups[job.id]
                    target = _setup_path(self.repository, Path(setup["project"]))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(
                        json.dumps(setup, indent=2) + "\n", encoding="utf-8"
                    )
        except (
            Exception
        ) as error:  # surface failures in the UI instead of killing the worker thread
            with self._lock:
                job.status, job.error, job.finished_at = "failed", str(error), _now()
        finally:
            with self._lock:
                self._pending_setups.pop(job.id, None)
                self._active = False

    @staticmethod
    def _run_process(command: list[str], *, cwd: Path) -> tuple[int, str]:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            output, _ = process.communicate(
                timeout=int(
                    os.environ.get("SECURITY_REVIEWER_JOB_TIMEOUT_SECONDS", "7200")
                )
            )
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
            output += "\nJob exceeded its time limit and was terminated.\n"
            return 124, output
        return process.returncode, output

    @staticmethod
    def _files(report_dir: str | None) -> list[str]:
        if not report_dir:
            return []
        root = Path(report_dir)
        if not root.is_dir():
            return []
        return sorted(
            str(p.relative_to(root)).replace("\\", "/")
            for p in root.rglob("*")
            if p.is_file()
        )[:200]


def create_app(
    repository: Path | None = None, *, store: JobStore | None = None
) -> Flask:
    repository = (repository or Path(__file__).resolve().parents[3]).resolve()
    app = Flask(__name__)
    if store is None:
        from .service import LocalService

        store = LocalService(repository)
    jobs = store
    app.config["JOB_STORE"] = jobs
    from .routes import install_routes

    token = install_routes(app, jobs, repository)

    @app.get("/")
    def index() -> str:
        return render_template("index.html", token=token)

    @app.get("/api/health")
    def health() -> Any:
        return jsonify(
            {
                "status": "ok",
                "service": "local-web-control-plane",
                "bind": "localhost",
                "ui_version": "2",
                "repository": str(repository),
            }
        )

    @app.get("/api/jobs")
    def all_jobs() -> Any:
        removed = jobs.db.removed_history() if hasattr(jobs, "db") else set()
        show_removed = request.args.get("removed") == "1"
        return jsonify(
            [
                {**asdict(job), "removed": job.id in removed}
                for job in jobs.list()
                if (job.id in removed) == show_removed
            ]
        )

    @app.post("/api/projects/inspect")
    def inspect_project() -> Any:
        payload = request.get_json(silent=True) or {}
        raw = payload.get("project")
        if not isinstance(raw, str) or not raw.strip():
            return jsonify({"error": "Choose a project directory first"}), 400
        project = Path(raw).expanduser().resolve()
        if not project.is_dir():
            return jsonify({"error": "Project directory is unavailable"}), 400
        from .runtime_discovery import discover

        application_map = discover(project)
        from security_reviewer_v2.test_environment.recipes import detect

        return jsonify(
            {
                "saved": _saved_setup(repository, project),
                "suggestion": _discover_setup(project, application_map)
                or detect(project),
                "application_map": application_map,
                "runtime_contract_draft": application_map.get("runtime_contract_draft"),
            }
        )

    @app.post("/api/jobs")
    def create_job() -> Any:
        payload = request.get_json(silent=True) or {}
        try:
            job = jobs.submit(payload)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(asdict(job)), 202

    @app.get("/api/jobs/<job_id>")
    def one_job(job_id: str) -> Any:
        job = jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(asdict(job))

    @app.get("/api/jobs/<job_id>/files/<path:filename>")
    def report_file(job_id: str, filename: str) -> Any:
        job = jobs.get(job_id)
        if job is None or not job.report_dir:
            return jsonify({"error": "Job not found"}), 404
        root = Path(job.report_dir).resolve()
        target = (root / filename).resolve()
        if target != root and not target.is_relative_to(root):
            return jsonify({"error": "Invalid report path"}), 400
        if not target.is_file():
            return jsonify({"error": "Report file not found"}), 404
        return send_file(target, as_attachment=True)

    return app


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the local-only security review web UI"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address; keep the default localhost-only value",
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("The local web deployment only permits a loopback bind address")
    repository = Path(__file__).resolve().parents[3]
    from waitress import serve

    print(f"Verdict local UI: http://{args.host}:{args.port} (Waitress)", flush=True)
    serve(
        create_app(repository),
        host=args.host,
        port=args.port,
        threads=6,
        max_request_body_size=65536,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Durable local projects and detached jobs; no credentials are serialized."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, fields
from pathlib import Path

import psutil

from .app import Job, JobStore, _now, _prepared_workflow_suite, _report_root
from .credentials import worker_environment
from .storage import Database

CONFIG_FIELDS = {
    "name",
    "project",
    "mode",
    "runtime_method",
    "compose_file",
    "app_service",
    "base_url",
    "health_path",
    "expected_status",
    "endpoints",
    "runtime_contract",
    "codeql_bundle",
    "ai_provider",
    "ai_model",
    "runtime_recipe",
    "runtime_entrypoint",
    "dast_engine",
    "browser_dast",
    "login_path",
    "username_field",
    "password_field",
    "logged_in_regex",
}


class LocalService(JobStore):
    def __init__(self, repository: Path, *, root: Path | None = None):
        super().__init__(repository)
        self.db = Database(root)
        self._payload = {}

    def _job(self, raw):
        return Job(
            **{
                key: value
                for key, value in raw.items()
                if key in {f.name for f in fields(Job)}
            }
        )

    def list(self):
        return [self._job(raw) for raw in self.db.all("jobs")]

    def get(self, identifier):
        raw = self.db.get("jobs", identifier)
        return self._job(raw) if raw else None

    def save_project(self, payload):
        project = Path(str(payload.get("project", ""))).expanduser().resolve()
        if payload.get("mode") != "docker-educational" and not project.is_dir():
            raise ValueError("Choose an existing project directory")
        identifier = str(payload.get("project_id") or uuid.uuid4().hex[:12])
        if not identifier.isalnum() or len(identifier) > 32:
            raise ValueError("Invalid project ID")
        value = {
            key: str(payload[key])[:4096] for key in CONFIG_FIELDS if key in payload
        }
        value.update(id=identifier, updated_at=_now())
        value["login_enabled"] = payload.get("login_enabled") is True
        value["browser_dast"] = payload.get("browser_dast") is True
        value["workflow_enabled"] = payload.get("workflow_enabled") is True
        if payload.get("workflow_suite") is not None:
            from security_reviewer_v2.scanners.runtime_workflows import validate_suite

            value["workflow_suite"] = validate_suite(
                _prepared_workflow_suite(
                    payload["workflow_suite"],
                    compose_mode=payload.get("runtime_method") == "trusted_compose",
                ),
                disposable=payload.get("runtime_method") == "trusted_compose",
            )
        self.db.save("projects", value)
        return value

    def submit(self, payload):
        with self._lock:
            if payload.get("mode") not in {
                "project-full",
                "project-static",
                "docker-educational",
            }:
                raise ValueError("Unknown review mode")
            if any(
                j.status in {"queued", "running", "cancelling", "cleanup_failed"}
                for j in self.list()
            ):
                raise ValueError(
                    "Finish or recover the current job before starting another"
                )
            self._payload = dict(payload)
            project = self.save_project(payload)
            self._payload["project_id"] = project["id"]
            self._active = False
            try:
                return super().submit(payload)
            finally:
                self._active = False

    def _dispatch(self, job):
        job.project_id = self._payload.get("project_id")
        raw = asdict(job)
        raw.update(
            repository=str(self.repository),
            created_at=time.time(),
            setup=self._pending_setups.pop(job.id, None),
            ai_provider=self._payload.get("ai_provider", "groq"),
            ai_model=self._payload.get("ai_model", "openai/gpt-oss-120b"),
        )
        self._launch(raw)

    def _launch(self, raw):
        self.db.save("jobs", raw, exclusive_job=True)
        project = self.db.get("projects", raw.get("project_id", "")) or {}
        suite = project.get("workflow_suite") or {}
        env = worker_environment(
            raw.get("project_id"), accounts=[a["id"] for a in suite.get("accounts", [])]
        )
        env["PATH"] = (
            str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
        )
        flags = (
            (subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
            if os.name == "nt"
            else 0
        )
        try:
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "security_reviewer_v2.web.worker",
                    str(self.db.root),
                    raw["id"],
                ],
                cwd=self.repository,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
                start_new_session=os.name != "nt",
            )
        except OSError as error:
            raw.update(status="failed", error=str(error))
            self.db.save("jobs", raw)
            raise ValueError("Unable to start the local worker") from error

    def cancel(self, identifier):
        job = self.db.get("jobs", identifier)
        if not job or job["status"] not in {"queued", "running", "cancelling"}:
            raise ValueError("This job is not running")
        state = self.db.root / "jobs" / identifier
        state.mkdir(parents=True, exist_ok=True)
        (state / "cancel").touch()

    def recover(self, identifier):
        from security_reviewer_v2.test_environment.leases import cleanup

        job = self.db.get("jobs", identifier)
        if not job:
            raise ValueError("Job not found")
        if job["status"] in {"completed", "cancelled"}:
            raise ValueError("This job has already finished; no recovery is needed")
        if job.get("worker_pid"):
            try:
                process = psutil.Process(job["worker_pid"])
                if abs(process.create_time() - job.get("worker_created", 0)) < 1:
                    raise ValueError("Worker is still running. Use Cancel instead.")
            except psutil.NoSuchProcess:
                pass
        if job["status"] == "queued" and time.time() - job.get("created_at", 0) < 60:
            raise ValueError("Worker is still starting; please wait")
        if job.get("process_pid"):
            try:
                child = psutil.Process(job["process_pid"])
                if abs(child.create_time() - job.get("process_created", 0)) < 1:
                    from .worker import terminate_tree

                    terminate_tree(child.pid)
            except psutil.NoSuchProcess:
                pass
        errors = cleanup(self.db.root / "jobs" / identifier / "leases")
        job.update(
            status="cleanup_failed" if errors else "interrupted",
            error="; ".join(errors) or None,
        )
        self.db.save("jobs", job)
        return self._job(job)

    def resume(self, identifier):
        source = self.db.get("jobs", identifier)
        if not source or source["status"] in {
            "queued",
            "running",
            "cancelling",
            "cleanup_failed",
        }:
            raise ValueError("Finish or recover the job first")
        saved = Path(source["report_dir"])
        if not all(
            (saved / name).is_file()
            for name in ("profile.json", "merged.json", "context.json")
        ):
            raise ValueError(
                "No complete static evidence is saved. Start a new review."
            )
        from security_reviewer_v2.profiler.artifact import (
            validate_saved_profile_artifact,
        )

        project = Path(
            source.get("project") or self.repository / "targets" / "security-lab-web"
        )
        validate_saved_profile_artifact(
            json.loads((saved / "profile.json").read_text(encoding="utf-8")), project
        )
        new_id = uuid.uuid4().hex[:12]
        output = _report_root(self.repository) / new_id
        command = [
            sys.executable,
            str(self.repository / "scripts" / "resume_local_review.py"),
            str(project),
            str(saved),
            str(output),
            "--provider",
            source.get("ai_provider", "groq"),
            "--model",
            source.get("ai_model", "openai/gpt-oss-120b"),
        ]
        raw = asdict(
            Job(
                new_id,
                source["mode"],
                project=str(project),
                report_dir=str(output),
                command=command,
                project_id=source.get("project_id"),
                previous_id=identifier,
            )
        )
        raw.update(
            repository=str(self.repository),
            created_at=time.time(),
            ai_provider=source.get("ai_provider", "groq"),
            ai_model=source.get("ai_model", "openai/gpt-oss-120b"),
        )
        self._launch(raw)
        return self._job(raw)

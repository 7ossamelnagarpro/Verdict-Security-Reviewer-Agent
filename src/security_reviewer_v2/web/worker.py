"""Detached, persistent local job runner. The browser and web server may close."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import psutil

from security_reviewer_v2.test_environment.leases import cleanup

from .credentials import redact
from .storage import Database


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def terminate_tree(pid: int):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in reversed(children):
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        parent.terminate()
        _, alive = psutil.wait_procs(children + [parent], timeout=5)
        for process in alive:
            try:
                process.kill()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass


def stage_for(output: Path) -> str:
    for filename, stage in (
        ("security-review.json", "Security review"),
        ("candidate-triage.json", "Verification and triage"),
        ("ai-discovery.json", "AI discovery"),
        ("context.json", "AI discovery"),
        ("merged.json", "Context collection"),
        ("profile.json", "Static scanners"),
        ("runtime.json", "Runtime evidence / static preflight"),
    ):
        if (output / filename).exists():
            return stage
    return "Readiness / application startup / DAST"


def run(root: Path, identifier: str) -> int:
    db = Database(root)
    job = db.get("jobs", identifier)
    if not job or job["status"] != "queued":
        return 1
    state = root / "jobs" / identifier
    state.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(PYTHONUNBUFFERED="1", VERDICT_LEASE_ROOT=str(state / "leases"))
    job.update(
        status="running",
        worker_pid=os.getpid(),
        worker_created=psutil.Process().create_time(),
        started_at=now(),
    )
    db.save("jobs", job)
    process = None
    timed_out = False
    try:
        with (state / "process.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                job["command"],
                cwd=job["repository"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

            def drain():
                for line in process.stdout:
                    log.write(redact(line, env))
                    log.flush()

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            try:
                created = psutil.Process(process.pid).create_time()
            except psutil.NoSuchProcess:
                created = 0
            job.update(process_pid=process.pid, process_created=created)
            db.save("jobs", job)
            started = time.monotonic()
            while process.poll() is None:
                cancelled = (state / "cancel").exists()
                timed_out = time.monotonic() - started > int(
                    env.get("SECURITY_REVIEWER_JOB_TIMEOUT_SECONDS", "7200")
                )
                if cancelled or timed_out:
                    job.update(
                        status="cancelling", stage="Stopping processes and cleaning up"
                    )
                    db.save("jobs", job)
                    terminate_tree(process.pid)
                    process.wait(timeout=15)
                    break
                job.update(
                    stage=stage_for(Path(job["report_dir"])),
                    elapsed_seconds=int(time.monotonic() - started),
                )
                raw = (state / "process.log").read_text(
                    encoding="utf-8", errors="replace"
                )[-12000:]
                job["tail"] = redact(raw, env)
                db.save("jobs", job)
                time.sleep(1)
            reader.join(timeout=10)
        raw = (state / "process.log").read_text(encoding="utf-8", errors="replace")
        safe = redact(raw, env)
        (state / "process.log").write_text(safe, encoding="utf-8")
        job.update(returncode=process.returncode, tail=safe[-12000:])
        from .app import _json_summary

        job["summary"] = _json_summary(safe)
        job["status"] = (
            "cancelled"
            if (state / "cancel").exists()
            else "failed"
            if timed_out or process.returncode
            else "completed"
        )
        if timed_out:
            job["error"] = (
                "The review reached its time limit. Saved evidence is retained."
            )
        output = Path(job["report_dir"])
        for filename in ("stage-summary.json", "pre-review-summary.json"):
            if (output / filename).is_file():
                job["summary"] = json.loads(
                    (output / filename).read_text(encoding="utf-8")
                )
                break
        job["files"] = sorted(p.name for p in output.glob("*") if p.is_file())
        if job["status"] == "completed" and job.get("setup"):
            from .app import _setup_path

            setup = job["setup"]
            path = _setup_path(Path(job["repository"]), Path(setup["project"]))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(setup), encoding="utf-8")
    except Exception as error:
        if process and process.poll() is None:
            terminate_tree(process.pid)
        job.update(status="failed", error=redact(str(error), env))
    finally:
        errors = cleanup(state / "leases")
        if errors:
            job.update(status="cleanup_failed", error="; ".join(errors))
        job.update(
            finished_at=now(),
            stage="Finished" if job["status"] == "completed" else job["status"],
        )
        db.save("jobs", job)
    return 0 if job["status"] == "completed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("job_id")
    args = parser.parse_args()
    raise SystemExit(run(args.root, args.job_id))

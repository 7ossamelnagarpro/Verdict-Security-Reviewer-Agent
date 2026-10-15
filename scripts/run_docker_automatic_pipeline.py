"""Trusted Security Lab Web Docker DAST, followed by the unchanged static/AI pipeline.

The application stack is removed before static scanning starts. This is not an
arbitrary-repository executor or a replacement for the Hyper-V worker.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from security_reviewer_v2.discovery.provider import provider_from_environment
from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.scanners.web_runtime import RuntimeConfig, run_checks
from security_reviewer_v2.test_environment import (
    load_environment_spec, plan_environment, provision_environment,
)
from security_reviewer_v2.test_environment.docker_runtime import (
    load_docker_runtime, sha256_file,
)


def _assert_stack_removed(docker: str, project_name: str) -> None:
    """Do not attest cleanup solely from the Compose down exit code."""
    if not project_name.startswith("sr-test-"):
        raise RuntimeError("Unexpected Compose project identity")
    inspected = subprocess.run(
        [docker, "ps", "--all", "--filter", f"label=com.docker.compose.project={project_name}",
         "--format", "{{.ID}}"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if inspected.returncode != 0 or inspected.stdout.strip():
        raise RuntimeError(f"Docker stack cleanup is unverified; inspect Compose project {project_name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan trusted Security Lab Web with disposable Docker containers")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--codeql-bundle", type=Path)
    parser.add_argument("--ai-provider", choices=("groq", "ollama"), default="groq")
    parser.add_argument("--ai-model")
    args = parser.parse_args(argv)

    repository = Path(__file__).resolve().parents[1]
    project = repository / "targets" / "security-lab-web"
    config = repository / "examples" / "security-lab-web-docker-environment.json"
    pipeline = repository / "scripts" / "run_pre_review_pipeline.py"
    auth_script = repository / "scripts" / "scan_tt_authorization.py"
    output = args.output.resolve()
    if output == project or output.is_relative_to(project):
        parser.error("Output directory must be outside the scanned project")
    if output.exists():
        parser.error("Choose a new output directory; existing reports are never overwritten")
    if os.environ.get("SECURITY_REVIEWER_RUNTIME_URL"):
        parser.error("Clear SECURITY_REVIEWER_RUNTIME_URL; this run imports only its own Docker DAST evidence")
    bundle = (args.codeql_bundle or repository.parent / "tools" / "codeql-2.27.1" / "codeql").resolve()
    if not (bundle / "codeql.exe").is_file():
        parser.error(f"Required CodeQL executable is missing from {bundle}")
    model = args.ai_model or ("openai/gpt-oss-120b" if args.ai_provider == "groq" else "qwen2.5-coder:7b")
    try:
        provider_from_environment(args.ai_provider, model)
    except (RuntimeError, ValueError) as error:
        parser.error(f"Required AI provider is not configured: {error}")

    print("Checking all four scanner adapters before starting Docker.", flush=True)
    preflight = subprocess.run(
        [sys.executable, str(pipeline), str(project), "--scanner-preflight-only",
         "--require-all-scanners", "--codeql-bundle", str(bundle)], check=False,
    )
    if preflight.returncode != 0:
        raise RuntimeError("Required scanner preflight failed; no container was started")

    spec = load_environment_spec(config, project_root=project)
    if spec.mode != "docker_compose" or spec.trust_level != "trusted_lab":
        raise RuntimeError("Only the explicitly trusted educational Compose target is supported")
    plan = plan_environment(spec, project_root=project, profile=profile_project(project))
    if plan.status != "ready_for_validation":
        raise RuntimeError("Docker environment preflight failed: " + "; ".join(plan.missing))
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker CLI is unavailable")

    run_id = secrets.token_hex(4)
    run_root = repository / "reports" / "docker-autoscan" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    source_hashes = {name: sha256_file(project / name)
                     for name in ("app.py", "requirements.txt", "Dockerfile", "compose.yaml",
                                  ".dockerignore", "secret_do_not_serve.txt", "files/report.txt")}
    print(f"Starting trusted Docker DAST run: {run_id}", flush=True)
    with provision_environment(spec, plan, project_root=project,
                               allow_compose_execution=True, docker_executable=docker) as session:
        if session.mode != "docker_compose" or not session.project_name:
            raise RuntimeError("Docker environment did not return a unique stack identity")
        runtime = run_checks(RuntimeConfig(session.base_url, run_root / "runtime.json",
                                           mutating=spec.mutating_checks))
        if runtime.get("status") != "completed" or not runtime.get("results"):
            raise RuntimeError("Web DAST did not produce completed probe results")
        authorized = subprocess.run(
            [sys.executable, str(auth_script), "--base-url", session.base_url,
             "--output", str(run_root / "authorization.json")],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if authorized.returncode != 0:
            raise RuntimeError("Authorization DAST did not complete: " + authorized.stderr[-1000:])
        stack_name = session.project_name
    _assert_stack_removed(docker, stack_name)

    auth = json.loads((run_root / "authorization.json").read_text(encoding="utf-8"))
    if auth.get("status") != "completed" or not auth.get("results"):
        raise RuntimeError("Authorization DAST returned no completed probe results")
    manifest = {
        "schema_version": "1.0", "run_id": run_id, "target_id": "security-lab-web",
        "backend": "docker_compose", "status": "passed", "stack_removed": True,
        "compose_project": stack_name, "http_status": 200,
        "network_exposure": "host_loopback_only",
        "mutating_checks_enabled": spec.mutating_checks,
        "source_sha256": source_hashes,
        "output_sha256": {name: sha256_file(run_root / name)
                          for name in ("runtime.json", "authorization.json")},
        "probe_counts": {"runtime.json": len(runtime["results"]),
                         "authorization.json": len(auth["results"])},
    }
    (run_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    load_docker_runtime(run_id, project_root=project, repository_root=repository)
    print(f"Docker DAST passed; temporary stack {stack_name} was removed.", flush=True)

    pipeline_args = [
        sys.executable, str(pipeline), str(project), "--output", str(output),
        "--docker-runtime-run-id", run_id, "--test-environment-config", str(config),
        "--require-dast", "--require-sast", "--require-all-scanners",
        "--codeql-bundle", str(bundle), "--ai-provider", args.ai_provider,
        "--ai-model", model,
    ]
    completed = subprocess.run(pipeline_args, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Static/AI pipeline did not complete; Docker is removed. Inspect {output}")
    print(f"Automatic Docker scan completed: {output}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Automatic Docker scan blocked: {error}", file=sys.stderr)
        raise SystemExit(1) from None

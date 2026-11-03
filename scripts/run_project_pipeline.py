"""Run the project-agnostic security review pipeline.

Full scans require an explicit Runtime Contract or approved startup template
and run bounded baseline DAST, with optional ZAP, before static/AI. Static-only mode is explicit so a
missing runtime target cannot be mistaken for a complete security scan.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Keep the entry point usable directly from a fresh checkout before the
# editable install has completed; installed environments still take precedence.
_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.scanners.hostpaths import find_codeql
from security_reviewer_v2.scanners.generic_runtime import (
    GenericRuntimeConfig,
    run_generic_checks,
)
from security_reviewer_v2.test_environment import (
    load_environment_spec,
    plan_environment,
    provision_environment,
)
from security_reviewer_v2.discovery.provider import provider_from_environment
import shutil


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a complete or explicitly source-only security review for any local project"
    )
    parser.add_argument("project", type=Path, help="local project directory to review")
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory for this run's reports")
    parser.add_argument("--runtime-contract", type=Path,
                        help="JSON Runtime Contract outside the project; required for a full scan")
    parser.add_argument("--static-only", action="store_true",
                        help="explicitly skip DAST; without this flag a Runtime Contract is required")
    parser.add_argument("--allow-trusted-local-compose", action="store_true",
                        help="opt in to running a trusted local project's reviewed Compose recipe")
    parser.add_argument("--codeql-bundle", type=Path,
                        help="CodeQL bundle directory containing codeql (Linux/macOS) or codeql.exe (Windows/WSL)")
    parser.add_argument("--ai-provider", choices=("groq", "ollama"), default="groq")
    parser.add_argument("--ai-model", default=None)
    parser.add_argument("--ai-max-targets", type=int, default=10)
    parser.add_argument("--ai-max-batches", type=int, default=20)
    parser.add_argument("--ai-max-files", type=int, default=64)
    parser.add_argument("--ai-max-context-chars", type=int, default=20_000)
    parser.add_argument("--ai-max-planned-targets", type=int, default=128)
    parser.add_argument("--ai-max-candidates", type=int, default=20)
    parser.add_argument("--ai-max-enrichment-rounds", type=int, default=2)
    parser.add_argument("--review-max-findings", type=int, default=3)
    parser.add_argument("--require-all-scanners", action="store_true",
                        help="require all four scanner adapters and their planned tasks")
    parser.add_argument("--runtime-recipe", choices=("flask", "fastapi", "express"))
    parser.add_argument("--runtime-entrypoint", default="app:app")
    parser.add_argument("--health-path", default="/")
    parser.add_argument("--health-status", type=int, default=200)
    parser.add_argument("--dast-engine", choices=("baseline", "zap-passive", "zap-active"), default="baseline")
    parser.add_argument("--zap-auth-config", type=Path)
    parser.add_argument("--browser-dast", action="store_true",
                        help="run an optional bounded same-origin Playwright crawl; missing Playwright is reported as a gap")
    parser.add_argument("--browser-seed-path", action="append", default=[],
                        help="extra authorized same-origin GET page for the bounded browser crawl; repeatable")
    return parser


def _validate(args: argparse.Namespace) -> tuple[Path, Path]:
    project = args.project.resolve()
    if not project.is_dir():
        raise ValueError(f"Project directory is unavailable: {project}")
    output = args.output.resolve()
    if output == project or output.is_relative_to(project):
        raise ValueError("Output directory must be outside the scanned project")
    if output.exists():
        raise ValueError(f"Choose a new output directory; existing reports are never overwritten: {output}")
    if args.static_only and args.runtime_contract is not None:
        raise ValueError("--static-only cannot be combined with --runtime-contract")
    if args.static_only and args.allow_trusted_local_compose:
        raise ValueError("--allow-trusted-local-compose requires a full scan")
    if getattr(args, "browser_seed_path", []) and (not getattr(args, "browser_dast", False) or args.static_only):
        raise ValueError("Browser seed paths require a full scan with --browser-dast")
    if getattr(args, "runtime_recipe", None) and (args.static_only or args.runtime_contract or not args.allow_trusted_local_compose):
        raise ValueError("Runtime templates require a full scan and explicit trusted Compose opt-in, without a contract")
    if not args.static_only and args.runtime_contract is None and not getattr(args, "runtime_recipe", None):
        raise ValueError("A full scan requires --runtime-contract; use --static-only explicitly to skip DAST")
    if args.runtime_contract is not None:
        contract = args.runtime_contract.resolve()
        if contract.is_relative_to(project):
            raise ValueError("Runtime Contract must be outside the scanned project")
        if not contract.is_file():
            raise ValueError(f"Runtime Contract is unavailable: {contract}")
    if args.codeql_bundle is not None:
        bundle = args.codeql_bundle.resolve()
        if find_codeql(bundle) is None:
            raise ValueError(f"Required CodeQL executable is missing from {bundle}")
    if args.ai_provider == "groq" and not os.environ.get("GROQ_API_KEY"):
        raise ValueError("GROQ_API_KEY is required for Groq; set it only in the current shell")
    return project, output


def _prepare_runtime(args: argparse.Namespace, *, project: Path, output: Path) -> Path:
    if getattr(args, "runtime_recipe", None):
        from security_reviewer_v2.test_environment.recipes import prepare
        from security_reviewer_v2.profiler.artifact import create_saved_profile_artifact, validate_saved_profile_artifact
        import copy
        import json
        original_profile = create_saved_profile_artifact(profile_project(project), project)
        with prepare(project, args.runtime_recipe, args.runtime_entrypoint, args.health_path, args.health_status) as (staged, contract):
            child = copy.copy(args)
            child.runtime_recipe = None
            child.runtime_contract = contract
            runtime = _prepare_runtime(child, project=staged, output=output)
            validate_saved_profile_artifact(original_profile, project)
            data = json.loads(runtime.read_text(encoding="utf-8"))
            data["template"] = {"kind": args.runtime_recipe, "entrypoint": args.runtime_entrypoint,
                                "original_source_unchanged": True}
            data.setdefault("coverage_notes", []).append("Runtime used a generated temporary template; .env, private key files and local dependency folders were excluded. This does not attest production configuration.")
            runtime.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return runtime
    if args.runtime_contract is None:
        raise ValueError("Runtime Contract is required for a full scan")
    contract = args.runtime_contract.resolve()
    spec = load_environment_spec(contract, project_root=project)
    if spec.mode == "docker_compose" and (
        spec.trust_level != "trusted_local_project" or not args.allow_trusted_local_compose
    ):
        raise ValueError("Project Compose needs trusted_local_project and explicit --allow-trusted-local-compose")
    if spec.mode == "existing_url" and args.allow_trusted_local_compose:
        raise ValueError("Compose opt-in cannot be used with an existing URL")
    if spec.authorization_checks:
        raise ValueError(
            "Generic authorization workflows need a project-specific adapter; "
            "set checks.authorization to false for baseline DAST"
        )
    if spec.mutating_checks:
        raise ValueError(
            "Generic mutating DAST is not enabled yet; set checks.mutating to false"
        )
    profile = profile_project(project)
    plan = plan_environment(spec, project_root=project, profile=profile)
    if plan.status != "ready_for_validation":
        raise ValueError("Runtime Contract is blocked: " + "; ".join(plan.missing))
    output.mkdir(parents=True, exist_ok=False)
    runtime_path = output / "runtime.json"
    if spec.mode == "docker_compose":
        docker = shutil.which("docker")
        if not docker:
            raise ValueError("Docker CLI is unavailable")
        with provision_environment(spec, plan, project_root=project,
                                   allow_compose_execution=True, docker_executable=docker) as session:
            run_generic_checks(GenericRuntimeConfig(
                session.base_url, runtime_path, spec.health_path,
                spec.expected_status, spec.endpoint_paths,
            ))
            stack_name = session.project_name
            if spec.workflow_suite:
                from security_reviewer_v2.scanners.runtime_workflows import append_workflows
                append_workflows(runtime_path, spec.workflow_suite, disposable=True)
            _zap(args, runtime_path, session.base_url, stack_name, spec.app_service)
            if getattr(args, "browser_dast", False):
                from security_reviewer_v2.scanners.browser_runtime import run_browser_dast
                run_browser_dast(session.base_url, runtime_path, output / "browser-runtime-evidence.json",
                                 seed_paths=tuple(getattr(args, "browser_seed_path", [])))
        if not stack_name or not stack_name.startswith("sr-test-"):
            raise RuntimeError("Docker stack identity was not verified")
        checked = subprocess.run(
            [docker, "ps", "--all", "--filter", f"label=com.docker.compose.project={stack_name}",
             "--format", "{{.ID}}"], capture_output=True, text=True, timeout=30, check=False)
        if checked.returncode != 0 or checked.stdout.strip():
            raise RuntimeError(f"Docker stack cleanup is unverified: {stack_name}")
    else:
        with provision_environment(spec, plan, project_root=project):
            run_generic_checks(GenericRuntimeConfig(
                spec.base_url, runtime_path, spec.health_path,
                spec.expected_status, spec.endpoint_paths,
            ))
            if spec.workflow_suite:
                from security_reviewer_v2.scanners.runtime_workflows import append_workflows
                append_workflows(runtime_path, spec.workflow_suite, disposable=False)
            _zap(args, runtime_path, spec.base_url)
            if getattr(args, "browser_dast", False):
                from security_reviewer_v2.scanners.browser_runtime import run_browser_dast
                run_browser_dast(spec.base_url, runtime_path, output / "browser-runtime-evidence.json",
                                 seed_paths=tuple(getattr(args, "browser_seed_path", [])))
    return runtime_path


def _zap(args, runtime_path, base_url, stack_name=None, app_service=None):
    import json
    from security_reviewer_v2.scanners.zap_runtime import run_zap
    auth_path = getattr(args, "zap_auth_config", None)
    auth = json.loads(auth_path.read_text(encoding="utf-8")) if auth_path else None
    run_zap(base_url, runtime_path, engine=getattr(args, "dast_engine", "baseline"),
            stack_name=stack_name, app_service=app_service, auth=auth)


def _command(args: argparse.Namespace, *, project: Path, output: Path,
             runtime_path: Path | None = None) -> list[str]:
    repository = Path(__file__).resolve().parents[1]
    pipeline = repository / "scripts" / "run_pre_review_pipeline.py"
    model = args.ai_model or (
        "openai/gpt-oss-120b" if args.ai_provider == "groq" else "qwen2.5-coder:7b"
    )
    command = [
        sys.executable, str(pipeline), str(project),
        "--output", str(output),
        "--require-sast",
        "--ai-provider", args.ai_provider,
        "--ai-model", model,
        "--ai-max-targets", str(args.ai_max_targets),
        "--ai-max-batches", str(args.ai_max_batches),
        "--ai-max-files", str(args.ai_max_files),
        "--ai-max-context-chars", str(args.ai_max_context_chars),
        "--ai-max-planned-targets", str(args.ai_max_planned_targets),
        "--ai-max-candidates", str(args.ai_max_candidates),
        "--ai-max-enrichment-rounds", str(args.ai_max_enrichment_rounds),
        "--review-max-findings", str(args.review_max_findings),
    ]
    if runtime_path is not None:
        command.extend(("--runtime-evidence", str(runtime_path),
                        "--require-dast"))
        if args.runtime_contract is not None:
            command.extend(("--test-environment-config", str(args.runtime_contract.resolve())))
    if args.require_all_scanners:
        command.append("--require-all-scanners")
    if args.codeql_bundle is not None:
        command.extend(("--codeql-bundle", str(args.codeql_bundle.resolve())))
    return command


def main(argv: list[str] | None = None) -> int:
    from security_reviewer_v2.agents.tracing import tracing_status
    from security_reviewer_v2.envfile import load_env_file
    load_env_file(Path(__file__).resolve().parents[1] / ".env", Path.cwd() / ".env")
    print(tracing_status(), flush=True)
    args = _parser().parse_args(argv)
    try:
        project, output = _validate(args)
        model = args.ai_model or ("openai/gpt-oss-120b" if args.ai_provider == "groq" else "qwen2.5-coder:7b")
        provider_from_environment(args.ai_provider, model)
        if not args.static_only and args.allow_trusted_local_compose:
            pipeline = Path(__file__).resolve().parents[1] / "scripts" / "run_pre_review_pipeline.py"
            preflight = subprocess.run(
                [sys.executable, str(pipeline), str(project), "--scanner-preflight-only",
                 "--require-all-scanners", "--codeql-bundle", str(args.codeql_bundle.resolve())]
                if args.codeql_bundle else
                [sys.executable, str(pipeline), str(project), "--scanner-preflight-only",
                 "--require-all-scanners"], check=False)
            if preflight.returncode != 0:
                raise ValueError("Required scanner preflight failed; Docker was not started")
        runtime_path = None if args.static_only else _prepare_runtime(
            args, project=project, output=output)
        command = _command(args, project=project, output=output,
                           runtime_path=runtime_path)
    except (ValueError, RuntimeError) as error:
        _parser().error(str(error))
    mode = "static-only" if args.static_only else "full scan with generic DAST"
    print(f"Starting {mode} for: {project}", flush=True)
    print(f"Reports will be written to: {output}", flush=True)
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        print("Security review did not complete; inspect the report directory.",
              file=sys.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())

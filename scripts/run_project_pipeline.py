"""Run the project-agnostic security review pipeline.

Full scans require an explicit Runtime Contract and run bounded, non-mutating
generic DAST before the static/AI stages. Static-only mode is explicit so a
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
from security_reviewer_v2.scanners.generic_runtime import (
    GenericRuntimeConfig,
    run_generic_checks,
)
from security_reviewer_v2.test_environment import (
    load_environment_spec,
    plan_environment,
    provision_environment,
)


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
    parser.add_argument("--codeql-bundle", type=Path,
                        help="CodeQL bundle directory containing codeql.exe")
    parser.add_argument("--ai-provider", choices=("groq", "ollama"), default="groq")
    parser.add_argument("--ai-model", default=None)
    parser.add_argument("--ai-max-targets", type=int, default=10)
    parser.add_argument("--ai-max-batches", type=int, default=20)
    parser.add_argument("--ai-max-planned-targets", type=int, default=128)
    parser.add_argument("--ai-max-candidates", type=int, default=20)
    parser.add_argument("--ai-max-enrichment-rounds", type=int, default=2)
    parser.add_argument("--review-max-findings", type=int, default=3)
    parser.add_argument("--require-all-scanners", action="store_true",
                        help="require all four scanner adapters and their planned tasks")
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
    if not args.static_only and args.runtime_contract is None:
        raise ValueError("A full scan requires --runtime-contract; use --static-only explicitly to skip DAST")
    if args.runtime_contract is not None:
        contract = args.runtime_contract.resolve()
        if contract.is_relative_to(project):
            raise ValueError("Runtime Contract must be outside the scanned project")
        if not contract.is_file():
            raise ValueError(f"Runtime Contract is unavailable: {contract}")
    if args.codeql_bundle is not None:
        bundle = args.codeql_bundle.resolve()
        if not (bundle / "codeql.exe").is_file():
            raise ValueError(f"Required CodeQL executable is missing from {bundle}")
    if args.ai_provider == "groq" and not os.environ.get("GROQ_API_KEY"):
        raise ValueError("GROQ_API_KEY is required for Groq; set it only in the current shell")
    return project, output


def _prepare_runtime(args: argparse.Namespace, *, project: Path, output: Path) -> Path:
    if args.runtime_contract is None:
        raise ValueError("Runtime Contract is required for a full scan")
    contract = args.runtime_contract.resolve()
    spec = load_environment_spec(contract, project_root=project)
    if spec.mode != "existing_url":
        raise ValueError(
            "Generic project execution currently supports an existing authorized URL only; "
            "untrusted Docker Compose requires the VM path"
        )
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
    with provision_environment(spec, plan, project_root=project):
        run_generic_checks(GenericRuntimeConfig(
            spec.base_url, runtime_path, spec.health_path,
            spec.expected_status, spec.endpoint_paths,
        ))
    return runtime_path


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
    args = _parser().parse_args(argv)
    try:
        project, output = _validate(args)
        runtime_path = None if args.static_only else _prepare_runtime(
            args, project=project, output=output)
        command = _command(args, project=project, output=output,
                           runtime_path=runtime_path)
    except ValueError as error:
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

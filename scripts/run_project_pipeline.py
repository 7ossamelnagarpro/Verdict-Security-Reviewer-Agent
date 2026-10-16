"""Run the project-agnostic source review pipeline.

This entry point deliberately provides source-only scanning for arbitrary
projects. The bundled HTTP probes are tailored to the educational fixture and
must not be presented as generic DAST. Runtime support will be added through
an explicit, project-specific contract in a later stage.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the source-only security review pipeline for any local project"
    )
    parser.add_argument("project", type=Path, help="local project directory to review")
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory for this run's reports")
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
    if args.codeql_bundle is not None:
        bundle = args.codeql_bundle.resolve()
        if not (bundle / "codeql.exe").is_file():
            raise ValueError(f"Required CodeQL executable is missing from {bundle}")
    if args.ai_provider == "groq" and not os.environ.get("GROQ_API_KEY"):
        raise ValueError("GROQ_API_KEY is required for Groq; set it only in the current shell")
    return project, output


def _command(args: argparse.Namespace, *, project: Path, output: Path) -> list[str]:
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
    if args.require_all_scanners:
        command.append("--require-all-scanners")
    if args.codeql_bundle is not None:
        command.extend(("--codeql-bundle", str(args.codeql_bundle.resolve())))
    return command


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        project, output = _validate(args)
        command = _command(args, project=project, output=output)
    except ValueError as error:
        _parser().error(str(error))
    print(f"Starting source-only security review for: {project}", flush=True)
    print(f"Reports will be written to: {output}", flush=True)
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        print("Source-only security review did not complete; inspect the report directory.",
              file=sys.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())

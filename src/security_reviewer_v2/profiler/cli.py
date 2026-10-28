"""CLI for local profiling; it never executes target code or scanners."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .artifact import create_saved_profile_artifact
from .discovery import ProfilingInputError
from .models import ProfilerLimits, ProfilerPolicy
from .reporting import render_markdown
from .review_gate import prompt_for_review
from .service import profile_project


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Profile a local project and build a scan plan")
    parser.add_argument("project_path", type=Path)
    parser.add_argument("--output", type=Path, help="Write JSON to this file instead of stdout")
    parser.add_argument(
        "--markdown-output",
        type=Path,
        help="Write a human-readable Markdown report; defaults beside --output",
    )
    parser.add_argument(
        "--review",
        action="store_true",
        help="Review the profile interactively before scanner execution",
    )
    parser.add_argument(
        "--review-decision-output",
        type=Path,
        help="Write the review decision JSON; defaults beside --output",
    )
    parser.add_argument("--max-files", type=int, default=10_000)
    parser.add_argument("--max-file-size", type=int, default=10 * 1024 * 1024)
    parser.add_argument("--max-content-read-bytes", type=int, default=64 * 1024)
    parser.add_argument("--max-manifest-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument(
        "--code-graph",
        action="store_true",
        help="Plan a Graphify code-graph enrichment task (pass 1; nothing is executed)",
    )
    parser.add_argument(
        "--code-graph-json",
        type=Path,
        help="Ingest an existing graph.json to refine the plan (pass 2)",
    )
    parser.add_argument("--max-depth", type=int, default=30)
    parser.add_argument("--max-content-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--large-component-files", type=int, default=750)
    parser.add_argument("--large-component-bytes", type=int, default=20 * 1024 * 1024)
    parser.add_argument("--sast-chunk-size", type=int, default=8)
    parser.add_argument(
        "--disable-scanner",
        action="append",
        default=[],
        choices=["semgrep-ce", "codeql-cli", "gitleaks", "trivy", "idor-dast"],
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    limits = ProfilerLimits(
        max_files=args.max_files,
        max_depth=args.max_depth,
        max_file_size_bytes=args.max_file_size,
        max_content_read_bytes=args.max_content_read_bytes,
        max_manifest_read_bytes=args.max_manifest_bytes,
        max_total_content_bytes=args.max_content_bytes,
        timeout_seconds=args.timeout,
    )
    enabled = tuple(
        scanner
        for scanner in ("semgrep-ce", "codeql-cli", "gitleaks", "trivy", "idor-dast")
        if scanner not in args.disable_scanner
    )
    policy = ProfilerPolicy(
        enabled_scanners=enabled,
        disabled_scanners=tuple(sorted(args.disable_scanner)),
        large_component_file_threshold=args.large_component_files,
        large_component_byte_threshold=args.large_component_bytes,
        sast_chunk_size=args.sast_chunk_size,
        enabled_enrichers=("graphify",) if args.code_graph else (),
    )
    try:
        result = profile_project(
            args.project_path,
            limits=limits,
            policy=policy,
            code_graph_path=args.code_graph_json,
        )
        artifact = create_saved_profile_artifact(
            result, args.project_path, limits=limits, policy=policy
        )
    except (ProfilingInputError, ValueError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2))
        return 2
    payload = json.dumps(artifact, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    markdown_output = args.markdown_output
    if markdown_output is None and args.output is not None:
        markdown_output = args.output.with_suffix(".md")
    if markdown_output is not None:
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(render_markdown(result), encoding="utf-8")
    if args.review:
        decision = prompt_for_review(result)
        decision_output = args.review_decision_output
        if decision_output is None and args.output is not None:
            decision_output = args.output.with_name(f"{args.output.stem}-review-decision.json")
        if decision_output is not None:
            decision_output.parent.mkdir(parents=True, exist_ok=True)
            decision_output.write_text(
                json.dumps(decision.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(f"Review decision: {decision.action.value} (scope: {decision.execution_scope})")
        if not decision.approved:
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

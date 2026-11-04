"""CLI for deterministic scanner finding normalization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .codeql import NormalizationInputError, normalize_codeql_sarif_file
from .gitleaks import normalize_gitleaks_json_file
from .idor import normalize_idor_json_file
from .semgrep import normalize_semgrep_json_file
from .trivy import normalize_trivy_json_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize scanner output into V2 findings"
    )
    parser.add_argument("input", type=Path, help="Scanner output input")
    parser.add_argument("output", type=Path, help="Normalized JSON output")
    parser.add_argument(
        "--scanner",
        choices=("codeql", "semgrep", "gitleaks", "trivy", "idor"),
        default="codeql",
        help="Input scanner format (default: codeql)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.scanner == "idor":
            result = normalize_idor_json_file(args.input)
        elif args.scanner == "semgrep":
            result = normalize_semgrep_json_file(args.input)
        elif args.scanner == "gitleaks":
            result = normalize_gitleaks_json_file(args.input)
        elif args.scanner == "trivy":
            result = normalize_trivy_json_file(args.input)
        else:
            result = normalize_codeql_sarif_file(args.input)
    except NormalizationInputError as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2))
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": result.status.value,
                "findings": result.summary.normalized_findings,
                "skipped": result.summary.skipped_results,
                "output": str(args.output),
            },
            indent=2,
        )
    )
    return 0 if result.status.value != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

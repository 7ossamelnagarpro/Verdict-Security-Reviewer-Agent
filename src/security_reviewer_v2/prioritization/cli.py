"""CLI for deterministic risk prioritization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.context import ContextArtifactError, load_context_result
from security_reviewer_v2.normalization import NormalizedArtifactError, load_merge_result

from .engine import prioritize_findings
from .models import RiskPolicy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prioritize merged security findings")
    parser.add_argument("merged_findings", type=Path)
    parser.add_argument("context", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--deep-review-threshold", type=int, default=65)
    parser.add_argument("--max-deep-reviews", type=int, default=20)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = prioritize_findings(
            load_merge_result(args.merged_findings),
            load_context_result(args.context),
            policy=RiskPolicy(
                deep_review_threshold=args.deep_review_threshold,
                max_deep_reviews=args.max_deep_reviews,
            ),
        )
    except (NormalizedArtifactError, ContextArtifactError, ValueError) as error:
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
                "ranked_findings": result.summary.ranked_findings,
                "selected_for_deep_review": result.summary.selected_for_deep_review,
                "queued_for_deep_review": result.summary.queued_for_deep_review,
                "standard_report": result.summary.standard_report,
                "needs_verification": result.summary.needs_verification,
                "output": str(args.output),
            },
            indent=2,
        )
    )
    return 0 if result.status.value != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

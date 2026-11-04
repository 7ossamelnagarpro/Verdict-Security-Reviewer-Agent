"""CLI for merging normalized scanner finding artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .merge import merge_normalized_findings
from .merge_models import DeduplicationPolicy
from .serialization import NormalizedArtifactError, load_normalization_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge and deduplicate normalized scanner findings"
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--line-tolerance", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        batches = tuple(load_normalization_result(path) for path in args.inputs)
        result = merge_normalized_findings(
            batches,
            policy=DeduplicationPolicy(line_tolerance=args.line_tolerance),
        )
    except (NormalizedArtifactError, ValueError) as error:
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
                "input_findings": result.summary.input_findings,
                "merged_findings": result.summary.merged_findings,
                "duplicates_collapsed": result.summary.duplicates_collapsed,
                "output": str(args.output),
            },
            indent=2,
        )
    )
    return 0 if result.status.value != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""CLI for collecting bounded source context for merged findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.normalization.serialization import (
    NormalizedArtifactError,
    load_merge_result,
)

from .collector import ContextCollectionError, collect_context
from .models import ContextPolicy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect source context for merged findings"
    )
    parser.add_argument("project_root", type=Path)
    parser.add_argument("merged_findings", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--profile",
        type=Path,
        help="saved profiler JSON with file inventory and hashes",
    )
    parser.add_argument("--window-before", type=int, default=4)
    parser.add_argument("--window-after", type=int, default=4)
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-total-bytes", type=int, default=5_000_000)
    parser.add_argument("--max-symbol-lines", type=int, default=120)
    parser.add_argument("--follow-symlinks", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        merged = load_merge_result(args.merged_findings)
        profile_artifact = (
            json.loads(args.profile.read_text(encoding="utf-8"))
            if args.profile
            else None
        )
        result = collect_context(
            merged,
            project_root=args.project_root,
            profile_artifact=profile_artifact,
            policy=ContextPolicy(
                window_before=args.window_before,
                window_after=args.window_after,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                max_symbol_lines=args.max_symbol_lines,
                follow_symlinks=args.follow_symlinks,
            ),
        )
    except (
        NormalizedArtifactError,
        ContextCollectionError,
        ValueError,
        OSError,
    ) as error:
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
                "contexts": result.summary.contexts_created,
                "evidence_locations": result.summary.evidence_locations,
                "files_read": result.summary.files_read,
                "unavailable_locations": result.summary.unavailable_locations,
                "output": str(args.output),
            },
            indent=2,
        )
    )
    stale = any(
        warning.startswith("source_changed_since_profile:")
        for warning in result.warnings
    )
    return 0 if result.status.value != "failed" and not stale else 1


if __name__ == "__main__":
    raise SystemExit(main())

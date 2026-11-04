"""Collect candidate context from an existing AI Discovery artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.discovery.serialization import (
    DiscoveryArtifactError,
    load_discovery_result,
)

from .candidate_collector import collect_candidate_context
from .collector import ContextCollectionError
from .models import ContextPolicy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect bounded source context for AI candidates"
    )
    parser.add_argument("project_root", type=Path)
    parser.add_argument("discovery_result", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--profile",
        type=Path,
        help="saved profiler JSON with file inventory and hashes",
    )
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-total-bytes", type=int, default=5_000_000)
    parser.add_argument("--max-symbol-lines", type=int, default=120)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        discovery = load_discovery_result(args.discovery_result)
        profile = (
            json.loads(args.profile.read_text(encoding="utf-8"))
            if args.profile
            else None
        )
        result = collect_candidate_context(
            discovery,
            project_root=args.project_root,
            profile_artifact=profile,
            policy=ContextPolicy(
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                max_symbol_lines=args.max_symbol_lines,
            ),
        )
    except (
        DiscoveryArtifactError,
        ContextCollectionError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, ensure_ascii=False))
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": result.status.value,
                "summary": result.to_dict()["summary"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return (
        0
        if result.status.value != "failed"
        and not any(
            warning.startswith("source_changed_since_profile:")
            for warning in result.warnings
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())

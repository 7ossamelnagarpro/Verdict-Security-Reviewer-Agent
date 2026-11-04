"""Combine a partial AI Discovery result with its completed continuation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.discovery.combine import combine_discovery_runs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("continuation", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = json.loads(args.base.read_text(encoding="utf-8"))
    continuation = json.loads(args.continuation.read_text(encoding="utf-8"))
    result = combine_discovery_runs(base, continuation)
    result["resumption"] = {
        "base": str(args.base),
        "continuation": str(args.continuation),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "targets": result["usage"]["targets"],
                "planned_targets": result["usage"]["planned_targets"],
                "candidates": len(result["candidates"]),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

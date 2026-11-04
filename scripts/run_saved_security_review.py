"""Run the Security Review Agent on a saved AI Discovery result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.discovery.models import (
    CandidateAnchor,
    CandidateDisposition,
    CandidateFinding,
    CandidateMissingCheck,
    DiscoveryResult,
    DiscoveryStatus,
)
from security_reviewer_v2.discovery.provider import provider_from_environment
from security_reviewer_v2.reviewers import run_security_review
from security_reviewer_v2.verification import verify_discovery


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("discovery", type=Path)
    parser.add_argument("--provider", default="ollama", choices=("ollama", "groq"))
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = json.loads(args.discovery.read_text(encoding="utf-8"))
    candidates = tuple(
        CandidateFinding(
            str(item.get("candidate_id", "")),
            str(item.get("title", "")),
            str(item.get("category", "unknown")),
            str(item.get("severity", "unknown")),
            str(item.get("confidence", "low")),
            item.get("path"),
            item.get("start_line"),
            item.get("end_line"),
            tuple(str(x) for x in item.get("evidence", [])),
            str(item.get("reasoning", "")),
            str(item.get("source", "ai_discovery")),
            CandidateDisposition(str(item.get("verification", "supported"))),
            tuple(str(x) for x in item.get("verification_notes", [])),
            CandidateAnchor(**item["entry_point"])
            if isinstance(item.get("entry_point"), dict)
            else None,
            CandidateAnchor(**item["sensitive_operation"])
            if isinstance(item.get("sensitive_operation"), dict)
            else None,
            CandidateMissingCheck(**item["missing_check"])
            if isinstance(item.get("missing_check"), dict)
            else None,
            tuple(str(x) for x in item.get("remaining_questions", [])),
        )
        for item in payload.get("candidates", [])
    )
    discovery = DiscoveryResult(
        "1.0",
        DiscoveryStatus(str(payload.get("status", "completed"))),
        str(payload.get("provider", args.provider)),
        payload.get("model", args.model),
        tuple(payload.get("scope", [])),
        candidates,
        tuple(payload.get("warnings", [])),
        tuple(payload.get("coverage_gaps", [])),
        payload.get("usage", {}),
    )
    verification = verify_discovery(discovery, project_root=args.project)
    provider = provider_from_environment(args.provider, args.model)
    review = run_security_review(
        discovery,
        verification,
        provider=provider,
        project_root=args.project,
        timeout_seconds=300,
        max_reviews=10,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {"verification": verification.to_dict(), "review": review.to_dict()},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": review.status,
                "reviews": len(review.reviews),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

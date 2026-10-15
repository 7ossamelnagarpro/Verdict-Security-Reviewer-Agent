"""Run real AI Discovery from saved, compatible pre-review artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.context import load_context_result
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.completion import required_discovery_satisfied
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.provider import provider_from_environment
from security_reviewer_v2.normalization import load_merge_result
from security_reviewer_v2.prioritization import prioritize_findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--merged", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider", choices=("ollama", "groq"), default="groq")
    parser.add_argument("--model", default=None)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--max-candidates", type=int, default=20)
    parser.add_argument("--max-context-chars", type=int, default=20_000)
    parser.add_argument("--max-batches", type=int, default=20)
    parser.add_argument("--max-planned-targets", type=int, default=128)
    parser.add_argument("--max-enrichment-rounds", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--target-id", action="append", default=None, help="rerun one or more IDs from the deterministic target plan")
    args = parser.parse_args()
    if args.model is None:
        args.model = "openai/gpt-oss-120b" if args.provider == "groq" else "qwen2.5-coder:7b"

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    merged = load_merge_result(args.merged)
    context = load_context_result(args.context)
    risk = prioritize_findings(merged, context)
    provider = provider_from_environment(args.provider, args.model)
    config = DiscoveryConfig(
        provider=args.provider,
        model=args.model,
        max_targets=args.batch_size,
        max_candidates=args.max_candidates,
        max_context_chars=args.max_context_chars,
        max_batches=args.max_batches,
        max_planned_targets=args.max_planned_targets,
        max_enrichment_rounds=args.max_enrichment_rounds,
        timeout_seconds=args.timeout_seconds,
    )
    result = DiscoveryAgent(provider, config).run(
        merged, context, risk, project_root=args.project.resolve(), profile_artifact=profile,
        on_batch=lambda batch: print(json.dumps({"batch": batch.batch_index, "status": batch.status,
            "targets": len(batch.target_ids), "candidates": batch.candidate_count,
            "provider_calls": batch.provider_calls, "usage": batch.usage}, ensure_ascii=False), flush=True),
        target_ids=tuple(args.target_id) if args.target_id is not None else None,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    satisfied = required_discovery_satisfied(result.to_dict())
    print(json.dumps({"status": result.status.value, "required_stage_satisfied": satisfied,
                      "planned_targets": result.usage["planned_targets"],
                      "inspected_targets": result.usage["targets"], "batches": len(result.batches),
                      "candidates": len(result.candidates), "context_exchanges": len(result.context_exchanges),
                      "output": str(args.output)}, ensure_ascii=False))
    return 0 if satisfied else 1


if __name__ == "__main__":
    raise SystemExit(main())

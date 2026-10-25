"""Review changed issue groups in a saved source-reverification derivative.

No target runtime, scanners, or AI Discovery are run. Existing model verdicts are reused
only when the issue group's complete source-ID tuple has not changed. The
provider is called for the remaining groups, and partial reviews stay partial.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

if __package__:
    from .reverify_saved_discovery import _attest_snapshot, _read_object
    from .run_saved_review_stages import _load_matching_reviews, _write
else:
    from reverify_saved_discovery import _attest_snapshot, _read_object
    from run_saved_review_stages import _load_matching_reviews, _write
from security_reviewer_v2.context import load_context_result
from security_reviewer_v2.context.candidate_collector import collect_candidate_context
from security_reviewer_v2.discovery.agent import reground_saved_discovery
from security_reviewer_v2.discovery.provider import provider_from_environment
from security_reviewer_v2.discovery.serialization import load_discovery_result
from security_reviewer_v2.normalization import load_merge_result
from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.reporting import write_final_report
from security_reviewer_v2.reviewers import run_security_review
from security_reviewer_v2.triage import triage_candidates
from security_reviewer_v2.verification import verify_discovery


def review_reverified(
    report_dir: Path, derivative_dir: Path, *, provider: Any, batch_size: int = 2,
) -> dict[str, Any]:
    if batch_size < 1:
        raise ValueError("Review batch size must be positive")
    report_dir = report_dir.resolve(strict=True)
    derivative_dir = derivative_dir.resolve(strict=True)
    if report_dir == derivative_dir or derivative_dir.is_relative_to(report_dir):
        raise ValueError("Review output must be a separate derivative directory")
    original = _read_object(report_dir / "pre-review-summary.json")
    postscan = _read_object(derivative_dir / "postscan-summary.json")
    if postscan.get("source_report") != str(report_dir) or postscan.get("source_sha256_attested") is not True:
        raise ValueError("Derivative is not an attested re-verification of this report")
    project_name = original.get("project")
    if original.get("status") != "completed" or not isinstance(project_name, str):
        raise ValueError("Source report is not a completed scan")
    project = Path(project_name).resolve(strict=True)
    if derivative_dir.is_relative_to(project):
        raise ValueError("Derivative must be outside the scanned source tree")
    profile = _read_object(report_dir / "profile.json")
    _attest_snapshot(project, profile)

    original_discovery = load_discovery_result(report_dir / "ai-discovery.json")
    merged = load_merge_result(report_dir / "merged.json")
    discovery = reground_saved_discovery(original_discovery, project_root=project,
                                           profile_artifact=profile)
    candidate_context = collect_candidate_context(discovery, project_root=project,
                                                   profile_artifact=profile)
    if candidate_context.summary.unavailable_locations:
        raise ValueError("Source context is no longer fully available")
    verification = verify_discovery(discovery, project_root=project,
                                    candidate_context=candidate_context)
    triage = triage_candidates(discovery, verification, merged, project_root=project)
    for filename, actual in (
        ("ai-discovery-regrounded.json", discovery.to_dict()),
        ("candidate-context.json", candidate_context.to_dict()),
        ("verification.json", verification.to_dict()),
        ("candidate-triage.json", triage.to_dict()),
    ):
        if _read_object(derivative_dir / filename) != actual:
            raise ValueError(f"Derivative evidence differs from current attested source: {filename}")

    original_reviews = _load_matching_reviews(report_dir / "security-review.json",
                                               provider.name, provider.model)
    resumed_reviews = _load_matching_reviews(derivative_dir / "security-review.json",
                                              provider.name, provider.model)
    prior_by_id = {item.candidate_id: item for item in (*original_reviews, *resumed_reviews)}
    scanner_context = load_context_result(report_dir / "context.json")
    review = run_security_review(
        discovery, verification, provider=provider, project_root=project,
        merged=merged, context=scanner_context, candidate_context=candidate_context,
        triage=triage, max_reviews=batch_size,
        prior_reviews=tuple(prior_by_id.values()),
        on_progress=lambda snapshot: _write(derivative_dir / "security-review.json",
                                            snapshot.to_dict()),
    )
    _attest_snapshot(project, profile)
    review_payload = review.to_dict()
    _write(derivative_dir / "security-review.json", review_payload)
    policy = evaluate_policy(review_payload, triage_payload=triage.to_dict(),
                             merged_payload=merged.to_dict(), verification_payload=verification.to_dict())
    _write(derivative_dir / "policy-gate.json", policy.to_dict())
    write_final_report(
        derivative_dir / "security-review-report.md", project=str(project),
        review=review_payload, policy=policy.to_dict(), triage=triage.to_dict(),
        verification=verification.to_dict(), discovery=discovery.to_dict(),
        discovery_required_satisfied=bool(original.get("ai_discovery", {}).get("satisfied")),
        merged=merged.to_dict(),
        docker_runtime=(original.get("docker_runtime")
                        if original.get("docker_runtime", {}).get("status") == "passed" else None),
        risk=_read_object(report_dir / "risk.json"),
        execution=_read_object(report_dir / "execution.json"),
        scanner_requirement=original.get("scanner_requirement"),
        coverage_gaps=original.get("coverage_gaps"),
    )
    result = {
        "status": "completed" if review.status == "completed" else "partial",
        "source_report": str(report_dir),
        "derivative_report": str(derivative_dir),
        "source_sha256_attested": True,
        "vm_scanner_and_discovery_calls": 0,
        "security_review": {
            "status": review.status,
            "reviewed_groups": len(review.reviews),
            "reused_groups": review.usage.get("reused_groups", 0),
            "new_provider_calls": review.usage.get("calls", 0),
            "pending_groups": len(review.pending_ids),
        },
        "policy_status": policy.status,
        "note": "Source grounding is not vulnerability confirmation; inspect verdicts and evidence before relying on policy decisions.",
    }
    _write(derivative_dir / "postscan-review-summary.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_dir", type=Path)
    parser.add_argument("derivative_dir", type=Path)
    parser.add_argument("--provider", choices=("groq", "ollama"), default="groq")
    parser.add_argument("--model", default="openai/gpt-oss-120b")
    parser.add_argument("--review-batch-size", type=int, default=2)
    args = parser.parse_args()
    provider = provider_from_environment(args.provider, args.model)
    result = review_reverified(args.report_dir, args.derivative_dir,
                               provider=provider, batch_size=args.review_batch_size)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

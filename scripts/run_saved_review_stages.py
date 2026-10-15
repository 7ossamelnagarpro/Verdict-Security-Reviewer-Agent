"""Continue a saved Discovery result through context, Verification and Triage.

The model is only contacted when --review is explicitly passed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_reviewer_v2.context import collect_candidate_context, load_context_result
from security_reviewer_v2.discovery.provider import provider_from_environment
from security_reviewer_v2.discovery.serialization import load_discovery_result
from security_reviewer_v2.normalization.serialization import load_merge_result
from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.profiler.artifact import validate_saved_profile_artifact
from security_reviewer_v2.reporting import write_final_report
from security_reviewer_v2.reviewers import ReviewItem, ReviewVerdict, run_security_review
from security_reviewer_v2.triage import triage_candidates
from security_reviewer_v2.test_environment.docker_runtime import load_docker_runtime
from security_reviewer_v2.verification import verify_discovery


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Continue saved AI Discovery without re-running scanners")
    parser.add_argument("project", type=Path)
    parser.add_argument("discovery", type=Path)
    parser.add_argument("merged", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--scanner-context", type=Path)
    parser.add_argument("--prior-review", type=Path,
                        help="reuse matching completed reviews from another report without modifying it")
    parser.add_argument("--re-review-id", action="append", default=[], metavar="GROUP_ID",
                        help="revisit only this saved review group; repeat for multiple groups")
    parser.add_argument("--docker-runtime-evidence", type=Path,
                        help="include saved Docker DAST evidence in the derived final report")
    parser.add_argument("--review", action="store_true", help="call the model for every eligible issue group")
    parser.add_argument("--provider", choices=("groq", "ollama"), default="groq")
    parser.add_argument("--model", default="openai/gpt-oss-120b")
    parser.add_argument("--review-batch-size", type=int, default=2)
    args = parser.parse_args(argv)
    if args.prior_review is not None and not args.prior_review.is_file():
        parser.error("--prior-review must point to an existing security-review.json")
    if args.re_review_id:
        if not args.review or args.prior_review is None:
            parser.error("--re-review-id requires --review and --prior-review")
        if args.output.exists():
            parser.error("targeted re-review requires a new output directory; saved reports are immutable")
        output_path = args.output.resolve()
        if (output_path.is_relative_to(args.project.resolve())
                or output_path.is_relative_to(args.prior_review.parent.resolve())):
            parser.error("targeted output must be outside the scanned project and source review")
    if args.docker_runtime_evidence is not None and not args.docker_runtime_evidence.is_file():
        parser.error("--docker-runtime-evidence must point to an existing JSON file")

    docker_runtime = None
    if args.docker_runtime_evidence is not None:
        try:
            saved_runtime = json.loads(args.docker_runtime_evidence.read_text(encoding="utf-8"))
            run_id = saved_runtime.get("run_id")
            docker_runtime = load_docker_runtime(
                run_id, project_root=args.project,
                repository_root=Path(__file__).resolve().parents[1],
            )
            if saved_runtime.get("app_sha256") != docker_runtime["app_sha256"]:
                raise ValueError("saved Docker evidence does not match the attested source")
        except (OSError, ValueError, AttributeError) as error:
            parser.error(f"Docker runtime evidence is not attested: {error}")

    discovery = load_discovery_result(args.discovery)
    merged = load_merge_result(args.merged)
    profile = json.loads(args.profile.read_text(encoding="utf-8")) if args.profile else None
    if profile is not None:
        try:
            validate_saved_profile_artifact(profile, args.project)
        except ValueError as error:
            parser.error(str(error))
    scanner_context = load_context_result(args.scanner_context) if args.scanner_context else None

    candidate_context = collect_candidate_context(discovery, project_root=args.project, profile_artifact=profile)
    if any(warning.startswith("source_changed_since_profile:") for warning in candidate_context.warnings):
        raise SystemExit("Source changed since profiling; stop and re-run profiling before review")
    verification = verify_discovery(discovery, project_root=args.project, candidate_context=candidate_context)
    triage = triage_candidates(discovery, verification, merged, project_root=args.project)

    targeted_prior_reviews = None
    if args.re_review_id:
        try:
            targeted_prior_reviews = _select_reviews_for_targeted_rereview(
                args.prior_review, args.provider, args.model, triage.groups,
                set(args.re_review_id),
            )
        except (OSError, ValueError) as error:
            parser.error(str(error))

    args.output.mkdir(parents=True, exist_ok=True)
    _write(args.output / "candidate-context.json", candidate_context.to_dict())
    _write(args.output / "verification.json", verification.to_dict())
    _write(args.output / "candidate-triage.json", triage.to_dict())

    summary = {"status": "completed", "candidate_context": candidate_context.status.value,
               "verification": {name: sum(record.disposition.value == name for record in verification.records)
                                for name in ("confirmed", "needs_more_evidence", "rejected")},
               "triage": triage.to_dict()["summary"], "review": "not_run"}
    if args.review:
        try:
            provider = provider_from_environment(args.provider, args.model)
            prior_path = args.prior_review or args.output / "security-review.json"
            saved_reviews = (targeted_prior_reviews if targeted_prior_reviews is not None
                             else _load_matching_reviews(prior_path, args.provider, args.model))
            review = run_security_review(
                discovery, verification, provider=provider, project_root=args.project,
                merged=merged, context=scanner_context, candidate_context=candidate_context,
                triage=triage, max_reviews=args.review_batch_size, prior_reviews=saved_reviews,
                deployment_context=(docker_runtime or {}).get("deployment_context"),
                on_progress=lambda snapshot: _write(args.output / "security-review.json", snapshot.to_dict()),
            )
            review_payload = review.to_dict()
        except (RuntimeError, ValueError) as error:
            review_payload = {"schema_version": "1.0", "status": "blocked", "provider": args.provider,
                              "model": args.model, "reviews": [], "pending_ids": [group.group_id for group in triage.groups],
                              "warnings": [str(error)], "usage": {"expected_groups": len(triage.groups),
                                                                     "reviewed_groups": 0, "calls": 0}}
        if profile is not None:
            validate_saved_profile_artifact(profile, args.project)
        _write(args.output / "security-review.json", review_payload)
        policy = evaluate_policy(review_payload, triage_payload=triage.to_dict())
        _write(args.output / "policy-gate.json", policy.to_dict())
        write_final_report(args.output / "security-review-report.md", project=str(args.project),
                           review=review_payload, policy=policy.to_dict(), triage=triage.to_dict(),
                           verification=verification.to_dict(), merged=merged.to_dict(),
                           docker_runtime=docker_runtime)
        summary["review"] = {"status": review_payload["status"], "reviewed": len(review_payload["reviews"]),
                             "pending": len(review_payload.get("pending_ids", []))}
        if args.re_review_id:
            summary["review"]["targeted_re_review_ids"] = sorted(set(args.re_review_id))
            summary["review"]["reused"] = len(targeted_prior_reviews)
        if review_payload["status"] != "completed":
            summary["status"] = "partial"
    _write(args.output / "stage-summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["status"] == "completed" else 1


def _write(path: Path, payload: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _load_matching_reviews(path: Path, provider: str, model: str) -> tuple[ReviewItem, ...]:
    if not path.is_file():
        return ()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("provider") != provider or payload.get("model") != model:
            return ()
        return tuple(ReviewItem(
            candidate_id=str(item["candidate_id"]), verdict=ReviewVerdict(item["verdict"]),
            severity=str(item["severity"]), confidence=str(item["confidence"]),
            title=str(item["title"]), explanation=str(item["explanation"]),
            impact=str(item["impact"]), remediation=str(item["remediation"]),
            evidence=tuple(str(value) for value in item["evidence"]),
            limitations=tuple(str(value) for value in item["limitations"]),
            source_ids=tuple(str(value) for value in item["source_ids"]),
        ) for item in payload.get("reviews", []))
    except (OSError, ValueError, TypeError, KeyError):
        return ()


def _select_reviews_for_targeted_rereview(
    path: Path, provider: str, model: str, groups: tuple, requested: set[str],
) -> tuple[ReviewItem, ...]:
    """Fail closed unless every untouched group has an exact saved review."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (payload.get("status") != "completed" or payload.get("provider") != provider
            or payload.get("model") != model):
        raise ValueError("targeted re-review requires a completed review from the same provider and model")
    expected = {group.group_id: tuple((*group.scanner_finding_ids, *group.candidate_ids))
                for group in groups}
    unknown = requested - expected.keys()
    if unknown:
        raise ValueError(f"unknown re-review group ID(s): {', '.join(sorted(unknown))}")
    saved = _load_matching_reviews(path, provider, model)
    saved_by_id = {item.candidate_id: item for item in saved}
    if (len(saved) != len(expected) or len(saved_by_id) != len(expected)
            or saved_by_id.keys() != expected.keys()
            or any(saved_by_id[group_id].source_ids != source_ids
                   for group_id, source_ids in expected.items())):
        raise ValueError("saved reviews no longer match all current issue groups; targeted re-review stopped")
    return tuple(item for item in saved if item.candidate_id not in requested)


if __name__ == "__main__":
    raise SystemExit(main())

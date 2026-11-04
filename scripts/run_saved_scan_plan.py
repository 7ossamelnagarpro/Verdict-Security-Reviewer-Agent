"""Execute a saved profiler scan plan without running later pipeline stages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.run_pre_review_pipeline import _build_registry
from security_reviewer_v2.orchestrator import OrchestratorPolicy, ScannerOrchestrator
from security_reviewer_v2.profiler.artifact import validate_saved_profile_artifact
from security_reviewer_v2.profiler.models import (
    Evidence,
    PlanStatus,
    PrerequisiteState,
    ScanPlan,
    ScanTask,
    ScanType,
)


def load_saved_plan(path: Path, *, project_root: Path) -> ScanPlan:
    """Restore typed tasks only after validating the saved project snapshot."""
    return load_saved_plan_with_fingerprint(path, project_root=project_root)[0]


def load_saved_plan_with_fingerprint(
    path: Path, *, project_root: Path
) -> tuple[ScanPlan, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    fingerprint = validate_saved_profile_artifact(payload, project_root)
    profile = payload["profile"]
    plan = payload["scan_plan"]
    if profile["root_name"] != project_root.name:
        raise ValueError("Saved profile root does not match the selected project")
    if profile["schema_version"] != plan["schema_version"]:
        raise ValueError("Saved profile and scan plan schema versions disagree")
    tasks = tuple(
        ScanTask(
            task_id=item["task_id"],
            scanner_id=item["scanner_id"],
            scan_type=ScanType(item["scan_type"]),
            component_id=item["component_id"],
            target_paths=tuple(item["target_paths"]),
            language_or_ecosystem=item["language_or_ecosystem"],
            mode=item["mode"],
            rule_references=tuple(item["rule_references"]),
            exclusions=tuple(item["exclusions"]),
            evidence=tuple(Evidence(**evidence) for evidence in item["evidence"]),
            reasons=tuple(item["reasons"]),
            prerequisites=tuple(item["prerequisites"]),
            prerequisite_status=PrerequisiteState(item["prerequisite_status"]),
            status=PlanStatus(item["status"]),
            resource_class=item.get("resource_class", "standard"),
        )
        for item in plan["tasks"]
    )
    scan_plan = ScanPlan(
        schema_version=plan["schema_version"],
        policy_version=plan["policy_version"],
        registry_version=plan["registry_version"],
        tasks=tasks,
        coverage_gaps=tuple(plan["coverage_gaps"]),
        warnings=tuple(plan["warnings"]),
    )
    return scan_plan, fingerprint


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run only the scanner-orchestration stage"
    )
    parser.add_argument("project", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--codeql-bundle", type=Path)
    parser.add_argument(
        "--resume-run-id", help="Resume this existing run; completed tasks are reused"
    )
    args = parser.parse_args()

    project = args.project.resolve()
    plan, fingerprint = load_saved_plan_with_fingerprint(
        args.profile.resolve(), project_root=project
    )
    bundle = args.codeql_bundle.resolve() if args.codeql_bundle else None
    registry = _build_registry(Path(__file__).resolve().parents[1], bundle)
    policy = OrchestratorPolicy(
        scanner_timeouts={
            "codeql-cli": 28800,
            "semgrep-ce": 3600,
            "gitleaks": 1800,
            "trivy": 3600,
        }
    )
    summary = ScannerOrchestrator(registry, policy=policy).execute(
        plan,
        project_root=project,
        runs_root=args.runs_root,
        run_id=args.resume_run_id,
        resume=bool(args.resume_run_id),
        input_fingerprint=fingerprint,
    )
    print(
        json.dumps(
            {
                "run_id": summary.run_id,
                "status": summary.status.value,
                "run_directory": str(args.runs_root.resolve() / summary.run_id),
                "tasks": [
                    {
                        "scanner": item.scanner_id,
                        "status": item.status.value,
                        "reason": item.reason,
                    }
                    for item in summary.tasks
                ],
                "coverage_gaps": list(summary.coverage_gaps),
            },
            indent=2,
        )
    )
    return 0 if summary.status.value == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

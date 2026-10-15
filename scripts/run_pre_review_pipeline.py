"""Run every pre-review stage and produce one auditable assessment bundle.

AI Discovery is required for a completed full scan. Scanner silence is never
treated as proof of safety.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import replace
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from security_reviewer_v2.context.collector import collect_context
from security_reviewer_v2.context.candidate_collector import collect_candidate_context
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.completion import required_discovery_satisfied
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.provider import provider_from_environment
from security_reviewer_v2.normalization.codeql import normalize_codeql_sarif_file
from security_reviewer_v2.normalization.gitleaks import normalize_gitleaks_json_file
from security_reviewer_v2.normalization.merge import merge_normalized_findings
from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file
from security_reviewer_v2.normalization.authorization import normalize_authorization_json_file
from security_reviewer_v2.normalization.semgrep import normalize_semgrep_json_file
from security_reviewer_v2.normalization.trivy import normalize_trivy_json_file
from security_reviewer_v2.orchestrator import OrchestratorPolicy, ScannerOrchestrator
from security_reviewer_v2.orchestrator.required_scanners import (
    AUTOMATIC_REQUIRED_SCANNERS,
    preflight_required_scanners,
    required_scanner_execution_failures,
)
from security_reviewer_v2.prioritization.engine import prioritize_findings
from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.profiler.artifact import create_saved_profile_artifact
from security_reviewer_v2.profiler.reporting import render_markdown
from security_reviewer_v2.scanners import AdapterRegistry
from security_reviewer_v2.scanners.models import ExecutionStatus
from security_reviewer_v2.verification import verify_discovery
from security_reviewer_v2.triage import triage_candidates
from security_reviewer_v2.reviewers import run_security_review
from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.reporting import write_final_report
from security_reviewer_v2.scanners.codeql import CodeQLAdapter, CodeQLConfig
from security_reviewer_v2.scanners.gitleaks import GitleaksAdapter, GitleaksConfig
from security_reviewer_v2.scanners.semgrep import SemgrepAdapter, SemgrepConfig
from security_reviewer_v2.scanners.trivy import TrivyAdapter, TrivyConfig
from security_reviewer_v2.scanners.web_runtime import RuntimeConfig, run_checks
from security_reviewer_v2.scanners.fixture_login_corroboration import corroborate_fixture_login
from security_reviewer_v2.test_environment import load_environment_spec, plan_environment
from security_reviewer_v2.test_environment.pilot_evidence import load_completed_pilot
from security_reviewer_v2.test_environment.isolated_runtime import load_isolated_runtime
from security_reviewer_v2.test_environment.docker_runtime import load_docker_runtime


def _which(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")


def _enrich_login_runtime_batch(normalized, source_facts):
    """Add fixture-only corroboration without changing any other finding."""
    if not source_facts:
        return normalized
    return replace(normalized, findings=tuple(
        replace(finding, runtime_evidence={
            **(finding.runtime_evidence or {}), **source_facts,
        }) if finding.rule_id == "web.missing-brute-force-protection"
        else finding for finding in normalized.findings))


def _build_registry(root: Path, bundle: Path | None) -> AdapterRegistry:
    adapters = []
    semgrep = _which("semgrep") or str(root / ".venv/Scripts/semgrep.exe")
    if Path(semgrep).is_file():
        adapters.append(SemgrepAdapter(SemgrepConfig(executable=str(Path(semgrep).resolve()))))
    gitleaks = _which("gitleaks")
    if not gitleaks:
        candidate = root.parent / "tools/gitleaks-v8.30.1/gitleaks.exe"
        gitleaks = str(candidate) if candidate.is_file() else None
    if gitleaks:
        adapters.append(GitleaksAdapter(GitleaksConfig(executable=str(Path(gitleaks).resolve()))))
    trivy = _which("trivy")
    if not trivy:
        candidate = root.parent / "tools/trivy-v0.75.0/trivy.exe"
        trivy = str(candidate) if candidate.is_file() else None
    if trivy:
        adapters.append(TrivyAdapter(TrivyConfig(executable=str(Path(trivy).resolve()))))
    if bundle and (bundle / "codeql.exe").is_file():
        suites = {}
        for language in ("python", "javascript", "typescript"):
            matches = list((bundle / "qlpacks/codeql").glob(f"{language}-queries/*/codeql-suites/{language}-security-extended.qls"))
            if matches:
                suites[language] = str(matches[0])
        adapters.append(CodeQLAdapter(CodeQLConfig(
            executable=str((bundle / "codeql.exe").resolve()), query_suites=suites,
            search_path=str(bundle / "qlpacks"), threads=2, ram_mb=3072,
            # Deep mode: effectively no practical timeout for a local run.
            extraction_timeout_seconds=14400, analysis_timeout_seconds=14400,
            default_paths_ignore=("node_modules/**", "**/node_modules/**", "dist/**", "**/dist/**", "build/**", "**/build/**", "coverage/**", "**/coverage/**", ".git/**", ".venv/**", "vendor/**", "**/*.min.js"),
        )))
    return AdapterRegistry(tuple(adapters))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the complete pre-review pipeline")
    parser.add_argument("project", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--runtime-url", default=None, help="authorized local runtime URL; defaults to SECURITY_REVIEWER_RUNTIME_URL when set")
    parser.add_argument("--require-dast", action="store_true",
                        help="fail before static scanning if no live runtime is available; an isolated health-smoke report does not count")
    parser.add_argument("--require-sast", action="store_true",
                        help="fail if neither Semgrep nor CodeQL completes a source scan")
    parser.add_argument("--require-all-scanners", action="store_true",
                        help="require Semgrep, CodeQL, Gitleaks, and Trivy to complete and normalize")
    parser.add_argument("--scanner-preflight-only", action="store_true",
                        help="check all four required scanner adapters without creating a report or running a VM")
    parser.add_argument("--runtime-auth", action="store_true", help="run two-account authorization probes; local lab only")
    parser.add_argument("--runtime-mutating", action="store_true", help="enable bounded stored-XSS and upload checks against an isolated test target")
    parser.add_argument("--authorization-checks", action="store_true", help="run the educational tt two-account authorization probe")
    parser.add_argument("--endpoint-coverage", action="store_true", help="collect endpoint and auth-matrix coverage when a runtime URL is supplied")
    parser.add_argument("--workflow-checks", action="store_true", help="run safe explicit checkout/coupon/review/upload workflow checks")
    parser.add_argument("--ai-discovery", action="store_true", help="legacy compatibility flag; AI Discovery is always required")
    parser.add_argument("--ai-provider", choices=("ollama", "groq"), default="groq")
    parser.add_argument("--ai-model", default=None, help="defaults to openai/gpt-oss-120b for Groq or qwen2.5-coder:7b for Ollama")
    parser.add_argument("--ai-max-targets", type=int, default=10, help="maximum targets per AI Discovery batch")
    parser.add_argument("--ai-max-batches", type=int, default=20)
    parser.add_argument("--ai-max-planned-targets", type=int, default=128)
    parser.add_argument("--ai-max-candidates", type=int, default=20, help="maximum candidates per provider response")
    parser.add_argument("--ai-max-enrichment-rounds", type=int, default=2)
    parser.add_argument("--ai-input-cost-per-million", type=float, default=None, help="optional caller-supplied USD rate for cost estimates")
    parser.add_argument("--ai-output-cost-per-million", type=float, default=None, help="optional caller-supplied USD rate for cost estimates")
    parser.add_argument("--review-max-findings", type=int, default=3, help="legacy name: maximum issue groups per model call, never a total-run cutoff")
    parser.add_argument("--codeql-bundle", type=Path)
    parser.add_argument("--test-environment-config", type=Path,
                        help="user-supplied environment configuration outside the target project; preflight only")
    parser.add_argument("--isolated-pilot-run-id", default=None,
                        help="attach a completed Security Lab Web VM health-smoke result; does not start a VM or run DAST")
    parser.add_argument("--isolated-runtime-run-id", default=None,
                        help="import completed, source-matched DAST results from the automatic networkless VM worker")
    parser.add_argument("--docker-runtime-run-id", default=None,
                        help="import completed, source-matched DAST results from the trusted educational Docker stack")
    args = parser.parse_args()
    if args.scanner_preflight_only:
        if not args.require_all_scanners:
            parser.error("--scanner-preflight-only requires --require-all-scanners")
        project = args.project.resolve()
        if not project.is_dir():
            parser.error(f"Project root is unavailable: {project}")
        registry = _build_registry(Path(__file__).resolve().parents[1],
                                   args.codeql_bundle.resolve() if args.codeql_bundle else None)
        failures = preflight_required_scanners(profile_project(project).scan_plan, registry,
                                               project_root=project)
        print(json.dumps({"status": "ready" if not failures else "blocked",
                          "required_scanners": AUTOMATIC_REQUIRED_SCANNERS,
                          "failures": failures}))
        return 0 if not failures else 1
    if args.output is None:
        parser.error("--output is required for a full scan")
    if args.ai_model is None:
        args.ai_model = "openai/gpt-oss-120b" if args.ai_provider == "groq" else "qwen2.5-coder:7b"
    # Runtime checks are part of every full scan when the caller has declared
    # an authorized target.  We still require an explicit URL (or environment
    # variable) so a source-only project is never probed accidentally.
    runtime_url = args.runtime_url or __import__("os").environ.get("SECURITY_REVIEWER_RUNTIME_URL")
    if args.isolated_pilot_run_id and runtime_url:
        parser.error("An isolated pilot result has no host runtime URL; run live DAST separately without --isolated-pilot-run-id")
    if sum(bool(item) for item in (runtime_url, args.isolated_pilot_run_id,
                                  args.isolated_runtime_run_id, args.docker_runtime_run_id)) > 1:
        parser.error("Import one runtime source at a time: VM DAST, Docker DAST, live URL, or historical health pilot")
    if (args.isolated_runtime_run_id or args.docker_runtime_run_id) and (
        args.runtime_mutating or args.runtime_auth or args.authorization_checks or
        args.endpoint_coverage or args.workflow_checks
    ):
        parser.error("Select runtime checks when creating the worker; host URL check flags do not apply to saved DAST")
    if args.require_dast and not (runtime_url or args.isolated_runtime_run_id or args.docker_runtime_run_id):
        parser.error("DAST is required but no live URL or completed runtime run was supplied; a health check is not DAST")
    try:
        provider = provider_from_environment(args.ai_provider, args.ai_model)
    except (RuntimeError, ValueError) as error:
        parser.error(f"AI Discovery is required for every full scan: {error}")
    project = args.project.resolve()
    repository_root = Path(__file__).resolve().parents[1]
    isolated_pilot_payload = None
    isolated_runtime_payload = None
    docker_runtime_payload = None
    if args.isolated_pilot_run_id:
        try:
            isolated_pilot_payload = load_completed_pilot(
                args.isolated_pilot_run_id, project_root=project,
                repository_root=repository_root,
            )
        except (OSError, ValueError) as error:
            parser.error(f"Invalid isolated pilot evidence: {error}")
    if args.isolated_runtime_run_id:
        try:
            isolated_runtime_payload = load_isolated_runtime(
                args.isolated_runtime_run_id, project_root=project,
                repository_root=repository_root,
            )
        except (OSError, ValueError) as error:
            parser.error(f"Invalid isolated VM DAST evidence: {error}")
    if args.docker_runtime_run_id:
        try:
            docker_runtime_payload = load_docker_runtime(
                args.docker_runtime_run_id, project_root=project,
                repository_root=repository_root,
            )
        except (OSError, ValueError) as error:
            parser.error(f"Invalid trusted Docker DAST evidence: {error}")
    saved_runtime_payload = isolated_runtime_payload or docker_runtime_payload
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if isolated_pilot_payload is not None:
        _write(output / "isolated-pilot-evidence.json", isolated_pilot_payload)
    if isolated_runtime_payload is not None:
        _write(output / "isolated-runtime-evidence.json", isolated_runtime_payload)
    if docker_runtime_payload is not None:
        _write(output / "docker-runtime-evidence.json", docker_runtime_payload)
    profile_result = profile_project(project)
    profile_artifact = create_saved_profile_artifact(profile_result, project)
    _write(output / "profile.json", profile_artifact)
    (output / "profile.md").write_text(render_markdown(profile_result), encoding="utf-8")
    environment_plan_payload = None
    if args.test_environment_config:
        try:
            environment_spec = load_environment_spec(args.test_environment_config, project_root=project)
            environment_plan_payload = plan_environment(
                environment_spec, project_root=project, profile=profile_result,
            ).to_dict()
        except (OSError, ValueError) as error:
            environment_plan_payload = {"schema_version": "1.0", "status": "blocked",
                                        "missing": [f"Invalid test-environment configuration: {error}"],
                                        "warnings": [], "evidence": []}
        _write(output / "test-environment-plan.json", environment_plan_payload)

    registry = _build_registry(Path(__file__).resolve().parents[1], args.codeql_bundle.resolve() if args.codeql_bundle else None)
    if args.require_all_scanners:
        failures = preflight_required_scanners(profile_result.scan_plan, registry, project_root=project)
        if failures:
            raise SystemExit("Required scanner preflight failed: " + "; ".join(failures))
    run_id = "static-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    execution = ScannerOrchestrator(registry, policy=OrchestratorPolicy(scanner_timeouts={"codeql-cli": 28800, "semgrep-ce": 3600, "gitleaks": 1800, "trivy": 3600})).execute(profile_result.scan_plan, project_root=project, runs_root=output / "runs", run_id=run_id, input_fingerprint=profile_artifact["project_snapshot"]["fingerprint"])
    _write(output / "execution.json", execution.to_dict())
    if args.require_sast and not args.require_all_scanners and not any(
        task.scanner_id in {"semgrep-ce", "codeql-cli"} and task.status == ExecutionStatus.COMPLETED
        for task in execution.tasks
    ):
        raise SystemExit("SAST was required but neither Semgrep nor CodeQL completed a source scan")
    normalizers = {"codeql-cli": normalize_codeql_sarif_file, "semgrep-ce": normalize_semgrep_json_file, "gitleaks": normalize_gitleaks_json_file, "trivy": normalize_trivy_json_file}
    batches = []
    normalized_task_ids: set[str] = set()
    for task in execution.tasks:
        normalizer = normalizers.get(task.scanner_id)
        if not normalizer:
            continue
        task_normalized = bool(task.raw_outputs)
        for raw in task.raw_outputs:
            source = output / "runs" / run_id / raw
            try:
                batch = normalizer(source)
            except Exception as error:
                task_normalized = False
                execution_warning = {"scanner": task.scanner_id, "path": str(source), "error": type(error).__name__}
                _write(output / f"{task.scanner_id}-normalization-error.json", execution_warning)
                continue
            batches.append(batch)
            _write(output / f"{task.scanner_id}-normalized.json", batch.to_dict())
        if task_normalized:
            normalized_task_ids.add(task.task_id)
    scanner_failures = (required_scanner_execution_failures(
        execution, normalized_task_ids=normalized_task_ids)
        if args.require_all_scanners else ())
    scanners_satisfied = not scanner_failures
    if saved_runtime_payload is not None:
        for source_name, normalizer, normalized_name in (
            ("runtime.json", normalize_runtime_json_file, "runtime-normalized.json"),
            ("authorization.json", normalize_authorization_json_file, "authorization-normalized.json"),
        ):
            staged_output = output / source_name
            shutil.copy2(saved_runtime_payload["result_paths"][source_name], staged_output)
            normalized = normalizer(staged_output)
            if source_name == "runtime.json":
                raw_runtime = json.loads(staged_output.read_text(encoding="utf-8"))
                source_facts = corroborate_fixture_login(
                    project, raw_runtime, str(saved_runtime_payload["app_sha256"]))
                _write(output / "login-source-corroboration.json", {
                    "status": "supported" if source_facts else "inconclusive",
                    "facts": source_facts or {},
                    "scope": "isolated_security_lab_web_only",
                })
                normalized = _enrich_login_runtime_batch(normalized, source_facts)
            batches.append(normalized)
            _write(output / normalized_name, normalized.to_dict())
    if runtime_url:
        runtime_path = output / "runtime.json"
        runtime_result = run_checks(RuntimeConfig(runtime_url, runtime_path, mutating=args.runtime_mutating))
        if args.require_dast and (runtime_result.get("status") != "completed" or not runtime_result.get("results")):
            raise SystemExit("DAST was required but runtime checks did not complete with probe results")
        runtime_batch = normalize_runtime_json_file(runtime_path)
        batches.append(runtime_batch)
        _write(output / "runtime-normalized.json", runtime_batch.to_dict())
        if args.authorization_checks:
            authorization_path = output / "authorization.json"
            authorization_script = Path(__file__).with_name("scan_tt_authorization.py")
            authorization_run = subprocess.run(
                [sys.executable, str(authorization_script), "--base-url", runtime_url, "--output", str(authorization_path)],
                check=False, capture_output=True, text=True,
            )
            if authorization_run.returncode == 0 and authorization_path.is_file():
                authorization_batch = normalize_authorization_json_file(authorization_path)
                batches.append(authorization_batch)
                _write(output / "authorization-normalized.json", authorization_batch.to_dict())
            else:
                _write(output / "authorization-error.json", {"returncode": authorization_run.returncode, "stderr": authorization_run.stderr[-4000:]})
        if args.runtime_auth:
            auth_path = output / "runtime-auth.json"
            auth_script = Path(__file__).with_name("scan_juice_shop_auth_runtime.py")
            completed = subprocess.run(
                [sys.executable, str(auth_script), "--base-url", runtime_url, "--output", str(auth_path)],
                check=False, capture_output=True, text=True,
            )
            if completed.returncode == 0 and auth_path.is_file():
                auth_batch = normalize_runtime_json_file(auth_path)
                batches.append(auth_batch)
                _write(output / "runtime-auth-normalized.json", auth_batch.to_dict())
            else:
                _write(output / "runtime-auth-error.json", {"returncode": completed.returncode, "stderr": completed.stderr[-4000:]})
        coverage_payload = None
        if args.endpoint_coverage and (project / "swagger.yml").is_file():
            coverage_path = output / "endpoint-coverage.json"
            coverage_script = Path(__file__).with_name("scan_juice_shop_coverage.py")
            coverage_args = [sys.executable, str(coverage_script), "--base-url", runtime_url,
                             "--project", str(project), "--output", str(coverage_path)]
            if args.runtime_auth:
                coverage_args.append("--with-test-users")
            if args.workflow_checks:
                coverage_args.append("--workflows")
            coverage_run = subprocess.run(coverage_args, check=False, capture_output=True, text=True)
            if coverage_run.returncode == 0 and coverage_path.is_file():
                coverage_payload = json.loads(coverage_path.read_text(encoding="utf-8"))
            else:
                coverage_payload = {"status": "failed", "error": coverage_run.stderr[-4000:]}
        elif args.endpoint_coverage:
            coverage_payload = {"status": "not_applicable", "reason": "No supported OpenAPI project descriptor was found."}
        else:
            coverage_payload = {"status": "not_run", "reason": "Pass --endpoint-coverage to collect endpoint coverage."}
    elif saved_runtime_payload is not None:
        coverage_payload = {"status": "isolated_completed" if isolated_runtime_payload else "docker_completed",
                            "probe_count": sum(saved_runtime_payload["probe_counts"].values()),
                            "coverage_gaps": saved_runtime_payload["limitations"]}
    else:
        coverage_payload = {"status": "not_run", "reason": "No runtime URL supplied; set SECURITY_REVIEWER_RUNTIME_URL or pass --runtime-url."}
    merged = merge_normalized_findings(tuple(batches))
    _write(output / "merged.json", merged.to_dict())
    context = collect_context(merged, project_root=project, profile_artifact=profile_artifact)
    _write(output / "context.json", context.to_dict())
    if any(warning.startswith("source_changed_since_profile:") for warning in context.warnings):
        raise SystemExit("Source files changed since profiling; rerun the pipeline before risk or AI review")
    risk = prioritize_findings(merged, context)
    _write(output / "risk.json", risk.to_dict())
    try:
        discovery = DiscoveryAgent(provider, DiscoveryConfig(provider=args.ai_provider, model=args.ai_model, max_targets=args.ai_max_targets,
            max_batches=args.ai_max_batches, max_planned_targets=args.ai_max_planned_targets,
            max_candidates=args.ai_max_candidates, max_enrichment_rounds=args.ai_max_enrichment_rounds,
            input_cost_per_million_tokens_usd=args.ai_input_cost_per_million,
            output_cost_per_million_tokens_usd=args.ai_output_cost_per_million)).run(
                merged, context, risk, project_root=project, profile_artifact=profile_artifact,
                additional_coverage_gaps=tuple(execution.coverage_gaps) + tuple(coverage_payload.get("coverage_gaps", ())))
    except (RuntimeError, ValueError) as error:
        _write(output / "ai-discovery.json", {"schema_version": "1.0", "status": "blocked", "provider": args.ai_provider,
                                              "model": args.ai_model, "candidates": [], "usage": {}, "batches": [],
                                              "warnings": [str(error)]})
        discovery = None
    discovery_payload = discovery.to_dict() if discovery is not None else json.loads((output / "ai-discovery.json").read_text(encoding="utf-8"))
    discovery_usage = discovery_payload.get("usage") or {}
    discovery_batches = discovery_payload.get("batches") or []
    failed_discovery_batches = sum(batch.get("status") != "completed" for batch in discovery_batches)
    discovery_satisfied = required_discovery_satisfied(discovery_payload)
    if discovery is not None:
        _write(output / "ai-discovery.json", discovery_payload)
        candidate_context = collect_candidate_context(discovery, project_root=project, profile_artifact=profile_artifact)
        candidate_context_payload = candidate_context.to_dict()
        _write(output / "candidate-context.json", candidate_context_payload)
        if any(warning.startswith("source_changed_since_profile:") for warning in candidate_context.warnings):
            raise SystemExit("Source files changed since profiling; rerun the pipeline before AI review")
    else:
        candidate_context_payload = {"schema_version": "1.0", "status": "not_run", "candidates": [], "warnings": ["AI Discovery did not produce a result."]}
        _write(output / "candidate-context.json", candidate_context_payload)
    if discovery is not None:
        verification = verify_discovery(discovery, project_root=project, candidate_context=candidate_context)
        verification_payload = verification.to_dict()
        triage = triage_candidates(discovery, verification, merged, project_root=project)
        triage_payload = triage.to_dict()
    else:
        verification_payload = {"schema_version": "1.0", "status": "not_run", "project_root": str(project), "records": [], "warnings": ["AI Discovery did not produce a result; verification was not run."]}
        triage_payload = {"schema_version": "1.0", "status": "not_run", "groups": [], "records": [], "warnings": ["AI Discovery did not produce a result; candidate triage was not run."]}
    _write(output / "verification.json", verification_payload)
    _write(output / "candidate-triage.json", triage_payload)
    verification_records = verification_payload.get("records", [])
    if discovery is not None and discovery_satisfied:
        selected_ids = {item.merged_finding_id for item in risk.findings if item.selected_for_deep_review}
        ordered_groups = tuple(sorted(triage.groups, key=lambda group: not any(
            source_id in selected_ids for source_id in group.scanner_finding_ids)))
        review_triage = replace(triage, groups=ordered_groups)
        review_result = run_security_review(discovery, verification, provider=provider, project_root=project,
                                            merged=merged, context=context, candidate_context=candidate_context,
                                            triage=review_triage, timeout_seconds=None,
                                            deployment_context=(docker_runtime_payload or {}).get("deployment_context"),
                                            max_reviews=max(1, args.review_max_findings))
        review_payload = review_result.to_dict()
    else:
        review_payload = {"schema_version": "1.0", "status": "not_run", "provider": None, "model": None, "reviews": [], "warnings": ["Security Review Agent was not run because required AI Discovery did not complete its planned inspection."], "usage": {}}
    _write(output / "security-review.json", review_payload)
    policy_result = evaluate_policy(review_payload, triage_payload=triage_payload)
    policy_payload = policy_result.to_dict()
    _write(output / "policy-gate.json", policy_payload)
    review_satisfied = (review_payload.get("status") == "completed" and
                        not review_payload.get("pending_ids"))
    pilot_coverage_gap = (
        "Isolated VM pilot checked local health only; no in-VM vulnerability scan or host-accessible DAST endpoint was provided.",
    ) if isolated_pilot_payload is not None else ()
    coverage_gaps = sorted(set(profile_result.profile.coverage_gaps + execution.coverage_gaps +
                               merged.coverage_gaps + risk.coverage_gaps + pilot_coverage_gap +
                               scanner_failures +
                               (tuple(saved_runtime_payload["limitations"])
                                if saved_runtime_payload is not None else ())))
    scanner_requirement = {"requested": args.require_all_scanners,
                           "required": list(AUTOMATIC_REQUIRED_SCANNERS) if args.require_all_scanners else [],
                           "satisfied": scanners_satisfied,
                           "failures": list(scanner_failures)}
    write_final_report(output / "security-review-report.md", project=str(project), review=review_payload,
                       policy=policy_payload, triage=triage_payload, verification=verification_payload,
                       discovery=discovery_payload, discovery_required_satisfied=discovery_satisfied,
                       isolated_pilot=isolated_pilot_payload,
                       isolated_runtime=isolated_runtime_payload,
                       docker_runtime=docker_runtime_payload,
                       merged=merged.to_dict(), risk=risk.to_dict(),
                       execution=execution.to_dict(), scanner_requirement=scanner_requirement,
                       coverage_gaps=coverage_gaps)
    report = {"status": "completed" if discovery_satisfied and scanners_satisfied and review_satisfied else "partial", "pre_review": review_payload.get("status") == "not_run",
              "review_agent_ran": bool(review_payload.get("usage", {}).get("calls")),
              "project": str(project), "adapter_ids": registry.scanner_ids(),
              "test_environment": environment_plan_payload or {"status": "not_requested"},
              "dast_requirement": {"requested": args.require_dast,
                                   "satisfied": (bool(runtime_url) or saved_runtime_payload is not None)
                                                and coverage_payload.get("status") != "failed"},
              "sast_requirement": {"requested": args.require_sast,
                                   "satisfied": any(task.scanner_id in {"semgrep-ce", "codeql-cli"}
                                                    and task.status == ExecutionStatus.COMPLETED
                                                    for task in execution.tasks)},
              "scanner_requirement": scanner_requirement,
              "isolated_pilot": isolated_pilot_payload or {"status": "not_requested"},
              "isolated_runtime": isolated_runtime_payload or {"status": "not_requested"},
              "docker_runtime": docker_runtime_payload or {"status": "not_requested"},
              "execution": execution.to_dict(), "merge_summary": asdict(merged.summary),
              "endpoint_coverage": {"status": coverage_payload.get("status"),
                                     "endpoint_count": coverage_payload.get("endpoint_count"),
                                     "probe_count": coverage_payload.get("probe_count"),
                                     "probed_count": sum(1 for item in coverage_payload.get("matrix", []) if item.get("status") == "probed") if isinstance(coverage_payload, dict) else None,
                                     "authentication": coverage_payload.get("authentication") if isinstance(coverage_payload, dict) else None,
                                     "workflows": coverage_payload.get("workflows") if isinstance(coverage_payload, dict) else None,
                                     "coverage_gaps": coverage_payload.get("coverage_gaps", []) if isinstance(coverage_payload, dict) else []},
              "ai_discovery": {"required": True, "satisfied": discovery_satisfied,
                               "status": discovery_payload.get("status"),
                               "provider": discovery_payload.get("provider"),
                               "model": discovery_payload.get("model"),
                               "provider_calls": discovery_usage.get("provider_calls", 0),
                               "planned_targets": discovery_usage.get("planned_targets", 0),
                               "inspected_targets": discovery_usage.get("targets", 0),
                               "failed_batches": failed_discovery_batches,
                               "candidate_count": len(discovery_payload.get("candidates", [])),
                               "supported_candidates": sum(1 for item in discovery_payload.get("candidates", []) if item.get("verification") == "supported"),
                               "coverage_gaps": discovery_payload.get("coverage_gaps", []),
                               "warnings": discovery_payload.get("warnings", [])},
              "candidate_context": {"status": candidate_context_payload.get("status"),
                                    "summary": candidate_context_payload.get("summary"),
                                    "coverage_gaps": candidate_context_payload.get("coverage_gaps", []),
                                    "warnings": candidate_context_payload.get("warnings", [])},
              "verification": {"status": verification_payload.get("status"),
                                "record_count": len(verification_records),
                                "confirmed": sum(1 for item in verification_records if item.get("disposition") == "confirmed"),
                                "needs_more_evidence": sum(1 for item in verification_records if item.get("disposition") == "needs_more_evidence"),
                                "rejected": sum(1 for item in verification_records if item.get("disposition") == "rejected"),
                                "warnings": verification_payload.get("warnings", [])},
              "candidate_triage": {"status": triage_payload.get("status"),
                                   "summary": triage_payload.get("summary"),
                                   "warnings": triage_payload.get("warnings", [])},
              "security_review": {"status": review_payload.get("status"),
                                  "satisfied": review_satisfied,
                                  "provider": review_payload.get("provider"),
                                   "model": review_payload.get("model"),
                                   "review_count": len(review_payload.get("reviews", [])),
                                   "pending_ids": review_payload.get("pending_ids", []),
                                   "warnings": review_payload.get("warnings", [])},
              "policy_gate": {"status": policy_payload.get("status"),
                              "blocking": policy_payload.get("blocking"),
                              "decision_count": len(policy_payload.get("decisions", [])),
                              "warnings": policy_payload.get("warnings", [])},
              "context_summary": asdict(context.summary), "risk_summary": asdict(risk.summary),
              "coverage_gaps": coverage_gaps,
              "limitations": (["Required AI Discovery did not inspect every planned target successfully; this scan is incomplete."]
                              if not discovery_satisfied else [])
                             + (["One or more required scanners did not complete with normalized output; this scan is incomplete."]
                                if not scanners_satisfied else [])
                             + (["Security review is incomplete; pending issue groups are not cleared."]
                              if review_payload.get("status") != "completed" else [])
                             + ["Scanner silence is not proof of safety."]
                             + (["Runtime checks require an authorized target URL."]
                                if saved_runtime_payload is None else [])
                             + (["Mutating workflows remain opt-in and are not executed by this run."]
                                if saved_runtime_payload is None or
                                not saved_runtime_payload["mutating_checks_enabled"] else
                                ["Only the bounded stored-XSS and upload probes were enabled; other mutating workflows were not executed."])
                             + (isolated_pilot_payload["limitations"] if isolated_pilot_payload is not None else [])
                             + (saved_runtime_payload["limitations"] if saved_runtime_payload is not None else [])}
    _write(output / "pre-review-summary.json", report)
    print(json.dumps({"status": report["status"], "ai_discovery_satisfied": discovery_satisfied,
                      "required_scanners_satisfied": scanners_satisfied,
                      "security_review_satisfied": review_satisfied,
                      "adapters": registry.scanner_ids(), "merged_findings": merged.summary.merged_findings,
                      "coverage_gaps": len(report["coverage_gaps"]), "output": str(output)}))
    return 0 if discovery_satisfied and scanners_satisfied and review_satisfied else 1


if __name__ == "__main__":
    raise SystemExit(main())

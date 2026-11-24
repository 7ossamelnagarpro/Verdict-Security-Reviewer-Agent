"""LangGraph orchestration for the evidence-grounded AI review stages.

The scanner and evidence implementations remain ordinary Python functions. The
graph makes stage order and the two failure routes explicit; no credentials or
provider objects are placed in graph state or persisted as checkpoints.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from security_reviewer_v2.context import CandidateContextResult, ContextResult, collect_candidate_context
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.completion import required_discovery_satisfied
from security_reviewer_v2.discovery.models import DiscoveryConfig, DiscoveryResult
from security_reviewer_v2.dynamic_penetration_agent import ExecutionBudget, RuntimeAccess
from security_reviewer_v2.dynamic_penetration_agent.agent import run_penetration_tests
from security_reviewer_v2.normalization.merge_models import MergeResult
from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.prioritization.models import RiskResult
from security_reviewer_v2.triage import TriageResult, triage_candidates
from security_reviewer_v2.verification import VerificationResult, verify_discovery
from security_reviewer_v2.verification.models import VerificationDisposition, VerificationRecord


class AgentReviewState(TypedDict, total=False):
    """Per-run stage results. A graph invocation starts with an empty state."""

    discovery: DiscoveryResult | None
    discovery_payload: dict[str, Any]
    discovery_satisfied: bool
    candidate_context: CandidateContextResult
    candidate_context_payload: dict[str, Any]
    verification: VerificationResult
    verification_payload: dict[str, Any]
    penetration_test_payload: dict[str, Any]
    triage: TriageResult
    triage_payload: dict[str, Any]
    review_payload: dict[str, Any]
    policy_payload: dict[str, Any]


def run_agent_review_graph(
    *,
    provider: Any,
    review_provider: Any = None,
    discovery_config: DiscoveryConfig,
    project_root: Path,
    profile_artifact: dict[str, Any],
    merged: MergeResult,
    context: ContextResult,
    risk: RiskResult,
    additional_coverage_gaps: tuple[str, ...],
    deployment_context: dict[str, Any] | None,
    max_reviews: int,
    write_artifact: Callable[[str, dict[str, Any]], None],
    review_runner: Callable[..., Any],
    penetration_access: RuntimeAccess | None = None,
    penetration_target_resolver: Callable[[Any], str | None] | None = None,
    penetration_budget: ExecutionBudget | None = None,
    penetration_transport: Any = None,
) -> AgentReviewState:
    """Run Discovery through Policy Gate using the existing stage implementations.

    Artifacts are written as each node finishes, so a failed later node does not
    erase earlier evidence. The graph itself has no persistent checkpointer:
    source evidence and provider credentials must not enter a checkpoint store.

    The optional ``dynamic_penetration_agent`` node (section 2 of the design) runs between
    ``verification`` and ``candidate_triage`` *only* when both ``penetration_access`` (the isolated
    second Docker stack's base URL, its allowlisted routes, and its Runtime Contract accounts) and
    ``penetration_target_resolver`` are supplied by the caller. With neither supplied (the default),
    this node is skipped and the graph is exactly the previous ``verification -> candidate_triage``
    edge — no existing behavior, test, or security control changes for a caller that does not opt in.
    The agent itself never gets network access beyond what ``penetration_access`` names: it reaches the
    target only through ``scanners.runtime_workflows`` (the same bounded, non-mutating HTTP executor the
    existing DAST stage uses), via the allowlisted routes and the Runtime Contract's own accounts.
    """

    def discovery_node(_state: AgentReviewState) -> AgentReviewState:
        try:
            discovery = DiscoveryAgent(provider, discovery_config).run(
                merged, context, risk, project_root=project_root,
                profile_artifact=profile_artifact,
                additional_coverage_gaps=additional_coverage_gaps,
            )
            payload = discovery.to_dict()
        except (RuntimeError, ValueError) as error:
            discovery = None
            payload = {
                "schema_version": "1.0", "status": "blocked",
                "provider": discovery_config.provider, "model": discovery_config.model,
                "candidates": [], "usage": {}, "batches": [], "warnings": [str(error)],
            }
        write_artifact("ai-discovery.json", payload)
        return {
            "discovery": discovery,
            "discovery_payload": payload,
            "discovery_satisfied": required_discovery_satisfied(payload),
        }

    def candidate_context_node(state: AgentReviewState) -> AgentReviewState:
        result = collect_candidate_context(
            state["discovery"], project_root=project_root,
            profile_artifact=profile_artifact,
        )
        payload = result.to_dict()
        write_artifact("candidate-context.json", payload)
        if any(warning.startswith("source_changed_since_profile:") for warning in result.warnings):
            raise SystemExit("Source files changed since profiling; rerun the pipeline before AI review")
        return {"candidate_context": result, "candidate_context_payload": payload}

    def verification_node(state: AgentReviewState) -> AgentReviewState:
        result = verify_discovery(
            state["discovery"], project_root=project_root,
            candidate_context=state["candidate_context"],
        )
        payload = result.to_dict()
        write_artifact("verification.json", payload)
        return {"verification": result, "verification_payload": payload}

    def penetration_node(state: AgentReviewState) -> AgentReviewState:
        from security_reviewer_v2.agents.tracing import node_trace

        confirmed = sum(1 for record in getattr(state["verification"], "records", ())
                        if getattr(record, "disposition", None) is VerificationDisposition.CONFIRMED)
        # A named, visible span in LangSmith for this node specifically: it makes no model calls of its
        # own (pure Python), so without this it would otherwise leave nothing of its own in the trace
        # tree beyond whatever the bare graph invocation shows. No-ops when tracing is off.
        with node_trace("dynamic_penetration_agent",
                        inputs={"candidates_confirmed_by_verification": confirmed,
                                "configured": penetration_access is not None}) as run:
            # Opt-in only (see the docstring above); still a no-op when the caller forgot the resolver.
            if penetration_access is None or penetration_target_resolver is None:
                payload = {"schema_version": "1.0", "status": "not_run", "results": [], "usage": {},
                          "warnings": ["dynamic_penetration_agent was not configured for this run."]}
                write_artifact("dynamic-penetration-test.json", payload)
                if run is not None:
                    run.end(outputs={"status": "not_run"})
                return {"penetration_test_payload": payload}

            report = run_penetration_tests(
                state["discovery"], state["verification"], access=penetration_access,
                target_endpoint_resolver=penetration_target_resolver, budget=penetration_budget,
                transport=penetration_transport,
            )
            payload = report.to_dict()
            write_artifact("dynamic-penetration-test.json", payload)
            if run is not None:
                run.end(outputs={"status": payload.get("status"), **payload.get("usage", {})})

            # This is the "Verification (evaluates exploitation evidence)" step from the design: it only
            # annotates an existing CONFIRMED record's notes with what the agent observed — it can never
            # change a disposition, and it never touches a candidate Verification did not already confirm.
            by_candidate = {item.candidate_id: item for item in report.results}
            updated_records = tuple(
                replace(record, notes=(*record.notes, f"dynamic_penetration_agent: {by_candidate[record.candidate_id].outcome.value} "
                                                        f"({len(by_candidate[record.candidate_id].attempts)} attempt(s)) "
                                                        f"\u2014 {by_candidate[record.candidate_id].summary}"))
                if record.candidate_id in by_candidate else record
                for record in state["verification"].records
            )
            updated_verification = replace(state["verification"], records=updated_records)
            return {"penetration_test_payload": payload, "verification": updated_verification,
                    "verification_payload": updated_verification.to_dict()}

    def triage_node(state: AgentReviewState) -> AgentReviewState:
        result = triage_candidates(state["discovery"], state["verification"], merged,
                                   project_root=project_root)
        payload = result.to_dict()
        write_artifact("candidate-triage.json", payload)
        return {"triage": result, "triage_payload": payload}

    def missing_discovery_node(_state: AgentReviewState) -> AgentReviewState:
        candidate_context = {
            "schema_version": "1.0", "status": "not_run", "candidates": [],
            "warnings": ["AI Discovery did not produce a result."],
        }
        verification = {
            "schema_version": "1.0", "status": "not_run", "project_root": str(project_root),
            "records": [], "warnings": ["AI Discovery did not produce a result; verification was not run."],
        }
        triage = {
            "schema_version": "1.0", "status": "not_run", "groups": [], "records": [],
            "warnings": ["AI Discovery did not produce a result; candidate triage was not run."],
        }
        penetration_test = {
            "schema_version": "1.0", "status": "not_run", "results": [], "usage": {},
            "warnings": ["AI Discovery did not produce a result; the penetration agent was not run."],
        }
        write_artifact("candidate-context.json", candidate_context)
        write_artifact("verification.json", verification)
        write_artifact("dynamic-penetration-test.json", penetration_test)
        write_artifact("candidate-triage.json", triage)
        return {
            "candidate_context_payload": candidate_context,
            "verification_payload": verification,
            "penetration_test_payload": penetration_test,
            "triage_payload": triage,
        }

    def review_node(state: AgentReviewState) -> AgentReviewState:
        selected_ids = {item.merged_finding_id for item in risk.findings if item.selected_for_deep_review}
        ordered_groups = tuple(sorted(state["triage"].groups, key=lambda group: not any(
            source_id in selected_ids for source_id in group.scanner_finding_ids)))
        review_triage = replace(state["triage"], groups=ordered_groups)
        result = review_runner(
            state["discovery"], state["verification"], provider=review_provider or provider,
            project_root=project_root, merged=merged, context=context,
            candidate_context=state["candidate_context"], triage=review_triage,
            timeout_seconds=None, deployment_context=deployment_context,
            max_reviews=max(1, max_reviews),
        )
        payload = result.to_dict()
        write_artifact("security-review.json", payload)
        return {"review_payload": payload}

    def skipped_review_node(_state: AgentReviewState) -> AgentReviewState:
        payload = {
            "schema_version": "1.0", "status": "not_run", "provider": None,
            "model": None, "reviews": [],
            "warnings": ["Security Review Agent was not run because required AI Discovery did not complete its planned inspection."],
            "usage": {},
        }
        write_artifact("security-review.json", payload)
        return {"review_payload": payload}

    def policy_node(state: AgentReviewState) -> AgentReviewState:
        # The gate must see the deterministic evidence (scanner findings, source verification) it names in its
        # rules; without it every decision is "not assessed" and RG-001 could block on an unchecked AI verdict.
        payload = evaluate_policy(
            state["review_payload"], triage_payload=state["triage_payload"],
            merged_payload=merged.to_dict(), verification_payload=state.get("verification_payload"),
        ).to_dict()
        write_artifact("policy-gate.json", payload)
        return {"policy_payload": payload}

    graph = StateGraph(AgentReviewState)
    graph.add_node("ai_discovery", discovery_node)
    graph.add_node("candidate_context", candidate_context_node)
    graph.add_node("verification", verification_node)
    graph.add_node("dynamic_penetration_agent", penetration_node)
    graph.add_node("candidate_triage", triage_node)
    graph.add_node("missing_discovery", missing_discovery_node)
    graph.add_node("security_review", review_node)
    graph.add_node("skipped_review", skipped_review_node)
    graph.add_node("policy_gate", policy_node)
    graph.add_edge(START, "ai_discovery")
    graph.add_conditional_edges(
        "ai_discovery",
        lambda state: "available" if state["discovery"] is not None else "missing",
        {"available": "candidate_context", "missing": "missing_discovery"},
    )
    graph.add_edge("candidate_context", "verification")
    graph.add_edge("verification", "dynamic_penetration_agent")
    graph.add_edge("dynamic_penetration_agent", "candidate_triage")
    graph.add_conditional_edges(
        "candidate_triage",
        lambda state: "ready" if state["discovery_satisfied"] else "incomplete",
        {"ready": "security_review", "incomplete": "skipped_review"},
    )
    graph.add_edge("missing_discovery", "skipped_review")
    graph.add_edge("security_review", "policy_gate")
    graph.add_edge("skipped_review", "policy_gate")
    graph.add_edge("policy_gate", END)
    return graph.compile().invoke({})

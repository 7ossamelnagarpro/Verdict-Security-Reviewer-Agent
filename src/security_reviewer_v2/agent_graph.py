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
from security_reviewer_v2.normalization.merge_models import MergeResult
from security_reviewer_v2.policy import evaluate_policy
from security_reviewer_v2.prioritization.models import RiskResult
from security_reviewer_v2.triage import TriageResult, triage_candidates
from security_reviewer_v2.verification import VerificationResult, verify_discovery


class AgentReviewState(TypedDict, total=False):
    """Per-run stage results. A graph invocation starts with an empty state."""

    discovery: DiscoveryResult | None
    discovery_payload: dict[str, Any]
    discovery_satisfied: bool
    candidate_context: CandidateContextResult
    candidate_context_payload: dict[str, Any]
    verification: VerificationResult
    verification_payload: dict[str, Any]
    triage: TriageResult
    triage_payload: dict[str, Any]
    review_payload: dict[str, Any]
    policy_payload: dict[str, Any]


def run_agent_review_graph(
    *,
    provider: Any,
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
) -> AgentReviewState:
    """Run Discovery through Policy Gate using the existing stage implementations.

    Artifacts are written as each node finishes, so a failed later node does not
    erase earlier evidence. The graph itself has no persistent checkpointer:
    source evidence and provider credentials must not enter a checkpoint store.
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
        write_artifact("candidate-context.json", candidate_context)
        write_artifact("verification.json", verification)
        write_artifact("candidate-triage.json", triage)
        return {
            "candidate_context_payload": candidate_context,
            "verification_payload": verification,
            "triage_payload": triage,
        }

    def review_node(state: AgentReviewState) -> AgentReviewState:
        selected_ids = {item.merged_finding_id for item in risk.findings if item.selected_for_deep_review}
        ordered_groups = tuple(sorted(state["triage"].groups, key=lambda group: not any(
            source_id in selected_ids for source_id in group.scanner_finding_ids)))
        review_triage = replace(state["triage"], groups=ordered_groups)
        result = review_runner(
            state["discovery"], state["verification"], provider=provider,
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
        payload = evaluate_policy(
            state["review_payload"], triage_payload=state["triage_payload"]
        ).to_dict()
        write_artifact("policy-gate.json", payload)
        return {"policy_payload": payload}

    graph = StateGraph(AgentReviewState)
    graph.add_node("ai_discovery", discovery_node)
    graph.add_node("candidate_context", candidate_context_node)
    graph.add_node("verification", verification_node)
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
    graph.add_edge("verification", "candidate_triage")
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

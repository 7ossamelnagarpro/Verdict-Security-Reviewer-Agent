"""LangGraph workflow for the Security Review agent.

::

    START -> prepare --(nothing eligible)--> END
                |
                v
           plan_batches --(no batches)--> finalize -> END
                |                            ^
                v                            |
              review_batch --(provider stopped)
                               ^   |                               ^
                               |   +--(missing groups)--> retry_missing
                               |   |                          |
                               |   v                          v
                               +-- checkpoint <---------------+
                                   (more batches -> review_batch, else -> finalize)

Same behaviour as the previous imperative loop: group-level evidence assembly, reuse of matching
prior reviews, size-bounded batches, one individual retry per group the model skipped, progress
snapshots after every batch, and a ``pending`` list that never lets an unreviewed group look safe.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from security_reviewer_v2.agents.tracing import agent_tracing, call_model, graph_config
from security_reviewer_v2.context.candidate_models import CandidateContextResult
from security_reviewer_v2.context.models import ContextResult
from security_reviewer_v2.discovery.models import DiscoveryResult
from security_reviewer_v2.normalization.merge_models import MergeResult
from security_reviewer_v2.triage.models import IssueGroup, TriageResult
from security_reviewer_v2.verification.models import VerificationDisposition, VerificationResult

from .agent import (
    _MAX_PROMPT_CHARS, ReviewProvider, _accept_reviews, _accumulate_usage, _group_payload, _review_prompt,
    _scope_debug_reviews,
)
from .models import ReviewItem, ReviewResult

Phase = Literal["review", "stopped", "retry", "next", "done", "empty"]
Prepared = tuple[IssueGroup, dict[str, Any]]
_MAX_GROUPS_PER_REQUEST = 3


@dataclass(frozen=True)
class ReviewInputs:
    """Immutable, run-scoped dependencies of the review agent."""

    discovery: DiscoveryResult
    verification: VerificationResult
    provider: ReviewProvider
    project_root: str | Path
    timeout_seconds: int | None = None
    max_reviews: int = 20
    merged: MergeResult | None = None
    context: ContextResult | None = None
    candidate_context: CandidateContextResult | None = None
    triage: TriageResult | None = None
    deployment_context: dict[str, Any] | None = None
    prior_reviews: tuple[ReviewItem, ...] = ()
    on_progress: Callable[[ReviewResult], None] | None = None


class ReviewState(TypedDict, total=False):
    phase: Phase
    expected_groups: int
    prepared: list[Prepared]
    unscheduled: list[str]
    reviews: dict[str, ReviewItem]
    pending: list[str]
    batches: list[list[Prepared]]
    cursor: int
    missing: list[str]
    usage: dict[str, Any]
    stopped: bool
    warnings: Annotated[list[str], operator.add]
    result: ReviewResult


class ReviewWorkflow:
    """Builds and runs the review graph."""

    def __init__(self, inputs: ReviewInputs) -> None:
        if inputs.max_reviews < 1:
            raise ValueError("max_reviews must be positive; it now limits each batch, not the whole run")
        self.inputs = inputs

    def run(self) -> ReviewResult:
        provider = self.inputs.provider
        with agent_tracing("security-review-agent"):
            final = self.compile().invoke(
                {"phase": "review", "warnings": [], "cursor": 0, "stopped": False},
                config=graph_config("security-review-agent", recursion_limit=self._step_budget(),
                                    metadata={"provider": provider.name, "model": provider.model}))
        return final["result"]

    def compile(self):
        return _Nodes(self.inputs).compile()

    def _step_budget(self) -> int:
        inputs = self.inputs
        groups = (len(inputs.triage.groups) if inputs.triage
                  else len(inputs.discovery.candidates) + (len(inputs.merged.findings) if inputs.merged else 0))
        return 3 * (groups + 2) + 10


class _Nodes:
    def __init__(self, inputs: ReviewInputs) -> None:
        self.inputs = inputs
        self.provider = inputs.provider
        self.candidates = {item.candidate_id: item for item in inputs.discovery.candidates}
        self.scanners = {item.merged_finding_id: item for item in inputs.merged.findings} if inputs.merged else {}

    # ------------------------------------------------------------------ wiring
    def compile(self):
        graph = StateGraph(ReviewState)
        for name in ("prepare", "plan_batches", "review_batch", "retry_missing", "checkpoint", "finalize"):
            graph.add_node(name, getattr(self, name))
        graph.add_edge(START, "prepare")
        _add_routes(graph, "prepare", {"review": "plan_batches", "empty": END})
        _add_routes(graph, "plan_batches", {"review": "review_batch", "done": "finalize"})
        _add_routes(graph, "review_batch", {"retry": "retry_missing", "next": "checkpoint", "stopped": "finalize"})
        graph.add_edge("retry_missing", "checkpoint")
        _add_routes(graph, "checkpoint", {"review": "review_batch", "done": "finalize"})
        graph.add_edge("finalize", END)
        return graph.compile()

    # ------------------------------------------------------------------ nodes
    def prepare(self, state: ReviewState) -> ReviewState:
        """Assemble per-group evidence, reuse matching saved reviews and decide if anything is reviewable."""
        inputs, provider = self.inputs, self.provider
        verified = {item.candidate_id: item for item in inputs.verification.records
                    if item.disposition is VerificationDisposition.CONFIRMED}
        groups = self._groups(verified)
        prepared: list[Prepared] = []
        warnings: list[str] = []
        unscheduled: list[str] = []
        for group in groups:
            group_scanners = [self.scanners[i] for i in group.scanner_finding_ids if i in self.scanners]
            group_records = [verified[i] for i in group.candidate_ids if i in verified]
            if not group_scanners and not group_records:
                warnings.append(f"{group.group_id}: no eligible source evidence is available for review.")
                unscheduled.append(group.group_id)
                continue
            prepared.append((group, _group_payload(group, group_records, self.candidates, group_scanners,
                                                    inputs.context, inputs.project_root, inputs.candidate_context)))
        group_by_id = {group.group_id: group for group, _ in prepared}
        reviews: dict[str, ReviewItem] = {}
        for prior in inputs.prior_reviews:
            group = group_by_id.get(prior.candidate_id)
            expected = tuple((*group.scanner_finding_ids, *group.candidate_ids)) if group else ()
            if group is not None and prior.source_ids == expected and prior.candidate_id not in reviews:
                reviews[prior.candidate_id] = prior
            else:
                warnings.append(f"{prior.candidate_id}: saved review did not match the current issue group and was not reused.")
        _scope_debug_reviews(reviews, group_by_id, self.scanners, inputs.deployment_context)
        if not prepared:
            return {"phase": "empty", "result": ReviewResult(
                "1.0", "partial" if unscheduled else "completed", provider.name, provider.model, (),
                tuple(warnings or ["No verified candidates or scanner findings were available for review."]),
                {"expected_groups": len(groups), "reviewed_groups": 0, "calls": 0, "pending_groups": len(unscheduled)},
                tuple(unscheduled))}
        return {"phase": "review", "prepared": prepared, "reviews": reviews, "warnings": warnings,
                "unscheduled": unscheduled, "pending": list(unscheduled), "expected_groups": len(groups)}

    def plan_batches(self, state: ReviewState) -> ReviewState:
        """Pack groups into batches bounded by group count and prompt size."""
        inputs = self.inputs
        limit = min(inputs.max_reviews, max(1, min(_MAX_GROUPS_PER_REQUEST,
                    int(getattr(self.provider, "max_review_groups_per_request", _MAX_GROUPS_PER_REQUEST)))))
        size = lambda items: len(_review_prompt(inputs.project_root, [entry[1] for entry in items], inputs.deployment_context))
        batches: list[list[Prepared]] = []
        current: list[Prepared] = []
        pending, warnings = list(state["pending"]), []
        for item in state["prepared"]:
            if item[0].group_id in state["reviews"]:
                continue
            if len([*current, item]) > limit or size([*current, item]) > _MAX_PROMPT_CHARS:
                if current:
                    batches.append(current)
                    current = []
            if size([item]) > _MAX_PROMPT_CHARS:
                pending.append(item[0].group_id)
                warnings.append(f"{item[0].group_id}: review context exceeds the prompt budget; group was not sent.")
                continue
            current.append(item)
        if current:
            batches.append(current)
        usage = {"provider": self.provider.name, "model": self.provider.model, "calls": 0,
                 "expected_groups": state["expected_groups"], "reused_groups": len(state["reviews"])}
        return {"batches": batches, "pending": pending, "warnings": warnings, "usage": usage,
                "phase": "review" if batches else "done"}

    def review_batch(self, state: ReviewState) -> ReviewState:
        batch = state["batches"][state["cursor"]]
        inputs = self.inputs
        expected = {group.group_id: group for group, _ in batch}
        try:
            raw, batch_usage = call_model(
                self.provider, "review", _review_prompt(inputs.project_root, [item for _, item in batch], inputs.deployment_context),
                span="security-review-model-call", timeout_seconds=inputs.timeout_seconds, max_reviews=len(batch))
        except RuntimeError as error:
            return {"phase": "stopped", "stopped": True, "warnings": [f"Review provider stopped: {error}"]}
        usage, reviews, warnings = dict(state["usage"]), dict(state["reviews"]), []
        _accumulate_usage(usage, batch_usage)
        missing = _accept_reviews(raw, expected, self.candidates, reviews, warnings)
        return {"usage": usage, "reviews": reviews, "warnings": warnings, "missing": missing,
                "phase": "retry" if missing else "next"}

    def retry_missing(self, state: ReviewState) -> ReviewState:
        """Ask once, individually, for every group the batched answer skipped."""
        inputs = self.inputs
        batch = {group.group_id: (group, payload) for group, payload in state["batches"][state["cursor"]]}
        usage, reviews, warnings = dict(state["usage"]), dict(state["reviews"]), []
        for group_id in state["missing"]:
            group, payload = batch[group_id]
            try:
                raw, retry_usage = call_model(
                    self.provider, "review", _review_prompt(inputs.project_root, [payload], inputs.deployment_context),
                    span="security-review-retry", timeout_seconds=inputs.timeout_seconds, max_reviews=1)
            except RuntimeError as error:
                warnings.append(f"{group_id}: individual review retry failed: {error}")
                continue
            _accumulate_usage(usage, retry_usage)
            _accept_reviews(raw, {group_id: group}, self.candidates, reviews, warnings)
        return {"usage": usage, "reviews": reviews, "warnings": warnings}

    def checkpoint(self, state: ReviewState) -> ReviewState:
        """Apply deployment scoping, publish a progress snapshot and advance to the next batch."""
        inputs = self.inputs
        group_by_id = {group.group_id: group for group, _ in state["prepared"]}
        reviews = dict(state["reviews"])
        _scope_debug_reviews(reviews, group_by_id, self.scanners, inputs.deployment_context)
        cursor = state["cursor"] + 1
        if inputs.on_progress is not None:
            remaining = tuple(group.group_id for group, _ in state["prepared"] if group.group_id not in reviews)
            unscheduled = state["unscheduled"]
            inputs.on_progress(ReviewResult(
                "1.0", "partial", self.provider.name, self.provider.model,
                tuple(reviews[group.group_id] for group, _ in state["prepared"] if group.group_id in reviews),
                tuple(state["warnings"]),
                {**state["usage"], "reviewed_groups": len(reviews), "pending_groups": len(remaining) + len(unscheduled)},
                tuple((*unscheduled, *remaining))))
        return {"reviews": reviews, "cursor": cursor, "missing": [],
                "phase": "review" if cursor < len(state["batches"]) else "done"}

    def finalize(self, state: ReviewState) -> ReviewState:
        reviews, prepared = state["reviews"], state["prepared"]
        pending = list(state["pending"])
        pending.extend(group.group_id for group, _ in prepared
                       if group.group_id not in reviews and group.group_id not in pending)
        usage = {**state["usage"], "reviewed_groups": len(reviews), "pending_groups": len(pending)}
        status = "completed" if not pending else ("blocked" if state["stopped"] and not reviews else "partial")
        ordered = tuple(reviews[group.group_id] for group, _ in prepared if group.group_id in reviews)
        return {"result": ReviewResult("1.0", status, self.provider.name, self.provider.model, ordered,
                                       tuple(state["warnings"]), usage, tuple(pending))}

    # ------------------------------------------------------------------ helpers
    def _groups(self, verified: dict[str, Any]) -> tuple[IssueGroup, ...]:
        inputs = self.inputs
        if inputs.triage:
            return inputs.triage.groups
        return (
            *(IssueGroup(item.merged_finding_id, "unclassified", item.primary_location.path,
                         (item.merged_finding_id,), (), ("Scanner finding.",)) for item in self.scanners.values()),
            *(IssueGroup(item.candidate_id, "unclassified", item.path, (), (item.candidate_id,),
                         ("Source-grounded AI candidate.",))
              for item in inputs.discovery.candidates if item.candidate_id in verified),
        )


def _add_routes(graph: StateGraph, source: str, routes: dict[str, str]) -> None:
    """Route on ``state["phase"]``; ``path_map`` makes every branch visible in diagrams and LangSmith."""
    def route(state: ReviewState) -> str:
        return routes[state["phase"]]
    route.__name__ = f"route_after_{source}"  # shown as the step name in LangSmith traces
    graph.add_conditional_edges(source, route, path_map=sorted(set(routes.values())))

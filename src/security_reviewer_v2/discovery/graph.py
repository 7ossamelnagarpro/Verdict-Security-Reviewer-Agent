"""LangGraph workflow for the AI Discovery agent.

The agent is a small state machine instead of nested loops, so every step is a named node that
LangSmith can show, time and replay::

    START -> plan_scope -> select_batch --ready--> call_model -> absorb_candidates -> plan_enrichment
                              ^   |  \\                |  (provider error)               |      |
                              |   |   \\ skipped       v                                 |      v
                              |   |    \\ (no fit)  close_batch <--- no more context ----+  fetch_context
                              |   |                      |  ^                                      |
                              |   done                   |  +----------- (re-prompt) --- call_model
                              |   v                      v
                              +- finalize <---- (fatal provider error)  -> END

An HTTP 413 (request larger than the provider allows) routes ``call_model -> shrink_batch -> call_model`` with a
smaller request instead of ending the run.  Otherwise semantics match the previous imperative loop: bounded batches, bounded on-demand
context rounds, deterministic candidate verification, and an honest ``PARTIAL`` status whenever
any coverage gap remains.  Deterministic domain logic stays in ``agent.py``; this module only
orchestrates it.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from security_reviewer_v2.agents.tracing import agent_tracing, call_model, graph_config
from security_reviewer_v2.context.models import ContextResult
from security_reviewer_v2.normalization.merge_models import MergeResult
from security_reviewer_v2.prioritization.models import RiskResult

from .agent import (
    _build_prompt, _enrichment_prompt, _redact, _sum_usage, _verify_candidate, _with_cost,
)
from .context_tools import ContextBroker
from .models import (
    DISCOVERY_SCHEMA_VERSION, CandidateDisposition, CandidateFinding, DiscoveryBatch, DiscoveryConfig,
    DiscoveryResult, DiscoveryStatus, DiscoveryTarget,
)
from .provider import DiscoveryProvider, ProviderResponseError, RequestTooLargeError
from .scope import DiscoveryScope, plan_discovery_scope

Phase = Literal["ready", "skipped", "done", "enrich", "call", "close", "next"]
_LEGACY_BATCH_LEVEL_MARKER = "non-JSON"  # providers that predate ``ProviderResponseError`` (e.g. Ollama)
_MAX_SHRINKS = 8          # bound on size-reduction retries for one batch
_MIN_CONTEXT_CHARS = 1_500  # a single target is not shrunk below this prompt budget


@dataclass(frozen=True)
class DiscoveryInputs:
    """Immutable, run-scoped dependencies (what the agent reads, never what it produces)."""

    merged: MergeResult
    context: ContextResult
    risk: RiskResult
    project_root: str | Path
    profile_artifact: dict[str, Any] | None = None
    additional_coverage_gaps: tuple[str, ...] = ()
    target_ids: tuple[str, ...] | None = None
    on_batch: Callable[[DiscoveryBatch], None] | None = None


@dataclass(frozen=True)
class BatchProgress:
    """Progress of the batch currently being sent to the model."""

    index: int
    targets: tuple[DiscoveryTarget, ...]
    prompt: str
    allowed_paths: frozenset[str]
    calls: int = 0
    requests: int = 0
    rounds: int = 0
    sent_prompt_chars: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    candidate_ids: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)
    selected_requests: tuple[Any, ...] = ()
    error: str | None = None
    batch_level_error: bool = False   # the model answered with unusable content; the provider itself is reachable
    budget: int = 0                   # prompt character budget this batch was built with
    shrinks: int = 0                  # how many times a 413 forced a smaller request
    size_ratio: float | None = None   # limit / requested tokens from the last 413, when reported
    reason: str = "size"              # why the batch is being shrunk: "size" (HTTP 413) or "output" (unusable answer)
    last_error: str = ""              # safe text of the failure that triggered the shrink
    counted: bool = False             # targets already credited as inspected by a successful call


class DiscoveryState(TypedDict, total=False):
    """Graph state.  ``Annotated`` fields are append/union channels; the rest are replaced."""

    phase: Phase
    scope: DiscoveryScope
    pending: list[DiscoveryTarget]
    batch_index: int
    batch: BatchProgress | None
    target_limit: int                 # largest batch the provider accepted so far (shrinks on HTTP 413, never grows)
    candidates: dict[str, CandidateFinding]
    totals: dict[str, int]
    failed: bool
    inspected: Annotated[list[DiscoveryTarget], operator.add]
    batches: Annotated[list[DiscoveryBatch], operator.add]
    exchanges: Annotated[list[Any], operator.add]
    warnings: Annotated[list[str], operator.add]
    gaps: Annotated[set[str], operator.or_]
    result: DiscoveryResult


class DiscoveryWorkflow:
    """Builds and runs the discovery graph for one provider/config pair."""

    def __init__(self, provider: DiscoveryProvider, config: DiscoveryConfig) -> None:
        self.provider = provider
        self.config = config

    def run(self, inputs: DiscoveryInputs) -> DiscoveryResult:
        nodes = _Nodes(self.provider, self.config, inputs)
        with agent_tracing("discovery-agent"):
            final = nodes.compile().invoke(_initial_state(), config=graph_config(
                "discovery-agent", recursion_limit=self._step_budget(),
                metadata={"provider": self.provider.name, "model": self.provider.model}))
        return final["result"]

    def _step_budget(self) -> int:
        per_batch = 3 + 3 * (self.config.max_enrichment_rounds + 1) + 2 * _MAX_SHRINKS
        return (self.config.max_batches + 1) * per_batch + 10

    @staticmethod
    def build_graph(provider: DiscoveryProvider, config: DiscoveryConfig, inputs: DiscoveryInputs):
        """Compiled graph (for visualisation and tests)."""
        return _Nodes(provider, config, inputs).compile()


def _initial_state() -> DiscoveryState:
    return {"phase": "ready", "batch_index": 0, "batch": None, "candidates": {}, "totals": {}, "failed": False,
            "inspected": [], "batches": [], "exchanges": [], "warnings": [], "gaps": set()}


class _Nodes:
    """Graph nodes.  Each returns a partial state update; none mutates ``state``."""

    def __init__(self, provider: DiscoveryProvider, config: DiscoveryConfig, inputs: DiscoveryInputs) -> None:
        self.provider, self.config, self.inputs = provider, config, inputs
        self.broker = ContextBroker(inputs.project_root, config, inputs.profile_artifact, _redact)

    # ------------------------------------------------------------------ wiring
    def compile(self):
        graph = StateGraph(DiscoveryState)
        for name in ("plan_scope", "select_batch", "call_model", "shrink_batch", "absorb_candidates",
                     "plan_enrichment", "fetch_context", "close_batch", "finalize"):
            graph.add_node(name, getattr(self, name))
        graph.add_edge(START, "plan_scope")
        graph.add_edge("plan_scope", "select_batch")
        _add_routes(graph, "select_batch", {"ready": "call_model", "skipped": "select_batch", "done": "finalize"})
        _add_routes(graph, "call_model", {"next": "absorb_candidates", "close": "close_batch", "shrink": "shrink_batch"})
        _add_routes(graph, "shrink_batch", {"call": "call_model", "close": "close_batch"})
        graph.add_edge("absorb_candidates", "plan_enrichment")
        _add_routes(graph, "plan_enrichment", {"enrich": "fetch_context", "close": "close_batch"})
        _add_routes(graph, "fetch_context", {"call": "call_model", "close": "close_batch"})
        _add_routes(graph, "close_batch", {"next": "select_batch", "done": "finalize"})
        graph.add_edge("finalize", END)
        return graph.compile()

    # ------------------------------------------------------------------ nodes
    def plan_scope(self, state: DiscoveryState) -> DiscoveryState:
        inputs = self.inputs
        scope = plan_discovery_scope(
            inputs.merged, inputs.risk, inputs.context, project_root=inputs.project_root, config=self.config,
            profile_artifact=inputs.profile_artifact, additional_coverage_gaps=inputs.additional_coverage_gaps)
        if inputs.target_ids is not None:
            selected = set(inputs.target_ids)
            missing = selected - {item.target_id for item in scope.targets}
            if missing:
                raise ValueError(f"Requested discovery target IDs are not in the planned scope: {', '.join(sorted(missing))}")
            scope = DiscoveryScope(
                tuple(item for item in scope.targets if item.target_id in selected), scope.snippets,
                scope.gap_evidence, scope.warnings,
                (*scope.coverage_gaps, "Discovery run was restricted to explicitly selected target IDs."))
        return {"scope": scope, "pending": list(scope.targets), "warnings": list(scope.warnings),
                "target_limit": self.config.max_targets,
                "gaps": {*scope.coverage_gaps, *scope.gap_evidence, *self.broker.inventory_gaps}}

    def select_batch(self, state: DiscoveryState) -> DiscoveryState:
        index = state["batch_index"] + 1
        pending = state["pending"]
        if not pending or index > self.config.max_batches:
            return {"batch_index": index, "batch": None, "phase": "done"}
        scope, cfg = state["scope"], self.config
        selection = pending[:min(cfg.max_targets, state["target_limit"])]
        batch_scope = DiscoveryScope(tuple(selection), scope.snippets, scope.gap_evidence, scope.warnings, scope.coverage_gaps)
        # Reserve room for requested context on a subsequent model call.
        budget = max(1_000, cfg.max_context_chars - min(4_000, cfg.max_context_chars // 4))
        prompt, targets, prompt_gaps = _build_prompt(self.inputs.merged, self.inputs.context, self.inputs.risk,
                                                      batch_scope, budget)
        if not targets:
            return {"batch_index": index, "batch": None, "phase": "skipped", "pending": pending[1:],
                    "gaps": {f"Discovery target {selection[0].target_id} did not fit the prompt budget."}}
        included = {item.target_id for item in targets}
        return {
            "batch_index": index, "phase": "ready",
            "pending": [item for item in pending if item.target_id not in included],
            "gaps": {gap for gap in prompt_gaps if "shortened" in gap or "background" in gap or "known findings" in gap},
            "batch": BatchProgress(index, targets, prompt,
                                   frozenset(item.path.replace("\\", "/") for item in targets if item.path),
                                   budget=budget),
        }

    def call_model(self, state: DiscoveryState) -> DiscoveryState:
        batch = state["batch"]
        batch = replace(batch, calls=batch.calls + 1, sent_prompt_chars=batch.sent_prompt_chars + len(batch.prompt))
        try:
            raw, usage = call_model(self.provider, "discover", batch.prompt, span="discovery-model-call",
                                    timeout_seconds=self.config.timeout_seconds,
                                    max_candidates=self.config.max_candidates)
        except (RequestTooLargeError, ProviderResponseError) as error:
            if batch.counted:
                # These targets were already answered by an earlier call; only the follow-up that adds on-demand
                # context failed.  Shrinking would re-queue targets that are already inspected (and count them
                # twice), so keep the first response and say what was lost.
                return {"batch": replace(batch, selected_requests=()), "phase": "close",
                        "gaps": {f"Discovery batch {batch.index}: on-demand context could not be added ({error}); "
                                 "the first response was kept."}}
            # Too large for the provider, or the model produced unusable output for this request: either way waiting
            # cannot help, a smaller request can (and isolates a target that keeps breaking the model's output).
            size = isinstance(error, RequestTooLargeError)
            return {"batch": replace(batch, size_ratio=error.fit_ratio if size else None,
                                     reason="size" if size else "output", last_error=str(error)),
                    "phase": "shrink",
                    "warnings": [f"Discovery batch {batch.index}: {error}; retrying with a smaller request."]}
        except RuntimeError as error:
            message = str(error)
            batch_level = isinstance(error, ProviderResponseError) or _LEGACY_BATCH_LEVEL_MARKER in message
            return {"batch": replace(batch, error=message, batch_level_error=batch_level), "failed": True,
                    "phase": "close",
                    "warnings": [f"Discovery batch {batch.index}: {message}"],
                    "gaps": {f"Discovery batch {batch.index} did not complete; targets: "
                             f"{', '.join(item.target_id for item in batch.targets)}."}}
        batch_usage, totals = dict(batch.usage), dict(state["totals"])
        _sum_usage(batch_usage, usage)
        _sum_usage(totals, usage)
        if isinstance(raw, list):  # Legacy test/provider boundary.
            raw = {"candidates": raw, "context_requests": []}
        if not isinstance(raw, dict):
            raw = {"candidates": [], "context_requests": []}
        update: DiscoveryState = {"batch": replace(batch, usage=batch_usage, raw=raw, counted=True),
                                  "totals": totals, "phase": "next"}
        if not batch.counted:  # credit the targets once, on the first call that actually succeeded
            update["inspected"] = list(batch.targets)
        return update

    def shrink_batch(self, state: DiscoveryState) -> DiscoveryState:
        """Rebuild the current batch smaller after an HTTP 413 or an unusable model answer, so one bad request
        cannot end discovery.

        Several targets: keep a leading share (sized from the provider's own limit/requested numbers when it
        reported them, otherwise 60% for size and half for output failures) and return the rest to the front of
        the queue.  One target: for a size problem shrink its prompt budget; for an output problem there is
        nothing smaller to try.  Nothing is dropped silently: a target that cannot be processed even then is
        reported as a gap and stays uninspected.
        """
        batch, scope = state["batch"], state["scope"]
        factor = (min(0.8, max(0.2, batch.size_ratio * 0.85)) if batch.size_ratio
                  else 0.5 if batch.reason == "output" else 0.6)
        giving_up = batch.shrinks >= _MAX_SHRINKS
        selection, returned, budget = batch.targets, (), batch.budget
        if not giving_up and len(batch.targets) > 1:
            keep = max(1, int(len(batch.targets) * factor))
            selection, returned = batch.targets[:keep], batch.targets[keep:]
        elif not giving_up:
            budget = int(batch.budget * factor)
            giving_up = batch.reason == "output" or budget < _MIN_CONTEXT_CHARS
        if not giving_up:
            batch_scope = DiscoveryScope(tuple(selection), scope.snippets, scope.gap_evidence, scope.warnings,
                                         scope.coverage_gaps)
            prompt, targets, _ = _build_prompt(self.inputs.merged, self.inputs.context, self.inputs.risk,
                                               batch_scope, budget)
            giving_up = not targets
        if giving_up:
            ids = ", ".join(item.target_id for item in batch.targets)
            why = ("exceeded the provider request-size limit even with reduced context" if batch.reason == "size"
                   else f"produced no usable model output even when sent alone ({batch.last_error})")
            return {"phase": "close", "failed": True,   # provider rejected it: never a silent success
                    "gaps": {f"Discovery target(s) {ids} {why} and were not inspected."},
                    "batch": replace(batch, error=f"request not processable: {why}", batch_level_error=True)}
        included = {item.target_id for item in targets}
        requeue = [*returned, *(item for item in selection if item.target_id not in included)]
        # A size limit applies to every later request, so remember the size that fits.  An output failure is caused
        # by particular targets, so later batches start at full size again (only the offender is isolated).
        learned = min(state["target_limit"], len(targets)) if len(batch.targets) > 1 and batch.reason == "size" else state["target_limit"]
        return {"phase": "call", "pending": [*requeue, *state["pending"]], "target_limit": learned,
                "batch": replace(batch, targets=targets, prompt=prompt, budget=budget, shrinks=batch.shrinks + 1,
                                 size_ratio=None, last_error="",
                                 allowed_paths=frozenset(item.path.replace("\\", "/") for item in targets if item.path))}

    def absorb_candidates(self, state: DiscoveryState) -> DiscoveryState:
        batch, raw = state["batch"], state["batch"].raw
        gaps: set[str] = set()
        for key, label in (("omitted_candidates", "candidates"), ("omitted_context_requests", "context requests")):
            if raw.get(key):
                gaps.add(f"Discovery batch {batch.index} omitted {raw[key]} {label} by provider response limit.")
        raw_candidates = raw.get("candidates", [])
        if not isinstance(raw_candidates, list):
            raw_candidates = []
            gaps.add(f"Discovery batch {batch.index} returned a malformed candidates list.")
        candidates, new_ids = dict(state["candidates"]), list(batch.candidate_ids)
        for item in raw_candidates[:self.config.max_candidates]:
            if not isinstance(item, dict):
                continue
            candidate = _verify_candidate(item, self.inputs.project_root, set(batch.allowed_paths), self.broker)
            prior = candidates.get(candidate.candidate_id)
            if prior is None and len(candidates) < self.config.max_total_candidates:
                candidates[candidate.candidate_id] = candidate
                new_ids.append(candidate.candidate_id)
            elif prior is None:
                gaps.add("Additional AI candidates were omitted by the overall candidate limit; target scanning continued.")
            elif (prior.verification is not CandidateDisposition.SUPPORTED
                  and candidate.verification is CandidateDisposition.SUPPORTED):
                candidates[candidate.candidate_id] = candidate
        return {"candidates": candidates, "gaps": gaps, "batch": replace(batch, candidate_ids=tuple(new_ids))}

    def plan_enrichment(self, state: DiscoveryState) -> DiscoveryState:
        batch, cfg = state["batch"], self.config
        requests = batch.raw.get("context_requests", [])
        if not isinstance(requests, list) or not requests:
            return {"phase": "close"}
        if batch.rounds >= cfg.max_enrichment_rounds or batch.requests >= cfg.max_context_requests_per_batch:
            return {"phase": "close",
                    "gaps": {f"Discovery batch {batch.index} had context requests beyond its enrichment budget."}}
        available = cfg.max_context_requests_per_batch - batch.requests
        gaps = ({f"Discovery batch {batch.index} omitted {len(requests) - available} context requests by budget."}
                if len(requests) > available else set())
        return {"phase": "enrich", "gaps": gaps,
                "batch": replace(batch, selected_requests=tuple(requests[:available]), rounds=batch.rounds + 1)}

    def fetch_context(self, state: DiscoveryState) -> DiscoveryState:
        batch = state["batch"]
        fresh = [self.broker.fetch(request, batch_index=batch.index, round_index=batch.rounds)
                 for request in batch.selected_requests]
        allowed, gaps = set(batch.allowed_paths), set()
        for exchange in fresh:
            if exchange.status == "collected" and exchange.resolved_path:
                allowed.add(exchange.resolved_path)
            elif exchange.note:
                gaps.add(f"Discovery batch {batch.index} context request {exchange.status}: {exchange.note}")
        prompt = _enrichment_prompt(batch.prompt, fresh, self.config.max_context_chars)
        base = replace(batch, requests=batch.requests + len(batch.selected_requests),
                       allowed_paths=frozenset(allowed), selected_requests=())
        if prompt is None:
            gaps.add(f"Discovery batch {batch.index} could not fit on-demand context in the prompt budget.")
            return {"batch": base, "exchanges": fresh, "gaps": gaps, "phase": "close"}
        return {"batch": replace(base, prompt=prompt), "exchanges": fresh, "gaps": gaps, "phase": "call"}

    def close_batch(self, state: DiscoveryState) -> DiscoveryState:
        batch = state["batch"]
        record = DiscoveryBatch(batch.index, tuple(item.target_id for item in batch.targets),
                                "failed" if batch.error else "completed", batch.sent_prompt_chars, batch.calls,
                                len(batch.candidate_ids), batch.requests, _with_cost(batch.usage, self.config),
                                batch.error, batch.candidate_ids)
        if self.inputs.on_batch is not None:
            self.inputs.on_batch(record)
        # A transport/HTTP outage stops the run; unusable model content only fails this batch (its targets stay
        # uninspected and are reported as gaps), so one bad answer cannot hide the remaining batches.
        fatal = bool(batch.error) and not batch.batch_level_error
        return {"batches": [record], "batch": None, "phase": "done" if fatal else "next"}

    def finalize(self, state: DiscoveryState) -> DiscoveryState:
        gaps, batches = set(state["gaps"]), state["batches"]
        seen: set[str] = set()   # invariant: a target is inspected at most once, so inspected <= planned
        inspected = [item for item in state["inspected"] if not (item.target_id in seen or seen.add(item.target_id))]
        pending, scope = state["pending"], state["scope"]
        if pending:
            gaps.add(f"{len(pending)} planned discovery targets were not inspected; batch or candidate budget was exhausted: "
                     + ", ".join(item.target_id for item in pending[:20]))
        if not inspected:
            gaps.add("No discovery target was inspected.")
        failed = state["failed"]
        status = (DiscoveryStatus.BLOCKED if failed and not inspected
                  else DiscoveryStatus.PARTIAL if gaps or failed else DiscoveryStatus.COMPLETED)
        usage = _with_cost({**state["totals"], "targets": len(inspected), "planned_targets": len(scope.targets),
                            "batches": len(batches), "provider_calls": sum(item.provider_calls for item in batches)},
                           self.config)
        return {"result": DiscoveryResult(
            DISCOVERY_SCHEMA_VERSION, status, self.provider.name, self.provider.model,
            tuple(item.target_id for item in inspected), tuple(state["candidates"].values()),
            tuple(dict.fromkeys(state["warnings"])), tuple(sorted(gaps)), usage,
            tuple(inspected), tuple(batches), tuple(state["exchanges"]))}


def _add_routes(graph: StateGraph, source: str, routes: dict[str, str]) -> None:
    """Route on ``state["phase"]``; ``path_map`` makes every branch visible in diagrams and LangSmith."""
    def route(state: DiscoveryState) -> str:
        return routes[state["phase"]]
    route.__name__ = f"route_after_{source}"  # shown as the step name in LangSmith traces
    graph.add_conditional_edges(source, route, path_map=sorted(set(routes.values())))

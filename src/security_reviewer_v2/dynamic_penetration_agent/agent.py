"""The ``dynamic_penetration_agent`` node's entry point (see ``agent_graph.py``).

Scope (sections 1 and 10): only candidates the deterministic Verification stage has already *grounded*
in the repository are eligible — this agent tests exploitability, it does not rediscover candidates and
it does not get to override Verification's or the Security Review Agent's judgement. A candidate this
agent confirms exploitation evidence for still goes through ordinary Verification/Triage/Review; it is
never auto-promoted to a final verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from security_reviewer_v2.agents.tracing import node_trace
from security_reviewer_v2.discovery.models import CandidateFinding, DiscoveryResult
from security_reviewer_v2.verification.models import VerificationDisposition, VerificationResult

from . import adaptive_controller, evidence_evaluator
from .execution_budget import BudgetTracker
from .models import PROVENANCE, SCHEMA_VERSION, ExecutionBudget, HypothesisTestResult, PenetrationTestReport


@dataclass(frozen=True)
class RuntimeAccess:
    """Everything the agent is explicitly allowed to use; nothing here is invented by the agent itself."""

    base_url: str
    allowed_endpoints: frozenset[str]
    accounts: tuple[str, ...]                 # account ids declared in the Runtime Contract's workflow_suite
    account_definitions: dict[str, dict]       # those same accounts' validated login/session definitions
    environment: Mapping[str, str] | None = None
    zap_context: Mapping[str, str] | None = None   # {"stack_name": ..., "app_service": ...}; enables "zap"
    playwright_enabled: bool = False               # explicit opt-in; enables "playwright"
    ai_provider: Any = None                         # explicit opt-in; an AttackPlanProvider (see ai_planner.py)

    @property
    def corroboration_tools(self) -> tuple[str, ...]:
        tools: list[str] = []
        if self.zap_context:
            tools.append("zap")
        if self.playwright_enabled:
            tools.append("playwright")
        return tuple(tools)


def run_penetration_tests(
    discovery: DiscoveryResult,
    verification: VerificationResult,
    *,
    access: RuntimeAccess,
    target_endpoint_resolver: Callable[[CandidateFinding], str | None],
    budget: ExecutionBudget | None = None,
    transport: Any = None,
) -> PenetrationTestReport:
    """Run the adaptive loop for every candidate Verification has confirmed as source-grounded.

    ``target_endpoint_resolver`` maps a candidate to the one HTTP route it concerns (for example via the
    same route index used to attach runtime findings to source, ``context/routes.py``); returning
    ``None`` makes the candidate ``cannot_test`` without spending any budget on it.
    """
    selected_budget = budget or ExecutionBudget()
    selected_budget.validate()
    tracker = BudgetTracker(selected_budget)
    candidates_by_id = {item.candidate_id: item for item in discovery.candidates}
    confirmed = [record.candidate_id for record in verification.records
                if record.disposition is VerificationDisposition.CONFIRMED]

    results: list[HypothesisTestResult] = []
    warnings: list[str] = []
    for candidate_id in confirmed:
        candidate = candidates_by_id.get(candidate_id)
        if candidate is None:
            continue
        target_endpoint = target_endpoint_resolver(candidate)
        # One parent span per hypothesis, so LangSmith shows a short, readable list of hypotheses (each holding its own
        # planner/interpretation calls) instead of every model call of the whole stage as one flat list.
        with node_trace("penetration_hypothesis", inputs={"candidate_id": candidate_id, "endpoint": target_endpoint or ""}) as span:
            attempts, evaluations, planning_gaps = adaptive_controller.run_hypothesis(
                candidate, target_endpoint=target_endpoint, base_url=access.base_url,
                accounts=access.accounts, account_definitions=access.account_definitions,
                allowed_endpoints=access.allowed_endpoints, tracker=tracker,
                environment=access.environment, transport=transport,
                zap_context=access.zap_context, corroboration_tools=access.corroboration_tools,
                ai_provider=access.ai_provider,
            )
            if span is not None:
                span.end(outputs={"attempts": len(attempts), "strategies": [a.test_strategy for a in attempts],
                                  "last_stop_reason": attempts[-1].stop_reason if attempts else "none"})
        outcome = evidence_evaluator.hypothesis_outcome(evaluations, planning_blocked=target_endpoint is None)
        if attempts:
            summary = attempts[-1].observation
        elif target_endpoint is None:
            summary = "No HTTP route was resolved for this candidate; no safe test exists."
        elif planning_gaps:
            summary = ("Every applicable scenario was considered but none could be executed: "
                      + "; ".join(f"{gap['strategy']} \u2014 {gap['reason']}" for gap in planning_gaps))
        else:
            summary = "No applicable template could be planned with the accounts and evidence on hand."
        results.append(HypothesisTestResult(candidate_id, outcome, attempts, summary,
                                            considered_but_not_executed=planning_gaps))

    status = "completed" if confirmed else "not_run"
    if not confirmed:
        warnings.append("No candidate was confirmed by Verification; the penetration agent has nothing to test.")
    usage = {"hypotheses_considered": len(confirmed), "hypotheses_tested": len(results),
             "total_attempts": sum(len(item.attempts) for item in results),
             "total_requests": tracker.total_requests,
             "exploitation_confirmed": sum(result.outcome.value == "exploitation_confirmed" for result in results)}
    return PenetrationTestReport(SCHEMA_VERSION, status, tuple(results), usage, tuple(warnings))


__all__ = ["RuntimeAccess", "run_penetration_tests", "PROVENANCE"]

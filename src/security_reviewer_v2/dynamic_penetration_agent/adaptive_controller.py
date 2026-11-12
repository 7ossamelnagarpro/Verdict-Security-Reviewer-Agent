"""Section 3, phase 5: Plan -> Execute -> Observe -> Evaluate -> Re-plan -> Next test or Stop.

This is the only module that runs the loop; every other module in the package is a single deterministic
step the controller calls in order. It never calls an execution tool itself — that is
``tool_orchestrator``'s job — and it never decides the final vulnerability verdict — that stays with
Verification and the Security Review Agent.
"""

from __future__ import annotations

from typing import Any, Mapping

from security_reviewer_v2.discovery.models import CandidateFinding

from . import attack_planner, evidence_collector, evidence_evaluator, hypothesis_analyzer, scenario_validator, tool_orchestrator
from .execution_budget import BudgetTracker
from .models import NextAction, PenetrationAttempt, StopReason, TestStrategy


def run_hypothesis(
    candidate: CandidateFinding,
    *,
    target_endpoint: str | None,
    base_url: str,
    accounts: tuple[str, ...],
    account_definitions: dict[str, dict],
    allowed_endpoints: frozenset[str],
    tracker: BudgetTracker,
    environment: Mapping[str, str] | None = None,
    transport: Any = None,
    zap_context: Mapping[str, str] | None = None,
    corroboration_tools: tuple[str, ...] = (),
) -> tuple[tuple[PenetrationAttempt, ...], tuple[evidence_evaluator.AttemptEvaluation, ...]]:
    """Run attempts for one candidate until a stop condition fires. Never raises for a blocked step.

    ``corroboration_tools`` (for example ``("zap", "playwright")`` when the agent's own stack and Node.js
    are available) is used at most ONCE per hypothesis, and only after every ``runtime_workflows`` strategy
    is exhausted with a result that is not already a confirmed violation: a plain-HTTP "passed" or
    "inconclusive" result is corroborated with a heavier, more realistic tool before the hypothesis is
    closed out — never used to repeat a strategy that already produced clear evidence either way.
    """
    assessment = hypothesis_analyzer.assess(candidate, target_endpoint=target_endpoint)
    if not assessment.testable:
        return (), ()

    attempts: list[PenetrationAttempt] = []
    evaluations: list[evidence_evaluator.AttemptEvaluation] = []
    tried: list[TestStrategy] = []
    corroboration_used = False

    while True:
        attempt_number = len(attempts) + 1
        budget_ok, budget_reason = tracker.can_attempt(candidate.candidate_id)
        strategy = hypothesis_analyzer.next_strategy(assessment, tried=tuple(tried))
        tools = ("runtime_workflows",)

        if strategy is None and budget_ok and corroboration_tools and not corroboration_used and tried and (
            evaluations and evaluations[-1].outcome in {"passed", "inconclusive"}
        ):
            # One corroboration round on the LAST strategy tried, with a different tool — not a new
            # strategy, and never run when runtime_workflows already produced a violation or every
            # attempt so far was blocked (nothing to corroborate in that case).
            strategy = tried[-1]
            tools = corroboration_tools
            corroboration_used = True

        if not budget_ok or strategy is None:
            if attempts:
                _, final_stop = evidence_evaluator.decide_next(
                    evaluations[-1].outcome, budget_ok=budget_ok, budget_stop_reason=budget_reason,
                    has_more_strategies=False,
                )
                attempts[-1] = _with_stop(attempts[-1], NextAction.STOP, final_stop)
            break

        is_corroboration = tools != ("runtime_workflows",)
        if not is_corroboration:
            tried.append(strategy)
        try:
            plan = attack_planner.build_plan(candidate, strategy, attempt_number=attempt_number,
                                             target_endpoint=target_endpoint, accounts=accounts, tools=tools)
            scenario_validator.validate_plan(plan, allowed_endpoints=allowed_endpoints,
                                             allowed_accounts=frozenset(account_definitions))
            suite = scenario_validator.build_and_validate_suite(plan, account_definitions=account_definitions)
        except (attack_planner.PlanUnavailable, scenario_validator.ScenarioRejected) as error:
            # This one strategy cannot be planned/validated; try the next applicable strategy, not a broken one.
            evaluations.append(evidence_evaluator.AttemptEvaluation("blocked", str(error),
                                                                     "Planning or validation rejected this strategy."))
            continue

        try:
            result = tool_orchestrator.execute(plan, suite, base_url=base_url, environment=environment,
                                               transport=transport, account_definitions=account_definitions,
                                               zap_context=zap_context)
        except tool_orchestrator.ToolUnavailable as error:
            evaluations.append(evidence_evaluator.AttemptEvaluation("blocked", str(error),
                                                                     "The selected tool is not available."))
            continue

        requests_made = result.get("coverage", {}).get("executed", len(plan.steps))
        tracker.record_attempt(candidate.candidate_id, requests_made=requests_made)
        request_evidence, response_evidence = evidence_collector.collect(result)
        label = strategy.value + ("_corroboration" if is_corroboration else "")
        evaluation = evidence_evaluator.evaluate_attempt(result, label)
        evaluations.append(evaluation)

        remaining = hypothesis_analyzer.next_strategy(assessment, tried=tuple(tried))
        can_corroborate_next = (not is_corroboration and not corroboration_used and bool(corroboration_tools)
                                and evaluation.outcome in {"passed", "inconclusive"})
        still_ok, still_reason = tracker.can_attempt(candidate.candidate_id)
        next_action, stop_reason = evidence_evaluator.decide_next(
            evaluation.outcome, budget_ok=still_ok, budget_stop_reason=still_reason,
            has_more_strategies=remaining is not None or can_corroborate_next,
        )
        attempts.append(PenetrationAttempt(
            candidate_id=candidate.candidate_id, hypothesis=assessment.hypothesis,
            entry_point=assessment.entry_point, target_endpoint=target_endpoint or "",
            attack_plan=plan.rationale, selected_tools=plan.selected_tools, attempt_number=attempt_number,
            test_strategy=strategy.value, request_evidence=request_evidence, response_evidence=response_evidence,
            observation=evaluation.observation, agent_reasoning_summary=evaluation.reasoning,
            next_action=next_action.value, stop_reason=stop_reason.value,
        ))
        if next_action is NextAction.STOP:
            break

    return tuple(attempts), tuple(evaluations)


def _with_stop(attempt: PenetrationAttempt, action: NextAction, reason: StopReason) -> PenetrationAttempt:
    from dataclasses import replace
    return replace(attempt, next_action=action.value, stop_reason=reason.value)

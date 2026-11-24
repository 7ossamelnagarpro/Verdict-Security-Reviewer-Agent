"""Two separate, narrow uses of an LLM for the Penetration Agent — neither one decides the hard security
fact of whether exploitation happened; both only make the loop's existing decisions better-informed.

1. :func:`choose_next_strategy` reasons over the hypothesis and every prior attempt's result to choose
   which of the four pre-approved templates (``unauthenticated_access``, ``authorization_matrix``,
   ``idor``, ``privilege_escalation``) to try next, or says "stop" — instead of the fixed keyword table
   in ``hypothesis_analyzer.py``.
2. :func:`interpret_evidence` writes a short narrative reading of one attempt's ALREADY-DECIDED,
   deterministic verdict and its bounded HTTP facts — for example, flagging that an "inconclusive" result
   still looks worth probing differently. This text is appended to that attempt's own reasoning (never
   changes its outcome) and, because it is then part of that hypothesis's prior-attempts history, the
   NEXT :func:`choose_next_strategy` call reads it too — so genuine interpretation of what happened can
   shape what gets tried next, without ever letting the model itself decide the yes/no fact.

What the model is, and is not, trusted with
--------------------------------------------
The model in (1) picks WHICH pre-approved template to try next; that choice is everything it controls.
It never sees, and never gets to specify, an endpoint, an account, a method, a payload, or any other
execution detail — those still come exclusively from ``attack_planner.py`` (built from the allowlisted
route/account the caller supplied) and are still re-checked by ``scenario_validator.py`` before anything
executes. A model reply naming anything other than one of the known template ids, verbatim, is rejected
outright and treated the same as "no usable decision" (see ``_parse_decision``) — there is no code path
from a model's text to an HTTP method, a URL, or an account that was not already allowlisted elsewhere.
The model in (2) never receives anything beyond the bounded facts already collected (status codes,
expected statuses, assertion results) and is explicitly told its reply cannot change the verdict; it has
no tool access and nothing it says is ever parsed as an instruction. Evidence is evaluated by the same
deterministic HTTP-status comparison as always (see ``evidence_evaluator.py``): neither use of the model
in this file ever becomes the thing that decides exploitation happened or didn't.

The model in (1) chooses freely among all four templates not yet tried for this hypothesis — it is not
first filtered down by the keyword table in ``hypothesis_analyzer.py``. That table still exists and is
used only as the FALLBACK ordering when no AI planner is configured, or when the AI call fails, returns
malformed JSON, or names anything that is not one of the known template ids verbatim (see
``_parse_decision``). Letting it choose among all four freely is still exactly as safe as the rule-based
path: there is no riskier template being unlocked — all four are the same fixed, read-only, allowlisted
building blocks either way, so widening which of them the model may pick next changes nothing about what
can execute.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from security_reviewer_v2.agents.tracing import node_trace
from security_reviewer_v2.discovery.models import CandidateFinding

from . import evidence_evaluator
from .hypothesis_analyzer import HypothesisAssessment
from .models import PenetrationAttempt, TestStrategy

_MAX_REASONING_CHARS = 600


class AttackPlanProvider(Protocol):
    def plan_attack(self, prompt: str, *, timeout_seconds: int | None) -> tuple[dict[str, Any], dict[str, Any]]: ...
    def interpret_evidence(self, prompt: str, *, timeout_seconds: int | None) -> tuple[dict[str, Any], dict[str, Any]]: ...


@dataclass(frozen=True)
class AIPlanDecision:
    strategy: TestStrategy | None   # None means "stop" or a safe fallback to rule-based selection
    reasoning: str
    source: str                     # "ai" | "fallback_no_provider" | "fallback_error" | "ai_stop"


def choose_next_strategy(
    candidate: CandidateFinding, assessment: HypothesisAssessment,
    prior_attempts: tuple[PenetrationAttempt, ...], *, tried: tuple[TestStrategy, ...],
    provider: AttackPlanProvider | None, timeout_seconds: int = 30,
) -> AIPlanDecision:
    """Ask the model which untried template (of all three) to run next for this hypothesis."""
    menu = tuple(strategy for strategy in TestStrategy if strategy not in tried)
    if provider is None:
        return AIPlanDecision(None, "No AI planner is configured for this run.", "fallback_no_provider")
    if not menu:
        return AIPlanDecision(None, "No untried template is applicable to this hypothesis.", "ai_stop")

    prompt = _build_prompt(candidate, menu, prior_attempts, entry_point=assessment.entry_point)
    # run_type="llm" + a messages-shaped input/output: this is what makes the span show up in LangSmith
    # as an actual chat transcript (what was asked, what the model replied) rather than a plain, collapsed
    # chain span — the one place in this module a reviewer can see the model's own reasoning.
    with node_trace("ai_planner.choose_next_strategy", run_type="llm",
                    inputs={"messages": [{"role": "user", "content": prompt}]}) as run:
        try:
            parsed, _usage = provider.plan_attack(prompt, timeout_seconds=timeout_seconds)
        except Exception as error:  # the provider boundary is adversarial-ish (network, rate limits, bad JSON)
            if run is not None:
                run.end(outputs={"messages": [{"role": "assistant", "content": f"<call failed: {error}>"}]})
            return AIPlanDecision(None, f"AI planner call failed: {error}", "fallback_error")
        if run is not None:
            run.end(outputs={"messages": [{"role": "assistant", "content": json.dumps(parsed)}]})
    return _parse_decision(parsed, menu)


def _build_prompt(candidate: CandidateFinding, menu: tuple[TestStrategy, ...],
                  prior_attempts: tuple[PenetrationAttempt, ...], *, entry_point: str | None = None) -> str:
    lines = [
        f"Hypothesis: {candidate.title}",
        f"Category: {candidate.category}",
        f"Why Discovery flagged it: {candidate.reasoning}"[:800],
    ]
    if entry_point:
        lines.append(f"Source entry point: {entry_point}"[:400])
    lines += ["", "Templates you may choose from (choose exactly one id, or \"stop\"):"]
    lines += [f"- {strategy.value}" for strategy in menu]
    lines.append("")
    if prior_attempts:
        lines.append("Attempts already made against this exact hypothesis:")
        for attempt in prior_attempts:
            lines.append(
                f"- Attempt {attempt.attempt_number} ({attempt.test_strategy} via "
                f"{', '.join(attempt.selected_tools)}): observed \u2014 {attempt.observation} "
                f"[reasoning: {attempt.agent_reasoning_summary}]"
            )
    else:
        lines.append("No attempts have been made against this hypothesis yet.")
    return "\n".join(lines)


def _parse_decision(parsed: dict[str, Any], menu: tuple[TestStrategy, ...]) -> AIPlanDecision:
    decision = parsed.get("decision") if isinstance(parsed, dict) else None
    reasoning = str(parsed.get("reasoning", "") if isinstance(parsed, dict) else "")[:_MAX_REASONING_CHARS]
    if not isinstance(decision, str):
        return AIPlanDecision(None, "AI planner reply had no usable decision field.", "fallback_error")
    decision = decision.strip().lower()
    if decision == "stop":
        return AIPlanDecision(None, reasoning or "The AI planner judged no further template would help.", "ai_stop")
    for strategy in menu:
        if strategy.value == decision:
            return AIPlanDecision(strategy, reasoning or f"The AI planner chose {strategy.value}.", "ai")
    # Anything else (a template not on the menu, a typo, free text) is NOT a usable decision: the known,
    # fixed set of template ids is the only vocabulary this function ever accepts as a real choice.
    return AIPlanDecision(None, f"AI planner returned an unrecognized decision ({decision!r}); "
                          "falling back to rule-based selection.", "fallback_error")


def interpret_evidence(
    candidate: CandidateFinding, strategy: TestStrategy, evaluation: "evidence_evaluator.AttemptEvaluation",
    response_evidence: tuple[dict[str, Any], ...], *, provider: AttackPlanProvider | None,
    timeout_seconds: int = 20,
) -> str | None:
    """A narrative AI reading of one already-finalized attempt's bounded evidence, or ``None``.

    This NEVER changes ``evaluation.outcome`` — that deterministic HTTP-status verdict is already final
    by the time this runs and is passed in only as context. What this adds is explanatory text (appended
    to the attempt's ``agent_reasoning_summary`` by the caller) that the NEXT :func:`choose_next_strategy`
    call will read as part of that hypothesis's prior-attempts history — so a genuinely richer reading of
    "does this still look worth probing a different way" can influence what the agent tries next, without
    ever letting the model itself decide the yes/no fact of whether exploitation happened.
    """
    if provider is None:
        return None
    prompt = (
        f"Hypothesis: {candidate.title}\n"
        f"Template tried: {strategy.value}\n"
        f"Deterministic verdict: {evaluation.outcome}\n"
        f"What was observed: {evaluation.observation}\n"
        f"Bounded HTTP facts: {json.dumps(response_evidence, sort_keys=True)[:1000]}"
    )
    with node_trace("ai_planner.interpret_evidence", run_type="llm",
                    inputs={"messages": [{"role": "user", "content": prompt}]}) as run:
        try:
            parsed, _usage = provider.interpret_evidence(prompt, timeout_seconds=timeout_seconds)
        except Exception as error:
            if run is not None:
                run.end(outputs={"messages": [{"role": "assistant", "content": f"<call failed: {error}>"}]})
            return None
        text = parsed.get("interpretation") if isinstance(parsed, dict) else None
        if run is not None:
            run.end(outputs={"messages": [{"role": "assistant", "content": json.dumps(parsed)}]})
    return str(text)[:_MAX_REASONING_CHARS] if isinstance(text, str) and text.strip() else None


def plan_attack_prompt_for_tests(candidate: CandidateFinding, menu: tuple[TestStrategy, ...],
                                 prior_attempts: tuple[PenetrationAttempt, ...], *,
                                 entry_point: str | None = None) -> str:
    """Test-only hook: exposes :func:`_build_prompt` under a stable public name."""
    return _build_prompt(candidate, menu, prior_attempts, entry_point=entry_point)

"""Tests for dynamic_penetration_agent.ai_planner: the LLM-based attack strategist.

Covers: a valid AI choice is honored and its reasoning reaches the report; an invalid/garbage AI reply
falls back to the rule-based choice; a provider error falls back too; the AI can never name anything
outside the three known template ids.
"""

from __future__ import annotations

from security_reviewer_v2.discovery.models import CandidateDisposition, CandidateFinding
from security_reviewer_v2.dynamic_penetration_agent import ai_planner
from security_reviewer_v2.dynamic_penetration_agent.hypothesis_analyzer import assess
from security_reviewer_v2.dynamic_penetration_agent.models import TestStrategy


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        candidate_id="c1", title="Missing authorization", category="authorization",
        severity="high", confidence="medium", path="api/app.py", start_line=10, end_line=20,
        evidence=("10: def get_order",), reasoning="Order route has no ownership check.",
        source="ai", verification=CandidateDisposition.SUPPORTED, verification_notes=(),
    )


class _FakeProvider:
    def __init__(self, reply: dict, *, raises: Exception | None = None):
        self.reply = reply
        self.raises = raises
        self.calls = 0

    def plan_attack(self, prompt, *, timeout_seconds):
        self.calls += 1
        if self.raises:
            raise self.raises
        return self.reply, {"provider": "fake"}


def test_a_valid_ai_choice_is_honored():
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    provider = _FakeProvider({"decision": "idor", "reasoning": "Evidence cites another account's order id."})
    decision = ai_planner.choose_next_strategy(candidate, assessment, (), tried=(), provider=provider)
    assert decision.strategy is TestStrategy.IDOR
    assert "another account" in decision.reasoning
    assert decision.source == "ai"


def test_an_explicit_stop_is_respected_and_not_treated_as_a_failure():
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    provider = _FakeProvider({"decision": "stop", "reasoning": "Every template has already been exhausted."})
    decision = ai_planner.choose_next_strategy(
        candidate, assessment, (), tried=(TestStrategy.IDOR, TestStrategy.AUTHORIZATION_MATRIX,
                                          TestStrategy.UNAUTHENTICATED_ACCESS),
        provider=provider,
    )
    assert decision.strategy is None
    assert decision.source == "ai_stop"


def test_an_unrecognized_decision_falls_back_safely_instead_of_executing_anything():
    """The model naming something outside the three known ids must never become a usable decision."""
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    provider = _FakeProvider({"decision": "sql_injection", "reasoning": "Let's try SQLi instead."})
    decision = ai_planner.choose_next_strategy(candidate, assessment, (), tried=(), provider=provider)
    assert decision.strategy is None
    assert decision.source == "fallback_error"


def test_a_malformed_reply_falls_back_safely():
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    provider = _FakeProvider({"nonsense": True})
    decision = ai_planner.choose_next_strategy(candidate, assessment, (), tried=(), provider=provider)
    assert decision.strategy is None
    assert decision.source == "fallback_error"


def test_a_provider_exception_falls_back_safely_and_never_propagates():
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    provider = _FakeProvider({}, raises=TimeoutError("provider timed out"))
    decision = ai_planner.choose_next_strategy(candidate, assessment, (), tried=(), provider=provider)
    assert decision.strategy is None
    assert decision.source == "fallback_error"
    assert "timed out" in decision.reasoning


def test_no_provider_configured_is_a_clean_no_op():
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    decision = ai_planner.choose_next_strategy(candidate, assessment, (), tried=(), provider=None)
    assert decision.strategy is None
    assert decision.source == "fallback_no_provider"


def test_the_ai_is_never_offered_a_strategy_that_was_already_tried():
    candidate = _candidate()
    assessment = assess(candidate, target_endpoint="/orders/5")
    provider = _FakeProvider({"decision": "idor", "reasoning": "x"})
    decision = ai_planner.choose_next_strategy(
        candidate, assessment, (), tried=(TestStrategy.IDOR,), provider=provider,
    )
    # "idor" was already tried, so even though the model said "idor", the prompt never offered it —
    # confirm the menu passed to the prompt excludes it.
    prompt = ai_planner.plan_attack_prompt_for_tests(candidate, (TestStrategy.AUTHORIZATION_MATRIX,
                                                                  TestStrategy.UNAUTHENTICATED_ACCESS), ())
    assert "idor" not in prompt
    assert decision.strategy is None  # "idor" is not on the real menu, so the model's answer is unusable
    assert decision.source == "fallback_error"

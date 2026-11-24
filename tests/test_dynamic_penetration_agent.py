"""Tests for the dynamic_penetration_agent package: adaptive loop, budget, scope limits."""

from __future__ import annotations

import pytest

from security_reviewer_v2.discovery.models import (
    CandidateDisposition,
    CandidateFinding,
    DiscoveryResult,
    DiscoveryStatus,
)
from security_reviewer_v2.dynamic_penetration_agent import (
    ExecutionBudget,
    RuntimeAccess,
    TestOutcome,
    run_penetration_tests,
)
from security_reviewer_v2.dynamic_penetration_agent.scenario_validator import ScenarioRejected, validate_plan
from security_reviewer_v2.dynamic_penetration_agent.models import AttackPlan, AttackStep, TestStrategy
from security_reviewer_v2.dynamic_penetration_agent.hypothesis_analyzer import assess
from security_reviewer_v2.verification.models import VerificationDisposition, VerificationRecord, VerificationResult

ACCOUNT_DEFINITIONS = {
    "user_b": {
        "id": "user_b", "login_path": "/auth/login", "verify_path": "/me", "encoding": "json",
        "session": "bearer", "token_path": "access_token", "username_field": "username",
        "password_field": "password", "identity_path": "username",
    }
}
ENVIRONMENT = {"SECURITY_TEST_WF_USER_B_USERNAME": "userb", "SECURITY_TEST_WF_USER_B_PASSWORD": "pw"}


def _candidate(**overrides) -> CandidateFinding:
    defaults = dict(
        candidate_id="c1", title="Missing authorization", category="authorization",
        severity="high", confidence="medium", path="api/app.py", start_line=10, end_line=20,
        evidence=("10: def get_order",), reasoning="Order route has no ownership check.",
        source="ai", verification=CandidateDisposition.SUPPORTED, verification_notes=(),
    )
    defaults.update(overrides)
    return CandidateFinding(**defaults)


def _discovery(candidate: CandidateFinding) -> DiscoveryResult:
    return DiscoveryResult("1.2", DiscoveryStatus.COMPLETED, "groq", "m", (), (candidate,), (), (), {})


def _confirmed(candidate_id: str) -> VerificationResult:
    return VerificationResult("1.0", "completed", "/", (
        VerificationRecord(candidate_id, VerificationDisposition.CONFIRMED, "api/app.py", 10, 20, (), (), ()),
    ), ())


class _FakeTransport:
    def __init__(self, response_status: int) -> None:
        self.response_status = response_status
        self.calls: list[tuple[str, str, str]] = []

    def request(self, actor, method, path, body=None, headers=None, encoding="json"):
        self.calls.append((actor, method, path))
        if path == "/auth/login":
            return 200, {"access_token": "tok-" + actor}
        if path == "/me":
            return 200, {"username": "userb"}
        return self.response_status, {"id": 5}


def _access(endpoint: str, *, transport_status: int) -> tuple[RuntimeAccess, _FakeTransport]:
    transport = _FakeTransport(transport_status)
    return RuntimeAccess(
        base_url="http://127.0.0.1:5000", allowed_endpoints=frozenset({endpoint}),
        accounts=("user_b",), account_definitions=ACCOUNT_DEFINITIONS, environment=ENVIRONMENT,
    ), transport


def test_exploitation_confirmed_stops_immediately_on_first_violation():
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=200)  # other account can read it: vulnerable
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED
    assert len(result.attempts) == 1
    assert result.attempts[0].next_action == "stop"
    assert result.attempts[0].stop_reason == "exploitation_confirmed"
    assert result.attempts[0].provenance == "ai_penetration_test"


def test_not_reproduced_when_every_template_is_denied():
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)  # correctly denied
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.NOT_REPRODUCED
    assert result.attempts[-1].stop_reason == "no_further_strategy"
    # Every attempt stays below the per-hypothesis attempt budget by itself.
    assert len(result.attempts) <= ExecutionBudget().max_attempts_per_hypothesis


def test_cannot_test_without_a_resolvable_route():
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: None, transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.CANNOT_TEST
    assert result.attempts == ()
    assert transport.calls == []  # no request was ever made


def test_only_verification_confirmed_candidates_are_tested():
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)
    unconfirmed = VerificationResult("1.0", "completed", "/", (
        VerificationRecord("c1", VerificationDisposition.NEEDS_MORE_EVIDENCE, "api/app.py", 10, 20, (), (), ()),
    ), ())
    report = run_penetration_tests(
        _discovery(candidate), unconfirmed, access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    assert report.status == "not_run"
    assert report.results == ()
    assert transport.calls == []


def test_budget_stops_the_loop_even_with_more_strategies_available():
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5",
        budget=ExecutionBudget(max_attempts_per_hypothesis=1), transport=transport,
    )
    result = report.results[0]
    assert len(result.attempts) == 1
    assert result.attempts[0].stop_reason == "budget_exhausted"


def test_scenario_validator_rejects_an_endpoint_outside_the_allowlist():
    plan = AttackPlan(
        candidate_id="c1", attempt_number=1, test_strategy=TestStrategy.UNAUTHENTICATED_ACCESS,
        target_endpoint="/admin/secret", selected_tools=("runtime_workflows",),
        steps=(AttackStep(actor="anonymous", method="GET", path="/admin/secret"),),
        accounts=(), rationale="x",
    )
    with pytest.raises(ScenarioRejected):
        validate_plan(plan, allowed_endpoints=frozenset({"/orders/5"}), allowed_accounts=frozenset())


def test_scenario_validator_rejects_a_mutating_method():
    plan = AttackPlan(
        candidate_id="c1", attempt_number=1, test_strategy=TestStrategy.UNAUTHENTICATED_ACCESS,
        target_endpoint="/orders/5", selected_tools=("runtime_workflows",),
        steps=(AttackStep(actor="anonymous", method="DELETE", path="/orders/5"),),
        accounts=(), rationale="x",
    )
    with pytest.raises(ScenarioRejected):
        validate_plan(plan, allowed_endpoints=frozenset({"/orders/5"}), allowed_accounts=frozenset())


def test_corroboration_round_uses_zap_after_a_clean_http_result(monkeypatch):
    """A denied runtime_workflows result is corroborated once with ZAP — not repeated, not skipped."""
    from security_reviewer_v2.dynamic_penetration_agent import tool_orchestrator, zap_attempt

    def fake_zap(base_url, target_endpoint, *, stack_name, app_service, auth, max_seconds=180):
        assert stack_name == "sr-test-stack" and app_service == "app"
        return {"workflows": [{"status": "completed", "steps": [{
            "step": 1, "actor": "user_b", "method": "ZAP_ACTIVE_SCAN", "path": target_endpoint,
            "security_check": True, "status": "violation", "reason": "ZAP found an access-control alert here.",
            "http_status": None, "expected_status": [],
        }]}]}

    monkeypatch.setattr(zap_attempt, "run_scoped_attempt", fake_zap)
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)  # plain HTTP: correctly denied
    access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                           access.account_definitions, access.environment,
                           zap_context={"stack_name": "sr-test-stack", "app_service": "app"})
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED
    assert "ZAP" in result.attempts[-1].observation
    assert result.attempts[-1].selected_tools == ("zap", "playwright") or result.attempts[-1].selected_tools == ("zap",)
    # The corroboration attempt only ever runs once: no second zap/playwright attempt follows it.
    corroboration_attempts = [a for a in result.attempts if "zap" in a.selected_tools or "playwright" in a.selected_tools]
    assert len(corroboration_attempts) == 1


def test_no_corroboration_without_zap_or_playwright_configured():
    """With RuntimeAccess.corroboration_tools empty (the default), the loop never tries zap/playwright."""
    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)
    assert access.corroboration_tools == ()
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert all(a.selected_tools == ("runtime_workflows",) for a in result.attempts)


def test_tool_orchestrator_falls_back_to_the_next_named_tool_when_zap_is_unavailable():
    from security_reviewer_v2.dynamic_penetration_agent import tool_orchestrator
    from security_reviewer_v2.dynamic_penetration_agent.models import AttackPlan, AttackStep, TestStrategy

    plan = AttackPlan(
        candidate_id="c1", attempt_number=1, test_strategy=TestStrategy.UNAUTHENTICATED_ACCESS,
        target_endpoint="/orders/5", selected_tools=("zap", "runtime_workflows"),
        steps=(AttackStep(actor="anonymous", method="GET", path="/orders/5", expect_status=(401, 403, 404)),),
        accounts=(), rationale="x",
    )
    suite = {"version": 1, "accounts": [], "workflows": [{"id": "w", "title": "t", "severity": "high",
             "steps": [{"actor": "anonymous", "method": "GET", "path": "/orders/5",
                       "security_check": True, "expect_status": [401, 403, 404]}]}],
             "max_requests": 4, "timeout_seconds": 10, "max_seconds": 30, "allow_mutation": False, "reset": "none"}
    transport = _FakeTransport(403)
    # zap_context is None, so "zap" is unavailable; the orchestrator should fall through to runtime_workflows.
    result = tool_orchestrator.execute(plan, suite, base_url="http://127.0.0.1:5000", transport=transport,
                                       zap_context=None)
    assert result["workflows"][0]["steps"][0]["status"] == "passed"


def test_final_report_lists_every_attempt_as_a_reproduction_step():
    """The security engineer can see exactly what the agent tried for a confirmed exploit — not just a verdict."""
    from security_reviewer_v2.reporting.final import render_final_report

    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=200)  # vulnerable: other account can read it
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    md = render_final_report(project="demo", review={"status": "completed", "reviews": []},
                             policy={"status": "passed", "decisions": [], "blocking": False},
                             penetration_test=report.to_dict())
    assert "## Autonomous Penetration Testing" in md
    assert "exploitation_confirmed" in md
    # The actual HTTP status and what was expected must be visible, not just the verdict label.
    assert "`GET /orders/5` as `user_b`" in md
    assert "`200`" in md
    assert "expected one of [401, 403, 404]" in md


def test_considered_but_not_executed_records_scenarios_that_never_fired_a_request():
    """Strategies the agent drew up but couldn't run (no account available) are not silently dropped."""
    candidate = _candidate()  # reasoning mentions "ownership" and "authorization" -> idor + authz_matrix + http
    access = RuntimeAccess("http://127.0.0.1:5000", frozenset({"/orders/5"}), (), {})  # no accounts at all
    transport = _FakeTransport(200)  # vulnerable even unauthenticated
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED  # unauthenticated_access still ran
    strategies_blocked = {gap["strategy"] for gap in result.considered_but_not_executed}
    assert "idor" in strategies_blocked
    assert "authorization_matrix" in strategies_blocked
    assert all("account" in gap["reason"].lower() for gap in result.considered_but_not_executed)


def test_report_lists_scenarios_considered_but_never_executed():
    from security_reviewer_v2.reporting.final import render_final_report

    candidate = _candidate()
    access = RuntimeAccess("http://127.0.0.1:5000", frozenset({"/orders/5"}), (), {})
    transport = _FakeTransport(200)
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    md = render_final_report(project="demo", review={"status": "completed", "reviews": []},
                             policy={"status": "passed", "decisions": [], "blocking": False},
                             penetration_test=report.to_dict())
    assert "could not execute at all" in md
    assert "`idor`" in md or "idor" in md


def test_report_marks_a_finding_as_confirmed_by_the_penetration_agent():
    from security_reviewer_v2.reporting.final import render_final_report

    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=200)
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    # c1 was merged with a scanner finding into review group "merged-xyz" — the report must still find it.
    triage = {"groups": [{"group_id": "merged-xyz", "candidate_ids": ["c1"]}]}
    review = {"status": "completed", "reviews": [{
        "candidate_id": "merged-xyz", "title": "Missing authorization", "verdict": "likely_vulnerability",
        "severity": "high", "confidence": "medium", "explanation": "x", "impact": "x", "remediation": "x",
    }]}
    policy = {"status": "passed", "decisions": [{"candidate_id": "merged-xyz", "action": "block", "reason": "x"}],
             "blocking": True}
    md = render_final_report(project="demo", review=review, policy=policy, triage=triage,
                             penetration_test=report.to_dict())
    assert "Independently confirmed by the Autonomous Penetration Agent" in md
    assert "confirmed by Penetration Agent" in md  # the Policy Decisions one-liner marker


def test_ai_planner_drives_the_adaptive_loop_end_to_end():
    """With an AI provider configured, its chosen strategy and reasoning reach the final attempt record."""
    class _FakeAIProvider:
        def plan_attack(self, prompt, *, timeout_seconds):
            # Always goes straight for IDOR-style authorization_matrix, citing its own reasoning.
            return {"decision": "authorization_matrix",
                    "reasoning": "The hypothesis describes an ownership check gap; test cross-account access first."}, {}

    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=200)  # vulnerable
    access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                           access.account_definitions, access.environment, ai_provider=_FakeAIProvider())
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED
    assert result.attempts[0].test_strategy == "authorization_matrix"
    assert "AI planner:" in result.attempts[0].attack_plan
    assert "ownership check gap" in result.attempts[0].attack_plan


def test_ai_planner_failure_falls_back_to_rule_based_selection_without_stalling():
    """A broken AI provider must not stop the agent from still testing the hypothesis."""
    class _BrokenAIProvider:
        def plan_attack(self, prompt, *, timeout_seconds):
            raise RuntimeError("provider unreachable")

    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)  # correctly denied
    access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                           access.account_definitions, access.environment, ai_provider=_BrokenAIProvider())
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.NOT_REPRODUCED
    assert len(result.attempts) >= 1  # the agent still ran, via the rule-based fallback


def test_a_blocked_login_does_not_stop_the_loop_while_an_untried_template_remains():
    """Regression: if authorization_matrix's login fails, the agent must still try
    unauthenticated_access (which needs no login at all) before giving up — not stop at 1 attempt."""
    candidate = _candidate(title="Missing ownership verification in coupon application",
                           reasoning="Missing ownership check: Authorization (CWE-639)")

    class _FlakyLoginTransport:
        def __init__(self, *a): pass
        def request(self, actor, method, path, body=None, headers=None, encoding="json"):
            if actor == "user_b" and path == "/auth/login":
                return 500, {}  # the one account's login fails -> that attempt is "blocked"
            if actor == "anonymous":
                return 200, {"id": 5}  # vulnerable with no session at all
            return 404, {}

    access = RuntimeAccess(
        "http://127.0.0.1:5000", frozenset({"/orders/5"}), ("user_b",), ACCOUNT_DEFINITIONS, ENVIRONMENT,
    )
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=_FlakyLoginTransport(),
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED
    assert len(result.attempts) >= 2  # did not stop after the one blocked attempt
    assert any(a.test_strategy == "unauthenticated_access" for a in result.attempts)
    assert result.attempts[-1].stop_reason == "exploitation_confirmed"


def test_ai_evidence_interpretation_enriches_the_attempt_without_changing_the_verdict():
    """The AI's narrative reading of a finalized attempt reaches the report but never flips the outcome."""
    class _FakeAIProvider:
        def plan_attack(self, prompt, *, timeout_seconds):
            return {"decision": "authorization_matrix", "reasoning": "Start with cross-account access."}, {}

        def interpret_evidence(self, prompt, *, timeout_seconds):
            return {"interpretation": "The denial looks solid; no further probing of this account is useful."}, {}

    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)  # correctly denied
    access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                           access.account_definitions, access.environment, ai_provider=_FakeAIProvider())
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.NOT_REPRODUCED  # the deterministic verdict is unchanged
    assert "AI interpretation:" in result.attempts[0].agent_reasoning_summary
    assert "denial looks solid" in result.attempts[0].agent_reasoning_summary


class _CountingAIProvider:
    """Picks the first template on the menu and counts every model call, to prove no call is wasted."""

    def __init__(self) -> None:
        self.plan_calls = 0
        self.interpret_calls = 0

    def plan_attack(self, prompt, *, timeout_seconds):
        self.plan_calls += 1
        menu = prompt.split("choose exactly one id", 1)[1].split("\n\n", 1)[0].splitlines()[1:]
        return {"decision": menu[0].lstrip("- ").strip(), "reasoning": "next"}, {}

    def interpret_evidence(self, prompt, *, timeout_seconds):
        self.interpret_calls += 1
        return {"interpretation": "read"}, {}


def test_no_planner_or_interpretation_call_is_spent_after_the_budget_is_exhausted():
    provider = _CountingAIProvider()
    access, transport = _access("/orders/5", transport_status=403)
    access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                           access.account_definitions, access.environment, ai_provider=provider)
    report = run_penetration_tests(
        _discovery(_candidate()), _confirmed("c1"), access=access, budget=ExecutionBudget(max_attempts_per_hypothesis=2),
        target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
    )
    result = report.results[0]
    assert len(result.attempts) == 2 and result.attempts[-1].stop_reason == "budget_exhausted"
    # one planner call per decision that could still lead to an attempt - none for the stop that the budget forced
    assert provider.plan_calls == len(result.attempts) + len(result.considered_but_not_executed)
    # the attempt that exhausted the budget is not interpreted; the one before it is
    assert provider.interpret_calls == len(result.attempts) - 1
    assert "AI interpretation:" not in result.attempts[-1].agent_reasoning_summary


def test_rule_based_menu_now_offers_many_templates_not_just_a_few():
    """The deterministic fallback itself now draws from ~9 templates for a typical authz hypothesis."""
    candidate = _candidate()  # mentions "ownership" and "authorization"
    assessment = assess(candidate, target_endpoint="/orders/5")
    assert len(assessment.candidate_strategies) >= 8
    names = {s.value for s in assessment.candidate_strategies}
    assert {"head_method_bypass", "trailing_slash_bypass", "case_sensitivity_bypass",
            "path_normalization_bypass", "extension_suffix_bypass"}.issubset(names)


def test_bypass_templates_find_the_vulnerability_when_other_templates_are_denied():
    """Each new bypass template can independently confirm exploitation when the 'normal' path is denied
    but the bypassed variant is not."""
    candidate = _candidate()

    class _OnlyTrailingSlashVulnerable:
        def __init__(self, *a): pass
        def request(self, actor, method, path, body=None, headers=None, encoding="json"):
            if path == "/orders/5/":
                return 200, {"id": 5}  # the bypassed variant leaks data
            return 403, {}  # everything else, including the canonical path, is denied

    access = RuntimeAccess("http://127.0.0.1:5000", frozenset({"/orders/5"}), (), {})
    report = run_penetration_tests(
        _discovery(candidate), _confirmed("c1"), access=access,
        target_endpoint_resolver=lambda c: "/orders/5", transport=_OnlyTrailingSlashVulnerable(),
    )
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED
    assert any(a.test_strategy == "trailing_slash_bypass" for a in result.attempts)


def test_corroboration_uses_the_last_strategy_that_actually_executed_not_the_last_tried():
    """Regression: with many templates, the strategy picked LAST for 'tried' can be one that never
    executed (planning-gap) — corroboration must still target the last one that actually ran."""
    from security_reviewer_v2.dynamic_penetration_agent import zap_attempt

    def fake_zap(base_url, target_endpoint, *, stack_name, app_service, auth, max_seconds=180):
        return {"workflows": [{"status": "completed", "steps": [{
            "step": 1, "actor": "anonymous", "method": "ZAP_ACTIVE_SCAN", "path": target_endpoint,
            "security_check": True, "status": "violation", "reason": "ZAP found an alert here.",
            "http_status": None, "expected_status": [],
        }]}]}

    original = zap_attempt.run_scoped_attempt
    zap_attempt.run_scoped_attempt = fake_zap
    try:
        candidate = _candidate()  # offers idor + idor_parameter_pollution, both blocked (no evidence/account)
        access, transport = _access("/orders/5", transport_status=403)  # every real template: denied
        access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                               access.account_definitions, access.environment,
                               zap_context={"stack_name": "sr-test-stack", "app_service": "app"})
        report = run_penetration_tests(
            _discovery(candidate), _confirmed("c1"), access=access,
            target_endpoint_resolver=lambda c: "/orders/5", transport=transport,
        )
    finally:
        zap_attempt.run_scoped_attempt = original
    result = report.results[0]
    assert result.outcome is TestOutcome.EXPLOITATION_CONFIRMED
    assert any("zap" in a.selected_tools for a in result.attempts)
    # idor and idor_parameter_pollution never executed at all (no evidence/account) — they must not be
    # mistaken for "the last executed strategy" that gets corroborated.
    gap_strategies = {g["strategy"] for g in result.considered_but_not_executed}
    assert "idor" in gap_strategies and "idor_parameter_pollution" in gap_strategies


def test_path_normalization_bypass_only_ever_uses_a_proven_equivalent_path():
    from security_reviewer_v2.dynamic_penetration_agent import path_variants

    for path in ("/orders/5", "/admin/panel", "/a/b/c/5", "/x"):
        variant = path_variants.dot_segment_detour(path)
        if variant is not None:
            import posixpath
            assert posixpath.normpath(variant) == posixpath.normpath(path)


def test_each_ai_call_gets_its_own_named_langsmith_span(monkeypatch):
    """Regression: previously only the outer 'dynamic_penetration_agent' node had a span, so individual
    LLM decisions never showed up in LangSmith at all — each AI call must now open its own named,
    llm-typed span (around the actual model call, in ai_planner.py) showing the real prompt/reply."""
    from security_reviewer_v2.dynamic_penetration_agent import ai_planner

    seen = []

    class _FakeRun:
        def end(self, outputs=None):
            pass

    from contextlib import contextmanager

    @contextmanager
    def fake_node_trace(name, inputs=None, run_type="chain"):
        seen.append((name, run_type))
        yield _FakeRun()

    monkeypatch.setattr(ai_planner, "node_trace", fake_node_trace)

    class _FakeAIProvider:
        def plan_attack(self, prompt, *, timeout_seconds):
            return {"decision": "unauthenticated_access", "reasoning": "x"}, {}

        def interpret_evidence(self, prompt, *, timeout_seconds):
            return {"interpretation": "y"}, {}

    candidate = _candidate()
    access, transport = _access("/orders/5", transport_status=403)
    access = RuntimeAccess(access.base_url, access.allowed_endpoints, access.accounts,
                           access.account_definitions, access.environment, ai_provider=_FakeAIProvider())
    run_penetration_tests(_discovery(candidate), _confirmed("c1"), access=access,
                          target_endpoint_resolver=lambda c: "/orders/5", transport=transport)
    seen_names = {name for name, _run_type in seen}
    assert "ai_planner.choose_next_strategy" in seen_names
    assert "ai_planner.interpret_evidence" in seen_names
    # Both are llm-typed so LangSmith renders the actual prompt/reply transcript, not a plain chain span.
    assert all(run_type == "llm" for _name, run_type in seen)


def test_scenario_validator_rejects_an_account_outside_the_contract():
    plan = AttackPlan(
        candidate_id="c1", attempt_number=1, test_strategy=TestStrategy.AUTHORIZATION_MATRIX,
        target_endpoint="/orders/5", selected_tools=("runtime_workflows",),
        steps=(AttackStep(actor="made_up_actor", method="GET", path="/orders/5"),),
        accounts=("made_up_actor",), rationale="x",
    )
    with pytest.raises(ScenarioRejected):
        validate_plan(plan, allowed_endpoints=frozenset({"/orders/5"}), allowed_accounts=frozenset({"user_b"}))

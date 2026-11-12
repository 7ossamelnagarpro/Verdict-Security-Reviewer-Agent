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


def test_scenario_validator_rejects_an_account_outside_the_contract():
    plan = AttackPlan(
        candidate_id="c1", attempt_number=1, test_strategy=TestStrategy.AUTHORIZATION_MATRIX,
        target_endpoint="/orders/5", selected_tools=("runtime_workflows",),
        steps=(AttackStep(actor="made_up_actor", method="GET", path="/orders/5"),),
        accounts=("made_up_actor",), rationale="x",
    )
    with pytest.raises(ScenarioRejected):
        validate_plan(plan, allowed_endpoints=frozenset({"/orders/5"}), allowed_accounts=frozenset({"user_b"}))

"""A lost provider response must cost one retry with a smaller request, not the whole discovery run.

Regression for run_comprehensive_008: Groq closed the connection while the answer was being read (115 s call), the
failure was treated as an outage and discovery stopped after batch 1 with 0 of 20 targets inspected.
"""

from pathlib import Path

from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.provider import _GroqTransportFailure
from test_ai_discovery import _inputs


def _lost(category="connection_closed", prefix="AI provider JSON fallback failed: "):
    return _GroqTransportFailure(
        f"{prefix}AI provider request failed ({category}): connection closed while reading the response (ConnectionResetError)",
        category, 1, 1, 0.0)


class Flaky:
    name, model = "fake", "test"

    def __init__(self, plan):
        self.plan, self.calls, self.prompts = list(plan), 0, []

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        self.calls += 1
        self.prompts.append(prompt)
        outcome = self.plan.pop(0) if self.plan else None
        if outcome is not None:
            raise outcome
        return {"candidates": [], "context_requests": []}, {"prompt_tokens": 4}


def _run(tmp_path: Path, plan, **config):
    merged, context, risk, profile = _inputs(tmp_path)
    provider = Flaky(plan)
    result = DiscoveryAgent(provider, DiscoveryConfig(**config)).run(merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    return provider, result


def _recovered(result, baseline):
    """Same outcome as a run without any failure: nothing failed, nothing left uninspected, same scope and status."""
    assert not any(b.status == "failed" for b in result.batches)
    assert len(result.scope) == len(baseline.scope) > 0
    assert result.status == baseline.status
    assert not any("not inspected" in g or "did not complete" in g for g in result.coverage_gaps)


def test_one_lost_response_is_retried_smaller_and_discovery_completes(tmp_path):
    reference, baseline = _run(tmp_path, [], max_targets=4)
    provider, result = _run(tmp_path, [_lost()], max_targets=4)
    _recovered(result, baseline)
    assert len(provider.prompts[1]) < len(provider.prompts[0])                             # the retry was a smaller request
    assert any("response was lost after the request was sent" in w and "1 of 2" in w for w in result.warnings)
    assert reference.calls < provider.calls


def test_a_read_timeout_is_treated_the_same_way(tmp_path):
    _, baseline = _run(tmp_path, [], max_targets=3)
    _, result = _run(tmp_path, [_lost("timeout", "")], max_targets=3)
    _recovered(result, baseline)


def test_repeated_lost_responses_stop_discovery_as_an_outage(tmp_path):
    provider, result = _run(tmp_path, [_lost(), _lost(), _lost(), _lost()], max_targets=4)
    assert provider.calls == 3                                                              # 2 retries, then it gives up
    assert any(b.status == "failed" for b in result.batches)
    assert any("did not complete" in g for g in result.coverage_gaps)


def test_a_success_resets_the_failure_streak(tmp_path):
    _, baseline = _run(tmp_path, [], max_targets=1)
    provider, result = _run(tmp_path, [_lost(), None, _lost(), None, _lost()], max_targets=1)
    _recovered(result, baseline)
    assert provider.calls >= 6


def test_failures_before_the_request_was_sent_still_stop_immediately(tmp_path):
    for category in ("dns", "tls", "connection"):
        provider, result = _run(tmp_path, [_lost(category, "")], max_targets=4)
        assert provider.calls == 1 and any(b.status == "failed" for b in result.batches), category


def test_a_lost_follow_up_keeps_the_first_response(tmp_path):
    class ContextThenLost(Flaky):
        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.calls += 1
            if self.calls == 1:
                return {"candidates": [], "context_requests": [{"path": "app.py", "start_line": 1}]}, {}
            raise _lost()
    merged, context, risk, profile = _inputs(tmp_path)
    provider = ContextThenLost([])
    result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=1, max_batches=1)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    assert any("the first response was kept" in g for g in result.coverage_gaps)
    assert result.batches[0].status == "completed"

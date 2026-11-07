"""A single target that keeps breaking the model's JSON output gets one different last attempt before it is a gap."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_reviewer_v2.discovery import provider as provider_module
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.provider import GroqProvider, ProviderResponseError

from tests.test_ai_discovery import _inputs
from tests.test_provider_resilience import (  # noqa: F401  (autouse fixture is re-used)
    API_KEY, PLAIN, PROMPT, STRICT, Wire, _fresh_rate_state, completion, validate_failed,
)

EMPTY_GENERATION = lambda: validate_failed(generated="")   # noqa: E731  Groq: "model output 0 chars"


def rescue(model: str = STRICT):
    return GroqProvider(model=model, api_key=API_KEY).discover_rescue(PROMPT, timeout_seconds=10, max_candidates=5)


# ------------------------------------------------------------------ provider level
def test_rescue_request_drops_constrained_decoding_and_lowers_reasoning(monkeypatch):
    sent: list[dict] = []
    wire = Wire(monkeypatch, completion())
    original = wire._open
    monkeypatch.setattr(provider_module, "_urlopen",
                        lambda request, timeout: (sent.append(json.loads(request.data)), original(request, timeout))[1])
    rescue()
    body = sent[0]
    assert "response_format" not in body and body["reasoning_effort"] == "low" and body["temperature"] > 0


def test_rescue_does_not_send_reasoning_effort_to_other_models(monkeypatch):
    sent: list[dict] = []
    wire = Wire(monkeypatch, completion())
    original = wire._open
    monkeypatch.setattr(provider_module, "_urlopen",
                        lambda request, timeout: (sent.append(json.loads(request.data)), original(request, timeout))[1])
    rescue(PLAIN)
    assert "reasoning_effort" not in sent[0]


def test_rescue_accepts_fenced_json_and_reads_omitted_nullable_anchors_as_null(monkeypatch):
    candidate = {"title": "t", "category": "c", "severity": "low", "confidence": "low", "path": "a.py", "start_line": 1,
                 "end_line": 1, "evidence": ["x"], "reasoning": "r"}      # no anchors, no remaining_questions
    Wire(monkeypatch, completion("```json\n" + json.dumps({"candidates": [candidate]}) + "\n```"))
    result, usage = rescue()
    assert result["candidates"][0]["entry_point"] is None and result["candidates"][0]["remaining_questions"] == []
    assert usage["rescue_attempt"] == 1 and usage["format_fallback_count"] == 1


def test_rescue_extracts_the_object_from_surrounding_prose(monkeypatch):
    Wire(monkeypatch, completion('Here you go: {"candidates": [], "context_requests": []} Hope it helps.'))
    assert rescue()[0]["candidates"] == []


@pytest.mark.parametrize("content", ["no json at all", '{"candidates": "nope"}', '{"candidates": [{"title": 1}]}'])
def test_rescue_never_accepts_an_unusable_reply(monkeypatch, content):
    Wire(monkeypatch, completion(content))
    with pytest.raises(ProviderResponseError):
        rescue()


def test_rescue_failure_is_a_batch_level_error_and_leaks_nothing(monkeypatch):
    wire = Wire(monkeypatch, EMPTY_GENERATION)
    with pytest.raises(ProviderResponseError) as error:
        rescue()
    assert "json_validate_failed" in str(error.value) and API_KEY not in str(error.value)
    assert wire.calls == 2                       # the single immediate format retry, nothing more


# ------------------------------------------------------------------ graph level
class StubbornProvider:
    """discover() always breaks; discover_rescue() behaves as configured."""

    name, model = "fake", "test"

    def __init__(self, rescue_works: bool | None):
        self.rescue_works, self.discover_calls, self.rescue_calls = rescue_works, 0, 0
        if rescue_works is not None:
            self.discover_rescue = self._rescue

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        self.discover_calls += 1
        raise ProviderResponseError("AI provider request failed with HTTP 400 (json_validate_failed); model output 0 chars, not valid JSON")

    def _rescue(self, prompt, *, timeout_seconds, max_candidates):
        self.rescue_calls += 1
        if not self.rescue_works:
            raise ProviderResponseError("AI provider request failed with HTTP 400 (json_validate_failed); model output 0 chars, not valid JSON")
        return {"candidates": [], "context_requests": []}, {"prompt_tokens": 1}


def _run(tmp_path: Path, provider):
    merged, context, risk, profile = _inputs(tmp_path)
    return DiscoveryAgent(provider, DiscoveryConfig(max_targets=1)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile)


def test_rescue_recovers_a_target_that_the_normal_request_cannot_get_answered(tmp_path: Path):
    provider = StubbornProvider(rescue_works=True)
    result = _run(tmp_path, provider)
    assert provider.rescue_calls >= 1
    assert result.status.value == "completed" and not any("not inspected" in gap for gap in result.coverage_gaps)


def test_failed_rescue_is_tried_once_per_target_then_reported_as_a_gap(tmp_path: Path):
    provider = StubbornProvider(rescue_works=False)
    result = _run(tmp_path, provider)
    assert provider.rescue_calls == provider.discover_calls          # exactly one rescue per broken target
    assert result.status.value != "completed"
    assert any("even when sent alone" in gap and "not inspected" in gap for gap in result.coverage_gaps)


def test_providers_without_a_rescue_method_keep_the_previous_behaviour(tmp_path: Path):
    provider = StubbornProvider(rescue_works=None)
    result = _run(tmp_path, provider)
    assert result.status.value != "completed"
    assert any("even when sent alone" in gap for gap in result.coverage_gaps)

"""Several API keys of one provider share the work; Gemini works through the same provider interface."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from security_reviewer_v2.discovery import provider as pm


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    pm._RATE_STATE.clear()
    pm._KEY_COOLDOWN.clear()
    for var in ("GROQ_API_KEY", "GROQ_API_KEYS", "GEMINI_API_KEY", "GOOGLE_API_KEY", *(f"GROQ_API_KEY_{i}" for i in range(2, 10))):
        monkeypatch.delenv(var, raising=False)
    yield
    pm._RATE_STATE.clear()
    pm._KEY_COOLDOWN.clear()


class FakeKey:
    """One key's provider: records calls, optionally raising HTTP 429 (and noting whether it was asked to fail fast)."""

    name, model = "groq", "m"

    def __init__(self, key: str, limited: bool = False, wait: float | None = 30) -> None:
        self.api_key, self.limited, self.wait, self.calls, self.fail_fast_seen = key, limited, wait, 0, []

    def _answer(self):
        self.calls += 1
        self.fail_fast_seen.append(pm._FAIL_FAST_ON_429.get())
        if self.limited:
            suffix = f"; provider asked to wait {self.wait:.0f} s" if self.wait is not None else "; provider sent no usable Retry-After"
            raise pm._GroqHTTPFailure(f"AI provider request failed with HTTP 429{suffix}", 429, 0, 0.0)
        return {"candidates": []}, {"provider": "groq"}

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        return self._answer()

    def plan_attack(self, prompt, *, timeout_seconds):
        return self._answer()


def _discover(pool):
    return pool.discover("p", timeout_seconds=1, max_candidates=1)


def test_calls_are_split_evenly_between_the_keys_and_report_the_slot_not_the_key():
    a, b = FakeKey("key-A"), FakeKey("key-B")
    pool = pm.KeyPoolProvider([a, b])
    slots = [_discover(pool)[1]["key_slot"] for _ in range(6)]
    assert (a.calls, b.calls) == (3, 3) and set(slots) == {"1/2", "2/2"}
    assert "key-A" not in json.dumps(slots)


def test_a_rate_limited_key_hands_the_call_to_the_other_key_without_waiting():
    limited, free = FakeKey("key-A", limited=True), FakeKey("key-B")
    pool = pm.KeyPoolProvider([limited, free])
    payload, usage = _discover(pool)
    assert usage["key_slot"] == "2/2" and free.calls == 1
    assert limited.fail_fast_seen == [True]                 # it was told not to sleep out a Retry-After
    # the limited key now rests: the next calls go straight to the free key
    for _ in range(3):
        _discover(pool)
    assert limited.calls == 1 and free.calls == 4


def test_cooldown_is_shared_between_pools_so_every_stage_benefits():
    limited, free = FakeKey("key-A", limited=True), FakeKey("key-B")
    _discover(pm.KeyPoolProvider([limited, free]))
    later = pm.KeyPoolProvider([limited, free])             # another stage builds its own pool over the same keys
    for _ in range(3):
        _discover(later)
    assert limited.calls == 1


def test_when_every_key_is_limited_the_last_one_waits_normally_and_its_error_surfaces():
    a, b = FakeKey("key-A", limited=True), FakeKey("key-B", limited=True)
    with pytest.raises(pm._GroqHTTPFailure, match="429"):
        _discover(pm.KeyPoolProvider([a, b]))
    assert a.fail_fast_seen == [True] and b.fail_fast_seen == [False]   # only the final key may sleep through Retry-After


def test_only_rate_limits_fail_over_other_errors_are_not_repeated_on_a_second_key():
    class TooLarge(FakeKey):
        def _answer(self):
            self.calls += 1
            raise pm.RequestTooLargeError("HTTP 413", 413, 0, 0.0)

    a, b = TooLarge("key-A"), FakeKey("key-B")
    pool = pm.KeyPoolProvider([a, b])
    with pytest.raises(pm.RequestTooLargeError):
        _discover(pool)
    assert a.calls == 1 and b.calls == 0


def test_fail_fast_flag_does_not_leak_after_a_call():
    pool = pm.KeyPoolProvider([FakeKey("key-A", limited=True), FakeKey("key-B")])
    _discover(pool)
    assert pm._FAIL_FAST_ON_429.get() is False


def test_the_pool_exposes_the_provider_attributes_the_pipeline_reads():
    pool = pm.KeyPoolProvider([FakeKey("key-A"), FakeKey("key-B")])
    assert (pool.name, pool.model, pool.max_review_groups_per_request, pool.key_count) == ("groq", "m", 1, 2)
    assert pool.plan_attack("p", timeout_seconds=1)[1]["key_slot"] in {"1/2", "2/2"}


def test_keys_are_collected_from_every_supported_variable_without_duplicates(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEYS", "k1, k2;k3")
    monkeypatch.setenv("GROQ_API_KEY", "k2")
    monkeypatch.setenv("GROQ_API_KEY_2", "k4")
    assert pm.api_keys_from_environment("groq") == ["k1", "k2", "k3", "k4"]
    assert pm.api_keys_from_environment("ollama") == []


def test_factory_returns_a_plain_provider_for_one_key_and_a_pool_for_several(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "only")
    single = pm.provider_from_environment("groq", "openai/gpt-oss-120b")
    assert type(single).__name__ == "GroqProvider" and single.api_key == "only"
    monkeypatch.setenv("GROQ_API_KEY_2", "second")
    pool = pm.provider_from_environment("groq", "openai/gpt-oss-120b")
    assert isinstance(pool, pm.KeyPoolProvider) and pool.key_count == 2 and pool.model == "openai/gpt-oss-120b"


def test_gemini_uses_the_openai_compatible_endpoint_and_its_own_key(monkeypatch):
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        pm.provider_from_environment("gemini", "any-gemini-model")
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    provider = pm.provider_from_environment("gemini", "any-gemini-model")
    assert type(provider).__name__ == "GeminiProvider" and provider.name == "gemini"
    assert provider.endpoint == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setenv("GOOGLE_API_KEY", "alias-key")
    assert pm.provider_from_environment("gemini", "m").api_key == "alias-key"


def test_gemini_request_goes_to_the_gemini_endpoint_with_a_bearer_key(monkeypatch):
    seen = {}

    class Response:
        headers: dict = {}
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, _n): return json.dumps({"choices": [{"message": {"content": '{"candidates":[],"context_requests":[]}'},
                                                            "finish_reason": "stop"}], "usage": {}}).encode()

    def fake_open(request, _timeout):
        seen["url"], seen["auth"] = request.full_url, request.get_header("Authorization")
        return Response()

    monkeypatch.setattr(pm, "_urlopen", fake_open)
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    payload, usage = pm.provider_from_environment("gemini", "gm").discover("p", timeout_seconds=5, max_candidates=3)
    assert seen["url"].startswith("https://generativelanguage.googleapis.com/v1beta/openai/") and seen["auth"] == "Bearer g-key"
    assert payload["candidates"] == [] and usage["provider"] == "gemini"


def _http_429(retry_after: str | None):
    headers = {"Retry-After": retry_after} if retry_after else {}
    return urllib.error.HTTPError("https://x", 429, "Too Many Requests", headers, io.BytesIO(b"{}"))


def test_fail_fast_makes_a_429_raise_at_once_instead_of_sleeping(monkeypatch):
    slept = []
    monkeypatch.setattr(pm.time, "sleep", slept.append)
    monkeypatch.setattr(pm, "_urlopen", lambda request, _t: (_ for _ in ()).throw(_http_429("5")))
    request = pm.urllib.request.Request("https://x", data=b"{}", headers={"Authorization": "Bearer k"}, method="POST")
    token = pm._FAIL_FAST_ON_429.set(True)
    try:
        with pytest.raises(pm._GroqHTTPFailure, match="429"):
            pm._groq_json_request(request, 5)
    finally:
        pm._FAIL_FAST_ON_429.reset(token)
    assert slept == []


def test_without_fail_fast_a_429_with_retry_after_still_waits_and_retries(monkeypatch):
    slept, calls = [], {"n": 0}
    monkeypatch.setattr(pm.time, "sleep", slept.append)

    class Ok:
        headers: dict = {}
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, _n): return b'{"ok": true}'

    def fake_open(request, _t):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_429("5")
        return Ok()

    monkeypatch.setattr(pm, "_urlopen", fake_open)
    request = pm.urllib.request.Request("https://x", data=b"{}", headers={"Authorization": "Bearer k"}, method="POST")
    assert pm._groq_json_request(request, 5)[0] == {"ok": True} and slept == [5.0]


def test_rate_pacing_is_tracked_per_key(monkeypatch):
    headers = {"x-ratelimit-remaining-tokens": "10", "x-ratelimit-reset-tokens": "20s"}
    request_a = pm.urllib.request.Request("https://x", data=b"x" * 3000, headers={"Authorization": "Bearer key-A"}, method="POST")
    request_b = pm.urllib.request.Request("https://x", data=b"x" * 3000, headers={"Authorization": "Bearer key-B"}, method="POST")
    slept = []
    monkeypatch.setattr(pm.time, "sleep", slept.append)
    pm._remember_rate_limits(headers, pm._rate_bucket(request_a))      # key A's window is nearly empty
    assert pm._pace_before_request(request_b) == 0.0 and slept == []   # key B is not slowed down by it
    assert pm._pace_before_request(request_a) > 0 and len(slept) == 1  # key A waits for its own window


def test_review_usage_records_how_many_calls_each_key_answered():
    from security_reviewer_v2.reviewers.agent import _accumulate_usage
    usage = {"calls": 0}
    for slot in ("1/2", "2/2", "1/2"):
        _accumulate_usage(usage, {"key_slot": slot, "total_tokens": 10})
    assert usage["key_slots"] == {"1/2": 2, "2/2": 1} and usage["calls"] == 3 and usage["total_tokens"] == 30

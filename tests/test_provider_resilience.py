"""Groq provider resilience: classified transport errors, bounded retries, strict response parsing, safe tracing.

Everything is mocked (no network, no tokens): ``_urlopen`` and ``time.sleep`` are patched, so the suite is fast
and deterministic.
"""

from __future__ import annotations

import http.client
import io
import json
import logging
import socket
import ssl
import urllib.error
from pathlib import Path

import pytest

from security_reviewer_v2.agents import tracing
from security_reviewer_v2.discovery import provider as provider_module
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.discovery.provider import GroqProvider, ProviderResponseError

from tests.test_ai_discovery import _inputs

@pytest.fixture(autouse=True)
def _fresh_rate_state():
    provider_module._RATE_STATE.clear()
    yield
    provider_module._RATE_STATE.clear()


API_KEY = "gsk_SECRET_do_not_leak_123"
PROMPT = "SENSITIVE-SOURCE-CODE: password = 'hunter2'"
STRICT = "openai/gpt-oss-120b"      # uses json_schema, so a 400 triggers the one-shot json_object fallback
PLAIN = "plain-model"               # json_object only
EMPTY_ANSWER = '{"candidates":[],"context_requests":[]}'


def completion(content: object = EMPTY_ANSWER, finish: object = "stop", usage: object = None) -> bytes:
    body: dict = {"choices": [{"message": {"content": content}, "finish_reason": finish}]}
    if usage is not None:
        body["usage"] = usage
    return json.dumps(body).encode()


def http_error(code: int, headers: dict | None = None, body: bytes = b"{}") -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.groq.com", code, "secret provider text", headers or {}, io.BytesIO(body))


class Wire:
    """Scripted transport: each entry is an exception to raise or bytes to return."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *outcomes: object) -> None:
        self.outcomes = list(outcomes)
        self.timeouts: list[object] = []
        self.sleeps: list[float] = []
        monkeypatch.setattr(provider_module, "_urlopen", self._open)
        monkeypatch.setattr(provider_module.time, "sleep", self.sleeps.append)

    def _open(self, request, timeout):
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if callable(outcome):                       # a factory: real HTTP errors are fresh objects (body is read once)
            outcome = outcome()
        if isinstance(outcome, BaseException):
            raise outcome
        return io.BytesIO(outcome)

    @property
    def calls(self) -> int:
        return len(self.timeouts)


def discover(model: str = PLAIN, timeout: int | None = 10):
    return GroqProvider(model=model, api_key=API_KEY).discover(PROMPT, timeout_seconds=timeout, max_candidates=5)


def dns_blip() -> urllib.error.URLError:
    return urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"))


# ------------------------------------------------------------------ success
def test_success_reports_finish_reason_and_no_retries(monkeypatch):
    wire = Wire(monkeypatch, completion(usage={"prompt_tokens": 3, "completion_tokens": 2}))
    result, usage = discover()
    assert result["candidates"] == [] and wire.calls == 1 and wire.sleeps == []
    assert usage["finish_reason"] == "stop" and usage["retry_count"] == 0 and usage["prompt_tokens"] == 3


# ------------------------------------------------------------------ URLError: classified, retried only when safe
def test_urlerror_keeps_the_underlying_reason_instead_of_just_the_class_name(monkeypatch):
    Wire(monkeypatch, dns_blip())
    with pytest.raises(RuntimeError) as error:
        discover()
    message = str(error.value)
    assert "URLError" not in message                                  # the old, useless message
    assert "(dns)" in message and "DNS resolution failed" in message and "Temporary failure in name resolution" in message
    assert "gave up after 3 attempts" in message


def test_transient_connection_failure_is_retried_with_backoff_then_succeeds(monkeypatch):
    wire = Wire(monkeypatch, dns_blip(), urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer")),
                completion())
    _, usage = discover()
    assert wire.calls == 3 and wire.sleeps == [1.0, 3.0]
    assert usage["retry_count"] == 2 and usage["rate_limit_wait_seconds"] == 4.0


def test_connection_retries_are_bounded(monkeypatch):
    wire = Wire(monkeypatch, urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")))
    with pytest.raises(RuntimeError, match=r"\(connection\): connection failed: .*Connection refused.*3 attempts"):
        discover()
    assert wire.calls == 3 and wire.sleeps == [1.0, 3.0]              # never an unbounded loop


@pytest.mark.parametrize("outcome,needle", [
    (urllib.error.URLError(ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")),
     "TLS certificate verification failed"),
    (urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "Name or service not known")), "DNS resolution failed"),
])
def test_permanent_connection_failures_are_not_retried(monkeypatch, outcome, needle):
    wire = Wire(monkeypatch, outcome)
    with pytest.raises(RuntimeError, match=needle):
        discover()
    assert wire.calls == 1 and wire.sleeps == []


def test_connect_timeout_is_retried_but_response_timeout_is_not(monkeypatch):
    wire = Wire(monkeypatch, urllib.error.URLError(socket.timeout("timed out")), completion())
    discover()
    assert wire.calls == 2                                            # request never reached the server: safe to retry
    wire = Wire(monkeypatch, TimeoutError("timed out"))
    with pytest.raises(RuntimeError, match=r"\(timeout\): no response within 10s after the request was sent"):
        discover()
    assert wire.calls == 1 and wire.sleeps == []                      # may be processing/billed: never duplicated


@pytest.mark.parametrize("raw", [ConnectionResetError(104, "reset"), http.client.RemoteDisconnected("closed")])
def test_errors_while_reading_the_response_become_runtime_errors_not_crashes(monkeypatch, raw):
    # urllib only wraps connect-phase errors in URLError; these used to escape discover() as raw exceptions.
    wire = Wire(monkeypatch, raw)
    with pytest.raises(RuntimeError, match=r"\(connection_closed\)") as error:
        discover()
    assert wire.calls == 1 and API_KEY not in str(error.value)


def test_no_timeout_means_a_bounded_default_for_the_hosted_api(monkeypatch):
    wire = Wire(monkeypatch, completion())
    discover(timeout=None)
    assert wire.timeouts == [provider_module._HOSTED_DEFAULT_TIMEOUT_SECONDS]
    wire = Wire(monkeypatch, completion())
    discover(timeout=7)
    assert wire.timeouts == [7]


def test_unreadable_http_body_is_a_fatal_protocol_error_not_a_batch_level_one(monkeypatch):
    Wire(monkeypatch, b"<html>captive portal login</html>")
    with pytest.raises(RuntimeError) as error:
        discover()
    assert "unreadable HTTP response body" in str(error.value) and "captive portal" not in str(error.value)
    assert not isinstance(error.value, ProviderResponseError) and "non-JSON" not in str(error.value)


# ------------------------------------------------------------------ HTTP: rate limits, 5xx, permanent errors
def test_http_429_honours_retry_after_and_stops_at_the_wait_budget(monkeypatch):
    wire = Wire(monkeypatch, http_error(429, {"Retry-After": "90"}))
    with pytest.raises(RuntimeError, match="HTTP 429"):
        discover()
    assert wire.sleeps == [90.0] * 6 and wire.calls == 7              # 6 x 90s = 540s; a 7th would exceed 600s


@pytest.mark.parametrize("headers", [{}, {"Retry-After": "soon"}, {"Retry-After": "inf"}, {"Retry-After": "120"}])
def test_http_429_without_a_usable_retry_after_is_not_retried(monkeypatch, headers):
    wire = Wire(monkeypatch, http_error(429, headers))
    with pytest.raises(RuntimeError, match="HTTP 429"):
        discover()
    assert wire.calls == 1 and wire.sleeps == []


@pytest.mark.parametrize("headers, expected", [({"Retry-After": "1140"}, "asked to wait 1140 s"), ({}, "no usable Retry-After"),
                                               ({"Retry-After": "inf"}, "no usable Retry-After")])
def test_http_429_failure_says_how_long_the_provider_wanted_us_to_wait(monkeypatch, headers, expected):
    Wire(monkeypatch, http_error(429, headers))
    with pytest.raises(RuntimeError, match=expected):
        discover()


def test_http_429_without_retry_after_waits_the_opt_in_fallback_and_retries(monkeypatch):
    monkeypatch.setenv("GROQ_RATE_LIMIT_FALLBACK_SECONDS", "65")
    wire = Wire(monkeypatch, http_error(429, {}), completion())
    discover()
    assert wire.calls == 2 and wire.sleeps == [65.0]


def test_http_429_with_a_long_retry_after_still_fails_fast_even_with_the_fallback(monkeypatch):
    monkeypatch.setenv("GROQ_RATE_LIMIT_FALLBACK_SECONDS", "65")
    wire = Wire(monkeypatch, http_error(429, {"Retry-After": "1140"}))
    with pytest.raises(RuntimeError, match="asked to wait 1140 s"):
        discover()
    assert wire.calls == 1 and wire.sleeps == []


class _Answer(io.BytesIO):
    def __init__(self, body: bytes, headers: dict) -> None:
        super().__init__(body)
        self.headers = headers


def _scripted(monkeypatch, *answers):
    sleeps: list[float] = []
    queue = list(answers)
    monkeypatch.setattr(provider_module, "_urlopen", lambda request, timeout: queue.pop(0))
    monkeypatch.setattr(provider_module.time, "sleep", sleeps.append)
    return sleeps


def test_pacing_waits_for_the_token_window_instead_of_provoking_a_429(monkeypatch):
    low = {"x-ratelimit-remaining-tokens": "300", "x-ratelimit-reset-tokens": "7.5s"}
    sleeps = _scripted(monkeypatch, _Answer(completion(), low), _Answer(completion(), {}))
    discover(); discover()
    assert len(sleeps) == 1 and sleeps[0] == pytest.approx(7.75, abs=0.2)


def test_pacing_does_not_wait_when_enough_tokens_remain(monkeypatch):
    plenty = {"x-ratelimit-remaining-tokens": "7900", "x-ratelimit-reset-tokens": "7.5s"}
    sleeps = _scripted(monkeypatch, _Answer(completion(), plenty), _Answer(completion(), {}))
    discover(); discover()
    assert sleeps == []


def test_pacing_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("GROQ_PACE_RATE_LIMITS", "0")
    low = {"x-ratelimit-remaining-tokens": "300", "x-ratelimit-reset-tokens": "7.5s"}
    sleeps = _scripted(monkeypatch, _Answer(completion(), low), _Answer(completion(), {}))
    discover(); discover()
    assert sleeps == []


@pytest.mark.parametrize("text, seconds", [("659ms", 0.659), ("7.66s", 7.66), ("1m2.5s", 62.5), ("", None), ("soon", None)])
def test_rate_limit_durations_are_parsed(text, seconds):
    assert provider_module._duration_seconds(text) == pytest.approx(seconds) if seconds is not None else provider_module._duration_seconds(text) is None


def test_reasoning_effort_is_opt_in_and_only_for_gpt_oss(monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(provider_module, "_urlopen", lambda request, timeout: (seen.append(json.loads(request.data)), io.BytesIO(completion()))[1])
    monkeypatch.setattr(provider_module.time, "sleep", lambda s: None)
    discover(STRICT)
    monkeypatch.setenv("GROQ_REASONING_EFFORT", "low")
    discover(STRICT); discover(PLAIN)
    assert "reasoning_effort" not in seen[0] and seen[1]["reasoning_effort"] == "low" and "reasoning_effort" not in seen[2]


def test_http_5xx_is_retried_a_bounded_number_of_times(monkeypatch):
    wire = Wire(monkeypatch, http_error(503))
    with pytest.raises(RuntimeError, match="HTTP 503"):
        discover()
    assert wire.calls == 3 and wire.sleeps == [1.0, 3.0]
    wire = Wire(monkeypatch, http_error(502, {"Retry-After": "2"}), completion())
    _, usage = discover()
    assert wire.sleeps == [2.0] and usage["retry_count"] == 1


@pytest.mark.parametrize("code", [400, 401, 403, 404, 413, 422])
def test_permanent_http_errors_are_never_retried(monkeypatch, code):
    wire = Wire(monkeypatch, http_error(code))
    with pytest.raises(RuntimeError, match=f"HTTP {code}") as error:
        discover(model=PLAIN)
    assert wire.calls == 1 and wire.sleeps == []
    assert "secret provider text" not in str(error.value) and API_KEY not in str(error.value)


def test_strict_schema_400_falls_back_exactly_once(monkeypatch):
    wire = Wire(monkeypatch, http_error(400), http_error(400))
    with pytest.raises(RuntimeError, match="HTTP 400"):
        discover(model=STRICT)
    assert wire.calls == 2                                            # json_schema attempt + one json_object attempt


def test_transport_failure_during_the_json_fallback_is_reported_as_such(monkeypatch):
    Wire(monkeypatch, http_error(400), dns_blip())
    with pytest.raises(RuntimeError, match=r"JSON fallback failed: AI provider request failed \(dns\)"):
        discover(model=STRICT)


# ------------------------------------------------------------------ response parsing: never a silent success
@pytest.mark.parametrize("body,needles", [
    (completion("", "length", {"completion_tokens": 7}),
     ("truncated before any content", "finish_reason=length", "completion_tokens=7")),
    (completion(None, "stop"), ("returned empty content", "finish_reason=stop")),
    (completion("   \n", "stop"), ("returned empty content",)),
    (completion('{"candidates": [', "length"), ("truncated mid-JSON", "finish_reason=length")),
    (completion("sorry, I cannot", "stop"), ("returned non-JSON content", "finish_reason=stop")),
    (completion("sorry", "x; DROP TABLE"), ("finish_reason=unknown",)),          # untrusted value is never echoed
])
def test_empty_truncated_or_invalid_content_is_a_batch_level_failure(monkeypatch, body, needles):
    Wire(monkeypatch, body)
    with pytest.raises(ProviderResponseError) as error:
        discover()
    for needle in needles:
        assert needle in str(error.value)
    assert "DROP TABLE" not in str(error.value) and "hunter2" not in str(error.value)


@pytest.mark.parametrize("body", [b"[]", b'{"choices": []}', b'{"choices": ["x"]}', b"{}"])
def test_structurally_malformed_completion_is_a_fatal_error(monkeypatch, body):
    Wire(monkeypatch, body)
    with pytest.raises(RuntimeError, match="malformed completion") as error:
        discover()
    assert not isinstance(error.value, ProviderResponseError)


def test_review_requests_share_the_same_hardening(monkeypatch):
    provider = GroqProvider(model=PLAIN, api_key=API_KEY)
    Wire(monkeypatch, dns_blip())
    with pytest.raises(RuntimeError, match=r"\(dns\)"):
        provider.review(PROMPT, timeout_seconds=10, max_reviews=1)
    Wire(monkeypatch, completion("", "length"))
    with pytest.raises(ProviderResponseError, match="truncated before any review content"):
        provider.review(PROMPT, timeout_seconds=10, max_reviews=1)
    Wire(monkeypatch, completion('{"reviews":[{"candidate_id":"a"}]}'))
    reviews, _ = provider.review(PROMPT, timeout_seconds=10, max_reviews=1)
    assert reviews == [{"candidate_id": "a"}]


# ------------------------------------------------------------------ discovery graph semantics
class Scripted:
    name, model = "fake", "test"

    def __init__(self, *outcomes: object) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return {"candidates": [], "context_requests": []}, {"prompt_tokens": 1}


def run_agent(tmp_path: Path, provider: Scripted):
    merged, context, risk, profile = _inputs(tmp_path)
    return DiscoveryAgent(provider, DiscoveryConfig(max_targets=1)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile)


def test_truncated_answer_fails_one_batch_and_later_batches_still_run(tmp_path):
    provider = Scripted(ProviderResponseError("AI provider response was truncated mid-JSON (finish_reason=length)"), None)
    result = run_agent(tmp_path, provider)
    assert result.status.value == "partial" and provider.calls == len(result.batches) >= 3
    assert result.batches[0].status == "failed" and all(b.status == "completed" for b in result.batches[1:])
    failed_targets = set(result.batches[0].target_ids)
    assert failed_targets and not failed_targets & set(result.scope)   # a failed batch is never marked inspected
    assert any("finish_reason=length" in warning for warning in result.warnings)


def test_transport_outage_stops_the_run_and_never_reports_success(tmp_path):
    outage = provider_module._GroqTransportFailure("AI provider request failed (dns): x", "dns", 3, 2, 4.0)
    provider = Scripted(outage)
    result = run_agent(tmp_path, provider)
    assert provider.calls == 1 and result.status.value == "blocked"
    assert result.scope == () and any("did not complete" in gap for gap in result.coverage_gaps)
    assert any("request failed (dns)" in warning for warning in result.warnings)


# ------------------------------------------------------------------ tracing can never change the outcome
class Provider:
    name, model = "fake", "m"

    def __init__(self, error: BaseException | None = None) -> None:
        self.calls = 0
        self.error = error

    def discover(self, prompt, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return {"ok": True}, {"prompt_tokens": 1}


def fake_traceable(*, fail: str):
    """A stand-in for ``langsmith.traceable`` whose machinery fails before/after calling the function."""
    def decorator(**_options):
        def wrap(function):
            def traced():
                if fail == "before":
                    raise RuntimeError("tracing exploded before the call")
                result = function()
                if fail == "after":
                    raise RuntimeError("tracing exploded after the call")
                return result
            return traced
        return wrap
    return decorator


def test_tracing_failure_before_the_call_still_calls_the_provider_once(monkeypatch):
    monkeypatch.setattr(tracing, "traceable", fake_traceable(fail="before"))
    provider = Provider()
    assert tracing.call_model(provider, "discover", "p", span="s") == ({"ok": True}, {"prompt_tokens": 1})
    assert provider.calls == 1


def test_tracing_failure_after_a_successful_call_keeps_the_response(monkeypatch):
    monkeypatch.setattr(tracing, "traceable", fake_traceable(fail="after"))
    provider = Provider()
    assert tracing.call_model(provider, "discover", "p", span="s")[0] == {"ok": True}
    assert provider.calls == 1                                         # no duplicate request


def test_tracing_failure_never_hides_the_provider_exception(monkeypatch):
    original = RuntimeError("AI provider request failed (dns): x")

    def failing_function_then_tracing_error(**_options):
        def wrap(function):
            def traced():
                try:
                    function()
                finally:
                    raise RuntimeError("tracing exploded while closing the run")   # replaces the provider error
            return traced
        return wrap

    monkeypatch.setattr(tracing, "traceable", failing_function_then_tracing_error)
    provider = Provider(original)
    with pytest.raises(RuntimeError) as error:
        tracing.call_model(provider, "discover", "p", span="s")
    assert error.value is original and provider.calls == 1


def test_real_langsmith_no_longer_logs_a_process_outputs_error_when_the_provider_raises(caplog):
    import requests
    from langsmith import Client

    class Quiet(requests.Session):
        def request(self, *_args, **_kwargs):
            response = requests.Response()
            response.status_code, response._content = 200, b"{}"
            response.headers["content-type"] = "application/json"
            return response

    client = Client(api_url="http://langsmith.invalid", api_key="k", session=Quiet(), auto_batch_tracing=False)
    original = RuntimeError("AI provider request failed (dns): x")
    with caplog.at_level(logging.DEBUG), tracing.agent_tracing("probe", client=client):
        with pytest.raises(RuntimeError) as error:
            tracing.call_model(Provider(original), "discover", "p", span="discovery-model-call")
    assert error.value is original
    assert not [r for r in caplog.records if "process_outputs failed" in r.getMessage()]


def test_unreachable_langsmith_cannot_fail_a_successful_model_call():
    import requests
    from langsmith import Client

    class Dead(requests.Session):
        def request(self, *_args, **_kwargs):
            raise requests.exceptions.ConnectionError("langsmith unreachable")

    for batching in (False, True):
        client = Client(api_url="http://langsmith.invalid", api_key="k", session=Dead(), auto_batch_tracing=batching)
        with tracing.agent_tracing("probe", client=client):
            assert tracing.call_model(Provider(), "discover", "p", span="s")[0] == {"ok": True}
        client.flush()


def test_a_broken_langsmith_setup_disables_tracing_instead_of_stopping_the_review(monkeypatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGSMITH_API_KEY", "k")

    def explode(*_args, **_kwargs):
        raise ValueError("bad LangSmith configuration")

    monkeypatch.setattr(tracing, "build_client", explode)
    ran = []
    with tracing.agent_tracing("probe"):
        ran.append(True)
    assert ran == [True]
    with pytest.raises(KeyError):                                       # body errors still propagate
        with tracing.agent_tracing("probe"):
            raise KeyError("body failure is not swallowed")


def test_trace_outputs_accepts_none_without_error():
    assert tracing._trace_outputs(None) == {}
    assert tracing._trace_outputs(({"a": 1}, {"b": 2})) == {"response": {"a": 1}, "usage": {"b": 2}}


# ------------------------------------------------------------------ HTTP 413: request too large (run_bench_02)
TPM_413 = json.dumps({"error": {"code": "rate_limit_exceeded", "message": (
    "Request too large for model `openai/gpt-oss-120b` in organization `org_secret123` service tier `on_demand` on "
    "tokens per minute (TPM): Limit 8000, Requested 11234, please reduce your message size and try again.")}}).encode()


def test_http_413_is_a_typed_non_retried_error_that_keeps_only_the_two_token_counts(monkeypatch):
    wire = Wire(monkeypatch, http_error(413, body=TPM_413))
    with pytest.raises(provider_module.RequestTooLargeError) as error:
        discover()
    text = str(error.value)
    assert "HTTP 413 (rate_limit_exceeded); request too large: 11234 tokens requested, limit 8000" in text
    assert "org_secret123" not in text and "gpt-oss" not in text and API_KEY not in text   # provider prose is dropped
    assert (error.value.limit_tokens, error.value.requested_tokens) == (8000, 11234)
    assert error.value.fit_ratio == pytest.approx(8000 / 11234)
    assert wire.calls == 1 and wire.sleeps == []                       # waiting cannot make a request smaller


def test_http_413_without_numbers_has_no_ratio_and_429_never_gets_the_413_hint(monkeypatch):
    Wire(monkeypatch, http_error(413, body=b'{"error":{"code":"rate_limit_exceeded"}}'))
    with pytest.raises(provider_module.RequestTooLargeError) as error:
        discover()
    assert error.value.fit_ratio is None and "request too large:" not in str(error.value)
    Wire(monkeypatch, http_error(429, body=TPM_413))
    with pytest.raises(RuntimeError) as limited:
        discover()
    assert "HTTP 429 (rate_limit_exceeded)" in str(limited.value) and "request too large" not in str(limited.value)
    assert not isinstance(limited.value, provider_module.RequestTooLargeError)


# ------------------------------------------------------------------ discovery graph: a 413 shrinks the request
from security_reviewer_v2.discovery.provider import RequestTooLargeError  # noqa: E402


class SizeLimited:
    """Fails with 413 whenever the prompt exceeds ``limit`` characters (like a tokens-per-minute cap)."""

    name, model = "fake", "test"

    def __init__(self, limit: float, *, always_for: str | None = None, requested: int | None = None) -> None:
        self.limit, self.always_for, self.requested = limit, always_for, requested
        self.prompts: list[int] = []

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        self.prompts.append(len(prompt))
        if len(prompt) > self.limit or (self.always_for and self.always_for in prompt):
            hint = f"; request too large: {self.requested} tokens requested, limit 8000" if self.requested else ""
            raise RequestTooLargeError(f"AI provider request failed with HTTP 413 (rate_limit_exceeded){hint}", 413, 0,
                                       0.0, 8000 if self.requested else None, self.requested)
        return {"candidates": [], "context_requests": []}, {"prompt_tokens": 1}


def run_with(tmp_path: Path, provider, *, max_targets: int = 10):
    merged, context, risk, profile = _inputs(tmp_path)
    return DiscoveryAgent(provider, DiscoveryConfig(max_targets=max_targets)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile)


def test_oversized_batch_is_retried_smaller_and_every_target_is_still_inspected(tmp_path):
    full, singles = SizeLimited(limit=10**9), SizeLimited(limit=10**9)
    baseline = run_with(tmp_path, full)                                # one batch with every target
    run_with(tmp_path, singles, max_targets=1)                         # measure the largest single-target prompt
    limit = max(singles.prompts)
    assert full.prompts[0] > limit                                     # the full batch genuinely does not fit
    provider = SizeLimited(limit, requested=int(8000 * full.prompts[0] / limit))   # provider reports its own numbers
    result = run_with(tmp_path, provider)
    assert len(provider.prompts) > len(result.batches)                 # oversized attempt(s) were retried in place
    assert set(result.scope) == set(baseline.scope) and len(result.scope) >= 3   # every target inspected
    assert len(result.scope) == len(set(result.scope))                 # ... exactly once
    assert result.status.value == baseline.status.value
    assert any("retrying with a smaller request" in w and "tokens requested, limit 8000" in w for w in result.warnings)
    assert result.usage["provider_calls"] == len(provider.prompts)


def test_a_target_that_never_fits_is_reported_uninspected_and_the_run_continues(tmp_path):
    provider = SizeLimited(limit=10**9, always_for="def authorize")   # auth.py can never be sent
    result = run_with(tmp_path, provider, max_targets=1)
    assert result.status.value == "partial" and result.scope
    assert not any("auth.py" in target for target in result.scope)    # never marked inspected
    assert any("exceeded the provider request-size limit" in gap and "auth.py" in gap for gap in result.coverage_gaps)
    assert any(batch.status == "failed" for batch in result.batches) and any(b.status == "completed" for b in result.batches)


def test_413_retries_are_bounded_even_if_every_request_is_too_large(tmp_path):
    provider = SizeLimited(limit=0)                                    # nothing ever fits
    result = run_with(tmp_path, provider)
    assert result.scope == () and result.status.value == "blocked"      # never a silent success
    assert len(provider.prompts) <= 20 * 12                            # bounded by max_batches * (shrinks + 1)
    assert any("exceeded the provider request-size limit" in gap for gap in result.coverage_gaps)


# ------------------------------------------------------------------ review stage: a 413 must not stop the review
from security_reviewer_v2.reviewers.agent import run_security_review  # noqa: E402
from tests.test_candidate_triage_review import ConfirmingReviewer, discovery, merged as merged_findings, scanner, verified  # noqa: E402


class OversizedFor(ConfirmingReviewer):
    def __init__(self, *, reject: set[str] | None = None, max_group: int = 1) -> None:
        super().__init__()
        self.reject, self.max_review_groups_per_request = reject or set(), max_group

    def review(self, prompt, *, timeout_seconds, max_reviews):
        ids = [item["candidate"]["candidate_id"] for item in json.loads(prompt.split("\n\n", 1)[1])["items"]]
        if self.reject & set(ids) or (len(ids) > 1 and "split" in self.reject):
            raise RequestTooLargeError("AI provider request failed with HTTP 413 (rate_limit_exceeded)", 413, 0, 0.0)
        return super().review(prompt, timeout_seconds=timeout_seconds, max_reviews=max_reviews)


def test_review_leaves_an_oversized_group_pending_and_still_reviews_the_rest(tmp_path):
    found = merged_findings(scanner("scan-a", 10, "sql"), scanner("scan-b", 30, "xss"))
    result = run_security_review(discovery(), verified(), provider=OversizedFor(reject={"scan-a"}),
                                 project_root=tmp_path, merged=found)
    assert [item.candidate_id for item in result.reviews] == ["scan-b"]
    assert result.pending_ids == ("scan-a",) and result.status == "partial"
    assert any("scan-a" in w and "group left pending" in w for w in result.warnings)


def test_review_splits_an_oversized_multi_group_request_into_single_groups(tmp_path):
    found = merged_findings(scanner("scan-a", 10, "sql"), scanner("scan-b", 30, "xss"))
    provider = OversizedFor(reject={"split"}, max_group=3)
    result = run_security_review(discovery(), verified(), provider=provider, project_root=tmp_path, merged=found)
    assert {item.candidate_id for item in result.reviews} == {"scan-a", "scan-b"} and result.status == "completed"
    assert any("one group at a time" in w for w in result.warnings)


# ------------------------------------------------------------------ bench_02 shape: ~45 targets, size cap on every request
import hashlib  # noqa: E402
import os  # noqa: E402
from types import SimpleNamespace  # noqa: E402


def scaled_inputs(root: Path, files: int = 45):
    """A project with many files and one finding per file (one target per file: 45, like run_bench_02)."""
    names, findings, ranks = [], [], []
    for index in range(files):
        name = f"mod{index:02d}.py"
        names.append(name)
        (root / name).write_text("".join(f"def handler_{index}_{n}(request):\n    return request.args.get('q{n}')\n"
                                         for n in range(3)), encoding="utf-8")
        location = SimpleNamespace(path=name, start_line=2, end_line=2)
        findings.append(SimpleNamespace(merged_finding_id=f"f-{index}", canonical_finding=SimpleNamespace(title=f"Finding {index}"),
                                        primary_location=location, source_findings=(SimpleNamespace(primary_location=location),)))
        ranks.append(SimpleNamespace(merged_finding_id=f"f-{index}", selected_for_deep_review=True,
                                     primary_location=location, rank=index + 1, risk_score=80 - index))
    profile = {"profile": {"inventory": [{"path": n, "category": "source"} for n in names], "coverage_gaps": []},
               "scan_plan": {"coverage_gaps": []},
               "project_snapshot": {"root_path": os.path.normcase(str(root.resolve())),
                                    "files": [{"path": n, "sha256": hashlib.sha256((root / n).read_bytes()).hexdigest()} for n in names]}}
    return (SimpleNamespace(findings=tuple(findings), coverage_gaps=()), SimpleNamespace(findings=(), coverage_gaps=()),
            SimpleNamespace(findings=tuple(ranks), coverage_gaps=()), profile)


def run_scaled(root: Path, provider):
    merged, context, risk, profile = scaled_inputs(root)
    return DiscoveryAgent(provider, DiscoveryConfig(max_targets=10)).run(
        merged, context, risk, project_root=root, profile_artifact=profile)


def test_large_scan_completes_when_every_request_is_capped_like_a_tokens_per_minute_limit(tmp_path):
    uncapped = SizeLimited(limit=10**9)
    baseline = run_scaled(tmp_path, uncapped)
    assert baseline.usage["planned_targets"] >= 40 and baseline.usage["targets"] == baseline.usage["planned_targets"]
    fits = SizeLimited(limit=10**9)
    merged, context, risk, profile = scaled_inputs(tmp_path)
    DiscoveryAgent(fits, DiscoveryConfig(max_targets=4)).run(
        merged, context, risk, project_root=tmp_path, profile_artifact=profile)
    cap = SizeLimited(limit=max(fits.prompts))                         # 4 targets fit; a 10-target batch does not
    assert max(uncapped.prompts) > cap.limit
    result = run_scaled(tmp_path, cap)
    assert result.usage["targets"] == result.usage["planned_targets"] == baseline.usage["planned_targets"]
    assert set(result.scope) == set(baseline.scope)                    # nothing skipped, nothing inspected twice
    assert result.status.value == baseline.status.value
    assert len(cap.prompts) <= len(baseline.batches) * 8               # bounded: the cost of adapting is small
    assert sum(1 for size in cap.prompts if size > cap.limit) <= 3     # it learns the size once; it does not re-hit the cap every batch
    assert sum(1 for size in cap.prompts if size > cap.limit) >= 1     # the cap really was exceeded along the way


def test_a_genuine_http_failure_still_ends_discovery_instead_of_being_retried_smaller(tmp_path):
    class Outage:
        name, model = "fake", "test"
        calls = 0

        def discover(self, prompt, **_kwargs):
            Outage.calls += 1
            raise provider_module._GroqHTTPFailure("AI provider request failed with HTTP 503", 503, 2, 4.0)

    result = run_scaled(tmp_path, Outage())
    assert Outage.calls == 1 and result.status.value == "blocked"      # not hidden, not retried smaller
    assert result.usage["targets"] == 0 and result.usage["planned_targets"] >= 40
    assert any("did not complete" in gap for gap in result.coverage_gaps)


# ------------------------------------------------------------------ HTTP 400 json_validate_failed (run_bench_03)
SECRET_OUTPUT = "{\"candidates\": [{\"evidence\": \"password = 'hunter2-SECRET' \\\\ broken"


def validate_failed(generated: object = SECRET_OUTPUT, message: str = "Failed to generate JSON.") -> urllib.error.HTTPError:
    error: dict = {"message": message, "type": "invalid_request_error", "code": "json_validate_failed"}
    if generated is not None:
        error["failed_generation"] = generated
    return http_error(400, body=json.dumps({"error": error}).encode())


def test_persistent_json_validate_failed_is_a_batch_level_error_with_safe_diagnostics(monkeypatch):
    wire = Wire(monkeypatch, validate_failed)
    with pytest.raises(ProviderResponseError) as error:
        discover(model=STRICT)
    text = str(error.value)
    assert "HTTP 400 (json_validate_failed)" in text and f"model output {len(SECRET_OUTPUT)} chars, not valid JSON" in text
    assert "hunter2" not in text and "SECRET" not in text and API_KEY not in text    # sizes and flags only, never content
    assert wire.calls == 4                                             # schema + 1 retry, then json_object + 1 retry


def test_json_validate_failed_on_a_plain_model_stops_after_one_retry(monkeypatch):
    wire = Wire(monkeypatch, validate_failed)
    with pytest.raises(ProviderResponseError):
        discover(model=PLAIN)
    assert wire.calls == 2


def test_diagnostics_distinguish_schema_rejection_and_token_cap(monkeypatch):
    Wire(monkeypatch, lambda: validate_failed(generated='{"candidates": 1}'))
    with pytest.raises(ProviderResponseError, match="valid JSON but rejected by the schema"):
        discover(model=PLAIN)
    Wire(monkeypatch, lambda: validate_failed(message="max completion tokens reached before generating a valid document"))
    with pytest.raises(ProviderResponseError, match="completion token cap reached"):
        discover(model=PLAIN)


def test_a_very_large_rejected_generation_does_not_hide_the_error_category(monkeypatch):
    Wire(monkeypatch, lambda: validate_failed(generated="x" * 40_000))
    with pytest.raises(ProviderResponseError, match=r"json_validate_failed\); model output 40000 chars"):
        discover(model=PLAIN)


def test_json_validate_failed_that_succeeds_on_retry_is_still_a_success(monkeypatch):
    wire = Wire(monkeypatch, validate_failed, completion())
    result, usage = discover(model=PLAIN)
    assert result["candidates"] == [] and wire.calls == 2 and usage["retry_count"] == 1


def test_other_400_errors_remain_fatal_provider_errors(monkeypatch):
    Wire(monkeypatch, http_error(400, body=b'{"error":{"code":"invalid_request_error"}}'))
    with pytest.raises(RuntimeError) as error:
        discover(model=PLAIN)
    assert not isinstance(error.value, ProviderResponseError)


# ------------------------------------------------------------------ discovery graph: one bad target must not end the scan
class BadOutputFor:
    """Raises 'unusable model output' whenever the prompt contains ``marker`` (a target that breaks the model)."""

    name, model = "fake", "test"

    def __init__(self, marker: str | None) -> None:
        self.marker, self.prompts = marker, []

    def discover(self, prompt, *, timeout_seconds, max_candidates):
        self.prompts.append(prompt)
        if self.marker is None or self.marker in prompt:
            raise ProviderResponseError("AI provider request failed with HTTP 400 (json_validate_failed); model output 9 chars, not valid JSON")
        return {"candidates": [], "context_requests": []}, {"prompt_tokens": 1}


def test_one_bad_target_among_45_is_isolated_reported_and_everything_else_is_inspected(tmp_path):
    baseline = run_scaled(tmp_path, SizeLimited(limit=10**9))
    provider = BadOutputFor('"target_id":"f-7"')   # appears in the prompt only for the batch that carries target f-7
    result = run_scaled(tmp_path, provider)
    bad = [target.target_id for target in baseline.target_plan if target.path == "mod07.py"]
    assert len(bad) == 1 and bad[0] not in result.scope                  # never marked inspected
    assert set(result.scope) == set(baseline.scope) - set(bad)           # the other 44 were all inspected
    assert result.status.value == "partial"
    assert any("produced no usable model output" in gap and bad[0] in gap for gap in result.coverage_gaps)
    assert len(provider.prompts) <= 25                                   # bounded isolation, not a retry storm


def test_when_every_answer_is_unusable_discovery_is_blocked_not_successful(tmp_path):
    provider = BadOutputFor(None)
    result = run_scaled(tmp_path, provider)
    assert result.scope == () and result.status.value == "blocked"
    assert len(provider.prompts) <= 20 * 5


# ------------------------------------------------------------------ review stage: unusable output for one group
class UnusableFor(ConfirmingReviewer):
    def __init__(self, bad: str) -> None:
        super().__init__()
        self.bad = bad

    def review(self, prompt, *, timeout_seconds, max_reviews):
        if self.bad in prompt:
            raise ProviderResponseError("AI provider returned empty review content (finish_reason=length)")
        return super().review(prompt, timeout_seconds=timeout_seconds, max_reviews=max_reviews)


def test_review_keeps_going_when_the_model_returns_unusable_output_for_one_group(tmp_path):
    found = merged_findings(scanner("scan-a", 10, "sql"), scanner("scan-b", 30, "xss"))
    result = run_security_review(discovery(), verified(), provider=UnusableFor("scan-a"), project_root=tmp_path, merged=found)
    assert [item.candidate_id for item in result.reviews] == ["scan-b"]
    assert result.pending_ids == ("scan-a",) and result.status == "partial"
    assert any("scan-a" in w and "empty review content" in w for w in result.warnings)


def test_seed_is_opt_in(monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(provider_module, "_urlopen", lambda request, timeout: (seen.append(json.loads(request.data)), io.BytesIO(completion()))[1])
    monkeypatch.setattr(provider_module.time, "sleep", lambda s: None)
    monkeypatch.delenv("GROQ_SEED", raising=False)
    discover(STRICT)
    monkeypatch.setenv("GROQ_SEED", "7")
    discover(STRICT)
    monkeypatch.setenv("GROQ_SEED", "not-a-number")
    discover(STRICT)
    assert "seed" not in seen[0] and seen[1]["seed"] == 7 and "seed" not in seen[2]

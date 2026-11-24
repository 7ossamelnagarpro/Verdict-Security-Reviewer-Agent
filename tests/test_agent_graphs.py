"""LangGraph agents: topology, behaviour parity hooks and LangSmith tracing (privacy included)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from langsmith import Client

from security_reviewer_v2.agents import tracing
from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.graph import DiscoveryInputs, DiscoveryWorkflow
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.reviewers.agent import _REVIEW_INSTRUCTION, run_security_review
from security_reviewer_v2.reviewers.graph import ReviewInputs, ReviewWorkflow

from tests.test_ai_discovery import FakeProvider, _inputs
from tests.test_candidate_triage_review import ConfirmingReviewer, discovery, merged, scanner, verified


class _RecordingSession(requests.Session):
    """Stands in for LangSmith's HTTP transport and keeps every payload that would be uploaded."""

    def __init__(self) -> None:
        super().__init__()
        self.bodies: list[str] = []

    def request(self, method, url, **kwargs):  # type: ignore[override]
        body = kwargs.get("data") or kwargs.get("json") or b""
        if isinstance(body, (bytes, bytearray)):
            try:
                body = gzip.decompress(body)
            except OSError:
                pass
            body = body.decode("utf-8", "replace")
        self.bodies.append(str(body))
        response = requests.Response()
        response.status_code = 200
        response._content = b"{}"
        response.headers["content-type"] = "application/json"
        return response


def _client(mode: str = "metadata") -> tuple[Client, _RecordingSession]:
    session = _RecordingSession()
    scrub = tracing.make_scrubber(mode)
    client = Client(api_url="http://langsmith.invalid", api_key="test", session=session,
                    auto_batch_tracing=False, hide_inputs=scrub, hide_outputs=scrub)
    return client, session


def _run_names(session: _RecordingSession) -> set[str]:
    names: set[str] = set()
    for body in session.bodies:
        try:
            payload = json.loads(body)
        except ValueError:
            continue
        for item in payload if isinstance(payload, list) else [payload]:
            if isinstance(item, dict) and item.get("name"):
                names.add(item["name"])
    return names


@pytest.fixture(autouse=True)
def _tracing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2", "LANGSMITH_API_KEY", "LANGCHAIN_API_KEY",
                 tracing.CONTENT_ENV):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------ topology
def test_discovery_graph_has_the_documented_nodes(tmp_path: Path) -> None:
    graph = DiscoveryWorkflow.build_graph(FakeProvider(), DiscoveryConfig(), DiscoveryInputs(
        merged=SimpleNamespace(), context=SimpleNamespace(), risk=SimpleNamespace(), project_root=tmp_path))
    assert set(graph.get_graph().nodes) - {"__start__", "__end__"} == {
        "plan_scope", "select_batch", "call_model", "shrink_batch", "absorb_candidates", "plan_enrichment",
        "fetch_context", "close_batch", "finalize"}


def test_review_graph_has_the_documented_nodes(tmp_path: Path) -> None:
    graph = ReviewWorkflow(ReviewInputs(discovery=discovery(), verification=verified(),
                                        provider=ConfirmingReviewer(), project_root=tmp_path)).compile()
    assert set(graph.get_graph().nodes) - {"__start__", "__end__"} == {
        "prepare", "plan_batches", "review_batch", "retry_missing", "checkpoint", "finalize"}


def test_review_workflow_validates_max_reviews(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_reviews"):
        run_security_review(discovery(), verified(), provider=ConfirmingReviewer(), project_root=tmp_path,
                            max_reviews=0)


# ------------------------------------------------------------------ tracing configuration
def test_tracing_is_off_by_default_and_needs_key_and_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    assert tracing.tracing_requested() is False
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    assert tracing.tracing_requested() is False          # switch without key: still off
    monkeypatch.setenv("LANGSMITH_API_KEY", "test")
    assert tracing.tracing_requested() is True


def test_content_mode_defaults_to_metadata_and_rejects_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    assert tracing.content_mode() == "metadata"
    monkeypatch.setenv(tracing.CONTENT_ENV, "everything")
    assert tracing.content_mode() == "metadata"
    monkeypatch.setenv(tracing.CONTENT_ENV, "REDACTED")
    assert tracing.content_mode() == "redacted"


def test_scrubber_modes() -> None:
    secret = "api_key = 'abc123def456'"
    long_text = "x" * 5_000 + " " + secret
    payload = {"short": secret, "long": long_text, "nested": [{"v": long_text}], "n": 3}
    metadata = tracing.make_scrubber("metadata")(payload)
    assert "abc123" not in json.dumps(metadata) and metadata["long"].startswith("<hidden 5") and metadata["n"] == 3
    redacted = tracing.make_scrubber("redacted")(payload)
    assert "abc123" not in json.dumps(redacted) and "truncated" in redacted["long"]
    full = tracing.make_scrubber("full")(payload)
    assert "abc123" not in json.dumps(full) and len(full["long"]) > 4_000   # secrets are removed in every mode


def test_scrubber_caps_huge_collections_except_in_full_mode() -> None:
    payload = {"targets": [{"id": i} for i in range(5_000)], "snippets": {f"t{i}": "code" for i in range(5_000)}}
    for mode in ("metadata", "redacted"):
        out = tracing.make_scrubber(mode)(payload)
        assert len(out["targets"]) == tracing._DEFAULT_MAX_ITEMS + 1 and "more items" in out["targets"][-1]
        assert len(out["snippets"]) == tracing._DEFAULT_MAX_ITEMS + 1 and "<omitted>" in out["snippets"]
        assert len(json.dumps(out)) < 20_000
    assert len(tracing.make_scrubber("full")(payload)["targets"]) == 5_000
    deep: dict = {}
    node = deep
    for _ in range(20):
        node["x"] = {}
        node = node["x"]
    assert "nested data omitted" in json.dumps(tracing.make_scrubber("metadata")(deep))


def test_flush_never_blocks_longer_than_its_timeout() -> None:
    import time

    class Stuck:
        def flush(self) -> None:
            time.sleep(5)

    started = time.monotonic()
    tracing.flush_traces(Stuck(), timeout_seconds=0.2)
    assert time.monotonic() - started < 2


def test_usage_metadata_maps_provider_specific_keys() -> None:
    assert tracing.usage_metadata({"prompt_tokens": 7, "completion_tokens": 3}) == {
        "input_tokens": 7, "output_tokens": 3, "total_tokens": 10}
    assert tracing.usage_metadata({"prompt_eval_count": 5, "eval_count": 1, "total_tokens": 9})["total_tokens"] == 9
    assert tracing.usage_metadata(None) == {}


def test_model_call_without_tracing_is_a_plain_call_and_propagates_errors() -> None:
    class Provider:
        name, model = "p", "m"

        def discover(self, prompt, **kwargs):
            if prompt == "boom":
                raise RuntimeError("provider down")
            return {"ok": prompt}, {"prompt_tokens": 1}

    assert tracing.call_model(Provider(), "discover", "hi", span="s") == ({"ok": "hi"}, {"prompt_tokens": 1})
    with pytest.raises(RuntimeError, match="provider down"):
        tracing.call_model(Provider(), "discover", "boom", span="s")


# ------------------------------------------------------------------ end-to-end traces
def test_discovery_agent_trace_shows_each_node_and_hides_prompt(tmp_path: Path) -> None:
    merged_, context, risk, profile = _inputs(tmp_path)
    client, session = _client()
    provider = FakeProvider()
    with tracing.agent_tracing("discovery-agent", client=client):
        result = DiscoveryAgent(provider, DiscoveryConfig(max_targets=4)).run(
            merged_, context, risk, project_root=tmp_path, profile_artifact=profile)
    client.flush()
    names = _run_names(session)
    assert {"discovery-agent", "plan_scope", "select_batch", "call_model", "discovery-model-call",
            "absorb_candidates", "plan_enrichment", "close_batch", "finalize"} <= names
    assert {"route_after_select_batch", "route_after_call_model"} <= names     # routers carry readable names
    blob = "\n".join(session.bodies)
    assert "<hidden" in blob                                                    # prompt replaced by a hash marker
    assert "Review only the JSON evidence below" not in blob                    # prompt text never uploaded
    assert result.candidates                                                    # tracing did not alter behaviour


def test_review_agent_trace_shows_each_node_and_hides_prompt(tmp_path: Path) -> None:
    finding = scanner("scan-sql", 10, "sql")
    client, session = _client()
    with tracing.agent_tracing("security-review-agent", client=client):
        result = run_security_review(discovery(), verified(), provider=ConfirmingReviewer(),
                                     project_root=tmp_path, merged=merged(finding))
    client.flush()
    assert {"security-review-agent", "prepare", "plan_batches", "review_batch", "checkpoint",
            "finalize", "security-review-model-call"} <= _run_names(session)
    assert _REVIEW_INSTRUCTION[:60] not in "\n".join(session.bodies)
    assert result.status == "completed" and len(result.reviews) == 1


def test_redacted_mode_uploads_prompt_without_credentials(tmp_path: Path) -> None:
    class SecretProvider:
        name, model = "fake", "m"

        def discover(self, prompt, **kwargs):
            return {"candidates": [], "context_requests": []}, {}

    merged_, context, risk, profile = _inputs(tmp_path)
    (tmp_path / "app.py").write_text("password = 'hunter2hunter2'\nvalue = 1\n", encoding="utf-8")
    client, session = _client("redacted")
    with tracing.agent_tracing("discovery-agent", client=client):
        DiscoveryAgent(SecretProvider(), DiscoveryConfig(max_targets=4)).run(
            merged_, context, risk, project_root=tmp_path, profile_artifact=None)
    client.flush()
    blob = "\n".join(session.bodies)
    assert "hunter2hunter2" not in blob


def test_pipeline_trace_nests_both_agents_in_one_trace(tmp_path: Path) -> None:
    merged_, context, risk, profile = _inputs(tmp_path)
    client, session = _client()
    with tracing.pipeline_trace("pre-review-pipeline", client=client):
        DiscoveryAgent(FakeProvider(), DiscoveryConfig(max_targets=4)).run(
            merged_, context, risk, project_root=tmp_path, profile_artifact=profile)
        run_security_review(discovery(), verified(), provider=ConfirmingReviewer(),
                            project_root=tmp_path, merged=merged(scanner("scan-sql", 10, "sql")))
    client.flush()
    traces: dict[str, set[str]] = {}
    for body in session.bodies:
        try:
            payload = json.loads(body)
        except ValueError:
            continue
        for item in payload if isinstance(payload, list) else [payload]:
            if isinstance(item, dict) and item.get("name") in {
                    "pre-review-pipeline", "discovery-agent", "security-review-agent"}:
                traces.setdefault(item["name"], set()).add(str(item.get("trace_id")))
    assert set(traces) == {"pre-review-pipeline", "discovery-agent", "security-review-agent"}
    assert len({trace for ids in traces.values() for trace in ids}) == 1       # a single shared trace


def test_every_conditional_branch_is_declared_for_diagrams_and_studio(tmp_path: Path) -> None:
    review = ReviewWorkflow(ReviewInputs(discovery=discovery(), verification=verified(),
                                         provider=ConfirmingReviewer(), project_root=tmp_path)).compile()
    review_edges = {(edge.source, edge.target) for edge in review.get_graph().edges}
    assert {("review_batch", "retry_missing"), ("review_batch", "checkpoint"), ("review_batch", "finalize"),
            ("checkpoint", "review_batch"), ("plan_batches", "finalize"), ("prepare", "__end__")} <= review_edges
    agent = DiscoveryWorkflow.build_graph(FakeProvider(), DiscoveryConfig(), DiscoveryInputs(
        merged=SimpleNamespace(), context=SimpleNamespace(), risk=SimpleNamespace(), project_root=tmp_path))
    discovery_edges = {(edge.source, edge.target) for edge in agent.get_graph().edges}
    assert {("fetch_context", "call_model"), ("select_batch", "select_batch"), ("call_model", "close_batch"),
            ("close_batch", "select_batch"), ("close_batch", "finalize"), ("call_model", "shrink_batch"),
            ("shrink_batch", "call_model"), ("shrink_batch", "close_batch")} <= discovery_edges

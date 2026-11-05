"""The LangGraph handoffs preserve review gating and evidence artifacts."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from security_reviewer_v2 import agent_graph
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.triage.models import TriageResult, TriageSummary


@pytest.mark.parametrize("discovery_mode", ["complete", "incomplete", "blocked"])
def test_agent_review_graph_routes_discovery_and_review(
    monkeypatch, tmp_path: Path, discovery_mode: str
) -> None:
    calls: list[str] = []
    artifacts: dict[str, dict] = {}
    discovery_payload = {
        "schema_version": "1.0",
        "status": "completed",
        "candidates": [],
        "usage": {"planned_targets": 1, "targets": 1, "provider_calls": 1},
        "batches": [{"status": "completed"}],
    }
    if discovery_mode == "incomplete":
        discovery_payload["batches"] = [{"status": "failed"}]

    class FakeDiscoveryAgent:
        def __init__(self, *_args):
            pass

        def run(self, *_args, **_kwargs):
            calls.append("discovery")
            if discovery_mode == "blocked":
                raise RuntimeError("provider unavailable")
            return SimpleNamespace(to_dict=lambda: discovery_payload)

    def fake_context(*_args, **_kwargs):
        calls.append("context")
        return SimpleNamespace(warnings=(), to_dict=lambda: {"status": "completed"})

    def fake_verification(*_args, **_kwargs):
        calls.append("verification")
        return SimpleNamespace(to_dict=lambda: {"status": "completed"})

    def fake_triage(*_args, **_kwargs):
        calls.append("triage")
        return TriageResult(
            "1.0", "completed", (), (), TriageSummary(*(0 for _ in range(9))), ()
        )

    def fake_review(*_args, **_kwargs):
        calls.append("review")
        return SimpleNamespace(to_dict=lambda: {"status": "completed", "reviews": []})

    def save_artifact(name: str, payload: dict) -> None:
        calls.append(name)
        artifacts[name] = payload

    monkeypatch.setattr(agent_graph, "DiscoveryAgent", FakeDiscoveryAgent)
    monkeypatch.setattr(agent_graph, "collect_candidate_context", fake_context)
    monkeypatch.setattr(agent_graph, "verify_discovery", fake_verification)
    monkeypatch.setattr(agent_graph, "triage_candidates", fake_triage)

    state = agent_graph.run_agent_review_graph(
        provider=object(),
        discovery_config=DiscoveryConfig(),
        project_root=tmp_path,
        profile_artifact={},
        merged=object(),
        context=object(),
        risk=SimpleNamespace(findings=()),
        additional_coverage_gaps=(),
        deployment_context=None,
        max_reviews=3,
        write_artifact=save_artifact,
        review_runner=fake_review,
    )

    assert list(artifacts) == [
        "ai-discovery.json",
        "candidate-context.json",
        "verification.json",
        "candidate-triage.json",
        "discovery-test-evidence.json",
        "security-review.json",
        "policy-gate.json",
    ]
    assert state["discovery_satisfied"] is (discovery_mode == "complete")
    assert state["review_payload"]["status"] == (
        "completed" if discovery_mode == "complete" else "not_run"
    )
    assert state["policy_payload"]["status"] == (
        "passed" if discovery_mode == "complete" else "incomplete"
    )
    if discovery_mode == "blocked":
        assert calls == [
            "discovery",
            "ai-discovery.json",
            "candidate-context.json",
            "verification.json",
            "candidate-triage.json",
            "discovery-test-evidence.json",
            "security-review.json",
            "policy-gate.json",
        ]
        assert artifacts["ai-discovery.json"]["warnings"] == ["provider unavailable"]
    else:
        assert calls[:9] == [
            "discovery",
            "ai-discovery.json",
            "context",
            "candidate-context.json",
            "verification",
            "verification.json",
            "triage",
            "candidate-triage.json",
            "discovery-test-evidence.json",
        ]
        assert ("review" in calls) is (discovery_mode == "complete")


def test_current_discovery_probes_run_before_review(
    monkeypatch, tmp_path: Path
) -> None:
    calls: list[str] = []
    artifacts: dict[str, dict] = {}

    class FakeDiscoveryAgent:
        def __init__(self, *_args):
            pass

        def run(self, *_args, **_kwargs):
            return SimpleNamespace(
                to_dict=lambda: {
                    "schema_version": "1.0",
                    "status": "completed",
                    "candidates": [],
                    "usage": {"planned_targets": 1, "targets": 1, "provider_calls": 1},
                    "batches": [{"status": "completed"}],
                }
            )

    monkeypatch.setattr(agent_graph, "DiscoveryAgent", FakeDiscoveryAgent)
    monkeypatch.setattr(
        agent_graph,
        "collect_candidate_context",
        lambda *_args, **_kwargs: SimpleNamespace(warnings=(), to_dict=lambda: {}),
    )
    monkeypatch.setattr(
        agent_graph,
        "verify_discovery",
        lambda *_args, **_kwargs: SimpleNamespace(to_dict=lambda: {}),
    )
    monkeypatch.setattr(
        agent_graph,
        "triage_candidates",
        lambda *_args, **_kwargs: TriageResult(
            "1.0", "completed", (), (), TriageSummary(*(0 for _ in range(9))), ()
        ),
    )

    def probe_runner(plan: dict) -> dict:
        calls.append("probes")
        assert plan["project_fingerprint"] == "snapshot-1"
        return {
            "schema_version": "1.0",
            "status": "no_eligible_routes",
            "source_plan": "current-scan",
            "project_fingerprint": "snapshot-1",
            "probes": [],
            "cleanup_verified": True,
        }

    def review_runner(*_args, **kwargs):
        calls.append("review")
        assert kwargs["discovery_test_evidence"]["status"] == "not_run"
        return SimpleNamespace(to_dict=lambda: {"status": "completed", "reviews": []})

    state = agent_graph.run_agent_review_graph(
        provider=object(),
        discovery_config=DiscoveryConfig(),
        project_root=tmp_path,
        profile_artifact={"project_snapshot": {"fingerprint": "snapshot-1"}},
        merged=object(),
        context=object(),
        risk=SimpleNamespace(findings=()),
        additional_coverage_gaps=(),
        deployment_context=None,
        max_reviews=3,
        write_artifact=lambda name, payload: artifacts.update({name: payload}),
        review_runner=review_runner,
        current_probe_runner=probe_runner,
    )

    assert calls == ["probes", "review"]
    assert artifacts["current-discovery-probes.json"]["cleanup_verified"] is True
    assert state["current_probe_payload"]["status"] == "no_eligible_routes"

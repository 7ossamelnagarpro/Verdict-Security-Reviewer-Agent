"""The LangGraph handoffs preserve review gating and evidence artifacts."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from security_reviewer_v2 import agent_graph
from security_reviewer_v2.discovery.models import DiscoveryConfig
from security_reviewer_v2.triage.models import TriageResult, TriageSummary


@pytest.mark.parametrize("discovery_mode", ["complete", "incomplete", "blocked"])
def test_agent_review_graph_routes_discovery_and_review(monkeypatch, tmp_path: Path, discovery_mode: str) -> None:
    calls: list[str] = []
    artifacts: dict[str, dict] = {}
    discovery_payload = {
        "schema_version": "1.0", "status": "completed", "candidates": [],
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
        return TriageResult("1.0", "completed", (), (), TriageSummary(*(0 for _ in range(9))), ())

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
        provider=object(), discovery_config=DiscoveryConfig(), project_root=tmp_path,
        profile_artifact={}, merged=SimpleNamespace(to_dict=lambda: {"findings": []}), context=object(),
        risk=SimpleNamespace(findings=()), additional_coverage_gaps=(),
        deployment_context=None, max_reviews=3, write_artifact=save_artifact,
        review_runner=fake_review,
    )

    assert list(artifacts) == [
        "ai-discovery.json", "candidate-context.json", "verification.json", "dynamic-penetration-test.json",
        "candidate-triage.json", "security-review.json", "policy-gate.json",
    ]
    assert state["discovery_satisfied"] is (discovery_mode == "complete")
    assert state["review_payload"]["status"] == ("completed" if discovery_mode == "complete" else "not_run")
    assert state["policy_payload"]["status"] == ("passed" if discovery_mode == "complete" else "incomplete")
    # Not configured with penetration_access/penetration_target_resolver: the node is a documented no-op.
    assert state["penetration_test_payload"]["status"] == "not_run"
    if discovery_mode == "blocked":
        assert calls == ["discovery", "ai-discovery.json", "candidate-context.json",
                         "verification.json", "dynamic-penetration-test.json",
                         "candidate-triage.json", "security-review.json", "policy-gate.json"]
        assert artifacts["ai-discovery.json"]["warnings"] == ["provider unavailable"]
    else:
        assert calls[:9] == ["discovery", "ai-discovery.json", "context", "candidate-context.json",
                             "verification", "verification.json", "dynamic-penetration-test.json",
                             "triage", "candidate-triage.json"]
        assert ("review" in calls) is (discovery_mode == "complete")


def _policy_state(monkeypatch, tmp_path, merged_findings, reviews, triage_groups, verification=None):
    """Run the graph with a canned review and return the policy decision for each reviewed group."""
    discovery = {"schema_version": "1.0", "status": "completed", "candidates": [], "usage": {"planned_targets": 1, "targets": 1, "provider_calls": 1},
                 "batches": [{"status": "completed"}]}
    monkeypatch.setattr(agent_graph, "DiscoveryAgent", lambda *_a: SimpleNamespace(run=lambda *_x, **_k: SimpleNamespace(to_dict=lambda: discovery)))
    monkeypatch.setattr(agent_graph, "collect_candidate_context", lambda *_a, **_k: SimpleNamespace(warnings=(), to_dict=lambda: {"status": "completed"}))
    monkeypatch.setattr(agent_graph, "verify_discovery", lambda *_a, **_k: SimpleNamespace(to_dict=lambda: verification or {"status": "completed", "records": []}))
    triage = TriageResult("1.0", "completed", (), (), TriageSummary(*(0 for _ in range(9))), ())
    monkeypatch.setattr(TriageResult, "to_dict", lambda self: {"records": [], "groups": triage_groups})
    monkeypatch.setattr(agent_graph, "triage_candidates", lambda *_a, **_k: triage)
    state = agent_graph.run_agent_review_graph(
        provider=object(), discovery_config=DiscoveryConfig(), project_root=tmp_path, profile_artifact={},
        merged=SimpleNamespace(to_dict=lambda: {"findings": merged_findings}), context=object(),
        risk=SimpleNamespace(findings=()), additional_coverage_gaps=(), deployment_context=None, max_reviews=3,
        write_artifact=lambda *_a: None,
        review_runner=lambda *_a, **_k: SimpleNamespace(to_dict=lambda: {"status": "completed", "reviews": reviews}))
    return {d["candidate_id"]: d for d in state["policy_payload"]["decisions"]}


def test_policy_gate_receives_scanner_evidence_so_a_block_is_actually_corroborated(monkeypatch, tmp_path: Path) -> None:
    finding = {"merged_finding_id": "merged-1", "severity": "high", "scanners": ["trivy"], "rule_ids": ["CVE-2026-1"],
               "primary_location": {"path": "requirements.txt", "start_line": 3}}
    decisions = _policy_state(monkeypatch, tmp_path, [finding],
                              [{"candidate_id": "merged-1", "verdict": "confirmed_vulnerability", "severity": "high"}],
                              [{"group_id": "merged-1", "scanner_finding_ids": ["merged-1"], "candidate_ids": []}])
    decision = decisions["merged-1"]
    assert (decision["rule_id"], decision["action"], decision["evidence_basis"]) == ("RG-001", "block", "scanner_corroborated")
    assert any("trivy high at requirements.txt:3" in line for line in decision["evidence"])


def test_a_confirmed_verdict_with_no_scanner_or_source_evidence_warns_instead_of_blocking(monkeypatch, tmp_path: Path) -> None:
    decisions = _policy_state(monkeypatch, tmp_path, [],
                              [{"candidate_id": "ai-1", "verdict": "confirmed_vulnerability", "severity": "high"}],
                              [{"group_id": "ai-1", "scanner_finding_ids": [], "candidate_ids": ["ai-1"]}])
    decision = decisions["ai-1"]
    assert (decision["rule_id"], decision["action"], decision["evidence_basis"]) == ("RG-002", "warn", "ai_assertion_only")

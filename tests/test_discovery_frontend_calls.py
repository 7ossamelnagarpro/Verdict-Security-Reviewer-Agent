"""Literal frontend calls are guidance, never executed or counted as findings."""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

from security_reviewer_v2.discovery.agent import DiscoveryAgent
from security_reviewer_v2.discovery.frontend_calls import collect_frontend_calls
from security_reviewer_v2.discovery.map_context import map_guidance


def _profile(root: Path, name: str) -> dict:
    source = root / name
    return {
        "profile": {"inventory": [{"path": name, "category": "source"}]},
        "project_snapshot": {
            "root_path": os.path.normcase(str(root.resolve())),
            "files": [
                {
                    "path": name,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ],
        },
    }


def test_literal_frontend_calls_are_bounded_and_never_execute(tmp_path: Path):
    source = tmp_path / "client.js"
    source.write_text(
        "fetch('/api/orders');\n"
        "fetch('/api/orders', {method: 'POST'});\n"
        "axios.delete('/api/orders/42');\n"
        "fetch('https://external.example/private');\n"
        "fetch('//external.example/private');\n"
        "fetch(variable);\n",
        encoding="utf-8",
    )
    profile = _profile(tmp_path, "client.js")
    result = collect_frontend_calls(tmp_path, profile)
    assert result["status"] == "completed"
    assert [
        (call["method"], call["path"], call["source"]["line"])
        for call in result["calls"]
    ] == [
        ("GET", "/api/orders", 1),
        ("POST", "/api/orders", 2),
        ("DELETE", "/api/orders/42", 3),
    ]
    assert "external.example" not in str(result)
    source.write_text("fetch('/changed');\n", encoding="utf-8")
    changed = collect_frontend_calls(tmp_path, profile)
    assert changed["status"] == "partial"
    assert changed["calls"] == []
    assert any("differs from profiler snapshot" in gap for gap in changed["gaps"])


def test_frontend_calls_reach_discovery_guidance_not_findings(tmp_path: Path):
    source = tmp_path / "client.js"
    source.write_text(
        "function loadAccount() {\n  return fetch('/api/account');\n}\n",
        encoding="utf-8",
    )
    profile = _profile(tmp_path, "client.js")
    empty = SimpleNamespace(findings=(), coverage_gaps=())

    class EmptyProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.prompt = prompt
            return {"candidates": [], "context_requests": []}, {}

    provider = EmptyProvider()
    result = DiscoveryAgent(provider).run(
        empty, empty, empty, project_root=tmp_path, profile_artifact=profile
    )
    guidance = result.application_map_guidance
    assert guidance["status"] == "not_provided"
    assert guidance["frontend_api_calls"][0]["path"] == "/api/account"
    assert guidance["frontend_calls_without_exact_map_match"] is None
    assert (
        guidance["frontend_api_calls"][0]["status"]
        == "static_reference_not_runtime_proof"
    )
    assert result.usage["frontend_api_hints_in_initial_prompts"] >= 1
    assert "/api/account" in provider.prompt
    assert result.candidates == ()
    compared = map_guidance(
        {"routes": []},
        scanner_paths=set(),
        planned_targets=(),
        frontend_result={
            "status": "completed",
            "calls": guidance["frontend_api_calls"],
            "gaps": [],
        },
    )
    assert compared["frontend_calls_without_exact_map_match"] == 1
    assert (
        compared["frontend_calls_needing_runtime_confirmation"][0]["path"]
        == "/api/account"
    )

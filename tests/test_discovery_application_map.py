"""Application Map guidance remains bounded, source-scoped, and non-authoritative."""

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

from security_reviewer_v2.discovery.agent import DiscoveryAgent, _build_prompt
from security_reviewer_v2.discovery.map_context import (
    map_guidance,
    validated_application_map,
)
from security_reviewer_v2.discovery.models import DiscoveryConfig, DiscoveryTarget
from security_reviewer_v2.discovery.scope import DiscoveryScope, plan_discovery_scope
from security_reviewer_v2.discovery.serialization import discovery_result_from_dict


def _profile(root: Path, names: tuple[str, ...]) -> dict:
    return {
        "profile": {
            "inventory": [{"path": name, "category": "source"} for name in names]
        },
        "project_snapshot": {
            "root_path": os.path.normcase(str(root.resolve())),
            "fingerprint": "snapshot-1",
            "files": [
                {
                    "path": name,
                    "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
                }
                for name in names
            ],
        },
    }


def _map(root: Path) -> dict:
    return {
        "schema_version": "1.0",
        "status": "generated",
        "project_root": str(root.resolve()),
        "project_fingerprint": "snapshot-1",
        "routes": [
            {
                "method": "POST",
                "path": "/orders/{order_id}",
                "source": {"file": "app.py", "line": 2},
                "parameters": [{"name": "order_id", "location": "path"}],
                "request_body": {"fields": [{"name": "owner_id"}]},
                "authentication": {"status": "unknown"},
                "required_role": None,
                "called_functions": ["save_order"],
                "database_interactions": [{"tables": ["orders"]}],
            },
            {
                "method": "GET",
                "path": "/unrelated",
                "source": {"file": "other.py", "line": 1},
                "parameters": [],
                "authentication": {"status": "unknown"},
            },
        ],
        "unmatched_graph_routes": [
            {"method": "DELETE", "path": "/invented", "file": "app.py"}
        ],
    }


def _empty_inputs():
    return SimpleNamespace(findings=(), coverage_gaps=())


def test_map_rejects_stale_or_foreign_snapshot(tmp_path: Path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    profile = _profile(tmp_path, ("app.py",))
    current, status = validated_application_map(
        _map(tmp_path), project_root=tmp_path, profile_artifact=profile
    )
    assert status == "accepted" and current is not None
    assert [route["path"] for route in current["routes"]] == ["/orders/{order_id}"]
    stale = _map(tmp_path)
    stale["project_fingerprint"] = "old"
    assert validated_application_map(
        stale, project_root=tmp_path, profile_artifact=profile
    ) == (None, "map_does_not_match_profile")
    foreign = _map(tmp_path)
    foreign["project_root"] = str(tmp_path / "other")
    assert (
        validated_application_map(
            foreign, project_root=tmp_path, profile_artifact=profile
        )[0]
        is None
    )


def test_prompt_hints_only_selected_source_routes_and_preserves_target_budget(
    tmp_path: Path,
):
    target = DiscoveryTarget("file:app.py", "source", "app.py", 1, 4, ())
    scope = DiscoveryScope(
        (target,),
        {target.target_id: "1: def save_order(order_id):\n2:     pass"},
        (),
        (),
        (),
    )
    prompt, included, _ = _build_prompt(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        scope,
        3_000,
        application_map=_map(tmp_path),
    )
    body = json.loads(prompt.split("\n\n", 1)[1])
    assert included == (target,)
    assert body["application_map_hints"][0]["path"] == "/orders/{order_id}"
    assert body["application_map_hints"][0]["direct_sql_tables"] == ["orders"]
    assert body["application_map_hints"][0]["authentication_observation"] == "unknown"
    assert "/unrelated" not in prompt and "/invented" not in prompt
    short_prompt, short_included, _ = _build_prompt(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        scope,
        1_000,
        application_map=_map(tmp_path),
    )
    assert short_included == (target,)
    assert len(short_prompt) <= 1_000
    assert json.loads(short_prompt.split("\n\n", 1)[1])["targets"]

    off_window = _map(tmp_path)
    off_window["routes"][0]["source"]["line"] = 200
    no_hint, _, _ = _build_prompt(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        scope,
        3_000,
        application_map=off_window,
    )
    assert "application_map_hints" not in json.loads(no_hint.split("\n\n", 1)[1])


def test_malformed_map_route_cannot_expand_prompt_scope(tmp_path: Path):
    target = DiscoveryTarget("file:app.py", "source", "app.py", 1, 3, ())
    scope = DiscoveryScope((target,), {target.target_id: "1: pass"}, (), (), ())
    malformed = _map(tmp_path)
    malformed["routes"].append(
        {
            "method": "GET",
            "path": "/escape",
            "source": {"file": "../outside.py", "line": 1},
            "parameters": ["not-a-parameter"],
            "database_interactions": "unexpected",
        }
    )
    prompt, included, _ = _build_prompt(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        scope,
        2_000,
        application_map=malformed,
    )
    assert included == (target,)
    assert "/escape" not in prompt
    assert "outside.py" not in prompt


def test_map_prioritizes_source_backed_route_without_scanner_findings(tmp_path: Path):
    for name in ("a.py", "app.py"):
        (tmp_path / name).write_text(
            "def handler(request):\n    return request.body\n", encoding="utf-8"
        )
    profile = _profile(tmp_path, ("a.py", "app.py"))
    scope = plan_discovery_scope(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        project_root=tmp_path,
        config=DiscoveryConfig(max_files_considered=1),
        profile_artifact=profile,
        application_map=_map(tmp_path),
    )
    assert scope.targets and all(target.path == "app.py" for target in scope.targets)


def test_role_names_are_test_account_hints_not_required_role_claims(tmp_path: Path):
    application_map = _map(tmp_path)
    application_map["routes"][0]["path"] = "/admin/orders/{order_id}"
    application_map["routes"][0]["called_functions"] = ["require_admin"]
    guidance = map_guidance(application_map, scanner_paths=set(), planned_targets=())
    suggestion = guidance["suggestions"][0]
    assert suggestion["required_role"] is None
    assert suggestion["role_name_candidates"] == ["admin"]
    assert (
        "admin test account, if policy confirms the role"
        in suggestion["account_scenarios"]
    )


def test_discovery_saves_review_suggestions_not_findings(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "@app.post('/orders/{order_id}')\ndef save_order(order_id):\n"
        "    return request.body\n",
        encoding="utf-8",
    )
    profile = _profile(tmp_path, ("app.py",))

    class EmptyProvider:
        name = "fake"
        model = "test"

        def discover(self, prompt, *, timeout_seconds, max_candidates):
            self.prompt = prompt
            return {"candidates": [], "context_requests": []}, {}

    provider = EmptyProvider()
    result = DiscoveryAgent(provider).run(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        project_root=tmp_path,
        profile_artifact=profile,
        application_map=_map(tmp_path),
    )
    guidance = result.to_dict()["application_map_guidance"]
    assert guidance["status"] == "generated"
    assert guidance["source_routes"] == 1
    assert guidance["routes_outside_planned_source_scope"] == 0
    assert guidance["suggestions"][0]["path"] == "/orders/{order_id}"
    assert guidance["suggestions"][0]["status"] == "proposal_requires_human_review"
    assert any(
        "cross-account" in check
        for check in guidance["suggestions"][0]["suggested_checks"]
    )
    assert result.usage["application_map_hints_in_initial_prompts"] >= 1
    assert result.candidates == ()
    assert "/invented" not in provider.prompt
    assert (
        discovery_result_from_dict(result.to_dict()).application_map_guidance
        == guidance
    )

    stale = _map(tmp_path)
    stale["project_fingerprint"] = "old"
    ignored = DiscoveryAgent(EmptyProvider()).run(
        _empty_inputs(),
        _empty_inputs(),
        _empty_inputs(),
        project_root=tmp_path,
        profile_artifact=profile,
        application_map=stale,
    )
    assert ignored.application_map_guidance["status"] == "map_does_not_match_profile"
    assert ignored.application_map_guidance["suggestions"] == []

"""Discovery proposals require review before bounded execution."""

import json
from pathlib import Path

import pytest

from security_reviewer_v2.discovery.test_plan import (
    apply_probe_execution,
    approved_readonly_proposals,
    approved_readonly_routes,
    bounded_probe_result,
    build_discovery_test_plan,
    link_probe_evidence,
    select_bounded_readonly_proposals,
)


def test_source_routes_produce_bounded_non_executable_proposals():
    discovery = {
        "candidates": [
            {
                "candidate_id": "ai-exact",
                "entry_point": {"path": "api/app.py", "line": 20},
            },
            {
                "candidate_id": "ai-other-line",
                "entry_point": {"path": "api/app.py", "line": 21},
            },
        ],
        "application_map_guidance": {
            "suggestions": [
                {
                    "method": "POST",
                    "path": "/orders/{order_id}",
                    "source": {"file": "api/app.py", "line": 10},
                    "suggested_checks": [
                        "compare authorized and cross-account object access on a disposable target",
                        "review a state-changing workflow; do not execute without approval",
                    ],
                    "account_scenarios": ["anonymous", "authenticated test user"],
                },
                {
                    "method": "GET",
                    "path": "/admin/users",
                    "source": {"file": "api/app.py", "line": 20},
                    "suggested_checks": [
                        "confirm expected anonymous and role-based access using approved test accounts"
                    ],
                },
                {"method": "GET", "path": "//external.example", "suggested_checks": []},
            ]
        },
    }
    plan = build_discovery_test_plan(discovery)
    assert plan["proposal_count"] == 2
    assert plan["executed_count"] == 0
    write, read = plan["proposals"]
    assert "cross_account_workflow_review" in write["proposal_types"]
    assert "state_changing_workflow_review" in write["proposal_types"]
    assert "bounded_http_probe_review" not in write["proposal_types"]
    assert "bounded_http_probe_review" in read["proposal_types"]
    assert "role_access_workflow_review" in read["proposal_types"]
    assert read["candidate_ids"] == ["ai-exact"]
    assert write["candidate_ids"] == []
    assert all(
        item["approval_required"] and not item["auto_executable"]
        for item in plan["proposals"]
    )


def test_browser_observations_add_read_only_review_proposals_without_query_values():
    browser = {
        "status": "completed",
        "observed_requests": [
            {"method": "GET", "path": "/api/catalog", "status": 200},
            {"method": "POST", "path": "/api/orders", "status": 201},
            {"method": "GET", "path": "//external.example", "status": 200},
        ],
        "observed_forms": [
            {
                "method": "POST",
                "path": "/orders",
                "fields": [{"name": "owner_id", "type": "text"}],
            }
        ],
    }
    plan = build_discovery_test_plan({}, browser)
    assert plan["proposal_count"] == 2
    assert plan["proposals"][0]["path"] == "/api/catalog"
    assert plan["proposals"][0]["proposal_types"] == ["browser_observed_route_review"]
    assert plan["proposals"][1]["proposal_types"] == ["browser_form_workflow_review"]
    assert "fields" not in plan["proposals"][1]


def test_malformed_browser_data_cannot_create_executable_proposals():
    plan = build_discovery_test_plan(
        {
            "application_map_guidance": {
                "suggestions": [
                    {"method": ["GET"], "path": "/invalid"},
                ]
            }
        },
        {
            "status": "completed",
            "observed_requests": None,
            "observed_forms": [{"method": ["POST"], "path": "/orders"}],
        },
    )
    assert plan["proposal_count"] == 0


def test_approved_plan_selects_only_current_declared_get_routes(tmp_path: Path):
    project = tmp_path / "target"
    project.mkdir()
    (project / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/account')\ndef account(): return {}\n"
        "@app.post('/orders')\ndef orders(): return {}\n",
        encoding="utf-8",
    )
    plan = build_discovery_test_plan(
        {
            "application_map_guidance": {
                "suggestions": [
                    {
                        "method": "GET",
                        "path": "/account",
                        "source": {"file": "app.py", "line": 3},
                    },
                    {
                        "method": "GET",
                        "path": "/logout",
                        "source": {"file": "app.py", "line": 3},
                    },
                    {
                        "method": "GET",
                        "path": "//host",
                        "source": {"file": "app.py", "line": 3},
                    },
                    {
                        "method": "POST",
                        "path": "/orders",
                        "source": {"file": "app.py", "line": 5},
                    },
                ]
            }
        },
        project_root=project,
        project_fingerprint="snapshot-1",
    )
    saved = tmp_path / "approved.json"
    saved.write_text(json.dumps(plan), encoding="utf-8")
    assert approved_readonly_routes(
        saved, project_root=project, project_fingerprint="snapshot-1"
    ) == ("/account",)
    approved = approved_readonly_proposals(
        saved, project_root=project, project_fingerprint="snapshot-1"
    )
    assert approved[0]["proposal_id"].startswith("route-")
    assert approved[0]["source"] == {"file": "app.py", "line": 3}
    assert select_bounded_readonly_proposals(
        plan, project_root=project, project_fingerprint="snapshot-1"
    ) == approved
    observed = bounded_probe_result(
        approved,
        {
            "results": [
                {
                    "rule_id": "web.endpoint-server-error",
                    "path": "/account",
                    "evidence": {"status": 200},
                }
            ]
        },
        health_path="/healthz",
        project_fingerprint="snapshot-1",
        source_plan="current-scan",
    )
    updated = apply_probe_execution(plan, observed)
    assert observed["status"] == "completed"
    assert updated["executed_count"] == 1
    assert updated["proposals"][0]["execution_status"] == "executed"
    assert updated["proposals"][1]["execution_status"] == "not_executed"
    assert apply_probe_execution(plan, {**observed, "project_fingerprint": "stale"}) == plan
    with pytest.raises(ValueError, match="snapshot"):
        approved_readonly_routes(
            saved, project_root=project, project_fingerprint="different"
        )


def test_approved_plan_rejects_file_inside_target(tmp_path: Path):
    project = tmp_path / "target"
    project.mkdir()
    saved = project / "approved.json"
    saved.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="outside"):
        approved_readonly_routes(
            saved, project_root=project, project_fingerprint="snapshot-1"
        )


def test_probe_evidence_links_only_current_candidates_at_exact_source_anchor():
    discovery = {
        "candidates": [
            {
                "candidate_id": "ai-current",
                "entry_point": {"path": "app.py", "line": 3},
            },
            {
                "candidate_id": "ai-other",
                "entry_point": {"path": "app.py", "line": 4},
            },
        ]
    }
    triage = {
        "records": [
            {"candidate_id": "ai-current", "group_id": "group-1"},
            {"candidate_id": "ai-other", "group_id": None},
        ]
    }
    probes = {
        "schema_version": "1.0",
        "project_fingerprint": "snapshot-1",
        "probes": [
            {
                "proposal_id": "route-1",
                "candidate_ids": ["ai-previous"],
                "method": "GET",
                "path": "/account",
                "source": {"file": "app.py", "line": 3},
                "execution_status": "executed",
                "http_status": 200,
                "security_assertion": "not_defined",
            }
        ],
    }
    linked = link_probe_evidence(
        discovery, triage, probes, project_fingerprint="snapshot-1"
    )
    assert linked["observed_candidates"] == 1
    assert linked["candidates"][0]["review_group_id"] == "group-1"
    assert linked["candidates"][0]["probes"][0]["conclusion"] == "inconclusive"
    assert linked["candidates"][1]["status"] == "not_tested"
    stale = link_probe_evidence(
        discovery, triage, probes, project_fingerprint="different"
    )
    assert stale["status"] == "not_run"
    assert stale["observed_candidates"] == 0
    blocked = link_probe_evidence(
        discovery,
        triage,
        {
            **probes,
            "status": "blocked",
            "probes": [],
            "warnings": ["Docker cleanup unverified"],
        },
        project_fingerprint="snapshot-1",
    )
    assert blocked["status"] == "partial"
    assert "Docker cleanup unverified" in blocked["limitations"]


def test_declared_workflow_assertion_links_to_candidate_without_response_values():
    linked = link_probe_evidence(
        {
            "candidates": [
                {
                    "candidate_id": "ai-me",
                    "entry_point": {"path": "app.py", "line": 20},
                }
            ]
        },
        {"records": [{"candidate_id": "ai-me", "group_id": "group-me"}]},
        None,
        project_fingerprint="snapshot-1",
        application_map={
            "routes": [
                {
                    "method": "GET",
                    "path": "/me",
                    "source": {"file": "app.py", "line": 20},
                }
            ]
        },
        runtime_evidence={
            "workflow_evidence": {
                "workflows": [
                    {
                        "id": "excessive-data",
                        "steps": [
                            {
                                "step": 2,
                                "actor": "user_a",
                                "method": "GET",
                                "path": "/me",
                                "security_check": True,
                                "http_status": 200,
                                "assertion_checks": [
                                    {
                                        "kind": "json_field_absent",
                                        "operator": "missing",
                                        "passed": False,
                                    }
                                ],
                                "response_body": "secret must not be copied",
                            }
                        ],
                    }
                ]
            }
        },
    )
    candidate = linked["candidates"][0]
    assert candidate["status"] == "observed_assertion"
    assert candidate["workflow_tests"][0]["result"] == "violated"
    assert "secret must not be copied" not in json.dumps(linked)

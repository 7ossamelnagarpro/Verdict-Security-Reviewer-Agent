"""Discovery proposals require review before bounded execution."""

import json
from pathlib import Path

import pytest

from security_reviewer_v2.discovery.test_plan import (
    approved_readonly_routes,
    build_discovery_test_plan,
)


def test_source_routes_produce_bounded_non_executable_proposals():
    discovery = {
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
        }
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

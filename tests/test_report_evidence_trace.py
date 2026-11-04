"""Saved report traces use only redacted, recorded evidence."""

from security_reviewer_v2.reporting.evidence_trace import build_evidence_traces
from security_reviewer_v2.reporting.final import render_final_report
from security_reviewer_v2.reporting.html import render_html_report


def _saved_bundle() -> dict:
    return {
        "project": "demo",
        "review": {
            "status": "completed",
            "reviews": [
                {
                    "candidate_id": "workflow-group",
                    "title": "Admin route exposed",
                    "verdict": "confirmed_vulnerability",
                    "severity": "high",
                    "source_ids": ["workflow-finding"],
                },
                {
                    "candidate_id": "static-group",
                    "title": "SQL input flow",
                    "verdict": "likely_vulnerability",
                    "severity": "high",
                    "source_ids": ["static-finding"],
                },
            ],
        },
        "policy": {"decisions": []},
        "triage": {
            "groups": [
                {
                    "group_id": "workflow-group",
                    "scanner_finding_ids": ["workflow-finding"],
                },
                {
                    "group_id": "static-group",
                    "scanner_finding_ids": ["static-finding"],
                },
            ]
        },
        "merged": {
            "findings": [
                {
                    "merged_finding_id": "workflow-finding",
                    "scanners": ["web-runtime"],
                    "source_findings": [
                        {
                            "finding_id": "source-workflow",
                            "scanner": {"scanner_id": "web-runtime"},
                            "rule_id": "workflow.admin.2",
                            "primary_location": {
                                "path": "/admin/jobs?token=SECRET_VALUE"
                            },
                            "runtime_evidence": {
                                "workflow_id": "admin_jobs",
                                "step": 2,
                                "status": 200,
                                "expected_statuses": [403, 404],
                                "response_body": "SECRET_VALUE",
                            },
                        }
                    ],
                },
                {
                    "merged_finding_id": "static-finding",
                    "scanners": ["codeql-cli"],
                    "source_findings": [
                        {
                            "finding_id": "source-static",
                            "scanner": {"scanner_id": "codeql-cli"},
                            "rule_id": "py/sql-injection",
                            "severity": "high",
                            "primary_location": {
                                "path": "api/app.py",
                                "start_line": 42,
                            },
                            "code_flow": [
                                {
                                    "location": {
                                        "path": "api/app.py",
                                        "start_line": 20,
                                    }
                                }
                            ],
                        }
                    ],
                },
            ]
        },
        "runtime_evidence": {
            "workflow_evidence": {
                "workflows": [
                    {
                        "id": "admin_jobs",
                        "steps": [
                            {
                                "step": 1,
                                "actor": "admin",
                                "method": "GET",
                                "path": "/admin/jobs",
                                "status": "passed",
                                "http_status": 200,
                                "expected_status": [200],
                                "assertion_checks": [
                                    {"kind": "status", "passed": True}
                                ],
                            },
                            {
                                "step": 2,
                                "actor": "user_a",
                                "method": "GET",
                                "path": "/admin/jobs?token=SECRET_VALUE",
                                "status": "violation",
                                "http_status": 200,
                                "expected_status": [403, 404],
                                "assertion_checks": [
                                    {"kind": "status", "passed": False}
                                ],
                                "body": "SECRET_VALUE",
                            },
                        ],
                    }
                ]
            }
        },
    }


def test_trace_links_workflow_steps_and_static_scanner_without_secret_values() -> None:
    bundle = _saved_bundle()
    traces = build_evidence_traces(
        bundle["review"],
        bundle["triage"],
        bundle["merged"],
        bundle["runtime_evidence"],
    )
    workflow = traces["workflow-group"][0]
    assert workflow["kind"] == "workflow"
    assert [step["actor"] for step in workflow["steps"]] == ["admin", "user_a"]
    assert workflow["steps"][1]["expected_statuses"] == [403, 404]
    assert workflow["steps"][1]["observed_status"] == 200
    assert traces["static-group"][0]["flow_locations"] == ["api/app.py:20"]
    assert "SECRET_VALUE" not in str(traces)


def test_html_and_markdown_show_scenario_and_saved_output() -> None:
    bundle = _saved_bundle()
    html = render_html_report(**bundle)
    markdown = render_final_report(**bundle)
    assert "How this finding was reached" in html
    assert "expected HTTP 403/404, observed HTTP 200" in html
    assert "Static scanner output" in html
    assert "Scanner-reported code-flow locations" in html
    assert "Workflow" in markdown and "expected HTTP 403/404" in markdown
    assert "SECRET_VALUE" not in html + markdown

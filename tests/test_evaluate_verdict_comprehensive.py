from __future__ import annotations

import json

import pytest

from scripts.evaluate_verdict_comprehensive import (
    TRUTH,
    _coverage_metrics,
    _discovery_evidence_metrics,
    _discovery_review_audit,
    _matches,
    evaluate,
    html_report,
    markdown,
)


def test_discovery_review_audit_keeps_grounded_disagreement_without_false_negative_claim():
    rows = _discovery_review_audit(
        {
            "candidates": [
                {
                    "candidate_id": "ai-one",
                    "title": "Issue",
                    "path": "app.py",
                    "start_line": 4,
                },
                {"candidate_id": "ai-two", "title": "Issue 2"},
            ]
        },
        {
            "records": [
                {"candidate_id": "ai-one", "disposition": "confirmed"},
                {"candidate_id": "ai-two", "disposition": "needs_more_evidence"},
            ]
        },
        {
            "records": [
                {
                    "candidate_id": "ai-one",
                    "group_id": "group-one",
                    "disposition": "novel_candidate",
                }
            ]
        },
        {"group-one": {"verdict": "false_positive"}},
    )
    assert len(rows) == 1
    assert rows[0]["candidate_id"] == "ai-one"
    assert rows[0]["review_verdict"] == "false_positive"
    assert rows[0]["independent_proof"] == "not_adjudicated"


def test_discovery_review_audit_does_not_call_pending_review_a_disagreement():
    rows = _discovery_review_audit(
        {"candidates": [{"candidate_id": "ai-one", "title": "Issue"}]},
        {"records": [{"candidate_id": "ai-one", "disposition": "confirmed"}]},
        {"records": [{"candidate_id": "ai-one", "group_id": "group-one"}]},
        {},
    )
    assert rows == []


def test_discovery_evidence_metrics_distinguish_observation_from_rule_failure():
    metrics = _discovery_evidence_metrics(
        {
            "candidates": [
                {
                    "candidate_id": "ai-one",
                    "review_group_id": "group-one",
                    "probes": [{"http_status": 200, "conclusion": "inconclusive"}],
                    "workflow_tests": [],
                },
                {
                    "candidate_id": "ai-two",
                    "review_group_id": None,
                    "probes": [],
                    "workflow_tests": [{"result": "violated"}],
                },
                {"candidate_id": "ai-three", "probes": [], "workflow_tests": []},
            ]
        }
    )
    assert metrics == {
        "measured": True,
        "candidate_count": 3,
        "observed_candidates": 2,
        "workflow_linked_candidates": 1,
        "violated_rule_candidates": 1,
        "review_group_linked_candidates": 1,
    }
    assert _discovery_evidence_metrics(None) == {"measured": False}


def test_coverage_metrics_count_only_saved_executed_scope() -> None:
    metrics = _coverage_metrics(
        {
            "endpoint_coverage": {"endpoint_count": 4, "probed_count": 3},
            "ai_discovery": {"planned_targets": 20, "inspected_targets": 20},
            "runtime_evidence": {
                "workflow_evidence": {
                    "coverage": {"declared": 8, "executed": 6},
                    "accounts": [
                        {"actor": "user_a", "role": "user", "status": "verified"},
                        {"actor": "user_b", "role": "user", "status": "verified"},
                        {"actor": "admin", "role": "admin", "status": "blocked"},
                    ],
                }
            },
        }
    )
    assert metrics["declared_routes_probed"]["rate"] == 0.75
    assert metrics["discovery_targets_inspected"]["rate"] == 1.0
    assert metrics["workflow_steps_executed"]["rate"] == 0.75
    assert metrics["test_accounts_verified"]["covered"] == 2
    assert metrics["declared_roles_verified"]["covered"] == 1
    assert metrics["declared_roles_verified"]["total"] == 2
    assert not _coverage_metrics({})["declared_roles_verified"]["measured"]


def test_source_route_coverage_uses_recorded_responses_only() -> None:
    metrics = _coverage_metrics(
        {
            "runtime_evidence": {
                "results": [
                    {
                        "rule_id": "web.endpoint-server-error",
                        "path": "/account",
                        "evidence": {"status": 200},
                    }
                ],
                "workflow_evidence": {
                    "workflows": [
                        {
                            "steps": [
                                {
                                    "method": "POST",
                                    "path": "/orders/{{order_id}}",
                                    "http_status": 200,
                                },
                                {
                                    "method": "GET",
                                    "path": "/unseen",
                                    "status": "skipped",
                                },
                            ]
                        }
                    ]
                },
            }
        },
        {
            "status": "generated",
            "routes": [
                {"method": "GET", "path": "/account"},
                {"method": "POST", "path": "/orders/{order_id}"},
                {"method": "GET", "path": "/unseen"},
            ],
        },
    )
    assert metrics["source_routes_observed"]["covered"] == 2
    assert metrics["source_routes_observed"]["total"] == 3


def test_runtime_assertion_mismatch_counts_even_with_expected_http_status() -> None:
    source = {
        "rule_id": "workflow.excessive_data.1",
        "primary_location": {"path": "/me"},
        "runtime_evidence": {
            "status": 200,
            "expected_statuses": [200],
            "assertion_results": [False],
        },
    }
    assert _matches("C24", source)
    assert not _matches("C01", source)


def test_unattributed_flagged_group_is_a_review_queue_not_a_false_positive() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    result = evaluate(
        truth,
        {"project": "targets/verdict-comprehensive-lab", "status": "completed"},
        {"status": "completed", "findings": []},
        {
            "groups": [
                {
                    "group_id": "unmatched-one",
                    "scanner_finding_ids": [],
                    "candidate_ids": ["candidate-one"],
                }
            ]
        },
        {
            "status": "completed",
            "reviews": [
                {
                    "candidate_id": "unmatched-one",
                    "source_ids": ["candidate-one"],
                    "title": "Needs independent review",
                    "verdict": "likely_vulnerability",
                    "severity": "medium",
                }
            ],
        },
    )
    assert result["summary"]["unattributed_flagged_groups"] == 1
    assert result["unattributed_flagged_groups"][0]["group_id"] == "unmatched-one"
    assert result["summary"]["precision"] is None
    assert "not automatically false positives" in markdown(result)
    assert "Needs independent review" in html_report(result)


def test_known_case_with_false_positive_verdict_needs_review() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    finding = {
        "merged_finding_id": "merged-one",
        "canonical_finding": {"title": "<script>signal</script>"},
        "scanners": ["web-runtime"],
        "categories": ["dast"],
        "severity": "high",
        "primary_location": {"path": "/me"},
        "source_findings": [
            {
                "rule_id": "workflow.excessive_data.1",
                "primary_location": {"path": "/me"},
                "runtime_evidence": {
                    "status": 200,
                    "expected_statuses": [200],
                    "assertion_results": [False],
                },
            }
        ],
    }
    result = evaluate(
        truth,
        {
            "project": "targets/verdict-comprehensive-lab",
            "status": "partial",
            "security_review": {"status": "partial"},
        },
        {"status": "completed", "findings": [finding]},
        {
            "groups": [
                {
                    "group_id": "merged-one",
                    "scanner_finding_ids": ["merged-one"],
                    "candidate_ids": [],
                }
            ]
        },
        {
            "status": "completed",
            "reviews": [
                {
                    "candidate_id": "merged-one",
                    "source_ids": ["merged-one"],
                    "verdict": "false_positive",
                }
            ],
        },
    )
    assert (
        next(item for item in result["cases"] if item["id"] == "C24")["status"]
        == "needs_review"
    )
    assert result["summary"]["known_positive_cases"] == 35
    assert len(result["cases"]) == 63
    assert result["summary"]["precision"] is None
    assert result["summary"]["f1"] is None
    assert result["scan_provenance"]["initial_security_review"]["status"] == "partial"
    assert result["scan_provenance"]["security_review"]["status"] == "completed"
    assert result["original_observations"] == [
        {
            "id": "merged-one",
            "title": "<script>signal</script>",
            "source": "DAST",
            "scanners": ["web-runtime"],
            "path": "/me",
            "line": None,
            "severity": "high",
            "review_groups": [{"group_id": "merged-one", "verdict": "false_positive"}],
        }
    ]
    assert "Safe controls — specificity not assessed" in markdown(result)
    assert "## Original scanner & DAST observations (1)" in markdown(result)
    assert "&lt;script&gt;signal&lt;/script&gt;" in markdown(result)
    assert "S01" in markdown(result)
    assert "All 63 benchmark cases" in html_report(result)
    assert "Original scanner &amp; DAST observations (1)" in html_report(result)
    assert "&lt;script&gt;signal&lt;/script&gt;" in html_report(result)
    assert "<script>signal</script>" not in html_report(result)
    assert "S01" in html_report(result)


def test_partial_review_is_explicitly_provisional_and_not_a_scanner_miss() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    source = {
        "rule_id": "src.security_reviewer_v2.scanners.rules.verdict.python.unsigned-jwt-algorithm",
        "primary_location": {"path": "api/app.py", "start_line": 90},
    }
    assert _matches("C16", source)
    assert _matches(
        "N06",
        {
            "rule_id": "web.cookie-missing-security-attributes",
            "primary_location": {"path": "/session/start"},
        },
    )
    merged = {
        "status": "completed",
        "findings": [{"merged_finding_id": "merged-one", "source_findings": [source]}],
    }
    triage = {
        "groups": [
            {
                "group_id": "merged-one",
                "scanner_finding_ids": ["merged-one"],
                "candidate_ids": [],
            }
        ]
    }
    partial = {"status": "partial", "reviews": []}
    with pytest.raises(ValueError, match="Complete final review"):
        evaluate(
            truth,
            {"project": "targets/verdict-comprehensive-lab"},
            merged,
            triage,
            partial,
        )
    result = evaluate(
        truth,
        {"project": "targets/verdict-comprehensive-lab"},
        merged,
        triage,
        partial,
        allow_partial=True,
    )
    assert result["evaluation_status"] == "provisional"
    assert (
        next(row for row in result["cases"] if row["id"] == "C16")["status"]
        == "pending_review"
    )
    assert result["summary"]["pending_review"] == 1
    assert result["summary"]["not_mapped"] == 0
    assert result["summary"]["not_detected"] > 0
    assert result["summary"]["precision"] is None
    assert "provisional" in markdown(result)


def test_runtime_signatures_cover_observed_error_upload_and_html_header() -> None:
    for case_id, rule_id, path in (
        ("C06", "workflow.stored_comment.2", "/comments"),
        ("C10", "workflow.guessed_session.1", "/session/whoami"),
        ("C12", "workflow.error_detail.1", "/errors/query"),
        ("C13", "workflow.login_lockout.4", "/auth/login"),
        ("C15", "workflow.upload_disposition.2", "/uploads/{{upload_id}}"),
        ("C17", "workflow.unsigned_refresh.1", "/auth/refresh"),
        ("C28", "verdict.yaml.hardcoded-application-secret", "compose.yaml"),
        ("C29", "workflow.worker_identity.3", "/admin/jobs"),
        ("N05", "workflow.stale_role.3", "/admin/token-report"),
        ("N07", "web.missing-content-security-policy", "/view"),
    ):
        source = {"rule_id": rule_id, "primary_location": {"path": path}}
        if rule_id.startswith("workflow."):
            source["runtime_evidence"] = {
                "status": 200,
                "expected_statuses": [200],
                "assertion_results": [True, False],
            }
        assert _matches(case_id, source)


def test_one_positive_and_one_rejected_exact_signal_is_detected_but_flagged() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    sources = [
        {
            "rule_id": "workflow.owner_assignment.2",
            "primary_location": {"path": "/orders"},
            "runtime_evidence": {
                "status": 200,
                "expected_statuses": [400, 403],
                "assertion_results": [False],
            },
        },
        {
            "rule_id": "workflow.negative_price.1",
            "primary_location": {"path": "/orders"},
            "runtime_evidence": {
                "status": 200,
                "expected_statuses": [400, 422],
                "assertion_results": [False],
            },
        },
    ]
    merged = {
        "status": "completed",
        "findings": [
            {"merged_finding_id": "positive", "source_findings": [sources[0]]},
            {"merged_finding_id": "rejected", "source_findings": [sources[1]]},
        ],
    }
    triage = {
        "groups": [
            {
                "group_id": "positive",
                "scanner_finding_ids": ["positive"],
                "candidate_ids": [],
            },
            {
                "group_id": "rejected",
                "scanner_finding_ids": ["rejected"],
                "candidate_ids": [],
            },
        ]
    }
    review = {
        "status": "completed",
        "reviews": [
            {
                "candidate_id": "positive",
                "source_ids": ["positive"],
                "verdict": "confirmed_vulnerability",
            },
            {
                "candidate_id": "rejected",
                "source_ids": ["rejected"],
                "verdict": "false_positive",
            },
        ],
    }
    result = evaluate(
        truth, {"project": "targets/verdict-comprehensive-lab"}, merged, triage, review
    )
    assert (
        next(row for row in result["cases"] if row["id"] == "C18")["status"]
        == "detected_mixed"
    )
    assert result["summary"]["detected_mixed"] == 1
    assert result["summary"]["detected"] == 1

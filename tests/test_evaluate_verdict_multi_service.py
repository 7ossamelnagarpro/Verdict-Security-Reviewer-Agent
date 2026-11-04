"""Held-out evaluator tests; no scanner or target code is executed."""

from __future__ import annotations

import copy
import json

import pytest

from scripts import evaluate_verdict_multi_service as audit


def fixture_inputs():
    truth = audit.read_object(audit.TRUTH)
    scan = {"project": r"C:\work\targets\verdict-multi-service-lab"}
    source = {
        "rule_id": "workflow.negative_price.1",
        "primary_location": {"path": "/orders"},
        "runtime_evidence": {
            "workflow_id": "negative_price",
            "method": "POST",
            "status": 200,
            "expected_statuses": [400, 422],
            "assertion_results": [False],
        },
    }
    merged = {
        "status": "complete",
        "findings": [
            {"merged_finding_id": "merged-price", "source_findings": [source]}
        ],
    }
    ai = {"candidates": []}
    triage = {
        "groups": [
            {
                "group_id": "merged-price",
                "scanner_finding_ids": ["merged-price"],
                "candidate_ids": [],
            }
        ]
    }
    review = {
        "status": "completed",
        "reviews": [
            {
                "candidate_id": "merged-price",
                "source_ids": ["merged-price"],
                "verdict": "confirmed_vulnerability",
                "evidence": ["Observed rejected-status mismatch"],
            }
        ],
    }
    return truth, scan, merged, ai, triage, review


def result_row(result, case_id):
    return next(row for row in result["scenarios"] if row["id"] == case_id)


def test_exact_runtime_evidence_counts_only_its_own_case():
    result = audit.evaluate(*fixture_inputs())
    assert result_row(result, "vmsl-business-001")["status"] == "detected"
    assert result_row(result, "vmsl-authz-001")["status"] == "not_detected"
    assert result["summary"]["confirmed_ground_truth"] == 16
    assert result["summary"]["candidate_only"] == 2
    assert result["summary"]["positive_case_recall"] == 1 / 16


def test_false_positive_review_does_not_override_runtime_conflict():
    inputs = fixture_inputs()
    inputs[-1]["reviews"][0]["verdict"] = "false_positive"
    result = audit.evaluate(*inputs)
    assert result_row(result, "vmsl-business-001")["status"] == "needs_review"
    assert result["summary"]["detected"] == 0


@pytest.mark.parametrize(
    "change",
    [
        lambda source: source["runtime_evidence"].update(status=422),
        lambda source: source["runtime_evidence"].update(workflow_id="other"),
        lambda source: source["primary_location"].update(path="/elsewhere"),
        lambda source: source["runtime_evidence"].update(assertion_results=[True]),
    ],
)
def test_runtime_match_requires_full_violation_facts(change):
    inputs = fixture_inputs()
    change(inputs[2]["findings"][0]["source_findings"][0])
    assert (
        result_row(audit.evaluate(*inputs), "vmsl-business-001")["status"]
        == "not_detected"
    )


def test_rejects_mixed_scan_and_review_or_wrong_target():
    inputs = fixture_inputs()
    inputs[4]["groups"][0]["scanner_finding_ids"] = ["other"]
    with pytest.raises(ValueError, match="absent"):
        audit.evaluate(*inputs)
    inputs = fixture_inputs()
    inputs[1]["project"] = r"C:\work\targets\other-app"
    with pytest.raises(ValueError, match="not for"):
        audit.evaluate(*inputs)


def test_candidate_truth_never_enters_recall_and_html_escapes():
    inputs = list(fixture_inputs())
    inputs[0] = copy.deepcopy(inputs[0])
    inputs[0]["scenarios"][0]["category"] = "<script>alert(1)</script>"
    result = audit.evaluate(*inputs)
    assert result_row(result, "vmsl-auth-002")["status"] == "needs_review"
    html = audit.html_report(result)
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert len(json.loads(json.dumps(result))["scenarios"]) == 18

from __future__ import annotations

import json

from scripts.evaluate_verdict_comprehensive import TRUTH, _matches, evaluate, html_report, markdown


def test_runtime_assertion_mismatch_counts_even_with_expected_http_status() -> None:
    source = {"rule_id": "workflow.excessive_data.1", "primary_location": {"path": "/me"},
              "runtime_evidence": {"status": 200, "expected_statuses": [200],
                                   "assertion_results": [False]}}
    assert _matches("C24", source)
    assert not _matches("C01", source)


def test_known_case_with_false_positive_verdict_needs_review() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    finding = {"merged_finding_id": "merged-one", "source_findings": [{
        "rule_id": "workflow.excessive_data.1", "primary_location": {"path": "/me"},
        "runtime_evidence": {"status": 200, "expected_statuses": [200], "assertion_results": [False]}}]}
    result = evaluate(truth, {"project": "targets/verdict-comprehensive-lab"},
        {"status": "completed", "findings": [finding]},
        {"groups": [{"group_id": "merged-one", "scanner_finding_ids": ["merged-one"], "candidate_ids": []}]},
        {"status": "completed", "reviews": [{"candidate_id": "merged-one", "source_ids": ["merged-one"],
                                               "verdict": "false_positive"}]})
    assert next(item for item in result["cases"] if item["id"] == "C24")["status"] == "needs_review"
    assert result["summary"]["known_positive_cases"] == 35
    assert len(result["cases"]) == 63
    assert result["summary"]["precision"] is None
    assert result["summary"]["f1"] is None
    assert "Safe controls — specificity not assessed" in markdown(result)
    assert "S01" in markdown(result)
    assert "All 63 benchmark cases" in html_report(result)
    assert "S01" in html_report(result)


def _workflow_source(evidence):
    return {"rule_id": "workflow.order_owner.3", "primary_location": {"path": "/orders/{{order_id}}"}, "runtime_evidence": evidence}


def test_workflow_violation_still_counts_when_normalization_kept_only_the_http_status():
    # Runs saved before the normalizer kept assertion details hold just {status, values_redacted}.
    assert _matches("C01", _workflow_source({"status": 200, "values_redacted": True}))


def test_workflow_signal_is_rejected_when_the_recorded_assertion_passed_or_status_is_missing():
    assert not _matches("C01", _workflow_source({"status": 200, "expected_statuses": [200], "assertion_results": [True]}))
    assert not _matches("C01", _workflow_source({"values_redacted": True}))
    assert not _matches("C01", _workflow_source(None))


def test_normalizer_keeps_the_workflow_assertion_facts_the_audit_needs():
    from security_reviewer_v2.normalization.runtime_evidence import bounded_runtime_evidence
    kept = bounded_runtime_evidence({"workflow_id": "order_owner", "step": 3, "method": "GET", "status": 200,
                                     "expected_statuses": [403], "assertion_results": [False], "token": "secret"})
    assert kept == {"assertion_results": [False], "expected_statuses": [403], "method": "GET", "status": 200,
                    "step": 3, "workflow_id": "order_owner"}

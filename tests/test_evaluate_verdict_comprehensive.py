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

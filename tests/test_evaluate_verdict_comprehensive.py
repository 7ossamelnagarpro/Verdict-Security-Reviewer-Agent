from __future__ import annotations

import json

from scripts.evaluate_verdict_comprehensive import TRUTH, SIGNATURES, _matches, _normalize_path_template, evaluate, html_report, markdown


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


def test_penetration_agent_confirmation_counts_as_detected_with_no_scanner_signature() -> None:
    """C01's path is /orders/{{order_id}}. If the Penetration Agent alone reaches exploitation_confirmed
    on the matching concrete endpoint, that case must count as detected — on its own, auditable origin —
    even with zero scanner/workflow findings at all."""
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rule_id, known_path, _lines = SIGNATURES["C01"][0]
    assert _normalize_path_template(known_path) == "/orders/{}"
    penetration_test = {"status": "completed", "results": [{
        "candidate_id": "ai-xyz", "outcome": "exploitation_confirmed",
        "attempts": [{"target_endpoint": "/orders/5"}],
    }]}
    result = evaluate(truth, {"project": "targets/verdict-comprehensive-lab"},
        {"status": "completed", "findings": []},
        {"groups": []}, {"status": "completed", "reviews": []},
        penetration_test=penetration_test)
    case = next(item for item in result["cases"] if item["id"] == "C01")
    assert case["status"] == "detected"
    assert case["origins"] == ["penetration_agent"]
    assert result["summary"]["detected_via_penetration_agent"] == 1


def test_penetration_agent_confirmation_on_a_different_endpoint_does_not_count() -> None:
    """The match is on the exact endpoint, not "the Penetration Agent found something, somewhere"."""
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    penetration_test = {"status": "completed", "results": [{
        "candidate_id": "ai-xyz", "outcome": "exploitation_confirmed",
        "attempts": [{"target_endpoint": "/completely/unrelated/path"}],
    }]}
    result = evaluate(truth, {"project": "targets/verdict-comprehensive-lab"},
        {"status": "completed", "findings": []},
        {"groups": []}, {"status": "completed", "reviews": []},
        penetration_test=penetration_test)
    case = next(item for item in result["cases"] if item["id"] == "C01")
    assert case["status"] == "not_detected"
    assert result["summary"]["detected_via_penetration_agent"] == 0


def test_a_not_reproduced_penetration_outcome_never_counts_as_detected() -> None:
    """Only exploitation_confirmed counts — not_reproduced/inconclusive/blocked/cannot_test never do."""
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    penetration_test = {"status": "completed", "results": [{
        "candidate_id": "ai-xyz", "outcome": "not_reproduced",
        "attempts": [{"target_endpoint": "/orders/5"}],
    }]}
    result = evaluate(truth, {"project": "targets/verdict-comprehensive-lab"},
        {"status": "completed", "findings": []},
        {"groups": []}, {"status": "completed", "reviews": []},
        penetration_test=penetration_test)
    case = next(item for item in result["cases"] if item["id"] == "C01")
    assert case["status"] == "not_detected"


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


def _penetration_only_result() -> dict:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    penetration_test = {"status": "completed", "results": [{
        "candidate_id": "ai-xyz", "outcome": "exploitation_confirmed", "attempts": [{"target_endpoint": "/orders/5"}]}]}
    return evaluate(truth, {"project": "targets/verdict-comprehensive-lab",
                            "status": "partial", "security_review": {"status": "partial"}},   # the pre-review summary is stale
                    {"status": "completed", "findings": []}, {"groups": []}, {"status": "completed", "reviews": []},
                    penetration_test=penetration_test)


def test_penetration_signal_is_described_in_words_not_as_group_none() -> None:
    result = _penetration_only_result()
    for text in (html_report(result), markdown(result)):
        assert "group None" not in text and "`None`" not in text
        assert "Penetration Agent reproduced the issue at /orders/5" in text
        assert "no scanner rule or review group" in text


def test_review_status_comes_from_the_review_that_was_scored_not_the_pre_review_summary() -> None:
    provenance = _penetration_only_result()["scan_provenance"]
    assert provenance["security_review"]["status"] == "completed"       # not the stale "partial"
    assert provenance["security_review"]["reviewed_groups"] == provenance["security_review"]["expected_groups"] == 0
    assert "completed · 0/0 groups" in html_report(_penetration_only_result())


def test_headline_says_how_many_detections_rest_only_on_the_penetration_agent() -> None:
    result = _penetration_only_result()
    assert "1 rest only on the Penetration Agent" in html_report(result)
    assert "detected_via_penetration_agent" not in html_report(result)  # no raw JSON key in user-facing text

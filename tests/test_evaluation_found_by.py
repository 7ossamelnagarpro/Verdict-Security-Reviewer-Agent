"""Comprehensive-lab evaluation: every known-positive case says whether static scanners, dynamic probes or AI discovery produced evidence."""

from __future__ import annotations

import pytest

from scripts.evaluate_verdict_comprehensive import found_by_text, html_report, markdown
from tests.test_evaluation_precision import LAB, _evaluate

STATIC_SQL = {"rule_id": "py/sql-injection", "primary_location": {"path": "api/extra.py", "start_line": 119}, "categories": ["sast"],
              "scanner": {"scanner_id": "codeql"}}
DYNAMIC_ME = {"rule_id": "workflow.excessive_data.1", "primary_location": {"path": "/me"}, "categories": ["dast", "runtime"],
              "scanner": {"scanner_id": "web-runtime"},
              "runtime_evidence": {"status": 200, "expected_statuses": [200], "assertion_results": [False]}}


def _group(group_id: str, finding: str | None, candidates: tuple[str, ...] = ()):
    return {"group_id": group_id, "scanner_finding_ids": [finding] if finding else [], "candidate_ids": list(candidates)}


def _review(group_id: str, sources: list[str], verdict: str = "confirmed_vulnerability"):
    return {"candidate_id": group_id, "source_ids": sources, "verdict": verdict, "severity": "high", "title": group_id}


def _run(discovery=None, source_root=None):
    merged = [{"merged_finding_id": "m-sql", "source_findings": [STATIC_SQL]}, {"merged_finding_id": "m-me", "source_findings": [DYNAMIC_ME]}]
    groups = [_group("m-sql", "m-sql", ("ai-1",)), _group("m-me", "m-me")]
    reviews = [_review("m-sql", ["m-sql", "ai-1"]), _review("m-me", ["m-me"])]
    return _evaluate(source_root, merged, groups, reviews, discovery)


def test_each_detected_case_names_its_source_and_ai_candidates_do_not_change_status() -> None:
    result = _run()
    rows = {row["id"]: row for row in result["cases"]}
    assert rows["C03"]["status"] == "detected" and rows["C03"]["found_by"] == ["static", "ai_discovery"]
    assert "grouped with the detecting evidence" in rows["C03"]["ai_discovery_basis"]
    assert rows["C24"]["status"] == "detected" and rows["C24"]["found_by"] == ["dynamic"] and rows["C24"]["ai_discovery_basis"] is None
    assert found_by_text(rows["C03"]) == "Static scanners + AI discovery" and found_by_text(rows["C24"]) == "Dynamic (runtime)"
    assert result["summary"]["detected"] == 2                       # the AI candidate in C03's group was not credited on its own


def test_summary_counts_sources_per_detected_case() -> None:
    found = _run()["summary"]["found_by"]
    assert found["detected_cases"] == 2 and found["static"] == 1 and found["dynamic"] == 1 and found["ai_discovery"] == 1
    assert found["static_only"] == 0 and found["dynamic_only"] == 1 and found["static_and_dynamic"] == 0
    assert found["ai_discovery_assessed_on_endpoints"] is False


def test_cases_without_evidence_say_none_and_other_ground_truths_are_dashes() -> None:
    result = _run()
    rows = {row["id"]: row for row in result["cases"]}
    assert rows["C01"]["status"] == "not_detected" and rows["C01"]["found_by"] == [] and found_by_text(rows["C01"]) == "none"
    safe = next(row for row in result["cases"] if row["ground_truth"] == "safe_control")
    assert "found_by" not in safe and found_by_text(safe) == "—"
    assert all("ai_in_detecting_group" not in row for row in result["cases"])        # internal marker is not left in the output


def test_reports_show_the_found_by_column_line_and_section() -> None:
    result = _run()
    page, text = html_report(result), markdown(result)
    assert "Found by" in page and "Static scanners + AI discovery" in page and "Detected cases by source" in page
    assert "Of 2 detected cases: 1 have static-scanner evidence, 1 have dynamic" in page
    assert "- Found by: Static scanners + AI discovery — an AI candidate was grouped" in text
    assert "- Found by: Dynamic (runtime)" in text and "## Detected cases by source" in text


@pytest.mark.skipif(not LAB.is_dir(), reason="lab source not available")
def test_ai_candidate_on_an_undetected_endpoint_is_listed_but_not_counted() -> None:
    discovery = {"candidates": [{"candidate_id": "ai-9", "title": "Stored XSS?", "path": "api/extra.py", "start_line": 161,
                                 "sensitive_operation": {"path": "api/extra.py", "line": 165}}]}
    merged = [{"merged_finding_id": "m-me", "source_findings": [DYNAMIC_ME]}]
    groups = [_group("m-me", "m-me"), _group("ai-g", None, ("ai-9",))]
    reviews = [_review("m-me", ["m-me"]), _review("ai-g", ["ai-9"], "likely_vulnerability")]
    result = _evaluate(LAB, merged, groups, reviews, discovery)
    row = next(item for item in result["cases"] if item["id"] == "C06")
    assert row["status"] == "not_detected" and row["found_by"] == ["ai_discovery"]
    assert found_by_text(row) == "AI discovery (not counted)"
    found = result["summary"]["found_by"]
    assert "C06" in found["ai_discovery_only_not_detected"] and found["ai_discovery_assessed_on_endpoints"] is True
    assert result["summary"]["detected"] == 1

"""The reports must say what the penetration agent did and whether it proved each AI Discovery finding."""

from __future__ import annotations

from security_reviewer_v2.reporting.final import render_final_report
from security_reviewer_v2.reporting.html_report import render_html
from security_reviewer_v2.reporting.penetration_summary import build_overview, rows_by_group
from security_reviewer_v2.reporting.view import build_view


def _attempt(candidate_id: str, status: int, expected: int = 200) -> dict:
    return {"candidate_id": candidate_id, "hypothesis": "h", "entry_point": "get_order", "target_endpoint": "/orders/5",
            "attack_plan": "Cross-account read", "selected_tools": ["runtime_workflows"], "attempt_number": 1,
            "test_strategy": "authorization_matrix",
            "request_evidence": [{"step": 1, "actor": "user_b", "method": "GET", "path": "/orders/5"}],
            "response_evidence": [{"step": 1, "http_status": status, "expected_status": [expected]}],
            "observation": f"HTTP {status}", "agent_reasoning_summary": "r", "next_action": "stop",
            "stop_reason": "exploitation_confirmed" if status == expected else "no_further_strategy"}


DISCOVERY = {"status": "completed", "usage": {}, "candidates": [
    {"candidate_id": "c1", "title": "IDOR on get_order", "severity": "high", "path": "api/app.py", "start_line": 10, "end_line": 20},
    {"candidate_id": "c2", "title": "Missing role check", "severity": "medium", "path": "api/admin.py", "start_line": 5, "end_line": 5},
    {"candidate_id": "c3", "title": "Weak hash", "severity": "low", "path": "api/h.py", "start_line": 1, "end_line": 2},
    {"candidate_id": "c4", "title": "Open redirect", "severity": "low", "path": "api/r.py", "start_line": 3, "end_line": 4}]}
VERIFICATION = {"records": [{"candidate_id": "c1", "disposition": "confirmed"}, {"candidate_id": "c2", "disposition": "confirmed"},
                            {"candidate_id": "c3", "disposition": "rejected"}, {"candidate_id": "c4", "disposition": "confirmed"}]}
PEN = {"status": "completed", "warnings": [], "usage": {"hypotheses_tested": 2, "total_attempts": 2, "total_requests": 2},
       "results": [
           {"candidate_id": "c1", "outcome": "exploitation_confirmed", "summary": "reproduced", "attempts": [_attempt("c1", 200)],
            "considered_but_not_executed": []},
           {"candidate_id": "c2", "outcome": "not_reproduced", "summary": "denied", "attempts": [_attempt("c2", 403)],
            "considered_but_not_executed": [{"strategy": "idor", "reason": "needs two accounts"}]}]}
TRIAGE = {"groups": [{"group_id": "merged-xyz", "candidate_ids": ["c1"]}]}
REVIEW = {"status": "completed", "reviews": [
    {"candidate_id": "merged-xyz", "title": "IDOR on get_order", "verdict": "likely_vulnerability", "severity": "high",
     "confidence": "medium", "explanation": "x", "impact": "x", "remediation": "x"}]}
POLICY = {"status": "failed", "blocking": True,
          "decisions": [{"candidate_id": "merged-xyz", "action": "block", "reason": "x", "rule_id": "r"}]}


def test_overview_answers_proven_or_not_for_every_source_confirmed_finding():
    overview = build_overview(PEN, DISCOVERY, VERIFICATION)
    by_id = {row.candidate_id: row for row in overview.rows}
    assert by_id["c1"].proven and by_id["c1"].label == "Proven" and by_id["c1"].title == "IDOR on get_order"
    assert by_id["c2"].outcome == "not_reproduced" and not by_id["c2"].proven
    assert by_id["c4"].outcome == "not_tested"                       # confirmed by Verification, never reached the agent
    assert "c3" not in by_id and overview.not_sent == 1               # rejected by Verification: counted, not listed
    assert [row.candidate_id for row in overview.rows][0] == "c1"      # proven findings come first
    assert by_id["c1"].attempts[0].steps == ("GET /orders/5 as user_b -> HTTP 200 (expected 200)",)
    assert by_id["c2"].not_executed == ("idor: needs two accounts",)
    assert rows_by_group(overview.rows, TRIAGE)["merged-xyz"].candidate_id == "c1"


def test_overview_is_absent_when_the_agent_was_not_part_of_the_run():
    assert build_overview(None, DISCOVERY, VERIFICATION) is None


def test_markdown_report_has_the_proven_or_not_table_and_the_attempt_log():
    md = render_final_report(project="demo", review=REVIEW, policy=POLICY, triage=TRIAGE, discovery=DISCOVERY,
                             verification=VERIFICATION, penetration_test=PEN)
    assert "Did the penetration test prove each AI Discovery finding?" in md
    assert "IDOR on get_order" in md and "**Proven**" in md and "**Not reproduced**" in md and "**Not tested**" in md
    assert "What the penetration agent did, attempt by attempt" in md
    assert "GET /orders/5" in md                                       # the per-attempt reproduction steps are still there
    assert "not proof that the flaw does not exist" in md.lower().replace("\n", " ")


def test_html_report_lists_the_penetration_work_and_marks_the_finding():
    html = render_html(build_view(project="demo", review=REVIEW, policy=POLICY, triage=TRIAGE, discovery=DISCOVERY,
                                  verification=VERIFICATION, penetration_test=PEN))
    assert 'id="pentest"' in html and 'href="#pentest"' in html
    assert "Did the penetration agent prove each AI Discovery finding?" in html
    assert "Missing role check" in html and "Open redirect" in html
    assert "Attempt 1" in html and "GET /orders/5 as user_b -&gt; HTTP 200" in html
    assert "Pen-test: Proven" in html                                  # chip on the reviewed finding that group c1 maps to


def test_html_report_without_the_agent_has_no_penetration_section():
    html = render_html(build_view(project="demo", review=REVIEW, policy=POLICY))
    assert 'id="pentest"' not in html


def test_html_escapes_untrusted_titles():
    discovery = {"candidates": [{"candidate_id": "c1", "title": "<script>alert(1)</script>", "severity": "high", "path": "a.py", "start_line": 1, "end_line": 1}]}
    html = render_html(build_view(project="demo", review={"status": "completed", "reviews": []}, policy={"status": "passed", "decisions": []},
                                  discovery=discovery, verification={"records": [{"candidate_id": "c1", "disposition": "confirmed"}]},
                                  penetration_test={"status": "completed", "usage": {}, "warnings": [], "results": [
                                      {"candidate_id": "c1", "outcome": "blocked", "summary": "<b>x</b>", "attempts": [], "considered_but_not_executed": []}]}))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html

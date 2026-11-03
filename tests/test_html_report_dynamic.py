"""HTML report: static/dynamic filter data, DAST test trace in the evidence, scan log, print view."""

from __future__ import annotations

import re

from security_reviewer_v2.reporting.html_report import render_html
from security_reviewer_v2.reporting.view import PROBE_DEFINITIONS, build_view


def _src(fid, scanner, rule, kind, path, line=None, cats=(), ev=None, sev="high"):
    return {"finding_id": fid, "scanner": {"scanner_id": scanner, "scanner_name": scanner}, "rule_id": rule, "title": rule,
            "severity": sev, "confidence": "high", "categories": list(cats), "finding_kind": kind,
            "primary_location": {"path": path, "start_line": line, "end_line": line}, "runtime_evidence": ev}


def _payload(rule="web.reflected-xss", hostile=False):
    merged = {"summary": {}, "findings": [
        {"merged_finding_id": "st", "canonical_finding": {"title": "SQL Injection"}, "primary_location": {"path": "app.py", "start_line": 42},
         "cwes": ["CWE-89"], "scanners": ["semgrep-ce"], "rule_ids": ["python.sqli"], "categories": ["sast"],
         "source_findings": [_src("s1", "semgrep-ce", "python.sqli", "sast", "app.py", 42)]},
        {"merged_finding_id": "dy", "canonical_finding": {"title": "Reflected XSS"}, "primary_location": {"path": "/search"},
         "cwes": [], "scanners": ["web-runtime"], "rule_ids": [rule], "categories": ["dast"],
         "source_findings": [_src("d1", "web-runtime", rule, "dast", "/search", cats=("dast",), ev={"status": 200, "payload_reflected": True})]},
        {"merged_finding_id": "wf", "canonical_finding": {"title": "Double refund"}, "primary_location": {"path": "/api/refund"},
         "cwes": [], "scanners": ["runtime-workflow"], "rule_ids": ["workflow.refund.2"], "categories": ["dast"],
         "source_findings": [_src("d2", "runtime-workflow", "workflow.refund.2", "dast", "/api/refund", cats=("dast",),
                                  ev={"workflow_id": "refund", "step": 2, "status": 200, "assertion_results": [False]})]}]}
    triage = {"groups": [{"group_id": g, "scanner_finding_ids": [g]} for g in ("st", "dy", "wf")], "records": []}
    reviews = [{"candidate_id": g, "title": t, "severity": "high", "verdict": "confirmed_vulnerability", "confidence": "high",
                "explanation": "e", "impact": "i", "remediation": "r", "evidence": [], "limitations": [], "source_ids": [g]}
               for g, t in (("st", "SQL Injection"), ("dy", "Reflected XSS"), ("wf", "Double refund"))]
    policy = {"status": "failed", "blocking": True, "decisions": [
        {"candidate_id": g, "action": "block", "severity": "high", "rule_id": "RG-001", "reason": "x", "evidence": []} for g in ("st", "dy", "wf")]}
    runtime = {"source": "web-runtime", "results": [
        {"rule_id": rule, "path": "/search", "vulnerable": True, "severity": "high", "confidence": "high",
         "evidence": {"status": 200, "payload_reflected": True, "note": "<img src=x onerror=alert(1)>" if hostile else "ok"}},
        {"rule_id": "web.verbose-error", "path": "/search", "vulnerable": False, "severity": "medium", "confidence": "high",
         "evidence": {"status": 200, "error_marker_present": False}}],
        "workflow_evidence": {"workflows": [{"id": "refund", "title": "Refund", "steps": [
            {"step": 1, "actor": "alice", "method": "POST", "path": "/api/refund", "status": "passed", "http_status": 200,
             "expected_status": [200], "assertion_results": [True]},
            {"step": 2, "actor": "alice", "method": "POST", "path": "/api/refund", "status": "violation", "http_status": 200,
             "expected_status": [409], "assertion_results": [False]}]}]}}
    return dict(project="demo", review={"status": "completed", "reviews": reviews}, policy=policy, triage=triage, merged=merged,
                runtime_evidence=runtime)


def _view(**kw):
    return build_view(**_payload(**kw))


def test_findings_are_classified_by_how_they_were_found():
    origins = {f.title: f.origins for f in _view().findings}
    assert origins == {"SQL Injection": ("static",), "Reflected XSS": ("dynamic",), "Double refund": ("dynamic",)}


def test_a_finding_confirmed_by_static_and_dynamic_testing_has_both_origins():
    payload = _payload()
    payload["merged"]["findings"][1]["source_findings"].append(_src("s9", "semgrep-ce", "flask.reflect", "sast", "app.py", 7))
    assert {f.title: f.origins for f in build_view(**payload).findings}["Reflected XSS"] == ("dynamic", "static")


def test_rows_and_print_blocks_carry_origin_for_the_filter():
    page = render_html(_view())
    assert 'data-k="origin" data-v="static"' in page and 'data-k="origin" data-v="dynamic"' in page
    assert len(re.findall(r'<tr data-f [^>]*data-origin="dynamic"', page)) == 2
    assert len(re.findall(r'<tr data-f [^>]*data-origin="static"', page)) == 1
    assert page.count('<article class="pd" data-f') == 3          # printable detail for every finding


def test_dynamic_evidence_shows_the_steps_followed_and_the_recorded_output():
    finding = next(f for f in _view().findings if f.title == "Reflected XSS")
    trace = finding.dynamic[0]
    assert trace.steps_source == "definition" and trace.steps == PROBE_DEFINITIONS["web.reflected-xss"]
    assert dict(trace.facts) == {"payload_reflected": "yes", "status": "200", "note": "ok"}
    assert dict(trace.record)["vulnerable"] == "yes"
    page = render_html(_view())
    assert "Dynamic test trace" in page and "GET /search?q=&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_workflow_findings_show_the_recorded_steps_and_never_invented_ones():
    trace = next(f for f in _view().findings if f.title == "Double refund").dynamic[0]
    assert trace.steps_source == "workflow" and len(trace.steps) == 2
    assert "violation - HTTP 200, expected 409" in trace.steps[1][1] and "<- reported step" in trace.steps[1][1]
    assert dict(trace.facts)["assertion_results"] == "fail"


def test_unknown_dynamic_rules_get_recorded_output_only():
    payload = _payload(rule="zap.10021")
    trace = next(f for f in build_view(**payload).findings if f.title == "Reflected XSS").dynamic[0]
    assert trace.steps_source == "none" and trace.steps == () and dict(trace.facts)["status"] == "200"


def test_scan_log_lists_every_probe_including_clean_ones():
    view = _view()
    assert [(p.rule_id, p.outcome) for p in view.probes] == [("web.reflected-xss", "finding"), ("web.verbose-error", "not observed")]
    page = render_html(view)
    assert 'id="dynamic"' in page and "not observed" in page and "Business workflows" in page


def test_hostile_runtime_output_is_escaped():
    page = render_html(_view(hostile=True))
    assert "<img src=x onerror" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "default-src 'none'" in page and "http://" not in re.sub(r"http://www\.w3\.org", "", page)


def test_reports_without_dynamic_data_are_unchanged_in_shape():
    payload = _payload()
    payload.pop("runtime_evidence")
    for item in payload["merged"]["findings"][1:]:
        item["source_findings"] = [dict(x, finding_kind="sast", categories=["sast"]) for x in item["source_findings"]]
        item["categories"] = ["sast"]
    view = build_view(**payload)
    assert all(f.dynamic == () and f.origins == ("static",) for f in view.findings) and view.probes == ()
    assert 'id="dynamic"' not in render_html(view)


# ----------------------------------------------------------------------------- redesign: structure and states
def test_sidebar_has_labelled_sections_with_counts_and_a_decision_stamp():
    page = render_html(_view())
    for label in ("Summary", "Fix first", "Findings", "Coverage &amp; trust", "Dynamic scan log", "Appendix", "Known gaps"):
        assert f"<span>{label}</span>" in page, label
    assert 'class="stamp blocked"' in page and 'id="print"' in page and 'class="skip"' in page


def test_severity_strip_counts_match_the_findings_and_filter_by_severity():
    page = render_html(_view())
    assert 'class="strip" role="img" aria-label="3 high"' in page
    assert 'data-k="sev" data-v="high" data-go="1"' in page and "High <b>3</b>" in page


def test_drawer_has_previous_next_navigation_and_a_copyable_location():
    page = render_html(_view())
    pane = re.search(r'<div class="pane" id="f2".*?</div></div></div>', page, re.S).group(0)
    assert 'data-open="f1"' in pane and 'data-open="f3"' in pane and 'data-copy="app.py:42"' in pane
    first = re.search(r'<div class="pane" id="f1".*?<div class="dnav">(.*?)</div>', page, re.S).group(1)
    assert "Previous finding" not in first and "Next finding" in first


def test_empty_and_no_match_states_explain_what_to_do():
    payload = _payload()
    payload["review"] = {"status": "completed", "reviews": []}
    payload["policy"] = {"status": "passed", "blocking": False, "decisions": []}
    page = render_html(build_view(**payload))
    assert "No reviewed findings" in page and "does not show the project is safe" in page
    page = render_html(_view())
    assert 'id="none"' in page and "No findings match these filters" in page


def test_without_dynamic_testing_the_no_match_state_says_why_dynamic_is_empty():
    payload = _payload()
    payload.pop("runtime_evidence")
    for item in payload["merged"]["findings"]:
        item["categories"] = ["sast"]
        item["source_findings"] = [dict(x, finding_kind="sast", categories=["sast"]) for x in item["source_findings"]]
    assert "Dynamic testing did not run in this scan" in render_html(build_view(**payload))


def test_print_layout_is_defined_and_keeps_every_finding_detail():
    page = render_html(_view())
    assert "@media print" in page and "@page{margin:14mm}" in page and "beforeprint" in page
    assert page.count('<article class="pd"') == 3

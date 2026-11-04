"""Summary charts, the Found-by tree, the pipeline side panel, the origin/tool filters and the dynamic test trace."""

from __future__ import annotations

import re

from security_reviewer_v2.reporting.html_report import render_html
from security_reviewer_v2.reporting.view import build_view, friendly_name


def _source(fid, scanner, rule, title, path, *, dast, line=None, snippet=None, evidence=None):
    return {"finding_id": fid, "finding_kind": "dast" if dast else "sast", "scanner": {"scanner_id": scanner, "scanner_name": scanner},
            "rule_id": rule, "title": title, "message": f"{title} observed", "severity": "high", "confidence": "high",
            "cwes": [], "categories": ["dast"] if dast else ["sast"],
            "primary_location": {"path": path, "start_line": line, "end_line": line, "snippet": snippet}, "runtime_evidence": evidence}


def _merged(mid, source):
    return {"merged_finding_id": mid, "canonical_finding": source, "source_findings": [source], "scanners": [source["scanner"]["scanner_id"]],
            "rule_ids": [source["rule_id"]], "severity": "high", "confidence": "high", "cwes": [], "categories": source["categories"],
            "primary_location": source["primary_location"]}


def _view(request: bool = True):
    sast = _source("s1", "semgrep-ce", "python.sqli", "SQL Injection", "app/db.py", dast=False, line=42, snippet="cursor.execute(q % name)")
    zap = _source("d1", "web-runtime", "zap.10038", "Missing CSP", "/home", dast=True, evidence={"status": 200})
    flow = _source("d2", "web-runtime", "workflow.admin_jobs.2", "Admin listing open", "/admin/jobs", dast=True,
                   evidence={"workflow_id": "admin_jobs", "step": 2, "method": "GET", "status": 200, "expected_statuses": [403, 404], "assertion_results": [False]})
    merged = {"findings": [_merged("m1", sast), _merged("m2", zap), _merged("m3", flow)]}
    gids = {"g1": ("m1", "SQL Injection"), "g2": ("m2", "Missing CSP"), "g3": ("m3", "Admin listing open"), "g4": (None, "AI only")}
    triage = {"groups": [{"group_id": g, "scanner_finding_ids": [m] if m else [], "candidate_ids": [] if m else ["c1"]} for g, (m, _) in gids.items()], "records": []}
    reviews = [{"candidate_id": g, "title": t, "severity": "high", "verdict": "confirmed_vulnerability", "confidence": "high", "explanation": "e", "impact": "i",
                "remediation": "Fix it.", "evidence": ["see `code`"], "source_ids": [m] if m else []} for g, (m, t) in gids.items()]
    policy = {"status": "failed", "blocking": True, "decisions": [{"candidate_id": g, "action": "block", "severity": "high", "rule_id": "RG-001", "reason": "r"} for g in gids]}
    wf = {"status": "completed", "coverage": {"executed": 2, "violations": 1}, "workflows": [{"id": "admin_jobs", "title": "Admin", "steps": [
        {"step": 1, "actor": "admin", "method": "GET", "path": "/admin/jobs", "status": "passed", "http_status": 200, "expected_status": [200], "assertion_results": [True]},
        {"step": 2, "actor": "user_a", "method": "GET", "path": "/admin/jobs", "status": "violation", "http_status": 200, "expected_status": [403, 404], "assertion_results": [False]}]}]}
    runtime = {"target": "http://127.0.0.1:1", "source": "generic-web-runtime", "workflow_evidence": wf, "zap": {"status": "completed", "engine": "zap-passive"},
               "results": [{"rule_id": "web.verbose-error", "title": "Verbose error", "path": "/search", "vulnerable": False, "evidence": {"status": 200}}]}
    discovery = {"status": "partial", "provider": "p", "model": "m", "usage": {"calls": 1}, "candidates": [{"candidate_id": "c1"}], "coverage_gaps": ["prompt shortened"]}
    return build_view(project="/home/me/targets/demo-lab", review={"status": "completed", "reviews": reviews, "provider": "p", "model": "m"}, policy=policy,
                      merged=merged, triage=triage, runtime_evidence=runtime, discovery=discovery)


def test_findings_get_origin_sets_and_the_found_by_tree_counts_them() -> None:
    view = _view()
    assert {f.group_id: f.origins for f in view.findings} == {"g1": ("static",), "g2": ("dynamic",), "g3": ("dynamic",), "g4": ("ai",)}
    tree = {n.key: n for n in view.found_by}
    assert (tree["static"].count, tree["dynamic"].count, tree["ai"].count) == (1, 2, 1)
    assert {c.key: c.count for c in tree["dynamic"].children} == {"web-probe": 0, "zap": 1, "workflow": 1}
    assert not tree["ai"].children


def test_summary_has_funnel_donut_tree_and_no_machine_path() -> None:
    page = render_html(_view())
    assert 'class="fun"' in page and 'aria-label="Reviewer verdict distribution"' in page and 'class="tn"' in page
    assert "Demo Lab" in page and "/home/me" not in page and friendly_name("/a/b/verdict-comprehensive-lab") == "Verdict Comprehensive Lab"
    assert 'data-k="tool" data-v="zap"' in page


def test_pipeline_side_panel_lists_agents_scanners_and_pipeline() -> None:
    page = render_html(_view())
    assert 'data-open="p-pipe"' in page and 'id="p-pipe"' in page
    pane = page[page.index('id="p-pipe"'):]
    assert "AI Discovery agent" in pane and "Partial" in pane and "Review agent" in pane and "Completed" in pane
    assert "issue groups reviewed" in pane and "blocking release" in pane


def test_rows_carry_origin_and_tool_tokens_for_the_filters() -> None:
    page = render_html(_view())
    assert len(re.findall(r'<tr data-f[^>]*data-origin="dynamic"', page)) == 2 and 'data-tool="zap"' in page and 'data-origin="ai"' in page


def test_workflow_finding_shows_the_executed_steps_and_output() -> None:
    page = render_html(_view())
    assert "Dynamic test trace" in page and "1. admin: GET /admin/jobs" in page and "&lt;- reported step" in page
    assert "<th>assertion_results</th><td>fail</td>" in page and "<th>expected_statuses</th><td>403, 404</td>" in page


def test_duplicate_blocks_were_removed_from_the_summary() -> None:
    page = render_html(_view())
    assert 'class="funnel"' not in page and "Deduplication." not in page and "Runtime evidence" not in page

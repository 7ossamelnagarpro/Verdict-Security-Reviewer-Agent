"""Final reports summarize scan evidence without duplicating the evaluation inventory."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.refresh_saved_report import refresh
from security_reviewer_v2.reporting.final import render_final_report, write_final_report


def _observation(
    identifier: str,
    title: str,
    scanner: str,
    path: str,
    *,
    dast: bool = False,
    line: int | None = None,
) -> dict:
    return {
        "merged_finding_id": identifier,
        "canonical_finding": {"title": title},
        "source_findings": [{"finding_id": f"source-{identifier}"}],
        "scanners": [scanner],
        "rule_ids": ["rule.example"],
        "severity": "high",
        "confidence": "medium",
        "categories": ["dast"] if dast else ["static"],
        "primary_location": {"path": path, "start_line": line},
    }


def test_report_preserves_observation_counts_without_inventory() -> None:
    merged = {
        "findings": [
            _observation("m-static", "SQL Injection", "semgrep-ce", "app.py", line=42),
            _observation(
                "m-dast",
                "Cross-user order access",
                "authorization-dast",
                "/orders/101",
                dast=True,
            ),
        ]
    }
    risk = {
        "findings": [
            {
                "merged_finding_id": "m-static",
                "rank": 1,
                "risk_score": 60,
                "priority_band": "medium",
                "review_disposition": "standard_report",
            },
            {
                "merged_finding_id": "m-dast",
                "rank": 2,
                "risk_score": 50,
                "priority_band": "medium",
                "review_disposition": "needs_verification",
            },
        ]
    }
    markdown = render_final_report(
        project="lab",
        review={"status": "not_run", "reviews": []},
        policy={"status": "incomplete", "decisions": []},
        merged=merged,
        risk=risk,
        execution={
            "tasks": [
                {"scanner_id": "semgrep-ce", "status": "completed"},
                {"scanner_id": "codeql-cli", "status": "adapter_unavailable"},
            ]
        },
        coverage_gaps=["CodeQL unavailable"],
    )
    assert "**2** scanner/DAST observation record(s)" in markdown
    assert "## Scanner and DAST Observations (Pre-Review)" not in markdown
    assert "SQL Injection" not in markdown and "Cross-user order access" not in markdown
    assert "source-m-static" not in markdown and "source-m-dast" not in markdown
    assert "codeql-cli" in markdown and "adapter_unavailable" in markdown
    assert "CodeQL unavailable" in markdown
    assert "No agent verdicts were produced" in markdown
    assert "## Security Review Agent Verdicts" in markdown


def test_report_keeps_agent_verdict_without_scanner_title() -> None:
    title = "<script>alert(1)</script> [click](https://example.test)"
    markdown = render_final_report(
        project="lab",
        review={
            "status": "completed",
            "reviews": [
                {
                    "title": "Reviewed issue",
                    "candidate_id": "g1",
                    "verdict": "likely_vulnerable",
                    "severity": "high",
                    "confidence": "high",
                }
            ],
        },
        policy={"status": "completed", "decisions": []},
        merged={
            "findings": [_observation("m1", title, "semgrep-ce", "app.py", line=7)]
        },
    )
    assert title not in markdown
    assert "## Scanner and DAST Observations" not in markdown
    assert "## Security Review Agent Verdicts" in markdown
    assert "Reviewed issue" in markdown


def test_report_marks_required_scanner_failure_incomplete() -> None:
    markdown = render_final_report(
        project="lab",
        review={"status": "completed", "reviews": []},
        policy={"status": "failed", "decisions": []},
        scanner_requirement={
            "requested": True,
            "required": ["semgrep-ce", "codeql-cli"],
            "satisfied": False,
            "failures": [
                "codeql-cli/task-codeql: no normalized scanner output was produced"
            ],
        },
    )
    assert "Required scanners: **incomplete**" in markdown
    assert "**This scan is incomplete.** One or more required scanners" in markdown
    assert "codeql-cli/task-codeql: no normalized scanner output" in markdown


def test_report_describes_completed_generic_dast_phases() -> None:
    markdown = render_final_report(
        project="lab",
        review={"status": "completed", "reviews": []},
        policy={"status": "failed", "decisions": []},
        runtime_evidence={
            "source": "generic-web-runtime",
            "target": "http://127.0.0.1:8090",
            "results": [{}],
            "zap": {"status": "completed", "engine": "zap-active", "alerts": 2},
            "workflow_evidence": {
                "status": "completed",
                "coverage": {"executed": 28, "violations": 12},
            },
        },
    )
    assert "Browser crawl: **not requested**" in markdown
    assert "ZAP: **completed**" in markdown
    assert "alerts: **2**" in markdown
    assert "Account and business workflows: **completed**" in markdown
    assert "executed: **28**" in markdown
    assert "contract violations: **12**" in markdown
    assert "No browser crawl, credentialed authorization workflow" not in markdown


def test_report_writes_standalone_html_next_to_markdown_and_escapes_evidence(
    tmp_path: Path,
) -> None:
    markdown_path = tmp_path / "security-review-report.md"
    malicious = '<script>alert("x")</script>'
    write_final_report(
        markdown_path,
        project="demo <app>",
        review={
            "status": "completed",
            "reviews": [
                {
                    "candidate_id": "g1",
                    "title": malicious,
                    "verdict": "confirmed_vulnerability",
                    "severity": "high",
                    "evidence": [malicious],
                    "source_ids": ["s1"],
                }
            ],
        },
        policy={
            "status": "failed",
            "blocking": True,
            "decisions": [{"candidate_id": "g1", "action": "block"}],
        },
        runtime_evidence={
            "source": "generic-web-runtime",
            "target": "http://127.0.0.1:8090",
            "results": [{}],
            "zap": {"status": "completed", "engine": "zap-active", "alerts": 2},
            "workflow_evidence": {
                "status": "completed",
                "coverage": {"executed": 28, "violations": 12},
            },
        },
        merged={
            "findings": [_observation("s1", malicious, "web-runtime", "/", dast=True)]
        },
    )
    html_path = markdown_path.with_suffix(".html")
    assert markdown_path.is_file() and html_path.is_file()
    content = html_path.read_text(encoding="utf-8")
    assert "- Evidence type: **DAST**" in markdown_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in content
    assert "<style>" in content and "<script>const cards=" in content
    assert "https://" not in content
    assert malicious not in content
    assert "&lt;script&gt;alert(&quot;" in content
    assert "Workflow rule violations</span><strong>12</strong>" in content
    assert "28 executed" not in content
    assert "confirmed vulnerability" in content
    assert "Security review findings" in content
    assert "How to read this report" not in content
    assert 'href="#guide"' not in content
    assert '<section id="guide"' not in content
    assert 'id="finding-1"' in content
    assert 'data-origin="dast"' in content
    assert '<section id="observations"' not in content
    assert 'href="#observations"' not in content


def test_executive_brief_separates_signals_verdicts_and_coverage() -> None:
    from security_reviewer_v2.reporting.html import render_html_report

    options = {
        "project": "demo",
        "review": {
            "status": "completed",
            "pending_ids": [],
            "reviews": [
                {
                    "candidate_id": "g1",
                    "title": "Cross-user order access",
                    "verdict": "confirmed_vulnerability",
                    "severity": "high",
                    "impact": "Another customer can read an order.",
                    "remediation": "Check ownership before returning the order.",
                    "source_ids": ["s1"],
                },
                {
                    "candidate_id": "g2",
                    "title": "Noise",
                    "verdict": "false_positive",
                    "severity": "medium",
                },
            ],
        },
        "policy": {
            "status": "completed",
            "blocking": True,
            "decisions": [
                {
                    "candidate_id": "g1",
                    "action": "block",
                    "reason": "High-severity access rule failed.",
                }
            ],
        },
        "merged": {
            "findings": [
                _observation("s1", "Order signal", "web-runtime", "/orders", dast=True),
                _observation("s2", "Rule signal", "semgrep-ce", "app.py"),
            ]
        },
        "triage": {"summary": {"input_ai_candidates": 1, "review_groups": 2}},
        "discovery": {
            "status": "partial",
            "usage": {"targets": 2, "planned_targets": 2},
        },
        "runtime_evidence": {
            "status": "completed",
            "results": [{}, {}],
            "zap": {"status": "completed", "alerts": 3},
            "workflow_evidence": {
                "status": "completed",
                "coverage": {"executed": 8, "violations": 2, "unresolved": 1},
            },
        },
        "scanner_requirement": {
            "requested": True,
            "satisfied": True,
            "required": ["semgrep-ce"],
        },
        "discovery_required_satisfied": True,
        "coverage_gaps": ["One path not tested"],
        "scan_status": "partial",
    }
    markdown = render_final_report(**options)
    html = render_html_report(**options)
    assert "| Original observations | 2 |" in markdown
    assert "| DAST-related observations | 1 |" in markdown
    assert "| Agent-flagged groups | 1 |" in markdown
    assert "confirmed 1, likely 0, false positive 1" in markdown
    assert (
        "workflows completed (8 steps, 2 contract violations, 1 unresolved)" in markdown
    )
    assert "## How to Read This Report" in markdown
    assert "**Recorded pipeline status:** partial" in markdown
    assert "**Cross-user order access**" in markdown
    assert '<h2 id="review-assessment-title">Review Agent assessment</h2>' not in html
    assert "Release decision</span><strong>Blocked</strong>" not in html
    assert "ZAP alerts</span><strong>3</strong>" in html
    assert "Review these groups first" not in html
    assert "All reviewed groups" not in html
    assert 'class="priority-list"' not in html
    assert "Severity among Review Agent-flagged groups:" not in html
    assert 'href="#briefing"' not in html
    assert '<section id="briefing"' not in html
    assert (
        '<span class="severity-count critical">Critical <strong>0</strong></span>'
        in html
    )
    assert '<span class="severity-count high">High <strong>1</strong></span>' in html
    assert (
        '<span class="severity-count medium">Medium <strong>1</strong></span>' in html
    )
    assert '<span class="severity-count low">Low <strong>0</strong></span>' in html
    assert '<span class="severity-count info">Info <strong>0</strong></span>' in html
    assert html.index('<section id="findings"') < html.index('id="finding-search"')
    assert "Another customer can read an order." in html
    assert '<section id="observations"' not in html
    assert 'href="#observations"' not in html
    assert "High-severity access rule failed." in html
    assert "Review stages complete" not in html
    assert "Release blocked by policy" not in html
    assert "This report separates scanner signals" not in html
    assert (
        '<span class="status-label">Discovery Agent</span><strong>Partial</strong>'
        in html
    )
    assert "Discovery stage details saved · requirement satisfied" in html
    assert (
        '<span class="status-label">Review Agent</span><strong>Complete</strong>'
        in html
    )
    assert (
        '<span class="status-label">Original pipeline scan</span><strong>Partial</strong>'
        in html
    )
    assert "1 Discovery Agent candidate" in html
    assert (
        html.index("Scanner findings</span><strong>1</strong>")
        < html.index("DAST findings</span><strong>1</strong>")
        < html.index("Workflow rule violations</span><strong>2</strong>")
        < html.index("ZAP alerts</span><strong>3</strong>")
        < html.index(
            "All initial findings before Review Agent</span><strong>2</strong>"
        )
    )
    assert "Workflow rule violations</span><strong>2</strong>" in html
    assert "1 known coverage limitations" in html
    assert "These source counts can overlap" in html


def test_html_severity_counts_include_all_reviewed_groups() -> None:
    from security_reviewer_v2.reporting.html import render_html_report

    html = render_html_report(
        project="demo",
        review={
            "reviews": [
                {
                    "candidate_id": "critical",
                    "severity": "critical",
                    "verdict": "confirmed_vulnerability",
                },
                {"candidate_id": "unclassified", "verdict": "needs_more_evidence"},
            ]
        },
        policy={"decisions": []},
    )
    assert (
        '<span class="severity-count critical">Critical <strong>1</strong></span>'
        in html
    )
    assert (
        '<span class="severity-count unknown">Unknown <strong>1</strong></span>' in html
    )
    assert '<option value="critical">Critical</option>' in html


def test_completed_review_without_discovery_proof_is_not_called_complete() -> None:
    markdown = render_final_report(
        project="demo",
        review={"status": "completed", "reviews": []},
        policy={"status": "completed", "blocking": False},
    )
    assert "Review incomplete or unverified" in markdown
    assert "not a safety certificate" in markdown


def test_refresh_saved_report_preserves_old_report(tmp_path: Path) -> None:
    payloads = {
        "pre-review-summary.json": {"project": "lab", "coverage_gaps": ["One gap"]},
        "merged.json": {
            "findings": [_observation("m1", "Visible signal", "semgrep-ce", "app.py")]
        },
        "security-review.json": {"status": "not_run", "reviews": []},
        "policy-gate.json": {"status": "incomplete", "decisions": []},
    }
    for name, payload in payloads.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    report = tmp_path / "security-review-report.md"
    report.write_text("old report\n", encoding="utf-8")
    refreshed = refresh(tmp_path)
    assert refreshed == report
    assert (tmp_path / "security-review-report.before-observations.md").read_text(
        encoding="utf-8"
    ) == "old report\n"
    assert "Visible signal" not in report.read_text(encoding="utf-8")
    assert (
        "scanner/DAST observation record(s) remain in the saved evidence"
        in report.read_text(encoding="utf-8")
    )
    assert "One gap" in report.read_text(encoding="utf-8")


def test_refresh_saved_report_preserves_trusted_docker_dast_section(
    tmp_path: Path,
) -> None:
    payloads = {
        "pre-review-summary.json": {"project": "lab", "coverage_gaps": []},
        "merged.json": {"findings": []},
        "security-review.json": {"status": "not_run", "reviews": []},
        "policy-gate.json": {"status": "incomplete", "decisions": []},
        "docker-runtime-evidence.json": {
            "run_id": "abcd1234",
            "http_status": 200,
            "probe_counts": {"runtime.json": 7, "authorization.json": 4},
            "mutating_checks_enabled": True,
            "manifest_path": "saved/manifest.json",
        },
    }
    for name, payload in payloads.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    markdown = refresh(tmp_path).read_text(encoding="utf-8")
    assert "Trusted Docker DAST" in markdown
    assert "web probes: **7**" in markdown


def test_refresh_saved_report_keeps_generic_dast_and_scanner_state(
    tmp_path: Path,
) -> None:
    payloads = {
        "pre-review-summary.json": {
            "project": "demo",
            "status": "partial",
            "coverage_gaps": ["One path not tested"],
            "ai_discovery": {"satisfied": True},
            "scanner_requirement": {
                "requested": True,
                "satisfied": True,
                "required": ["semgrep-ce"],
                "failures": [],
            },
            "execution": {
                "tasks": [{"scanner_id": "semgrep-ce", "status": "completed"}]
            },
        },
        "merged.json": {"findings": []},
        "security-review.json": {"status": "completed", "reviews": []},
        "policy-gate.json": {"status": "completed", "blocking": False, "decisions": []},
        "runtime.json": {
            "status": "completed",
            "target": "http://127.0.0.1:8090",
            "results": [{}],
            "zap": {"status": "completed", "alerts": 2},
            "workflow_evidence": {
                "status": "completed",
                "coverage": {"executed": 4, "violations": 1},
            },
        },
    }
    for name, payload in payloads.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    markdown = refresh(tmp_path).read_text(encoding="utf-8")
    assert "ZAP: **completed**" in markdown
    assert "executed: **4**" in markdown
    assert "Required scanners: **complete**" in markdown
    assert "semgrep-ce" in markdown
    assert "Recorded pipeline status:** partial" in markdown

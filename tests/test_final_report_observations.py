"""Human-readable reports must not hide scanner or DAST observations."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.refresh_saved_report import refresh
from security_reviewer_v2.reporting.final import render_final_report, write_final_report


def _observation(identifier: str, title: str, scanner: str, path: str,
                 *, dast: bool = False, line: int | None = None) -> dict:
    return {
        "merged_finding_id": identifier,
        "canonical_finding": {"title": title},
        "source_findings": [{"finding_id": f"source-{identifier}"}],
        "scanners": [scanner], "rule_ids": ["rule.example"],
        "severity": "high", "confidence": "medium",
        "categories": ["dast"] if dast else ["static"],
        "primary_location": {"path": path, "start_line": line},
    }


def test_report_shows_all_observations_without_agent_review() -> None:
    merged = {"findings": [
        _observation("m-static", "SQL Injection", "semgrep-ce", "app.py", line=42),
        _observation("m-dast", "Cross-user order access", "authorization-dast", "/orders/101", dast=True),
    ]}
    risk = {"findings": [
        {"merged_finding_id": "m-static", "rank": 1, "risk_score": 60,
         "priority_band": "medium", "review_disposition": "standard_report"},
        {"merged_finding_id": "m-dast", "rank": 2, "risk_score": 50,
         "priority_band": "medium", "review_disposition": "needs_verification"},
    ]}
    markdown = render_final_report(
        project="lab", review={"status": "not_run", "reviews": []},
        policy={"status": "incomplete", "decisions": []}, merged=merged, risk=risk,
        execution={"tasks": [{"scanner_id": "semgrep-ce", "status": "completed"},
                             {"scanner_id": "codeql-cli", "status": "adapter_unavailable"}]},
        coverage_gaps=["CodeQL unavailable"],
    )
    assert "**2** scanner/DAST observation record(s)" in markdown
    assert "**2** merged observation record(s): **1** DAST-related" in markdown
    assert "SQL Injection" in markdown and "Cross-user order access" in markdown
    assert "<code>app.py:42</code>" in markdown
    assert "<code>/orders/101</code>" in markdown
    assert "source-m-static" in markdown and "source-m-dast" in markdown
    assert "needs_verification" in markdown
    assert "codeql-cli" in markdown and "adapter_unavailable" in markdown
    assert "CodeQL unavailable" in markdown
    assert "No agent verdicts were produced" in markdown
    assert "## Security Review Agent Verdicts" in markdown


def test_report_keeps_agent_verdict_separate_and_escapes_scanner_title() -> None:
    title = "<script>alert(1)</script> [click](https://example.test)"
    markdown = render_final_report(
        project="lab",
        review={"status": "completed", "reviews": [{"title": "Reviewed issue", "candidate_id": "g1",
                 "verdict": "likely_vulnerable", "severity": "high", "confidence": "high"}]},
        policy={"status": "completed", "decisions": []},
        merged={"findings": [_observation("m1", title, "semgrep-ce", "app.py", line=7)]},
    )
    assert "&lt;script&gt;" in markdown
    assert "[click](https://example.test)" not in markdown
    assert markdown.index("## Scanner and DAST Observations") < markdown.index("## Security Review Agent Verdicts")
    assert "Reviewed issue" in markdown


def test_report_marks_required_scanner_failure_incomplete() -> None:
    markdown = render_final_report(
        project="lab", review={"status": "completed", "reviews": []},
        policy={"status": "failed", "decisions": []},
        scanner_requirement={"requested": True, "required": ["semgrep-ce", "codeql-cli"],
                             "satisfied": False,
                             "failures": ["codeql-cli/task-codeql: no normalized scanner output was produced"]},
    )
    assert "Required scanners: **incomplete**" in markdown
    assert "**This scan is incomplete.** One or more required scanners" in markdown
    assert "codeql-cli/task-codeql: no normalized scanner output" in markdown


def test_report_describes_completed_generic_dast_phases() -> None:
    markdown = render_final_report(
        project="lab", review={"status": "completed", "reviews": []},
        policy={"status": "failed", "decisions": []},
        runtime_evidence={
            "source": "generic-web-runtime", "target": "http://127.0.0.1:8090", "results": [{}],
            "zap": {"status": "completed", "engine": "zap-active", "alerts": 2},
            "workflow_evidence": {"status": "completed", "coverage": {"executed": 28, "violations": 12}},
        },
    )
    assert "Browser crawl: **not requested**" in markdown
    assert "ZAP: **completed**" in markdown
    assert "alerts: **2**" in markdown
    assert "Account and business workflows: **completed**" in markdown
    assert "executed: **28**" in markdown
    assert "contract violations: **12**" in markdown
    assert "No browser crawl, credentialed authorization workflow" not in markdown


def test_report_writes_standalone_html_next_to_markdown_and_escapes_evidence(tmp_path: Path) -> None:
    markdown_path = tmp_path / "security-review-report.md"
    malicious = '<script>alert("x")</script>'
    write_final_report(
        markdown_path, project="demo <app>",
        review={"status": "completed", "reviews": [{
            "candidate_id": "g1", "title": malicious, "verdict": "confirmed_vulnerability",
            "severity": "high", "evidence": [malicious], "source_ids": ["s1"],
        }]},
        policy={"status": "failed", "blocking": True,
                "decisions": [{"candidate_id": "g1", "action": "block"}]},
        runtime_evidence={"source": "generic-web-runtime", "target": "http://127.0.0.1:8090",
                          "results": [{}], "zap": {"status": "completed", "engine": "zap-active", "alerts": 2},
                          "workflow_evidence": {"status": "completed", "coverage": {"executed": 28, "violations": 12}}},
        merged={"findings": [_observation("s1", malicious, "web-runtime", "/", dast=True)]},
    )
    html_path = markdown_path.with_suffix(".html")
    assert markdown_path.is_file() and html_path.is_file()
    content = html_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in content
    assert "<style>" in content and "<script>const cards=" in content
    assert "https://" not in content
    assert malicious not in content
    assert '&lt;script&gt;alert(&quot;' in content
    assert "28 executed" in content and "12 violations" in content
    assert "confirmed vulnerability" in content


def test_refresh_saved_report_preserves_old_report(tmp_path: Path) -> None:
    payloads = {
        "pre-review-summary.json": {"project": "lab", "coverage_gaps": ["One gap"]},
        "merged.json": {"findings": [_observation("m1", "Visible signal", "semgrep-ce", "app.py")]},
        "security-review.json": {"status": "not_run", "reviews": []},
        "policy-gate.json": {"status": "incomplete", "decisions": []},
    }
    for name, payload in payloads.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    report = tmp_path / "security-review-report.md"
    report.write_text("old report\n", encoding="utf-8")
    refreshed = refresh(tmp_path)
    assert refreshed == report
    assert (tmp_path / "security-review-report.before-observations.md").read_text(encoding="utf-8") == "old report\n"
    assert "Visible signal" in report.read_text(encoding="utf-8")
    assert "One gap" in report.read_text(encoding="utf-8")


def test_refresh_saved_report_preserves_trusted_docker_dast_section(tmp_path: Path) -> None:
    payloads = {
        "pre-review-summary.json": {"project": "lab", "coverage_gaps": []},
        "merged.json": {"findings": []},
        "security-review.json": {"status": "not_run", "reviews": []},
        "policy-gate.json": {"status": "incomplete", "decisions": []},
        "docker-runtime-evidence.json": {
            "run_id": "abcd1234", "http_status": 200,
            "probe_counts": {"runtime.json": 7, "authorization.json": 4},
            "mutating_checks_enabled": True, "manifest_path": "saved/manifest.json",
        },
    }
    for name, payload in payloads.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    markdown = refresh(tmp_path).read_text(encoding="utf-8")
    assert "Trusted Docker DAST" in markdown
    assert "web probes: **7**" in markdown

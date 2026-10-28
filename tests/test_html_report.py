"""HTML report: structure, privacy (no network) and injection safety."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from security_reviewer_v2.reporting import render_final_report, write_final_report
from security_reviewer_v2.reporting.html_report import _rich, render_html
from security_reviewer_v2.reporting.view import build_view, lead

_VOID = {"meta", "br", "link", "img", "input", "hr"}


class _Balance(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: set[str] = set()
        self.attrs: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.attrs.extend(attrs)
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> (open: {self.stack[-3:]})")
        else:
            self.stack.pop()


def _payload(title: str = "SQL Injection", explanation: str = "Builds a query from `username`. Second sentence here."):
    review = {"status": "completed", "reviews": [
        {"candidate_id": "g1", "title": title, "severity": "critical", "verdict": "confirmed_vulnerability",
         "confidence": "high", "explanation": explanation, "impact": "Full database read. More text.",
         "remediation": "Use parameterized queries. Also hash passwords.", "evidence": ["app.py:9 `cursor.execute(q)`"],
         "limitations": ["No runtime probe"], "source_ids": ["g1"]},
        {"candidate_id": "g2", "title": "Cookie flag", "severity": "low", "verdict": "false_positive",
         "confidence": "medium", "explanation": "e", "impact": "i", "remediation": "r", "evidence": [], "source_ids": []}]}
    policy = {"status": "failed", "blocking": True, "rule_set": "release-gate-rules/2", "decisions": [
        {"candidate_id": "g1", "action": "block", "severity": "critical", "verdict": "confirmed_vulnerability",
         "reason": "RG-001: blocked", "rule_id": "RG-001", "evidence_basis": "scanner_corroborated",
         "evidence": ["scanner semgrep-ce high at app.py:9"], "blocking_reason": "RG-001: blocked"},
        {"candidate_id": "g2", "action": "allow", "severity": "low", "verdict": "false_positive",
         "reason": "RG-004: fp", "rule_id": "RG-004", "evidence_basis": "ai_assertion_only", "evidence": []}]}
    execution = {"tasks": [{"scanner_id": "semgrep-ce", "status": "completed", "prerequisite_checks": []},
                           {"scanner_id": "gitleaks", "status": "failed", "reason": "boom", "prerequisite_checks": []}]}
    return dict(project="demo", review=review, policy=policy, execution=execution)


def test_html_is_well_formed_self_contained_and_has_the_expected_sections() -> None:
    page = render_html(build_view(**_payload()))
    parser = _Balance()
    parser.feed(page)
    assert parser.errors == [] and parser.stack == []
    assert {"details", "summary", "table", "button", "style", "script"} <= parser.tags
    assert 'http-equiv="Content-Security-Policy"' in page and "default-src 'none'" in page
    assert not re.search(r'(?:src|href)="https?://', page)                    # nothing is fetched from the network
    for needle in ('class="banner blocked"', "Release blocked", "Fix first", "Findings", "Coverage &amp; trust",
                   'id="f1"', 'data-action="block"', "RG-001", "Appendix"):
        assert needle in page, needle


def test_html_escapes_hostile_scanner_and_model_text() -> None:
    hostile = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    page = render_html(build_view(**_payload(title=hostile, explanation=f"Look {hostile} `x` **bold**")))
    assert "<script>alert" not in page and "<img" not in page and "onerror=alert" not in page.replace("&lt;img src=x onerror=alert(2)&gt;", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<code>x</code>" in page and "<strong>bold</strong>" in page    # formatting survives, markup does not
    assert _rich("`a<b>`") == "<code>a&lt;b&gt;</code>"


def test_lead_keeps_sentences_and_drops_list_markers() -> None:
    assert lead("* Use parameterized queries. Then hash passwords. Third.", 2)[0] == "Use parameterized queries. Then hash passwords."
    short, cut = lead("A" * 400 + ".", 1, 100)
    assert cut and len(short) <= 100
    assert lead("One sentence only.", 2) == ("One sentence only.", False)


def test_write_final_report_emits_markdown_and_html_side_by_side(tmp_path: Path) -> None:
    path = write_final_report(tmp_path / "out" / "security-review-report.md", **_payload())
    assert path.suffix == ".md" and path.with_suffix(".html").is_file()
    assert "Release blocked" in path.read_text(encoding="utf-8")
    assert "<!doctype html>" in path.with_suffix(".html").read_text(encoding="utf-8")


def test_markdown_model_text_cannot_inject_html_or_links() -> None:
    text = render_final_report(**_payload(explanation="<img src=x onerror=1> [click](https://evil.test) `ok`"))
    assert "<img" not in text and "`ok`" in text
    assert not re.search(r"(?<!\\)\]\(https://evil\.test\)", text)       # no live link: brackets are escaped


def test_lead_never_cuts_inside_an_inline_code_span() -> None:
    short, cut = lead("Replace it with `db.execute(\"SELECT * FROM users WHERE name = ?\", (name,))` and hash passwords.", 1, 40)
    assert cut and short.count("`") % 2 == 0 and short.endswith("\u2026")


def test_rich_renders_italics_but_not_intraword_asterisks() -> None:
    assert _rich("Validate the *filename* parameter") == "Validate the <em>filename</em> parameter"
    assert _rich("2*3*4") == "2*3*4"


def test_trivy_tasks_are_labelled_by_what_they_scan() -> None:
    execution = {"tasks": [
        {"scanner_id": "trivy", "status": "prerequisite_unverified", "prerequisite_checks": [
            {"name": "trivy_databases", "status": "unverified", "detail": "SCA requires a verified Trivy vulnerability database"}]},
        {"scanner_id": "trivy", "status": "completed", "prerequisite_checks": [
            {"name": "trivy_databases", "status": "available", "detail": "This Trivy scan type does not require a vulnerability database"}]}]}
    view = build_view(**{**_payload(), "execution": execution})
    roles = {row.status: row.role for row in view.scanners}
    assert roles["prerequisite_unverified"].endswith("(SCA)") and roles["completed"].endswith("Dockerfile & config")


def _trivy_run(adapters: list[str], trivy_task: dict | None = None):
    tasks = [{"scanner_id": "semgrep-ce", "status": "completed", "prerequisite_checks": []}]
    if trivy_task:
        tasks.append(trivy_task)
    gap = "Dependency/SCA coverage is unknown for component x: no supported manifest or lockfile was found."
    return {**_payload(), "execution": {"tasks": tasks}, "adapter_ids": adapters, "coverage_gaps": [gap]}


def test_a_registered_scanner_with_no_task_is_shown_as_not_scheduled_with_the_reason() -> None:
    kwargs = _trivy_run(["semgrep-ce", "trivy"])
    view = build_view(**kwargs)
    row = next(r for r in view.scanners if r.scanner == "trivy")
    assert row.status == "not_scheduled" and row.outcome == "Not scheduled"
    assert any("no Trivy task" in n for n in row.notes) and any("manifest or lockfile" in n for n in row.notes)
    assert view.not_scheduled == ("trivy",)
    assert (view.coverage_done, view.coverage_total) == (1, 1)         # nothing to scan is not a failed scan
    markdown = render_final_report(**kwargs)
    assert "Trivy" in markdown and "Not scheduled" in markdown and "Registered but not scheduled" in markdown
    assert "Not scheduled" in render_html(view)


def test_a_scanner_that_only_has_skipped_tasks_is_not_reported_as_unscheduled() -> None:
    view = build_view(**_trivy_run(["semgrep-ce", "trivy"], {"scanner_id": "trivy", "status": "skipped",
                                                              "prerequisite_checks": []}))
    assert view.not_scheduled == () and view.skipped_tasks == 1


def test_without_adapter_ids_behaviour_is_unchanged() -> None:
    kwargs = _trivy_run(["semgrep-ce", "trivy"])
    kwargs.pop("adapter_ids")
    assert build_view(**kwargs).not_scheduled == ()

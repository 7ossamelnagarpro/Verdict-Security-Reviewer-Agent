import re

from security_reviewer_v2.reporting.evaluation_html import render_evaluation
from security_reviewer_v2.reporting.html_report import _CSS


def _page(**over):
    rows = [{"id": "C01", "status": "detected", "cells": [("Broken access", "/orders"), "confirmed vulnerability", "high"],
             "details": [("Proof", "workflow violation"), ("Matched evidence", ["rule @ /orders"])]},
            {"id": "C02", "status": "not_detected", "cells": [("<script>alert(1)</script>", "x"), "confirmed vulnerability", "low"],
             "details": [("Reason", "<img src=x onerror=alert(1)>")]}]
    args = dict(title="Lab evaluation", intro="Held-out.", headline="1/2 detected", cards=[("1/2", "Detected")],
                table_title="All 2 cases", columns=["Case", "Category", "Truth", "Severity"], outcome_header="Outcome", rows=rows,
                donut=[("Detected", 1, "var(--mint)"), ("Missed", 1, "var(--high)")],
                provenance=[("Project", "lab")], sections=[("Limits", ["a limit"])], notes=["not exhaustive"])
    args.update(over)
    return render_evaluation(**args)


def test_evaluation_page_shares_the_run_report_stylesheet_and_has_the_dark_mode_switch():
    page = _page()
    assert _CSS in page and 'id="theme"' in page and "verdict-theme" in page
    assert 'class="rail"' in page and 'id="dr"' in page


def test_evaluation_page_is_static_and_escapes_everything():
    page = _page()
    assert "Content-Security-Policy" in page and "<img" not in page
    assert not re.search(r"(?:src|href)=[\"']https?://", page)
    assert "<script>alert(1)</script>" not in page and "onerror=alert" not in page.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_rows_open_detail_panes_and_filter_by_outcome():
    page = _page()
    assert 'data-open="c0"' in page and 'id="c0"' in page and 'id="c1"' in page
    assert 'data-k="action" data-v="detected"' in page and 'data-k="action" data-v="not_detected"' in page
    assert 'data-action="not_detected"' in page and "All 2 cases" in page


def test_long_note_lists_collapse_and_empty_ones_say_so():
    page = _page(sections=[("Gaps", [f"gap {i}" for i in range(9)]), ("Limits", [])])
    assert "<details" in page and "None recorded" in page

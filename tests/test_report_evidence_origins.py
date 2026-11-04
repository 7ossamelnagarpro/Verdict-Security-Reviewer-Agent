"""Review groups show the type of their saved evidence, not inferred exploits."""

from security_reviewer_v2.reporting.html import render_html_report
from security_reviewer_v2.reporting.provenance import review_evidence_origins


def test_origin_labels_follow_group_scanner_evidence() -> None:
    review = {
        "reviews": [
            {"candidate_id": group_id, "source_ids": source_ids}
            for group_id, source_ids in (
                ("static", ["s"]),
                ("dast", ["d"]),
                ("mixed", ["s", "d"]),
                ("discovery", ["candidate"]),
                ("unknown", []),
            )
        ]
    }
    triage = {
        "groups": [
            {"group_id": "static", "scanner_finding_ids": ["s"]},
            {"group_id": "dast", "scanner_finding_ids": ["d"]},
            {"group_id": "mixed", "scanner_finding_ids": ["s", "d"]},
            {
                "group_id": "discovery",
                "scanner_finding_ids": [],
                "candidate_ids": ["candidate"],
            },
        ]
    }
    merged = {
        "findings": [
            {"merged_finding_id": "s", "scanners": ["codeql-cli"]},
            {"merged_finding_id": "d", "categories": ["dast", "runtime"]},
        ]
    }
    assert review_evidence_origins(review, triage, merged) == {
        "static": ("Static",),
        "dast": ("DAST",),
        "mixed": ("Static", "DAST"),
        "discovery": ("Discovery Agent",),
        "unknown": ("Unclassified",),
    }


def test_html_finding_shows_and_filters_both_evidence_types() -> None:
    content = render_html_report(
        project="demo",
        review={
            "status": "completed",
            "reviews": [
                {
                    "candidate_id": "mixed",
                    "title": "Mixed evidence",
                    "severity": "high",
                    "verdict": "likely_vulnerability",
                    "source_ids": ["s", "d"],
                }
            ],
        },
        policy={"decisions": []},
        triage={"groups": [{"group_id": "mixed", "scanner_finding_ids": ["s", "d"]}]},
        merged={
            "findings": [
                {"merged_finding_id": "s", "scanners": ["semgrep-ce"]},
                {"merged_finding_id": "d", "scanners": ["owasp-zap"]},
            ]
        },
    )
    assert 'data-origin="static dast"' in content
    assert 'aria-label="Evidence type: Static"' in content
    assert 'aria-label="Evidence type: DAST"' in content
    assert 'id="origin-filter"' in content

"""The held-out review audit must not count duplicates as extra detections."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.audit_security_lab_review import audit_review, render_audit

ROOT = Path(__file__).resolve().parents[1]
SAVED_REVIEW = (
    ROOT
    / "reports/stepwise-security-lab-web/review-stages-20261007/security-review.json"
)


def _inputs() -> tuple[dict, dict, dict]:
    ground_truth = json.loads(
        (ROOT / "benchmark/security_lab_web_ground_truth.json").read_text(
            encoding="utf-8"
        )
    )
    review = json.loads(SAVED_REVIEW.read_text(encoding="utf-8"))
    mapping = json.loads(
        (ROOT / "benchmark/security_lab_web_review_audit_mapping.json").read_text(
            encoding="utf-8"
        )
    )
    return ground_truth, review, mapping


def test_positive_only_evaluation_and_duplicate_correlation() -> None:
    gt = {
        "fixture": "small",
        "findings": [
            {"id": "GT-1", "expected_status": "vulnerable", "title": "SQL injection"},
            {"id": "GT-2", "expected_status": "vulnerable", "title": "IDOR"},
        ],
    }
    review = {
        "status": "completed",
        "reviews": [
            {
                "candidate_id": "one",
                "verdict": "confirmed_vulnerability",
                "source_ids": ["scan-one"],
            },
            {
                "candidate_id": "two",
                "verdict": "likely_vulnerability",
                "source_ids": ["scan-two"],
            },
            {
                "candidate_id": "extra",
                "verdict": "likely_vulnerability",
                "source_ids": ["ai-extra"],
            },
        ],
    }
    mapping = {
        "fixture": "small",
        "issues": [
            {
                "issue_id": "sql",
                "ground_truth_id": "GT-1",
                "review_ids": ["one", "two"],
                "note": "Same sink",
            },
            {
                "issue_id": "extra",
                "ground_truth_id": None,
                "review_ids": ["extra"],
                "note": "Not in GT",
            },
        ],
    }
    result = audit_review(gt, review, mapping)
    assert result["ground_truth_matched_cases"] == 1
    assert result["positive_case_recall"] == 0.5
    assert result["groups_collapsed_within_audit_buckets"] == 1
    assert result["ground_truth_missed_ids"] == ["GT-2"]
    assert result["precision"] is None
    assert result["outside_ground_truth_review_groups"] == 1
    assert result["issues"][0]["source_ids"] == ["scan-one", "scan-two"]


@pytest.mark.skipif(
    not SAVED_REVIEW.is_file(), reason="saved Groq review artifact is not present"
)
def test_saved_review_has_lossless_audited_mapping_and_honest_metrics() -> None:
    ground_truth, review, mapping = _inputs()
    result = audit_review(ground_truth, review, mapping)
    assert result["reviewed_groups"] == len(review["reviews"]) == 35
    assert result["audited_issue_buckets"] == 18
    assert result["ground_truth_matched_cases"] == 8
    assert result["ground_truth_positive_cases"] == 15
    assert result["positive_case_recall"] == 0.5333
    assert result["matched_review_groups"] == 22
    assert result["outside_ground_truth_review_groups"] == 13
    assert result["precision"] is None
    assert "TT-IDOR-002" in result["ground_truth_missed_ids"]
    assert "TT-SESSION-001" in result["ground_truth_missed_ids"]
    assert "TT-EXPOSURE-001" in result["ground_truth_missed_ids"]
    assert "TT-UPLOAD-001" in result["ground_truth_missed_ids"]
    report = render_audit(result, ground_truth)
    assert "8/15" in report
    assert "not measurable" in report
    assert "Django" in report


@pytest.mark.skipif(
    not SAVED_REVIEW.is_file(), reason="saved Groq review artifact is not present"
)
def test_mapping_fails_closed_if_review_is_omitted_or_claimed_twice() -> None:
    ground_truth, review, mapping = _inputs()
    review["reviews"] = review["reviews"][:-1]
    with pytest.raises(ValueError, match="Unknown review ID"):
        audit_review(ground_truth, review, mapping)
    _, review, mapping = _inputs()
    mapping["issues"][1]["review_ids"].append(mapping["issues"][0]["review_ids"][0])
    with pytest.raises(ValueError, match="multiple audit issues"):
        audit_review(ground_truth, review, mapping)

"""Targeted saved review must never silently revisit unrelated groups."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_saved_review_stages import _select_reviews_for_targeted_rereview
from security_reviewer_v2.triage.models import IssueGroup


def _saved_review(path: Path) -> tuple[IssueGroup, IssueGroup]:
    groups = (
        IssueGroup("upload", "upload", "/upload", ("scan-upload",), (), ()),
        IssueGroup("login", "auth", "/login", ("scan-login",), (), ()),
    )
    path.write_text(json.dumps({
        "status": "completed", "provider": "groq", "model": "test-model",
        "reviews": [{
            "candidate_id": group.group_id, "verdict": "needs_more_evidence",
            "severity": "high", "confidence": "medium", "title": group.group_id,
            "explanation": "", "impact": "", "remediation": "",
            "evidence": ["bounded fact"], "limitations": [],
            "source_ids": list(group.scanner_finding_ids),
        } for group in groups],
    }), encoding="utf-8")
    return groups


def test_targeted_review_reuses_every_other_group(tmp_path: Path) -> None:
    path = tmp_path / "security-review.json"
    groups = _saved_review(path)
    reused = _select_reviews_for_targeted_rereview(path, "groq", "test-model", groups, {"upload"})
    assert [item.candidate_id for item in reused] == ["login"]


def test_targeted_review_refuses_stale_or_unknown_groups(tmp_path: Path) -> None:
    path = tmp_path / "security-review.json"
    groups = _saved_review(path)
    with pytest.raises(ValueError, match="unknown re-review"):
        _select_reviews_for_targeted_rereview(path, "groq", "test-model", groups, {"missing"})
    changed = IssueGroup("login", "auth", "/login", ("different-source",), (), ())
    with pytest.raises(ValueError, match="no longer match"):
        _select_reviews_for_targeted_rereview(path, "groq", "test-model", (groups[0], changed), {"upload"})
    with pytest.raises(ValueError, match="same provider and model"):
        _select_reviews_for_targeted_rereview(path, "ollama", "test-model", groups, {"upload"})

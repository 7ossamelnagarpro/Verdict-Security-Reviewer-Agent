"""Behavioral checks for the AI candidate context stage."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_reviewer_v2.context.candidate_cli import main as candidate_context_cli
from security_reviewer_v2.context.candidate_collector import collect_candidate_context
from security_reviewer_v2.context.models import ContextPolicy, ContextStatus
from security_reviewer_v2.discovery.models import (
    CandidateAnchor, CandidateDisposition, CandidateFinding,
    CandidateMissingCheck, DiscoveryResult, DiscoveryStatus,
)
from security_reviewer_v2.reviewers.agent import _build_prompt
from security_reviewer_v2.verification import verify_discovery


def candidate(**changes: object) -> CandidateFinding:
    base = CandidateFinding(
        candidate_id="ai-one",
        title="Possible missing ownership check",
        category="Broken Access Control",
        severity="high",
        confidence="medium",
        path="app.py",
        start_line=2,
        end_line=7,
        evidence=("row = get_order(order_id)",),
        reasoning="Ownership might be missing; needs review.",
        source="ai_discovery",
        verification=CandidateDisposition.SUPPORTED,
        verification_notes=(),
        entry_point=CandidateAnchor("app.py", 2, "order_id = request.args['id']"),
        sensitive_operation=CandidateAnchor("app.py", 7, "return row"),
        missing_check=CandidateMissingCheck("app.py", 5, "owner == current_user", "No check visible"),
        remaining_questions=("Is authorization implemented elsewhere?",),
    )
    return replace(base, **changes)


def discovery(*candidates: CandidateFinding, status: DiscoveryStatus = DiscoveryStatus.COMPLETED) -> DiscoveryResult:
    return DiscoveryResult("1.2", status, "test", "test-model", (), candidates, (), (), {})


def source(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def show_order(request):\n"
        "    order_id = request.args['id']\n"
        "    api_key = 'gsk_abcdefghijklmnopqrstuvwxyz'\n"
        "    row = get_order(order_id)\n"
        "    if row is None: return None\n"
        "    # Is the ownership check elsewhere?\n"
        "    return row\n",
        encoding="utf-8",
    )


def profile(tmp_path: Path) -> dict:
    file = tmp_path / "app.py"
    return {
        "project_snapshot": {
            "root_path": os.path.normcase(str(tmp_path.resolve())),
            "files": [{"path": "app.py", "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}],
        },
        "profile": {"inventory": [{"path": "app.py"}]},
    }


def test_collects_all_anchor_roles_and_bounded_symbol_context(tmp_path: Path) -> None:
    source(tmp_path)
    result = collect_candidate_context(discovery(candidate()), project_root=tmp_path, profile_artifact=profile(tmp_path))

    assert result.status is ContextStatus.COMPLETE
    assert result.summary.input_candidates == 1
    assert result.summary.files_read == 1
    assert result.summary.evidence_locations == 5  # Primary, three roles, and the end of the range.
    context = result.candidates[0]
    assert context.primary.enclosing_symbol.name == "show_order"
    assert context.entry_point.excerpt.start_line == 1
    assert context.sensitive_operation.excerpt.end_line == 7
    assert context.claimed_missing_check.evidence_type == "claimed_missing_check"
    assert "abcdefghijklmnopqrstuvwxyz" not in json.dumps(result.to_dict())
    assert "[REDACTED]" in json.dumps(result.to_dict())


def test_shared_serialization_is_stable_and_does_not_repeat_windows(tmp_path: Path) -> None:
    source(tmp_path)
    result = collect_candidate_context(
        discovery(candidate(), candidate(candidate_id="ai-two")), project_root=tmp_path
    )
    payload = result.to_dict()

    assert payload == collect_candidate_context(
        discovery(candidate(), candidate(candidate_id="ai-two")), project_root=tmp_path
    ).to_dict()
    assert len(payload["shared_excerpts"]) < 2 * result.summary.excerpts_collected
    assert payload["candidates"][0]["primary"]["excerpt_ref"] in payload["shared_excerpts"]
    assert len(payload["shared_symbols"]) >= 1


def test_bad_ai_path_is_not_resolved_by_suffix_or_outside_root(tmp_path: Path) -> None:
    source(tmp_path)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "nested.py").write_text("x = 1\n", encoding="utf-8")
    result = collect_candidate_context(
        discovery(
            candidate(candidate_id="escape", path="../outside.py", entry_point=None, sensitive_operation=None, missing_check=None),
            candidate(candidate_id="suffix", path="nested.py", entry_point=None, sensitive_operation=None, missing_check=None),
        ), project_root=tmp_path,
    )

    assert result.status is ContextStatus.FAILED
    assert result.summary.bytes_read == 0
    assert "unsafe_relative_path" in result.candidates[0].primary.warning
    assert "source_unavailable" in result.candidates[1].primary.warning
    assert len(result.coverage_gaps) == 2


def test_missing_evidence_stays_visible_and_does_not_become_verified(tmp_path: Path) -> None:
    source(tmp_path)
    result = collect_candidate_context(discovery(
        candidate(entry_point=CandidateAnchor("missing.py", 2, "x"), verification=CandidateDisposition.INCONCLUSIVE),
    ), project_root=tmp_path)

    assert result.status is ContextStatus.PARTIAL
    assert result.candidates[0].discovery_disposition == "inconclusive"
    assert result.candidates[0].entry_point.excerpt is None
    assert result.candidates[0].primary.excerpt is not None
    assert any("entry_point context unavailable" in gap for gap in result.coverage_gaps)


def test_profile_hash_change_and_file_limit_are_reported(tmp_path: Path) -> None:
    source(tmp_path)
    snapshot = profile(tmp_path)
    (tmp_path / "app.py").write_text("changed = True\n", encoding="utf-8")
    stale = collect_candidate_context(discovery(candidate()), project_root=tmp_path, profile_artifact=snapshot)
    assert stale.status is ContextStatus.FAILED
    assert any("source_changed_since_profile" in warning for warning in stale.warnings)
    limited = collect_candidate_context(
        discovery(candidate()), project_root=tmp_path, policy=ContextPolicy(max_file_bytes=2)
    )
    assert limited.status is ContextStatus.FAILED
    assert any("file_limit_exceeded" in warning for warning in limited.warnings)


def test_symlink_outside_project_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path.parent / "private-candidate-context.txt"
    outside.write_text("not for the context collector", encoding="utf-8")
    link = tmp_path / "app.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this host")
    result = collect_candidate_context(discovery(candidate()), project_root=tmp_path)
    assert result.status is ContextStatus.FAILED
    assert result.summary.bytes_read == 0
    assert "symlink_skipped" in result.candidates[0].primary.warning


def test_cli_collects_saved_discovery_without_running_a_model(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source(tmp_path)
    saved = tmp_path / "discovery.json"
    output = tmp_path / "candidate-context.json"
    saved.write_text(json.dumps(discovery(candidate()).to_dict()), encoding="utf-8")

    exit_code = candidate_context_cli([str(tmp_path), str(saved), str(output)])

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["contexts_created"] == 1
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


def test_reviewer_uses_collected_candidate_context_not_a_live_reread(tmp_path: Path) -> None:
    source(tmp_path)
    finding = candidate(evidence=("api_key = 'gsk_abcdefghijklmnopqrstuvwxyz'",))
    context = collect_candidate_context(discovery(finding), project_root=tmp_path)
    (tmp_path / "app.py").write_text("new_secret = 'do not send this'\n", encoding="utf-8")

    prompt = _build_prompt(
        [SimpleNamespace(candidate_id="ai-one", checks=(), notes=())],
        {"ai-one": finding}, [], None, tmp_path, 1, candidate_context=context,
    )
    item = json.loads(prompt.split("\n\n", 1)[1])["items"][0]

    assert "show_order" in item["enclosing_symbol"]["excerpt"]
    assert "new_secret" not in json.dumps(item)
    assert "abcdefghijklmnopqrstuvwxyz" not in json.dumps(item)
    assert {part["role"] for part in item["additional_candidate_context"]} == {
        "entry_point", "sensitive_operation", "claimed_missing_check", "range_end",
    }


def test_verification_does_not_confirm_unavailable_candidate_anchor(tmp_path: Path) -> None:
    source(tmp_path)
    finding = candidate(sensitive_operation=CandidateAnchor("app.py", 345, "not present"))
    result = discovery(finding)
    context = collect_candidate_context(result, project_root=tmp_path)

    verification = verify_discovery(result, project_root=tmp_path, candidate_context=context)

    assert verification.records[0].disposition.value == "needs_more_evidence"
    assert any("sensitive_operation context is unavailable" in note for note in verification.records[0].notes)


def test_verification_rechecks_source_snapshot_after_context_collection(tmp_path: Path) -> None:
    source(tmp_path)
    finding = candidate()
    result = discovery(finding)
    context = collect_candidate_context(result, project_root=tmp_path)
    (tmp_path / "app.py").write_text((tmp_path / "app.py").read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")

    verification = verify_discovery(result, project_root=tmp_path, candidate_context=context)

    assert verification.records[0].disposition.value == "needs_more_evidence"
    assert any("changed after candidate context" in note for note in verification.records[0].notes)

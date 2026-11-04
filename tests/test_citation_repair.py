"""A wrong AI line number is repairable only with a unique nearby literal."""

import hashlib
import os
from pathlib import Path

from security_reviewer_v2.discovery.agent import reground_saved_discovery
from security_reviewer_v2.discovery.models import (
    CandidateAnchor,
    CandidateDisposition,
    CandidateFinding,
    CandidateMissingCheck,
    DiscoveryResult,
    DiscoveryStatus,
    DiscoveryTarget,
)
from security_reviewer_v2.verification import VerificationDisposition, verify_discovery


def _saved(
    tmp_path: Path,
    source: str,
    *,
    evidence: tuple[str, ...],
    entry: CandidateAnchor | None = None,
    sink: CandidateAnchor | None = None,
) -> tuple[DiscoveryResult, dict]:
    file = tmp_path / "app.py"
    file.write_text(source, encoding="utf-8")
    lines = source.splitlines()
    candidate_id = "ai-" + hashlib.sha256(b"Possible issueapp.py1").hexdigest()[:16]
    candidate = CandidateFinding(
        candidate_id,
        "Possible issue",
        "authorization",
        "high",
        "medium",
        "app.py",
        1,
        len(lines),
        evidence,
        "Review required",
        "ai_discovery",
        CandidateDisposition.INCONCLUSIVE,
        (),
        entry,
        sink,
        CandidateMissingCheck(
            "app.py", len(lines), "check owner", "No visible owner check"
        ),
        ("Is there another guard?",),
    )
    result = DiscoveryResult(
        "1.2",
        DiscoveryStatus.COMPLETED,
        "test",
        "test",
        ("file:app.py",),
        (candidate,),
        (),
        (),
        {},
        (DiscoveryTarget("file:app.py", "source", "app.py", 1, len(lines), ()),),
    )
    profile = {
        "profile": {"inventory": [{"path": "app.py", "category": "source"}]},
        "project_snapshot": {
            "root_path": os.path.normcase(str(tmp_path.resolve())),
            "files": [
                {
                    "path": "app.py",
                    "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                }
            ],
        },
    }
    return result, profile


def test_unique_off_by_one_quote_and_anchor_repaired_and_audited(
    tmp_path: Path,
) -> None:
    source = (
        "def profile(user_id):\n"
        "    if not logged_in():\n"
        "        return None\n"
        "    db = get_db()\n"
        "    row = db.execute(user_id)\n"
        "    return row\n"
    )
    result, profile = _saved(
        tmp_path,
        source,
        evidence=("5:     db = get_db()", "6:     row = db.execute(user_id)"),
        entry=CandidateAnchor("app.py", 1, "def profile(user_id):"),
        sink=CandidateAnchor("app.py", 4, "    row = db.execute(user_id)"),
    )
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    candidate = updated.candidates[0]
    assert candidate.candidate_id == result.candidates[0].candidate_id
    assert candidate.evidence == ("4: db = get_db()", "5: row = db.execute(user_id)")
    assert candidate.sensitive_operation.line == 5
    assert candidate.verification is CandidateDisposition.SUPPORTED
    assert set(candidate.verification_notes) >= {
        "source_citation_reanchored:evidence:app.py:5->4",
        "source_citation_reanchored:evidence:app.py:6->5",
        "source_citation_reanchored:sensitive_operation:app.py:4->5",
    }
    record = verify_discovery(updated, project_root=tmp_path).records[0]
    assert record.disposition is VerificationDisposition.CONFIRMED
    assert "source_citation_reanchored:evidence:app.py:5->4" in record.notes
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == source


def test_ambiguous_nearby_matches_remain_unresolved(tmp_path: Path) -> None:
    source = "def view():\n    step()\n    pass\n    step()\n    return None\n"
    result, profile = _saved(tmp_path, source, evidence=("3:     step()",))
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    assert updated.candidates[0].evidence == result.candidates[0].evidence
    assert not any(
        "source_citation_reanchored" in note
        for note in updated.candidates[0].verification_notes
    )
    assert (
        verify_discovery(updated, project_root=tmp_path).records[0].disposition
        is VerificationDisposition.NEEDS_MORE_EVIDENCE
    )


def test_compact_anchor_matches_unique_multiline_python_statement(
    tmp_path: Path,
) -> None:
    source = (
        "def profile(user_id):\n"
        "    db = get_db()\n"
        "    row = db.execute(\n"
        "        'SELECT id FROM users WHERE id = ?', (user_id,)\n"
        "    ).fetchone()\n"
        "    return row\n"
    )
    result, profile = _saved(
        tmp_path,
        source,
        evidence=("2:     db = get_db()",),
        entry=CandidateAnchor("app.py", 1, "def profile(user_id):"),
        sink=CandidateAnchor(
            "app.py",
            4,
            "row = db.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()",
        ),
    )
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    candidate = updated.candidates[0]
    assert candidate.sensitive_operation.line == 3
    assert (
        "source_citation_reanchored:sensitive_operation:app.py:4->3"
        in candidate.verification_notes
    )
    assert candidate.verification is CandidateDisposition.SUPPORTED
    assert (
        verify_discovery(updated, project_root=tmp_path).records[0].disposition
        is VerificationDisposition.CONFIRMED
    )


def test_correction_never_crosses_function_boundary(tmp_path: Path) -> None:
    source = "def first():\n    target()\ndef second():\n    pass\n"
    result, profile = _saved(tmp_path, source, evidence=("4:     target()",))
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    assert updated.candidates[0].evidence == result.candidates[0].evidence
    assert (
        verify_discovery(updated, project_root=tmp_path).records[0].disposition
        is VerificationDisposition.NEEDS_MORE_EVIDENCE
    )


def test_correction_never_enters_nested_function(tmp_path: Path) -> None:
    source = (
        "def outer():\n"
        "    pass\n"
        "    def inner():\n"
        "        target()\n"
        "    return inner()\n"
    )
    result, profile = _saved(tmp_path, source, evidence=("2:         target()",))
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    assert updated.candidates[0].evidence == result.candidates[0].evidence
    assert (
        verify_discovery(updated, project_root=tmp_path).records[0].disposition
        is VerificationDisposition.NEEDS_MORE_EVIDENCE
    )


def test_correction_requires_attested_unchanged_source(tmp_path: Path) -> None:
    source = "def view():\n    target()\n    return None\n"
    result, profile = _saved(tmp_path, source, evidence=("3:     target()",))
    (tmp_path / "app.py").write_text(
        "def view():\n    changed()\n    return None\n", encoding="utf-8"
    )
    updated = reground_saved_discovery(
        result, project_root=tmp_path, profile_artifact=profile
    )
    assert updated.candidates[0].evidence == result.candidates[0].evidence
    assert (
        verify_discovery(updated, project_root=tmp_path).records[0].disposition
        is VerificationDisposition.NEEDS_MORE_EVIDENCE
    )

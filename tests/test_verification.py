from pathlib import Path

from security_reviewer_v2.discovery.models import (
    CandidateDisposition,
    CandidateFinding,
    DiscoveryResult,
    DiscoveryStatus,
)
from security_reviewer_v2.verification import VerificationDisposition, verify_discovery


def _result(candidate: CandidateFinding) -> DiscoveryResult:
    return DiscoveryResult(
        "1.0",
        DiscoveryStatus.COMPLETED,
        "test",
        "test",
        ("file:x.py",),
        (candidate,),
        (),
        (),
        {},
    )


def test_verification_confirms_grounded_candidate(tmp_path: Path) -> None:
    target = tmp_path / "x.py"
    target.write_text(
        "value = request.args.get('url')\nfetch(value)\n", encoding="utf-8"
    )
    candidate = CandidateFinding(
        "c1",
        "SSRF",
        "injection",
        "high",
        "high",
        "x.py",
        2,
        2,
        ("fetch(value)",),
        "reason",
        "ai_discovery",
        CandidateDisposition.SUPPORTED,
        (),
    )
    verified = verify_discovery(_result(candidate), project_root=tmp_path)
    assert verified.records[0].disposition is VerificationDisposition.CONFIRMED
    assert "file_exists" in verified.records[0].checks


def test_verification_rejects_outside_path(tmp_path: Path) -> None:
    candidate = CandidateFinding(
        "c1",
        "x",
        "x",
        "high",
        "high",
        "../secret.py",
        1,
        1,
        ("x",),
        "",
        "ai_discovery",
        CandidateDisposition.SUPPORTED,
        (),
    )
    verified = verify_discovery(_result(candidate), project_root=tmp_path)
    assert verified.records[0].disposition is VerificationDisposition.REJECTED


def test_numbered_source_evidence_is_checked_at_exact_lines(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def view():\n    return secret\n", encoding="utf-8"
    )
    grounded = CandidateFinding(
        "c1",
        "x",
        "x",
        "high",
        "high",
        "app.py",
        1,
        2,
        ("1: def view():", "2:     return secret"),
        "",
        "ai_discovery",
        CandidateDisposition.SUPPORTED,
        (),
    )
    result = verify_discovery(_result(grounded), project_root=tmp_path)
    assert result.records[0].disposition is VerificationDisposition.CONFIRMED
    assert "evidence_present_in_excerpt" in result.records[0].checks

    wrong_line = CandidateFinding(
        "c2",
        "x",
        "x",
        "high",
        "high",
        "app.py",
        1,
        2,
        ("2: def view():",),
        "",
        "ai_discovery",
        CandidateDisposition.SUPPORTED,
        (),
    )
    assert (
        verify_discovery(_result(wrong_line), project_root=tmp_path)
        .records[0]
        .disposition
        is VerificationDisposition.NEEDS_MORE_EVIDENCE
    )


def test_one_true_quote_does_not_validate_a_hallucinated_quote(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def view():\n    return secret\n", encoding="utf-8"
    )
    candidate = CandidateFinding(
        "c1",
        "x",
        "x",
        "high",
        "high",
        "app.py",
        1,
        2,
        ("1: def view():", "2:     return public"),
        "",
        "ai_discovery",
        CandidateDisposition.SUPPORTED,
        (),
    )
    record = verify_discovery(_result(candidate), project_root=tmp_path).records[0]
    assert record.disposition is VerificationDisposition.NEEDS_MORE_EVIDENCE
    assert "evidence_present_in_excerpt" not in record.checks

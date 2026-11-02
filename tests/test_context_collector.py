"""Behavioral tests for bounded, deterministic context collection."""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from security_reviewer_v2.context import (
    ContextCollectionError,
    ContextPolicy,
    ContextStatus,
    collect_context,
    context_result_from_dict,
)
from security_reviewer_v2.normalization import load_merge_result
from security_reviewer_v2.normalization.merge_models import (
    MergeResult,
    MergeStatus,
    MergeSummary,
    MergedFinding,
    SourceCoverage,
)
from security_reviewer_v2.normalization.models import (
    CodeFlowStep,
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    RelatedLocation,
    ScannerProvenance,
    UnifiedFinding,
)


def unified(
    *,
    path: str = "vulnerable.py",
    line: int = 3,
    flow: tuple[CodeFlowStep, ...] = (),
    related: tuple[RelatedLocation, ...] = (),
) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id="finding-one",
        schema_version="1.0",
        scanner=ScannerProvenance("codeql-cli", "CodeQL", "test", 0, 0, None),
        rule_id="py/sql-injection",
        title="SQL query built from user-controlled sources",
        description=None,
        message="User input reaches SQL execution",
        severity=FindingSeverity.HIGH,
        security_severity_score=8.8,
        confidence=FindingConfidence.HIGH,
        cwes=("CWE-89",),
        categories=("security",),
        primary_location=FindingLocation(path, line, 1, line, 8),
        code_flow=flow,
        related_locations=related,
        fingerprints={},
        rule_kind="path-problem",
        rule_help_uri=None,
    )


def merged(finding: UnifiedFinding | None = None) -> MergeResult:
    if finding is None:
        findings: tuple[MergedFinding, ...] = ()
    else:
        findings = (
            MergedFinding(
                merged_finding_id="merged-one",
                schema_version="1.0",
                canonical_finding=finding,
                source_findings=(finding,),
                scanners=("codeql-cli",),
                rule_ids=(finding.rule_id,),
                severity=finding.severity,
                confidence=finding.confidence,
                cwes=finding.cwes,
                categories=finding.categories,
                primary_location=finding.primary_location,
                merge_reasons=("single_source_finding",),
            ),
        )
    return MergeResult(
        schema_version="1.0",
        status=MergeStatus.COMPLETE,
        findings=findings,
        source_coverage=(SourceCoverage("codeql-cli", "codeql-sarif-2.1", "complete", len(findings), 0, 0),),
        warnings=(),
        coverage_gaps=(),
        summary=MergeSummary(1, len(findings), len(findings), 0),
    )


def test_collects_primary_flow_related_and_python_symbol(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text(
        "def unsafe(connection, username):\n"
        "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
        "    return connection.execute(query)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "def route(connection, username):\n"
        "    return unsafe(connection, username)\n",
        encoding="utf-8",
    )
    flow = (
        CodeFlowStep(0, 0, 0, FindingLocation("app.py", 2, 12, 2, 18), "source", "source"),
        CodeFlowStep(0, 0, 1, FindingLocation("vulnerable.py", 3, 12, 3, 30), "sink", "sink"),
    )
    related = (RelatedLocation(FindingLocation("app.py", 2, 12, 2, 18), "input"),)

    result = collect_context(merged(unified(flow=flow, related=related)), project_root=tmp_path)

    assert result.status == ContextStatus.COMPLETE
    assert result.summary.files_read == 2
    assert result.summary.evidence_locations == 4
    assert result.summary.excerpts_collected == 4
    context = result.findings[0]
    assert context.primary.enclosing_symbol is not None
    assert context.primary.enclosing_symbol.name == "unsafe"
    assert "3 |     return connection.execute(query)" in context.primary.excerpt.code
    assert [item.step_index for item in context.code_flow] == [0, 1]
    assert context.code_flow[0].enclosing_symbol.name == "route"


def test_missing_flow_file_makes_result_partial_without_losing_primary(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text("def unsafe():\n    value = 1\n    return value\n", encoding="utf-8")
    flow = (
        CodeFlowStep(0, 0, 0, FindingLocation("missing.py", 1, 1, 1, 2), None, None),
    )

    result = collect_context(merged(unified(flow=flow)), project_root=tmp_path)

    assert result.status == ContextStatus.PARTIAL
    assert result.findings[0].primary.excerpt is not None
    assert result.findings[0].code_flow[0].collection_status == "unavailable"
    assert result.summary.unavailable_locations == 1


def test_path_traversal_is_rejected_as_unavailable_context(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("secret = 'do not read'\n", encoding="utf-8")

    result = collect_context(merged(unified(path="../outside.py", line=1)), project_root=tmp_path)

    assert result.status == ContextStatus.FAILED
    assert result.summary.files_read == 0
    assert "unsafe_relative_path" in result.findings[0].primary.warning


def test_file_size_limit_is_visible(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text("x" * 100, encoding="utf-8")

    result = collect_context(
        merged(unified(line=1)),
        project_root=tmp_path,
        policy=ContextPolicy(max_file_bytes=10),
    )

    assert result.status == ContextStatus.FAILED
    assert "file_limit_exceeded" in result.warnings[0]


def test_generic_text_context_does_not_claim_a_symbol(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("const input = request.query.q;\nrun(input);\n", encoding="utf-8")

    result = collect_context(merged(unified(path="app.js", line=2)), project_root=tmp_path)

    primary = result.findings[0].primary
    assert result.status == ContextStatus.COMPLETE
    assert primary.excerpt is not None
    assert primary.enclosing_symbol is None


def test_unique_suffix_path_from_scanner_subroot_is_resolved(tmp_path: Path) -> None:
    nested = tmp_path / "routes"
    nested.mkdir()
    (nested / "login.ts").write_text("export const login = () => true;\n", encoding="utf-8")

    result = collect_context(merged(unified(path="login.ts", line=1)), project_root=tmp_path)

    assert result.status == ContextStatus.COMPLETE
    assert result.findings[0].primary.excerpt is not None
    assert result.findings[0].primary.excerpt.path == "routes/login.ts"


def test_symbol_excerpt_is_bounded_and_marked_truncated(tmp_path: Path) -> None:
    source = "def long_function():\n" + "".join(f"    value_{i} = {i}\n" for i in range(10))
    (tmp_path / "vulnerable.py").write_text(source, encoding="utf-8")

    result = collect_context(
        merged(unified(line=5)),
        project_root=tmp_path,
        policy=ContextPolicy(max_symbol_lines=3),
    )

    symbol = result.findings[0].primary.enclosing_symbol
    assert symbol is not None
    assert symbol.truncated is True
    assert symbol.excerpt.end_line - symbol.excerpt.start_line + 1 == 3


def test_repeated_locations_use_one_bounded_file_read(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text("def unsafe():\n    a = 1\n    return a\n", encoding="utf-8")
    flow = tuple(
        CodeFlowStep(0, 0, index, FindingLocation("vulnerable.py", 2, 1, 2, 2), None, None)
        for index in range(5)
    )

    result = collect_context(merged(unified(flow=flow)), project_root=tmp_path)

    assert result.summary.files_read == 1
    assert result.summary.bytes_read == (tmp_path / "vulnerable.py").stat().st_size


def test_empty_complete_merge_is_complete_empty_context(tmp_path: Path) -> None:
    result = collect_context(merged(), project_root=tmp_path)

    assert result.status == ContextStatus.COMPLETE
    assert result.summary.contexts_created == 0


def test_failed_merge_cannot_become_successful_empty_context(tmp_path: Path) -> None:
    failed_merge = replace(merged(), status=MergeStatus.FAILED)

    result = collect_context(failed_merge, project_root=tmp_path)

    assert result.status == ContextStatus.FAILED


def test_missing_project_root_is_a_startup_error(tmp_path: Path) -> None:
    with pytest.raises(ContextCollectionError):
        collect_context(merged(), project_root=tmp_path / "missing")


def test_context_output_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text("def unsafe():\n    a = 1\n    return a\n", encoding="utf-8")
    artifact = merged(unified())

    assert collect_context(artifact, project_root=tmp_path).to_dict() == collect_context(
        artifact, project_root=tmp_path
    ).to_dict()


def test_file_level_finding_collects_bounded_file_context(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("Flask==3.1.0\n", encoding="utf-8")
    finding = replace(
        unified(),
        primary_location=FindingLocation("requirements.txt", None, None, None, None),
    )

    result = collect_context(merged(finding), project_root=tmp_path)

    assert result.status == ContextStatus.COMPLETE
    assert result.findings[0].primary.collection_status == "file_context"
    assert result.findings[0].primary.excerpt is not None


def test_merged_artifact_round_trip(tmp_path: Path) -> None:
    original = merged(unified())
    path = tmp_path / "merged.json"
    path.write_text(json.dumps(original.to_dict()), encoding="utf-8")

    loaded = load_merge_result(path)

    assert loaded.to_dict() == original.to_dict()


def _profile_for(root: Path, *paths: str) -> dict:
    return {
        "profile": {"inventory": [{"path": path} for path in paths]},
        "project_snapshot": {
            "root_path": os.path.normcase(str(root.resolve())),
            "files": [
                {"path": path, "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest()}
                for path in paths
            ],
        },
    }


def test_keeps_each_scanner_primary_and_compacts_without_losing_evidence(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text("def unsafe():\n    a = 1\n    return a\n", encoding="utf-8")
    first = unified()
    second = replace(
        first,
        finding_id="finding-two",
        scanner=ScannerProvenance("semgrep-ce", "Semgrep", "test", 0, 0, None),
        rule_id="python.sql-injection",
        primary_location=FindingLocation("vulnerable.py", 2, 1, 2, 8),
    )
    one = merged(first)
    combined = replace(
        one,
        findings=(replace(one.findings[0], source_findings=(first, second), scanners=("codeql-cli", "semgrep-ce")),),
    )
    result = collect_context(combined, project_root=tmp_path)
    context = result.findings[0]
    assert context.primary.source_finding_id == "finding-one"
    assert len(context.additional_primaries) == 1
    assert context.additional_primaries[0].source_finding_id == "finding-two"
    assert context.additional_primaries[0].scanner_id == "semgrep-ce"
    assert context.additional_primaries[0].location.start_line == 2
    assert result.summary.evidence_locations == 2
    compact = result.to_dict()
    assert compact["findings"][0]["primary"]["excerpt_ref"]
    assert len(compact["shared_symbols"]) == 1
    restored = context_result_from_dict(compact)
    assert restored == result


def test_profile_index_resolves_suffix_and_rejects_changed_source(tmp_path: Path) -> None:
    nested = tmp_path / "routes"
    nested.mkdir()
    source = nested / "login.ts"
    source.write_text("export const login = () => true;\n", encoding="utf-8")
    profile = _profile_for(tmp_path, "routes/login.ts")
    finding = merged(unified(path="login.ts", line=1))

    fresh = collect_context(finding, project_root=tmp_path, profile_artifact=profile)
    assert fresh.status == ContextStatus.COMPLETE
    assert fresh.findings[0].primary.excerpt.path == "routes/login.ts"
    source.write_text("export const login = () => false;\n", encoding="utf-8")
    stale = collect_context(finding, project_root=tmp_path, profile_artifact=profile)
    assert stale.status == ContextStatus.FAILED
    assert stale.summary.files_read == 0
    assert "source_changed_since_profile" in stale.findings[0].primary.warning


def test_profile_from_another_root_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text("x = 1\n", encoding="utf-8")
    profile = _profile_for(tmp_path, "vulnerable.py")
    profile["project_snapshot"]["root_path"] = "somewhere-else"
    with pytest.raises(ContextCollectionError, match="profile_root_mismatch"):
        collect_context(merged(unified(line=1)), project_root=tmp_path, profile_artifact=profile)


def test_review_prompt_receives_additional_scanner_primary(tmp_path: Path) -> None:
    from security_reviewer_v2.reviewers.agent import _build_prompt

    (tmp_path / "vulnerable.py").write_text("def unsafe():\n    a = 1\n    return a\n", encoding="utf-8")
    first = unified()
    second = replace(
        first,
        finding_id="finding-two",
        scanner=ScannerProvenance("semgrep-ce", "Semgrep", "test", 0, 0, None),
        rule_id="python.sql-injection",
        primary_location=FindingLocation("vulnerable.py", 2, 1, 2, 8),
    )
    one = merged(first)
    combined = replace(one, findings=(replace(one.findings[0], source_findings=(first, second)),))
    context = collect_context(combined, project_root=tmp_path)

    prompt = _build_prompt([], {}, list(combined.findings), context, tmp_path, 1)
    body = json.loads(prompt.split("\n\n", 1)[1])
    other = body["items"][0]["additional_scanner_evidence"][0]
    assert other["scanner_id"] == "semgrep-ce"
    assert other["line"] == 2
    assert "a = 1" in other["excerpt"]


DAST_APP = (
    "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
    "@router.post(\"/comments\")\ndef add_comment():\n    return 1\n\n"
    "@router.get(\"/comments\")\ndef show_comments():\n    return 2\n"
)


def dast_finding(method: str | None) -> UnifiedFinding:
    facts = {"status": 200, **({"method": method} if method else {})}
    return replace(unified(), rule_id="zap.10038", categories=("security", "dast"),
                   primary_location=FindingLocation("/comments", None, None, None, None), runtime_evidence=facts)


def test_runtime_finding_with_an_ambiguous_path_gets_one_reasoned_gap(tmp_path: Path) -> None:
    (tmp_path / "extra.py").write_text(DAST_APP, encoding="utf-8")

    result = collect_context(merged(dast_finding(None)), project_root=tmp_path)

    assert result.status == ContextStatus.FAILED or result.status == ContextStatus.PARTIAL
    gaps = [gap for gap in result.coverage_gaps if "Primary source context is unavailable" in gap]
    assert len(gaps) == 1
    assert "several handlers serve /comments (GET, POST) and the request method was not recorded" in gaps[0]
    assert "for 1 finding(s)" in gaps[0] and "merged-one" in gaps[0]


def test_runtime_finding_with_a_recorded_method_resolves_to_its_handler(tmp_path: Path) -> None:
    (tmp_path / "extra.py").write_text(DAST_APP, encoding="utf-8")

    result = collect_context(merged(dast_finding("GET")), project_root=tmp_path)

    assert not any("Primary source context is unavailable" in gap for gap in result.coverage_gaps)
    excerpt = result.findings[0].primary.excerpt
    assert excerpt is not None and "show_comments" in excerpt.code


def test_runtime_finding_without_any_matching_route_names_the_path(tmp_path: Path) -> None:
    (tmp_path / "extra.py").write_text(DAST_APP, encoding="utf-8")
    finding = replace(dast_finding(None), primary_location=FindingLocation("/missing", None, None, None, None))

    result = collect_context(merged(finding), project_root=tmp_path)

    assert any("no declared route matches the runtime path /missing" in gap for gap in result.coverage_gaps)


def test_static_finding_gap_carries_the_collector_warning_code(tmp_path: Path) -> None:
    result = collect_context(merged(unified(path="../outside.py", line=1)), project_root=tmp_path)

    assert any("unsafe_relative_path" in gap and "Primary source context is unavailable" in gap for gap in result.coverage_gaps)


def test_gap_lists_are_compact_and_deterministic() -> None:
    from security_reviewer_v2.context.collector import _unavailable_gaps

    (line,) = _unavailable_gaps({"reason": [f"merged-{n}" for n in (9, 1, 5, 3, 7, 2, 8)]})
    assert line == ("Primary source context is unavailable for 7 finding(s): reason: "
                    "merged-1, merged-2, merged-3, merged-5, merged-7 (+2 more).")

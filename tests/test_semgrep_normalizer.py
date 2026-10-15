"""Behavioral tests for Semgrep JSON normalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_reviewer_v2.normalization import (
    FindingConfidence,
    FindingSeverity,
    NormalizationInputError,
    NormalizationStatus,
    normalize_semgrep_json,
    normalize_semgrep_json_file,
)


def semgrep_finding(*, path: str = "src/db.py") -> dict:
    return {
        "check_id": "python.security.sql-injection",
        "path": path,
        "start": {"line": 12, "col": 5, "offset": 100},
        "end": {"line": 12, "col": 20, "offset": 115},
        "extra": {
            "message": "User input reaches a SQL query.",
            "severity": "ERROR",
            "fingerprint": "stable-fingerprint",
            "metadata": {
                "category": "security",
                "cwe": ["CWE-89: SQL Injection"],
                "technology": ["python", "sql"],
                "confidence": "MEDIUM",
                "impact": "HIGH",
                "shortlink": "https://example.test/semgrep-rule",
            },
            "dataflow_trace": {
                "taint_source": {
                    "path": "app.py",
                    "start": {"line": 4, "col": 2},
                    "end": {"line": 4, "col": 10},
                    "content": "request.args",
                },
                "intermediate_vars": [
                    {
                        "path": "src/db.py",
                        "start": {"line": 8, "col": 2},
                        "end": {"line": 8, "col": 7},
                        "content": "query",
                    }
                ],
                "taint_sink": {
                    "path": "src/db.py",
                    "start": {"line": 12, "col": 5},
                    "end": {"line": 12, "col": 20},
                    "content": "execute(query)",
                },
            },
        },
    }


def payload(results: list | None = None, errors: list | None = None) -> dict:
    return {
        "version": "1.178.0",
        "results": [semgrep_finding()] if results is None else results,
        "errors": [] if errors is None else errors,
        "paths": {"scanned": ["src/db.py"]},
    }


def test_normalizes_semgrep_finding_and_dataflow() -> None:
    result = normalize_semgrep_json(payload())

    assert result.status == NormalizationStatus.COMPLETE
    finding = result.findings[0]
    assert finding.scanner.scanner_id == "semgrep-ce"
    assert finding.scanner.scanner_version == "1.178.0"
    assert finding.rule_id == "python.security.sql-injection"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.confidence == FindingConfidence.MEDIUM
    assert finding.cwes == ("CWE-89",)
    assert finding.primary_location.path == "src/db.py"
    assert [step.role for step in finding.code_flow] == ["source", "step", "sink"]
    assert finding.fingerprints == {"semgrep": "stable-fingerprint"}
    assert finding.rule_help_uri == "https://example.test/semgrep-rule"


def test_zero_findings_is_complete() -> None:
    result = normalize_semgrep_json(payload(results=[]))

    assert result.status == NormalizationStatus.COMPLETE
    assert result.findings == ()


def test_scan_errors_make_normalization_partial() -> None:
    result = normalize_semgrep_json(
        payload(results=[], errors=[{"type": "ParseError", "message": "bad file"}])
    )

    assert result.status == NormalizationStatus.PARTIAL
    assert result.warnings[0].code == "semgrep_scan_error"


def test_invalid_result_is_skipped_without_losing_valid_sibling() -> None:
    result = normalize_semgrep_json(payload(results=[semgrep_finding(), {"path": "x.py"}]))

    assert result.status == NormalizationStatus.PARTIAL
    assert result.summary.normalized_findings == 1
    assert result.summary.skipped_results == 1


def test_path_traversal_is_rejected() -> None:
    result = normalize_semgrep_json(payload(results=[semgrep_finding(path="../outside.py")]))

    assert result.status == NormalizationStatus.FAILED
    assert result.findings == ()


def test_unrecognized_json_is_rejected() -> None:
    with pytest.raises(NormalizationInputError):
        normalize_semgrep_json({"findings": []})


def test_malformed_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(NormalizationInputError):
        normalize_semgrep_json_file(path)


def test_semgrep_normalization_is_stable() -> None:
    first = normalize_semgrep_json(payload()).to_dict()
    second = normalize_semgrep_json(payload()).to_dict()

    assert first == second
    assert first["findings"][0]["finding_id"].startswith("finding-")


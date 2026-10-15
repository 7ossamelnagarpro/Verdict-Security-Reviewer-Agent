"""Behavioral tests for CodeQL SARIF normalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_reviewer_v2.normalization import (
    FindingConfidence,
    FindingSeverity,
    NormalizationInputError,
    NormalizationStatus,
    normalize_codeql_sarif,
    normalize_codeql_sarif_file,
)


def sarif_result(*, uri: str = "src/db.py", line: int = 17) -> dict:
    return {
        "ruleId": "py/sql-injection",
        "message": {"text": "Query depends on user input."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": line,
                        "startColumn": 9,
                        "endColumn": 14,
                        "snippet": {"text": "execute(query)"},
                    },
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": "abc:1"},
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 5, "startColumn": 2},
                                    },
                                    "message": {"text": "user input"},
                                },
                                "taxa": [
                                    {
                                        "id": "source",
                                        "properties": {"CodeQL/DataflowRole": "source"},
                                    }
                                ],
                            },
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": line, "startColumn": 9},
                                    },
                                    "message": {"text": "SQL sink"},
                                }
                            },
                        ]
                    }
                ]
            }
        ],
        "relatedLocations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 5},
                },
                "message": {"text": "source"},
            }
        ],
    }


def sarif_payload(results: list | None = None) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": "test/category"},
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.27.1",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "shortDescription": {"text": "SQL injection"},
                                "fullDescription": {"text": "Unsafe SQL construction."},
                                "helpUri": "https://example.test/rule",
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-089"],
                                    "precision": "high",
                                    "security-severity": "8.8",
                                    "kind": "path-problem",
                                },
                            }
                        ],
                    }
                },
                "results": [sarif_result()] if results is None else results,
            }
        ],
    }


def test_normalizes_rule_metadata_location_and_code_flow() -> None:
    normalized = normalize_codeql_sarif(sarif_payload())

    assert normalized.status == NormalizationStatus.COMPLETE
    assert normalized.summary.normalized_findings == 1
    finding = normalized.findings[0]
    assert finding.rule_id == "py/sql-injection"
    assert finding.title == "SQL injection"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.security_severity_score == 8.8
    assert finding.confidence == FindingConfidence.HIGH
    assert finding.cwes == ("CWE-89",)
    assert finding.categories == ("security",)
    assert finding.primary_location.path == "src/db.py"
    assert finding.primary_location.start_line == 17
    assert finding.primary_location.snippet == "execute(query)"
    assert len(finding.code_flow) == 2
    assert finding.code_flow[0].role == "source"
    assert finding.related_locations[0].message == "source"
    assert finding.scanner.scanner_version == "2.27.1"
    assert finding.fingerprints["primaryLocationLineHash"] == "abc:1"


def test_empty_results_is_complete_not_a_security_claim() -> None:
    normalized = normalize_codeql_sarif(sarif_payload(results=[]))

    assert normalized.status == NormalizationStatus.COMPLETE
    assert normalized.findings == ()
    assert normalized.summary.input_results == 0


def test_invalid_result_is_skipped_and_makes_result_partial() -> None:
    normalized = normalize_codeql_sarif(sarif_payload(results=[sarif_result(), {"message": {"text": "missing rule"}}]))

    assert normalized.status == NormalizationStatus.PARTIAL
    assert normalized.summary.normalized_findings == 1
    assert normalized.summary.skipped_results == 1
    assert normalized.warnings[0].code == "result_skipped"


def test_all_invalid_results_make_normalization_failed() -> None:
    normalized = normalize_codeql_sarif(sarif_payload(results=[{"ruleId": "x"}]))

    assert normalized.status == NormalizationStatus.FAILED
    assert normalized.findings == ()


def test_non_sarif_json_is_rejected() -> None:
    with pytest.raises(NormalizationInputError):
        normalize_codeql_sarif({"results": []})


def test_malformed_json_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.sarif"
    path.write_text("{bad", encoding="utf-8")

    with pytest.raises(NormalizationInputError):
        normalize_codeql_sarif_file(path)


def test_encoded_uri_is_decoded_and_normalized() -> None:
    normalized = normalize_codeql_sarif(
        sarif_payload(results=[sarif_result(uri="src/my%20module/db.py")])
    )

    assert normalized.findings[0].primary_location.path == "src/my module/db.py"


def test_path_traversal_location_is_rejected() -> None:
    normalized = normalize_codeql_sarif(
        sarif_payload(results=[sarif_result(uri="../outside.py")])
    )

    assert normalized.status == NormalizationStatus.FAILED
    assert normalized.summary.skipped_results == 1


def test_finding_ids_and_output_are_stable() -> None:
    first = normalize_codeql_sarif(sarif_payload()).to_dict()
    second = normalize_codeql_sarif(sarif_payload()).to_dict()

    assert first == second
    assert first["findings"][0]["finding_id"].startswith("finding-")


def test_unknown_precision_and_level_remain_explicit() -> None:
    payload = sarif_payload()
    properties = payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    properties.pop("security-severity")
    properties.pop("precision")

    finding = normalize_codeql_sarif(payload).findings[0]

    assert finding.severity == FindingSeverity.UNKNOWN
    assert finding.confidence == FindingConfidence.UNKNOWN


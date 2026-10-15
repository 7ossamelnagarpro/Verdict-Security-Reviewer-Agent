"""Normalize the local differential authorization probe output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .codeql import NormalizationInputError
from .models import (
    FINDING_SCHEMA_VERSION,
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    NormalizationResult,
    NormalizationStatus,
    NormalizationSummary,
    ScannerProvenance,
    UnifiedFinding,
)


def normalize_idor_json_file(path: str | Path) -> NormalizationResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizationInputError(f"IDOR JSON file is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NormalizationInputError(f"IDOR input could not be read as JSON: {type(error).__name__}") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise NormalizationInputError("Input is not recognized IDOR probe JSON")
    findings: list[UnifiedFinding] = []
    for index, item in enumerate(payload["results"]):
        if not isinstance(item, dict) or not item.get("vulnerable"):
            continue
        path_value = str(item.get("path") or "runtime://authorization")
        rule_id = str(item.get("rule_id") or "idor.cross-user-resource-access")
        fingerprint = hashlib.sha256(f"idor:{path_value}:{rule_id}".encode()).hexdigest()[:24]
        findings.append(
            UnifiedFinding(
                finding_id=f"idor-{fingerprint}",
                schema_version=FINDING_SCHEMA_VERSION,
                scanner=ScannerProvenance("idor-dast", "Authorization Differential Probe", "1.0", 0, index, None),
                rule_id=rule_id,
                title=str(item.get("title") or "Cross-user resource access (possible IDOR)"),
                description=str(item.get("message") or "Authorization boundary was bypassed during a cross-user request."),
                message=str(item.get("message") or "Authorization boundary was bypassed during a cross-user request."),
                severity=FindingSeverity.HIGH,
                security_severity_score=8.0,
                confidence=FindingConfidence.HIGH,
                cwes=("CWE-639",),
                categories=("authorization", "idor", "dast"),
                primary_location=FindingLocation(path_value, item.get("start_line"), None, item.get("start_line"), None),
                code_flow=(),
                related_locations=(),
                fingerprints={"primary": fingerprint},
                rule_kind="differential_authorization",
                rule_help_uri="https://cwe.mitre.org/data/definitions/639.html",
            )
        )
    return NormalizationResult(
        schema_version=FINDING_SCHEMA_VERSION,
        source_format="idor-json",
        status=NormalizationStatus.COMPLETE,
        findings=tuple(findings),
        warnings=(),
        summary=NormalizationSummary(1, len(payload["results"]), len(findings), 0),
    )

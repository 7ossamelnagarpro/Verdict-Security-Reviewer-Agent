"""Normalize Gitleaks JSON without persisting secret values."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .codeql import NormalizationInputError
from .common import line_hash, normalize_relative_path
from .models import (
    FINDING_SCHEMA_VERSION,
    KIND_SECRETS,
    FindingConfidence,
    FindingLocation,
    FindingSeverity,
    NormalizationResult,
    NormalizationStatus,
    NormalizationSummary,
    NormalizationWarning,
    ScannerProvenance,
    UnifiedFinding,
)


LINE_HASH_KEY = "verdict.lineHash/v1"
# CWE-798: Use of Hard-coded Credentials. Gitleaks does not label its rules
# with a CWE, so without this the risk engine's CWE-798 weighting and the
# cross-scanner merge (Semgrep/Trivy secret findings) could never apply.
SECRET_CWE = "CWE-798"


def normalize_gitleaks_json_file(path: str | Path, *, project_root: str | Path | None = None) -> NormalizationResult:
    source = Path(path)
    if not source.is_file():
        raise NormalizationInputError(f"Gitleaks JSON file is unavailable: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NormalizationInputError(
            f"Gitleaks input could not be read as JSON: {type(error).__name__}"
        ) from error
    return normalize_gitleaks_json(payload, project_root=project_root)


def normalize_gitleaks_json(payload: Any, *, project_root: str | Path | None = None) -> NormalizationResult:
    if not isinstance(payload, list):
        raise NormalizationInputError("Input is not recognized Gitleaks JSON (expected an array)")
    findings: list[UnifiedFinding] = []
    warnings: list[NormalizationWarning] = []
    skipped = 0
    for index, result in enumerate(payload):
        if not isinstance(result, dict):
            skipped += 1
            warnings.append(NormalizationWarning("invalid_result", "Gitleaks result is not an object", 0, index))
            continue
        try:
            findings.append(_normalize_result(result, index, project_root))
        except ValueError as error:
            skipped += 1
            warnings.append(NormalizationWarning("result_skipped", str(error), 0, index))
    findings.sort(key=lambda item: (item.primary_location.path.casefold(), item.primary_location.start_line or 0, item.rule_id, item.finding_id))
    status = NormalizationStatus.PARTIAL if skipped else NormalizationStatus.COMPLETE
    if payload and not findings and skipped == len(payload):
        status = NormalizationStatus.FAILED
    return NormalizationResult(
        schema_version=FINDING_SCHEMA_VERSION,
        source_format="gitleaks-json",
        status=status,
        findings=tuple(findings),
        warnings=tuple(warnings),
        summary=NormalizationSummary(1, len(payload), len(findings), skipped),
    )


def _normalize_result(
    result: dict[str, Any], index: int, project_root: str | Path | None = None
) -> UnifiedFinding:
    rule_id = _text(result.get("RuleID")) or _text(result.get("RuleId"))
    path = _normalize_path(result.get("File"), project_root)
    if not rule_id:
        raise ValueError("Gitleaks result has no RuleID")
    if path is None:
        raise ValueError(f"Gitleaks result {rule_id} has no safe relative file path")
    start_line = _positive_int(result.get("StartLine"))
    end_line = _positive_int(result.get("EndLine")) or start_line
    location = FindingLocation(
        path=path,
        start_line=start_line,
        start_column=_positive_int(result.get("StartColumn")),
        end_line=end_line,
        end_column=_positive_int(result.get("EndColumn")),
        snippet=None,
    )
    description = _text(result.get("Description")) or "A possible secret matched a Gitleaks detection rule."
    fingerprint = _text(result.get("Fingerprint"))
    material = "|".join((rule_id, path, str(start_line or 0), fingerprint or ""))
    finding_id = "finding-" + hashlib.sha256(("gitleaks|" + material).encode("utf-8")).hexdigest()[:20]
    return UnifiedFinding(
        finding_id=finding_id,
        schema_version=FINDING_SCHEMA_VERSION,
        scanner=ScannerProvenance("gitleaks", "Gitleaks", None, 0, index, None),
        rule_id=rule_id,
        title=_text(result.get("Description")) or rule_id,
        description=description,
        message="Potential secret detected; secret values were intentionally omitted from normalized output.",
        severity=FindingSeverity.HIGH,
        security_severity_score=None,
        confidence=FindingConfidence.MEDIUM,
        cwes=(SECRET_CWE,),
        categories=("secrets",),
        primary_location=location,
        code_flow=(),
        related_locations=(),
        fingerprints=_fingerprints(fingerprint, project_root, path, start_line),
        rule_kind="secret",
        rule_help_uri=None,
        finding_kind=KIND_SECRETS,
    )


def _fingerprints(
    fingerprint: str | None, project_root: str | Path | None, path: str, line: int | None
) -> dict[str, str]:
    result = {"gitleaks": fingerprint} if fingerprint else {}
    # Hash only: the secret text is never read into the finding.
    content_hash = line_hash(project_root, path, line)
    if content_hash:
        result[LINE_HASH_KEY] = content_hash
    return result


def _normalize_path(value: Any, project_root: str | Path | None = None) -> str | None:
    return normalize_relative_path(value, project_root=project_root)


def _text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _positive_int(value: Any) -> int | None:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None

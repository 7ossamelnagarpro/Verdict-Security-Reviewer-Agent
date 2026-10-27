"""Normalize web-runtime probe results into the shared finding schema."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import (FINDING_SCHEMA_VERSION, FindingConfidence, FindingLocation,
                     FindingSeverity, NormalizationResult, NormalizationStatus,
                     NormalizationSummary, ScannerProvenance, UnifiedFinding)
from .runtime_evidence import bounded_runtime_evidence


def normalize_runtime_json_file(path: str | Path) -> NormalizationResult:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    results = payload.get("results", []) if isinstance(payload, dict) else []
    findings = []
    for index, item in enumerate(results):
        if not isinstance(item, dict) or not item.get("vulnerable"):
            continue
        rule_id = str(item.get("rule_id", "web.runtime-check"))
        location = str(item.get("path", "runtime://web"))
        is_zap = item.get("source") == "owasp-zap"
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        identity = f"runtime:{rule_id}:{location}"
        if is_zap:
            # Distinct parameters/methods must not silently share one finding ID.
            identity += ":" + json.dumps([evidence.get("method"), evidence.get("parameter")])
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()[:24]
        cwe = str(evidence.get("cwe_id", "")) if is_zap else ""
        severity = FindingSeverity(str(item.get("severity", "medium")))
        confidence = FindingConfidence(str(item.get("confidence", "medium")))
        message = str(item.get("title", rule_id))
        findings.append(UnifiedFinding(
            finding_id=f"runtime-{fingerprint}", schema_version=FINDING_SCHEMA_VERSION,
            scanner=ScannerProvenance("owasp-zap" if is_zap else "web-runtime",
                                     "OWASP ZAP" if is_zap else "Bounded Web Runtime Checks", None if is_zap else "1.0", 0, index, None),
            rule_id=rule_id, title=message, description=message, message=message,
            severity=severity, security_severity_score=None, confidence=confidence,
            cwes=(f"CWE-{cwe}",) if cwe.isdigit() and int(cwe) > 0 else (), categories=("dast", "runtime"),
            primary_location=FindingLocation(location, None, None, None, None),
            code_flow=(), related_locations=(), fingerprints={"primary": fingerprint},
            rule_kind="runtime_behavior", rule_help_uri=None,
            runtime_evidence=bounded_runtime_evidence(item.get("evidence"))))
    return NormalizationResult(FINDING_SCHEMA_VERSION, "web-runtime-json", NormalizationStatus.COMPLETE,
        tuple(findings), (), NormalizationSummary(1, len(results), len(findings), len(results) - len(findings)))

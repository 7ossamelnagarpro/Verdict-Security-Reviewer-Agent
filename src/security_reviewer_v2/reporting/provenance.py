"""Evidence-origin labels for reviewed issue groups, not vulnerability verdicts."""

from __future__ import annotations

from typing import Any

_STATIC_SCANNERS = {"codeql-cli", "semgrep-ce", "trivy", "gitleaks"}
_DAST_SCANNERS = {"web-runtime", "owasp-zap", "browser-runtime", "authorization-dast"}
_STATIC_CATEGORIES = {"static", "sast", "sca", "dependency", "secret", "iac"}
_DAST_CATEGORIES = {"dast", "runtime"}


def _records(value: Any) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _evidence_types(finding: dict[str, Any]) -> set[str]:
    records = [finding, *_records(finding.get("source_findings"))]
    categories: set[str] = set()
    scanners: set[str] = set()
    for record in records:
        raw_categories = record.get("categories")
        if isinstance(raw_categories, list):
            categories.update(str(value).lower() for value in raw_categories)
        raw_scanners = record.get("scanners")
        if isinstance(raw_scanners, list):
            scanners.update(str(value).lower() for value in raw_scanners)
        scanner = record.get("scanner")
        if isinstance(scanner, dict):
            scanners.add(str(scanner.get("scanner_id") or "").lower())
    types = set()
    if categories & _STATIC_CATEGORIES or scanners & _STATIC_SCANNERS:
        types.add("Static")
    if categories & _DAST_CATEGORIES or scanners & _DAST_SCANNERS:
        types.add("DAST")
    return types


def review_evidence_origins(
    review: dict[str, Any],
    triage: dict[str, Any] | None,
    merged: dict[str, Any] | None,
) -> dict[str, tuple[str, ...]]:
    """Classify each group from saved scanner evidence; never infer from its title."""
    findings = {
        str(item["merged_finding_id"]): item
        for item in _records((merged or {}).get("findings"))
        if item.get("merged_finding_id")
    }
    groups = {
        str(item["group_id"]): item
        for item in _records((triage or {}).get("groups"))
        if item.get("group_id")
    }
    result: dict[str, tuple[str, ...]] = {}
    for item in _records(review.get("reviews")):
        group_id = str(item.get("candidate_id") or "")
        group = groups.get(group_id, {})
        raw_ids = group.get("scanner_finding_ids")
        if not isinstance(raw_ids, list):
            raw_ids = (
                item.get("source_ids")
                if isinstance(item.get("source_ids"), list)
                else []
            )
        finding_ids = [str(value) for value in raw_ids if str(value) in findings]
        if not finding_ids and isinstance(item.get("source_ids"), list):
            finding_ids = [
                str(value) for value in item["source_ids"] if str(value) in findings
            ]
        types: set[str] = set()
        for finding_id in finding_ids:
            types.update(_evidence_types(findings[finding_id]))
        if types:
            result[group_id] = tuple(
                label for label in ("Static", "DAST") if label in types
            )
        elif group.get("candidate_ids") or (item.get("source_ids") and not finding_ids):
            result[group_id] = ("Discovery Agent",)
        else:
            result[group_id] = ("Unclassified",)
    return result

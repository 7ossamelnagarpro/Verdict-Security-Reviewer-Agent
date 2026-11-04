"""Read-only report projection. Missing evidence never becomes a clean result."""

from __future__ import annotations

import json
from pathlib import Path


def read(root: Path, name: str, default=None):
    path = root / name
    if not path.is_file() or path.stat().st_size > 50_000_000:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return default


def project_report(root: Path):
    review = read(root, "security-review.json", {})
    merged = read(root, "merged.json", {})
    triage = read(root, "candidate-triage.json", {})
    findings = merged.get("findings", merged.get("merged_findings", []))
    if not isinstance(findings, list):
        findings = []
    by_id = {f.get("merged_finding_id", f.get("id", "")): f for f in findings}
    items = []
    covered = set()
    for item in review.get("reviews", []):
        sources = item.get("source_ids", [])
        covered.update(sources)
        items.append(
            {
                "id": item.get("candidate_id"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "verdict": item.get("verdict"),
                "explanation": item.get("explanation"),
                "remediation": item.get("remediation"),
                "evidence": item.get("evidence", []),
                "limitations": item.get("limitations", []),
                "source_ids": sources,
                "sources": [by_id[s] for s in sources if s in by_id],
            }
        )
    for identifier, item in by_id.items():
        if identifier not in covered:
            canonical = item.get("canonical_finding", item)
            items.append(
                {
                    "id": identifier,
                    "title": canonical.get("title", "Scanner observation"),
                    "severity": item.get(
                        "severity", canonical.get("severity", "unknown")
                    ),
                    "verdict": "not_reviewed",
                    "evidence": [],
                    "sources": [item],
                }
            )
    return {
        "items": items,
        "review_status": review.get("status", "not_run"),
        "pending_ids": review.get("pending_ids", []),
        "policy": read(root, "policy-gate.json", {}),
        "gaps": read(
            root,
            "coverage-gaps.json",
            read(root, "pre-review-summary.json", {}).get(
                "coverage_gaps", merged.get("coverage_gaps", [])
            ),
        ),
        "triage": triage.get("summary", {}),
        "verification": read(root, "verification.json", {}),
        "runtime": read(
            root, "runtime.json", read(root, "docker-runtime-evidence.json", {})
        ),
        "coverage_summary": read(root, "coverage-summary.json", {}),
        "summary": read(
            root, "stage-summary.json", read(root, "pre-review-summary.json", {})
        ),
    }


def compare(current: dict, previous: dict):
    before = {item["id"] for item in previous["items"]}
    after = {item["id"] for item in current["items"]}
    return {
        "new": sorted(after - before),
        "persisting": sorted(after & before),
        "no_longer_observed": sorted(before - after),
        "note": "A missing observation is not proof of a fix; compare scope, coverage and review completion.",
    }

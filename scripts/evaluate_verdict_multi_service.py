"""Held-out, post-scan audit for the 18-scenario multi-service lab.

Only saved findings and final reviews are read. Never import this module into a
scanner, an AI prompt, or the target application: it contains answer mappings.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from security_reviewer_v2.reporting.evaluation_html import render_evaluation


ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "benchmark" / "verdict-multi-service-scenarios.json"
POSITIVE = {"confirmed_vulnerability", "likely_vulnerability"}

# Exact workflow rule, workflow ID, method, and route. Similar words in a
# scanner title are deliberately not enough to claim a scenario was found.
RUNTIME = {
    "vmsl-authz-001": ("workflow.owner_assignment.2", "owner_assignment", "POST", "/orders"),
    "vmsl-authz-002": ("workflow.order_owner.3", "order_owner", "GET", "/orders/{{order_id}}"),
    "vmsl-authz-003": ("workflow.admin_users.2", "admin_users", "GET", "/admin/users"),
    "vmsl-business-001": ("workflow.negative_price.1", "negative_price", "POST", "/orders"),
    "vmsl-business-002": ("workflow.coupon_bounds.2", "coupon_bounds", "POST", "/orders/{{order_id}}/apply-coupon"),
    "vmsl-business-003": ("workflow.payment_replay.3", "payment_replay", "POST", "/orders/{{order_id}}/pay"),
    "vmsl-business-004": ("workflow.paid_cancel.3", "paid_cancel", "POST", "/orders/{{order_id}}/cancel"),
    "vmsl-data-002": ("workflow.invoice_owner.4", "invoice_owner", "GET", "/invoices/{{invoice_id}}"),
    "vmsl-api-002": ("workflow.debug_access.1", "debug_access", "GET", "/debug/config"),
    "vmsl-worker-001": ("workflow.worker_role.1", "worker_role", "POST", "/jobs"),
}
STATIC = {
    "vmsl-api-001": ("python.fastapi.security.wildcard-cors.wildcard-cors", "api/app.py", 20, 40),
    "vmsl-logging-001": ("py/clear-text-logging-sensitive-data", "api/app.py", 130, 150),
}


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _sources(finding: dict[str, Any]) -> list[dict[str, Any]]:
    sources = finding.get("source_findings") or [finding.get("canonical_finding")]
    return [source for source in sources if isinstance(source, dict)]


def _runtime_match(case_id: str, source: dict[str, Any]) -> bool:
    signature = RUNTIME.get(case_id)
    if signature is None:
        return False
    rule, workflow, method, path = signature
    facts = source.get("runtime_evidence") or {}
    actual, expected, results = facts.get("status"), facts.get("expected_statuses"), facts.get("assertion_results")
    if (source.get("rule_id") != rule or (source.get("primary_location") or {}).get("path") != path
            or type(actual) is not int or facts.get("workflow_id") not in (None, workflow) or facts.get("method") not in (None, method)):
        return False
    # A workflow.* finding exists only for a confirmed violation. Runs saved before the normalizer kept the assertion
    # details carry just the HTTP status: accept those, but never a recorded pass or a status that was expected.
    if expected is not None and not (isinstance(expected, list) and all(type(item) is int for item in expected) and actual not in expected):
        return False
    return results is None or False in results


def _static_match(case_id: str, source: dict[str, Any]) -> bool:
    signature = STATIC.get(case_id)
    if signature is None:
        return False
    rule, path, first, last = signature
    loc = source.get("primary_location") or {}
    line = loc.get("start_line")
    return (source.get("rule_id") == rule and loc.get("path") == path
            and type(line) is int and first <= line <= last)


def _ai_match(case_id: str, candidate: dict[str, Any]) -> bool:
    if candidate.get("verification") != "supported" or candidate.get("path") != "api/app.py":
        return False
    entry = candidate.get("entry_point") or {}
    operation = candidate.get("sensitive_operation") or {}
    if case_id == "vmsl-data-001":
        return (entry.get("path") == operation.get("path") == "api/app.py"
                and '"/me"' in str(entry.get("code", ""))
                and "ssn" in str(operation.get("code", "")).lower()
                and type(candidate.get("start_line")) is int)
    return False


def _validate_inputs(scan: dict[str, Any], merged: dict[str, Any], ai: dict[str, Any],
                     triage: dict[str, Any], review: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    target = str(scan.get("project", "")).replace("\\", "/").rstrip("/").split("/")[-1]
    if target.lower() != "verdict-multi-service-lab":
        raise ValueError("Saved scan is not for verdict-multi-service-lab")
    if merged.get("status") not in {"complete", "completed"} or review.get("status") != "completed":
        raise ValueError("Evaluation requires completed merged findings and final review")
    findings = {item["merged_finding_id"]: item for item in merged.get("findings", [])}
    candidates = {item["candidate_id"]: item for item in ai.get("candidates", [])}
    groups = {}
    for group in triage.get("groups", []):
        ids = set(group.get("scanner_finding_ids", [])) | set(group.get("candidate_ids", []))
        if not set(group.get("scanner_finding_ids", [])) <= findings.keys() or not set(group.get("candidate_ids", [])) <= candidates.keys():
            raise ValueError("Triage refers to a source absent from this scan")
        groups[group["group_id"]] = ids
    reviews = {}
    for item in review.get("reviews", []):
        group_id = item["candidate_id"]
        if group_id not in groups or set(item.get("source_ids", [])) != groups[group_id]:
            raise ValueError("Final review does not match triage groups for this scan")
        reviews[group_id] = item
    if set(reviews) != set(groups):
        raise ValueError("Final review does not cover every triage group")
    return findings, candidates


def evaluate(truth: dict[str, Any], scan: dict[str, Any], merged: dict[str, Any],
             ai: dict[str, Any], triage: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    findings, candidates = _validate_inputs(scan, merged, ai, triage, review)
    if truth.get("target") != "verdict-multi-service-lab":
        raise ValueError("Wrong ground-truth fixture")
    cases = truth.get("scenarios", [])
    if len(cases) != 18 or len({case["id"] for case in cases}) != 18:
        raise ValueError("Expected 18 distinct ground-truth scenarios")
    reviewed = {item["candidate_id"]: item for item in review["reviews"]}
    rows = []
    for case in cases:
        case_id = case["id"]
        matches = []
        for finding_id, finding in findings.items():
            if any(_runtime_match(case_id, source) or _static_match(case_id, source)
                   for source in _sources(finding)):
                matches.append(finding_id)
        for candidate_id, candidate in candidates.items():
            if _ai_match(case_id, candidate):
                matches.append(candidate_id)
        signals = [{"group_id": source_id, "verdict": reviewed[source_id]["verdict"],
                    "review_evidence_present": bool(reviewed[source_id].get("evidence"))}
                   for source_id in matches if source_id in reviewed]
        if case["outcome"] == "candidate":
            status = "needs_review"
            reason = "Ground truth marks this as candidate-only; excluded from confirmed-case recall."
        elif signals and any(item["verdict"] in POSITIVE and item["review_evidence_present"] for item in signals):
            if any(item["verdict"] not in POSITIVE for item in signals):
                status, reason = "needs_review", "Direct evidence has conflicting final verdicts."
            else:
                status, reason = "detected", "Exact source evidence and a positive final review agree."
        elif signals:
            status, reason = "needs_review", "Direct source evidence exists, but the final review did not confirm it."
        else:
            status, reason = "not_detected", "No exact, reviewed evidence for this scenario in the saved run."
        rows.append({"id": case_id, "category": case["category"], "location": case["location"],
                     "severity": case["severity"], "ground_truth": case["outcome"],
                     "status": status, "reason": reason, "signals": signals})
    confirmed = [row for row in rows if row["ground_truth"] == "confirmed"]
    detected = sum(row["status"] == "detected" for row in confirmed)
    return {"schema_version": "1.0", "target": truth["target"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"total_scenarios": len(rows), "confirmed_ground_truth": len(confirmed),
                        "candidate_only": len(rows) - len(confirmed), "detected": detected,
                        "needs_review_confirmed": sum(row["status"] == "needs_review" for row in confirmed),
                        "not_detected_confirmed": sum(row["status"] == "not_detected" for row in confirmed),
                        "positive_case_recall": round(detected / len(confirmed), 4)},
            "limitations": ["This is a held-out, post-scan positive-case audit, not a new scan.",
                            "No labeled negative cases exist here, so precision and F1 are not estimated.",
                            "Not detected does not mean safe; candidate-only truth is not counted as confirmed.",
                            "A conflicting or unsupported final verdict is never counted as detected."],
            "scenarios": rows}


def markdown(result: dict[str, Any]) -> str:
    s = result["summary"]
    lines = ["# Verdict multi-service evaluation", "", "Held-out comparison after the scan; ground truth was not supplied to scanners or AI.", "",
             f"Confirmed cases detected: **{s['detected']}/{s['confirmed_ground_truth']}** ({s['positive_case_recall']:.1%}). "
             f"Needs review: **{s['needs_review_confirmed']}**. Not detected: **{s['not_detected_confirmed']}**. "
             f"Candidate-only cases: **{s['candidate_only']}** (excluded).", "",
             "| Scenario | Category | Truth | Result | Reviewed signal |", "|---|---|---|---|---|"]
    for row in result["scenarios"]:
        signals = ", ".join(item["group_id"] for item in row["signals"]) or "—"
        lines.append(f"| {row['id']} | {row['category']} | {row['ground_truth']} | {row['status']} | {signals} |")
    lines += ["", "## Interpretation", ""] + [f"- {item}" for item in result["limitations"]]
    lines += ["", "## Case notes", ""]
    lines += [f"- **{row['id']} — {row['status']}:** {row['reason']}" for row in result["scenarios"]]
    return "\n".join(lines) + "\n"


def html_report(result: dict[str, Any]) -> str:
    """Evaluation page in the same style (and dark/light switch) as the run report."""
    s = result["summary"]
    rows = [{"id": row["id"], "status": row["status"],
             "cells": [row["category"], row["ground_truth"], ", ".join(item["group_id"] for item in row["signals"]) or "—"],
             "details": [("Reason", row["reason"]), ("Reviewed signal(s)", [item["group_id"] for item in row["signals"]] or ["None"])]}
            for row in result["scenarios"]]
    return render_evaluation(
        title="Multi-service",
        headline="Confirmed cases found by the saved scan",
        intro="Held-out comparison after scanning. Ground truth was not supplied to scanners or AI.",
        gauge=(s["detected"], s["confirmed_ground_truth"], "confirmed cases detected"),
        donut=[("Detected", s["detected"], "var(--mint)"), ("Needs review", s["needs_review_confirmed"], "var(--medium)"),
               ("Not detected", s["not_detected_confirmed"], "var(--high)"), ("Excluded", s["candidate_only"], "var(--ln)")],
        donut_unit="scenarios", table_title=f"All {len(result['scenarios'])} scenarios",
        columns=["Scenario", "Category", "Truth", "Reviewed signal"], outcome_header="Result", rows=rows,
        sections=[("Interpretation", result["limitations"])])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir", type=Path, help="Saved scanner/DAST/AI outputs")
    parser.add_argument("--review-dir", type=Path, help="Saved triage and final review; defaults to scan_dir")
    parser.add_argument("--output-dir", type=Path, help="Defaults to review_dir/evaluation")
    args = parser.parse_args()
    review_dir = args.review_dir or args.scan_dir
    output_dir = args.output_dir or review_dir / "evaluation"
    result = evaluate(read_object(TRUTH), read_object(args.scan_dir / "pre-review-summary.json"),
                      read_object(args.scan_dir / "merged.json"), read_object(args.scan_dir / "ai-discovery.json"),
                      read_object(review_dir / "candidate-triage.json"), read_object(review_dir / "security-review.json"))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evaluation.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "evaluation.md").write_text(markdown(result), encoding="utf-8")
    (output_dir / "evaluation.html").write_text(html_report(result), encoding="utf-8")
    print(json.dumps({"summary": result["summary"], "output": str(output_dir)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

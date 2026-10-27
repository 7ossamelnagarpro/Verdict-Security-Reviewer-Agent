"""Held-out, post-scan audit for the 18-scenario multi-service lab.

Only saved findings and final reviews are read. Never import this module into a
scanner, an AI prompt, or the target application: it contains answer mappings.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any


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
    actual = facts.get("status")
    expected = facts.get("expected_statuses")
    return (source.get("rule_id") == rule
            and (source.get("primary_location") or {}).get("path") == path
            and facts.get("workflow_id") == workflow and facts.get("method") == method
            and type(actual) is int and isinstance(expected, list)
            and all(type(item) is int for item in expected)
            and actual not in expected and False in (facts.get("assertion_results") or []))


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
    s = result["summary"]
    rows = "\n".join(
        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><span class='{}'>{}</span></td><td>{}</td><td>{}</td></tr>".format(
            escape(row["id"]), escape(row["category"]), escape(row["ground_truth"]),
            escape(row["status"]), escape(row["status"].replace("_", " ")),
            escape(", ".join(item["group_id"] for item in row["signals"]) or "—"), escape(row["reason"]))
        for row in result["scenarios"])
    limitations = "".join(f"<li>{escape(item)}</li>" for item in result["limitations"])
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verdict · Multi-service evaluation</title><style>
body{{margin:0;background:#0b1220;color:#e8f0f6;font:15px system-ui,sans-serif}}main{{max-width:1400px;margin:auto;padding:40px 24px}}
h1{{font-size:30px}}p,li{{color:#b8c9d8;line-height:1.55}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}
.card{{background:#152237;border:1px solid #30445d;border-radius:12px;padding:18px;min-width:170px}}.card strong{{display:block;font-size:28px;color:#80e1c5}}
.scroll{{overflow:auto;border:1px solid #30445d;border-radius:12px}}table{{width:100%;border-collapse:collapse;min-width:1050px}}
th,td{{text-align:left;padding:12px;border-bottom:1px solid #26384c;vertical-align:top}}th{{background:#152237}}tr:nth-child(even){{background:#101c2e}}
code{{color:#c7e4ff}}span.detected{{color:#80e1c5}}span.needs_review{{color:#ffd382}}span.not_detected{{color:#ff9c9c}}
</style><main><h1>Multi-service evaluation</h1><p>Held-out comparison after scanning. Ground truth was not supplied to scanners or AI.</p>
<div class="cards"><div class="card"><strong>{s['detected']}/{s['confirmed_ground_truth']}</strong>Detected confirmed cases</div>
<div class="card"><strong>{s['positive_case_recall']:.1%}</strong>Positive-case recall</div>
<div class="card"><strong>{s['needs_review_confirmed']}</strong>Needs review</div>
<div class="card"><strong>{s['not_detected_confirmed']}</strong>Not detected</div>
<div class="card"><strong>{s['candidate_only']}</strong>Candidate-only, excluded</div></div>
<div class="scroll"><table><thead><tr><th>Scenario</th><th>Category</th><th>Truth</th><th>Result</th><th>Reviewed signal</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Interpretation</h2><ul>{limitations}</ul></main></html>"""


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

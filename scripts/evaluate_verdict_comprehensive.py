"""Held-out, post-scan audit of the comprehensive lab's known positive cases.

This answer map must never be imported by a scanner or supplied to an AI prompt.
Only exact rule/location evidence in saved artifacts counts as a signal.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from security_reviewer_v2.reporting.evaluation_html import render_evaluation


ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "benchmark" / "verdict-comprehensive-ground-truth.json"
POSITIVE_VERDICTS = {"confirmed_vulnerability", "likely_vulnerability"}

# Each signature is (rule ID, exact primary path, optional inclusive line range).
# A missing signature means this saved run has no independently attributable signal.
SIGNATURES: dict[str, tuple[tuple[str, str, tuple[int, int] | None], ...]] = {
    "C01": (("workflow.order_owner.3", "/orders/{{order_id}}", None),),
    "C02": (("workflow.profile_owner.2", "/profiles/{{other_id}}", None),),
    "C03": (("py/sql-injection", "api/extra.py", (119, 119)),),
    "C04": (("py/sql-injection", "api/extra.py", (144, 144)),),
    "C05": (("py/reflective-xss", "api/extra.py", (145, 145)),),
    "C07": (("workflow.admin_users.2", "/admin/users", None),),
    "C08": (("py/path-injection", "api/extra.py", (212, 215)),),
    "C11": (("workflow.debug_access.1", "/debug/config", None),),
    "C14": (("python.fastapi.security.wildcard-cors.wildcard-cors", "api/app.py", (26, 26)),),
    "C18": (("workflow.owner_assignment.2", "/orders", None),
             ("workflow.order_initial_state.1", "/orders", None),
             ("workflow.negative_price.1", "/orders", None)),
    "C19": (("workflow.invoice_owner.3", "/invoices/{{invoice_id}}", None),),
    "C20": (("workflow.price_catalog.1", "/orders", None),),
    "C21": (("workflow.coupon_bounds.2", "/orders/{{order_id}}/apply-coupon", None),),
    "C22": (("workflow.payment_replay.3", "/orders/{{order_id}}/pay", None),),
    "C23": (("workflow.paid_cancel.3", "/orders/{{order_id}}/cancel", None),),
    "C24": (("workflow.excessive_data.1", "/me", None),),
    "C25": (("workflow.worker_role.1", "/jobs", None),),
    "C26": (("workflow.webhook_destination.1", "/webhooks", None),),
    "C27": (("py/clear-text-logging-sensitive-data", "api/app.py", (137, 137)),),
    "N01": (("workflow.reset_replay.3", "/auth/reset/confirm", None),),
    "N02": (("py/url-redirection", "api/extra.py", (617, 617)),),
    "N03": (("workflow.unsigned_hook.1", "/integrations/hook", None),),
    "N04": (("workflow.nested_note.1", "/orders/1/notes/2", None),),
    "N05": (("workflow.stale_role.3", "/admin/token-report", None),),
    "N07": (("zap.10038", "/view", None),),
}


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _matches(case_id: str, source: dict[str, Any]) -> bool:
    location = source.get("primary_location") or {}
    for rule, path, line_range in SIGNATURES.get(case_id, ()):
        if source.get("rule_id") != rule or location.get("path") != path:
            continue
        line = location.get("start_line")
        if line_range is not None and (type(line) is not int or not line_range[0] <= line <= line_range[1]):
            continue
        if rule.startswith("workflow."):
            facts = source.get("runtime_evidence") or {}
            expected = facts.get("expected_statuses") or []
            actual = facts.get("status")
            if not (type(actual) is int and all(type(item) is int for item in expected)
                    and False in (facts.get("assertion_results") or [])):
                continue
        return True
    return False


def evaluate(truth: dict[str, Any], scan: dict[str, Any], merged: dict[str, Any],
             triage: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    if truth.get("target") != "targets/verdict-comprehensive-lab":
        raise ValueError("Wrong benchmark fixture")
    if Path(str(scan.get("project", ""))).name.lower() != "verdict-comprehensive-lab":
        raise ValueError("Saved scan is for a different target")
    if merged.get("status") not in {"complete", "completed"} or review.get("status") != "completed":
        raise ValueError("Complete merged findings and final review are required")
    findings = {item["merged_finding_id"]: item for item in merged.get("findings", [])}
    groups = {item["group_id"]: item for item in triage.get("groups", [])}
    reviews = {item["candidate_id"]: item for item in review.get("reviews", [])}
    if set(reviews) != set(groups):
        raise ValueError("Final review does not cover all triage groups")
    for group_id, group in groups.items():
        scanner_ids = set(group.get("scanner_finding_ids", []))
        if not scanner_ids <= set(findings):
            raise ValueError(f"Unknown scanner evidence in group {group_id}")
        expected_sources = scanner_ids | set(group.get("candidate_ids", []))
        if set(reviews[group_id].get("source_ids", [])) != expected_sources:
            raise ValueError(f"Review sources do not match group {group_id}")
    cases = truth.get("cases", [])
    if len(cases) != 63 or len({item["id"] for item in cases}) != 63:
        raise ValueError("Expected 63 distinct benchmark cases")
    rows = []
    for case in cases:
        signals = []
        if case["label"] == "confirmed_vulnerability":
            for group_id, group in groups.items():
                for finding_id in group.get("scanner_finding_ids", []):
                    finding = findings[finding_id]
                    sources = finding.get("source_findings") or [finding.get("canonical_finding")]
                    for source in sources:
                        if not isinstance(source, dict) or not _matches(case["id"], source):
                            continue
                        location = source.get("primary_location") or {}
                        signals.append({"group_id": group_id, "finding_id": finding_id,
                                        "source_finding_id": source.get("finding_id"),
                                        "scanner": source.get("scanner"), "rule_id": source.get("rule_id"),
                                        "path": location.get("path"), "line": location.get("start_line"),
                                        "verdict": reviews[group_id]["verdict"]})
        if case["label"] != "confirmed_vulnerability":
            status = "excluded" if case["label"] == "candidate_only" else "safe_control_not_assessed"
        elif not signals:
            status = "not_detected"
        elif all(item["verdict"] in POSITIVE_VERDICTS for item in signals):
            status = "detected"
        else:
            status = "needs_review"
        signatures = [{"rule_id": rule, "path": path, "line_range": line_range}
                      for rule, path, line_range in SIGNATURES.get(case["id"], ())]
        rows.append({"id": case["id"], "category": case["category"], "location": case["location"],
                     "ground_truth": case["label"], "severity": case.get("severity"),
                     "source": case.get("source"), "expected_behavior": case.get("evidence"),
                     "proof_ref": case.get("proof_ref"), "origin": case.get("origin", []),
                     "status": status, "expected_signatures": signatures, "signals": signals})
    positive = [row for row in rows if row["ground_truth"] == "confirmed_vulnerability"]
    detected = sum(row["status"] == "detected" for row in positive)
    return {"schema_version": "1.1", "target": truth["target"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_provenance": {"project": scan.get("project"), "scan_status": scan.get("status"),
                                "adapters": scan.get("adapter_ids", []),
                                "dast_requirement": scan.get("dast_requirement"),
                                "sast_requirement": scan.get("sast_requirement"),
                                "scanner_requirement": scan.get("scanner_requirement"),
                                "ai_discovery": scan.get("ai_discovery"),
                                "security_review": scan.get("security_review"),
                                "endpoint_coverage": scan.get("endpoint_coverage"),
                                "coverage_gaps": scan.get("coverage_gaps", []),
                                "merged_findings": len(findings), "reviewed_groups": len(groups)},
            "summary": {"known_positive_cases": len(positive), "detected": detected,
                        "needs_review": sum(row["status"] == "needs_review" for row in positive),
                        "not_detected": sum(row["status"] == "not_detected" for row in positive),
                        "positive_case_recall_lower_bound": round(detected / len(positive), 4),
                        "safe_controls_not_assessed": sum(row["status"] == "safe_control_not_assessed" for row in rows),
                        "candidate_only_excluded": sum(row["status"] == "excluded" for row in rows),
                        "precision": None, "f1": None},
            "limitations": ["Held-out comparison of one saved run; the benchmark was not supplied to scanning or AI.",
                            "Only exact source signatures and positive reviewed verdicts count as detected.",
                            "A case without a defined signature remains not detected by this strict audit, even if a broader finding might deserve manual review.",
                            "Needs-review evidence is not counted as detected; not-detected does not mean safe.",
                            "Safe controls need a separate specificity audit; precision and F1 are not estimated.",
                            "One case may generate several observations, so issue-group counts are not vulnerability counts."],
            "cases": rows}


def markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    provenance = result["scan_provenance"]
    lines = ["# Comprehensive lab · held-out scan audit", "",
             "Ground truth was used only after the saved scan and review were complete.", "",
             f"Known-positive cases detected: **{summary['detected']}/{summary['known_positive_cases']}** "
             f"({summary['positive_case_recall_lower_bound']:.1%} conservative lower bound). "
             f"Needs review: **{summary['needs_review']}**. Not detected by exact signal: **{summary['not_detected']}**.",
             f"Safe controls not assessed for specificity: **{summary['safe_controls_not_assessed']}**. "
             f"Candidate-only exclusions: **{summary['candidate_only_excluded']}**.", "",
             "Precision and F1: **not calculated** (unmatched findings and safe controls need manual adjudication).", "",
             "## Scan provenance", "",
             f"- Target: `{provenance['project']}`", f"- Scan status: `{provenance['scan_status']}`",
             f"- Scanners: {', '.join(provenance['adapters']) or 'none'}",
             f"- Merged findings: {provenance['merged_findings']}; reviewed groups: {provenance['reviewed_groups']}",
             f"- DAST required/satisfied: {provenance['dast_requirement']}",
             f"- SAST required/satisfied: {provenance['sast_requirement']}",
             f"- AI discovery: {provenance['ai_discovery']}",
             f"- AI review: {provenance['security_review']}",
             f"- Endpoint coverage: {provenance['endpoint_coverage']}", "",
             "## Recorded coverage gaps", ""]
    lines.extend(f"- {gap}" for gap in provenance["coverage_gaps"])
    if not provenance["coverage_gaps"]:
        lines.append("- None recorded")
    lines.append("")
    for label, title in (("confirmed_vulnerability", "Known-positive cases"),
                         ("safe_control", "Safe controls — specificity not assessed"),
                         ("candidate_only", "Excluded candidate")):
        lines += [f"## {title}", ""]
        for row in result["cases"]:
            if row["ground_truth"] != label:
                continue
            lines += [f"### {row['id']} · {row['category']} — {row['status']}", "",
                      f"- Location: `{row['location']}`", f"- Severity: {row['severity'] or 'not assigned'}",
                      f"- Expected behavior / ground-truth evidence: {row['expected_behavior'] or 'not recorded'}",
                      f"- Evidence source: {row['source'] or 'not recorded'}; proof: `{row['proof_ref'] or 'not recorded'}`",
                      f"- Origin: {', '.join(row['origin']) or 'not recorded'}"]
            if row["expected_signatures"]:
                lines.append("- Exact audit signatures: " + "; ".join(
                    f"`{item['rule_id']}` at `{item['path']}`" +
                    (f" lines {item['line_range'][0]}–{item['line_range'][1]}" if item['line_range'] else "")
                    for item in row["expected_signatures"]))
            else:
                lines.append("- Exact audit signatures: none defined")
            if row["signals"]:
                lines.append("- Matched reviewed signals:")
                lines.extend(f"  - `{item['group_id']}` / `{item['finding_id']}`: "
                             f"{item['scanner'] or 'unknown scanner'} · `{item['rule_id']}` at "
                             f"`{item['path']}`; review verdict `{item['verdict']}`"
                             for item in row["signals"])
            else:
                lines.append("- Matched reviewed signals: none")
            lines.append("")
    lines += ["## Limits", ""] + [f"- {item}" for item in result["limitations"]]
    return "\n".join(lines) + "\n"


def html_report(result: dict[str, Any]) -> str:
    """Evaluation page in the same style (and dark/light switch) as the run report."""
    summary, provenance = result["summary"], result["scan_provenance"]
    discovery, review = provenance["ai_discovery"] or {}, provenance["security_review"] or {}
    rows = []
    for row in result["cases"]:
        rows.append({
            "id": row["id"], "status": row["status"],
            "cells": [(row["category"], row["location"]), row["ground_truth"].replace("_", " "), row["severity"] or "not assigned"],
            "details": [
                ("Expected behavior", row["expected_behavior"]), ("Proof", row["proof_ref"]),
                ("Source / origin", f"{row['source'] or 'not recorded'}; origin: {', '.join(row['origin']) or 'not recorded'}"),
                ("Audit signatures", [f"{item['rule_id']} @ {item['path']}" for item in row["expected_signatures"]] or ["No exact signature defined"]),
                ("Matched evidence", [f"{item['scanner'] or 'unknown'} / {item['rule_id']} @ {item['path']} → {item['verdict']} (group {item['group_id']})"
                                      for item in row["signals"]] or ["No exact reviewed signal"]),
            ],
        })
    return render_evaluation(
        title="Comprehensive lab · held-out evaluation",
        headline=f"{summary['detected']}/{summary['known_positive_cases']} known-positive cases detected",
        intro="Ground truth was used only after the saved scan and review were complete. This is not a claim of exhaustive vulnerability coverage.",
        cards=[(f"{summary['detected']}/{summary['known_positive_cases']}", "Detected known-positive cases"),
               (summary["needs_review"], "Need review"), (summary["not_detected"], "No exact reviewed signal"),
               (summary["safe_controls_not_assessed"], "Safe controls not audited")],
        notes=["Precision and F1 are not calculated: safe controls and unmatched findings require manual adjudication. "
               "A missing exact match does not prove the application is safe."],
        provenance=[("Project", provenance["project"]), ("Scan status", provenance["scan_status"]),
                    ("Scanners", ", ".join(provenance["adapters"])),
                    ("Findings", f"{provenance['merged_findings']} merged · {provenance['reviewed_groups']} reviewed groups"),
                    ("AI discovery", f"{discovery.get('provider', 'unknown')} / {discovery.get('model', 'unknown')}"),
                    ("AI review", review.get("status", "unknown")), ("Coverage gaps", len(provenance["coverage_gaps"]))],
        donut=[("Detected", summary["detected"], "var(--mint)"), ("Needs review", summary["needs_review"], "var(--medium)"),
               ("No exact signal", summary["not_detected"], "var(--high)"),
               ("Safe controls", summary["safe_controls_not_assessed"], "var(--low)")],
        table_title=f"All {len(result['cases'])} benchmark cases",
        columns=["Case", "Category / location", "Ground truth", "Severity"], outcome_header="Outcome",
        rows=rows,
        sections=[("Recorded coverage gaps", provenance["coverage_gaps"]), ("Limits", result["limitations"])])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir", type=Path)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(_read(TRUTH), _read(args.scan_dir / "pre-review-summary.json"),
                      _read(args.scan_dir / "merged.json"),
                      _read(args.review_dir / "candidate-triage.json"),
                      _read(args.review_dir / "security-review.json"))
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "evaluation.md").write_text(markdown(result), encoding="utf-8")
    (args.output_dir / "evaluation.html").write_text(html_report(result), encoding="utf-8")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()

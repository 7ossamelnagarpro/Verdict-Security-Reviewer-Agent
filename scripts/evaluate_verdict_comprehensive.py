"""Held-out, post-scan audit of the comprehensive lab's known positive cases.

This answer map must never be imported by a scanner or supplied to an AI prompt.
Only exact rule/location evidence in saved artifacts counts as a signal.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from security_reviewer_v2.reporting.evaluation_html import render_evaluation
from security_reviewer_v2.reporting.evaluation_precision import audit, load_handlers, source_origin
from security_reviewer_v2.reporting.view import friendly_name


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
            expected, results = facts.get("expected_statuses") or [], facts.get("assertion_results")
            # The workflow scanner emits a workflow.* finding only for a confirmed violation. Runs saved before the
            # normalizer kept assertion details carry just the HTTP status: accept those, never a recorded pass.
            if not (type(facts.get("status")) is int and all(type(item) is int for item in expected)
                    and (results is None or False in results)):
                continue
        return True
    return False


def _normalize_path_template(path: str) -> str:
    """``/orders/{{order_id}}`` (ground truth), ``/orders/{order_id}`` (route-index style), and a
    concrete, already-resolved ``/orders/5`` (what the Penetration Agent actually tested) all become
    ``/orders/{}`` — collapsing both placeholder spellings AND any purely numeric path segment onto the
    same wildcard is what lets a ground-truth signature be compared against a real tested endpoint."""
    collapsed = re.sub(r"\{\{?[^{}]+\}\}?", "{}", path or "")
    return "/".join("{}" if segment.isdigit() else segment for segment in collapsed.split("/"))


def _penetration_agent_signals(case_id: str, penetration_test: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Independent of any scanner rule_id: a case counts as detected this way only when the Penetration
    Agent itself reached ``exploitation_confirmed`` for a candidate whose own tested endpoint matches this
    case's known path — i.e. the agent actually exploited it, not merely that some tool flagged it."""
    if not isinstance(penetration_test, dict):
        return []
    known_paths = {_normalize_path_template(path) for _rule, path, _lines in SIGNATURES.get(case_id, ())}
    if not known_paths:
        return []
    signals = []
    for result in penetration_test.get("results", []) or []:
        if not isinstance(result, dict) or result.get("outcome") != "exploitation_confirmed":
            continue
        attempts = result.get("attempts") or []
        endpoint = attempts[-1].get("target_endpoint") if attempts else None
        if endpoint and _normalize_path_template(endpoint) in known_paths:
            signals.append({"group_id": None, "finding_id": None, "source_finding_id": result.get("candidate_id"),
                            "scanner": None, "rule_id": None, "path": endpoint, "line": None,
                            "origin": "penetration_agent", "verdict": "confirmed_vulnerability"})
    return signals


def evaluate(truth: dict[str, Any], scan: dict[str, Any], merged: dict[str, Any],
             triage: dict[str, Any], review: dict[str, Any], *, source_root: Path | None = None,
             discovery: dict[str, Any] | None = None,
             penetration_test: dict[str, Any] | None = None) -> dict[str, Any]:
    """Strict signature audit; with ``source_root`` it also measures safe-control specificity and precision bounds.

    ``source_root`` is the audited application's source (never the answer key); ``discovery`` is the saved AI
    discovery result, used to place AI candidates on routes. ``penetration_test`` is the saved
    ``dynamic-penetration-test.json``: a case that no scanner/workflow signature reaches can still be counted
    as detected when the Penetration Agent independently reached ``exploitation_confirmed`` on that exact
    endpoint — this is tracked as its own distinct origin (``summary.detected_via_penetration_agent``), never
    silently merged into the strict scanner-signature count, so the two remain separately auditable.
    """
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
    strict_matches: dict[str, set[str]] = {}
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
                                        "origin": source_origin(source), "verdict": reviews[group_id]["verdict"]})
                        strict_matches.setdefault(group_id, set()).add(case["id"])
            signals.extend(_penetration_agent_signals(case["id"], penetration_test))
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
                     "status": status, "expected_signatures": signatures, "signals": signals,
                     "has_signature": bool(signatures),
                     "origins": sorted({item["origin"] for item in signals})})
    positive = [row for row in rows if row["ground_truth"] == "confirmed_vulnerability"]
    detected = sum(row["status"] == "detected" for row in positive)
    # Cases detected ONLY via the Penetration Agent's own exploitation_confirmed result (no independent
    # scanner/workflow signature) — tracked separately so this never gets silently folded into, or
    # mistaken for, the strict scanner-signature count above.
    detected_via_penetration_agent = sum(
        row["status"] == "detected" and "penetration_agent" in row["origins"]
        and not (set(row["origins"]) - {"penetration_agent"})
        for row in positive
    )
    result = {"schema_version": "1.1", "target": truth["target"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_provenance": {"project": scan.get("project"), "scan_status": scan.get("status"),
                                "adapters": scan.get("adapter_ids", []),
                                "dast_requirement": scan.get("dast_requirement"),
                                "sast_requirement": scan.get("sast_requirement"),
                                "scanner_requirement": scan.get("scanner_requirement"),
                                "ai_discovery": scan.get("ai_discovery"),
                                # The audit above only runs on a completed review, so report THAT review. The pre-review
                                # summary was written before the review stage and still says "partial".
                                "security_review": {**(scan.get("security_review") or {}), "status": review.get("status"),
                                                    "reviewed_groups": len(reviews), "expected_groups": len(groups)},
                                "endpoint_coverage": scan.get("endpoint_coverage"),
                                "coverage_gaps": scan.get("coverage_gaps", []),
                                "merged_findings": len(findings), "reviewed_groups": len(groups)},
            "summary": {"known_positive_cases": len(positive), "detected": detected,
                        "detected_via_penetration_agent": detected_via_penetration_agent,
                        "needs_review": sum(row["status"] == "needs_review" for row in positive),
                        "not_detected": sum(row["status"] == "not_detected" for row in positive),
                        "positive_case_recall_lower_bound": round(detected / len(positive), 4),
                        "safe_controls_not_assessed": sum(row["status"] == "safe_control_not_assessed" for row in rows),
                        "candidate_only_excluded": sum(row["status"] == "excluded" for row in rows),
                        "precision": None, "f1": None},
            "limitations": ["Held-out comparison of one saved run; the benchmark was not supplied to scanning or AI.",
                            "Only exact source signatures and positive reviewed verdicts count as detected, "
                            "OR the Penetration Agent independently reaching exploitation_confirmed on that "
                            "exact endpoint; the number of detected cases that rest only on that second path is listed "
                            "under 'Detections by origin'.",
                            "A case without a defined signature remains not detected by this strict audit, even if a broader finding might deserve manual review.",
                            "Needs-review evidence is not counted as detected; not-detected does not mean safe.",
                            "Safe controls need a separate specificity audit; precision and F1 are not estimated.",
                            "One case may generate several observations, so issue-group counts are not vulnerability counts."],
            "cases": rows}
    if source_root is not None:
        candidates = {item["candidate_id"]: item for item in (discovery or {}).get("candidates", [])
                      if isinstance(item, dict) and "candidate_id" in item}
        _add_precision_audit(result, cases=cases, groups=groups, reviews=reviews, findings=findings,
                             candidates=candidates, strict_matches=strict_matches, handlers=load_handlers(source_root),
                             discovery=discovery)
    return result


_DISCOVERY_USAGE_KEYS = ("provider_calls", "batches", "retry_count", "rate_limit_wait_seconds", "wall_seconds",
                         "total_time", "total_tokens", "duplicate_candidates_merged")


def _brief(group: dict[str, Any]) -> dict[str, Any]:
    return {key: group[key] for key in ("group_id", "verdict", "severity", "title", "origins", "routes")}


def _add_precision_audit(result: dict[str, Any], *, cases: list[dict[str, Any]], groups: dict[str, Any],
                         reviews: dict[str, Any], findings: dict[str, Any], candidates: dict[str, Any],
                         strict_matches: dict[str, set[str]], handlers: list[Any],
                         discovery: dict[str, Any] | None) -> None:
    """Add specificity, precision bounds, detection origin and verdict calibration to ``result`` (in place)."""
    extra = audit(cases=cases, handlers=handlers, groups=groups, reviews=reviews, findings=findings,
                  candidates=candidates, strict_matches=strict_matches)
    rows, summary = result["cases"], result["summary"]
    for row in rows:
        if row["ground_truth"] == "safe_control":
            control = extra["safe_controls"][row["id"]]
            row["status"], row["flagged_by"] = f"safe_control_{control['status']}", control["flagged_by"]
        elif row["ground_truth"] == "confirmed_vulnerability":
            row["endpoint_findings"] = [_brief(item) for item in extra["endpoint_groups"].get(row["id"], [])]
    positive = [row for row in rows if row["ground_truth"] == "confirmed_vulnerability"]
    unscored = [row["id"] for row in positive if not row["has_signature"]]
    ai_on_endpoint = [row["id"] for row in positive if row["status"] != "detected"
                      and any("ai_discovery" in item["origins"] for item in row["endpoint_findings"])]
    summary.update(extra["summary"])
    summary["safe_controls_not_assessed"] = summary["safe_controls_not_assessable"]
    summary["detections_by_origin"] = dict(Counter("+".join(row["origins"]) or "none"
                                                   for row in positive if row["status"] == "detected"))
    summary["cases_without_signature"] = unscored
    summary["not_detected_without_signature"] = sum(row["status"] == "not_detected" and not row["has_signature"] for row in positive)
    summary["ai_discovery_on_undetected_endpoints"] = ai_on_endpoint
    result["adjudication_queue"] = [_brief(item) | {"outcome": item["outcome"], "known_cases": item["known_cases"]}
                                    for item in extra["groups"]
                                    if item["verdict"] in POSITIVE_VERDICTS and item["outcome"] in ("known_endpoint", "unlabeled")]
    result["outside_scope_findings"] = [_brief(item) for item in extra["groups"]
                                        if item["verdict"] in POSITIVE_VERDICTS and item["outcome"] == "outside_scope"]
    result["safe_control_hits"] = [_brief(item) | {"safe_controls": item["safe_controls"]} for item in extra["groups"]
                                   if item["verdict"] in POSITIVE_VERDICTS and item["outcome"] == "safe_control"]
    usage = (discovery or {}).get("usage") or {}
    result["scan_provenance"]["ai_discovery_usage"] = {key: usage[key] for key in _DISCOVERY_USAGE_KEYS if key in usage}
    result["schema_version"] = "1.2"
    result["limitations"] = [item for item in result["limitations"] if not item.startswith("Safe controls need a separate")] + [
        "Safe-control and precision figures place findings on routes using the lab's source code. A positive finding on a "
        "safe control's route is a false-positive signal that still needs a human check that it is the same issue class.",
        "Precision is reported only as bounds, never as a point estimate. precision_on_labeled counts only the findings the "
        "key can label (matches against safe-control hits, so it is optimistic); precision_lower_bound treats every other "
        "positive finding as wrong (pessimistic); precision_lower_bound_in_scope first sets aside dependency advisories and "
        "header/cookie hardening alerts, which the answer key does not cover. Positive findings that match no case are an "
        "adjudication queue, because the answer key is not exhaustive.",
        "AI-discovery candidates are never counted as detections here; one on a known endpoint is listed for adjudication, "
        "because its issue class is not verified against the case.",
        "A clean safe control means no positive finding of its issue class landed on its route; it does not prove the "
        "scan exercised that route, so read specificity together with the recorded endpoint coverage.",
        "Cases with no defined signature cannot be credited by this audit at all, whatever the scan found."]


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _signal_text(item: dict[str, Any]) -> str:
    """One matched signal in words. A Penetration Agent signal has no scanner and no review group by design."""
    if item.get("origin") == "penetration_agent":
        return (f"Penetration Agent reproduced the issue at {item['path']} (exploitation_confirmed, candidate "
                f"{item.get('source_finding_id') or 'n/a'}) \u2192 counted as detected; this signal has no scanner rule or review group")
    return (f"{item['scanner'] or 'unknown'} / {item['rule_id']} @ {item['path']} \u2192 {item['verdict']} "
            f"(group {item['group_id']})")


def _finding_line(item: dict[str, Any]) -> str:
    where = ", ".join(item["routes"]) or "no route resolved"
    near = f" · near known case {', '.join(item['known_cases'])}" if item.get("known_cases") else ""
    return (f"{item['verdict'].replace('_', ' ')} · {item.get('severity') or 'severity n/a'} · {item['title']} — {where} · "
            f"origin: {', '.join(item['origins']) or 'unknown'} · group {item['group_id']}{near}")


def _audit_headline(summary: dict[str, Any]) -> list[str]:
    """Plain-language summary lines for an audited result (precision bounds, specificity, scoring gaps)."""
    return [
        f"Safe controls: **{summary['safe_controls_clean']} clean**, **{summary['safe_controls_flagged']} flagged**, "
        f"{summary['safe_controls_not_assessable']} not assessable (specificity {_percent(summary['safe_control_specificity'])}).",
        f"Positive findings: **{summary['positive_groups']}** — matched to a known case {summary['matched_groups']}, on a known "
        f"case's endpoint (unverified) {summary['known_endpoint_groups']}, on a safe control {summary['safe_control_groups']}, "
        f"outside the answer key's scope {summary['outside_scope_groups']}, unlabeled {summary['unlabeled_groups']}.",
        f"Precision bounds (not a point estimate): labeled-only {_percent(summary['precision_on_labeled'])} (optimistic), "
        f"in-scope lower bound {_percent(summary['precision_lower_bound_in_scope'])}, "
        f"strict lower bound {_percent(summary['precision_lower_bound'])} (pessimistic).",
        f"{summary['not_detected_without_signature']} of {summary['not_detected']} not-detected cases have no signature at all, so this "
        "audit could never credit them.", ""]


def _audit_sections(result: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Sections shared by the markdown and HTML renderers; empty for an unaudited result."""
    if "adjudication_queue" not in result:
        return []
    summary = result["summary"]
    calibration = summary["verdict_calibration"]
    usage = result["scan_provenance"].get("ai_discovery_usage") or {}
    return [
        ("Detections by origin (scanner signal, dynamic test, penetration agent)",
         [f"{origin.replace('+', ' + ')}: {count} case(s)" for origin, count in summary["detections_by_origin"].items()]
         + [f"Detected ONLY because the Penetration Agent reproduced it (no scanner/workflow signature): "
            f"{summary['detected_via_penetration_agent']} case(s)"]),
        ("Verdict calibration (how each outcome class was judged)",
         [f"{outcome.replace('_', ' ')}: " + ", ".join(f"{verdict.replace('_', ' ')} {count}" for verdict, count in counts.items())
          for outcome, counts in calibration.items()]),
        ("Cases the strict audit cannot score (no signature defined)", summary["cases_without_signature"]),
        ("AI discovery on endpoints of undetected cases (issue class not verified)", summary["ai_discovery_on_undetected_endpoints"]),
        ("Adjudication queue — positive findings the key cannot label", [_finding_line(item) for item in result["adjudication_queue"]]),
        ("Safe-control hits — positive findings on a safe control's route", [_finding_line(item) for item in result["safe_control_hits"]]),
        ("Outside the answer key's scope (dependency advisories, header/cookie hardening)",
         [_finding_line(item) for item in result["outside_scope_findings"]]),
        ("AI discovery cost", [f"{key}: {value}" for key, value in usage.items()]),
    ]


def markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    provenance = result["scan_provenance"]
    lines = ["# Comprehensive lab · held-out scan audit", "",
             "Ground truth was used only after the saved scan and review were complete.", "",
             f"Known-positive cases detected: **{summary['detected']}/{summary['known_positive_cases']}** "
             f"({summary['positive_case_recall_lower_bound']:.1%} conservative lower bound), of which "
             f"**{summary['detected_via_penetration_agent']}** rest only on the Penetration Agent's own "
             f"exploitation_confirmed result (no independent scanner/workflow signature). "
             f"Needs review: **{summary['needs_review']}**. Not detected by exact signal: **{summary['not_detected']}**.",
             *(_audit_headline(summary) if "adjudication_queue" in result else
               [f"Safe controls not assessed for specificity: **{summary['safe_controls_not_assessed']}**. "
                f"Candidate-only exclusions: **{summary['candidate_only_excluded']}**.", "",
                "Precision and F1: **not calculated** (unmatched findings and safe controls need manual adjudication).", ""]),
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
                         ("safe_control", "Safe controls — specificity audit" if "adjudication_queue" in result
                          else "Safe controls — specificity not assessed"),
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
            if "origins" in row and row["ground_truth"] == "confirmed_vulnerability" and row["signals"]:
                lines.append(f"- Detection origin: {', '.join(row['origins'])}")
            if row.get("endpoint_findings"):
                lines.append("- Other findings on this endpoint (not counted as detections):")
                lines.extend(f"  - {_finding_line(item)}" for item in row["endpoint_findings"])
            if row.get("flagged_by"):
                lines.append(f"- Flagged by group(s): {', '.join(row['flagged_by'])}")
            if row["signals"]:
                lines.append("- Matched reviewed signals:")
                lines.extend(f"  - {_signal_text(item)}" for item in row["signals"])
            else:
                lines.append("- Matched reviewed signals: none")
            lines.append("")
    for heading, items in _audit_sections(result):
        lines += [f"## {heading}", ""] + ([f"- {item}" for item in items] or ["- None recorded"]) + [""]
    lines += ["## Limits", ""] + [f"- {item}" for item in result["limitations"]]
    return "\n".join(lines) + "\n"


def html_report(result: dict[str, Any]) -> str:
    """Evaluation page in the same style (and dark/light switch) as the run report."""
    summary, provenance = result["summary"], result["scan_provenance"]
    discovery, review = provenance["ai_discovery"] or {}, provenance["security_review"] or {}
    audited = "adjudication_queue" in result
    rows = []
    for row in result["cases"]:
        extra_details = []
        if audited and row["ground_truth"] == "confirmed_vulnerability":
            extra_details = [("Detection origin", ", ".join(row["origins"]) or "no exact signal"),
                             ("Other findings on this endpoint (not counted as detections)",
                              [_finding_line(item) for item in row["endpoint_findings"]] or ["None"])]
            if not row["has_signature"]:
                extra_details.append(("Scoring", "No signature is defined for this case, so the strict audit can never credit it."))
        elif audited and row["ground_truth"] == "safe_control":
            extra_details = [("Specificity audit", row["status"].replace("_", " ")),
                             ("Flagged by", row["flagged_by"] or ["No positive finding of the same issue class on this route"])]
        rows.append({
            "id": row["id"], "status": row["status"],
            "cells": [(row["category"], row["location"]), row["ground_truth"].replace("_", " "), (row["severity"] or "not assigned").replace("_", " ")],
            "details": [
                ("Expected behavior", row["expected_behavior"]), ("Proof", row["proof_ref"]),
                ("Source / origin", f"{row['source'] or 'not recorded'}; origin: {', '.join(row['origin']) or 'not recorded'}"),
                ("Audit signatures", [f"{item['rule_id']} @ {item['path']}" for item in row["expected_signatures"]] or ["No exact signature defined"]),
                ("Matched evidence", [_signal_text(item) for item in row["signals"]] or ["No exact reviewed signal"]),
                *extra_details,
            ],
        })
    return render_evaluation(
        title="Comprehensive lab",
        headline="Known vulnerabilities found by the saved scan",
        intro="Ground truth was used only after the saved scan and review were complete. This is not a claim of exhaustive vulnerability coverage.",
        gauge=(summary["detected"], summary["known_positive_cases"], "known-positive cases detected"),
        notes=([f"Of the {summary['detected']} detected cases, {summary['detected_via_penetration_agent']} rest only on the "
                f"Penetration Agent reproducing the issue on a running test stack; the rest have a scanner, workflow or reviewed signal.",
                f"Precision bounds, not a point estimate: labeled-only {_percent(summary['precision_on_labeled'])} (optimistic), "
                f"in-scope lower bound {_percent(summary['precision_lower_bound_in_scope'])}, strict lower bound "
                f"{_percent(summary['precision_lower_bound'])} (pessimistic). Safe-control specificity: "
                f"{_percent(summary['safe_control_specificity'])} ({summary['safe_controls_flagged']} flagged).",
                f"{summary['not_detected_without_signature']} of {summary['not_detected']} not-detected cases have no signature at all, "
                "so this audit could never credit them. A missing exact match does not prove the application is safe."]
               if audited else
               [f"Of the {summary['detected']} detected cases, {summary['detected_via_penetration_agent']} rest only on the "
                "Penetration Agent reproducing the issue on a running test stack.",
                "Precision and F1 are not calculated: safe controls and unmatched findings require manual adjudication. "
                "A missing exact match does not prove the application is safe."]),
        provenance=[("Project", friendly_name(provenance["project"])), ("Scan status (before AI review)", provenance["scan_status"]),
                    ("Scanners", ", ".join(provenance["adapters"])),
                    ("Findings", f"{provenance['merged_findings']} merged · {provenance['reviewed_groups']} issue groups"),
                    ("AI discovery", f"{discovery.get('provider', 'unknown')} / {discovery.get('model', 'unknown')}"),
                    ("AI review", f"{review.get('status', 'unknown')} · {review.get('reviewed_groups', '?')}/{review.get('expected_groups', '?')} groups"),
                    *([("Precision (in-scope lower bound)", _percent(summary["precision_lower_bound_in_scope"])),
                       ("Safe-control specificity", _percent(summary["safe_control_specificity"])),
                       ("Findings awaiting adjudication", len(result["adjudication_queue"]))] if audited else [])],
        donut=[("Detected", summary["detected"], "var(--mint)"), ("Needs review", summary["needs_review"], "var(--medium)"),
               ("No exact signal", summary["not_detected"], "var(--high)"),
               *([("Safe controls clean", summary["safe_controls_clean"], "var(--low)"),
                  ("Safe controls flagged", summary["safe_controls_flagged"], "var(--medium)"),
                  ("Safe controls not assessable", summary["safe_controls_not_assessable"], "var(--ln)")] if audited else
                 [("Safe controls", summary["safe_controls_not_assessed"], "var(--low)")]),
               ("Candidate only", summary["candidate_only_excluded"], "var(--ln)")],
        table_title=f"All {len(result['cases'])} benchmark cases",
        columns=["Case", "Category / location", "Ground truth", "Severity"], outcome_header="Outcome",
        rows=rows,
        sections=[("Recorded coverage gaps", provenance["coverage_gaps"]), *_audit_sections(result),
                  ("Limits", result["limitations"])])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir", type=Path)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT / "targets" / "verdict-comprehensive-lab",
                        help="the audited application's source, used to place findings on routes (not the answer key)")
    parser.add_argument("--no-precision-audit", action="store_true",
                        help="keep only the strict signature audit (no safe-control or precision analysis)")
    args = parser.parse_args()
    discovery_path = args.scan_dir / "ai-discovery.json"
    penetration_path = args.scan_dir / "dynamic-penetration-test.json"
    audit_root = None if args.no_precision_audit or not args.source_root.is_dir() else args.source_root
    result = evaluate(_read(TRUTH), _read(args.scan_dir / "pre-review-summary.json"),
                      _read(args.scan_dir / "merged.json"),
                      _read(args.review_dir / "candidate-triage.json"),
                      _read(args.review_dir / "security-review.json"),
                      source_root=audit_root, discovery=_read(discovery_path) if discovery_path.is_file() else None,
                      penetration_test=_read(penetration_path) if penetration_path.is_file() else None)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "evaluation.md").write_text(markdown(result), encoding="utf-8")
    (args.output_dir / "evaluation.html").write_text(html_report(result), encoding="utf-8")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()

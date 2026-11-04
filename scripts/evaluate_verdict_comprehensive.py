"""Held-out, post-scan audit of the comprehensive lab's known positive cases.

This answer map must never be imported by a scanner or supplied to an AI prompt.
Only exact rule/location evidence in saved artifacts counts as a signal.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

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
    "C06": (("workflow.stored_comment.2", "/comments", None),),
    "C07": (("workflow.admin_users.2", "/admin/users", None),),
    "C08": (("py/path-injection", "api/extra.py", (212, 215)),),
    "C10": (("workflow.guessed_session.1", "/session/whoami", None),),
    "C11": (("workflow.debug_access.1", "/debug/config", None),),
    "C12": (("workflow.error_detail.1", "/errors/query", None),),
    "C13": (("workflow.login_lockout.4", "/auth/login", None),),
    "C14": (
        ("python.fastapi.security.wildcard-cors.wildcard-cors", "api/app.py", (26, 26)),
    ),
    "C15": (("workflow.upload_disposition.2", "/uploads/{{upload_id}}", None),),
    "C16": (
        ("verdict.python.unsigned-jwt-algorithm", "api/app.py", (90, 90)),
        ("verdict.python.decoded-token-as-identity", "api/app.py", (101, 101)),
    ),
    "C17": (("workflow.unsigned_refresh.1", "/auth/refresh", None),),
    "C18": (
        ("workflow.owner_assignment.2", "/orders", None),
        ("workflow.order_initial_state.1", "/orders", None),
        ("workflow.negative_price.1", "/orders", None),
    ),
    "C19": (("workflow.invoice_owner.3", "/invoices/{{invoice_id}}", None),),
    "C20": (("workflow.price_catalog.1", "/orders", None),),
    "C21": (("workflow.coupon_bounds.2", "/orders/{{order_id}}/apply-coupon", None),),
    "C22": (("workflow.payment_replay.3", "/orders/{{order_id}}/pay", None),),
    "C23": (("workflow.paid_cancel.3", "/orders/{{order_id}}/cancel", None),),
    "C24": (("workflow.excessive_data.1", "/me", None),),
    "C25": (("workflow.worker_role.1", "/jobs", None),),
    "C26": (("workflow.webhook_destination.1", "/webhooks", None),),
    "C27": (("py/clear-text-logging-sensitive-data", "api/app.py", (137, 137)),),
    "C28": (("verdict.yaml.hardcoded-application-secret", "compose.yaml", None),),
    "C29": (("workflow.worker_identity.3", "/admin/jobs", None),),
    "N01": (("workflow.reset_replay.3", "/auth/reset/confirm", None),),
    "N02": (("py/url-redirection", "api/extra.py", (617, 617)),),
    "N03": (("workflow.unsigned_hook.1", "/integrations/hook", None),),
    "N04": (("workflow.nested_note.1", "/orders/1/notes/2", None),),
    "N05": (("workflow.stale_role.3", "/admin/token-report", None),),
    "N06": (
        ("web.cookie-missing-security-attributes", "/session/start", None),
        ("verdict.python.cookie-without-httponly", "api/extra.py", (278, 278)),
    ),
    "N07": (
        ("zap.10038", "/view", None),
        ("web.missing-content-security-policy", "/view", None),
    ),
}


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _matches(case_id: str, source: dict[str, Any]) -> bool:
    location = source.get("primary_location") or {}
    for rule, path, line_range in SIGNATURES.get(case_id, ()):
        actual_rule = source.get("rule_id")
        # Semgrep prefixes local rule IDs with the trusted config path.
        rule_matches = actual_rule == rule or (
            rule.startswith("verdict.")
            and isinstance(actual_rule, str)
            and actual_rule.endswith("." + rule)
        )
        if not rule_matches or location.get("path") != path:
            continue
        line = location.get("start_line")
        if line_range is not None and (
            type(line) is not int or not line_range[0] <= line <= line_range[1]
        ):
            continue
        if rule.startswith("workflow."):
            facts = source.get("runtime_evidence") or {}
            expected = facts.get("expected_statuses") or []
            actual = facts.get("status")
            if not (
                type(actual) is int
                and all(type(item) is int for item in expected)
                and False in (facts.get("assertion_results") or [])
            ):
                continue
        return True
    return False


def _original_observations(
    findings: dict[str, dict[str, Any]],
    groups: dict[str, dict[str, Any]],
    reviews: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    review_links: dict[str, list[dict[str, str]]] = {}
    for group_id, group in groups.items():
        for finding_id in group.get("scanner_finding_ids", []):
            review_links.setdefault(finding_id, []).append(
                {
                    "group_id": group_id,
                    "verdict": str(
                        reviews.get(group_id, {}).get("verdict") or "pending_review"
                    ),
                }
            )

    observations = []
    for finding_id, finding in findings.items():
        canonical = finding.get("canonical_finding") or {}
        location = finding.get("primary_location") or {}
        categories = finding.get("categories") or []
        observations.append(
            {
                "id": finding_id,
                "title": canonical.get("title") or "Untitled observation",
                "source": "DAST" if "dast" in categories else "Static / dependency",
                "scanners": finding.get("scanners") or [],
                "path": location.get("path") or "unknown",
                "line": location.get("start_line"),
                "severity": finding.get("severity") or "unknown",
                "review_groups": review_links.get(finding_id, []),
            }
        )
    return observations


def _markdown_cell(value: Any) -> str:
    compact = " ".join(str(value).split())
    escaped = escape(compact, quote=False)
    return re.sub(r"([\\`*_{}\[\]#+!|>~])", r"\\\1", escaped)


def _coverage_fraction(numerator: Any, denominator: Any) -> dict[str, Any]:
    if (
        type(numerator) is not int
        or type(denominator) is not int
        or denominator <= 0
        or not 0 <= numerator <= denominator
    ):
        return {"measured": False, "covered": None, "total": None, "rate": None}
    return {
        "measured": True,
        "covered": numerator,
        "total": denominator,
        "rate": round(numerator / denominator, 4),
    }


def _source_route_coverage(
    application_map: dict[str, Any] | None, runtime: dict[str, Any]
) -> dict[str, Any]:
    if (
        not isinstance(application_map, dict)
        or application_map.get("status") != "generated"
    ):
        return _coverage_fraction(None, None)
    routes = application_map.get("routes")
    if not isinstance(routes, list) or not routes:
        return _coverage_fraction(None, None)
    observed: set[tuple[str, str]] = set()
    runtime_results = runtime.get("results")
    for result in runtime_results if isinstance(runtime_results, list) else []:
        if (
            isinstance(result, dict)
            and result.get("rule_id") == "web.endpoint-server-error"
            and isinstance(result.get("path"), str)
            and isinstance(result.get("evidence"), dict)
            and type(result["evidence"].get("status")) is int
        ):
            observed.add(("GET", result["path"]))
    workflow = runtime.get("workflow_evidence")
    if isinstance(workflow, dict):
        workflow_records = workflow.get("workflows")
        for record in workflow_records if isinstance(workflow_records, list) else []:
            if not isinstance(record, dict):
                continue
            record_steps = record.get("steps")
            for step in record_steps if isinstance(record_steps, list) else []:
                if (
                    isinstance(step, dict)
                    and isinstance(step.get("method"), str)
                    and isinstance(step.get("path"), str)
                    and type(step.get("http_status")) is int
                ):
                    path = re.sub(r"\{\{[^{}]+\}\}", "1", step["path"])
                    observed.add((step["method"], path.split("?", 1)[0]))
    browser = runtime.get("browser")
    if isinstance(browser, dict):
        browser_requests = browser.get("observed_requests")
        for request in browser_requests if isinstance(browser_requests, list) else []:
            if (
                isinstance(request, dict)
                and isinstance(request.get("method"), str)
                and isinstance(request.get("path"), str)
                and type(request.get("status")) is int
            ):
                observed.add((request["method"], request["path"]))
    unique_routes = {
        (route["method"], route["path"])
        for route in routes
        if isinstance(route, dict)
        and isinstance(route.get("method"), str)
        and isinstance(route.get("path"), str)
    }
    matched = 0
    for method, path in unique_routes:
        pattern = "^" + re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(path)) + "$"
        if any(
            method == seen_method and re.fullmatch(pattern, seen_path)
            for seen_method, seen_path in observed
        ):
            matched += 1
    return _coverage_fraction(matched, len(unique_routes))


def _coverage_metrics(
    scan: dict[str, Any], application_map: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Compute coverage only when a saved run provides a real denominator."""
    endpoint = scan.get("endpoint_coverage")
    endpoint = endpoint if isinstance(endpoint, dict) else {}
    discovery = scan.get("ai_discovery")
    discovery = discovery if isinstance(discovery, dict) else {}
    runtime = scan.get("runtime_evidence")
    runtime = runtime if isinstance(runtime, dict) else {}
    workflow = runtime.get("workflow_evidence")
    workflow = workflow if isinstance(workflow, dict) else {}
    workflow_coverage = workflow.get("coverage")
    workflow_coverage = workflow_coverage if isinstance(workflow_coverage, dict) else {}
    accounts = workflow.get("accounts")
    accounts = accounts if isinstance(accounts, list) else []
    valid_accounts = [
        account
        for account in accounts
        if isinstance(account, dict)
        and isinstance(account.get("actor"), str)
        and account.get("status") in {"verified", "blocked"}
    ]
    roles = {
        account["role"]
        for account in valid_accounts
        if isinstance(account.get("role"), str) and account["role"]
    }
    verified_roles = {
        account["role"]
        for account in valid_accounts
        if account["status"] == "verified" and account.get("role") in roles
    }
    return {
        "source_routes_observed": _source_route_coverage(application_map, runtime),
        "declared_routes_probed": _coverage_fraction(
            endpoint.get("probed_count"), endpoint.get("endpoint_count")
        ),
        "discovery_targets_inspected": _coverage_fraction(
            discovery.get("inspected_targets"), discovery.get("planned_targets")
        ),
        "workflow_steps_executed": _coverage_fraction(
            workflow_coverage.get("executed"), workflow_coverage.get("declared")
        ),
        "test_accounts_verified": _coverage_fraction(
            sum(account["status"] == "verified" for account in valid_accounts),
            len(valid_accounts),
        ),
        "declared_roles_verified": _coverage_fraction(len(verified_roles), len(roles)),
    }


def evaluate(
    truth: dict[str, Any],
    scan: dict[str, Any],
    merged: dict[str, Any],
    triage: dict[str, Any],
    review: dict[str, Any],
    *,
    allow_partial: bool = False,
    application_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if truth.get("target") != "targets/verdict-comprehensive-lab":
        raise ValueError("Wrong benchmark fixture")
    if Path(str(scan.get("project", ""))).name.lower() != "verdict-comprehensive-lab":
        raise ValueError("Saved scan is for a different target")
    if merged.get("status") not in {"complete", "completed"}:
        raise ValueError("Complete merged findings are required")
    provisional = review.get("status") != "completed"
    if provisional and (not allow_partial or review.get("status") != "partial"):
        raise ValueError(
            "Complete final review is required; use diagnostic partial mode explicitly"
        )
    findings = {item["merged_finding_id"]: item for item in merged.get("findings", [])}
    groups = {item["group_id"]: item for item in triage.get("groups", [])}
    reviews = {item["candidate_id"]: item for item in review.get("reviews", [])}
    if not set(reviews) <= set(groups) or (
        not provisional and set(reviews) != set(groups)
    ):
        raise ValueError("Final review does not cover all triage groups")
    for group_id, group in groups.items():
        scanner_ids = set(group.get("scanner_finding_ids", []))
        if not scanner_ids <= set(findings):
            raise ValueError(f"Unknown scanner evidence in group {group_id}")
        expected_sources = scanner_ids | set(group.get("candidate_ids", []))
        if (
            group_id in reviews
            and set(reviews[group_id].get("source_ids", [])) != expected_sources
        ):
            raise ValueError(f"Review sources do not match group {group_id}")
    cases = truth.get("cases", [])
    if len(cases) != 63 or len({item["id"] for item in cases}) != 63:
        raise ValueError("Expected 63 distinct benchmark cases")
    rows = []
    for case in cases:
        signals = []
        signatures = [
            {"rule_id": rule, "path": path, "line_range": line_range}
            for rule, path, line_range in SIGNATURES.get(case["id"], ())
        ]
        if case["label"] == "confirmed_vulnerability":
            for group_id, group in groups.items():
                for finding_id in group.get("scanner_finding_ids", []):
                    finding = findings[finding_id]
                    sources = finding.get("source_findings") or [
                        finding.get("canonical_finding")
                    ]
                    for source in sources:
                        if not isinstance(source, dict) or not _matches(
                            case["id"], source
                        ):
                            continue
                        location = source.get("primary_location") or {}
                        signals.append(
                            {
                                "group_id": group_id,
                                "finding_id": finding_id,
                                "source_finding_id": source.get("finding_id"),
                                "scanner": source.get("scanner"),
                                "rule_id": source.get("rule_id"),
                                "path": location.get("path"),
                                "line": location.get("start_line"),
                                "verdict": reviews[group_id]["verdict"]
                                if group_id in reviews
                                else "pending_review",
                            }
                        )
        if case["label"] != "confirmed_vulnerability":
            status = (
                "excluded"
                if case["label"] == "candidate_only"
                else "safe_control_not_assessed"
            )
        elif not signatures:
            status = "not_mapped"
        elif not signals:
            status = "not_detected"
        elif any(item["verdict"] == "pending_review" for item in signals):
            status = "pending_review"
        elif all(item["verdict"] in POSITIVE_VERDICTS for item in signals):
            status = "detected"
        elif any(item["verdict"] in POSITIVE_VERDICTS for item in signals):
            status = "detected_mixed"
        else:
            status = "needs_review"
        rows.append(
            {
                "id": case["id"],
                "category": case["category"],
                "location": case["location"],
                "ground_truth": case["label"],
                "severity": case.get("severity"),
                "source": case.get("source"),
                "expected_behavior": case.get("evidence"),
                "proof_ref": case.get("proof_ref"),
                "origin": case.get("origin", []),
                "status": status,
                "expected_signatures": signatures,
                "signals": signals,
            }
        )
    positive = [row for row in rows if row["ground_truth"] == "confirmed_vulnerability"]
    detected = sum(row["status"] in {"detected", "detected_mixed"} for row in positive)
    linked_positive_groups = {
        signal["group_id"] for row in positive for signal in row["signals"]
    }
    unattributed_flagged_groups = [
        {
            "group_id": group_id,
            "title": assessment.get("title"),
            "verdict": assessment["verdict"],
            "severity": assessment.get("severity"),
            "source_ids": assessment.get("source_ids", []),
        }
        for group_id, assessment in reviews.items()
        if assessment.get("verdict") in POSITIVE_VERDICTS
        and group_id not in linked_positive_groups
    ]
    return {
        "schema_version": "1.4",
        "target": truth["target"],
        "evaluation_status": "provisional" if provisional else "final",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_provenance": {
            "project": scan.get("project"),
            "scan_status": scan.get("status"),
            "adapters": scan.get("adapter_ids", []),
            "dast_requirement": scan.get("dast_requirement"),
            "sast_requirement": scan.get("sast_requirement"),
            "scanner_requirement": scan.get("scanner_requirement"),
            "ai_discovery": scan.get("ai_discovery"),
            "security_review": {
                "status": review.get("status"),
                "provider": review.get("provider"),
                "model": review.get("model"),
                "review_count": len(reviews),
                "pending_ids": review.get("pending_ids", []),
            },
            "initial_security_review": scan.get("security_review"),
            "endpoint_coverage": scan.get("endpoint_coverage"),
            "coverage_gaps": scan.get("coverage_gaps", []),
            "merged_findings": len(findings),
            "reviewed_groups": len(reviews),
            "total_groups": len(groups),
        },
        "summary": {
            "known_positive_cases": len(positive),
            "detected": detected,
            "needs_review": sum(row["status"] == "needs_review" for row in positive),
            "detected_mixed": sum(
                row["status"] == "detected_mixed" for row in positive
            ),
            "not_detected": sum(row["status"] == "not_detected" for row in positive),
            "not_mapped": sum(row["status"] == "not_mapped" for row in positive),
            "pending_review": sum(
                row["status"] == "pending_review" for row in positive
            ),
            "reviewed_groups": len(reviews),
            "total_groups": len(groups),
            "positive_case_recall_lower_bound": round(detected / len(positive), 4),
            "safe_controls_not_assessed": sum(
                row["status"] == "safe_control_not_assessed" for row in rows
            ),
            "candidate_only_excluded": sum(row["status"] == "excluded" for row in rows),
            "unattributed_flagged_groups": len(unattributed_flagged_groups),
            "precision": None,
            "f1": None,
        },
        "coverage_metrics": _coverage_metrics(scan, application_map),
        "limitations": [
            "Held-out comparison of one saved run; the benchmark was not supplied to scanning or AI.",
            *(
                [
                    "Provisional diagnostic only: AI review is incomplete; do not present these counts as a final evaluation."
                ]
                if provisional
                else []
            ),
            "Only exact source signatures with a positive reviewed verdict count as detected; mixed verdicts are flagged separately.",
            "An unmapped case has no exact audit signature; it is not evidence of a scanner miss.",
            "Needs-review evidence is not counted as detected; not-detected does not mean safe.",
            "Safe controls need a separate specificity audit; precision and F1 are not estimated.",
            "One case may generate several observations, so issue-group counts are not vulnerability counts.",
        ],
        "cases": rows,
        "unattributed_flagged_groups": unattributed_flagged_groups,
        "original_observations": _original_observations(findings, groups, reviews),
    }


def markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    provenance = result["scan_provenance"]
    coverage = result.get("coverage_metrics", {})
    undetected = [
        row
        for row in result["cases"]
        if row["ground_truth"] == "confirmed_vulnerability"
        and row["status"] == "not_detected"
    ]
    lines = [
        "# Comprehensive lab · held-out scan audit",
        "",
        (
            f"Evaluation status: **{result['evaluation_status']}**. Ground truth was used only after the saved scan; "
            "a provisional result must not be presented as a completed evaluation."
        ),
        "",
        (
            f"Known-positive cases detected: **{summary['detected']}/{summary['known_positive_cases']}** "
            f"({summary['positive_case_recall_lower_bound']:.1%} conservative lower bound). "
            f"Mixed verdicts among detected cases: **{summary['detected_mixed']}**. "
            f"Needs review: **{summary['needs_review']}**. Pending AI review: **{summary['pending_review']}**. "
            f"Not mapped: **{summary['not_mapped']}**. No exact signal: **{summary['not_detected']}**."
        ),
        (
            f"Safe controls not assessed for specificity: **{summary['safe_controls_not_assessed']}**. "
            f"Candidate-only exclusions: **{summary['candidate_only_excluded']}**."
        ),
        "",
        "Precision and F1: **not calculated** (unmatched findings and safe controls need manual adjudication).",
        (
            "Review Agent-flagged groups not linked to a known-positive benchmark case: "
            f"**{summary.get('unattributed_flagged_groups', 0)}**. "
            "These require adjudication; they are not automatically false positives."
        ),
        "",
        "## Undetected ground-truth cases",
        "",
        (
            f"The evaluation found **{len(undetected)}** confirmed ground-truth cases "
            "without an exact reviewed signal in this saved run. This is a detection gap, "
            "not proof that the issue is absent from the application."
        ),
        "",
        "| Case | Category | Location | Severity |",
        "| --- | --- | --- | --- |",
    ]
    lines.extend(
        f"| `{row['id']}` | {row['category']} | `{row['location']}` | "
        f"{row['severity'] or 'not assigned'} |"
        for row in undetected
    )
    if not undetected:
        lines.append("| — | None | — | — |")
    lines += [
        "",
        "## Measured coverage",
        "",
        "| Scope | Covered | Total | Rate |",
        "| --- | ---: | ---: | ---: |",
        *(
            f"| {label} | {coverage.get(key, {}).get('covered')} | "
            f"{coverage.get(key, {}).get('total')} | "
            f"{coverage[key]['rate']:.1%} |"
            if coverage.get(key, {}).get("measured")
            else f"| {label} | — | — | Not measured |"
            for key, label in (
                (
                    "source_routes_observed",
                    "Source routes with a recorded runtime response",
                ),
                ("declared_routes_probed", "Declared routes probed"),
                ("discovery_targets_inspected", "Discovery targets inspected"),
                ("workflow_steps_executed", "Workflow steps executed"),
                ("test_accounts_verified", "Test accounts verified"),
                ("declared_roles_verified", "Declared roles verified"),
            )
        ),
        "",
        "These ratios describe execution of the declared scope, not vulnerability detection.",
        "",
        "## Scan provenance",
        "",
        f"- Target: `{provenance['project']}`",
        f"- Initial scan status: `{provenance['scan_status']}`",
        f"- Scanners: {', '.join(provenance['adapters']) or 'none'}",
        (
            f"- Merged findings: {provenance['merged_findings']}; reviewed groups: "
            f"{provenance['reviewed_groups']}/{provenance['total_groups']}"
        ),
        f"- DAST required/satisfied: {provenance['dast_requirement']}",
        f"- SAST required/satisfied: {provenance['sast_requirement']}",
        (
            f"- AI discovery: `{(provenance['ai_discovery'] or {}).get('status', 'unknown')}`; "
            f"requirement satisfied: `{(provenance['ai_discovery'] or {}).get('satisfied', False)}`"
        ),
        (
            f"- Initial AI review: `{(provenance['initial_security_review'] or {}).get('status', 'unknown')}`; "
            f"final review artifact: `{(provenance['security_review'] or {}).get('status', 'unknown')}`"
        ),
        (
            f"- Endpoint coverage: `{(provenance['endpoint_coverage'] or {}).get('status', 'unknown')}`; "
            f"probes: `{(provenance['endpoint_coverage'] or {}).get('probe_count', 'unknown')}`"
        ),
        "",
        "## Recorded coverage gaps",
        "",
    ]
    lines.extend(f"- {gap}" for gap in provenance["coverage_gaps"])
    if not provenance["coverage_gaps"]:
        lines.append("- None recorded")
    lines.append("")
    lines += ["## Review Agent groups awaiting benchmark adjudication", ""]
    for group in result.get("unattributed_flagged_groups", []):
        lines.append(
            f"- `{group['group_id']}` · {group['title'] or 'Untitled'} · "
            f"{group['verdict']} · {group['severity'] or 'unrated'}"
        )
    if not result.get("unattributed_flagged_groups"):
        lines.append("- None recorded")
    lines.append("")
    for label, title in (
        ("confirmed_vulnerability", "Known-positive cases"),
        ("safe_control", "Safe controls — specificity not assessed"),
        ("candidate_only", "Excluded candidate"),
    ):
        lines += [f"## {title}", ""]
        for row in result["cases"]:
            if row["ground_truth"] != label:
                continue
            lines += [
                f"### {row['id']} · {row['category']} — {row['status']}",
                "",
                f"- Location: `{row['location']}`",
                f"- Severity: {row['severity'] or 'not assigned'}",
                f"- Expected behavior / ground-truth evidence: {row['expected_behavior'] or 'not recorded'}",
                f"- Evidence source: {row['source'] or 'not recorded'}; proof: `{row['proof_ref'] or 'not recorded'}`",
                f"- Origin: {', '.join(row['origin']) or 'not recorded'}",
            ]
            if row["expected_signatures"]:
                lines.append(
                    "- Exact audit signatures: "
                    + "; ".join(
                        f"`{item['rule_id']}` at `{item['path']}`"
                        + (
                            f" lines {item['line_range'][0]}–{item['line_range'][1]}"
                            if item["line_range"]
                            else ""
                        )
                        for item in row["expected_signatures"]
                    )
                )
            else:
                lines.append("- Exact audit signatures: none defined")
            if row["signals"]:
                lines.append("- Matched reviewed signals:")
                lines.extend(
                    f"  - `{item['group_id']}` / `{item['finding_id']}`: "
                    f"{item['scanner'] or 'unknown scanner'} · `{item['rule_id']}` at "
                    f"`{item['path']}`; review verdict `{item['verdict']}`"
                    for item in row["signals"]
                )
            else:
                lines.append("- Matched reviewed signals: none")
            lines.append("")
    observations = result.get("original_observations", [])
    lines += [
        f"## Original scanner & DAST observations ({len(observations)})",
        "",
        "Saved normalized signals before Review Agent assessment; these are not benchmark matches or confirmed vulnerabilities.",
        "",
        "| Observation | Source | Scanner | Location | Severity | Review Agent group / verdict |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in observations:
        location = str(item["path"])
        if type(item.get("line")) is int:
            location += f":{item['line']}"
        links = (
            ", ".join(
                f"{link['group_id']} ({link['verdict']})"
                for link in item["review_groups"]
            )
            or "No linked review"
        )
        values = (
            f"{item['title']} [{item['id']}]",
            item["source"],
            ", ".join(str(scanner) for scanner in item["scanners"]) or "unknown",
            location,
            item["severity"],
            links,
        )
        lines.append(
            "| " + " | ".join(_markdown_cell(value) for value in values) + " |"
        )
    lines += ["", "## Limits", ""] + [f"- {item}" for item in result["limitations"]]
    return "\n".join(lines) + "\n"


def html_report(result: dict[str, Any]) -> str:
    summary = result["summary"]
    provenance = result["scan_provenance"]
    coverage = result.get("coverage_metrics", {})
    undetected = [
        row
        for row in result["cases"]
        if row["ground_truth"] == "confirmed_vulnerability"
        and row["status"] == "not_detected"
    ]
    undetected_rows = "".join(
        "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>".format(
            escape(str(row["id"])),
            escape(str(row["category"])),
            escape(str(row["location"])),
            escape(str(row["severity"] or "not assigned")),
        )
        for row in undetected
    ) or '<tr><td colspan="4">None</td></tr>'
    coverage_rows = "".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(
            escape(label),
            (
                f"{coverage[key]['covered']}/{coverage[key]['total']} "
                f"({coverage[key]['rate']:.1%})"
            )
            if coverage.get(key, {}).get("measured")
            else "Not measured",
        )
        for key, label in (
            (
                "source_routes_observed",
                "Source routes with a recorded runtime response",
            ),
            ("declared_routes_probed", "Declared routes probed"),
            ("discovery_targets_inspected", "Discovery targets inspected"),
            ("workflow_steps_executed", "Workflow steps executed"),
            ("test_accounts_verified", "Test accounts verified"),
            ("declared_roles_verified", "Declared roles verified"),
        )
    )
    unattributed_rows = "".join(
        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(str(group["group_id"])),
            escape(str(group["title"] or "Untitled")),
            escape(str(group["verdict"])),
            escape(str(group["severity"] or "unrated")),
        )
        for group in result.get("unattributed_flagged_groups", [])
    )
    rows = []
    for row in result["cases"]:
        signatures = (
            "; ".join(
                f"{item['rule_id']} @ {item['path']}"
                for item in row["expected_signatures"]
            )
            or "No exact signature defined"
        )
        signals = (
            "; ".join(
                f"{item['scanner'] or 'unknown'} / {item['rule_id']} @ {item['path']} "
                f"→ {item['verdict']} (group {item['group_id']})"
                for item in row["signals"]
            )
            or "No exact reviewed signal"
        )
        rows.append(
            "<tr><td><code>{}</code></td><td>{}<small>{}</small></td><td>{}</td>"
            "<td>{}<small>{}</small></td><td>{}<small>Proof: {}</small><small>Source: {}; origin: {}</small></td>"
            "<td><small>Expected: {}</small><br>{}</td></tr>".format(
                escape(row["id"]),
                escape(row["category"]),
                escape(row["location"]),
                escape(row["ground_truth"].replace("_", " ")),
                escape(row["status"].replace("_", " ")),
                escape(row["severity"] or "not assigned"),
                escape(row["expected_behavior"] or "not recorded"),
                escape(row["proof_ref"] or "not recorded"),
                escape(row["source"] or "not recorded"),
                escape(", ".join(row["origin"]) or "not recorded"),
                escape(signatures),
                escape(signals),
            )
        )
    observations = result.get("original_observations", [])
    observation_rows = []
    for item in observations:
        location = str(item["path"])
        if type(item.get("line")) is int:
            location += f":{item['line']}"
        links = (
            ", ".join(
                f"{link['group_id']} ({link['verdict']})"
                for link in item["review_groups"]
            )
            or "No linked review"
        )
        observation_rows.append(
            "<tr><td><strong>{}</strong><small>{}</small></td><td>{}</td><td>{}</td>"
            "<td><code>{}</code></td><td>{}</td><td>{}</td></tr>".format(
                escape(str(item["title"])),
                escape(str(item["id"])),
                escape(str(item["source"])),
                escape(
                    ", ".join(str(scanner) for scanner in item["scanners"]) or "unknown"
                ),
                escape(location),
                escape(str(item["severity"])),
                escape(links),
            )
        )
    limits = "".join(f"<li>{escape(item)}</li>" for item in result["limitations"])
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verdict · Comprehensive lab evaluation</title><style>
body{{margin:0;background:#0b1220;color:#e8f0f6;font:15px system-ui,sans-serif}}main{{max-width:1400px;margin:auto;padding:40px 24px}}
h1{{font-size:30px}}p,li{{color:#b8c9d8;line-height:1.55}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}
.card{{background:#152237;border:1px solid #30445d;border-radius:12px;padding:18px;min-width:170px}}.card strong{{display:block;font-size:28px;color:#80e1c5}}
.scroll{{overflow:auto;border:1px solid #30445d;border-radius:12px}}table{{width:100%;border-collapse:collapse;min-width:800px}}
th,td{{text-align:left;padding:12px;border-bottom:1px solid #26384c;vertical-align:top}}th{{background:#152237}}tr:nth-child(even){{background:#101c2e}}
code{{color:#c7e4ff}}small{{display:block;color:#95aabd;margin-top:5px}}.note{{background:#152237;border-left:3px solid #80e1c5;padding:12px 16px}}
</style><main><h1>Comprehensive lab · held-out evaluation</h1>
<p>Evaluation status: <strong>{escape(result["evaluation_status"])}</strong>. Ground truth was used only after the saved scan.
A provisional diagnostic is not a completed evaluation. This is not a claim of exhaustive vulnerability coverage.</p>
<div class="cards"><div class="card"><strong>{summary["detected"]}/{summary["known_positive_cases"]}</strong>Detected known-positive cases</div>
<div class="card"><strong>{summary["detected_mixed"]}</strong>Detected with conflicting reviews</div>
<div class="card"><strong>{summary["needs_review"]}</strong>Need review</div>
<div class="card"><strong>{summary["not_detected"]}</strong>No exact reviewed signal</div>
<div class="card"><strong>{summary["pending_review"]}</strong>Pending AI review</div>
<div class="card"><strong>{summary["not_mapped"]}</strong>Not mapped to an exact signature</div>
<div class="card"><strong>{summary["safe_controls_not_assessed"]}</strong>Safe controls not audited</div>
<div class="card"><strong>{summary.get("unattributed_flagged_groups", 0)}</strong>Flagged groups awaiting benchmark adjudication</div></div>
<p class="note">Precision and F1 are not calculated: safe controls and unmatched findings require manual adjudication. A missing exact match does not prove the application is safe.</p>
<h2>Undetected ground-truth cases ({len(undetected)})</h2>
<p class="note">These confirmed benchmark cases had no exact reviewed signal in this saved run. This is a detection gap, not proof that the issue is absent from the application.</p>
<div class="scroll"><table><thead><tr><th>Case</th><th>Category</th><th>Location</th><th>Severity</th></tr></thead><tbody>{undetected_rows}</tbody></table></div>
<h2>Measured coverage</h2><p>Execution of the declared scope; these ratios do not measure vulnerability detection.</p>
<div class="scroll"><table><thead><tr><th>Scope</th><th>Covered / total</th></tr></thead><tbody>{coverage_rows}</tbody></table></div>
<h2>Scan provenance</h2><p>{escape(str(provenance["project"]))} · initial scan {escape(str(provenance["scan_status"]))} ·
{escape(", ".join(provenance["adapters"]))} · {provenance["merged_findings"]} merged findings · {provenance["reviewed_groups"]}/{provenance["total_groups"]} reviewed groups</p>
<p>AI discovery: {escape(str((provenance["ai_discovery"] or {}).get("provider", "unknown")))} / {escape(str((provenance["ai_discovery"] or {}).get("model", "unknown")))};
initial AI review: {escape(str((provenance["initial_security_review"] or {}).get("status", "unknown")))};
final AI review artifact: {escape(str((provenance["security_review"] or {}).get("status", "unknown")))};
recorded coverage gaps: {len(provenance["coverage_gaps"])}.</p>
<h2>Flagged groups awaiting benchmark adjudication</h2>
<p>These Review Agent groups are not linked to a known-positive case by the exact signatures. They are not automatically false positives.</p>
<div class="scroll"><table><thead><tr><th>Group</th><th>Title</th><th>Verdict</th><th>Severity</th></tr></thead><tbody>{unattributed_rows or '<tr><td colspan="4">None recorded</td></tr>'}</tbody></table></div>
<h2>All {len(result["cases"])} benchmark cases</h2>
<div class="scroll"><table><thead><tr><th>Case</th><th>Category / location</th><th>Ground truth</th><th>Scan outcome / severity</th><th>Expected behavior / proof</th><th>Audit signatures / matched evidence</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<h2>Original scanner &amp; DAST observations ({len(observations)})</h2>
<p>Saved normalized signals before Review Agent assessment; these are not benchmark matches or confirmed vulnerabilities.</p>
<div class="scroll"><table><thead><tr><th>Observation</th><th>Source</th><th>Scanner</th><th>Location</th><th>Severity</th><th>Review Agent group / verdict</th></tr></thead><tbody>{"".join(observation_rows)}</tbody></table></div>
<h2>Recorded coverage gaps</h2><ul>{"".join(f"<li>{escape(str(gap))}</li>" for gap in provenance["coverage_gaps"]) or "<li>None recorded</li>"}</ul>
<h2>Limits</h2><ul>{limits}</ul></main></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir", type=Path)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--diagnostic-partial",
        action="store_true",
        help="Produce a clearly provisional audit when AI review is incomplete",
    )
    args = parser.parse_args()
    result = evaluate(
        _read(TRUTH),
        _read(args.scan_dir / "pre-review-summary.json"),
        _read(args.scan_dir / "merged.json"),
        _read(args.review_dir / "candidate-triage.json"),
        _read(args.review_dir / "security-review.json"),
        allow_partial=args.diagnostic_partial,
        application_map=_read(args.scan_dir / "application-map.json")
        if (args.scan_dir / "application-map.json").is_file()
        else None,
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "evaluation.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "evaluation.md").write_text(markdown(result), encoding="utf-8")
    (args.output_dir / "evaluation.html").write_text(
        html_report(result), encoding="utf-8"
    )
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()

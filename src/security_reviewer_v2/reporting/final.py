"""Human-readable final report rendering."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .view import _scanner_rows, build_view


def _plain(value: Any) -> str:
    """Keep scanner-controlled labels from becoming Markdown or HTML."""
    compact = " ".join(str(value).split())
    escaped = html.escape(compact, quote=False)
    return re.sub(r"([\\`*_{}\[\]#+!|>~])", r"\\\1", escaped)


def _code(value: Any) -> str:
    """Display untrusted identifiers literally, including embedded backticks."""
    return f"<code>{html.escape(' '.join(str(value).split()))}</code>"


def _render_observations(merged: dict[str, Any], risk: dict[str, Any] | None) -> list[str]:
    findings = merged.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    risk_items = risk.get("findings", []) if isinstance(risk, dict) else []
    priorities = {item.get("merged_finding_id"): item for item in risk_items
                  if isinstance(item, dict) and isinstance(item.get("merged_finding_id"), str)}
    def order_key(item: dict[str, Any]) -> tuple[int, str]:
        rank = priorities.get(item.get("merged_finding_id"), {}).get("rank")
        return (rank if type(rank) is int else 10**9,
                str(item.get("merged_finding_id", "")))

    ordered = sorted(findings, key=order_key)
    dast_count = sum("dast" in item.get("categories", []) for item in ordered)
    lines = ["", "## Scanner and DAST Observations (Pre-Review)", "",
             f"**{len(ordered)}** merged observation record(s): **{dast_count}** DAST-related and "
             f"**{len(ordered) - dast_count}** other scanner record(s). "
             "These are signals to assess, not confirmed independent vulnerabilities. "
             "Risk disposition describes routing, not an agent verdict.", ""]
    if not ordered:
        lines.append("No scanner or DAST observations were recorded; check scanner execution and coverage before concluding safety.")
        return lines
    for number, item in enumerate(ordered, 1):
        finding_id = str(item.get("merged_finding_id", "unknown"))
        canonical = item.get("canonical_finding") or {}
        location = item.get("primary_location") or {}
        priority = priorities.get(finding_id, {})
        path = str(location.get("path") or "unknown")
        line = location.get("start_line")
        location_label = f"{path}:{line}" if isinstance(line, int) and line > 0 else path
        origin = "DAST" if "dast" in item.get("categories", []) else "scanner"
        scanners = ", ".join(str(value) for value in item.get("scanners", [])) or "unknown"
        severity = str(item.get("severity", "unknown"))
        confidence = str(item.get("confidence", "unknown"))
        disposition = str(priority.get("review_disposition", "not_ranked"))
        score = priority.get("risk_score")
        risk_label = f"{score}/100 ({priority.get('priority_band', 'unknown')})" if isinstance(score, int) else "not ranked"
        title = canonical.get("title") or priority.get("title") or "Untitled observation"
        rule_ids = ", ".join(str(value) for value in item.get("rule_ids", [])) or "unknown"
        source_ids = [str(source.get("finding_id")) for source in item.get("source_findings", [])
                      if isinstance(source, dict) and source.get("finding_id")]
        evidence_indent = " " * (len(str(number)) + 2)
        lines += [f"{number}. **{_plain(title)}** — {_plain(origin)} from {_plain(scanners)}; "
                  f"location: {_code(location_label)}; severity: **{_plain(severity)}**; "
                  f"confidence: {_plain(confidence)}; risk: {_plain(risk_label)}; "
                  f"disposition: {_code(disposition)}.",
                  f"{evidence_indent}- Record: {_code(finding_id)}; rule(s): {_code(rule_ids)}; "
                  "source evidence: " + (", ".join(_code(value) for value in source_ids)
                                          if source_ids else "not recorded") + "."]
        runtime_sources = [source for source in item.get("source_findings", [])
                           if isinstance(source, dict) and isinstance(source.get("runtime_evidence"), dict)
                           and source["runtime_evidence"]]
        for source in runtime_sources:
            facts = json.dumps(source["runtime_evidence"], sort_keys=True, ensure_ascii=False)
            lines.append(f"{evidence_indent}- Bounded runtime evidence: {_code(facts)}.")
    return lines


def render_final_report(*, project: str, review: dict[str, Any], policy: dict[str, Any],
                        triage: dict[str, Any] | None = None, verification: dict[str, Any] | None = None,
                        discovery: dict[str, Any] | None = None,
                        discovery_required_satisfied: bool | None = None,
                        docker_runtime: dict[str, Any] | None = None,
                        runtime_evidence: dict[str, Any] | None = None,
                        merged: dict[str, Any] | None = None,
                        risk: dict[str, Any] | None = None,
                        execution: dict[str, Any] | None = None,
                        scanner_requirement: dict[str, Any] | None = None,
                        coverage_gaps: list[str] | tuple[str, ...] | None = None,
                        adapter_ids: list[str] | tuple[str, ...] | None = None) -> str:
    lines = ["# Security Review Report", "", f"- Project: `{project}`", f"- Generated (UTC): `{datetime.now(timezone.utc).isoformat()}`", f"- Policy status: **{policy.get('status', 'unknown')}**", f"- Review status: **{review.get('status', 'unknown')}**", "", "## Executive Summary", ""]
    if scanner_requirement and scanner_requirement.get("requested"):
        scanner_status = "complete" if scanner_requirement.get("satisfied") else "incomplete"
        required = ", ".join(_code(item) for item in scanner_requirement.get("required", []))
        lines += [f"- Required scanners: **{scanner_status}** ({required})."]
        if scanner_status == "incomplete":
            lines += ["- **This scan is incomplete.** One or more required scanners did not complete with normalized output."]
            lines.extend(f"- Required scanner failure: {_plain(item)}"
                         for item in scanner_requirement.get("failures", []))
    if discovery is not None:
        usage = discovery.get("usage") or {}
        ai_status = ("completed required stage" if discovery_required_satisfied is True else
                     "incomplete required stage" if discovery_required_satisfied is False else
                     "not verified in this saved run")
        lines += [f"- AI Discovery: **{ai_status}**; stage status: {_code(discovery.get('status') or 'unknown')}; "
                  f"provider: {_code(discovery.get('provider') or 'unknown')}; "
                  f"model: {_code(discovery.get('model') or 'unknown')}; "
                  f"targets inspected: **{usage.get('targets', 0)}/{usage.get('planned_targets', 0)}**; "
                  f"model calls: **{usage.get('provider_calls', 0)}**."]
        if discovery_required_satisfied is False:
            lines += ["- **This scan is incomplete.** Scanner and DAST observations below remain available, "
                      "but the required AI Discovery did not finish."]
        for warning in discovery.get("warnings", []):
            lines.append(f"- AI Discovery warning: {_plain(warning)}")
        lines.append("")
    reviews = review.get("reviews", [])
    if not reviews:
        observation_count = len(merged.get("findings", [])) if merged is not None else 0
        if merged is not None:
            lines.append(f"No Security Review Agent verdicts were produced. **{observation_count}** "
                         "scanner/DAST observation record(s) are listed below for investigation. "
                         "This does not mean the project is secure.")
        else:
            lines.append("No reviewed findings were produced. This does not mean the project is secure; check coverage gaps and scanner status.")
    else:
        observation_note = (f" **{len(merged.get('findings', []))}** scanner/DAST "
                            "observation record(s) are listed separately below."
                            if merged is not None else "")
        lines.append(
            f"The agent reviewed **{len(reviews)}** issue group(s). "
            "These are model verdicts, not a count of distinct, independently validated vulnerabilities. "
            f"Policy blocking: **{policy.get('blocking', False)}**." + observation_note
        )
    expected = review.get("usage", {}).get("expected_groups")
    if expected is not None:
        lines.append(f"Issue groups expected: **{expected}**; reviewed: **{len(reviews)}**; pending: **{len(review.get('pending_ids', []))}**.")
    if docker_runtime is not None:
        counts = docker_runtime["probe_counts"]
        lines += ["", "## Trusted Docker DAST", "",
                  f"- Completed Docker run: `{docker_runtime['run_id']}`",
                  f"- Health: **HTTP {docker_runtime['http_status']}**; "
                  f"web probes: **{counts['runtime.json']}**; "
                  f"authorization probes: **{counts['authorization.json']}**.",
                  f"- Mutating probes: **{'enabled' if docker_runtime['mutating_checks_enabled'] else 'disabled'}**.",
                  "- The application was published on host loopback; its temporary Compose stack was removed before static and AI review.",
                  "- Docker is not a security boundary for untrusted application code.",
                  "- Probe findings are evidence to review, not proof that every endpoint or vulnerability was covered.",
                  f"- Docker DAST manifest: `{docker_runtime['manifest_path']}`"]
        deployment = docker_runtime.get("deployment_context")
        if isinstance(deployment, dict) and type(deployment.get("flask_debug")) is bool:
            configured = "enabled" if deployment["flask_debug"] else "disabled"
            lines.append(f"- Hash-matched Docker startup recipe: Flask debug **{configured}**. "
                         "This describes this Compose deployment only, not alternate entrypoints.")
    if runtime_evidence is not None:
        lines += ["", "## Generic Runtime DAST", "",
                  f"- Source: `{runtime_evidence.get('source', 'unknown')}`",
                  f"- Target: `{runtime_evidence.get('target', 'redacted')}`",
                  f"- Bounded probe records: **{len(runtime_evidence.get('results', []))}**",
                  "- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks."]
        browser = runtime_evidence.get("browser")
        if isinstance(browser, dict):
            lines.append(f"- Browser crawl: **{_plain(browser.get('status', 'unknown'))}**; "
                         f"pages visited: **{browser.get('pages_visited', 0)}**.")
        else:
            lines.append("- Browser crawl: **not requested**.")
        zap = runtime_evidence.get("zap")
        if isinstance(zap, dict):
            lines.append(f"- ZAP: **{_plain(zap.get('status', 'unknown'))}**; "
                         f"engine: {_code(zap.get('engine', 'unknown'))}; "
                         f"alerts: **{zap.get('alerts', 0)}**.")
        else:
            lines.append("- ZAP: **not requested**.")
        workflows = runtime_evidence.get("workflow_evidence")
        if isinstance(workflows, dict):
            counts = workflows.get("coverage") or {}
            lines.append(f"- Account and business workflows: **{_plain(workflows.get('status', 'unknown'))}**; "
                         f"executed: **{counts.get('executed', 0)}**; "
                         f"contract violations: **{counts.get('violations', 0)}**.")
        else:
            lines.append("- Account and business workflows: **not requested**.")
        lines.append("- These observations do not prove complete vulnerability coverage or exploitation.")
    if execution is not None:
        lines += ["", "## Scanner Execution", ""]
        tasks = execution.get("tasks", [])
        if tasks:
            lines.extend(f"- {_code(task.get('scanner_id', 'unknown'))}: "
                         f"{_code(task.get('status', 'unknown'))}"
                         for task in tasks if isinstance(task, dict))
        else:
            lines.append("No scanner tasks were recorded.")
        idle = [row for row in _scanner_rows(execution, tuple(adapter_ids or ()), tuple(coverage_gaps or ()))
                if row.status == "not_scheduled"]
        if idle:
            lines.extend(f"- {_plain(row.role)}: **{_plain(row.outcome)}**" + "".join(f" — {_plain(n)}" for n in row.notes) for row in idle)
            lines.append("Registered but not scheduled (nothing to scan): " + ", ".join(_code(row.scanner) for row in idle) + ".")
    if merged is not None:
        lines.extend(_render_observations(merged, risk))
    lines += ["", "## Security Review Agent Verdicts", ""]
    if not reviews:
        lines += ["No agent verdicts were produced. The pre-review observations above remain visible "
                  "but have not been cleared or confirmed by the agent.", ""]
    for index, item in enumerate(reviews, 1):
        lines += [f"### {index}. {item.get('title', 'Untitled finding')}", "", f"- Issue group: `{item.get('candidate_id', 'unknown')}`", f"- Verdict: **{item.get('verdict', 'unknown')}**", f"- Severity: **{item.get('severity', 'unknown')}**", f"- Confidence: **{item.get('confidence', 'unknown')}**", "", f"**Explanation:** {item.get('explanation', '')}", "", f"**Impact:** {item.get('impact', '')}", "", f"**Remediation:** {item.get('remediation', '')}", "Evidence:"]
        if item.get("source_ids"):
            formatted_sources = ", ".join("`" + str(source_id) + "`" for source_id in item["source_ids"])
            lines.append(f"- Source IDs: {formatted_sources}")
        for evidence in item.get("evidence", []):
            lines.append(f"- `{evidence}`")
        if item.get("limitations"):
            lines += ["", "Limitations:"]
            lines.extend(f"- {value}" for value in item["limitations"])
        lines.append("")
    lines += ["## Policy Decisions", ""]
    for decision in policy.get("decisions", []):
        lines.append(f"- `{decision.get('candidate_id')}`: **{decision.get('action')}** — {decision.get('reason')}")
    if triage is not None:
        summary = triage.get("summary", {})
        lines += ["", "## Candidate Triage and Unresolved Evidence", "",
                  f"Scanner/DAST observation records: **{summary.get('input_scanner_findings', 0)}**; "
                  f"issue groups after conservative correlation: **{summary.get('review_groups', 0)}**. "
                  "Every original observation remains listed above and linked by source ID in its review group.",
                  f"AI candidates: **{summary.get('input_ai_candidates', 0)}**; scanner overlaps: **{summary.get('scanner_overlap', 0)}**; AI overlaps: **{summary.get('candidate_overlap', 0)}**; new candidates: **{summary.get('novel_candidates', 0)}**; uncertain overlaps: **{summary.get('uncertain_overlap', 0)}**; needs more evidence: **{summary.get('needs_more_evidence', 0)}**; rejected: **{summary.get('rejected', 0)}**."]
        unresolved = [item for item in triage.get("records", []) if item.get("disposition") in {"needs_more_evidence", "uncertain_overlap"}]
        if unresolved:
            lines += ["", "These AI candidates are not confirmed vulnerabilities and were not silently discarded:"]
            lines.extend(f"- `{item.get('candidate_id')}`: {item.get('disposition')}" for item in unresolved)
    if verification is not None and verification.get("status") != "completed":
        lines += ["", f"Verification status: **{verification.get('status', 'unknown')}**; see `verification.json` for individual source-evidence checks."]
    if review.get("pending_ids"):
        lines += ["", "## Pending Security Reviews", ""]
        lines.extend(f"- `{group_id}`" for group_id in review["pending_ids"])
    if coverage_gaps:
        lines += ["", "## Coverage Gaps", ""]
        lines.extend(f"- {_plain(gap)}" for gap in coverage_gaps)
    lines += ["", "## Limitations", "", "Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.", ""]
    return "\n".join(lines)


def write_final_report(path: str | Path, *, project: str, review: dict[str, Any], policy: dict[str, Any],
                       triage: dict[str, Any] | None = None, verification: dict[str, Any] | None = None,
                       discovery: dict[str, Any] | None = None,
                       discovery_required_satisfied: bool | None = None,
                       docker_runtime: dict[str, Any] | None = None,
                       runtime_evidence: dict[str, Any] | None = None,
                       merged: dict[str, Any] | None = None,
                       risk: dict[str, Any] | None = None,
                       execution: dict[str, Any] | None = None,
                       scanner_requirement: dict[str, Any] | None = None,
                       coverage_gaps: list[str] | tuple[str, ...] | None = None,
                       adapter_ids: list[str] | tuple[str, ...] | None = None) -> Path:
    from .html_report import render_html

    path = Path(path)
    options = dict(project=project, review=review, policy=policy, triage=triage, verification=verification,
                   discovery=discovery, discovery_required_satisfied=discovery_required_satisfied,
                   docker_runtime=docker_runtime, runtime_evidence=runtime_evidence, merged=merged, risk=risk,
                   execution=execution, scanner_requirement=scanner_requirement, coverage_gaps=coverage_gaps,
                   adapter_ids=adapter_ids)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_final_report(**options), encoding="utf-8")
    path.with_suffix(".html").write_text(render_html(build_view(**options)), encoding="utf-8")
    return path

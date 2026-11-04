"""Human-readable final report rendering."""

from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence_trace import build_evidence_traces
from .provenance import review_evidence_origins
from .summary import build_summary


def _plain(value: Any) -> str:
    """Keep scanner-controlled labels from becoming Markdown or HTML."""
    compact = " ".join(str(value).split())
    escaped = html.escape(compact, quote=False)
    return re.sub(r"([\\`*_{}\[\]#+!|>~])", r"\\\1", escaped)


def _code(value: Any) -> str:
    """Display untrusted identifiers literally, including embedded backticks."""
    return f"<code>{html.escape(' '.join(str(value).split()))}</code>"


def _trace_lines(trace: dict[str, Any]) -> list[str]:
    kind = trace.get("kind")
    if kind == "discovery":
        return [
            "- Discovery Agent candidate only; no scanner or runtime reproduction was saved."
        ]
    if kind == "unavailable":
        return ["- No linked scanner or runtime scenario was saved for this group."]
    source = (
        f"{_code(trace.get('scanner') or 'unknown scanner')} · "
        f"rule {_code(trace.get('rule_id') or 'not recorded')} · "
        f"location {_code(trace.get('location') or 'not recorded')}"
    )
    if kind == "static":
        lines = [
            f"- Static scanner output: {source}; severity {_plain(trace.get('severity') or 'not recorded')}.",
        ]
        flow = trace.get("flow_locations") or []
        if flow:
            lines.append(
                "- Scanner-reported code-flow locations: "
                + " → ".join(_code(location) for location in flow)
                + (" …" if trace.get("flow_truncated") else "")
            )
        lines.append(
            "- No HTTP response or runtime reproduction was saved for this signal."
        )
        return lines
    if kind == "workflow":
        lines = [f"- Workflow {_code(trace.get('workflow_id'))}: {source}."]
        steps = trace.get("steps") or []
        for step in steps:
            expected = (
                "/".join(str(value) for value in step.get("expected_statuses", []))
                or "not declared"
            )
            observed = step.get("observed_status")
            lines.append(
                f"  - Step {step['number']}: {_plain(step.get('actor'))} "
                f"{_plain(step.get('method'))} {_code(step.get('path'))}; "
                f"expected HTTP {expected}, observed HTTP {observed if observed is not None else 'not saved'}; "
                f"result {_plain(step.get('status'))}."
            )
            for check in step.get("checks", []):
                lines.append(
                    "    - Assertion "
                    + _plain(
                        " ".join(
                            str(check.get(key) or "")
                            for key in ("kind", "field", "operator")
                        )
                    )
                    + (": passed." if check.get("passed") else ": failed.")
                )
        if not steps:
            lines.append("  - Earlier workflow steps were not saved in this bundle.")
            expected = (
                "/".join(str(value) for value in trace.get("expected_statuses", []))
                or "not declared"
            )
            observed = trace.get("observed_status")
            lines.append(
                f"  - Recorded check: {_plain(trace.get('actor'))} {_plain(trace.get('method'))} "
                f"{_code(trace.get('location'))}; expected HTTP {expected}, "
                f"observed HTTP {observed if observed is not None else 'not saved'}."
            )
        lines.append("- Response bodies, tokens and captured values are withheld.")
        return lines
    expected = (
        "/".join(str(value) for value in trace.get("expected_statuses", []))
        or "not declared"
    )
    observed = trace.get("observed_status")
    return [
        (
            f"- Runtime tool output: {source}; request {_plain(trace.get('method') or 'not recorded')} "
            f"{_code(trace.get('location'))}; expected HTTP {expected}, "
            f"observed HTTP {observed if observed is not None else 'not saved'}."
        ),
        "- This alert or observation is not independent proof of exploitation; response bodies are not saved.",
    ]


def render_final_report(
    *,
    project: str,
    review: dict[str, Any],
    policy: dict[str, Any],
    triage: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    discovery_required_satisfied: bool | None = None,
    docker_runtime: dict[str, Any] | None = None,
    runtime_evidence: dict[str, Any] | None = None,
    merged: dict[str, Any] | None = None,
    risk: dict[str, Any] | None = None,
    execution: dict[str, Any] | None = None,
    scanner_requirement: dict[str, Any] | None = None,
    coverage_gaps: list[str] | tuple[str, ...] | None = None,
    scan_status: str | None = None,
) -> str:
    summary = build_summary(
        review=review,
        policy=policy,
        merged=merged,
        runtime_evidence=runtime_evidence,
        scanner_requirement=scanner_requirement,
        discovery_required_satisfied=discovery_required_satisfied,
        coverage_gaps=coverage_gaps,
    )
    verdicts = summary["verdicts"]
    severities = summary["actionable_severities"]
    policy_message = (
        "Blocks release under the configured policy"
        if summary["policy_blocking"]
        else "No blocking decision recorded; this is not a safety certificate"
    )
    lines = [
        "# Security Review Report",
        "",
        f"- Project: `{project}`",
        f"- Generated (UTC): `{datetime.now(UTC).isoformat()}`",
        f"- Policy status: **{_plain(summary['policy_status'])}**",
        f"- Review status: **{_plain(review.get('status', 'unknown'))}**",
        "",
        "## Executive Summary",
        "",
        (
            f"**Assessment state:** {_plain(summary['stage_status'])}. "
            "This describes the saved review stages, not complete coverage of the application."
        ),
        f"**Release decision:** {_plain(policy_message)}.",
        "",
        "| Measure | Saved result | What it means |",
        "| --- | ---: | --- |",
        f"| Original observations | {summary['observations']} | Scanner and DAST signals before agent review; not unique vulnerabilities. |",
        f"| DAST-related observations | {summary['dast_observations']} | Subset of original observations, not the number of endpoints tested. |",
        f"| Reviewed issue groups | {summary['reviewed_groups']} | Correlated groups assessed by the agent; {summary['pending_groups']} still pending. |",
        f"| Agent-flagged groups | {summary['actionable_groups']} | Confirmed/likely model verdicts, not independently reproduced exploits. |",
        f"| Policy blocks | {summary['policy_blocks']} | Groups for which the configured gate says block. |",
        f"| Coverage gaps | {summary['coverage_gaps']} | Distinct saved limitations; read them before interpreting silence. |",
        "",
        (
            "**Agent verdict breakdown:** "
            f"confirmed {verdicts.get('confirmed_vulnerability', 0)}, "
            f"likely {verdicts.get('likely_vulnerability', 0) + verdicts.get('likely_vulnerable', 0)}, "
            f"false positive {verdicts.get('false_positive', 0)}, "
            f"needs more evidence {verdicts.get('needs_more_evidence', 0)}. "
        ),
        (
            "**Severity among agent-flagged groups:** "
            f"critical {severities.get('critical', 0)}, high {severities.get('high', 0)}, "
            f"medium {severities.get('medium', 0)}, low {severities.get('low', 0)}."
        ),
        "",
        (
            "**What ran:** "
            f"required scanners {_plain(summary['required_scanners'])}; "
            f"AI discovery {_plain(summary['ai_discovery'])}; "
            f"runtime {_plain(summary['runtime_status'])} "
            f"({summary['baseline_probes']} baseline records); "
            f"ZAP {_plain(summary['zap_status'])} ({summary['zap_alerts']} alerts); "
            f"browser {_plain(summary['browser_status'])}; "
            f"workflows {_plain(summary['workflow_status'])} "
            f"({summary['workflow_executed']} steps, {summary['workflow_violations']} contract violations, "
            f"{summary['workflow_unresolved']} unresolved)."
        ),
        "",
    ]
    if scan_status:
        lines += [
            (
                f"**Recorded pipeline status:** {_plain(scan_status)}. "
                "This is the saved run's status; a later resumed AI review can finish without rerunning DAST or scanners."
            ),
            "",
        ]
    if summary["first_actions"]:
        lines += [
            "### Review these groups first",
            "",
            "Prioritized by policy block, then severity. Open each full review below and validate the evidence before changing production.",
            "",
        ]
        for item in summary["first_actions"]:
            lines.append(
                f"- **{_plain(item['title'])}** ({_code(item['id'])}; "
                f"{_plain(item['severity'])}; {_plain(item['verdict'])}; "
                f"policy: {_plain(item['action'])}). "
                f"Impact: {_plain(item['impact'])} "
                f"Suggested fix: {_plain(item['remediation'])}"
            )
        lines.append("")
    lines += [
        "## How to Read This Report",
        "",
        "- **Original observation:** one normalized scanner or DAST signal. Several signals can describe the same issue, and a signal can be wrong.",
        "- **Issue group and agent verdict:** correlated evidence assessed by the AI reviewer. Even a `confirmed_vulnerability` verdict is an evidence-based model assessment, not independent exploit proof.",
        "- **Policy block:** a release decision under configured rules, not a second vulnerability count.",
        "- **DAST contract violation:** an observed mismatch with a declared expected behavior. Review the assertion and request context before calling it exploitable.",
        "- **Coverage gap:** an untested or inconclusive area. No finding in that area must not be read as a pass.",
        "",
    ]
    if scanner_requirement and scanner_requirement.get("requested"):
        scanner_status = (
            "complete" if scanner_requirement.get("satisfied") else "incomplete"
        )
        required = ", ".join(
            _code(item) for item in scanner_requirement.get("required", [])
        )
        lines += [f"- Required scanners: **{scanner_status}** ({required})."]
        if scanner_status == "incomplete":
            lines += [
                "- **This scan is incomplete.** One or more required scanners did not complete with normalized output."
            ]
            lines.extend(
                f"- Required scanner failure: {_plain(item)}"
                for item in scanner_requirement.get("failures", [])
            )
    if discovery is not None:
        usage = discovery.get("usage") or {}
        ai_status = (
            "completed required stage"
            if discovery_required_satisfied is True
            else "incomplete required stage"
            if discovery_required_satisfied is False
            else "not verified in this saved run"
        )
        lines += [
            (
                f"- AI Discovery: **{ai_status}**; stage status: {_code(discovery.get('status') or 'unknown')}; "
                f"provider: {_code(discovery.get('provider') or 'unknown')}; "
                f"model: {_code(discovery.get('model') or 'unknown')}; "
                f"targets inspected: **{usage.get('targets', 0)}/{usage.get('planned_targets', 0)}**; "
                f"model calls: **{usage.get('provider_calls', 0)}**."
            )
        ]
        if discovery_required_satisfied is False:
            lines += [
                (
                    "- **This scan is incomplete.** Scanner and DAST observations remain in the saved evidence, "
                    "but the required AI Discovery did not finish."
                )
            ]
        for warning in discovery.get("warnings", []):
            lines.append(f"- AI Discovery warning: {_plain(warning)}")
        lines.append("")
    reviews = review.get("reviews", [])
    origins_by_group = review_evidence_origins(review, triage, merged)
    traces_by_group = build_evidence_traces(review, triage, merged, runtime_evidence)
    if not reviews:
        observation_count = len(merged.get("findings", [])) if merged is not None else 0
        if merged is not None:
            lines.append(
                f"No Security Review Agent verdicts were produced. **{observation_count}** "
                "scanner/DAST observation record(s) remain in the saved evidence for investigation. "
                "This does not mean the project is secure."
            )
        else:
            lines.append(
                "No reviewed findings were produced. This does not mean the project is secure; check coverage gaps and scanner status."
            )
    else:
        observation_note = (
            f" **{len(merged.get('findings', []))}** scanner/DAST "
            "observation record(s) remain in the saved evidence."
            if merged is not None
            else ""
        )
        lines.append(
            f"The agent reviewed **{len(reviews)}** issue group(s). "
            "These are model verdicts, not a count of distinct, independently validated vulnerabilities. "
            f"Policy blocking: **{policy.get('blocking', False)}**." + observation_note
        )
    expected = review.get("usage", {}).get("expected_groups")
    if expected is not None:
        lines.append(
            f"Issue groups expected: **{expected}**; reviewed: **{len(reviews)}**; pending: **{len(review.get('pending_ids', []))}**."
        )
    if docker_runtime is not None:
        counts = docker_runtime["probe_counts"]
        lines += [
            "",
            "## Trusted Docker DAST",
            "",
            f"- Completed Docker run: `{docker_runtime['run_id']}`",
            (
                f"- Health: **HTTP {docker_runtime['http_status']}**; "
                f"web probes: **{counts['runtime.json']}**; "
                f"authorization probes: **{counts['authorization.json']}**."
            ),
            f"- Mutating probes: **{'enabled' if docker_runtime['mutating_checks_enabled'] else 'disabled'}**.",
            "- The application was published on host loopback; its temporary Compose stack was removed before static and AI review.",
            "- Docker is not a security boundary for untrusted application code.",
            "- Probe findings are evidence to review, not proof that every endpoint or vulnerability was covered.",
            f"- Docker DAST manifest: `{docker_runtime['manifest_path']}`",
        ]
        deployment = docker_runtime.get("deployment_context")
        if isinstance(deployment, dict) and type(deployment.get("flask_debug")) is bool:
            configured = "enabled" if deployment["flask_debug"] else "disabled"
            lines.append(
                f"- Hash-matched Docker startup recipe: Flask debug **{configured}**. "
                "This describes this Compose deployment only, not alternate entrypoints."
            )
    if runtime_evidence is not None:
        lines += [
            "",
            "## Generic Runtime DAST",
            "",
            f"- Source: `{runtime_evidence.get('source', 'unknown')}`",
            f"- Target: `{runtime_evidence.get('target', 'redacted')}`",
            f"- Bounded probe records: **{len(runtime_evidence.get('results', []))}**",
            "- The baseline uses bounded checks; optional ZAP and contract workflows below may make active or mutating requests when approved.",
        ]
        browser = runtime_evidence.get("browser")
        if isinstance(browser, dict):
            lines.append(
                f"- Browser crawl: **{_plain(browser.get('status', 'unknown'))}**; "
                f"pages visited: **{browser.get('pages_visited', 0)}**."
            )
        else:
            lines.append("- Browser crawl: **not requested**.")
        zap = runtime_evidence.get("zap")
        if isinstance(zap, dict):
            lines.append(
                f"- ZAP: **{_plain(zap.get('status', 'unknown'))}**; "
                f"engine: {_code(zap.get('engine', 'unknown'))}; "
                f"alerts: **{zap.get('alerts', 0)}**."
            )
        else:
            lines.append("- ZAP: **not requested**.")
        workflows = runtime_evidence.get("workflow_evidence")
        if isinstance(workflows, dict):
            counts = workflows.get("coverage") or {}
            lines.append(
                f"- Account and business workflows: **{_plain(workflows.get('status', 'unknown'))}**; "
                f"executed: **{counts.get('executed', 0)}**; "
                f"contract violations: **{counts.get('violations', 0)}**."
            )
        else:
            lines.append("- Account and business workflows: **not requested**.")
        lines.append(
            "- These observations do not prove complete vulnerability coverage or exploitation."
        )
    if execution is not None:
        lines += ["", "## Scanner Execution", ""]
        tasks = execution.get("tasks", [])
        if tasks:
            lines.extend(
                f"- {_code(task.get('scanner_id', 'unknown'))}: "
                f"{_code(task.get('status', 'unknown'))}"
                for task in tasks
                if isinstance(task, dict)
            )
        else:
            lines.append("No scanner tasks were recorded.")
    lines += ["", "## Security Review Agent Verdicts", ""]
    if not reviews:
        lines += [
            (
                "No agent verdicts were produced. Saved pre-review observations have not been "
                "cleared or confirmed by the agent."
            ),
            "",
        ]
    for index, item in enumerate(reviews, 1):
        lines += [
            f"### {index}. {item.get('title', 'Untitled finding')}",
            "",
            f"- Issue group: `{item.get('candidate_id', 'unknown')}`",
            "- Evidence type: **"
            + _plain(
                " + ".join(
                    origins_by_group.get(
                        str(item.get("candidate_id")), ("Unclassified",)
                    )
                )
            )
            + "**",
            f"- Verdict: **{item.get('verdict', 'unknown')}**",
            f"- Severity: **{item.get('severity', 'unknown')}**",
            f"- Confidence: **{item.get('confidence', 'unknown')}**",
            "",
            "**How this finding was reached:**",
            *(
                line
                for trace in traces_by_group.get(str(item.get("candidate_id")), [])
                for line in _trace_lines(trace)
            ),
            "",
            f"**Explanation:** {item.get('explanation', '')}",
            "",
            f"**Impact:** {item.get('impact', '')}",
            "",
            f"**Remediation:** {item.get('remediation', '')}",
            "Evidence:",
        ]
        if item.get("source_ids"):
            formatted_sources = ", ".join(
                "`" + str(source_id) + "`" for source_id in item["source_ids"]
            )
            lines.append(f"- Source IDs: {formatted_sources}")
        for evidence in item.get("evidence", []):
            lines.append(f"- `{evidence}`")
        if item.get("limitations"):
            lines += ["", "Limitations:"]
            lines.extend(f"- {value}" for value in item["limitations"])
        lines.append("")
    lines += ["## Policy Decisions", ""]
    for decision in policy.get("decisions", []):
        lines.append(
            f"- `{decision.get('candidate_id')}`: **{decision.get('action')}** — {decision.get('reason')}"
        )
    if triage is not None:
        summary = triage.get("summary", {})
        lines += [
            "",
            "## Candidate Triage and Unresolved Evidence",
            "",
            (
                f"Scanner/DAST observation records: **{summary.get('input_scanner_findings', 0)}**; "
                f"issue groups after conservative correlation: **{summary.get('review_groups', 0)}**. "
                "Original observations remain in saved evidence and review groups refer to their source IDs."
            ),
            f"AI candidates: **{summary.get('input_ai_candidates', 0)}**; scanner overlaps: **{summary.get('scanner_overlap', 0)}**; AI overlaps: **{summary.get('candidate_overlap', 0)}**; new candidates: **{summary.get('novel_candidates', 0)}**; uncertain overlaps: **{summary.get('uncertain_overlap', 0)}**; needs more evidence: **{summary.get('needs_more_evidence', 0)}**; rejected: **{summary.get('rejected', 0)}**.",
        ]
        unresolved = [
            item
            for item in triage.get("records", [])
            if item.get("disposition") in {"needs_more_evidence", "uncertain_overlap"}
        ]
        if unresolved:
            lines += [
                "",
                "These AI candidates are not confirmed vulnerabilities and were not silently discarded:",
            ]
            lines.extend(
                f"- `{item.get('candidate_id')}`: {item.get('disposition')}"
                for item in unresolved
            )
    if verification is not None and verification.get("status") != "completed":
        lines += [
            "",
            f"Verification status: **{verification.get('status', 'unknown')}**; see `verification.json` for individual source-evidence checks.",
        ]
    if review.get("pending_ids"):
        lines += ["", "## Pending Security Reviews", ""]
        lines.extend(f"- `{group_id}`" for group_id in review["pending_ids"])
    if coverage_gaps:
        lines += ["", "## Coverage Gaps", ""]
        lines.extend(f"- {_plain(gap)}" for gap in coverage_gaps)
    lines += [
        "",
        "## Limitations",
        "",
        "Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.",
        "",
    ]
    return "\n".join(lines)


def write_final_report(
    path: str | Path,
    *,
    project: str,
    review: dict[str, Any],
    policy: dict[str, Any],
    triage: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    discovery_required_satisfied: bool | None = None,
    docker_runtime: dict[str, Any] | None = None,
    runtime_evidence: dict[str, Any] | None = None,
    merged: dict[str, Any] | None = None,
    risk: dict[str, Any] | None = None,
    execution: dict[str, Any] | None = None,
    scanner_requirement: dict[str, Any] | None = None,
    coverage_gaps: list[str] | tuple[str, ...] | None = None,
    scan_status: str | None = None,
) -> None:
    from .html import render_html_report

    path = Path(path)
    options = {
        "project": project,
        "review": review,
        "policy": policy,
        "triage": triage,
        "verification": verification,
        "discovery": discovery,
        "discovery_required_satisfied": discovery_required_satisfied,
        "docker_runtime": docker_runtime,
        "runtime_evidence": runtime_evidence,
        "merged": merged,
        "risk": risk,
        "execution": execution,
        "scanner_requirement": scanner_requirement,
        "coverage_gaps": coverage_gaps,
        "scan_status": scan_status,
    }
    markdown = render_final_report(**options)
    html_report = render_html_report(**options)
    path.write_text(markdown, encoding="utf-8")
    path.with_suffix(".html").write_text(html_report, encoding="utf-8")

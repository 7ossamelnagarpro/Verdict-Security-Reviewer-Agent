"""Standalone, escaped HTML view of the saved security review evidence."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from html import escape
from typing import Any

from .evidence_trace import build_evidence_traces
from .provenance import review_evidence_origins
from .summary import build_summary


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _items(value: Any) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _text_list(value: Any) -> str:
    if not isinstance(value, (list, tuple)) or not value:
        return '<p class="muted">None recorded.</p>'
    return (
        '<ul class="detail-list">'
        + "".join(f"<li>{_e(item)}</li>" for item in value)
        + "</ul>"
    )


def _chip(value: Any, kind: str = "") -> str:
    label = str(value or "unknown")
    normalized = label.lower().replace(" ", "-").replace("_", "-")
    tone = {
        "confirmed-vulnerability": "danger",
        "block": "danger",
        "failed": "danger",
        "critical": "danger",
        "high": "danger",
        "likely-vulnerability": "warn",
        "warn": "warn",
        "medium": "warn",
        "partial": "warn",
        "completed": "good",
        "allow": "good",
        "false-positive": "good",
        "needs-more-evidence": "neutral",
        "low": "neutral",
        "info": "neutral",
    }.get(normalized, "neutral")
    return f'<span class="chip {tone}" aria-label="{_e(kind + label)}">{_e(label.replace("_", " "))}</span>'


def _metric(label: str, value: Any, note: str = "", detail: str = "") -> str:
    return (
        f'<div class="metric"><span class="metric-label">{_e(label)}</span>'
        f"<strong>{_e(value)}</strong><small>{_e(note)}</small>"
        + (f'<small class="metric-detail">{_e(detail)}</small>' if detail else "")
        + "</div>"
    )


def _status(label: str, value: Any, note: str, tone: str) -> str:
    return (
        f'<div class="status-card {tone}"><span class="status-label">{_e(label)}</span>'
        f"<strong>{_e(value)}</strong><small>{_e(note)}</small></div>"
    )


def _pair(label: str, value: Any) -> str:
    return f'<div class="pair"><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>'


def _scanner_label(item: dict[str, Any]) -> str:
    scanner_id = str(item.get("scanner_id") or "unknown")
    if scanner_id.lower() != "trivy":
        return scanner_id
    commands = item.get("commands") if isinstance(item.get("commands"), list) else []
    if str(item.get("status") or "").lower() == "skipped":
        return "Trivy · additional scan"
    if len(commands) > 1:
        return f"Trivy · {len(commands)} filesystem targets"
    return "Trivy · filesystem scan"


def _status_text(value: Any) -> str:
    return str(value) if type(value) is int else "not saved"


def _expected_text(value: Any) -> str:
    return "/".join(str(status) for status in value) if value else "not declared"


def _checks_html(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return ""
    parts = []
    for check in value:
        label = " ".join(
            str(check.get(key) or "") for key in ("kind", "field", "operator")
        ).strip()
        parts.append(
            f"<li>{_e(label or 'Assertion')}: "
            f"{'passed' if check.get('passed') is True else 'failed'}</li>"
        )
    return '<ul class="trace-checks">' + "".join(parts) + "</ul>"


def _trace_html(traces: list[dict[str, Any]]) -> str:
    blocks = []
    for trace in traces:
        kind = trace.get("kind")
        if kind in {"discovery", "unavailable"}:
            message = (
                "Discovery Agent proposed this candidate; no scanner or runtime reproduction is saved."
                if kind == "discovery"
                else "No linked scanner or runtime scenario was saved for this group."
            )
            blocks.append(f'<p class="muted">{message}</p>')
            continue
        source = (
            f"{trace.get('scanner') or 'Unknown scanner'} · "
            f"{trace.get('rule_id') or 'rule not recorded'} · "
            f"{trace.get('location') or 'location not recorded'}"
        )
        if kind == "workflow":
            steps = []
            for step in trace.get("steps", []):
                request = " ".join(
                    str(step.get(key) or "") for key in ("actor", "method", "path")
                ).strip()
                steps.append(
                    f"<li><strong>{_e(request)}</strong> — expected HTTP "
                    f"{_e(_expected_text(step.get('expected_statuses')))}, "
                    f"observed HTTP {_e(_status_text(step.get('observed_status')))} "
                    f"({_e(step.get('status') or 'unrecorded')})"
                    + _checks_html(step.get("checks"))
                    + "</li>"
                )
            step_list = (
                '<ol class="trace-steps">' + "".join(steps) + "</ol>"
                if steps
                else (
                    '<p class="muted">Earlier workflow steps were not saved in this bundle.</p>'
                    f"<p>Recorded check: {_e(trace.get('actor'))} {_e(trace.get('method'))} "
                    f"{_e(trace.get('location'))}; expected HTTP "
                    f"{_e(_expected_text(trace.get('expected_statuses')))}, observed HTTP "
                    f"{_e(_status_text(trace.get('observed_status')))}.</p>"
                    + _checks_html(trace.get("checks"))
                )
            )
            blocks.append(
                f'<div class="trace"><p><strong>Workflow {_e(trace.get("workflow_id"))}</strong> · {_e(source)}</p>'
                + step_list
                + '<p class="muted">Saved output contains HTTP status and assertion results only; response bodies, tokens and captured values are withheld.</p></div>'
            )
        elif kind == "runtime":
            blocks.append(
                f'<div class="trace"><p><strong>Runtime tool output:</strong> {_e(source)}</p>'
                f"<p>Request: {_e(trace.get('method') or 'not recorded')} {_e(trace.get('location'))}. "
                f"Expected HTTP: {_e(_expected_text(trace.get('expected_statuses')))}; "
                f"observed HTTP: {_e(_status_text(trace.get('observed_status')))}.</p>"
                + _checks_html(trace.get("checks"))
                + '<p class="muted">An alert or observation is not independent proof of exploitation; response bodies are not saved.</p></div>'
            )
        else:
            locations = trace.get("flow_locations") or []
            flow = (
                "<p>Scanner-reported code-flow locations: "
                + " → ".join(_e(value) for value in locations)
                + (" …" if trace.get("flow_truncated") else "")
                + "</p>"
                if locations
                else ""
            )
            blocks.append(
                f'<div class="trace"><p><strong>Static scanner output:</strong> {_e(source)} · '
                f"severity {_e(trace.get('severity') or 'not recorded')}.</p>"
                + flow
                + '<p class="muted">This is source-analysis evidence; no HTTP response or runtime reproduction was saved for this signal.</p></div>'
            )
    return (
        '<div class="trace-panel"><h4>How this finding was reached</h4>'
        + "".join(blocks)
        + "</div>"
    )


def _finding(
    index: int,
    item: dict[str, Any],
    decision: dict[str, Any],
    origins: tuple[str, ...],
    traces: list[dict[str, Any]],
) -> str:
    title = item.get("title") or "Untitled finding"
    verdict = item.get("verdict") or "not_reviewed"
    severity = item.get("severity") or "unknown"
    action = decision.get("action") or "not set"
    searchable = " ".join(
        [
            str(item.get(key) or "")
            for key in ("title", "verdict", "severity", "explanation", "remediation")
        ]
        + [
            str(value)
            for key in ("evidence", "limitations", "source_ids")
            for value in (item.get(key) if isinstance(item.get(key), list) else [])
        ]
    )
    evidence = _text_list(item.get("evidence"))
    limits = _text_list(item.get("limitations"))
    sources = _text_list(item.get("source_ids"))
    origin_chips = "".join(_chip(origin, "Evidence type: ") for origin in origins)
    origin_filter = " ".join(origin.lower().replace(" ", "-") for origin in origins)
    return (
        f'<article id="finding-{index}" class="finding" data-verdict="{_e(verdict)}" data-severity="{_e(severity)}" '
        f'data-origin="{_e(origin_filter)}" data-search="{_e(searchable.lower())}">'
        f'<details><summary><span class="finding-no">{index:02d}</span>'
        f'<span class="finding-main"><strong>{_e(title)}</strong><small>{_e(item.get("candidate_id") or "")}</small></span>'
        f'<span class="finding-tags">{origin_chips}{_chip(severity)}{_chip(verdict)}{_chip(action)}</span>'
        '<span class="chevron" aria-hidden="true">⌄</span></summary>'
        '<div class="finding-body">'
        f"{_trace_html(traces)}"
        '<div class="finding-grid">'
        f"<div><h4>Assessment</h4><p>{_e(item.get('explanation') or 'Not recorded.')}</p></div>"
        f"<div><h4>Impact</h4><p>{_e(item.get('impact') or 'Not recorded.')}</p></div>"
        f"<div><h4>Remediation</h4><p>{_e(item.get('remediation') or 'Not recorded.')}</p></div>"
        '</div><div class="policy-note"><h4>Policy decision</h4>'
        f"<p>{_chip(action)} {_e(decision.get('reason') or 'No reason recorded.')}</p></div>"
        '<div class="evidence-grid">'
        f"<div><h4>Evidence</h4>{evidence}</div>"
        f"<div><h4>Source IDs</h4>{sources}</div>"
        f"<div><h4>Limitations</h4>{limits}</div>"
        "</div></div></details></article>"
    )


def render_html_report(
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
    """Render a local-first report; every external value is HTML-escaped."""
    reviews = _items(review.get("reviews"))
    decisions = _items(policy.get("decisions"))
    summary = build_summary(
        review=review,
        policy=policy,
        merged=merged,
        runtime_evidence=runtime_evidence,
        scanner_requirement=scanner_requirement,
        discovery_required_satisfied=discovery_required_satisfied,
        coverage_gaps=coverage_gaps,
    )
    decision_by_id = {str(item.get("candidate_id")): item for item in decisions}
    pending = (
        review.get("pending_ids") if isinstance(review.get("pending_ids"), list) else []
    )
    severity_levels = ("critical", "high", "medium", "low", "info")
    severity_counts = Counter(
        str(item.get("severity") or "unknown").strip().lower() for item in reviews
    )
    unclassified_count = len(reviews) - sum(
        severity_counts[level] for level in severity_levels
    )
    severity_summary = "".join(
        f'<span class="severity-count {level}">{level.title()} <strong>{severity_counts[level]}</strong></span>'
        for level in severity_levels
    )
    if unclassified_count:
        severity_summary += f'<span class="severity-count unknown">Unknown <strong>{unclassified_count}</strong></span>'
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    runtime = runtime_evidence if isinstance(runtime_evidence, dict) else None
    workflow = runtime.get("workflow_evidence") if runtime else None
    workflow = workflow if isinstance(workflow, dict) else {}
    zap = runtime.get("zap") if runtime else None
    zap = zap if isinstance(zap, dict) else {}
    browser = runtime.get("browser") if runtime else None
    browser = browser if isinstance(browser, dict) else {}
    scanner_tasks = _items((execution or {}).get("tasks"))
    origins_by_group = review_evidence_origins(review, triage, merged)
    traces_by_group = build_evidence_traces(review, triage, merged, runtime_evidence)

    finding_cards = "".join(
        _finding(
            i,
            item,
            decision_by_id.get(str(item.get("candidate_id")), {}),
            origins_by_group.get(str(item.get("candidate_id")), ("Unclassified",)),
            traces_by_group.get(str(item.get("candidate_id")), []),
        )
        for i, item in enumerate(reviews, 1)
    )
    if not finding_cards:
        finding_cards = '<div class="empty">No Review Agent verdicts were produced. Check the saved scan evidence before drawing conclusions.</div>'

    scanner_cards = [
        f'<div class="scanner"><span>{_e(_scanner_label(item))}</span>{_chip(item.get("status"))}</div>'
        for item in scanner_tasks
    ]
    trivy_cards = "".join(
        card
        for card, item in zip(scanner_cards, scanner_tasks)
        if str(item.get("scanner_id") or "").lower() == "trivy"
    )
    other_cards = "".join(
        card
        for card, item in zip(scanner_cards, scanner_tasks)
        if str(item.get("scanner_id") or "").lower() != "trivy"
    )
    if not trivy_cards:
        trivy_cards = '<p class="muted">No Trivy task records were supplied.</p>'
    if not other_cards:
        other_cards = (
            '<p class="muted">No other scanner task records were supplied.</p>'
        )
    gaps = list(coverage_gaps or ())
    if runtime:
        notes = runtime.get("coverage_notes")
        if isinstance(notes, list):
            gaps.extend(notes)
    if scanner_requirement and isinstance(scanner_requirement.get("failures"), list):
        gaps.extend(scanner_requirement["failures"])
    if discovery and isinstance(discovery.get("warnings"), list):
        gaps.extend(discovery["warnings"])
    if isinstance(review.get("warnings"), list):
        gaps.extend(review["warnings"])
    if pending:
        gaps.append(
            f"{len(pending)} security review groups are pending: "
            + ", ".join(str(value) for value in pending)
        )
    normalized_gaps = []
    source_context_gaps = 0
    generic_gap_map = {
        "A negative result means only that this probe did not observe the behavior.": "Negative results only show that a probe did not observe the behavior.",
        "A violation is an observed contract mismatch requiring security review.": "Workflow violations are observed contract mismatches requiring review.",
        "Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.": "Baseline checks use bounded HTTP GET requests against declared paths.",
        "Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.": "Browser crawl was same-origin and GET-only; forms, OAuth/MFA and destructive workflows were not submitted.",
        "Coverage applies only to declared assertions, accounts and workflows.": "Coverage applies only to declared assertions, accounts and workflows.",
        "Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.": "Each workflow must create independent test data; no per-step database reset is performed.",
        "The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.": "The baseline phase does not crawl browsers, test account workflows or confirm exploitation.",
    }
    for raw_gap in gaps:
        gap = str(raw_gap).strip()
        if not gap:
            continue
        if "primary source context is unavailable" in gap:
            source_context_gaps += 1
            continue
        normalized_gaps.append(generic_gap_map.get(gap, gap))
    if source_context_gaps:
        normalized_gaps.append(
            f"{source_context_gaps} findings have incomplete primary source context."
        )
    gaps = list(dict.fromkeys(normalized_gaps))
    gap_content = _text_list(gaps)

    runtime_facts = (
        (
            _pair("Target", runtime.get("target") or "unknown")
            + _pair("Browser crawl", browser.get("status") or "not requested")
        )
        if runtime
        else '<p class="muted">No generic runtime evidence was supplied.</p>'
    )
    if docker_runtime:
        runtime_facts += _pair(
            "Trusted Docker run", docker_runtime.get("run_id") or "completed"
        )

    discovery_facts = ""
    if discovery is not None:
        discovery_facts = _pair(
            "Provider / model",
            f"{discovery.get('provider', 'unknown')} / {discovery.get('model', 'unknown')}",
        ) + _pair(
            "Required stage satisfied",
            "yes" if discovery_required_satisfied else "no / not verified",
        )
    verification_facts = (
        _pair("Verification", verification.get("status") or "unknown")
        if verification
        else ""
    )
    scanner_requirement_fact = ""
    if scanner_requirement and scanner_requirement.get("requested"):
        scanner_requirement_fact = _pair(
            "Required scanners",
            "satisfied" if scanner_requirement.get("satisfied") else "incomplete",
        )

    review_complete = review.get("status") == "completed" and not pending
    review_state = "Complete" if review_complete else "Incomplete or unverified"
    scan_state = scan_status.capitalize() if scan_status else "Not recorded"
    discovery_status = (
        str(discovery.get("status") or "Not recorded") if discovery else "Not recorded"
    )
    discovery_usage = (
        discovery.get("usage")
        if discovery and isinstance(discovery.get("usage"), dict)
        else {}
    )
    discovery_note = (
        "Discovery stage details saved"
        if discovery_usage
        else "No discovery stage details saved"
    )
    if discovery_required_satisfied is not None:
        discovery_note += (
            " · requirement satisfied"
            if discovery_required_satisfied
            else " · requirement not satisfied"
        )
    discovery_candidate_count = 0
    if triage and isinstance(triage.get("summary"), dict):
        discovery_candidate_count = int(
            triage["summary"].get("input_ai_candidates", 0) or 0
        )
    status_cards = (
        _status(
            "Original pipeline scan",
            scan_state,
            "Original pipeline status; later review does not rerun scanners"
            if scan_status
            else "Original pipeline status unavailable",
            "good"
            if scan_status == "completed"
            else "danger"
            if scan_status == "failed"
            else "warn",
        )
        + _status(
            "Discovery Agent",
            discovery_status.capitalize(),
            discovery_note,
            "good"
            if discovery_status == "completed"
            else "danger"
            if discovery_status == "failed"
            else "warn",
        )
        + _status(
            "Review Agent",
            review_state,
            f"{summary['reviewed_groups']} reviewed · {summary['pending_groups']} pending",
            "good" if review_complete else "warn",
        )
    )

    return (
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>Verdict · Security Review Report</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#e8eef6;background:#09111e;font-size:15px}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;line-height:1.55}a{color:inherit;text-decoration:none}
.shell{max-width:1440px;margin:auto;display:grid;grid-template-columns:230px minmax(0,1fr);min-height:100vh}
aside{position:sticky;top:0;height:100vh;padding:30px 18px;border-right:1px solid #26354a;background:#0d1828}
.brand{font-weight:900;letter-spacing:.12em;font-size:1.25rem;color:#7de7c9;margin:0 0 4px}.brand-sub{font-size:.67rem;letter-spacing:.19em;color:#8da3bb;text-transform:uppercase;margin:0 0 44px}
nav a{display:block;padding:10px 12px;border-radius:9px;color:#a9bbce;font-size:.88rem;margin-bottom:4px}nav a:hover,nav a:focus{background:#192c3e;color:#fff}
.side-note{margin-top:40px;padding:14px;border:1px solid #294557;border-radius:10px;color:#9db2c4;font-size:.78rem}
main{min-width:0;padding:38px clamp(20px,4vw,66px) 80px}.eyebrow{color:#7de7c9;text-transform:uppercase;letter-spacing:.18em;font-size:.72rem;font-weight:800}
h1{font-size:clamp(2rem,4vw,3.6rem);line-height:1.1;margin:.25em 0}.subtitle{color:#aebfd1;margin:0 0 26px;overflow-wrap:anywhere}
.hero{padding:28px 32px;border:1px solid #31526a;border-radius:20px;background:linear-gradient(125deg,#142b3b,#112034 60%,#182439)}
.hero-top{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.hero p{max-width:760px;color:#b6c5d4;margin:12px 0 0}.hero .subtitle{margin:0;overflow-wrap:anywhere}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{display:inline-flex;align-items:center;white-space:nowrap;border-radius:99px;padding:4px 9px;font-weight:750;font-size:.7rem;letter-spacing:.015em;background:#243346;color:#c8d7e5}
.chip.danger{background:#512630;color:#ffc0c7}.chip.warn{background:#4b3b24;color:#ffe2a5}.chip.good{background:#20483c;color:#9df0ce}.chip.neutral{background:#26394e;color:#c4dbef}
.status-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0 20px}.status-card{display:grid;grid-template-columns:1fr;align-content:start;gap:8px;min-height:108px;padding:18px 18px 16px;border:1px solid #2b4056;border-radius:14px;background:#132135}.status-card.danger{border-color:#8a4c59;background:linear-gradient(145deg,#1b2234,#162237)}.status-card.good{border-color:#347665;background:linear-gradient(145deg,#142c35,#142637)}.status-card.warn{border-color:#80633b;background:linear-gradient(145deg,#2a2930,#182437)}.status-label{color:#9eb4c6;font-size:.8rem}.status-card strong,.status-card small{grid-column:auto;text-align:left}.status-card strong{display:block;margin:0;font-size:1.18rem}.status-card small{color:#9eb4c6;font-size:.72rem;line-height:1.45}
.metric-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:26px;margin:14px 0 0}.metric-grid.runtime-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:2px 16px;background:transparent;border:0;border-bottom:1px solid #2b4056;border-radius:0;padding:12px 0;min-height:0}.metric-label{color:#94a9bd;font-size:.8rem}.metric strong,.metric small{grid-column:2;text-align:right}.metric strong{display:block;font-size:1.05rem;line-height:1.35;margin:0;color:#f5f9fd}.metric small{display:block;color:#839bb2;font-size:.72rem}.metric .metric-detail{grid-column:1 / -1;margin-top:6px;padding-top:6px;border-top:0;color:#adc1d1;text-align:left}
.metric-section{margin-bottom:16px}.metric-section .section-head{margin-bottom:0}.metric-note{margin:12px 0 0;color:#91a6b9;font-size:.78rem}.gap-banner{display:flex;justify-content:space-between;align-items:center;gap:14px;margin:0 0 24px;padding:15px 20px;border:1px solid #84613a;border-radius:12px;background:#2b2927}.gap-banner strong{font-size:1rem}.gap-banner span{color:#d3c3a8;font-size:.8rem}.gap-banner a{color:#f5ca85;font-weight:750;white-space:nowrap}.gap-banner a:hover{text-decoration:underline}
section{margin:0 0 24px;padding:24px;background:#111d2f;border:1px solid #263a50;border-radius:16px;scroll-margin-top:20px}
.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:18px}.section-head h2{margin:0;font-size:1.22rem}.section-head span{color:#91a6b9;font-size:.78rem}
.pairs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 24px}.pair{display:flex;justify-content:space-between;gap:16px;padding:11px 0;border-bottom:1px solid #26374a}.pair dt{color:#9cb0c3}.pair dd{margin:0;text-align:right;font-weight:650;overflow-wrap:anywhere}
.scanner-columns{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.scanner-column{display:grid;align-content:start;gap:10px}.scanner-column h4{margin:0 0 2px;color:#9eb4c6;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}.scanner{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:#0d1929;border:1px solid #26394d;border-radius:9px;gap:10px}
.toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:15px}.toolbar input,.toolbar select{background:#0a1625;border:1px solid #365069;color:#edf4fb;border-radius:9px;padding:10px 12px;font:inherit;min-height:42px}.toolbar input{flex:1 1 250px}.toolbar select{flex:0 1 205px}
.severity-counts{display:flex;flex-wrap:wrap;gap:8px;margin:-2px 0 18px}.severity-count{display:inline-flex;align-items:center;gap:7px;padding:5px 10px;border:1px solid #365069;border-radius:99px;color:#b4c8d9;font-size:.8rem}.severity-count strong{color:#f4f8fc;font-variant-numeric:tabular-nums}.severity-count.critical{border-color:#97545e}.severity-count.high{border-color:#87535b}.severity-count.medium{border-color:#8b713e}.severity-count.low{border-color:#456886}
.finding{border:1px solid #2b4056;border-radius:10px;margin-bottom:8px;overflow:hidden;background:#0e1b2c}.finding[hidden]{display:none}.finding summary{list-style:none;display:flex;gap:12px;align-items:center;padding:15px;cursor:pointer}.finding summary::-webkit-details-marker{display:none}.finding summary:hover{background:#17283b}
.finding-no{font-size:.75rem;font-weight:800;color:#7ce5cb;min-width:30px}.finding-main{flex:1;min-width:0}.finding-main strong{display:block;font-size:.95rem}.finding-main small{display:block;color:#869db3;font-size:.69rem;overflow-wrap:anywhere}.finding-tags{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}.chevron{color:#8fa7ba;font-size:1.2rem}.finding details[open] .chevron{transform:rotate(180deg)}
.finding-body{padding:2px 20px 22px 56px;border-top:1px solid #26374a;color:#bdcddd}.finding-body h4{margin:16px 0 4px;color:#7de7c9;font-size:.77rem;letter-spacing:.08em;text-transform:uppercase}.finding-body p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.finding-grid,.evidence-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 28px}.evidence-grid{border-top:1px solid #26374a;margin-top:18px}
.trace-panel{margin:16px 0 22px;padding:14px 18px;border:1px solid #34516a;border-radius:10px;background:#112438}.trace-panel>h4{margin-top:0}.trace{padding:10px 0;border-top:1px solid #2b4258}.trace:first-of-type{border-top:0}.trace p{margin:5px 0}.trace-steps{margin:9px 0;padding-left:24px}.trace-steps>li{padding:6px 0;overflow-wrap:anywhere}.trace-checks{margin:5px 0;padding-left:20px;color:#a8c0d2;font-size:.82rem}.trace-checks li{margin:3px 0}
.policy-note{margin-top:17px;padding:1px 15px 14px;border:1px solid #2d4659;border-radius:9px;background:#132438}.policy-note p{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.detail-list{padding-left:19px;margin:4px 0}.detail-list li{margin:5px 0;overflow-wrap:anywhere}.muted{color:#91a6b9}.empty{color:#97acbe;padding:18px;border:1px dashed #3c5368;border-radius:10px}
.callout{padding:14px 16px;border-left:3px solid #e7ae5d;background:#2d2b2a;color:#e9d7ba;border-radius:0 8px 8px 0}.foot{font-size:.8rem;color:#8ca2b5;padding:8px 0}
@media(max-width:1000px){.shell{grid-template-columns:1fr}aside{position:static;height:auto;border-right:0;border-bottom:1px solid #26354a;padding:15px 20px}.brand-sub,.side-note{display:none}.brand{display:inline-block;margin:0 15px 0 0}nav{display:inline-flex;flex-wrap:wrap}nav a{margin:0;padding:7px 9px}main{padding:22px 16px 55px}.status-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:620px){.hero-top{display:block}.status-grid,.metric-grid,.metric-grid.runtime-metrics,.pairs,.scanner-columns,.finding-grid,.evidence-grid{grid-template-columns:1fr}.gap-banner{align-items:flex-start;flex-direction:column}.finding summary{align-items:flex-start;flex-wrap:wrap}.finding-tags{width:100%;justify-content:flex-start;padding-left:42px}.finding-body{padding-left:18px}.pair dd{max-width:58%}}
@media print{:root{color:#172337;background:#fff}aside,.toolbar{display:none}.shell{display:block}main{padding:0}.hero,section,.metric,.finding{background:#fff;color:#172337;border-color:#bdc9d3}.hero p,.subtitle,.muted,.pair dt{color:#536272}.finding details{display:block}.finding details>.finding-body{display:block}.finding{break-inside:avoid}.chip{border:1px solid #909eaa;color:#172337;background:#fff}}
</style></head><body><div class="shell"><aside><p class="brand">V / VERDICT</p><p class="brand-sub">Security review</p>
<nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#coverage">Coverage</a><a href="#findings">Review findings</a><a href="#gaps">Gaps &amp; limits</a></nav>
<div class="side-note">Offline report · generated from saved evidence.</div></aside><main>
<header id="overview" class="hero"><span class="eyebrow">Security assessment</span><h1>Review report</h1>
<p class="subtitle">"""
        + _e(project)
        + """</p><p class="muted">Generated """
        + _e(generated)
        + """</p></header>
<div class="status-grid" aria-label="Agent and pipeline status">"""
        + status_cards
        + """</div>
<section class="metric-section" aria-labelledby="initial-findings-title"><div class="section-head"><h2 id="initial-findings-title">Initial findings before Review Agent</h2></div>
<div class="metric-grid">"""
        + _metric(
            "Scanner findings",
            summary["observations"] - summary["dast_observations"],
            "static and dependency scanner records",
        )
        + _metric(
            "DAST findings",
            summary["dast_observations"],
            "runtime and web testing records",
        )
        + _metric(
            "Workflow rule violations",
            summary["workflow_violations"],
            "business-rule mismatches recorded during workflows",
        )
        + _metric("ZAP alerts", summary["zap_alerts"], "alerts reported by OWASP ZAP")
        + _metric(
            "All initial findings before Review Agent",
            summary["observations"],
            f"{summary['observations'] - summary['dast_observations']} scanner findings + {summary['dast_observations']} DAST findings",
        )
        + _metric(
            "Discovery Agent candidates",
            discovery_candidate_count,
            f"{discovery_candidate_count} Discovery Agent candidate"
            + ("s" if discovery_candidate_count != 1 else "")
            + " supplied for Review Agent assessment",
        )
        + """</div><p class="metric-note">These source counts can overlap when multiple tools describe the same underlying issue.</p></section>
<div class="gap-banner"><div><strong>"""
        + _e(len(gaps))
        + """ known coverage limitations</strong><br><span>Untested or inconclusive areas; no alert does not mean a pass.</span></div><a href="#gaps">View coverage limits →</a></div>
<section id="coverage"><div class="section-head"><h2>Coverage &amp; execution</h2><span>What actually ran</span></div><div class="pairs">"""
        + runtime_facts
        + discovery_facts
        + verification_facts
        + scanner_requirement_fact
        + """</div>
<h3>Scanner tasks</h3><div class="scanner-columns"><div class="scanner-column"><h4>Trivy tasks</h4>"""
        + trivy_cards
        + """</div><div class="scanner-column"><h4>Other tools</h4>"""
        + other_cards
        + """</div></div></section>
<section id="findings"><div class="section-head"><h2>Security review findings</h2><span>"""
        + _e(len(reviews))
        + """ groups · """
        + _e(len(pending))
        + """ pending</span></div>
<div class="severity-counts" aria-label="Reviewed groups by severity">"""
        + severity_summary
        + """</div>
<p class="metric-note">Evidence type shows where each group originated, not whether a vulnerability was independently proven. Static includes code and dependency scanners; DAST includes runtime checks and ZAP.</p>
<div class="toolbar"><input id="finding-search" type="search" placeholder="Search findings, evidence or remediation" aria-label="Search findings"><select id="verdict-filter" aria-label="Filter by verdict"><option value="">All verdicts</option><option value="confirmed_vulnerability">Confirmed</option><option value="likely_vulnerability">Likely</option><option value="false_positive">False positive</option><option value="needs_more_evidence">Needs more evidence</option></select><select id="severity-filter" aria-label="Filter by severity"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select><select id="origin-filter" aria-label="Filter by evidence type"><option value="">All evidence types</option><option value="static">Static</option><option value="dast">DAST</option><option value="discovery-agent">Discovery Agent</option><option value="unclassified">Unclassified</option></select></div>
<p id="visible-count" class="muted" aria-live="polite"></p>"""
        + finding_cards
        + """</section>
<section id="gaps"><div class="section-head"><h2>Coverage gaps &amp; limitations</h2><span>Read before interpreting a clean result</span></div>"""
        + gap_content
        + """<div class="callout">A missing finding does not prove a vulnerability is absent. Check scope, evidence quality and untested paths before release.</div></section>
<p class="foot">Verdict · standalone local HTML report. No external fonts, scripts or network resources.</p></main></div>
<script>const cards=[...document.querySelectorAll('.finding')];const q=document.querySelector('#finding-search');const v=document.querySelector('#verdict-filter');const s=document.querySelector('#severity-filter');const o=document.querySelector('#origin-filter');const count=document.querySelector('#visible-count');function filter(){let n=0;for(const card of cards){const show=(!q.value||card.dataset.search.includes(q.value.toLowerCase()))&&(!v.value||card.dataset.verdict===v.value)&&(!s.value||card.dataset.severity===s.value)&&(!o.value||card.dataset.origin.split(' ').includes(o.value));card.hidden=!show;if(show)n++}count.textContent=n+' of '+cards.length+' findings shown'}for(const el of [q,v,s,o])el.addEventListener('input',filter);filter();</script>
</body></html>"""
    )

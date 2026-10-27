"""Standalone, escaped HTML view of the saved security review evidence."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
from typing import Any


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _text_list(value: Any) -> str:
    if not isinstance(value, (list, tuple)) or not value:
        return '<p class="muted">None recorded.</p>'
    return '<ul class="detail-list">' + ''.join(f'<li>{_e(item)}</li>' for item in value) + '</ul>'


def _chip(value: Any, kind: str = "") -> str:
    label = str(value or "unknown")
    normalized = label.lower().replace(" ", "-").replace("_", "-")
    tone = {
        "confirmed-vulnerability": "danger", "block": "danger", "failed": "danger", "high": "danger",
        "likely-vulnerability": "warn", "warn": "warn", "medium": "warn", "partial": "warn",
        "completed": "good", "allow": "good", "false-positive": "good",
        "needs-more-evidence": "neutral", "low": "neutral", "info": "neutral",
    }.get(normalized, "neutral")
    return f'<span class="chip {tone}" aria-label="{_e(kind + label)}">{_e(label.replace("_", " "))}</span>'


def _metric(label: str, value: Any, note: str = "") -> str:
    return (f'<div class="metric"><span class="metric-label">{_e(label)}</span>'
            f'<strong>{_e(value)}</strong><small>{_e(note)}</small></div>')


def _pair(label: str, value: Any) -> str:
    return f'<div class="pair"><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>'


def _finding(index: int, item: dict[str, Any], action: str) -> str:
    title = item.get("title") or "Untitled finding"
    verdict = item.get("verdict") or "not_reviewed"
    severity = item.get("severity") or "unknown"
    searchable = " ".join(
        [str(item.get(key) or "") for key in ("title", "verdict", "severity", "explanation", "remediation")]
        + [str(value) for key in ("evidence", "limitations", "source_ids")
           for value in (item.get(key) if isinstance(item.get(key), list) else [])]
    )
    evidence = _text_list(item.get("evidence"))
    limits = _text_list(item.get("limitations"))
    sources = _text_list(item.get("source_ids"))
    return (
        f'<article class="finding" data-verdict="{_e(verdict)}" data-severity="{_e(severity)}" '
        f'data-search="{_e(searchable.lower())}">'
        f'<details><summary><span class="finding-no">{index:02d}</span>'
        f'<span class="finding-main"><strong>{_e(title)}</strong><small>{_e(item.get("candidate_id") or "")}</small></span>'
        f'<span class="finding-tags">{_chip(severity)}{_chip(verdict)}{_chip(action)}</span>'
        '<span class="chevron" aria-hidden="true">⌄</span></summary>'
        '<div class="finding-body">'
        '<div class="finding-grid">'
        f'<div><h4>Assessment</h4><p>{_e(item.get("explanation") or "Not recorded.")}</p></div>'
        f'<div><h4>Impact</h4><p>{_e(item.get("impact") or "Not recorded.")}</p></div>'
        f'<div><h4>Remediation</h4><p>{_e(item.get("remediation") or "Not recorded.")}</p></div>'
        '</div><div class="evidence-grid">'
        f'<div><h4>Evidence</h4>{evidence}</div>'
        f'<div><h4>Source IDs</h4>{sources}</div>'
        f'<div><h4>Limitations</h4>{limits}</div>'
        '</div></div></details></article>'
    )


def render_html_report(*, project: str, review: dict[str, Any], policy: dict[str, Any],
                       triage: dict[str, Any] | None = None, verification: dict[str, Any] | None = None,
                       discovery: dict[str, Any] | None = None,
                       discovery_required_satisfied: bool | None = None,
                       docker_runtime: dict[str, Any] | None = None,
                       runtime_evidence: dict[str, Any] | None = None,
                       merged: dict[str, Any] | None = None,
                       risk: dict[str, Any] | None = None,
                       execution: dict[str, Any] | None = None,
                       scanner_requirement: dict[str, Any] | None = None,
                       coverage_gaps: list[str] | tuple[str, ...] | None = None) -> str:
    """Render a local-first report; every external value is HTML-escaped."""
    reviews = _items(review.get("reviews"))
    observations = _items((merged or {}).get("findings"))
    decisions = _items(policy.get("decisions"))
    action_by_id = {str(item.get("candidate_id")): str(item.get("action") or "not set") for item in decisions}
    verdicts = Counter(str(item.get("verdict") or "unknown") for item in reviews)
    blocks = sum(item.get("action") == "block" for item in decisions)
    pending = review.get("pending_ids") if isinstance(review.get("pending_ids"), list) else []
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    runtime = runtime_evidence if isinstance(runtime_evidence, dict) else None
    workflow = runtime.get("workflow_evidence") if runtime else None
    workflow = workflow if isinstance(workflow, dict) else {}
    workflow_counts = workflow.get("coverage") if isinstance(workflow.get("coverage"), dict) else {}
    zap = runtime.get("zap") if runtime else None
    zap = zap if isinstance(zap, dict) else {}
    browser = runtime.get("browser") if runtime else None
    browser = browser if isinstance(browser, dict) else {}
    scanner_tasks = _items((execution or {}).get("tasks"))
    risk_items = _items((risk or {}).get("findings"))
    ranks = {str(item.get("merged_finding_id")): item for item in risk_items}
    observations.sort(key=lambda item: (ranks.get(str(item.get("merged_finding_id")), {}).get("rank")
                                       if isinstance(ranks.get(str(item.get("merged_finding_id")), {}).get("rank"), int)
                                       else 10**9, str(item.get("merged_finding_id"))))

    finding_cards = ''.join(_finding(i, item, action_by_id.get(str(item.get("candidate_id")), "not set"))
                            for i, item in enumerate(reviews, 1))
    if not finding_cards:
        finding_cards = '<div class="empty">No agent verdicts were produced. Scanner observations remain below.</div>'

    observation_rows = []
    for item in observations:
        canonical = item.get("canonical_finding") if isinstance(item.get("canonical_finding"), dict) else {}
        location = item.get("primary_location") if isinstance(item.get("primary_location"), dict) else {}
        origin = "DAST" if "dast" in (item.get("categories") or []) else "Static / dependency"
        path = str(location.get("path") or "unknown")
        if isinstance(location.get("start_line"), int):
            path += f':{location["start_line"]}'
        scanners = item.get("scanners") if isinstance(item.get("scanners"), list) else []
        observation_rows.append(
            '<tr>'
            f'<td><strong>{_e(canonical.get("title") or "Untitled observation")}</strong>'
            f'<small>{_e(item.get("merged_finding_id") or "")}</small></td>'
            f'<td>{_e(origin)}</td><td>{_e(", ".join(str(value) for value in scanners))}</td>'
            f'<td><code>{_e(path)}</code></td><td>{_chip(item.get("severity"))}</td></tr>'
        )

    scanner_content = ''.join(
        f'<div class="scanner"><span>{_e(item.get("scanner_id") or "unknown")}</span>'
        f'{_chip(item.get("status"))}</div>' for item in scanner_tasks
    ) or '<p class="muted">Execution details were not included in this saved report.</p>'
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
        gaps.append(f"{len(pending)} security review groups are pending: " + ", ".join(str(value) for value in pending))
    gaps = list(dict.fromkeys(str(gap) for gap in gaps if gap))
    gap_content = _text_list(gaps)

    runtime_facts = (
        _pair("Target", runtime.get("target") or "unknown")
        + _pair("Bounded HTTP probes", len(runtime.get("results") or []))
        + _pair("ZAP", f'{zap.get("status", "not requested")} · {zap.get("engine", "—")} · {zap.get("alerts", 0)} alerts')
        + _pair("Business workflows", f'{workflow.get("status", "not requested")} · {workflow_counts.get("executed", 0)} executed · {workflow_counts.get("violations", 0)} violations')
        + _pair("Browser crawl", browser.get("status") or "not requested")
    ) if runtime else '<p class="muted">No generic runtime evidence was supplied.</p>'
    if docker_runtime:
        runtime_facts += _pair("Trusted Docker run", docker_runtime.get("run_id") or "completed")

    discovery_facts = ''
    if discovery is not None:
        usage = discovery.get("usage") if isinstance(discovery.get("usage"), dict) else {}
        discovery_facts = (_pair("AI discovery", discovery.get("status") or "unknown")
                           + _pair("Provider / model", f'{discovery.get("provider", "unknown")} / {discovery.get("model", "unknown")}')
                           + _pair("Targets inspected", f'{usage.get("targets", 0)} / {usage.get("planned_targets", 0)}')
                           + _pair("Required stage satisfied", "yes" if discovery_required_satisfied else "no / not verified"))
    verification_facts = _pair("Verification", verification.get("status") or "unknown") if verification else ''
    triage_facts = ''
    if triage:
        summary = triage.get("summary") if isinstance(triage.get("summary"), dict) else {}
        triage_facts = (_pair("AI candidates", summary.get("input_ai_candidates", 0))
                        + _pair("Review groups", summary.get("review_groups", len(reviews))))
    scanner_requirement_fact = ''
    if scanner_requirement and scanner_requirement.get("requested"):
        scanner_requirement_fact = _pair("Required scanners", "satisfied" if scanner_requirement.get("satisfied") else "incomplete")

    return '''<!doctype html>
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
.hero-top{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.hero p{max-width:760px;color:#b6c5d4;margin:12px 0 0}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{display:inline-flex;align-items:center;white-space:nowrap;border-radius:99px;padding:4px 9px;font-weight:750;font-size:.7rem;letter-spacing:.015em;background:#243346;color:#c8d7e5}
.chip.danger{background:#512630;color:#ffc0c7}.chip.warn{background:#4b3b24;color:#ffe2a5}.chip.good{background:#20483c;color:#9df0ce}.chip.neutral{background:#26394e;color:#c4dbef}
.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0 34px}.metric{background:#132135;border:1px solid #294057;border-radius:14px;padding:16px 18px;min-height:106px}
.metric-label{display:block;color:#94a9bd;font-size:.77rem;font-weight:700}.metric strong{display:block;font-size:1.85rem;line-height:1.35;margin:4px 0;color:#f5f9fd}.metric small{color:#839bb2;font-size:.72rem}
section{margin:0 0 24px;padding:24px;background:#111d2f;border:1px solid #263a50;border-radius:16px;scroll-margin-top:20px}
.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:18px}.section-head h2{margin:0;font-size:1.22rem}.section-head span{color:#91a6b9;font-size:.78rem}
.pairs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 24px}.pair{display:flex;justify-content:space-between;gap:16px;padding:11px 0;border-bottom:1px solid #26374a}.pair dt{color:#9cb0c3}.pair dd{margin:0;text-align:right;font-weight:650;overflow-wrap:anywhere}
.scanner-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.scanner{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:#0d1929;border:1px solid #26394d;border-radius:9px;gap:10px}
.toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:15px}.toolbar input,.toolbar select{background:#0a1625;border:1px solid #365069;color:#edf4fb;border-radius:9px;padding:10px 12px;font:inherit;min-height:42px}.toolbar input{flex:1 1 250px}.toolbar select{flex:0 1 205px}
.finding{border:1px solid #2b4056;border-radius:10px;margin-bottom:8px;overflow:hidden;background:#0e1b2c}.finding[hidden]{display:none}.finding summary{list-style:none;display:flex;gap:12px;align-items:center;padding:15px;cursor:pointer}.finding summary::-webkit-details-marker{display:none}.finding summary:hover{background:#17283b}
.finding-no{font-size:.75rem;font-weight:800;color:#7ce5cb;min-width:30px}.finding-main{flex:1;min-width:0}.finding-main strong{display:block;font-size:.95rem}.finding-main small{display:block;color:#869db3;font-size:.69rem;overflow-wrap:anywhere}.finding-tags{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}.chevron{color:#8fa7ba;font-size:1.2rem}.finding details[open] .chevron{transform:rotate(180deg)}
.finding-body{padding:2px 20px 22px 56px;border-top:1px solid #26374a;color:#bdcddd}.finding-body h4{margin:16px 0 4px;color:#7de7c9;font-size:.77rem;letter-spacing:.08em;text-transform:uppercase}.finding-body p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.finding-grid,.evidence-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 28px}.evidence-grid{border-top:1px solid #26374a;margin-top:18px}
.detail-list{padding-left:19px;margin:4px 0}.detail-list li{margin:5px 0;overflow-wrap:anywhere}.muted{color:#91a6b9}.empty{color:#97acbe;padding:18px;border:1px dashed #3c5368;border-radius:10px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.84rem}th{text-align:left;color:#92acc2;background:#17283c;font-size:.73rem;letter-spacing:.06em;text-transform:uppercase}th,td{padding:12px;border-bottom:1px solid #27384a;vertical-align:top}td small{display:block;color:#8199b0;font-size:.68rem;overflow-wrap:anywhere}td code{white-space:nowrap;color:#8ee7ce}
.callout{padding:14px 16px;border-left:3px solid #e7ae5d;background:#2d2b2a;color:#e9d7ba;border-radius:0 8px 8px 0}.foot{font-size:.8rem;color:#8ca2b5;padding:8px 0}
@media(max-width:1000px){.shell{grid-template-columns:1fr}aside{position:static;height:auto;border-right:0;border-bottom:1px solid #26354a;padding:15px 20px}.brand-sub,.side-note{display:none}.brand{display:inline-block;margin:0 15px 0 0}nav{display:inline-flex;flex-wrap:wrap}nav a{margin:0;padding:7px 9px}main{padding:22px 16px 55px}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:620px){.hero-top{display:block}.metric-grid,.pairs,.scanner-grid,.finding-grid,.evidence-grid{grid-template-columns:1fr}.finding summary{align-items:flex-start}.finding-tags{display:none}.finding-body{padding-left:18px}.pair dd{max-width:58%}}
@media print{:root{color:#172337;background:#fff}aside,.toolbar{display:none}.shell{display:block}main{padding:0}.hero,section,.metric,.finding{background:#fff;color:#172337;border-color:#bdc9d3}.hero p,.subtitle,.muted,.pair dt{color:#536272}.finding details{display:block}.finding details>.finding-body{display:block}.finding{break-inside:avoid}.chip{border:1px solid #909eaa;color:#172337;background:#fff}}
</style></head><body><div class="shell"><aside><p class="brand">V / VERDICT</p><p class="brand-sub">Security review</p>
<nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#coverage">Coverage</a><a href="#findings">Review findings</a><a href="#observations">Original observations</a><a href="#gaps">Gaps &amp; limits</a></nav>
<div class="side-note">Offline report · generated from saved evidence. Model verdicts are not independent exploit proof.</div></aside><main>
<header id="overview" class="hero"><div class="hero-top"><div><span class="eyebrow">Security assessment</span><h1>Review report</h1><p class="subtitle">''' + _e(project) + '''</p></div><div class="chips">''' + _chip(policy.get("status"), "Policy: ") + _chip(review.get("status"), "Review: ") + '''</div></div>
<p>Policy <strong>''' + ("blocks release" if policy.get("blocking") else "does not block release") + '''</strong>. A completed scan can still fail the security policy. Findings are model assessments of evidence, not a count of distinct independently validated vulnerabilities.</p>
<p class="muted">Generated ''' + _e(generated) + '''</p></header>
<div class="metric-grid">''' + _metric("Reviewed groups", len(reviews), f'{len(pending)} pending') + _metric("Original observations", len(observations), "scanner + DAST") + _metric("Policy blocks", blocks, "release gate") + _metric("Confirmed verdicts", verdicts.get("confirmed_vulnerability", 0), "agent assessments") + '''</div>
<section id="coverage"><div class="section-head"><h2>Coverage &amp; execution</h2><span>What actually ran</span></div><div class="pairs">''' + runtime_facts + discovery_facts + verification_facts + triage_facts + scanner_requirement_fact + '''</div>
<h3>Scanner tasks</h3><div class="scanner-grid">''' + scanner_content + '''</div></section>
<section id="findings"><div class="section-head"><h2>Security review findings</h2><span>''' + _e(len(reviews)) + ''' groups · ''' + _e(len(pending)) + ''' pending</span></div>
<div class="toolbar"><input id="finding-search" type="search" placeholder="Search findings, evidence or remediation" aria-label="Search findings"><select id="verdict-filter" aria-label="Filter by verdict"><option value="">All verdicts</option><option value="confirmed_vulnerability">Confirmed</option><option value="likely_vulnerability">Likely</option><option value="false_positive">False positive</option><option value="needs_more_evidence">Needs more evidence</option></select><select id="severity-filter" aria-label="Filter by severity"><option value="">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></div>
<p id="visible-count" class="muted" aria-live="polite"></p>''' + finding_cards + '''</section>
<section id="observations"><div class="section-head"><h2>Original scanner &amp; DAST observations</h2><span>Before agent review · preserved separately</span></div>
<p class="muted">Observations are signals, not automatically confirmed vulnerabilities. Correlated results remain traceable by record ID.</p><div class="table-wrap"><table><thead><tr><th>Observation</th><th>Source</th><th>Scanner</th><th>Location</th><th>Severity</th></tr></thead><tbody>''' + ''.join(observation_rows) + '''</tbody></table></div></section>
<section id="gaps"><div class="section-head"><h2>Coverage gaps &amp; limitations</h2><span>Read before interpreting a clean result</span></div>''' + gap_content + '''<div class="callout">A missing finding does not prove a vulnerability is absent. Check scope, evidence quality and untested paths before release.</div></section>
<p class="foot">Verdict · standalone local HTML report. No external fonts, scripts or network resources.</p></main></div>
<script>const cards=[...document.querySelectorAll('.finding')];const q=document.querySelector('#finding-search');const v=document.querySelector('#verdict-filter');const s=document.querySelector('#severity-filter');const count=document.querySelector('#visible-count');function filter(){let n=0;for(const card of cards){const show=(!q.value||card.dataset.search.includes(q.value.toLowerCase()))&&(!v.value||card.dataset.verdict===v.value)&&(!s.value||card.dataset.severity===s.value);card.hidden=!show;if(show)n++}count.textContent=n+' of '+cards.length+' findings shown'}for(const el of [q,v,s])el.addEventListener('input',filter);filter();</script>
</body></html>'''

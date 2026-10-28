"""Self-contained HTML renderer for the final report (no network access, dark-mode aware, printable).

Every string from scanners, models or the repository is HTML-escaped *before* the small inline formatter
(`code`, **bold**) runs, so report content can never inject markup or script.  A strict Content-Security-Policy
blocks any external request even if that guarantee were broken.
"""

from __future__ import annotations

import html
import re

from security_reviewer_v2.policy.rules import RULES

from .view import ACTION_ICON, SEVERITY_ICON, Finding, ReportView, first_sentence, lead

_CSS = """
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--ink:#14181f;--mut:#5b6573;--line:#e3e7ee;--accent:#3b5bdb;
--crit:#c92a2a;--high:#e8590c;--med:#d9a400;--low:#1c7ed6;--info:#868e96;--ok:#2b8a3e;--warn:#e67700;--block:#c92a2a;
--chip:#eef1f6;--code:#eef1f6;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08)}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#161b22;--ink:#e6edf3;--mut:#9aa6b2;--line:#2a313c;
--accent:#7c93ff;--chip:#222a35;--code:#222a35;--shadow:none}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:28px 20px 80px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:34px 0 12px;display:flex;align-items:center;gap:8px}
h3{font-size:1rem;margin:0}small,.mut{color:var(--mut)}
code{background:var(--code);padding:1px 6px;border-radius:5px;font:0.86em ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.banner{border-radius:14px;padding:20px 22px;color:#fff;box-shadow:var(--shadow);margin:14px 0 8px}
.banner h2{margin:0 0 6px;font-size:1.35rem;color:#fff}.banner p{margin:4px 0;opacity:.96}
.banner.blocked{background:linear-gradient(135deg,#c92a2a,#8f1f1f)}.banner.incomplete{background:linear-gradient(135deg,#e67700,#a85600)}
.banner.clear{background:linear-gradient(135deg,#2b8a3e,#1d6a2d)}.banner.no_findings{background:linear-gradient(135deg,#5b6573,#3d4651)}
.meta{display:flex;flex-wrap:wrap;gap:6px 14px;color:var(--mut);font-size:.85rem;margin:8px 2px 0}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.kpi{flex:1 1 150px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.kpi b{display:block;font-size:1.7rem;line-height:1.1}.kpi span{color:var(--mut);font-size:.8rem}
.kpi.block b{color:var(--block)}.kpi.warn b{color:var(--warn)}.kpi.ok b{color:var(--ok)}
.card,.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
.panel{padding:16px 18px}.bars{display:grid;gap:7px}
.bar{display:grid;grid-template-columns:78px 1fr 34px;align-items:center;gap:10px;font-size:.88rem}
.bar i{display:block;height:10px;border-radius:6px;background:var(--c)}.bar .track{background:var(--chip);border-radius:6px}
.sev-critical{--c:var(--crit)}.sev-high{--c:var(--high)}.sev-medium{--c:var(--med)}.sev-low{--c:var(--low)}.sev-info{--c:var(--info)}
.chip{display:inline-block;background:var(--chip);border-radius:999px;padding:2px 10px;margin:0 2px;font-size:.78rem;white-space:nowrap}
.chip.sev{background:var(--c);color:#fff;font-weight:600}.chip.block{background:var(--block);color:#fff;font-weight:600}
.chip.warn{background:var(--warn);color:#fff;font-weight:600}.chip.allow{background:var(--ok);color:#fff;font-weight:600}
.fix{display:grid;gap:10px;margin:0;padding:0;list-style:none}
.fix li{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--c);border-radius:10px;padding:12px 14px}
.fix .t{font-weight:650}.fix .w{color:var(--mut);font-size:.88rem;margin-top:2px}.fix .f{margin-top:6px}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.tools button{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:5px 12px;border-radius:999px;cursor:pointer;font:inherit;font-size:.82rem}
.tools button[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;font-size:.88rem}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--chip);font-weight:600}
tr:last-child td{border-bottom:0}.scroll{overflow-x:auto}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
details.card{border-left:5px solid var(--c);margin:10px 0}details.card>summary{list-style:none;cursor:pointer;padding:13px 16px;display:grid;gap:6px}
details.card>summary::-webkit-details-marker{display:none}.sum{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.body{padding:0 18px 16px;border-top:1px solid var(--line)}.kv{margin:12px 0 0}.kv b{display:inline-block;min-width:74px;color:var(--mut);font-weight:600}
.refs{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.sub{margin:14px 0 4px;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
ul.tight{margin:4px 0;padding-left:20px}ul.tight li{margin:3px 0}pre{background:var(--code);padding:12px;border-radius:8px;overflow:auto;font-size:.8rem;white-space:pre-wrap}
.note{border-left:4px solid var(--warn);background:var(--card);padding:10px 14px;border-radius:8px;margin:8px 0;border:1px solid var(--line);border-left-width:4px}
footer{margin-top:44px;color:var(--mut);font-size:.8rem;text-align:center}
@page{size:A4;margin:12mm}
@media print{body{background:#fff;color:#000;font-size:12px}.wrap{max-width:none;padding:0}.tools{display:none}.scroll{overflow:visible}table{font-size:.78rem}th,td{padding:5px 7px}details.card{break-inside:avoid}details>*{display:block!important}}
"""

_JS = """
(function(){var cards=[].slice.call(document.querySelectorAll('[data-f]')),btns=[].slice.call(document.querySelectorAll('.tools button[data-k]'));
function apply(k,v){cards.forEach(function(c){var ok=k==='all'||c.getAttribute('data-'+k)===v;c.hidden=!ok});
btns.forEach(function(b){b.setAttribute('aria-pressed',String(b.getAttribute('data-k')===k&&b.getAttribute('data-v')===v))})}
btns.forEach(function(b){b.addEventListener('click',function(){apply(b.getAttribute('data-k'),b.getAttribute('data-v'))})});
var t=document.getElementById('toggle');if(t){t.addEventListener('click',function(){var o=t.getAttribute('data-open')!=='1';
document.querySelectorAll('details.card').forEach(function(d){d.open=o});t.setAttribute('data-open',o?'1':'0');t.textContent=o?'Collapse all':'Expand all'})}})();
"""


def _e(value: object) -> str:
    return html.escape(" ".join(str(value).split()), quote=True)


def _rich(text: object) -> str:
    """Escape first, then allow only `code` and **bold** formatting."""
    safe = html.escape(str(text).strip(), quote=True).replace("\n", "<br>")
    safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", safe)
    safe = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", safe)
    return re.sub(r"(?<![*\w])\*([^*\s][^*]*?)\*(?![*\w])", r"<em>\1</em>", safe)


def _sev(severity: str) -> str:
    return f'<span class="chip sev sev-{_e(severity)}">{_e(severity.upper())}</span>'


def _action(f_action: str, rule: str) -> str:
    cls = f_action if f_action in {"block", "warn", "allow"} else ""
    return f'<span class="chip {cls}">{ACTION_ICON.get(f_action, "")} {_e(f_action)}' + (f" · {_e(rule)}" if rule else "") + "</span>"


def render_html(view: ReportView) -> str:
    c = view.counts
    cov = f"{view.coverage_done}/{view.coverage_total}" if view.has_execution and view.coverage_total else "n/a"
    dedup = f"{view.dedup[0]}→{view.dedup[1]}" if view.dedup else "n/a"
    parts: list[str] = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">",
        f"<title>Security Review · {_e(view.project)}</title><style>{_CSS}</style></head><body><div class=\"wrap\">",
        "<h1>🛡️ Security Review Report</h1>",
        f'<div class="banner {_e(view.decision)}"><h2>{_e(view.headline)}</h2>'
        + "".join(f"<p>{_e(s)}</p>" for s in view.bottom_line) + "</div>",
        '<div class="meta">' + "".join(f"<span>{x}</span>" for x in (
            f"Project <code>{_e(view.project)}</code>", f"Generated {_e(view.generated)}",
            f"Policy <code>{_e(view.policy_status)}</code>", f"Review <code>{_e(view.review_status)}</code>",
            *( [f"Rules <code>{_e(view.rule_set)}</code>"] if view.rule_set else []))) + "</div>",
    ]
    for note in _notes(view):
        parts.append(f'<div class="note">{note}</div>')
    parts.append('<div class="kpis">' + "".join(
        f'<div class="kpi {cls}"><b>{_e(value)}</b><span>{_e(label)}</span></div>' for cls, value, label in (
            ("", c["reviewed"], "issues reviewed"), ("block", c["block"], "blocking"), ("warn", c["warn"], "need manual review"),
            ("ok", c["allow"], "cleared"), ("", cov, "scanners completed"), ("", dedup, "duplicates merged"),
            ("", "performed" if view.dynamic else "not run", "dynamic testing"))) + "</div>")
    if view.severity_counts:
        parts.append('<div class="panel"><div class="bars">' + "".join(
            f'<div class="bar sev-{_e(s)}"><span>{_e(s.capitalize())}</span><span class="track"><i style="width:{max(4, round(100 * n / c["reviewed"]))}%"></i></span><b>{n}</b></div>'
            for s, n in view.severity_counts) + "</div></div>")

    parts.append("<h2>🎯 Fix first</h2>")
    if view.blocking:
        parts.append('<ol class="fix">' + "".join(
            f'<li class="sev-{_e(f.severity)}"><div class="t"><a href="#f{f.number}">{_e(f.title)}</a> {_sev(f.severity)} {_action(f.action, f.rule_id)}</div>'
            f'<div class="w">' + " · ".join(x for x in (
                ("<code>" + _e(f.location) + "</code>") if f.location else "",
                f"{f.corroboration} tools agree" if f.corroboration > 1 else "", _e(", ".join(f.cwes))) if x) + "</div>"
            + (f'<div class="f"><b>Fix:</b> {_rich(first_sentence(f.remediation))}</div>' if f.remediation else "") + "</li>"
            for f in view.blocking) + "</ol>")
    else:
        parts.append('<div class="panel">Nothing met the automatic blocking criteria. This is not a security clearance.</div>')
    if view.next_steps:
        parts.append('<div class="sub">Then</div><ol class="tight">' + "".join(f"<li>{_e(s)}</li>" for s in view.next_steps) + "</ol>")

    if view.findings:
        sevs = sorted({f.severity for f in view.findings}, key=lambda s: (["critical", "high", "medium", "low", "info"].index(s) if s in ["critical", "high", "medium", "low", "info"] else 9))
        parts.append("<h2>Findings</h2><div class=\"tools\"><button data-k=\"all\" data-v=\"\" aria-pressed=\"true\">All</button>"
                     + "".join(f'<button data-k="action" data-v="{a}" aria-pressed="false">{ACTION_ICON[a]} {a}</button>' for a in ("block", "warn"))
                     + "".join(f'<button data-k="sev" data-v="{_e(s)}" aria-pressed="false">{SEVERITY_ICON.get(s, "")} {_e(s)}</button>' for s in sevs)
                     + '<button id="toggle" data-open="0" aria-pressed="false">Expand all</button></div>')
        parts.append('<div class="scroll"><table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Location</th><th>Verdict</th><th>Tools</th><th>Decision</th></tr></thead><tbody>'
                     + "".join(
                         f'<tr data-f data-action="{_e(f.action)}" data-sev="{_e(f.severity)}"><td>{f.number}</td><td><a href="#f{f.number}">{_e(f.title)}</a></td>'
                         f'<td>{_sev(f.severity)}</td><td>{("<code>" + _e(f.location) + "</code>") if f.location else "—"}</td>'
                         f'<td>{_e(f.verdict.replace("_", " "))}</td><td>{f.corroboration or "—"}</td><td>{_action(f.action, f.rule_id)}</td></tr>'
                         for f in view.findings) + "</tbody></table></div>")
        for f in view.findings:
            parts.append(_card(f, opened=f.action == "block" and f.number <= 2))

    parts.append("<h2>🧭 Coverage &amp; trust</h2>")
    if view.scanners:
        parts.append('<div class="scroll"><table><thead><tr><th>Scanner</th><th>Result</th><th>What it means</th></tr></thead><tbody>' + "".join(
            f"<tr><td><b>{_e(r.role)}</b></td><td>{'✅' if r.status == 'completed' else '➖' if r.status == 'not_scheduled' else '❌'} {_e(r.outcome)} <small>({_e(r.status)})</small></td>"
            f"<td>{_e(r.meaning)}" + "".join(f'<br><small>{_e(n)}</small>' for n in r.notes) + "</td></tr>" for r in view.scanners) + "</tbody></table></div>")
        parts.append(f'<p class="mut">{view.coverage_done} of {view.coverage_total} applicable scanner task(s) completed.'
                     + (f" {view.skipped_tasks} skipped as not applicable." if view.skipped_tasks else "")
                     + (f" Registered but not scheduled (nothing to scan): {_e(', '.join(view.not_scheduled))}." if view.not_scheduled else "") + "</p>")
    if view.dedup:
        parts.append(f'<p><b>Deduplication.</b> {view.dedup[0]} raw scanner results → {view.dedup[1]} root-cause records '
                     f"({view.dedup[2]} duplicates merged: same vulnerability family, file and overlapping lines). "
                     "Nothing is discarded; every raw result and rule id stays attached to its record.</p>")
    if view.gaps:
        parts.append('<div class="sub">Known gaps — each lowers confidence in a clean result for that area</div><ul class="tight">'
                     + "".join(f"<li>{_e(g)}</li>" for g in view.gaps) + "</ul>")
    if view.runtime_lines:
        parts.append("<details class=\"panel\"><summary>Runtime evidence</summary><pre>" + html.escape("\n".join(view.runtime_lines)) + "</pre></details>")

    parts.append("<h2>Appendix</h2>")
    if view.policy_rows:
        parts.append("<details class=\"panel\"><summary><b>A. Release-gate decisions</b></summary><p class=\"mut\">Each decision comes from one named rule applied to the AI verdict <b>and</b> deterministic evidence; the AI description alone never blocks a release.</p>"
                     '<div class="scroll"><table><thead><tr><th>Action</th><th>Rule</th><th>Finding</th><th>Severity</th><th>Evidence basis</th></tr></thead><tbody>'
                     + "".join(f"<tr><td>{_action(str(d.get('action')), '')}</td><td><code>{_e(d.get('rule_id') or '—')}</code></td><td>{_e(d.get('title'))}</td>"
                               f"<td>{_e(d.get('severity', '—'))}</td><td>{_e(str(d.get('evidence_basis') or '—').replace('_', ' '))}</td></tr>" for d in view.policy_rows)
                     + "</tbody></table></div><ul class=\"tight\">"
                     + "".join(f"<li><code>{_e(r)}</code> — {_e(RULES[r].title)}</li>" for r in sorted({str(d.get('rule_id')) for d in view.policy_rows if d.get('rule_id') in RULES}))
                     + "</ul></details>")
    if view.observations:
        parts.append(f"<details class=\"panel\"><summary><b>B. Scanner and DAST observations</b> ({len(view.observations)})</summary><p class=\"mut\">Signals to assess, not confirmed independent vulnerabilities.</p>"
                     '<div class="scroll"><table><thead><tr><th>#</th><th>Observation</th><th>Origin</th><th>Evidence</th><th>Location</th><th>Severity</th><th>Risk</th></tr></thead><tbody>'
                     + "".join(f"<tr><td>{o.number}</td><td>{_e(o.title)}<br><small>{_e(', '.join(o.rule_ids))}</small></td><td>{_e(o.origin)}</td><td>{o.evidence_count}</td>"
                               f"<td><code>{_e(o.location)}</code></td><td>{_e(o.severity)}</td><td>{_e(o.risk)}</td></tr>" for o in view.observations)
                     + "</tbody></table></div></details>")
    if view.triage is not None:
        t = view.triage
        parts.append("<details class=\"panel\"><summary><b>C. Candidate triage</b></summary><p>"
                     f"Observation records: {_e(t.get('input_scanner_findings', 0))}; issue groups after correlation: {_e(t.get('review_groups', 0))}. "
                     f"AI candidates: {_e(t.get('input_ai_candidates', 0))}; new: {_e(t.get('novel_candidates', 0))}; needs more evidence: {_e(t.get('needs_more_evidence', 0))}; rejected: {_e(t.get('rejected', 0))}.</p>"
                     + ("<ul class=\"tight\">" + "".join(f"<li><code>{_e(cid)}</code>: {_e(disp)}" + (f" at <code>{_e(where)}</code>" if where else "") + "</li>" for cid, disp, where in view.unresolved) + "</ul>" if view.unresolved else "")
                     + "</details>")
    parts.append("<details class=\"panel\"><summary><b>D. Method and limitations</b></summary><ul class=\"tight\">"
                 + "".join(f"<li>{_e(s)}</li>" for s in view.limitations) + "</ul></details>")
    parts.append(f"<footer>Static report · no external requests · generated {_e(view.generated)}</footer></div><script>{_JS}</script></body></html>")
    return "".join(parts)


def _notes(view: ReportView) -> list[str]:
    notes: list[str] = []
    req = view.scanner_requirement
    if req and req.get("requested") and not req.get("satisfied"):
        notes.append("<b>This scan is incomplete.</b> One or more required scanners did not complete with normalized output."
                     + "".join(f"<br><small>{_e(i)}</small>" for i in req.get("failures", [])))
    ai = view.ai
    if ai is not None:
        stage = ai["required_ok"]
        label = "completed" if stage is True else "incomplete" if stage is False else "not verified in this saved run"
        notes.append(f"<b>AI Discovery</b> {_e(label)} · status <code>{_e(ai['status'])}</code> · {_e(ai['provider'])} / <code>{_e(ai['model'])}</code> · "
                     f"targets {_e(ai['targets'])}/{_e(ai['planned'])} · model calls {_e(ai['calls'])}"
                     + "".join(f"<br><small>{_e(w)}</small>" for w in ai["warnings"]))
    return notes


def _card(f: Finding, *, opened: bool) -> str:
    refs = "".join(f'<span class="chip">{_e(x)}</span>' for x in (*f.cwes, *("OWASP " + o for o in f.owasp)))
    if f.corroboration:
        refs += f'<span class="chip">detected by {f.corroboration} tool(s)</span>'
    body = [f'<div class="refs">{refs}</div>' if refs else ""]
    full: list[tuple[str, str]] = []
    for label, text, sentences, limit in (("Problem", f.explanation, 2, 360), ("Impact", f.impact, 1, 220),
                                          ("Fix", f.remediation, 2, 360)):
        if text:
            short, cut = lead(text, sentences, limit)
            body.append(f'<p class="kv"><b>{label}</b> {_rich(short)}</p>')
            if cut:
                full.append((label, text))
    if full:
        body.append('<details><summary class="sub">Full analysis</summary>'
                    + "".join(f'<p class="kv"><b>{label}</b> {_rich(text)}</p>' for label, text in full) + "</details>")
    if f.detected_by:
        body.append('<div class="sub">Detected by</div><ul class="tight">' + "".join(f"<li>{_e(d)}</li>" for d in f.detected_by) + "</ul>")
    if f.evidence:
        body.append('<div class="sub">Evidence</div><ul class="tight">' + "".join(f"<li>{_rich(e)}</li>" for e in f.evidence) + "</ul>")
    if f.reason:
        body.append('<div class="sub">Why this decision</div><ul class="tight"><li>' + _e(f.reason) + "</li>"
                    + "".join(f"<li>{_e(e)}</li>" for e in f.policy_evidence) + "</ul>")
    if f.limitations:
        body.append('<div class="sub">Limitations</div><ul class="tight">' + "".join(f"<li>{_rich(e)}</li>" for e in f.limitations) + "</ul>")
    body.append(f'<p class="mut"><small>Issue group <code>{_e(f.group_id)}</code></small></p>')
    return (f'<details class="card sev-{_e(f.severity)}" id="f{f.number}" data-f data-action="{_e(f.action)}" data-sev="{_e(f.severity)}"{" open" if opened else ""}>'
            f'<summary><div class="sum">{_sev(f.severity)}<h3>{f.number}. {_e(f.title)}</h3>{_action(f.action, f.rule_id)}</div>'
            f'<div class="sum mut"><span>{_e(f.verdict.replace("_", " "))}</span><span>·</span><span>{_e(f.confidence)} confidence</span>'
            + (f'<span>·</span><code>{_e(f.location)}</code>' if f.location else "") + f'</div></summary><div class="body">{"".join(body)}</div></details>')

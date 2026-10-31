"""Self-contained HTML renderer for the final report (no network access, light/dark switch, printable).

Layout: icon rail, decision banner, summary cards, "fix first" cards and a findings table whose rows open a
detail drawer (Overview / Evidence / Fix / Decision).  Every string from scanners, models or the repository is
HTML-escaped *before* the small inline formatter (`code`, **bold**) runs, so report content can never inject
markup or script.  A strict Content-Security-Policy blocks any external request even if that were broken.
"""

from __future__ import annotations

import html
import re
from collections import Counter

from security_reviewer_v2.policy.rules import RULES

from .view import ACTION_ICON, Finding, ReportView, first_sentence, lead

_CSS = """
:root{--bg:#09111E;--pn:#142B3B;--pn2:#0e1d2c;--ink:#F5F9FD;--mut:#8fa6ba;--ln:#1f3a4f;--mint:#7DE7C9;--mi:#7DE7C9;
--crit:#ff5c70;--high:#ff7b86;--medium:#f4bd5e;--low:#6fa8d6;--info:#8fa6ba;--glow:rgba(125,231,201,.08);color-scheme:dark}
@media(prefers-color-scheme:light){:root:not([data-theme]){--bg:#F5F9FD;--pn:#fff;--pn2:#eef4f9;--ink:#09111E;--mut:#52687b;--ln:#d3e0ea;--mi:#0a7a60;
--crit:#b3202f;--high:#c42b3b;--medium:#946400;--low:#2b6590;--info:#52687b;--glow:rgba(10,122,96,.07);color-scheme:light}}
:root[data-theme=light]{--bg:#F5F9FD;--pn:#fff;--pn2:#eef4f9;--ink:#09111E;--mut:#52687b;--ln:#d3e0ea;--mi:#0a7a60;
--crit:#b3202f;--high:#c42b3b;--medium:#946400;--low:#2b6590;--info:#52687b;--glow:rgba(10,122,96,.07);color-scheme:light}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:radial-gradient(900px 380px at 70% -80px,var(--glow),transparent),var(--bg);color:var(--ink);
font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;font-variant-numeric:tabular-nums}
button{font:inherit;color:inherit;cursor:pointer;background:none;border:0}a{color:var(--mi);text-decoration:none}
code,pre,.mono{font-family:ui-monospace,Consolas,"SFMono-Regular",monospace}code{font-size:.92em;background:var(--pn2);border:1px solid var(--ln);border-radius:5px;padding:0 5px;overflow-wrap:anywhere}
pre{background:var(--pn2);border:1px solid var(--ln);border-radius:9px;padding:12px;overflow-x:auto;white-space:pre-wrap}
.app{display:grid;grid-template-columns:64px minmax(0,1fr);min-height:100vh}
.rail{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;align-items:center;gap:8px;padding:16px 0;background:var(--pn2);border-right:1px solid var(--ln)}
.logo{width:38px;height:38px;border-radius:11px;background:var(--mint);color:#09111E;display:grid;place-items:center;font-weight:900;margin-bottom:14px}
.ri{position:relative;width:42px;height:42px;border-radius:11px;display:grid;place-items:center;color:var(--mut)}
.ri:hover,.ri:focus-visible{background:var(--pn);color:var(--mi)}
.ri svg,.theme svg{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.ri em{position:absolute;left:52px;background:var(--pn);border:1px solid var(--ln);padding:3px 9px;border-radius:7px;font-style:normal;font-size:12px;white-space:nowrap;opacity:0;pointer-events:none;z-index:20}
.ri:hover em,.ri:focus-visible em{opacity:1}.ri b{position:absolute;top:2px;right:0;background:var(--medium);color:#09111E;border-radius:99px;font-size:10px;padding:0 5px}
.top{display:flex;align-items:center;gap:14px;padding:14px 32px;border-bottom:1px solid var(--ln)}.top .t{flex:1;min-width:0}.top small{color:var(--mut)}.top h1{margin:0;font-size:18px}
.theme{width:38px;height:38px;border-radius:10px;border:1px solid var(--ln);background:var(--pn);display:grid;place-items:center}.theme:hover{border-color:var(--mint)}
.theme .sun{display:none}:root[data-theme=light] .theme .sun{display:block}:root[data-theme=light] .theme .moon{display:none}
@media(prefers-color-scheme:light){:root:not([data-theme]) .theme .sun{display:block}:root:not([data-theme]) .theme .moon{display:none}}
main{padding:24px 32px 56px;max-width:1360px}
.banner{padding:22px 26px;border-radius:16px;border:1px solid var(--ln);border-left:5px solid var(--info);background:linear-gradient(120deg,var(--pn),var(--pn2))}
.banner.blocked{border-left-color:var(--high)}.banner.clear{border-left-color:var(--mint)}.banner.incomplete,.banner.no_findings{border-left-color:var(--medium)}
.banner h2{margin:0 0 4px;font-size:22px}.banner p{margin:3px 0 0;color:var(--mut)}
.meta{display:flex;flex-wrap:wrap;gap:6px 14px;margin:12px 0 0;color:var(--mut);font-size:12px}
.note{margin:12px 0 0;padding:12px 16px;border:1px solid var(--ln);border-left:3px solid var(--medium);border-radius:10px;background:var(--pn);font-size:13px}
.g3{display:grid;grid-template-columns:1.1fr 1.2fr 1fr;gap:16px;margin-top:16px}
.card,.panel{background:linear-gradient(180deg,var(--pn),var(--pn2));border:1px solid var(--ln);border-radius:16px;padding:18px 20px}
.panel{margin:12px 0}.panel>summary{cursor:pointer}
.card h3{margin:0 0 12px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--mut)}
.dn{display:flex;gap:16px;align-items:center}.dn svg{width:120px;height:120px;flex:none}.dn b{font-size:30px;display:block;line-height:1}
.leg{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--mut)}.leg i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.bar{display:grid;grid-template-columns:62px 1fr 28px;align-items:center;gap:10px;width:100%;padding:6px 8px;border-radius:8px;text-align:left}
.bar:hover,.bar[aria-pressed=true]{background:var(--glow)}.track{height:8px;background:var(--ln);border-radius:9px;overflow:hidden}.track i{display:block;height:100%;border-radius:9px}.bar b{text-align:right}
.step{display:flex;gap:12px;align-items:baseline;padding:5px 0;border-bottom:1px dashed var(--ln)}.step:last-child{border:0}.step b{font-size:20px;min-width:44px}.step span{color:var(--mut);font-size:12.5px}
h2.sec{margin:30px 0 12px;font-size:15px;display:flex;align-items:baseline;gap:10px;scroll-margin-top:12px}h2.sec small{color:var(--mut);font-weight:400;font-size:12px}
.fix{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.fc{text-align:left;position:relative;background:var(--pn);border:1px solid var(--ln);border-radius:14px;padding:15px 18px 15px 22px;overflow:hidden}
.fc:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--info)}.fc.sev-critical:before{background:var(--crit)}.fc.sev-high:before{background:var(--high)}.fc.sev-medium:before{background:var(--medium)}.fc.sev-low:before{background:var(--low)}
.fc:hover,.fc:focus-visible{border-color:var(--mint)}.fc strong{display:block;margin:7px 0 3px}.fc p{margin:4px 0 0;color:var(--mut);font-size:12.5px}
.chip{display:inline-block;border-radius:6px;padding:1px 8px;font-size:11px;font-weight:700;border:1px solid var(--ln);background:var(--pn2);color:var(--mut);white-space:nowrap;margin:0 4px 3px 0}
.chip.block,.chip.sev-critical,.chip.sev-high{color:var(--high);border-color:var(--high);background:transparent}.chip.sev-critical{color:var(--crit);border-color:var(--crit)}
.chip.warn,.chip.sev-medium{color:var(--medium);border-color:var(--medium);background:transparent}.chip.allow{color:var(--mi);border-color:var(--mi);background:transparent}.chip.sev-low{color:var(--low);border-color:var(--low);background:transparent}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.tools input{flex:1 1 240px;background:var(--pn);border:1px solid var(--ln);color:var(--ink);border-radius:10px;padding:9px 13px;font:inherit}
.tools button{border:1px solid var(--ln);border-radius:99px;padding:6px 13px;font-size:12px;color:var(--mut)}.tools button[aria-pressed=true]{background:var(--mint);color:#09111E;border-color:var(--mint);font-weight:700}
.scroll{overflow-x:auto;border:1px solid var(--ln);border-radius:14px;background:var(--pn)}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);padding:11px 14px;background:var(--pn2);border-bottom:1px solid var(--ln)}
td{padding:12px 14px;border-bottom:1px solid var(--ln);vertical-align:top}tbody tr:last-child td{border:0}tr[data-open]{cursor:pointer}tr[data-open]:hover td,tr[data-open]:focus-visible td{background:var(--glow)}
td small{display:block;color:var(--mut);font-size:11px;overflow-wrap:anywhere}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:var(--info)}
.dot.sev-critical{background:var(--crit)}.dot.sev-high{background:var(--high)}.dot.sev-medium{background:var(--medium)}.dot.sev-low{background:var(--low)}
.mut,.sub{color:var(--mut)}.sub{margin:14px 0 4px;font-weight:700;font-size:12px}ul.tight{margin:4px 0;padding-left:18px}ul.tight li{margin:3px 0;overflow-wrap:anywhere}
footer{color:var(--mut);font-size:12px;margin-top:28px}
.scrim{position:fixed;inset:0;background:rgba(4,9,16,.6);display:none;z-index:30}.scrim.on{display:block}
.dr{position:fixed;top:0;right:0;bottom:0;width:min(640px,100%);z-index:31;background:var(--bg);border-left:1px solid var(--ln);transform:translateX(100%);transition:transform .2s;overflow:auto}.dr.on{transform:none}
.dh{padding:20px 26px 0;border-bottom:1px solid var(--ln);background:linear-gradient(180deg,var(--pn),var(--bg))}.dh h2{margin:10px 0 4px;font-size:20px}.x{float:right;font-size:24px;color:var(--mut)}
.tabs{display:flex;gap:2px;margin-top:12px}.tabs button{padding:10px 14px;color:var(--mut);border-bottom:2px solid transparent}.tabs button.on{color:var(--mi);border-color:var(--mint)}
.db{padding:20px 26px 40px}.db h4{margin:16px 0 5px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--mi)}.db h4:first-child{margin-top:0}.db p{margin:0 0 6px}
[hidden]{display:none!important}
@media(max-width:1000px){.app{grid-template-columns:1fr}.rail{position:static;height:auto;flex-direction:row;justify-content:center}.logo{margin:0}.ri em{display:none}.g3,.fix{grid-template-columns:1fr}.top,main{padding-left:16px;padding-right:16px}}
@media print{:root{--bg:#fff;--pn:#fff;--pn2:#f4f7fa;--ink:#111;--mut:#555;--ln:#bbb;--mi:#0a5a48}body{background:#fff}.rail,.tools,.theme,.scrim,.dr{display:none!important}.app{display:block}.banner,.card,.panel,.fc{break-inside:avoid}}
"""

_JS = """
(function(){var D=document,R=D.documentElement,K='verdict-theme',$=function(s){return D.querySelector(s)};
$('#theme').addEventListener('click',function(){var c=R.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'),n=c==='dark'?'light':'dark';
R.setAttribute('data-theme',n);try{localStorage.setItem(K,n)}catch(e){}});
var rows=[].slice.call(D.querySelectorAll('tr[data-f]')),st={action:'',sev:'',q:''},cnt=$('#cnt'),q=$('#q');
function apply(){var n=0;rows.forEach(function(r){var ok=(!st.action||r.getAttribute('data-action')===st.action)&&(!st.sev||r.getAttribute('data-sev')===st.sev)&&(!st.q||r.textContent.toLowerCase().indexOf(st.q)>-1);r.hidden=!ok;if(ok)n++});
if(cnt)cnt.textContent=n+' of '+rows.length+' shown';
[].forEach.call(D.querySelectorAll('[data-k]'),function(b){var k=b.getAttribute('data-k'),v=b.getAttribute('data-v');b.setAttribute('aria-pressed',String(k==='all'?(!st.action&&!st.sev):st[k]===v))})}
if(q)q.addEventListener('input',function(){st.q=q.value.toLowerCase();apply()});
var dr=$('#dr'),sc=$('#scrim');function close(){dr.classList.remove('on');sc.classList.remove('on');dr.setAttribute('aria-hidden','true')}
function open(id){var p=D.getElementById(id);if(!p)return;dr.innerHTML=p.innerHTML;dr.classList.add('on');sc.classList.add('on');dr.setAttribute('aria-hidden','false');dr.scrollTop=0;var x=dr.querySelector('.x');if(x)x.focus()}
D.addEventListener('click',function(e){var t=e.target.closest('[data-k],[data-open],[data-tab],.x,#scrim');if(!t)return;
if(t.hasAttribute('data-k')){var k=t.getAttribute('data-k'),v=t.getAttribute('data-v');if(k==='all'){st.action='';st.sev=''}else{st[k]=st[k]===v?'':v}apply();if(t.hasAttribute('data-go')){var f=$('#findings');if(f)f.scrollIntoView()}}
else if(t.hasAttribute('data-open'))open(t.getAttribute('data-open'));
else if(t.hasAttribute('data-tab')){var tb=t.getAttribute('data-tab');[].forEach.call(dr.querySelectorAll('[data-tab]'),function(b){b.classList.toggle('on',b===t)});[].forEach.call(dr.querySelectorAll('[data-tp]'),function(s){s.hidden=s.getAttribute('data-tp')!==tb})}
else close()});
D.addEventListener('keydown',function(e){if(e.key==='Escape')close();if(e.key==='Enter'&&e.target.hasAttribute&&e.target.hasAttribute('data-open'))open(e.target.getAttribute('data-open'))});
apply()})();
"""

_THEME_BOOT = "try{var t=localStorage.getItem('verdict-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}"

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_VERDICT_STYLE = (("confirmed_vulnerability", "Confirmed", "var(--high)"), ("likely_vulnerability", "Likely", "var(--medium)"),
                  ("likely_vulnerable", "Likely", "var(--medium)"), ("needs_more_evidence", "Needs evidence", "var(--low)"),
                  ("false_positive", "False positive", "var(--ln)"))
_ICON = {
    "grid": '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    "fix": '<path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.5M3 12h.5M3 18h.5"/>',
    "cov": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
    "warn": '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.5"/>',
    "book": '<path d="M4 4h12a4 4 0 014 4v12H8a4 4 0 01-4-4z"/><path d="M4 16a4 4 0 014-4h12"/>',
}


def _e(value: object) -> str:
    return html.escape(" ".join(str(value).split()), quote=True)


def _rich(text: object) -> str:
    """Escape first, then allow only `code` and **bold** formatting."""
    safe = html.escape(str(text).strip(), quote=True).replace("\n", "<br>")
    safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", safe)
    safe = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", safe)
    return re.sub(r"(?<![*\w])\*([^*\s][^*]*?)\*(?![*\w])", r"<em>\1</em>", safe)


def _sev(severity: str) -> str:
    return f'<span class="chip sev-{_e(severity)}">{_e(severity.upper())}</span>'


def _action(f_action: str, rule: str) -> str:
    cls = f_action if f_action in {"block", "warn", "allow"} else ""
    return f'<span class="chip {cls}">{ACTION_ICON.get(f_action, "")} {_e(f_action)}' + (f" · {_e(rule)}" if rule else "") + "</span>"


def _svg(name: str) -> str:
    return f'<svg viewBox="0 0 24 24" aria-hidden="true">{_ICON[name]}</svg>'


def _rail(view: ReportView) -> str:
    items = (("#overview", "grid", "Overview", ""), ("#fix", "fix", "Fix first", ""), ("#findings", "list", "Findings", ""),
             ("#coverage", "cov", "Coverage & trust", ""))
    out = '<nav class="rail" aria-label="Report sections"><div class="logo">V</div>' + "".join(
        f'<a class="ri" href="{h}" aria-label="{_e(n)}">{_svg(i)}<em>{_e(n)}</em></a>' for h, i, n, _ in items)
    badge = f"<b>{len(view.gaps)}</b>" if view.gaps else ""
    out += f'<button class="ri" data-open="p-gaps" aria-label="Known gaps">{_svg("warn")}<em>Known gaps</em>{badge}</button>'
    out += f'<button class="ri" data-open="p-guide" aria-label="How to read">{_svg("book")}<em>How to read</em></button></nav>'
    return out


def _donut(view: ReportView) -> str:
    total = len(view.findings)
    if not total:
        return '<p class="mut">No reviewed findings.</p>'
    counts = Counter(f.verdict for f in view.findings)
    merged: dict[str, tuple[int, str]] = {}
    for key, label, color in _VERDICT_STYLE:
        if counts.get(key):
            n = merged.get(label, (0, color))[0] + counts[key]
            merged[label] = (n, color)
    r, circ, off, rings = 46, 2 * 3.14159265 * 46, 0.0, []
    for label, (n, color) in merged.items():
        seg = n / total * circ
        rings.append(f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" stroke-width="13" stroke-dasharray="{max(seg - 2, 0):.1f} {circ - max(seg - 2, 0):.1f}" '
                     f'stroke-dashoffset="{-off:.1f}" transform="rotate(-90 60 60)"/>')
        off += seg
    legend = "".join(f'<span><i style="background:{color}"></i>{_e(label)} {n}</span>' for label, (n, color) in merged.items())
    return (f'<div class="dn"><svg viewBox="0 0 120 120" role="img" aria-label="Verdict distribution">{"".join(rings)}'
            f'<text x="60" y="62" text-anchor="middle" font-size="26" font-weight="800" fill="currentColor">{total}</text>'
            f'<text x="60" y="78" text-anchor="middle" font-size="9" fill="currentColor" opacity=".6">groups</text></svg><div class="leg">{legend}</div></div>')


def _severity_bars(view: ReportView) -> str:
    if not view.severity_counts:
        return '<p class="mut">Nothing to chart.</p>'
    peak = max(n for _, n in view.severity_counts) or 1
    return "".join(f'<button class="bar" data-k="sev" data-v="{_e(s)}" data-go="1" aria-pressed="false"><span>{_e(s.capitalize())}</span>'
                   f'<span class="track"><i style="width:{max(4, round(100 * n / peak))}%;background:var(--{_e(s) if s in _SEV_ORDER else "info"})"></i></span><b>{n}</b></button>'
                   for s, n in view.severity_counts)


def _pipeline(view: ReportView) -> str:
    c = view.counts
    steps = []
    if view.dedup:
        steps += [(view.dedup[0], "raw scanner results"), (view.dedup[1], "root-cause records")]
    steps += [(c["reviewed"], "issue groups reviewed"), (c["block"], "blocking release")]
    cov = f"{view.coverage_done}/{view.coverage_total} scanners completed" if view.has_execution and view.coverage_total else "scanner coverage n/a"
    body = "".join(f'<div class="step"><b>{_e(n)}</b><span>{_e(label)}</span></div>' for n, label in steps)
    return body + f'<p class="mut" style="margin:10px 0 0;font-size:12px">{_e(cov)} · dynamic testing {"performed" if view.dynamic else "not run"}</p>'


def _fix_card(f: Finding) -> str:
    where = " · ".join(x for x in ((f"<code>{_e(f.location)}</code>" if f.location else ""),
                                   (f"{f.corroboration} tools agree" if f.corroboration > 1 else ""), _e(", ".join(f.cwes))) if x)
    fix = f'<p><b>Fix:</b> {_rich(first_sentence(f.remediation))}</p>' if f.remediation else ""
    return (f'<button class="fc sev-{_e(f.severity)}" data-open="f{f.number}">{_sev(f.severity)}{_action(f.action, f.rule_id)}'
            f'<strong>{_e(f.title)}</strong><p>{where}</p>{fix}</button>')


def _row(f: Finding) -> str:
    refs = ", ".join(f.cwes) or "—"
    owasp = f"<small>{_e(', '.join(f.owasp))}</small>" if f.owasp else ""
    return (f'<tr data-f data-open="f{f.number}" tabindex="0" data-action="{_e(f.action)}" data-sev="{_e(f.severity)}"><td>{f.number}</td>'
            f'<td><strong>{_e(f.title)}</strong>{f"<small class=mono>{_e(f.location)}</small>" if f.location else ""}</td>'
            f'<td><span class="dot sev-{_e(f.severity)}"></span>{_e(f.severity)}</td><td>{_e(refs)}{owasp}</td>'
            f'<td>{_e(f.verdict.replace("_", " "))}<small>{_e(f.confidence)} confidence</small></td><td>{f.corroboration or "—"}</td>'
            f'<td>{_action(f.action, f.rule_id)}</td></tr>')


def _pane(f: Finding) -> str:
    refs = "".join(f'<span class="chip">{_e(x)}</span>' for x in (*f.cwes, *("OWASP " + o for o in f.owasp)))
    ov, fx, ev, wh = [], [], [], []
    for label, text in (("Problem", f.explanation), ("Impact", f.impact)):
        if text:
            ov.append(f"<h4>{label}</h4><p>{_rich(text)}</p>")
    if f.location:
        ov.append(f"<h4>Location</h4><pre>{_e(f.location)}</pre>")
    fx.append(f"<h4>Recommended fix</h4><p>{_rich(f.remediation)}</p>" if f.remediation else '<p class="mut">No remediation text was produced.</p>')
    for title, items, rich in (("Detected by", f.detected_by, False), ("Evidence", f.evidence, True), ("Limitations", f.limitations, True)):
        if items:
            ev.append(f"<h4>{title}</h4><ul class=\"tight\">" + "".join(f"<li>{_rich(i) if rich else _e(i)}</li>" for i in items) + "</ul>")
    wh.append("<h4>Why this decision</h4><ul class=\"tight\">" + (f"<li>{_e(f.reason)}</li>" if f.reason else "<li>No decision reason recorded.</li>")
              + "".join(f"<li>{_e(e)}</li>" for e in f.policy_evidence) + "</ul>")
    wh.append(f'<p class="mut"><small>Issue group <code>{_e(f.group_id)}</code></small></p>')
    tabs = (("ov", "Overview", ov), ("ev", "Evidence", ev), ("fx", "Fix", fx), ("wh", "Decision", wh))
    return (f'<div class="pane" id="f{f.number}" hidden><div class="dh"><button class="x" aria-label="Close">×</button>{_sev(f.severity)}{_action(f.action, f.rule_id)}{refs}'
            f'<h2>{f.number}. {_e(f.title)}</h2><div class="tabs">'
            + "".join(f'<button data-tab="{k}"{" class=on" if k == "ov" else ""}>{n}</button>' for k, n, _ in tabs)
            + '</div></div><div class="db">' + "".join(f'<div data-tp="{k}"{"" if k == "ov" else " hidden"}>{"".join(parts) or "<p class=mut>Nothing recorded.</p>"}</div>' for k, _, parts in tabs)
            + "</div></div>")


def _side_panes(view: ReportView) -> str:
    def pane(pid: str, title: str, body: str) -> str:
        return (f'<div class="pane" id="{pid}" hidden><div class="dh"><button class="x" aria-label="Close">×</button><h2 style="margin-bottom:16px">{title}</h2></div>'
                f'<div class="db">{body}</div></div>')
    gaps = ("<ul class=\"tight\">" + "".join(f"<li>{_e(g)}</li>" for g in view.gaps) + "</ul>") if view.gaps else '<p class="mut">No gaps were recorded.</p>'
    guide = ("<h4>Observation</h4><p>A raw scanner or DAST signal before review.</p><h4>Issue group &amp; verdict</h4><p>Correlated evidence assessed by the Review Agent. "
             "A model assessment, not independent exploit proof.</p><h4>Policy decision</h4><p>A release-gate outcome from a named rule. Never add it to the vulnerability count.</p>"
             "<h4>Coverage gap</h4><p>No finding in an untested area does not mean it passed.</p>")
    return pane("p-gaps", f"Known gaps ({len(view.gaps)})", gaps) + pane("p-guide", "How to read this report", guide)


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


def _coverage(view: ReportView, parts: list[str]) -> None:
    parts.append('<h2 class="sec" id="coverage">Coverage &amp; trust <small>What actually ran</small></h2>')
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
        parts.append(f'<details class="panel"><summary><b>Known gaps ({len(view.gaps)})</b> — each lowers confidence in a clean result for that area</summary>'
                     '<ul class="tight">' + "".join(f"<li>{_e(g)}</li>" for g in view.gaps) + "</ul></details>")
    if view.runtime_lines:
        parts.append('<details class="panel" open><summary><b>Runtime evidence</b></summary><pre>' + html.escape("\n".join(l.replace("**", "").replace("`", "").lstrip("# ") for l in view.runtime_lines if l.strip())) + "</pre></details>")


def render_html(view: ReportView) -> str:
    c = view.counts
    meta = (f"Project <code>{_e(view.project)}</code>", f"Generated {_e(view.generated)}", f"Policy <code>{_e(view.policy_status)}</code>",
            f"Review <code>{_e(view.review_status)}</code>", *([f"Rules <code>{_e(view.rule_set)}</code>"] if view.rule_set else []))
    parts: list[str] = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">",
        f"<title>Security Review · {_e(view.project)}</title><script>{_THEME_BOOT}</script><style>{_CSS}</style></head><body><div class=\"app\">",
        _rail(view),
        f'<div><header class="top"><div class="t"><small>Security review</small><h1>{_e(view.project)}</h1></div>'
        '<button class="theme" id="theme" aria-label="Toggle dark / light mode" title="Dark / light mode">'
        '<svg class="moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/></svg>'
        '<svg class="sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/></svg></button></header><main>',
        f'<section id="overview"><div class="banner {_e(view.decision)}"><h2>{_e(view.headline)}</h2>'
        + "".join(f"<p>{_e(s)}</p>" for s in view.bottom_line) + '</div><div class="meta">' + "".join(f"<span>{x}</span>" for x in meta) + "</div>",
    ]
    parts += [f'<div class="note">{n}</div>' for n in _notes(view)]
    parts.append(f'<div class="g3"><div class="card"><h3>Verdicts</h3>{_donut(view)}</div>'
                 f'<div class="card"><h3>Severity · {c["reviewed"]} reviewed</h3>{_severity_bars(view)}</div>'
                 f'<div class="card"><h3>Pipeline</h3>{_pipeline(view)}</div></div></section>')

    parts.append('<h2 class="sec" id="fix">Fix first <small>Blocking findings, highest severity first</small></h2>')
    if view.blocking:
        parts.append('<div class="fix">' + "".join(_fix_card(f) for f in view.blocking[:6]) + "</div>")
        if len(view.blocking) > 6:
            parts.append(f'<p><button class="chip block" data-k="action" data-v="block" data-go="1">Show all {len(view.blocking)} blocking findings →</button></p>')
    else:
        parts.append('<div class="panel">Nothing met the automatic blocking criteria. This is not a security clearance.</div>')
    if view.next_steps:
        parts.append('<div class="sub">Then</div><ol class="tight">' + "".join(f"<li>{_e(s)}</li>" for s in view.next_steps) + "</ol>")

    if view.findings:
        sevs = sorted({f.severity for f in view.findings}, key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 9)
        parts.append('<h2 class="sec" id="findings">Findings <small id="cnt"></small></h2><div class="tools"><input id="q" type="search" placeholder="Search title, path, CWE…" aria-label="Search findings">'
                     '<button data-k="all" aria-pressed="true">All</button>'
                     + "".join(f'<button data-k="action" data-v="{a}" aria-pressed="false">{ACTION_ICON[a]} {a}</button>' for a in ("block", "warn"))
                     + "".join(f'<button data-k="sev" data-v="{_e(s)}" aria-pressed="false">{_e(s)}</button>' for s in sevs) + "</div>")
        parts.append('<div class="scroll"><table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>CWE · OWASP</th><th>Verdict</th><th>Tools</th><th>Decision</th></tr></thead><tbody>'
                     + "".join(_row(f) for f in view.findings) + "</tbody></table></div>")
    _coverage(view, parts)
    _appendix(view, parts)
    parts.append(f'<footer>Static report · no external requests · generated {_e(view.generated)}</footer></main></div></div>'
                 '<div class="scrim" id="scrim"></div><aside class="dr" id="dr" aria-hidden="true"></aside>'
                 f'<div hidden>{"".join(_pane(f) for f in view.findings)}{_side_panes(view)}</div><script>{_JS}</script></body></html>')
    return "".join(parts)


def _appendix(view: ReportView, parts: list[str]) -> None:
    parts.append('<h2 id="appendix">Appendix</h2>')
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

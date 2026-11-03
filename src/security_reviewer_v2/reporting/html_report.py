"""Self-contained HTML renderer for the final report (no network access, light/dark switch, printable).

Layout: labelled sidebar, decision banner, severity/verdict strips, briefing (origin, reliability, next actions), ranked
"fix first" list and a findings table whose rows open a detail drawer (Overview / Evidence / Fix / Decision).  Every string from scanners, models or the repository is
HTML-escaped *before* the small inline formatter (`code`, **bold**) runs, so report content can never inject
markup or script.  A strict Content-Security-Policy blocks any external request even if that were broken.
"""

from __future__ import annotations

import html
import re
from collections import Counter

from security_reviewer_v2.policy.rules import RULES

from .view import ACTION_ICON, DynamicTrace, Finding, ReportView, first_sentence, lead

_CSS = """
:root{--bg:#0D1218;--pn:#141B23;--pn2:#1A232D;--ink:#E9EEF4;--mut:#97A5B5;--ln:#283443;--ln2:#364559;--acc:#8CA8FF;--acc-ink:#0D1218;
--mint:#4FD1B0;--mi:#4FD1B0;--glow:rgba(140,168,255,.09);--crit:#FF6B7A;--high:#FF9D5C;--medium:#F2C14E;--low:#74B0F7;--info:#97A5B5;
--serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
--sans:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"Cascadia Code","SF Mono",Consolas,"Liberation Mono",monospace;--r:6px;--R:10px;color-scheme:dark}
@media(prefers-color-scheme:light){:root:not([data-theme]){--bg:#F3F5F8;--pn:#fff;--pn2:#EDF0F4;--ink:#141B24;--mut:#546273;--ln:#D5DCE5;--ln2:#C0CBD8;--acc:#2347C5;--acc-ink:#fff;
--mint:#0E7A62;--mi:#0E7A62;--glow:rgba(35,71,197,.06);--crit:#B3261E;--high:#B8480A;--medium:#8A5A00;--low:#1B5FA6;--info:#546273;color-scheme:light}}
:root[data-theme=light]{--bg:#F3F5F8;--pn:#fff;--pn2:#EDF0F4;--ink:#141B24;--mut:#546273;--ln:#D5DCE5;--ln2:#C0CBD8;--acc:#2347C5;--acc-ink:#fff;
--mint:#0E7A62;--mi:#0E7A62;--glow:rgba(35,71,197,.06);--crit:#B3261E;--high:#B8480A;--medium:#8A5A00;--low:#1B5FA6;--info:#546273;color-scheme:light}
*{box-sizing:border-box}html{scroll-behavior:smooth}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{transition:none!important}}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 var(--sans);font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
button{font:inherit;color:inherit;cursor:pointer;background:none;border:0;padding:0}a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px;border-radius:4px}
h1,h2{font-family:var(--serif);font-weight:600;letter-spacing:-.01em}
code,pre,.mono{font-family:var(--mono)}code{font-size:.9em;background:var(--pn2);border:1px solid var(--ln);border-radius:4px;padding:0 5px;overflow-wrap:anywhere}
pre{background:var(--pn2);border:1px solid var(--ln);border-radius:var(--r);padding:12px;overflow-x:auto;white-space:pre-wrap;font-size:12.5px}
.app{display:grid;grid-template-columns:64px minmax(0,1fr);min-height:100vh}
.rail{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;align-items:center;gap:8px;padding:16px 0;background:var(--pn);border-right:1px solid var(--ln)}
.logo{width:36px;height:36px;border-radius:var(--r);background:var(--acc);color:var(--acc-ink);display:grid;place-items:center;font:700 18px var(--serif);margin-bottom:14px}
.ri{position:relative;width:42px;height:42px;border-radius:var(--r);display:grid;place-items:center;color:var(--mut)}
.ri:hover,.ri:focus-visible{background:var(--pn2);color:var(--ink)}
.ri svg,.theme svg{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.ri em{position:absolute;left:52px;background:var(--pn2);border:1px solid var(--ln);padding:3px 9px;border-radius:var(--r);font-style:normal;font-size:12px;white-space:nowrap;opacity:0;pointer-events:none;z-index:20}
.ri:hover em,.ri:focus-visible em{opacity:1}.ri b{position:absolute;top:2px;right:0;background:var(--medium);color:#0D1218;border-radius:99px;font-size:10px;padding:0 5px}
.top{display:flex;align-items:center;gap:14px;padding:14px 32px;border-bottom:1px solid var(--ln)}.top .t{flex:1;min-width:0}.top small{color:var(--mut)}.top h1{margin:0;font-size:20px}
.theme{width:36px;height:36px;border-radius:var(--r);border:1px solid var(--ln);background:var(--pn);display:grid;place-items:center;color:var(--mut)}.theme:hover{color:var(--ink);border-color:var(--ln2)}
.theme .sun{display:none}:root[data-theme=light] .theme .sun{display:block}:root[data-theme=light] .theme .moon{display:none}
@media(prefers-color-scheme:light){:root:not([data-theme]) .theme .sun{display:block}:root:not([data-theme]) .theme .moon{display:none}}
main{padding:24px 32px 56px;max-width:1360px}
.banner{padding:20px 24px;border-radius:var(--R);border:1px solid var(--ln);border-left:4px solid var(--info);background:var(--pn)}
.banner.blocked{border-left-color:var(--high)}.banner.clear{border-left-color:var(--mint)}.banner.incomplete,.banner.no_findings{border-left-color:var(--medium)}
.banner h2{margin:0 0 4px;font-size:24px;line-height:1.25}.banner p{margin:4px 0 0;color:var(--mut);max-width:78ch}
.meta{display:flex;flex-wrap:wrap;gap:4px 18px;margin:12px 0 0;color:var(--mut);font-size:12.5px}
.note{margin:12px 0 0;padding:12px 16px;border:1px solid var(--ln);border-left:3px solid var(--medium);border-radius:var(--r);background:var(--pn);font-size:13px}
.g3{display:grid;grid-template-columns:1.1fr 1.2fr 1fr;gap:16px;margin-top:16px}
.card,.panel{background:var(--pn);border:1px solid var(--ln);border-radius:var(--R);padding:16px 18px}
.panel{margin:12px 0}.panel>summary{cursor:pointer}
.card h3{margin:0 0 10px;font-size:13px;font-weight:650;color:var(--ink)}
.dn{display:flex;gap:16px;align-items:center}.dn svg{width:120px;height:120px;flex:none}.dn b{font-size:30px;display:block;line-height:1}
.leg{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--mut)}.leg i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.bar{display:grid;grid-template-columns:96px 1fr 30px;align-items:center;gap:10px;width:100%;padding:6px 8px;border-radius:var(--r);text-align:left}
.bar:hover,.bar[aria-pressed=true]{background:var(--glow)}.bar[aria-pressed=true]{box-shadow:inset 0 0 0 1px var(--acc)}.track{height:8px;background:var(--pn2);border-radius:99px;overflow:hidden}.track i{display:block;height:100%;border-radius:99px}.bar b{text-align:right}
.step{display:flex;gap:12px;align-items:baseline;padding:5px 0;border-bottom:1px dashed var(--ln)}.step:last-child{border:0}.step b{font-size:20px;min-width:44px}.step span{color:var(--mut);font-size:12.5px}
h2.sec{margin:36px 0 12px;font-size:20px;display:flex;align-items:baseline;gap:12px;scroll-margin-top:16px}h2.sec small{color:var(--mut);font:400 13px var(--sans)}
.fix{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.fc{text-align:left;position:relative;background:var(--pn);border:1px solid var(--ln);border-radius:var(--R);padding:14px 16px 14px 20px;overflow:hidden}
.fc:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--info)}.fc.sev-critical:before{background:var(--crit)}.fc.sev-high:before{background:var(--high)}.fc.sev-medium:before{background:var(--medium)}.fc.sev-low:before{background:var(--low)}
.fc:hover,.fc:focus-visible{border-color:var(--acc)}.fc strong{display:block;margin:7px 0 3px}.fc p{margin:4px 0 0;color:var(--mut);font-size:12.5px}
.chip{display:inline-block;border-radius:4px;padding:1px 7px;font-size:11.5px;font-weight:650;border:1px solid var(--ln);background:var(--pn2);color:var(--mut);white-space:nowrap;margin:0 4px 3px 0}
.chip.block,.chip.sev-critical,.chip.sev-high{color:var(--high);border-color:currentColor;background:transparent}.chip.sev-critical{color:var(--crit)}
.chip.warn,.chip.sev-medium{color:var(--medium);border-color:currentColor;background:transparent}.chip.allow{color:var(--mi);border-color:currentColor;background:transparent}.chip.sev-low{color:var(--low);border-color:currentColor;background:transparent}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.tools input{flex:1 1 240px;background:var(--pn);border:1px solid var(--ln);color:var(--ink);border-radius:var(--r);padding:9px 13px;font:inherit}.tools input:focus-visible{border-color:var(--acc)}
.tools button{border:1px solid var(--ln);border-radius:99px;padding:6px 13px;font-size:12px;color:var(--mut)}.tools button[aria-pressed=true]{background:var(--acc);color:var(--acc-ink);border-color:var(--acc);font-weight:700}
.scroll{overflow-x:auto;border:1px solid var(--ln);border-radius:var(--R);background:var(--pn)}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;font-size:12px;font-weight:650;color:var(--mut);padding:10px 14px;background:var(--pn2);border-bottom:1px solid var(--ln);white-space:nowrap}
td{padding:11px 14px;border-bottom:1px solid var(--ln);vertical-align:top}tbody tr:last-child td{border:0}tr[data-open]{cursor:pointer}tr[data-open]:hover td,tr[data-open]:focus-visible td{background:var(--glow)}
td small{display:block;color:var(--mut);font-size:11.5px;overflow-wrap:anywhere}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:var(--info)}
.dot.sev-critical{background:var(--crit)}.dot.sev-high{background:var(--high)}.dot.sev-medium{background:var(--medium)}.dot.sev-low{background:var(--low)}
.mut,.sub{color:var(--mut)}.sub{margin:14px 0 4px;font-weight:650;font-size:12.5px}ul.tight,ol.tight{margin:4px 0;padding-left:18px}ul.tight li,ol.tight li{margin:3px 0;overflow-wrap:anywhere}
footer{color:var(--mut);font-size:12px;margin-top:32px;padding-top:12px;border-top:1px solid var(--ln)}
.scrim{position:fixed;inset:0;background:rgba(4,9,16,.55);display:none;z-index:30}.scrim.on{display:block}
.dr{position:fixed;top:0;right:0;bottom:0;width:min(720px,100%);z-index:31;background:var(--bg);border-left:1px solid var(--ln);transform:translateX(100%);transition:transform .18s ease-out;overflow:auto}.dr.on{transform:none;box-shadow:-12px 0 32px rgba(0,0,0,.25)}
.dh{padding:20px 28px 0;border-bottom:1px solid var(--ln);background:var(--pn)}.dh h2{margin:10px 0 6px;font-size:22px;line-height:1.25}.x{float:right;font-size:26px;line-height:1;color:var(--mut);padding:2px 6px;border-radius:var(--r)}.x:hover{color:var(--ink);background:var(--pn2)}
.tabs{display:flex;gap:2px;margin-top:14px}.tabs button{padding:10px 14px;color:var(--mut);border-bottom:2px solid transparent}.tabs button:hover{color:var(--ink)}.tabs button.on{color:var(--ink);border-color:var(--acc);font-weight:650}
.db{padding:20px 28px 40px;max-width:780px}.db h4{margin:18px 0 6px;font-size:13px;font-weight:650;color:var(--ink)}.db h4:first-child{margin-top:0}.db p{margin:0 0 8px;max-width:72ch}
[hidden]{display:none!important}
@media(max-width:1000px){.app{grid-template-columns:1fr}.rail{position:static;height:auto;flex-direction:row;justify-content:center}.logo{margin:0}.ri em{display:none}.g3,.fix{grid-template-columns:1fr}.top,main{padding-left:16px;padding-right:16px}}
@media print{:root{--bg:#fff;--pn:#fff;--pn2:#F3F5F8;--ink:#111;--mut:#555;--ln:#C9CFD8;--mi:#0A5A48;--acc:#1B3AA0}body{background:#fff;font-size:11px}.rail,.tools,.theme,.scrim,.dr{display:none!important}.app{display:block}.banner,.card,.panel,.fc{break-inside:avoid}}
"""

_REPORT_CSS = """
.app.wide{grid-template-columns:248px minmax(0,1fr)}.app.wide>div{min-width:0}
.side{position:sticky;top:0;height:100vh;overflow:auto;display:flex;flex-direction:column;gap:18px;padding:20px 16px;background:var(--pn);border-right:1px solid var(--ln)}
.brand{display:flex;gap:10px;align-items:center}.brand .logo{margin:0}.brand b{font:650 16px var(--serif);display:block;line-height:1.2}.brand span{font-size:12px;color:var(--mut)}
.stamp{display:inline-block;border-radius:4px;padding:2px 9px;font-size:12px;font-weight:700;border:1px solid var(--info);color:var(--info)}.stamp.blocked{color:var(--high);border-color:var(--high)}.stamp.clear{color:var(--mi);border-color:var(--mi)}.stamp.incomplete,.stamp.no_findings{color:var(--medium);border-color:var(--medium)}
.toc{display:flex;flex-direction:column;gap:2px}.toc a,.toc button{display:flex;justify-content:space-between;gap:8px;align-items:center;padding:7px 10px;border-radius:var(--r);color:var(--mut);font-size:13px;text-align:left;width:100%}
.toc a:hover,.toc button:hover{background:var(--pn2);color:var(--ink);text-decoration:none}.toc a[aria-current=true]{background:var(--pn2);color:var(--ink);font-weight:650;box-shadow:inset 3px 0 0 var(--acc)}
.toc em{font-style:normal;font-size:11.5px;color:var(--mut);background:var(--pn2);border-radius:99px;padding:0 7px}.toc .gap em{background:var(--medium);color:#0D1218}
.toc hr{border:0;border-top:1px solid var(--ln);margin:8px 0;width:100%}
.sidefoot{margin-top:auto;display:flex;gap:8px}.sidefoot button{flex:1;border:1px solid var(--ln);border-radius:var(--r);padding:7px 10px;font-size:12.5px;color:var(--mut)}.sidefoot button:hover{color:var(--ink);border-color:var(--ln2)}.sidefoot .theme{flex:none}
.skip{position:absolute;left:-999px;top:8px;background:var(--acc);color:var(--acc-ink);padding:6px 12px;border-radius:var(--r);z-index:50}.skip:focus{left:8px}
.doc-head{margin-bottom:16px}.doc-head small{color:var(--mut);font-size:13px}.doc-head h1{margin:2px 0 0;font-size:34px;line-height:1.15}
.sevs{margin-top:20px}.sevs h3,.brief h3,.vs h3{margin:0 0 8px;font-size:13px;font-weight:650}
.strip{display:flex;height:14px;border-radius:99px;overflow:hidden;gap:2px;background:var(--pn2)}.strip i{display:block;min-width:6px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.legend{display:flex;flex-wrap:wrap;gap:4px 8px;margin-top:8px}.legend button,.legend span{display:inline-flex;gap:7px;align-items:center;padding:3px 10px 3px 8px;border:1px solid var(--ln);border-radius:99px;font-size:12.5px;color:var(--ink);background:var(--pn)}
.legend button:hover{border-color:var(--acc)}.legend button[aria-pressed=true]{box-shadow:inset 0 0 0 1px var(--acc);background:var(--glow)}.legend i{width:9px;height:9px;border-radius:50%;display:inline-block}.legend b{font-weight:700}.legend em{font-style:normal;color:var(--mut)}
.vs{margin-top:16px}
.brief{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));margin-top:24px;border:1px solid var(--ln);border-radius:var(--R);background:var(--pn)}
.brief>div{padding:16px 20px}.brief>div+div{border-left:1px solid var(--ln)}
.brief ul{list-style:none;margin:0;padding:0;display:grid;gap:8px;font-size:13px}.brief ul li{display:flex;gap:9px;align-items:baseline;overflow-wrap:anywhere}.brief ul li i{font-style:normal;flex:none;width:14px;font-weight:700}
.brief .ok i{color:var(--mi)}.brief .bad i{color:var(--crit)}.brief .warn i{color:var(--medium)}.brief ol{margin:0;padding-left:18px;font-size:13px}.brief ol li{margin:0 0 8px;padding-left:2px}
.funnel{display:flex;flex-wrap:wrap;gap:8px 0;margin-top:12px;border:1px solid var(--ln);border-radius:var(--R);background:var(--pn)}
.fn{flex:1 1 150px;padding:12px 18px;position:relative}.fn+.fn{border-left:1px solid var(--ln)}.fn b{display:block;font:600 24px/1.1 var(--serif)}.fn span{font-size:12.5px;color:var(--mut)}
.fn+.fn:before{content:"";position:absolute;left:-5px;top:50%;width:9px;height:9px;margin-top:-5px;background:var(--pn);border-top:1px solid var(--ln);border-right:1px solid var(--ln);transform:rotate(45deg)}
.fixlist{list-style:none;margin:0;padding:0;border:1px solid var(--ln);border-radius:var(--R);background:var(--pn);overflow:hidden}
.fixlist li+li{border-top:1px solid var(--ln)}.fr{display:grid;grid-template-columns:34px minmax(0,1fr) auto;gap:14px;align-items:start;width:100%;text-align:left;padding:14px 18px 14px 0;position:relative}
.fr:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--info)}.fr.sev-critical:before{background:var(--crit)}.fr.sev-high:before{background:var(--high)}.fr.sev-medium:before{background:var(--medium)}.fr.sev-low:before{background:var(--low)}
.fr:hover,.fr:focus-visible{background:var(--glow)}.rk{font:600 20px/1.2 var(--serif);color:var(--mut);text-align:right;padding-left:12px}.fr strong{font-size:14.5px}.fl{display:flex;flex-wrap:wrap;gap:2px 8px;align-items:center;margin-top:3px;font-size:12.5px;color:var(--mut)}
.ff{display:block;margin-top:5px;color:var(--ink);font-size:13px;max-width:80ch}.ff b{color:var(--mut);font-weight:650}.fs{display:flex;flex-direction:column;align-items:flex-end}
.more{margin-top:10px}.more button{border:1px solid var(--ln);border-radius:var(--r);padding:6px 12px;font-size:12.5px;color:var(--acc)}.more button:hover{border-color:var(--acc)}
.filters{display:flex;flex-wrap:wrap;gap:8px 22px;margin-bottom:12px;align-items:center}.fg{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.fg>span{font-size:12.5px;color:var(--mut);margin-right:2px}
.fg button{border:1px solid var(--ln);border-radius:99px;padding:5px 12px;font-size:12.5px;color:var(--mut);background:var(--pn)}.fg button:hover{border-color:var(--ln2);color:var(--ink)}.fg button[aria-pressed=true]{background:var(--acc);color:var(--acc-ink);border-color:var(--acc);font-weight:700}.fg button em{font-style:normal;opacity:.75;margin-left:5px}
td:nth-child(2){min-width:190px}tr[data-f] td:first-child{box-shadow:inset 4px 0 0 var(--info)}tr[data-sev=critical] td:first-child{box-shadow:inset 4px 0 0 var(--crit)}tr[data-sev=high] td:first-child{box-shadow:inset 4px 0 0 var(--high)}tr[data-sev=medium] td:first-child{box-shadow:inset 4px 0 0 var(--medium)}tr[data-sev=low] td:first-child{box-shadow:inset 4px 0 0 var(--low)}
th .sort{font:inherit;color:inherit}th .sort:after{content:" \\2195";opacity:.4}th[aria-sort=ascending] .sort:after{content:" \\2191";opacity:1}th[aria-sort=descending] .sort:after{content:" \\2193";opacity:1}
.chip.o-static{color:var(--low);border-color:currentColor;background:transparent}.chip.o-dynamic{color:var(--mi);border-color:currentColor;background:transparent}.chip.o-ai{color:var(--medium);border-color:currentColor;background:transparent}
.empty{padding:28px 24px;border:1px dashed var(--ln2);border-radius:var(--R);color:var(--mut);background:var(--pn)}.empty b{color:var(--ink);display:block;margin-bottom:4px;font-size:15px}
.st{display:inline-flex;gap:6px;align-items:center;font-weight:650}.st:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--info)}.st.ok:before{background:var(--mint)}.st.bad:before{background:var(--crit)}.st.warn:before{background:var(--medium)}
.trace{border:1px solid var(--ln);border-radius:var(--r);background:var(--pn);padding:12px 14px;margin:6px 0 14px}.trace .th{font-size:12.5px;overflow-wrap:anywhere}.trace p.src{margin:8px 0;color:var(--mut);font-size:12.5px}
ol.steps{margin:6px 0 10px;padding:0;list-style:none;counter-reset:s}ol.steps li{counter-increment:s;position:relative;padding:6px 0 6px 30px;border-left:2px solid var(--ln);margin-left:10px}
ol.steps li:before{content:counter(s);position:absolute;left:-11px;top:6px;width:20px;height:20px;border-radius:50%;background:var(--pn2);border:1px solid var(--ln);font-size:11px;display:grid;place-items:center;color:var(--mut)}
ol.steps code{display:block;white-space:pre-wrap;overflow-wrap:anywhere}ol.steps span{display:block;color:var(--mut);font-size:12.5px;margin-top:2px}
table.kv{width:100%;font-size:12.5px;border:1px solid var(--ln);border-radius:var(--r);overflow:hidden}table.kv th{width:36%;font-weight:600;font-size:12px;padding:6px 10px;background:var(--pn2);white-space:normal}table.kv td{padding:6px 10px;overflow-wrap:anywhere}
.loc{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0 0}.loc code{font-size:12.5px}.loc button{border:1px solid var(--ln);border-radius:var(--r);padding:2px 9px;font-size:12px;color:var(--mut)}.loc button:hover{color:var(--ink);border-color:var(--ln2)}
.dnav{display:flex;justify-content:space-between;gap:10px;margin-top:28px;padding-top:14px;border-top:1px solid var(--ln)}.dnav button{border:1px solid var(--ln);border-radius:var(--r);padding:7px 14px;font-size:13px;color:var(--ink);max-width:48%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dnav button:hover{border-color:var(--acc)}
.print-only{display:none}.pd{padding:14px 0;border-top:1px solid var(--ln)}.pd h3{margin:6px 0;font:600 16px var(--serif)}.pd h4{margin:10px 0 3px;font-size:12.5px;color:var(--mi)}
.ok-t{color:var(--mi);font-weight:650}.bad-t{color:var(--crit);font-weight:650}
@media(max-width:1000px){.app.wide{grid-template-columns:minmax(0,1fr)}.side{position:sticky;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:10px 14px;z-index:15;overflow:visible}.side .stamp{display:none}
.toc{flex-direction:row;overflow-x:auto;flex:1 1 100%;order:3;min-width:0}.toc a,.toc button{width:auto;white-space:nowrap}.toc hr{display:none}.sidefoot{margin:0 0 0 auto}.brief{grid-template-columns:1fr}.brief>div+div{border-left:0;border-top:1px solid var(--ln)}.fr{grid-template-columns:28px minmax(0,1fr)}.fs{grid-column:2;flex-direction:row;align-items:center;gap:6px}.doc-head h1{font-size:26px}}
@page{margin:14mm}
@media print{.side,.filters,.fix,.more,.sidefoot,.skip,#none{display:none!important}.app.wide{display:block}main{padding:0;max-width:none}.doc-head h1{font-size:26px}
.banner,.brief,.funnel,.fixlist li,.trace,.pd tr,tr{break-inside:avoid}.scroll{overflow:visible;border:0}thead{display:table-header-group}h2.sec{break-after:avoid}.sort:after{content:""!important}.print-only{display:block}.pd{break-inside:auto}.pd h3,.pd h4,.pd>div:first-child{break-after:avoid}a{color:inherit}.strip,.strip i,.fr:before,tr[data-f] td:first-child{-webkit-print-color-adjust:exact;print-color-adjust:exact}.brief{grid-template-columns:repeat(3,minmax(0,1fr))}}
"""

_JS = """
(function(){var D=document,R=D.documentElement,K='verdict-theme',$=function(s){return D.querySelector(s)};
$('#theme').addEventListener('click',function(){var c=R.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'),n=c==='dark'?'light':'dark';
R.setAttribute('data-theme',n);try{localStorage.setItem(K,n)}catch(e){}});
var KEYS=['origin','action','sev'],st={origin:'',action:'',sev:'',q:''},items=[].slice.call(D.querySelectorAll('[data-f]')),cnt=$('#cnt'),q=$('#q');
function has(el,k,v){return(' '+(el.getAttribute('data-'+k)||'')+' ').indexOf(' '+v+' ')>-1}
function apply(){var n=0,rows=0;items.forEach(function(r){var ok=KEYS.every(function(k){return!st[k]||has(r,k,st[k])})&&(!st.q||r.textContent.toLowerCase().indexOf(st.q)>-1);r.hidden=!ok;if(r.tagName==='TR'){rows++;if(ok)n++}});
if(cnt)cnt.textContent=n+' of '+rows+' shown';var none=$('#none');if(none)none.hidden=n>0;
[].forEach.call(D.querySelectorAll('[data-k]'),function(b){var k=b.getAttribute('data-k'),v=b.getAttribute('data-v');b.setAttribute('aria-pressed',String(k==='all'?!KEYS.some(function(x){return st[x]}):st[k]===v))})}
if(q)q.addEventListener('input',function(){st.q=q.value.toLowerCase();apply()});
var dr=$('#dr'),sc=$('#scrim'),last=null;function close(){dr.classList.remove('on');sc.classList.remove('on');dr.setAttribute('aria-hidden','true');if(last)last.focus()}
function open(id){var p=D.getElementById(id);if(!p)return;if(!dr.classList.contains('on'))last=D.activeElement;dr.innerHTML=p.innerHTML;dr.classList.add('on');sc.classList.add('on');dr.setAttribute('aria-hidden','false');dr.scrollTop=0;var x=dr.querySelector('.x');if(x)x.focus()}
function sortBy(h){var key=h.getAttribute('data-sort'),dir=h.getAttribute('aria-sort')==='ascending'?-1:1,tb=h.closest('table').tBodies[0];
[].slice.call(tb.rows).sort(function(a,b){var x=a.getAttribute('data-'+key)||'',y=b.getAttribute('data-'+key)||'',nx=parseFloat(x),ny=parseFloat(y);return(isNaN(nx)||isNaN(ny)?x.localeCompare(y):nx-ny)*dir}).forEach(function(r){tb.appendChild(r)});
[].forEach.call(h.parentNode.children,function(c){c.removeAttribute('aria-sort')});h.setAttribute('aria-sort',dir===1?'ascending':'descending')}
D.addEventListener('click',function(e){var t=e.target.closest('[data-k],[data-open],[data-tab],[data-sort],[data-copy],#print,.x,#scrim');if(!t)return;
if(t.id==='print'){print();return}
if(t.hasAttribute('data-copy')){var v=t.getAttribute('data-copy'),done=function(){var o=t.textContent;t.textContent='Copied';setTimeout(function(){t.textContent=o},1200)};
try{navigator.clipboard.writeText(v).then(done,function(){})}catch(x){}return}
if(t.hasAttribute('data-sort')){sortBy(t);return}
if(t.hasAttribute('data-k')){var k=t.getAttribute('data-k'),v=t.getAttribute('data-v');if(k==='all'){KEYS.forEach(function(x){st[x]=''})}else{st[k]=st[k]===v?'':v}apply();if(t.hasAttribute('data-go')){var f=$('#findings');if(f)f.scrollIntoView()}}
else if(t.hasAttribute('data-open'))open(t.getAttribute('data-open'));
else if(t.hasAttribute('data-tab')){var tb=t.getAttribute('data-tab');[].forEach.call(dr.querySelectorAll('[data-tab]'),function(b){b.classList.toggle('on',b===t)});[].forEach.call(dr.querySelectorAll('[data-tp]'),function(s){s.hidden=s.getAttribute('data-tp')!==tb})}
else close()});
D.addEventListener('keydown',function(e){if(e.key==='Escape')close();if(e.key==='Enter'&&e.target.hasAttribute&&e.target.hasAttribute('data-open'))open(e.target.getAttribute('data-open'))});
var toc=[].slice.call(D.querySelectorAll('.toc a[href^="#"]'));if(toc.length&&'IntersectionObserver' in window){var io=new IntersectionObserver(function(en){en.forEach(function(x){if(x.isIntersecting){toc.forEach(function(a){a.removeAttribute('aria-current')});var a=D.querySelector('.toc a[href="#'+x.target.id+'"]');if(a)a.setAttribute('aria-current','true')}})},{rootMargin:'-10% 0px -80% 0px'});
toc.forEach(function(a){var t=D.getElementById(a.getAttribute('href').slice(1));if(t)io.observe(t)})}
var closed=[];addEventListener('beforeprint',function(){closed=[].filter.call(D.querySelectorAll('details:not([open])'),function(d){d.open=true;return true})});
addEventListener('afterprint',function(){closed.forEach(function(d){d.open=false});closed=[]});
apply()})();
"""

_THEME_BOOT = "try{var t=localStorage.getItem('verdict-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}"

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_ORIGIN_LABEL = {"static": "Static", "dynamic": "Dynamic", "ai": "AI discovery"}
_ORIGIN_HINT = {"static": "scanners reading the code, dependencies, secrets and configuration",
                "dynamic": "probes sent to the running application (DAST)",
                "ai": "candidates found by the AI Discovery agent reading source"}
_STEPS_NOTE = {
    "definition": "Request sequence this scanner runs for this rule (fixed in the scanner's source code). The recorded output below is what this run observed.",
    "workflow": "Steps executed by the workflow runner in this run, with the HTTP status actually observed.",
    "none": "This scanner does not define a step sequence for this rule, so only the recorded output is shown.",
}
_VERDICT_STYLE = (("confirmed_vulnerability", "Confirmed", "var(--ink)"), ("likely_vulnerability", "Likely", "var(--mut)"),
                  ("likely_vulnerable", "Likely", "var(--mut)"), ("needs_more_evidence", "Needs evidence", "var(--ln2)"),
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


def _origin_chips(f: Finding) -> str:
    return "".join(f'<span class="chip o-{_e(o)}">{_e(_ORIGIN_LABEL.get(o, o))}</span>' for o in f.origins)


def _kv(pairs: tuple[tuple[str, str], ...]) -> str:
    return ('<table class="kv"><tbody>' + "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in pairs) + "</tbody></table>") if pairs else ""


def _trace(t: DynamicTrace) -> str:
    steps = ('<ol class="steps">' + "".join(f"<li><code>{_e(a)}</code><span>{_e(b)}</span></li>" for a, b in t.steps) + "</ol>") if t.steps else ""
    record = _kv(t.record)
    out = _kv(t.facts) or '<p class="mut">No output values were recorded for this probe.</p>'
    return (f'<div class="trace"><div class="th"><b>{_e(t.scanner)}</b> · <code>{_e(t.rule_id)}</code> · target <code>{_e(t.target)}</code> '
            f'· {_sev(t.severity)}<span class="chip">{_e(t.confidence)} confidence</span></div>'
            f'<p class="src">{_e(_STEPS_NOTE[t.steps_source])}</p>{steps}'
            f'<div class="sub">Recorded output</div>{out}'
            + (f'<div class="sub">Probe result</div>{record}' if record else "")
            + '<p class="mut"><small>The dynamic scanners keep status codes and flags only; response bodies, cookies and credentials are withheld by design.</small></p></div>')


def _svg(name: str) -> str:
    return f'<svg viewBox="0 0 24 24" aria-hidden="true">{_ICON[name]}</svg>'


_STAMP = {"blocked": "Release blocked", "clear": "No blockers", "incomplete": "Incomplete", "no_findings": "No findings"}
_SIDE_ICONS = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/></svg>',
               '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/></svg>')


def _sidebar(view: ReportView) -> str:
    """Labelled table of contents with live counts; replaces the old icon-only rail."""
    c = view.counts
    items = [("#overview", "Summary", ""), ("#fix", "Fix first", c["block"] or ""), ("#findings", "Findings", c["reviewed"] or ""),
             ("#coverage", "Coverage & trust", "")]
    if view.probes or view.workflow_steps:
        items.append(("#dynamic", "Dynamic scan log", len(view.probes) or len(view.workflow_steps)))
    items.append(("#appendix", "Appendix", ""))
    links = "".join(f'<a href="{h}"><span>{_e(n)}</span>{f"<em>{x}</em>" if x != "" else ""}</a>' for h, n, x in items)
    gaps = f"<em>{len(view.gaps)}</em>" if view.gaps else ""
    return ('<aside class="side" aria-label="Report navigation"><div class="brand"><div class="logo">V</div><div><b>Verdict</b><span>Security assessment</span></div></div>'
            f'<div><span class="stamp {_e(view.decision)}">{_e(_STAMP.get(view.decision, view.decision))}</span></div>'
            f'<nav class="toc" aria-label="Sections">{links}<hr>'
            f'<button class="gap" data-open="p-gaps"><span>Known gaps</span>{gaps}</button><button data-open="p-guide"><span>How to read this report</span></button></nav>'
            '<div class="sidefoot"><button id="print" title="Print or save as PDF">Print / PDF</button>'
            f'<button class="theme" id="theme" aria-label="Toggle dark / light mode" title="Dark / light mode"><span class="moon">{_SIDE_ICONS[0]}</span><span class="sun">{_SIDE_ICONS[1]}</span></button></div></aside>')


def _strip_block(title: str, parts: list[tuple[str, str, int, str]], *, filter_key: str = "") -> str:
    """Proportional bar plus a legend; ``parts`` is (value, label, count, css colour variable)."""
    parts = [x for x in parts if x[2] > 0]
    if not parts:
        return ""
    bar = "".join(f'<i style="flex:{n};background:var({col})"></i>' for _, _, n, col in parts)
    legend = "".join(
        (f'<button data-k="{filter_key}" data-v="{_e(v)}" data-go="1" aria-pressed="false"><i style="background:var({col})"></i>{_e(lab)} <b>{n}</b></button>' if filter_key
         else f'<span><i style="background:var({col})"></i>{_e(lab)} <b>{n}</b></span>') for v, lab, n, col in parts)
    summary = ", ".join(f"{n} {lab.lower()}" for _, lab, n, _ in parts)
    return f'<h3>{_e(title)}</h3><div class="strip" role="img" aria-label="{_e(summary)}">{bar}</div><div class="legend">{legend}</div>'


def _distribution(view: ReportView) -> str:
    sev = _strip_block(f"Severity of {view.counts['reviewed']} reviewed finding(s)",
                       [(s, s.capitalize(), n, f"--{s if s in _SEV_ORDER else 'info'}") for s, n in view.severity_counts], filter_key="sev")
    verdicts: dict[str, tuple[int, str]] = {}
    tally = Counter(f.verdict for f in view.findings)
    for key, label, color in _VERDICT_STYLE:
        if tally.get(key):
            verdicts[label] = (verdicts.get(label, (0, color))[0] + tally[key], color)
    vs = _strip_block("Reviewer verdict", [(lab, lab, n, col[4:-1] if col.startswith("var(") else "--ln") for lab, (n, col) in verdicts.items()])
    return f'<div class="sevs">{sev}</div>' + (f'<div class="vs">{vs}</div>' if vs else "")


def _funnel(view: ReportView) -> str:
    c = view.counts
    steps = []
    if view.dedup:
        steps += [(view.dedup[0], "raw scanner results"), (view.dedup[1], "root-cause records")]
    steps += [(c["reviewed"], "issue groups reviewed"), (c["block"], "blocking release")]
    return '<div class="funnel" aria-label="From raw results to decision">' + "".join(f'<div class="fn"><b>{_e(n)}</b><span>{_e(label)}</span></div>' for n, label in steps) + "</div>"


def _fix_row(f: Finding, rank: int) -> str:
    where = (f"<code>{_e(f.location)}</code>" if f.location else "") + (f"<span>{f.corroboration} tools agree</span>" if f.corroboration > 1 else "")
    fix = f'<span class="ff"><b>Fix:</b> {_rich(first_sentence(f.remediation))}</span>' if f.remediation else ""
    return (f'<li><button class="fr sev-{_e(f.severity)}" data-open="f{f.number}"><span class="rk">{rank}</span>'
            f'<span><strong>{_e(f.title)}</strong><span class="fl">{where}{_origin_chips(f)}{_refs(f)}</span>{fix}</span>'
            f'<span class="fs">{_sev(f.severity)}{_action(f.action, f.rule_id)}</span></button></li>')


def _row(f: Finding) -> str:
    refs = ", ".join(f.cwes) or "—"
    owasp = f"<small>{_e(', '.join(f.owasp))}</small>" if f.owasp else ""
    rank = _SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 9
    return (f'<tr data-f data-open="f{f.number}" tabindex="0" data-action="{_e(f.action)}" data-sev="{_e(f.severity)}" data-origin="{_e(" ".join(f.origins))}" '
            f'data-n="{f.number}" data-r="{rank}" data-loc="{_e(f.location)}" data-originsort="{_e(" ".join(f.origins))}"><td>{f.number}</td>'
            f'<td><strong>{_e(f.title)}</strong></td>'
            f'<td><span class="dot sev-{_e(f.severity)}"></span>{_e(f.severity)}</td><td>{_origin_chips(f) or "—"}</td>'
            f'<td>{f"<code>{_e(f.location)}</code>" if f.location else "—"}</td><td>{_e(refs)}{owasp}</td>'
            f'<td>{_e(f.verdict.replace("_", " "))}<small>{_e(f.confidence)} confidence</small></td><td>{f.corroboration or "—"}</td>'
            f'<td>{_action(f.action, f.rule_id)}</td></tr>')


def _refs(f: Finding) -> str:
    return "".join(f'<span class="chip">{_e(x)}</span>' for x in (*f.cwes, *("OWASP " + o for o in f.owasp)))


def _parts(f: Finding) -> tuple[list[str], list[str], list[str], list[str]]:
    """Overview, evidence, fix and decision sections of one finding (shared by the drawer and the print view)."""
    ov, fx, ev, wh = [], [], [], []
    for label, text in (("Problem", f.explanation), ("Impact", f.impact)):
        if text:
            ov.append(f"<h4>{label}</h4><p>{_rich(text)}</p>")
    if f.location:
        ov.append(f"<h4>Location</h4><pre>{_e(f.location)}</pre>")
    fx.append(f"<h4>Recommended fix</h4><p>{_rich(f.remediation)}</p>" if f.remediation else '<p class="mut">No remediation text was produced.</p>')
    for title, items, rich in (("Detected by", f.detected_by, False), ("Evidence", f.evidence, True)):
        if items:
            ev.append(f"<h4>{title}</h4><ul class=\"tight\">" + "".join(f"<li>{_rich(i) if rich else _e(i)}</li>" for i in items) + "</ul>")
    if f.dynamic:
        ev.append("<h4>Dynamic test trace</h4>" + "".join(_trace(t) for t in f.dynamic))
    if f.limitations:
        ev.append("<h4>Limitations</h4><ul class=\"tight\">" + "".join(f"<li>{_rich(i)}</li>" for i in f.limitations) + "</ul>")
    wh.append("<h4>Why this decision</h4><ul class=\"tight\">" + (f"<li>{_e(f.reason)}</li>" if f.reason else "<li>No decision reason recorded.</li>")
              + "".join(f"<li>{_e(e)}</li>" for e in f.policy_evidence) + "</ul>")
    wh.append(f'<p class="mut"><small>Issue group <code>{_e(f.group_id)}</code></small></p>')
    return ov, ev, fx, wh


def _print_detail(f: Finding) -> str:
    ov, ev, fx, wh = _parts(f)
    body = "".join(f"<div>{''.join(part)}</div>" for part in (ov, ev, fx, wh) if part)
    return (f'<article class="pd" data-f data-action="{_e(f.action)}" data-sev="{_e(f.severity)}" data-origin="{_e(" ".join(f.origins))}">'
            f'<div>{_sev(f.severity)}{_action(f.action, f.rule_id)}{_origin_chips(f)}{_refs(f)}</div><h3>{f.number}. {_e(f.title)}</h3>{body}</article>')


def _pane(f: Finding, prev: Finding | None = None, nxt: Finding | None = None) -> str:
    ov, ev, fx, wh = _parts(f)
    tabs = (("ov", "Overview", ov), ("ev", "Evidence", ev), ("fx", "Fix", fx), ("wh", "Decision", wh))
    loc = (f'<div class="loc"><code>{_e(f.location)}</code><button data-copy="{_e(f.location)}">Copy</button></div>' if f.location else "")
    nav = "".join(f'<button data-open="f{o.number}" title="{_e(o.title)}">{label}</button>' if o else "<span></span>"
                  for label, o in (("\u2190 Previous finding", prev), ("Next finding \u2192", nxt)))
    return (f'<div class="pane" id="f{f.number}" hidden><div class="dh"><button class="x" aria-label="Close">×</button>{_sev(f.severity)}{_action(f.action, f.rule_id)}{_origin_chips(f)}{_refs(f)}'
            f'<h2>{f.number}. {_e(f.title)}</h2>{loc}<div class="tabs" role="tablist">'
            + "".join(f'<button role="tab" data-tab="{k}"{" class=on" if k == "ov" else ""}>{n}</button>' for k, n, _ in tabs)
            + '</div></div><div class="db">' + "".join(f'<div data-tp="{k}"{"" if k == "ov" else " hidden"}>{"".join(parts) or "<p class=mut>Nothing recorded.</p>"}</div>' for k, _, parts in tabs)
            + f'<div class="dnav">{nav}</div></div></div>')


def _side_panes(view: ReportView) -> str:
    def pane(pid: str, title: str, body: str) -> str:
        return (f'<div class="pane" id="{pid}" hidden><div class="dh"><button class="x" aria-label="Close">×</button><h2 style="margin-bottom:16px">{title}</h2></div>'
                f'<div class="db">{body}</div></div>')
    gaps = ("<ul class=\"tight\">" + "".join(f"<li>{_e(g)}</li>" for g in view.gaps) + "</ul>") if view.gaps else '<p class="mut">No gaps were recorded.</p>'
    guide = ("<h4>Observation</h4><p>A raw scanner or DAST signal before review.</p><h4>Issue group &amp; verdict</h4><p>Correlated evidence assessed by the Review Agent. "
             "A model assessment, not independent exploit proof.</p><h4>Policy decision</h4><p>A release-gate outcome from a named rule. Never add it to the vulnerability count.</p>"
             "<h4>Coverage gap</h4><p>No finding in an untested area does not mean it passed.</p>")
    return pane("p-gaps", f"Known gaps ({len(view.gaps)})", gaps) + pane("p-guide", "How to read this report", guide)


def _exec(view: ReportView) -> str:
    """Briefing: where findings came from, how far the scan can be trusted, what to do next."""
    c, oc = view.counts, view.origin_counts

    def line(kind: str, icon: str, text: str) -> str:
        return f'<li class="{kind}"><i>{icon}</i><span>{text}</span></li>'

    rel: list[str] = []
    if view.has_execution and view.coverage_total:
        full = view.coverage_done == view.coverage_total
        rel.append(line("ok" if full else "bad", "✓" if full else "✗",
                        f"{view.coverage_done} of {view.coverage_total} scanner tasks completed" + ("" if full else f" — missing: {_e(', '.join(view.coverage_missing))}")))
    else:
        rel.append(line("warn", "!", "Scanner execution record not available"))
    req = view.scanner_requirement
    if req and req.get("requested"):
        met = bool(req.get("satisfied"))
        rel.append(line("ok" if met else "bad", "✓" if met else "✗", "Required scanners " + ("completed" if met else "did not all complete")))
    if view.ai is not None:
        stage = view.ai["required_ok"]
        rel.append(line("ok" if stage is True else "bad" if stage is False else "warn", "✓" if stage is True else "✗" if stage is False else "!",
                        f"AI Discovery {'completed' if stage is True else 'incomplete' if stage is False else 'not verified'}: {_e(view.ai['targets'])}/{_e(view.ai['planned'])} targets"))
    if view.dynamic:
        hits = sum(p.outcome == "finding" for p in view.probes)
        rel.append(line("ok", "✓", f"Dynamic testing ran: {len(view.probes)} probe(s) recorded, {hits} with a finding" if view.probes else "Dynamic testing ran"))
    else:
        rel.append(line("warn", "!", "Dynamic testing (DAST) did not run"))
    rel.append(line("warn" if view.gaps else "ok", "!" if view.gaps else "✓", f"{len(view.gaps)} known coverage gap(s)" if view.gaps else "No coverage gaps recorded"))
    origin = "".join(
        f'<button class="bar" data-k="origin" data-v="{o}" data-go="1" aria-pressed="false" title="{_e(_ORIGIN_HINT[o])}">'
        f'<span>{_e(_ORIGIN_LABEL[o])}</span><span class="track"><i style="width:{round(100 * oc.get(o, 0) / max(1, c["reviewed"]))}%;background:var(--{"low" if o == "static" else "mi" if o == "dynamic" else "medium"})"></i></span><b>{oc.get(o, 0)}</b></button>'
        for o in ("static", "dynamic", "ai"))
    steps = "".join(f"<li>{_e(x)}</li>" for x in view.next_steps[:4]) or "<li>No follow-up recorded.</li>"
    return (f'<div class="brief"><div><h3>Found by</h3>{origin}<p class="mut"><small>A finding confirmed by more than one kind of test counts in each.</small></p></div>'
            f'<div><h3>Scan reliability</h3><ul>{"".join(rel)}</ul></div>'
            f'<div><h3>Next actions</h3><ol>{steps}</ol></div></div>')


def _filters(view: ReportView) -> str:
    c, oc = view.counts, view.origin_counts
    sevs = sorted({f.severity for f in view.findings}, key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 9)
    count = lambda key, value: sum(getattr(f, key) == value for f in view.findings)
    return ('<div class="filters" role="group" aria-label="Filter findings">'
            '<div class="fg"><button data-k="all" aria-pressed="true">All findings</button></div>'
            '<div class="fg"><span>Found by</span>'
            + "".join(f'<button data-k="origin" data-v="{o}" aria-pressed="false" title="{_e(_ORIGIN_HINT[o])}">{_e(_ORIGIN_LABEL[o])}<em>{oc.get(o, 0)}</em></button>' for o in ("static", "dynamic", "ai"))
            + '</div><div class="fg"><span>Decision</span>'
            + "".join(f'<button data-k="action" data-v="{a}" aria-pressed="false">{ACTION_ICON[a]} {a}<em>{c[a]}</em></button>' for a in ("block", "warn"))
            + '</div><div class="fg"><span>Severity</span>'
            + "".join(f'<button data-k="sev" data-v="{_e(x)}" aria-pressed="false">{_e(x)}<em>{count("severity", x)}</em></button>' for x in sevs)
            + "</div></div>")


def _dynamic_log(view: ReportView, parts: list[str]) -> None:
    """Every dynamic check that ran, passes included, with the output it recorded."""
    if not (view.probes or view.workflow_steps):
        return
    parts.append('<h2 class="sec" id="dynamic">Dynamic scan log <small>Every probe that ran and what it recorded</small></h2>')
    if view.probes:
        hits = sum(p.outcome == "finding" for p in view.probes)
        parts.append(f'<details class="panel" open><summary><b>Probes</b> — {len(view.probes)} executed, {hits} with a finding, {len(view.probes) - hits} not observed</summary>'
                     '<p class="mut">“Not observed” means this probe did not confirm the behavior; it is not proof of absence. Status codes and flags only — response bodies, cookies and credentials are never stored.</p>'
                     '<div class="scroll"><table><thead><tr><th>Source</th><th>Rule</th><th>Target</th><th>Outcome</th><th>Severity</th><th>Recorded output</th></tr></thead><tbody>'
                     + "".join(f'<tr><td>{_e(r.source)}</td><td><code>{_e(r.rule_id)}</code></td><td><code>{_e(r.target)}</code></td>'
                               f'<td><span class="{"bad-t" if r.outcome == "finding" else "ok-t"}">{_e(r.outcome)}</span></td><td>{_e(r.severity or "—")}'
                               f'{f"<small>{_e(r.confidence)} confidence</small>" if r.confidence else ""}</td>'
                               f'<td>{"<br>".join(f"<small>{_e(k)}: {_e(v)}</small>" for k, v in r.output) or "—"}</td></tr>' for r in view.probes)
                     + "</tbody></table></div>"
                     + (f'<p class="mut">{view.probes_omitted} more probe record(s) are not shown.</p>' if view.probes_omitted else "") + "</details>")
    if view.workflow_steps:
        parts.append(f'<details class="panel" open><summary><b>Business workflows</b> — {len(view.workflow_steps)} step(s) declared</summary>'
                     '<p class="mut">Each step shows the HTTP status actually observed against the status the workflow expected. Skipped steps did not run because an earlier step or account check did not complete.</p>'
                     '<div class="scroll"><table><thead><tr><th>Workflow</th><th>Step</th><th>Actor</th><th>Request</th><th>Result</th><th>HTTP</th><th>Expected</th><th>Assertions</th></tr></thead><tbody>'
                     + "".join(f"<tr><td>{_e(w.workflow)}</td><td>{w.step}</td><td>{_e(w.actor)}</td><td><code>{_e(w.request)}</code></td>"
                               f"<td>{_e(w.status)}</td><td>{_e(w.http_status)}</td><td>{_e(w.expected)}</td><td>{_e(w.assertions)}</td></tr>" for w in view.workflow_steps)
                     + "</tbody></table></div></details>")


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
            f"<tr><td><b>{_e(r.role)}</b></td><td><span class=\"st {'ok' if r.status == 'completed' else 'warn' if r.status == 'not_scheduled' else 'bad'}\">{_e(r.outcome)}</span><small>{_e(r.status)}</small></td>"
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
    meta = (f"Generated {_e(view.generated)}", f"Policy <code>{_e(view.policy_status)}</code>", f"Review <code>{_e(view.review_status)}</code>",
            *([f"Rules <code>{_e(view.rule_set)}</code>"] if view.rule_set else []))
    parts: list[str] = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">",
        f"<title>Security Review · {_e(view.project)}</title><script>{_THEME_BOOT}</script><style>{_CSS}{_REPORT_CSS}</style></head><body>"
        '<a class="skip" href="#overview">Skip to report</a><div class="app wide">',
        _sidebar(view),
        f'<div><main><header class="doc-head"><small>Security assessment report</small><h1>{_e(view.project)}</h1>'
        '<div class="meta">' + "".join(f"<span>{x}</span>" for x in meta) + "</div></header>",
        f'<section id="overview"><div class="banner {_e(view.decision)}"><h2>{_e(view.headline)}</h2>'
        + "".join(f"<p>{_e(s)}</p>" for s in view.bottom_line) + "</div>",
    ]
    parts += [f'<div class="note">{n}</div>' for n in _notes(view)]
    parts.append(_distribution(view) + _exec(view) + _funnel(view) + "</section>")

    parts.append('<h2 class="sec" id="fix">Fix first <small>Blocking findings in priority order</small></h2>')
    if view.blocking:
        parts.append('<ol class="fixlist">' + "".join(_fix_row(f, i) for i, f in enumerate(view.blocking[:6], 1)) + "</ol>")
        if len(view.blocking) > 6:
            parts.append(f'<div class="more"><button data-k="action" data-v="block" data-go="1">Show all {len(view.blocking)} blocking findings in the table</button></div>')
    else:
        parts.append('<div class="empty"><b>Nothing met the automatic blocking criteria</b>This is not a security clearance; review the warnings and the coverage gaps below.</div>')

    parts.append('<h2 class="sec" id="findings">Findings <small id="cnt"></small></h2>')
    if view.findings:
        sortable = lambda label, key: f'<th data-sort="{key}"><button class="sort">{label}</button></th>'
        parts.append('<div class="tools"><input id="q" type="search" placeholder="Search title, path, CWE, rule…" aria-label="Search findings"></div>')
        parts.append(_filters(view))
        hint = "" if view.dynamic else " Dynamic testing did not run in this scan, so there are no Dynamic findings."
        parts.append('<div class="scroll"><table><thead><tr>' + sortable("#", "n") + "<th>Finding</th>" + sortable("Severity", "r") + sortable("Found by", "originsort")
                     + sortable("Affected file : line", "loc") + "<th>CWE · OWASP</th><th>Verdict</th><th>Tools</th><th>Decision</th></tr></thead><tbody>"
                     + "".join(_row(f) for f in view.findings) + "</tbody></table></div>"
                     f'<div id="none" class="empty" hidden><b>No findings match these filters</b>Clear a filter or change the search.{_e(hint)} <button class="chip" data-k="all">Clear filters</button></div>')
        parts.append('<section class="print-only" aria-label="Finding details"><h2 class="sec">Finding details</h2>' + "".join(_print_detail(f) for f in view.findings) + "</section>")
    else:
        parts.append('<div class="empty"><b>No reviewed findings</b>This does not show the project is safe. Check scanner coverage below before relying on a clean result.</div>')
    _coverage(view, parts)
    _dynamic_log(view, parts)
    _appendix(view, parts)
    panes = "".join(_pane(f, view.findings[i - 1] if i else None, view.findings[i + 1] if i + 1 < len(view.findings) else None) for i, f in enumerate(view.findings))
    parts.append(f'<footer>Static report · no external requests · generated {_e(view.generated)}</footer></main></div></div>'
                 '<div class="scrim" id="scrim"></div><aside class="dr" id="dr" aria-hidden="true"></aside>'
                 f'<div hidden>{panes}{_side_panes(view)}</div><script>{_JS}</script></body></html>')
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

"""VERDICT run report (HTML): one self-contained, offline page.

Layout: sidebar navigation, summary (decision, severity funnel, reviewer-verdict donut, "Found by" decomposition tree,
scan reliability), fix-first list, filterable findings table, side drawers (finding details, scan pipeline with agents and
scanners, known gaps, guide), coverage, dynamic scan log and appendix.  `_CSS`, `_JS`, `_THEME_BOOT`, `_e` and `_svg`
stay importable because `evaluation_html` shares them.  All scanner, model and repository text is HTML-escaped; the page
sends no network requests (strict CSP).
"""

from __future__ import annotations

import html
import re
from collections import Counter
from typing import Iterable

from security_reviewer_v2.policy.rules import RULES

from .penetration_summary import OUTCOMES, HypothesisRow
from .view import ACTION_ICON, DynamicEvidence, Finding, FoundNode, ReportView, first_sentence

_CSS = r"""

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
.chip.pen-exploitation_confirmed{color:var(--crit);border-color:currentColor;background:transparent}.chip.pen-not_reproduced{color:var(--mi);border-color:currentColor;background:transparent}
.chip.pen-inconclusive,.chip.pen-blocked,.chip.pen-cannot_test{color:var(--medium);border-color:currentColor;background:transparent}
.pen-sum{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 12px}.pen-sum span{border:1px solid var(--ln);border-radius:var(--r);padding:6px 12px;background:var(--pn)}.pen-sum b{font-size:18px;margin-right:6px}
.pen-steps{margin:4px 0 10px;padding-left:18px}.pen-steps li{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
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

_REPORT_CSS = r"""
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
th .sort{font:inherit;color:inherit}th .sort:after{content:" \2195";opacity:.4}th[aria-sort=ascending] .sort:after{content:" \2191";opacity:1}th[aria-sort=descending] .sort:after{content:" \2193";opacity:1}
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
.charts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:16px}
.cc{border:1px solid var(--ln);border-radius:var(--R);background:var(--pn);padding:16px 18px;min-width:0}
.cc h3{margin:0 0 12px;font-size:13px;font-weight:650;display:flex;justify-content:space-between;gap:8px;align-items:baseline}
.cc h3 small{color:var(--mut);font-weight:400;font-size:12px}
.fun{display:flex;flex-direction:column;gap:3px}
.fst{display:grid;grid-template-columns:minmax(0,1fr) 116px;gap:10px;align-items:center;width:100%;text-align:left;border-radius:var(--r);padding:0 4px}
.fst:hover,.fst[aria-pressed=true]{background:var(--glow)}
.fst[aria-pressed=true]{box-shadow:inset 0 0 0 1px var(--acc)}
.fz{display:flex;justify-content:center;height:34px}
.fz i{display:block;height:100%;clip-path:polygon(0 0,100% 0,calc(100% - var(--in,0%)) 100%,var(--in,0%) 100%);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.fl{font-size:13px;display:flex;gap:6px;align-items:baseline}
.fl b{font-weight:700}
.fl em{font-style:normal;color:var(--mut);font-size:12px}
.cc .dn{flex-wrap:wrap}
.cc .dn svg text{font-family:var(--serif)}
.cc .leg{gap:5px;font-size:12.5px;color:var(--ink)}
.cc .leg span{display:flex;gap:7px;align-items:baseline}.cc .leg b{font:700 13px var(--sans);margin-left:auto}.cc .leg{min-width:150px;flex:1}
.tree{font-size:13px}
.troot{display:flex;align-items:baseline;gap:8px;margin-bottom:8px;color:var(--mut)}
.troot b{font:600 22px var(--serif);color:var(--ink)}
.tn>summary{list-style:none;display:flex;align-items:center;gap:2px;cursor:pointer}
.tn>summary::-webkit-details-marker{display:none}
.tn>summary .bar{flex:1}
.tg{flex:none;width:18px;height:18px;display:grid;place-items:center;color:var(--mut);transition:transform .12s}
.tg:before{content:"";border:solid currentColor;border-width:0 2px 2px 0;width:6px;height:6px;transform:rotate(-45deg)}
.tn[open]>summary .tg{transform:rotate(90deg)}
.tn.leaf{padding-left:20px}
.kids{margin:2px 0 6px 9px;padding-left:12px;border-left:1px solid var(--ln);display:grid;gap:1px}
.kids .bar{grid-template-columns:140px 1fr 30px;padding:4px 8px;font-size:12.5px;position:relative}
.kids .bar:before{content:"";position:absolute;left:-12px;top:50%;width:10px;border-top:1px solid var(--ln)}
.kids .bar.zero{opacity:.6}
.thint{margin:8px 0 0;color:var(--mut);font-size:12px}
.brief.two{grid-template-columns:repeat(2,minmax(0,1fr))}
.hh{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.lk{color:var(--acc);font-size:12.5px;font-weight:600}
.lk:hover{text-decoration:underline}
.tf{font:500 12px var(--sans);border:1px solid var(--acc);border-radius:99px;padding:2px 10px;color:var(--ink);background:var(--glow)}
.agent{border:1px solid var(--ln);border-radius:var(--R);padding:12px 14px;margin:8px 0;background:var(--pn)}
.agent .ah{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.agent p{margin:2px 0 6px;color:var(--mut);font-size:12.5px}
.agent ul{margin:4px 0 0}
.agent details{margin-top:6px;font-size:12.5px}
.agent summary{cursor:pointer;color:var(--mut)}
.runs{list-style:none;margin:8px 0 0;padding:0;border:1px solid var(--ln);border-radius:var(--R);overflow:hidden;background:var(--pn)}
.runs li{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;padding:8px 12px;align-items:baseline}
.runs li+li{border-top:1px solid var(--ln)}
.runs small{color:var(--mut);text-align:right}
.runs .rg{background:var(--pn2);font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
.pipe{list-style:none;margin:8px 0 0;padding:0}
.pipe li{position:relative;display:grid;grid-template-columns:64px minmax(0,1fr);gap:14px;padding:10px 0 16px;border-bottom:1px dashed var(--ln)}
.pipe li:last-child{border:0}
.pipe li:not(:last-child):after{content:"";position:absolute;left:26px;bottom:-6px;border:6px solid transparent;border-top-color:var(--ln2)}
.pipe b{font:600 28px/1 var(--serif);text-align:right}
.pipe span{font-weight:650}
.pipe small{display:block;color:var(--mut);font-size:12.5px}
.db h4 .sub{color:var(--mut);font-weight:400;font-size:12.5px;margin-left:6px}
.cb{margin:6px 0}
.cb .cap{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);padding:4px 10px;background:var(--pn2);border:1px solid var(--ln);border-bottom:0;border-radius:var(--r) var(--r) 0 0}
.cb pre{margin:0;border-radius:0 0 var(--r) var(--r)}
.cb pre .k{color:var(--mut)}
.cb pre .m{color:var(--acc);font-weight:700}
.cb pre .t{color:var(--mint)}
.cb pre .f{color:var(--crit)}
.rules{display:grid;grid-template-columns:auto 1fr auto;gap:6px 14px;margin:8px 0 0;align-items:baseline}
@media(max-width:1280px){.charts{grid-template-columns:repeat(2,minmax(0,1fr))}.charts .cc:last-child{grid-column:1/-1}}
@media(max-width:1000px){.charts,.brief.two{grid-template-columns:1fr}}
@media print{.lk,.tf{display:none!important}.charts,.cc{break-inside:avoid}.charts{grid-template-columns:repeat(3,1fr)}.fst{pointer-events:none}}
"""

_JS = r"""
(function(){var D=document,R=D.documentElement,K='verdict-theme',$=function(s){return D.querySelector(s)};
$('#theme').addEventListener('click',function(){var c=R.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'),n=c==='dark'?'light':'dark';
R.setAttribute('data-theme',n);try{localStorage.setItem(K,n)}catch(e){}});
var KEYS=['origin','action','sev','tool'],st={origin:'',action:'',sev:'',tool:'',q:''},toolName='',items=[].slice.call(D.querySelectorAll('[data-f]')),cnt=$('#cnt'),q=$('#q');
function has(el,k,v){return(' '+(el.getAttribute('data-'+k)||'')+' ').indexOf(' '+v+' ')>-1}
function apply(){var n=0,rows=0;items.forEach(function(r){var ok=KEYS.every(function(k){return!st[k]||has(r,k,st[k])})&&(!st.q||r.textContent.toLowerCase().indexOf(st.q)>-1);r.hidden=!ok;if(r.tagName==='TR'){rows++;if(ok)n++}});
if(cnt)cnt.textContent=n+' of '+rows+' shown';var none=$('#none');if(none)none.hidden=n>0;var tf=$('#tf');if(tf){tf.hidden=!st.tool;if(st.tool){tf.setAttribute('data-k','tool');tf.setAttribute('data-v',st.tool);tf.textContent='Tool: '+(toolName||st.tool)+' \u00d7'}}
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
if(t.hasAttribute('data-k')){var k=t.getAttribute('data-k'),v=t.getAttribute('data-v');if(k==='tool'&&t.hasAttribute('data-label'))toolName=t.getAttribute('data-label');if(k==='all'){KEYS.forEach(function(x){st[x]=''})}else{st[k]=st[k]===v?'':v}apply();if(t.hasAttribute('data-go')){var f=$('#findings');if(f)f.scrollIntoView()}}
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
_VERDICTS = (("confirmed_vulnerability", "Confirmed", "var(--high)"), ("likely_vulnerability", "Likely", "var(--medium)"),
             ("likely_vulnerable", "Likely", "var(--medium)"), ("needs_more_evidence", "Needs evidence", "var(--low)"),
             ("false_positive", "False positive", "var(--ln2)"))
_ORIGIN_LABEL = {"static": "Static", "dynamic": "Dynamic", "ai": "AI discovery"}
_ORIGIN_COLOR = {"static": "var(--low)", "dynamic": "var(--mi)", "ai": "var(--medium)"}
_STAMP = {"blocked": "Release blocked", "clear": "No blocking findings", "incomplete": "Review incomplete", "no_findings": "No findings"}
_ICON = {
    "grid": '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.5M3 12h.5M3 18h.5"/>',
    "book": '<path d="M4 4h12a4 4 0 014 4v12H8a4 4 0 01-4-4z"/><path d="M4 16a4 4 0 014-4h12"/>',
}
_SUN_MOON = ('<span class="moon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/></svg></span>'
             '<span class="sun"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/>'
             '<path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/></svg></span>')


def _e(value: object) -> str:
    return html.escape(" ".join(str(value).split()), quote=True)


def _raw(value: object) -> str:
    return html.escape(str(value), quote=True)


def _rich(text: object) -> str:
    """Escape first, then allow only `code` and **bold** formatting."""
    safe = html.escape(str(text).strip(), quote=True).replace("\n", "<br>")
    safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", safe)
    safe = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", safe)
    return re.sub(r"(?<![*\w])\*([^*\s][^*]*?)\*(?![*\w])", r"<em>\1</em>", safe)


def _svg(name: str) -> str:
    return f'<svg viewBox="0 0 24 24" aria-hidden="true">{_ICON[name]}</svg>'


def _sev(severity: str) -> str:
    return f'<span class="chip sev-{_e(severity)}">{_e(severity.upper())}</span>'


def _action(action: str, rule: str = "") -> str:
    cls = action if action in {"block", "warn", "allow"} else ""
    return f'<span class="chip {cls}">{ACTION_ICON.get(action, "")} {_e(action)}' + (f" · {_e(rule)}" if rule else "") + "</span>"


def _origins(f: Finding) -> str:
    return "".join(f'<span class="chip o-{o}">{_ORIGIN_LABEL[o]}</span>' for o in f.origins) or '<span class="chip">n/a</span>'


def _yesno(value: str) -> str:
    return {"true": "yes", "false": "no"}.get(value, value)


# ----------------------------------------------------------------------------- summary charts
def _funnel(view: ReportView) -> str:
    """Severity funnel: one tapered bar per severity (most severe first), each clickable as a table filter."""
    stages = [(s, n) for s, n in view.severity_counts if n]
    if not stages:
        return '<p class="mut">No reviewed findings.</p>'
    total, peak = sum(n for _, n in stages), max(n for _, n in stages)
    rows = []
    for i, (sev, n) in enumerate(stages):
        width = max(18.0, 100.0 * n / peak)
        nxt = max(18.0, 100.0 * stages[i + 1][1] / peak) if i + 1 < len(stages) else width * 0.55
        inset = max(0.0, (1 - min(nxt, width) / width) / 2 * 100)
        color = f"var(--{sev})" if sev in _SEV_ORDER else "var(--info)"
        rows.append(f'<button class="fst" data-k="sev" data-v="{_e(sev)}" data-go="1" aria-pressed="false" aria-label="{_e(sev)}: {n} findings">'
                    f'<span class="fz"><i style="width:{width:.1f}%;--in:{inset:.1f}%;background:{color}"></i></span>'
                    f'<span class="fl">{_e(sev.capitalize())} <b>{n}</b><em>{round(100 * n / total)}%</em></span></button>')
    return f'<div class="fun" role="group" aria-label="Findings by severity">{"".join(rows)}</div>'


def _donut(view: ReportView) -> str:
    """Reviewer verdict donut with its legend."""
    total = len(view.findings)
    if not total:
        return '<p class="mut">No reviewed findings.</p>'
    counts = Counter(f.verdict for f in view.findings)
    merged: dict[str, tuple[int, str]] = {}
    for key, label, color in _VERDICTS:
        if counts.get(key):
            merged[label] = (merged.get(label, (0, color))[0] + counts[key], color)
    others = total - sum(n for n, _ in merged.values())
    if others:
        merged["Other"] = (others, "var(--ln)")
    radius, circ, offset, rings = 46, 2 * 3.14159265 * 46, 0.0, []
    for label, (n, color) in merged.items():
        seg = n / total * circ
        rings.append(f'<circle cx="60" cy="60" r="{radius}" fill="none" stroke="{color}" stroke-width="13" '
                     f'stroke-dasharray="{max(seg - 2, 0):.1f} {circ - max(seg - 2, 0):.1f}" stroke-dashoffset="{-offset:.1f}" transform="rotate(-90 60 60)"/>')
        offset += seg
    legend = "".join(f'<span><i style="background:{color}"></i>{_e(label)} <b>{n}</b></span>' for label, (n, color) in merged.items())
    return (f'<div class="dn"><svg viewBox="0 0 120 120" role="img" aria-label="Reviewer verdict distribution">{"".join(rings)}'
            f'<text x="60" y="62" text-anchor="middle" font-size="26" font-weight="700" fill="currentColor">{total}</text>'
            f'<text x="60" y="78" text-anchor="middle" font-size="9" fill="currentColor" opacity=".6">issue groups</text></svg>'
            f'<div class="leg">{legend}</div></div>')


def _node_bar(node: FoundNode, total: int, *, color: str, zero: bool = False, label_attr: bool = False) -> str:
    width = max(3, round(100 * node.count / total)) if node.count and total else 0
    key = "tool" if node.kind == "tool" else "origin"
    extra = f' data-label="{_e(node.label)}"' if node.kind == "tool" else ""
    title = f' title="{_e(node.note)}"' if node.note else ""
    return (f'<button class="bar{" zero" if zero else ""}" data-k="{key}" data-v="{_e(node.key)}" data-go="1" aria-pressed="false"{extra}{title}>'
            f'<span>{_e(node.label)}</span><span class="track"><i style="width:{width}%;background:{color}"></i></span><b>{node.count}</b></button>')


def _tree(view: ReportView) -> str:
    """"Found by" decomposition tree: origin -> the scanners / dynamic components that produced the findings."""
    if not view.found_by:
        return '<p class="mut">No origin data.</p>'
    total = len(view.findings)
    nodes = []
    for node in view.found_by:
        color = _ORIGIN_COLOR.get(node.key, "var(--info)")
        if not node.children:
            nodes.append(f'<div class="tn leaf">{_node_bar(node, total, color=color)}</div>')
            continue
        kids = "".join(_node_bar(c, node.count or 1, color=color, zero=c.count == 0) for c in node.children)
        nodes.append(f'<details class="tn"><summary><span class="tg" aria-hidden="true"></span>{_node_bar(node, total, color=color)}</summary>'
                     f'<div class="kids">{kids}</div></details>')
    return (f'<div class="tree"><div class="troot"><b>{total}</b><span>reviewed findings</span></div>{"".join(nodes)}'
            '<p class="thint">Open a branch to see each tool. A finding confirmed by more than one kind of test counts in each.</p></div>')


# ----------------------------------------------------------------------------- side panel: agents, tools, pipeline
def _state_word(state: str) -> str:
    return {"ok": "Completed", "warn": "Partial", "bad": "Failed"}.get(state, state)


def _pipeline_pane(view: ReportView) -> str:
    done = sum(a.state == "ok" for a in view.agents)
    out = ['<div class="pane" id="p-pipe" hidden><div class="dh"><button class="x" aria-label="Close">×</button>'
           '<h2 style="margin-bottom:4px">Scan pipeline</h2><p class="mut" style="margin:0 0 16px">Which agents and tests ran, and how the results became a decision.</p></div><div class="db">']
    if view.agents:
        out.append(f'<h4>Agents<span class="sub">{done} of {len(view.agents)} completed</span></h4>')
        for a in view.agents:
            notes = (f'<details><summary>{len(a.notes)} note(s)</summary><ul class="tight">' + "".join(f"<li>{_e(n)}</li>" for n in a.notes) + "</ul></details>") if a.notes else ""
            out.append(f'<div class="agent"><div class="ah"><b>{_e(a.name)}</b><span class="st {a.state}">{_state_word(a.state)}</span></div>'
                       f'<p>{_e(a.role)}</p><ul class="tight">' + "".join(f"<li>{_e(d)}</li>" for d in a.detail) + f"</ul>{notes}</div>")
    if view.test_runs:
        ran = sum(t.state == "ok" for t in view.test_runs)
        applicable = sum(t.state != "na" for t in view.test_runs)
        out.append(f'<h4>Scanners and tests<span class="sub">{ran} of {applicable} ran{f" · {view.skipped_tasks} skipped as not applicable" if view.skipped_tasks else ""}</span></h4><ul class="runs">')
        group = None
        for t in view.test_runs:
            if t.group != group:
                group = t.group
                n_ok = sum(x.state == "ok" for x in view.test_runs if x.group == group)
                n_all = sum(x.state != "na" for x in view.test_runs if x.group == group)
                out.append(f'<li class="rg"><span>{_e(group)}</span><small>{n_ok}/{n_all}</small></li>')
            out.append(f'<li><span><span class="st {t.state if t.state != "na" else ""}">{_e(t.label)}</span></span><small>{_e(t.detail)}</small></li>')
        out.append("</ul>")
    steps: list[tuple[int, str, str]] = []
    if view.dedup:
        steps.append((view.dedup[0], "raw scanner results", "Static and dynamic findings before de-duplication."))
        steps.append((view.dedup[1], "root-cause records", f"{view.dedup[2]} duplicate(s) merged: same vulnerability family, file and overlapping lines. Nothing is discarded."
                      if view.dedup[2] else "No duplicates found; every result is its own record."))
    ai_note = f"Includes {view.ai_only_groups} group(s) that came only from AI candidates." if view.ai_only_groups else "Scanner records grouped for review."
    steps.append((view.counts["reviewed"], "issue groups reviewed", ai_note))
    c = view.counts
    steps.append((c["block"], "blocking release", f'{c["warn"]} warn · {c["allow"]} allow. Decided by named release-gate rules, never by the AI description alone.'))
    out.append('<h4>Pipeline</h4><ol class="pipe">' + "".join(f"<li><b>{n}</b><div><span>{_e(label)}</span><small>{_e(note)}</small></div></li>" for n, label, note in steps) + "</ol>")
    return "".join(out) + "</div></div>"


# ----------------------------------------------------------------------------- findings
def _fact_display(key: str, value: str) -> str:
    if value in {"true", "false"}:
        return "yes" if value == "true" else "no"
    if value.startswith("[") and value.endswith("]"):
        items = [x.strip() for x in value[1:-1].split(",") if x.strip()]
        if key == "assertion_results":
            items = ["pass" if x == "true" else "fail" if x == "false" else x for x in items]
        return ", ".join(items)
    return value


def _trace_block(d: DynamicEvidence) -> str:
    """Dynamic test trace: what the probe did (workflow steps or request sent) and what it recorded."""
    head = (f'<div class="th"><b>{_e(d.scanner_name or d.scanner)}</b> · <code>{_e(d.rule_id)}</code> · target <code>{_e(d.endpoint)}</code> · {_sev(d.severity)}'
            f'<span class="chip">{_e(d.confidence)} confidence</span></div>')
    steps = ""
    if d.trace:
        items = "".join(f"<li><code>{_e(label)}</code><span>{_e(result)}</span></li>" for label, result in d.trace)
        steps = f'<p class="src">{_e(d.trace_note)}</p><ol class="steps">{items}</ol>'
    else:
        steps = '<p class="src">This scanner does not define a step sequence for this rule, so only the recorded output is shown.</p>'
    output = ('<div class="sub">Recorded output</div><table class="kv"><tbody>'
              + "".join(f"<tr><th>{_e(k)}</th><td>{_e(_fact_display(k, v))}</td></tr>" for k, v in d.output) + "</tbody></table>") if d.output else ""
    result = ('<div class="sub">Probe result</div><table class="kv"><tbody>'
              f'<tr><th>vulnerable</th><td>{"yes" if d.vulnerable else "no"}</td></tr><tr><th>severity</th><td>{_e(d.severity)}</td></tr>'
              f'<tr><th>confidence</th><td>{_e(d.confidence)}</td></tr></tbody></table>')
    note = '<p class="mut"><small>The dynamic scanners keep status codes and flags only; response bodies, cookies and credentials are withheld by design.</small></p>'
    return f'<h4>Dynamic test trace</h4><div class="trace">{head}{steps}{output}{result}{note}</div>'


def _fix_row(f: Finding) -> str:
    chips = (f"<code>{_e(f.location)}</code>" if f.location else "") + (f"<span>{f.corroboration} tools agree</span>" if f.corroboration > 1 else "") + _origins(f) \
        + "".join(f'<span class="chip">{_e(c)}</span>' for c in f.cwes) + "".join(f'<span class="chip">OWASP {_e(o)}</span>' for o in f.owasp)
    fix = f'<span class="ff"><b>Fix:</b> {_rich(first_sentence(f.remediation))}</span>' if f.remediation else ""
    return (f'<li><button class="fr sev-{_e(f.severity)}" data-open="f{f.number}"><span class="rk">{f.number}</span>'
            f'<span><strong>{_e(f.title)}</strong><span class="fl">{chips}</span>{fix}</span>'
            f'<span class="fs">{_sev(f.severity)}{_action(f.action, f.rule_id)}</span></button></li>')


def _row(f: Finding) -> str:
    refs = ", ".join(f.cwes) or "—"
    owasp = f"<small>{_e(', '.join(f.owasp))}</small>" if f.owasp else ""
    rank = _SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 9
    return (f'<tr data-f data-open="f{f.number}" tabindex="0" data-action="{_e(f.action)}" data-sev="{_e(f.severity)}" data-origin="{_e(" ".join(f.origins))}" '
            f'data-tool="{_e(" ".join(f.tools))}" data-n="{f.number}" data-r="{rank}" data-loc="{_e(f.location)}" data-originsort="{_e(f.origins[0] if f.origins else "")}">'
            f'<td>{f.number}</td><td><strong>{_e(f.title)}</strong></td><td><span class="dot sev-{_e(f.severity)}"></span>{_e(f.severity)}</td>'
            f'<td>{_origins(f)}</td><td>{f"<code>{_e(f.location)}</code>" if f.location else "—"}</td><td>{_e(refs)}{owasp}</td>'
            f'<td>{_e(f.verdict.replace("_", " "))}<small>{_e(f.confidence)} confidence</small></td><td>{f.corroboration or "—"}</td>'
            f'<td>{_action(f.action, f.rule_id)}</td></tr>')


def _pentest_chip(f: Finding) -> str:
    return f'<span class="chip pen-{_e(f.pentest_key)}" title="{_e(f.pentest_meaning)}">Pen-test: {_e(f.pentest_label)}</span>' if f.pentest_key else ""


def _chips(f: Finding) -> str:
    return (_sev(f.severity) + _action(f.action, f.rule_id) + _origins(f) + _pentest_chip(f) + "".join(f'<span class="chip">{_e(c)}</span>' for c in f.cwes)
            + "".join(f'<span class="chip">OWASP {_e(o)}</span>' for o in f.owasp))


def _lines(items: Iterable[str], rich: bool = False) -> str:
    return "<ul class=\"tight\">" + "".join(f"<li>{_rich(i) if rich else _e(i)}</li>" for i in items) + "</ul>"


def _sections(f: Finding) -> dict[str, str]:
    """The text blocks shared by the drawer tabs and the print layout."""
    ov = (f"<h4>Problem</h4><p>{_rich(f.explanation)}</p>" if f.explanation else "") + (f"<h4>Impact</h4><p>{_rich(f.impact)}</p>" if f.impact else "") \
        + (f"<h4>Location</h4><pre>{_raw(f.location)}</pre>" if f.location else "")
    ev = (f"<h4>Detected by</h4>{_lines(f.detected_by)}" if f.detected_by else "") + (f"<h4>Evidence</h4>{_lines(f.evidence, True)}" if f.evidence else "") \
        + "".join(f'<h4>Scanner snippet · {_e(label)}</h4><pre>{_raw(code)}</pre>' for label, code in f.snippets) \
        + "".join(_trace_block(d) for d in f.dynamic) \
        + (f"<h4>Limitations</h4>{_lines(f.limitations, True)}" if f.limitations else "")
    fx = f"<h4>Recommended fix</h4><p>{_rich(f.remediation)}</p>" if f.remediation else ""
    basis = f"<p class=\"mut\"><small>Evidence basis: {_e(f.evidence_basis.replace('_', ' '))}</small></p>" if f.evidence_basis else ""
    pen = (f"<h4>Penetration test</h4><p><b>{_e(f.pentest_label)}</b> — {_e(f.pentest_meaning)} See the Penetration testing section for every attempt.</p>"
           if f.pentest_key else "")
    wh = ("<h4>Why this decision</h4>" + _lines([x for x in (f.reason, *f.policy_evidence) if x]) + pen + basis
          + f'<p class="mut"><small>Issue group <code>{_e(f.group_id)}</code></small></p>')
    return {"ov": ov, "ev": ev, "fx": fx, "wh": wh}


def _pane(f: Finding, next_f: Finding | None, prev_f: Finding | None = None) -> str:
    chips = _chips(f)
    loc = f'<div class="loc"><code>{_e(f.location)}</code><button data-copy="{_e(f.location)}">Copy</button></div>' if f.location else ""
    tabs = (("ov", "Overview"), ("ev", "Evidence"), ("fx", "Fix"), ("wh", "Decision"))
    sec = _sections(f)
    prev = f'<button data-open="f{prev_f.number}" title="{_e(prev_f.title)}">← Previous finding</button>' if prev_f else "<span></span>"
    nav = (f'<button data-open="f{next_f.number}" title="{_e(next_f.title)}">Next finding →</button>' if next_f else "")
    return (f'<div class="pane" id="f{f.number}" hidden><div class="dh"><button class="x" aria-label="Close">×</button>{chips}<h2>{f.number}. {_e(f.title)}</h2>{loc}'
            '<div class="tabs" role="tablist">' + "".join(f'<button role="tab" data-tab="{k}"{" class=on" if k == "ov" else ""}>{n}</button>' for k, n in tabs) + "</div></div>"
            '<div class="db">' + "".join(f'<div data-tp="{k}"{"" if k == "ov" else " hidden"}>{sec[k] or "<p class=mut>Not recorded.</p>"}</div>' for k, _ in tabs)
            + f'<div class="dnav">{prev}{nav}</div></div></div>')


def _print_article(f: Finding) -> str:
    sec = _sections(f)
    chips = _chips(f)
    return (f'<article class="pd" data-f data-action="{_e(f.action)}" data-sev="{_e(f.severity)}" data-origin="{_e(" ".join(f.origins))}" data-tool="{_e(" ".join(f.tools))}">'
            f'<div>{chips}</div><h3>{f.number}. {_e(f.title)}</h3><div>{sec["ov"]}</div><div>{sec["ev"]}</div><div>{sec["fx"]}</div><div>{sec["wh"]}</div></article>')


def _filters(view: ReportView) -> str:
    def group(label: str, key: str, items: Iterable[tuple[str, str, int, str]]) -> str:
        buttons = "".join(f'<button data-k="{key}" data-v="{_e(v)}" aria-pressed="false"{f" title={chr(34)}{_e(t)}{chr(34)}" if t else ""}>{text}<em>{n}</em></button>' for v, text, n, t in items if n)
        return f'<div class="fg"><span>{label}</span>{buttons}</div>' if buttons else ""
    oc = {o: sum(o in f.origins for f in view.findings) for o in _ORIGIN_LABEL}
    notes = {n.key: n.note for n in view.found_by}
    c = view.counts
    return ('<div class="filters" role="group" aria-label="Filter findings"><div class="fg"><button data-k="all" aria-pressed="true">All findings</button></div>'
            + group("Found by", "origin", [(o, _ORIGIN_LABEL[o], oc[o], notes.get(o, "")) for o in _ORIGIN_LABEL])
            + group("Decision", "action", [(a, f"{ACTION_ICON[a]} {a}", c.get(a, 0), "") for a in ("block", "warn", "allow")])
            + group("Severity", "sev", [(s, s, n, "") for s, n in view.severity_counts]) + "</div>")


# ----------------------------------------------------------------------------- coverage, dynamic log, appendix
def _coverage(view: ReportView) -> str:
    out = ['<h2 class="sec" id="coverage">Coverage &amp; trust <small>What actually ran</small></h2>']
    if view.scanners:
        out.append('<div class="scroll"><table><thead><tr><th>Scanner</th><th>Result</th><th>What it means</th></tr></thead><tbody>' + "".join(
            f'<tr><td><b>{_e(r.role)}</b></td><td><span class="st {"ok" if r.status == "completed" else "warn" if r.status in {"not_scheduled", "skipped"} else "bad"}">{_e(r.outcome)}</span>'
            f'<small>{_e(r.status)}</small></td><td>{_e(r.meaning)}' + "".join(f"<br><small>{_e(n)}</small>" for n in r.notes) + "</td></tr>" for r in view.scanners)
            + "</tbody></table></div>")
    else:
        out.append('<div class="empty"><b>No scanner execution record</b>This saved run has no scanner task information, so scanner coverage cannot be verified.</div>')
    if view.gaps:
        out.append(f'<p class="mut">{len(view.gaps)} known coverage gap(s) lower confidence in a clean result for those areas. '
                   '<button class="lk" data-open="p-gaps">View the gaps</button></p>')
    return "".join(out)


def _outcome(vulnerable: bool) -> str:
    return '<span class="bad-t">finding</span>' if vulnerable else '<span class="ok-t">not observed</span>'


def _dynamic(view: ReportView) -> str:
    if not view.dynamic:
        return ""
    out = ['<h2 class="sec" id="dynamic">Dynamic scan log <small>Every probe that ran and what it recorded</small></h2>']
    target = next((v for k, v in view.dynamic_facts if k == "Target"), "")
    caveats = [l.lstrip("- ").strip() for l in view.runtime_lines if l.lstrip("- ").startswith(("This evidence", "These observations"))]
    if target or caveats:
        out.append(f'<p class="mut">' + (f"Target <code>{_e(target)}</code>. " if target else "") + " ".join(_e(c) for c in caveats) + "</p>")
    if view.probe_log:
        pos = sum(p.vulnerable for p in view.probe_log)
        rows = "".join(
            f'<tr><td>{_e(p.source or "—")}</td><td><code>{_e(p.rule_id)}</code></td><td><code>{_e(p.endpoint)}</code></td><td>{_outcome(p.vulnerable)}</td>'
            f'<td>{_e(p.severity)}{f"<small>{_e(p.confidence)} confidence</small>" if p.confidence else ""}</td>'
            f'<td>{"<br>".join(f"<small>{_e(k)}: {_e(_fact_display(k, v))}</small>" for k, v in p.output) or "—"}</td></tr>' for p in view.probe_log)
        out.append(f'<details class="panel" open><summary><b>Probes</b> — {len(view.probe_log)} executed, {pos} with a finding, {len(view.probe_log) - pos} not observed</summary>'
                   '<p class="mut">“Not observed” means this probe did not confirm the behavior; it is not proof of absence. Status codes and flags only — response bodies, cookies and credentials are never stored.</p>'
                   '<div class="scroll"><table><thead><tr><th>Source</th><th>Rule</th><th>Target</th><th>Outcome</th><th>Severity</th><th>Recorded output</th></tr></thead>'
                   f'<tbody>{rows}</tbody></table></div></details>')
    if view.workflow_steps:
        rows = "".join(f'<tr><td>{_e(w.workflow)}</td><td>{w.step}</td><td>{_e(w.actor)}</td><td><code>{_e(w.request)}</code></td><td>{_e(w.result)}</td>'
                       f'<td>{_e(w.http)}</td><td>{_e(w.expected)}</td><td>{_e(w.assertions)}</td></tr>' for w in view.workflow_steps)
        out.append(f'<details class="panel" open><summary><b>Business workflows</b> — {len(view.workflow_steps)} step(s) declared</summary>'
                   '<p class="mut">Each step shows the HTTP status actually observed against the status the workflow expected. Skipped steps did not run because an earlier step or account check did not complete.</p>'
                   '<div class="scroll"><table><thead><tr><th>Workflow</th><th>Step</th><th>Actor</th><th>Request</th><th>Result</th><th>HTTP</th><th>Expected</th><th>Assertions</th></tr></thead>'
                   f'<tbody>{rows}</tbody></table></div></details>')
    return "".join(out)


def _pen_chip(row: HypothesisRow) -> str:
    return f'<span class="chip pen-{_e(row.outcome)}" title="{_e(row.meaning)}">{_e(row.label)}</span>'


def _pen_detail(row: HypothesisRow) -> str:
    body = [f'<p class="mut">{_e(row.meaning)}</p>']
    if row.summary:
        body.append(f"<p>{_e(row.summary)}</p>")
    meta = [("Source location", row.location), ("Tested endpoint", row.endpoint), ("Verification", row.verification.replace("_", " "))]
    body.append('<p class="mut">' + " · ".join(f"{_e(k)}: <code>{_e(v)}</code>" for k, v in meta if v) + "</p>")
    for a in row.attempts:
        steps = ('<ol class="pen-steps">' + "".join(f"<li>{_e(s)}</li>" for s in a.steps) + "</ol>") if a.steps else '<p class="mut">No request was sent.</p>'
        nxt = a.next_action.replace("_", " ") + (f" ({a.stop_reason.replace('_', ' ')})" if a.stop_reason not in ("", "none") else "")
        body.append(f'<h4>Attempt {a.number} · <code>{_e(a.strategy)}</code> via {_e(", ".join(a.tools) or "unknown")}</h4>'
                    f'<p class="mut"><small>Plan: {_e(a.plan)}</small></p>{steps}<p><b>Observation:</b> {_e(a.observation)}</p>'
                    + (f'<p class="mut"><small>Reasoning: {_e(a.reasoning)}</small></p>' if a.reasoning else "")
                    + f'<p class="mut"><small>Next action: {_e(nxt)}</small></p>')
    if row.not_executed:
        body.append('<h4>Scenarios drawn up but never sent</h4><ul class="tight">' + "".join(f"<li>{_e(g)}</li>" for g in row.not_executed) + "</ul>")
    return (f'<details class="panel"><summary>{_pen_chip(row)} <b>{_e(row.title)}</b> <small>· {len(row.attempts)} attempt(s)</small></summary>'
            + "".join(body) + "</details>")


def _penetration(view: ReportView) -> str:
    pen = view.penetration
    if pen is None:
        return ""
    out = ['<h2 class="sec" id="pentest">Penetration testing <small>Did the penetration agent prove each AI Discovery finding?</small></h2>']
    if pen.status != "completed":
        out.append(f'<div class="note"><b>The penetration stage did not complete (status: {_e(pen.status)}).</b>'
                   + "".join(f"<br><small>{_e(w)}</small>" for w in pen.warnings) + "</div>")
        return "".join(out)
    u = pen.usage
    out.append('<p class="mut">The agent only sends read-only requests to an isolated test stack with test accounts. '
               f'{_e(u.get("hypotheses_tested", 0))} hypothesis(es) tested, {_e(u.get("total_attempts", 0))} attempt(s), {_e(u.get("total_requests", 0))} request(s).</p>')
    if not pen.rows:
        out.append('<div class="empty"><b>No AI Discovery finding was eligible for penetration testing</b>Only findings that Verification confirmed in the source are tested.</div>')
        return "".join(out)
    out.append('<div class="pen-sum">' + "".join(f'<span class="pen-{k}"><b>{pen.count(k)}</b>{_e(OUTCOMES[k][0])}</span>' for k in OUTCOMES if pen.count(k)) + "</div>")
    if pen.not_sent:
        out.append(f'<p class="mut"><small>{pen.not_sent} more AI Discovery candidate(s) were not source-confirmed by Verification, so they were never sent to the penetration agent.</small></p>')
    rows = "".join(f'<tr><td>{i}</td><td><strong>{_e(r.title)}</strong><br><small><code>{_e(r.candidate_id)}</code></small></td><td>{_e(r.severity)}</td>'
                   f'<td>{f"<code>{_e(r.location)}</code>" if r.location else "—"}</td><td>{_pen_chip(r)}</td><td>{len(r.attempts)}</td></tr>' for i, r in enumerate(pen.rows, 1))
    out.append('<div class="scroll"><table><thead><tr><th>#</th><th>AI Discovery finding</th><th>Severity</th><th>Location</th><th>Penetration test result</th><th>Attempts</th></tr></thead>'
               f"<tbody>{rows}</tbody></table></div>")
    out.append('<p class="mut"><small>“Not reproduced” means every attempt was denied as expected; it is not proof that the flaw does not exist. '
               "“Proven” means the probe reproduced the access violation against the test stack.</small></p>")
    out.append("<h3>What the agent did, finding by finding</h3>" + "".join(_pen_detail(r) for r in pen.rows))
    return "".join(out)


def _appendix(view: ReportView) -> str:
    out = ['<h2 id="appendix">Appendix</h2>']
    if view.policy_rows:
        by_rule: dict[str, list[dict]] = {}
        for d in view.policy_rows:
            by_rule.setdefault(str(d.get("rule_id") or "—"), []).append(d)
        rules = "".join(
            f'<tr><td>{_action(str(ds[0].get("action")))}</td><td><code>{_e(r)}</code></td><td>{_e(RULES[r].title) if r in RULES else "—"}</td><td>{len(ds)}</td>'
            f'<td>{_e(", ".join(sorted({str(d.get("evidence_basis") or "—").replace("_", " ") for d in ds})))}</td></tr>' for r, ds in sorted(by_rule.items()))
        out.append('<details class="panel"><summary><b>A. Release-gate rules applied</b></summary><p class="mut">Each decision comes from one named rule applied to the AI verdict <b>and</b> deterministic evidence; '
                   'the AI description alone never blocks a release. The rule behind each finding is shown in the findings table.</p>'
                   '<div class="scroll"><table><thead><tr><th>Action</th><th>Rule</th><th>Meaning</th><th>Findings</th><th>Evidence basis</th></tr></thead>'
                   f'<tbody>{rules}</tbody></table></div></details>')
    if view.observations:
        out.append(f'<details class="panel"><summary><b>B. Scanner and DAST observations</b> ({len(view.observations)})</summary><p class="mut">Signals to assess, not confirmed independent vulnerabilities.</p>'
                   '<div class="scroll"><table><thead><tr><th>#</th><th>Observation</th><th>Origin</th><th>Evidence</th><th>Location</th><th>Severity</th><th>Risk</th></tr></thead><tbody>'
                   + "".join(f'<tr><td>{o.number}</td><td>{_e(o.title)}<br><small>{_e(", ".join(o.rule_ids))}</small></td><td>{_e(o.origin)}</td><td>{o.evidence_count}</td>'
                             f'<td><code>{_e(o.location)}</code></td><td>{_e(o.severity)}</td><td>{_e(o.risk)}</td></tr>' for o in view.observations) + "</tbody></table></div></details>")
    if view.triage is not None:
        t = view.triage
        unresolved = ("<ul class=\"tight\">" + "".join(f"<li><code>{_e(cid)}</code>: {_e(disp)}" + (f" at <code>{_e(w)}</code>" if w else "") + "</li>" for cid, disp, w in view.unresolved) + "</ul>") if view.unresolved else ""
        out.append("<details class=\"panel\"><summary><b>C. Candidate triage</b></summary><p>"
                   f"Observation records: {_e(t.get('input_scanner_findings', 0))}; issue groups after correlation: {_e(t.get('review_groups', 0))}. "
                   f"AI candidates: {_e(t.get('input_ai_candidates', 0))}; new: {_e(t.get('novel_candidates', 0))}; needs more evidence: {_e(t.get('needs_more_evidence', 0))}; rejected: {_e(t.get('rejected', 0))}.</p>{unresolved}</details>")
    out.append("<details class=\"panel\"><summary><b>D. Method and limitations</b></summary><ul class=\"tight\">" + "".join(f"<li>{_e(s)}</li>" for s in view.limitations) + "</ul></details>")
    return "".join(out)


def _side_panes(view: ReportView) -> str:
    def pane(pid: str, title: str, body: str) -> str:
        return (f'<div class="pane" id="{pid}" hidden><div class="dh"><button class="x" aria-label="Close">×</button><h2 style="margin-bottom:16px">{_e(title)}</h2></div>'
                f'<div class="db">{body}</div></div>')
    gaps = "<ul class=\"tight\">" + "".join(f"<li>{_e(g)}</li>" for g in view.gaps) + "</ul>" if view.gaps else "<p class=\"mut\">No coverage gaps were recorded.</p>"
    gaps = ("<p class=\"mut\">Each gap lowers confidence in a clean result for that area.</p>" + gaps) if view.gaps else gaps
    guide = ("<h4>Observation</h4><p>A raw scanner or DAST signal before review.</p><h4>Issue group &amp; verdict</h4><p>Correlated evidence assessed by the Review Agent. A model assessment, not independent exploit proof.</p>"
             "<h4>Found by</h4><p>Static = scanners reading code, dependencies, secrets and configuration. Dynamic = probes sent to the running app. AI discovery = candidates the AI agent found by reading source.</p>"
             "<h4>Policy decision</h4><p>A release-gate outcome from a named rule. Never add it to the vulnerability count.</p>"
             "<h4>Coverage gap</h4><p>No finding in an untested area does not mean it passed.</p>")
    return pane("p-gaps", f"Known gaps ({len(view.gaps)})", gaps) + pane("p-guide", "How to read this report", guide)


# ----------------------------------------------------------------------------- page
def _reliability(view: ReportView) -> str:
    items: list[tuple[str, str]] = []
    if view.has_execution and view.coverage_total:
        bad = view.coverage_done < view.coverage_total
        items.append(("bad" if bad else "ok", f"{view.coverage_done} of {view.coverage_total} scanner tasks completed" + (f" — not completed: {', '.join(view.coverage_missing)}" if view.coverage_missing else "")))
    elif not view.has_execution:
        items.append(("warn", "No scanner execution record; scanner coverage cannot be verified"))
    for a in view.agents:
        items.append((a.state, f"{a.name}: {_state_word(a.state).lower()} · {a.detail[1] if len(a.detail) > 1 else a.status}"))
    if view.dynamic:
        n = len(view.probe_log)
        items.append(("ok", f"Dynamic testing ran: {n} probe(s) recorded, {sum(p.vulnerable for p in view.probe_log)} with a finding" if n else "Dynamic testing ran"))
    else:
        items.append(("warn", "Dynamic testing was not run; exploitability is inferred from code"))
    if view.gaps:
        items.append(("warn", f"{len(view.gaps)} known coverage gap(s)"))
    glyph = {"ok": "✓", "warn": "!", "bad": "✕"}
    return ('<div><h3 class="hh">Scan reliability<button class="lk" data-open="p-pipe">Agents &amp; pipeline →</button></h3><ul>'
            + "".join(f'<li class="{s}"><i>{glyph[s]}</i><span>{_e(t)}</span></li>' for s, t in items) + "</ul></div>")


def render_html(view: ReportView) -> str:
    """Render the VERDICT report: sidebar navigation, summary charts, findings table, side drawers, coverage and dynamic log."""
    c = view.counts
    title = view.display_name or view.project
    stamp = _STAMP.get(view.decision, view.decision)
    gap_badge = f"<em>{len(view.gaps)}</em>" if view.gaps else ""
    open_agents = [a for a in view.agents if a.state != "ok"]
    pipe_badge = f"<em>{len(open_agents)} {'partial' if all(a.state == 'warn' for a in open_agents) else 'issue'}</em>" if open_agents else ""
    nav = [("#overview", "Summary", ""), ("#fix", "Fix first", str(len(view.blocking)) if view.blocking else ""), ("#findings", "Findings", str(len(view.findings))),
           ("#coverage", "Coverage & trust", "")]
    if view.penetration is not None:
        nav.append(("#pentest", "Penetration testing", f"{view.penetration.count('exploitation_confirmed')} proven" if view.penetration.rows else ""))
    if view.dynamic:
        nav.append(("#dynamic", "Dynamic scan log", str(len(view.probe_log)) if view.probe_log else ""))
    nav.append(("#appendix", "Appendix", ""))
    toc = "".join(f'<a href="{h}"><span>{_e(n)}</span>{f"<em>{_e(b)}</em>" if b else ""}</a>' for h, n, b in nav)
    side = (f'<aside class="side" aria-label="Report navigation"><div class="brand"><div class="logo">V</div><div><b>Verdict</b><span>Security assessment</span></div></div>'
            f'<div><span class="stamp {_e(view.decision)}">{_e(stamp)}</span></div><nav class="toc" aria-label="Sections">{toc}<hr>'
            f'<button class="{"gap" if open_agents else ""}" data-open="p-pipe"><span>Scan pipeline</span>{pipe_badge}</button>'
            f'<button class="gap" data-open="p-gaps"><span>Known gaps</span>{gap_badge}</button><button data-open="p-guide"><span>How to read this report</span></button></nav>'
            f'<div class="sidefoot"><button id="print" title="Print or save as PDF">Print / PDF</button><button class="theme" id="theme" aria-label="Toggle dark / light mode" title="Dark / light mode">{_SUN_MOON}</button></div></aside>')
    meta = (f"<span>Generated {_e(view.generated)}</span><span>Policy <code>{_e(view.policy_status)}</code></span><span>Review <code>{_e(view.review_status)}</code></span>"
            + (f"<span>Rules <code>{_e(view.rule_set)}</code></span>" if view.rule_set else ""))
    notes = ""
    req = view.scanner_requirement
    if req and req.get("requested") and not req.get("satisfied"):
        notes = ('<div class="note"><b>This scan is incomplete.</b> One or more required scanners did not complete with normalized output.'
                 + "".join(f"<br><small>{_e(i)}</small>" for i in req.get("failures", [])) + "</div>")
    summary = (f'<section id="overview"><div class="banner {_e(view.decision)}"><h2>{_e(view.headline)}</h2>' + "".join(f"<p>{_e(s)}</p>" for s in view.bottom_line) + f"</div>{notes}"
               f'<div class="charts"><div class="cc"><h3>Severity<small>{len(view.findings)} reviewed finding(s)</small></h3>{_funnel(view)}</div>'
               f'<div class="cc"><h3>Reviewer verdict</h3>{_donut(view)}</div><div class="cc"><h3>Found by</h3>{_tree(view)}</div></div>'
               f'<div class="brief two">{_reliability(view)}<div><h3>Next actions</h3><ol>' + "".join(f"<li>{_e(s)}</li>" for s in view.next_steps) + "</ol></div></div></section>")
    if view.blocking:
        fix = ('<h2 class="sec" id="fix">Fix first <small>Blocking findings in priority order</small></h2><ol class="fixlist">' + "".join(_fix_row(f) for f in view.blocking[:6]) + "</ol>"
               + (f'<div class="more"><button data-k="action" data-v="block" data-go="1">Show all {len(view.blocking)} blocking findings in the table</button></div>' if len(view.blocking) > 6 else ""))
    else:
        fix = '<h2 class="sec" id="fix">Fix first <small>Blocking findings in priority order</small></h2><div class="empty"><b>Nothing met the automatic blocking criteria</b>This is not a security clearance; read the coverage section.</div>'
    if view.findings:
        head = ("<tr>" + "".join(h for h in ('<th data-sort="n"><button class="sort">#</button></th>', "<th>Finding</th>", '<th data-sort="r"><button class="sort">Severity</button></th>',
                '<th data-sort="originsort"><button class="sort">Found by</button></th>', '<th data-sort="loc"><button class="sort">Affected file : line</button></th>',
                "<th>CWE · OWASP</th>", "<th>Verdict</th>", "<th>Tools</th>", "<th>Decision</th>")) + "</tr>")
        findings = (f'<h2 class="sec" id="findings">Findings <small id="cnt"></small><button class="tf" id="tf" hidden></button></h2><div class="tools"><input id="q" type="search" placeholder="Search title, path, CWE, rule…" aria-label="Search findings"></div>'
                    f'{_filters(view)}<div class="scroll"><table><thead>{head}</thead><tbody>{"".join(_row(f) for f in view.findings)}</tbody></table></div>'
                    '<div id="none" class="empty" hidden><b>No findings match these filters</b>Clear a filter or change the search. <button class="chip" data-k="all">Clear filters</button></div>'
                    '<section class="print-only" aria-label="Finding details"><h2 class="sec">Finding details</h2>' + "".join(_print_article(f) for f in view.findings) + "</section>")
    else:
        findings = ('<h2 class="sec" id="findings">Findings</h2><div class="empty"><b>No agent-reviewed findings</b>Absence of findings is not evidence of safety; check the coverage section.</div>')
    panes = "".join(_pane(f, view.findings[i + 1] if i + 1 < len(view.findings) else None, view.findings[i - 1] if i else None) for i, f in enumerate(view.findings)) + _pipeline_pane(view) + _side_panes(view)
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">"
            f"<title>Security Review · {_e(title)}</title><script>{_THEME_BOOT}</script><style>{_CSS}{_REPORT_CSS}</style></head><body>"
            f'<a class="skip" href="#overview">Skip to report</a><div class="app wide">{side}<div><main><header class="doc-head"><small>Security assessment report</small><h1>{_e(title)}</h1>'
            f'<div class="meta">{meta}</div></header>{summary}{fix}{findings}{_coverage(view)}{_penetration(view)}{_dynamic(view)}{_appendix(view)}'
            f'<footer>Static report · no external requests · generated {_e(view.generated)}</footer></main></div></div>'
            f'<div class="scrim" id="scrim"></div><aside class="dr" id="dr" aria-hidden="true"></aside><div hidden>{panes}</div><script>{_JS}</script></body></html>')

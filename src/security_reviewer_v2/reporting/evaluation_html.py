"""Evaluation report page: same look, rail and dark/light switch as the run report (`html_report`).

Both held-out evaluators (comprehensive lab, multi-service lab) describe their results as plain data and let this
module draw them, so the two evaluation pages and the run report always share one stylesheet and one script.
Every string is HTML-escaped; the page is static, self-contained and sends no network requests (strict CSP).
"""

from __future__ import annotations

import math

from typing import Any, Iterable, Sequence

from .html_report import _CSS, _JS, _THEME_BOOT, _e, _svg

_EXTRA_CSS = """
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:16px}
.kpi{background:linear-gradient(180deg,var(--pn),var(--pn2));border:1px solid var(--ln);border-radius:14px;padding:16px 18px}
.kpi strong{display:block;font-size:28px;color:var(--mi);line-height:1.15}.kpi span{color:var(--mut);font-size:12.5px}
.g2{display:grid;grid-template-columns:minmax(260px,1fr) 2fr;gap:16px;margin-top:16px}
dl.prov{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:7px 18px;margin:0}dl.prov dt{color:var(--mut)}dl.prov dd{margin:0;overflow-wrap:anywhere}
@media(max-width:1000px){.g2{grid-template-columns:1fr}}
.banner.has-gauge{display:grid;grid-template-columns:minmax(0,1fr) 240px;gap:24px;align-items:center}
.gauge{width:100%;text-align:center}.gauge svg{width:100%;height:auto;display:block}
.gauge .gt{stroke:var(--ln2)}.gauge .gv{stroke:var(--mint)}.gauge text{fill:currentColor;font-family:var(--serif)}.gauge .gs{font-family:var(--sans);opacity:.65}
@media(max-width:760px){.banner.has-gauge{grid-template-columns:1fr}}
"""
_STATUS_CLASS = {"detected": "allow", "needs_review": "warn", "not_detected": "block"}
_SUN_MOON = ('<svg class="moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/></svg>'
             '<svg class="sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/></svg>')


def _label(status: str) -> str:
    return status.replace("_", " ")


def _chip(status: str) -> str:
    return f'<span class="chip {_STATUS_CLASS.get(status, "")}">{_e(_label(status))}</span>'


def _cell(value: Any) -> str:
    main, sub = value if isinstance(value, (tuple, list)) else (value, None)
    return f"<td>{_e(main)}" + (f"<small>{_e(sub)}</small>" if sub else "") + "</td>"


def _donut(parts: Sequence[tuple[str, int, str]], unit: str) -> str:
    parts = [p for p in parts if p[1] > 0]
    total = sum(p[1] for p in parts)
    if not total:
        return '<p class="mut">Nothing to chart.</p>'
    radius, circ, offset, rings = 46, 2 * 3.14159265 * 46, 0.0, []
    for _, count, color in parts:
        seg = count / total * circ
        rings.append(f'<circle cx="60" cy="60" r="{radius}" fill="none" stroke="{color}" stroke-width="13" '
                     f'stroke-dasharray="{max(seg - 2, 0):.1f} {circ - max(seg - 2, 0):.1f}" stroke-dashoffset="{-offset:.1f}" transform="rotate(-90 60 60)"/>')
        offset += seg
    legend = "".join(f'<span><i style="background:{color}"></i>{_e(label)} {count}</span>' for label, count, color in parts)
    return (f'<div class="dn"><svg viewBox="0 0 120 120" role="img" aria-label="Outcome distribution">{"".join(rings)}'
            f'<text x="60" y="62" text-anchor="middle" font-size="26" font-weight="800" fill="currentColor">{total}</text>'
            f'<text x="60" y="78" text-anchor="middle" font-size="9" fill="currentColor" opacity=".6">{_e(unit)}</text></svg>'
            f'<div class="leg">{legend}</div></div>')


def _pane(index: int, row: dict[str, Any]) -> str:
    body = []
    for heading, content in row.get("details", ()):
        if isinstance(content, (list, tuple)):
            items = "".join(f"<li>{_e(item)}</li>" for item in content) or "<li>None recorded</li>"
            body.append(f'<h4>{_e(heading)}</h4><ul class="tight">{items}</ul>')
        else:
            body.append(f"<h4>{_e(heading)}</h4><p>{_e(content) if content else 'not recorded'}</p>")
    return (f'<div class="pane" id="c{index}" hidden><div class="dh"><button class="x" aria-label="Close">×</button>{_chip(row["status"])}'
            f'<h2>{_e(row["id"])}</h2></div><div class="db">{"".join(body)}</div></div>')


def _section(heading: str, items: Iterable[Any]) -> str:
    items = [str(i) for i in items] or ["None recorded"]
    lis = "".join(f"<li>{_e(i)}</li>" for i in items)
    if len(items) > 6:
        return f'<details class="panel"><summary><b>{_e(heading)}</b> ({len(items)})</summary><ul class="tight">{lis}</ul></details>'
    return f'<div class="panel"><b>{_e(heading)}</b><ul class="tight">{lis}</ul></div>'


def _gauge(value: int, total: int, label: str) -> str:
    """Semicircle gauge: ``value`` of ``total``, with the share as a percentage."""
    if total <= 0:
        return ""
    frac = max(0.0, min(1.0, value / total))
    x, y = 100 - 80 * math.cos(math.pi * frac), 100 - 80 * math.sin(math.pi * frac)
    arc = f'<path class="gv" d="M20 100 A80 80 0 0 1 {x:.2f} {y:.2f}" fill="none" stroke-width="16" stroke-linecap="round"/>' if value > 0 else ""
    return (f'<div class="gauge"><svg viewBox="0 0 200 128" role="img" aria-label="{value} of {total} {_e(label)} ({frac:.1%})">'
            f'<path class="gt" d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke-width="16" stroke-linecap="round"/>{arc}'
            f'<text x="100" y="86" text-anchor="middle" font-size="34" font-weight="700">{value}/{total}</text>'
            f'<text class="gs" x="100" y="106" text-anchor="middle" font-size="13">{frac:.1%}</text>'
            f'<text class="gs" x="20" y="123" text-anchor="middle" font-size="10">0</text><text class="gs" x="180" y="123" text-anchor="middle" font-size="10">{total}</text></svg>'
            f'<small class="mut">{_e(label)}</small></div>')


def render_evaluation(*, title: str, intro: str, headline: str, cards: Sequence[tuple[Any, str]] = (),
                      gauge: tuple[int, int, str] | None = None, table_title: str, columns: Sequence[str], outcome_header: str, rows: Sequence[dict[str, Any]],
                      donut: Sequence[tuple[str, int, str]] = (), donut_unit: str = "cases",
                      notes: Sequence[str] = (), provenance: Sequence[tuple[str, Any]] = (),
                      sections: Sequence[tuple[str, Iterable[Any]]] = ()) -> str:
    """Rows: ``{"id", "status", "cells": [text | (text, subtext)], "details": [(heading, text | [lines])]}``."""
    statuses = list(dict.fromkeys(row["status"] for row in rows))
    rail = ('<nav class="rail" aria-label="Report sections"><div class="logo">V</div>'
            + "".join(f'<a class="ri" href="{h}" aria-label="{n}">{_svg(i)}<em>{n}</em></a>'
                      for h, i, n in (("#overview", "grid", "Overview"), ("#cases", "list", "Results"), ("#notes", "book", "Notes & limits")))
            + "</nav>")
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">",
        f"<title>Verdict · {_e(title)}</title><script>{_THEME_BOOT}</script><style>{_CSS}{_EXTRA_CSS}</style></head><body><div class=\"app\">{rail}",
        f'<div><header class="top"><div class="t"><small>Held-out evaluation</small><h1>{_e(title)}</h1></div>'
        '<button class="theme" id="theme" aria-label="Toggle dark / light mode" title="Dark / light mode">' + _SUN_MOON + "</button></header><main>",
        f'<section id="overview"><div class="banner clear{" has-gauge" if gauge else ""}"><div><h2>{_e(headline)}</h2><p>{_e(intro)}</p></div>'
        f'{_gauge(*gauge) if gauge else ""}</div>',
    ]
    if cards and not any(p[1] for p in donut):  # the donut legend already lists every outcome count; cards only fill in when there is no donut
        parts.append('<div class="kpis">' + "".join(f"<div class=\"kpi\"><strong>{_e(v)}</strong><span>{_e(l)}</span></div>" for v, l in cards) + "</div>")
    parts += [f'<div class="note">{_e(n)}</div>' for n in notes]
    side = f'<div class="card"><h3>Outcomes</h3>{_donut(donut, donut_unit)}</div>' if any(p[1] for p in donut) else ""
    prov = ('<div class="card"><h3>Scan provenance</h3><dl class="prov">'
            + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in provenance) + "</dl></div>") if provenance else ""
    if side or prov:
        parts.append(f'<div class="g2">{side}{prov}</div>')
    parts.append("</section>")
    parts.append(f'<h2 class="sec" id="cases">{_e(table_title)} <small id="cnt"></small></h2><div class="tools">'
                 '<input id="q" type="search" placeholder="Search case, category, location…" aria-label="Search results">'
                 '<button data-k="all" aria-pressed="true">All</button>'
                 + "".join(f'<button data-k="action" data-v="{_e(s)}" aria-pressed="false">{_e(_label(s))}</button>' for s in statuses) + "</div>")
    head = "".join(f"<th>{_e(c)}</th>" for c in (*columns, outcome_header))
    body = "".join(
        f'<tr data-f data-open="c{i}" tabindex="0" data-action="{_e(row["status"])}"><td><code>{_e(row["id"])}</code></td>'
        + "".join(_cell(c) for c in row["cells"]) + f'<td>{_chip(row["status"])}</td></tr>' for i, row in enumerate(rows))
    parts.append(f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')
    parts.append('<h2 class="sec" id="notes">Notes &amp; limits</h2>' + "".join(_section(h, items) for h, items in sections))
    parts.append('<footer>Static report · no external requests</footer></main></div></div>'
                 '<div class="scrim" id="scrim"></div><aside class="dr" id="dr" aria-hidden="true"></aside>'
                 f'<div hidden>{"".join(_pane(i, row) for i, row in enumerate(rows))}</div><script>{_JS}</script></body></html>')
    return "".join(parts)

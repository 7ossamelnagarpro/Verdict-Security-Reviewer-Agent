<<<<<<< HEAD
"""Human-readable final report rendering."""
=======
"""Markdown renderer for the final security report (see ``view.py`` for the data model).

Reading order follows what an application-security lead needs: verdict, scorecard, what to fix first, the
evidence behind each finding, how far the scan can be trusted, and only then the appendix.
"""
>>>>>>> e8f1f4e (Add agent graphs and benchmark evaluation)

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

<<<<<<< HEAD
=======
from security_reviewer_v2.policy.rules import RULES

from .view import ACTION_ICON, SEVERITY_ICON, Finding, ReportView, build_view, first_sentence, lead

_DASH = "\u2014"        # constants: Python 3.11 forbids backslashes inside f-string expressions
_DOT = " \u00b7 "
_OK, _FAIL, _NA = "\u2705", "\u274C", "\u2796"
_DECISION_ICON = {"blocked": "\u26D4", "incomplete": "\u23F3", "clear": "\u2705", "no_findings": "\u2754"}

>>>>>>> e8f1f4e (Add agent graphs and benchmark evaluation)

def _plain(value: Any) -> str:
    """Keep scanner-controlled labels from becoming Markdown or HTML."""
    escaped = html.escape(" ".join(str(value).split()), quote=False)
    return re.sub(r"([\\`*_{}\[\]#+!|>~])", r"\\\1", escaped)


def _code(value: Any) -> str:
<<<<<<< HEAD
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
=======
    """Display untrusted identifiers literally, including embedded backticks and table pipes."""
    return f"<code>{html.escape(' '.join(str(value).split())).replace('|', '&#124;')}</code>"


def _ticks(value: Any) -> str:
    text = " ".join(str(value).split())
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _md_text(value: Any) -> str:
    """Model prose: HTML-escaped and links disabled, but inline `code` and emphasis stay readable."""
    return html.escape(str(value).strip(), quote=False).replace("[", "\\[").replace("]", "\\]")


def _bar(count: int, total: int, width: int = 24) -> str:
    filled = round(width * count / total) if total else 0
    return "\u2588" * max(filled, 1 if count else 0) + "\u2591" * (width - max(filled, 1 if count else 0))


def _label(value: str) -> str:
    return value.replace("_", " ")


def render_markdown(view: ReportView) -> str:
    out: list[str] = [
        "# \U0001F6E1\uFE0F Security Review Report", "",
        f"> {_DECISION_ICON[view.decision]} **{_plain(view.headline)}**"]
    for sentence in view.bottom_line:
        out += [">", f"> {_plain(sentence)}"]
    meta = [f"Project {_code(view.project)}", f"generated {_plain(view.generated)}",
            f"policy {_code(view.policy_status)}", f"review {_code(view.review_status)}"]
    if view.rule_set:
        meta.append(f"rules {_code(view.rule_set)}")
    out += ["", " \u00b7 ".join(meta), ""]
    out += _status_notes(view)

    # -- scorecard
    c = view.counts
    cov = f"{view.coverage_done} / {view.coverage_total}" if view.has_execution and view.coverage_total else "n/a"
    dedup = f"{view.dedup[0]} \u2192 {view.dedup[1]}" if view.dedup else "n/a"
    out += ["## Scorecard", "",
            "| Issues reviewed | \u26D4 Blocking | \u26A0\uFE0F Manual review | \u2705 Cleared | Scanners completed | Duplicates merged | DAST |",
            "|:-:|:-:|:-:|:-:|:-:|:-:|:-:|",
            f"| **{c['reviewed']}** | **{c['block']}** | **{c['warn']}** | **{c['allow']}** | **{cov}** | {dedup} | "
            f"{'performed' if view.dynamic else 'not run'} |"]
    if view.severity_counts:
        width = max(len(s) for s, _ in view.severity_counts)
        out += ["", "```"]
        out += [f"{s.capitalize():<{width}}  {_bar(n, c['reviewed'])}  {n}" for s, n in view.severity_counts]
        out += ["```"]
    out.append("")

    # -- fix first
    out += ["## \U0001F3AF Fix first", ""]
    if view.blocking:
        for n, f in enumerate(view.blocking, 1):
            out.append(f"{n}. {SEVERITY_ICON.get(f.severity, '')} **{_plain(f.title)}** \u2014 "
                       + (f"{_code(f.location)} \u00b7 " if f.location else "")
                       + f"{_plain(f.severity)} \u00b7 {_plain(f.rule_id or 'rule n/a')}"
                       + (f" \u00b7 {f.corroboration} tools agree" if f.corroboration > 1 else "")
                       + (f"  \n   *Fix:* {_md_text(first_sentence(f.remediation))}" if f.remediation else ""))
        out.append("")
    else:
        out += ["Nothing met the automatic blocking criteria. This is not a security clearance.", ""]
    if view.next_steps:
        out += ["**Then:**", ""] + [f"{n}. {_plain(s)}" for n, s in enumerate(view.next_steps, 1)] + [""]

    # -- findings
    shown = [f for f in view.findings if f.action != "allow"]
    cleared = [f for f in view.findings if f.action == "allow"]
    if view.findings:
        out += ["## Findings overview", "",
                "| # | | Finding | Location | Verdict | Tools | Decision |", "|--:|---|---|---|---|--:|---|"]
        for f in view.findings:
            out.append(f"| {f.number} | {SEVERITY_ICON.get(f.severity, '')} | {_plain(f.title)} | "
                       f"{_code(f.location) if f.location else _DASH} | {_plain(_label(f.verdict))} | {f.corroboration or _DASH} | "
                       f"{ACTION_ICON.get(f.action, '')} {_plain(f.action)}{f' ({_plain(f.rule_id)})' if f.rule_id else ''} |")
        out += ["", "## Findings in detail", "",
                "Security Review Agent verdicts, most urgent first. Raw scanner observations are in Appendix B.", ""]
    for f in shown:
        out += _card(f)
    if cleared:
        out += ["<details><summary>Cleared as false positive (" + str(len(cleared)) + ")</summary>", ""]
        out += [f"- **{_plain(f.title)}**" + (f" \u2014 {_code(f.location)}" if f.location else "")
                + (f" \u2014 {_plain(f.reason)}" if f.reason else "") for f in cleared]
        out += ["", "</details>", ""]
    if not view.findings:
        out += ["## Findings", "", "No agent verdicts were produced. "
                f"**{len(view.observations)}** scanner/DAST observation record(s) are listed in the appendix for "
                "investigation. The observations have not been cleared or confirmed by the agent, and this does not "
                "mean the project is secure.", ""]

    # -- coverage & trust
    out += ["## \U0001F9ED Coverage & trust", ""]
    if view.scanners:
        out += ["| Scanner | Result | What it means |", "|---|---|---|"]
        for r in view.scanners:
            note = "<br>".join(_plain(n) for n in r.notes)
            out.append(f"| **{_plain(r.role)}**<br>{_code(r.scanner)} | {_OK if r.status == 'completed' else _NA if r.status == 'not_scheduled' else _FAIL} {_plain(r.outcome)} "
                       f"({_code(r.status)}) | {_plain(r.meaning)}" + (f"<br>{note}" if note else "") + " |")
        out += ["", f"{view.coverage_done} of {view.coverage_total} applicable scanner task(s) completed."
                + (f" {view.skipped_tasks} skipped as not applicable." if view.skipped_tasks else "")
                + (f" Registered but not scheduled (nothing to scan): {', '.join(view.not_scheduled)}." if view.not_scheduled else ""), ""]
    elif view.has_execution:
        out += ["No scanner tasks were recorded.", ""]
    if view.dedup:
        out += [f"**Deduplication.** {view.dedup[0]} raw scanner results \u2192 {view.dedup[1]} root-cause records "
                f"({view.dedup[2]} duplicates merged: same vulnerability family, file and overlapping lines). "
                "Nothing is discarded; every raw result and rule id stays attached to its record.", ""]
    if view.gaps:
        out += ["**Known gaps** (each lowers confidence in a clean result for that area):", ""]
        out += [f"- {_plain(g)}" for g in view.gaps] + [""]
    if view.runtime_lines:
        out += list(view.runtime_lines) + [""]

    # -- appendix
    out += ["## Appendix", "", "### A. Release-gate decisions", ""]
    if view.policy_rows:
        out += ["Each decision comes from one named rule applied to the AI verdict **and** deterministic evidence "
                "(scanner findings, source verification); the AI description alone never blocks a release.", "",
                "| Action | Rule | Finding | Severity | Evidence basis |", "|---|---|---|---|---|"]
        for d in view.policy_rows:
            out.append(f"| {ACTION_ICON.get(str(d.get('action')), '')} **{_plain(d.get('action'))}** | {_code(d.get('rule_id') or _DASH)} | "
                       f"{_plain(d.get('title'))} | {_plain(d.get('severity', _DASH))} | "
                       f"{_plain(_label(str(d.get('evidence_basis') or _DASH)))} |")
        used = sorted({str(d.get("rule_id")) for d in view.policy_rows if d.get("rule_id") in RULES})
        out += ["", "**Rules used:**", ""] + [f"- {_code(r)} \u2014 {_plain(RULES[r].title)}" for r in used] + [""]
    else:
        out += ["No policy decisions were recorded.", ""]
    out += _appendix_observations(view)
    out += _appendix_triage(view)
    out += ["### D. Method and limitations", ""]
    out += [f"- {_plain(s)}" for s in view.limitations] + [""]
    return "\n".join(out)


def _status_notes(view: ReportView) -> list[str]:
    notes: list[str] = []
    req = view.scanner_requirement
    if req and req.get("requested"):
        status = "complete" if req.get("satisfied") else "incomplete"
        notes.append(f"- Required scanners: **{status}** ({', '.join(_code(i) for i in req.get('required', []))}).")
        if status == "incomplete":
            notes.append("- **This scan is incomplete.** One or more required scanners did not complete with normalized output.")
            notes += [f"- Required scanner failure: {_plain(i)}" for i in req.get("failures", [])]
    ai = view.ai
    if ai is not None:
        ok = ai["required_ok"]
        stage = ("completed required stage" if ok is True else "incomplete required stage" if ok is False
                 else "not verified in this saved run")
        notes.append(f"- AI Discovery: **{stage}**; stage status: {_code(ai['status'])}; provider: {_code(ai['provider'])}; "
                     f"model: {_code(ai['model'])}; targets inspected: **{ai['targets']}/{ai['planned']}**; "
                     f"model calls: **{ai['calls']}**.")
        if ok is False:
            notes.append("- **This scan is incomplete.** Scanner and DAST observations remain available, "
                         "but the required AI Discovery did not finish.")
        notes += [f"- AI Discovery warning: {_plain(w)}" for w in ai["warnings"]]
    if view.expected_groups is not None:
        notes.append(f"- Issue groups expected: **{view.expected_groups}**; reviewed: **{view.counts['reviewed']}**; "
                     f"pending: **{len(view.pending_ids)}**.")
    return notes + [""] if notes else []


def _card(f: Finding) -> list[str]:
    tags = [f"{SEVERITY_ICON.get(f.severity, '')} **{_plain(f.severity)}**", _plain(_label(f.verdict)),
            f"{_plain(f.confidence)} confidence",
            f"{ACTION_ICON.get(f.action, '')} **{_plain(f.action)}**" + (f" ({_plain(f.rule_id)})" if f.rule_id else "")]
    if f.location:
        tags.append(_code(f.location))
    out = [f"### {SEVERITY_ICON.get(f.severity, '')} {f.number}. {_plain(f.title)}", "", " \u00b7 ".join(tags)]
    refs = [*(_plain(c) for c in f.cwes), *(_plain("OWASP " + o) for o in f.owasp)]
    if refs or f.corroboration:
        out += ["", " \u00b7 ".join(refs) + (f"{_DOT if refs else ''}detected by **{f.corroboration}** tool(s)" if f.corroboration else "")]
    full: list[tuple[str, str]] = []
    for label, text, sentences, limit in (("Problem", f.explanation, 2, 360), ("Impact", f.impact, 1, 220),
                                          ("Fix", f.remediation, 2, 360)):
        if text:
            short, cut = lead(text, sentences, limit)
            out += ["", f"**{label}.** {_md_text(short)}"]
            if cut:
                full.append((label, text))
    out += ["", "<details><summary>Evidence, detection and decision</summary>", ""]
    for label, text in full:
        out += [f"**Full {label.lower()}**", "", _md_text(text), ""]
    if f.detected_by:
        out += ["**Detected by**", ""] + [f"- {_plain(d)}" for d in f.detected_by] + [""]
    if f.evidence:
        out += ["**Evidence**", ""] + [f"- {_ticks(e)}" for e in f.evidence] + [""]
    if f.reason:
        out += ["**Why this decision**", "", f"- {_plain(f.reason)}"] + [f"- {_plain(e)}" for e in f.policy_evidence] + [""]
    if f.limitations:
        out += ["**Limitations**", ""] + [f"- {_plain(e)}" for e in f.limitations] + [""]
    out += [f"Issue group {_ticks(f.group_id)}", "", "</details>", ""]
    return out


def _appendix_observations(view: ReportView) -> list[str]:
    out = ["### B. Scanner and DAST Observations (Pre-Review)", ""]
    if not view.observations:
        return out + ["No scanner or DAST observations were recorded; check coverage before concluding safety.", ""]
    dast = sum(o.origin.startswith("DAST") for o in view.observations)
    out += [f"**{len(view.observations)}** merged observation record(s): **{dast}** DAST-related and "
            f"**{len(view.observations) - dast}** other scanner record(s). These are signals to assess, not confirmed "
            "independent vulnerabilities. Risk disposition describes routing, not an agent verdict.", "",
            "<details><summary>Show all observations</summary>", "",
            "| # | Observation | Origin | Evidence | Location | Severity | Confidence | Risk | Disposition |",
            "|--:|---|---|--:|---|---|---|---|---|"]
    details: list[str] = []
    for o in view.observations:
        out.append(f"| {o.number} | **{_plain(o.title)}** | {_plain(o.origin)} | {o.evidence_count} | {_code(o.location)} | "
                   f"{_plain(o.severity)} | {_plain(o.confidence)} | {_plain(o.risk)} | {_code(o.disposition)} |")
        details.append(f"{o.number}. Record {_code(o.record_id)}; rule(s): {_code(', '.join(o.rule_ids) or 'unknown')}; "
                       "source evidence: " + (", ".join(_code(i) for i in o.source_ids) if o.source_ids else "not recorded") + ".")
        details += [f"    - Bounded runtime evidence: {_code(fact)}." for fact in o.runtime_facts]
    return out + ["", "Identifiers:", ""] + details + ["", "</details>", ""]


def _appendix_triage(view: ReportView) -> list[str]:
    out = ["### C. Candidate triage and unresolved evidence", ""]
    s = view.triage
    if s is None:
        return out + ["Triage was not part of this run.", ""]
    out += [f"Scanner/DAST observation records: **{s.get('input_scanner_findings', 0)}**; issue groups after conservative "
            f"correlation: **{s.get('review_groups', 0)}**. Every original observation stays linked by source ID.",
            f"AI candidates: **{s.get('input_ai_candidates', 0)}**; scanner overlaps: **{s.get('scanner_overlap', 0)}**; "
            f"AI overlaps: **{s.get('candidate_overlap', 0)}**; new candidates: **{s.get('novel_candidates', 0)}**; "
            f"uncertain overlaps: **{s.get('uncertain_overlap', 0)}**; needs more evidence: **{s.get('needs_more_evidence', 0)}**; "
            f"rejected: **{s.get('rejected', 0)}**."]
    if view.unresolved:
        out += ["", "These AI candidates are not confirmed vulnerabilities and were not silently discarded:", ""]
        out += [f"- {_ticks(cid)}: {_plain(disp)}" + (f" at {_ticks(where)}" if where else "") for cid, disp, where in view.unresolved]
    if view.verification_status not in (None, "completed"):
        out += ["", f"Verification status: **{_plain(view.verification_status)}**; see `verification.json` for source-evidence checks."]
    if view.pending_ids:
        out += ["", "**Pending security reviews**", ""] + [f"- {_ticks(p)}" for p in view.pending_ids]
    return out + [""]
>>>>>>> e8f1f4e (Add agent graphs and benchmark evaluation)


def render_final_report(*, project: str, review: dict[str, Any], policy: dict[str, Any],
                        triage: dict[str, Any] | None = None, verification: dict[str, Any] | None = None,
<<<<<<< HEAD
                        discovery: dict[str, Any] | None = None,
                        discovery_required_satisfied: bool | None = None,
                        docker_runtime: dict[str, Any] | None = None,
                        runtime_evidence: dict[str, Any] | None = None,
                        merged: dict[str, Any] | None = None,
                        risk: dict[str, Any] | None = None,
                        execution: dict[str, Any] | None = None,
                        scanner_requirement: dict[str, Any] | None = None,
                        coverage_gaps: list[str] | tuple[str, ...] | None = None) -> str:
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
                       coverage_gaps: list[str] | tuple[str, ...] | None = None) -> None:
    from .html import render_html_report

    path = Path(path)
    options = dict(project=project, review=review, policy=policy,
                                              triage=triage, verification=verification,
                                              discovery=discovery, discovery_required_satisfied=discovery_required_satisfied,
                                              docker_runtime=docker_runtime,
                                              runtime_evidence=runtime_evidence,
                                              merged=merged, risk=risk, execution=execution,
                                              scanner_requirement=scanner_requirement,
                                              coverage_gaps=coverage_gaps)
    path.write_text(render_final_report(**options), encoding="utf-8")
    path.with_suffix(".html").write_text(render_html_report(**options), encoding="utf-8")
=======
                        discovery: dict[str, Any] | None = None, discovery_required_satisfied: bool | None = None,
                        isolated_pilot: dict[str, Any] | None = None, isolated_runtime: dict[str, Any] | None = None,
                        docker_runtime: dict[str, Any] | None = None, runtime_evidence: dict[str, Any] | None = None,
                        merged: dict[str, Any] | None = None, risk: dict[str, Any] | None = None,
                        execution: dict[str, Any] | None = None, scanner_requirement: dict[str, Any] | None = None,
                        coverage_gaps: list[str] | tuple[str, ...] | None = None,
                        adapter_ids: list[str] | tuple[str, ...] | None = None) -> str:
    return render_markdown(build_view(
        project=project, review=review, policy=policy, triage=triage, verification=verification, discovery=discovery,
        discovery_required_satisfied=discovery_required_satisfied, isolated_pilot=isolated_pilot,
        isolated_runtime=isolated_runtime, docker_runtime=docker_runtime, runtime_evidence=runtime_evidence,
        merged=merged, risk=risk, execution=execution, scanner_requirement=scanner_requirement,
        coverage_gaps=coverage_gaps, adapter_ids=adapter_ids))


def write_final_report(path: str | Path, **kwargs: Any) -> Path:
    """Write ``<name>.md`` and a self-contained ``<name>.html`` next to it; returns the Markdown path."""
    from .html_report import render_html  # local import keeps the Markdown path dependency-free

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    view = build_view(**kwargs)
    target.write_text(render_markdown(view), encoding="utf-8")
    target.with_suffix(".html").write_text(render_html(view), encoding="utf-8")
    return target
>>>>>>> e8f1f4e (Add agent graphs and benchmark evaluation)

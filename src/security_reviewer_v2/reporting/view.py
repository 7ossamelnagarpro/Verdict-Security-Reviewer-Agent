"""Report view model: every number, label and sentence a renderer needs, computed once.

``build_view`` turns the pipeline artifacts into a :class:`ReportView`.  The Markdown and HTML renderers only
format it, so both outputs always agree.  Nothing here changes a verdict, severity, confidence, policy action
or scanner status: it orders, labels and explains existing data.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ACTION_ORDER = {"block": 0, "warn": 1, "allow": 2}
VERDICT_ORDER = {"confirmed_vulnerability": 0, "likely_vulnerability": 1, "likely_vulnerable": 1,
                 "needs_more_evidence": 2, "false_positive": 3}
SEVERITY_ICON = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U0001F535", "info": "\u26AA"}
ACTION_ICON = {"block": "\u26D4", "warn": "\u26A0\uFE0F", "allow": "\u2705"}

SCANNER_ROLES = {
    "semgrep-ce": "Semgrep CE \u00b7 SAST patterns",
    "codeql-cli": "CodeQL \u00b7 SAST data-flow",
    "gitleaks": "Gitleaks \u00b7 secrets",
    "trivy": "Trivy \u00b7 dependencies & config",
}
STATUS_MEANING = {
    "completed": "Results are included in this report.",
    "failed": "Produced no results \u2014 this area is not covered.",
    "timed_out": "Timed out \u2014 results are missing or incomplete.",
    "skipped": "Not applicable to this project.",
    "prerequisite_unverified": "Did not run: a prerequisite could not be verified.",
    "prerequisite_missing": "Did not run: a prerequisite is missing.",
    "adapter_unavailable": "Did not run: the scanner is not installed or not configured.",
    "not_scheduled": "Nothing applicable was found to scan, so this scanner did not run.",
}
# OWASP Top 10 (2021) category for well-known CWEs; unlisted CWEs are simply not tagged.
OWASP_BY_CWE = {
    "79": "A03 Injection", "80": "A03 Injection", "89": "A03 Injection", "564": "A03 Injection",
    "78": "A03 Injection", "77": "A03 Injection", "94": "A03 Injection", "917": "A03 Injection",
    "22": "A01 Broken Access Control", "23": "A01 Broken Access Control", "352": "A01 Broken Access Control",
    "200": "A01 Broken Access Control", "639": "A01 Broken Access Control",
    "614": "A05 Security Misconfiguration", "1004": "A05 Security Misconfiguration",
    "798": "A07 Identification & Authentication Failures", "259": "A07 Identification & Authentication Failures",
    "502": "A08 Software & Data Integrity Failures", "918": "A10 Server-Side Request Forgery",
}
_ACRONYMS = {"sql": "SQL", "xss": "XSS", "html": "HTML", "db": "DB", "os": "OS", "csrf": "CSRF", "ssrf": "SSRF",
             "url": "URL", "http": "HTTP", "https": "HTTPS", "json": "JSON", "xml": "XML", "api": "API", "jwt": "JWT",
             "tls": "TLS", "ssl": "SSL", "rce": "RCE", "idor": "IDOR", "xxe": "XXE", "ldap": "LDAP"}
_SLUG_TITLE = re.compile(r"^[A-Z][A-Za-z0-9]*(?: [A-Z][A-Za-z0-9]*)+$")


def pretty_title(title: str) -> str:
    """Restore acronym casing in titles generated from rule slugs ("Sql Injection Db" -> "SQL Injection DB")."""
    if not _SLUG_TITLE.match(title):
        return title
    return " ".join(_ACRONYMS.get(word.lower(), word) for word in title.split(" "))


def rank(mapping: dict[str, int], value: Any) -> int:
    return mapping.get(str(value).lower(), len(mapping))


_LIST_MARKER = re.compile(r"^(?:[*\-\u2022]|\d+[.)])\s+")


def lead(text: str, sentences: int = 1, limit: int = 170) -> tuple[str, bool]:
    """First ``sentences`` sentences of model prose (list markers dropped), capped at ``limit`` characters.

    Returns ``(short_text, was_shortened)`` so a renderer can keep the full text one click away.
    """
    compact = _LIST_MARKER.sub("", " ".join(str(text or "").split()))
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9`*])", compact)
    short = " ".join(parts[:sentences])
    shortened = len(parts) > sentences
    if len(short) > limit:
        short, shortened = short[:limit - 1].rstrip(), True
        if short.count("`") % 2:  # never cut inside an inline-code span (would leave a stray backtick)
            short = short[:short.rfind("`")].rstrip()
        short += "\u2026"
    return short, shortened


def first_sentence(text: str, limit: int = 170) -> str:
    return lead(text, 1, limit)[0]


def location_label(location: dict[str, Any] | None) -> str:
    location = location or {}
    path = str(location.get("path") or "")
    start, end = location.get("start_line"), location.get("end_line")
    if not path:
        return ""
    if isinstance(start, int) and start > 0:
        return f"{path}:{start}-{end}" if isinstance(end, int) and end > start else f"{path}:{start}"
    return path


def owasp_for(cwes: tuple[str, ...]) -> tuple[str, ...]:
    seen: list[str] = []
    for cwe in cwes:
        match = re.search(r"(\d+)", str(cwe))
        label = OWASP_BY_CWE.get(str(int(match.group(1)))) if match else None
        if label and label not in seen:
            seen.append(label)
    return tuple(seen)


# ----------------------------------------------------------------------------- view dataclasses
@dataclass(frozen=True)
class Finding:
    number: int
    group_id: str
    title: str
    severity: str
    verdict: str
    confidence: str
    action: str
    rule_id: str
    location: str
    cwes: tuple[str, ...]
    owasp: tuple[str, ...]
    detected_by: tuple[str, ...]
    corroboration: int
    explanation: str
    impact: str
    remediation: str
    evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    source_ids: tuple[str, ...]
    reason: str
    evidence_basis: str
    policy_evidence: tuple[str, ...]


@dataclass(frozen=True)
class ScannerRow:
    scanner: str
    role: str
    status: str
    outcome: str
    meaning: str
    notes: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    number: int
    title: str
    origin: str
    location: str
    severity: str
    confidence: str
    risk: str
    disposition: str
    record_id: str
    rule_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    evidence_count: int
    runtime_facts: tuple[str, ...]


@dataclass(frozen=True)
class ReportView:
    project: str
    generated: str
    decision: str                      # blocked | incomplete | clear | no_findings
    headline: str
    bottom_line: tuple[str, ...]
    policy_status: str
    review_status: str
    rule_set: str
    findings: tuple[Finding, ...]
    blocking: tuple[Finding, ...]
    counts: dict[str, int]
    severity_counts: tuple[tuple[str, int], ...]
    coverage_done: int
    coverage_total: int
    coverage_missing: tuple[str, ...]
    has_execution: bool
    scanners: tuple[ScannerRow, ...]
    dedup: tuple[int, int, int] | None
    ai: dict[str, Any] | None
    dynamic: bool
    gaps: tuple[str, ...]
    observations: tuple[Observation, ...]
    policy_rows: tuple[dict[str, Any], ...]
    triage: dict[str, Any] | None
    unresolved: tuple[tuple[str, str, str], ...]
    pending_ids: tuple[str, ...]
    verification_status: str | None
    next_steps: tuple[str, ...]
    scanner_requirement: dict[str, Any] | None
    runtime_lines: tuple[str, ...]
    expected_groups: int | None
    skipped_tasks: int = 0
    not_scheduled: tuple[str, ...] = ()
    limitations: tuple[str, ...] = field(default=())


# ----------------------------------------------------------------------------- evidence index
class _Evidence:
    """Resolve, for one reviewed issue group, its location, CWEs and the tools that detected it."""

    def __init__(self, review: dict[str, Any], policy: dict[str, Any], merged: dict[str, Any] | None,
                 triage: dict[str, Any] | None, verification: dict[str, Any] | None,
                 discovery: dict[str, Any] | None) -> None:
        self.decisions = {str(d.get("candidate_id")): d for d in policy.get("decisions", []) if isinstance(d, dict)}
        self.merged = {str(f.get("merged_finding_id")): f for f in (merged or {}).get("findings", [])
                       if isinstance(f, dict)}
        self.groups = {str(g.get("group_id")): g for g in (triage or {}).get("groups", []) if isinstance(g, dict)}
        self.verification = {str(r.get("candidate_id")): r for r in (verification or {}).get("records", [])
                             if isinstance(r, dict)}
        self.records = {str(r.get("candidate_id")): r for r in (triage or {}).get("records", []) if isinstance(r, dict)}
        self.ai_candidates = {str(c.get("candidate_id")): c for c in (discovery or {}).get("candidates", [])
                              if isinstance(c, dict)}

    def _members(self, group_id: str) -> tuple[list[str], list[str]]:
        group = self.groups.get(group_id) or {}
        scanner_ids = list(group.get("scanner_finding_ids") or ([group_id] if group_id in self.merged else []))
        ai_ids = list(group.get("candidate_ids") or ([group_id] if group_id in self.ai_candidates else []))
        return scanner_ids, ai_ids

    def location(self, group_id: str, review_item: dict[str, Any]) -> str:
        scanner_ids, ai_ids = self._members(group_id)
        for identifier in scanner_ids:
            label = location_label((self.merged.get(identifier) or {}).get("primary_location"))
            if label:
                return label
        for identifier in ai_ids:
            record = self.verification.get(identifier) or self.records.get(identifier) or {}
            if record.get("path"):
                line = record.get("start_line")
                return f"{record['path']}:{line}" if isinstance(line, int) and line > 0 else str(record["path"])
        for text in review_item.get("evidence", []) or []:
            match = re.match(r"^\s*([\w./\\-]+\.\w+):(\d+)", str(text))
            if match:
                return f"{match.group(1)}:{match.group(2)}"
        return ""

    def cwes(self, group_id: str) -> tuple[str, ...]:
        found: list[str] = []
        for identifier in self._members(group_id)[0]:
            for cwe in (self.merged.get(identifier) or {}).get("cwes", []):
                if cwe not in found:
                    found.append(str(cwe))
        return tuple(found)

    def detected_by(self, group_id: str) -> tuple[tuple[str, ...], int]:
        scanner_ids, ai_ids = self._members(group_id)
        lines: list[str] = []
        tools: set[str] = set()
        for identifier in scanner_ids:
            finding = self.merged.get(identifier) or {}
            names = [str(s) for s in finding.get("scanners", [])]
            tools.update(names)
            rules = ", ".join(sorted({str(r).split(".")[-1] for r in finding.get("rule_ids", [])}))
            lines.append(f"{' + '.join(names) or 'scanner'}: {rules or 'rule not recorded'}")
        for identifier in ai_ids:
            verified = (self.verification.get(identifier) or {}).get("disposition") == "confirmed"
            lines.append("AI discovery" + (" (source verified)" if verified else " (unverified)"))
            tools.add("ai-discovery")
        return tuple(lines), len(tools)


def _runtime_lines(isolated_pilot: dict[str, Any] | None, isolated_runtime: dict[str, Any] | None,
                   docker_runtime: dict[str, Any] | None, runtime_evidence: dict[str, Any] | None) -> list[str]:
    lines: list[str] = []
    if isolated_pilot is not None:
        lines += ["", "## Isolated VM Pilot Evidence", "",
                  f"- Completed run: `{isolated_pilot['run_id']}`",
                  f"- Local application health: **HTTP {isolated_pilot['http_status']}**",
                  "- The disposable worker was removed; the base checkpoint and disk hashes were unchanged according to its lifecycle record.",
                  "- This is a historical startup smoke test, not a vulnerability scan or a live DAST endpoint.",
                  f"- Guest report: `{isolated_pilot['guest_report_path']}`",
                  f"- Lifecycle record: `{isolated_pilot['lifecycle_path']}`"]
    if isolated_runtime is not None:
        counts = isolated_runtime["probe_counts"]
        lines += ["", "## Automatic Isolated DAST", "",
                  f"- Completed VM run: `{isolated_runtime['run_id']}`",
                  f"- Health: **HTTP {isolated_runtime['http_status']}**; "
                  f"web probes: **{counts['runtime.json']}**; "
                  f"authorization probes: **{counts['authorization.json']}**.",
                  f"- Mutating probes: **{'enabled' if isolated_runtime['mutating_checks_enabled'] else 'disabled'}**.",
                  "- The guest had no virtual switch; its loopback probe results were imported after the disposable worker was removed.",
                  "- Probe findings are evidence to review, not proof that every endpoint or vulnerability was covered.",
                  f"- Guest report: `{isolated_runtime['guest_report_path']}`",
                  f"- Lifecycle record: `{isolated_runtime['lifecycle_path']}`"]
    if docker_runtime is not None:
        counts = docker_runtime["probe_counts"]
        lines += ["", "## Trusted Docker DAST", "",
                  f"- Completed Docker run: `{docker_runtime['run_id']}`",
                  f"- Health: **HTTP {docker_runtime['http_status']}**; "
                  f"web probes: **{counts['runtime.json']}**; "
                  f"authorization probes: **{counts['authorization.json']}**.",
                  f"- Mutating probes: **{'enabled' if docker_runtime['mutating_checks_enabled'] else 'disabled'}**.",
                  "- The application was published on host loopback; its temporary Compose stack was removed before static and AI review.",
                  "- Docker does not provide the disposable VM's no-switch network or base-disk integrity guarantees.",
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
                  "- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.",
                  ]
        browser, zap, flows = (runtime_evidence.get(k) for k in ("browser", "zap", "workflow_evidence"))
        lines.append(f"- Browser crawl: **{browser.get('status', 'unknown')}**; pages visited: **{browser.get('pages_visited', 0)}**."
                     if isinstance(browser, dict) else "- Browser crawl: **not requested**.")
        lines.append(f"- ZAP: **{zap.get('status', 'unknown')}**; engine: `{zap.get('engine', 'unknown')}`; alerts: **{zap.get('alerts', 0)}**."
                     if isinstance(zap, dict) else "- ZAP: **not requested**.")
        if isinstance(flows, dict):
            counts = flows.get("coverage") if isinstance(flows.get("coverage"), dict) else {}
            lines.append(f"- Account and business workflows: **{flows.get('status', 'unknown')}** · "
                         f"{counts.get('executed', 0)} executed · {counts.get('violations', 0)} violations.")
        else:
            lines.append("- Account and business workflows: **not requested**.")
        lines.append("- These observations do not prove complete vulnerability coverage or exploitation.")
    return lines


def _no_task_notes(scanner: str, gaps: tuple[str, ...]) -> tuple[str, ...]:
    """Why a registered scanner has no task: the plan found nothing it can scan."""
    if scanner == "trivy":
        related = next((g for g in gaps if "SCA" in g or "manifest" in g), "")
        return tuple(n for n in ("The scan plan has no Trivy task: no supported dependency manifest or lockfile, "
                                 "Dockerfile or compose file was found.", related) if n)
    return ("The scan plan has no task for this scanner.",)


def _scanner_rows(execution: dict[str, Any] | None, adapter_ids: tuple[str, ...] = (),
                  gaps: tuple[str, ...] = ()) -> tuple[ScannerRow, ...]:
    rows: list[ScannerRow] = []
    for task in (execution or {}).get("tasks", []):
        if not isinstance(task, dict):
            continue
        status = str(task.get("status", "unknown"))
        notes: list[str] = []
        blocked = any(isinstance(c, dict) and c.get("status") not in (None, "available")
                      for c in task.get("prerequisite_checks", []) or [])
        if task.get("reason") and not blocked:
            notes.append(str(task["reason"]))
        for check in task.get("prerequisite_checks", []) or []:
            if not isinstance(check, dict):
                continue
            detail = str(check.get("detail", ""))
            if check.get("status") not in (None, "available"):
                notes.append(f"{check.get('name', 'prerequisite')} is {check.get('status')}: {detail}")
            elif "version check skipped" in detail:
                notes.append(f"Scanner version not verified: {detail}")
        scanner = str(task.get("scanner_id", "unknown"))
        if status == "skipped":
            continue
        role = SCANNER_ROLES.get(scanner, scanner)
        if scanner == "trivy":  # one adapter, several jobs; the DB check says whether this one needs a vulnerability DB
            db = next((c for c in task.get("prerequisite_checks", []) or []
                       if isinstance(c, dict) and c.get("name") == "trivy_databases"), None)
            needs_db = db is not None and "does not require" not in str(db.get("detail", ""))
            role = "Trivy \u00b7 dependencies (SCA)" if needs_db else "Trivy \u00b7 Dockerfile & config"
        outcome = {"completed": "Completed", "failed": "Failed", "timed_out": "Timed out", "skipped": "Skipped"}.get(
            status, "Not run")
        rows.append(ScannerRow(scanner, role, status, outcome,
                               STATUS_MEANING.get(status, "See notes."), tuple(notes)))
    if execution is not None:  # a registered scanner with no task at all must still be visible, not silently absent
        planned = {str(t.get("scanner_id")) for t in execution.get("tasks", []) if isinstance(t, dict)}
        for scanner in adapter_ids:
            if scanner not in planned:
                rows.append(ScannerRow(scanner, SCANNER_ROLES.get(scanner, scanner), "not_scheduled", "Not scheduled",
                                       STATUS_MEANING["not_scheduled"], _no_task_notes(scanner, gaps)))
    order = {"failed": 0, "timed_out": 0, "prerequisite_unverified": 1, "prerequisite_missing": 1,
             "adapter_unavailable": 1, "not_scheduled": 2, "completed": 3, "skipped": 4}
    return tuple(sorted(rows, key=lambda row: (order.get(row.status, 1), row.scanner)))


def _observations(merged: dict[str, Any] | None, risk: dict[str, Any] | None) -> tuple[Observation, ...]:
    findings = [f for f in (merged or {}).get("findings", []) if isinstance(f, dict)]
    priorities = {item.get("merged_finding_id"): item for item in (risk or {}).get("findings", [])
                  if isinstance(item, dict) and isinstance(item.get("merged_finding_id"), str)}

    def order_key(item: dict[str, Any]) -> tuple[int, str]:
        value = priorities.get(item.get("merged_finding_id"), {}).get("rank")
        return (value if type(value) is int else 10**9, str(item.get("merged_finding_id", "")))

    result: list[Observation] = []
    for number, item in enumerate(sorted(findings, key=order_key), 1):
        finding_id = str(item.get("merged_finding_id", "unknown"))
        canonical = item.get("canonical_finding") or {}
        priority = priorities.get(finding_id, {})
        score = priority.get("risk_score")
        sources = [s for s in item.get("source_findings", []) if isinstance(s, dict)]
        facts = tuple(json.dumps(s["runtime_evidence"], sort_keys=True, ensure_ascii=False)
                      for s in sources if isinstance(s.get("runtime_evidence"), dict) and s["runtime_evidence"])
        result.append(Observation(
            number, pretty_title(str(canonical.get("title") or priority.get("title") or "Untitled observation")),
            "DAST" if "dast" in item.get("categories", []) else "scanner",
            location_label(item.get("primary_location")) or "unknown",
            str(item.get("severity", "unknown")), str(item.get("confidence", "unknown")),
            f"{score}/100 ({priority.get('priority_band', 'unknown')})" if isinstance(score, int) else "not ranked",
            str(priority.get("review_disposition", "not_ranked")), finding_id,
            tuple(str(r) for r in item.get("rule_ids", [])),
            tuple(str(s.get("finding_id")) for s in sources if s.get("finding_id")),
            len(sources) or 1, facts))
    scanners_of = {str(item.get("merged_finding_id")): ", ".join(str(s) for s in item.get("scanners", [])) for item in findings}
    return tuple(Observation(**{**o.__dict__, "origin": f"{o.origin} / {scanners_of.get(o.record_id) or 'unknown'}"})
                 for o in result)


def build_view(*, project: str, review: dict[str, Any], policy: dict[str, Any], triage: dict[str, Any] | None = None,
               verification: dict[str, Any] | None = None, discovery: dict[str, Any] | None = None,
               discovery_required_satisfied: bool | None = None, isolated_pilot: dict[str, Any] | None = None,
               isolated_runtime: dict[str, Any] | None = None, docker_runtime: dict[str, Any] | None = None,
               runtime_evidence: dict[str, Any] | None = None, merged: dict[str, Any] | None = None,
               risk: dict[str, Any] | None = None, execution: dict[str, Any] | None = None,
               scanner_requirement: dict[str, Any] | None = None,
               coverage_gaps: list[str] | tuple[str, ...] | None = None,
               adapter_ids: list[str] | tuple[str, ...] | None = None) -> ReportView:
    evidence = _Evidence(review, policy, merged, triage, verification, discovery)
    raw_reviews = [item for item in review.get("reviews", []) if isinstance(item, dict)]

    def action_of(item: dict[str, Any]) -> str:
        return str((evidence.decisions.get(str(item.get("candidate_id"))) or {}).get("action", "not evaluated"))

    raw_reviews.sort(key=lambda item: (rank(ACTION_ORDER, action_of(item)), rank(SEVERITY_ORDER, item.get("severity")),
                                       rank(VERDICT_ORDER, item.get("verdict")), str(item.get("candidate_id", ""))))
    findings: list[Finding] = []
    for number, item in enumerate(raw_reviews, 1):
        gid = str(item.get("candidate_id", "unknown"))
        decision = evidence.decisions.get(gid) or {}
        cwes = evidence.cwes(gid)
        detected, tools = evidence.detected_by(gid)
        merged_title = ((evidence.merged.get(next(iter(evidence._members(gid)[0]), "")) or {})
                        .get("canonical_finding") or {}).get("title")
        findings.append(Finding(
            number, gid, pretty_title(str(item.get("title") or merged_title or gid)),
            str(item.get("severity", "unknown")).lower(), str(item.get("verdict", "unknown")),
            str(item.get("confidence", "unknown")), action_of(item), str(decision.get("rule_id") or ""),
            evidence.location(gid, item), cwes, owasp_for(cwes), detected, tools,
            str(item.get("explanation", "")), str(item.get("impact", "")), str(item.get("remediation", "")),
            tuple(str(e) for e in item.get("evidence", []) or []),
            tuple(str(e) for e in item.get("limitations", []) or []),
            tuple(str(e) for e in item.get("source_ids", []) or []),
            str(decision.get("blocking_reason") or decision.get("reason") or ""),
            str(decision.get("evidence_basis") or ""), tuple(str(e) for e in decision.get("evidence", []) or [])))
    blocking = tuple(f for f in findings if f.action == "block")
    counts = {"reviewed": len(findings), "block": len(blocking),
              "warn": sum(f.action == "warn" for f in findings), "allow": sum(f.action == "allow" for f in findings)}
    severities = sorted({f.severity for f in findings}, key=lambda s: (rank(SEVERITY_ORDER, s), s))
    severity_counts = tuple((s, sum(f.severity == s for f in findings)) for s in severities)

    rows = _scanner_rows(execution, tuple(adapter_ids or ()), tuple(coverage_gaps or ()))
    applicable = [r for r in rows if r.status != "not_scheduled"]
    skipped = sum(1 for t in (execution or {}).get("tasks", []) if isinstance(t, dict) and t.get("status") == "skipped")
    done = sum(r.status == "completed" for r in applicable)
    missing = tuple(f"{r.role} ({r.status.replace('_', ' ')})" for r in applicable if r.status != "completed")

    summary = (merged or {}).get("summary") or {}
    dedup = ((int(summary["input_findings"]), int(summary.get("merged_findings", len((merged or {}).get("findings", [])))),
              int(summary.get("duplicates_collapsed", 0))) if isinstance(summary.get("input_findings"), int) else None)
    ai = None
    if discovery is not None:
        usage = discovery.get("usage") or {}
        ai = {"status": str(discovery.get("status") or "unknown"), "provider": str(discovery.get("provider") or "unknown"),
              "model": str(discovery.get("model") or "unknown"), "targets": usage.get("targets", 0),
              "planned": usage.get("planned_targets", 0), "calls": usage.get("provider_calls", 0),
              "required_ok": discovery_required_satisfied,
              "warnings": tuple(str(w) for w in discovery.get("warnings", []))}
    dynamic = any(v is not None for v in (isolated_pilot, isolated_runtime, docker_runtime, runtime_evidence))

    if policy.get("blocking"):
        decision_key, headline = "blocked", f"Release blocked \u2014 {len(blocking)} finding(s) must be fixed"
    elif not findings:
        decision_key, headline = "no_findings", "No reviewed findings \u2014 no conclusion about safety can be drawn"
    elif policy.get("status") in {"incomplete", "unknown", None}:
        decision_key, headline = "incomplete", "Review incomplete \u2014 no release decision"
    else:
        decision_key, headline = "clear", "No release-blocking findings \u2014 this is not a security clearance"

    bottom: list[str] = []
    if blocking:
        top = blocking[0]
        urgent = sum(f.severity in {"critical", "high"} for f in blocking)
        bottom.append(f"Most urgent: {top.title} ({top.severity}" + (f", {top.location}" if top.location else "") + "). "
                      f"{urgent} of the {len(blocking)} blocking finding(s) are critical or high.")
    elif findings:
        bottom.append(f"{counts['warn']} finding(s) need manual review; none met the automatic blocking criteria.")
    if rows and missing:
        bottom.append(f"Scanner coverage is partial ({done} of {len(applicable)} completed). "
                      "Scanners that did not run say nothing about their area \u2014 missing is not clean.")
    if not dynamic:
        bottom.append("No dynamic testing (DAST) was performed; findings come from static analysis and AI review.")

    steps: list[str] = []
    if blocking:
        steps.append(f"Fix the {len(blocking)} blocking finding(s) under Fix first, then re-run the review.")
    likely = sum("likely" in f.verdict for f in findings)
    if likely:
        steps.append(f"Validate the {likely} \"likely\" finding(s) manually or with a runtime probe; they are not auto-confirmed.")
    if rows and missing:
        steps.append("Restore the scanners that did not complete (see Coverage & trust) and re-run so their coverage counts.")
    if not dynamic:
        steps.append("Add authorised runtime testing (DAST) if the app can run in an isolated environment.")

    policy_rows = tuple(
        {**d, "title": next((f.title for f in findings if f.group_id == str(d.get("candidate_id"))), str(d.get("candidate_id")))}
        for d in sorted((d for d in policy.get("decisions", []) if isinstance(d, dict)),
                        key=lambda d: (rank(ACTION_ORDER, d.get("action")), rank(SEVERITY_ORDER, d.get("severity")),
                                       str(d.get("candidate_id")))))
    triage_summary = (triage or {}).get("summary") if triage is not None else None
    unresolved = tuple((str(r.get("candidate_id")), str(r.get("disposition")), evidence.location(str(r.get("candidate_id")), {}))
                       for r in (triage or {}).get("records", [])
                       if isinstance(r, dict) and r.get("disposition") in {"needs_more_evidence", "uncertain_overlap"})
    limitations = (
        "Scanner and AI silence is not proof that the project is secure; validate before release decisions.",
        "Verdicts are produced by an AI model reading bounded code excerpts; they are not independently validated exploits.",
        "Severities and scores are triage aids, not CVSS ratings.",
    ) + (() if dynamic else ("No runtime/DAST evidence is included, so exploitability is inferred from code.",))
    return ReportView(
        project=project, generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), decision=decision_key,
        headline=headline, bottom_line=tuple(bottom), policy_status=str(policy.get("status", "unknown")),
        review_status=str(review.get("status", "unknown")), rule_set=str(policy.get("rule_set") or ""),
        findings=tuple(findings), blocking=blocking, counts=counts, severity_counts=severity_counts,
        coverage_done=done, coverage_total=len(applicable), coverage_missing=missing, has_execution=execution is not None,
        scanners=rows, dedup=dedup, ai=ai, dynamic=dynamic, gaps=tuple(dict.fromkeys(coverage_gaps or ())),
        observations=_observations(merged, risk) if merged is not None else (), policy_rows=policy_rows,
        triage=triage_summary, unresolved=unresolved, pending_ids=tuple(str(p) for p in review.get("pending_ids", [])),
        verification_status=(verification or {}).get("status") if verification is not None else None,
        next_steps=tuple(steps), scanner_requirement=scanner_requirement,
        runtime_lines=tuple(_runtime_lines(isolated_pilot, isolated_runtime, docker_runtime, runtime_evidence)),
        expected_groups=(review.get("usage") or {}).get("expected_groups"), skipped_tasks=skipped,
        not_scheduled=tuple(r.scanner for r in rows if r.status == "not_scheduled"), limitations=limitations)

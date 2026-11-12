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


# ----------------------------------------------------------------------------- dynamic evidence helpers
# Probe facts that are names/flags/statuses, never target-provided values. They are shown next to the facts the
# normalizer already keeps (`bounded_runtime_evidence`) when the saved probe record is available.
_REPORT_FACT_KEYS = frozenset({"actor", "parameter", "scanner_rule", "cwe_id", "resource", "user_b_status", "safe_mode",
                               "cookie_name", "missing_attributes", "header_present", "x_frame_options_present",
                               "content_security_policy_present", "nosniff_present"})
_REQUEST_ORDER = ("method", "path", "query", "content_type", "body", "repeat")
_PATH_LINE = re.compile(r"^(?P<path>.*?):(?P<a>\d+)(?:-(?P<b>\d+))?$")


def friendly_name(project: str) -> str:
    """A readable report title from the project path: the last folder name, not the machine path."""
    leaf = re.split(r"[\\/]+", str(project or "").strip().rstrip("/\\"))[-1] or "Project"
    words = re.sub(r"[-_.]+", " ", leaf).strip()
    return " ".join(w if w.isupper() else w.capitalize() for w in words.split()) or leaf


def expected_groups_n(review: dict[str, Any], reviewed: int) -> int:
    expected = (review.get("usage") or {}).get("expected_groups")
    return expected if isinstance(expected, int) and expected >= reviewed else reviewed


def dynamic_tool(rule_id: str, scanner: str = "") -> str:
    """Which dynamic component produced a finding, from its rule id (zap.* / workflow.* / web.* / idor.*)."""
    head = (rule_id or "").split(".")[0].lower()
    return {"zap": "zap", "workflow": "workflow", "web": "web-probe", "idor": "idor"}.get(head, scanner or "dynamic")


def split_location(label: str) -> tuple[str, int, int]:
    """``path:12-18`` -> (path, 12, 18); no line -> (path, 0, 0)."""
    match = _PATH_LINE.match(label or "")
    if not match:
        return label or "", 0, 0
    start = int(match.group("a"))
    return match.group("path"), start, int(match.group("b") or start)


def _fact_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_fact_text(v) for v in list(value)[:16] if isinstance(v, (bool, int, float, str, list, tuple))) + "]"
    return " ".join(str(value).split())[:200]


@dataclass(frozen=True)
class DynamicEvidence:
    """One DAST observation behind a finding: what the probe sent and what it recorded."""
    finding_id: str
    scanner: str
    rule_id: str
    title: str
    message: str
    severity: str
    confidence: str
    endpoint: str
    request: tuple[tuple[tuple[str, str], ...], ...]   # request steps, each an ordered list of (field, value)
    request_recorded: bool                              # False: only endpoint/method metadata could be recovered
    output: tuple[tuple[str, str], ...]                 # recorded probe output, in a stable order
    vulnerable: bool | None = None
    scanner_name: str = ""
    trace: tuple[tuple[str, str], ...] = ()             # (step label, result): workflow steps or the request the probe sent
    trace_note: str = ""


@dataclass(frozen=True)
class ProbeRow:
    rule_id: str
    title: str
    endpoint: str
    vulnerable: bool
    severity: str
    request: tuple[tuple[tuple[str, str], ...], ...]
    output: tuple[tuple[str, str], ...]
    source: str = ""
    confidence: str = ""


@dataclass(frozen=True)
class FoundNode:
    """One node of the "Found by" decomposition tree: an origin (Static / Dynamic / AI) or a tool under it."""
    key: str                       # origin key for filtering: static | dynamic | ai ; or tool key for children
    label: str
    count: int
    children: tuple["FoundNode", ...] = ()
    kind: str = "origin"           # origin | tool
    note: str = ""


@dataclass(frozen=True)
class AgentRow:
    name: str
    role: str
    status: str                    # raw status from the saved stage
    state: str                     # ok | warn | bad
    detail: tuple[str, ...]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TestRun:
    group: str                     # Static scanners | Dynamic tests
    label: str
    state: str                     # ok | warn | bad | na
    detail: str


@dataclass(frozen=True)
class WorkflowStep:
    workflow: str
    step: int
    actor: str
    request: str
    result: str
    http: str
    expected: str
    assertions: str


@dataclass(frozen=True)
class ReliabilityCheck:
    label: str
    state: str     # pass | warn | fail | na
    detail: str


def _request_steps(probe: dict[str, Any] | None, source: dict[str, Any], endpoint: str) -> tuple[tuple[tuple[tuple[str, str], ...], ...], bool]:
    """Request steps from the saved probe record; otherwise only what the evidence itself recorded (never invented)."""
    steps: list[tuple[tuple[str, str], ...]] = []
    for raw in (probe or {}).get("request", []) if isinstance((probe or {}).get("request"), list) else []:
        if isinstance(raw, dict):
            ordered = [(k, _fact_text(raw[k])) for k in _REQUEST_ORDER if k in raw]
            ordered += [(str(k), _fact_text(v)) for k, v in raw.items() if k not in _REQUEST_ORDER]
            steps.append(tuple(ordered))
    if steps:
        return tuple(steps), True
    facts = {**(source.get("runtime_evidence") or {}), **((probe or {}).get("evidence") or {})}
    fields = [("method", _fact_text(facts["method"]))] if facts.get("method") else []
    fields.append(("path", endpoint))
    for key in ("parameter", "actor", "workflow_id", "step"):
        if key in facts and key in (_REPORT_FACT_KEYS | {"workflow_id", "step"}):
            fields.append((key, _fact_text(facts[key])))
    return (tuple(fields),), False


def _output_facts(source: dict[str, Any], probe: dict[str, Any] | None) -> tuple[tuple[str, str], ...]:
    facts = dict(source.get("runtime_evidence") or {})
    for key, value in ((probe or {}).get("evidence") or {}).items():
        if key in _REPORT_FACT_KEYS and key not in facts:
            facts[key] = value
    return tuple((str(k), _fact_text(facts[k])) for k in sorted(facts))


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
    origin: str = "unknown"                                  # static | dynamic | both | unknown
    path: str = ""
    start_line: int = 0
    end_line: int = 0
    rule_ids: tuple[str, ...] = ()
    static_sources: tuple[str, ...] = ()
    dynamic_sources: tuple[str, ...] = ()
    dynamic: tuple[DynamicEvidence, ...] = ()
    snippets: tuple[tuple[str, str], ...] = ()               # (location, code) captured by scanners
    origins: tuple[str, ...] = ()                            # any of: static, dynamic, ai (a finding can have several)
    tools: tuple[str, ...] = ()                              # tool keys: scanner ids, zap, workflow, web-probe, ai-discovery


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
    origin_counts: dict[str, int] = field(default_factory=dict)
    cwe_counts: tuple[tuple[str, int], ...] = ()
    file_counts: tuple[tuple[str, int], ...] = ()
    reliability: tuple[ReliabilityCheck, ...] = ()
    reliability_state: str = "unknown"                       # complete | partial | incomplete
    probe_log: tuple[ProbeRow, ...] = ()
    dynamic_facts: tuple[tuple[str, str], ...] = ()
    display_name: str = ""
    found_by: tuple[FoundNode, ...] = ()
    agents: tuple[AgentRow, ...] = ()
    test_runs: tuple[TestRun, ...] = ()
    workflow_steps: tuple[WorkflowStep, ...] = ()
    ai_only_groups: int = 0


# ----------------------------------------------------------------------------- evidence index
class _Evidence:
    """Resolve, for one reviewed issue group, its location, CWEs and the tools that detected it."""

    def __init__(self, review: dict[str, Any], policy: dict[str, Any], merged: dict[str, Any] | None,
                 triage: dict[str, Any] | None, verification: dict[str, Any] | None,
                 discovery: dict[str, Any] | None, runtime: dict[str, Any] | None = None) -> None:
        self.decisions = {str(d.get("candidate_id")): d for d in policy.get("decisions", []) if isinstance(d, dict)}
        self.merged = {str(f.get("merged_finding_id")): f for f in (merged or {}).get("findings", [])
                       if isinstance(f, dict)}
        self.groups = {str(g.get("group_id")): g for g in (triage or {}).get("groups", []) if isinstance(g, dict)}
        self.verification = {str(r.get("candidate_id")): r for r in (verification or {}).get("records", [])
                             if isinstance(r, dict)}
        self.records = {str(r.get("candidate_id")): r for r in (triage or {}).get("records", []) if isinstance(r, dict)}
        self.ai_candidates = {str(c.get("candidate_id")): c for c in (discovery or {}).get("candidates", [])
                              if isinstance(c, dict)}
        self.probes = {(str(r.get("rule_id")), str(r.get("path"))): r for r in (runtime or {}).get("results", [])
                       if isinstance(r, dict)}
        flows = (runtime or {}).get("workflow_evidence")
        self.workflows = {str(w.get("id")): w for w in (flows or {}).get("workflows", []) if isinstance(w, dict)} if isinstance(flows, dict) else {}

    def trace(self, rule_id: str, facts: dict[str, Any], steps: tuple, recorded: bool) -> tuple[tuple[tuple[str, str], ...], str]:
        """What the probe did: the workflow steps with their observed HTTP status, or the request a baseline probe sent."""
        flow = self.workflows.get(str(facts.get("workflow_id")))
        if rule_id.startswith("workflow.") and flow:
            out = []
            for st in flow.get("steps", []):
                checks = st.get("assertion_results") or []
                expected = ", ".join(str(x) for x in st.get("expected_status", [])) or "n/a"
                result = (f'{st.get("status", "unknown")} - HTTP {st.get("http_status", "n/a")}, expected {expected}, checks {sum(bool(c) for c in checks)}/{len(checks)} passed'
                          + (" <- reported step" if st.get("step") == facts.get("step") else ""))
                out.append((f'{st.get("step")}. {st.get("actor")}: {st.get("method")} {st.get("path")}', result))
            return tuple(out), "Steps executed by the workflow runner in this run, with the HTTP status actually observed."
        if recorded:
            out = []
            for i, step in enumerate(steps, 1):
                f = dict(step)
                target = f.get("path", "") + (("?" + f["query"]) if f.get("query") else "")
                out.append((f'{i}. {f.get("method", "")} {target}'.strip(), " · ".join(x for x in (f.get("content_type"), f.get("body"), (f"sent x{f['repeat']}" if f.get("repeat") else "")) if x)))
            return tuple(out), "Request sent by the probe (a fixed shape written by VERDICT; credentials are redacted)."
        return (), ""

    def origin_and_evidence(self, group_id: str) -> dict[str, Any]:
        """Static/dynamic classification plus the dynamic evidence and code snippets behind one issue group."""
        scanner_ids, ai_ids = self._members(group_id)
        static: list[str] = []
        dynamic_src: list[str] = []
        dynamic: list[DynamicEvidence] = []
        snippets: list[tuple[str, str]] = []
        rules: list[str] = []
        for identifier in scanner_ids:
            merged = self.merged.get(identifier) or {}
            sources = [s for s in merged.get("source_findings", []) if isinstance(s, dict)] or [merged.get("canonical_finding") or {}]
            for source in sources:
                scanner = source.get("scanner") if isinstance(source.get("scanner"), dict) else {}
                name = str(scanner.get("scanner_id") or "scanner")
                is_dast = source.get("finding_kind") == "dast" or "dast" in (source.get("categories") or ())
                rule = str(source.get("rule_id") or "")
                if rule and rule not in rules:
                    rules.append(rule)
                location = source.get("primary_location") if isinstance(source.get("primary_location"), dict) else {}
                if is_dast:
                    if name not in dynamic_src:
                        dynamic_src.append(name)
                    endpoint = str(location.get("path") or "")
                    probe = self.probes.get((rule, endpoint))
                    steps, recorded = _request_steps(probe, source, endpoint)
                    trace, trace_note = self.trace(rule, {**(source.get("runtime_evidence") or {})}, steps, recorded)
                    dynamic.append(DynamicEvidence(
                        str(source.get("finding_id") or identifier), name, rule, str(source.get("title") or rule),
                        str(source.get("message") or source.get("description") or ""), str(source.get("severity") or "unknown"),
                        str(source.get("confidence") or "unknown"), endpoint, steps, recorded,
                        _output_facts(source, probe), True, str(scanner.get("scanner_name") or name), trace, trace_note))
                else:
                    if name not in static:
                        static.append(name)
                    if location.get("snippet"):
                        label = location_label(location)
                        item = (label, str(location["snippet"]))
                        if item not in snippets:
                            snippets.append(item)
        if ai_ids and "ai-discovery" not in static:
            static.append("ai-discovery")
        origin = "both" if static and dynamic_src else "dynamic" if dynamic_src else "static" if static else "unknown"
        tools = [t for t in static if t != "ai-discovery"] + [dynamic_tool(d.rule_id, d.scanner) for d in dynamic]
        if ai_ids:
            tools.append("ai-discovery")
        origins = tuple(o for o, present in (("static", any(t not in {"ai-discovery"} for t in static)), ("dynamic", bool(dynamic_src)),
                                              ("ai", bool(ai_ids))) if present)
        return {"origin": origin, "static": tuple(static), "dynamic_sources": tuple(dynamic_src), "dynamic": tuple(dynamic),
                "snippets": tuple(snippets), "rules": tuple(rules), "origins": origins, "tools": tuple(dict.fromkeys(tools))}

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
                   docker_runtime: dict[str, Any] | None, runtime_evidence: dict[str, Any] | None,
                   penetration_test: dict[str, Any] | None = None) -> list[str]:
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
    if penetration_test is not None and penetration_test.get("status") == "completed":
        usage = penetration_test.get("usage", {}) or {}
        lines += ["", "## Autonomous Penetration Testing", "",
                  f"- Hypotheses tested: **{usage.get('hypotheses_tested', 0)}**; "
                  f"total attempts: **{usage.get('total_attempts', 0)}**; "
                  f"exploitation confirmed: **{usage.get('exploitation_confirmed', 0)}**.",
                  "- Every probe is read-only against an isolated test stack with test accounts.",
                  "- Full per-attempt reproduction steps (exact method/path/account and response for each "
                  "try) are in the Markdown report and `dynamic-penetration-test.json`, not summarized here."]
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
               runtime_evidence: dict[str, Any] | None = None,
               penetration_test: dict[str, Any] | None = None,
               merged: dict[str, Any] | None = None,
               risk: dict[str, Any] | None = None, execution: dict[str, Any] | None = None,
               scanner_requirement: dict[str, Any] | None = None,
               coverage_gaps: list[str] | tuple[str, ...] | None = None,
               adapter_ids: list[str] | tuple[str, ...] | None = None) -> ReportView:
    evidence = _Evidence(review, policy, merged, triage, verification, discovery,
                         runtime_evidence if isinstance(runtime_evidence, dict) else None)
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
        extra = evidence.origin_and_evidence(gid)
        where = evidence.location(gid, item)
        w_path, w_start, w_end = split_location(where)
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
            str(decision.get("evidence_basis") or ""), tuple(str(e) for e in decision.get("evidence", []) or []),
            extra["origin"], w_path, w_start, w_end, extra["rules"], extra["static"], extra["dynamic_sources"],
            extra["dynamic"], extra["snippets"], extra["origins"], extra["tools"]))
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
    # ---- aggregates for the executive summary, scan reliability and the dynamic probe log
    origin_counts = {k: sum(f.origin == k for f in findings) for k in ("static", "dynamic", "both", "unknown")}
    cwe_tally: dict[str, int] = {}
    for f in findings:
        for cwe in f.cwes:
            cwe_tally[cwe] = cwe_tally.get(cwe, 0) + 1
    file_tally: dict[str, int] = {}
    for f in findings:
        if f.path:
            file_tally[f.path] = file_tally.get(f.path, 0) + 1
    rank_count = lambda t: tuple(sorted(t.items(), key=lambda kv: (-kv[1], kv[0]))[:8])

    runtime = runtime_evidence if isinstance(runtime_evidence, dict) else {}
    probe_rows: list[ProbeRow] = []
    for r in runtime.get("results", []) if isinstance(runtime.get("results"), list) else []:
        if not isinstance(r, dict):
            continue
        end = str(r.get("path") or "")
        req_steps, _ = _request_steps(r, {}, end)
        out = tuple((str(k), _fact_text(v)) for k, v in sorted((r.get("evidence") or {}).items())) if isinstance(r.get("evidence"), dict) else ()
        probe_rows.append(ProbeRow(str(r.get("rule_id") or ""), str(r.get("title") or r.get("rule_id") or ""), end,
                                   bool(r.get("vulnerable")), str(r.get("severity") or "unknown"), req_steps, out,
                                   str(r.get("source") or runtime.get("source") or ""), str(r.get("confidence") or "")))
    dyn_facts: list[tuple[str, str]] = []
    if runtime:
        dyn_facts.append(("Target", str(runtime.get("target") or "redacted")))
        dyn_facts.append(("Bounded probes", f"{len(probe_rows)} run · {sum(p.vulnerable for p in probe_rows)} positive"))
        for label, key in (("Browser crawl", "browser"), ("ZAP", "zap")):
            part = runtime.get(key)
            dyn_facts.append((label, "not requested" if not isinstance(part, dict) else
                              " · ".join(str(x) for x in (part.get("status", "unknown"), part.get("engine"),
                                         (f"{part.get('pages_visited')} pages" if key == "browser" and part.get("pages_visited") is not None else None),
                                         (f"{part.get('alerts', 0)} alerts" if key == "zap" else None)) if x)))
        flows = runtime.get("workflow_evidence")
        if isinstance(flows, dict):
            cov = flows.get("coverage") if isinstance(flows.get("coverage"), dict) else {}
            dyn_facts.append(("Workflows", f"{flows.get('status', 'unknown')} · {cov.get('executed', 0)} executed · {cov.get('violations', 0)} violations"))
    for label, blob in (("Docker DAST", docker_runtime), ("Isolated DAST", isolated_runtime)):
        if isinstance(blob, dict):
            dyn_facts.append((label, f"run {blob.get('run_id', '?')} · health HTTP {blob.get('http_status', '?')}"))

    checks: list[ReliabilityCheck] = []
    if rows:
        bad = [r for r in applicable if r.status in {"failed", "timed_out"}]
        checks.append(ReliabilityCheck("Scanner coverage", "fail" if bad else "warn" if missing else "pass",
                                       f"{done} of {len(applicable)} applicable scanner tasks completed"
                                       + (f"; not completed: {', '.join(missing)}" if missing else "")))
    else:
        checks.append(ReliabilityCheck("Scanner coverage", "warn", "No scanner execution record in this saved run, so coverage cannot be verified"))
    if scanner_requirement and scanner_requirement.get("requested"):
        ok = bool(scanner_requirement.get("satisfied"))
        checks.append(ReliabilityCheck("Required scanners", "pass" if ok else "fail",
                                       "All required scanners produced normalized output" if ok else
                                       "; ".join(str(x) for x in scanner_requirement.get("failures", [])) or "Requirement not satisfied"))
    if ai is not None:
        state = "pass" if ai["required_ok"] is True else "fail" if ai["required_ok"] is False else "warn"
        checks.append(ReliabilityCheck("AI discovery", state, f"{ai['status']} · targets {ai['targets']}/{ai['planned']} · {ai['calls']} model calls"
                                       + ("" if ai["required_ok"] is not None else " · stage not verified in this saved run")))
    pending = tuple(str(x) for x in review.get("pending_ids", []))
    expected = (review.get("usage") or {}).get("expected_groups")
    short = isinstance(expected, int) and len(findings) < expected
    checks.append(ReliabilityCheck("Agent review", "fail" if pending else "warn" if short else "pass",
                                   f"{len(pending)} issue group(s) still pending" if pending else
                                   f"{len(findings)} of {expected} expected groups reviewed" if short else f"{len(findings)} issue group(s) reviewed"))
    if verification is not None:
        vs = str(verification.get("status") or "unknown")
        checks.append(ReliabilityCheck("Source verification", "pass" if vs == "completed" else "warn", f"status {vs}"))
    checks.append(ReliabilityCheck("Dynamic testing", "pass" if dynamic else "warn",
                                   f"{len(probe_rows)} bounded probe(s) recorded" if dynamic and probe_rows else
                                   "Runtime evidence present" if dynamic else "Not performed: exploitability is inferred from code"))
    gap_n = len(tuple(dict.fromkeys(coverage_gaps or ())))
    checks.append(ReliabilityCheck("Known coverage gaps", "warn" if gap_n else "pass", f"{gap_n} recorded" if gap_n else "None recorded"))
    reliability_state = ("incomplete" if any(c.state == "fail" for c in checks) else
                         "partial" if any(c.state == "warn" for c in checks) else "complete")

    # ---- charts, agents and pipeline for the summary and the side panel
    display_name = friendly_name(project)
    tool_label = {"zap": "OWASP ZAP", "workflow": "Business workflows", "web-probe": "Baseline web probes", "idor": "IDOR probes",
                  "ai-discovery": "AI discovery"}
    static_ids = list(dict.fromkeys([r.scanner for r in rows if r.status not in {"not_scheduled", "skipped"}]
                                    + [t for f in findings for t in f.tools if t not in {"zap", "workflow", "web-probe", "idor", "ai-discovery"}
                                       and "static" in f.origins]))

    def short(scanner: str) -> str:
        return (SCANNER_ROLES.get(scanner, scanner).split(" \u00b7 ")[0]) if scanner in SCANNER_ROLES else scanner

    def count_tool(tool: str) -> int:
        return sum(tool in f.tools for f in findings)

    static_kids = tuple(FoundNode(t, short(t), count_tool(t), kind="tool") for t in static_ids)
    ran_dynamic = [("web-probe", any(p.source == "generic-web-runtime" or p.rule_id.startswith("web.") for p in probe_rows)),
                   ("zap", isinstance(runtime.get("zap"), dict) or any(p.rule_id.startswith("zap.") for p in probe_rows)),
                   ("workflow", isinstance(runtime.get("workflow_evidence"), dict) or any(p.rule_id.startswith("workflow.") for p in probe_rows)),
                   ("idor", any(p.rule_id.startswith("idor.") for p in probe_rows))]
    seen_dyn = {t for f in findings for t in f.tools if t in {"zap", "workflow", "web-probe", "idor"}}
    dynamic_kids = tuple(FoundNode(t, tool_label[t], count_tool(t), kind="tool") for t, ran in ran_dynamic if ran or t in seen_dyn)
    found_by = tuple(n for n in (
        FoundNode("static", "Static", sum("static" in f.origins for f in findings), static_kids,
                  note="scanners reading the code, dependencies, secrets and configuration"),
        FoundNode("dynamic", "Dynamic", sum("dynamic" in f.origins for f in findings), dynamic_kids,
                  note="probes sent to the running application (DAST)"),
        FoundNode("ai", "AI discovery", sum("ai" in f.origins for f in findings), (), note="candidates found by the AI Discovery agent reading source"),
    ) if n.count or n.children)

    def stage_state(status: str) -> str:
        return "ok" if status in {"completed", "complete", "success"} else "bad" if status in {"failed", "error", "timed_out"} else "warn"

    agents: list[AgentRow] = []
    if ai is not None:
        ai_gaps = tuple(str(g) for g in (discovery or {}).get("coverage_gaps", []) if str(g) not in set(coverage_gaps or ()))
        agents.append(AgentRow("AI Discovery agent", "Reads source code and proposes candidate vulnerabilities", ai["status"], stage_state(ai["status"]),
                               (f'{ai["provider"]} / {ai["model"]}', f'{ai["targets"]} of {ai["planned"]} targets inspected', f'{ai["calls"]} model call(s)',
                                f'{(discovery or {}).get("usage", {}).get("candidates", len((discovery or {}).get("candidates", [])))} candidate(s) proposed'),
                               ai_gaps + tuple(ai["warnings"])))
    rev_usage = review.get("usage") or {}
    agents.append(AgentRow("Review agent", "Judges every issue group and writes the verdict", str(review.get("status", "unknown")),
                           "bad" if review.get("pending_ids") else stage_state(str(review.get("status", "unknown"))),
                           (f'{review.get("provider", "unknown")} / {review.get("model", "unknown")}',
                            f'{len(findings)} of {expected_groups_n(review, len(findings))} issue groups reviewed',
                            *( (f'{len(review.get("pending_ids", []))} still pending',) if review.get("pending_ids") else ())),
                           tuple(str(w) for w in review.get("warnings", []))))

    runs: list[TestRun] = []
    for r in rows:
        runs.append(TestRun("Static scanners", r.role, {"completed": "ok", "not_scheduled": "na", "skipped": "na"}.get(r.status, "bad"), r.outcome))
    if runtime:
        probes_n = [p for p in probe_rows if p.rule_id.startswith("web.")]
        runs.append(TestRun("Dynamic tests", "Baseline web probes", "ok" if probes_n else "na", f"{len(probes_n)} probe(s) · {sum(p.vulnerable for p in probes_n)} finding(s)"))
        z = runtime.get("zap")
        if isinstance(z, dict):
            runs.append(TestRun("Dynamic tests", "OWASP ZAP", stage_state(str(z.get("status", "unknown"))),
                                f'{z.get("status", "unknown")} · {z.get("engine", "engine n/a")} · {sum(p.rule_id.startswith("zap.") for p in probe_rows)} alert(s)'))
        w = runtime.get("workflow_evidence")
        if isinstance(w, dict):
            cov = w.get("coverage") if isinstance(w.get("coverage"), dict) else {}
            runs.append(TestRun("Dynamic tests", "Business workflows", stage_state(str(w.get("status", "unknown"))),
                                f'{w.get("status", "unknown")} · {cov.get("executed", 0)} executed · {cov.get("violations", 0)} violations'))
        b = runtime.get("browser")
        if isinstance(b, dict):
            runs.append(TestRun("Dynamic tests", "Browser crawl", stage_state(str(b.get("status", "unknown"))),
                                f'{b.get("status", "unknown")} · {b.get("pages_visited", 0)} page(s) visited'))
    wf_steps: list[WorkflowStep] = []
    for wf in ((runtime.get("workflow_evidence") or {}).get("workflows") or []) if isinstance(runtime.get("workflow_evidence"), dict) else []:
        for st in (wf.get("steps") or []):
            ok = st.get("assertion_results") or []
            wf_steps.append(WorkflowStep(str(wf.get("title") or wf.get("id") or ""), int(st.get("step") or 0), str(st.get("actor") or ""),
                                         f'{st.get("method", "")} {st.get("path", "")}'.strip(), str(st.get("status") or ""),
                                         str(st.get("http_status", "") if st.get("http_status") is not None else "\u2014"),
                                         ", ".join(str(x) for x in (st.get("expected_status") or [])) or "\u2014",
                                         f"{sum(bool(x) for x in ok)}/{len(ok)} passed" if ok else "\u2014"))
    ai_only = sum(1 for g in (triage or {}).get("groups", []) if isinstance(g, dict) and g.get("candidate_ids") and not g.get("scanner_finding_ids"))

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
        runtime_lines=tuple(_runtime_lines(isolated_pilot, isolated_runtime, docker_runtime, runtime_evidence,
                                          penetration_test)),
        expected_groups=(review.get("usage") or {}).get("expected_groups"), skipped_tasks=skipped,
        not_scheduled=tuple(r.scanner for r in rows if r.status == "not_scheduled"), limitations=limitations,
        origin_counts=origin_counts, cwe_counts=rank_count(cwe_tally), file_counts=rank_count(file_tally),
        reliability=tuple(checks), reliability_state=reliability_state, probe_log=tuple(probe_rows),
        dynamic_facts=tuple(dyn_facts), display_name=display_name, found_by=found_by, agents=tuple(agents),
        test_runs=tuple(runs), workflow_steps=tuple(wf_steps), ai_only_groups=ai_only)

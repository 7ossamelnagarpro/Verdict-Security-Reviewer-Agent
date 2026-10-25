"""Apply release policy after semantic security review, using explicit rules (see ``rules.py``)."""

from __future__ import annotations

from typing import Any

from .models import PolicyDecision, PolicyResult
from .rules import (AI_ONLY, NOT_ASSESSED, RULE_SET_VERSION, RULES, SCANNER_CORROBORATED, SEVERITY_RANK,
                    SOURCE_VERIFIED, RuleInput, decide)


def _evidence_for(candidate_id: str, triage: dict[str, Any] | None, merged: dict[str, Any] | None,
                  verification: dict[str, Any] | None) -> tuple[str, str, tuple[str, ...]]:
    """(basis, max scanner severity, evidence items) for one reviewed issue group."""
    if merged is None and verification is None:
        return NOT_ASSESSED, "unknown", ()
    groups = {str(g.get("group_id")): g for g in (triage or {}).get("groups", []) if isinstance(g, dict)}
    group = groups.get(candidate_id) or {}
    scanner_ids = set(group.get("scanner_finding_ids") or ([candidate_id] if candidate_id.startswith("merged-") else []))
    ai_ids = set(group.get("candidate_ids") or ([candidate_id] if candidate_id.startswith("ai-") else []))
    evidence: list[str] = []
    strongest = "unknown"
    for finding in (merged or {}).get("findings", []):
        if not isinstance(finding, dict) or finding.get("merged_finding_id") not in scanner_ids:
            continue
        severity = str(finding.get("severity", "unknown")).lower()
        location = finding.get("primary_location") or {}
        where = f"{location.get('path', '?')}:{location.get('start_line') or '?'}"
        evidence.append(f"scanner {','.join(finding.get('scanners', []))} {severity} at {where} "
                        f"rules={'|'.join(str(r).split('.')[-1] for r in finding.get('rule_ids', []))}")
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(strongest, 0):
            strongest = severity
    verified = [r for r in (verification or {}).get("records", [])
                if isinstance(r, dict) and r.get("candidate_id") in ai_ids and r.get("disposition") == "confirmed"]
    for record in verified:
        evidence.append(f"source verification confirmed {record.get('path', '?')}:{record.get('start_line') or '?'}"
                        f" ({', '.join(record.get('checks', []))})")
    if SEVERITY_RANK.get(strongest, 0) >= SEVERITY_RANK["medium"]:
        return SCANNER_CORROBORATED, strongest, tuple(evidence)
    if verified:
        return SOURCE_VERIFIED, strongest, tuple(evidence)
    return AI_ONLY, strongest, tuple(evidence)


def evaluate_policy(review_payload: dict[str, Any], *, block_severities: frozenset[str] = frozenset({"critical", "high"}),
                    triage_payload: dict[str, Any] | None = None, merged_payload: dict[str, Any] | None = None,
                    verification_payload: dict[str, Any] | None = None) -> PolicyResult:
    decisions: list[PolicyDecision] = []
    for item in review_payload.get("reviews", []):
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("candidate_id", "unknown"))
        severity = str(item.get("severity", "unknown")).lower()
        verdict = str(item.get("verdict", "needs_more_evidence"))
        basis, scanner_severity, evidence = _evidence_for(candidate_id, triage_payload, merged_payload, verification_payload)
        rule_id, action = decide(RuleInput(verdict, severity, basis, scanner_severity, block_severities))
        rule = RULES[rule_id]
        reason = _reason(rule_id, severity, verdict, basis, scanner_severity, block_severities)
        decisions.append(PolicyDecision(candidate_id, action, severity, verdict, reason, rule_id, basis, evidence,
                                        reason if action == "block" else ""))
        assert rule.action == action
    blocking = any(item.action == "block" for item in decisions)
    unresolved = tuple(item for item in (triage_payload or {}).get("records", [])
                       if isinstance(item, dict) and item.get("disposition") in {"needs_more_evidence", "uncertain_overlap"})
    review_incomplete = review_payload.get("status") != "completed" or bool(review_payload.get("pending_ids"))
    status = "failed" if blocking else ("incomplete" if review_incomplete or unresolved else "passed")
    warnings = tuple(item.reason for item in decisions if item.action == "warn") + (
        (f"{len(unresolved)} AI candidates remain unresolved; they are not confirmed vulnerabilities.",)
        if unresolved else ()
    ) + (("Security review is incomplete; unreviewed issue groups must not be treated as safe.",)
         if review_incomplete else ())
    return PolicyResult("1.1", status, blocking, tuple(decisions), warnings, RULE_SET_VERSION)


def _reason(rule_id: str, severity: str, verdict: str, basis: str, scanner_severity: str,
            block_severities: frozenset[str]) -> str:
    label = verdict.replace("_", " ")
    support = {"scanner_corroborated": f"corroborated by a {scanner_severity} scanner finding",
               "source_verified": "AI claim confirmed against the cited source by deterministic checks",
               "ai_assertion_only": "supported only by the AI assertion (no scanner finding, source not confirmed)",
               "not_assessed": "deterministic evidence was not supplied to the gate"}[basis]
    if rule_id in {"RG-001", "RG-007"}:
        return (f"{rule_id}: {severity} {label} is {support}; blocking severities are "
                f"{', '.join(sorted(block_severities, key=lambda s: -SEVERITY_RANK.get(s, 0)))}.")
    if rule_id == "RG-002":
        return f"{rule_id}: {severity} {label} is {support}, so it cannot block automatically; manual confirmation required."
    if rule_id == "RG-003":
        return f"{rule_id}: {severity} likely vulnerability requires manual review; not auto-confirmed."
    if rule_id == "RG-004":
        return f"{rule_id}: classified as a false positive; no high/critical scanner finding contradicts it."
    if rule_id == "RG-005":
        return f"{rule_id}: AI classed this a false positive but a {scanner_severity} scanner finding exists; confirm manually."
    return f"{rule_id}: {severity} {label} is not sufficiently confirmed for an automatic block."

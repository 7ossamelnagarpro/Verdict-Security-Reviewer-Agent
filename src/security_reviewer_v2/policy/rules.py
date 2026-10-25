"""Explicit, versioned release-gate rules.

The gate must not rest on an AI description alone.  Each decision is produced by one named rule
(``RG-xxx``) from checkable inputs: the AI verdict/severity *and* deterministic evidence
(scanner findings, source-grounding verification).  The rule id, the evidence basis and the
evidence items are recorded on every decision so a block can be audited and tested.
"""

from __future__ import annotations

from dataclasses import dataclass

RULE_SET_VERSION = "release-gate-rules/2"
SEVERITY_RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Evidence bases, strongest first.
SCANNER_CORROBORATED = "scanner_corroborated"   # >=1 scanner finding of severity >= medium in the issue group
SOURCE_VERIFIED = "source_verified"             # AI claim whose cited source was confirmed by deterministic checks
AI_ONLY = "ai_assertion_only"                   # nothing deterministic supports the claim
NOT_ASSESSED = "not_assessed"                   # caller supplied no evidence payloads (legacy call)


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    action: str
    title: str


RULES = {
    "RG-001": PolicyRule("RG-001", "block", "Confirmed vulnerability at a blocking severity with deterministic evidence"),
    "RG-002": PolicyRule("RG-002", "warn", "Confirmed blocking-severity claim without deterministic evidence (AI assertion only)"),
    "RG-003": PolicyRule("RG-003", "warn", "Likely vulnerability at a blocking severity (manual confirmation required)"),
    "RG-004": PolicyRule("RG-004", "allow", "Classified false positive and no scanner reports high/critical for it"),
    "RG-005": PolicyRule("RG-005", "warn", "False-positive verdict contradicts a high/critical scanner finding"),
    "RG-006": PolicyRule("RG-006", "warn", "Not sufficiently confirmed for an automatic block"),
    "RG-007": PolicyRule("RG-007", "block", "Confirmed vulnerability backed by a high/critical scanner finding (severity downgraded by AI)"),
}


@dataclass(frozen=True)
class RuleInput:
    verdict: str
    severity: str
    evidence_basis: str
    max_scanner_severity: str
    block_severities: frozenset[str]


def decide(item: RuleInput) -> tuple[str, str]:
    """Return ``(rule_id, action)``. Pure function of its input; first matching rule wins."""
    blocking = item.severity in item.block_severities
    scanner_high = SEVERITY_RANK.get(item.max_scanner_severity, 0) >= SEVERITY_RANK["high"]
    if item.verdict == "confirmed_vulnerability" and blocking:
        if item.evidence_basis in (SCANNER_CORROBORATED, SOURCE_VERIFIED, NOT_ASSESSED):
            return "RG-001", "block"
        return "RG-002", "warn"
    if item.verdict == "confirmed_vulnerability" and scanner_high and item.evidence_basis == SCANNER_CORROBORATED:
        return "RG-007", "block"
    if item.verdict == "likely_vulnerability" and blocking:
        return "RG-003", "warn"
    if item.verdict == "false_positive":
        return ("RG-005", "warn") if scanner_high else ("RG-004", "allow")
    return "RG-006", "warn"

"""What the Autonomous Penetration Agent did, and whether it proved each AI Discovery finding.

Both report renderers (Markdown and HTML) format the same :class:`PenetrationOverview`, so they always agree.  This module
only reads existing artifacts (``discovery``, ``verification``, ``dynamic-penetration-test``, ``triage``); it never changes a
verdict, severity or policy action.

Reading the outcome correctly matters:

* ``exploitation_confirmed`` - the read-only probe reproduced the access violation against the isolated test stack.
* ``not_reproduced`` - every attempt was denied as it should be.  That is **not** proof the flaw does not exist.
* ``not_tested`` - the finding never reached the penetration agent (Verification did not source-confirm it, or the run
  ended first), so there is no dynamic evidence either way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# key -> (short label, one-sentence meaning).  ``proven`` is True only for exploitation_confirmed.
OUTCOMES: dict[str, tuple[str, str]] = {
    "exploitation_confirmed": ("Proven", "The penetration agent reproduced the issue against the running test stack."),
    "inconclusive": ("Inconclusive", "Responses were ambiguous (for example a server error), so the issue was neither proven nor ruled out."),
    "not_reproduced": ("Not reproduced", "Every attempt was denied as expected. This is not proof that the flaw does not exist."),
    "blocked": ("Could not be tested", "A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run."),
    "cannot_test": ("Cannot test", "No HTTP route could be resolved for this finding, so no safe dynamic test exists."),
    "not_tested": ("Not tested", "This finding never reached the penetration agent."),
}
_PRIORITY = ("exploitation_confirmed", "inconclusive", "not_reproduced", "blocked", "cannot_test", "not_tested")
_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class AttemptRow:
    number: int
    strategy: str
    tools: tuple[str, ...]
    steps: tuple[str, ...]            # "GET /orders/5 as user_b -> HTTP 403 (expected 200)"
    plan: str
    observation: str
    reasoning: str
    next_action: str
    stop_reason: str


@dataclass(frozen=True)
class HypothesisRow:
    candidate_id: str
    title: str
    severity: str
    location: str
    endpoint: str
    verification: str                 # Verification disposition, "" when unknown
    outcome: str                      # a key of OUTCOMES
    summary: str
    attempts: tuple[AttemptRow, ...]
    not_executed: tuple[str, ...]     # "strategy: reason" for scenarios drawn up but never fired

    @property
    def label(self) -> str:
        return OUTCOMES[self.outcome][0]

    @property
    def meaning(self) -> str:
        return OUTCOMES[self.outcome][1]

    @property
    def proven(self) -> bool:
        return self.outcome == "exploitation_confirmed"


@dataclass(frozen=True)
class PenetrationOverview:
    status: str                       # completed | not_run | blocked | ...
    rows: tuple[HypothesisRow, ...]
    not_sent: int                     # discovery candidates that Verification did not source-confirm
    usage: dict[str, Any]
    warnings: tuple[str, ...]

    def count(self, outcome: str) -> int:
        return sum(row.outcome == outcome for row in self.rows)


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in (value or []) if isinstance(item, dict)]


def _location(item: dict[str, Any]) -> str:
    path = item.get("path")
    if not path:
        return ""
    start, end = item.get("start_line"), item.get("end_line")
    if start and end and end != start:
        return f"{path}:{start}-{end}"
    return f"{path}:{start}" if start else str(path)


def _step_text(request: dict[str, Any], response: dict[str, Any]) -> str:
    status = response.get("http_status", response.get("status", "unknown"))
    expected = response.get("expected_status")
    return (f"{request.get('method', '?')} {request.get('path', '?')} as {request.get('actor', '?')} -> HTTP {status}"
            + (f" (expected {', '.join(str(x) for x in expected) if isinstance(expected, (list, tuple)) else expected})" if expected else ""))


def _attempt(item: dict[str, Any]) -> AttemptRow:
    requests = _dicts(item.get("request_evidence"))
    responses = _dicts(item.get("response_evidence"))
    steps = tuple(_step_text(request, responses[index] if index < len(responses) else {}) for index, request in enumerate(requests))
    return AttemptRow(int(item.get("attempt_number") or 0), str(item.get("test_strategy") or "unknown"),
                      tuple(str(t) for t in item.get("selected_tools") or ()), steps, str(item.get("attack_plan") or ""),
                      str(item.get("observation") or ""), str(item.get("agent_reasoning_summary") or ""),
                      str(item.get("next_action") or ""), str(item.get("stop_reason") or ""))


def build_overview(penetration_test: dict[str, Any] | None, discovery: dict[str, Any] | None = None,
                   verification: dict[str, Any] | None = None) -> PenetrationOverview | None:
    """One row per AI Discovery finding that is source-confirmed or was tested; ``None`` when the agent was not part of the run."""
    if not isinstance(penetration_test, dict):
        return None
    status = str(penetration_test.get("status") or "unknown")
    candidates = {str(c.get("candidate_id")): c for c in _dicts((discovery or {}).get("candidates"))}
    dispositions = {str(r.get("candidate_id")): str(r.get("disposition") or "") for r in _dicts((verification or {}).get("records"))}
    results = {str(r.get("candidate_id")): r for r in _dicts(penetration_test.get("results"))}

    rows: list[HypothesisRow] = []
    not_sent = 0
    for candidate_id in dict.fromkeys([*results, *candidates]):
        candidate, result = candidates.get(candidate_id, {}), results.get(candidate_id)
        disposition = dispositions.get(candidate_id, "")
        if result is None and verification is not None and disposition != "confirmed":
            not_sent += 1          # Verification did not source-confirm it, so it was never eligible; counted, not listed
            continue
        if result is None:
            outcome = "not_tested"
            summary = ("Not reached in this run (the penetration stage did not complete or ran out of budget)."
                       if status == "completed" else f"The penetration stage did not run (status: {status}).")
            attempts, gaps, endpoint = (), (), ""
        else:
            outcome = str(result.get("outcome") or "blocked")
            outcome = outcome if outcome in OUTCOMES else "blocked"
            summary = str(result.get("summary") or "")
            attempts = tuple(_attempt(a) for a in _dicts(result.get("attempts")))
            gaps = tuple(f"{g.get('strategy', 'unknown')}: {g.get('reason', '')}" for g in _dicts(result.get("considered_but_not_executed")))
            endpoint = next((a.get("target_endpoint") for a in _dicts(result.get("attempts")) if a.get("target_endpoint")), "") or ""
        rows.append(HypothesisRow(candidate_id, str(candidate.get("title") or candidate_id),
                                  str(candidate.get("severity") or "unknown").lower(), _location(candidate), str(endpoint),
                                  disposition, outcome, summary, attempts, gaps))
    rows.sort(key=lambda r: (_PRIORITY.index(r.outcome), _SEVERITY.get(r.severity, 9), r.candidate_id))
    return PenetrationOverview(status, tuple(rows), not_sent, dict(penetration_test.get("usage") or {}),
                               tuple(str(w) for w in penetration_test.get("warnings") or ()))


def rows_by_group(rows: tuple[HypothesisRow, ...], triage: dict[str, Any] | None) -> dict[str, HypothesisRow]:
    """Map each review-group id (``merged-...`` or a novel ``ai-...``) to the best penetration row among its AI candidates."""
    mapping: dict[str, HypothesisRow] = {}

    def offer(group_id: str, row: HypothesisRow) -> None:
        current = mapping.get(group_id)
        if current is None or _PRIORITY.index(row.outcome) < _PRIORITY.index(current.outcome):
            mapping[group_id] = row

    by_candidate = {row.candidate_id: row for row in rows}
    for row in rows:
        offer(row.candidate_id, row)              # a novel AI candidate keeps its own id as the group id
    for group in _dicts((triage or {}).get("groups")):
        for candidate_id in group.get("candidate_ids") or ():
            row = by_candidate.get(str(candidate_id))
            if row is not None:
                offer(str(group.get("group_id")), row)
    return mapping

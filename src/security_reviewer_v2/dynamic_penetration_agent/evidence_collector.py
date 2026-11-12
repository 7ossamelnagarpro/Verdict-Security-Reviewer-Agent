"""Section 3, phase 4 (collection half): bounded, redacted facts only — never raw bodies, tokens or secrets.

Reuses ``normalization.runtime_evidence.bounded_runtime_evidence`` so this agent's evidence is filtered by
the exact same allowlist the rest of the pipeline already trusts, rather than a second, parallel one.
"""

from __future__ import annotations

from typing import Any

from security_reviewer_v2.normalization.runtime_evidence import bounded_runtime_evidence


def collect(workflow_result: dict[str, Any]) -> tuple[tuple[dict, ...], tuple[dict, ...]]:
    """Split one ``run_workflows`` result's single workflow into request/response evidence pairs.

    ``run_workflows`` deliberately never records request/response bodies, tokens or captured values
    (see its own docstring), so there is nothing further to redact here beyond the existing allowlist.
    """
    workflows = workflow_result.get("workflows") or []
    if not workflows:
        return (), ()
    steps = workflows[0].get("steps") or []
    requests: list[dict] = []
    responses: list[dict] = []
    for step in steps:
        requests.append({
            "step": step.get("step"), "actor": step.get("actor"),
            "method": step.get("method"), "path": step.get("path"),
        })
        evidence = {k: v for k, v in step.items()
                    if k in {"status", "http_status", "expected_status", "assertion_results"}}
        bounded = bounded_runtime_evidence(evidence) or {}
        responses.append({**bounded, "step_status": step.get("status"), "reason": step.get("reason")})
    return tuple(requests), tuple(responses)

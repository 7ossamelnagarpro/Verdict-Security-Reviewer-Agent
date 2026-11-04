"""Bounded, redacted reproduction context from saved scanner and workflow evidence."""

from __future__ import annotations

from typing import Any


def _records(value: Any) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _safe_text(value: Any, limit: int = 180) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _safe_path(value: Any) -> str:
    return _safe_text(value, 200).split("?", 1)[0].split("#", 1)[0]


def _statuses(value: Any) -> list[int]:
    return (
        [item for item in value if type(item) is int][:10]
        if isinstance(value, list)
        else []
    )


def _checks(value: Any) -> list[dict[str, Any]]:
    return [
        {
            "kind": _safe_text(item.get("kind"), 30),
            "field": _safe_text(item.get("field"), 100),
            "operator": _safe_text(item.get("operator"), 30),
            "passed": item.get("passed") is True,
        }
        for item in _records(value)[:10]
    ]


def _location(source: dict[str, Any]) -> str:
    location = source.get("primary_location")
    if not isinstance(location, dict):
        return "Not recorded"
    path = _safe_path(location.get("path")) or "Not recorded"
    line = location.get("start_line")
    return f"{path}:{line}" if type(line) is int else path


def _workflow_steps(workflow: dict[str, Any], last_step: int) -> list[dict[str, Any]]:
    steps = []
    for item in _records(workflow.get("steps"))[:20]:
        number = item.get("step")
        if type(number) is not int or number > last_step:
            continue
        steps.append(
            {
                "number": number,
                "actor": _safe_text(item.get("actor"), 60),
                "method": _safe_text(item.get("method"), 10),
                "path": _safe_path(item.get("path")),
                "status": _safe_text(item.get("status"), 30),
                "observed_status": item.get("http_status")
                if type(item.get("http_status")) is int
                else None,
                "expected_statuses": _statuses(item.get("expected_status")),
                "checks": _checks(item.get("assertion_checks")),
            }
        )
    return steps


def _source_trace(
    source: dict[str, Any],
    finding: dict[str, Any],
    workflows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    scanner = source.get("scanner")
    parent_scanners = finding.get("scanners")
    scanner_id = (
        _safe_text(scanner.get("scanner_id"), 60)
        if isinstance(scanner, dict)
        else _safe_text(parent_scanners[0], 60)
        if isinstance(parent_scanners, list) and parent_scanners
        else "unknown scanner"
    )
    runtime = source.get("runtime_evidence")
    runtime = runtime if isinstance(runtime, dict) else {}
    workflow_id = runtime.get("workflow_id")
    step_number = runtime.get("step")
    trace: dict[str, Any] = {
        "source_id": _safe_text(source.get("finding_id"), 100),
        "scanner": scanner_id,
        "rule_id": _safe_text(source.get("rule_id"), 120),
        "location": _location(source),
        "severity": _safe_text(source.get("severity"), 30),
    }
    if isinstance(workflow_id, str) and type(step_number) is int:
        trace["kind"] = "workflow"
        trace["workflow_id"] = _safe_text(workflow_id, 100)
        trace["actor"] = _safe_text(runtime.get("actor"), 60)
        trace["method"] = _safe_text(runtime.get("method"), 10)
        trace["steps"] = _workflow_steps(workflows.get(workflow_id, {}), step_number)
        trace["observed_status"] = (
            runtime.get("status") if type(runtime.get("status")) is int else None
        )
        trace["expected_statuses"] = _statuses(runtime.get("expected_statuses"))
        trace["checks"] = _checks(runtime.get("assertion_checks"))
    elif runtime or "dast" in (
        _records_categories(source) | _records_categories(finding)
    ):
        trace["kind"] = "runtime"
        trace["method"] = _safe_text(runtime.get("method"), 10)
        trace["observed_status"] = (
            runtime.get("status") if type(runtime.get("status")) is int else None
        )
        trace["expected_statuses"] = _statuses(runtime.get("expected_statuses"))
        trace["checks"] = _checks(runtime.get("assertion_checks"))
    else:
        trace["kind"] = "static"
        flow = _records(source.get("code_flow"))
        if flow and type(flow[0].get("flow_index")) is int:
            first_flow = flow[0]["flow_index"]
            flow = [item for item in flow if item.get("flow_index") == first_flow]
        visible_flow = flow[:3] + flow[-3:] if len(flow) > 6 else flow
        trace["flow_locations"] = [
            _location({"primary_location": item.get("location")})
            for item in visible_flow
        ]
        trace["flow_truncated"] = len(flow) > 6
    return trace


def _records_categories(source: dict[str, Any]) -> set[str]:
    categories = source.get("categories")
    return (
        {str(item).lower() for item in categories}
        if isinstance(categories, list)
        else set()
    )


def build_evidence_traces(
    review: dict[str, Any],
    triage: dict[str, Any] | None,
    merged: dict[str, Any] | None,
    runtime_evidence: dict[str, Any] | None,
) -> dict[str, list[dict[str, Any]]]:
    """Link reviewed groups to saved evidence without response bodies or secrets."""
    findings = {
        str(item["merged_finding_id"]): item
        for item in _records((merged or {}).get("findings"))
        if item.get("merged_finding_id")
    }
    groups = {
        str(item["group_id"]): item
        for item in _records((triage or {}).get("groups"))
        if item.get("group_id")
    }
    workflow_payload = (runtime_evidence or {}).get("workflow_evidence")
    workflows = (
        {
            str(item["id"]): item
            for item in _records((workflow_payload or {}).get("workflows"))
            if item.get("id")
        }
        if isinstance(workflow_payload, dict)
        else {}
    )
    result: dict[str, list[dict[str, Any]]] = {}
    for item in _records(review.get("reviews")):
        group_id = str(item.get("candidate_id") or "")
        group = groups.get(group_id, {})
        raw_ids = group.get("scanner_finding_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            raw_ids = (
                item.get("source_ids")
                if isinstance(item.get("source_ids"), list)
                else []
            )
        linked = [findings[str(value)] for value in raw_ids if str(value) in findings]
        traces = []
        for finding in linked[:4]:
            sources = _records(finding.get("source_findings"))
            if not sources and isinstance(finding.get("canonical_finding"), dict):
                sources = [finding["canonical_finding"]]
            if not sources:
                sources = [finding]
            for source in sources[:4]:
                traces.append(_source_trace(source, finding, workflows))
        if not traces:
            traces.append(
                {
                    "kind": "discovery"
                    if group.get("candidate_ids") or item.get("source_ids")
                    else "unavailable"
                }
            )
        result[group_id] = traces[:8]
    return result

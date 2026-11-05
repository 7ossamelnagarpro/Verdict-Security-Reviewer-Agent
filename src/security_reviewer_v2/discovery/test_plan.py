"""Review-only runtime test proposals derived from source-backed route guidance."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
_WRITES = {"POST", "PUT", "PATCH", "DELETE"}
_PROBE_PATH = re.compile(r"/[A-Za-z0-9/_-]{0,255}\Z")


def _safe_path(path: Any) -> bool:
    return (
        isinstance(path, str)
        and path.startswith("/")
        and not path.startswith("//")
        and "\\" not in path
        and "#" not in path
        and "?" not in path
        and len(path) <= 500
        and all(ord(char) >= 32 for char in path)
    )


def _candidate_ids_for_route(
    candidates: Any, source_file: str | None, source_line: int | None
) -> list[str]:
    """Link only candidates anchored to this exact route declaration."""
    if not source_file or source_line is None or not isinstance(candidates, list):
        return []
    matched: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        identifier = candidate.get("candidate_id")
        entry = candidate.get("entry_point")
        if (
            isinstance(identifier, str)
            and isinstance(entry, dict)
            and entry.get("path") == source_file
            and entry.get("line") == source_line
            and identifier not in matched
        ):
            matched.append(identifier)
    return matched


def build_discovery_test_plan(
    discovery: dict[str, Any],
    browser: dict[str, Any] | None = None,
    *,
    project_root: Path | None = None,
    project_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Create bounded proposals without issuing requests or security findings."""
    guidance = discovery.get("application_map_guidance")
    suggestions = guidance.get("suggestions", []) if isinstance(guidance, dict) else []
    proposals: list[dict[str, Any]] = []
    for item in suggestions[:50] if isinstance(suggestions, list) else []:
        if not isinstance(item, dict):
            continue
        method, path = item.get("method"), item.get("path")
        if (
            not isinstance(method, str)
            or method not in _METHODS
            or not _safe_path(path)
        ):
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        source_file = (
            source.get("file") if isinstance(source.get("file"), str) else None
        )
        source_line = source.get("line") if type(source.get("line")) is int else None
        identifier = hashlib.sha256(
            f"{method}\0{path}\0{source_file}\0{source_line}".encode()
        ).hexdigest()[:16]
        checks = (
            item.get("suggested_checks")
            if isinstance(item.get("suggested_checks"), list)
            else []
        )
        types = ["zap_scope_review"]
        if method in {"GET", "HEAD"} and "{" not in path:
            types.append("bounded_http_probe_review")
            if method == "GET":
                types.append("browser_seed_review")
        if any("cross-account" in check for check in checks if isinstance(check, str)):
            types.append("cross_account_workflow_review")
        if any("role-based" in check for check in checks if isinstance(check, str)):
            types.append("role_access_workflow_review")
        if method in _WRITES:
            types.append("state_changing_workflow_review")
        proposals.append(
            {
                "id": f"route-{identifier}",
                "method": method,
                "path": path,
                "source": {"file": source_file, "line": source_line},
                "candidate_ids": _candidate_ids_for_route(
                    discovery.get("candidates"), source_file, source_line
                ),
                "proposal_types": types,
                "account_scenarios": [
                    value[:100]
                    for value in item.get("account_scenarios", [])[:6]
                    if isinstance(value, str)
                ]
                if isinstance(item.get("account_scenarios"), list)
                else [],
                "requires_confirmation": [
                    "mounted route prefix and reachability",
                    "expected status and security rule",
                    "approved test accounts and roles",
                    "request body and cleanup for writes",
                ],
                "approval_required": True,
                "auto_executable": False,
            }
        )
    existing = {(item["method"], item["path"]) for item in proposals}
    if isinstance(browser, dict) and browser.get("status") == "completed":
        observed_requests = browser.get("observed_requests")
        observed_forms = browser.get("observed_forms")
        for observed in (
            observed_requests[:100] if isinstance(observed_requests, list) else []
        ):
            if not isinstance(observed, dict):
                continue
            method, path = observed.get("method"), observed.get("path")
            if method != "GET" or not _safe_path(path) or (method, path) in existing:
                continue
            existing.add((method, path))
            proposals.append(
                {
                    "id": "browser-" + hashlib.sha256(path.encode()).hexdigest()[:16],
                    "method": method,
                    "path": path,
                    "source": {"kind": "browser_observation"},
                    "proposal_types": ["browser_observed_route_review"],
                    "account_scenarios": [],
                    "requires_confirmation": [
                        "expected status and security rule",
                        "account and role coverage",
                    ],
                    "approval_required": True,
                    "auto_executable": False,
                }
            )
        for form in observed_forms[:40] if isinstance(observed_forms, list) else []:
            if not isinstance(form, dict):
                continue
            method, path = form.get("method"), form.get("path")
            if (
                not isinstance(method, str)
                or method not in _METHODS
                or not _safe_path(path)
                or (method, path) in existing
            ):
                continue
            existing.add((method, path))
            proposals.append(
                {
                    "id": "form-"
                    + hashlib.sha256(f"{method}\0{path}".encode()).hexdigest()[:16],
                    "method": method,
                    "path": path,
                    "source": {"kind": "browser_form_observation"},
                    "proposal_types": ["browser_form_workflow_review"],
                    "account_scenarios": [],
                    "requires_confirmation": [
                        "form purpose and expected result",
                        "approved test account",
                        "safe test values and cleanup for writes",
                    ],
                    "approval_required": True,
                    "auto_executable": False,
                }
            )
    for proposal in proposals:
        proposal["execution_status"] = "not_executed"
    return {
        "schema_version": "1.0",
        "status": "proposed" if proposals else "no_proposals",
        "source": "discovery-application-map-guidance",
        "project_root": os.path.normcase(str(project_root.resolve()))
        if project_root is not None
        else None,
        "project_fingerprint": project_fingerprint,
        "proposals": proposals,
        "proposal_count": len(proposals),
        "executed_count": 0,
        "limitations": [
            "Source declarations are hypotheses, not confirmed mounted routes or vulnerabilities.",
            "Only explicit trusted Compose opt-in can probe current source-backed GET proposals before review.",
            "Request bodies, expected statuses, credentials, authorization and cleanup need human review.",
        ],
    }


def approved_readonly_routes(
    plan_path: Path, *, project_root: Path, project_fingerprint: str
) -> tuple[str, ...]:
    return tuple(
        item["path"]
        for item in approved_readonly_proposals(
            plan_path,
            project_root=project_root,
            project_fingerprint=project_fingerprint,
        )
    )


def approved_readonly_proposals(
    plan_path: Path, *, project_root: Path, project_fingerprint: str
) -> tuple[dict[str, Any], ...]:
    """Select source-backed GET routes from a reviewed plan for disposable Docker.

    Passing this file is an explicit approval of bounded read-only probes. A
    proposal never supplies credentials, request bodies or expected policy.
    """
    root = project_root.resolve(strict=True)
    try:
        saved = plan_path.resolve(strict=True)
    except OSError as error:
        raise ValueError("Approved Discovery plan is unavailable") from error
    if (
        saved.is_relative_to(root)
        or not saved.is_file()
        or saved.stat().st_size > 128 * 1024
    ):
        raise ValueError(
            "Approved Discovery plan must be a small JSON file outside the target"
        )
    try:
        plan = json.loads(saved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Approved Discovery plan is not valid JSON") from error
    return select_bounded_readonly_proposals(
        plan, project_root=root, project_fingerprint=project_fingerprint
    )


def select_bounded_readonly_proposals(
    plan: dict[str, Any], *, project_root: Path, project_fingerprint: str
) -> tuple[dict[str, Any], ...]:
    """Validate a current or reviewed plan against the exact source snapshot."""
    root = project_root.resolve(strict=True)
    if (
        not isinstance(plan, dict)
        or plan.get("schema_version") != "1.0"
        or plan.get("status") not in {"proposed", "no_proposals"}
        or plan.get("project_root") != os.path.normcase(str(root))
        or plan.get("project_fingerprint") != project_fingerprint
        or not isinstance(plan.get("proposals"), list)
        or len(plan["proposals"]) > 100
    ):
        raise ValueError("Approved Discovery plan does not match this target snapshot")
    from security_reviewer_v2.web.runtime_discovery import discover

    declared = {
        (item["method"], item["path"], item["source"])
        for item in discover(root)["endpoints"]
    }
    selected: list[dict[str, Any]] = []
    paths: set[str] = set()
    for proposal in plan["proposals"]:
        if not isinstance(proposal, dict):
            continue
        path = proposal.get("path")
        source = proposal.get("source")
        if (
            proposal.get("method") != "GET"
            or not isinstance(path, str)
            or not _PROBE_PATH.fullmatch(path)
            or "//" in path
            or "/../" in path
            or path.endswith("/..")
            or not isinstance(source, dict)
            or not isinstance(source.get("file"), str)
            or not isinstance(proposal.get("proposal_types"), list)
            or "bounded_http_probe_review" not in proposal.get("proposal_types", [])
            or proposal.get("approval_required") is not True
            or proposal.get("auto_executable") is not False
        ):
            continue
        source_relative = Path(source["file"])
        if source_relative.is_absolute() or ".." in source_relative.parts:
            continue
        try:
            source_path = (root / source_relative).resolve()
        except (OSError, ValueError):
            continue
        if not source_path.is_relative_to(root) or not source_path.is_file():
            continue
        source_line = source.get("line")
        if source_line is not None and type(source_line) is not int:
            continue
        declared_source = source_relative.as_posix()
        if source_line is not None:
            declared_source += f":{source_line}"
        if ("GET", path, declared_source) not in declared:
            continue
        if path not in paths:
            selected.append(
                {
                    "proposal_id": proposal.get("id")
                    if isinstance(proposal.get("id"), str)
                    else None,
                    "path": path,
                    "source": {
                        "file": source_relative.as_posix(),
                        "line": source_line,
                    },
                    "candidate_ids": [
                        identifier
                        for identifier in proposal.get("candidate_ids", [])[:20]
                        if isinstance(identifier, str)
                    ]
                    if isinstance(proposal.get("candidate_ids"), list)
                    else [],
                }
            )
            paths.add(path)
        if len(selected) >= 20:
            break
    return tuple(selected)


def bounded_probe_result(
    proposals: tuple[dict[str, Any], ...],
    baseline: dict[str, Any] | None,
    *,
    health_path: str,
    project_fingerprint: str,
    source_plan: str,
) -> dict[str, Any]:
    """Save status-only GET observations; no expected security rule is inferred."""
    results = baseline.get("results", []) if isinstance(baseline, dict) else []
    statuses = {
        row.get("path"): row.get("evidence", {}).get("status")
        for row in results
        if isinstance(row, dict)
        and row.get("rule_id") == "web.endpoint-server-error"
        and isinstance(row.get("evidence"), dict)
    }
    health_status = next(
        (
            row.get("evidence", {}).get("status")
            for row in results
            if isinstance(row, dict)
            and row.get("path") == health_path
            and row.get("rule_id") == "web.missing-content-security-policy"
            and isinstance(row.get("evidence"), dict)
        ),
        None,
    )
    if any(item["path"] == health_path for item in proposals):
        statuses[health_path] = health_status
    probes = [
        {
            **proposal,
            "method": "GET",
            "execution_status": "executed"
            if type(statuses.get(proposal["path"])) is int
            else "not_executed",
            "http_status": statuses.get(proposal["path"]),
            "security_assertion": "not_defined",
        }
        for proposal in proposals
    ]
    return {
        "schema_version": "1.0",
        "status": "no_eligible_routes"
        if not probes
        else "completed"
        if all(item["execution_status"] == "executed" for item in probes)
        else "partial",
        "source_plan": source_plan,
        "project_fingerprint": project_fingerprint,
        "probes": probes,
        "finding_count": 0,
    }


def apply_probe_execution(
    plan: dict[str, Any], probes: dict[str, Any] | None
) -> dict[str, Any]:
    """Reflect only exact current-scan probe IDs in the generated proposal plan."""
    if (
        not isinstance(probes, dict)
        or probes.get("source_plan") != "current-scan"
        or probes.get("project_fingerprint") != plan.get("project_fingerprint")
        or not isinstance(probes.get("probes"), list)
    ):
        return plan
    observed = {
        (item.get("proposal_id"), item.get("path")): item
        for item in probes["probes"][:20]
        if isinstance(item, dict)
        and isinstance(item.get("proposal_id"), str)
        and isinstance(item.get("path"), str)
        and item.get("method") == "GET"
    }
    proposals = []
    for proposal in plan.get("proposals", []):
        item = dict(proposal)
        probe = observed.get((item.get("id"), item.get("path")))
        if probe and probe.get("source") == item.get("source"):
            item["execution_status"] = (
                "executed"
                if probe.get("execution_status") == "executed"
                and type(probe.get("http_status")) is int
                else "not_executed"
            )
            item["http_status"] = probe.get("http_status")
            item["security_assertion"] = "not_defined"
        proposals.append(item)
    return {
        **plan,
        "proposals": proposals,
        "executed_count": sum(
            item.get("execution_status") == "executed" for item in proposals
        ),
    }


def link_probe_evidence(
    discovery: dict[str, Any],
    triage: dict[str, Any],
    probes: dict[str, Any] | None,
    *,
    project_fingerprint: str | None,
    application_map: dict[str, Any] | None = None,
    runtime_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach bounded runtime observations by exact source anchor.

    An HTTP response has no expected security assertion, so every linked probe
    remains inconclusive regardless of its status code.
    """
    valid_probes = (
        isinstance(probes, dict)
        and probes.get("schema_version") == "1.0"
        and isinstance(project_fingerprint, str)
        and probes.get("project_fingerprint") == project_fingerprint
        and isinstance(probes.get("probes"), list)
    )
    by_anchor: dict[tuple[str, int], list[dict[str, Any]]] = {}
    if valid_probes:
        for item in probes["probes"][:20]:
            if not isinstance(item, dict) or item.get("method") != "GET":
                continue
            source = item.get("source")
            if not isinstance(source, dict):
                continue
            file, line = source.get("file"), source.get("line")
            path, status = item.get("path"), item.get("http_status")
            if (
                not isinstance(file, str)
                or type(line) is not int
                or not isinstance(path, str)
                or not _PROBE_PATH.fullmatch(path)
                or type(status) is not int
                or not 100 <= status <= 599
                or item.get("execution_status") != "executed"
                or item.get("security_assertion") != "not_defined"
            ):
                continue
            by_anchor.setdefault((file, line), []).append(
                {
                    "proposal_id": item.get("proposal_id")
                    if isinstance(item.get("proposal_id"), str)
                    else None,
                    "method": "GET",
                    "path": path,
                    "http_status": status,
                    "security_assertion": "not_defined",
                    "conclusion": "inconclusive",
                }
            )
    workflow_by_anchor: dict[tuple[str, int], list[dict[str, Any]]] = {}
    workflow = (
        runtime_evidence.get("workflow_evidence")
        if isinstance(runtime_evidence, dict)
        else None
    )
    routes = (
        application_map.get("routes") if isinstance(application_map, dict) else None
    )
    workflows = workflow.get("workflows") if isinstance(workflow, dict) else None
    if isinstance(routes, list) and isinstance(workflows, list):
        declared: dict[tuple[str, str], list[tuple[str, int]]] = {}
        for route in routes:
            if not isinstance(route, dict) or not isinstance(route.get("source"), dict):
                continue
            source = route["source"]
            if (
                isinstance(route.get("method"), str)
                and isinstance(route.get("path"), str)
                and isinstance(source.get("file"), str)
                and type(source.get("line")) is int
            ):
                declared.setdefault((route["method"], route["path"]), []).append(
                    (source["file"], source["line"])
                )
        for record in workflows[:100]:
            if not isinstance(record, dict):
                continue
            steps = record.get("steps")
            for step in steps[:100] if isinstance(steps, list) else []:
                if not isinstance(step, dict) or step.get("security_check") is not True:
                    continue
                method, path = step.get("method"), step.get("path")
                if not isinstance(method, str) or not isinstance(path, str):
                    continue
                normalized_path = re.sub(r"\{\{([^{}]+)\}\}", r"{\1}", path)
                anchors = declared.get((method, normalized_path), [])
                status = step.get("http_status")
                if type(status) is not int or not 100 <= status <= 599:
                    continue
                checks = (
                    [
                        {
                            "kind": check.get("kind"),
                            "operator": check.get("operator"),
                            "passed": check.get("passed"),
                        }
                        for check in step.get("assertion_checks", [])[:10]
                        if isinstance(check, dict)
                        and type(check.get("passed")) in {bool, type(None)}
                    ]
                    if isinstance(step.get("assertion_checks"), list)
                    else []
                )
                observed = {
                    "workflow_id": record.get("id")
                    if isinstance(record.get("id"), str)
                    else None,
                    "step": step.get("step") if type(step.get("step")) is int else None,
                    "actor": step.get("actor")[:64]
                    if isinstance(step.get("actor"), str)
                    else None,
                    "method": method,
                    "path": normalized_path,
                    "http_status": status,
                    "assertion_checks": checks,
                    "result": "violated"
                    if any(check["passed"] is False for check in checks)
                    else "inconclusive"
                    if not checks or any(check["passed"] is None for check in checks)
                    else "passed",
                }
                for anchor in anchors:
                    workflow_by_anchor.setdefault(anchor, []).append(observed)
    groups = {
        item.get("candidate_id"): item.get("group_id")
        for item in triage.get("records", [])
        if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
    }
    candidates: list[dict[str, Any]] = []
    for candidate in discovery.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        identifier = candidate.get("candidate_id")
        entry = candidate.get("entry_point")
        if not isinstance(identifier, str):
            continue
        anchor = (
            (entry.get("path"), entry.get("line")) if isinstance(entry, dict) else None
        )
        matched = by_anchor.get(anchor, []) if anchor is not None else []
        workflow_tests = (
            workflow_by_anchor.get(anchor, [])[:5] if anchor is not None else []
        )
        candidates.append(
            {
                "candidate_id": identifier,
                "review_group_id": groups.get(identifier),
                "status": "observed_assertion"
                if workflow_tests
                else "observed_inconclusive"
                if matched
                else "not_tested",
                "probes": matched,
                "workflow_tests": workflow_tests,
            }
        )
    probe_warnings = (
        [str(item) for item in probes["warnings"][:5] if isinstance(item, str)]
        if valid_probes and isinstance(probes.get("warnings"), list)
        else []
    )
    return {
        "schema_version": "1.0",
        "status": "partial"
        if valid_probes and probes.get("status") in {"partial", "blocked"}
        else "completed"
        if by_anchor or workflow_by_anchor
        else "not_run",
        "candidates": candidates,
        "observed_candidates": sum(
            bool(item["probes"] or item["workflow_tests"]) for item in candidates
        ),
        "limitations": [
            "GET response status alone has no expected security assertion and cannot confirm a vulnerability.",
            "Only candidates with an exact source-file and entry-point line match are linked.",
            "Workflow assertion results are declared-rule observations, not independent exploit proof.",
            *probe_warnings,
        ],
    }


def candidates_with_violated_workflow(evidence: dict[str, Any] | None) -> set[str]:
    """Return candidate IDs with a source-linked, failed declared assertion."""
    if not isinstance(evidence, dict):
        return set()
    return {
        item["candidate_id"]
        for item in evidence.get("candidates", [])
        if isinstance(item, dict)
        and isinstance(item.get("candidate_id"), str)
        and isinstance(item.get("workflow_tests"), list)
        and any(
            isinstance(test, dict) and test.get("result") == "violated"
            for test in item["workflow_tests"]
        )
    }

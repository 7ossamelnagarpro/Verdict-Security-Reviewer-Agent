"""Bounded, non-authoritative Application Map context for discovery."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .models import DiscoveryTarget

_SENSITIVE_NAME = re.compile(
    r"owner|user|account|role|admin|token|secret|password|file|path|coupon|price|amount",
    re.IGNORECASE,
)
_OBJECT_ID = re.compile(r"(?:^id$|_id$)", re.IGNORECASE)
_ROLE_NAME = re.compile(
    r"(?<![A-Za-z])(admin|staff|manager|moderator)(?![A-Za-z])", re.IGNORECASE
)


def validated_application_map(
    application_map: dict[str, Any] | None,
    *,
    project_root: str | Path,
    profile_artifact: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str]:
    """Reject stale, foreign, or malformed maps before they can guide the agent."""
    if application_map is None:
        return None, "not_provided"
    snapshot = (
        profile_artifact.get("project_snapshot")
        if isinstance(profile_artifact, dict)
        else None
    )
    if (
        not isinstance(snapshot, dict)
        or not isinstance(snapshot.get("fingerprint"), str)
        or not snapshot["fingerprint"]
    ):
        return None, "missing_profile_fingerprint"
    if (
        not isinstance(application_map, dict)
        or application_map.get("schema_version") != "1.0"
    ):
        return None, "unsupported_map_schema"
    if application_map.get("status") != "generated" or not isinstance(
        application_map.get("routes"), list
    ):
        return None, "map_not_generated"
    root = os.path.normcase(str(Path(project_root).resolve()))
    if (
        os.path.normcase(str(application_map.get("project_root"))) != root
        or application_map.get("project_fingerprint") != snapshot["fingerprint"]
    ):
        return None, "map_does_not_match_profile"
    records = snapshot.get("files")
    if not isinstance(records, list):
        return None, "missing_profile_inventory"
    profiled_paths = {
        record.get("path")
        for record in records
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    source_routes = [
        route
        for route in application_map["routes"][:250]
        if isinstance(route, dict)
        and isinstance(route.get("source"), dict)
        and route["source"].get("file") in profiled_paths
    ]
    return {**application_map, "routes": source_routes}, "accepted"


def route_priority(application_map: dict[str, Any] | None) -> dict[str, int]:
    """Rank source-backed entry-point files without treating unknown auth as a flaw."""
    scores: dict[str, int] = {}
    for route in _routes(application_map):
        path = route["source"]["file"]
        score = 1 + 2 * (route["method"] in {"POST", "PUT", "PATCH", "DELETE"})
        score += 2 * any(
            _OBJECT_ID.search(item.get("name", "")) for item in route["parameters"]
        )
        score += 2 * bool(
            route.get("database_interactions")
            or route.get("same_file_database_candidates")
        )
        score += 1 * bool(_SENSITIVE_NAME.search(route["path"]))
        scores[path] = max(scores.get(path, 0), score)
    return scores


def map_hints_for_targets(
    application_map: dict[str, Any] | None,
    targets: tuple[DiscoveryTarget, ...],
    *,
    max_hints: int = 12,
) -> list[dict[str, Any]]:
    """Project only routes belonging to the bounded source targets in this batch."""
    if application_map is None:
        return []
    by_file: dict[str, list[dict[str, Any]]] = {}
    for route in _routes(application_map):
        by_file.setdefault(route["source"]["file"], []).append(route)
    hints: list[dict[str, Any]] = []
    seen_routes: set[tuple[str, str, str, int | None]] = set()
    for target in targets:
        if not target.path:
            continue
        routes = [
            route
            for route in by_file.get(target.path.replace("\\", "/"), [])
            if _line_in_target(route["source"].get("line"), target)
        ]
        routes = sorted(
            routes,
            key=lambda route: (
                not _line_in_target(route["source"].get("line"), target),
                abs((route["source"].get("line") or 0) - (target.start_line or 0)),
                route["method"],
                route["path"],
            ),
        )
        target_hints = 0
        for route in routes:
            key = (
                route["method"],
                route["path"],
                route["source"]["file"],
                route["source"].get("line"),
            )
            if key in seen_routes:
                continue
            seen_routes.add(key)
            hints.append({"target_id": target.target_id, **_route_hint(route)})
            target_hints += 1
            if len(hints) >= max_hints:
                return hints
            if target_hints >= 2:
                break
    return hints


def frontend_hints_for_targets(
    frontend_calls: list[dict[str, Any]],
    targets: tuple[DiscoveryTarget, ...],
    *,
    max_hints: int = 12,
) -> list[dict[str, Any]]:
    """Only show literal calls whose source line is present in a selected window."""
    hints = []
    for target in targets:
        for call in frontend_calls:
            source = call.get("source", {})
            if source.get("file") != target.path or not _line_in_target(
                source.get("line"), target
            ):
                continue
            hints.append(
                {
                    "target_id": target.target_id,
                    "method": call["method"],
                    "path": call["path"],
                    "source_line": source["line"],
                    "evidence_kind": call["evidence_kind"],
                }
            )
            if len(hints) >= max_hints:
                return hints
    return hints


def map_guidance(
    application_map: dict[str, Any] | None,
    *,
    scanner_paths: set[str],
    planned_targets: tuple[DiscoveryTarget, ...],
    frontend_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Save review suggestions, not findings or executable workflow steps."""
    routes = _routes(application_map)
    planned_paths = {
        target.path.replace("\\", "/") for target in planned_targets if target.path
    }
    unplanned = [
        route for route in routes if route["source"]["file"] not in planned_paths
    ]
    suggestions: list[dict[str, Any]] = []
    file_scores = route_priority(application_map)
    prioritized_routes = sorted(
        routes,
        key=lambda route: (
            route["source"]["file"] not in planned_paths,
            route["source"]["file"] in scanner_paths,
            -file_scores.get(route["source"]["file"], 0),
            route["source"]["file"],
            route["method"],
            route["path"],
        ),
    )
    for route in prioritized_routes:
        names = [item.get("name", "") for item in route["parameters"]]
        body = route.get("request_body")
        if isinstance(body, dict):
            names.extend(
                item.get("name", "")
                for item in body.get("fields", [])[:20]
                if isinstance(item, dict)
            )
        checks = []
        if _SENSITIVE_NAME.search(route["path"]) or route.get("required_role"):
            checks.append(
                "confirm expected anonymous and role-based access using approved test accounts"
            )
        if any(_OBJECT_ID.search(name) for name in names):
            checks.append(
                "compare authorized and cross-account object access on a disposable target"
            )
        if any(_SENSITIVE_NAME.search(name) for name in names):
            checks.append(
                "review sensitive input validation and authorization boundaries"
            )
        if route["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            checks.append(
                "review a state-changing workflow; do not execute without approval"
            )
        if not checks:
            continue
        role_candidates = _role_candidates(route)
        suggestions.append(
            {
                "method": route["method"],
                "path": route["path"],
                "source": {
                    "file": route["source"]["file"],
                    "line": route["source"].get("line"),
                },
                "scanner_primary_in_file": route["source"]["file"] in scanner_paths,
                "in_planned_source_scope": route["source"]["file"] in planned_paths,
                "required_role": route.get("required_role"),
                "role_name_candidates": role_candidates,
                "account_scenarios": [
                    "anonymous",
                    "authenticated test user",
                    *(
                        f"{role} test account, if policy confirms the role"
                        for role in role_candidates
                    ),
                ],
                "suggested_checks": checks[:4],
                "status": "proposal_requires_human_review",
            }
        )
        if len(suggestions) >= 50:
            break
    frontend_calls = (
        frontend_result.get("calls", []) if isinstance(frontend_result, dict) else []
    )
    route_keys = {(route["method"], route["path"]) for route in routes}
    unmatched_frontend = []
    if application_map is not None:
        unmatched_frontend = [
            call
            for call in frontend_calls
            if (call["method"], call["path"]) not in route_keys
            and (
                call["method"] != "GET_or_configured"
                or not any(route_path == call["path"] for _, route_path in route_keys)
            )
        ]
    return {
        "status": "generated",
        "source_routes": len(routes),
        "routes_with_scanner_primary_file": sum(
            route["source"]["file"] in scanner_paths for route in routes
        ),
        "routes_in_planned_source_scope": sum(
            route["source"]["file"] in planned_paths for route in routes
        ),
        "routes_outside_planned_source_scope": len(unplanned),
        "unplanned_route_examples": [
            {
                "method": route["method"],
                "path": route["path"],
                "source": route["source"],
            }
            for route in unplanned[:10]
        ],
        "frontend_api_calls": frontend_calls,
        "frontend_calls_without_exact_map_match": len(unmatched_frontend)
        if application_map is not None
        else None,
        "frontend_calls_needing_runtime_confirmation": unmatched_frontend[:20],
        "frontend_scan_status": frontend_result.get("status")
        if isinstance(frontend_result, dict)
        else "not_run",
        "frontend_scan_gaps": frontend_result.get("gaps", [])
        if isinstance(frontend_result, dict)
        else [],
        "suggestions": suggestions,
        "limitations": [
            "Suggestions are source-backed hypotheses, not vulnerabilities or executable test plans.",
            "Account credentials, role policy, mounted prefixes and runtime reachability require confirmation.",
            "Only direct handler calls are mapped; transitive service/database flow and browser-only routes are not established.",
        ],
    }


def _line_in_target(line: Any, target: DiscoveryTarget) -> bool:
    return (
        isinstance(line, int)
        and target.start_line is not None
        and target.end_line is not None
        and target.start_line <= line <= target.end_line
    )


def _route_hint(route: dict[str, Any]) -> dict[str, Any]:
    body = route.get("request_body")
    auth = route.get("authentication")
    return {
        "method": route["method"],
        "path": route["path"],
        "source_line": route["source"].get("line"),
        "parameters": [
            {"name": item.get("name"), "location": item.get("location")}
            for item in route["parameters"][:8]
        ],
        "body_fields": [
            item.get("name")
            for item in body.get("fields", [])[:8]
            if isinstance(item, dict)
        ]
        if isinstance(body, dict)
        else [],
        "authentication_observation": auth.get("status")
        if isinstance(auth, dict)
        else "unknown",
        "required_role": route.get("required_role"),
        "role_name_candidates": _role_candidates(route),
        "direct_calls": route.get("called_functions", [])[:8],
        "same_file_call_candidates": route.get("same_file_call_candidates", [])[:8],
        "direct_sql_tables": [
            table
            for item in route.get("database_interactions", [])[:4]
            if isinstance(item, dict)
            for table in item.get("tables", [])[:4]
        ],
        "same_file_sql_tables": [
            table
            for item in route.get("same_file_database_candidates", [])[:4]
            if isinstance(item, dict)
            for table in item.get("tables", [])[:4]
        ],
        "evidence_kind": "source_declaration_not_runtime_proof",
    }


def _role_candidates(route: dict[str, Any]) -> list[str]:
    names = [route["path"], *route.get("called_functions", [])]
    roles = {
        match.group(1).lower() for name in names for match in _ROLE_NAME.finditer(name)
    }
    if isinstance(route.get("required_role"), str):
        roles.add(route["required_role"].lower())
    return sorted(roles)[:5]


def _routes(application_map: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(application_map, dict):
        return []
    result = []
    for route in application_map.get("routes", [])[:250]:
        if not isinstance(route, dict) or not isinstance(route.get("source"), dict):
            continue
        source = route["source"]
        if not all(isinstance(route.get(key), str) for key in ("method", "path")):
            continue
        file = source.get("file")
        if (
            not isinstance(file, str)
            or not file
            or len(file) > 256
            or Path(file).is_absolute()
            or ".." in Path(file).parts
        ):
            continue
        if not isinstance(route.get("parameters"), list):
            continue
        method, path = route["method"].upper(), route["path"]
        if (
            method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
            or len(path) > 256
        ):
            continue
        parameters = [
            {
                "name": item["name"][:80],
                "location": str(item.get("location", "unknown"))[:40],
            }
            for item in route["parameters"][:30]
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]
        body = route.get("request_body")
        body_fields = []
        if isinstance(body, dict) and isinstance(body.get("fields"), list):
            body_fields = [
                {"name": item["name"][:80]}
                for item in body["fields"][:20]
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            ]
        raw_calls = route.get("called_functions")
        calls = (
            [item[:80] for item in raw_calls[:8] if isinstance(item, str)]
            if isinstance(raw_calls, list)
            else []
        )
        raw_database = route.get("database_interactions")
        database = []
        if isinstance(raw_database, list):
            for item in raw_database[:4]:
                if isinstance(item, dict) and isinstance(item.get("tables"), list):
                    database.append(
                        {
                            "tables": [
                                table[:80]
                                for table in item["tables"][:4]
                                if isinstance(table, str)
                            ]
                        }
                    )
        auth = route.get("authentication")
        auth_status = auth.get("status") if isinstance(auth, dict) else None
        raw_same_file_calls = route.get("same_file_call_candidates")
        raw_same_file_database = route.get("same_file_database_candidates")
        result.append(
            {
                "method": method,
                "path": path,
                "source": {
                    "file": file.replace("\\", "/"),
                    "line": source.get("line")
                    if type(source.get("line")) is int and source["line"] > 0
                    else None,
                },
                "parameters": parameters,
                "request_body": {"fields": body_fields},
                "authentication": {
                    "status": auth_status[:40]
                    if isinstance(auth_status, str)
                    else "unknown"
                },
                "required_role": route["required_role"][:80]
                if isinstance(route.get("required_role"), str)
                else None,
                "called_functions": calls,
                "database_interactions": database,
                "same_file_call_candidates": [
                    name[:80]
                    for name in (
                        raw_same_file_calls[:8]
                        if isinstance(raw_same_file_calls, list)
                        else []
                    )
                    if isinstance(name, str)
                ],
                "same_file_database_candidates": [
                    {
                        "tables": [
                            table[:80]
                            for table in item["tables"][:4]
                            if isinstance(table, str)
                        ]
                    }
                    for item in (
                        raw_same_file_database[:4]
                        if isinstance(raw_same_file_database, list)
                        else []
                    )
                    if isinstance(item, dict) and isinstance(item.get("tables"), list)
                ],
            }
        )
    return result

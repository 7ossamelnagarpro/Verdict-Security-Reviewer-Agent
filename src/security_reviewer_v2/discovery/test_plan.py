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


def build_discovery_test_plan(
    discovery: dict[str, Any],
    browser: dict[str, Any] | None = None,
    *,
    project_root: Path | None = None,
    project_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Create bounded proposals, never executable requests or security findings."""
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
            "No proposal is sent to ZAP, the browser, or the workflow runner automatically.",
            "Request bodies, expected statuses, credentials, authorization and cleanup need human review.",
        ],
    }


def approved_readonly_routes(
    plan_path: Path, *, project_root: Path, project_fingerprint: str
) -> tuple[str, ...]:
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
        (item["method"], item["path"], item["source"].split(":", 1)[0])
        for item in discover(root)["endpoints"]
    }
    paths: list[str] = []
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
        if ("GET", path, source_relative.as_posix()) not in declared:
            continue
        if path not in paths:
            paths.append(path)
        if len(paths) >= 20:
            break
    return tuple(paths)

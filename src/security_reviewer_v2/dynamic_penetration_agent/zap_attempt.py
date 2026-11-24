"""ZAP as one of the Agent's tools: one scoped active-scan attempt against ONE endpoint.

``scanners/zap_runtime.run_zap`` is a whole-origin, Docker-container-per-call scan (several minutes,
designed to run once per runtime session, not once per adaptive-loop attempt). Rather than pretending
the agent calls a lighter "ZAP request" that doesn't exist, this module runs the real tool, narrowed by
the ``scope_path`` parameter added to ``automation_plan``/``run_zap`` specifically for this use, and
treats the whole scoped run as ONE attempt (not one attempt per HTTP request). Because of that cost, the
controller only ever makes one ZAP attempt per hypothesis — see ``adaptive_controller``'s tool-specific
attempt cap.

Hard requirements inherited unchanged from ``run_zap`` (not relaxed here): active ZAP only runs against a
disposable Compose stack (never ``existing_url``), and the compose project/service name must be known.
When those aren't met, this raises :class:`ZapUnavailable` with the specific reason instead of running an
unscoped or mutating scan.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

from security_reviewer_v2.scanners.zap_runtime import run_zap


class ZapUnavailable(RuntimeError):
    """ZAP cannot run a scoped attempt here; the caller should fall back to another tool."""


def run_scoped_attempt(
    base_url: str, target_endpoint: str, *,
    stack_name: str | None, app_service: str | None,
    auth: Mapping[str, Any] | None = None, max_seconds: int = 180,
) -> dict[str, Any]:
    """Run one ZAP active scan scoped to ``target_endpoint`` and return a ``run_workflows``-shaped result.

    The returned shape (``{"workflows": [{"status": ..., "steps": [...]}]}``) matches
    ``scanners.runtime_workflows.run_workflows`` on purpose, so ``evidence_collector`` and
    ``evidence_evaluator`` read it without any ZAP-specific branching.
    """
    if not stack_name or not app_service:
        raise ZapUnavailable(
            "Active ZAP requires the penetration agent's own disposable Compose stack "
            "(stack_name and app_service); it does not run against an existing_url target."
        )
    with tempfile.TemporaryDirectory(prefix="verdict-pentest-zap-") as directory:
        runtime_path = Path(directory) / "runtime.json"
        runtime_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        try:
            run_zap(base_url, runtime_path, engine="zap-automated-scan", stack_name=stack_name,
                   app_service=app_service, auth=dict(auth) if auth else None,
                   scope_path=target_endpoint, max_seconds=max_seconds)
        except (ValueError, RuntimeError) as error:
            return _result("blocked", "blocked", target_endpoint,
                          actor=(auth or {}).get("username_field", "anonymous"),
                          reason=f"ZAP did not complete: {error}")
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))

    relevant = [item for item in runtime.get("results", [])
               if isinstance(item, dict) and item.get("path") == target_endpoint]
    actor = (auth or {}).get("username_field", "anonymous")
    if relevant:
        top = max(relevant, key=lambda item: {"high": 3, "medium": 2, "low": 1}.get(item.get("severity"), 0))
        return _result("completed", "violation", target_endpoint, actor=actor,
                      reason=f"ZAP active scan reported {len(relevant)} alert(s) at this exact path, "
                             f"highest severity {top.get('severity')}: {top.get('title')}.")
    return _result("completed", "passed", target_endpoint, actor=actor,
                  reason="ZAP active scan completed and reported no alert at this exact path.")


def _result(status: str, step_status: str, path: str, *, actor: str, reason: str) -> dict[str, Any]:
    return {"workflows": [{
        "id": "pentest_zap", "status": status,
        "steps": [{"step": 1, "actor": actor, "method": "ZAP_ACTIVE_SCAN", "path": path,
                  "security_check": True, "status": step_status, "reason": reason,
                  "http_status": None, "expected_status": []}],
    }]}

"""Playwright as one of the Agent's tools: one real authenticated browser visit to ONE endpoint.

Runs ``scripts/run_browser_probe.mjs`` (a new, minimal, single-page script — the existing
``run_browser_dast.mjs`` is a whole-site crawler and is not reused here because it has no concept of
"as this one account, check this one page"). The subprocess is bounded (timeout, loopback-only target,
GET-only interception inside the browser) the same way ``scanners/browser_runtime.py`` already bounds
its own Playwright subprocess.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "run_browser_probe.mjs"
_DENIED_STATUSES = {401, 403, 404}


class PlaywrightUnavailable(RuntimeError):
    """Playwright cannot run here (Node.js/script missing, or the target isn't an authorized loopback)."""


def run_single_page_attempt(
    base_url: str, target_endpoint: str, *,
    account: Mapping[str, Any] | None = None, timeout_seconds: int = 20,
) -> dict[str, Any]:
    """Visit ``target_endpoint`` in a real browser session and return a ``run_workflows``-shaped result."""
    node = shutil.which("node")
    parsed = urlsplit(base_url)
    try:
        loopback = parsed.hostname in {"localhost"} or ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = False
    actor = (account or {}).get("id", "anonymous")
    if not node:
        raise PlaywrightUnavailable("Node.js is unavailable; the Playwright probe was not run.")
    if not _SCRIPT.is_file():
        raise PlaywrightUnavailable("The Playwright probe script is unavailable.")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not loopback:
        raise PlaywrightUnavailable("The Playwright probe is restricted to an authorized loopback target.")

    try:
        completed = subprocess.run(
            [node, str(_SCRIPT), "--base-url", base_url, "--target-path", target_endpoint,
             "--account-json", json.dumps(dict(account) if account else None),
             "--timeout-ms", str(max(1000, timeout_seconds * 1000))],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout_seconds + 15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return _result("blocked", "blocked", target_endpoint, actor,
                       f"Playwright probe did not finish: {type(error).__name__}.")

    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    try:
        payload = json.loads(lines[-1]) if lines else {}
    except (ValueError, TypeError):
        payload = {}
    if not isinstance(payload, dict) or payload.get("status") != "completed":
        reason = "; ".join(payload.get("coverage_gaps", [])) if isinstance(payload, dict) else ""
        return _result("blocked", "blocked", target_endpoint, actor,
                       f"Playwright probe could not complete{(': ' + reason) if reason else '.'}")

    observed = [item for item in payload.get("observed_statuses", [])
               if isinstance(item, dict) and item.get("path") == target_endpoint]
    statuses = {item.get("status") for item in observed} or ({payload.get("document_status")}
                if payload.get("document_status") is not None else set())
    if not statuses:
        return _result("completed", "inconclusive", target_endpoint, actor,
                       "The browser never observed a same-origin response at this exact path.")
    if any(status not in _DENIED_STATUSES for status in statuses if isinstance(status, int)):
        served = sorted(s for s in statuses if isinstance(s, int))
        return _result("completed", "violation", target_endpoint, actor,
                       f"A real authenticated browser session as {actor} received HTTP {served} at this "
                       f"path, not one of the expected denial statuses {sorted(_DENIED_STATUSES)}.")
    return _result("completed", "passed", target_endpoint, actor,
                   f"The browser session as {actor} only ever observed denial statuses "
                   f"{sorted(statuses)} at this path.")


def _result(status: str, step_status: str, path: str, actor: str, reason: str) -> dict[str, Any]:
    return {"workflows": [{
        "id": "pentest_playwright", "status": status,
        "steps": [{"step": 1, "actor": actor, "method": "BROWSER_GET", "path": path,
                  "security_check": True, "status": step_status, "reason": reason,
                  "http_status": None, "expected_status": []}],
    }]}

"""Optional bounded browser crawl for JavaScript applications.

The runner is deliberately additive: when Playwright is not installed it
writes an explicit blocked artifact and leaves the ordinary HTTP/ZAP evidence
intact. It never submits forms, clicks destructive controls, or visits a
different origin.
"""
from __future__ import annotations

import json
import ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def run_browser_dast(base_url: str, runtime_path: Path, output_path: Path, *,
                     max_pages: int = 12, seed_paths: tuple[str, ...] = ()) -> dict[str, Any]:
    parsed = urlsplit(base_url)
    payload: dict[str, Any] = {
        "schema_version": "1.0", "source": "playwright-browser-runtime",
        "target": base_url, "max_pages": max_pages,
    }
    node = shutil.which("node")
    script = Path(__file__).resolve().parents[3] / "scripts" / "run_browser_dast.mjs"
    try:
        loopback = parsed.hostname in {"localhost"} or ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if not node:
        payload.update(status="blocked", pages_visited=0, results=[],
                       coverage_gaps=["Node.js is unavailable; browser DAST was not run."])
    elif not script.is_file():
        payload.update(status="blocked", pages_visited=0, results=[],
                       coverage_gaps=["The reviewed browser runner is unavailable."])
    elif parsed.scheme not in {"http", "https"} or not parsed.hostname or not loopback:
        payload.update(status="blocked", pages_visited=0, results=[],
                       coverage_gaps=["Browser DAST is restricted to an authorized loopback target."])
    else:
        try:
            for path in seed_paths:
                if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                        or "\\" in path or "#" in path or len(path) > 500
                        or any(ord(char) < 32 for char in path)):
                    raise ValueError("Browser seed paths must be bounded same-origin GET paths")
            completed = subprocess.run(
                [node, str(script), "--base-url", base_url, "--max-pages", str(max_pages),
                 "--seed-paths-json", json.dumps(seed_paths)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, check=False,
            )
            lines = [line for line in completed.stdout.splitlines() if line.strip()]
            try:
                child = json.loads(lines[-1]) if lines else {}
            except (ValueError, TypeError):
                child = {}
            if completed.returncode == 0 and isinstance(child, dict):
                payload.update(child)
            else:
                payload.update(status="blocked", pages_visited=0, results=[],
                               coverage_gaps=["Playwright browser crawl could not start; install the optional browser dependency.",
                                              (completed.stderr or completed.stdout)[-1000:]])
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            payload.update(status="blocked", pages_visited=0, results=[],
                           coverage_gaps=[f"Browser DAST stopped safely: {type(error).__name__}."])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if runtime_path.is_file():
        try:
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            runtime["browser"] = {key: value for key, value in payload.items() if key not in {"results"}}
            runtime.setdefault("results", []).extend(payload.get("results", []))
            runtime.setdefault("coverage_notes", []).extend(payload.get("coverage_gaps", []))
            runtime_path.write_text(json.dumps(runtime, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError, TypeError):
            # The standalone artifact remains authoritative if an older runtime
            # file is malformed; never turn browser optional coverage into a
            # false successful DAST result.
            pass
    return payload

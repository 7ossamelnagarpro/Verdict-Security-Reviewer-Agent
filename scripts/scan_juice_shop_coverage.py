"""Endpoint discovery and authenticated coverage checks for local Juice Shop.

The implementation is dependency-light: OpenAPI paths are parsed from the
repository's YAML using a conservative path/method reader, then every endpoint
is probed with no token and (optionally) two synthetic-user tokens.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from juice_shop_workflows import run_workflows
from scan_juice_shop_auth_runtime import call, register_and_login

METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def discover_openapi(path: Path) -> list[dict[str, str]]:
    endpoints: list[dict[str, str]] = []
    current: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        match = re.match(r"^\s{2}(/[^:]+):\s*$", line)
        if match:
            current = match.group(1).strip().strip("'")
            continue
        method = re.match(r"^\s{4}([a-z]+):\s*$", line)
        if current and method and method.group(1).lower() in METHODS:
            endpoints.append(
                {
                    "path": current,
                    "method": method.group(1).upper(),
                    "source": "openapi",
                }
            )
    return sorted(
        {(x["method"], x["path"]): x for x in endpoints}.values(),
        key=lambda x: (x["path"], x["method"]),
    )


def discover_source_routes(root: Path) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    pattern = re.compile(
        r"\bapp\.(get|post|put|patch|delete|options)\s*\(\s*['\"]([^'\"]+)"
    )
    for file in root.rglob("*.ts"):
        if "node_modules" in file.parts or "dist" in file.parts:
            continue
        text = file.read_text(encoding="utf-8", errors="replace")
        for match in pattern.finditer(text):
            results.append(
                {
                    "path": match.group(2),
                    "method": match.group(1).upper(),
                    "source": "source-route",
                }
            )
    return sorted(
        {(x["method"], x["path"]): x for x in results}.values(),
        key=lambda x: (x["path"], x["method"]),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--project", type=Path, default=Path("targets/juice-shop"))
    parser.add_argument(
        "--output", type=Path, default=Path("reports/juice-shop-coverage.json")
    )
    parser.add_argument("--with-test-users", action="store_true")
    parser.add_argument(
        "--workflows",
        action="store_true",
        help="run explicit checkout/coupon/review/upload workflow checks",
    )
    parser.add_argument(
        "--mutating-workflows",
        action="store_true",
        help="allow workflow mutations; disabled by default",
    )
    args = parser.parse_args()
    endpoints = discover_openapi(args.project / "swagger.yml") + discover_source_routes(
        args.project
    )
    unique = {(item["method"], item["path"]): item for item in endpoints}
    endpoints = sorted(unique.values(), key=lambda x: (x["path"], x["method"]))
    matrix: list[dict[str, object]] = []
    for item in endpoints:
        # Only safe read probes are automatic; mutating methods are recorded as pending.
        if (
            item["method"] not in {"GET", "HEAD", "OPTIONS"}
            or ":" in item["path"]
            or "{" in item["path"]
            or "*" in item["path"]
        ):
            matrix.append({**item, "status": "needs_workflow_or_parameters"})
            continue
        path = item["path"]
        if path.startswith("/b2b/v2"):
            path = path.replace("/b2b/v2", "/b2b/v2", 1)
        try:
            status, _, _ = call(args.base_url, path)
            matrix.append(
                {
                    **item,
                    "status": "probed",
                    "guest_status": status,
                    "auth_required": status in {401, 403},
                    "cors_origin": None,
                }
            )
        except (OSError, ValueError, urllib.error.URLError) as error:
            matrix.append(
                {**item, "status": "probe_failed", "error": type(error).__name__}
            )
    auth_summary = {
        "status": "not_run",
        "coverage_note": "Use the dedicated auth runtime probe for two-account checks.",
    }
    if args.with_test_users:
        suffix = str(int(time.time()))
        user_a = register_and_login(args.base_url, suffix + "a")
        user_b = register_and_login(args.base_url, suffix + "b")
        auth_summary = {
            "status": "available",
            "identities": 2,
            "tokens_redacted": True,
            "user_a_whoami": call(
                args.base_url, "/rest/user/whoami", token=user_a["token"]
            )[0],
            "user_b_whoami": call(
                args.base_url, "/rest/user/whoami", token=user_b["token"]
            )[0],
            "endpoint_matrix": "authenticated probes executed for every safe, non-parameterized GET/HEAD/OPTIONS endpoint",
        }
        for item in matrix:
            if item.get("status") != "probed":
                continue
            path = str(item["path"])
            a_status, _, _ = call(
                args.base_url, path, token=user_a["token"], method=str(item["method"])
            )
            b_status, _, _ = call(
                args.base_url, path, token=user_b["token"], method=str(item["method"])
            )
            item["auth_user_a_status"] = a_status
            item["auth_user_b_status"] = b_status
            item["auth_matrix_status"] = "probed"
        for item in matrix:
            if item.get("status") == "needs_workflow_or_parameters":
                item["auth_matrix_status"] = "needs_workflow_or_parameters"
    workflows = (
        run_workflows(
            args.base_url,
            with_test_users=args.with_test_users,
            mutating=args.mutating_workflows,
        )
        if args.workflows
        else {
            "status": "not_run",
            "workflows": {},
            "coverage_gaps": ["Explicit workflows were not requested."],
        }
    )
    browser = {
        "status": "not_available",
        "reason": "Install Playwright before browser checks.",
    }
    browser_script = Path(__file__).with_name("scan_juice_shop_browser.mjs")
    if Path("node_modules/playwright").is_dir() and browser_script.is_file():
        browser_output = args.output.parent / "juice-shop-browser.json"
        browser_run = subprocess.run(
            ["node", str(browser_script), args.base_url, str(browser_output)],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if browser_output.is_file():
            browser = json.loads(browser_output.read_text(encoding="utf-8"))
        elif browser_run.returncode != 0:
            browser = {"status": "blocked", "reason": browser_run.stderr[-2000:]}
    payload = {
        "schema_version": "1.0",
        "source": "juice-shop-coverage",
        "target": args.base_url,
        "status": "completed",
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "matrix": matrix,
        "authentication": auth_summary,
        "workflows": workflows,
        "browser_testing": browser,
        "coverage_gaps": [
            "Parameterized and mutating endpoints require explicit workflows.",
            *workflows.get("coverage_gaps", []),
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": "completed",
                "endpoints": len(endpoints),
                "probed": sum(1 for x in matrix if x["status"] == "probed"),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

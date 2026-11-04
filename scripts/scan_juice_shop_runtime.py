"""Bounded, non-destructive runtime checks for a local OWASP Juice Shop."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(
        base.rstrip("/") + path, data=body, method=method, headers=headers or {}
    )
    try:
        response = urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return (
            response.status,
            dict(response.headers.items()),
            response.read(256 * 1024),
        )


def finding(
    rule_id: str,
    title: str,
    path: str,
    vulnerable: bool,
    evidence: dict[str, object],
    severity: str = "medium",
    confidence: str = "high",
) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "title": title,
        "path": path,
        "vulnerable": vulnerable,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
    }


def run(base: str) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    status, _, body = request(base, "/")
    if status != 200 or b"Juice Shop" not in body:
        raise RuntimeError("Target is not a reachable OWASP Juice Shop instance")

    # Authorization boundary probes: no credentials and no state changes.
    for path, rule, title in (
        (
            "/api/Users",
            "juice-shop.unauthenticated-users-api",
            "Users API accessible without authentication",
        ),
        (
            "/rest/basket/1",
            "juice-shop.unauthenticated-basket",
            "Basket accessible without authentication",
        ),
    ):
        code, _, _ = request(base, path)
        checks.append(
            finding(
                rule,
                title,
                path,
                code not in {401, 403},
                {"status": code, "expected_denied_statuses": [401, 403]},
                "high",
            )
        )

    # Search reflection probe. A safe marker is enough; no browser is launched.
    marker = "SECURITY_REVIEWER_XSS_MARKER"
    code, _, response = request(
        base, "/rest/products/search?q=" + urllib.parse.quote(marker)
    )
    reflected = marker.encode() in response
    checks.append(
        finding(
            "juice-shop.reflected-input",
            "Search input reflected by API",
            "/rest/products/search",
            reflected,
            {"status": code, "marker_reflected": reflected},
            "medium",
        )
    )

    # Error disclosure probe with a malformed search value; retain only marker presence.
    code, _, response = request(base, "/rest/products/search?q=%27%22%22%22")
    text = response.decode("utf-8", errors="replace").lower()
    leaked = code >= 500 and any(
        token in text
        for token in ("sql", "sqlite", "sequelize", "stack trace", "syntax error")
    )
    checks.append(
        finding(
            "juice-shop.verbose-api-error",
            "Verbose error returned by product search",
            "/rest/products/search",
            leaked,
            {"status": code, "error_marker_present": leaked},
            "medium",
        )
    )

    # CORS policy probe. A reflected arbitrary origin plus credentials is dangerous.
    origin = "https://security-reviewer.invalid"
    code, headers, _ = request(base, "/", headers={"Origin": origin})
    reflected_origin = headers.get("Access-Control-Allow-Origin") == origin
    credentials = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    checks.append(
        finding(
            "juice-shop.cors-reflection",
            "Arbitrary Origin reflected with credentials",
            "/",
            reflected_origin and credentials,
            {
                "status": code,
                "origin_reflected": reflected_origin,
                "allow_credentials": credentials,
            },
            "high",
        )
    )

    # Public product endpoint is recorded as coverage evidence, not a finding.
    code, _, _ = request(base, "/api/Products/1")
    checks.append(
        finding(
            "juice-shop.public-products-api",
            "Public product API probe",
            "/api/Products/1",
            False,
            {
                "status": code,
                "note": "Public catalog access is expected and is not classified as a vulnerability.",
            },
            "info",
        )
    )

    return {
        "schema_version": "1.0",
        "source": "juice-shop-runtime",
        "target": base,
        "status": "completed",
        "results": checks,
        "coverage_notes": [
            "Checks are non-destructive and unauthenticated.",
            "Authorization and business-logic coverage requires configured test identities.",
            "A negative result means this probe did not confirm the behavior; it is not proof of absence.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument(
        "--output", type=Path, default=Path("reports/juice-shop-runtime.json")
    )
    args = parser.parse_args()
    result = run(args.base_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "findings": sum(1 for x in result["results"] if x["vulnerable"]),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

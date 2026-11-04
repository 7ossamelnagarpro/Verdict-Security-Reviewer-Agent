"""Bounded authorization checks for the educational tt/VulnShop target."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path


def client(base: str, username: str, password: str):
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    request = urllib.request.Request(
        base.rstrip("/") + "/login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with opener.open(request, timeout=5) as response:
            login_status = response.status
    except urllib.error.HTTPError as error:
        login_status = error.code
    return opener, login_status


def get(opener, url: str, headers: dict[str, str] | None = None):
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with opener.open(request, timeout=5) as response:
            return (
                response.status,
                response.read(256 * 1024),
                dict(response.headers.items()),
            )
    except urllib.error.HTTPError as error:
        return error.code, error.read(256 * 1024), dict(error.headers.items())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    alice, alice_login = client(base, "alice", "alice123")
    bob, bob_login = client(base, "bob", "bob123")
    results = []

    # Compare Bob's known order/profile response with Alice's response.
    for path, title in (
        ("/orders/101", "IDOR: cross-user order access"),
        ("/profile/2", "IDOR: cross-user profile access"),
    ):
        bob_status, bob_body, _ = get(bob, base + path)
        alice_status, alice_body, _ = get(alice, base + path)
        vulnerable = (
            bob_status == 200
            and alice_status == 200
            and bool(bob_body)
            and alice_body == bob_body
        )
        results.append(
            {
                "rule_id": "auth.idor",
                "title": title,
                "path": path,
                "vulnerable": vulnerable,
                "severity": "high",
                "confidence": "high" if vulnerable else "medium",
                "evidence": {
                    "owner_status": bob_status,
                    "cross_user_status": alice_status,
                    "response_equal": alice_body == bob_body,
                },
            }
        )

    admin_status, admin_body, _ = get(alice, base + "/admin")
    admin_vulnerable = admin_status == 200 and bool(admin_body)
    results.append(
        {
            "rule_id": "auth.broken-access-control",
            "title": "Admin panel accessible to non-admin",
            "path": "/admin",
            "vulnerable": admin_vulnerable,
            "severity": "high",
            "confidence": "high" if admin_vulnerable else "medium",
            "evidence": {"alice_status": admin_status},
        }
    )

    cors_status, _, cors_headers = get(
        alice, base + "/", {"Origin": "https://attacker.example"}
    )
    allow_origin = cors_headers.get("Access-Control-Allow-Origin", "")
    allow_credentials = cors_headers.get("Access-Control-Allow-Credentials", "")
    cors_vulnerable = (
        allow_origin == "https://attacker.example"
        and allow_credentials.lower() == "true"
    )
    results.append(
        {
            "rule_id": "web.cors-reflection",
            "title": "CORS reflects arbitrary origin with credentials",
            "path": "/",
            "vulnerable": cors_vulnerable,
            "severity": "high",
            "confidence": "high" if cors_vulnerable else "medium",
            "evidence": {
                "status": cors_status,
                "allow_origin": allow_origin,
                "allow_credentials": allow_credentials,
            },
        }
    )

    payload = {
        "schema_version": "1.0",
        "source": "tt-authorization-runtime",
        "target": base,
        "status": "completed",
        "login": {"alice_status": alice_login, "bob_status": bob_login},
        "results": results,
        "coverage_notes": [
            "Two synthetic local users were used.",
            "A negative result is not proof of authorization correctness.",
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
                "findings": sum(1 for x in results if x["vulnerable"]),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

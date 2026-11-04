"""Opt-in two-account authorization probes for a local Juice Shop lab."""

from __future__ import annotations

import argparse
import base64
import json
import time
import urllib.error
import urllib.request
from pathlib import Path


def call(
    base: str,
    path: str,
    method: str = "GET",
    payload: dict | None = None,
    token: str | None = None,
):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        base.rstrip("/") + path, data=body, headers=headers, method=method
    )
    try:
        response = urllib.request.urlopen(request, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(256 * 1024)
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            parsed = None
        return response.status, parsed, raw


def register_and_login(base: str, suffix: str) -> dict[str, object]:
    email = f"security-reviewer-{suffix}@example.invalid"
    password = "SecurityReviewer-Only-2026!"
    registration = {
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 7, "question": "Name of your favorite pet?"},
        "securityAnswer": f"lab-answer-{suffix}",
    }
    status, _, _ = call(base, "/api/Users", "POST", registration)
    if status not in {200, 201}:
        raise RuntimeError(f"test account registration failed with HTTP {status}")
    status, parsed, _ = call(
        base, "/rest/user/login", "POST", {"email": email, "password": password}
    )
    if status != 200 or not isinstance(parsed, dict):
        raise RuntimeError(f"test account login failed with HTTP {status}")
    auth = parsed.get("authentication") or {}
    token = auth.get("token") if isinstance(auth, dict) else None
    user_id = auth.get("id") if isinstance(auth, dict) else None
    basket_id = auth.get("bid") if isinstance(auth, dict) else None
    if user_id is None:
        # Juice Shop versions commonly put the user id in the JWT subject.
        try:
            segment = token.split(".")[1]
            segment += "=" * (-len(segment) % 4)
            claims = json.loads(base64.urlsafe_b64decode(segment).decode())
            user_id = claims.get("id") or claims.get("userId") or claims.get("sub")
        except (IndexError, ValueError, TypeError, json.JSONDecodeError):
            user_id = None
    if not isinstance(token, str) or not token:
        raise RuntimeError("login response did not contain a token")
    return {"email": email, "token": token, "user_id": user_id, "basket_id": basket_id}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument(
        "--output", type=Path, default=Path("reports/juice-shop-auth-runtime.json")
    )
    args = parser.parse_args()
    suffix = str(int(time.time()))
    user_a = register_and_login(args.base_url, suffix + "a")
    user_b = register_and_login(args.base_url, suffix + "b")
    results = []
    # Never write tokens to the report. Probe a small deterministic basket-id set.
    for basket_id in range(1, 6):
        a_status, _a_json, a_raw = call(
            args.base_url, f"/rest/basket/{basket_id}", token=user_a["token"]
        )
        b_status, _b_json, b_raw = call(
            args.base_url, f"/rest/basket/{basket_id}", token=user_b["token"]
        )
        same_protected_resource = a_status == b_status == 200 and a_raw == b_raw
        results.append(
            {
                "rule_id": "juice-shop.cross-user-basket-access",
                "title": "Cross-user basket access",
                "path": f"/rest/basket/{basket_id}",
                "vulnerable": same_protected_resource,
                "severity": "high",
                "confidence": "high" if same_protected_resource else "medium",
                "evidence": {
                    "user_a_status": a_status,
                    "user_b_status": b_status,
                    "identical_response": same_protected_resource,
                },
            }
        )
    # User API must not allow one account to read the other account without a policy decision.
    if isinstance(user_b["user_id"], int):
        status, _, _ = call(
            args.base_url, f"/api/Users/{user_b['user_id']}", token=user_a["token"]
        )
        results.append(
            {
                "rule_id": "juice-shop.cross-user-profile-access",
                "title": "Cross-user profile API access",
                "path": f"/api/Users/{user_b['user_id']}",
                "vulnerable": status == 200,
                "severity": "high",
                "confidence": "high" if status == 200 else "medium",
                "evidence": {
                    "user_a_status": status,
                    "expected_denied_statuses": [401, 403],
                },
            }
        )
    # Administrative configuration must not be readable with an ordinary account.
    for path, rule, title in (
        (
            "/rest/admin/application-configuration",
            "juice-shop.unauthenticated-admin-configuration",
            "Admin configuration accessible to normal user",
        ),
        (
            "/rest/user/authentication-details",
            "juice-shop.authentication-details-disclosure",
            "Authentication details exposed to normal user",
        ),
    ):
        status, _, _ = call(args.base_url, path, token=user_a["token"])
        results.append(
            {
                "rule_id": rule,
                "title": title,
                "path": path,
                "vulnerable": status == 200,
                "severity": "high",
                "confidence": "high" if status == 200 else "medium",
                "evidence": {"status": status, "expected_denied_statuses": [401, 403]},
            }
        )
    payload = {
        "schema_version": "1.0",
        "source": "juice-shop-auth-runtime",
        "target": args.base_url,
        "status": "completed",
        "results": results,
        "coverage_notes": [
            "Two synthetic accounts were created in the local lab.",
            "Tokens and passwords were not written to the report.",
            "A negative result does not prove authorization correctness for all resources.",
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
                "findings": sum(1 for item in results if item["vulnerable"]),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

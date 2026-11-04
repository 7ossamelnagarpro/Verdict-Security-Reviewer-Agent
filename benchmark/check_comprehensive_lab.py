"""Independent live checks for the disposable comprehensive target.

Run only against the loopback Compose stack. This file is outside the target.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import subprocess
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "targets" / "verdict-comprehensive-lab" / "compose.yaml"
BASE = "http://127.0.0.1:8091"
PASSWORDS = {
    "user_a": "UserA-Lab-Only-1",
    "user_b": "UserB-Lab-Only-1",
    "admin": "Admin-Lab-Only-1",
}


def call(
    method: str, path: str, *, token: str | None = None, **kwargs
) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(method, BASE + path, headers=headers, timeout=8, **kwargs)


def login(name: str, *, verified: bool = False) -> str:
    path = "/auth/checked-login" if verified else "/auth/login"
    response = call("POST", path, json={"username": name, "password": PASSWORDS[name]})
    assert response.status_code == 200, (
        path,
        response.status_code,
        response.text[:200],
    )
    return response.json()["access_token"]


def forged_role(token: str) -> str:
    header, payload, _ = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["role"] = "admin"
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{encoded}."


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--no-reset", action="store_true", help="Reuse current target data"
    )
    args = parser.parse_args()
    if not args.no_reset:
        subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                "verdict-comprehensive-lab",
                "-f",
                str(COMPOSE),
                "exec",
                "-T",
                "api",
                "python",
                "-m",
                "api.seed",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    assert call("GET", "/healthz").status_code == 200
    weak_a, weak_b, weak_admin = (login(name) for name in ("user_a", "user_b", "admin"))
    strong_a, strong_b, strong_admin = (
        login(name, verified=True) for name in ("user_a", "user_b", "admin")
    )
    results: list[dict[str, str | bool]] = []

    def check(case_id: str, fn) -> None:
        try:
            value = fn()
            if not value:
                raise AssertionError("Expected observation was not present")
            results.append({"id": case_id, "passed": True})
        except Exception as error:
            results.append(
                {
                    "id": case_id,
                    "passed": False,
                    "error": f"{type(error).__name__}: {error}",
                }
            )

    check("C01", lambda: call("GET", "/orders/2", token=weak_a).status_code == 200)
    check("C02", lambda: call("GET", "/profiles/2", token=weak_a).status_code == 200)
    check(
        "C03",
        lambda: (
            call(
                "POST",
                "/auth/legacy-login",
                json={"username": "admin' --", "password": "bad"},
            ).status_code
            == 200
        ),
    )
    check(
        "C04",
        lambda: (
            "service"
            in call("GET", "/catalog/search", params={"q": "%' OR 1=1 --"}).text
        ),
    )
    check(
        "C05",
        lambda: (
            "<script>alert(1)</script>"
            in call(
                "GET", "/catalog/search", params={"q": "<script>alert(1)</script>"}
            ).text
        ),
    )

    xss = "<img src=x onerror=alert(1)>"

    def stored_xss() -> bool:
        posted = call("POST", "/comments", token=weak_a, json={"body": xss})
        return posted.status_code == 200 and xss in call("GET", "/comments").text

    check("C06", stored_xss)

    check("C07", lambda: call("GET", "/admin/users", token=weak_a).status_code == 200)
    check(
        "C08",
        lambda: (
            "INTERNAL-LAB-NOTE"
            in call("GET", "/files", params={"name": "../private/internal.txt"}).text
        ),
    )
    check(
        "C10",
        lambda: (
            call("GET", "/session/whoami", cookies={"lab_session": "session-3"})
            .json()
            .get("username")
            == "admin"
        ),
    )
    check("C11", lambda: "app_secret" in call("GET", "/debug/config").json())
    check("C12", lambda: "unavailable_column" in call("GET", "/errors/query").text)

    def unlimited_login() -> bool:
        for _ in range(4):
            response = call(
                "POST", "/auth/login", json={"username": "user_a", "password": "wrong"}
            )
            if response.status_code != 401:
                return False
        return (
            call(
                "POST",
                "/auth/login",
                json={"username": "user_a", "password": PASSWORDS["user_a"]},
            ).status_code
            == 200
        )

    check("C13", unlimited_login)

    check(
        "C14",
        lambda: (
            call(
                "GET", "/healthz", headers={"Origin": "https://untrusted.example"}
            ).headers.get("Access-Control-Allow-Origin")
            in {"*", "https://untrusted.example"}
        ),
    )

    def html_upload() -> bool:
        upload = call(
            "POST",
            "/uploads",
            token=weak_a,
            files={"file": ("note.html", b"<script>alert(1)</script>", "text/html")},
        )
        if upload.status_code != 200:
            return False
        served = call("GET", f"/uploads/{upload.json()['id']}")
        return served.status_code == 200 and "text/html" in served.headers.get(
            "Content-Type", ""
        )

    check("C15", html_upload)

    check(
        "C16",
        lambda: (
            call("GET", "/admin/token-report", token=forged_role(weak_a)).status_code
            == 200
        ),
    )
    check(
        "C17",
        lambda: (
            call("POST", "/auth/refresh", token=forged_role(weak_a)).status_code == 200
        ),
    )

    def assigned_order() -> bool:
        response = call(
            "POST",
            "/orders",
            token=weak_a,
            json={
                "item": "widget",
                "quantity": 1,
                "owner_id": 2,
                "unit_price": 0.01,
                "status": "paid",
            },
        )
        return (
            response.status_code == 200
            and response.json()["owner_id"] == 2
            and float(response.json()["unit_price"]) == 0.01
        )

    check("C18", assigned_order)

    def create_weak_order() -> int:
        response = call(
            "POST",
            "/orders",
            token=weak_a,
            json={"item": "widget", "quantity": 1, "unit_price": 100},
        )
        assert response.status_code == 200, response.text
        return response.json()["id"]

    weak_order = create_weak_order()
    check(
        "C20",
        lambda: (
            float(
                call(
                    "POST",
                    "/orders",
                    token=weak_a,
                    json={"item": "widget", "quantity": 1, "unit_price": 0.01},
                ).json()["unit_price"]
            )
            == 0.01
        ),
    )
    check(
        "C21",
        lambda: (
            float(
                call(
                    "POST",
                    f"/orders/{weak_order}/apply-coupon",
                    token=weak_a,
                    json={"code": "WELCOME20", "discount": 99},
                ).json()["discount"]
            )
            == 99
        ),
    )

    paid = call("POST", f"/orders/{weak_order}/pay", token=weak_a)
    check(
        "C22",
        lambda: (
            paid.status_code == 200
            and call("POST", f"/orders/{weak_order}/pay", token=weak_a).status_code
            == 200
        ),
    )
    check(
        "C23",
        lambda: (
            call("POST", f"/orders/{weak_order}/cancel", token=weak_a)
            .json()
            .get("status")
            == "cancelled"
        ),
    )
    check(
        "C19",
        lambda: (
            paid.status_code == 200
            and call("GET", f"/invoices/{paid.json()['id']}", token=weak_b).status_code
            == 200
        ),
    )
    check("C24", lambda: "ssn" in call("GET", "/me", token=weak_a).json())
    check(
        "C25",
        lambda: (
            call(
                "POST",
                "/jobs",
                token=weak_a,
                json={"kind": "echo", "payload": {}, "run_as": "admin"},
            )
            .json()
            .get("run_as")
            == "admin"
        ),
    )

    bad_destination = "http://other-internal:9000/mock-external/webhook"

    def wrong_webhook_host() -> bool:
        created = call(
            "POST",
            "/webhooks",
            token=weak_a,
            json={"target_url": bad_destination, "body": {"hello": "lab"}},
        )
        if created.status_code != 200:
            return False
        job_id = created.json()["id"]
        for _ in range(15):
            jobs = call("GET", "/admin/jobs", token=weak_admin).json()
            match = next((job for job in jobs if job["id"] == job_id), None)
            if match and match["status"] == "complete":
                return True
            time.sleep(1)
        return False

    check("C26", wrong_webhook_host)

    def sensitive_log() -> bool:
        logged = subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                "verdict-comprehensive-lab",
                "-f",
                str(COMPOSE),
                "logs",
                "--no-color",
                "api",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return "app_secret=lab-only-not-a-real-secret" in logged.stdout

    check("C27", sensitive_log)
    check(
        "C28",
        lambda: (
            "APP_SECRET: lab-only-not-a-real-secret"
            in COMPOSE.read_text(encoding="utf-8")
        ),
    )

    def cross_service() -> bool:
        created = call(
            "POST",
            "/webhooks",
            token=weak_a,
            json={
                "target_url": "http://mock-external:9000/webhook",
                "body": {"test": True},
                "run_as": "admin",
            },
        )
        if created.status_code != 200:
            return False
        job_id = created.json()["id"]
        for _ in range(15):
            jobs = call("GET", "/admin/jobs", token=weak_admin).json()
            match = next((job for job in jobs if job["id"] == job_id), None)
            if match and match["status"] == "complete":
                return match["result"].get("worker_identity") == "admin"
            time.sleep(1)
        return False

    check("C29", cross_service)

    def reset_reuse() -> bool:
        request = call("POST", "/auth/reset/request", json={"username": "user_b"})
        if request.status_code != 200:
            return False
        token = request.json()["reset_token"]
        first = call(
            "POST",
            "/auth/reset/confirm",
            json={"token": token, "password": "new-lab-password"},
        )
        second = call(
            "POST",
            "/auth/reset/confirm",
            json={"token": token, "password": PASSWORDS["user_b"]},
        )
        return first.status_code == 200 and second.status_code == 200

    check("N01", reset_reuse)

    check(
        "N02",
        lambda: (
            call(
                "GET",
                "/auth/continue",
                params={"next": "https://untrusted.example/"},
                allow_redirects=False,
            ).headers.get("Location")
            == "https://untrusted.example/"
        ),
    )
    check(
        "N03",
        lambda: (
            call("POST", "/integrations/hook", data=b'{"event":"order"}').status_code
            == 200
        ),
    )
    check(
        "N04",
        lambda: (
            call("GET", "/orders/1/notes/2", token=weak_a).json().get("order_id") == 2
        ),
    )
    check(
        "N06",
        lambda: (
            "httponly"
            not in call("GET", "/session/start", params={"username": "user_a"})
            .headers.get("Set-Cookie", "")
            .lower()
        ),
    )
    check("N07", lambda: "Content-Security-Policy" not in call("GET", "/view").headers)

    # A role change is last because it mutates the seeded administrator.
    def stale_role() -> bool:
        changed = call(
            "POST", "/admin/roles/3", token=strong_admin, json={"role": "user"}
        )
        return (
            changed.status_code == 200
            and call("GET", "/admin/token-report", token=weak_admin).status_code == 200
            and call("GET", "/admin/current-report", token=strong_admin).status_code
            == 403
        )

    check("N05", stale_role)

    # Matched controls use separate opaque credentials and similar legitimate operations.
    check(
        "S01",
        lambda: call("GET", "/orders/2/verified", token=strong_a).status_code == 403,
    )
    check(
        "S02",
        lambda: (
            call("GET", "/profiles/2/verified", token=strong_a).status_code == 403
            and call("GET", "/profiles/1/verified", token=strong_a).status_code == 200
        ),
    )
    check(
        "S03",
        lambda: (
            call(
                "POST",
                "/auth/checked-login",
                json={"username": "admin' --", "password": "bad"},
            ).status_code
            == 401
        ),
    )
    check(
        "S04",
        lambda: (
            "service"
            not in call("GET", "/catalog/query", params={"q": "%' OR 1=1 --"}).text
        ),
    )
    check(
        "S05",
        lambda: (
            "&lt;script&gt;"
            in call(
                "GET", "/catalog/query", params={"q": "<script>alert(1)</script>"}
            ).text
        ),
    )
    check("S06", lambda: xss not in call("GET", "/forum/messages").text)
    check("S07", lambda: call("GET", "/admin/audit", token=strong_a).status_code == 403)
    check(
        "S08",
        lambda: (
            call(
                "GET", "/files/verified", params={"name": "../private/internal.txt"}
            ).status_code
            == 404
            and call(
                "GET", "/files/verified", params={"name": "manual.txt"}
            ).status_code
            == 200
        ),
    )
    check(
        "S09",
        lambda: call("GET", "/errors/checked").text.find("unavailable_column") == -1,
    )

    def limited() -> bool:
        for _ in range(3):
            if (
                call(
                    "POST",
                    "/auth/limited-login",
                    json={"username": "user_a", "password": "wrong"},
                ).status_code
                != 401
            ):
                return False
        return (
            call(
                "POST",
                "/auth/limited-login",
                json={"username": "user_a", "password": PASSWORDS["user_a"]},
            ).status_code
            == 429
        )

    check("S10", limited)

    def safe_upload() -> bool:
        rejected = call(
            "POST",
            "/documents",
            token=strong_a,
            files={"file": ("note.html", b"<script>alert(1)</script>", "text/html")},
        )
        accepted = call(
            "POST",
            "/documents",
            token=strong_a,
            files={"file": ("note.txt", b"hello", "text/plain")},
        )
        if accepted.status_code != 200:
            return False
        served = call("GET", f"/documents/{accepted.json()['id']}")
        return (
            rejected.status_code == 400
            and served.status_code == 200
            and "attachment" in served.headers.get("Content-Disposition", "")
        )

    check("S11", safe_upload)

    def safe_order() -> bool:
        response = call(
            "POST",
            "/orders/verified",
            token=strong_a,
            json={
                "item": "widget",
                "quantity": 1,
                "owner_id": 2,
                "unit_price": 0.01,
                "status": "paid",
            },
        )
        return (
            response.status_code == 200
            and response.json()["owner_id"] == 1
            and float(response.json()["unit_price"]) == 100
            and response.json()["status"] == "new"
        )

    check("S12", safe_order)

    safe_order_response = call(
        "POST",
        "/orders/verified",
        token=strong_a,
        json={"item": "widget", "quantity": 1},
    )
    safe_id = (
        safe_order_response.json()["id"]
        if safe_order_response.status_code == 200
        else -1
    )
    check(
        "S13",
        lambda: (
            float(
                call(
                    "POST",
                    f"/orders/{safe_id}/verified-coupon",
                    token=strong_a,
                    json={"code": "WELCOME20", "discount": 99},
                )
                .json()
                .get("discount", -1)
            )
            == 20
        ),
    )
    safe_paid = call("POST", f"/orders/{safe_id}/verified-pay", token=strong_a)
    check(
        "S14",
        lambda: (
            safe_paid.status_code == 200
            and call(
                "POST", f"/orders/{safe_id}/verified-pay", token=strong_a
            ).status_code
            == 409
        ),
    )
    check(
        "S15",
        lambda: (
            call(
                "POST", f"/orders/{safe_id}/verified-cancel", token=strong_a
            ).status_code
            == 409
        ),
    )
    check(
        "S16",
        lambda: (
            safe_paid.status_code == 200
            and call(
                "GET", f"/invoices/{safe_paid.json()['id']}/verified", token=strong_b
            ).status_code
            == 404
        ),
    )
    check(
        "S17", lambda: "ssn" not in call("GET", "/me/verified", token=strong_a).json()
    )
    check(
        "S18",
        lambda: (
            call(
                "POST",
                "/jobs/verified",
                token=strong_a,
                json={"kind": "echo", "payload": {}, "run_as": "admin"},
            )
            .json()
            .get("run_as")
            == "user"
        ),
    )
    check(
        "S19",
        lambda: (
            call(
                "POST",
                "/webhooks/verified",
                token=strong_a,
                json={"target_url": bad_destination},
            ).status_code
            == 400
            and call(
                "POST",
                "/webhooks/verified",
                token=strong_a,
                json={"target_url": "http://mock-external:9000/webhook"},
            ).status_code
            == 200
        ),
    )
    check(
        "S20",
        lambda: (
            call("GET", "/orders/1/notes/2/verified", token=strong_a).status_code == 404
        ),
    )
    check(
        "S21",
        lambda: (
            call(
                "GET",
                "/auth/continue/verified",
                params={"next": "https://untrusted.example/"},
                allow_redirects=False,
            ).status_code
            == 400
            and call(
                "GET",
                "/auth/continue/verified",
                params={"next": "/view"},
                allow_redirects=False,
            ).headers.get("Location")
            == "/view"
        ),
    )

    def signed_hook() -> bool:
        body = b'{"event":"order"}'
        signature = hmac.new(
            b"lab-only-not-a-real-secret", body, hashlib.sha256
        ).hexdigest()
        return (
            call("POST", "/integrations/hook-verified", data=body).status_code == 401
            and call(
                "POST",
                "/integrations/hook-verified",
                data=body,
                headers={"X-Lab-Signature": signature},
            ).status_code
            == 200
        )

    check("S22", signed_hook)
    check(
        "S23",
        lambda: all(
            flag
            in call("GET", "/session/secure-start", token=strong_a)
            .headers.get("Set-Cookie", "")
            .lower()
            for flag in ("httponly", "secure", "samesite=strict")
        ),
    )
    check(
        "S24",
        lambda: "Content-Security-Policy" in call("GET", "/status/secure").headers,
    )
    check(
        "S25",
        lambda: call("GET", "/admin/current-report", token=strong_a).status_code == 403,
    )
    check(
        "S26",
        lambda: (
            call("GET", "/orders/1/notes/1/verified", token=strong_b).status_code == 403
        ),
    )

    # This control is reset-specific and must not alter the established users.
    def single_use_reset() -> bool:
        request = call(
            "POST", "/auth/reset/verified-request", json={"username": "user_a"}
        )
        if request.status_code != 200:
            return False
        token = request.json()["reset_token"]
        first = call(
            "POST",
            "/auth/reset/verified-confirm",
            json={"token": token, "password": PASSWORDS["user_a"]},
        )
        second = call(
            "POST",
            "/auth/reset/verified-confirm",
            json={"token": token, "password": PASSWORDS["user_a"]},
        )
        return first.status_code == 200 and second.status_code == 400

    check("S27", single_use_reset)

    truth = json.loads(
        (ROOT / "benchmark" / "verdict-comprehensive-ground-truth.json").read_text(
            encoding="utf-8"
        )
    )
    expected = {
        item["id"] for item in truth["cases"] if item["label"] != "candidate_only"
    }
    actual = {item["id"] for item in results}
    if actual != expected or len(results) != len(actual):
        raise AssertionError(
            f"Proof/label mismatch: missing={expected - actual}, extra={actual - expected}"
        )
    passed = sum(bool(item["passed"]) for item in results)
    print(
        json.dumps(
            {"passed": passed, "total": len(results), "results": results}, indent=2
        )
    )
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

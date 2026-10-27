"""Ordinary app behavior checks against a running local stack."""
from __future__ import annotations

import json
import os
import unittest
import http.cookiejar
import urllib.parse
import urllib.request


BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:8091")


def request(method: str, path: str, body: dict | None = None, token: str | None = None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(
        urllib.request.Request(BASE + path, data=data, headers=headers, method=method), timeout=5
    ) as response:
        return response.status, json.loads(response.read())


class NormalBehaviorTests(unittest.TestCase):
    def test_health(self) -> None:
        status, body = request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_login_and_identity(self) -> None:
        status, body = request("POST", "/auth/checked-login", {"username": "user_a", "password": "UserA-Lab-Only-1"})
        self.assertEqual(status, 200)
        status, identity = request("GET", "/me/verified", token=body["access_token"])
        self.assertEqual(status, 200)
        self.assertEqual(identity["username"], "user_a")

    def test_create_and_read_own_order(self) -> None:
        _, session = request("POST", "/auth/checked-login", {"username": "user_a", "password": "UserA-Lab-Only-1"})
        token = session["access_token"]
        status, order = request("POST", "/orders/verified", {"item": "widget", "quantity": 2}, token)
        self.assertEqual(status, 200)
        status, loaded = request("GET", f"/orders/{order['id']}/verified", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(loaded["id"], order["id"])

    def test_browser_form_session(self) -> None:
        client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        form = urllib.parse.urlencode({"username": "user_a", "password": "UserA-Lab-Only-1"}).encode()
        with client.open(urllib.request.Request(BASE + "/auth/form-login", data=form, method="POST"), timeout=5) as response:
            self.assertIn("Signed in as user_a", response.read().decode())
        with client.open(BASE + "/account", timeout=5) as response:
            self.assertIn("Signed in as user_a", response.read().decode())


if __name__ == "__main__":
    unittest.main()

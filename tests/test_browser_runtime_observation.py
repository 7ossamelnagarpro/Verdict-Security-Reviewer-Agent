"""The browser records same-origin navigation hints without executing forms."""

from __future__ import annotations

import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_reviewer_v2.scanners.browser_runtime import run_browser_dast


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/catalog":
            body, content_type = b'{"items":[]}', "application/json"
        else:
            body = (
                b"<html><form method='post' action='/orders'>"
                b"<input name='item_id' value='private-value'></form>"
                b"<script>fetch('/api/catalog?token=private-value')</script></html>"
            )
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class _AuthenticatedHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/auth/login":
            self.send_error(404)
            return
        self.rfile.read(int(self.headers["Content-Length"]))
        body = b'{"access_token":"private-test-token"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        authorized = self.headers.get("Authorization") == "Bearer private-test-token"
        if self.path == "/me":
            status, body, kind = (
                (200, b'{"username":"user_a"}', "application/json")
                if authorized
                else (401, b"{}", "application/json")
            )
        elif self.path == "/private":
            status, body, kind = (
                (200, b"<script>fetch('/api/private')</script>", "text/html")
                if authorized
                else (401, b"no", "text/plain")
            )
        elif self.path == "/api/private":
            status, body, kind = (
                (200, b"{}", "application/json")
                if authorized
                else (401, b"{}", "application/json")
            )
        else:
            status, body, kind = 200, b"<html></html>", "text/html"
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def test_browser_records_api_and_forms_without_values_or_submissions(
    tmp_path: Path,
) -> None:
    if (
        not shutil.which("node")
        or not (
            Path(__file__).resolve().parents[1] / "scripts/node_modules/playwright"
        ).is_dir()
    ):
        pytest.skip("optional Node Playwright is unavailable")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        output = tmp_path / "browser.json"
        result = run_browser_dast(
            f"http://127.0.0.1:{server.server_port}",
            tmp_path / "runtime.json",
            output,
            max_pages=2,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    assert result["status"] == "completed"
    assert any(item["path"] == "/api/catalog" for item in result["observed_requests"])
    assert any(
        item["path"] == "/orders" and item["method"] == "POST"
        for item in result["observed_forms"]
    )
    assert "private-value" not in json.dumps(result)


def test_browser_uses_verified_test_account_without_saving_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if (
        not shutil.which("node")
        or not (
            Path(__file__).resolve().parents[1] / "scripts/node_modules/playwright"
        ).is_dir()
    ):
        pytest.skip("optional Node Playwright is unavailable")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthenticatedHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("SECURITY_TEST_WF_USER_A_USERNAME", "user_a")
    monkeypatch.setenv("SECURITY_TEST_WF_USER_A_PASSWORD", "private-password")
    account = {
        "id": "user_a",
        "login_path": "/auth/login",
        "verify_path": "/me",
        "encoding": "json",
        "session": "bearer",
        "username_field": "username",
        "password_field": "password",
        "token_path": "access_token",
        "identity_path": "username",
    }
    try:
        result = run_browser_dast(
            f"http://127.0.0.1:{server.server_port}",
            tmp_path / "runtime.json",
            tmp_path / "browser.json",
            max_pages=2,
            seed_paths=("/private",),
            accounts=(account,),
            disposable=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    assert result["status"] == "completed"
    assert result["accounts"] == [{"actor": "user_a", "status": "verified"}]
    assert any(
        row["actor"] == "user_a"
        and row["path"] == "/api/private"
        and row["status"] == 200
        for row in result["observed_requests"]
    )
    assert "private-password" not in json.dumps(result)
    assert "private-test-token" not in json.dumps(result)

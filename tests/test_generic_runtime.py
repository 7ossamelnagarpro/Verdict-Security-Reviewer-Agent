from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_reviewer_v2.scanners.generic_runtime import (
    GenericRuntimeConfig,
    run_generic_checks,
)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "session=redacted; Path=/")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/broken":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"error")
        elif self.path == "/session/start":
            self.send_response(200)
            self.send_header("Set-Cookie", "safe=1; HttpOnly; SameSite=Lax")
            self.send_header("Set-Cookie", "unsafe=HttpOnly; SameSite=Lax")
            self.end_headers()
        elif self.path == "/view":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<p>view</p>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture()
def runtime_server() -> tuple[str, ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_generic_runtime_writes_bounded_evidence(
    runtime_server: tuple[str, ThreadingHTTPServer], tmp_path: Path
) -> None:
    base_url, _ = runtime_server
    output = tmp_path / "runtime.json"

    payload = run_generic_checks(
        GenericRuntimeConfig(base_url, output, "/health", 200, ("/broken",))
    )

    assert payload["status"] == "completed"
    assert payload["source"] == "generic-web-runtime"
    assert any(
        item["rule_id"] == "web.endpoint-server-error" and item["vulnerable"]
        for item in payload["results"]
    )
    assert any(
        item["rule_id"] == "web.cookie-missing-security-attributes"
        and item["vulnerable"]
        for item in payload["results"]
    )
    assert json.loads(output.read_text(encoding="utf-8"))["target"] == base_url


def test_generic_runtime_fails_when_health_status_is_wrong(
    runtime_server: tuple[str, ThreadingHTTPServer],
    tmp_path: Path,
) -> None:
    base_url, _ = runtime_server
    with pytest.raises(RuntimeError, match="expected 204"):
        run_generic_checks(
            GenericRuntimeConfig(base_url, tmp_path / "runtime.json", "/health", 204)
        )


def test_endpoint_cookie_and_html_checks_cover_each_declared_path(
    runtime_server: tuple[str, ThreadingHTTPServer],
    tmp_path: Path,
) -> None:
    base_url, _ = runtime_server
    payload = run_generic_checks(
        GenericRuntimeConfig(
            base_url,
            tmp_path / "runtime.json",
            "/health",
            200,
            ("/session/start", "/view", "/session/start"),
        )
    )
    cookies = [
        item
        for item in payload["results"]
        if item["path"] == "/session/start"
        and item["rule_id"] == "web.cookie-missing-security-attributes"
    ]
    assert len(cookies) == 1
    assert cookies[0]["evidence"]["cookie_name"] == "unsafe"
    assert cookies[0]["evidence"]["missing_attributes"] == ["HttpOnly"]
    assert not any(
        "safe=1" in str(item) or "unsafe=HttpOnly" in str(item)
        for item in payload["results"]
    )
    assert any(
        item["path"] == "/view"
        and item["rule_id"] == "web.missing-content-security-policy"
        and item["vulnerable"]
        for item in payload["results"]
    )


def test_html_header_check_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from security_reviewer_v2.scanners import generic_runtime

    def lowercase_headers(_client, _base_url, path, _timeout):
        if path == "/health":
            return 200, {"content-type": "application/json"}, b"{}"
        return 200, {"content-type": "text/html; charset=utf-8"}, b"<p>view</p>"

    monkeypatch.setattr(generic_runtime, "_get", lowercase_headers)
    payload = run_generic_checks(
        GenericRuntimeConfig(
            "http://127.0.0.1:8090",
            tmp_path / "runtime.json",
            "/health",
            200,
            ("/view",),
        )
    )
    assert any(
        item["path"] == "/view"
        and item["rule_id"] == "web.missing-content-security-policy"
        and item["vulnerable"]
        for item in payload["results"]
    )

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
    def do_GET(self) -> None:  # noqa: N802 - stdlib protocol name
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


def test_generic_runtime_writes_bounded_evidence(runtime_server: tuple[str, ThreadingHTTPServer], tmp_path: Path) -> None:
    base_url, _ = runtime_server
    output = tmp_path / "runtime.json"

    payload = run_generic_checks(GenericRuntimeConfig(
        base_url, output, "/health", 200, ("/broken",)))

    assert payload["status"] == "completed"
    assert payload["source"] == "generic-web-runtime"
    assert any(item["rule_id"] == "web.endpoint-server-error" and item["vulnerable"]
               for item in payload["results"])
    assert any(item["rule_id"] == "web.cookie-missing-security-attributes" and item["vulnerable"]
               for item in payload["results"])
    assert json.loads(output.read_text(encoding="utf-8"))["target"] == base_url


def test_generic_runtime_fails_when_health_status_is_wrong(
    runtime_server: tuple[str, ThreadingHTTPServer], tmp_path: Path,
) -> None:
    base_url, _ = runtime_server
    with pytest.raises(RuntimeError, match="expected 204"):
        run_generic_checks(GenericRuntimeConfig(base_url, tmp_path / "runtime.json", "/health", 204))

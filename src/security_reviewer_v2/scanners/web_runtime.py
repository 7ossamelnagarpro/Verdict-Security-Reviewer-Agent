"""Bounded HTTP checks for a local, authorized security-test target.

The checks deliberately produce evidence, not exploit output.  Mutating checks
(stored XSS and upload) are opt-in because they change the target's test data.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuntimeConfig:
    base_url: str
    output: Path
    mutating: bool = False
    timeout_seconds: float = 5.0

    def validate(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must use http or https")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _client() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        NoRedirect(),
    )


def _request(client: urllib.request.OpenerDirector, base: str, path: str, *,
             data: dict[str, str] | None = None, headers: dict[str, str] | None = None,
             timeout: float = 5.0, files: tuple[str, bytes, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    body: bytes | None = None
    request_headers = dict(headers or {})
    if files:
        name, content, content_type = files
        boundary = "----security-reviewer-boundary"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                f"Content-Type: {content_type}\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        request_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(base.rstrip("/") + path, data=body, headers=request_headers)
    try:
        response = client.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        headers = dict(response.headers.items())
        # Preserve repeated Set-Cookie headers; dict(items()) keeps only one.
        cookies = response.headers.get_all("Set-Cookie")
        if cookies:
            headers["Set-Cookie"] = "\n".join(cookies)
        return response.status, headers, response.read(256 * 1024)


def _check(rule_id: str, title: str, path: str, vulnerable: bool, *,
           evidence: dict[str, Any], severity: str = "medium", confidence: str = "high",
           request: list[dict[str, str]] | None = None) -> dict[str, Any]:
    result = {"rule_id": rule_id, "title": title, "path": path, "vulnerable": vulnerable,
              "severity": severity, "confidence": confidence, "evidence": evidence}
    if request:  # The probe's own fixed request shape (never target data); credentials are written as <redacted>.
        result["request"] = request
    return result


def run_checks(config: RuntimeConfig) -> dict[str, Any]:
    config.validate()
    base = config.base_url.rstrip("/")
    client = _client()
    checks: list[dict[str, Any]] = []
    status, _, home = _request(client, base, "/", timeout=config.timeout_seconds)
    if status < 200 or status >= 400:
        raise RuntimeError(f"target is not reachable (HTTP {status})")

    # Reflected XSS: no browser is launched; we only verify unescaped reflection.
    payload = "<script>alert(1)</script>"
    status, _, body = _request(client, base, "/search?q=" + urllib.parse.quote(payload), timeout=config.timeout_seconds)
    reflected = payload.encode() in body
    checks.append(_check("web.reflected-xss", "Reflected XSS", "/search", reflected,
                         evidence={"status": status, "payload_reflected": reflected},
                         request=[{"method": "GET", "path": "/search", "query": "q=" + payload}]))

    # Token check: retain only shape, never the cookie value.
    login, headers, _ = _request(client, base, "/login", data={"username": "alice", "password": "alice123"}, timeout=config.timeout_seconds)
    cookies = headers.get("Set-Cookie", "")
    token_match = re.search(r"(?:^|;\s*)token=([^;]+)", cookies)
    token_value = token_match.group(1) if token_match else ""
    predictable = bool(re.fullmatch(r"tok-\d+-staticsalt", token_value))
    checks.append(_check("web.predictable-session-token", "Predictable session token", "/login", predictable,
                         evidence={"login_status": login, "token_shape": "tok-<numeric-id>-staticsalt" if predictable else "not-observed"}, severity="high",
                         request=[{"method": "POST", "path": "/login", "content_type": "application/x-www-form-urlencoded",
                                   "body": "username=alice&password=<redacted>"}]))

    # Debug exposure: report keys and types only, never secret values.
    status, _, body = _request(client, base, "/debug", timeout=config.timeout_seconds)
    try:
        debug = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        debug = {}
    keys = sorted(str(key) for key in debug) if isinstance(debug, dict) else []
    exposed = status == 200 and any(key in keys for key in ("secret_key", "env"))
    checks.append(_check("web.sensitive-data-exposure", "Sensitive data exposed by debug endpoint", "/debug", exposed,
                         evidence={"status": status, "response_keys": keys, "values_redacted": True}, severity="high",
                         request=[{"method": "GET", "path": "/debug"}]))

    # Verbose errors: inspect markers only, do not retain the query or secret data.
    status, _, body = _request(client, base, "/search?q=%27%22%22%22", timeout=config.timeout_seconds)
    text = body.decode("utf-8", errors="replace").lower()
    verbose = status >= 500 and any(marker in text for marker in ("db error", "query:", "traceback", "sqlite"))
    checks.append(_check("web.verbose-error", "Verbose database error returned to client", "/search", verbose,
                         evidence={"status": status, "error_marker_present": verbose}, severity="medium",
                         request=[{"method": "GET", "path": "/search", "query": "q=%27%22%22%22"}]))

    # Bounded rate-limit check: five invalid requests, no password spraying.
    statuses = []
    for _ in range(5):
        code, _, _ = _request(client, base, "/login", data={"username": "alice", "password": "definitely-wrong"}, timeout=config.timeout_seconds)
        statuses.append(code)
    rate_limited = any(code in {429, 423} for code in statuses)
    checks.append(_check("web.missing-brute-force-protection", "No rate-limit response observed on login", "/login", not rate_limited,
                         evidence={"attempt_count": len(statuses), "statuses": statuses}, severity="medium", confidence="medium",
                         request=[{"method": "POST", "path": "/login", "content_type": "application/x-www-form-urlencoded",
                                   "body": "username=alice&password=<redacted: invalid>", "repeat": "5"}]))

    if config.mutating:
        xss = "<img src=x onerror=alert(1)>"
        post_status, _, _ = _request(client, base, "/comments", data={"author": "security-test", "body": xss}, timeout=config.timeout_seconds)
        get_status, _, body = _request(client, base, "/comments", timeout=config.timeout_seconds)
        stored = post_status in {200, 302} and get_status == 200 and xss.encode() in body
        checks.append(_check("web.stored-xss", "Stored XSS in comments", "/comments", stored,
                             evidence={"post_status": post_status, "get_status": get_status, "payload_reflected": stored}, severity="high",
                             request=[{"method": "POST", "path": "/comments", "content_type": "application/x-www-form-urlencoded",
                                       "body": "author=security-test&body=" + xss},
                                      {"method": "GET", "path": "/comments"}]))

        filename = "security-reviewer-test.html"
        upload_status, _, upload_body = _request(client, base, "/upload", files=(filename, b"<script>security_test_marker</script>", "text/html"), timeout=config.timeout_seconds)
        serve_status, serve_headers, served = _request(client, base, "/uploads/" + filename, timeout=config.timeout_seconds)
        upload_vulnerable = upload_status in {200, 302} and serve_status == 200 and b"security_test_marker" in served
        checks.append(_check("web.insecure-file-upload", "Uploaded HTML is served back to clients", "/upload", upload_vulnerable,
                             evidence={"upload_status": upload_status, "serve_status": serve_status,
                                       "marker_present": b"security_test_marker" in served,
                                       "content_type": serve_headers.get("Content-Type", "")}, severity="high",
                             request=[{"method": "POST", "path": "/upload", "content_type": "multipart/form-data",
                                       "body": f"file={filename} (text/html): <script>security_test_marker</script>"},
                                      {"method": "GET", "path": "/uploads/" + filename}]))

    payload = {"schema_version": "1.0", "source": "web-runtime", "target": base,
               "status": "completed", "mutating_checks_enabled": config.mutating,
               "results": checks, "coverage_notes": [
                   "Checks are bounded and intended for an authorized local test target.",
                   "A negative result means this probe did not confirm the behavior; it is not proof of absence.",
               ]}
    config.output.parent.mkdir(parents=True, exist_ok=True)
    config.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run bounded local web security checks")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mutating", action="store_true", help="enable stored-XSS and upload test writes")
    args = parser.parse_args(argv)
    payload = run_checks(RuntimeConfig(args.base_url, args.output, args.mutating))
    print(json.dumps({"status": payload["status"], "findings": sum(1 for item in payload["results"] if item["vulnerable"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Bounded, non-mutating HTTP checks for an explicitly authorized runtime.

These checks are intentionally generic. They do not pretend to replace
application-specific authorization, workflow, or browser testing. The target
URL and endpoint paths must come from a Runtime Contract outside the project.
"""

from __future__ import annotations

import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GenericRuntimeConfig:
    base_url: str
    output: Path
    health_path: str = "/"
    expected_status: int = 200
    endpoint_paths: tuple[str, ...] = ()
    timeout_seconds: float = 5.0

    def validate(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must use http or https")
        if (
            parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("base_url must be an origin without credentials or a path")
        if not self.health_path.startswith("/") or self.health_path.startswith("//"):
            raise ValueError("health_path must be an absolute path")
        if (
            type(self.expected_status) is not int
            or not 200 <= self.expected_status < 400
        ):
            raise ValueError("expected_status must be a successful HTTP status")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        for path in self.endpoint_paths:
            if not path.startswith("/") or path.startswith("//"):
                raise ValueError("endpoint paths must be absolute paths")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _client() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        _NoRedirect(),
    )


def _get(
    client: urllib.request.OpenerDirector, base_url: str, path: str, timeout: float
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(base_url.rstrip("/") + path, method="GET")
    try:
        response = client.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        headers = dict(response.headers.items())
        # Mapping conversion drops repeated Set-Cookie fields. Preserve every
        # cookie for the attribute audit without retaining their values.
        cookies = response.headers.get_all("Set-Cookie", [])
        if cookies:
            headers["Set-Cookie"] = "\n".join(cookies)
        return response.status, headers, response.read(256 * 1024)


def _observation(
    rule_id: str,
    title: str,
    path: str,
    vulnerable: bool,
    evidence: dict[str, Any],
    *,
    severity: str = "low",
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "path": path,
        "vulnerable": vulnerable,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
    }


def _cookie_observations(
    headers: dict[str, str], path: str, *, is_https: bool
) -> list[dict[str, Any]]:
    raw = headers.get("Set-Cookie", "")
    if not raw:
        return []
    records: list[dict[str, Any]] = []
    for cookie in raw.split("\n"):
        name = cookie.split("=", 1)[0].strip() or "unknown"
        attributes = {
            part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]
        }
        missing = [
            flag
            for flag, marker in (("HttpOnly", "httponly"), ("SameSite", "samesite"))
            if marker not in attributes
        ]
        if is_https and "secure" not in attributes:
            missing.append("Secure")
        if missing:
            records.append(
                _observation(
                    "web.cookie-missing-security-attributes",
                    "Cookie is missing security attributes",
                    path,
                    True,
                    {
                        "cookie_name": name[:80],
                        "missing_attributes": missing,
                        "cookie_value_redacted": True,
                    },
                    severity="medium",
                )
            )
    return records


def run_generic_checks(config: GenericRuntimeConfig) -> dict[str, Any]:
    config.validate()
    client = _client()
    status, headers, _ = _get(
        client, config.base_url, config.health_path, config.timeout_seconds
    )
    if status != config.expected_status:
        raise RuntimeError(
            f"target health check returned HTTP {status}; expected {config.expected_status}"
        )

    results: list[dict[str, Any]] = []
    lower_headers = {key.lower(): value for key, value in headers.items()}
    results.append(
        _observation(
            "web.missing-content-security-policy",
            "Missing Content-Security-Policy header",
            config.health_path,
            "content-security-policy" not in lower_headers,
            {
                "status": status,
                "header_present": "content-security-policy" in lower_headers,
            },
            severity="low",
        )
    )
    results.append(
        _observation(
            "web.missing-clickjacking-protection",
            "Missing clickjacking protection header",
            config.health_path,
            "x-frame-options" not in lower_headers
            and "content-security-policy" not in lower_headers,
            {
                "status": status,
                "x_frame_options_present": "x-frame-options" in lower_headers,
                "content_security_policy_present": "content-security-policy"
                in lower_headers,
            },
            severity="low",
        )
    )
    results.append(
        _observation(
            "web.missing-content-type-protection",
            "Missing X-Content-Type-Options header",
            config.health_path,
            lower_headers.get("x-content-type-options", "").lower() != "nosniff",
            {
                "status": status,
                "nosniff_present": lower_headers.get(
                    "x-content-type-options", ""
                ).lower()
                == "nosniff",
            },
            severity="low",
        )
    )
    is_https = urllib.parse.urlsplit(config.base_url).scheme == "https"
    results.extend(_cookie_observations(headers, config.health_path, is_https=is_https))

    for path in dict.fromkeys(config.endpoint_paths):
        if path == config.health_path:
            continue
        endpoint_status, endpoint_headers, _ = _get(
            client, config.base_url, path, config.timeout_seconds
        )
        endpoint_lower = {key.lower(): value for key, value in endpoint_headers.items()}
        content_type = endpoint_lower.get("content-type", "")
        results.append(
            _observation(
                "web.endpoint-server-error",
                "Declared endpoint returned a server error",
                path,
                endpoint_status >= 500,
                {"status": endpoint_status, "content_type": content_type},
                severity="medium",
                confidence="medium",
            )
        )
        results.extend(_cookie_observations(endpoint_headers, path, is_https=is_https))
        if "text/html" in content_type.lower():
            results.append(
                _observation(
                    "web.missing-content-security-policy",
                    "Missing Content-Security-Policy header",
                    path,
                    "content-security-policy" not in endpoint_lower,
                    {
                        "status": endpoint_status,
                        "header_present": "content-security-policy" in endpoint_lower,
                    },
                    severity="low",
                )
            )

    payload = {
        "schema_version": "1.0",
        "source": "generic-web-runtime",
        "target": config.base_url,
        "status": "completed",
        "mutating_checks_enabled": False,
        "authorization_checks_enabled": False,
        "results": results,
        "coverage_notes": [
            "Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.",
            "The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.",
            "A negative result means only that this probe did not observe the behavior.",
        ],
    }
    config.output.parent.mkdir(parents=True, exist_ok=True)
    config.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return payload

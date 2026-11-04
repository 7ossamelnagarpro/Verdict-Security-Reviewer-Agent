"""Declarative, bounded HTTP workflows. No shell, eval, external redirects or raw-body evidence."""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
REF = re.compile(r"\{\{([a-z][a-z0-9_]{0,31})\}\}")


def local_path(value):
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or any(c.isspace() or ord(c) < 32 for c in value)
        or "#" in value
        or "\\" in value
    ):
        raise ValueError("Use one local path, without spaces, fragments or a host")
    return value


def env_name(actor, field):
    return f"SECURITY_TEST_WF_{actor.upper()}_{field.upper()}"


def validate_suite(suite, *, disposable=False):
    if not isinstance(suite, dict) or set(suite) - {
        "version",
        "accounts",
        "workflows",
        "max_requests",
        "timeout_seconds",
        "max_seconds",
        "allow_mutation",
        "reset",
    }:
        raise ValueError("Invalid workflow contract fields")
    if suite.get("version") != 1:
        raise ValueError("Unsupported workflow contract version")
    for key, default, low, high in (
        ("max_requests", 100, 1, 300),
        ("timeout_seconds", 5, 1, 15),
        ("max_seconds", 300, 5, 600),
    ):
        n = suite.get(key, default)
        if type(n) is not int or not low <= n <= high:
            raise ValueError(f"{key} must be between {low} and {high}")
    if type(suite.get("allow_mutation", False)) is not bool:
        raise ValueError("allow_mutation must be boolean")
    if suite.get("allow_mutation") and not disposable:
        raise ValueError(
            "Mutating workflows require a disposable trusted Compose target"
        )
    if suite.get("reset", "none") not in {"none", "fresh_stack"}:
        raise ValueError(
            "Reset supports none or fresh_stack; shell commands are not accepted"
        )
    if suite.get("reset") == "fresh_stack" and not disposable:
        raise ValueError("fresh_stack requires a disposable Compose target")
    accounts = suite.get("accounts", [])
    workflows = suite.get("workflows", [])
    if (
        not isinstance(accounts, list)
        or len(accounts) > 8
        or not isinstance(workflows, list)
        or not 1 <= len(workflows) <= 40
    ):
        raise ValueError("Supply 1–40 workflows and at most 8 accounts")
    actors = set()
    for a in accounts:
        if not isinstance(a, dict) or set(a) - {
            "id",
            "role",
            "login_path",
            "encoding",
            "username_field",
            "password_field",
            "session",
            "token_path",
            "verify_path",
            "identity_path",
        }:
            raise ValueError(
                "Invalid account; credentials must be saved in the OS vault"
            )
        name = a.get("id", "")
        if (
            not isinstance(name, str)
            or not ID.fullmatch(name)
            or name in actors
            or name == "anonymous"
        ):
            raise ValueError("Account IDs must be unique lowercase names, e.g. user_a")
        actors.add(name)
        for field in ("login_path", "verify_path"):
            local_path(a.get(field))
        if a.get("encoding") not in {"json", "form"} or a.get("session") not in {
            "bearer",
            "cookie",
        }:
            raise ValueError("Choose JSON/form login and bearer/cookie session")
        for field in ("username_field", "password_field", "identity_path"):
            if not isinstance(a.get(field), str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_.]{0,63}", a[field]
            ):
                raise ValueError(f"Provide an explicit {field}")
        if a["session"] == "bearer" and not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.]{0,63}", a.get("token_path", "")
        ):
            raise ValueError("Bearer login needs the token JSON field")
    names = set()
    for w in workflows:
        if not isinstance(w, dict) or set(w) - {"id", "title", "severity", "steps"}:
            raise ValueError("Invalid workflow fields")
        if not ID.fullmatch(str(w.get("id", ""))) or w["id"] in names:
            raise ValueError("Workflow IDs must be unique lowercase names")
        names.add(w["id"])
        if not isinstance(w.get("title"), str) or not 1 <= len(w["title"]) <= 160:
            raise ValueError("Each workflow needs a short title")
        if w.get("severity", "medium") not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid workflow severity")
        steps = w.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
            raise ValueError("Each workflow needs 1–20 steps")
        captured = set()
        for step_index, s in enumerate(steps):
            if not isinstance(s, dict) or set(s) - {
                "actor",
                "method",
                "path",
                "body",
                "multipart",
                "capture",
                "expect_status",
                "assertions",
                "response_assertions",
                "security_check",
                "wait_before_seconds",
                "lockout_after_failures",
                "auth_probe",
            }:
                raise ValueError("Invalid workflow step")
            if (
                type(s.get("wait_before_seconds", 0)) is not int
                or not 0 <= s.get("wait_before_seconds", 0) <= 10
            ):
                raise ValueError("wait_before_seconds must be between 0 and 10")
            if s.get("actor", "anonymous") not in actors | {"anonymous"}:
                raise ValueError("Step references an unknown account")
            local_path(s.get("path"))
            if s.get("method") not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                raise ValueError("Unsupported HTTP method")
            if s.get("wait_before_seconds", 0) and s["method"] not in {"GET", "HEAD"}:
                raise ValueError(
                    "wait_before_seconds is only supported for read-only steps"
                )
            if s["method"] not in {"GET", "HEAD"} and not suite.get("allow_mutation"):
                raise ValueError("Approve mutation to execute write requests")
            if type(s.get("security_check", False)) is not bool:
                raise ValueError("security_check must be boolean")
            if "auth_probe" in s:
                probe = s["auth_probe"]
                if (
                    not disposable
                    or not suite.get("allow_mutation")
                    or s.get("actor", "anonymous") != "anonymous"
                    or not s.get("security_check")
                ):
                    raise ValueError(
                        "Synthetic authentication probes require an approved disposable target and an anonymous security step"
                    )
                if not isinstance(probe, dict) or probe.get("kind") not in {
                    "numbered_cookie",
                    "unsigned_jwt",
                }:
                    raise ValueError("Unsupported synthetic authentication probe")
                if probe["kind"] == "numbered_cookie":
                    if (
                        set(probe) != {"kind", "name", "prefix", "number"}
                        or not isinstance(probe["name"], str)
                        or not re.fullmatch(
                            r"[A-Za-z_][A-Za-z0-9_]{0,31}", probe["name"]
                        )
                        or not isinstance(probe["prefix"], str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", probe["prefix"])
                        or type(probe["number"]) is not int
                        or not 1 <= probe["number"] <= 10000
                    ):
                        raise ValueError(
                            "Numbered cookie probe needs a short safe name, prefix and number"
                        )
                else:
                    claims = probe.get("claims")
                    if (
                        set(probe) != {"kind", "claims"}
                        or not isinstance(claims, dict)
                        or not 1 <= len(claims) <= 8
                        or len(json.dumps(claims)) > 512
                        or any(
                            not isinstance(key, str)
                            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", key)
                            or type(value) not in {str, int, bool}
                            or (isinstance(value, str) and len(value) > 128)
                            for key, value in claims.items()
                        )
                    ):
                        raise ValueError(
                            "Unsigned JWT probe needs bounded scalar test claims"
                        )
            if "body" in s and (
                not isinstance(s["body"], dict) or len(json.dumps(s["body"])) > 8192
            ):
                raise ValueError("Step JSON body must be an object of at most 8 KiB")
            if "multipart" in s:
                part = s["multipart"]
                if (
                    not disposable
                    or not suite.get("allow_mutation")
                    or s["method"] not in {"POST", "PUT", "PATCH"}
                    or "body" in s
                ):
                    raise ValueError(
                        "Multipart upload requires approved mutation on a disposable Compose target"
                    )
                if not isinstance(part, dict) or set(part) != {
                    "field",
                    "filename",
                    "content_type",
                    "content",
                }:
                    raise ValueError(
                        "Multipart upload needs field, filename, content_type and content"
                    )
                if (
                    not isinstance(part["field"], str)
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", part["field"])
                    or not isinstance(part["filename"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", part["filename"])
                    or not isinstance(part["content_type"], str)
                    or not re.fullmatch(
                        r"[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+", part["content_type"]
                    )
                    or not isinstance(part["content"], str)
                    or not 1 <= len(part["content"].encode("utf-8", "replace")) <= 4096
                ):
                    raise ValueError(
                        "Multipart upload fields must be safe and content at most 4 KiB"
                    )
            statuses = s.get("expect_status", [])
            if (
                not isinstance(statuses, list)
                or not statuses
                or any(type(v) is not int or not 100 <= v <= 599 for v in statuses)
            ):
                raise ValueError("Every step needs expected HTTP statuses")
            threshold = s.get("lockout_after_failures")
            if threshold is not None:
                if (
                    type(threshold) is not int
                    or not 2 <= threshold <= 10
                    or s.get("actor", "anonymous") != "anonymous"
                    or s["method"] != "POST"
                    or not s.get("security_check")
                    or not set(statuses) <= {423, 429}
                    or "body" not in s
                ):
                    raise ValueError(
                        "Lockout checks need 2–10 prior anonymous failed POSTs and an expected 423/429"
                    )
                prior = [
                    item
                    for item in steps[:step_index]
                    if isinstance(item, dict)
                    and item.get("actor", "anonymous") == "anonymous"
                    and item.get("method") == "POST"
                    and item.get("path") == s["path"]
                    and item.get("body") == s["body"]
                    and item.get("expect_status") == [401]
                ]
                if len(prior) < threshold:
                    raise ValueError(
                        "Lockout check needs matching prior failed login steps"
                    )
            assertions = s.get("assertions", [])
            if not isinstance(assertions, list) or len(assertions) > 10:
                raise ValueError("At most 10 assertions per step")
            for a in assertions:
                if (
                    not isinstance(a, dict)
                    or set(a) - {"path", "op", "value"}
                    or a.get("op")
                    not in {"eq", "ne", "absent", "present", "gte", "lte"}
                ):
                    raise ValueError("Invalid JSON assertion")
                if not isinstance(a.get("path"), str) or len(a["path"]) > 128:
                    raise ValueError("Assertion needs a JSON field path")
                if a["op"] not in {"present", "absent"} and "value" not in a:
                    raise ValueError("Comparison needs an expected value")
            response_assertions = s.get("response_assertions", [])
            if (
                not isinstance(response_assertions, list)
                or len(response_assertions) > 10
            ):
                raise ValueError("At most 10 response assertions per step")
            for assertion in response_assertions:
                if not isinstance(assertion, dict) or set(assertion) - {
                    "op",
                    "name",
                    "value",
                }:
                    raise ValueError("Invalid response assertion")
                op = assertion.get("op")
                if op not in {
                    "body_contains",
                    "body_not_contains",
                    "header_present",
                    "header_absent",
                    "header_contains",
                    "header_not_contains",
                }:
                    raise ValueError("Unsupported response assertion")
                if op.startswith("header_") and not re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9-]{0,63}", assertion.get("name", "")
                ):
                    raise ValueError("Response header assertion needs a header name")
                if op.endswith("contains") and (
                    not isinstance(assertion.get("value"), str)
                    or not 1 <= len(assertion["value"]) <= 128
                ):
                    raise ValueError(
                        "Response contains assertion needs a short literal"
                    )
            refs = set(
                REF.findall(json.dumps({k: v for k, v in s.items() if k != "capture"}))
            )
            if refs - captured:
                raise ValueError(
                    "Capture variables before using them: "
                    + ", ".join(sorted(refs - captured))
                )
            captures = s.get("capture", {})
            if not isinstance(captures, dict) or len(captures) > 8:
                raise ValueError("Invalid capture mapping")
            for key, path in captures.items():
                if (
                    not ID.fullmatch(key)
                    or not isinstance(path, str)
                    or len(path) > 128
                    or key in captured
                ):
                    raise ValueError("Captures need unique names and JSON field paths")
                captured.add(key)
    return suite


def field(data, path):
    for part in path.split("."):
        if isinstance(data, list) and part.isdigit():
            data = data[int(part)]
        else:
            data = data[part]
    return data


def substitute(value, variables, *, path=False):
    if isinstance(value, str):
        match = REF.fullmatch(value)
        if match and not path:
            return variables[match[1]]
        return REF.sub(
            lambda m: (
                urllib.parse.quote(str(variables[m[1]]), safe="")
                if path
                else str(variables[m[1]])
            ),
            value,
        )
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Transport:
    def __init__(self, base_url, suite):
        from security_reviewer_v2.test_environment.manager import _loopback_url

        self.base = _loopback_url(base_url).rstrip("/")
        self.suite, self.count, self.start = suite, 0, time.monotonic()
        self.clients = {}

    def request(
        self,
        actor,
        method,
        path,
        body=None,
        headers=None,
        encoding="json",
        multipart=None,
    ):
        local_path(path)
        remaining = self.suite.get("max_seconds", 300) - (time.monotonic() - self.start)
        if self.count >= self.suite.get("max_requests", 100) or remaining <= 0:
            raise RuntimeError("Workflow request/time budget exhausted")
        self.count += 1
        if actor not in self.clients:
            self.clients[actor] = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                NoRedirect(),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            )
        hdr = dict(headers or {})
        data = None
        if multipart is not None:
            boundary = "Verdict" + secrets.token_hex(12)
            data = (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{multipart["field"]}"; '
                f'filename="{multipart["filename"]}"\r\nContent-Type: {multipart["content_type"]}\r\n\r\n'
            ).encode()
            data += (
                multipart["content"].encode("utf-8")
                + f"\r\n--{boundary}--\r\n".encode()
            )
            hdr["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif body is not None:
            data = (
                json.dumps(body) if encoding == "json" else urllib.parse.urlencode(body)
            ).encode()
            hdr["Content-Type"] = (
                "application/json"
                if encoding == "json"
                else "application/x-www-form-urlencoded"
            )
        req = urllib.request.Request(
            self.base + path, data=data, headers=hdr, method=method
        )
        try:
            response = self.clients[actor].open(
                req, timeout=min(remaining, self.suite.get("timeout_seconds", 5))
            )
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(262145)
            if len(raw) > 262144:
                raise RuntimeError("Response exceeds the bounded evidence limit")
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeError):
                payload = None
            # The bounded raw response is used only for explicit assertions;
            # neither body nor headers are persisted in workflow evidence.
            return (
                response.status,
                payload,
                {
                    "headers": dict(response.headers.items()),
                    "body": raw.decode("utf-8", "replace"),
                },
            )


def _response_parts(result):
    if not isinstance(result, tuple) or len(result) not in {2, 3}:
        raise ValueError("Invalid HTTP transport result")
    status, payload = result[:2]
    metadata = result[2] if len(result) == 3 else {}
    return status, payload, metadata


def _response_check(assertion, metadata):
    op = assertion["op"]
    if op.startswith("header_"):
        if not isinstance(metadata, dict) or not isinstance(
            metadata.get("headers"), dict
        ):
            return None
        headers = {
            str(key).lower(): str(value)
            for key, value in metadata.get("headers", {}).items()
        }
        name = assertion["name"].lower()
        present = name in headers
        if op == "header_present":
            return present
        if op == "header_absent":
            return not present
        value = headers.get(name, "")
    else:
        if not isinstance(metadata, dict) or not isinstance(metadata.get("body"), str):
            return None
        value = metadata.get("body", "")
    needle = assertion.get("value", "")
    return needle not in value if "_not_contains" in op else needle in value


def _auth_probe_headers(probe):
    if probe["kind"] == "numbered_cookie":
        return {"Cookie": f"{probe['name']}={probe['prefix']}{probe['number']}"}
    header = (
        base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    )
    claims = json.dumps(probe["claims"], separators=(",", ":"), sort_keys=True).encode()
    payload = base64.urlsafe_b64encode(claims).decode().rstrip("=")
    return {"Authorization": f"Bearer {header}.{payload}."}


def run_workflows(base_url, suite, *, disposable, environment=None, transport=None):
    validate_suite(suite, disposable=disposable)
    env = os.environ if environment is None else environment
    http = transport or Transport(base_url, suite)
    sessions, auth = {}, []
    for a in suite.get("accounts", []):
        actor = a["id"]
        user, password = (
            env.get(env_name(actor, "username")),
            env.get(env_name(actor, "password")),
        )
        try:
            if not user or not password:
                raise ValueError("Test credentials missing")
            status, data, _ = _response_parts(
                http.request(
                    actor,
                    "POST",
                    a["login_path"],
                    {a["username_field"]: user, a["password_field"]: password},
                    encoding=a["encoding"],
                )
            )
            if not 200 <= status < 300:
                raise ValueError("Login rejected")
            headers = {}
            if a["session"] == "bearer":
                token = field(data, a["token_path"])
                if (
                    not isinstance(token, str)
                    or not token
                    or len(token) > 8192
                    or any(ord(c) < 32 for c in token)
                ):
                    raise ValueError("Invalid token")
                headers["Authorization"] = "Bearer " + token
            status, identity, _ = _response_parts(
                http.request(actor, "GET", a["verify_path"], headers=headers)
            )
            if status != 200 or str(field(identity, a["identity_path"])) != user:
                raise ValueError("Authenticated identity was not verified")
            sessions[actor] = headers
            auth.append({"actor": actor, "role": a["role"], "status": "verified"})
        except (ValueError, KeyError, TypeError, IndexError, OSError, RuntimeError):
            auth.append(
                {
                    "actor": actor,
                    "role": a["role"],
                    "status": "blocked",
                    "reason": "Check credentials, login schema and identity endpoint",
                }
            )
    records, observations = [], []
    for w in suite["workflows"]:
        variables, blocked, steps = {}, False, []
        for index, step in enumerate(w["steps"], 1):
            actor = step.get("actor", "anonymous")
            record = {
                "step": index,
                "actor": actor,
                "method": step["method"],
                "path": step["path"],
                "security_check": step.get("security_check", False),
            }
            if blocked or (actor != "anonymous" and actor not in sessions):
                record.update(
                    status="skipped",
                    reason="Prerequisite or account verification did not complete",
                )
                blocked = True
            else:
                try:
                    if step.get("wait_before_seconds", 0):
                        time.sleep(step["wait_before_seconds"])
                    path = substitute(step["path"], variables, path=True)
                    body = substitute(step.get("body"), variables)
                    multipart = substitute(step.get("multipart"), variables)
                    if (
                        multipart is not None
                        and len(multipart["content"].encode("utf-8", "replace")) > 4096
                    ):
                        raise ValueError("Substituted upload exceeds 4 KiB")
                    request_options = (
                        {"multipart": multipart} if multipart is not None else {}
                    )
                    request_headers = dict(sessions.get(actor) or {})
                    if "auth_probe" in step:
                        request_headers.update(_auth_probe_headers(step["auth_probe"]))
                    status, response, metadata = _response_parts(
                        http.request(
                            actor,
                            step["method"],
                            path,
                            body,
                            headers=request_headers,
                            **request_options,
                        )
                    )
                    # Evidence deliberately excludes bodies, tokens, personal data and captured values.
                    checks = [status in step["expect_status"]]
                    check_details = [
                        {"kind": "status", "operator": "in", "passed": checks[0]}
                    ]
                    for assertion in step.get("assertions", []):
                        try:
                            actual, present = field(response, assertion["path"]), True
                        except (KeyError, IndexError, TypeError):
                            actual, present = None, False
                        expected = substitute(assertion.get("value"), variables)
                        op = assertion["op"]
                        if op in {"absent", "present"}:
                            ok = not present if op == "absent" else present
                        elif not present:
                            ok = False
                        elif op == "eq":
                            ok = actual == expected
                        elif op == "ne":
                            ok = actual != expected
                        else:
                            ok = (
                                type(actual) in (float, int)
                                and type(expected) in (float, int)
                                and (
                                    actual >= expected
                                    if op == "gte"
                                    else actual <= expected
                                )
                            )
                        checks.append(ok)
                        check_details.append(
                            {
                                "kind": "json",
                                "operator": op,
                                "field": assertion["path"],
                                "passed": ok,
                                "expected_value_redacted": op
                                not in {"present", "absent"},
                            }
                        )
                    for assertion in step.get("response_assertions", []):
                        ok = _response_check(assertion, metadata)
                        checks.append(ok)
                        check_details.append(
                            {
                                "kind": "response",
                                "operator": assertion["op"],
                                "field": assertion.get("name", "body"),
                                "passed": ok,
                                "expected_value_redacted": "contains"
                                in assertion["op"],
                            }
                        )
                    passed = all(checks)
                    # A server error or authentication failure cannot by itself prove a business vulnerability.
                    explicit_response_rule = (
                        bool(step.get("response_assertions")) and checks[0]
                    )
                    prior_failed_attempts = sum(
                        prior_step.get("method") == "POST"
                        and prior_step.get("path") == step["path"]
                        and prior_step.get("body") == step.get("body")
                        and prior_record.get("http_status") == 401
                        for prior_step, prior_record in zip(
                            w["steps"][: index - 1], steps
                        )
                    )
                    lockout_mismatch = (
                        step.get("lockout_after_failures") is not None
                        and status == 401
                        and not checks[0]
                        and prior_failed_attempts >= step["lockout_after_failures"]
                    )
                    inconclusive = (
                        None in checks
                        or (
                            (status >= 500 or 300 <= status < 400)
                            and not explicit_response_rule
                        )
                        or (
                            status in {401, 403, 404}
                            and not checks[0]
                            and not lockout_mismatch
                        )
                    )
                    state = (
                        "passed"
                        if passed
                        else "inconclusive"
                        if inconclusive
                        else "violation"
                        if step.get("security_check")
                        else "blocked"
                    )
                    record.update(
                        status=state,
                        http_status=status,
                        expected_status=step["expect_status"],
                        assertion_results=checks,
                        assertion_checks=check_details,
                    )
                    if "auth_probe" in step:
                        record["auth_probe_kind"] = step["auth_probe"]["kind"]
                    if state == "violation":
                        observations.append(
                            {
                                "rule_id": f"workflow.{w['id']}.{index}",
                                "source": "runtime-workflow",
                                "title": w["title"],
                                "path": step["path"],
                                "vulnerable": True,
                                "severity": w.get("severity", "medium"),
                                "confidence": "medium",
                                "evidence": {
                                    "workflow_id": w["id"],
                                    "step": index,
                                    "actor": actor,
                                    "method": step["method"],
                                    "status": status,
                                    "expected_statuses": step["expect_status"],
                                    "assertion_results": checks,
                                    "assertion_checks": check_details,
                                    "values_redacted": True,
                                    **(
                                        {"auth_probe_kind": step["auth_probe"]["kind"]}
                                        if "auth_probe" in step
                                        else {}
                                    ),
                                    **(
                                        {
                                            "lockout_after_failures": step[
                                                "lockout_after_failures"
                                            ],
                                            "prior_failed_attempts": prior_failed_attempts,
                                        }
                                        if lockout_mismatch
                                        else {}
                                    ),
                                },
                            }
                        )
                    if not passed:
                        blocked = True
                    if passed:
                        for key, source in step.get("capture", {}).items():
                            captured = field(response, source)
                            if (
                                type(captured) not in (int, float, str, bool)
                                or len(str(captured)) > 8192
                            ):
                                raise ValueError("Unsupported capture")
                            variables[key] = captured
                except (
                    ValueError,
                    KeyError,
                    TypeError,
                    IndexError,
                    OSError,
                    RuntimeError,
                ):
                    record.update(
                        status="blocked",
                        reason="Request, capture or budget could not be completed; response values withheld",
                    )
                    blocked = True
            steps.append(record)
        states = {s["status"] for s in steps}
        records.append(
            {
                "id": w["id"],
                "title": w["title"],
                "status": "partial"
                if states & {"blocked", "skipped", "inconclusive"}
                else "violation"
                if "violation" in states
                else "passed",
                "steps": steps,
            }
        )
    incomplete = any(r["status"] == "partial" for r in records) or any(
        a["status"] != "verified" for a in auth
    )
    return {
        "status": "partial" if incomplete else "completed",
        "contract_sha256": hashlib.sha256(
            json.dumps(suite, sort_keys=True).encode()
        ).hexdigest(),
        "accounts": auth,
        "workflows": records,
        "results": observations,
        "coverage": {
            "declared": sum(len(w["steps"]) for w in suite["workflows"]),
            "executed": sum("http_status" in s for w in records for s in w["steps"]),
            "violations": len(observations),
            "unresolved": sum(
                s["status"] in {"skipped", "blocked", "inconclusive"}
                for w in records
                for s in w["steps"]
            ),
        },
        "limitations": [
            "Coverage applies only to declared assertions, accounts and workflows.",
            "A violation is an observed contract mismatch requiring security review.",
            "Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.",
        ],
    }


def append_workflows(runtime_path: Path, suite, *, disposable):
    payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    evidence = run_workflows(payload["target"], suite, disposable=disposable)
    payload["workflow_evidence"] = evidence
    payload["results"].extend(evidence["results"])
    payload["authorization_checks_enabled"] = bool(suite.get("accounts"))
    payload["mutating_checks_enabled"] = suite.get("allow_mutation", False)
    payload["coverage_notes"].extend(evidence["limitations"])
    if evidence["status"] != "completed":
        payload["status"] = "partial"
        payload["coverage_notes"].append(
            "Declared workflows did not all complete; inspect workflow_evidence."
        )
    runtime_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    runtime_path.with_name("workflow-evidence.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf-8"
    )
    return evidence

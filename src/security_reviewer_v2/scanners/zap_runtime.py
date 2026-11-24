"""Bounded ZAP Automation Framework scans of an authorized local target."""
from __future__ import annotations
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from security_reviewer_v2.test_environment.leases import register, release

IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
MAX_RESULTS = 500


def automation_plan(origin: str, *, active=False, auth=None, scope_path: str | None = None):
    """Build a ZAP Automation Framework plan.

    ``scope_path`` narrows the crawl/scan to one path instead of the whole origin — used by the
    Penetration Agent's :mod:`dynamic_penetration_agent.zap_attempt` to run one scoped attempt
    against a single hypothesis's endpoint rather than re-spidering and re-scanning the entire
    application for every attempt. ``None`` (the default) keeps the original whole-origin plan
    unchanged, so every existing caller and test is unaffected.
    """
    if scope_path is not None and (
        not scope_path.startswith("/") or scope_path.startswith("//") or "\\" in scope_path
        or "#" in scope_path or len(scope_path) > 500 or any(ord(char) < 32 for char in scope_path)
    ):
        raise ValueError("scope_path must be a bounded same-origin path")
    target = origin + scope_path if scope_path is not None else origin + "/"
    include = [re.escape(origin + scope_path) + r"(?:[/?].*)?$"] if scope_path is not None else \
              [re.escape(origin) + r"(?:/.*)?"]
    context = {"name": "verdict", "urls": [origin], "includePaths": include,
               "excludePaths": [re.escape(origin) + r"/.*(?i:logout|signout|delete|destroy).*" ]}
    spider = {"type": "spider", "parameters": {"context": "verdict", "url": target,
              "maxDuration": 1, "maxDepth": 0 if scope_path is not None else 3, "maxChildren": 10,
              "logoutAvoidance": True, "processForm": False, "postForm": False},
              "tests": [{"name": "At least one scoped URL must be visited", "type": "stats",
                         "statistic": "automation.spider.urls.added", "operator": ">=", "value": 1, "onFail": "error"}]}
    if auth:
        path = str(auth.get("login_path", ""))
        page_path = str(auth.get("login_page_path", path))
        start_path = str(auth.get("start_path", "/"))
        if any(not value.startswith("/") or value.startswith("//") or "\\" in value or "#" in value
               or len(value) > 500 or any(ord(char) < 32 for char in value)
               for value in (path, page_path, start_path)):
            raise ValueError("Login path must remain inside the target")
        user_field = str(auth.get("username_field", "username"))
        pass_field = str(auth.get("password_field", "password"))
        if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\[\]-]{0,63}", f) for f in (user_field, pass_field)):
            raise ValueError("Unsupported login form field names")
        marker = str(auth.get("logged_in_regex", ""))
        if not marker or len(marker) > 256:
            raise ValueError("Supply a specific logged-in response indicator (at most 256 characters)")
        context.update(authentication={"method": "form", "parameters": {
            "loginPageUrl": origin + page_path, "loginRequestUrl": origin + path,
            "loginRequestBody": user_field + "={%username%}&" + pass_field + "={%password%}"},
            "verification": {"method": "response", "loggedInRegex": marker}},
            sessionManagement={"method": "cookie"}, users=[{"name": "tester", "credentials": {
                "username": "${SECURITY_TEST_ZAP_USERNAME}", "password": "${SECURITY_TEST_ZAP_PASSWORD}"}}])
        spider["parameters"]["user"] = "tester"
        spider["parameters"]["url"] = origin + start_path
        spider["tests"].append({"name": "Authenticated response must be observed", "type": "stats", "statistic": "stats.auth.state.loggedin",
                              "site": origin, "operator": ">=", "value": 1, "onFail": "error"})
    jobs = [spider, {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}}]
    if active:
        params = {"context": "verdict", "maxRuleDurationInMins": 1, "maxScanDurationInMins": 3,
                  "threadPerHost": 2, "delayInMs": 100, "maxAlertsPerRule": 10}
        if auth:
            params["user"] = "tester"
        if scope_path is not None:
            params["url"] = target
        jobs.extend([{"type": "activeScan", "parameters": params},
                     {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}}])
    jobs.append({"type": "report", "parameters": {"template": "traditional-json", "reportDir": "/zap/wrk",
                                                   "reportFile": "zap-report.json", "displayReport": False}})
    return {"env": {"contexts": [context], "parameters": {"failOnError": True, "failOnWarning": False,
             "continueOnFailure": False, "progressToStdout": True, "maxDuration": 600}}, "jobs": jobs}


def parse_alerts(payload, origin):
    results = []
    for site in payload.get("site", []):
        if str(site.get("@name", "")).rstrip("/") != origin.rstrip("/"):
            continue
        for alert in site.get("alerts", [])[:1000]:
            risk = str(alert.get("riskcode", "0"))
            if risk == "0" or str(alert.get("confidence", "1")) == "0":
                continue
            for instance in alert.get("instances", [])[:50]:
                url = urlsplit(str(instance.get("uri", "")))
                if f"{url.scheme}://{url.netloc}" != origin:
                    continue
                results.append({"rule_id": "zap." + str(alert.get("pluginid", "unknown")),
                    "source": "owasp-zap", "title": str(alert.get("name", alert.get("alert", "ZAP alert")))[:300],
                    "path": url.path or "/", "vulnerable": True,
                    "severity": {"1": "low", "2": "medium", "3": "high"}.get(risk, "medium"),
                    "confidence": {"1": "low", "2": "medium", "3": "high", "4": "high"}.get(str(alert.get("confidence")), "low"),
                    "evidence": {"scanner_rule": str(alert.get("pluginid", "")), "method": str(instance.get("method", "GET"))[:10],
                                 "parameter": str(instance.get("param", ""))[:80], "values_redacted": True,
                                 "cwe_id": str(alert.get("cweid", ""))[:12]}})
                if len(results) > MAX_RESULTS:
                    return results  # One extra record signals truncation to the caller.
    return results


def run_zap(base_url: str, runtime_path: Path, *, engine: str, stack_name=None, app_service=None, auth=None,
            scope_path: str | None = None, max_seconds: int | None = None):
    """Run one ZAP Automation Framework job and merge its alerts into ``runtime_path``.

    ``scope_path`` and ``max_seconds`` are additive, optional, and used only by the Penetration
    Agent's scoped one-endpoint attempts (:mod:`dynamic_penetration_agent.zap_attempt`); every
    existing caller passes neither and gets the original whole-origin behavior unchanged.
    """
    if engine == "zap-automated-scan":
        engine = "zap-active"  # same engine (spider -> passive -> active -> passive -> report); clearer name
    if engine == "baseline":
        return
    if engine not in {"zap-passive", "zap-active"}:
        raise ValueError("Unsupported DAST engine")
    if engine == "zap-active" and not stack_name:
        raise ValueError("Active ZAP (Automated Scan) is limited to disposable Compose targets")
    docker = shutil.which("docker")
    if not docker:
        raise ValueError("Docker is required for ZAP")
    def command(args, timeout=30):
        result = subprocess.run([docker, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError("ZAP Docker prerequisite failed: " + result.stderr[-500:])
        return result.stdout.strip()
    image_id = command(["image", "inspect", IMAGE, "--format", "{{.Id}}"])
    network = []
    if stack_name:
        ids = command(["ps", "--filter", f"label=com.docker.compose.project={stack_name}", "--filter",
                       f"label=com.docker.compose.service={app_service}", "--format", "{{.ID}}"]).splitlines()
        if len(ids) != 1 or not re.fullmatch(r"[a-f0-9]+", ids[0]):
            raise RuntimeError("ZAP requires one identified app container")
        info = json.loads(command(["inspect", ids[0]]))[0]
        ports = info.get("NetworkSettings", {}).get("Ports", {})
        host_port = str(urlsplit(base_url).port)
        targets = [int(key.split("/")[0]) for key, mappings in ports.items()
                   if mappings and any(m.get("HostPort") == host_port for m in mappings)]
        if len(targets) != 1:
            raise RuntimeError("Cannot identify app port for ZAP")
        origin = f"http://127.0.0.1:{targets[0]}"
        network = ["--network", "container:" + ids[0]]
    else:
        origin = f"http://host.docker.internal:{urlsplit(base_url).port}"
    if auth and not all(os.environ.get(key) for key in ("SECURITY_TEST_ZAP_USERNAME", "SECURITY_TEST_ZAP_PASSWORD")):
        raise ValueError("Save the test account in the OS credential vault first")
    plan = automation_plan(origin, active=engine == "zap-active", auth=auth, scope_path=scope_path)
    name = "sr-zap-" + secrets.token_hex(5)
    lease, _ = register(name)
    with tempfile.TemporaryDirectory(prefix="verdict-zap-") as directory:
        folder = Path(directory)
        folder.chmod(0o777)
        (folder / "plan.yaml").write_text(json.dumps(plan), encoding="utf-8")
        command_args = [docker, "run", "--rm", "--name", name, "--cpus", "2", "--memory", "2g",
                        "--pids-limit", "512", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                        *network, "-v", str(folder) + ":/zap/wrk:rw"]
        if auth:
            command_args.extend(["-e", "SECURITY_TEST_ZAP_USERNAME", "-e", "SECURITY_TEST_ZAP_PASSWORD"])
        # ZAP shares the app's network namespace. Its default proxy port (8080)
        # would collide with many application servers, including our templates.
        proxy_port = "8099" if urlsplit(origin).port != 8099 else "8100"
        command_args.extend([image_id, "zap.sh", "-cmd", "-host", "127.0.0.1", "-port", proxy_port,
                             "-autorun", "/zap/wrk/plan.yaml"])
        print("ZAP: crawling the scoped target and collecting bounded evidence…", flush=True)
        try:
            completed = subprocess.run(command_args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=max_seconds or 660, check=False)
            report = folder / "zap-report.json"
            if completed.returncode not in {0, 2} or not report.is_file():
                from security_reviewer_v2.web.credentials import redact
                lines = [line[:500] for line in (completed.stdout + completed.stderr).splitlines()
                         if line.startswith(("Job ", "Automation plan", "\tJob ", "\tUnrecognised", "\tUnrecognized", "\tTest ",
                                             "Failed to start", "Terminating ZAP"))]
                safe = redact("\n".join(lines[-30:]), dict(os.environ))
                runtime_path.with_name("zap-diagnostics.json").write_text(json.dumps({"status": "failed",
                    "exit_code": completed.returncode, "events": safe}, indent=2), encoding="utf-8")
                raise RuntimeError("ZAP did not finish its plan (including login verification if configured). Check scope/login settings; no successful ZAP result was recorded.")
            if report.stat().st_size > 50_000_000:
                raise RuntimeError("ZAP report exceeded the 50 MB evidence limit; no complete result was recorded")
            payload = json.loads(report.read_text(encoding="utf-8"))
            additions = parse_alerts(payload, origin)
            truncated = len(additions) > MAX_RESULTS
            additions = additions[:MAX_RESULTS]
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            runtime.setdefault("results", []).extend(additions)
            runtime["zap"] = {"status": "completed", "engine": engine, "image_id": image_id,
                              "alerts": len(additions), "results_truncated": truncated,
                              "authentication": "verified" if auth else "anonymous",
                              "limits": "Traditional spider: 1 minute / depth 3. Active scan: at most 3 minutes.",
                              "limitations": ["Not exhaustive", "No generic IDOR or business-workflow proof", "No JavaScript browser crawl"]}
            if truncated:
                runtime["zap"]["limitations"].append("ZAP observations were limited to 500; additional observations were not imported.")
                runtime.setdefault("coverage_notes", []).append("ZAP observation import was truncated at 500 results.")
            runtime_path.write_text(json.dumps(runtime, indent=2), encoding="utf-8")
        finally:
            subprocess.run([docker, "rm", "--force", name], capture_output=True, timeout=30, check=False)
            if command(["ps", "--all", "--filter", f"name=^/{name}$", "--format", "{{.ID}}"]):
                raise RuntimeError("ZAP container cleanup is unverified")
            release(lease)

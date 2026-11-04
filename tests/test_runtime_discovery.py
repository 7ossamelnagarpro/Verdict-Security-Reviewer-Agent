from __future__ import annotations

import json
from pathlib import Path

from security_reviewer_v2.web.runtime_discovery import discover


def test_discovery_reads_python_framework_routes_and_draft(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/healthz')\ndef health(): pass\n@app.post('/auth/login')\ndef login(): pass\n@app.get('/me')\ndef me(): pass\n",
        encoding="utf-8",
    )
    result = discover(tmp_path)
    assert result["framework"]["name"] == "FastAPI"
    assert {item["path"] for item in result["endpoints"]} == {
        "/healthz",
        "/auth/login",
        "/me",
    }
    assert result["health_path"] == "/healthz"
    assert result["login"]["path"] == "/auth/login"
    assert result["runtime_contract_draft"]["accounts"] == []


def test_discovery_reads_javascript_and_openapi_yaml_without_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express'); const app = express();\napp.get('/items', handler);\nrouter.post('/items', handler);\n",
        encoding="utf-8",
    )
    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.0.0\npaths:\n  /health:\n    get:\n      responses: {}\n  /items:\n    post:\n      responses: {}\n",
        encoding="utf-8",
    )
    result = discover(tmp_path)
    assert {("GET", "/items"), ("POST", "/items"), ("GET", "/health")} <= {
        (item["method"], item["path"]) for item in result["endpoints"]
    }
    assert result["framework"]["name"] == "Express/Fastify"


def test_browser_dast_records_missing_optional_runtime(
    tmp_path: Path, monkeypatch
) -> None:
    from security_reviewer_v2.scanners import browser_runtime

    monkeypatch.setattr(browser_runtime.shutil, "which", lambda _name: None)
    runtime = tmp_path / "runtime.json"
    runtime.write_text(
        json.dumps({"status": "completed", "results": []}), encoding="utf-8"
    )
    evidence = browser_runtime.run_browser_dast(
        "http://127.0.0.1:8080", runtime, tmp_path / "browser-runtime-evidence.json"
    )
    assert evidence["status"] == "blocked"
    assert (tmp_path / "browser-runtime-evidence.json").is_file()


def test_browser_seed_paths_are_scoped_and_passed_to_runner(
    tmp_path: Path, monkeypatch
) -> None:
    import subprocess

    from security_reviewer_v2.scanners import browser_runtime

    monkeypatch.setattr(browser_runtime.shutil, "which", lambda _name: "node")
    seen = []

    def fake_run(argv, **_kwargs):
        seen.extend(argv)
        return subprocess.CompletedProcess(
            argv, 0, '{"status":"completed","pages_visited":2,"results":[]}', ""
        )

    monkeypatch.setattr(browser_runtime.subprocess, "run", fake_run)
    runtime = tmp_path / "runtime.json"
    runtime.write_text(
        json.dumps({"status": "completed", "results": []}), encoding="utf-8"
    )
    evidence = browser_runtime.run_browser_dast(
        "http://127.0.0.1:8080",
        runtime,
        tmp_path / "browser.json",
        seed_paths=("/view", "/catalog/search?q=widget"),
    )
    assert evidence["pages_visited"] == 2
    assert json.loads(seen[seen.index("--seed-paths-json") + 1]) == [
        "/view",
        "/catalog/search?q=widget",
    ]
    blocked = browser_runtime.run_browser_dast(
        "http://127.0.0.1:8080",
        runtime,
        tmp_path / "blocked.json",
        seed_paths=("//evil.example",),
    )
    assert blocked["status"] == "blocked"

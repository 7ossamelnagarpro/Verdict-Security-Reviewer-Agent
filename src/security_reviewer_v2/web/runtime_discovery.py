"""Bounded, read-only discovery for runtime setup suggestions.

Discovery never imports, builds, starts, or sends requests to the target. It
only reads small source/configuration files and returns suggestions that the
developer must review before a DAST run.
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
EXCLUDED = {".git", ".venv", "venv", "node_modules", "reports", "benchmark", "__pycache__", "dist", "build"}


def _literal(value: ast.AST) -> str | None:
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def _decorator_routes(node: ast.FunctionDef | ast.AsyncFunctionDef, relative: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for decorator in node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        func = call.func if call else decorator
        method_name = func.attr.lower() if isinstance(func, ast.Attribute) else ""
        if not method_name:
            continue
        args = call.args if call else []
        route = _literal(args[0]) if args else None
        if not route or not route.startswith("/"):
            continue
        methods: list[str]
        if method_name == "route":
            methods = []
            for keyword in (call.keywords if call else []):
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                    methods = [str(item.value).upper() for item in keyword.value.elts
                               if isinstance(item, ast.Constant) and str(item.value).upper() in HTTP_METHODS]
            methods = methods or ["GET"]
        elif method_name.upper() in HTTP_METHODS:
            methods = [method_name.upper()]
        else:
            continue
        for method in methods:
            found.append({"method": method, "path": route,
                          "source": f"{relative}:{getattr(decorator, 'lineno', node.lineno)}",
                          "confidence": "source declaration; router prefixes need confirmation"})
    return found


def _python_routes(text: str, relative: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    routes: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            routes.extend(_decorator_routes(node, relative))
    return routes


def _javascript_routes(text: str, relative: str) -> list[dict[str, Any]]:
    # Conservative patterns for Express/Fastify routers. They never execute JS.
    routes: list[dict[str, Any]] = []
    pattern = re.compile(r"\b(?:app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['\"]([^'\"]+)")
    for match in pattern.finditer(text):
        method, path = match.group(1).upper(), match.group(2)
        if path.startswith("/"):
            line = text.count("\n", 0, match.start()) + 1
            routes.append({"method": method, "path": path, "source": f"{relative}:{line}",
                           "confidence": "static JavaScript route; mounted prefixes need confirmation"})
    return routes


def _openapi_routes(path: Path, relative: str, text: str) -> list[dict[str, Any]]:
    if path.suffix == ".json":
        try:
            document = json.loads(text)
        except (ValueError, TypeError):
            return []
        paths = document.get("paths", {}) if isinstance(document, dict) else {}
        return [{"method": method.upper(), "path": route, "source": relative,
                 "confidence": "OpenAPI declaration; runtime validation pending"}
                for route, operations in paths.items() if isinstance(route, str) and isinstance(operations, dict)
                for method in operations if method.upper() in HTTP_METHODS]
    routes: list[dict[str, Any]] = []
    current: str | None = None
    for line in text.splitlines():
        path_match = re.match(r"^\s{2}(/[^:]+):\s*$", line)
        if path_match:
            current = path_match.group(1).strip()
            continue
        method_match = re.match(r"^\s{4}(get|post|put|patch|delete|head|options):\s*$", line, re.I)
        if method_match and current:
            routes.append({"method": method_match.group(1).upper(), "path": current,
                           "source": relative, "confidence": "OpenAPI YAML declaration; runtime validation pending"})
    return routes


def _framework(names: set[str], snippets: list[tuple[str, str]]) -> dict[str, str]:
    text = "\n".join(value.lower() for _, value in snippets)
    if "fastapi" in text or "from fastapi" in text:
        return {"name": "FastAPI", "confidence": "high", "evidence": "FastAPI import/dependency detected"}
    if "flask" in text or "from flask" in text:
        return {"name": "Flask", "confidence": "high", "evidence": "Flask import/dependency detected"}
    if "express" in text or "fastify" in text:
        return {"name": "Express/Fastify", "confidence": "medium", "evidence": "Node web framework dependency detected"}
    if {"package.json", "requirements.txt", "pyproject.toml"} & names:
        return {"name": "Unknown web application", "confidence": "low", "evidence": "Application manifest detected"}
    return {"name": "Unknown", "confidence": "low", "evidence": "No supported framework signature found"}


def discover(project: Path) -> dict[str, Any]:
    endpoints: list[dict[str, Any]] = []
    inspected = 0
    visited = 0
    names: set[str] = set()
    snippets: list[tuple[str, str]] = []

    def candidates():
        for root, dirs, files in os.walk(project, followlinks=False):
            dirs[:] = [d for d in dirs if d not in EXCLUDED and not d.startswith('.') and not (Path(root) / d).is_symlink()]
            for name in files:
                yield Path(root) / name

    for path in candidates():
        visited += 1
        if len(endpoints) >= 250 or inspected >= 700 or visited >= 4000:
            break
        try:
            relative = path.relative_to(project)
            if any(p in EXCLUDED or p.startswith(".") for p in relative.parts) or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(project):
                continue
            if path.stat().st_size > 262144:
                continue
            suffix = path.suffix.lower()
            if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".txt"}:
                continue
            inspected += 1
            names.add(path.name.lower())
            text = path.read_text(encoding="utf-8")
            if len(snippets) < 100:
                snippets.append((relative.as_posix(), text[:20000]))
            if suffix == ".py":
                endpoints.extend(_python_routes(text, relative.as_posix()))
            elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
                endpoints.extend(_javascript_routes(text, relative.as_posix()))
            elif path.name.lower() in {"openapi.json", "swagger.json", "openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml"}:
                endpoints.extend(_openapi_routes(path, relative.as_posix(), text))
        except (UnicodeError, OSError):
            continue

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for endpoint in endpoints:
        key = (endpoint["method"], endpoint["path"], endpoint["source"])
        if key not in seen:
            seen.add(key)
            unique.append(endpoint)
    endpoints = unique[:250]
    health = next((e["path"] for e in endpoints if e["method"] == "GET" and e["path"].rstrip("/") in {"/healthz", "/health", "/ready", "/health/ready"}), None)
    login_endpoint = next((e for e in endpoints if e["method"] == "POST" and e["path"].lower().endswith(("/login", "/token", "/auth"))), None)
    login = None
    if login_endpoint:
        login = {"path": login_endpoint["path"], "method": "POST", "encoding": "json",
                 "username_field": "username", "password_field": "password",
                 "session": "bearer", "token_path": "access_token", "verify_path": None,
                 "confidence": "suggestion; confirm request/response fields and session behavior"}
    lower_text = "\n".join(text for _, text in snippets).lower()
    unsupported = [f"{label} requires a dedicated workflow adapter or browser test"
                   for label, marker in (("OAuth", "oauth"), ("MFA", "mfa"), ("GraphQL", "graphql"),
                                          ("WebSocket", "websocket"), ("file upload", "multipart/form-data"))
                   if marker in lower_text]
    framework = _framework(names, snippets)
    gaps = ["Mounted router prefixes and dynamic routes need confirmation."]
    if not endpoints:
        gaps.append("No supported route declaration was found; provide endpoint paths or an OpenAPI document.")
    if login and not any(e["path"] == "/me" for e in endpoints):
        gaps.append("A login route was found but no identity verification endpoint was inferred; configure it in the Runtime Contract.")
    gaps.extend(unsupported)
    suggested = {"health_path": health or "/", "expected_status": "200",
                 "endpoints": "\n".join(dict.fromkeys(e["path"] for e in endpoints if e["method"] == "GET")),
                 "login_path": login["path"] if login else ""}
    return {"schema_version": "1.1", "framework": framework, "endpoints": endpoints,
            "health_path": health, "login_path": login["path"] if login else None, "login": login,
            "suggested_setup": suggested, "coverage_gaps": gaps, "unsupported_features": unsupported,
            "runtime_contract_draft": {"version": 1, "accounts": [], "workflows": [],
                                       "allow_mutation": False, "reset": "none", "max_requests": 100,
                                       "max_seconds": 300, "timeout_seconds": 5,
                                       "source": "read-only route discovery; review before use"},
            "inspected_files": inspected, "visited_files": visited,
            "notes": ["Suggestions only: confirm expected statuses, prefixes, authentication and business rules.",
                      "Discovery reads source declarations; it does not import, execute, build or contact the application.",
                      "No credentials or benchmark answers are read or inferred."]}

"""Validate completed, fixed-target DAST evidence from a trusted Docker lab."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any


_RUN_ID = re.compile(r"[0-9a-f]{8}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 1024 * 1024
_RESULTS = (("runtime.json", "web-runtime"),
            ("authorization.json", "tt-authorization-runtime"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_BYTES:
        raise ValueError(f"Docker runtime artifact is missing, linked, or oversized: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Docker runtime artifact is invalid JSON: {path.name}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"Docker runtime artifact must be an object: {path.name}")
    return payload


def _flask_debug_startup(project: Path) -> dict[str, object] | None:
    """Describe only the hash-matched, unoverridden Dockerfile CMD.

    This is a configuration observation, not proof about arbitrary deployments.
    Unknown syntax deliberately leaves the finding for ordinary review.
    """
    dockerfile = (project / "Dockerfile").read_text(encoding="utf-8")
    compose = (project / "compose.yaml").read_text(encoding="utf-8")
    if re.search(r"(?im)^\s*(?:command|entrypoint)\s*:", compose):
        return None
    if len(re.findall(r"(?im)^\s*CMD\b", dockerfile)) != 1:
        return None
    commands = re.findall(r"(?im)^\s*CMD\s+(\[.*\])\s*$", dockerfile)
    if len(commands) != 1 or re.search(r"(?im)^\s*ENTRYPOINT\b", dockerfile):
        return None
    try:
        command = json.loads(commands[0])
        if (not isinstance(command, list) or len(command) != 3 or
                command[:2] not in (["python", "-c"], ["python3", "-c"]) or
                not isinstance(command[2], str)):
            return None
        tree = ast.parse(command[2])
    except (ValueError, SyntaxError, json.JSONDecodeError):
        return None
    imports_app = any(isinstance(node, ast.ImportFrom) and node.module == "app" and
                      any(alias.name == "app" and alias.asname is None for alias in node.names)
                      for node in tree.body)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
             isinstance(node.func, ast.Attribute) and node.func.attr == "run" and
             isinstance(node.func.value, ast.Name) and node.func.value.id == "app"]
    if not imports_app or len(calls) != 1:
        return None
    debug = [keyword.value.value for keyword in calls[0].keywords
             if keyword.arg == "debug" and isinstance(keyword.value, ast.Constant)
             and type(keyword.value.value) is bool]
    if len(debug) != 1:
        return None
    return {"backend": "docker_compose", "flask_debug": debug[0],
            "basis": "hash-matched Dockerfile CMD without Compose command/entrypoint override"}


def load_docker_runtime(run_id: str, *, project_root: Path,
                        repository_root: Path) -> dict[str, object]:
    """Reject incomplete cleanup, source changes, and mismatched probe output."""
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("Docker runtime run ID must be eight lowercase hexadecimal characters")
    repository = repository_root.resolve(strict=True)
    project = project_root.resolve(strict=True)
    target = (repository / "targets" / "security-lab-web").resolve(strict=True)
    if project != target:
        raise ValueError("Automatic Docker DAST currently supports only Security Lab Web")
    result_root = repository / "reports" / "docker-autoscan" / run_id
    if (not result_root.is_dir() or result_root.is_symlink() or
            result_root.resolve(strict=True) != result_root.absolute()):
        raise ValueError("Completed Docker runtime result directory is unavailable")
    manifest_path = result_root / "manifest.json"
    manifest = _read_json(manifest_path)
    if (manifest.get("schema_version") != "1.0" or manifest.get("run_id") != run_id or
            manifest.get("target_id") != "security-lab-web" or
            manifest.get("backend") != "docker_compose" or
            manifest.get("status") != "passed" or
            manifest.get("stack_removed") is not True or
            manifest.get("network_exposure") != "host_loopback_only" or
            manifest.get("http_status") != 200 or
            type(manifest.get("mutating_checks_enabled")) is not bool):
        raise ValueError("Docker runtime did not attest a passing scan and stack cleanup")
    source_hashes = manifest.get("source_sha256")
    if not isinstance(source_hashes, dict):
        raise ValueError("Docker runtime source fingerprint is missing")
    for filename in ("app.py", "requirements.txt", "Dockerfile", "compose.yaml",
                     ".dockerignore", "secret_do_not_serve.txt", "files/report.txt"):
        expected = source_hashes.get(filename)
        source = project / filename
        if (not isinstance(expected, str) or not _SHA256.fullmatch(expected) or
                not source.is_file() or source.is_symlink() or
                sha256_file(source) != expected):
            raise ValueError(f"Security Lab Web source changed since Docker DAST: {filename}")
    output_hashes = manifest.get("output_sha256")
    probe_counts = manifest.get("probe_counts")
    if not isinstance(output_hashes, dict) or not isinstance(probe_counts, dict):
        raise ValueError("Docker DAST output inventory is missing")
    result_paths: dict[str, str] = {}
    counts: dict[str, int] = {}
    for filename, expected_source in _RESULTS:
        path = result_root / filename
        payload = _read_json(path)
        expected_hash = output_hashes.get(filename)
        expected_count = probe_counts.get(filename)
        if (not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash) or
                sha256_file(path) != expected_hash or
                payload.get("schema_version") != "1.0" or
                payload.get("source") != expected_source or
                payload.get("target") != "http://127.0.0.1:5055" or
                payload.get("status") != "completed" or
                not isinstance(payload.get("results"), list) or
                type(expected_count) is not int or expected_count < 1 or
                len(payload["results"]) != expected_count):
            raise ValueError(f"Docker DAST result did not match its manifest: {filename}")
        result_paths[filename] = str(path)
        counts[filename] = expected_count
    zap = _read_json(result_root / "runtime.json").get("zap")
    return {
        "schema_version": "1.0", "status": "passed", "run_id": run_id,
        "target_id": "security-lab-web", "backend": "docker_compose",
        "http_status": 200, "app_sha256": source_hashes["app.py"],
        "mutating_checks_enabled": manifest["mutating_checks_enabled"],
        "network_exposure": "host_loopback_only", "stack_removed": True,
        "probe_counts": counts, "result_paths": result_paths,
        "manifest_path": str(manifest_path),
        "deployment_context": _flask_debug_startup(project),
        "zap": zap,
        "limitations": [
            ("DAST includes bounded Security Lab Web probes and the selected ZAP plan; neither provides exhaustive workflow coverage."
             if zap else "DAST checks are fixed Security Lab Web HTTP probes, not generic browser or business-workflow coverage."),
            "Docker published the test service on host loopback; containers are not strong isolation for untrusted code.",
            "The trusted container build may access package repositories; review and approve the project before execution.",
        ],
    }

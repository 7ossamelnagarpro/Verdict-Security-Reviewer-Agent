"""Fixed, opt-in runtime templates for small trusted local applications."""
from __future__ import annotations
import ast
import json
import re
import shutil
import socket
import tempfile
from contextlib import contextmanager
from pathlib import Path

IGNORED = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "reports", ".idea", ".vscode"}


def detect(root: Path):
    candidates = []
    if (root / "requirements.txt").is_file():
        for name in ("app.py", "main.py", "server.py"):
            path = root / name
            if not path.is_file() or path.stat().st_size > 200_000:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in tree.body:
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                        call = node.value.func
                        kind = getattr(call, "id", getattr(call, "attr", ""))
                        if kind in {"Flask", "FastAPI"} and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                            candidates.append({"runtime_method": "recipe", "runtime_recipe": kind.lower(),
                                               "runtime_entrypoint": f"{path.stem}:{node.targets[0].id}",
                                               "health_path": "/", "expected_status": "200", "endpoints": "/"})
            except (SyntaxError, UnicodeError):
                continue
    package = root / "package.json"
    if package.is_file() and package.stat().st_size < 200_000 and (root / "package-lock.json").is_file():
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
            if "express" in data.get("dependencies", {}) and data.get("scripts", {}).get("start"):
                candidates.append({"runtime_method": "recipe", "runtime_recipe": "express", "runtime_entrypoint": "npm-start",
                                   "health_path": "/", "expected_status": "200", "endpoints": "/"})
        except ValueError:
            pass
    return candidates[0] if len(candidates) == 1 else None


@contextmanager
def prepare(root: Path, kind: str, entry: str, health="/", expected=200, endpoints=()):
    if kind not in {"flask", "fastapi", "express"}:
        raise ValueError("Unsupported runtime template")
    if kind != "express" and not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", entry):
        raise ValueError("Entrypoint must look like app:app or package.main:app")
    if kind == "express" and not (root / "package-lock.json").is_file():
        raise ValueError("Express template requires package-lock.json and npm start")
    if kind != "express" and not (root / "requirements.txt").is_file():
        raise ValueError("Python templates require requirements.txt")
    with tempfile.TemporaryDirectory(prefix="verdict-runtime-") as temporary:
        parent = Path(temporary)
        staging = parent / "app"
        staging.mkdir()
        total = count = 0
        for source in root.rglob("*"):
            relative = source.relative_to(root)
            if any(part in IGNORED or part.startswith(".env") for part in relative.parts):
                continue
            if source.is_symlink() or source.suffix.lower() in {".pem", ".key", ".pfx", ".p12"}:
                continue
            if not source.is_file():
                continue
            if not source.resolve().is_relative_to(root.resolve()):
                raise ValueError("Template source contains a link outside the project")
            total += source.stat().st_size
            count += 1
            if count > 10000 or total > 100_000_000:
                raise ValueError("Template staging is limited to 10,000 files / 100 MB; provide a reviewed Compose setup")
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        if kind == "express":
            dockerfile = 'FROM node:22-bookworm-slim\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY --chown=10001:10001 . .\nENV PORT=8080 HOST=0.0.0.0\nUSER 10001:10001\nCMD ["npm", "start"]\n'
        else:
            command = ["python", "-m", "flask", "--app", entry, "run", "--host=0.0.0.0", "--port=8080"] if kind == "flask" else ["python", "-m", "uvicorn", entry, "--host", "0.0.0.0", "--port", "8080"]
            extra = " uvicorn" if kind == "fastapi" else ""
            dockerfile = 'FROM python:3.11-slim\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt' + extra + '\nCOPY --chown=10001:10001 . .\nENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\nUSER 10001:10001\nCMD ' + json.dumps(command) + '\n'
        (staging / "Dockerfile.verdict").write_text(dockerfile, encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        compose = {"services": {"app": {"build": {"context": ".", "dockerfile": "Dockerfile.verdict"},
                    "ports": [f"127.0.0.1:{port}:8080"], "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true"], "mem_limit": "1g", "cpus": 1.0,
                    "pids_limit": 256}}}
        (staging / "compose.yaml").write_text(json.dumps(compose), encoding="utf-8")
        contract = parent / "runtime.json"
        contract.write_text(json.dumps({"schema_version": "1.0", "mode": "docker_compose",
            "trust_level": "trusted_local_project", "authorized_for_testing": True,
            "compose": {"file": "compose.yaml", "app_service": "app"},
            "target": {"base_url": f"http://127.0.0.1:{port}", "health_path": health, "expected_status": int(expected)},
            "endpoints": list(endpoints), "checks": {"authorization": False, "mutating": False},
            "accounts": [], "required_env": []}), encoding="utf-8")
        yield staging, contract

"""Tiny ``.env`` loader for the local entry-point scripts.

Why it exists: the pipeline is often started from WSL/Linux while API keys were exported in a Windows
PowerShell session (or stored in the Windows credential vault).  Neither is visible to the Linux process, so
LangSmith tracing was silently off.  A git-ignored ``.env`` next to the repository works in every shell.

Safety: only allow-listed variable names are read, values already present in the environment always win, and
nothing is ever printed except the *names* that were loaded.
"""

from __future__ import annotations

import os
from pathlib import Path

_ALLOWED_PREFIXES = ("LANGSMITH_", "LANGCHAIN_", "GROQ_", "SECURITY_REVIEWER_", "TRIVY_")


def _parse(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[7:].lstrip()
    name, separator, value = line.partition("=")
    name, value = name.strip(), value.strip()
    if not separator or not name.isidentifier() or not name.startswith(_ALLOWED_PREFIXES):
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    elif " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return (name, value) if value else None


def load_env_file(*candidates: str | Path) -> list[str]:
    """Load the first existing ``.env`` among ``candidates``; return the names that were newly set."""
    for candidate in candidates:
        path = Path(candidate)
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            continue
        loaded: list[str] = []
        for line in lines:
            parsed = _parse(line)
            if parsed and not os.environ.get(parsed[0]):
                os.environ[parsed[0]] = parsed[1]
                loaded.append(parsed[0])
        return loaded
    return []

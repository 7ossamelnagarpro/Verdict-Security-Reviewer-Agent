"""Shared helpers for scanner normalizers.

The four scanner normalizers used to carry private copies of these functions,
which drift apart over time. Keep one implementation here.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

_DRIVE = re.compile(r"^[A-Za-z]:/")
_LINE_HASH_MAX_FILE_BYTES = 2 * 1024 * 1024


def optional_text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def positive_int(value: Any) -> int | None:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None


def parse_cwes(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, (list, tuple)) else [value]
    found: set[str] = set()
    for item in values:
        match = re.search(r"CWE[-_: ]*0*(\d+)", str(item or ""), flags=re.IGNORECASE)
        if match:
            found.add(f"CWE-{int(match.group(1))}")
    return tuple(sorted(found, key=lambda item: int(item.split("-")[1])))


def normalize_relative_path(value: Any, *, project_root: str | Path | None = None) -> str | None:
    """Return a safe project-relative POSIX path, or None when it cannot be trusted.

    With ``project_root`` an absolute scanner path is made relative to that
    root; an absolute path outside the root is rejected instead of being
    silently rewritten into a different, wrong relative path. Without a root
    the historical behaviour is kept (strip drive letter and leading slash).
    """
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().replace("\\", "/")
    if normalized.lower().startswith("file://"):
        normalized = normalized[7:]
        if re.match(r"^/[A-Za-z]:/", normalized):
            normalized = normalized[1:]
    absolute = normalized.startswith("/") or bool(_DRIVE.match(normalized))
    if absolute and project_root is not None:
        root = os.path.normcase(str(Path(project_root).resolve())).replace("\\", "/").rstrip("/")
        candidate = os.path.normcase(normalized)
        if candidate == root or not candidate.startswith(root + "/"):
            return None
        normalized = normalized[len(root) + 1:]
    else:
        normalized = _DRIVE.sub("", normalized).lstrip("/")
    path = PurePosixPath(normalized)
    if not normalized or ".." in path.parts:
        return None
    return path.as_posix()


def line_hash(project_root: str | Path | None, path: str, line: int | None) -> str | None:
    """Content hash of one source line, stable when the line moves.

    This is the SARIF ``primaryLocationLineHash`` idea: it lets a later run
    recognise the same finding after unrelated edits shift line numbers. Only
    the hash is stored, never the source text, so it is safe for secrets.
    """
    if project_root is None or not line or line < 1:
        return None
    try:
        root = Path(project_root).resolve()
        target = (root / path).resolve(strict=True)
        if not target.is_relative_to(root) or not target.is_file():
            return None
        if target.stat().st_size > _LINE_HASH_MAX_FILE_BYTES:
            return None
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, start=1):
                if number == line:
                    collapsed = " ".join(text.split())
                    if not collapsed:
                        return None
                    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()[:16]
    except (OSError, RuntimeError):
        return None
    return None

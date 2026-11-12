"""Validation of CWE ids against the official MITRE CWE dictionary.

The dictionary file (``data/cwe_dictionary.json``) is built by ``scripts/fetch_cwe_dictionary.py`` from the official
MITRE catalog. Nothing in it is written by an LLM. The usage field is MITRE's own "Vulnerability Mapping Notes":
ALLOWED, ALLOWED_WITH_REVIEW, DISCOURAGED or PROHIBITED.

This module only reads and validates. It is not wired into the pipeline yet, so importing it changes no behavior.

Verdict rules (identical to ``validate_cwe`` in ``scripts/fetch_cwe_dictionary.py``):

* not found, status Deprecated/Obsolete, usage DISCOURAGED or PROHIBITED -> ``refuse``
* usage ALLOWED_WITH_REVIEW, or no usage in this catalog version -> ``needs_review_note``
* usage ALLOWED -> ``ok``
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

ENV_VAR = "CWE_DICTIONARY_PATH"
DEFAULT_RELATIVE_PATH = Path("data") / "cwe_dictionary.json"
BUILD_HINT = "python scripts/fetch_cwe_dictionary.py"

VERDICT_OK = "ok"
VERDICT_NEEDS_REVIEW_NOTE = "needs_review_note"
VERDICT_REFUSE = "refuse"

_CWE_ID = re.compile(r"(?:CWE-)?(\d{1,5})", re.IGNORECASE)
_DEAD_STATUSES = {"deprecated", "obsolete"}
_REFUSED_USAGES = {"DISCOURAGED", "PROHIBITED"}

_CACHE: dict[Path, dict[str, Any]] = {}


class CweDictionaryError(RuntimeError):
    """The dictionary file is missing, unreadable or not in the expected shape."""


def default_path() -> Path:
    """``$CWE_DICTIONARY_PATH`` if set, otherwise ``<repo root>/data/cwe_dictionary.json``."""
    override = os.environ.get(ENV_VAR)
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / DEFAULT_RELATIVE_PATH


def clear_cache() -> None:
    _CACHE.clear()


def load_dictionary(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Load the dictionary once per path and keep it in memory. Raises CweDictionaryError with a clear message."""
    target = Path(path) if path is not None else default_path()
    key = target.resolve()
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    if not target.is_file():
        raise CweDictionaryError(
            f"CWE dictionary not found at {target}. Build it with `{BUILD_HINT}` or set {ENV_VAR} to its location.")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CweDictionaryError(f"CWE dictionary at {target} is unreadable: {exc}. Rebuild it with `{BUILD_HINT}`.") from exc
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, dict) or not entries:
        raise CweDictionaryError(
            f"CWE dictionary at {target} has no 'entries' object; it is not the expected format. "
            f"Rebuild it with `{BUILD_HINT}`.")
    _CACHE[key] = data
    return data


def normalize_cwe_id(value: object) -> str | None:
    """79, '79', 'CWE-79' and 'cwe-79' all become 'CWE-79'. Anything else returns None."""
    if isinstance(value, bool) or value is None:
        return None
    match = _CWE_ID.fullmatch(str(value).strip())
    return f"CWE-{int(match.group(1))}" if match else None


def _verdict(entry: dict[str, Any] | None) -> tuple[str, str]:
    if entry is None:
        return VERDICT_REFUSE, "not found in the catalog"
    status = str(entry.get("status") or "")
    if status.casefold() in _DEAD_STATUSES:
        return VERDICT_REFUSE, f"status is {status}"
    usage = entry.get("usage")
    if usage == "ALLOWED":
        return VERDICT_OK, "mapping usage ALLOWED"
    if usage == "ALLOWED_WITH_REVIEW":
        return VERDICT_NEEDS_REVIEW_NOTE, "mapping usage ALLOWED_WITH_REVIEW: a reviewer note is required"
    if usage in _REFUSED_USAGES:
        return VERDICT_REFUSE, f"mapping usage {usage}"
    return VERDICT_NEEDS_REVIEW_NOTE, "no mapping usage in this catalog version: a reviewer note is required"


def validate_cwe(cwe: object, *, dictionary: dict[str, Any] | None = None,
                 path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Check one CWE id. Pass ``dictionary`` to skip the file, or ``path`` to read another file.

    Returns ``{id, exists, kind, status, usage, name, verdict, reason}``.
    """
    key = normalize_cwe_id(cwe)
    if key is None:
        return {"id": str(cwe), "exists": False, "kind": None, "status": None, "usage": None, "name": None,
                "verdict": VERDICT_REFUSE, "reason": "not a valid CWE id"}
    data = dictionary if dictionary is not None else load_dictionary(path)
    entry = (data.get("entries") or {}).get(key)
    verdict, reason = _verdict(entry)
    entry = entry or {}
    return {"id": key, "exists": bool(entry), "kind": entry.get("kind"), "status": entry.get("status"),
            "usage": entry.get("usage"), "name": entry.get("name"), "verdict": verdict, "reason": reason}

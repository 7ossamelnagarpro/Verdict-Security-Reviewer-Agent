"""Allowlisted, bounded facts from trusted local runtime probes."""

from __future__ import annotations

from typing import Any


_SAFE_KEYS = frozenset({
    "status", "owner_status", "cross_user_status", "response_equal",
    "alice_status", "allow_origin", "allow_credentials", "payload_reflected",
    "login_status", "token_shape", "response_keys", "values_redacted",
    "error_marker_present", "attempt_count", "statuses", "post_status",
    "get_status", "upload_status", "serve_status", "content_type",
    "served_as_html", "content_disposition", "marker_present",
    "source_guard_absent", "source_scope", "source_path", "source_line",
    "source_sha256",
})


def bounded_runtime_evidence(value: Any) -> dict[str, Any] | None:
    """Retain probe metadata, never arbitrary target-provided bodies or tokens."""
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for key in sorted(value):
        if key not in _SAFE_KEYS:
            continue
        item = value[key]
        if type(item) in (bool, int, float):
            result[key] = item
        elif isinstance(item, str):
            result[key] = item[:128]
        elif isinstance(item, list):
            result[key] = [entry if type(entry) in (bool, int, float) else entry[:64]
                           for entry in item[:16] if type(entry) in (bool, int, float) or isinstance(entry, str)]
    return result or None

"""Deterministic path transforms for the bypass-pattern templates.

Every function here is pure, fixed, code-reviewed logic — never influenced by an AI planner or any
other runtime input beyond the one canonical, already-allowlisted ``target_endpoint`` string. None of
them can produce a path outside that one endpoint's own identity: each either keeps the literal string
provably equivalent (the normalization transforms) or only appends from a small, fixed, hardcoded
suffix list designed to test well-known framework bypass patterns, never a value chosen at runtime.

A function returns ``None`` when it has nothing meaningful to test for a given path (for example, a path
with no trailing slash to toggle meaningfully, or no alphabetic segment to re-case) — callers treat that
as "this template is not applicable here", the same as any other planning gap.
"""

from __future__ import annotations

import posixpath

#: Small, fixed, hardcoded set — never generated or chosen at runtime. Chosen because real frameworks
#: have historically stripped or ignored these suffixes before routing while naive string-based access
#: checks compared the raw, un-stripped path (classic Rails/Sinatra-era "format" suffix bypass pattern).
_EXTENSION_SUFFIXES: tuple[str, ...] = (".json", ".xml", ".html")


def toggle_trailing_slash(path: str) -> str | None:
    """``/admin`` <-> ``/admin/`` — some routers normalize this before matching but a hand-rolled
    access-control check compares the raw path and only recognizes one of the two forms."""
    if path.endswith("/") and len(path) > 1:
        return path[:-1]
    if not path.endswith("/"):
        return path + "/"
    return None


def uppercase_static_segments(path: str) -> str | None:
    """Re-cases every alphabetic path segment (``/orders/5`` -> ``/ORDERS/5``). Many routers match case-
    insensitively while an access-control string comparison is case-sensitive, or vice versa."""
    segments = path.split("/")
    changed = False
    upper_segments = []
    for segment in segments:
        if segment.isalpha() and not segment.isupper():
            upper_segments.append(segment.upper())
            changed = True
        else:
            upper_segments.append(segment)
    return "/".join(upper_segments) if changed else None


def dot_segment_detour(path: str) -> str | None:
    """Inserts a harmless ``/x/..`` detour before the last segment and PROVES (via ``posixpath.normpath``,
    not assumption) that it still normalizes to the exact same canonical path before ever being used —
    this is the one invariant that keeps this transform from ever becoming a real path-traversal primitive:
    if the proof fails for any input shape, this returns ``None`` instead of a guessed path."""
    if path.count("/") < 1:
        return None
    head, _, tail = path.rpartition("/")
    if not tail:
        return None
    candidate = f"{head}/x/../{tail}"
    normalized = posixpath.normpath(candidate)
    if normalized != posixpath.normpath(path):
        return None  # the proof failed: never use an unverified path
    return candidate


def append_extension_suffix(path: str, suffix: str) -> str | None:
    """Appends one of the small, fixed ``_EXTENSION_SUFFIXES`` to the last segment. ``suffix`` must
    already be one of those exact, hardcoded strings — this never accepts an arbitrary caller-supplied
    suffix, so there is no path from any input (AI-chosen or otherwise) to an invented value here."""
    if suffix not in _EXTENSION_SUFFIXES:
        return None
    if path.endswith("/") or "." in path.rsplit("/", 1)[-1]:
        return None  # already has an extension-like segment, or is a directory-style path
    return path + suffix


def available_extension_suffixes() -> tuple[str, ...]:
    return _EXTENSION_SUFFIXES

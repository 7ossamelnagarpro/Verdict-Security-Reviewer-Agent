"""Best-effort redaction before source excerpts leave the local reader."""

from __future__ import annotations

import re


def redact_source(text: str) -> str:
    patterns = (
        r"(?i)\b(?:[\w.]*?(?:api[_-]?key|secret|password|token|credential)[\w.-]*)\s*[:=]\s*(['\"]).*?\1",
        r"(?i)\b(?:[\w.]*?(?:api[_-]?key|secret|password|token|credential)[\w.-]*)\s*[:=]\s*[^\s,;]+",
        r"\b(?:sk|gsk)_[A-Za-z0-9_-]{12,}\b",
    )
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text

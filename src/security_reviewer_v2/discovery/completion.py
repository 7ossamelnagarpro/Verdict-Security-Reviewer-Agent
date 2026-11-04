"""Completion rule for mandatory AI Discovery in full scans."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def required_discovery_satisfied(payload: Mapping[str, Any]) -> bool:
    """A model response must cover every planned target without failed batches.

    Coverage gaps may keep the stage's raw status partial even when the bounded
    plan was fully inspected; those gaps remain visible in the report.
    """
    usage = payload.get("usage")
    batches = payload.get("batches")
    if not isinstance(usage, dict) or not isinstance(batches, list):
        return False
    planned = usage.get("planned_targets")
    inspected = usage.get("targets")
    calls = usage.get("provider_calls")
    return (
        payload.get("status") in {"completed", "partial"}
        and type(planned) is int
        and planned > 0
        and type(inspected) is int
        and inspected == planned
        and type(calls) is int
        and calls > 0
        and bool(batches)
        and all(
            isinstance(batch, dict) and batch.get("status") == "completed"
            for batch in batches
        )
    )

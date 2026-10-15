"""Combine a partial Discovery run with a continuation of its missing targets."""

from __future__ import annotations

import re
from typing import Any


def combine_discovery_runs(base: dict[str, Any], continuation: dict[str, Any]) -> dict[str, Any]:
    for field in ("schema_version", "provider", "model"):
        if base.get(field) != continuation.get(field):
            raise ValueError(f"Discovery runs disagree on {field}")

    base_done = [batch for batch in base.get("batches", []) if batch.get("status") == "completed"]
    continuation_batches = list(continuation.get("batches", []))
    if not continuation_batches or any(batch.get("status") != "completed" for batch in continuation_batches):
        raise ValueError("Continuation still has incomplete batches")
    completed = [*base_done, *continuation_batches]
    target_ids = [target_id for batch in completed for target_id in batch.get("target_ids", [])]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("A completed target appears in more than one run")
    planned = base.get("usage", {}).get("planned_targets")
    if type(planned) is not int or len(target_ids) != planned:
        raise ValueError("Combined runs do not cover every originally planned target")

    base_failed_indices = {batch.get("batch_index") for batch in base.get("batches", [])
                           if batch.get("status") != "completed"}
    warnings = _unique([
        warning for warning in [*base.get("warnings", []), *continuation.get("warnings", [])]
        if not any(warning.startswith(f"Discovery batch {index}:") for index in base_failed_indices)
    ])
    gaps = _unique([
        gap for gap in [*base.get("coverage_gaps", []), *continuation.get("coverage_gaps", [])]
        if not gap.startswith("Discovery run was restricted to explicitly selected target IDs.")
        and not re.match(r"\d+ planned discovery targets were not inspected;", gap)
        and not any(gap.startswith(f"Discovery batch {index} did not complete;") for index in base_failed_indices)
    ])

    batch_index_map: dict[tuple[str, int], int] = {}
    batches: list[dict[str, Any]] = []
    for source, source_batches in (("base", base_done), ("continuation", continuation_batches)):
        for batch in source_batches:
            new_index = len(batches) + 1
            batch_index_map[(source, batch["batch_index"])] = new_index
            batches.append({**batch, "batch_index": new_index})

    exchanges = []
    for source, payload in (("base", base), ("continuation", continuation)):
        for exchange in payload.get("context_exchanges", []):
            new_index = batch_index_map.get((source, exchange.get("batch_index")))
            if new_index is not None:
                exchanges.append({**exchange, "batch_index": new_index})

    accepted_candidate_ids = {candidate_id for batch in completed for candidate_id in batch.get("candidate_ids", [])}
    candidates: dict[str, dict[str, Any]] = {}
    for candidate in [*base.get("candidates", []), *continuation.get("candidates", [])]:
        candidate_id = candidate.get("candidate_id")
        if candidate_id in accepted_candidate_ids:
            prior = candidates.get(candidate_id)
            if prior is None or (prior.get("verification") != "supported" and candidate.get("verification") == "supported"):
                candidates[candidate_id] = candidate

    target_plan = {}
    for target in [*base.get("target_plan", []), *continuation.get("target_plan", [])]:
        if target.get("target_id") in target_ids:
            target_plan[target["target_id"]] = target

    usage: dict[str, Any] = {}
    for payload in (base, continuation):
        for key, value in payload.get("usage", {}).items():
            if key not in {"targets", "planned_targets", "batches", "estimated_cost_usd", "cost_note"} and type(value) in (int, float):
                usage[key] = usage.get(key, 0) + value
    usage.update({"targets": len(target_ids), "planned_targets": planned, "batches": len(batches),
                  "attempted_batches": len(base.get("batches", [])) + len(continuation_batches),
                  "estimated_cost_usd": None,
                  "cost_note": "Token usage includes both runs and discarded failed attempts; USD rate was not configured."})
    return {
        "schema_version": base["schema_version"], "status": "partial" if gaps or warnings else "completed",
        "provider": base["provider"], "model": base["model"], "scope": target_ids,
        "candidates": list(candidates.values()), "warnings": warnings, "coverage_gaps": gaps,
        "usage": usage, "target_plan": [target_plan[target_id] for target_id in target_ids if target_id in target_plan],
        "batches": batches, "context_exchanges": exchanges,
    }


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))

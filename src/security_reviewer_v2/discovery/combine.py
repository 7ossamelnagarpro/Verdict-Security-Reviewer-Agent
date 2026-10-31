"""Combine a partial Discovery run with a continuation of its missing targets.

Strict mode (default) needs a continuation that finished every missing target.  ``allow_partial=True`` also accepts a
continuation that stopped early (e.g. a provider quota): its completed batches are kept, the unfinished target IDs are
recorded, and the result can be combined again with the next continuation until every planned target is covered.
"""

from __future__ import annotations

import re
from typing import Any

_BATCH_WARNING = re.compile(r"^Discovery batch (\d+): ")
_PLANNED_GAP = re.compile(r"\d+ planned discovery targets were not inspected;")
_BATCH_GAP = re.compile(r"Discovery batch \d+ did not complete;")
_RESUME_PREFIX = "Discovery resumption: "


def combine_discovery_runs(base: dict[str, Any], continuation: dict[str, Any], *, allow_partial: bool = False) -> dict[str, Any]:
    for field in ("schema_version", "provider", "model"):
        if base.get(field) != continuation.get(field):
            raise ValueError(f"Discovery runs disagree on {field}")

    base_batches = list(base.get("batches", []))
    base_done = [batch for batch in base_batches if batch.get("status") == "completed"]
    continuation_all = list(continuation.get("batches", []))
    continuation_batches = [b for b in continuation_all if b.get("status") == "completed"] if allow_partial else continuation_all
    if allow_partial:
        if not continuation_batches:
            raise ValueError("Continuation completed no batches; nothing to combine")
    elif not continuation_batches or any(batch.get("status") != "completed" for batch in continuation_batches):
        raise ValueError("Continuation still has incomplete batches")
    completed = [*base_done, *continuation_batches]
    target_ids = [target_id for batch in completed for target_id in batch.get("target_ids", [])]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("A completed target appears in more than one run")
    planned = base.get("usage", {}).get("planned_targets")
    uncovered = type(planned) is int and len(target_ids) < planned
    if type(planned) is not int or len(target_ids) > planned or (uncovered and not allow_partial):
        raise ValueError("Combined runs do not cover every originally planned target")

    pending: list[str] = []
    if uncovered:
        covered = set(target_ids)
        known = [*base.get("unfinished_target_ids", []), *continuation.get("unfinished_target_ids", []),
                 *(t.get("target_id") for t in [*base.get("target_plan", []), *continuation.get("target_plan", [])]),
                 *(i for b in [*base_batches, *continuation_all] for i in b.get("target_ids", []))]
        pending = [i for i in dict.fromkeys(known) if isinstance(i, str) and i not in covered]

    failed_base = {batch.get("batch_index") for batch in base_batches if batch.get("status") != "completed"}
    failed_cont = {batch.get("batch_index") for batch in continuation_all if batch.get("status") != "completed"}
    if allow_partial:
        warnings = []
        for payload, failed in ((base, failed_base), (continuation, failed_cont)):
            for warning in payload.get("warnings", []):
                match = _BATCH_WARNING.match(warning)
                if match and int(match.group(1)) in failed:
                    if uncovered:
                        warnings.append(_RESUME_PREFIX + warning[match.end():])
                    continue
                if not (warning.startswith(_RESUME_PREFIX) and not uncovered):
                    warnings.append(warning)
        warnings = _unique(warnings)
    else:
        warnings = _unique([
            warning for warning in [*base.get("warnings", []), *continuation.get("warnings", [])]
            if not any(warning.startswith(f"Discovery batch {index}:") for index in failed_base)
        ])
    gaps = _unique([
        gap for gap in [*base.get("coverage_gaps", []), *continuation.get("coverage_gaps", [])]
        if not gap.startswith("Discovery run was restricted to explicitly selected target IDs.")
        and not _PLANNED_GAP.match(gap)
        and (not any(gap.startswith(f"Discovery batch {index} did not complete;") for index in failed_base)
             if not allow_partial else not _BATCH_GAP.match(gap))
    ])
    if uncovered:
        gaps.append(f"{planned - len(target_ids)} planned discovery targets were not inspected; the run stopped before "
                    "they completed: " + ", ".join(pending[:20]))

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
        if allow_partial or target.get("target_id") in target_ids:
            target_plan[target["target_id"]] = target

    usage: dict[str, Any] = {}
    for payload in (base, continuation):
        for key, value in payload.get("usage", {}).items():
            if key not in {"targets", "planned_targets", "batches", "estimated_cost_usd", "cost_note"} and type(value) in (int, float):
                usage[key] = usage.get(key, 0) + value
    usage.update({"targets": len(target_ids), "planned_targets": planned, "batches": len(batches),
                  "attempted_batches": len(base_batches) + len(continuation_all),
                  "estimated_cost_usd": None,
                  "cost_note": "Token usage includes both runs and discarded failed attempts; USD rate was not configured."})
    result = {
        "schema_version": base["schema_version"], "status": "partial" if gaps or warnings else "completed",
        "provider": base["provider"], "model": base["model"], "scope": target_ids,
        "candidates": list(candidates.values()), "warnings": warnings, "coverage_gaps": gaps,
        "usage": usage,
        "target_plan": list(target_plan.values()) if allow_partial else [target_plan[i] for i in target_ids if i in target_plan],
        "batches": batches, "context_exchanges": exchanges,
    }
    if pending:
        result["unfinished_target_ids"] = pending
    return result


def remaining_target_ids(payload: dict[str, Any]) -> list[str]:
    """Planned target IDs of a saved Discovery result that no completed batch has covered yet."""
    batches = payload.get("batches", [])
    covered = {i for b in batches if b.get("status") == "completed" for i in b.get("target_ids", [])}
    known = [*payload.get("unfinished_target_ids", []), *(t.get("target_id") for t in payload.get("target_plan", [])),
             *(i for b in batches for i in b.get("target_ids", []))]
    return [i for i in dict.fromkeys(known) if isinstance(i, str) and i not in covered]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))

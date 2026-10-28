"""Join normalized findings back to the profiler's scan plan.

Without this join a finding does not know which component or plan task it came
from, so later stages cannot use what the profiler learned about the project.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Sequence

from .models import NormalizationResult, NormalizationSummary, NormalizationStatus


def attach_plan_context(
    batch: NormalizationResult,
    *,
    task_id: str | None,
    components: Sequence[tuple[str, str]],
) -> NormalizationResult:
    """Set ``task_id`` and the owning ``component_id`` on every finding.

    ``components`` is ``(component_id, root)`` pairs. The longest matching root
    wins, and root ``"."`` matches everything as the fallback.
    """
    ordered = sorted(components, key=lambda item: len(_clean(item[1])), reverse=True)
    findings = tuple(
        replace(
            finding,
            component_id=finding.component_id or _owner(finding.primary_location.path, ordered),
            scanner=replace(finding.scanner, task_id=task_id or finding.scanner.task_id),
        )
        for finding in batch.findings
    )
    return replace(batch, findings=findings)


def combine_batches(batches: Iterable[NormalizationResult]) -> NormalizationResult:
    """One result per scanner from several tasks; run_index keeps provenance unique."""
    items = list(batches)
    if not items:
        raise ValueError("combine_batches needs at least one batch")
    if len(items) == 1:
        return items[0]
    findings = tuple(
        replace(finding, scanner=replace(finding.scanner, run_index=index))
        for index, batch in enumerate(items)
        for finding in batch.findings
    )
    summary = NormalizationSummary(
        input_runs=sum(b.summary.input_runs for b in items),
        input_results=sum(b.summary.input_results for b in items),
        normalized_findings=len(findings),
        skipped_results=sum(b.summary.skipped_results for b in items),
    )
    warnings = tuple(w for b in items for w in b.warnings)
    complete = all(b.status == NormalizationStatus.COMPLETE for b in items)
    return replace(
        items[0],
        status=NormalizationStatus.COMPLETE if complete else NormalizationStatus.PARTIAL,
        findings=findings, summary=summary, warnings=warnings,
    )


def _clean(root: str) -> str:
    return "" if root in {".", "./", ""} else root.strip("/").replace("\\", "/")


def _owner(path: str, ordered: Sequence[tuple[str, str]]) -> str | None:
    for component_id, root in ordered:
        prefix = _clean(root)
        if not prefix or path == prefix or path.startswith(prefix + "/"):
            return component_id
    return None

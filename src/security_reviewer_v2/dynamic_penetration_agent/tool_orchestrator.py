"""Section 3, phase 3 / section 6: the Agent decides *what* to test, this module decides *how it runs*.

Three tools are wired: ``runtime_workflows`` (the generic DAST stage's own bounded HTTP executor — see
``scanners/runtime_workflows.py``), ``zap`` (one ZAP active-scan attempt scoped to a single endpoint —
see ``zap_attempt.py``), and ``playwright`` (one real authenticated browser visit to a single endpoint —
see ``playwright_attempt.py``). ``custom_requests`` is not: the design's own scope (section 4) rules out
the agent issuing free-form requests of its own, and nothing here substitutes for that boundary.

Each adapter has its own prerequisites (ZAP needs the agent's disposable stack's compose project/service
name; Playwright needs Node.js and a loopback target). When a plan names a tool whose prerequisites are
not met, the orchestrator tries the plan's *next* named tool instead of failing outright — the same way a
tester would fall back from "run ZAP" to "just check it over HTTP" when the heavier tool isn't available
— and only raises once none of the plan's named tools can run.
"""

from __future__ import annotations

from typing import Any, Mapping

from security_reviewer_v2.scanners.runtime_workflows import run_workflows

from . import playwright_attempt, zap_attempt
from .models import AttackPlan


class ToolUnavailable(RuntimeError):
    """None of the plan's named tools could run; the caller should record this attempt as blocked."""


def execute(
    plan: AttackPlan, suite: dict, *, base_url: str,
    environment: Mapping[str, str] | None = None, transport: Any = None,
    account_definitions: Mapping[str, Mapping[str, Any]] | None = None,
    zap_context: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run exactly one attempt through the first of the plan's named tools whose prerequisites are met.

    All three adapters return the same ``{"workflows": [{"status": ..., "steps": [...]}]}`` shape, so
    ``evidence_collector``/``evidence_evaluator`` read any of them without tool-specific branching.
    """
    account = account_definitions.get(plan.accounts[0]) if (account_definitions and plan.accounts) else None
    reasons: list[str] = []
    for tool in plan.selected_tools:
        try:
            if tool == "runtime_workflows":
                return run_workflows(base_url, suite, disposable=False, environment=environment, transport=transport)
            if tool == "zap":
                return zap_attempt.run_scoped_attempt(
                    base_url, plan.target_endpoint,
                    stack_name=(zap_context or {}).get("stack_name"),
                    app_service=(zap_context or {}).get("app_service"), auth=account,
                )
            if tool == "playwright":
                return playwright_attempt.run_single_page_attempt(base_url, plan.target_endpoint, account=account)
            reasons.append(f"'{tool}' is not an approved execution tool for this agent.")
        except (zap_attempt.ZapUnavailable, playwright_attempt.PlaywrightUnavailable) as error:
            reasons.append(str(error))
    raise ToolUnavailable("; ".join(reasons) or f"No supported tool among {plan.selected_tools!r}")

"""Section 3, phase 2: pick a strategy and tools, without inventing endpoints, accounts or ids.

A plan is a *starting point* from the three section-5 templates. ``adaptive_controller`` may ask for a
different strategy on the next attempt based on evidence, but every individual plan this module returns
still only ever uses the route and accounts it was explicitly given.
"""

from __future__ import annotations

import re

from security_reviewer_v2.discovery.models import CandidateFinding

from . import templates
from .models import AttackPlan, TestStrategy


class PlanUnavailable(ValueError):
    """This strategy cannot be planned for this hypothesis with the evidence/accounts on hand."""


def build_plan(
    candidate: CandidateFinding,
    strategy: TestStrategy,
    *,
    attempt_number: int,
    target_endpoint: str,
    accounts: tuple[str, ...],
    tools: tuple[str, ...] = ("runtime_workflows",),
) -> AttackPlan:
    """Build one attempt's plan. Raises :class:`PlanUnavailable` if this strategy needs evidence or
    accounts that are not actually on hand — never substitutes an invented endpoint, account or id."""
    rationale: str
    used_accounts: tuple[str, ...] = ()

    if strategy is TestStrategy.UNAUTHENTICATED_ACCESS:
        steps = templates.unauthenticated_access(target_endpoint)
        rationale = "Cheapest, safest first probe: does the route respond without any session at all?"

    elif strategy is TestStrategy.AUTHORIZATION_MATRIX:
        if not accounts:
            raise PlanUnavailable("No authenticated test account is declared in the Runtime Contract.")
        used_accounts = (accounts[0],)
        steps = templates.authorization_matrix(target_endpoint, other_actor=accounts[0])
        rationale = f"Does an authenticated account ({accounts[0]}) that is not the resource owner still get in?"

    elif strategy is TestStrategy.IDOR:
        if not accounts:
            raise PlanUnavailable("No authenticated test account is declared in the Runtime Contract.")
        resource_path = _concrete_resource_path(candidate, target_endpoint)
        if resource_path is None:
            raise PlanUnavailable(
                "No cited evidence names a concrete resource id belonging to a different account; "
                "the agent does not invent one."
            )
        used_accounts = (accounts[0],)
        steps = templates.idor(resource_path, other_actor=accounts[0])
        rationale = f"Evidence cites {resource_path} as another account's resource; can {accounts[0]} read it?"

    else:
        raise PlanUnavailable(f"Unsupported strategy: {strategy!r}")

    return AttackPlan(
        candidate_id=candidate.candidate_id, attempt_number=attempt_number, test_strategy=strategy,
        target_endpoint=target_endpoint, selected_tools=tools, steps=steps,
        accounts=used_accounts, rationale=rationale,
    )


def _concrete_resource_path(candidate: CandidateFinding, target_endpoint: str) -> str | None:
    """A literal path matching ``target_endpoint``'s shape, cited in the candidate's own evidence.

    Only accepts an id already named by Discovery (in ``evidence``) — never generates or guesses one.
    """
    pattern = re.compile(
        "^" + re.sub(r"\{[^}/]+\}|<[^>]+>", r"(\\d+)", re.escape(target_endpoint)
                     .replace(r"\{", "{").replace(r"\}", "}").replace(r"\<", "<").replace(r"\>", ">")) + "$"
    )
    for item in candidate.evidence:
        text = item.split(":", 1)[-1] if re.fullmatch(r"\d+:.*", item) else item
        for token in re.findall(r"/[\w./-]+", text):
            if pattern.fullmatch(token) and token != target_endpoint:
                return token
    return None

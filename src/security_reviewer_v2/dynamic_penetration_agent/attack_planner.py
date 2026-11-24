"""Section 3, phase 2: pick a strategy and tools, without inventing endpoints, accounts or ids.

A plan is a *starting point* from the three section-5 templates. ``adaptive_controller`` may ask for a
different strategy on the next attempt based on evidence, but every individual plan this module returns
still only ever uses the route and accounts it was explicitly given.
"""

from __future__ import annotations

import re
from typing import Mapping

from security_reviewer_v2.discovery.models import CandidateFinding

from . import path_variants, templates
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
    account_roles: Mapping[str, str] | None = None,
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

    elif strategy is TestStrategy.PRIVILEGE_ESCALATION:
        if not accounts:
            raise PlanUnavailable("No authenticated test account is declared in the Runtime Contract.")
        lower = _lowest_privilege_account(accounts, account_roles)
        if lower is None:
            raise PlanUnavailable(
                "No account is declared with a role other than 'admin' in the Runtime Contract; "
                "the agent does not invent one to test privilege escalation with."
            )
        used_accounts = (lower,)
        steps = templates.privilege_escalation(target_endpoint, lower_privilege_actor=lower)
        rationale = f"Does the non-admin account ({lower}) reach an endpoint that should require admin privileges?"

    elif strategy is TestStrategy.HEAD_METHOD_BYPASS:
        steps = templates.head_method_bypass(target_endpoint)
        rationale = "Does a HEAD request reach the route when a hand-wired auth check only covers GET?"

    elif strategy is TestStrategy.TRAILING_SLASH_BYPASS:
        variant = path_variants.toggle_trailing_slash(target_endpoint)
        if variant is None:
            raise PlanUnavailable("No meaningful trailing-slash variant exists for this path.")
        steps = templates.trailing_slash_bypass(variant)
        rationale = f"Does toggling the trailing slash ({variant}) reach a route a naive string check missed?"

    elif strategy is TestStrategy.CASE_SENSITIVITY_BYPASS:
        variant = path_variants.uppercase_static_segments(target_endpoint)
        if variant is None:
            raise PlanUnavailable("This path has no alphabetic segment to re-case.")
        steps = templates.case_sensitivity_bypass(variant)
        rationale = f"Does re-casing the path ({variant}) reach a route a case-sensitive check missed?"

    elif strategy is TestStrategy.PATH_NORMALIZATION_BYPASS:
        variant = path_variants.dot_segment_detour(target_endpoint)
        if variant is None:
            raise PlanUnavailable(
                "No dot-segment detour of this path could be proven to normalize to the identical "
                "canonical endpoint; the agent will not use an unverified path."
            )
        steps = templates.path_normalization_bypass(variant)
        rationale = (f"Does a dot-segment detour ({variant}, proven to normalize to {target_endpoint}) "
                    "reach a route whose access check compares the raw, un-normalized path?")

    elif strategy is TestStrategy.EXTENSION_SUFFIX_BYPASS:
        variant = next((derived for suffix in path_variants.available_extension_suffixes()
                        if (derived := path_variants.append_extension_suffix(target_endpoint, suffix)) is not None),
                       None)
        if variant is None:
            raise PlanUnavailable("No fixed extension suffix is applicable to this path.")
        actor = accounts[0] if accounts else "anonymous"
        used_accounts = (accounts[0],) if accounts else ()
        steps = templates.extension_suffix_bypass(variant, other_actor=actor)
        rationale = f"Does appending a known format suffix ({variant}) bypass an extension-unaware access check?"

    elif strategy is TestStrategy.IDOR_PARAMETER_POLLUTION:
        if not accounts:
            raise PlanUnavailable("No authenticated test account is declared in the Runtime Contract.")
        resource_path = _concrete_resource_path(candidate, target_endpoint)
        if resource_path is None:
            raise PlanUnavailable(
                "No cited evidence names a concrete resource id belonging to a different account; "
                "the agent does not invent one."
            )
        other_owner_id = resource_path.rsplit("/", 1)[-1]
        used_accounts = (accounts[0],)
        steps = templates.idor_parameter_pollution(target_endpoint, other_owner_id, other_actor=accounts[0])
        rationale = (f"Evidence cites {other_owner_id} as another account's resource id; does a duplicated "
                    f"query parameter let {accounts[0]} reach it even when the path-based IDOR check holds?")

    else:
        raise PlanUnavailable(f"Unsupported strategy: {strategy!r}")

    return AttackPlan(
        candidate_id=candidate.candidate_id, attempt_number=attempt_number, test_strategy=strategy,
        target_endpoint=target_endpoint, selected_tools=tools, steps=steps,
        accounts=used_accounts, rationale=rationale,
    )


def _lowest_privilege_account(accounts: tuple[str, ...], account_roles: Mapping[str, str] | None) -> str | None:
    """The first declared account whose ``role`` (from the Runtime Contract's own accounts) is not
    ``admin``/``administrator``/``superuser`` — never a guessed or invented account."""
    if not account_roles:
        return None
    for account in accounts:
        role = (account_roles.get(account) or "").strip().lower()
        if role and role not in {"admin", "administrator", "superuser", "root"}:
            return account
    return None


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

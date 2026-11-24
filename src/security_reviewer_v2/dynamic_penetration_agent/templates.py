"""Section 5 templates: starting points, never the whole strategy space.

Each function returns an :class:`~.models.AttackStep` tuple only. The planner decides accounts, the
endpoint and the resource id; the template only shapes *which* request(s) prove or disprove the
hypothesis, and the expected *safe* status so a 200 response is a designed assertion failure
(an observed "violation" in ``runtime_workflows`` terms), never a bare, unexamined 200.
"""

from __future__ import annotations

from . import path_variants
from .models import AttackStep, TestStrategy

# A 200 here is the thing being tested for; 401/403/404 are the only statuses that mean "access was denied".
_DENIED_STATUSES = (401, 403, 404)


def unauthenticated_access(target_endpoint: str) -> tuple[AttackStep, ...]:
    """One anonymous GET. A successful (2xx) response is the exploitation evidence."""
    return (
        AttackStep(
            actor="anonymous", method="GET", path=target_endpoint, security_check=True,
            expect_status=_DENIED_STATUSES,
        ),
    )


def authorization_matrix(target_endpoint: str, *, other_actor: str) -> tuple[AttackStep, ...]:
    """``other_actor`` (authenticated, but not the resource's owner by role) requests the owner-only endpoint."""
    return (
        AttackStep(
            actor=other_actor, method="GET", path=target_endpoint, security_check=True,
            expect_status=_DENIED_STATUSES,
        ),
    )


def privilege_escalation(target_endpoint: str, *, lower_privilege_actor: str) -> tuple[AttackStep, ...]:
    """``lower_privilege_actor`` (an account the Runtime Contract itself declares as NOT ``role: admin``)
    requests an endpoint the hypothesis suspects is meant to be admin-only.

    Shares ``authorization_matrix``'s mechanics exactly (one GET, same denial statuses); it exists as its
    own named template only so a role-aware account is specifically chosen and the report says plainly
    that privilege escalation, not just generic cross-account access, was what got tested.
    """
    return (
        AttackStep(
            actor=lower_privilege_actor, method="GET", path=target_endpoint, security_check=True,
            expect_status=_DENIED_STATUSES,
        ),
    )


def idor(other_owner_resource_path: str, *, other_actor: str) -> tuple[AttackStep, ...]:
    """``other_actor`` requests a concrete resource path known (from evidence) to belong to a different account.

    ``other_owner_resource_path`` is a literal path with the real identifier already substituted by the planner
    from the candidate's own evidence (never invented and never a path/account the agent generated itself) — for
    example ``/orders/5`` when evidence shows order 5 belongs to a different test account than ``other_actor``.
    Only GET is used: this template proves read-IDOR, not a write primitive.
    """
    return (
        AttackStep(actor=other_actor, method="GET", path=other_owner_resource_path, security_check=True,
                   expect_status=_DENIED_STATUSES),
    )


def head_method_bypass(target_endpoint: str) -> tuple[AttackStep, ...]:
    """Anonymous HEAD instead of GET. Some frameworks auto-derive a HEAD route from a GET handler at the
    router level, while a hand-written auth check is only ever wired onto the GET verb specifically."""
    return (
        AttackStep(actor="anonymous", method="HEAD", path=target_endpoint, security_check=True,
                   expect_status=_DENIED_STATUSES),
    )


def trailing_slash_bypass(variant_path: str) -> tuple[AttackStep, ...]:
    """Anonymous GET of ``variant_path`` — ``target_endpoint`` with its trailing slash toggled by
    :func:`path_variants.toggle_trailing_slash` (never a freely chosen path)."""
    return (
        AttackStep(actor="anonymous", method="GET", path=variant_path, security_check=True,
                   expect_status=_DENIED_STATUSES),
    )


def case_sensitivity_bypass(variant_path: str) -> tuple[AttackStep, ...]:
    """Anonymous GET of ``variant_path`` — ``target_endpoint`` re-cased by
    :func:`path_variants.uppercase_static_segments`."""
    return (
        AttackStep(actor="anonymous", method="GET", path=variant_path, security_check=True,
                   expect_status=_DENIED_STATUSES),
    )


def path_normalization_bypass(variant_path: str) -> tuple[AttackStep, ...]:
    """Anonymous GET of ``variant_path`` — a ``/x/..`` detour around ``target_endpoint`` that
    :func:`path_variants.dot_segment_detour` has already PROVED normalizes to the identical path."""
    return (
        AttackStep(actor="anonymous", method="GET", path=variant_path, security_check=True,
                   expect_status=_DENIED_STATUSES),
    )


def idor_parameter_pollution(target_endpoint: str, other_owner_id: str, *, other_actor: str) -> tuple[AttackStep, ...]:
    """``other_actor`` requests ``target_endpoint`` with a duplicated, polluted query parameter
    (``?id=<own>&id=<other_owner_id>``) — probes whether a validation layer reads the first occurrence
    while the business logic layer reads the last (or vice versa). ``other_owner_id`` must already be the
    same literal identifier :func:`idor` would use (cited in evidence, never invented)."""
    separator = "&" if "?" in target_endpoint else "?"
    return (
        AttackStep(actor=other_actor, method="GET",
                   path=f"{target_endpoint}{separator}id={other_owner_id}&id={other_owner_id}",
                   security_check=True, expect_status=_DENIED_STATUSES),
    )


def extension_suffix_bypass(variant_path: str, *, other_actor: str = "anonymous") -> tuple[AttackStep, ...]:
    """GET of ``variant_path`` — ``target_endpoint`` with one of a small, fixed suffix list
    (:func:`path_variants.append_extension_suffix`) appended, as an unauthenticated (or, when an account
    is available, cross-account) request."""
    return (
        AttackStep(actor=other_actor, method="GET", path=variant_path, security_check=True,
                   expect_status=_DENIED_STATUSES),
    )


TEMPLATES = {
    TestStrategy.UNAUTHENTICATED_ACCESS: unauthenticated_access,
    TestStrategy.AUTHORIZATION_MATRIX: authorization_matrix,
    TestStrategy.IDOR: idor,
    TestStrategy.PRIVILEGE_ESCALATION: privilege_escalation,
    TestStrategy.HEAD_METHOD_BYPASS: head_method_bypass,
    TestStrategy.TRAILING_SLASH_BYPASS: trailing_slash_bypass,
    TestStrategy.CASE_SENSITIVITY_BYPASS: case_sensitivity_bypass,
    TestStrategy.PATH_NORMALIZATION_BYPASS: path_normalization_bypass,
    TestStrategy.IDOR_PARAMETER_POLLUTION: idor_parameter_pollution,
    TestStrategy.EXTENSION_SUFFIX_BYPASS: extension_suffix_bypass,
}

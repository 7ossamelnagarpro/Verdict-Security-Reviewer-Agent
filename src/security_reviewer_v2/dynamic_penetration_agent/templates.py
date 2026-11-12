"""Section 5 templates: starting points, never the whole strategy space.

Each function returns an :class:`~.models.AttackStep` tuple only. The planner decides accounts, the
endpoint and the resource id; the template only shapes *which* request(s) prove or disprove the
hypothesis, and the expected *safe* status so a 200 response is a designed assertion failure
(an observed "violation" in ``runtime_workflows`` terms), never a bare, unexamined 200.
"""

from __future__ import annotations

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


TEMPLATES = {
    TestStrategy.UNAUTHENTICATED_ACCESS: unauthenticated_access,
    TestStrategy.AUTHORIZATION_MATRIX: authorization_matrix,
    TestStrategy.IDOR: idor,
}

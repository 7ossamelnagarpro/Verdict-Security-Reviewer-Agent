"""Explicit, bounded Juice Shop workflows used by endpoint coverage.

Mutating actions are opt-in. The default run proves reachability and auth
state without placing orders, applying coupons, posting reviews, or uploading
files. This keeps profiling safe while making the required workflows visible.
"""

from __future__ import annotations

from typing import Any

from scan_juice_shop_auth_runtime import call, register_and_login


def run_workflows(
    base_url: str, *, with_test_users: bool = False, mutating: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "completed",
        "mutating_enabled": mutating,
        "workflows": {},
        "coverage_gaps": [],
    }
    token = None
    identity: dict[str, Any] | None = None
    if with_test_users:
        identity = register_and_login(
            base_url, "workflow" + str(__import__("time").time_ns())
        )
        token = identity["token"]

    checkout: dict[str, Any] = {"name": "checkout", "steps": []}
    basket_id = identity.get("basket_id") if identity else None
    if token:
        status, body, _ = call(base_url, "/rest/user/whoami", token=token)
        checkout["steps"].append({"action": "authenticate", "status": status})
        if isinstance(body, dict):
            basket_id = body.get("bid") or body.get("basketId")
        if basket_id is None:
            # Some Juice Shop builds do not return the basket id in login/whoami.
            # Find only an already-authorized basket without creating data.
            for candidate in range(1, 6):
                probe_status, _, _ = call(
                    base_url, f"/rest/basket/{candidate}", token=token
                )
                if probe_status == 200:
                    basket_id = candidate
                    break
    if basket_id is not None:
        status, _, _ = call(base_url, f"/rest/basket/{basket_id}", token=token)
        checkout["steps"].append({"action": "read_basket", "status": status})
        if mutating:
            status, _, _ = call(
                base_url,
                f"/rest/basket/{basket_id}/checkout",
                token=token,
                method="POST",
                payload={},
            )
            checkout["steps"].append({"action": "place_order", "status": status})
        else:
            checkout["steps"].append(
                {"action": "place_order", "status": "needs_confirmation"}
            )
            result["coverage_gaps"].append(
                "Checkout mutation is opt-in to avoid creating an order."
            )
    else:
        checkout["status"] = "needs_test_identity"
    result["workflows"]["checkout"] = checkout

    coupons: dict[str, Any] = {"name": "coupons", "steps": []}
    if basket_id is not None:
        if mutating:
            status, _, _ = call(
                base_url,
                f"/rest/basket/{basket_id}/coupon/invalid-test-coupon",
                token=token,
                method="PUT",
            )
            coupons["steps"].append({"action": "apply_test_coupon", "status": status})
        else:
            coupons["steps"].append(
                {"action": "apply_test_coupon", "status": "needs_confirmation"}
            )
            result["coverage_gaps"].append(
                "Coupon mutation is opt-in; no coupon was applied."
            )
    else:
        coupons["status"] = "needs_test_identity"
    result["workflows"]["coupons"] = coupons

    reviews: dict[str, Any] = {"name": "reviews", "steps": []}
    status, _, _ = call(base_url, "/rest/products/1/reviews")
    reviews["steps"].append({"action": "read_reviews", "status": status})
    if mutating and token:
        status, _, _ = call(
            base_url,
            "/rest/products/1/reviews",
            token=token,
            method="PUT",
            payload={
                "message": "security workflow test",
                "author": "workflow@example.invalid",
                "rating": 1,
            },
        )
        reviews["steps"].append({"action": "post_test_review", "status": status})
    else:
        reviews["steps"].append(
            {"action": "post_test_review", "status": "needs_confirmation"}
        )
        result["coverage_gaps"].append(
            "Review mutation is opt-in; no review was posted."
        )
    result["workflows"]["reviews"] = reviews

    upload: dict[str, Any] = {"name": "file_upload", "steps": []}
    if mutating:
        upload["steps"].append(
            {"action": "upload_benign_text_fixture", "status": "needs_implementation"}
        )
        result["coverage_gaps"].append(
            "File upload requires a multipart fixture and cleanup policy."
        )
    else:
        upload["steps"].append(
            {"action": "upload_benign_text_fixture", "status": "needs_confirmation"}
        )
        result["coverage_gaps"].append(
            "File upload is opt-in and disabled in safe mode."
        )
    result["workflows"]["file_upload"] = upload
    return result

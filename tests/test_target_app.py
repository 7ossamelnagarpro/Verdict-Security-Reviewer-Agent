"""Behavioral proof that the matched examples are vulnerable and safe."""

from __future__ import annotations

from targets.target_app.app import create_app


def test_health_endpoint() -> None:
    client = create_app().test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_normal_username_has_the_same_expected_result() -> None:
    client = create_app().test_client()

    vulnerable_response = client.get(
        "/vulnerable/users",
        query_string={"username": "alice"},
    )
    safe_response = client.get(
        "/safe/users",
        query_string={"username": "alice"},
    )

    assert vulnerable_response.get_json()["count"] == 1
    assert safe_response.get_json()["count"] == 1


def test_sql_injection_payload_changes_only_vulnerable_behavior() -> None:
    client = create_app().test_client()
    payload = "' OR 1=1 --"

    vulnerable_response = client.get(
        "/vulnerable/users",
        query_string={"username": payload},
    )
    safe_response = client.get(
        "/safe/users",
        query_string={"username": payload},
    )

    assert vulnerable_response.status_code == 200
    assert safe_response.status_code == 200
    assert vulnerable_response.get_json()["count"] == 3
    assert safe_response.get_json()["count"] == 0

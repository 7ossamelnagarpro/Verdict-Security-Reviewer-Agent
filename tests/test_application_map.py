from __future__ import annotations

from pathlib import Path

from security_reviewer_v2.application_map import build_application_map
from security_reviewer_v2.web.runtime_discovery import discover


def test_source_map_records_declared_fields_without_inventing_role(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Header\n"
        "from pydantic import BaseModel\n"
        "app = FastAPI()\n"
        "class OrderBody(BaseModel):\n"
        "    item: str\n"
        "    quantity: int\n"
        "@app.post('/orders/{order_id}')\n"
        "def update_order(order_id: int, body: OrderBody, authorization: str = Header(default='')) -> dict:\n"
        "    user = principal(authorization)\n"
        "    conn.execute('UPDATE orders SET item=%s WHERE id=%s')\n"
        "    return {'id': order_id}\n",
        encoding="utf-8",
    )

    result = build_application_map(tmp_path, discover(tmp_path))

    assert result["summary"]["source_routes"] == 1
    route = result["routes"][0]
    assert route["method"] == "POST"
    assert route["source"]["symbol"] == "update_order"
    assert route["parameters"] == [
        {"name": "order_id", "location": "path", "type": "int"}
    ]
    assert route["request_body"]["fields"] == [
        {"name": "item", "type": "str"},
        {"name": "quantity", "type": "int"},
    ]
    assert route["authentication"]["status"] == "check_candidate"
    assert route["required_role"] is None
    assert route["database_interactions"][0]["tables"] == ["orders"]


def test_source_map_tracks_bounded_same_file_helper_database_calls(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "def load_order(order_id):\n    return query_order(order_id)\n"
        "def query_order(order_id):\n"
        "    conn.execute('SELECT * FROM orders WHERE id=?', (order_id,))\n"
        "@app.get('/orders/{order_id}')\n"
        "def get_order(order_id: int):\n    return load_order(order_id)\n",
        encoding="utf-8",
    )
    result = build_application_map(tmp_path, discover(tmp_path))
    route = result["routes"][0]
    assert route["database_interactions"] == []
    assert route["same_file_call_candidates"] == ["load_order", "query_order"]
    assert route["same_file_database_candidates"] == [
        {
            "operation": "sql_call",
            "line": 6,
            "tables": ["orders"],
            "via_function": "query_order",
        }
    ]


def test_graph_only_routes_are_separate_and_untrusted(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health():\n    return {}\n",
        encoding="utf-8",
    )
    result = build_application_map(
        tmp_path,
        discover(tmp_path),
        graph_routes=[
            {"method": "GET", "path": "/health", "file": "app.py"},
            {"method": "ANY", "path": "/unverified", "file": "app.py"},
        ],
        graph_status="completed",
    )

    assert result["summary"]["graph_corroborated"] == 1
    assert result["summary"]["graph_unmatched"] == 1
    assert len(result["routes"]) == 1
    assert result["unmatched_graph_routes"][0]["path"] == "/unverified"


def test_graph_route_matches_normalized_path_without_claiming_file_match(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/orders/{order_id}')\ndef get_order(order_id: int):\n    return {}\n",
        encoding="utf-8",
    )
    result = build_application_map(
        tmp_path,
        discover(tmp_path),
        graph_routes=[{"method": "GET", "path": "/orders/{}", "file": ""}],
        graph_status="completed",
    )

    assert result["summary"]["graph_corroborated"] == 1
    assert result["summary"]["graph_file_corroborated"] == 0
    assert result["summary"]["graph_unmatched"] == 0


def test_invalid_source_location_is_not_read(tmp_path: Path) -> None:
    result = build_application_map(
        tmp_path,
        {
            "endpoints": [
                {"method": "GET", "path": "/secret", "source": "../secret.py:1"},
            ]
        },
    )

    assert result["routes"] == []


def test_openapi_declaration_without_line_is_preserved(tmp_path: Path) -> None:
    (tmp_path / "openapi.json").write_text(
        '{"paths":{"/items/{item_id}":{"get":{"responses":{"200":{}}}}}}',
        encoding="utf-8",
    )

    result = build_application_map(tmp_path, discover(tmp_path))

    assert result["summary"]["source_routes"] == 1
    assert result["routes"][0]["source"] == {
        "file": "openapi.json",
        "line": None,
        "symbol": None,
    }
    assert result["routes"][0]["parameters"][0]["name"] == "item_id"


def test_comprehensive_lab_map_has_expected_source_routes() -> None:
    root = Path(__file__).resolve().parents[1] / "targets" / "verdict-comprehensive-lab"
    result = build_application_map(root, discover(root))

    assert result["summary"]["source_routes"] >= 60
    order = next(
        route
        for route in result["routes"]
        if route["method"] == "POST" and route["path"] == "/orders"
    )
    assert order["request_body"]["type"] == "OrderBody"
    assert order["source"]["file"] == "api/app.py"
    assert order["database_interactions"]

import ast

import pytest

from security_reviewer_v2.context.routes import build_route_index, explain_route, resolve_route

APP = """
from fastapi import APIRouter
router = APIRouter()

@router.post("/comments")
def add_comment(): ...

@router.get("/comments")
def show_comments(): ...

@router.get("/orders/{order_id}")
def get_order(order_id): ...
"""


@pytest.fixture()
def index():
    return build_route_index([("api/extra.py", ast.parse(APP))])


def test_a_known_method_picks_the_one_matching_handler(index):
    assert resolve_route(index, "/comments", "GET").function == "show_comments"
    assert resolve_route(index, "/comments", "post").function == "add_comment"


def test_an_unknown_method_on_a_shared_path_is_ambiguous_and_lists_every_candidate(index):
    match = explain_route(index, "/comments")
    assert match.handler is None and match.reason == "ambiguous"
    assert {name for handler in match.candidates for name in handler.methods} == {"GET", "POST"}
    assert resolve_route(index, "/comments") is None          # still never guesses


def test_a_path_with_no_declared_route_says_so(index):
    assert explain_route(index, "/nowhere").reason == "no_route"
    assert explain_route(index, "/comments", "DELETE").reason == "no_route"


def test_runtime_contract_placeholders_match_route_parameters(index):
    match = explain_route(index, "/orders/{{order_id}}", "GET")
    assert match.reason == "matched" and match.handler.function == "get_order"

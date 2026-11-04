"""Conservative source corroboration for the isolated Security Lab Web login probe.

This is deliberately fixture-specific. Unknown source shapes return no evidence;
they must not be interpreted as an unprotected login on another project.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any

_LOGIN_CALLS = {
    "request.form.get",
    "get_db",
    "db.execute",
    "db.execute(query).fetchone",
    "make_response",
    "redirect",
    "make_token",
    "resp.set_cookie",
}
_IMPORTS = {"sqlite3", "os", "subprocess", "uuid", "flask"}
_DB_HELPER = """\
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db
"""
_RESPONSE_HOOK = """\
@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
"""


def _decorator_name(node: ast.expr) -> str:
    return ast.unparse(node.func if isinstance(node, ast.Call) else node)


def _calls(statements: list[ast.stmt]) -> set[str]:
    return {
        ast.unparse(node.func)
        for statement in statements
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
    }


def _same_ast(function: ast.FunctionDef, template: str) -> bool:
    expected = ast.parse(template).body[0]
    return ast.dump(function, include_attributes=False) == ast.dump(
        expected, include_attributes=False
    )


def _source_has_no_visible_login_guard(source: str) -> tuple[bool, int | None]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False, None
    imports = {
        alias.name.split(".", 1)[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", 1)[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    )
    if imports != _IMPORTS:
        return False, None
    app_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func).startswith("app.")
    ]
    if any(
        ast.unparse(node.func) not in {"app.route", "app.run"} for node in app_calls
    ):
        return False, None
    if (
        sum(
            isinstance(node, ast.Call)
            and ast.unparse(node.func) == "app.route"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "/login"
            for node in app_calls
        )
        != 1
    ):
        return False, None
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    db_helpers = [node for node in functions if node.name == "get_db"]
    if len(db_helpers) != 1 or not _same_ast(db_helpers[0], _DB_HELPER):
        return False, None
    login = [node for node in functions if node.name == "login"]
    if len(login) != 1 or len(login[0].decorator_list) != 1:
        return False, None
    route = login[0].decorator_list[0]
    if (
        not isinstance(route, ast.Call)
        or _decorator_name(route) != "app.route"
        or not route.args
        or not isinstance(route.args[0], ast.Constant)
        or route.args[0].value != "/login"
    ):
        return False, None
    # The reviewed fixture has a direct login handler. An added conditional,
    # helper call, decorator, or registration makes the analysis inconclusive.
    expected_statements = (
        ast.If,
        ast.Assign,
        ast.Assign,
        ast.Assign,
        ast.Assign,
        ast.Try,
        ast.If,
        ast.Return,
    )
    if tuple(type(node) for node in login[0].body) != expected_statements:
        return False, None
    if _calls(login[0].body) != _LOGIN_CALLS:
        return False, None
    if (
        sum(isinstance(node, ast.If) for node in ast.walk(login[0])) != 2
        or sum(isinstance(node, ast.Return) for node in ast.walk(login[0])) != 4
        or any(
            isinstance(
                node,
                (
                    ast.For,
                    ast.While,
                    ast.Global,
                    ast.Nonlocal,
                    ast.Await,
                    ast.AugAssign,
                ),
            )
            for node in ast.walk(login[0])
        )
    ):
        return False, None
    last_return = login[0].body[-1]
    if (
        not isinstance(last_return, ast.Return)
        or ast.unparse(last_return.value) != "('Invalid credentials', 401)"
    ):
        return False, None
    for function in functions:
        for decorator in function.decorator_list:
            name = _decorator_name(decorator)
            if name not in {
                "app.route",
                "app.teardown_appcontext",
                "app.after_request",
            }:
                return False, None
            if name == "app.after_request":
                if function.name != "add_cors" or not _same_ast(
                    function, _RESPONSE_HOOK
                ):
                    return False, None
    if (
        sum(
            _decorator_name(decorator) == "app.after_request"
            for function in functions
            for decorator in function.decorator_list
        )
        != 1
    ):
        return False, None
    # Reject a direct middleware replacement outside a function as well.
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                ast.unparse(target).startswith("app.")
                and ast.unparse(target) != "app.secret_key"
                for target in targets
            ):
                return False, None
    return True, login[0].lineno


def corroborate_fixture_login(
    project_root: Path, runtime: dict[str, Any], attested_app_sha256: str
) -> dict[str, Any] | None:
    """Return bounded facts only for the source-matched isolated fixture run."""
    source_path = project_root / "app.py"
    if (
        not source_path.is_file()
        or source_path.is_symlink()
        or any(path.name != "app.py" for path in project_root.glob("*.py"))
    ):
        return None
    source_bytes = source_path.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if source_hash != attested_app_sha256:
        return None
    probes = [
        item
        for item in runtime.get("results", [])
        if isinstance(item, dict)
        and item.get("rule_id") == "web.missing-brute-force-protection"
        and item.get("path") == "/login"
    ]
    if len(probes) != 1 or probes[0].get("vulnerable") is not True:
        return None
    facts = probes[0].get("evidence")
    if not isinstance(facts, dict):
        return None
    statuses = facts.get("statuses")
    attempts = facts.get("attempt_count")
    if (
        not isinstance(statuses, list)
        or type(attempts) is not int
        or not 5 <= attempts <= 16
        or len(statuses) != attempts
        or any(type(status) is not int or status != 401 for status in statuses)
    ):
        return None
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    no_guard, line = _source_has_no_visible_login_guard(source)
    if not no_guard or line is None:
        return None
    return {
        "attempt_count": attempts,
        "statuses": statuses,
        "source_guard_absent": True,
        "source_scope": "isolated_fixture_login_and_hooks",
        "source_path": "app.py",
        "source_line": line,
        "source_sha256": source_hash,
    }

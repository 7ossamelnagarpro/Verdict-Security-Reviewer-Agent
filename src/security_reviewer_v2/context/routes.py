"""Route index: map an observed HTTP path to the handler function that serves it.

Runtime (DAST) findings carry an HTTP path such as ``/orders/{{order_id}}``, not a source location, so the AI
reviewer used to receive "primary source context is unavailable" for every one of them.  This module reads the
project's own Python sources (never executes them) and resolves a runtime path to a handler without guessing:
the answer is a handler only when exactly one declared route fits (and, if the HTTP method is known, serves it).

Supported declarations: FastAPI/Starlette ``@app.get("/x/{id}")`` and ``@router.post(...)``, ``@x.api_route(...)``,
Flask ``@app.route("/x/<int:id>", methods=[...])``, with ``APIRouter(prefix=...)``, ``include_router(..., prefix=...)``
and ``Blueprint(..., url_prefix=...)`` prefixes.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Iterable

_VERBS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})
_ROUTER_FACTORIES = {"APIRouter": "prefix", "Blueprint": "url_prefix", "Router": "prefix"}
_PLACEHOLDER = re.compile(r"\{\{[^}]*\}\}|\{[^}/]*\}")     # {{order_id}} (runtime contract) or {order_id}
_TOKEN = re.compile(r"(\{[^}]*\}|<[^>]*>)")


@dataclass(frozen=True)
class RouteHandler:
    methods: tuple[str, ...]
    template: str
    path: str
    line: int
    function: str
    pattern: re.Pattern[str] = field(compare=False, repr=False, default=re.compile(""))

    @property
    def specificity(self) -> int:
        """Literal characters in the template: ``/orders/verified`` beats ``/orders/{order_id}``."""
        return sum(len(part) for part in _TOKEN.split(self.template)[::2])


def _template_regex(template: str) -> re.Pattern[str]:
    parts: list[str] = []
    for token in _TOKEN.split(template):
        if token.startswith("{"):
            parts.append(".+" if token.endswith(":path}") else "[^/]+")
        elif token.startswith("<"):
            converter = token[1:-1].split(":", 1)[0] if ":" in token else ""
            parts.append("[0-9]+" if converter == "int" else ".+" if converter == "path" else "[^/]+")
        else:
            parts.append(re.escape(token))
    return re.compile("".join(parts) + "/?")


def _string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _join(*parts: str) -> str:
    return "/" + "/".join(part.strip("/") for part in parts if part.strip("/"))


def _prefixes(trees: Iterable[ast.AST]) -> dict[str, str]:
    """Router variable name -> URL prefix, from constructors and include/register calls."""
    own: dict[str, str] = {}
    mounted: dict[str, str] = {}
    for tree in trees:
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value.func, (ast.Name, ast.Attribute))):
                factory = node.value.func.id if isinstance(node.value.func, ast.Name) else node.value.func.attr
                if factory in _ROUTER_FACTORIES:
                    own[node.targets[0].id] = _string(_keyword(node.value, _ROUTER_FACTORIES[factory])) or ""
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr in {"include_router", "register_blueprint"} and node.args and isinstance(node.args[0], ast.Name)):
                prefix = _string(_keyword(node, "prefix")) or _string(_keyword(node, "url_prefix"))
                if prefix:
                    mounted[node.args[0].id] = prefix
    return {name: _join(mounted.get(name, ""), own.get(name, "")) for name in {*own, *mounted}}


def build_route_index(files: Iterable[tuple[str, ast.AST]]) -> list[RouteHandler]:
    files = list(files)
    prefixes = _prefixes(tree for _, tree in files)
    index: list[RouteHandler] = []
    for relative, tree in files:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.args):
                    continue
                route = _string(decorator.args[0])
                verb = decorator.func.attr
                if route is None or not (verb in _VERBS or verb in {"route", "api_route"}):
                    continue
                if verb in _VERBS:
                    methods = (verb.upper(),)
                else:
                    listed = _keyword(decorator, "methods")
                    names = [_string(item) for item in listed.elts] if isinstance(listed, (ast.List, ast.Tuple)) else []
                    methods = tuple(sorted(name.upper() for name in names if name)) or ("GET",)
                owner = decorator.func.value.id if isinstance(decorator.func.value, ast.Name) else ""
                template = _join(prefixes.get(owner, ""), route)
                index.append(RouteHandler(methods, template, relative, node.lineno, node.name, _template_regex(template)))
    return index


@dataclass(frozen=True)
class RouteMatch:
    """Outcome of resolving a runtime path: the handler, or why there is none (``no_route`` / ``ambiguous``)."""

    handler: RouteHandler | None
    reason: str
    candidates: tuple[RouteHandler, ...] = ()


def explain_route(index: Iterable[RouteHandler], request_path: str, method: str | None = None) -> RouteMatch:
    path = _PLACEHOLDER.sub("0", request_path.split("?", 1)[0].split("#", 1)[0])   # contract placeholders -> any id
    matches = [handler for handler in index if handler.pattern.fullmatch(path)]
    if method:
        matches = [handler for handler in matches if method.upper() in handler.methods]
    if not matches:
        return RouteMatch(None, "no_route")
    best = max(handler.specificity for handler in matches)
    top = {(h.path, h.line): h for h in matches if h.specificity == best}
    if len(top) == 1:
        return RouteMatch(next(iter(top.values())), "matched")
    return RouteMatch(None, "ambiguous", tuple(top.values()))


def handler_for_source_location(index: Iterable[RouteHandler], path: str, start_line: int, end_line: int) -> RouteHandler | None:
    """The one route handler whose decorator sits inside ``[start_line, end_line]`` of ``path``, if any.

    Used to turn a Discovery/Verification candidate's source anchor into the HTTP route it concerns, for
    ``dynamic_penetration_agent``'s ``target_endpoint_resolver`` — never a guess, only an exact source match.
    """
    matches = [handler for handler in index if handler.path == path and start_line <= handler.line <= end_line]
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_route(index: Iterable[RouteHandler], request_path: str, method: str | None = None) -> RouteHandler | None:
    """The single handler serving ``request_path`` (and ``method`` when known), or None when unknown/ambiguous."""
    return explain_route(index, request_path, method).handler

"""Conservative, source-backed application entry-point map.

The map describes declarations and observed code structure. It does not assert
that a route is reachable, authorized, or vulnerable at runtime.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

_PATH_PARAMETER = re.compile(r"\{([A-Za-z_]\w*)\}|<(?:[^:>]+:)?([A-Za-z_]\w*)>")
_SQL_TABLE = re.compile(
    r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([A-Za-z_][\w.]*)", re.IGNORECASE
)
_SCALAR_TYPES = {"str", "int", "float", "bool"}


def _route_key(method: str, route_path: str) -> tuple[str, str]:
    normalized = re.sub(r"\{[^}]*\}|<[^>]*>", "{}", route_path)
    return method, normalized


def _safe_source(root: Path, source: str) -> tuple[Path, str, int | None] | None:
    try:
        relative, separator, line_text = source.rpartition(":")
        if separator and line_text.isdecimal():
            line: int | None = int(line_text)
        else:
            relative, line = source, None
        relative_path = Path(relative)
        if (
            (line is not None and line < 1)
            or relative_path.is_absolute()
            or ".." in relative_path.parts
        ):
            return None
        path = (root / relative_path).resolve(strict=True)
        if (
            not path.is_relative_to(root)
            or not path.is_file()
            or path.stat().st_size > 262144
        ):
            return None
        return path, relative_path.as_posix(), line
    except (OSError, ValueError):
        return None


def _handler(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            getattr(decorator, "lineno", None) == line
            for decorator in node.decorator_list
        ):
            return node
    return None


def _model_fields(tree: ast.AST, model_name: str) -> list[dict[str, str]]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != model_name:
            continue
        if not any(ast.unparse(base).endswith("BaseModel") for base in node.bases):
            return []
        return [
            {"name": field.target.id, "type": ast.unparse(field.annotation)}
            for field in node.body
            if isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name)
        ][:50]
    return []


def _argument_map(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.arg]:
    return {
        argument.arg: argument
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    }


def _parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef, route_path: str
) -> list[dict[str, str]]:
    arguments = _argument_map(node)
    path_names = list(
        dict.fromkeys(
            (match.group(1) or match.group(2))
            for match in _PATH_PARAMETER.finditer(route_path)
        )
    )
    parameters = [
        {
            "name": name,
            "location": "path",
            "type": ast.unparse(arguments[name].annotation)
            if name in arguments and arguments[name].annotation
            else "unknown",
        }
        for name in path_names
    ]
    defaults = node.args.defaults
    positional = (*node.args.posonlyargs, *node.args.args)
    positional_defaults = (
        dict(zip((arg.arg for arg in positional[-len(defaults) :]), defaults))
        if defaults
        else {}
    )
    for argument in positional:
        if argument.arg in path_names or argument.annotation is None:
            continue
        annotation = ast.unparse(argument.annotation)
        if annotation not in _SCALAR_TYPES or argument.arg not in positional_defaults:
            continue
        if isinstance(positional_defaults[argument.arg], ast.Constant):
            parameters.append(
                {
                    "name": argument.arg,
                    "location": "candidate_query",
                    "type": annotation,
                }
            )
    return parameters


def _request_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.AST
) -> dict[str, Any] | None:
    for argument in _argument_map(node).values():
        if argument.annotation is None:
            continue
        annotation = ast.unparse(argument.annotation)
        if argument.arg == "body" or annotation == "Request":
            return {
                "parameter": argument.arg,
                "type": annotation,
                "fields": _model_fields(tree, annotation)
                if annotation.isidentifier()
                else [],
                "status": "dynamic_request"
                if annotation == "Request"
                else "declared_type",
            }
    return None


def _response_class(
    node: ast.FunctionDef | ast.AsyncFunctionDef, line: int
) -> str | None:
    for decorator in node.decorator_list:
        if (
            not isinstance(decorator, ast.Call)
            or getattr(decorator, "lineno", None) != line
        ):
            continue
        for keyword in decorator.keywords:
            if keyword.arg == "response_class":
                return ast.unparse(keyword.value)
    return None


def _code_evidence(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    call_names: set[str] = set()
    database: list[dict[str, Any]] = []
    for child in (
        descendant for statement in node.body for descendant in ast.walk(statement)
    ):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            call_names.add(child.func.id)
        if not isinstance(child.func, ast.Attribute) or child.func.attr not in {
            "execute",
            "executemany",
        }:
            continue
        tables: list[str] = []
        if (
            child.args
            and isinstance(child.args[0], ast.Constant)
            and isinstance(child.args[0].value, str)
        ):
            tables = list(dict.fromkeys(_SQL_TABLE.findall(child.args[0].value)))[:20]
        database.append(
            {"operation": "sql_call", "line": child.lineno, "tables": tables}
        )

    auth_calls = sorted(
        name
        for name in call_names
        if re.search(
            r"auth|principal|identity|permission|require_", name, re.IGNORECASE
        )
    )
    header = any(
        ast.unparse(default).startswith("Header(") for default in node.args.defaults
    )
    authentication = {
        "status": "check_candidate"
        if auth_calls
        else "header_observed"
        if header
        else "unknown",
        "evidence_calls": auth_calls,
    }
    return authentication, database[:50], sorted(call_names)[:50]


def _same_file_call_context(
    tree: ast.AST, handler: ast.FunctionDef | ast.AsyncFunctionDef
) -> tuple[list[str], list[dict[str, Any]]]:
    """Follow a bounded chain of module functions without inferring data flow."""
    definitions = {
        node.name: node
        for node in getattr(tree, "body", [])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    _, _, initial_calls = _code_evidence(handler)
    pending = [(name, 1) for name in initial_calls]
    visited: set[str] = set()
    database: list[dict[str, Any]] = []
    while pending and len(visited) < 20:
        name, depth = pending.pop(0)
        if depth > 3 or name in visited or name == handler.name:
            continue
        function = definitions.get(name)
        if function is None:
            continue
        visited.add(name)
        _, interactions, calls = _code_evidence(function)
        database.extend({**item, "via_function": name} for item in interactions)
        pending.extend((called, depth + 1) for called in calls)
    return sorted(visited), database[:50]


def _business_context(
    route_path: str,
) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
    segments = [segment for segment in route_path.split("/") if segment]
    static_segments = [
        segment for segment in segments if not segment.startswith(("{", "<"))
    ]
    if not static_segments:
        return None, []
    business_object = {
        "name": static_segments[0],
        "confidence": "path_segment_candidate",
    }
    relationships = [
        {
            "from": segments[index],
            "to": segments[index + 2],
            "kind": "nested_path_candidate",
        }
        for index in range(len(segments) - 2)
        if not segments[index].startswith(("{", "<"))
        and segments[index + 1].startswith(("{", "<"))
        and not segments[index + 2].startswith(("{", "<"))
    ]
    return business_object, relationships


def build_application_map(
    project_root: Path,
    discovered: dict[str, Any],
    *,
    graph_routes: list[dict[str, str]] | None = None,
    graph_status: str = "not_requested",
    project_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Combine bounded source declarations with optional graph corroboration."""
    root = project_root.resolve()
    if not root.is_dir():
        raise ValueError(f"Project directory is unavailable: {root}")
    source_routes = discovered.get("endpoints", [])
    if not isinstance(source_routes, list):
        raise ValueError("Discovered endpoints must be a list")
    source_gaps = discovered.get("coverage_gaps", [])
    if not isinstance(source_gaps, list):
        source_gaps = []
    graph_records = [
        item
        for item in (graph_routes or [])
        if isinstance(item, dict)
        and all(isinstance(item.get(key), str) for key in ("method", "path", "file"))
    ]
    graph_route_keys = {
        _route_key(item["method"], item["path"]) for item in graph_records
    }
    graph_file_keys = {
        (*_route_key(item["method"], item["path"]), item["file"])
        for item in graph_records
        if item["file"]
    }
    trees: dict[Path, ast.AST | None] = {}
    routes: list[dict[str, Any]] = []
    source_route_keys: set[tuple[str, str]] = set()
    for candidate in source_routes[:250]:
        if not isinstance(candidate, dict):
            continue
        method, route_path, source = (
            candidate.get(key) for key in ("method", "path", "source")
        )
        if not all(isinstance(value, str) for value in (method, route_path, source)):
            continue
        location = _safe_source(root, source)
        if location is None:
            continue
        file_path, relative, line = location
        if file_path not in trees:
            try:
                trees[file_path] = (
                    ast.parse(file_path.read_text(encoding="utf-8"))
                    if file_path.suffix == ".py"
                    else None
                )
            except (OSError, UnicodeError, SyntaxError, ValueError):
                trees[file_path] = None
        tree = trees[file_path]
        node = _handler(tree, line) if tree is not None and line is not None else None
        authentication: dict[str, Any] = {"status": "unknown", "evidence_calls": []}
        database: list[dict[str, Any]] = []
        calls: list[str] = []
        indirect_calls: list[str] = []
        indirect_database: list[dict[str, Any]] = []
        if node is not None and tree is not None:
            authentication, database, calls = _code_evidence(node)
            indirect_calls, indirect_database = _same_file_call_context(tree, node)
        business_object, relationships = _business_context(route_path)
        route_key = _route_key(method, route_path)
        source_route_keys.add(route_key)
        routes.append(
            {
                "method": method,
                "path": route_path,
                "source": {
                    "file": relative,
                    "line": line,
                    "symbol": node.name if node else None,
                },
                "parameters": _parameters(node, route_path)
                if node
                else [
                    {
                        "name": match.group(1) or match.group(2),
                        "location": "path",
                        "type": "unknown",
                    }
                    for match in _PATH_PARAMETER.finditer(route_path)
                ],
                "request_body": _request_body(node, tree) if node and tree else None,
                "response_type": ast.unparse(node.returns)
                if node and node.returns
                else None,
                "response_class": _response_class(node, line)
                if node and line is not None
                else None,
                "authentication": authentication,
                "required_role": None,
                "service": None,
                "called_functions": calls,
                "database_interactions": database,
                "same_file_call_candidates": indirect_calls,
                "same_file_database_candidates": indirect_database,
                "business_object": business_object,
                "relationships": relationships,
                "graph_corroborated": route_key in graph_route_keys,
                "graph_file_corroborated": (*route_key, relative) in graph_file_keys,
                "confidence": candidate.get("confidence"),
            }
        )
    unmatched_graph = [
        {"method": item["method"], "path": item["path"], "file": item["file"]}
        for item in graph_records
        if _route_key(item["method"], item["path"]) not in source_route_keys
    ]
    return {
        "schema_version": "1.0",
        "status": "generated",
        "project_root": str(root),
        "project_fingerprint": project_fingerprint,
        "framework": discovered.get("framework"),
        "routes": routes,
        "summary": {
            "source_routes": len(routes),
            "graph_routes": len(graph_records),
            "source_inspected_files": discovered.get("inspected_files"),
            "source_visited_files": discovered.get("visited_files"),
            "graph_corroborated": sum(route["graph_corroborated"] for route in routes),
            "graph_file_corroborated": sum(
                route["graph_file_corroborated"] for route in routes
            ),
            "graph_unmatched": len(unmatched_graph),
            "graph_status": graph_status,
        },
        "unmatched_graph_routes": sorted(
            unmatched_graph,
            key=lambda item: (item["file"], item["method"], item["path"]),
        )[:250],
        "source_coverage_gaps": [gap for gap in source_gaps if isinstance(gap, str)][
            :50
        ],
        "limitations": [
            "Source and graph declarations do not prove runtime reachability or authorization.",
            "Same-file helper calls are bounded candidates; cross-file calls, data flow, roles and services are not inferred.",
            "Mounted router prefixes and dynamic routes require runtime confirmation.",
        ],
    }

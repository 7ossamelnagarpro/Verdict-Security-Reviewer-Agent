"""Post-scan precision audit for the held-out lab evaluations.

The strict audit in ``scripts/evaluate_verdict_comprehensive.py`` only credits a known vulnerability when a *scanner*
finding carries an exact, pre-declared signature.  That measures recall but says nothing about false positives, never
credits the AI discovery agent, and cannot score a case that has no signature.  This module adds the missing evidence
without loosening the strict count:

* every reviewed issue group is placed on the application's routes (dynamic findings by URL, static findings and AI
  candidates by file and line) using the lab's *source code*, never its answer key;
* a positive group on a safe control's route marks that control ``flagged`` (a false-positive signal);
* positive groups that match no case are an adjudication queue, not silently "wrong": the lab's answer key is not
  exhaustive, so they may be real, unlisted vulnerabilities.

Nothing here sees a scanner or an AI prompt, and it reads the answer key only through the cases handed in by the caller.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

POSITIVE_VERDICTS = frozenset({"confirmed_vulnerability", "likely_vulnerability"})
VERDICTS = ("confirmed_vulnerability", "likely_vulnerability", "needs_more_evidence", "false_positive")
OUTCOMES = ("matched", "known_endpoint", "safe_control", "outside_scope", "unlabeled")

# Hardening checks (missing security headers, cookie flags, CORS) are a different issue class from injection or
# access-control flaws.  A passive header alert on a route must not count against a safe control about SQL injection,
# and an injection finding must not count against a header control, so route overlap alone is never enough.
HARDENING_CATEGORIES = frozenset({"cookie_flags", "response_headers", "cors"})

_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
_SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages", ".mypy_cache", "tests"})
_PARAMETER = re.compile(r"\{+[^{}/]*\}+")
_CASE_LOCATION = re.compile(r"^([A-Za-z]+(?:\+[A-Za-z]+)*)\s+(/\S*)$")


@dataclass(frozen=True)
class Handler:
    """One route handler of the audited application."""

    method: str
    template: str      # normalized: every path parameter is "{}"
    path: str          # file, relative to the application root, POSIX separators
    start: int         # first decorator line
    end: int

    @property
    def key(self) -> str:
        return f"{self.method} {self.template}"


def normalize_route(path: str) -> str:
    """``/orders/{{order_id}}?x=1`` and ``/orders/{id}`` both become ``/orders/{}``."""
    route = path.split("?", 1)[0].split("#", 1)[0].strip()
    route = _PARAMETER.sub("{}", route)
    return route.rstrip("/") or "/"


def _template_matches(template: str, concrete: str) -> bool:
    """Whether ``concrete`` (a template or a URL) is an instance of ``template``."""
    left, right = template.split("/"), concrete.split("/")
    if len(left) != len(right):
        return False
    return all(a == b or a == "{}" for a, b in zip(left, right))


def load_handlers(root: Path) -> list[Handler]:
    """Route handlers declared with ``@x.get/post/put/patch/delete("/path")`` anywhere under ``root``."""
    handlers: list[Handler] = []
    for file in sorted(root.rglob("*.py")):
        relative = file.relative_to(root)
        if any(part in _SKIP_DIRS for part in relative.parts[:-1]):
            continue
        try:
            tree = ast.parse(file.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            first_line = min((item.lineno for item in node.decorator_list), default=node.lineno)
            for decorator in node.decorator_list:
                if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr in _ROUTE_METHODS and decorator.args
                        and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)):
                    continue
                handlers.append(Handler(decorator.func.attr.upper(), normalize_route(decorator.args[0].value),
                                        relative.as_posix(), first_line, node.end_lineno or node.lineno))
    return handlers


def parse_case_route(location: Any) -> tuple[frozenset[str], str] | None:
    """``"POST+GET /comments"`` -> ({POST, GET}, "/comments"); anything that is not a route -> None."""
    match = _CASE_LOCATION.match(str(location or "").strip())
    if not match:
        return None
    return frozenset(part.upper() for part in match.group(1).split("+")), normalize_route(match.group(2))


def case_handlers(location: Any, handlers: Sequence[Handler]) -> tuple[Handler, ...]:
    parsed = parse_case_route(location)
    if parsed is None:
        return ()
    methods, template = parsed
    return tuple(item for item in handlers if item.template == template and item.method in methods)


def resolve_location(path: Any, line: Any, method: Any, handlers: Sequence[Handler]) -> tuple[Handler, ...]:
    """Handlers a finding sits on: a URL path selects by route, a file path plus line by source span."""
    if not isinstance(path, str) or not path:
        return ()
    if path.startswith("/"):
        concrete = normalize_route(path)
        verb = str(method).upper() if isinstance(method, str) and method else None
        hits = [item for item in handlers if _template_matches(item.template, concrete) and (verb is None or item.method == verb)]
        if not hits:
            return ()
        # "/orders/verified" matches both "/orders/{}" and a literal route: the most specific one wins.
        fewest = min(item.template.count("{}") for item in hits)
        return tuple(item for item in hits if item.template.count("{}") == fewest)
    if type(line) is not int:
        return ()
    relative = path.replace("\\", "/").lstrip("./")
    return tuple(item for item in handlers
                 if (item.path == relative or item.path.endswith("/" + relative) or relative.endswith("/" + item.path))
                 and item.start <= line <= item.end)


def _candidate_handlers(candidate: Mapping[str, Any], handlers: Sequence[Handler]) -> tuple[Handler, ...]:
    """The handler an AI candidate is about: its sensitive operation first, then entry point, then its line range."""
    for key in ("sensitive_operation", "entry_point", "missing_check"):
        anchor = candidate.get(key)
        if isinstance(anchor, Mapping):
            hit = resolve_location(anchor.get("path") or candidate.get("path"), anchor.get("line"), None, handlers)
            if hit:
                return hit[:1]
    return resolve_location(candidate.get("path"), candidate.get("start_line"), None, handlers)[:1]


def _origin_of(source: Mapping[str, Any]) -> str:
    scanner = source.get("scanner") if isinstance(source.get("scanner"), Mapping) else {}
    categories = source.get("categories") or []
    return "dynamic" if "dast" in categories or scanner.get("scanner_id") == "web-runtime" else "static"


def source_origin(source: Mapping[str, Any]) -> str:
    """``dynamic`` for runtime/DAST evidence, ``static`` for source analysis (SAST, SCA, secrets, config)."""
    return _origin_of(source)


def _group_view(group: Mapping[str, Any], findings: Mapping[str, Mapping[str, Any]],
                candidates: Mapping[str, Mapping[str, Any]],
                handlers: Sequence[Handler]) -> tuple[set[str], set[str], list[str], bool, bool]:
    """(origins, routes, titles, hardening_only, dependency_only) of every source finding and AI candidate in a group."""
    origins: set[str] = set()
    routes: set[str] = set()
    titles: list[str] = []
    rule_ids: list[str] = []
    categories: list[set[str]] = []
    for finding_id in group.get("scanner_finding_ids", []):
        finding = findings.get(finding_id) or {}
        for source in finding.get("source_findings") or [finding.get("canonical_finding") or {}]:
            if not isinstance(source, Mapping):
                continue
            origins.add(_origin_of(source))
            rule_ids.append(str(source.get("rule_id") or ""))
            categories.append({str(item) for item in source.get("categories") or []})
            location = source.get("primary_location") or {}
            facts = source.get("runtime_evidence") or {}
            routes.update(item.key for item in resolve_location(location.get("path"), location.get("start_line"),
                                                                facts.get("method") if isinstance(facts, Mapping) else None, handlers))
        canonical = finding.get("canonical_finding")
        if isinstance(canonical, Mapping) and canonical.get("title"):
            titles.append(str(canonical["title"]))
    for candidate_id in group.get("candidate_ids", []):
        origins.add("ai_discovery")
        candidate = candidates.get(candidate_id)
        if isinstance(candidate, Mapping):
            routes.update(item.key for item in _candidate_handlers(candidate, handlers))
            titles.append(str(candidate.get("title", "")))
    # Passive ZAP alerts and the bounded baseline web probes are header/cookie/CORS checks; an AI candidate is never
    # hardening-only.
    hardening_only = bool(rule_ids) and not group.get("candidate_ids") and all(rule.startswith(("zap.", "web.")) for rule in rule_ids)
    # Dependency advisories (SCA) are about third-party packages; the lab's answer key lists application flaws only.
    dependency_only = bool(categories) and not group.get("candidate_ids") and all("sca" in item for item in categories)
    return origins, routes, [title for title in titles if title], hardening_only, dependency_only


def audit(*, cases: Sequence[Mapping[str, Any]], handlers: Sequence[Handler], groups: Mapping[str, Mapping[str, Any]],
          reviews: Mapping[str, Mapping[str, Any]], findings: Mapping[str, Mapping[str, Any]],
          candidates: Mapping[str, Mapping[str, Any]], strict_matches: Mapping[str, Iterable[str]]) -> dict[str, Any]:
    """Classify every reviewed group and assess every safe control.  See the module docstring for the rules."""
    positive_routes: dict[str, set[str]] = {}
    safe_routes: dict[str, set[str]] = {}
    hardening_cases = {case["id"] for case in cases if case.get("category") in HARDENING_CATEGORIES}
    for case in cases:
        keys = {item.key for item in case_handlers(case.get("location"), handlers)}
        if case.get("label") == "confirmed_vulnerability":
            positive_routes[case["id"]] = keys
        elif case.get("label") == "safe_control":
            safe_routes[case["id"]] = keys

    group_rows: list[dict[str, Any]] = []
    for group_id, group in groups.items():
        origins, routes, titles, hardening, dependency = _group_view(group, findings, candidates, handlers)
        review = reviews.get(group_id) or {}
        matched = sorted(set(strict_matches.get(group_id, ())))
        same_class = lambda case_id: (case_id in hardening_cases) == hardening
        known = sorted(case_id for case_id, keys in positive_routes.items() if keys & routes and same_class(case_id))
        controls = sorted(case_id for case_id, keys in safe_routes.items() if keys & routes and same_class(case_id))
        outside_scope = hardening or dependency   # header/cookie hardening or a dependency CVE that matched no case above
        outcome = ("matched" if matched else "known_endpoint" if known else "safe_control" if controls
                   else "outside_scope" if outside_scope else "unlabeled")
        group_rows.append({"group_id": group_id, "verdict": review.get("verdict", "unknown"), "severity": review.get("severity"),
                           "title": review.get("title") or (titles[0] if titles else group_id),
                           "origins": sorted(origins), "routes": sorted(routes), "outcome": outcome, "hardening_only": hardening,
                           "cases": matched, "known_cases": known, "safe_controls": controls})

    positive = [row for row in group_rows if row["verdict"] in POSITIVE_VERDICTS]
    counts = {name: sum(row["outcome"] == name for row in positive) for name in OUTCOMES}

    controls: dict[str, dict[str, Any]] = {}
    for case_id, keys in safe_routes.items():
        flagged_by = [row["group_id"] for row in positive if case_id in row["safe_controls"] and row["outcome"] == "safe_control"]
        controls[case_id] = {"status": "not_assessable" if not keys else "flagged" if flagged_by else "clean",
                             "flagged_by": flagged_by}
    assessable = [item for item in controls.values() if item["status"] != "not_assessable"]

    labeled = counts["matched"] + counts["safe_control"]
    calibration = {outcome: {verdict: sum(row["outcome"] == outcome and row["verdict"] == verdict for row in group_rows)
                             for verdict in VERDICTS} for outcome in OUTCOMES}
    endpoint_groups: dict[str, list[dict[str, Any]]] = {}
    for case_id, keys in positive_routes.items():
        endpoint_groups[case_id] = [row for row in group_rows if keys & set(row["routes"]) and case_id not in row["cases"]]

    return {
        "groups": group_rows,
        "safe_controls": controls,
        "endpoint_groups": endpoint_groups,
        "summary": {
            "positive_groups": len(positive), "matched_groups": counts["matched"],
            "known_endpoint_groups": counts["known_endpoint"], "safe_control_groups": counts["safe_control"],
            "outside_scope_groups": counts["outside_scope"], "unlabeled_groups": counts["unlabeled"],
            "precision_on_labeled": round(counts["matched"] / labeled, 4) if labeled else None,
            "precision_lower_bound": round(counts["matched"] / len(positive), 4) if positive else None,
            "precision_lower_bound_in_scope": (round(counts["matched"] / (len(positive) - counts["outside_scope"]), 4)
                                               if len(positive) > counts["outside_scope"] else None),
            "safe_controls_clean": sum(item["status"] == "clean" for item in controls.values()),
            "safe_controls_flagged": sum(item["status"] == "flagged" for item in controls.values()),
            "safe_controls_not_assessable": sum(item["status"] == "not_assessable" for item in controls.values()),
            "safe_control_specificity": (round(sum(item["status"] == "clean" for item in assessable) / len(assessable), 4)
                                         if assessable else None),
            "verdict_calibration": calibration,
        },
    }

"""Conservative issue correlation. Proximity alone is never a security verdict."""

from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from security_reviewer_v2.discovery.models import CandidateFinding, DiscoveryResult
from security_reviewer_v2.normalization.merge_models import MergedFinding, MergeResult
from security_reviewer_v2.verification.models import (
    VerificationDisposition,
    VerificationResult,
)

from .models import (
    IssueGroup,
    TriageDisposition,
    TriageRecord,
    TriageResult,
    TriageSummary,
)


@dataclass
class _Group:
    group_id: str
    family: str
    path: str | None
    scanners: list[MergedFinding] = field(default_factory=list)
    candidates: list[CandidateFinding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def triage_candidates(
    discovery: DiscoveryResult,
    verification: VerificationResult,
    merged: MergeResult,
    *,
    project_root: str | Path | None = None,
) -> TriageResult:
    """Group only well-supported same-family, same-location evidence.

    Unknown or ambiguous relationships stay separate and visible. No candidate
    is deleted, and source grounding does not become a vulnerability verdict.
    """
    scanner_groups = _scanner_groups(merged.findings, project_root=project_root)
    groups = list(scanner_groups)
    verified = {record.candidate_id: record for record in verification.records}
    records: list[TriageRecord] = []
    warnings: list[str] = []
    for candidate in discovery.candidates:
        record = verified.get(candidate.candidate_id)
        if (
            record is None
            or record.disposition is VerificationDisposition.NEEDS_MORE_EVIDENCE
        ):
            records.append(
                TriageRecord(
                    candidate.candidate_id,
                    TriageDisposition.NEEDS_MORE_EVIDENCE,
                    None,
                    (),
                    (),
                    (
                        "Source evidence is not fully grounded; retain for enrichment or manual review.",
                    ),
                )
            )
            continue
        if record.disposition is VerificationDisposition.REJECTED:
            records.append(
                TriageRecord(
                    candidate.candidate_id,
                    TriageDisposition.REJECTED,
                    None,
                    (),
                    (),
                    ("Deterministic verification rejected the cited source evidence.",),
                )
            )
            continue

        family = _candidate_family(candidate)
        scanner_matches = [
            group
            for group in scanner_groups
            if family != "unknown"
            and group.family == family
            and _candidate_hits_scanner_group(candidate, group)
        ]
        if len(scanner_matches) == 1:
            group = scanner_matches[0]
            group.candidates.append(candidate)
            group.reasons.append(
                "AI and scanner evidence share a vulnerability family and source location; security impact still needs review."
            )
            records.append(
                TriageRecord(
                    candidate.candidate_id,
                    TriageDisposition.SCANNER_OVERLAP,
                    group.group_id,
                    tuple(item.merged_finding_id for item in group.scanners),
                    tuple(
                        item.candidate_id
                        for item in group.candidates
                        if item != candidate
                    ),
                    ("Same family and bounded source overlap with scanner evidence.",),
                )
            )
            continue

        candidate_matches = [
            group
            for group in groups
            if not group.scanners
            and family != "unknown"
            and group.family == family
            and any(
                _same_candidate_issue(candidate, other) for other in group.candidates
            )
        ]
        if len(scanner_matches) == 0 and len(candidate_matches) == 1:
            group = candidate_matches[0]
            prior = tuple(item.candidate_id for item in group.candidates)
            group.candidates.append(candidate)
            group.reasons.append(
                "Multiple AI candidates cite the same bounded source issue; keep every source ID."
            )
            records.append(
                TriageRecord(
                    candidate.candidate_id,
                    TriageDisposition.CANDIDATE_OVERLAP,
                    group.group_id,
                    (),
                    prior,
                    ("Same family and closely matching source anchors.",),
                )
            )
            continue

        ambiguous = bool(scanner_matches or candidate_matches) or family == "unknown"
        disposition = (
            TriageDisposition.UNCERTAIN_OVERLAP
            if ambiguous
            else TriageDisposition.NOVEL_CANDIDATE
        )
        group = _Group(
            candidate.candidate_id,
            family,
            candidate.path,
            candidates=[candidate],
            reasons=[
                "No unambiguous matching issue group; retain as its own review item."
            ],
        )
        groups.append(group)
        related_scanners = tuple(
            item.merged_finding_id
            for match in scanner_matches
            for item in match.scanners
        )
        related_candidates = tuple(
            item.candidate_id
            for match in candidate_matches
            for item in match.candidates
        )
        reason = (
            "Category or location is ambiguous; a possible overlap is not collapsed."
            if ambiguous
            else "No same-family source overlap with a scanner or earlier AI candidate."
        )
        records.append(
            TriageRecord(
                candidate.candidate_id,
                disposition,
                group.group_id,
                related_scanners,
                related_candidates,
                (reason,),
            )
        )
        if ambiguous:
            warnings.append(
                f"{candidate.candidate_id}: overlap is uncertain; separate review is required."
            )

    counts = Counter(item.disposition for item in records)
    result_groups = tuple(
        IssueGroup(
            group.group_id,
            group.family,
            group.path,
            tuple(item.merged_finding_id for item in group.scanners),
            tuple(item.candidate_id for item in group.candidates),
            tuple(dict.fromkeys(group.reasons)),
        )
        for group in groups
    )
    if len({group.group_id for group in result_groups}) != len(result_groups):
        raise ValueError("Issue group identifiers are not unique")
    status = (
        "partial"
        if verification.status != "completed" or merged.status.value != "complete"
        else "completed"
    )
    return TriageResult(
        "1.0",
        status,
        result_groups,
        tuple(records),
        TriageSummary(
            len(merged.findings),
            len(discovery.candidates),
            len(result_groups),
            counts[TriageDisposition.SCANNER_OVERLAP],
            counts[TriageDisposition.CANDIDATE_OVERLAP],
            counts[TriageDisposition.NOVEL_CANDIDATE],
            counts[TriageDisposition.UNCERTAIN_OVERLAP],
            counts[TriageDisposition.NEEDS_MORE_EVIDENCE],
            counts[TriageDisposition.REJECTED],
        ),
        tuple(sorted(set(warnings))),
    )


def _scanner_groups(
    findings: tuple[MergedFinding, ...], *, project_root: str | Path | None
) -> list[_Group]:
    ordered = sorted(
        findings,
        key=lambda item: (
            _path(item.primary_location.path),
            item.primary_location.start_line or -1,
            item.merged_finding_id,
        ),
    )
    # MergeResult remains lossless. Issue-level grouping only collapses exact
    # same-line, same-family observations or SQL source alerts explicitly
    # present in one CodeQL flow to its sink. Proximity alone is never enough.
    buckets: dict[tuple[str, int, str], list[MergedFinding]] = {}
    groups: list[_Group] = []
    for finding in ordered:
        family = _scanner_family(finding)
        line = finding.primary_location.start_line
        if line is None or family == "unknown":
            groups.append(
                _Group(
                    finding.merged_finding_id,
                    family,
                    finding.primary_location.path,
                    scanners=[finding],
                    reasons=["No reliable same-root-cause identity; kept separate."],
                )
            )
            continue
        buckets.setdefault(
            (_path(finding.primary_location.path), line, family), []
        ).append(finding)
    for bucket in buckets.values():
        identities = [
            (item.canonical_finding.scanner.scanner_id, item.canonical_finding.rule_id)
            for item in bucket
        ]
        codeql_count = sum("codeql-cli" in item.scanners for item in bucket)
        # Same-rule same-line findings can still be different dataflows; do not
        # collapse them without a reliable common sink identity.
        members_sets = (
            [bucket]
            if len(set(identities)) == len(bucket) and codeql_count <= 1
            else [[item] for item in bucket]
        )
        for members in members_sets:
            primary = next(
                (item for item in members if "codeql-cli" in item.scanners), members[0]
            )
            groups.append(
                _Group(
                    primary.merged_finding_id,
                    _scanner_family(primary),
                    primary.primary_location.path,
                    scanners=list(members),
                    reasons=[
                        "Same source line and vulnerability family."
                        if len(members) > 1
                        else "Single merged scanner finding."
                    ],
                )
            )

    sql_sinks = [
        group
        for group in groups
        if group.family == "sql_injection"
        and any(
            source.scanner.scanner_id == "codeql-cli"
            and source.rule_id == "py/sql-injection"
            for item in group.scanners
            for source in item.source_findings
        )
    ]
    absorbed: set[str] = set()
    for group in groups:
        if group.family != "sql_injection" or any(sink is group for sink in sql_sinks):
            continue
        anchors = {
            (_path(item.primary_location.path), item.primary_location.start_line)
            for item in group.scanners
        }
        if any(line is None for _, line in anchors):
            continue
        matches = [
            sink
            for sink in sql_sinks
            if sink is not group and anchors.issubset(_sql_flow_anchors(sink))
        ]
        if len(matches) == 1:
            sink = matches[0]
            sink.scanners.extend(group.scanners)
            sink.reasons.append(
                "SQL source alert is in this CodeQL sink flow; all source IDs retained."
            )
            absorbed.add(group.group_id)
    if project_root is not None:
        _coalesce_source_and_runtime(groups, absorbed, Path(project_root))
    return sorted(
        (group for group in groups if group.group_id not in absorbed),
        key=lambda group: (_path(group.path), group.group_id),
    )


def _coalesce_source_and_runtime(
    groups: list[_Group], absorbed: set[str], root: Path
) -> None:
    """Join only source-flow and route observations with a unique proven anchor."""
    try:
        root = root.resolve(strict=True)
    except OSError:
        return
    trees: dict[str, ast.AST | None] = {}

    def tree_for(path: str) -> ast.AST | None:
        normalized = _path(path)
        if normalized not in trees:
            source = (root / path).resolve()
            if (
                not source.is_relative_to(root)
                or source.suffix != ".py"
                or not source.is_file()
            ):
                trees[normalized] = None
            else:
                try:
                    trees[normalized] = ast.parse(source.read_text(encoding="utf-8"))
                except (OSError, SyntaxError, UnicodeError):
                    trees[normalized] = None
        return trees[normalized]

    xss_sinks = [
        group
        for group in groups
        if group.family == "xss"
        and any(
            source.scanner.scanner_id == "codeql-cli"
            and source.rule_id == "py/reflective-xss"
            for item in group.scanners
            for source in item.source_findings
        )
    ]
    for group in groups:
        if group in xss_sinks or group.group_id in absorbed or not group.scanners:
            continue
        item = group.scanners[0]
        line = item.primary_location.start_line
        path = item.primary_location.path
        if (
            group.family != "xss"
            or line is None
            or not path
            or any(
                _path(member.primary_location.path) != _path(path)
                or member.primary_location.start_line != line
                for member in group.scanners
            )
            or not all(
                source.scanner.scanner_id == "semgrep-ce"
                and "raw-html-format" in source.rule_id
                for member in group.scanners
                for source in member.source_findings
            )
        ):
            continue
        tree = tree_for(path)
        if tree is None:
            continue
        line_names = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and node.lineno == line
        }
        matches = [
            sink
            for sink in xss_sinks
            if sink is not group
            and (_path(path), line) in _codeql_flow_anchors(sink, "py/reflective-xss")
            and line_names.intersection(_request_source_names(sink, tree))
        ]
        if len(matches) == 1:
            matches[0].scanners.extend(group.scanners)
            matches[0].reasons.append(
                "Semgrep HTML construction uses the same request source in this CodeQL XSS flow; all source IDs retained."
            )
            absorbed.add(group.group_id)

    for group in groups:
        if group.group_id in absorbed or len(group.scanners) != 1:
            continue
        source = group.scanners[0].canonical_finding
        runtime = source.runtime_evidence or {}
        if (
            source.rule_id == "web.reflected-xss"
            and runtime.get("status") == 200
            and runtime.get("payload_reflected") is True
        ):
            family, static_rule, exception_branch = "xss", "py/reflective-xss", False
        elif (
            source.rule_id == "web.verbose-error"
            and runtime.get("status") == 500
            and runtime.get("error_marker_present") is True
        ):
            family, static_rule, exception_branch = (
                "verbose_errors",
                "py/stack-trace-exposure",
                True,
            )
        else:
            continue
        matches = []
        for sink in groups:
            if sink is group or sink.group_id in absorbed or sink.family != family:
                continue
            for item in sink.scanners:
                path, line = (
                    item.primary_location.path,
                    item.primary_location.start_line,
                )
                tree = tree_for(path) if path else None
                if (
                    tree is not None
                    and line is not None
                    and _route_for_line(tree, line) == group.path
                    and _in_exception_handler(tree, line) is exception_branch
                    and any(
                        s.scanner.scanner_id == "codeql-cli"
                        and s.rule_id == static_rule
                        for s in item.source_findings
                    )
                ):
                    matches.append(sink)
                    break
        if len(matches) == 1:
            matches[0].scanners.extend(group.scanners)
            matches[0].reasons.append(
                "Bounded runtime probe and one static sink refer to the same route and response branch; all source IDs retained."
            )
            absorbed.add(group.group_id)


def _codeql_flow_anchors(group: _Group, rule: str) -> set[tuple[str, int | None]]:
    return {
        (_path(step.location.path), step.location.start_line)
        for item in group.scanners
        for source in item.source_findings
        if source.scanner.scanner_id == "codeql-cli" and source.rule_id == rule
        for step in source.code_flow
    }


def _request_source_names(group: _Group, tree: ast.AST) -> set[str]:
    flow = _codeql_flow_anchors(group, "py/reflective-xss")
    names = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) for target in node.targets)
            and isinstance(node.value, ast.Call)
            and any(
                isinstance(part, ast.Name) and part.id == "request"
                for part in ast.walk(node.value)
            )
            and (_path(group.path), node.lineno) in flow
        ):
            names.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
    return names


def _route_for_line(tree: ast.AST, line: int) -> str | None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not (
            node.lineno <= line <= node.end_lineno
        ):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                return decorator.args[0].value
    return None


def _in_exception_handler(tree: ast.AST, line: int) -> bool:
    return any(
        isinstance(node, ast.ExceptHandler) and node.lineno <= line <= node.end_lineno
        for node in ast.walk(tree)
    )


def _sql_flow_anchors(group: _Group) -> set[tuple[str, int | None]]:
    anchors: set[tuple[str, int | None]] = set()
    for item in group.scanners:
        for source in item.source_findings:
            if (
                source.scanner.scanner_id == "codeql-cli"
                and source.rule_id == "py/sql-injection"
            ):
                anchors.update(
                    (_path(step.location.path), step.location.start_line)
                    for step in source.code_flow
                )
    return anchors


def _candidate_hits_scanner_group(candidate: CandidateFinding, group: _Group) -> bool:
    if _path(candidate.path) != _path(group.path):
        return _runtime_route_match(candidate, group)
    anchor_lines = [
        anchor.line
        for anchor in (candidate.sensitive_operation, candidate.entry_point)
        if anchor is not None and _path(anchor.path) == _path(group.path)
    ]
    if candidate.missing_check is not None and _path(
        candidate.missing_check.path
    ) == _path(group.path):
        anchor_lines.append(candidate.missing_check.line)
    for scanner in group.scanners:
        line = scanner.primary_location.start_line
        if line is None:
            continue
        if any(abs(line - anchor_line) <= 2 for anchor_line in anchor_lines):
            return True
        start, end = candidate.start_line, candidate.end_line or candidate.start_line
        if (
            start is not None
            and end is not None
            and 0 <= end - start <= 25
            and start - 1 <= line <= end + 1
        ):
            return True
    return False


def _runtime_route_match(candidate: CandidateFinding, group: _Group) -> bool:
    """Match a grounded Flask route anchor to one runtime observation."""
    anchor = candidate.entry_point
    if (
        anchor is None
        or _path(anchor.path) != _path(candidate.path)
        or not any("dast" in item.categories for item in group.scanners)
    ):
        return False
    route = re.search(r"\.route\(\s*['\"]([^'\"]+)['\"]", anchor.code)
    if route is None:
        return False
    pattern = re.escape(route.group(1))
    pattern = re.sub(r"<int:[^>]+>", r"[0-9]+", pattern)
    pattern = re.sub(r"<path:[^>]+>", r".+", pattern)
    pattern = re.sub(r"<[^>]+>", r"[^/]+", pattern)
    return re.fullmatch(pattern, group.path or "") is not None


def _same_candidate_issue(first: CandidateFinding, second: CandidateFinding) -> bool:
    if _path(first.path) != _path(second.path):
        return False
    for role in ("sensitive_operation", "missing_check"):
        left, right = getattr(first, role), getattr(second, role)
        if (
            left is not None
            and right is not None
            and _path(left.path) == _path(right.path)
            and abs(left.line - right.line) <= 2
        ):
            return True
    return (
        first.start_line is not None
        and second.start_line is not None
        and abs(first.start_line - second.start_line) <= 2
        and (first.end_line or first.start_line) - first.start_line <= 25
        and (second.end_line or second.start_line) - second.start_line <= 25
    )


def _path(value: str | None) -> str:
    return (value or "").replace("\\", "/").casefold()


def _candidate_family(candidate: CandidateFinding) -> str:
    missing = candidate.missing_check
    if missing is not None and "authorization" in candidate.category.casefold():
        check = f"{missing.observation} {missing.expected_check}".casefold()
        if "session" in check and any(
            term in check for term in ("requested", "owner", "matches the", "equal to")
        ):
            return "idor"
    return _family(f"{candidate.title} {candidate.category}")


def _scanner_family(finding: MergedFinding) -> str:
    if any(source.rule_id == "web.verbose-error" for source in finding.source_findings):
        return "verbose_errors"
    if any(
        source.rule_id == "py/stack-trace-exposure"
        for source in finding.source_findings
    ):
        return "verbose_errors"
    cwes = {value.casefold().replace("cwe-", "") for value in finding.cwes}
    for cwe, family in (
        ("89", "sql_injection"),
        ("79", "xss"),
        ("78", "command_injection"),
        ("22", "path_traversal"),
        ("918", "ssrf"),
        ("601", "open_redirect"),
        ("352", "csrf"),
        ("200", "information_disclosure"),
    ):
        if cwe in cwes:
            return family
    return _family(
        f"{finding.canonical_finding.rule_id} {finding.canonical_finding.title} "
        f"{' '.join(finding.categories)}"
    )


def _family(text: str) -> str:
    value = text.casefold().replace("‑", "-")
    checks = (
        (
            "idor",
            ("idor", "ownership", "object reference", "other user's", "another user's"),
        ),
        ("csrf", ("csrf", "cross-site request forgery", "cross site request forgery")),
        (
            "sql_injection",
            ("sql injection", "sql-injection", "tainted-sql", "sql string"),
        ),
        (
            "xss",
            ("xss", "cross-site scripting", "reflective-xss", "raw-html", "raw html"),
        ),
        (
            "command_injection",
            (
                "command injection",
                "command-line-injection",
                "command line",
                "shell injection",
            ),
        ),
        (
            "path_traversal",
            ("path traversal", "directory traversal", "path-injection", "file access"),
        ),
        ("ssrf", ("ssrf", "server-side request forgery")),
        ("open_redirect", ("open redirect", "url redirect", "redirect")),
        ("cors", ("cors", "cross-origin")),
        ("verbose_errors", ("stack trace", "verbose error", "exception exposure")),
        ("debug", ("flask-debug", "debug mode", "debug enabled")),
        (
            "session",
            ("session token", "session cookie", "set-cookie", "predictable token"),
        ),
        (
            "authorization",
            (
                "authorization",
                "access control",
                "broken-access-control",
                "permission",
                "admin access",
            ),
        ),
        (
            "information_disclosure",
            ("information disclosure", "information exposure", "sensitive data"),
        ),
    )
    return next(
        (family for family, hints in checks if any(hint in value for hint in hints)),
        "unknown",
    )

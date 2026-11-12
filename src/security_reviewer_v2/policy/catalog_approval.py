"""Approving rows of the CWE catalog and of the rule -> CWE map.

A person approves; this module only records that decision. It changes the review fields of a row (status, reviewed_by,
reviewed_at, review_note and, for the rule map, human_must_confirm) and nothing else, so no number, CWE or rating can be
edited through it. Every request is all-or-nothing: if any id has a problem, nothing is written.

Who must write a note:
* catalog rows: ambiguous or insufficient_data rows, and rows MITRE marks ALLOWED_WITH_REVIEW.
* rule-map rows: every row. A fixed rating decides whether a release is blocked, so each approval carries a written
  reason (one --note can cover several ids). validate_rule_map enforces the same rule on the file.
Rows refused by MITRE, rows built from an incomplete download, and rows already approved cannot be approved.
"""
from __future__ import annotations

import argparse
import copy
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .cwe_catalog_builder import (BASES, BASIS_AMBIGUOUS, BASIS_INSUFFICIENT, STATUS_APPROVED, STATUS_DRAFT,
                                  STATUS_REFUSED, STATUS_SOURCE_INCOMPLETE, STATUSES)
from .cwe_dictionary import CweDictionaryError, default_path, load_dictionary, normalize_cwe_id, validate_cwe

KIND_CATALOG = "catalog"
KIND_RULE_MAP = "rule_map"
RULE_MAP_STATUSES = (STATUS_DRAFT, STATUS_APPROVED)
FIXED_RATINGS = ("critical", "high", "medium", "low", "info")
RATING_POLICIES = ("fixed", "catalog")
POLICY_DIR = Path(__file__).resolve().parent
_CWE_FORMAT = re.compile(r"^CWE-\d{1,5}$")


class ApprovalError(ValueError):
    def __init__(self, problems: Sequence[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


# --------------------------------------------------------------------------- reading and writing

def split_header(text: str) -> tuple[str, str]:
    """The leading comment block is kept as is when a file is rewritten."""
    lines = text.splitlines(keepends=True)
    count = 0
    for line in lines:
        if line.strip() == "" or line.lstrip().startswith("#"):
            count += 1
        else:
            break
    return "".join(lines[:count]), "".join(lines[count:])


def load_document(path: Path) -> tuple[str, dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ApprovalError([f"cannot read {path}: {exc}"]) from exc
    header, body = split_header(text)
    try:
        data = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise ApprovalError([f"{path} is not valid YAML: {exc}"]) from exc
    if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
        raise ApprovalError([f"{path} has no 'rows' list; it is not the expected format"])
    return header, data


def dump_document(header: str, data: Mapping[str, Any]) -> str:
    body = yaml.safe_dump(dict(data), sort_keys=False, allow_unicode=True, width=120, default_flow_style=False)
    return header + body


def write_document(path: Path, header: str, data: Mapping[str, Any]) -> None:
    """Atomic write: a crash can never leave a half-written catalog."""
    path = Path(path)
    descriptor, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(dump_document(header, data))
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- structural validation

def validate_catalog(data: Mapping[str, Any]) -> list[str]:
    problems = []
    seen: set[str] = set()
    for index, row in enumerate(data.get("rows") or []):
        where = f"rows[{index}]"
        if not isinstance(row, dict):
            problems.append(f"{where}: not an object")
            continue
        cwe = row.get("id")
        where = str(cwe or where)
        if not isinstance(cwe, str) or not _CWE_FORMAT.match(cwe):
            problems.append(f"{where}: id must look like CWE-<n>")
        elif cwe in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(str(cwe))
        if row.get("status") not in STATUSES:
            problems.append(f"{where}: status must be one of {', '.join(STATUSES)}")
        if row.get("default_basis") not in BASES:
            problems.append(f"{where}: default_basis must be one of {', '.join(BASES)}")
        if row.get("status") == STATUS_APPROVED and not (row.get("reviewed_by") and row.get("reviewed_at")):
            problems.append(f"{where}: an approved row needs reviewed_by and reviewed_at")
    return problems


def validate_rule_map(data: Mapping[str, Any]) -> list[str]:
    problems = []
    seen: set[tuple[Any, Any]] = set()
    for index, row in enumerate(data.get("rows") or []):
        where = f"rows[{index}]"
        if not isinstance(row, dict):
            problems.append(f"{where}: not an object")
            continue
        where = str(row.get("rule_id") or where)
        if not row.get("scanner") or not row.get("rule_id"):
            problems.append(f"{where}: scanner and rule_id are required")
        key = (row.get("scanner"), row.get("rule_id"))
        if key in seen:
            problems.append(f"{where}: duplicate (scanner, rule_id)")
        seen.add(key)
        if row.get("status") not in RULE_MAP_STATUSES:
            problems.append(f"{where}: status must be one of {', '.join(RULE_MAP_STATUSES)}")
        if row.get("rating_policy") not in RATING_POLICIES:
            problems.append(f"{where}: rating_policy must be one of {', '.join(RATING_POLICIES)}")
        if row.get("rating_policy") == "fixed" and row.get("fixed_rating") not in FIXED_RATINGS:
            problems.append(f"{where}: fixed_rating must be one of {', '.join(FIXED_RATINGS)}")
        cwe = row.get("cwe")
        if cwe is not None and not (isinstance(cwe, str) and _CWE_FORMAT.match(cwe)):
            problems.append(f"{where}: cwe must be null or CWE-<n>")
        for alt in row.get("alt_cwes") or []:
            if not (isinstance(alt, str) and _CWE_FORMAT.match(alt)):
                problems.append(f"{where}: alt_cwes must contain CWE-<n> values")
        if row.get("rating_policy") == "catalog" and not cwe:
            problems.append(f"{where}: rating_policy catalog needs a cwe")
        if row.get("status") == STATUS_APPROVED and not (row.get("reviewed_by") and row.get("review_note")):
            problems.append(f"{where}: an approved row needs reviewed_by and review_note")
    return problems


# --------------------------------------------------------------------------- rules per kind

def _catalog_note_required(row: Mapping[str, Any]) -> bool:
    return row.get("default_basis") in (BASIS_AMBIGUOUS, BASIS_INSUFFICIENT) or bool(row.get("needs_review_note"))


def _rule_map_note_required(row: Mapping[str, Any]) -> bool:
    return True


def _key_field(kind: str) -> str:
    return "id" if kind == KIND_CATALOG else "rule_id"


def _normalize_ids(kind: str, ids: Sequence[str]) -> tuple[list[str], list[str]]:
    keys, problems = [], []
    for raw in ids:
        key = normalize_cwe_id(raw) if kind == KIND_CATALOG else str(raw).strip()
        if not key:
            problems.append(f"{raw!r}: not a valid id")
        elif key not in keys:
            keys.append(key)
    return keys, problems


def _find_rows(data: Mapping[str, Any], kind: str, key: str) -> list[dict]:
    field = _key_field(kind)
    return [row for row in data["rows"] if row.get(field) == key]


# --------------------------------------------------------------------------- approve / revoke

def approve_rows(data: Mapping[str, Any], ids: Sequence[str], reviewer: str, note: str | None, *, kind: str,
                 dictionary: Mapping[str, Any], now: str | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return (new document, approved ids). Raises ApprovalError and changes nothing if any id has a problem."""
    problems: list[str] = []
    reviewer = (reviewer or "").strip()
    note = (note or "").strip()
    if not reviewer:
        problems.append("--reviewer is required")
    keys, bad = _normalize_ids(kind, ids)
    problems += bad
    if not keys and not bad:
        problems.append("no ids given")
    new = copy.deepcopy(dict(data))
    stamp = now or utc_now()
    approved: list[str] = []
    for key in keys:
        matches = _find_rows(new, kind, key)
        if not matches:
            problems.append(f"{key}: not found in the file")
            continue
        if len(matches) > 1:
            problems.append(f"{key}: appears in {len(matches)} rows; fix the file first")
            continue
        row = matches[0]
        if row.get("status") == STATUS_APPROVED:
            problems.append(f"{key}: already approved by {row.get('reviewed_by')}; revoke it first to change the review")
            continue
        if row.get("status") in (STATUS_REFUSED, STATUS_SOURCE_INCOMPLETE):
            detail = (row.get("mitre") or {}).get("reason") or "rebuild the catalog after re-fetching the data"
            problems.append(f"{key}: cannot be approved, status is {row['status']} ({detail})")
            continue
        cwe = row.get("id") if kind == KIND_CATALOG else row.get("cwe")
        if cwe:
            check = validate_cwe(cwe, dictionary=dict(dictionary))
            if check["verdict"] == "refuse":
                problems.append(f"{key}: {cwe} is refused by the MITRE dictionary ({check['reason']})")
                continue
            if check["verdict"] == "needs_review_note" and not row.get("needs_review_note"):
                row["needs_review_note"] = True                       # the dictionary changed since the file was built
        required = _catalog_note_required(row) if kind == KIND_CATALOG else _rule_map_note_required(row)
        if required and not note:
            problems.append(f"{key}: a written --note is required for this row")
            continue
        row["status"] = STATUS_APPROVED
        row["reviewed_by"] = reviewer
        row["reviewed_at"] = stamp
        row["review_note"] = note or None
        if kind == KIND_RULE_MAP:
            row["human_must_confirm"] = False
        approved.append(key)
    if problems:
        raise ApprovalError(problems)
    return new, approved


def revoke_rows(data: Mapping[str, Any], ids: Sequence[str], *, kind: str) -> tuple[dict[str, Any], list[str]]:
    problems: list[str] = []
    keys, bad = _normalize_ids(kind, ids)
    problems += bad
    if not keys and not bad:
        problems.append("no ids given")
    new = copy.deepcopy(dict(data))
    revoked: list[str] = []
    for key in keys:
        matches = _find_rows(new, kind, key)
        if len(matches) != 1:
            problems.append(f"{key}: {'not found in the file' if not matches else 'appears in several rows'}")
            continue
        row = matches[0]
        if row.get("status") != STATUS_APPROVED:
            problems.append(f"{key}: is not approved (status {row.get('status')})")
            continue
        row["status"] = STATUS_DRAFT
        row["reviewed_by"] = None
        row["reviewed_at"] = None
        row["review_note"] = None
        if kind == KIND_RULE_MAP:
            row["human_must_confirm"] = True
        revoked.append(key)
    if problems:
        raise ApprovalError(problems)
    return new, revoked


# --------------------------------------------------------------------------- command line

def _list_rows(data: Mapping[str, Any], kind: str) -> str:
    lines = []
    for row in data["rows"]:
        if kind == KIND_CATALOG:
            note = "note required" if _catalog_note_required(row) else ""
            lines.append(f"{row.get('id'):<10}{row.get('status'):<26}{row.get('default_basis'):<18}{note}")
        else:
            note = "note required" if _rule_map_note_required(row) else ""
            lines.append(f"{str(row.get('rule_id')):<46}{row.get('status'):<26}{str(row.get('cwe')):<10}{note}")
    return "\n".join(lines)


def cli_main(kind: str, argv: Sequence[str] | None = None) -> int:
    default_file = POLICY_DIR / ("cwe_catalog.yaml" if kind == KIND_CATALOG else "rule_cwe_map.yaml")
    what = "CWE ids (79 or CWE-79)" if kind == KIND_CATALOG else "rule ids (for example workflow.order_owner.3)"
    parser = argparse.ArgumentParser(description=f"Approve or revoke rows of {default_file.name}. "
                                                 "Only the review fields change; no number is ever edited.")
    parser.add_argument("--ids", nargs="+", help=what)
    parser.add_argument("--reviewer", help="your name; recorded on the row")
    parser.add_argument("--note", help="why you approve it (required for flagged rows)")
    parser.add_argument("--revoke", action="store_true", help="set the rows back to draft")
    parser.add_argument("--list", action="store_true", help="show every row with its status and whether a note is required")
    parser.add_argument("--file", "--catalog", "--map", dest="file", default=str(default_file))
    parser.add_argument("--dictionary", default=None, help="MITRE dictionary json (default: data/cwe_dictionary.json)")
    args = parser.parse_args(argv)

    path = Path(args.file)
    try:
        header, data = load_document(path)
        problems = validate_catalog(data) if kind == KIND_CATALOG else validate_rule_map(data)
        if problems:
            raise ApprovalError([f"{path} is not valid:", *problems])
        if args.list:
            try:
                print(_list_rows(data, kind))
            except BrokenPipeError:            # `... --list | head` closes the pipe early; that is not an error
                pass
            return 0
        if not args.ids:
            raise ApprovalError(["--ids is required (or use --list)"])
        if args.revoke:
            new, changed = revoke_rows(data, args.ids, kind=kind)
            verb = "revoked"
        else:
            try:
                dictionary = load_dictionary(args.dictionary)
            except CweDictionaryError as exc:
                raise ApprovalError([str(exc)]) from exc
            new, changed = approve_rows(data, args.ids, args.reviewer or "", args.note, kind=kind, dictionary=dictionary)
            verb = "approved"
        write_document(path, header, new)
    except ApprovalError as exc:
        print("NOT CHANGED:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    print(f"{verb} {len(changed)} row(s) in {path}: {', '.join(changed)}")
    return 0

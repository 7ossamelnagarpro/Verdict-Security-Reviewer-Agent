"""Tests for approving catalog rows and rule-map rows. Tiny fixtures, no network."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
import yaml

from security_reviewer_v2.policy import catalog_approval as ca
from security_reviewer_v2.policy.catalog_approval import ApprovalError, KIND_CATALOG, KIND_RULE_MAP

NOW = "2026-11-12T08:00:00Z"
DICTIONARY = {"version": "9.9", "entries": {
    "CWE-89": {"id": "CWE-89", "kind": "weakness", "name": "SQLi", "status": "Stable", "usage": "ALLOWED"},
    "CWE-79": {"id": "CWE-79", "kind": "weakness", "name": "XSS", "status": "Stable", "usage": "ALLOWED"},
    "CWE-862": {"id": "CWE-862", "kind": "weakness", "name": "Missing Authorization", "status": "Stable",
                "usage": "ALLOWED_WITH_REVIEW"},
    "CWE-639": {"id": "CWE-639", "kind": "weakness", "name": "IDOR", "status": "Stable", "usage": "ALLOWED"},
    "CWE-20": {"id": "CWE-20", "kind": "weakness", "name": "Input Validation", "status": "Stable", "usage": "DISCOURAGED"},
    "CWE-1004": {"id": "CWE-1004", "kind": "weakness", "name": "Cookie without HttpOnly", "status": "Stable",
                 "usage": "ALLOWED"},
}}
REVIEW_KEYS = {"status", "reviewed_by", "reviewed_at", "review_note", "human_must_confirm"}


def cat_row(cwe, basis="stable_high", status="draft_needs_human_review", needs_note=False, **extra):
    row = {"id": cwe, "name": cwe, "status": status, "default_basis": basis,
           "modal_rating": "HIGH" if basis == "stable_high" else None, "sample_size": 300,
           "reference_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "reference_vector_share": 0.9123,
           "high_critical_share": 0.9, "flags": [], "needs_review_note": needs_note,
           "mitre": {"verdict": "needs_review_note" if needs_note else "ok", "reason": "mapping usage X"},
           "reviewed_by": None, "reviewed_at": None, "review_note": None, "content_sha256": "abc"}
    row.update(extra)
    return row


def catalog_doc():
    return {"schema_version": 1, "cvss_version": "3.1", "rows": [
        cat_row("CWE-89"),
        cat_row("CWE-79", basis="stable_low"),
        cat_row("CWE-862", basis="ambiguous", needs_note=True),
        cat_row("CWE-639", basis="ambiguous"),
        cat_row("CWE-1004", basis="insufficient_data"),
        cat_row("CWE-20", status="refused_by_mitre", mitre={"verdict": "refuse", "reason": "mapping usage DISCOURAGED"}),
        cat_row("CWE-5", status="source_incomplete"),
    ]}


def rule_row(rule_id, *, cwe="CWE-639", source="llm_proposal", confidence="high", needs_note=False, **extra):
    row = {"scanner": "web-runtime", "rule_id": rule_id, "title": rule_id, "cwe": cwe, "alt_cwes": ["CWE-863"],
           "tool_severity_seen": "high", "rating_policy": "fixed", "fixed_rating": "high", "confidence": confidence,
           "status": "draft_needs_human_review", "reviewed_by": None, "source": source, "evidence": None,
           "human_must_confirm": True, "needs_review_note": needs_note, "note": "proposal"}
    row.update(extra)
    return row


def rule_doc():
    return {"schema_version": 3, "rows": [
        rule_row("workflow.a.1"),                                                        # llm_proposal -> note
        rule_row("web.header", cwe=None, source="no_cwe_applicable", confidence="high"),  # rating-only, no note needed
        rule_row("web.equiv", cwe="CWE-79", source="tool_equivalent"),                   # equivalence -> note
        rule_row("workflow.b.2", cwe="CWE-862", source="no_cwe_applicable", needs_note=True),  # MITRE review -> note
        rule_row("workflow.c.3", source="no_cwe_applicable", confidence="medium"),       # confidence -> note
        rule_row("workflow.d.4", cwe="CWE-20", source="no_cwe_applicable"),              # MITRE refuses its CWE
    ]}


def changed_keys(before, after):
    """Every key whose value differs, for rows present in both documents."""
    changed = set()
    for old, new in zip(before["rows"], after["rows"]):
        changed |= {k for k in set(old) | set(new) if old.get(k) != new.get(k)}
    return changed


def approve(doc, ids, reviewer="Sara", note=None, kind=KIND_CATALOG, dictionary=DICTIONARY):
    return ca.approve_rows(doc, ids, reviewer, note, kind=kind, dictionary=dictionary, now=NOW)


# --------------------------------------------------------------------------- catalog rows

def test_approving_a_clean_row_changes_only_the_review_fields():
    doc = catalog_doc()
    original = copy.deepcopy(doc)
    new, approved = approve(doc, ["CWE-89"])
    assert approved == ["CWE-89"] and doc == original                       # the input is never mutated
    row = new["rows"][0]
    assert (row["status"], row["reviewed_by"], row["reviewed_at"], row["review_note"]) == ("approved", "Sara", NOW, None)
    assert changed_keys(original, new) <= REVIEW_KEYS                         # no number, vector or flag was touched
    assert new["rows"][1:] == original["rows"][1:]


@pytest.mark.parametrize("cwe", ["CWE-862", "CWE-639", "CWE-1004"])
def test_ambiguous_insufficient_and_mitre_review_rows_require_a_note(cwe):
    with pytest.raises(ApprovalError) as error:
        approve(catalog_doc(), [cwe])
    assert "note is required" in str(error.value)
    with pytest.raises(ApprovalError):
        approve(catalog_doc(), [cwe], note="   ")                            # whitespace is not a note
    new, _ = approve(catalog_doc(), [cwe], note="looked at the distribution")
    assert next(r for r in new["rows"] if r["id"] == cwe)["review_note"] == "looked at the distribution"


def test_a_stable_row_that_mitre_wants_reviewed_also_needs_a_note():
    doc = {"rows": [cat_row("CWE-862", basis="stable_high", needs_note=True)]}
    with pytest.raises(ApprovalError):
        approve(doc, ["CWE-862"])
    approve(doc, ["CWE-862"], note="ok")


@pytest.mark.parametrize("cwe", ["CWE-20", "CWE-5"])
def test_refused_and_incomplete_rows_cannot_be_approved_even_with_a_note(cwe):
    with pytest.raises(ApprovalError) as error:
        approve(catalog_doc(), [cwe], note="please")
    assert "cannot be approved" in str(error.value)


def test_a_reviewer_is_required():
    with pytest.raises(ApprovalError) as error:
        approve(catalog_doc(), ["CWE-89"], reviewer="  ")
    assert "--reviewer is required" in str(error.value)


def test_a_request_is_all_or_nothing():
    doc = catalog_doc()
    original = copy.deepcopy(doc)
    with pytest.raises(ApprovalError) as error:
        approve(doc, ["CWE-89", "CWE-862", "CWE-4242"])                       # one needs a note, one does not exist
    assert len(error.value.problems) == 2 and doc == original


def test_id_forms_are_normalized_and_duplicates_collapse():
    new, approved = approve(catalog_doc(), ["89", "cwe-89", " CWE-89 "])
    assert approved == ["CWE-89"]
    with pytest.raises(ApprovalError) as error:
        approve(catalog_doc(), ["nonsense"])
    assert "not a valid id" in str(error.value)


def test_an_already_approved_row_must_be_revoked_first():
    approved, _ = approve(catalog_doc(), ["CWE-89"])
    with pytest.raises(ApprovalError) as error:
        approve(approved, ["CWE-89"], reviewer="Omar")
    assert "already approved by Sara" in str(error.value)
    revoked, ids = ca.revoke_rows(approved, ["CWE-89"], kind=KIND_CATALOG)
    assert ids == ["CWE-89"] and revoked == catalog_doc()                     # back to exactly the draft
    again, _ = approve(revoked, ["CWE-89"], reviewer="Omar")
    assert again["rows"][0]["reviewed_by"] == "Omar"


def test_revoking_a_row_that_is_not_approved_is_an_error():
    with pytest.raises(ApprovalError) as error:
        ca.revoke_rows(catalog_doc(), ["CWE-89"], kind=KIND_CATALOG)
    assert "is not approved" in str(error.value)


def test_the_dictionary_is_checked_again_at_approval_time():
    stricter = json.loads(json.dumps(DICTIONARY))
    stricter["entries"]["CWE-89"]["usage"] = "DISCOURAGED"
    with pytest.raises(ApprovalError) as error:
        approve(catalog_doc(), ["CWE-89"], dictionary=stricter)
    assert "refused by the MITRE dictionary" in str(error.value)
    review = json.loads(json.dumps(DICTIONARY))
    review["entries"]["CWE-89"]["usage"] = "ALLOWED_WITH_REVIEW"              # became review-only: a note is now needed
    with pytest.raises(ApprovalError):
        approve(catalog_doc(), ["CWE-89"], dictionary=review)
    approve(catalog_doc(), ["CWE-89"], dictionary=review, note="reviewed")


# --------------------------------------------------------------------------- rule-map rows

def test_every_rule_map_approval_needs_a_written_note():
    doc = rule_doc()
    for rule_id in ("workflow.a.1", "web.header", "web.equiv", "workflow.b.2", "workflow.c.3"):
        with pytest.raises(ApprovalError) as error:
            approve(doc, [rule_id], kind=KIND_RULE_MAP)
        assert "note is required" in str(error.value), rule_id
        approve(doc, [rule_id], note="confirmed", kind=KIND_RULE_MAP)
    new, approved = approve(doc, ["web.header", "workflow.a.1"], note="one reason covers both", kind=KIND_RULE_MAP)
    assert approved == ["web.header", "workflow.a.1"] and new["rows"][1]["review_note"] == "one reason covers both"


def without_empty_review_keys(doc):
    """A revoked rule-map row gains empty reviewed_at/review_note keys; that is the same meaning as not having them."""
    return {**doc, "rows": [{k: v for k, v in r.items() if not (k in ("reviewed_at", "review_note") and v is None)}
                            for r in doc["rows"]]}


@pytest.mark.parametrize("kind,make_doc,ids", [
    (KIND_CATALOG, catalog_doc, ["CWE-89", "CWE-79", "CWE-862", "CWE-639", "CWE-1004"]),
    (KIND_RULE_MAP, rule_doc, ["workflow.a.1", "web.header", "web.equiv", "workflow.b.2", "workflow.c.3"]),
])
def test_anything_the_approver_accepts_leaves_a_file_that_still_validates(kind, make_doc, ids):
    validate = ca.validate_catalog if kind == KIND_CATALOG else ca.validate_rule_map
    for row_id in ids:
        for note in (None, "a written reason"):
            try:
                new, _ = approve(make_doc(), [row_id], note=note, kind=kind)
            except ApprovalError:
                continue                                                      # refused: nothing was written
            assert validate(new) == [], (kind, row_id, note)
            revoked, _ = ca.revoke_rows(new, [row_id], kind=kind)
            assert validate(revoked) == [] and without_empty_review_keys(revoked) == without_empty_review_keys(make_doc())


def test_listing_survives_a_closed_pipe(files, monkeypatch):
    catalog, dictionary = files

    def closed(*args, **kwargs):
        raise BrokenPipeError()
    monkeypatch.setattr("builtins.print", closed)
    assert run_cli(KIND_CATALOG, catalog, dictionary, "--list") == 0


def test_rule_map_approval_never_edits_the_cwe_or_the_rating():
    doc = rule_doc()
    new, _ = approve(doc, ["workflow.a.1", "web.header"], note="ok", kind=KIND_RULE_MAP)
    assert changed_keys(doc, new) <= REVIEW_KEYS
    row = new["rows"][0]
    assert (row["cwe"], row["fixed_rating"], row["alt_cwes"], row["rating_policy"]) == ("CWE-639", "high", ["CWE-863"], "fixed")
    assert row["human_must_confirm"] is False and row["reviewed_by"] == "Sara"
    revoked, _ = ca.revoke_rows(new, ["workflow.a.1"], kind=KIND_RULE_MAP)
    assert revoked["rows"][0]["human_must_confirm"] is True and revoked["rows"][0]["reviewed_by"] is None


def test_a_rule_whose_cwe_mitre_refuses_cannot_be_approved():
    with pytest.raises(ApprovalError) as error:
        approve(rule_doc(), ["workflow.d.4"], note="ok", kind=KIND_RULE_MAP)
    assert "refused by the MITRE dictionary" in str(error.value)


def test_a_duplicate_rule_id_in_the_file_is_reported_not_guessed():
    doc = rule_doc()
    doc["rows"].append(rule_row("workflow.a.1", source="no_cwe_applicable"))
    with pytest.raises(ApprovalError) as error:
        approve(doc, ["workflow.a.1"], note="ok", kind=KIND_RULE_MAP)
    assert "appears in 2 rows" in str(error.value)


# --------------------------------------------------------------------------- structural validation

def test_catalog_validation_catches_malformed_files():
    assert ca.validate_catalog(catalog_doc()) == []
    bad = catalog_doc()
    bad["rows"][0]["status"] = "maybe"
    bad["rows"][1]["default_basis"] = "great"
    bad["rows"][2]["id"] = "CWE-89"
    bad["rows"][3].update(status="approved")                                  # approved without reviewer
    problems = " | ".join(ca.validate_catalog(bad))
    for needle in ("status must be one of", "default_basis must be one of", "duplicate id", "needs reviewed_by"):
        assert needle in problems


def test_rule_map_validation_catches_malformed_files():
    assert ca.validate_rule_map(rule_doc()) == []
    bad = rule_doc()
    bad["rows"][0]["fixed_rating"] = "catastrophic"
    bad["rows"][1]["rating_policy"] = "magic"
    bad["rows"][2]["cwe"] = "79"
    bad["rows"][3]["alt_cwes"] = ["x"]
    bad["rows"][4]["rating_policy"] = "catalog"
    bad["rows"][4]["cwe"] = None
    bad["rows"].append(dict(bad["rows"][5]))                                  # duplicate (scanner, rule_id)
    problems = " | ".join(ca.validate_rule_map(bad))
    for needle in ("fixed_rating must be one of", "rating_policy must be one of", "cwe must be null or CWE-<n>",
                   "alt_cwes must contain", "catalog needs a cwe", "duplicate (scanner, rule_id)"):
        assert needle in problems


# --------------------------------------------------------------------------- files and the command line

HEADER = "# CWE catalog header\n# Human review is required before any use.\n\n"


def write_catalog(path: Path, doc=None):
    path.write_text(ca.dump_document(HEADER, doc or catalog_doc()), encoding="utf-8")


def test_a_file_round_trip_keeps_the_header_and_every_value(tmp_path):
    path = tmp_path / "cwe_catalog.yaml"
    write_catalog(path)
    header, data = ca.load_document(path)
    assert header == HEADER and data == catalog_doc()
    ca.write_document(path, header, data)
    assert path.read_text(encoding="utf-8").startswith(HEADER)
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == catalog_doc()
    assert not list(tmp_path.glob("*.tmp"))


def test_a_failed_write_leaves_the_original_file_and_no_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "cwe_catalog.yaml"
    write_catalog(path)
    before = path.read_bytes()

    def boom(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        ca.write_document(path, HEADER, {"rows": []})
    assert path.read_bytes() == before and not list(tmp_path.glob("*.tmp"))


def test_unreadable_or_wrong_shape_files_are_reported(tmp_path):
    with pytest.raises(ApprovalError):
        ca.load_document(tmp_path / "missing.yaml")
    (tmp_path / "bad.yaml").write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(ApprovalError):
        ca.load_document(tmp_path / "bad.yaml")
    (tmp_path / "shape.yaml").write_text("rows: nope\n", encoding="utf-8")
    with pytest.raises(ApprovalError):
        ca.load_document(tmp_path / "shape.yaml")


@pytest.fixture()
def files(tmp_path):
    catalog = tmp_path / "cwe_catalog.yaml"
    write_catalog(catalog)
    dictionary = tmp_path / "cwe_dictionary.json"
    dictionary.write_text(json.dumps(DICTIONARY), encoding="utf-8")
    return catalog, dictionary


def run_cli(kind, catalog, dictionary, *args):
    return ca.cli_main(kind, ["--file", str(catalog), "--dictionary", str(dictionary), *args])


def test_cli_approves_and_preserves_the_header(files, capsys):
    catalog, dictionary = files
    code = run_cli(KIND_CATALOG, catalog, dictionary, "--ids", "CWE-89", "79", "--reviewer", "Sara")
    assert code == 0 and "approved 2 row(s)" in capsys.readouterr().out
    text = catalog.read_text(encoding="utf-8")
    assert text.startswith(HEADER)
    rows = {r["id"]: r for r in yaml.safe_load(text)["rows"]}
    assert rows["CWE-89"]["status"] == "approved" and rows["CWE-79"]["reviewed_by"] == "Sara"
    assert rows["CWE-862"]["status"] == "draft_needs_human_review"


def test_cli_refuses_without_changing_the_file(files, capsys):
    catalog, dictionary = files
    before = catalog.read_bytes()
    code = run_cli(KIND_CATALOG, catalog, dictionary, "--ids", "CWE-89", "CWE-862", "--reviewer", "Sara")
    captured = capsys.readouterr()
    assert code == 2 and "NOT CHANGED" in captured.err and "CWE-862: a written --note is required" in captured.err
    assert catalog.read_bytes() == before


def test_cli_revoke_list_and_missing_inputs(files, capsys):
    catalog, dictionary = files
    assert run_cli(KIND_CATALOG, catalog, dictionary, "--ids", "CWE-89", "--reviewer", "Sara") == 0
    assert run_cli(KIND_CATALOG, catalog, dictionary, "--list") == 0
    listing = capsys.readouterr().out
    assert "CWE-89" in listing and "approved" in listing and "note required" in listing
    assert run_cli(KIND_CATALOG, catalog, dictionary, "--ids", "CWE-89", "--revoke") == 0
    assert {r["id"]: r["status"] for r in yaml.safe_load(catalog.read_text(encoding="utf-8"))["rows"]}["CWE-89"] \
        == "draft_needs_human_review"
    assert run_cli(KIND_CATALOG, catalog, dictionary) == 2                    # no --ids
    missing = catalog.parent / "no-dictionary.json"
    assert ca.cli_main(KIND_CATALOG, ["--file", str(catalog), "--dictionary", str(missing),
                                      "--ids", "CWE-89", "--reviewer", "Sara"]) == 2
    assert "scripts/fetch_cwe_dictionary.py" in capsys.readouterr().err


def test_cli_refuses_to_work_on_a_malformed_file(tmp_path, capsys):
    broken = tmp_path / "cwe_catalog.yaml"
    doc = catalog_doc()
    doc["rows"][0]["default_basis"] = "great"
    write_catalog(broken, doc)
    dictionary = tmp_path / "d.json"
    dictionary.write_text(json.dumps(DICTIONARY), encoding="utf-8")
    assert run_cli(KIND_CATALOG, broken, dictionary, "--ids", "CWE-89", "--reviewer", "Sara") == 2
    assert "is not valid" in capsys.readouterr().err


def test_cli_on_a_rule_map(tmp_path, capsys):
    rule_map = tmp_path / "rule_cwe_map.yaml"
    rule_map.write_text(ca.dump_document("# draft\n", rule_doc()), encoding="utf-8")
    dictionary = tmp_path / "d.json"
    dictionary.write_text(json.dumps(DICTIONARY), encoding="utf-8")
    assert run_cli(KIND_RULE_MAP, rule_map, dictionary, "--ids", "workflow.a.1", "--reviewer", "Sara") == 2
    assert run_cli(KIND_RULE_MAP, rule_map, dictionary, "--ids", "web.header", "--reviewer", "Sara") == 2
    assert run_cli(KIND_RULE_MAP, rule_map, dictionary, "--ids", "workflow.a.1", "--reviewer", "Sara",
                   "--note", "confirmed with the app owner") == 0
    rows = {r["rule_id"]: r for r in yaml.safe_load(rule_map.read_text(encoding="utf-8"))["rows"]}
    assert rows["workflow.a.1"]["status"] == "approved" and rows["workflow.a.1"]["fixed_rating"] == "high"


# --------------------------------------------------------------------------- the shipped files stay well-formed

POLICY = Path(ca.__file__).resolve().parent


def test_the_shipped_rule_map_is_valid_and_fully_unapproved():
    path = POLICY / "rule_cwe_map.yaml"
    if not path.is_file():
        pytest.skip("rule_cwe_map.yaml is not in this checkout")
    _, data = ca.load_document(path)
    assert ca.validate_rule_map(data) == []
    assert all(r["status"] == "draft_needs_human_review" and r["human_must_confirm"] for r in data["rows"]
               if r["status"] != "approved")


def test_the_shipped_catalog_is_valid_when_present():
    path = POLICY / "cwe_catalog.yaml"
    if not path.is_file():
        pytest.skip("cwe_catalog.yaml has not been built in this checkout")
    _, data = ca.load_document(path)
    assert ca.validate_catalog(data) == []
    refused = [r for r in data["rows"] if r["status"] in ("refused_by_mitre", "source_incomplete")]
    assert all(r["reviewed_by"] is None for r in refused)


@pytest.mark.parametrize("name", ["build_cwe_catalog.py", "approve_cwe_rows.py", "approve_rule_map.py"])
def test_scripts_put_src_on_the_path_before_importing_the_package(name):
    text = (POLICY.parents[2] / "scripts" / name).read_text(encoding="utf-8")
    assert text.index('sys.path.insert(0, str(ROOT / "src"))') < text.index("from security_reviewer_v2")

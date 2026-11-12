"""Pure-function tests for the CWE catalog builder. Tiny fixtures, no network."""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from security_reviewer_v2.policy import cwe_catalog_builder as cb
from security_reviewer_v2.policy.cwe_catalog_builder import CatalogConfig

CFG = CatalogConfig()
BASE_DAY = datetime(2020, 1, 1)


def vec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"):
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def rec(n, *, cwe="CWE-79", vector=None, severity="HIGH", score=8.0, source="nvd@nist.gov", primary=True,
        secondary=False):
    return {"cve": f"CVE-2020-{n:05d}", "published": (BASE_DAY + timedelta(days=n)).isoformat() + ".000",
            "vector": vector or vec(), "base_score": score, "severity": severity, "metric_source": source,
            "metric_type": "Primary", "cwe_primary": [cwe] if primary else [],
            "cwe_secondary": [cwe] if secondary else [], "cwe_count": 1}


def with_high_critical(total, high_critical, cwe="CWE-79"):
    """`total` records of which `high_critical` are HIGH and the rest MEDIUM."""
    return [rec(n, cwe=cwe, severity="HIGH" if n < high_critical else "MEDIUM",
                score=8.0 if n < high_critical else 5.0) for n in range(total)]


DICTIONARY = {"version": "9.9", "date": "2026-01-01", "entries": {
    "CWE-79": {"id": "CWE-79", "kind": "weakness", "name": "Cross-site Scripting", "status": "Stable", "usage": "ALLOWED"},
    "CWE-22": {"id": "CWE-22", "kind": "weakness", "name": "Path Traversal", "status": "Stable",
               "usage": "ALLOWED_WITH_REVIEW"},
    "CWE-20": {"id": "CWE-20", "kind": "weakness", "name": "Improper Input Validation", "status": "Stable",
               "usage": "DISCOURAGED"},
    "CWE-89": {"id": "CWE-89", "kind": "weakness", "name": "SQL Injection", "status": "Stable", "usage": "ALLOWED"},
    "CWE-1004": {"id": "CWE-1004", "kind": "weakness", "name": "Cookie Without HttpOnly", "status": "Stable",
                 "usage": "ALLOWED"},
}}


def row_for(records, cwe="CWE-79", meta=None, config=CFG, dictionary=DICTIONARY):
    return cb.build_row(cwe, records, meta, dictionary, config)


# --------------------------------------------------------------------------- sampling

def test_sample_uses_primary_assignments_when_there_are_enough():
    records = with_high_critical(40, 40) + [rec(100 + n, primary=False, secondary=True) for n in range(10)]
    selection = cb.select_sample(records, "CWE-79", CFG)
    assert len(selection.records) == 40 and "weak_cwe_assignment" not in selection.flags


def test_falls_back_to_secondary_and_flags_it_when_primary_is_too_few():
    records = with_high_critical(10, 10) + [rec(100 + n, primary=False, secondary=True) for n in range(25)]
    selection = cb.select_sample(records, "CWE-79", CFG)
    assert len(selection.records) == 35 and "weak_cwe_assignment" in selection.flags


def test_prefers_the_nvd_scorer_only_when_enough_of_its_records_remain():
    enough = [rec(n) for n in range(35)] + [rec(100 + n, source="cna@example.org") for n in range(20)]
    selection = cb.select_sample(enough, "CWE-79", CFG)
    assert len(selection.records) == 35 and "non_nvd_scores_used" not in selection.flags
    few = [rec(n) for n in range(10)] + [rec(100 + n, source="cna@example.org") for n in range(40)]
    selection = cb.select_sample(few, "CWE-79", CFG)
    assert len(selection.records) == 50 and "non_nvd_scores_used" in selection.flags


def test_sample_is_the_newest_300_by_published_date_newest_first():
    records = [rec(n) for n in range(400)]
    selection = cb.select_sample(records, "CWE-79", CFG)
    assert len(selection.records) == 300 and len(selection.pool) == 400
    published = [r["published"] for r in selection.records]
    assert published == sorted(published, reverse=True)
    assert selection.records[0]["cve"] == "CVE-2020-00399" and selection.records[-1]["cve"] == "CVE-2020-00100"


# --------------------------------------------------------------------------- statistics

def test_statistics_are_counted_from_the_records():
    a, b = vec(pr="N"), vec(pr="L", c="L", i="N", a="N")
    records = ([rec(n, vector=a, severity="HIGH", score=8.0) for n in range(30)]
               + [rec(100 + n, vector=b, severity="MEDIUM", score=5.0) for n in range(10)])
    stats = cb.compute_stats(records, CFG)
    assert stats["sample_size"] == 40
    assert stats["reference_vector"] == a and stats["reference_vector_share"] == 0.75
    assert stats["rating_distribution"] == {"CRITICAL": 0.0, "HIGH": 0.75, "MEDIUM": 0.25, "LOW": 0.0}
    assert stats["high_critical_share"] == 0.75
    assert stats["per_metric_agreement"]["AV"] == {"value": "N", "share": 1.0}
    assert stats["per_metric_agreement"]["PR"] == {"value": "N", "share": 0.75}
    assert stats["per_metric_agreement"]["C"] == {"value": "H", "share": 0.75}
    assert list(stats["per_metric_agreement"]) == list(cb.METRICS)
    assert stats["nvd_median_base_score"] == 8.0           # published scores, not recomputed


def test_rating_falls_back_to_the_score_bands_when_severity_is_missing():
    assert cb.rating_of({"severity": "critical"}) == "CRITICAL"
    assert [cb.rating_of({"base_score": s}) for s in (9.8, 7.0, 4.0, 3.9, 0.0)] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", None]
    stats = cb.compute_stats([rec(1, severity=None, score=9.1), rec(2, severity="NONE", score=None)], CFG)
    assert stats["unrated_records"] == 1 and stats["rating_distribution"]["CRITICAL"] == 1.0


@pytest.mark.parametrize("total,high_critical,expected", [
    (40, 34, "stable_high"),        # exactly 0.85 is inclusive
    (40, 33, "ambiguous"),
    (40, 6, "stable_low"),          # exactly 0.15 is inclusive
    (40, 7, "ambiguous"),
    (40, 20, "ambiguous"),
    (29, 29, "insufficient_data"),  # below the minimum sample, whatever the share
    (30, 30, "stable_high"),
])
def test_default_basis_thresholds(total, high_critical, expected):
    assert row_for(with_high_critical(total, high_critical))["default_basis"] == expected


def test_thresholds_are_configuration_constants():
    records = with_high_critical(40, 20)
    assert row_for(records)["default_basis"] == "ambiguous"
    assert row_for(records, config=CatalogConfig(stable_high_threshold=0.5))["default_basis"] == "stable_high"
    assert row_for(records, config=CatalogConfig(min_sample=50))["default_basis"] == "insufficient_data"


def test_modal_rating_is_only_given_for_stable_rows_and_ties_go_to_the_more_severe():
    tied = ([rec(n, severity="CRITICAL", score=9.8) for n in range(20)]
            + [rec(100 + n, severity="HIGH", score=8.0) for n in range(20)])
    stable = row_for(tied)
    assert stable["default_basis"] == "stable_high" and stable["modal_rating"] == "CRITICAL"
    ambiguous = row_for(with_high_critical(40, 20))
    assert ambiguous["modal_rating"] is None and ambiguous["modal_rating_share"] is None


def test_unstable_over_time_flag_when_the_recent_mode_differs_from_the_all_time_mode():
    old, new_a, new_b = vec(pr="L"), vec(pr="N"), vec(pr="L", c="L")
    records = ([rec(n, vector=old) for n in range(300)]                     # oldest 300: vector `old`
               + [rec(300 + n, vector=new_a) for n in range(100)]           # newest 300: 100 `new_a`, 200 `new_b`
               + [rec(400 + n, vector=new_b) for n in range(200)])
    row = row_for(records)
    assert row["reference_vector"] == new_b and "unstable_over_time" in row["flags"]
    assert "unstable_over_time" not in row_for([rec(n) for n in range(100)])["flags"]


def test_low_vector_agreement_flag_needs_a_real_sample():
    spread = [rec(n, vector=vec(pr=pr, c=c, i=i, a=a)) for n, (pr, c, i, a) in enumerate(
        (pr, c, i, a) for pr in "NLH" for c in "NLH" for i in "NLH" for a in "NLH")][:40]
    assert "low_vector_agreement" in row_for(spread)["flags"]
    assert "low_vector_agreement" not in row_for(spread[:5])["flags"]       # too small to judge: small_sample instead


def test_tiny_and_empty_data_never_crash_and_are_insufficient():
    one = row_for([rec(1)])
    assert one["default_basis"] == "insufficient_data" and "small_sample" in one["flags"] and one["sample_size"] == 1
    zero = row_for([])
    assert zero["default_basis"] == "insufficient_data" and zero["reference_vector"] is None
    assert zero["rating_distribution"] == {r: None for r in cb.RATINGS}


# --------------------------------------------------------------------------- MITRE verdicts and incomplete data

def test_mitre_verdicts_decide_the_row_status():
    records = with_high_critical(40, 40)
    ok = row_for(records, "CWE-79")
    assert ok["status"] == "draft_needs_human_review" and ok["needs_review_note"] is False and ok["name"] == "Cross-site Scripting"
    review = row_for(records, "CWE-22")
    assert review["status"] == "draft_needs_human_review" and review["needs_review_note"] is True
    refused = row_for(records, "CWE-20")
    assert refused["status"] == "refused_by_mitre" and refused["mitre"]["usage"] == "DISCOURAGED"
    assert "DISCOURAGED" in refused["mitre"]["reason"]
    missing = row_for(records, "CWE-9999")
    assert missing["status"] == "refused_by_mitre" and missing["mitre"]["reason"] == "not found in the catalog"
    assert "name_missing" in missing["flags"]


def test_rows_start_unreviewed():
    row = row_for(with_high_critical(40, 40))
    assert (row["reviewed_by"], row["reviewed_at"], row["review_note"]) == (None, None, None)


def test_an_incomplete_download_is_never_usable():
    row = row_for(with_high_critical(40, 40), meta={"complete": False})
    assert row["status"] == "source_incomplete" and row["default_basis"] == "insufficient_data"
    assert "source_incomplete" in row["flags"] and row["modal_rating"] is None
    assert row_for(with_high_critical(40, 40), meta={"complete": True})["status"] == "draft_needs_human_review"


# --------------------------------------------------------------------------- reading the cache

def write_cache(directory, items):
    directory.mkdir(parents=True, exist_ok=True)
    for number, (records, complete) in items.items():
        (directory / f"CWE-{number}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        (directory / f"CWE-{number}.meta.json").write_text(json.dumps({"complete": complete}), encoding="utf-8")


def test_build_catalog_orders_rows_numerically_and_reports_missing_and_extra(tmp_path):
    raw = tmp_path / "raw"
    write_cache(raw, {1004: (with_high_critical(40, 2, "CWE-1004"), True), 22: (with_high_critical(40, 40, "CWE-22"), True),
                      79: (with_high_critical(40, 20), True), 5: (with_high_critical(3, 3, "CWE-5"), True)})
    (raw / "MANIFEST.json").write_text(json.dumps({"query_date_utc": "2026-11-10T00:00:00Z"}), encoding="utf-8")
    now = datetime(2026, 11, 12, 8, 0, 0, tzinfo=timezone.utc)
    catalog, report = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79, 89, 1004, 22], now=now)
    assert [r["id"] for r in catalog["rows"]] == ["CWE-5", "CWE-22", "CWE-79", "CWE-1004"]
    assert report["missing_data"] == ["CWE-89"] and report["not_expected"] == ["CWE-5"]
    assert catalog["generated"]["at_utc"] == "2026-11-12T08:00:00Z"
    assert catalog["generated"]["nvd_query_date_utc"] == "2026-11-10T00:00:00Z"
    assert catalog["generated"]["mitre_catalog_version"] == "9.9"
    assert report["by_default_basis"]["stable_low"] == 1 and report["by_default_basis"]["insufficient_data"] == 1
    assert [cwe for cwe, _ in report["refused_by_mitre"]] == ["CWE-5"]     # not in the test dictionary
    assert report["needs_review_note"] == ["CWE-22"]


def test_a_missing_raw_folder_gives_an_empty_catalog_not_a_crash(tmp_path):
    catalog, report = cb.build_catalog(tmp_path / "nope", DICTIONARY, CFG, expected=[79])
    assert catalog["rows"] == [] and report["missing_data"] == ["CWE-79"]


def test_malformed_jsonl_fails_with_the_file_and_line(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "CWE-79.jsonl").write_text(json.dumps(rec(1)) + "\n{not json\n", encoding="utf-8")
    with pytest.raises(cb.CatalogBuildError) as error:
        cb.build_catalog(raw, DICTIONARY, CFG)
    assert "CWE-79.jsonl:2" in str(error.value)


def test_expected_list_is_the_agreed_43():
    assert len(cb.EXPECTED_CWES) == 43 == len(set(cb.EXPECTED_CWES))
    assert {16, 22, 79, 639, 862, 1284, 1321} <= set(cb.EXPECTED_CWES)


def test_building_never_touches_the_network(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", refuse)
    raw = tmp_path / "raw"
    write_cache(raw, {79: (with_high_critical(40, 20), True)})
    catalog, _ = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79])
    assert len(catalog["rows"]) == 1


# --------------------------------------------------------------------------- approvals survive rebuilds only for identical data

def test_fingerprint_ignores_review_fields_but_not_numbers():
    row = row_for(with_high_critical(40, 20))
    same = dict(row, status="approved", reviewed_by="x", reviewed_at="t", review_note="n")
    assert cb.content_fingerprint(same) == row["content_sha256"]
    assert cb.content_fingerprint(row_for(with_high_critical(41, 20))) != row["content_sha256"]


def test_approvals_carry_over_only_when_the_numbers_are_identical(tmp_path):
    raw = tmp_path / "raw"
    write_cache(raw, {79: (with_high_critical(40, 20), True), 22: (with_high_critical(40, 40, "CWE-22"), True)})
    first, _ = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79, 22])
    for row in first["rows"]:
        row.update(status="approved", reviewed_by="Sara", reviewed_at="2026-11-12T00:00:00Z", review_note="looked")
    # same data again: approvals kept
    again, report = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79, 22], previous=first)
    assert report["approvals_carried_over"] == ["CWE-22", "CWE-79"] and report["approvals_invalidated"] == []
    assert all(r["status"] == "approved" and r["reviewed_by"] == "Sara" for r in again["rows"])
    # CWE-79 gets new data: its approval drops to draft with the reason; CWE-22 keeps its approval
    write_cache(raw, {79: (with_high_critical(41, 20), True)})
    changed, report = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79, 22], previous=first)
    by_id = {r["id"]: r for r in changed["rows"]}
    assert report["approvals_invalidated"] == ["CWE-79"] and report["approvals_carried_over"] == ["CWE-22"]
    assert by_id["CWE-79"]["status"] == "draft_needs_human_review" and by_id["CWE-79"]["reviewed_by"] is None
    assert by_id["CWE-79"]["previous_approval_invalidated"]["reviewed_by"] == "Sara"
    assert by_id["CWE-22"]["status"] == "approved"


def test_an_approved_row_that_loses_its_data_file_is_reported(tmp_path):
    raw = tmp_path / "raw"
    write_cache(raw, {79: (with_high_critical(40, 20), True)})
    first, _ = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79])
    first["rows"][0]["status"] = "approved"
    (raw / "CWE-79.jsonl").unlink()
    (raw / "CWE-79.meta.json").unlink()
    _, report = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79], previous=first)
    assert report["approved_rows_dropped"] == ["CWE-79"]


def test_an_approval_is_dropped_when_mitre_now_refuses_the_cwe(tmp_path):
    raw = tmp_path / "raw"
    write_cache(raw, {79: (with_high_critical(40, 20), True)})
    first, _ = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79])
    first["rows"][0].update(status="approved", reviewed_by="Sara", reviewed_at="t")
    stricter = json.loads(json.dumps(DICTIONARY))
    stricter["entries"]["CWE-79"]["usage"] = "DISCOURAGED"
    rebuilt, report = cb.build_catalog(raw, stricter, CFG, expected=[79], previous=first)
    assert rebuilt["rows"][0]["status"] == "refused_by_mitre" and report["approvals_invalidated"] == ["CWE-79"]


# --------------------------------------------------------------------------- rendering

def test_yaml_round_trips_every_value_and_keeps_the_header(tmp_path):
    raw = tmp_path / "raw"
    write_cache(raw, {79: (with_high_critical(40, 20), True)})
    catalog, _ = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79])
    text = cb.render_yaml(catalog)
    assert text.startswith("# CWE catalog") and "Human review is required before any use." in text
    loaded = yaml.safe_load(text)
    assert loaded == catalog
    agreement = loaded["rows"][0]["per_metric_agreement"]
    assert agreement["AV"]["value"] == "N" and agreement["S"]["value"] == "U" and isinstance(agreement["UI"]["value"], str)


def test_the_thresholds_are_written_into_the_catalog_file():
    catalog, _ = cb.build_catalog(__import__("pathlib").Path("/nonexistent-raw-dir"), DICTIONARY,
                                  CatalogConfig(stable_high_threshold=0.9), expected=[])
    assert yaml.safe_load(cb.render_yaml(catalog))["config"]["stable_high_threshold"] == 0.9


def test_review_doc_lists_rows_by_basis_refusals_and_missing_data(tmp_path):
    raw = tmp_path / "raw"
    write_cache(raw, {79: (with_high_critical(40, 20), True), 20: (with_high_critical(40, 40, "CWE-20"), True),
                      22: (with_high_critical(40, 40, "CWE-22"), True)})
    catalog, report = cb.build_catalog(raw, DICTIONARY, CFG, expected=[79, 20, 22, 89])
    doc = cb.render_review_doc(catalog, report)
    assert "## All rows" in doc and "| CWE-79 |" in doc
    for basis in cb.BASES:
        assert f"**{basis}**" in doc
    assert "CWE-20: mapping usage DISCOURAGED" in doc
    assert "## Data not cached yet" in doc and "CWE-89" in doc
    assert "CWE-22" in doc.split("ALLOWED_WITH_REVIEW)")[1]
    assert "statistics, not official values" in doc

"""Tests for security_reviewer_v2.policy.cwe_dictionary (tiny JSON fixture, no network)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from security_reviewer_v2.policy import cwe_dictionary as cd

REPO_ROOT = Path(__file__).resolve().parents[1]

ENTRIES = {
    "CWE-79": {"id": "CWE-79", "kind": "weakness", "name": "Cross-site Scripting", "status": "Stable", "usage": "ALLOWED"},
    "CWE-22": {"id": "CWE-22", "kind": "weakness", "name": "Path Traversal", "status": "Stable",
               "usage": "ALLOWED_WITH_REVIEW"},
    "CWE-20": {"id": "CWE-20", "kind": "weakness", "name": "Improper Input Validation", "status": "Stable",
               "usage": "DISCOURAGED"},
    "CWE-16": {"id": "CWE-16", "kind": "grouping", "name": "Configuration", "status": "Draft", "usage": "PROHIBITED"},
    "CWE-613": {"id": "CWE-613", "kind": "weakness", "name": "DEPRECATED: Session Expiration", "status": "Deprecated",
                "usage": "PROHIBITED"},
    "CWE-900": {"id": "CWE-900", "kind": "weakness", "name": "Old but ALLOWED", "status": "Obsolete", "usage": "ALLOWED"},
    "CWE-901": {"id": "CWE-901", "kind": "weakness", "name": "Lower-case status", "status": "deprecated",
                "usage": "ALLOWED"},
    "CWE-1284": {"id": "CWE-1284", "kind": "weakness", "name": "Quantity validation", "status": "Incomplete",
                 "usage": None},
}


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.delenv(cd.ENV_VAR, raising=False)
    cd.clear_cache()
    yield
    cd.clear_cache()


@pytest.fixture()
def dict_file(tmp_path) -> Path:
    path = tmp_path / "cwe_dictionary.json"
    path.write_text(json.dumps({"version": "9.9", "date": "2026-01-01", "entries": ENTRIES}), encoding="utf-8")
    return path


def test_allowed_is_ok(dict_file):
    result = cd.validate_cwe("CWE-79", path=dict_file)
    assert result == {"id": "CWE-79", "exists": True, "kind": "weakness", "status": "Stable", "usage": "ALLOWED",
                      "name": "Cross-site Scripting", "verdict": "ok", "reason": "mapping usage ALLOWED"}


def test_allowed_with_review_needs_a_note(dict_file):
    result = cd.validate_cwe("CWE-22", path=dict_file)
    assert result["verdict"] == "needs_review_note" and "reviewer note" in result["reason"]


def test_discouraged_and_prohibited_are_refused(dict_file):
    assert cd.validate_cwe("CWE-20", path=dict_file)["verdict"] == "refuse"
    prohibited = cd.validate_cwe("CWE-16", path=dict_file)
    assert prohibited["verdict"] == "refuse" and prohibited["kind"] == "grouping"
    assert "PROHIBITED" in prohibited["reason"]


def test_deprecated_and_obsolete_are_refused_even_when_usage_says_allowed(dict_file):
    for cwe in ("CWE-613", "CWE-900", "CWE-901"):          # includes a lower-case status value
        result = cd.validate_cwe(cwe, path=dict_file)
        assert result["verdict"] == "refuse" and result["reason"].startswith("status is "), cwe


def test_missing_usage_needs_a_note_and_is_never_silently_ok(dict_file):
    result = cd.validate_cwe("CWE-1284", path=dict_file)
    assert result["verdict"] == "needs_review_note" and result["usage"] is None
    assert "no mapping usage" in result["reason"]


def test_not_found_is_refused(dict_file):
    result = cd.validate_cwe("CWE-99999", path=dict_file)
    assert result["verdict"] == "refuse" and result["exists"] is False
    assert result["reason"] == "not found in the catalog" and result["name"] is None


@pytest.mark.parametrize("value", ["garbage", "", "CWE-", "CWE-123456", "79.5", None, True, 7.5, [], "CWE 79"])
def test_invalid_ids_are_refused_without_touching_the_file(value):
    result = cd.validate_cwe(value, dictionary={"entries": ENTRIES})
    assert result["verdict"] == "refuse" and result["exists"] is False
    assert result["reason"] == "not a valid CWE id"


@pytest.mark.parametrize("value", [79, "79", "CWE-79", "cwe-79", "  CWE-79  ", "0079"])
def test_every_id_form_normalizes_to_the_same_entry(value, dict_file):
    assert cd.validate_cwe(value, path=dict_file)["id"] == "CWE-79"
    assert cd.normalize_cwe_id(value) == "CWE-79"


def test_explicit_dictionary_argument_needs_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv(cd.ENV_VAR, str(tmp_path / "does-not-exist.json"))
    assert cd.validate_cwe(79, dictionary={"entries": ENTRIES})["verdict"] == "ok"


def test_missing_file_fails_clearly(tmp_path):
    missing = tmp_path / "nope" / "cwe_dictionary.json"
    with pytest.raises(cd.CweDictionaryError) as error:
        cd.validate_cwe(79, path=missing)
    message = str(error.value)
    assert str(missing) in message and "scripts/fetch_cwe_dictionary.py" in message and cd.ENV_VAR in message


@pytest.mark.parametrize("content", ["not json", "[]", '{"entries": []}', '{"entries": {}}', '{"version": "1"}'])
def test_malformed_files_fail_clearly(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(cd.CweDictionaryError) as error:
        cd.load_dictionary(path)
    assert "scripts/fetch_cwe_dictionary.py" in str(error.value)


def test_file_is_cached_after_the_first_load(dict_file):
    first = cd.load_dictionary(dict_file)
    dict_file.write_text(json.dumps({"entries": {"CWE-1": {"id": "CWE-1", "usage": "ALLOWED"}}}), encoding="utf-8")
    assert cd.load_dictionary(dict_file) is first                       # same object, file not re-read
    assert cd.validate_cwe(79, path=dict_file)["exists"] is True        # still the original content
    cd.clear_cache()
    assert cd.validate_cwe(79, path=dict_file)["exists"] is False       # a reload sees the new file
    assert cd.validate_cwe(1, path=dict_file)["verdict"] == "ok"


def test_a_failed_load_is_not_cached(tmp_path):
    path = tmp_path / "late.json"
    with pytest.raises(cd.CweDictionaryError):
        cd.load_dictionary(path)
    path.write_text(json.dumps({"entries": ENTRIES}), encoding="utf-8")
    assert cd.validate_cwe(79, path=path)["verdict"] == "ok"


def test_environment_variable_overrides_the_default_path(dict_file, monkeypatch):
    monkeypatch.setenv(cd.ENV_VAR, str(dict_file))
    assert cd.default_path() == dict_file
    assert cd.validate_cwe("CWE-22")["verdict"] == "needs_review_note"   # no path argument: uses the override


def test_default_path_is_the_repo_data_folder():
    assert cd.default_path() == REPO_ROOT / "data" / "cwe_dictionary.json"


def test_importing_the_module_does_not_read_any_file(monkeypatch):
    monkeypatch.setenv(cd.ENV_VAR, "/definitely/not/here.json")
    importlib.reload(cd)                     # would raise if the import tried to load the dictionary
    assert cd._CACHE == {}


def _load_fetch_script():
    script = REPO_ROOT / "scripts" / "fetch_cwe_dictionary.py"
    if not script.is_file():
        pytest.skip("scripts/fetch_cwe_dictionary.py is not in this checkout")
    spec = importlib.util.spec_from_file_location("fetch_cwe_dictionary_under_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rules_match_the_builder_script_for_every_fixture_entry():
    script = _load_fetch_script()
    dictionary = {"entries": ENTRIES}
    for cwe in [*ENTRIES, "CWE-99999", "79", 20]:
        ours = cd.validate_cwe(cwe, dictionary=dictionary)
        theirs = script.validate_cwe(dictionary, cwe)
        for field in ("id", "exists", "verdict", "reason", "usage", "kind", "status", "name"):
            assert ours[field] == theirs[field], (cwe, field)


def test_the_real_dictionary_has_the_expected_shape_when_it_is_present():
    real = REPO_ROOT / "data" / "cwe_dictionary.json"
    if not real.is_file():
        pytest.skip("data/cwe_dictionary.json has not been built in this checkout")
    data = cd.load_dictionary(real)
    assert len(data["entries"]) > 500
    assert cd.validate_cwe(79, dictionary=data)["exists"] is True
    assert all(e.get("id") == key for key, e in data["entries"].items())

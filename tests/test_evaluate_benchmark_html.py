"""The OWASP Benchmark scorecard script: per-mode category table, CWE ids written in AI text, and the --html page."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_benchmark.py"


@pytest.fixture(scope="module")
def bench():
    spec = importlib.util.spec_from_file_location("evaluate_benchmark_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture(tmp_path: Path, category_x: str = "xss") -> tuple[Path, Path, Path]:
    truth = tmp_path / "truth.csv"
    truth.write_text("# test name, category, real vulnerability, cwe\n"
                     "BenchmarkTest00001,sqli,true,89\nBenchmarkTest00002,sqli,false,89\n"
                     f"BenchmarkTest00003,{category_x},true,79\nBenchmarkTest00004,{category_x},false,79\n", encoding="utf-8")
    root = tmp_path / "scan"
    (root / "testcode").mkdir(parents=True)
    for number in range(1, 5):
        (root / "testcode" / f"BenchmarkTest0000{number}.py").write_text("pass\n", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    (run / "merged.json").write_text(json.dumps({"findings": [{"merged_finding_id": "m1", "cwes": ["CWE-89"], "source_findings": [
        {"primary_location": {"path": "testcode/BenchmarkTest00001.py"}, "cwes": ["CWE-89"], "rule_id": "sql", "title": "SQL"}]}]}), encoding="utf-8")
    # AI names the weakness only in free text, with its CWE id; it also (wrongly) reports the safe XSS test
    (run / "ai-discovery.json").write_text(json.dumps({"candidates": [
        {"candidate_id": "c1", "path": "testcode/BenchmarkTest00003.py", "title": "Reflected input", "category": "Cross-site scripting (CWE-79)", "description": ""},
        {"candidate_id": "c2", "path": "testcode/BenchmarkTest00004.py", "title": "Reflected input", "category": "Cross-site scripting (CWE-79)", "description": ""}]}), encoding="utf-8")
    (run / "security-review.json").write_text(json.dumps({"reviews": [
        {"candidate_id": "m1", "source_ids": ["m1"], "verdict": "confirmed_vulnerability", "title": "SQL injection", "explanation": ""},
        {"candidate_id": "c1", "source_ids": ["c1"], "verdict": "likely_vulnerability", "title": "XSS", "explanation": ""},
        {"candidate_id": "c2", "source_ids": ["c2"], "verdict": "false_positive", "title": "XSS", "explanation": ""}]}), encoding="utf-8")
    return truth, root, run


def test_cwe_written_in_ai_text_counts_as_the_category(bench):
    item = bench.Item(frozenset(), frozenset(), "Cross-site scripting (CWE-79)")
    assert bench.matches("xss", item) and not bench.matches("sqli", item)


def test_result_carries_one_row_per_test_and_the_scores_are_right(bench, tmp_path):
    result = bench.evaluate(*_fixture(tmp_path), {})
    assert [c["id"] for c in result["cases"]] == [f"BenchmarkTest0000{n}" for n in range(1, 5)]
    assert result["cases"][2]["reported_by"] == ["ai_discovery", "agent_final"]
    agent = result["modes"]["agent_final"]
    assert (agent["tp"], agent["fn"], agent["fp"], agent["tn"]) == (2, 0, 0, 2)
    assert result["modes"]["ai_discovery"]["fp"] == 1                  # the safe XSS test the AI reported; the agent dropped it


def test_text_report_shows_every_mode_per_category(bench, tmp_path):
    text = bench.render(bench.evaluate(*_fixture(tmp_path), {}))
    header = next(line for line in text.splitlines() if line.strip().startswith("category"))
    assert "scanners_only" in header and "ai_discovery" in header and "agent_final" in header


def test_html_page_has_the_comprehensive_layout_and_all_tests(bench, tmp_path):
    page = bench.html_report(bench.evaluate(*_fixture(tmp_path), {}))
    for expected in ("OWASP Benchmark scorecard", "Known vulnerabilities".lower(), "BenchmarkTest00004", "Per category", "What the agent changed",
                     "Content-Security-Policy", 'id="theme"'):
        assert expected.lower() in page.lower(), expected
    assert page.count('data-open="c') == 4 and "http://" not in page.replace("http://www.w3.org", "") and "src=\"http" not in page


def test_html_page_escapes_everything_that_came_from_the_data(bench, tmp_path):
    page = bench.html_report(bench.evaluate(*_fixture(tmp_path, category_x="<img src=x onerror=alert(1)>"), {}))
    assert "<img src=x" not in page and "&lt;img src=x" in page


def test_main_writes_html_and_json_next_to_each_other(bench, tmp_path, monkeypatch, capsys):
    truth, root, run = _fixture(tmp_path)
    out_html, out_json = tmp_path / "out" / "card.html", tmp_path / "out" / "card.json"
    monkeypatch.setattr("sys.argv", ["evaluate_benchmark.py", "--ground-truth", str(truth), "--scan-root", str(root),
                                     "--run-dir", str(run), "--html", str(out_html), "--output", str(out_json)])
    assert bench.main() == 0
    assert out_html.read_text(encoding="utf-8").lstrip().lower().startswith("<!doctype html>")
    assert json.loads(out_json.read_text(encoding="utf-8"))["cases"]

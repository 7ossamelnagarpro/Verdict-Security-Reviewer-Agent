"""OWASP Benchmark scorecard for the scanners, AI Discovery and the review agent.

Every Benchmark test case is one file with a known label (vulnerable or safe), so,
unlike the 15-case Security Lab fixture, true/false positives and negatives are all
defined. Scoring follows the Benchmark convention: per category TPR, FPR and
``score = TPR - FPR``; the overall score is the mean of the category scores.

A test counts as *reported* by a mode when a finding in that test's file describes
that category's weakness (same CWE family, or the category's wording when the
finding has no CWE). For the agent, only a positive verdict (confirmed or likely)
counts. Only tests whose file exists under ``--scan-root`` are scored, so a sample
is never penalised for tests it did not scan.

    python scripts/evaluate_benchmark.py --ground-truth BenchmarkPython/expectedresults-0.1.csv \
        --scan-root targets/owasp-benchmark-python --run-dir runs/run_31 \
        [--baseline bandit=BenchmarkPython/results/BenchmarkPython-Bandit.sarif] [--output FILE] [--html FILE]

Standard library only (``--html`` additionally imports the project's own report styling). The ground truth is read after the scan and is never a scan input.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, NamedTuple

POSITIVE = {"confirmed_vulnerability", "likely_vulnerability", "likely_vulnerable"}
TEST_FILE = re.compile(r"BenchmarkTest(\d{5})\.py$")

# CWEs that count as the same weakness as the category's own CWE.
CATEGORY_CWES = {
    "cmdi": {78, 77, 88}, "codeinj": {94, 95, 96}, "deserialization": {502}, "hash": {327, 328, 326, 916},
    "ldapi": {90}, "pathtraver": {22, 23, 36, 73}, "redirect": {601}, "securecookie": {614, 1004, 1275},
    "sqli": {89, 564}, "trustbound": {501}, "weakrand": {330, 331, 335, 336, 337, 338}, "xpathi": {643},
    "xss": {79, 80, 83, 87}, "xxe": {611, 776, 827},
}
# Used only when a finding carries no CWE (AI Discovery labels findings with free text).
CATEGORY_WORDS = {
    "cmdi": ("command injection", "os command", "shell injection"), "codeinj": ("code injection", "eval injection"),
    "deserialization": ("deserializ", "pickle", "unsafe yaml"), "hash": ("weak hash", "insecure hash", "md5", "sha1", "sha-1"),
    "ldapi": ("ldap",), "pathtraver": ("path traversal", "directory traversal"), "redirect": ("open redirect",),
    "securecookie": ("secure flag", "cookie without", "insecure cookie"), "sqli": ("sql injection",),
    "trustbound": ("trust boundary",), "weakrand": ("weak random", "insecure random", "predictable random", "pseudo-random", "pseudorandom"),
    "xpathi": ("xpath",), "xss": ("cross-site scripting", "xss"), "xxe": ("xxe", "xml external entity"),
}


class Item(NamedTuple):
    tests: frozenset[str]
    cwes: frozenset[int]
    text: str
    verdict: str | None = None


def test_name(path: Any) -> str | None:
    match = TEST_FILE.search(str(path).replace("\\", "/")) if path else None
    return f"BenchmarkTest{match.group(1)}" if match else None


def cwe_numbers(values: Any) -> frozenset[int]:
    return frozenset(int(m) for v in (values or []) for m in re.findall(r"cwe[-_]?(\d+)", str(v), re.I))


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def load_truth(path: Path) -> dict[str, dict[str, Any]]:
    truth: dict[str, dict[str, Any]] = {}
    if path.suffix.lower() == ".json":
        for case in read_json(path).get("test_cases", []):
            truth[case["test_name"]] = {"category": case["category"], "vulnerable": bool(case["real_vulnerability"])}
        return truth
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(line for line in handle if line.strip() and not line.lstrip().startswith("#")):
            if len(row) >= 4:
                truth[row[0].strip()] = {"category": row[1].strip(), "vulnerable": row[2].strip().lower() == "true"}
    return truth


def scanned_tests(scan_root: Path) -> set[str]:
    return {p.stem for p in (scan_root / "testcode").glob("BenchmarkTest*.py")} if (scan_root / "testcode").is_dir() else set()


def merged_items(merged: dict[str, Any]) -> dict[str, Item]:
    items: dict[str, Item] = {}
    for finding in merged.get("findings", []) or []:
        tests, cwes, text = set(), set(cwe_numbers(finding.get("cwes"))), []
        for source in finding.get("source_findings", []) or []:
            name = test_name((source.get("primary_location") or {}).get("path"))
            if name:
                tests.add(name)
            cwes |= cwe_numbers(source.get("cwes"))
            text += [str(source.get("rule_id", "")), str(source.get("title", ""))]
        items[str(finding.get("merged_finding_id"))] = Item(frozenset(tests), frozenset(cwes), " ".join(text))
    return items


def candidate_items(discovery: dict[str, Any]) -> dict[str, Item]:
    items = {}
    for cand in discovery.get("candidates", []) or []:
        tests = {t for t in (test_name(cand.get("path")), test_name((cand.get("entry_point") or {}).get("path")),
                             test_name((cand.get("sensitive_operation") or {}).get("path"))) if t}
        items[str(cand.get("candidate_id"))] = Item(frozenset(tests), frozenset(),
                                                    " ".join(str(cand.get(k, "")) for k in ("title", "category", "description")))
    return items


def review_items(review: dict[str, Any], pools: list[dict[str, Item]]) -> list[Item]:
    items = []
    for entry in review.get("reviews", []) or []:
        tests, cwes, text = set(), set(), [str(entry.get("title", "")), str(entry.get("explanation", ""))[:300]]
        for source in entry.get("source_ids", []) or [entry.get("candidate_id")]:
            for pool in pools:
                if source in pool:
                    tests |= pool[source].tests; cwes |= pool[source].cwes; text.append(pool[source].text)
        items.append(Item(frozenset(tests), frozenset(cwes), " ".join(text), str(entry.get("verdict"))))
    return items


def sarif_items(path: Path) -> list[Item]:
    run = (read_json(path).get("runs") or [{}])[0]
    rule_cwes = {r.get("id"): cwe_numbers((r.get("properties") or {}).get("tags")) for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
    items = []
    for result in run.get("results", []) or []:
        uri = (((result.get("locations") or [{}])[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        name = test_name(uri)
        if name:
            items.append(Item(frozenset({name}), rule_cwes.get(result.get("ruleId"), frozenset()),
                              f"{result.get('ruleId', '')} {(result.get('message') or {}).get('text', '')}"))
    return items


CWE_IN_TEXT = re.compile(r"CWE[- ]?(\d{1,4})", re.IGNORECASE)


def matches(category: str, item: Item) -> bool:
    wanted = CATEGORY_CWES.get(category, set())
    if item.cwes:
        return bool(item.cwes & wanted)
    if {int(number) for number in CWE_IN_TEXT.findall(item.text)} & wanted:     # AI findings that name their CWE in text
        return True
    flat = item.text.lower().replace("_", " ").replace("-", " ")
    return any(word in flat for word in CATEGORY_WORDS.get(category, ()))


def predictions(items: list[Item], truth: dict[str, dict[str, Any]], scope: set[str], *, agent: bool = False) -> set[str]:
    reported: set[str] = set()
    for item in items:
        if agent and item.verdict not in POSITIVE:
            continue
        for name in item.tests & scope:
            if matches(truth[name]["category"], item):
                reported.add(name)
    return reported


def scorecard(truth: dict[str, dict[str, Any]], scope: set[str], reported: set[str]) -> dict[str, Any]:
    cats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for name in scope:
        real, hit, cat = truth[name]["vulnerable"], name in reported, truth[name]["category"]
        cats[cat]["tp" if real and hit else "fn" if real else "fp" if hit else "tn"] += 1
    rows, scores = {}, []
    for cat, c in sorted(cats.items()):
        tpr = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
        fpr = c["fp"] / (c["fp"] + c["tn"]) if c["fp"] + c["tn"] else None
        score = round(tpr - fpr, 4) if tpr is not None and fpr is not None else None
        if score is not None:
            scores.append(score)
        rows[cat] = {**c, "tpr": None if tpr is None else round(tpr, 4), "fpr": None if fpr is None else round(fpr, 4), "score": score}
    tp, fn, fp, tn = (sum(c[k] for c in cats.values()) for k in ("tp", "fn", "fp", "tn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    r = lambda v: None if v is None else round(v, 4)
    return {"tests": len(scope), "tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": r(precision), "recall_tpr": r(recall),
            "fpr": r(fp / (fp + tn) if fp + tn else None), "f1": r(f1), "accuracy": r((tp + tn) / len(scope) if scope else None),
            "benchmark_score": r(sum(scores) / len(scores) if scores else None), "categories": rows}


def evaluate(truth_path: Path, scan_root: Path, run_dir: Path | None, baselines: dict[str, Path]) -> dict[str, Any]:
    truth = load_truth(truth_path)
    scope = scanned_tests(scan_root) & set(truth)
    if not scope:
        raise SystemExit(f"No Benchmark test files found under {scan_root / 'testcode'} that appear in the ground truth.")
    modes: dict[str, set[str]] = {}
    notes: list[str] = []
    if run_dir is not None:
        merged_pool = merged_items(read_json(run_dir / "merged.json"))
        cand_pool = candidate_items(read_json(run_dir / "ai-discovery.json"))
        modes["scanners_only"] = predictions(list(merged_pool.values()), truth, scope)
        modes["ai_discovery"] = predictions(list(cand_pool.values()), truth, scope)
        reviews = review_items(read_json(run_dir / "security-review.json"), [merged_pool, cand_pool])
        modes["agent_final"] = predictions(reviews, truth, scope, agent=True)
        skipped = sum(1 for r in reviews if r.verdict == "needs_more_evidence")
        if skipped:
            notes.append(f"{skipped} review(s) ended as needs_more_evidence and are not counted as reports.")
        unmapped = sum(1 for r in reviews if not r.tests)
        if unmapped:
            notes.append(f"{unmapped} review(s) could not be tied to a Benchmark test file and were ignored.")
    for name, path in baselines.items():
        modes[name] = predictions(sarif_items(path), truth, scope)
    cards = {name: scorecard(truth, scope, reported) for name, reported in modes.items()}
    out: dict[str, Any] = {"schema_version": "1.0", "ground_truth": str(truth_path), "scan_root": str(scan_root),
                           "scored_tests": len(scope), "vulnerable": sum(truth[t]["vulnerable"] for t in scope),
                           "safe": sum(not truth[t]["vulnerable"] for t in scope), "modes": cards, "notes": notes}
    out["cases"] = [{"id": name, "category": truth[name]["category"], "vulnerable": bool(truth[name]["vulnerable"]),
                     "reported_by": [mode for mode, reported in modes.items() if name in reported]} for name in sorted(scope)]
    if "scanners_only" in modes and "agent_final" in modes:
        s, a = modes["scanners_only"], modes["agent_final"]
        real = {t for t in scope if truth[t]["vulnerable"]}
        out["agent_effect"] = {
            "false_positives_removed": sorted((s - a) - real), "real_vulnerabilities_lost": sorted((s - a) & real),
            "real_vulnerabilities_recovered": sorted((a - s) & real), "false_positives_introduced": sorted((a - s) - real)}
    return out


def render(result: dict[str, Any]) -> str:
    lines = [f"Scored tests: {result['scored_tests']} ({result['vulnerable']} vulnerable, {result['safe']} safe)", "",
             f"{'MODE':16} {'TPR':>6} {'FPR':>6} {'PREC':>6} {'F1':>6} {'ACC':>6} {'SCORE':>7}   TP  FN  FP  TN"]
    fmt = lambda v: "   n/a" if v is None else f"{v:6.2f}"
    for name, c in result["modes"].items():
        lines.append(f"{name:16} {fmt(c['recall_tpr'])} {fmt(c['fpr'])} {fmt(c['precision'])} {fmt(c['f1'])} {fmt(c['accuracy'])} "
                     f"{fmt(c['benchmark_score']):>7} {c['tp']:4} {c['fn']:3} {c['fp']:3} {c['tn']:3}")
    effect = result.get("agent_effect")
    if effect:
        lines += ["", "What the agent changed compared with the scanners alone:"]
        lines += [f"  false positives removed:         {len(effect['false_positives_removed'])}",
                  f"  real vulnerabilities lost:       {len(effect['real_vulnerabilities_lost'])}  <- the costly mistake",
                  f"  real vulnerabilities recovered:  {len(effect['real_vulnerabilities_recovered'])}",
                  f"  false positives introduced:      {len(effect['false_positives_introduced'])}"]
    modes = result["modes"]
    categories = list(next(iter(modes.values()))["categories"])
    lines += ["", "Per category, TPR/FPR for every mode (each category is usually one vulnerable + one safe test, so values are 0 or 1):",
              f"  {'category':16}" + "".join(f"{name:>14}" for name in modes)]
    for cat in categories:
        cells = []
        for card in modes.values():
            c = card["categories"].get(cat, {})
            part = lambda v: "n/a" if v is None else f"{v:.2f}"
            cells.append(f"{part(c.get('tpr'))}/{part(c.get('fpr'))}")
        lines.append(f"  {cat:16}" + "".join(f"{cell:>14}" for cell in cells))
    lines += [f"note: {n}" for n in result["notes"]]
    return "\n".join(lines)


_MODE_LABELS = {"scanners_only": "Scanners only", "ai_discovery": "AI discovery only", "agent_final": "Final agent (scanners + AI + review)"}
_SHORT_LABELS = {"scanners_only": "Scanners", "ai_discovery": "AI discovery", "agent_final": "Final agent"}


def _outcome(case: dict[str, Any], mode: str) -> str:
    hit = mode in case["reported_by"]
    if case["vulnerable"]:
        return "detected" if hit else "not_detected"
    return "safe_control_flagged" if hit else "safe_control_clean"


def html_report(result: dict[str, Any]) -> str:
    """The scorecard as a page in the same style (rail, dark/light switch) as the Comprehensive lab evaluation."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from security_reviewer_v2.reporting.evaluation_html import render_evaluation

    modes = result["modes"]
    primary = "agent_final" if "agent_final" in modes else next(iter(modes))
    card = modes[primary]
    label = lambda mode: _MODE_LABELS.get(mode, mode)
    pct = lambda v: "n/a" if v is None else f"{v * 100:.1f}%"
    num = lambda v: "n/a" if v is None else f"{v:.2f}"
    rows = []
    for case in result["cases"]:
        status = _outcome(case, primary)
        rows.append({
            "id": case["id"], "status": status,
            "cells": [case["category"], "vulnerable" if case["vulnerable"] else "safe",
                      ", ".join(_SHORT_LABELS.get(m, m) for m in case["reported_by"]) or "none"],
            "details": [("Category", case["category"]),
                        ("Ground truth", "real vulnerability" if case["vulnerable"] else "safe test (no vulnerability)"),
                        ("Outcome per mode", [f"{label(m)}: {_outcome(case, m).replace('_', ' ')}" for m in modes])]})
    effect = result.get("agent_effect")
    sections = [("Per category, TPR / FPR for each mode",
                 [f"{cat}: " + " · ".join(f"{label(m)} {num(c['categories'][cat]['tpr'])}/{num(c['categories'][cat]['fpr'])}"
                                          for m, c in modes.items() if cat in c["categories"])
                  for cat in next(iter(modes.values()))["categories"]])]
    if effect:
        sections.append(("What the agent changed compared with the scanners alone", [
            f"False positives removed: {len(effect['false_positives_removed'])} ({', '.join(effect['false_positives_removed']) or 'none'})",
            f"Real vulnerabilities lost: {len(effect['real_vulnerabilities_lost'])} ({', '.join(effect['real_vulnerabilities_lost']) or 'none'})",
            f"Real vulnerabilities recovered: {len(effect['real_vulnerabilities_recovered'])} ({', '.join(effect['real_vulnerabilities_recovered']) or 'none'})",
            f"False positives introduced: {len(effect['false_positives_introduced'])} ({', '.join(effect['false_positives_introduced']) or 'none'})"]))
    if result["notes"]:
        sections.append(("Run notes", result["notes"]))
    sections.append(("How to read the scores", [
        "TPR (recall): the share of real vulnerabilities that were reported. FPR: the share of safe tests that were wrongly reported.",
        "Score = TPR minus FPR. Zero is no better than guessing; a negative score is worse than guessing.",
        "Each category usually has one vulnerable and one safe test, so category values are 0 or 1 and small samples move the totals a lot.",
        "A test counts as reported when a finding in its file describes that category's weakness (same CWE family, or the category's wording). "
        "For the final agent only confirmed and likely verdicts count."]))
    return render_evaluation(
        title="OWASP Benchmark scorecard",
        headline=f"{label(primary)}: {card['tp']} of {card['tp'] + card['fn']} known vulnerabilities found",
        intro="The ground truth was read only after the scan and review were finished. This is a sample of the Benchmark, not a claim of full coverage.",
        gauge=(card["tp"], card["tp"] + card["fn"], "known vulnerabilities detected"),
        notes=[f"{label(primary)}: TPR {pct(card['recall_tpr'])}, FPR {pct(card['fpr'])}, precision {pct(card['precision'])}, score {num(card['benchmark_score'])}."],
        provenance=[("Scored tests", f"{result['scored_tests']} ({result['vulnerable']} vulnerable, {result['safe']} safe)"),
                    ("Scan folder", Path(result["scan_root"]).name),
                    *[(label(m), f"TPR {pct(c['recall_tpr'])} · FPR {pct(c['fpr'])} · precision {pct(c['precision'])} · score {num(c['benchmark_score'])}"
                       f" · TP {c['tp']} FN {c['fn']} FP {c['fp']} TN {c['tn']}") for m, c in modes.items()]],
        donut=[("Vulnerability found", card["tp"], "var(--mint)"), ("Vulnerability missed", card["fn"], "var(--high)"),
               ("Safe test wrongly flagged", card["fp"], "var(--medium)"), ("Safe test left clean", card["tn"], "var(--low)")],
        donut_unit="tests", table_title=f"All {result['scored_tests']} scored tests",
        columns=["Test", "Category", "Ground truth", "Reported by"], outcome_header="Final outcome" if primary == "agent_final" else "Outcome",
        rows=rows, sections=sections)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ground-truth", type=Path, required=True, help="expectedresults-0.1.csv or the JSON built from it")
    parser.add_argument("--scan-root", type=Path, required=True, help="the folder that was scanned (contains testcode/)")
    parser.add_argument("--run-dir", type=Path, help="the pipeline run folder (merged.json, security-review.json, ...)")
    parser.add_argument("--baseline", action="append", default=[], metavar="NAME=FILE.sarif", help="a tool's SARIF results to score the same way")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--html", type=Path, help="also write the scorecard as an HTML page in the Comprehensive lab evaluation style")
    args = parser.parse_args()
    if args.run_dir is None and not args.baseline:
        parser.error("give --run-dir and/or --baseline")
    baselines = {item.split("=", 1)[0]: Path(item.split("=", 1)[1]) for item in args.baseline if "=" in item}
    result = evaluate(args.ground_truth, args.scan_root, args.run_dir, baselines)
    print(render(result))
    if args.html:
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(html_report(result), encoding="utf-8")
        print(f"\nSaved: {args.html}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nSaved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
        [--baseline bandit=BenchmarkPython/results/BenchmarkPython-Bandit.sarif] [--output FILE]

Standard library only. The ground truth is read after the scan and is never a scan input.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
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


def matches(category: str, item: Item) -> bool:
    if item.cwes:
        return bool(item.cwes & CATEGORY_CWES.get(category, set()))
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
    first = next(iter(result["modes"].values()))
    lines += ["", "Per category (first mode):", f"  {'category':16} {'TPR':>6} {'FPR':>6} {'SCORE':>7}"]
    lines += [f"  {cat:16} {fmt(c['tpr'])} {fmt(c['fpr'])} {fmt(c['score']):>7}" for cat, c in first["categories"].items()]
    lines += [f"note: {n}" for n in result["notes"]]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ground-truth", type=Path, required=True, help="expectedresults-0.1.csv or the JSON built from it")
    parser.add_argument("--scan-root", type=Path, required=True, help="the folder that was scanned (contains testcode/)")
    parser.add_argument("--run-dir", type=Path, help="the pipeline run folder (merged.json, security-review.json, ...)")
    parser.add_argument("--baseline", action="append", default=[], metavar="NAME=FILE.sarif", help="a tool's SARIF results to score the same way")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.run_dir is None and not args.baseline:
        parser.error("give --run-dir and/or --baseline")
    baselines = {item.split("=", 1)[0]: Path(item.split("=", 1)[1]) for item in args.baseline if "=" in item}
    result = evaluate(args.ground_truth, args.scan_root, args.run_dir, baselines)
    print(render(result))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nSaved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Evaluate Security Lab Web detection modes against held-out ground truth."""
from __future__ import annotations

import argparse
import json
import re
import urllib.request
from collections import Counter
from pathlib import Path


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def flatten(value) -> str:
    if isinstance(value, dict):
        return " ".join(f"{flatten(k)} {flatten(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " ".join(flatten(x) for x in value)
    return str(value)


def category_hits(items: list[str], ground_truth: list[dict]) -> Counter[str]:
    hits: Counter[str] = Counter()
    for text in items:
        normalized = text.lower().replace("_", " ").replace("-", " ")
        matched: set[str] = set()
        for item in ground_truth:
            aliases = [str(x).lower().replace("_", " ").replace("-", " ") for x in item.get("aliases", [])]
            if any(alias in normalized for alias in aliases):
                matched.add(item["category"])
        for category in matched:
            hits[category] += 1
    return hits


def metrics(ground_truth: list[dict], detected: Counter[str]) -> dict:
    expected = Counter(item["category"] for item in ground_truth if item.get("expected_status") == "vulnerable")
    tp = sum(min(expected[k], detected[k]) for k in expected)
    fn = sum(max(0, expected[k] - detected[k]) for k in expected)
    duplicate_detections = sum(max(0, detected[k] - expected[k]) for k in expected)
    # Findings repeated by several scanners are duplicates, not automatically
    # false positives. Only categories outside the declared ground truth count
    # as false positives in this fixture-level evaluation.
    fp = sum(detected[k] for k in detected if k not in expected)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"true_positive": tp, "false_positive": fp, "duplicate_detections": duplicate_detections, "false_negative": fn,
            "true_negative": None, "precision": round(precision, 4),
            "recall": round(recall, 4), "f1_score": round(f1, 4),
            "accuracy": None, "accuracy_note": "No safe/negative tt examples were defined in README.md."}


def llm_discover(project: Path, model: str) -> dict:
    files = []
    for path in sorted(project.rglob("*.py")):
        if any(part in {".venv", "venv", "node_modules", "uploads"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")[:120000]
        files.append(f"FILE: {path.relative_to(project)}\n{text}")
    prompt = """You are performing a security review of an intentionally vulnerable educational Flask app.\nReturn ONLY JSON: {\"findings\":[{\"category\":\"one of: idor,sql_injection,reflected_xss,stored_xss,broken_access_control,path_traversal,command_injection,weak_session_token,sensitive_data_exposure,verbose_errors,missing_brute_force_protection,cors_misconfiguration,insecure_file_upload\",\"evidence\":\"short file/function evidence\"}]}\nReport only vulnerabilities supported by the supplied code. Do not invent runtime behavior.\n\n""" + "\n\n".join(files)
    body = json.dumps({"model": model, "stream": False, "format": "json", "messages": [{"role": "user", "content": prompt}]})
    request = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=body.encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode("utf-8"))
    content = payload.get("message", {}).get("content", "")
    try:
        result = json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, re.S)
        result = json.loads(match.group(0)) if match else {"findings": []}
    result["provider"] = "ollama"
    result["model"] = model
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, default=Path("benchmark/security_lab_web_ground_truth.json"))
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--merged", type=Path, required=True)
    parser.add_argument("--security-review", type=Path, required=True)
    parser.add_argument("--ai-discovery", type=Path, required=True)
    parser.add_argument("--llm-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--run-llm-only", action="store_true")
    args = parser.parse_args()
    gt = read_json(args.ground_truth, {}).get("findings", [])
    merged = read_json(args.merged, {})
    review = read_json(args.security_review, {})
    ai = read_json(args.ai_discovery, {})
    if args.run_llm_only:
        llm = llm_discover(args.project.resolve(), args.model)
        args.llm_output.parent.mkdir(parents=True, exist_ok=True)
        args.llm_output.write_text(json.dumps(llm, indent=2) + "\n", encoding="utf-8")
    else:
        llm = read_json(args.llm_output, {"findings": [], "status": "not_run"})

    scanner_items = [flatten(item.get("canonical_finding", item)) for item in merged.get("findings", [])]
    llm_items = [flatten(item) for item in llm.get("findings", [])]
    combined_items = scanner_items + llm_items + [flatten(item) for item in review.get("reviews", [])] + [flatten(item) for item in ai.get("candidates", [])]
    modes = {
        "scanners_only": scanner_items,
        "llm_only": llm_items,
        "scanners_with_llm": combined_items,
    }
    result = {"schema_version": "1.0", "fixture": "security-lab-web", "ground_truth": str(args.ground_truth),
              "ground_truth_count": len(gt), "modes": {}}
    for name, text in modes.items():
        detected = category_hits(text, gt)
        result["modes"][name] = {"detected_category_counts": dict(detected),
                                 "metrics": metrics(gt, detected)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

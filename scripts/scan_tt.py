"""Local VulnShop assessment; runtime writes are opt-in."""
import argparse
import json
from pathlib import Path
from dataclasses import asdict
from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.profiler.reporting import render_markdown
from security_reviewer_v2.orchestrator import ScannerOrchestrator, OrchestratorPolicy
from security_reviewer_v2.scanners import AdapterRegistry
from security_reviewer_v2.scanners.codeql import CodeQLAdapter, CodeQLConfig
from security_reviewer_v2.scanners.semgrep import SemgrepAdapter, SemgrepConfig
from security_reviewer_v2.scanners.gitleaks import GitleaksAdapter, GitleaksConfig
from security_reviewer_v2.normalization.codeql import normalize_codeql_sarif_file
from security_reviewer_v2.normalization.semgrep import normalize_semgrep_json_file
from security_reviewer_v2.normalization.gitleaks import normalize_gitleaks_json_file
from security_reviewer_v2.normalization.runtime import normalize_runtime_json_file
from security_reviewer_v2.scanners.web_runtime import RuntimeConfig, run_checks
from security_reviewer_v2.normalization.merge import merge_normalized_findings
from security_reviewer_v2.context.collector import collect_context
from security_reviewer_v2.prioritization.engine import prioritize_findings

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(r"C:\Users\jonal\OneDrive\Desktop\tt")
OUT = ROOT / "reports/tt-assessment"
TOOLS = ROOT.parent / "tools"

def save(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-mutating", action="store_true",
                        help="enable stored-XSS and upload checks; modifies only the lab target")
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    profile = profile_project(TARGET)
    save("profile.json", profile.to_dict())
    (OUT / "profile.md").write_text(render_markdown(profile), encoding="utf-8")
    bundle = TOOLS / "codeql-2.27.1/codeql"
    suite = next(bundle.glob("qlpacks/codeql/python-queries/*/codeql-suites/python-security-extended.qls"))
    adapters = AdapterRegistry((
        SemgrepAdapter(SemgrepConfig(executable=str(ROOT / ".venv/Scripts/semgrep.exe"))),
        CodeQLAdapter(CodeQLConfig(executable=str(bundle / "codeql.exe"),
            query_suites={"python": str(suite)}, search_path=str(bundle / "qlpacks"))),
        GitleaksAdapter(GitleaksConfig(executable=str(TOOLS / "gitleaks-v8.30.1/gitleaks.exe"))),
    ))
    summary = ScannerOrchestrator(adapters, policy=OrchestratorPolicy(
        scanner_timeouts={"codeql-cli":2700,"semgrep-ce":600,"gitleaks":120}
    )).execute(profile.scan_plan, project_root=TARGET, runs_root=OUT, run_id="static-rerun")
    save("execution.json", summary.to_dict())
    batches = []
    funcs = {"codeql-cli": normalize_codeql_sarif_file, "semgrep-ce": normalize_semgrep_json_file,
             "gitleaks":normalize_gitleaks_json_file}
    for task in summary.tasks:
        print(task.scanner_id, task.status.value, flush=True)
        for output in task.raw_outputs:
            batch = funcs[task.scanner_id](OUT / "static-rerun" / output)
            batches.append(batch)
            save(task.scanner_id + "-normalized.json",batch.to_dict())
            print("findings",len(batch.findings),flush=True)
    runtime_path = OUT / "runtime-v2.json"
    run_checks(RuntimeConfig("http://127.0.0.1:5000", runtime_path, args.runtime_mutating))
    runtime_batch = normalize_runtime_json_file(runtime_path)
    save("runtime-v2.normalized.json", runtime_batch.to_dict())
    batches.append(runtime_batch)
    print("web-runtime", "findings", len(runtime_batch.findings), flush=True)
    merged = merge_normalized_findings(tuple(batches))
    save("merged.json",merged.to_dict())
    context = collect_context(merged, project_root=TARGET)
    save("context.json",context.to_dict())
    risk = prioritize_findings(merged,context)
    save("risk.json",risk.to_dict())
    print("merge",asdict(merged.summary),"risk",asdict(risk.summary),flush=True)

if __name__ == "__main__":
    main()

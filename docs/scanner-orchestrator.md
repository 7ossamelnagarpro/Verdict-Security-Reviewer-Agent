# Scanner Interface and Orchestrator

See [CodeQL performance and isolated runs](codeql-performance.md) for the
repeatable CodeQL CLI, deduplicated scopes and separate stage budgets.

The orchestrator turns an explainable `ScanPlan` into bounded scanner execution.
It does not interpret findings, normalize SARIF/JSON, review vulnerabilities, or
produce a deployment verdict.

## Responsibilities

1. Read planning decisions without confusing them with execution state.
2. Find a registered adapter for each scanner task.
3. Verify local prerequisites without installing or downloading anything.
4. Build trusted executable/argument specifications instead of shell strings.
5. Run commands sequentially with a total task timeout.
6. Keep stdout/stderr bounded and redact common secret patterns.
7. Continue other tasks when one scanner fails.
8. Validate expected raw outputs and write an execution summary.
9. Expose missing coverage for unavailable, failed, timed-out, or invalid scans.
10. Checkpoint each task so an interrupted run can resume without repeating completed scans.

## Main API

```python
from security_reviewer_v2.orchestrator import ScannerOrchestrator
from security_reviewer_v2.scanners import AdapterRegistry

orchestrator = ScannerOrchestrator(AdapterRegistry((adapter,)))
summary = orchestrator.execute(
    scan_plan,
    project_root="path/to/project",
    runs_root="scans/runs",
)
```

To resume the same run, call `execute(..., run_id=summary.run_id, resume=True)`
with the same project, scan plan, registered adapters, and input fingerprint.
An interrupted run may not have a final summary; its run ID is in its directory
name and `manifest.json`. Resume retries failed, timed-out, or unfinished tasks
in new attempt directories. Completed tasks are reused only while their raw
output files still exist. A per-run OS lock prevents concurrent resumes.

For a saved profiler artifact, use the standalone stage command:

```powershell
python -m scripts.run_saved_scan_plan PROJECT --profile profile.json --runs-root scans/runs
python -m scripts.run_saved_scan_plan PROJECT --profile profile.json --runs-root scans/runs --resume-run-id RUN_ID
```

New profiler JSON artifacts include a project snapshot: the resolved root path,
discovered file hashes, and scan-plan digest. A changed project or plan is
rejected before scanner execution; regenerate the profile first. Older JSON
artifacts without a snapshot must also be regenerated. The snapshot covers the
profiler's inventory, so an already-partial profile still has its documented
coverage gaps; it is not a guarantee about undiscovered files or concurrent
edits during a scan.

The initial implementation is intentionally sequential. This makes failures and
resource use easier to reason about; controlled concurrency can be introduced
later without changing the adapter contract.

## Planning state versus execution state

Profiler planning states include `selected`, `needs_verification`, `blocked`,
`not_applicable`, and `disabled_by_policy`. Orchestrator execution states include
`completed`, `failed`, `timed_out`, `skipped`, `adapter_unavailable`,
`prerequisite_missing`, `prerequisite_unverified`, `unsupported`, and
`invalid_output`.

A task that did not complete becomes an explicit coverage gap. It is never
treated as a successful scan with zero findings.
Tasks skipped because of the per-invocation task limit make the overall run
`partial` when other tasks completed. A later resume can process the skipped
tasks without rerunning completed ones. Policy-disabled and not-applicable
tasks remain intentional skips.

## Command safety

Adapters return an absolute trusted executable plus a separate argument tuple.
The process runner uses `shell=False`, closed standard input, a restricted
environment allowlist, bounded task time, and bounded logs. Repository files do
not supply executables or raw command strings. Common token/key/password patterns
are redacted from captured logs.

## CodeQL adapter

`CodeQLAdapter` currently supports planned standard-suite SAST tasks for
languages that have an explicitly configured query suite. Its trusted config
contains:

- absolute CodeQL executable path;
- explicit language-to-query-suite paths;
- optional pack search path;
- verified CLI version;
- build modes for interpreted languages.

Before execution it verifies the executable and runtime version, query suite,
target containment, and search path. It then runs:

1. `database create` into the isolated task directory;
2. `database analyze` into `result.sarif`;
3. SARIF JSON/version/runs validation.

Compiled-language build strategies are not implemented yet. No query pack is
downloaded automatically.

## Semgrep Community Edition adapter

`SemgrepAdapter` supports trusted Community Registry configurations and trusted
absolute local-rule paths. V2 defaults to `p/python` and `p/security-audit`; it
does not generate or require a project-specific local rule for normal scans.

Before execution the adapter verifies the executable and runtime version,
configured rule references, and target containment. It runs with `shell=False`,
JSON output, metrics disabled by the current trusted config, and explicit
per-task exclusions. Targets are passed relative to the project root so result
paths remain portable. Generated Python cache files are excluded from SAST.

Registry availability is ultimately verified during execution because registry
rules may require local cache or network access. Missing or invalid registry
configuration causes the task to fail visibly rather than returning zero
findings.

## Gitleaks adapter

`GitleaksAdapter` supports current-file `directory` scans and `git_history`
scans. It verifies the executable/version, target containment, and Git metadata
when history mode is requested. Reports are JSON and run with redaction enabled
and `--exit-code=0`, so a detected secret is a finding rather than a failed
process. Secret values are not copied into normalized findings.

## Trivy adapter

`TrivyAdapter` supports filesystem tasks for SCA, secrets, and misconfiguration
scans. It creates one command/output per target, maps trusted exclusions to
Trivy skip flags, verifies the executable/version, and validates every JSON
output. Vulnerability database availability is a separate prerequisite for
offline SCA. The adapter auto-detects the standard local Trivy cache (or accepts
an explicit configured cache directory) and leaves SCA explicitly unverified
when neither contains `db/trivy.db` and `db/metadata.json`.

## Run artifacts

```text
scans/runs/<run-id>/
├── manifest.json
├── checkpoint.json
├── execution-summary.json
└── <scanner-id>/<task-id>/
    ├── logs/
    └── raw scanner output
```

Retries use a sibling `<task-id>-attempt-2/` directory so earlier logs and
partial artifacts are preserved. `execution-summary.json` is written after
all attempted tasks finish; `checkpoint.json` is updated atomically after each
task, including failures and resource-limit skips.

The execution summary contains relative artifact paths, prerequisite checks,
command status/exit codes/durations, overall status, warnings, and coverage
gaps. It does not claim the project is secure.

## Implemented limits

- total tasks per run;
- total elapsed time per task;
- maximum captured bytes per stdout/stderr log;
- safe run identifiers;
- isolated non-overwriting run directories;
- expected outputs restricted to the task directory.

## Current limitations

- Execution is sequential; concurrency is not implemented yet.
- CodeQL, Semgrep, Gitleaks, and Trivy real adapters exist. Their executable
  paths are configuration inputs and are verified before execution.
- Process cancellation through an external UI is not implemented.
- Raw CodeQL SARIF, Semgrep JSON, Gitleaks JSON, and Trivy JSON can be normalized
  by the normalization layer.
- Log redaction is defensive but cannot guarantee recognition of every possible
  secret format; scanner configurations should avoid echoing secret values.

## Trivy vulnerability database (SCA)

Scans run with `--skip-db-update`, so `~/.cache/trivy` may contain only the misconfiguration checks
(`policy/`) and no `db/trivy.db`; the SCA task is then reported `prerequisite_unverified` (never "clean").
`scripts/run_pre_review_pipeline.py` now downloads the DB once (`trivy image --download-db-only`, DB only,
no source code is sent) when it is missing. Set `TRIVY_AUTO_DOWNLOAD_DB=0` for offline runs and download
it yourself: `trivy image --download-db-only`.

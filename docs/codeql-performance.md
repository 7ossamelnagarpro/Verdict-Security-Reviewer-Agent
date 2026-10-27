# CodeQL execution and performance

Run the standalone CodeQL stage from the repository root:

```powershell
.venv\Scripts\python.exe -m security_reviewer_v2.orchestrator.codeql_cli targets/security-lab-web --bundle "C:\path\to\codeql" --output scans/runs/my-new-codeql-run
```

The output directory must be new. The CLI uses only locally installed query
packs. It selects security-extended by default; --suite security-and-quality
explicitly adds quality checks. It records the actual suite paths, exclusions,
profile gaps, per-command duration and execution status.

JavaScript and TypeScript use one database per covering source root. A root
task covers nested frontend tasks with matching standard policy; their evidence
and component identifiers remain in its reasons. Independent component roots
remain separate. Custom exclusion policies prevent parent/child consolidation.
The root database preserves cross-file relationships; arbitrary file chunks
are not used for CodeQL.

Defaults: 2 threads, 4096 MB evaluator RAM, 900 seconds extraction and 1800
seconds analysis. Override with --threads, --ram-mb, --extract-timeout and
--analyze-timeout. RAM is an evaluator budget, not an operating-system limit
on all child processes. Timeout values are starting budgets, not a speed guarantee.

Each task runs sequentially in its own run directory. A slow CodeQL task
does not block a separate Semgrep/Gitleaks/Trivy run. This CLI does not launch
those other scanners and does not add concurrent jobs on this machine.
Results are checkpointed after each completed task in codeql-results.json.
Read its finished_tasks against planned_tasks to detect interrupted batches.

Exclusions are passed through a generated CodeQL configuration to extraction.
Default application exclusions cover dependency/build directories; tests and
fixtures are retained. Custom exclusions require explicit trusted policy and
remain visible in the plan. Files outside scanner support and scanner-internal
exclusions can still limit coverage, even when command execution completes.

This change does not implement database caching or incremental/overlay analysis.
Reusing a stale database for changed source would be incorrect. A future cache
must key source content, scope, extraction options and CodeQL version, and
validate compatibility before reuse.

Sources:
- https://docs.github.com/en/code-security/tutorials/customize-code-scanning/prepare-code-for-analysis
- https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-query-suites

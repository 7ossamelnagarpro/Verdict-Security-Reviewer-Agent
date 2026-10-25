# Root Cause Analysis — run_v27 (`security-lab-web`)

**Outcome of the run:** execution `partial`; only 2 of 5 applicable scanner tasks completed
(Semgrep, Trivy misconfiguration). Gitleaks, CodeQL and Trivy SCA produced no results.
The policy gate (`failed`, blocking) was based on Semgrep + Trivy-misconfig + AI review only.

| # | Symptom (artifact) | Root cause (code) | Fix |
|---|---|---|---|
| 1 | CodeQL `database-create` exit 2: *"Cannot create database at `C:\mnt\c\Users\…` because `C:\mnt\c\…\task-…` does not exist"* (`codeql-cli/.../database-create.stderr.log`) | Pipeline runs in WSL (paths `/mnt/c/...`) but the CodeQL bundle is a Windows `codeql.exe`. `CodeQLAdapter` passed POSIX paths unchanged, and Windows reads `/mnt/c/x` as `C:\mnt\c\x`. | New `scanners/hostpaths.py::translate_arguments`, applied in `orchestrator/runner.py` for any `.exe` launched from a POSIX interpreter: `/mnt/<d>/…` → `D:\…`, other paths via `wslpath -w`. Linux binaries are untouched. |
| 2 | Gitleaks exit 1: *unknown command "dir"* (`gitleaks-dir.stderr.log`) | Adapter always built `gitleaks dir …`. That subcommand only exists in Gitleaks ≥ 8.19; the installed binary is older. The earlier "accept any version" change let this binary through instead of stopping at the version check. | `gitleaks.py` probes `gitleaks dir --help`; if the binary positively reports *unknown command*, it uses the equivalent `detect --no-git --source=…` and a legacy-format allowlist (`[allowlist]`). Modern binaries are unchanged. |
| 3 | "runtime version could not be read" for Gitleaks/Semgrep | Version regex `\b\d+\.\d+\.\d+\b` cannot match `v8.18.4` (no word boundary between `v` and `8`); Semgrep probe read stdout only with a 15 s timeout. | Shared tolerant `parse_version` (accepts `v` prefix, reads stdout+stderr); Semgrep probe timeout 45 s. |
| 4 | Trivy SCA `prerequisite_unverified: trivy_databases` although Trivy had a populated cache (`~/.cache/trivy/policy` is in the logs) | `_trivy_cache_dir` only looked in `TRIVY_CACHE_DIR`, `%LOCALAPPDATA%`, `%USERPROFILE%` — never `~/.cache/trivy` / `$XDG_CACHE_HOME/trivy` used on Linux/WSL. | Added Linux/macOS defaults; a candidate that actually contains `db/trivy.db` + `metadata.json` wins. If the DB truly is missing, SCA still reports *unverified* (never silently "clean") and the message now names the directory checked and the fix. |
| 5 | Semgrep `status: partial` — *Syntax error at line Dockerfile:3* | The target `Dockerfile` uses CRLF line endings; Semgrep's Dockerfile parser rejects `\` + CRLF continuations. **Target-side data issue, not a pipeline bug** — the target is not modified. | Coverage-gap text now includes the scanner's own reason. Convert the Dockerfile to LF to restore Semgrep coverage of it. |
| 6 | Pre-review summary said `status: completed` while 3 scanner tasks failed | `scanners_satisfied` is only evaluated with `--require-all-scanners`; otherwise it is trivially true, and the report showed no coverage statement. | Report header/executive summary compute coverage from the execution record; `pre-review-summary.json` gains `scanner_coverage` (`status` semantics unchanged). |
| 7 | Trivy 0.71.2 / CodeQL 2.27.2 ran against "expected" 0.75.0 / 2.27.1 | Version enforcement was disabled by request. Trivy logged that a `rego` check needs ≥ 0.72.0 and was skipped. | Version differences are now **disclosed** in the report (*"Scanner version not verified"*) instead of being invisible. Upgrading Trivy restores the skipped check. |

## Security-result integrity
No verdict, severity, confidence, risk score or policy action is computed or altered by these changes.
The report renderer only re-orders and labels existing data. Verified by re-rendering the saved `run_v27`
artifacts: 19 reviews, 26 observations, 5 blocking decisions — identical to the original report.
Not verifiable offline: a live CodeQL/Gitleaks run on your machine (no scanners available in this environment);
please re-run the pipeline to confirm items 1–2 end to end.

## Report changes (`reporting/final.py`)
Header table with release decision and scanner coverage; blocking findings first; severity × verdict matrix;
"Findings at a Glance" table; next steps; scanner table (outcome + why + version warnings); observations as a
table (identifiers moved into a collapsible block); verdicts sorted by policy action then severity, each with
location; policy decisions as a table with finding titles; de-duplicated coverage gaps; acronym casing
(`Sql` → `SQL`); backtick-safe evidence rendering.

---

# Follow-up: duplicate findings, release gate, Trivy/Gitleaks

## 1. Duplicates — root cause and fix
`merged.json` of run_v27 shows `input_findings: 26, merged_findings: 26, duplicates_collapsed: 0`: the merge layer
never collapsed anything inside one scanner unless rule **and** fingerprint matched, and cross-scanner merging needed the
exact same start line and an overlapping CWE. Real duplicates: two Semgrep rules (flask + django) on the same XSS line (×2 on 6 lines),
three subprocess rules on `app.py:275` (×3), the same SQL statement reported at 145-152 and 146-152 plus `tainted-sql-string`
(CWE-704, really SQL injection).

Fix (`normalization/families.py`, `normalization/merge.py`, `merge_models.py`): findings merge when they share
**vulnerability family** (CWE aliases + rule/title patterns), **file**, and **overlapping source range** (root cause = same
statement), with a span cap so overlap never chains distinct statements. Secrets and SCA/config findings keep their own identity.
**Nothing is deleted:** every raw result stays in `source_findings`, every rule id in `rule_ids`, and `merge_reasons` records
`root_cause:<family>` / `same_scanner_multiple_rules`. Severity/confidence of a merged record = the strongest member.
Toggle: `DeduplicationPolicy(root_cause_dedup=False)`.

Measured on the real run_v27 scanner output: **26 → 14 records, 26/26 raw results retained**; replaying triage offline:
review groups **19 → 16** (SQL-injection groups 5 → 2). Distinct XSS sinks on different lines correctly stay separate.

## 2. Release gate — explicit, testable rules (`policy/rules.py`, `policy/gate.py`)
Decisions now come from named rules `RG-001…RG-007` evaluated on the AI verdict **and** deterministic evidence
(scanner findings in the issue group; source-grounding verification). Basis is recorded as `scanner_corroborated`,
`source_verified`, `ai_assertion_only` or `not_assessed`. Every decision stores `rule_id`, `evidence_basis`, `evidence[]`
and, for blocks, `blocking_reason`. Key properties (all unit-tested): an AI claim with no scanner finding and no confirmed source
cannot block (RG-002); an AI "false positive" cannot auto-allow a finding a scanner rates high/critical (RG-005); an AI downgrade
cannot hide a confirmed vulnerability backed by a high scanner finding (RG-007). Callers pass `merged_payload` and
`verification_payload`; legacy calls without them behave as before (`not_assessed`).
**Replay of run_v27: identical outcome** — the same 5 blocks (4 SQL injection + 1 critical privilege escalation), 0 decisions changed,
each now carrying its rule and evidence.

## 3. Trivy and Gitleaks
* **Trivy SCA "not run":** only the vulnerability database is unverified; the version note is informational. The pipeline never downloads
  databases by itself — run once `trivy fs --download-db-only` (or set `TRIVY_CACHE_DIR`). The misconfiguration task is unaffected.
* **Gitleaks "failed":** no new log was supplied, so the exact cause could not be confirmed. One real risk was fixed: for
  legacy binaries the fallback used a generated `--config`, which on old Gitleaks **replaces** the built-in rules (silent zero-rule scan).
  Legacy mode now runs on the default ruleset with no config (path exclusions are not applied there — scans more, never less).
  Please send `gitleaks/*/logs/*.stderr.log` from the failing run.

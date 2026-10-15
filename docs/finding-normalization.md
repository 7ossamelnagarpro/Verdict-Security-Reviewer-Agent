# Finding Normalization

Normalization converts scanner-specific output into a stable V2 finding model.
It does not decide whether a finding is a true positive, merge findings from
different scanners, collect source context, or call an AI reviewer.

## Unified finding fields

The schema includes:

- stable `finding_id` and schema version;
- scanner identity, version, run index, and result index;
- rule id, title, description, message, kind, and help URI;
- normalized severity and optional numeric security score;
- normalized confidence;
- CWE identifiers and non-CWE categories;
- primary relative location and optional snippet;
- complete available code-flow steps;
- related locations;
- scanner fingerprints.

The models are in
`src/security_reviewer_v2/normalization/models.py`. They use only Python standard
library dataclasses and produce deterministic JSON for identical inputs.

## CodeQL SARIF mapping

The CodeQL normalizer accepts SARIF `2.1.0` data produced by CodeQL. Rule metadata is
resolved from `tool.driver.rules`; individual results provide messages,
locations, fingerprints, code flows, and related locations.

Security severity is mapped from CodeQL's numeric score:

```text
9.0–10.0 → critical
7.0–8.9  → high
4.0–6.9  → medium
0.1–3.9  → low
0.0      → info
```

When no numeric score exists, SARIF levels provide a conservative fallback.
CodeQL precision maps `very-high` and `high` to high confidence, `medium` to
medium, and `low` to low. Missing information remains explicitly `unknown`.

CWE tags such as `external/cwe/cwe-089` are normalized to `CWE-89`.

## Semgrep JSON mapping

Semgrep results map `check_id`, locations, messages, metadata, severity,
confidence, CWE, technology/category tags, fingerprints, and rule references
into the same `UnifiedFinding` model. When Semgrep provides a data-flow trace,
the normalizer preserves source, intermediate, and sink steps.

Semgrep scan errors become structured warnings and make normalization `partial`.
A successful scan with zero findings remains a complete normalization result;
it is not a security verdict.

## Safety and partial results

- The normalizer reads JSON only and does not execute scanner or project code.
- URI encoding is decoded and separators are normalized.
- Non-file URI schemes and paths containing `..` are rejected.
- One malformed result does not discard valid sibling results.
- Skipped results produce structured warnings and `partial` status.
- If every input result is unusable, status becomes `failed`.
- A valid SARIF file with zero results is `complete`; that is not a statement
  that the project is secure.

## Gitleaks JSON mapping

Gitleaks findings map `RuleID`, `Description`, `File`, line/column fields, and
the stable fingerprint into a secret finding. `Secret` and `Match` values are
intentionally discarded so raw secret material is not copied into normalized
artifacts. A possible secret is represented as high severity with medium
confidence pending verification.

## Trivy JSON mapping

Trivy `Vulnerabilities`, `Misconfigurations`, and `Secrets` are each converted
to the same finding model. Package vulnerabilities use the vulnerability ID and
target path; misconfigurations use their cause line when available; secret
matches never copy the matched secret. A metadata-only Trivy report is a valid
complete zero-finding result.

## Usage

Internal API:

```python
from security_reviewer_v2.normalization import normalize_codeql_sarif_file

result = normalize_codeql_sarif_file("result.sarif")
payload = result.to_dict()
```

CLI after package installation for CodeQL:

```text
security-normalize-codeql result.sarif normalized.json
```

Semgrep uses the generic command with an explicit format:

```text
security-normalize-findings result.json normalized.json --scanner semgrep
```

Gitleaks and Trivy use the same command with their respective format names:

```text
security-normalize-findings result.json normalized.json --scanner gitleaks
security-normalize-findings result.json normalized.json --scanner trivy
```

From a source checkout:

```text
python -m security_reviewer_v2.normalization result.sarif normalized.json
```

To normalize every completed task from one saved orchestrator run, without
merging findings or starting scanners:

```text
python -m scripts.normalize_saved_run scans/runs/RUN_ID --output reports/normalized/RUN_ID
```

This writes one normalized JSON file per raw scanner output plus
`normalization-summary.json`. The summary reports input, normalized, and
skipped finding counts separately for each scanner. Missing raw files and
unfinished scanner tasks are visible instead of being treated as zero
findings. Trivy's input-result count refers to vulnerability, misconfiguration,
or secret entries, not the number of target files in its JSON report.

## Current limitations

- CodeQL SARIF, Semgrep JSON, Gitleaks JSON, and Trivy JSON are normalized.
- Cross-scanner merge and deduplication are implemented as a separate,
  conservative stage documented in `merge-deduplication.md`.
- Location validation is structural; source-file existence is checked later by
  context collection.
- Rule-specific remediation and true/false-positive decisions belong to the
  Security Review Agent, not normalization.

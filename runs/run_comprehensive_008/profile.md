# Project Profile Report

> This report describes project discovery and planned security scans. It is not a vulnerability report.

## Project Summary

- **Project root:** `verdict-comprehensive-lab`
- **Profiling status:** `complete`
- **Schema version:** `1.0`
- **Files discovered:** 16
- **Files skipped:** 0
- **Components:** 1
- **Git metadata:** not detected

## Inventory

| Category | Count |
|---|---:|
| configuration | 4 |
| dependency_manifest | 1 |
| source | 8 |
| test | 1 |
| unknown | 2 |

## Components

### `component-cdb4ee2aea`

- **Root:** `.`
- **Kind:** `application`
- **Confidence:** `high`
- **Inventory:** 16 files / 52316 bytes
- **Languages:** `python`
- **Frameworks:** `fastapi`
- **Dependency files:**
  - `requirements.txt` (python, parsed_constraints)

## Planned Scan Tasks

| Scanner | Type | Target | Mode | Status |
|---|---|---|---|---|
| `trivy` | `sca` | `requirements.txt` | `filesystem` | `needs_verification` |
| `gitleaks` | `secrets` | `.` | `directory` | `needs_verification` |
| `trivy` | `container_image` | `project` | `image` | `not_applicable` |
| `semgrep-ce` | `sast` | `.` | `community_registry_rules` | `needs_verification` |
| `codeql-cli` | `sast` | `.` | `standard_query_suite` | `needs_verification` |
| `trivy` | `misconfiguration` | `Dockerfile.api, Dockerfile.mock, Dockerfile.worker, compose.yaml` | `filesystem` | `needs_verification` |

### `task-45e5f84af47a`

- **Scanner:** `trivy`
- **Reasons:** `Detected a supported python dependency file.`, `SCA covers known dependency vulnerabilities; SAST does not replace it.`, `Only declared constraints may be available; resolved transitive coverage can be incomplete.`
- **Prerequisites:** `trivy_executable`, `trivy_databases`
- **Prerequisite status:** `unverified`
- **Resource class:** `standard`
- **Phase:** `scan`

### `task-510db4138e2f`

- **Scanner:** `gitleaks`
- **Reasons:** `Current-file secret scanning is useful even when Git metadata is absent.`, `Secret scanning is separate from SAST and dependency analysis.`
- **Prerequisites:** `gitleaks_executable`
- **Prerequisite status:** `unverified`
- **Resource class:** `standard`
- **Phase:** `scan`

### `task-9f00818366ac`

- **Scanner:** `trivy`
- **Reasons:** `A Dockerfile alone does not provide a container image target.`
- **Prerequisites:** `trivy_executable`, `trivy_databases`
- **Prerequisite status:** `unverified`
- **Resource class:** `standard`
- **Phase:** `scan`

### `task-dcae5d188e58`

- **Scanner:** `semgrep-ce`
- **Reasons:** `Component contains supported python source code.`, `Semgrep provides fast rule-based pattern coverage.`
- **Prerequisites:** `semgrep_executable`, `semgrep_rules`
- **Prerequisite status:** `unverified`
- **Resource class:** `standard`
- **Phase:** `scan`

### `task-e01e4c2db2dc`

- **Scanner:** `codeql-cli`
- **Reasons:** `Component contains supported python source code.`, `CodeQL adds query-based data-flow coverage complementary to Semgrep.`
- **Prerequisites:** `codeql_executable`, `language_query_pack`
- **Prerequisite status:** `unverified`
- **Resource class:** `standard`
- **Phase:** `scan`

### `task-ea7752418b98`

- **Scanner:** `trivy`
- **Reasons:** `Configuration or Infrastructure-as-Code targets were discovered.`, `Misconfiguration analysis is distinct from source and dependency scanning.`
- **Prerequisites:** `trivy_executable`, `trivy_databases`
- **Prerequisite status:** `unverified`
- **Resource class:** `standard`
- **Phase:** `scan`

## Coverage Gaps

- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile. All 4 direct dependencies are exactly pinned; their transitive dependencies are not recorded.

## Warnings

None.

## Skipped Items

None.

## Interpretation

The tasks above are a plan. The Scanner Orchestrator must still verify executables, rules, databases, and other prerequisites before execution.
A complete profile means project discovery completed within its limits; it does not mean every security scan ran or every dependency version is known.
Runtime URLs, test accounts, and application reachability are not verified by this profiler. No DAST task in this report does not mean that dynamic testing is unnecessary.

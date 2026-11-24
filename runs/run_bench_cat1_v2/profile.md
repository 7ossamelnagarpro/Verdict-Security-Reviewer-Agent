# Project Profile Report

> This report describes project discovery and planned security scans. It is not a vulnerability report.

## Project Summary

- **Project root:** `owasp-benchmark-python-cat1-v2`
- **Profiling status:** `complete`
- **Schema version:** `1.0`
- **Files discovered:** 44
- **Files skipped:** 0
- **Components:** 1
- **Git metadata:** not detected

## Inventory

| Category | Count |
|---|---:|
| configuration | 3 |
| source | 33 |
| unknown | 8 |

## Components

### `component-cdb4ee2aea`

- **Root:** `.`
- **Kind:** `application`
- **Confidence:** `medium`
- **Inventory:** 44 files / 235207 bytes
- **Languages:** `python`
- **Frameworks:** `flask`
- **Dependency files:** none detected

## Planned Scan Tasks

| Scanner | Type | Target | Mode | Status |
|---|---|---|---|---|
| `gitleaks` | `secrets` | `.` | `directory` | `needs_verification` |
| `semgrep-ce` | `sast` | `.` | `community_registry_rules` | `needs_verification` |
| `codeql-cli` | `sast` | `.` | `standard_query_suite` | `needs_verification` |

### `task-510db4138e2f`

- **Scanner:** `gitleaks`
- **Reasons:** `Current-file secret scanning is useful even when Git metadata is absent.`, `Secret scanning is separate from SAST and dependency analysis.`
- **Prerequisites:** `gitleaks_executable`
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

## Coverage Gaps

- Dependency/SCA coverage is unknown for component component-cdb4ee2aea: no supported manifest or lockfile was found.

## Warnings

- Component boundary for . is conservative because no supported manifest or workspace definition was found.

## Skipped Items

None.

## Interpretation

The tasks above are a plan. The Scanner Orchestrator must still verify executables, rules, databases, and other prerequisites before execution.
A complete profile means project discovery completed within its limits; it does not mean every security scan ran or every dependency version is known.
Runtime URLs, test accounts, and application reachability are not verified by this profiler. No DAST task in this report does not mean that dynamic testing is unnecessary.

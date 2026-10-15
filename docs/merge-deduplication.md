# Merge and Deduplication

The merge layer combines normalized scanner batches and collapses duplicate
reports conservatively. It does not use an LLM, decide true/false positives, or
discard scanner-specific evidence.

## Cross-scanner matching

Two findings from different scanners merge only when all of these conditions
hold:

1. their normalized primary file paths are the same;
2. their primary lines are within the configured tolerance (default: 0, the
   same line);
3. they share a security identity, normally a CWE.

When CWE metadata is absent, a small documented family map can recognize common
identities such as SQL injection, command injection, XSS, path traversal, SSRF,
hardcoded credentials, and unsafe deserialization. Name similarity by itself is
not enough.

Two nearby findings from the same scanner remain separate unless they have the
same reliable scanner fingerprint or the same stable finding id. Placeholder
fingerprints such as `requires login` and column-only fingerprints are ignored.
Even with an explicit wider line tolerance, each merged group must fit within
that total span and share one security identity; transitive chains cannot join
distant or unrelated vulnerabilities. The strict default favors extra reports
over silently hiding distinct issues. A broader tolerance is opt-in.

## Preserved evidence

Each `MergedFinding` contains:

- a deterministic merged id;
- one canonical finding selected by severity, confidence, and evidence richness;
- every original source finding in full;
- contributing scanner and rule ids;
- strongest severity and confidence;
- unioned CWE/category metadata;
- explicit merge reasons.

The canonical finding is a convenient primary representation, not a replacement
for the other scanner evidence.

## Coverage and incomplete inputs

`source_coverage` records every normalized batch, including a successful scanner
that returned zero findings. Partial or failed normalization creates an explicit
merge coverage gap. No input batches produces `failed`, never an empty success.

## Usage

```text
security-merge-findings merged.json codeql.normalized.json semgrep.normalized.json
```

The line tolerance can be changed explicitly:

```text
security-merge-findings merged.json input-a.json input-b.json --line-tolerance 3
```

## Current limitations

- This page describes the lossless scanner Merge layer. Candidate Triage can
  additionally correlate a Semgrep source alert with one CodeQL XSS flow when
  the same request variable appears at the cited source line. For a profiled
  Python route, it can also associate one bounded runtime response with one
  matching static sink in the same normal/error branch. Ambiguous matches stay
  separate, and every original source ID remains in the issue group.
- These narrow Triage rules are not general dataflow equivalence or a promise
  to remove every review-level duplicate. Different routes, response branches,
  or possible input sources remain separate even if a manual benchmark groups
  them under one broad case.
- The family fallback is intentionally small to avoid aggressive false merges.
- Gitleaks and Trivy finding types will require domain-specific matching rules
  after their adapters and normalizers are implemented.
- Business-logic equivalence and true-positive validation belong to later review
  stages, not deterministic deduplication.

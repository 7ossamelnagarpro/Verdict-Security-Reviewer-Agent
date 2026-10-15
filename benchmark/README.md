# Benchmark

Ground truth is kept outside the scanned target directories. Use it only after
scanning to evaluate detection quality; scanners and reviewers must not use it
as discovery input.

- `ground_truth.json`: the small vulnerable/safe source fixture.
- `security_lab_web_ground_truth.json`: Security Lab Web cases. The detailed
  scenarios and test accounts are in `security_lab_web_fixture_notes.md`.
- `owasp_benchmark_java_ground_truth.json`: OWASP Benchmark Java cases.

Scan `targets/security-lab-web`, not the repository root or `benchmark`, when
evaluating the Security Lab Web fixture. The Flask requirement is pinned for
repeatability, but `requirements.txt` is not a resolved transitive lockfile.

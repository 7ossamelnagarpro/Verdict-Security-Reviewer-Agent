# Benchmark

Ground truth is kept outside the scanned target directories. Use it only after
scanning to evaluate detection quality; scanners and reviewers must not use it
as discovery input.

- `verdict-comprehensive-ground-truth.json`: confirmed and safe-control cases
  for the comprehensive lab. Use it only after the scan.
- `verdict-comprehensive-runtime-contract.example.json`: a reviewable baseline
  contract example, not the benchmark answer key.
- `verdict-comprehensive-runtime-contract.full.example.json`: a bounded,
  reviewable full-scan example with account, business-rule and matched safe
  workflows. It contains no passwords and starts with testing authorization
  disabled. Keep it outside the scanned target and review every rule before
  enabling it; it is not a ground-truth label file.

For the comprehensive lab, use `scripts/evaluate_verdict_comprehensive.py`
after completing the review. See `docs/verdict-comprehensive-lab.md` for
its setup and interpretation limits.

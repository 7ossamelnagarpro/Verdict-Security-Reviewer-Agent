# Benchmark

Ground truth is kept outside the scanned target directories. Use it only after
scanning to evaluate detection quality; scanners and reviewers must not use it
as discovery input.

- `ground_truth.json`: the small vulnerable/safe source fixture.
- `security_lab_web_ground_truth.json`: Security Lab Web cases. The detailed
  scenarios and test accounts are in `security_lab_web_fixture_notes.md`.
- `verdict-multi-service-scenarios.json`: 18 held-out multi-service scenarios
  (16 confirmed, two candidate-only). Keep this file outside the scanned
  target and never pass it to scanner or AI inputs.
- `verdict-comprehensive-ground-truth.json`: confirmed and safe-control cases
  for the comprehensive lab. Use it only after the scan.
- `verdict-comprehensive-runtime-contract.example.json`: a reviewable baseline
  contract example, not the benchmark answer key.
- `verdict-comprehensive-runtime-contract.full.example.json`: a bounded,
  reviewable full-scan example with account, business-rule and matched safe
  workflows. It contains no passwords and starts with testing authorization
  disabled. Keep it outside the scanned target and review every rule before
  enabling it; it is not a ground-truth label file.

After a multi-service scan and final review have finished, run the evaluator
against their saved output directories:

```powershell
& .\.venv\Scripts\python.exe scripts\evaluate_verdict_multi_service.py `
  reports\SCAN_DIRECTORY --review-dir reports\REVIEW_DIRECTORY
```

It writes `evaluation.json`, `evaluation.md`, and `evaluation.html` under the
review directory's `evaluation` folder. It does not rescan or contact the app.
Detection requires an exact evidence anchor and a positive final verdict;
conflicts remain `needs_review`. Candidate-only scenarios are excluded from
the confirmed-case recall denominator. The fixture contains no labeled
negative cases, so this audit does not estimate precision or F1.

For the comprehensive lab, use `scripts/evaluate_verdict_comprehensive.py`
after completing the review. See `docs/verdict-comprehensive-lab.md` for
its setup and interpretation limits.

Scan `targets/security-lab-web`, not the repository root or `benchmark`, when
evaluating the Security Lab Web fixture. The Flask requirement is pinned for
repeatability, but `requirements.txt` is not a resolved transitive lockfile.

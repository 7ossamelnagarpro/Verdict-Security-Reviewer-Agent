# Risk Prioritization

Risk Prioritization gives every merged finding a deterministic operational
priority. It decides review order; it does not replace scanner severity, CVSS,
verification, or business-impact analysis.

No finding is removed. Every input finding receives a rank and one disposition:

- `deep_review`: selected now for detailed Security Review Agent analysis;
- `queued_for_deep_review`: qualified, but is beyond the configured Top N;
- `standard_report`: retained in the final report without expensive deep review;
- `needs_verification`: source context is missing and must be recovered or
  checked before deep review.

## Heuristic policy v1

The score is clamped to 0-100 and is the sum of visible factors:

| Factor | Points |
| --- | ---: |
| Scanner severity: critical / high / medium / low / info | 50 / 40 / 25 / 10 / 0 |
| Scanner confidence: high / medium / low | 12 / 7 / 2 |
| Known impact class | 8-18, using only the strongest recognized CWE |
| Independent support from multiple scanners | 8 |
| Scanner-provided data flow with at least two collected steps | 10 |
| Recognized external-input signal in that flow | 12 |
| Missing context package | -15 |
| Missing primary source context | -20 |

Priority bands are `critical` at 85+, `high` at 65+, `medium` at 35+, and
`low` below 35. These bands are workflow priority, deliberately separate from
the original scanner severity stored beside them.

The default deep-review threshold is 65 and the default limit is 20 findings.
Qualifying findings beyond that limit are queued, never discarded.

## Usage

After installing the project in editable mode:

```powershell
security-prioritize-findings `
  scans/merged/target-app-20261002.merged.json `
  scans/context/target-app-20261002.context.json `
  scans/prioritized/target-app-20261002.prioritized.json
```

Use `--deep-review-threshold` and `--max-deep-reviews` to apply an explicit
cost policy.

## Current limitations

- The score is an explainable triage heuristic, not a probability of exploit or
  a formal risk assessment.
- Business criticality, internet deployment, authentication boundaries, asset
  value, and production reachability are not yet profile inputs.
- External-input recognition currently uses a small, explicit token registry.
- A scanner false positive can still rank highly; the later Security Review and
  Verification stages are responsible for the verdict.
- Unrecognized CWEs receive no invented impact points.

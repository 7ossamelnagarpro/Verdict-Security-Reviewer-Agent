# CWE catalog review

Generated 2026-11-12T06:43:26Z from NVD data queried 2026-11-10T11:21:09Z and the MITRE CWE catalog 5.0 (2026-10-28).

**These are statistics, not official values. A row is unusable until a person approves it.**

## How to read this

- Sample: records where the CWE is the primary assignment (else primary+secondary), scored by `nvd@nist.gov` when at least 30 remain, newest 300.
- `stable_high`: High+Critical share >= 85%. `stable_low`: <= 15%. `insufficient_data`: fewer than 30 records. Anything else is `ambiguous`: the CWE alone does not decide the rating.
- The two thresholds are policy choices, not standards. They live in `CatalogConfig`.
- `needs_review_note`: MITRE says ALLOWED_WITH_REVIEW, so approving the row requires a written note.

## All rows

| CWE | Name | Status | Basis | n | High+Crit | Modal | Ref. vector share | Flags |
|---|---|---|---|---:|---:|---|---:|---|
| CWE-16 | - | refused_by_mitre | insufficient_data | 1 | 100% | - | 100% | name_missing, non_nvd_scores_used, small_sample, weak_cwe_assignment |
| CWE-22 | Improper Limitation of a Pathname to a Restric | draft_needs_human_review | ambiguous | 300 | 70% | - | 18% | low_vector_agreement |
| CWE-77 | Improper Neutralization of Special Elements us | draft_needs_human_review | stable_high | 300 | 96% | CRITICAL | 47% | - |
| CWE-78 | Improper Neutralization of Special Elements us | draft_needs_human_review | stable_high | 300 | 95% | HIGH | 36% | low_vector_agreement |
| CWE-79 | Improper Neutralization of Input During Web Pa | draft_needs_human_review | stable_low | 300 | 5% | MEDIUM | 40% | unstable_over_time |
| CWE-89 | Improper Neutralization of Special Elements us | draft_needs_human_review | stable_high | 300 | 97% | CRITICAL | 75% | - |
| CWE-94 | Improper Control of Generation of Code | draft_needs_human_review | stable_high | 300 | 91% | HIGH | 35% | low_vector_agreement |
| CWE-200 | Exposure of Sensitive Information to an Unauth | refused_by_mitre | ambiguous | 300 | 31% | - | 23% | low_vector_agreement |
| CWE-287 | Improper Authentication | refused_by_mitre | ambiguous | 300 | 67% | - | 26% | low_vector_agreement |
| CWE-306 | Missing Authentication for Critical Functional | draft_needs_human_review | ambiguous | 300 | 78% | - | 27% | low_vector_agreement |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorit | draft_needs_human_review | ambiguous | 300 | 65% | - | 39% | low_vector_agreement |
| CWE-328 | Use of Weak Hash | draft_needs_human_review | insufficient_data | 1 | 0% | - | 100% | non_nvd_scores_used, small_sample, weak_cwe_assignment |
| CWE-330 | Use of Insufficiently Random Values | refused_by_mitre | ambiguous | 210 | 56% | - | 19% | low_vector_agreement |
| CWE-352 | Cross-Site Request Forgery | draft_needs_human_review | ambiguous | 300 | 55% | - | 51% | - |
| CWE-434 | Unrestricted Upload of File with Dangerous Typ | draft_needs_human_review | stable_high | 300 | 93% | CRITICAL | 46% | - |
| CWE-502 | Deserialization of Untrusted Data | draft_needs_human_review | stable_high | 300 | 94% | HIGH | 42% | - |
| CWE-601 | URL Redirection to Untrusted Site | draft_needs_human_review | stable_low | 300 | 6% | MEDIUM | 81% | - |
| CWE-611 | Improper Restriction of XML External Entity Re | draft_needs_human_review | ambiguous | 300 | 69% | - | 22% | low_vector_agreement |
| CWE-639 | Authorization Bypass Through User-Controlled K | draft_needs_human_review | ambiguous | 300 | 42% | - | 13% | low_vector_agreement |
| CWE-798 | Use of Hard-coded Credentials | draft_needs_human_review | ambiguous | 300 | 83% | - | 41% | - |
| CWE-862 | Missing Authorization | draft_needs_human_review | ambiguous | 300 | 47% | - | 11% | low_vector_agreement, unstable_over_time |
| CWE-863 | Incorrect Authorization | draft_needs_human_review | ambiguous | 300 | 48% | - | 10% | low_vector_agreement, unstable_over_time |
| CWE-918 | Server-Side Request Forgery | draft_needs_human_review | ambiguous | 300 | 56% | - | 16% | low_vector_agreement |
| CWE-1321 | Improperly Controlled Modification of Object P | draft_needs_human_review | stable_high | 278 | 88% | CRITICAL | 57% | - |

## Rows by default_basis

- **stable_high** (7): CWE-77, CWE-78, CWE-89, CWE-94, CWE-434, CWE-502, CWE-1321. _the CWE alone is a reasonable High/Critical default._
- **stable_low** (2): CWE-79, CWE-601. _the CWE alone is a reasonable Medium/Low default._
- **ambiguous** (13): CWE-22, CWE-200, CWE-287, CWE-306, CWE-327, CWE-330, CWE-352, CWE-611, CWE-639, CWE-798, CWE-862, CWE-863, CWE-918. _the CWE alone does not decide; evidence-based metrics are required._
- **insufficient_data** (2): CWE-16, CWE-328. _not enough data; a human decision is needed._

## Refused by MITRE (never usable)

- CWE-16: not found in the catalog
- CWE-200: mapping usage DISCOURAGED
- CWE-287: mapping usage DISCOURAGED
- CWE-330: mapping usage DISCOURAGED

## Approving these rows requires a written note (MITRE: ALLOWED_WITH_REVIEW)

CWE-22, CWE-77, CWE-94, CWE-327, CWE-798, CWE-862, CWE-863

## Data not cached yet

CWE-90, CWE-95, CWE-269, CWE-284, CWE-338, CWE-347, CWE-359, CWE-472, CWE-532, CWE-614, CWE-640, CWE-693, CWE-841, CWE-915, CWE-939, CWE-942, CWE-1004, CWE-1021, CWE-1284

Fetch them with `python scripts/fetch_nvd_cwe_data.py` and rebuild this catalog.

## What a reviewer should check

- Do the reference vector and the rating distribution look plausible for this weakness in a typical web app?
- For `ambiguous` rows, accept that the CWE alone cannot give a rating; approving only records that you looked.
- Rows flagged `unstable_over_time`, `low_vector_agreement` or `non_nvd_scores_used` deserve a closer look.
- CVSS 4.0-only records are excluded (this catalog is CVSS 3.1).

## Approving

```
python scripts/approve_cwe_rows.py --ids CWE-89 CWE-77 --reviewer "Your Name" --note "why"
```

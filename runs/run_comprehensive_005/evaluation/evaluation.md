# Comprehensive lab · held-out scan audit

Ground truth was used only after the saved scan and review were complete.

Known-positive cases detected: **10/35** (28.6% conservative lower bound). Needs review: **15**. Not detected by exact signal: **10**.
Safe controls not assessed for specificity: **27**. Candidate-only exclusions: **1**.

Precision and F1: **not calculated** (unmatched findings and safe controls need manual adjudication).

## Scan provenance

- Target: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Scan status: `completed`
- Scanners: codeql-cli, gitleaks, semgrep-ce, trivy
- Merged findings: 63; reviewed groups: 68
- DAST required/satisfied: {'requested': True, 'satisfied': True}
- SAST required/satisfied: {'requested': True, 'satisfied': True}
- AI discovery: {'required': True, 'satisfied': True, 'status': 'partial', 'provider': 'groq', 'model': 'openai/gpt-oss-120b', 'provider_calls': 4, 'planned_targets': 20, 'inspected_targets': 20, 'failed_batches': 0, 'candidate_count': 6, 'supported_candidates': 5, 'coverage_gaps': ['2 source windows were shortened by the prompt character budget.', "23 known findings were omitted from the discovery prompt's duplicate-avoidance list.", "33 known findings were omitted from the discovery prompt's duplicate-avoidance list.", "35 known findings were omitted from the discovery prompt's duplicate-avoidance list.", '37 background coverage gaps were omitted from the discovery prompt budget.', 'A negative result means only that this probe did not observe the behavior.', 'A violation is an observed contract mismatch requiring security review.', 'Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.', 'Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.', 'Coverage applies only to declared assertions, accounts and workflows.', 'Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.', 'Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile.', 'The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.', 'merged-16678dc11308a0a16a81: primary source context is unavailable.', 'merged-17a5197f906426a224ef: primary source context is unavailable.', 'merged-19f4a13e0b2d4f7413d0: primary source context is unavailable.', 'merged-1ba9f8276fc6dae95df8: primary source context is unavailable.', 'merged-2b80ed0c48c0c70a93a4: primary source context is unavailable.', 'merged-2d4a81712313b5f2f621: primary source context is unavailable.', 'merged-38e7cf77bdf9145d2ae4: primary source context is unavailable.', 'merged-41e99a7ce6d803bedda1: primary source context is unavailable.', 'merged-50485291173e2448f7c7: primary source context is unavailable.', 'merged-553cfc223024a5e03f34: primary source context is unavailable.', 'merged-5fe9a08fc103085427f9: primary source context is unavailable.', 'merged-65c41e5a25b6337fec07: primary source context is unavailable.', 'merged-65f25bcf14fa2ab91271: primary source context is unavailable.', 'merged-7457580a7c7bb31a32cd: primary source context is unavailable.', 'merged-7c9406875347cad8b1ce: primary source context is unavailable.', 'merged-7da23d65adeef42d71a6: primary source context is unavailable.', 'merged-87e0399272a390813ea5: primary source context is unavailable.', 'merged-8946f8391fc9049cbb58: primary source context is unavailable.', 'merged-8e21db3fe42adbf58979: primary source context is unavailable.', 'merged-9b32fbabacaa9f45b768: primary source context is unavailable.', 'merged-a5ea8ca4c36bd6c25e2a: primary source context is unavailable.', 'merged-a9e9047867c909f567ad: primary source context is unavailable.', 'merged-ade7b890a037d8c82a1f: primary source context is unavailable.', 'merged-b4c1c4d005665a5249a7: primary source context is unavailable.', 'merged-bbf1646deeb18d1e95db: primary source context is unavailable.', 'merged-bdfe7542047da39c6151: primary source context is unavailable.', 'merged-cc8a9ed20905505868f0: primary source context is unavailable.', 'merged-d5c3b6b8d8dad90c4d3c: primary source context is unavailable.', 'merged-d9421dbfc4162d6dea91: primary source context is unavailable.', 'merged-da0f922505b4c0c7fed1: primary source context is unavailable.', 'merged-dd64ece99563dbbb173a: primary source context is unavailable.', 'merged-dfd8d33b4f84ccf0c23f: primary source context is unavailable.', 'merged-e683a977084f2bbcee2e: primary source context is unavailable.', 'merged-e7caea540245938b275b: primary source context is unavailable.', 'merged-ec17a70b00fa38747671: primary source context is unavailable.', 'merged-fbfa546bfd43886d2b10: primary source context is unavailable.', 'merged-fe76cc1a4803fb50214c: primary source context is unavailable.'], 'warnings': ['Discovery batch 2: AI provider JSON fallback did not match the discovery response schema; retrying with a smaller request.']}
- AI review: {'status': 'completed', 'satisfied': True, 'provider': 'groq', 'model': 'openai/gpt-oss-120b', 'review_count': 68, 'pending_ids': [], 'warnings': []}
- Endpoint coverage: {'status': 'generic_completed', 'endpoint_count': None, 'probe_count': 51, 'probed_count': 0, 'authentication': None, 'workflows': None, 'coverage_gaps': ['Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.', 'The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.', 'A negative result means only that this probe did not observe the behavior.', 'Coverage applies only to declared assertions, accounts and workflows.', 'A violation is an observed contract mismatch requiring security review.', 'Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.', 'Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.']}

## Recorded coverage gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.
- Coverage applies only to declared assertions, accounts and workflows.
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile.
- The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.
- merged-16678dc11308a0a16a81: primary source context is unavailable.
- merged-17a5197f906426a224ef: primary source context is unavailable.
- merged-19f4a13e0b2d4f7413d0: primary source context is unavailable.
- merged-1ba9f8276fc6dae95df8: primary source context is unavailable.
- merged-2b80ed0c48c0c70a93a4: primary source context is unavailable.
- merged-2d4a81712313b5f2f621: primary source context is unavailable.
- merged-38e7cf77bdf9145d2ae4: primary source context is unavailable.
- merged-41e99a7ce6d803bedda1: primary source context is unavailable.
- merged-50485291173e2448f7c7: primary source context is unavailable.
- merged-553cfc223024a5e03f34: primary source context is unavailable.
- merged-5fe9a08fc103085427f9: primary source context is unavailable.
- merged-65c41e5a25b6337fec07: primary source context is unavailable.
- merged-65f25bcf14fa2ab91271: primary source context is unavailable.
- merged-7457580a7c7bb31a32cd: primary source context is unavailable.
- merged-7c9406875347cad8b1ce: primary source context is unavailable.
- merged-7da23d65adeef42d71a6: primary source context is unavailable.
- merged-87e0399272a390813ea5: primary source context is unavailable.
- merged-8946f8391fc9049cbb58: primary source context is unavailable.
- merged-8e21db3fe42adbf58979: primary source context is unavailable.
- merged-9b32fbabacaa9f45b768: primary source context is unavailable.
- merged-a5ea8ca4c36bd6c25e2a: primary source context is unavailable.
- merged-a9e9047867c909f567ad: primary source context is unavailable.
- merged-ade7b890a037d8c82a1f: primary source context is unavailable.
- merged-b4c1c4d005665a5249a7: primary source context is unavailable.
- merged-bbf1646deeb18d1e95db: primary source context is unavailable.
- merged-bdfe7542047da39c6151: primary source context is unavailable.
- merged-cc8a9ed20905505868f0: primary source context is unavailable.
- merged-d5c3b6b8d8dad90c4d3c: primary source context is unavailable.
- merged-d9421dbfc4162d6dea91: primary source context is unavailable.
- merged-da0f922505b4c0c7fed1: primary source context is unavailable.
- merged-dd64ece99563dbbb173a: primary source context is unavailable.
- merged-dfd8d33b4f84ccf0c23f: primary source context is unavailable.
- merged-e683a977084f2bbcee2e: primary source context is unavailable.
- merged-e7caea540245938b275b: primary source context is unavailable.
- merged-ec17a70b00fa38747671: primary source context is unavailable.
- merged-fbfa546bfd43886d2b10: primary source context is unavailable.
- merged-fe76cc1a4803fb50214c: primary source context is unavailable.

## Known-positive cases

### C01 · cross_user_order — needs_review

- Location: `GET /orders/{id}`
- Severity: high
- Expected behavior / ground-truth evidence: user_a reads user_b order
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C01`
- Origin: SL01, MS04
- Exact audit signatures: `workflow.order_owner.3` at `/orders/{{order_id}}`
- Matched reviewed signals:
  - `merged-a9e9047867c909f567ad` / `merged-a9e9047867c909f567ad`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 17, 'automation_id': None, 'task_id': None} · `workflow.order_owner.3` at `/orders/{{order_id}}`; review verdict `false_positive`

### C02 · cross_user_profile — detected

- Location: `GET /profiles/{id}`
- Severity: high
- Expected behavior / ground-truth evidence: user_a reads user_b profile
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C02`
- Origin: SL02
- Exact audit signatures: `workflow.profile_owner.2` at `/profiles/{{other_id}}`
- Matched reviewed signals:
  - `merged-2b80ed0c48c0c70a93a4` / `merged-2b80ed0c48c0c70a93a4`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 29, 'automation_id': None, 'task_id': None} · `workflow.profile_owner.2` at `/profiles/{{other_id}}`; review verdict `likely_vulnerability`

### C03 · sql_injection_login — detected

- Location: `POST /auth/legacy-login`
- Severity: high
- Expected behavior / ground-truth evidence: quoted username bypasses password
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C03`
- Origin: SL03
- Exact audit signatures: `py/sql-injection` at `api/extra.py` lines 119–119
- Matched reviewed signals:
  - `merged-18f1abe978f9fdaad8e6` / `merged-18f1abe978f9fdaad8e6`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 7, 'automation_id': None, 'task_id': None} · `py/sql-injection` at `api/extra.py`; review verdict `confirmed_vulnerability`

### C04 · sql_injection_search — detected

- Location: `GET /catalog/search`
- Severity: high
- Expected behavior / ground-truth evidence: query returns unrelated item
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C04`
- Origin: SL04
- Exact audit signatures: `py/sql-injection` at `api/extra.py` lines 144–144
- Matched reviewed signals:
  - `merged-f60fee7d82fbca512208` / `merged-f60fee7d82fbca512208`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 8, 'automation_id': None, 'task_id': None} · `py/sql-injection` at `api/extra.py`; review verdict `likely_vulnerability`

### C05 · reflected_xss — detected

- Location: `GET /catalog/search`
- Severity: medium
- Expected behavior / ground-truth evidence: script markup returned unescaped
- Evidence source: browser+static; proof: `benchmark/check_comprehensive_lab.py:C05`
- Origin: SL05
- Exact audit signatures: `py/reflective-xss` at `api/extra.py` lines 145–145
- Matched reviewed signals:
  - `merged-ea527a7d7441e2b11700` / `merged-ea527a7d7441e2b11700`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 6, 'automation_id': None, 'task_id': None} · `py/reflective-xss` at `api/extra.py`; review verdict `confirmed_vulnerability`

### C06 · stored_xss — not_detected

- Location: `POST+GET /comments`
- Severity: high
- Expected behavior / ground-truth evidence: stored markup returned unescaped
- Evidence source: browser+static; proof: `benchmark/check_comprehensive_lab.py:C06`
- Origin: SL06
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C07 · admin_authorization — needs_review

- Location: `GET /admin/users`
- Severity: high
- Expected behavior / ground-truth evidence: ordinary user obtains admin listing
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C07`
- Origin: SL07, MS05
- Exact audit signatures: `workflow.admin_users.2` at `/admin/users`
- Matched reviewed signals:
  - `merged-38e7cf77bdf9145d2ae4` / `merged-38e7cf77bdf9145d2ae4`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 19, 'automation_id': None, 'task_id': None} · `workflow.admin_users.2` at `/admin/users`; review verdict `needs_more_evidence`

### C08 · path_traversal — needs_review

- Location: `GET /files?name=`
- Severity: high
- Expected behavior / ground-truth evidence: parent path reads lab-private note
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C08`
- Origin: SL08
- Exact audit signatures: `py/path-injection` at `api/extra.py` lines 212–215
- Matched reviewed signals:
  - `merged-83d97da4516adf20e20f` / `merged-83d97da4516adf20e20f`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 1, 'automation_id': None, 'task_id': None} · `py/path-injection` at `api/extra.py`; review verdict `false_positive`
  - `merged-b527b3ed30e57aac5ec5` / `merged-b527b3ed30e57aac5ec5`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 2, 'automation_id': None, 'task_id': None} · `py/path-injection` at `api/extra.py`; review verdict `false_positive`
  - `merged-f4eaf141df049c63545d` / `merged-f4eaf141df049c63545d`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 0, 'automation_id': None, 'task_id': None} · `py/path-injection` at `api/extra.py`; review verdict `false_positive`

### C10 · predictable_session — not_detected

- Location: `GET /session/whoami`
- Severity: medium
- Expected behavior / ground-truth evidence: guessed session ID impersonates admin
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C10`
- Origin: SL10
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C11 · debug_exposure — needs_review

- Location: `GET /debug/config`
- Severity: medium
- Expected behavior / ground-truth evidence: response includes lab secret
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C11`
- Origin: SL11, MS13
- Exact audit signatures: `workflow.debug_access.1` at `/debug/config`
- Matched reviewed signals:
  - `merged-e7caea540245938b275b` / `merged-e7caea540245938b275b`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 28, 'automation_id': None, 'task_id': None} · `workflow.debug_access.1` at `/debug/config`; review verdict `false_positive`

### C12 · verbose_error — not_detected

- Location: `GET /errors/query`
- Severity: medium
- Expected behavior / ground-truth evidence: database column name in error response
- Evidence source: dast; proof: `benchmark/check_comprehensive_lab.py:C12`
- Origin: SL12
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C13 · login_brute_force — not_detected

- Location: `POST /auth/login`
- Severity: medium
- Expected behavior / ground-truth evidence: correct password succeeds after repeated failures
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C13`
- Origin: SL13
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C14 · cors — detected

- Location: `GET /healthz`
- Severity: medium
- Expected behavior / ground-truth evidence: untrusted Origin is allowed
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C14`
- Origin: SL14, MS12
- Exact audit signatures: `python.fastapi.security.wildcard-cors.wildcard-cors` at `api/app.py` lines 26–26
- Matched reviewed signals:
  - `merged-70f8087c412d06924742` / `merged-70f8087c412d06924742`: {'scanner_id': 'semgrep-ce', 'scanner_name': 'Semgrep', 'scanner_version': '1.178.0', 'run_index': 0, 'result_index': 0, 'automation_id': None, 'task_id': None} · `python.fastapi.security.wildcard-cors.wildcard-cors` at `api/app.py`; review verdict `likely_vulnerability`

### C15 · unsafe_upload — not_detected

- Location: `POST+GET /uploads`
- Severity: high
- Expected behavior / ground-truth evidence: HTML uploaded and served as text/html
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C15`
- Origin: SL15
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C16 · unsigned_token — not_detected

- Location: `api/app.py:principal`
- Severity: high
- Expected behavior / ground-truth evidence: tampered role is accepted
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C16`
- Origin: MS01
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C17 · refresh_token — not_detected

- Location: `POST /auth/refresh`
- Severity: high
- Expected behavior / ground-truth evidence: tampered bearer token obtains fresh token
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C17`
- Origin: MS02
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C18 · mass_assignment — needs_review

- Location: `POST /orders`
- Severity: high
- Expected behavior / ground-truth evidence: client controls owner, price and status
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C18`
- Origin: MS03
- Exact audit signatures: `workflow.owner_assignment.2` at `/orders`; `workflow.order_initial_state.1` at `/orders`; `workflow.negative_price.1` at `/orders`
- Matched reviewed signals:
  - `merged-1ba9f8276fc6dae95df8` / `merged-1ba9f8276fc6dae95df8`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 26, 'automation_id': None, 'task_id': None} · `workflow.owner_assignment.2` at `/orders`; review verdict `likely_vulnerability`
  - `merged-2d4a81712313b5f2f621` / `merged-2d4a81712313b5f2f621`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 25, 'automation_id': None, 'task_id': None} · `workflow.order_initial_state.1` at `/orders`; review verdict `needs_more_evidence`
  - `merged-8946f8391fc9049cbb58` / `merged-8946f8391fc9049cbb58`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 24, 'automation_id': None, 'task_id': None} · `workflow.negative_price.1` at `/orders`; review verdict `likely_vulnerability`

### C19 · invoice_authorization — needs_review

- Location: `GET /invoices/{id}`
- Severity: high
- Expected behavior / ground-truth evidence: user_b reads user_a invoice
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C19`
- Origin: MS11
- Exact audit signatures: `workflow.invoice_owner.3` at `/invoices/{{invoice_id}}`
- Matched reviewed signals:
  - `merged-d5c3b6b8d8dad90c4d3c` / `merged-d5c3b6b8d8dad90c4d3c`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 18, 'automation_id': None, 'task_id': None} · `workflow.invoice_owner.3` at `/invoices/{{invoice_id}}`; review verdict `false_positive`

### C20 · price_tampering — needs_review

- Location: `POST /orders`
- Severity: high
- Expected behavior / ground-truth evidence: client sets item price below catalog value
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C20`
- Origin: MS06
- Exact audit signatures: `workflow.price_catalog.1` at `/orders`
- Matched reviewed signals:
  - `merged-cc8a9ed20905505868f0` / `merged-cc8a9ed20905505868f0`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 31, 'automation_id': None, 'task_id': None} · `workflow.price_catalog.1` at `/orders`; review verdict `false_positive`

### C21 · coupon_tampering — detected

- Location: `POST /orders/{id}/apply-coupon`
- Severity: medium
- Expected behavior / ground-truth evidence: client overrides coupon percentage
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C21`
- Origin: MS07
- Exact audit signatures: `workflow.coupon_bounds.2` at `/orders/{{order_id}}/apply-coupon`
- Matched reviewed signals:
  - `merged-7da23d65adeef42d71a6` / `merged-7da23d65adeef42d71a6`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 23, 'automation_id': None, 'task_id': None} · `workflow.coupon_bounds.2` at `/orders/{{order_id}}/apply-coupon`; review verdict `likely_vulnerability`

### C22 · payment_replay — needs_review

- Location: `POST /orders/{id}/pay`
- Severity: high
- Expected behavior / ground-truth evidence: second payment accepted
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C22`
- Origin: MS08
- Exact audit signatures: `workflow.payment_replay.3` at `/orders/{{order_id}}/pay`
- Matched reviewed signals:
  - `merged-dd64ece99563dbbb173a` / `merged-dd64ece99563dbbb173a`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 21, 'automation_id': None, 'task_id': None} · `workflow.payment_replay.3` at `/orders/{{order_id}}/pay`; review verdict `false_positive`

### C23 · order_state — needs_review

- Location: `POST /orders/{id}/cancel`
- Severity: medium
- Expected behavior / ground-truth evidence: paid order cancelled
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C23`
- Origin: MS09
- Exact audit signatures: `workflow.paid_cancel.3` at `/orders/{{order_id}}/cancel`
- Matched reviewed signals:
  - `merged-e683a977084f2bbcee2e` / `merged-e683a977084f2bbcee2e`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 22, 'automation_id': None, 'task_id': None} · `workflow.paid_cancel.3` at `/orders/{{order_id}}/cancel`; review verdict `false_positive`

### C24 · excessive_data — needs_review

- Location: `GET /me`
- Severity: medium
- Expected behavior / ground-truth evidence: SSN returned to client
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C24`
- Origin: MS10
- Exact audit signatures: `workflow.excessive_data.1` at `/me`
- Matched reviewed signals:
  - `merged-65c41e5a25b6337fec07` / `merged-65c41e5a25b6337fec07`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 30, 'automation_id': None, 'task_id': None} · `workflow.excessive_data.1` at `/me`; review verdict `false_positive`

### C25 · worker_trust — needs_review

- Location: `POST /jobs`
- Severity: high
- Expected behavior / ground-truth evidence: ordinary user assigns admin worker role
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C25`
- Origin: MS14
- Exact audit signatures: `workflow.worker_role.1` at `/jobs`
- Matched reviewed signals:
  - `merged-a5ea8ca4c36bd6c25e2a` / `merged-a5ea8ca4c36bd6c25e2a`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 27, 'automation_id': None, 'task_id': None} · `workflow.worker_role.1` at `/jobs`; review verdict `false_positive`

### C26 · webhook_destination — needs_review

- Location: `POST /webhooks`
- Severity: high
- Expected behavior / ground-truth evidence: different internal host passes substring path validation and receives callback
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C26`
- Origin: MS15
- Exact audit signatures: `workflow.webhook_destination.1` at `/webhooks`
- Matched reviewed signals:
  - `merged-65f25bcf14fa2ab91271` / `merged-65f25bcf14fa2ab91271`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 32, 'automation_id': None, 'task_id': None} · `workflow.webhook_destination.1` at `/webhooks`; review verdict `needs_more_evidence`

### C27 · sensitive_logging — detected

- Location: `api/app.py:_login`
- Severity: medium
- Expected behavior / ground-truth evidence: fake application secret appears in container log
- Evidence source: static+log; proof: `benchmark/check_comprehensive_lab.py:C27`
- Origin: MS16
- Exact audit signatures: `py/clear-text-logging-sensitive-data` at `api/app.py` lines 137–137
- Matched reviewed signals:
  - `merged-3202e1e1074cfd44b9bf` / `merged-3202e1e1074cfd44b9bf`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 9, 'automation_id': None, 'task_id': None} · `py/clear-text-logging-sensitive-data` at `api/app.py`; review verdict `confirmed_vulnerability`

### C28 · weak_config — not_detected

- Location: `compose.yaml`
- Severity: low
- Expected behavior / ground-truth evidence: fixed lab secret in Compose environment
- Evidence source: static+config; proof: `benchmark/check_comprehensive_lab.py:C28`
- Origin: MS17
- Exact audit signatures: none defined
- Matched reviewed signals: none

### C29 · cross_service_trust — not_detected

- Location: `webhook -> worker -> mock`
- Severity: high
- Expected behavior / ground-truth evidence: user-provided admin role reaches worker result
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C29`
- Origin: MS18
- Exact audit signatures: none defined
- Matched reviewed signals: none

### N01 · reset_replay — needs_review

- Location: `POST /auth/reset/confirm`
- Severity: high
- Expected behavior / ground-truth evidence: same reset token changes password twice
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N01`
- Origin: not recorded
- Exact audit signatures: `workflow.reset_replay.3` at `/auth/reset/confirm`
- Matched reviewed signals:
  - `merged-d9421dbfc4162d6dea91` / `merged-d9421dbfc4162d6dea91`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 35, 'automation_id': None, 'task_id': None} · `workflow.reset_replay.3` at `/auth/reset/confirm`; review verdict `needs_more_evidence`

### N02 · open_redirect — detected

- Location: `GET /auth/continue`
- Severity: medium
- Expected behavior / ground-truth evidence: external Location is accepted
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:N02`
- Origin: not recorded
- Exact audit signatures: `py/url-redirection` at `api/extra.py` lines 617–617
- Matched reviewed signals:
  - `merged-51bf51abe866bf8d3d67` / `merged-51bf51abe866bf8d3d67`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 10, 'automation_id': None, 'task_id': None} · `py/url-redirection` at `api/extra.py`; review verdict `likely_vulnerability`

### N03 · webhook_signature — detected

- Location: `POST /integrations/hook`
- Severity: high
- Expected behavior / ground-truth evidence: unsigned event is accepted
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N03`
- Origin: not recorded
- Exact audit signatures: `workflow.unsigned_hook.1` at `/integrations/hook`
- Matched reviewed signals:
  - `merged-8e21db3fe42adbf58979` / `merged-8e21db3fe42adbf58979`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 34, 'automation_id': None, 'task_id': None} · `workflow.unsigned_hook.1` at `/integrations/hook`; review verdict `likely_vulnerability`

### N04 · nested_resource_access — needs_review

- Location: `GET /orders/{id}/notes/{note_id}`
- Severity: high
- Expected behavior / ground-truth evidence: note does not belong to path order
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N04`
- Origin: not recorded
- Exact audit signatures: `workflow.nested_note.1` at `/orders/1/notes/2`
- Matched reviewed signals:
  - `merged-b4c1c4d005665a5249a7` / `merged-b4c1c4d005665a5249a7`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 33, 'automation_id': None, 'task_id': None} · `workflow.nested_note.1` at `/orders/1/notes/2`; review verdict `false_positive`

### N05 · stale_role — needs_review

- Location: `GET /admin/token-report`
- Severity: high
- Expected behavior / ground-truth evidence: demoted admin retains token role
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N05`
- Origin: not recorded
- Exact audit signatures: `workflow.stale_role.3` at `/admin/token-report`
- Matched reviewed signals:
  - `merged-da0f922505b4c0c7fed1` / `merged-da0f922505b4c0c7fed1`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 36, 'automation_id': None, 'task_id': None} · `workflow.stale_role.3` at `/admin/token-report`; review verdict `false_positive`

### N06 · cookie_flags — not_detected

- Location: `GET /session/start`
- Severity: medium
- Expected behavior / ground-truth evidence: session cookie omits HttpOnly
- Evidence source: dast; proof: `benchmark/check_comprehensive_lab.py:N06`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### N07 · security_headers — detected

- Location: `GET /view`
- Severity: low
- Expected behavior / ground-truth evidence: CSP absent on HTML page
- Evidence source: dast; proof: `benchmark/check_comprehensive_lab.py:N07`
- Origin: not recorded
- Exact audit signatures: `zap.10038` at `/view`
- Matched reviewed signals:
  - `merged-dfd8d33b4f84ccf0c23f` / `merged-dfd8d33b4f84ccf0c23f`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 39, 'automation_id': None, 'task_id': None} · `zap.10038` at `/view`; review verdict `likely_vulnerability`

## Safe controls — specificity not assessed

### S01 · order_ownership — safe_control_not_assessed

- Location: `GET /orders/{id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: cross-user read denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S01`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S02 · profile_ownership — safe_control_not_assessed

- Location: `GET /profiles/{id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: cross-user read denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S02`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S03 · parameterized_login — safe_control_not_assessed

- Location: `POST /auth/checked-login`
- Severity: not assigned
- Expected behavior / ground-truth evidence: SQL payload denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S03`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S04 · parameterized_search — safe_control_not_assessed

- Location: `GET /catalog/query`
- Severity: not assigned
- Expected behavior / ground-truth evidence: SQL payload does not broaden results
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S04`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S05 · escaped_reflection — safe_control_not_assessed

- Location: `GET /catalog/query`
- Severity: not assigned
- Expected behavior / ground-truth evidence: script markup escaped
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S05`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S06 · escaped_comments — safe_control_not_assessed

- Location: `GET /forum/messages`
- Severity: not assigned
- Expected behavior / ground-truth evidence: stored markup escaped
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S06`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S07 · admin_role — safe_control_not_assessed

- Location: `GET /admin/audit`
- Severity: not assigned
- Expected behavior / ground-truth evidence: ordinary user denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S07`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S08 · file_boundary — safe_control_not_assessed

- Location: `GET /files/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: parent path denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S08`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S09 · generic_errors — safe_control_not_assessed

- Location: `GET /errors/checked`
- Severity: not assigned
- Expected behavior / ground-truth evidence: database details hidden
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S09`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S10 · login_lockout — safe_control_not_assessed

- Location: `POST /auth/limited-login`
- Severity: not assigned
- Expected behavior / ground-truth evidence: repeated failures lock account
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S10`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S11 · document_upload — safe_control_not_assessed

- Location: `POST /documents`
- Severity: not assigned
- Expected behavior / ground-truth evidence: HTML upload rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S11`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S12 · server_order_fields — safe_control_not_assessed

- Location: `POST /orders/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: owner, price and state set by server
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S12`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S13 · server_coupon — safe_control_not_assessed

- Location: `POST /orders/{id}/verified-coupon`
- Severity: not assigned
- Expected behavior / ground-truth evidence: client percentage ignored
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S13`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S14 · payment_idempotency — safe_control_not_assessed

- Location: `POST /orders/{id}/verified-pay`
- Severity: not assigned
- Expected behavior / ground-truth evidence: second payment denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S14`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S15 · order_transition — safe_control_not_assessed

- Location: `POST /orders/{id}/verified-cancel`
- Severity: not assigned
- Expected behavior / ground-truth evidence: paid order cannot cancel
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S15`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S16 · invoice_ownership — safe_control_not_assessed

- Location: `GET /invoices/{id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: cross-user read denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S16`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S17 · minimal_identity — safe_control_not_assessed

- Location: `GET /me/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: SSN omitted
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S17`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S18 · worker_identity — safe_control_not_assessed

- Location: `POST /jobs/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: worker role set from account
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S18`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S19 · webhook_host — safe_control_not_assessed

- Location: `POST /webhooks/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: alternate internal host rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S19`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S20 · nested_resource_binding — safe_control_not_assessed

- Location: `GET /orders/{id}/notes/{note_id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: note must match order ID
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S20`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S21 · local_redirect — safe_control_not_assessed

- Location: `GET /auth/continue/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: external Location rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S21`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S22 · hook_hmac — safe_control_not_assessed

- Location: `POST /integrations/hook-verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: unsigned event rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S22`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S23 · cookie_flags — safe_control_not_assessed

- Location: `GET /session/secure-start`
- Severity: not assigned
- Expected behavior / ground-truth evidence: HttpOnly, Secure and SameSite present
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S23`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S24 · response_headers — safe_control_not_assessed

- Location: `GET /status/secure`
- Severity: not assigned
- Expected behavior / ground-truth evidence: CSP present
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S24`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S25 · current_admin_role — safe_control_not_assessed

- Location: `GET /admin/current-report`
- Severity: not assigned
- Expected behavior / ground-truth evidence: ordinary user denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S25`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S26 · nested_ownership — safe_control_not_assessed

- Location: `GET /orders/{id}/notes/{note_id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: foreign owner denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S26`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S27 · single_use_reset — safe_control_not_assessed

- Location: `POST /auth/reset/verified-confirm`
- Severity: not assigned
- Expected behavior / ground-truth evidence: second use rejected; token delivery remains lab-only
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S27`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

## Excluded candidate

### C09 · command_injection — excluded

- Location: `not implemented`
- Severity: not_assigned
- Expected behavior / ground-truth evidence: Arbitrary shell execution was excluded from the Docker-only safety boundary
- Evidence source: not_testable; proof: `not recorded`
- Origin: SL09
- Exact audit signatures: none defined
- Matched reviewed signals: none

## Limits

- Held-out comparison of one saved run; the benchmark was not supplied to scanning or AI.
- Only exact source signatures and positive reviewed verdicts count as detected.
- A case without a defined signature remains not detected by this strict audit, even if a broader finding might deserve manual review.
- Needs-review evidence is not counted as detected; not-detected does not mean safe.
- Safe controls need a separate specificity audit; precision and F1 are not estimated.
- One case may generate several observations, so issue-group counts are not vulnerability counts.

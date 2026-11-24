# Comprehensive lab · held-out scan audit

Ground truth was used only after the saved scan and review were complete.

Known-positive cases detected: **24/35** (68.6% conservative lower bound), of which **0** rest only on the Penetration Agent's own exploitation_confirmed result (no independent scanner/workflow signature). Needs review: **1**. Not detected by exact signal: **10**.
Safe controls: **22 clean**, **5 flagged**, 0 not assessable (specificity 81.5%).
Positive findings: **84** — matched to a known case 26, on a known case's endpoint (unverified) 22, on a safe control 5, outside the answer key's scope 18, unlabeled 13.
Precision bounds (not a point estimate): labeled-only 83.9% (optimistic), in-scope lower bound 39.4%, strict lower bound 30.9% (pessimistic).
10 of 10 not-detected cases have no signature at all, so this audit could never credit them.

## Scan provenance

- Target: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Scan status: `partial`
- Scanners: codeql-cli, gitleaks, semgrep-ce, trivy
- Merged findings: 63; reviewed groups: 96
- DAST required/satisfied: {'requested': True, 'satisfied': True}
- SAST required/satisfied: {'requested': True, 'satisfied': True}
- AI discovery: {'required': True, 'satisfied': True, 'status': 'completed', 'provider': 'groq', 'model': 'openai/gpt-oss-120b', 'provider_calls': 15, 'planned_targets': 71, 'inspected_targets': 71, 'failed_batches': 0, 'candidate_count': 46, 'supported_candidates': 40, 'coverage_gaps': [], 'warnings': ['3 empty source file(s) were skipped; they contain nothing to review.', 'The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.', "Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.", 'Discovery batch 2: AI provider request failed with HTTP 413 (rate_limit_exceeded); request too large: 8530 tokens requested, limit 8000; retrying with a smaller request.', 'Discovery batch 5: AI provider request failed (timeout): no response within 120s after the request was sent; the response was lost after the request was sent; retrying with a smaller request (1 of 2).', '3 duplicate AI candidate(s) were merged into 3 stronger one(s): ai-b25b877a4040d288 <- ai-6b2866191f7959f6; ai-45373d0b0f185864 <- ai-118e8dd460abde2d; ai-36ac21e5893e61d7 <- ai-31b627b904cf366b']}
- AI review: {'status': 'partial', 'satisfied': False, 'provider': 'groq', 'model': 'openai/gpt-oss-120b', 'review_count': 10, 'pending_ids': ['merged-4c6d36222f8ebf7f1f68', 'merged-15dd977d52312c30635a', 'merged-d58491aad5be35b48233', 'merged-c5b44871f1955b338344', 'merged-0bcbb317cfb96e7d5505', 'merged-3913d8f00a297cfbf214', 'merged-56ecc860a2c48330a29a', 'merged-69b75a0aa3f8fc9fb800', 'merged-efce9419c25ced2d8892', 'merged-4a2311054cdc2bfe890d', 'merged-a9a9a0b97f19f8bf52ae', 'merged-6e468e09eab3ca889e3d', 'merged-81ff94e895c53dbc2029', 'merged-d716d5afb61da294d286', 'merged-f5fff899f9294177dc70', 'merged-19f4a13e0b2d4f7413d0', 'merged-87e0399272a390813ea5', 'merged-916563c278b3e6b62930', 'merged-bbf1646deeb18d1e95db', 'merged-b98074828fe298997980', 'merged-54b1ddb055358b3579a2', 'merged-b7e0b624f8cddd0a9e8c', 'merged-c0dcf73e8d7a6a1fbf02', 'merged-218d6fc43fe64432894a', 'merged-5a7c783c30e11426af42', 'merged-767d54ff7a729b156819', 'merged-d0789be823f0fd7fa381', 'merged-0f6fe31b81367808748c', 'merged-fe4ca713f11faf9b96d6', 'merged-7ed325c02dd6cf8227d2', 'merged-ccc894903304aa8847bd', 'merged-1bcb1da144dffdcf3fd8', 'merged-18063ba27bc289f53c8a', 'merged-4ae7658c2abfbf689e2b', 'merged-a4473061f97f0a366678', 'merged-cad468186f9fd0b4e99b', 'merged-8cdc677a9810b317840f', 'merged-70f8087c412d06924742', 'merged-9c6fcf61fc01168b15e2', 'merged-51bf51abe866bf8d3d67', 'merged-f41fd10802e7c4dd22bb', 'merged-58377a692410b6446bbd', 'merged-0de42012099941c48e01', 'merged-df83daf10f817c7aa965', 'merged-051697f9b8567d596874', 'merged-3503f2dec888990b31f2', 'merged-74bb99c1ff3b5ed1fea8', 'merged-8a5f28db4eebc517239e', 'merged-8ce42d9c8b52a95b109d', 'merged-e76230cbef200116e4ae', 'merged-f15e42abb7b2acd921f1', 'merged-7711056ee3332442a201', 'merged-c150b78349615dd9bc2d', 'ai-a15d98c2851e9a64', 'ai-0b9106bba642ef41', 'ai-d3c8ae68a75d8b90', 'ai-eb33fbefb86b87d2', 'ai-e8ec08f388c6f0b9', 'ai-b25b877a4040d288', 'ai-fdb73441313bbd62', 'ai-0c59bf73442d38e5', 'ai-5d4c30816d85620a', 'ai-f0dce5b04fc274c8', 'ai-45373d0b0f185864', 'ai-4ecfe3ddba19f11e', 'ai-977152a429a6be98', 'ai-1c96865ffd2139a6', 'ai-b3070a1396939b3b', 'ai-1ae6ed5ebe1063cc', 'ai-a4a245f41e176a0f', 'ai-af22fc4057174aa4', 'ai-382002314551c090', 'ai-1b3aac1279d7c1b7', 'ai-9725570d578c01b3', 'ai-ad853b8088744ec9', 'ai-36ac21e5893e61d7', 'ai-53836baec7106573', 'ai-486324d802ecdfbd', 'ai-29b6f398101e94dc', 'ai-6322be0c6e12b177', 'ai-40fd1ed3ab05cb13', 'ai-60d3cec6938c5b6f', 'ai-9a06c902b7e9dd83', 'ai-e358d3ef59fad665', 'ai-d3f22b49b98909b6', 'ai-9f1624303e929d51'], 'warnings': ['Review provider stopped: AI provider request failed (connection_closed): connection closed while reading the response (ConnectionResetError)']}
- Endpoint coverage: {'status': 'generic_completed', 'endpoint_count': None, 'probe_count': 51, 'probed_count': 0, 'authentication': None, 'workflows': None, 'coverage_gaps': ['Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.', 'This baseline phase only makes bounded HTTP GET observations; browser crawling, ZAP and account workflows are separate phases, reported only when they ran.', 'A negative result means only that this probe did not observe the behavior.', 'Coverage applies only to declared assertions, accounts and workflows.', 'A violation is an observed contract mismatch requiring security review.', 'Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.', 'Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.']}

## Recorded coverage gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.
- Coverage applies only to declared assertions, accounts and workflows.
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile. All 4 direct dependencies are exactly pinned; their transitive dependencies are not recorded.
- This baseline phase only makes bounded HTTP GET observations; browser crawling, ZAP and account workflows are separate phases, reported only when they ran.

## Known-positive cases

### C01 · cross_user_order — detected

- Location: `GET /orders/{id}`
- Severity: high
- Expected behavior / ground-truth evidence: user_a reads user_b order
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C01`
- Origin: SL01, MS04
- Exact audit signatures: `workflow.order_owner.3` at `/orders/{{order_id}}`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Potential IDOR on order retrieval (CWE-639) — GET /orders/{} · origin: ai_discovery · group ai-b3070a1396939b3b
- Matched reviewed signals:
  - `merged-fe4ca713f11faf9b96d6` / `merged-fe4ca713f11faf9b96d6`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 17, 'automation_id': None, 'task_id': None} · `workflow.order_owner.3` at `/orders/{{order_id}}`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/orders/{order_id}`; review verdict `confirmed_vulnerability`

### C02 · cross_user_profile — detected

- Location: `GET /profiles/{id}`
- Severity: high
- Expected behavior / ground-truth evidence: user_a reads user_b profile
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C02`
- Origin: SL02
- Exact audit signatures: `workflow.profile_owner.2` at `/profiles/{{other_id}}`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Insecure Direct Object Reference (CWE-639) in profile endpoint — GET /profiles/{} · origin: ai_discovery · group ai-6322be0c6e12b177
- Matched reviewed signals:
  - `merged-18063ba27bc289f53c8a` / `merged-18063ba27bc289f53c8a`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 29, 'automation_id': None, 'task_id': None} · `workflow.profile_owner.2` at `/profiles/{{other_id}}`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/profiles/{profile_id}`; review verdict `confirmed_vulnerability`

### C03 · sql_injection_login — detected

- Location: `POST /auth/legacy-login`
- Severity: high
- Expected behavior / ground-truth evidence: quoted username bypasses password
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C03`
- Origin: SL03
- Exact audit signatures: `py/sql-injection` at `api/extra.py` lines 119–119
- Detection origin: static
- Matched reviewed signals:
  - `merged-18f1abe978f9fdaad8e6` / `merged-18f1abe978f9fdaad8e6`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 7, 'automation_id': None, 'task_id': None} · `py/sql-injection` at `api/extra.py`; review verdict `confirmed_vulnerability`

### C04 · sql_injection_search — detected

- Location: `GET /catalog/search`
- Severity: high
- Expected behavior / ground-truth evidence: query returns unrelated item
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C04`
- Origin: SL04
- Exact audit signatures: `py/sql-injection` at `api/extra.py` lines 144–144
- Detection origin: static
- Other findings on this endpoint (not counted as detections):
  - confirmed vulnerability · high · Reflected server-side cross-site scripting — GET /catalog/search · origin: static · group merged-ea527a7d7441e2b11700
- Matched reviewed signals:
  - `merged-f60fee7d82fbca512208` / `merged-f60fee7d82fbca512208`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 8, 'automation_id': None, 'task_id': None} · `py/sql-injection` at `api/extra.py`; review verdict `likely_vulnerability`

### C05 · reflected_xss — detected

- Location: `GET /catalog/search`
- Severity: medium
- Expected behavior / ground-truth evidence: script markup returned unescaped
- Evidence source: browser+static; proof: `benchmark/check_comprehensive_lab.py:C05`
- Origin: SL05
- Exact audit signatures: `py/reflective-xss` at `api/extra.py` lines 145–145
- Detection origin: static
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · SQL query built from user-controlled sources — GET /catalog/search · origin: static · group merged-f60fee7d82fbca512208
- Matched reviewed signals:
  - `merged-ea527a7d7441e2b11700` / `merged-ea527a7d7441e2b11700`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 6, 'automation_id': None, 'task_id': None} · `py/reflective-xss` at `api/extra.py`; review verdict `confirmed_vulnerability`

### C06 · stored_xss — not_detected

- Location: `POST+GET /comments`
- Severity: high
- Expected behavior / ground-truth evidence: stored markup returned unescaped
- Evidence source: browser+static; proof: `benchmark/check_comprehensive_lab.py:C06`
- Origin: SL06
- Exact audit signatures: none defined
- Other findings on this endpoint (not counted as detections):
  - confirmed vulnerability · medium · Missing Anti-clickjacking Header — GET /comments · origin: dynamic · group merged-6e468e09eab3ca889e3d
  - likely vulnerability · medium · Content Security Policy (CSP) Header Not Set — GET /comments · origin: dynamic · group merged-81ff94e895c53dbc2029
  - likely vulnerability · low · X-Content-Type-Options Header Missing — GET /comments · origin: dynamic · group merged-d716d5afb61da294d286
  - likely vulnerability · high · Stored cross-site scripting (CWE-79) in /comments endpoint — GET /comments · origin: ai_discovery · group ai-9f1624303e929d51
- Matched reviewed signals: none

### C07 · admin_authorization — detected

- Location: `GET /admin/users`
- Severity: high
- Expected behavior / ground-truth evidence: ordinary user obtains admin listing
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C07`
- Origin: SL07, MS05
- Exact audit signatures: `workflow.admin_users.2` at `/admin/users`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Missing authorization check for admin users endpoint (CWE-284) — GET /admin/users · origin: ai_discovery · group ai-977152a429a6be98
- Matched reviewed signals:
  - `merged-c5b44871f1955b338344` / `merged-c5b44871f1955b338344`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 19, 'automation_id': None, 'task_id': None} · `workflow.admin_users.2` at `/admin/users`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/admin/users`; review verdict `confirmed_vulnerability`

### C08 · path_traversal — needs_review

- Location: `GET /files?name=`
- Severity: high
- Expected behavior / ground-truth evidence: parent path reads lab-private note
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C08`
- Origin: SL08
- Exact audit signatures: `py/path-injection` at `api/extra.py` lines 212–215
- Detection origin: static
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Potential path traversal via unverified file name (CWE-22) — GET /files · origin: ai_discovery · group ai-d3c8ae68a75d8b90
  - likely vulnerability · medium · Unauthenticated file download endpoint (CWE-284) — GET /files · origin: ai_discovery · group ai-4ecfe3ddba19f11e
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

### C11 · debug_exposure — detected

- Location: `GET /debug/config`
- Severity: medium
- Expected behavior / ground-truth evidence: response includes lab secret
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C11`
- Origin: SL11, MS13
- Exact audit signatures: `workflow.debug_access.1` at `/debug/config`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Sensitive debug configuration exposure (CWE-200) — GET /debug/config · origin: ai_discovery · group ai-a4a245f41e176a0f
- Matched reviewed signals:
  - `merged-f5fff899f9294177dc70` / `merged-f5fff899f9294177dc70`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 28, 'automation_id': None, 'task_id': None} · `workflow.debug_access.1` at `/debug/config`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/debug/config`; review verdict `confirmed_vulnerability`

### C12 · verbose_error — not_detected

- Location: `GET /errors/query`
- Severity: medium
- Expected behavior / ground-truth evidence: database column name in error response
- Evidence source: dast; proof: `benchmark/check_comprehensive_lab.py:C12`
- Origin: SL12
- Exact audit signatures: none defined
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Potential information disclosure via exception details (CWE-209) — GET /errors/query · origin: ai_discovery · group ai-45373d0b0f185864
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
- Detection origin: static
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · low · Missing Content-Security-Policy header — GET /healthz · origin: dynamic · group merged-19f4a13e0b2d4f7413d0
  - likely vulnerability · low · Missing clickjacking protection header — GET /healthz · origin: dynamic · group merged-87e0399272a390813ea5
  - likely vulnerability · low · X-Content-Type-Options Header Missing — GET /healthz · origin: dynamic · group merged-916563c278b3e6b62930
  - likely vulnerability · low · Missing X-Content-Type-Options header on /healthz endpoint — GET /healthz · origin: dynamic · group merged-bbf1646deeb18d1e95db
  - likely vulnerability · low · Potential missing authentication on health check (CWE-306) — GET /healthz · origin: ai_discovery · group ai-af22fc4057174aa4
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
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Potential insecure token handling in refresh endpoint (CWE-613) — POST /auth/refresh · origin: ai_discovery · group ai-e8ec08f388c6f0b9
- Matched reviewed signals: none

### C18 · mass_assignment — detected

- Location: `POST /orders`
- Severity: high
- Expected behavior / ground-truth evidence: client controls owner, price and status
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C18`
- Origin: MS03
- Exact audit signatures: `workflow.owner_assignment.2` at `/orders`; `workflow.order_initial_state.1` at `/orders`; `workflow.negative_price.1` at `/orders`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Catalog price must be set by the server — POST /orders · origin: dynamic · group merged-218d6fc43fe64432894a
  - likely vulnerability · high · Missing ownership check on order creation (CWE-639) — POST /orders · origin: ai_discovery · group ai-fdb73441313bbd62
- Matched reviewed signals:
  - `merged-5a7c783c30e11426af42` / `merged-5a7c783c30e11426af42`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 25, 'automation_id': None, 'task_id': None} · `workflow.order_initial_state.1` at `/orders`; review verdict `confirmed_vulnerability`
  - `merged-767d54ff7a729b156819` / `merged-767d54ff7a729b156819`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 24, 'automation_id': None, 'task_id': None} · `workflow.negative_price.1` at `/orders`; review verdict `likely_vulnerability`
  - `merged-d0789be823f0fd7fa381` / `merged-d0789be823f0fd7fa381`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 26, 'automation_id': None, 'task_id': None} · `workflow.owner_assignment.2` at `/orders`; review verdict `likely_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/orders`; review verdict `confirmed_vulnerability`

### C19 · invoice_authorization — detected

- Location: `GET /invoices/{id}`
- Severity: high
- Expected behavior / ground-truth evidence: user_b reads user_a invoice
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C19`
- Origin: MS11
- Exact audit signatures: `workflow.invoice_owner.3` at `/invoices/{{invoice_id}}`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Potential IDOR on invoice retrieval (CWE-639) — GET /invoices/{} · origin: ai_discovery · group ai-1ae6ed5ebe1063cc
- Matched reviewed signals:
  - `merged-54b1ddb055358b3579a2` / `merged-54b1ddb055358b3579a2`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 18, 'automation_id': None, 'task_id': None} · `workflow.invoice_owner.3` at `/invoices/{{invoice_id}}`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/invoices/{invoice_id}`; review verdict `confirmed_vulnerability`

### C20 · price_tampering — detected

- Location: `POST /orders`
- Severity: high
- Expected behavior / ground-truth evidence: client sets item price below catalog value
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C20`
- Origin: MS06
- Exact audit signatures: `workflow.price_catalog.1` at `/orders`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - confirmed vulnerability · high · Order creation endpoint allows arbitrary initial status — POST /orders · origin: dynamic · group merged-5a7c783c30e11426af42
  - likely vulnerability · high · Negative order prices are not rejected — POST /orders · origin: dynamic · group merged-767d54ff7a729b156819
  - likely vulnerability · high · Missing ownership check when creating orders — POST /orders · origin: dynamic · group merged-d0789be823f0fd7fa381
  - likely vulnerability · high · Missing ownership check on order creation (CWE-639) — POST /orders · origin: ai_discovery · group ai-fdb73441313bbd62
- Matched reviewed signals:
  - `merged-218d6fc43fe64432894a` / `merged-218d6fc43fe64432894a`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 31, 'automation_id': None, 'task_id': None} · `workflow.price_catalog.1` at `/orders`; review verdict `likely_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/orders`; review verdict `confirmed_vulnerability`

### C21 · coupon_tampering — detected

- Location: `POST /orders/{id}/apply-coupon`
- Severity: medium
- Expected behavior / ground-truth evidence: client overrides coupon percentage
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C21`
- Origin: MS07
- Exact audit signatures: `workflow.coupon_bounds.2` at `/orders/{{order_id}}/apply-coupon`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Arbitrary discount value bypass via request body (CWE-353) — POST /orders/{}/apply-coupon · origin: ai_discovery · group ai-b25b877a4040d288
  - likely vulnerability · high · Missing ownership/role check on coupon application (CWE-639) — POST /orders/{}/apply-coupon · origin: ai_discovery · group ai-0c59bf73442d38e5
- Matched reviewed signals:
  - `merged-7ed325c02dd6cf8227d2` / `merged-7ed325c02dd6cf8227d2`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 23, 'automation_id': None, 'task_id': None} · `workflow.coupon_bounds.2` at `/orders/{{order_id}}/apply-coupon`; review verdict `likely_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/orders/{order_id}/apply-coupon`; review verdict `confirmed_vulnerability`

### C22 · payment_replay — detected

- Location: `POST /orders/{id}/pay`
- Severity: high
- Expected behavior / ground-truth evidence: second payment accepted
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C22`
- Origin: MS08
- Exact audit signatures: `workflow.payment_replay.3` at `/orders/{{order_id}}/pay`
- Detection origin: dynamic
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Missing ownership check on order payment (CWE-639) — POST /orders/{}/pay · origin: ai_discovery · group ai-5d4c30816d85620a
- Matched reviewed signals:
  - `merged-1bcb1da144dffdcf3fd8` / `merged-1bcb1da144dffdcf3fd8`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 21, 'automation_id': None, 'task_id': None} · `workflow.payment_replay.3` at `/orders/{{order_id}}/pay`; review verdict `confirmed_vulnerability`

### C23 · order_state — detected

- Location: `POST /orders/{id}/cancel`
- Severity: medium
- Expected behavior / ground-truth evidence: paid order cancelled
- Evidence source: workflow; proof: `benchmark/check_comprehensive_lab.py:C23`
- Origin: MS09
- Exact audit signatures: `workflow.paid_cancel.3` at `/orders/{{order_id}}/cancel`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Missing ownership check on order cancellation (CWE-639) — POST /orders/{}/cancel · origin: ai_discovery · group ai-f0dce5b04fc274c8
- Matched reviewed signals:
  - `merged-ccc894903304aa8847bd` / `merged-ccc894903304aa8847bd`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 22, 'automation_id': None, 'task_id': None} · `workflow.paid_cancel.3` at `/orders/{{order_id}}/cancel`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/orders/{order_id}/cancel`; review verdict `confirmed_vulnerability`

### C24 · excessive_data — detected

- Location: `GET /me`
- Severity: medium
- Expected behavior / ground-truth evidence: SSN returned to client
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:C24`
- Origin: MS10
- Exact audit signatures: `workflow.excessive_data.1` at `/me`
- Detection origin: dynamic
- Matched reviewed signals:
  - `merged-c0dcf73e8d7a6a1fbf02` / `merged-c0dcf73e8d7a6a1fbf02`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 30, 'automation_id': None, 'task_id': None} · `workflow.excessive_data.1` at `/me`; review verdict `likely_vulnerability`

### C25 · worker_trust — detected

- Location: `POST /jobs`
- Severity: high
- Expected behavior / ground-truth evidence: ordinary user assigns admin worker role
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C25`
- Origin: MS14
- Exact audit signatures: `workflow.worker_role.1` at `/jobs`
- Detection origin: dynamic
- Matched reviewed signals:
  - `merged-b7e0b624f8cddd0a9e8c` / `merged-b7e0b624f8cddd0a9e8c`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 27, 'automation_id': None, 'task_id': None} · `workflow.worker_role.1` at `/jobs`; review verdict `likely_vulnerability`

### C26 · webhook_destination — detected

- Location: `POST /webhooks`
- Severity: high
- Expected behavior / ground-truth evidence: different internal host passes substring path validation and receives callback
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:C26`
- Origin: MS15
- Exact audit signatures: `workflow.webhook_destination.1` at `/webhooks`
- Detection origin: dynamic
- Matched reviewed signals:
  - `merged-8cdc677a9810b317840f` / `merged-8cdc677a9810b317840f`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 32, 'automation_id': None, 'task_id': None} · `workflow.webhook_destination.1` at `/webhooks`; review verdict `confirmed_vulnerability`

### C27 · sensitive_logging — detected

- Location: `api/app.py:_login`
- Severity: medium
- Expected behavior / ground-truth evidence: fake application secret appears in container log
- Evidence source: static+log; proof: `benchmark/check_comprehensive_lab.py:C27`
- Origin: MS16
- Exact audit signatures: `py/clear-text-logging-sensitive-data` at `api/app.py` lines 137–137
- Detection origin: static
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

### N01 · reset_replay — detected

- Location: `POST /auth/reset/confirm`
- Severity: high
- Expected behavior / ground-truth evidence: same reset token changes password twice
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N01`
- Origin: not recorded
- Exact audit signatures: `workflow.reset_replay.3` at `/auth/reset/confirm`
- Detection origin: dynamic
- Matched reviewed signals:
  - `merged-efce9419c25ced2d8892` / `merged-efce9419c25ced2d8892`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 35, 'automation_id': None, 'task_id': None} · `workflow.reset_replay.3` at `/auth/reset/confirm`; review verdict `likely_vulnerability`

### N02 · open_redirect — detected

- Location: `GET /auth/continue`
- Severity: medium
- Expected behavior / ground-truth evidence: external Location is accepted
- Evidence source: dast+static; proof: `benchmark/check_comprehensive_lab.py:N02`
- Origin: not recorded
- Exact audit signatures: `py/url-redirection` at `api/extra.py` lines 617–617
- Detection origin: static
- Matched reviewed signals:
  - `merged-51bf51abe866bf8d3d67` / `merged-51bf51abe866bf8d3d67`: {'scanner_id': 'codeql-cli', 'scanner_name': 'CodeQL', 'scanner_version': '2.27.2', 'run_index': 0, 'result_index': 10, 'automation_id': None, 'task_id': None} · `py/url-redirection` at `api/extra.py`; review verdict `confirmed_vulnerability`

### N03 · webhook_signature — detected

- Location: `POST /integrations/hook`
- Severity: high
- Expected behavior / ground-truth evidence: unsigned event is accepted
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N03`
- Origin: not recorded
- Exact audit signatures: `workflow.unsigned_hook.1` at `/integrations/hook`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · low · Unauthenticated data ingestion endpoint (trust boundary violation) — POST /integrations/hook · origin: ai_discovery · group ai-d3f22b49b98909b6
- Matched reviewed signals:
  - `merged-b98074828fe298997980` / `merged-b98074828fe298997980`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 34, 'automation_id': None, 'task_id': None} · `workflow.unsigned_hook.1` at `/integrations/hook`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/integrations/hook`; review verdict `confirmed_vulnerability`

### N04 · nested_resource_access — detected

- Location: `GET /orders/{id}/notes/{note_id}`
- Severity: high
- Expected behavior / ground-truth evidence: note does not belong to path order
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N04`
- Origin: not recorded
- Exact audit signatures: `workflow.nested_note.1` at `/orders/1/notes/2`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Insecure Direct Object Reference (IDOR) in notes endpoint — GET /orders/{}/notes/{} · origin: ai_discovery · group ai-60d3cec6938c5b6f
- Matched reviewed signals:
  - `merged-0f6fe31b81367808748c` / `merged-0f6fe31b81367808748c`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 33, 'automation_id': None, 'task_id': None} · `workflow.nested_note.1` at `/orders/1/notes/2`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/orders/{order_id}/notes/{note_id}`; review verdict `confirmed_vulnerability`

### N05 · stale_role — detected

- Location: `GET /admin/token-report`
- Severity: high
- Expected behavior / ground-truth evidence: demoted admin retains token role
- Evidence source: workflow+static; proof: `benchmark/check_comprehensive_lab.py:N05`
- Origin: not recorded
- Exact audit signatures: `workflow.stale_role.3` at `/admin/token-report`
- Detection origin: dynamic, penetration_agent
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Missing token validation before admin token report (CWE-287) — GET /admin/token-report · origin: ai_discovery · group ai-29b6f398101e94dc
- Matched reviewed signals:
  - `merged-d58491aad5be35b48233` / `merged-d58491aad5be35b48233`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 36, 'automation_id': None, 'task_id': None} · `workflow.stale_role.3` at `/admin/token-report`; review verdict `confirmed_vulnerability`
  - `None` / `None`: unknown scanner · `None` at `/admin/token-report`; review verdict `confirmed_vulnerability`

### N06 · cookie_flags — not_detected

- Location: `GET /session/start`
- Severity: medium
- Expected behavior / ground-truth evidence: session cookie omits HttpOnly
- Evidence source: dast; proof: `benchmark/check_comprehensive_lab.py:N06`
- Origin: not recorded
- Exact audit signatures: none defined
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · high · Predictable session identifier (CWE-330) — GET /session/start · origin: ai_discovery · group ai-36ac21e5893e61d7
- Matched reviewed signals: none

### N07 · security_headers — detected

- Location: `GET /view`
- Severity: low
- Expected behavior / ground-truth evidence: CSP absent on HTML page
- Evidence source: dast; proof: `benchmark/check_comprehensive_lab.py:N07`
- Origin: not recorded
- Exact audit signatures: `zap.10038` at `/view`
- Detection origin: dynamic
- Other findings on this endpoint (not counted as detections):
  - likely vulnerability · medium · Missing Anti-clickjacking Header — GET /view · origin: dynamic · group merged-4ae7658c2abfbf689e2b
  - likely vulnerability · low · X-Content-Type-Options Header Missing — GET /view · origin: dynamic · group merged-cad468186f9fd0b4e99b
- Matched reviewed signals:
  - `merged-a4473061f97f0a366678` / `merged-a4473061f97f0a366678`: {'scanner_id': 'web-runtime', 'scanner_name': 'Bounded Web Runtime Checks', 'scanner_version': '1.0', 'run_index': 0, 'result_index': 39, 'automation_id': None, 'task_id': None} · `zap.10038` at `/view`; review verdict `likely_vulnerability`

## Safe controls — specificity audit

### S01 · order_ownership — safe_control_flagged

- Location: `GET /orders/{id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: cross-user read denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S01`
- Origin: not recorded
- Exact audit signatures: none defined
- Flagged by group(s): ai-9a06c902b7e9dd83
- Matched reviewed signals: none

### S02 · profile_ownership — safe_control_flagged

- Location: `GET /profiles/{id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: cross-user read denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S02`
- Origin: not recorded
- Exact audit signatures: none defined
- Flagged by group(s): ai-a15d98c2851e9a64
- Matched reviewed signals: none

### S03 · parameterized_login — safe_control_clean

- Location: `POST /auth/checked-login`
- Severity: not assigned
- Expected behavior / ground-truth evidence: SQL payload denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S03`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S04 · parameterized_search — safe_control_clean

- Location: `GET /catalog/query`
- Severity: not assigned
- Expected behavior / ground-truth evidence: SQL payload does not broaden results
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S04`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S05 · escaped_reflection — safe_control_clean

- Location: `GET /catalog/query`
- Severity: not assigned
- Expected behavior / ground-truth evidence: script markup escaped
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S05`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S06 · escaped_comments — safe_control_clean

- Location: `GET /forum/messages`
- Severity: not assigned
- Expected behavior / ground-truth evidence: stored markup escaped
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S06`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S07 · admin_role — safe_control_flagged

- Location: `GET /admin/audit`
- Severity: not assigned
- Expected behavior / ground-truth evidence: ordinary user denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S07`
- Origin: not recorded
- Exact audit signatures: none defined
- Flagged by group(s): ai-0b9106bba642ef41
- Matched reviewed signals: none

### S08 · file_boundary — safe_control_clean

- Location: `GET /files/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: parent path denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S08`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S09 · generic_errors — safe_control_clean

- Location: `GET /errors/checked`
- Severity: not assigned
- Expected behavior / ground-truth evidence: database details hidden
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S09`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S10 · login_lockout — safe_control_clean

- Location: `POST /auth/limited-login`
- Severity: not assigned
- Expected behavior / ground-truth evidence: repeated failures lock account
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S10`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S11 · document_upload — safe_control_flagged

- Location: `POST /documents`
- Severity: not assigned
- Expected behavior / ground-truth evidence: HTML upload rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S11`
- Origin: not recorded
- Exact audit signatures: none defined
- Flagged by group(s): ai-1b3aac1279d7c1b7
- Matched reviewed signals: none

### S12 · server_order_fields — safe_control_clean

- Location: `POST /orders/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: owner, price and state set by server
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S12`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S13 · server_coupon — safe_control_clean

- Location: `POST /orders/{id}/verified-coupon`
- Severity: not assigned
- Expected behavior / ground-truth evidence: client percentage ignored
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S13`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S14 · payment_idempotency — safe_control_flagged

- Location: `POST /orders/{id}/verified-pay`
- Severity: not assigned
- Expected behavior / ground-truth evidence: second payment denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S14`
- Origin: not recorded
- Exact audit signatures: none defined
- Flagged by group(s): ai-53836baec7106573
- Matched reviewed signals: none

### S15 · order_transition — safe_control_clean

- Location: `POST /orders/{id}/verified-cancel`
- Severity: not assigned
- Expected behavior / ground-truth evidence: paid order cannot cancel
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S15`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S16 · invoice_ownership — safe_control_clean

- Location: `GET /invoices/{id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: cross-user read denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S16`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S17 · minimal_identity — safe_control_clean

- Location: `GET /me/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: SSN omitted
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S17`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S18 · worker_identity — safe_control_clean

- Location: `POST /jobs/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: worker role set from account
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S18`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S19 · webhook_host — safe_control_clean

- Location: `POST /webhooks/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: alternate internal host rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S19`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S20 · nested_resource_binding — safe_control_clean

- Location: `GET /orders/{id}/notes/{note_id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: note must match order ID
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S20`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S21 · local_redirect — safe_control_clean

- Location: `GET /auth/continue/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: external Location rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S21`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S22 · hook_hmac — safe_control_clean

- Location: `POST /integrations/hook-verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: unsigned event rejected
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S22`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S23 · cookie_flags — safe_control_clean

- Location: `GET /session/secure-start`
- Severity: not assigned
- Expected behavior / ground-truth evidence: HttpOnly, Secure and SameSite present
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S23`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S24 · response_headers — safe_control_clean

- Location: `GET /status/secure`
- Severity: not assigned
- Expected behavior / ground-truth evidence: CSP present
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S24`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S25 · current_admin_role — safe_control_clean

- Location: `GET /admin/current-report`
- Severity: not assigned
- Expected behavior / ground-truth evidence: ordinary user denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S25`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S26 · nested_ownership — safe_control_clean

- Location: `GET /orders/{id}/notes/{note_id}/verified`
- Severity: not assigned
- Expected behavior / ground-truth evidence: foreign owner denied
- Evidence source: not recorded; proof: `benchmark/check_comprehensive_lab.py:S26`
- Origin: not recorded
- Exact audit signatures: none defined
- Matched reviewed signals: none

### S27 · single_use_reset — safe_control_clean

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

## Detections by origin (static / dynamic)

- dynamic + penetration_agent: 12 case(s)
- static: 6 case(s)
- dynamic: 6 case(s)

## Verdict calibration (how each outcome class was judged)

- matched: confirmed vulnerability 16, likely vulnerability 10, needs more evidence 0, false positive 3
- known endpoint: confirmed vulnerability 0, likely vulnerability 22, needs more evidence 0, false positive 0
- safe control: confirmed vulnerability 0, likely vulnerability 5, needs more evidence 0, false positive 4
- outside scope: confirmed vulnerability 6, likely vulnerability 12, needs more evidence 1, false positive 0
- unlabeled: confirmed vulnerability 1, likely vulnerability 12, needs more evidence 1, false positive 3

## Cases the strict audit cannot score (no signature defined)

- C06
- C10
- C12
- C13
- C15
- C16
- C17
- C28
- C29
- N06

## AI discovery on endpoints of undetected cases (issue class not verified)

- C06
- C08
- C12
- C17
- N06

## Adjudication queue — positive findings the key cannot label

- confirmed vulnerability · high · Job listing requires admin role — GET /admin/jobs · origin: dynamic · group merged-15dd977d52312c30635a
- likely vulnerability · low · Missing Content-Security-Policy header — GET /healthz · origin: dynamic · group merged-19f4a13e0b2d4f7413d0 · near known case C14
- likely vulnerability · low · Missing clickjacking protection header — GET /healthz · origin: dynamic · group merged-87e0399272a390813ea5 · near known case C14
- likely vulnerability · low · X-Content-Type-Options Header Missing — GET /healthz · origin: dynamic · group merged-916563c278b3e6b62930 · near known case C14
- likely vulnerability · low · Missing X-Content-Type-Options header on /healthz endpoint — GET /healthz · origin: dynamic · group merged-bbf1646deeb18d1e95db · near known case C14
- likely vulnerability · low · Dynamic Urllib Use Detected — no route resolved · origin: static · group merged-7711056ee3332442a201
- likely vulnerability · low · Dynamic Urllib Use Detected — no route resolved · origin: static · group merged-c150b78349615dd9bc2d
- likely vulnerability · medium · Potential path traversal via unverified file name (CWE-22) — GET /files · origin: ai_discovery · group ai-d3c8ae68a75d8b90 · near known case C08
- likely vulnerability · low · Missing CSRF protection on state‑changing endpoint — POST /auth/register · origin: ai_discovery · group ai-eb33fbefb86b87d2
- likely vulnerability · medium · Potential insecure token handling in refresh endpoint (CWE-613) — POST /auth/refresh · origin: ai_discovery · group ai-e8ec08f388c6f0b9 · near known case C17
- likely vulnerability · medium · Arbitrary discount value bypass via request body (CWE-353) — POST /orders/{}/apply-coupon · origin: ai_discovery · group ai-b25b877a4040d288 · near known case C21
- likely vulnerability · high · Missing ownership check on order creation (CWE-639) — POST /orders · origin: ai_discovery · group ai-fdb73441313bbd62 · near known case C18, C20
- likely vulnerability · high · Missing ownership/role check on coupon application (CWE-639) — POST /orders/{}/apply-coupon · origin: ai_discovery · group ai-0c59bf73442d38e5 · near known case C21
- likely vulnerability · high · Missing ownership check on order payment (CWE-639) — POST /orders/{}/pay · origin: ai_discovery · group ai-5d4c30816d85620a · near known case C22
- likely vulnerability · high · Missing ownership check on order cancellation (CWE-639) — POST /orders/{}/cancel · origin: ai_discovery · group ai-f0dce5b04fc274c8 · near known case C23
- likely vulnerability · medium · Potential information disclosure via exception details (CWE-209) — GET /errors/query · origin: ai_discovery · group ai-45373d0b0f185864 · near known case C12
- likely vulnerability · medium · Unauthenticated file download endpoint (CWE-284) — GET /files · origin: ai_discovery · group ai-4ecfe3ddba19f11e · near known case C08
- likely vulnerability · high · Missing authorization check for admin users endpoint (CWE-284) — GET /admin/users · origin: ai_discovery · group ai-977152a429a6be98 · near known case C07
- likely vulnerability · high · Missing authorization check for admin jobs endpoint (CWE-284) — GET /admin/jobs · origin: ai_discovery · group ai-1c96865ffd2139a6
- likely vulnerability · medium · Potential IDOR on order retrieval (CWE-639) — GET /orders/{} · origin: ai_discovery · group ai-b3070a1396939b3b · near known case C01
- likely vulnerability · medium · Potential IDOR on invoice retrieval (CWE-639) — GET /invoices/{} · origin: ai_discovery · group ai-1ae6ed5ebe1063cc · near known case C19
- likely vulnerability · medium · Sensitive debug configuration exposure (CWE-200) — GET /debug/config · origin: ai_discovery · group ai-a4a245f41e176a0f · near known case C11
- likely vulnerability · low · Potential missing authentication on health check (CWE-306) — GET /healthz · origin: ai_discovery · group ai-af22fc4057174aa4
- likely vulnerability · medium · Cookie set without Secure flag (CWE-614) — POST /auth/form-login · origin: ai_discovery · group ai-382002314551c090
- likely vulnerability · medium · User enumeration via password reset request (CWE-203) — POST /auth/reset/request · origin: ai_discovery · group ai-9725570d578c01b3
- likely vulnerability · medium · User enumeration via verified password reset request (CWE-203) — POST /auth/reset/verified-request · origin: ai_discovery · group ai-ad853b8088744ec9
- likely vulnerability · high · Predictable session identifier (CWE-330) — GET /session/start · origin: ai_discovery · group ai-36ac21e5893e61d7
- likely vulnerability · medium · Missing expiration for password reset tokens (CWE-613) — POST /auth/reset/request · origin: ai_discovery · group ai-486324d802ecdfbd
- likely vulnerability · high · Missing token validation before admin token report (CWE-287) — GET /admin/token-report · origin: ai_discovery · group ai-29b6f398101e94dc · near known case N05
- likely vulnerability · high · Insecure Direct Object Reference (CWE-639) in profile endpoint — GET /profiles/{} · origin: ai_discovery · group ai-6322be0c6e12b177 · near known case C02
- likely vulnerability · medium · Missing Authorization Check (CWE-862) — GET /admin/overview · origin: ai_discovery · group ai-40fd1ed3ab05cb13
- likely vulnerability · high · Insecure Direct Object Reference (IDOR) in notes endpoint — GET /orders/{}/notes/{} · origin: ai_discovery · group ai-60d3cec6938c5b6f · near known case N04
- likely vulnerability · medium · Insecure Direct Object Reference (IDOR) on file upload retrieval — GET /uploads/{} · origin: ai_discovery · group ai-e358d3ef59fad665
- likely vulnerability · low · Unauthenticated data ingestion endpoint (trust boundary violation) — POST /integrations/hook · origin: ai_discovery · group ai-d3f22b49b98909b6 · near known case N03
- likely vulnerability · high · Stored cross-site scripting (CWE-79) in /comments endpoint — GET /comments · origin: ai_discovery · group ai-9f1624303e929d51 · near known case C06

## Safe-control hits — positive findings on a safe control's route

- likely vulnerability · high · Potential IDOR in profile verification endpoint (CWE-639) — GET /profiles/{}/verified · origin: ai_discovery · group ai-a15d98c2851e9a64
- likely vulnerability · high · Missing admin role verification on audit endpoint (CWE-284) — GET /admin/audit · origin: ai_discovery · group ai-0b9106bba642ef41
- likely vulnerability · medium · Potential IDOR in document upload endpoint (CWE-639) — POST /documents · origin: ai_discovery · group ai-1b3aac1279d7c1b7
- likely vulnerability · high · Potential IDOR in verified payment endpoint (CWE-639) — POST /orders/{}/verified-pay · origin: ai_discovery · group ai-53836baec7106573
- likely vulnerability · high · Potential IDOR in order verification endpoint — GET /orders/{}/verified · origin: ai_discovery · group ai-9a06c902b7e9dd83

## Outside the answer key's scope (dependency advisories, header/cookie hardening)

- likely vulnerability · low · X-Content-Type-Options Header Missing — GET / · origin: dynamic · group merged-4c6d36222f8ebf7f1f68
- likely vulnerability · low · Cookie No HttpOnly Flag — POST /auth/form-login · origin: dynamic · group merged-0bcbb317cfb96e7d5505
- likely vulnerability · low · X-Content-Type-Options Header Missing — POST /auth/form-login · origin: dynamic · group merged-3913d8f00a297cfbf214
- likely vulnerability · medium · Missing Anti-clickjacking Header — POST /auth/form-login · origin: dynamic · group merged-56ecc860a2c48330a29a
- confirmed vulnerability · medium · Content Security Policy (CSP) Header Not Set — GET /catalog/query · origin: dynamic · group merged-4a2311054cdc2bfe890d
- likely vulnerability · medium · Missing Anti-clickjacking Header — GET /catalog/query · origin: dynamic · group merged-a9a9a0b97f19f8bf52ae
- confirmed vulnerability · medium · Missing Anti-clickjacking Header — GET /comments · origin: dynamic · group merged-6e468e09eab3ca889e3d
- likely vulnerability · medium · Content Security Policy (CSP) Header Not Set — GET /comments · origin: dynamic · group merged-81ff94e895c53dbc2029
- likely vulnerability · low · X-Content-Type-Options Header Missing — GET /comments · origin: dynamic · group merged-d716d5afb61da294d286
- likely vulnerability · medium · Missing Anti-clickjacking Header — GET /view · origin: dynamic · group merged-4ae7658c2abfbf689e2b
- likely vulnerability · low · X-Content-Type-Options Header Missing — GET /view · origin: dynamic · group merged-cad468186f9fd0b4e99b
- confirmed vulnerability · high · python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies — no route resolved · origin: static · group merged-051697f9b8567d596874
- confirmed vulnerability · high · python-multipart: Denial of Service via excessive multipart part headers — no route resolved · origin: static · group merged-3503f2dec888990b31f2
- likely vulnerability · low · python-multipart: Information disclosure due to parser differential in form data handling — no route resolved · origin: static · group merged-74bb99c1ff3b5ed1fea8
- confirmed vulnerability · medium · python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests — no route resolved · origin: static · group merged-8a5f28db4eebc517239e
- confirmed vulnerability · high · python-multipart: Arbitrary file write via path traversal vulnerability — no route resolved · origin: static · group merged-8ce42d9c8b52a95b109d
- likely vulnerability · low · multipart: Python-Multipart: Information disclosure via header parsing discrepancy — no route resolved · origin: static · group merged-e76230cbef200116e4ae
- likely vulnerability · low · python-multipart: Python-Multipart: Negative Content-Length in parse_form buffers the entire body in memory — no route resolved · origin: static · group merged-f15e42abb7b2acd921f1

## AI discovery cost

- provider_calls: 15
- batches: 11
- retry_count: 3
- rate_limit_wait_seconds: 461.5150654970007
- wall_seconds: 550.131
- total_time: 53.293276516
- total_tokens: 70983
- duplicate_candidates_merged: 3

## Limits

- Held-out comparison of one saved run; the benchmark was not supplied to scanning or AI.
- Only exact source signatures and positive reviewed verdicts count as detected, OR the Penetration Agent independently reaching exploitation_confirmed on that exact endpoint (see summary.detected_via_penetration_agent for how many of the detected cases rest on that second path rather than a scanner/workflow signature).
- A case without a defined signature remains not detected by this strict audit, even if a broader finding might deserve manual review.
- Needs-review evidence is not counted as detected; not-detected does not mean safe.
- One case may generate several observations, so issue-group counts are not vulnerability counts.
- Safe-control and precision figures place findings on routes using the lab's source code. A positive finding on a safe control's route is a false-positive signal that still needs a human check that it is the same issue class.
- Precision is reported only as bounds, never as a point estimate. precision_on_labeled counts only the findings the key can label (matches against safe-control hits, so it is optimistic); precision_lower_bound treats every other positive finding as wrong (pessimistic); precision_lower_bound_in_scope first sets aside dependency advisories and header/cookie hardening alerts, which the answer key does not cover. Positive findings that match no case are an adjudication queue, because the answer key is not exhaustive.
- AI-discovery candidates are never counted as detections here; one on a known endpoint is listed for adjudication, because its issue class is not verified against the case.
- A clean safe control means no positive finding of its issue class landed on its route; it does not prove the scan exercised that route, so read specificity together with the recorded endpoint coverage.
- Cases with no defined signature cannot be credited by this audit at all, whatever the scan found.

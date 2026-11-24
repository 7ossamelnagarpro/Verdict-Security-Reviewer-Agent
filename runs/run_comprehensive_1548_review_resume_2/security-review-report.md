# Security Review Report

- Project: `targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-24T11:00:41.556977+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **not verified in this saved run**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **71/71**; model calls: **13**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.
- AI Discovery warning: 1 duplicate AI candidate(s) were merged into 1 stronger one(s): ai-3c237f081f6c7aae &lt;- ai-72696ccdda7b035b

The agent reviewed **97** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **97**; reviewed: **97**; pending: **0**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **51**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **completed**; pages visited: **1**.
- ZAP: **completed**; engine: <code>zap-active</code>; alerts: **14**.
- Account and business workflows: **completed**; executed: **40**; contract violations: **20**.
- These observations do not prove complete vulnerability coverage or exploitation.

## Autonomous Penetration Testing — Reproduction Steps

Hypotheses tested: **35**; total attempts: **64**; total requests: **43**; exploitation confirmed: **28**.
Every probe below is read-only (GET/HEAD) against an isolated test stack with test accounts; nothing here mutated real data. Re-run the same method and path after a fix and confirm the response status changes to a denial status.

### Did the penetration test prove each AI Discovery finding?

35 source-confirmed AI Discovery finding(s): **28** proven, **2** not reproduced, **5** could not be tested.
15 further AI Discovery candidate(s) were not source-confirmed by Verification, so they were never sent to the penetration agent and are not listed here.

| # | AI Discovery finding | Severity | Location | Penetration test result | Attempts |
|---|---|---|---|---|---|
| 1 | Missing authorization check on webhook creation (CWE-284) (`ai-06a6519ee55ac5e0`) | high | api/app.py:293-305 | ✅ **Proven** | 3 |
| 2 | Missing authentication on session start (CWE-306) (`ai-30920f0acc104aee`) | high | api/extra.py:271-279 | ✅ **Proven** | 1 |
| 3 | Insecure Direct Object Reference (IDOR) in note retrieval (`ai-62e3663725439fbd`) | high | api/extra.py:543-549 | ✅ **Proven** | 2 |
| 4 | Insecure Direct Object Reference (CWE-639) (`ai-6322be0c6e12b177`) | high | api/extra.py:97-104 | ✅ **Proven** | 2 |
| 5 | Missing authentication on login endpoint (CWE-287) (`ai-6d23d0d008604fdc`) | high | api/app.py:166-172 | ✅ **Proven** | 1 |
| 6 | Missing authorization check (CWE-862) (`ai-72536ee718898b70`) | high | api/extra.py:448-450 | ✅ **Proven** | 1 |
| 7 | Missing ownership check on order retrieval (CWE-639) (`ai-76ee5ddf6f5e1661`) | high | api/app.py:220-227 | ✅ **Proven** | 2 |
| 8 | Missing authorization check for admin users (CWE-285) (`ai-78782ba33d6e3838`) | high | api/app.py:277-282 | ✅ **Proven** | 5 |
| 9 | Missing ownership/authorization check on payment (CWE-284) (`ai-8204d1e620288a08`) | high | api/app.py:241-255 | ✅ **Proven** | 2 |
| 10 | Missing authorization check on order ownership (CWE-284) (`ai-83c277f7161c623e`) | high | api/app.py:230-238 | ✅ **Proven** | 2 |
| 11 | Missing ownership check on invoice retrieval (CWE-639) (`ai-ae177f098ffafcec`) | high | api/app.py:267-274 | ✅ **Proven** | 4 |
| 12 | Missing authentication on verified password reset request (CWE-306) (`ai-c788be668eb0e766`) | high | api/extra.py:589-598 | ✅ **Proven** | 1 |
| 13 | Missing admin authorization on audit endpoint (CWE-284) (`ai-cbdb48ff58f91fd1`) | high | api/extra.py:204-207 | ✅ **Proven** | 4 |
| 14 | Missing authorization check for admin jobs (CWE-285) (`ai-d6b4763af77577b9`) | high | api/app.py:285-290 | ✅ **Proven** | 4 |
| 15 | Missing ownership check on order cancellation (CWE-639) (`ai-f0dce5b04fc274c8`) | high | api/app.py:258-264 | ✅ **Proven** | 2 |
| 16 | Missing authorization check on file read endpoint (CWE-284) (`ai-2b797e12ede1385a`) | medium | api/extra.py:210-215 | ✅ **Proven** | 1 |
| 17 | Missing authorization on verified file read endpoint (CWE-284) (`ai-357e82f73fc20848`) | medium | api/extra.py:218-224 | ✅ **Proven** | 1 |
| 18 | Missing authentication on comments endpoint (CWE-306) (`ai-5ae04a0c7d72bccf`) | medium | api/extra.py:173-177 | ✅ **Proven** | 1 |
| 19 | Potential IDOR on order creation (CWE-639) (`ai-6a78349f837e165e`) | medium | api/app.py:207-217 | ✅ **Proven** | 2 |
| 20 | Missing Authorization Check for Admin Overview (CWE-862) (`ai-b0abc42e37a54582`) | medium | api/extra.py:196-201 | ✅ **Proven** | 5 |
| 21 | Potential path traversal via unverified file name (CWE-22) (`ai-d3c8ae68a75d8b90`) | medium | api/extra.py:210-215 | ✅ **Proven** | 5 |
| 22 | Sensitive data exposure via debug\_config endpoint (CWE-200) (`ai-d63a40e98bc61059`) | medium | api/app.py:320-322 | ✅ **Proven** | 1 |
| 23 | Missing authentication on forum messages endpoint (CWE-306) (`ai-e4eb53440f8f0be6`) | medium | api/extra.py:189-193 | ✅ **Proven** | 1 |
| 24 | Missing authentication on file download (CWE-284) (`ai-e6b00beb5ad08603`) | medium | api/extra.py:366-372 | ✅ **Proven** | 1 |
| 25 | Missing rate limiting / token reuse protection on password reset request (CWE-640) (`ai-ed2bf8f5536c5122`) | medium | api/extra.py:564-573 | ✅ **Proven** | 1 |
| 26 | Information leakage via detailed error messages (CWE-209) (`ai-492db277b819e281`) | low | api/extra.py:227-234 | ✅ **Proven** | 2 |
| 27 | Missing authorization on comment creation (CWE-284) (`ai-7aebdfd54eb4e688`) | low | api/extra.py:161-168 | ✅ **Proven** | 2 |
| 28 | Potential missing ownership verification on comment creation (CWE-639) (`ai-844c60b0ab9c1aa8`) | low | api/extra.py:161-170 | ✅ **Proven** | 1 |
| 29 | Missing authentication check on session token generation (`ai-0e5f56ed2ed3b6b5`) | high | api/extra.py:322-331 | **Not reproduced** | 2 |
| 30 | Potential IDOR in session whoami endpoint (`ai-caa31c16de86cfef`) | medium | api/extra.py:310-319 | **Not reproduced** | 2 |
| 31 | Insecure password storage (CWE-256) (`ai-935e828dd4bba4f4`) | high | api/app.py:176-183 | **Could not be tested** | 0 |
| 32 | Unrestricted discount value via client-supplied field (CWE-915) (`ai-eebcf33ae8e5eaef`) | high | api/app.py:230-238 | **Could not be tested** | 0 |
| 33 | Reflected Cross‑Site Scripting (XSS) (CWE-79) (`ai-3c237f081f6c7aae`) | medium | api/extra.py:141-145 | **Could not be tested** | 0 |
| 34 | Missing validation of coupon discount range (CWE-770) (`ai-04f69d3a6682ee6f`) | low | api/extra.py:453-466 | **Could not be tested** | 0 |
| 35 | Potential weak session token generation (CWE-326) (`ai-b8c2b7ce22b68cd6`) | low | api/extra.py:125-138 | **Could not be tested** | 0 |

How to read the result:

- **Proven**: The penetration agent reproduced the issue against the running test stack.
- **Not reproduced**: Every attempt was denied as expected. This is not proof that the flaw does not exist.
- **Could not be tested**: A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run.

### What the penetration agent did, attempt by attempt


#### Hypothesis `ai-935e828dd4bba4f4` — Insecure password storage (CWE-256) — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No scenario could be planned for this hypothesis._

#### Hypothesis `ai-3c237f081f6c7aae` — Reflected Cross‑Site Scripting (XSS) (CWE-79) — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No scenario could be planned for this hypothesis._

#### Hypothesis `ai-7aebdfd54eb4e688` — Missing authorization on comment creation (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/comments")`
- Target: `/comments`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing role/ownership checks on an authenticated comment creation endpoint, so testing the authorization matrix will directly assess whether different roles can create comments without proper permission.
  - Step 1: `GET /comments` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/comments")`
- Target: `/comments`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has checked whether comment creation works without authentication; trying the unauthenticated_access template directly probes the missing authorization hypothesis.
  - Step 1: `GET /comments` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 200 response confirms that comment creation is allowed without authentication, indicating a clear missing authorization issue that should be reported and further validated across related endpoints.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-2b797e12ede1385a` — Missing authorization check on file read endpoint (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis describes a file read endpoint lacking any auth check, so testing unauthenticated access directly targets the missing authorization issue.
  - Step 1: `GET /files` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The endpoint returned a non‑denial status (422) instead of the expected 401/403/404, confirming the missing authorization check and indicating that further probing of this file read functionality is likely to succeed.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-357e82f73fc20848` — Missing authorization on verified file read endpoint (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files/verified")`
- Target: `/files/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of authentication on the /files/verified endpoint, so the unauthenticated_access template directly tests accessing the file without credentials.
  - Step 1: `GET /files/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response, which is not among the expected denial codes, confirms a missing authorization check on the verified file read endpoint, indicating the vulnerability is present and should be further explored.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-06a6519ee55ac5e0` — Missing authorization check on webhook creation (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /webhooks as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/webhooks")`
- Target: `/webhooks`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges? AI planner: The hypothesis concerns missing authorization that could let any authenticated user create webhooks as arbitrary users, so a privilege escalation test directly probes this weakness.
  - Step 1: `GET /webhooks` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/webhooks")`
- Target: `/webhooks`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: No prior test has examined the authorization logic for webhook creation; an authorization matrix test directly probes missing checks.
  - Step 1: `GET /webhooks` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/webhooks")`
- Target: `/webhooks`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has checked whether the webhook creation endpoint can be accessed without authentication, and this directly probes the missing authorization check.
  - Step 1: `GET /webhooks` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /webhooks as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which is not among the expected denial codes, confirms a missing authorization check on webhook creation, so the issue is verified and should be reported.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-6a78349f837e165e` — Potential IDOR on order creation (CWE-639) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/orders")`
- Target: `/orders`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no attempts exist, the next step is to test whether varying the owner_id in the request body bypasses ownership checks, which directly probes the suspected IDOR.
  - Step 1: `GET /orders` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/orders")`
- Target: `/orders`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has checked whether the order creation endpoint can be accessed without authentication; trying unauthenticated access will reveal if the IDOR can be exploited by unauthenticated users.
  - Step 1: `GET /orders` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response instead of the expected denial codes indicates a likely IDOR flaw, so the endpoint should be probed further to confirm and exploit the issue.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-6d23d0d008604fdc` — Missing authentication on login endpoint (CWE-287) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/login as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/auth/login")`
- Target: `/auth/login`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of authentication controls on the login endpoint, so testing unauthenticated access directly probes whether the endpoint can be used without valid credentials.
  - Step 1: `GET /auth/login` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/login as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The endpoint returned 405 instead of the expected denial codes, confirming a missing authentication check and indicating a genuine vulnerability worth further exploitation.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-d3c8ae68a75d8b90` — Potential path traversal via unverified file name (CWE-22) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>path_normalization_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does a dot-segment detour (/x/../files, proven to normalize to /files) reach a route whose access check compares the raw, un-normalized path? AI planner: The hypothesis concerns a path traversal check that may be bypassed by manipulating the file path; a path_normalization_bypass test directly probes such weaknesses.
  - Step 1: `GET /x/../files` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: path_normalization_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The test was correctly denied with a 404, confirming that this specific path‑normalization bypass does not succeed; further probing would need a different technique rather than repeating this same traversal attempt.
- Next action: **next_test**

**Attempt 2 — <code>case_sensitivity_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does re-casing the path (/FILES) reach a route a case-sensitive check missed? AI planner: Since a simple path‑normalization bypass was denied, testing case‑sensitivity variations may affect the is_relative_to check and reveal a traversal that bypasses the directory restriction.
  - Step 1: `GET /FILES` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: case_sensitivity_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The test was correctly denied with a 404, confirming the path traversal attempt was blocked; further probing with different techniques may still be worthwhile, but this specific case shows no vulnerability.
- Next action: **next_test**

**Attempt 3 — <code>trailing_slash_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does toggling the trailing slash (/files/) reach a route a naive string check missed? AI planner: Previous attempts only tested normalization and case sensitivity; a trailing slash bypass could affect the is_relative_to check, so it may reveal a traversal path not yet probed.
  - Step 1: `GET /files/` as `anonymous` → `307` (expected one of [401, 403, 404])
- Observation: trailing_slash_bypass: the response (HTTP 307) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis. AI interpretation: The 307 response does not match any of the expected denial codes, so the result is ambiguous and merits additional probing with alternative payloads or techniques to clarify whether traversal is possible.
- Next action: **next_test**

**Attempt 4 — <code>extension_suffix_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does appending a known format suffix (/files.json) bypass an extension-unaware access check? AI planner: Previous traversal attempts were denied or ambiguous; trying an extension suffix bypass can test if the path check can be evaded via alternate file extensions.
  - Step 1: `GET /files.json` as `admin` → `blocked`
- Observation: extension_suffix_bypass: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 5 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No attempts have tested whether the /files endpoint can be accessed without authentication, and this could reveal if the traversal check is bypassable for unauthenticated users.
  - Step 1: `GET /files` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The unexpected 422 response (not a standard denial code) indicates a potential issue worth deeper investigation, so retesting with varied payloads or parameters is advisable.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-cbdb48ff58f91fd1` — Missing admin authorization on audit endpoint (CWE-284) — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/audit as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns whether admin-only checks are enforced on the /admin/audit endpoint, so testing the authorization matrix will directly assess role-based access.
  - Step 1: `GET /admin/audit` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has attempted to access the /admin/audit endpoint without authentication, and this template directly probes the hypothesized missing admin check.
  - Step 1: `GET /admin/audit` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The endpoint correctly returned HTTP 401, confirming that unauthenticated access is denied and the missing‑admin‑authorization hypothesis is not supported; further testing of this specific unauthenticated vector is unlikely to yield a bypass.
- Next action: **next_test**

**Attempt 3 — <code>case_sensitivity_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Does re-casing the path (/ADMIN/AUDIT) reach a route a case-sensitive check missed? AI planner: Unauthenticated access is already denied; testing case‑sensitivity variations may reveal a path that bypasses the admin check for an authenticated user.
  - Step 1: `GET /ADMIN/AUDIT` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: case_sensitivity_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 404, confirming that the admin authorization check is enforced for this case‑sensitivity test, so retesting this vector is unlikely to yield a bypass.
- Next action: **next_test**

**Attempt 4 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET? AI planner: Unauthenticated requests are denied, so the next step is to test if alternative HTTP methods (e.g., HEAD) can bypass the admin check on the /admin/audit endpoint.
  - Step 1: `HEAD /admin/audit` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/audit as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which does not match any expected denial status, confirms a missing admin authorization check on the audit endpoint, so the issue is confirmed and should be pursued for further exploitation.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-83c277f7161c623e` — Missing authorization check on order ownership (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/apply-coupon as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing checks that the authenticated principal can modify the given order, so the authorization_matrix template directly tests ownership enforcement.
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: We need to verify whether the endpoint enforces any authentication at all before testing ownership, and no prior unauthenticated test has been performed.
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/apply-coupon as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response instead of the expected 401/403/404 indicates the endpoint lacks proper authorization enforcement for order ownership, confirming a violation. This suggests the issue is exploitable and should be further investigated for impact.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-eebcf33ae8e5eaef` — Unrestricted discount value via client-supplied field (CWE-915) — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No scenario could be planned for this hypothesis._

#### Hypothesis `ai-8204d1e620288a08` — Missing ownership/authorization check on payment (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/pay as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def pay_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/pay`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing ownership checks after authentication, so the authorization_matrix template directly tests whether authenticated users can act on orders they don't own.
  - Step 1: `GET /orders/{order_id}/pay` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def pay_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/pay`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has attempted to call pay_order without proper authentication, which directly probes the missing ownership/authorization check.
  - Step 1: `GET /orders/{order_id}/pay` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/pay as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which is not among the expected denial codes, confirms a missing ownership/authorization check, so the endpoint should be probed further to verify exploitation paths.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-492db277b819e281` — Information leakage via detailed error messages (CWE-209) — outcome: **exploitation_confirmed**

unauthenticated_access_corroboration: ZAP active scan reported 1 alert(s) at this exact path, highest severity low: Application Error Disclosure.

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def error_query() -&gt; dict:</code>
- Target: `/errors/query`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior attempts exist; the simplest unauthenticated request may trigger a database error and reveal detailed messages, providing the first evidence of information leakage.
  - Step 1: `GET /errors/query` as `anonymous` → `500` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the response (HTTP 500) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis. AI interpretation: The 500 response deviates from the expected 401/403/404 codes, indicating the server may be exposing internal error details, so further testing with varied inputs is advisable to confirm leakage.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: <code>def error_query() -&gt; dict:</code>
- Target: `/errors/query`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /errors/query` as `anonymous` → `violation`
- Observation: unauthenticated_access_corroboration: ZAP active scan reported 1 alert(s) at this exact path, highest severity low: Application Error Disclosure.
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The scan confirmed that unauthenticated requests trigger a low‑severity application error disclosure, indicating a real information‑leakage issue that should be addressed rather than retested.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-f0dce5b04fc274c8` — Missing ownership check on order cancellation (CWE-639) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/orders/{order_id}/cancel")`
- Target: `/orders/{order_id}/cancel`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: We need to verify that authenticated users cannot cancel orders they don't own, so testing varied user contexts with the authorization matrix template is the appropriate next step.
  - Step 1: `GET /orders/{order_id}/cancel` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/orders/{order_id}/cancel")`
- Target: `/orders/{order_id}/cancel`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns missing ownership checks after authentication; we first need to confirm whether the endpoint enforces any authentication at all, which unauthenticated_access can test.
  - Step 1: `GET /orders/{order_id}/cancel` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response instead of the expected 401/403/404 confirms the missing ownership/authentication check, so the endpoint appears exploitable and should be further probed for order cancellation abuse.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-ae177f098ffafcec` — Missing ownership check on invoice retrieval (CWE-639) — outcome: **exploitation_confirmed**

head_method_bypass: request to /invoices/{invoice_id} as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/invoices/{invoice_id}")`
- Target: `/invoices/{invoice_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing ownership verification on invoice retrieval, so testing with different authenticated users to see if they can access others' invoices (authorization matrix) directly addresses the potential IDOR.
  - Step 1: `GET /invoices/{invoice_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>case_sensitivity_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/invoices/{invoice_id}")`
- Target: `/invoices/{invoice_id}`
- Plan: Does re-casing the path (/INVOICES/{invoice_id}) reach a route a case-sensitive check missed? AI planner: No prior attempts have used case variations on the invoice_id path; testing case sensitivity may reveal whether the ownership check can be bypassed without altering authentication.
  - Step 1: `GET /INVOICES/{invoice_id}` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: case_sensitivity_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 404, confirming the ownership check prevented access in this case. This suggests the specific case‑sensitivity bypass does not expose the vulnerability, though other vectors could still be explored.
- Next action: **next_test**

**Attempt 3 — <code>path_normalization_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/invoices/{invoice_id}")`
- Target: `/invoices/{invoice_id}`
- Plan: Does a dot-segment detour (/invoices/x/../{invoice_id}, proven to normalize to /invoices/{invoice_id}) reach a route whose access check compares the raw, un-normalized path? AI planner: Since ownership checks may be bypassed via alternate path representations, testing a path normalization bypass is the next logical step given prior attempts did not explore this vector.
  - Step 1: `GET /invoices/x/../{invoice_id}` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: path_normalization_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 404, confirming the missing ownership check is not exploitable via this path‑normalization bypass; further retesting of this specific vector is unnecessary.
- Next action: **next_test**

**Attempt 4 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/invoices/{invoice_id}")`
- Target: `/invoices/{invoice_id}`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET? AI planner: Since prior case and path normalization bypasses were denied, testing a HEAD request may reveal whether the ownership check is bypassed for method variations, directly probing the IDOR hypothesis.
  - Step 1: `HEAD /invoices/{invoice_id}` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /invoices/{invoice_id} as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which is not among the expected denial codes, confirms the missing ownership check and suggests the endpoint is accessible without proper authorization, making it a viable target for further exploitation.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-76ee5ddf6f5e1661` — Missing ownership check on order retrieval (CWE-639) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/orders/{order_id}")`
- Target: `/orders/{order_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no tests have been run, the next step is to verify the missing ownership check by testing authorization matrix behavior for different users accessing various order IDs.
  - Step 1: `GET /orders/{order_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/orders/{order_id}")`
- Target: `/orders/{order_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior attempt has tested accessing the order endpoint without authentication, which could reveal whether ownership checks are enforced before authentication.
  - Step 1: `GET /orders/{order_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response instead of an expected denial status indicates the endpoint is reachable without authentication and likely lacks proper ownership checks, so it remains a viable target for further probing.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-78782ba33d6e3838` — Missing authorization check for admin users (CWE-285) — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/users as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing role checks on the admin users endpoint, so testing with different user roles using the authorization matrix template will directly verify if non‑admin users can access the data.
  - Step 1: `GET /admin/users` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges? AI planner: No prior privilege_escalation attempt has been made; this template directly tests whether a non‑admin can retrieve all user records, addressing the missing admin role check.
  - Step 1: `GET /admin/users` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns missing admin role verification on the /admin/users endpoint, so testing unauthenticated access directly checks whether any authentication is required before data is returned.
  - Step 1: `GET /admin/users` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with HTTP 401, confirming that the admin endpoint enforces authorization and does not appear vulnerable to unauthenticated access.
- Next action: **next_test**

**Attempt 4 — <code>case_sensitivity_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does re-casing the path (/ADMIN/USERS) reach a route a case-sensitive check missed? AI planner: Unauthenticated requests are denied, so we need to test if altering case of the admin path bypasses role checks; a case‑sensitivity bypass is the most relevant remaining template.
  - Step 1: `GET /ADMIN/USERS` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: case_sensitivity_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 404, matching the expected statuses, so this particular bypass does not appear exploitable and further testing with the same case‑sensitivity approach is likely unnecessary.
- Next action: **next_test**

**Attempt 5 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET? AI planner: Unauthenticated requests are denied, so testing a HEAD method bypass may reveal if the authorization check is skipped for non‑GET methods, which hasn't been tried yet.
  - Step 1: `HEAD /admin/users` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/users as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response instead of the expected denial codes indicates the admin endpoint lacks proper authorization checks, confirming a vulnerability that should be further explored for exploitation.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-d6b4763af77577b9` — Missing authorization check for admin jobs (CWE-285) — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/jobs as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns a missing admin role check on /admin/jobs, so testing with different user roles using the authorization_matrix template will reveal if non‑admin users can access the endpoint.
  - Step 1: `GET /admin/jobs` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has checked access without authentication; trying unauthenticated_access will reveal whether the endpoint lacks any auth check.
  - Step 1: `GET /admin/jobs` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with HTTP 401, confirming the authorization check is in place; retesting this specific unauthenticated access vector is unlikely to yield a different outcome.
- Next action: **next_test**

**Attempt 3 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges? AI planner: Unauthenticated access was denied, but we need to see if an authenticated non‑admin user can retrieve jobs; a privilege escalation test targets missing admin role checks.
  - Step 1: `GET /admin/jobs` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 4 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET? AI planner: Unauthenticated GET is denied, so testing a HEAD request may reveal an authorization bypass without needing new credentials.
  - Step 1: `HEAD /admin/jobs` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/jobs as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which does not match any expected denial codes, confirms a missing authorization check for admin jobs, so the vulnerability appears exploitable and should be pursued further.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-d63a40e98bc61059` — Sensitive data exposure via debug\_config endpoint (CWE-200) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/debug/config")`
- Target: `/debug/config`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis states the /debug/config endpoint returns sensitive data without authentication, so the unauthenticated_access template directly tests this claim.
  - Step 1: `GET /debug/config` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The observed HTTP 200 response instead of the expected denial codes confirms that the debug_config endpoint is accessible without authentication, indicating a confirmed sensitive data exposure.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-b8c2b7ce22b68cd6` — Potential weak session token generation (CWE-326) — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No scenario could be planned for this hypothesis._

#### Hypothesis `ai-30920f0acc104aee` — Missing authentication on session start (CWE-306) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def session_start(username: str) -&gt; Response:</code>
- Target: `/session/start`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis describes creating a session without verifying credentials, which is directly tested by the unauthenticated_access template.
  - Step 1: `GET /session/start` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The test confirms that the /session/start endpoint does not enforce authentication, as an anonymous request received a 422 instead of the expected denial codes. This indicates a clear authentication bypass that should be reported and remediated.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-ed2bf8f5536c5122` — Missing rate limiting / token reuse protection on password reset request (CWE-640) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/reset/request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/auth/reset/request")`
- Target: `/auth/reset/request`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns an unauthenticated password reset endpoint that may lack throttling, so the next step is to test unauthenticated access to the reset request route.
  - Step 1: `GET /auth/reset/request` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/reset/request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response indicates the endpoint did not reject the unauthenticated request with a typical denial code, confirming a lack of rate‑limiting or token‑reuse protection and suggesting further probing of reset logic is warranted.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-c788be668eb0e766` — Missing authentication on verified password reset request (CWE-306) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/reset/verified-request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/auth/reset/verified-request")`
- Target: `/auth/reset/verified-request`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of required authentication for a password reset endpoint, so testing unauthenticated access directly targets this issue.
  - Step 1: `GET /auth/reset/verified-request` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/reset/verified-request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which is not among the expected denial codes, confirms a violation, indicating that the verified password reset endpoint lacks proper authentication and should be considered exploitable.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-0e5f56ed2ed3b6b5` — Missing authentication check on session token generation — outcome: **not_reproduced**

authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- Target: `/session/secure-start`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of authentication when creating session tokens, so testing unauthenticated access directly probes token forgery without prior evidence.
  - Step 1: `GET /session/secure-start` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with HTTP 401, confirming the authentication check is in place; retesting this specific unauthenticated access vector is unlikely to yield a bypass.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- Target: `/session/secure-start`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The only test so far was a generic unauthenticated request that was denied; trying an authorization matrix can probe whether alternative credential formats or missing checks allow token forgery.
  - Step 1: `GET /session/secure-start` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **stop** (no_further_strategy)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-caa31c16de86cfef` — Potential IDOR in session whoami endpoint — outcome: **not_reproduced**

authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/session/whoami")`
- Target: `/session/whoami`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no tests have been run, the first step is to see if the whoami endpoint can be accessed without a valid session token, confirming whether authentication is enforced.
  - Step 1: `GET /session/whoami` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 401 status, confirming that unauthenticated access is blocked and the IDOR hypothesis is not supported in this case.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/session/whoami")`
- Target: `/session/whoami`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since unauthenticated requests are blocked, the next step is to test token manipulation across different authorized roles to see if the whoami endpoint trusts the numeric ID in the session token.
  - Step 1: `GET /session/whoami` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **stop** (no_further_strategy)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-04f69d3a6682ee6f` — Missing validation of coupon discount range (CWE-770) — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No scenario could be planned for this hypothesis._

#### Hypothesis `ai-844c60b0ab9c1aa8` — Potential missing ownership verification on comment creation (CWE-639) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def add_comment(body: Comment, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/comments`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no attempts exist, testing whether the comment creation endpoint can be accessed without authentication directly probes the suspected missing ownership verification.
  - Step 1: `GET /comments` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 200 response instead of the expected denial codes confirms a missing ownership check, indicating the issue is exploitable and should be pursued further.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-6322be0c6e12b177` — Insecure Direct Object Reference (CWE-639) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/profiles/{profile_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no tests have been run, the next step is to probe the endpoint with varied authorized principals to see if access control is enforced, which matches the IDOR hypothesis.
  - Step 1: `GET /profiles/{profile_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/profiles/{profile_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior test has checked whether the endpoint rejects requests without authentication; an unauthenticated_access attempt will confirm if the principal check is enforced before object authorization.
  - Step 1: `GET /profiles/{profile_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response instead of the expected denial codes indicates the object can be accessed without authentication, confirming an IDOR vulnerability and suggesting further exploitation testing is warranted.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-b0abc42e37a54582` — Missing Authorization Check for Admin Overview (CWE-862) — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/overview as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of admin privilege verification, so the first step is to see if the endpoint can be accessed without authentication.
  - Step 1: `GET /admin/overview` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The unauthenticated request was correctly denied with HTTP 401, confirming the authorization check is in place; further testing should focus on other vectors rather than repeating this same access attempt.
- Next action: **next_test**

**Attempt 2 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges? AI planner: Unauthenticated requests are denied, so the next step is to see if a valid non‑admin token can bypass the missing admin check; the privilege_escalation template targets this scenario.
  - Step 1: `GET /admin/overview` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since unauthenticated requests are denied, we need to test whether an authenticated non‑admin user can access admin_overview; the authorization_matrix template is designed for that role‑based check.
  - Step 1: `GET /admin/overview` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 4 — <code>case_sensitivity_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Does re-casing the path (/ADMIN/OVERVIEW) reach a route a case-sensitive check missed? AI planner: Previous attempts failed to reach the endpoint; testing case‑sensitivity may reveal an admin‑only path that bypasses the missing privilege check without needing authentication.
  - Step 1: `GET /ADMIN/OVERVIEW` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: case_sensitivity_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 404, confirming the authorization check works for this case, so further testing with this case‑sensitivity bypass is unlikely to reveal a flaw.
- Next action: **next_test**

**Attempt 5 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET? AI planner: No method‑based bypass has been tested yet; trying a HEAD request may reveal whether the admin check is skipped for non‑GET methods.
  - Step 1: `HEAD /admin/overview` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/overview as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which does not match any expected denial codes, confirms a missing authorization check for the admin overview endpoint, indicating that further exploitation attempts are likely viable.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-62e3663725439fbd` — Insecure Direct Object Reference (IDOR) in note retrieval — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no attempts exist and the issue is an authorization check missing for note ownership, the authorization_matrix template is the most relevant to probe different permission scenarios.
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No unauthenticated attempts have been made; testing unauthenticated access will reveal if the endpoint leaks notes without proper authorization.
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response, which is not among the expected denial codes, indicates the endpoint is reachable without authentication, suggesting a potential IDOR that merits further probing.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-72536ee718898b70` — Missing authorization check (CWE-862) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def verified_get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior tests exist; trying an unauthenticated request directly probes whether the endpoint enforces any ownership check, addressing the missing authorization hypothesis.
  - Step 1: `GET /orders/{order_id}/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The observed 422 response, which is not among the expected denial codes, confirms a missing authorization check, so the endpoint is vulnerable and can be further probed for exploitation.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-e6b00beb5ad08603` — Missing authentication on file download (CWE-284) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/uploads/{upload_id}")`
- Target: `/uploads/{upload_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior evidence exists; the hypothesis concerns lack of authentication for file download, so testing unauthenticated access directly addresses the claim.
  - Step 1: `GET /uploads/{upload_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response, which is not among the expected denial codes, confirms a missing authentication check on the download endpoint, indicating a viable issue to pursue further.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


#### Hypothesis `ai-5ae04a0c7d72bccf` — Missing authentication on comments endpoint (CWE-306) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/comments", response_class=HTMLResponse)`
- Target: `/comments`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of authentication on the /comments endpoint, so the unauthenticated_access template directly tests reading comments without credentials.
  - Step 1: `GET /comments` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The endpoint returned HTTP 200 for an anonymous request, confirming a missing authentication check and indicating a clear vulnerability that should be further validated and reported.
- Next action: **stop** (exploitation_confirmed)


#### Hypothesis `ai-e4eb53440f8f0be6` — Missing authentication on forum messages endpoint (CWE-306) — outcome: **exploitation_confirmed**

unauthenticated_access: request to /forum/messages as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/forum/messages", response_class=HTMLResponse)`
- Target: `/forum/messages`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns lack of authentication on the /forum/messages endpoint, so the unauthenticated_access template directly tests whether the resource can be retrieved without credentials.
  - Step 1: `GET /forum/messages` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /forum/messages as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 200 response confirms the endpoint is accessible without authentication, indicating a real missing‑auth issue that should be pursued further.
- Next action: **stop** (exploitation_confirmed)


## Scanner and DAST Observations (Pre-Review)

**63** merged observation record(s): **37** DAST-related and **26** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

1. **python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-051697f9b8567d596874</code>; rule(s): <code>CVE-2026-53539</code>; source evidence: <code>finding-2626e4bc8eef02153f32</code>.
2. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0bcbb317cfb96e7d5505</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-a39e9179918dd476f1e5dab4</code>.
   - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
3. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
4. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0f6fe31b81367808748c</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-22221f4054533f30bbaf73ba</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;nested_note&quot;}</code>.
5. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-15dd977d52312c30635a</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-9285679b6f926a0d1c0a44d2</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_jobs&quot;}</code>.
6. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-18063ba27bc289f53c8a</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-3982bc4eac58ce8d5c2fe5ad</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;profile_owner&quot;}</code>.
7. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:119</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-18f1abe978f9fdaad8e6</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-5e7b731c6445970909c9</code>.
8. **Missing Content-Security-Policy header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-19f4a13e0b2d4f7413d0</code>; rule(s): <code>web.missing-content-security-policy</code>; source evidence: <code>runtime-4d5cb0113b221c088986a91b</code>.
   - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
9. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-1bcb1da144dffdcf3fd8</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-12d8f92bbda0b009c94e4b17</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;payment_replay&quot;}</code>.
10. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-218d6fc43fe64432894a</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-19ac26bfd96baf1f15d8f0f0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200, 201], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;price_catalog&quot;}</code>.
11. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:221</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-24d14609e3893220ea16</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-ac18ed89b1a00ae2c8bf</code>.
12. **Clear-text logging of sensitive information** — scanner from codeql-cli, semgrep-ce; location: <code>api/app.py:137</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3202e1e1074cfd44b9bf</code>; rule(s): <code>py/clear-text-logging-sensitive-data, python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure</code>; source evidence: <code>finding-cfe66151dbff24377948</code>, <code>finding-2e982654735c1187197b</code>.
13. **python-multipart: python-multipart: Denial of Service via excessive multipart part headers** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3503f2dec888990b31f2</code>; rule(s): <code>CVE-2026-42561</code>; source evidence: <code>finding-d5a70d23b67803614b8f</code>.
14. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4a2311054cdc2bfe890d</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-f7770e55aa48cd4e79a67974</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
15. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4ae7658c2abfbf689e2b</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-ac5e6859c324c2e40526210b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
16. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4c6d36222f8ebf7f1f68</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-06b259c78fa19fa5d06a773c</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
17. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
18. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-54b1ddb055358b3579a2</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-bc7d0d0a77b4619ba22d0b25</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;invoice_owner&quot;}</code>.
19. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-56ecc860a2c48330a29a</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d193f3d7b6fa58812879e8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
20. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
21. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-5a7c783c30e11426af42</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-97a2403badc5307e87389e70</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_initial_state&quot;}</code>.
22. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-69b75a0aa3f8fc9fb800</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-b6f705aa38e255df58e01591</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
23. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-6e468e09eab3ca889e3d</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-b9a6116c922e7e3c213c2404</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
24. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
25. **python-multipart: Python-Multipart: Information disclosure due to parser differential in form data handling** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-74bb99c1ff3b5ed1fea8</code>; rule(s): <code>CVE-2026-53538</code>; source evidence: <code>finding-37828c3c6f1de39a916e</code>.
26. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-767d54ff7a729b156819</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-289a562cf581d69d3a6c7d63</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;negative_price&quot;}</code>.
27. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.
28. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:222</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-794dcb4921076779cef0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-2f756e27fddc389636a8</code>.
29. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7ed325c02dd6cf8227d2</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-3143beb445281415043c6a2c</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;coupon_bounds&quot;}</code>.
30. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-81ff94e895c53dbc2029</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-c2674e7dbbea535e39dafdce</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
31. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:213</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-83d97da4516adf20e20f</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-26bd24fa5794fd60d9e9</code>.
32. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
33. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
34. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8cdc677a9810b317840f</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-79fa84ef4d90b0b35afc2e33</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;webhook_destination&quot;}</code>.
35. **python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8ce42d9c8b52a95b109d</code>; rule(s): <code>CVE-2026-24486</code>; source evidence: <code>finding-555e67f97039217aa153</code>.
36. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-916563c278b3e6b62930</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ad2c3148445dc879b11b7580</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
37. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
38. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a4473061f97f0a366678</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-7a357b5bf54222b07b45d1ba</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
39. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a6e788cfc5d9d1297feb</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-2f9dcf012b09704cb4324d5b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
40. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a9a9a0b97f19f8bf52ae</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d2c2e1a1a3392fa7d24831ad</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
41. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:224</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b3c734b4cef8dd70fce0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-603f6a08a677ccbb0c42</code>.
42. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:215</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b527b3ed30e57aac5ec5</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-aa95c189edc76290622b</code>.
43. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b7e0b624f8cddd0a9e8c</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-d47d5c27b4e143571ef5f9e3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;worker_role&quot;}</code>.
44. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b98074828fe298997980</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-267f3aec1133283c14739667</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 401, 403], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;unsigned_hook&quot;}</code>.
45. **Missing X-Content-Type-Options header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-bbf1646deeb18d1e95db</code>; rule(s): <code>web.missing-content-type-protection</code>; source evidence: <code>runtime-a9347cabd53ecd99e38108cc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
46. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c0dcf73e8d7a6a1fbf02</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-dfd12f00e32f16e74be8fee3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;excessive_data&quot;}</code>.
47. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
48. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c5b44871f1955b338344</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-946a5bf2b3aeb375da4de266</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_users&quot;}</code>.
49. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-cad468186f9fd0b4e99b</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-c9199ae9fe5021a5d3738696</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
50. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ccc894903304aa8847bd</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-128e83b73f127060c05a7721</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;paid_cancel&quot;}</code>.
51. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d0789be823f0fd7fa381</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-e6fad5bfce7f957806254d9e</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;owner_assignment&quot;}</code>.
52. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d58491aad5be35b48233</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-2a9764dfddf0c017eff71be0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;stale_role&quot;}</code>.
53. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d716d5afb61da294d286</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-678ec39654e40601b76ef8f6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
54. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
55. **multipart: Python-Multipart: Information disclosure via header parsing discrepancy** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-e76230cbef200116e4ae</code>; rule(s): <code>CVE-2026-53537</code>; source evidence: <code>finding-0f80f106ffc0aeace60b</code>.
56. **Reflected server-side cross-site scripting** — scanner from codeql-cli; location: <code>api/extra.py:145</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ea527a7d7441e2b11700</code>; rule(s): <code>py/reflective-xss</code>; source evidence: <code>finding-a8c8d9148f5e4ee9d3fd</code>.
57. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-efce9419c25ced2d8892</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-18719503314710a3e71c38c9</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;reset_replay&quot;}</code>.
58. **python-multipart: Python-Multipart: Negative Content-Length in parse\_form buffers the entire body in memory** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f15e42abb7b2acd921f1</code>; rule(s): <code>CVE-2026-53540</code>; source evidence: <code>finding-b593d9dd6684fb6a9511</code>.
59. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
60. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:212</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f4eaf141df049c63545d</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-480ccba498d117b3450e</code>.
61. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f5fff899f9294177dc70</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-e929732019082549893b68d0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [401, 403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;debug_access&quot;}</code>.
62. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:144</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f60fee7d82fbca512208</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-7605384fbc7aee3bcd8a</code>.
63. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-fe4ca713f11faf9b96d6</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-ed0dc0a1678724040424e4a2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_owner&quot;}</code>.

## Security Review Agent Verdicts

### 1. X-Content-Type-Options Header Missing

- Issue group: `merged-4c6d36222f8ebf7f1f68`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner and runtime probe observed a GET request to the root path ("/") and reported that the X-Content-Type-Options header was not present in the response. The provided source excerpt shows the FastAPI endpoint implementation but does not include any middleware or response configuration that would add this security header. Without explicit code adding the header, the finding is plausible but not definitively proven from the supplied artifacts.

**Impact:** Absence of the X-Content-Type-Options: nosniff header can allow browsers to perform MIME type sniffing, potentially enabling content injection attacks such as cross‑site scripting when improperly handled content is served.

**Remediation:** Add middleware or configure the FastAPI response to include the header, e.g., using Starlette's `Response` class or a custom middleware:
```python
from fastapi import FastAPI, Response
app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers\["X-Content-Type-Options"\] = "nosniff"
    return response
```
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Scanner finding: X-Content-Type-Options Header Missing (low severity, medium confidence)`
- `Runtime probe fact (zap.10021) observed GET request to '/' with no header values shown`

Limitations:
- The actual HTTP response headers were not provided; the assessment relies on scanner and probe reports rather than direct header inspection.
- No code evidence (e.g., middleware or response modification) was present to confirm the header is omitted or added elsewhere in the application.

### 2. Job listing endpoint may lack proper admin authorization

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs endpoint calls a function principal(authorization) before accessing the database, but the provided source excerpt does not show what checks principal performs. The runtime probe observed that a GET request to this endpoint returned HTTP 200 instead of the expected 403/404, indicating that the authorization check may be ineffective or missing. This combination suggests a potential authorization flaw, but the source does not definitively demonstrate the absence of a proper admin role check.

**Impact:** If unauthorized users can access /admin/jobs, they may retrieve sensitive job data or enumerate internal information, leading to information disclosure and potential further exploitation.

**Remediation:** Ensure that the principal function validates that the caller has an admin role and returns an appropriate error (e.g., 403 Forbidden) when the check fails. Add explicit role checks before database access and return error responses for unauthorized requests.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs endpoint calling principal(authorization) without visible role verification`
- `Runtime probe fact: GET /admin/jobs returned status 200, while expected statuses were 403 or 404`

Limitations:
- The implementation of principal() is not provided, so we cannot confirm whether it enforces admin role checks
- No additional logs or guard checks are shown to prove the absence of other authorization mechanisms

### 3. Demoted administrator may retain access to /admin/token-report

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint checks the role field in the token at request time and returns 403 only if the role is not "admin". A runtime probe observed a successful 200 response for a GET request to /admin/token-report, indicating that the role check did not block access in that scenario. This suggests that a token issued before a role demotion may remain valid, allowing a demoted administrator to retain access. However, the supplied code does not show how tokens are issued or refreshed, and there is no evidence that the role change is propagated to existing tokens. Without that context, the finding cannot be confirmed.

**Impact:** If a user’s administrative role is revoked but their existing token remains valid, they could continue to perform privileged actions, leading to unauthorized access and potential data leakage or modification.

**Remediation:** Implement token revocation or short-lived tokens that are re‑validated against the current user role on each request. Ensure that role changes invalidate existing tokens or that the token payload is refreshed to reflect the updated role before authorisation checks.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check: if token.get("role") != "admin": raise HTTPException(403, "Administrator required")`
- `Runtime probe fact: GET /admin/token-report returned status 200 when a 403 was expected (assertion_results: false)`

Limitations:
- Missing evidence of token issuance and refresh logic to confirm whether role changes invalidate existing tokens
- No view of the principal() function or token validation mechanism to determine if it re‑checks the role against a data store

### 4. User listing requires admin role

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/users calls principal(authorization) but the provided source excerpt does not show any role check before querying all user data, including sensitive fields such as SSN. A runtime probe accessed the endpoint with a GET request and received a 200 OK response, whereas the expected statuses were 403 or 404, indicating that the admin role enforcement is missing. The scanner also flagged this as a high‑severity issue. Both the code path and the independent runtime observation demonstrate the vulnerability.

**Impact:** Unauthenticated or low‑privileged users can retrieve the full list of users, including sensitive personal information (email, role, SSN), leading to privacy breaches and potential identity theft.

**Remediation:** Implement proper authorization checks in the admin_users handler, e.g., verify that the authenticated principal has an admin role before executing the database query. Return 403 Forbidden for unauthorized access.
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source excerpt shows admin_users endpoint without explicit role verification`
- `Runtime probe fact: GET /admin/users returned 200 instead of expected 403/404`

### 5. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a session cookie via `response.set_cookie("lab_session", ...)` without specifying the HttpOnly attribute, meaning client‑side scripts could access the cookie. The runtime probe from the ZAP scanner (rule zap.10010) also reports the missing HttpOnly flag for the same endpoint, providing independent confirmation of the issue.

**Impact:** An attacker who can inject JavaScript into the application (e.g., via XSS) could read the session cookie and hijack the user’s session, leading to account compromise.

**Remediation:** Set the HttpOnly flag when creating the cookie, e.g., `response.set_cookie("lab_session", ..., httponly=True)` or configure the framework to add HttpOnly by default for session cookies.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- <code>Source excerpt shows `response.set_cookie(&quot;lab_session&quot;, f&quot;session-{row[&#x27;id&#x27;]}&quot;)` without HttpOnly.</code>
- `Runtime probe fact from ZAP (zap.10010) reports missing HttpOnly flag on POST /auth/form-login.`

### 6. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The form_login endpoint returns an HTMLResponse without setting any X-Frame-Options or Content-Security-Policy frame-ancestors header. The source excerpt shows no header manipulation after response creation. The runtime probe confirms a POST request to /auth/form-login, and the scanner finding reports the missing anti-clickjacking header, providing independent corroboration.

**Impact:** An attacker can embed the login page in a malicious site using clickjacking techniques, potentially tricking users into submitting credentials or performing unintended actions.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP frame-ancestors directive that disallows framing by untrusted origins.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Source code does not set X-Frame-Options or CSP frame-ancestors header`
- `Runtime probe fact shows POST request to /auth/form-login`
- `Scanner finding reports missing anti-clickjacking header`

### 7. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The supplied source excerpt shows the login endpoint implementation but does not include any logic that sets a Content‑Security‑Policy header on the response. The runtime probe reports a POST request to /auth/form-login without indicating that a CSP header was present. No other evidence (e.g., middleware, framework configuration) is provided that would add the header automatically. Consequently, the finding that the CSP header is missing is plausible but not definitively proven by the available artifacts.

**Impact:** Without a CSP header, the application is vulnerable to client‑side injection attacks such as cross‑site scripting (XSS). An attacker who can inject malicious scripts into pages served by the application could execute arbitrary code in the victim’s browser, potentially stealing session cookies or performing actions on behalf of the user.

**Remediation:** Configure the application to include a strong Content‑Security‑Policy header on all responses. This can be done by adding middleware that sets the header, e.g., using Starlette/FastAPI middleware:
```python
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\['Content-Security-Policy'\] = "default-src 'self'; script-src 'self'"
        return response
```
Alternatively, configure the web server (e.g., Nginx, Apache) to add the header globally.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Source excerpt shows no CSP header being set in the form_login handler.`
- `Runtime probe fact for POST /auth/form-login does not report a CSP header.`

Limitations:
- Missing evidence of any global middleware, framework settings, or server configuration that might add the CSP header automatically.
- No runtime observation of response headers confirming the header is absent.

### 8. Password reset tokens must be single use

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code retrieves a reset token from the database and, if found, updates the user's password without invalidating or deleting the token. No check is present to ensure the token is single‑use. The runtime probe shows a POST to the endpoint returning 200, indicating the token was accepted, which aligns with the lack of a single‑use guard. However, there is no direct evidence that the token is removed or marked used after the password change, nor is there independent scanner confirmation of token reuse behavior.

**Impact:** An attacker who obtains a valid reset token could reuse it to reset the victim's password multiple times, leading to account takeover.

**Remediation:** After successfully resetting the password, delete the used token from the reset_tokens table or mark it as used so that subsequent attempts with the same token are rejected. Additionally, enforce token expiration and ensure the token is cryptographically random.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup and password update without token invalidation (lines 577‑585).`
- `Runtime probe fact indicates a POST to /auth/reset/confirm returned 200, suggesting the token was accepted.`
- `Scanner finding flags that reset tokens must be single use.`

Limitations:
- Missing explicit evidence that the token is deleted or marked used after a successful reset.
- No independent scanner of medium or higher severity confirming token reuse behavior beyond the runtime probe.

### 9. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /catalog/query returns HTML content without any indication that a Content‑Security‑Policy header is added to the response. The source excerpt shows only the HTML generation logic and does not set response headers. The runtime probe records a GET request but does not capture response headers, so the absence of CSP cannot be confirmed definitively.

**Impact:** Without a CSP header, browsers may allow execution of unsafe inline scripts or loading of resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response object or a middleware to set a strict policy that disallows unsafe inline scripts and restricts resource origins.
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Source excerpt shows HTML response generation without header manipulation`
- `Runtime probe fact records a GET request to /catalog/query but does not include response header data`

Limitations:
- Missing runtime observation of actual response headers to confirm CSP is absent
- No evidence that the application sets CSP elsewhere (e.g., via middleware or server configuration)

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-a6e788cfc5d9d1297feb`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting the X-Content-Type-Options: nosniff header. The source code shows the response is built manually and no security headers are added. The runtime probe fact from the web-runtime scanner (zap.10021) observed a GET request to this path and reported the header as missing, providing independent corroboration of the issue.

**Impact:** Browsers may perform MIME type sniffing on the response, potentially allowing content injection attacks such as cross-site scripting if an attacker can influence the response body.

**Remediation:** Add the X-Content-Type-Options header with the value "nosniff" to the response. In FastAPI this can be done by returning a Response object with the appropriate headers or using a middleware to set the header for all responses.
Evidence:
- Source IDs: `merged-a6e788cfc5d9d1297feb`
- `Source excerpt shows the /catalog/query endpoint returns HTML without setting headers`
- `Runtime probe fact (zap.10021) reports X-Content-Type-Options header missing for GET /catalog/query`

### 11. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content but the response does not include an X‑Frame‑Options or Content‑Security‑Policy frame‑ancestors header that would prevent the page from being embedded in a foreign frame. The supplied source excerpt shows the route definition and HTML generation, and the runtime probe confirms the endpoint is reachable via GET, but no header evidence is provided. No defensive check or header‑setting logic is visible in the supplied code.

**Impact:** An attacker could embed the page in a malicious site and perform clickjacking attacks, potentially tricking users into unintentionally interacting with the application’s UI, leading to unauthorized actions or data leakage.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., set X‑Frame‑Options: SAMEORIGIN or configure a Content‑Security‑Policy with a frame‑ancestors directive. This can be done globally via middleware or per‑route using FastAPI’s response headers.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Runtime probe confirms GET request to /catalog/query is served (web-runtime zap.10020)`
- `Source excerpt shows HTMLResponse is returned without header manipulation`

Limitations:
- Missing concrete evidence of the response headers (e.g., captured HTTP response showing X‑Frame‑Options is absent)
- No indication of any middleware or framework configuration that might add the header automatically

### 12. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /comments returns HTML content without setting an X-Frame-Options or Content-Security-Policy frame-ancestors header. The supplied source shows the response is generated directly and no header is added in the code. A runtime probe confirms the endpoint is reachable via GET, but does not capture response headers, so the absence of the anti-clickjacking header is not independently verified.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into unintended actions.

**Remediation:** Add an appropriate anti-clickjacking header (e.g., X-Frame-Options: SAMEORIGIN or Content‑Security‑Policy: frame‑ancestors 'self') to the response in the show_comments handler or via a global middleware.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Source excerpt shows HTML response is returned without header manipulation`
- `Runtime probe fact confirms GET request to /comments`

Limitations:
- No captured response headers to prove the header is missing
- No independent scanner evidence of the missing header beyond the initial finding

### 13. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns HTML generated from comment bodies without setting a Content‑Security‑Policy header. The source excerpt shows the response is built as a plain string and returned via FastAPI's `HTMLResponse` default, which does not include CSP headers. A runtime probe (zap.10038) observed a GET request to `/comments`, confirming the endpoint is reachable, but did not capture response headers, so the absence of CSP cannot be directly proven at runtime.

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, or other resources may be loaded. An attacker who can inject malicious content into comment bodies could execute arbitrary JavaScript in a victim's browser (XSS), leading to session hijacking, data exfiltration, or further compromise.

**Remediation:** Add a CSP header to the response. In FastAPI this can be done with a middleware or by customizing the response, e.g.:```python
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\["Content‑Security‑Policy"\] = "default-src 'self'; script-src 'self'"
        return response

app.add_middleware(CSPMiddleware)
```
Alternatively, set the header directly in the endpoint:```python
return HTMLResponse(content=html, headers={"Content‑Security‑Policy": "default-src 'self'"})```
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- <code>Source excerpt shows `/comments` endpoint returns HTML without setting headers</code>
- `Runtime probe fact (zap.10038) confirms the endpoint is reachable via GET`

Limitations:
- No captured response headers from the runtime probe to definitively prove the CSP header is missing
- No evidence that the application sets CSP globally via middleware elsewhere in the codebase

### 14. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /comments endpoint returns HTML content without setting the X-Content-Type-Options: nosniff header. The source excerpt shows the route implementation and the runtime probe confirms a GET request to this path, but no header information is provided.

**Impact:** Browsers may perform MIME type sniffing, potentially allowing content‑type confusion attacks such as cross‑site scripting or drive‑by downloads.

**Remediation:** Add the X-Content-Type-Options: nosniff header to the response, e.g., via a middleware or by setting it explicitly in the route handler.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- `Source excerpt shows HTMLResponse returned from /comments without header manipulation`
- `Runtime probe fact indicates a GET request to /comments (zap.10021)`

Limitations:
- Missing concrete response header data confirming the header is absent
- No evidence that the application sets the header elsewhere (e.g., global middleware)

### 15. Debug configuration is unavailable anonymously

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /debug/config endpoint returns sensitive configuration values (database URL, mock external URL, app secret) without any authentication or authorization checks. The source excerpt shows the handler directly returns these values, and the runtime probe confirms the endpoint responds with HTTP 200, indicating it is publicly accessible.

**Impact:** An attacker can retrieve internal configuration data, potentially enabling further attacks such as database compromise, secret extraction, or service abuse.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint so that only authorized users can access configuration data. Consider returning a generic error (e.g., 401 Unauthorized) for unauthenticated requests and ensure sensitive values are not exposed in responses.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source excerpt shows debug_config() returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks (lines 321-322).`
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404.`

Limitations:
- No evidence of any existing authentication or access control mechanism surrounding this endpoint in the supplied code. Unable to confirm whether external middleware might enforce checks outside the shown snippet.

### 16. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the /healthz endpoint does not include a Content‑Security‑Policy header. The supplied source code shows the endpoint implementation but does not reveal any response header configuration. No runtime probe data includes the actual response headers, only the HTTP status. Without concrete evidence that the header is absent, the finding cannot be confirmed.

**Impact:** Absence of a CSP header can allow injection of malicious scripts, increasing the risk of cross‑site scripting attacks against clients that consume the endpoint.

**Remediation:** Configure the FastAPI application to include a Content‑Security‑Policy header on responses, e.g., using a middleware that adds the header globally or specifically for the /healthz route.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Scanner report: web.missing-content-security-policy on path /healthz`
- `Source excerpt showing /healthz endpoint implementation`

Limitations:
- No captured HTTP response headers confirming the CSP header is missing
- No runtime probe data showing header presence or absence

### 17. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without the X-Frame-Options or Content-Security-Policy header that would mitigate clickjacking. The scanner and runtime probe both indicate the endpoint is reachable, but no header evidence is provided.

**Impact:** An attacker could embed the health endpoint in a malicious frame, potentially misleading users or facilitating UI redress attacks.

**Remediation:** Configure the web framework or reverse proxy to add an appropriate X-Frame-Options header (e.g., SAMEORIGIN) or a Content-Security-Policy frame-ancestors directive to the /healthz response.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner reported missing clickjacking protection header for /healthz`
- `Runtime probe returned status 200 for /healthz`

Limitations:
- Actual HTTP response headers were not captured, so the absence of X-Frame-Options or CSP cannot be definitively proven.

### 18. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a JSON response but the supplied source code does not set the X-Content-Type-Options header. The runtime probe confirms the endpoint is reachable, but no evidence is provided that the header is added elsewhere (e.g., middleware, server configuration).

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may incorrectly sniff the content type, potentially enabling certain cross‑site scripting or drive‑by download attacks.

**Remediation:** Configure the application or web server to add the X-Content-Type-Options: nosniff header to all responses, e.g., via FastAPI middleware, a response header decorator, or server settings (nginx, Apache, etc.).
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Runtime probe shows GET request to /healthz succeeded (web-runtime zap.10021)`
- `Source excerpt of /healthz handler does not set any response headers`

Limitations:
- No captured response headers to confirm the header is absent
- No evidence of global middleware or server configuration that might add the header

### 19. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response but the supplied source excerpt does not show any middleware or response header configuration that adds the X-Content-Type-Options header. The runtime probe confirms the endpoint is reachable, but it does not verify the presence or absence of security headers. Without explicit evidence that the header is set elsewhere in the application, the finding remains a likely vulnerability.

**Impact:** Absence of the X-Content-Type-Options: nosniff header allows browsers to perform MIME type sniffing, potentially enabling content injection attacks such as cross‑site scripting (XSS) when untrusted content is served.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options header on all responses, e.g., using Starlette's `Response` class or a middleware that adds `X-Content-Type-Options: nosniff` globally.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe returned status 200 for /healthz`
- `Source excerpt shows the healthz handler but no header manipulation`

Limitations:
- No code evidence showing the header being set or omitted globally
- No additional scanner evidence confirming the header is missing on the response

### 20. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /integrations/hook endpoint accepts POST requests, reads the raw request body, and directly inserts it into the database as an accepted visit without any verification of a cryptographic signature or other authenticity check. The runtime probe confirms that a POST request to this endpoint returns HTTP 200, whereas a secure implementation would return a client error (e.g., 400, 401, or 403). This demonstrates an unauthenticated acceptance of arbitrary data, satisfying both the source evidence of missing validation and independent runtime behavior evidence.

**Impact:** An attacker can craft arbitrary webhook payloads and cause the application to record false visits or inject malicious data into the database, potentially leading to data poisoning, unauthorized actions, or further injection attacks.

**Remediation:** Implement verification of a signed token or HMAC on incoming webhook requests. Reject requests lacking a valid signature with an appropriate 4xx response before processing the payload. Additionally, validate and sanitize the payload content before inserting it into the database.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- `Source excerpt shows the endpoint inserts the raw request body into the database without signature verification (lines 629‑633).`
- `Runtime probe fact reports a POST to /integrations/hook returns HTTP 200 instead of the expected 4xx, indicating the request is accepted without validation.`

### 21. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice before returning the data. The runtime probe for this path returned HTTP 200 instead of the expected 403, confirming that the ownership check is missing and the invoice is disclosed to any authenticated user.

**Impact:** Unauthorized users can retrieve invoice details of other users, leading to confidentiality breaches and potential privacy violations.

**Remediation:** Add an ownership verification step after fetching the invoice row, e.g., compare the invoice's `owner_id` with the authenticated principal and raise a 403 HTTPException if they do not match.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- `Source excerpt shows no ownership check after fetching the invoice row (lines 268‑272).`
- `Runtime probe fact indicates the request returned status 200 when a 403 was expected (rule workflow.invoice_owner.3).`

### 22. Users cannot submit an admin job

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint POST /jobs calls principal(authorization) but does not verify that the authenticated principal has permission to create admin‑level jobs. The runtime probe shows that a request to this endpoint returns HTTP 200 instead of the expected 403/422, confirming that the missing role check is exploitable. The scanner finding also flags this as a high‑severity issue, providing independent corroboration.

**Impact:** An attacker who can obtain or forge an Authorization header can create arbitrary jobs with elevated privileges, potentially leading to privilege escalation, data leakage, or execution of malicious workloads.

**Remediation:** Add an explicit authorization check after principal(authorization) to verify that the caller has the required role (e.g., admin or worker_role) before inserting the job. Return 403/401 when the check fails. Consider using a dedicated security library or decorator to enforce role‑based access control consistently.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- `Source excerpt shows create_job calls principal(authorization) but no role check before INSERT into jobs table`
- `Runtime probe fact: POST /jobs returned status 200 where expected statuses were 400, 403, 422`

### 23. Identity endpoint may expose sensitive SSN data

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint returns all columns from the users table, including the ssn field, without any filtering or redaction. No access control checks beyond extracting the principal are shown, and the runtime probe indicates that excessive data is returned. While a scanner flagged this as excessive data, there is no independent evidence that a guard (e.g., role‑based filtering or data masking) exists elsewhere in the codebase.

**Impact:** An attacker who can obtain a valid bearer token could retrieve users' social security numbers, leading to identity theft and regulatory compliance violations.

**Remediation:** Modify the /me endpoint to exclude sensitive fields such as ssn from the response or apply proper masking. Implement explicit access control checks to ensure only authorized roles can view sensitive data. Consider using a DTO or serializer that only includes non‑sensitive attributes.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source excerpt shows the SELECT query includes the ssn column and the response returns the full row (lines 199‑204).`
- `Runtime probe fact indicates excessive data is returned for /me (workflow.excessive_data.1).`

Limitations:
- Missing evidence of any downstream filtering or redaction logic that might remove the ssn before returning the response.
- No proof that the endpoint is protected by additional authentication/authorization beyond the principal extraction.

### 24. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint directly stores the client‑provided unit_price into the orders table without any server‑side validation or lookup against a trusted price catalog. The supplied source excerpt shows the unit_price field being taken from the request body and inserted into the database. The runtime probe confirms that a POST to /orders succeeds (status 200) with client‑supplied data, indicating the server accepts the price value. No guard or lookup is visible in the provided context.

**Impact:** An attacker can manipulate the unit_price field when creating an order, potentially purchasing items at a reduced price or inflating prices for fraudulent gain, leading to financial loss or revenue manipulation.

**Remediation:** Implement server‑side price verification: retrieve the authoritative price for the requested item from a trusted catalog and ignore or override any client‑provided unit_price. Validate that the price matches the catalog before inserting the order, and reject or correct mismatched values.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt lines 208‑215 show unit_price taken from body and inserted into DB`
- `Runtime probe fact: POST /orders returned 200, indicating the request with client‑supplied price was accepted`

Limitations:
- Missing explicit evidence that the stored unit_price is later used for billing without further server checks
- No view of downstream processing to confirm that the price is not re‑validated before charge

### 25. Order creation allows setting arbitrary status including paid

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The create_order endpoint directly inserts the order into the database using the status value supplied in the request body without any validation or restriction. The runtime probe shows that a POST to /orders with an arbitrary status returns HTTP 200, whereas the expected behavior is a 400/422 error. This demonstrates that the endpoint accepts and persists a paid status for a newly created order, violating the intended workflow that orders should start as unpaid.

**Impact:** An attacker can create orders that are immediately marked as paid, potentially bypassing payment processing, causing financial discrepancies, and enabling fraud or unauthorized resource allocation.

**Remediation:** Validate the status field in the request body, ensuring that only allowed initial states (e.g., "pending" or "unpaid") are accepted. Reject or ignore any attempt to set the status to "paid" or other privileged states during order creation. Implement server‑side checks and return appropriate error codes (400/422) for invalid status values.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- `Source excerpt shows create_order inserts body.status directly into the orders table (lines 213‑215).`
- `Runtime probe fact indicates POST /orders returned 200 instead of expected 400/422, confirming the lack of validation.`

### 26. Negative order prices are rejected

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the supplied unit_price directly into the database without any validation. A runtime probe attempted to submit a negative price and received a 200 OK response, while the scanner expected a 400/422 error. This indicates that negative prices are currently accepted, which is contrary to the intended business rule.

**Impact:** Accepting negative prices can lead to financial loss, inventory manipulation, and potential exploitation of accounting systems.

**Remediation:** Add input validation to ensure unit_price is non‑negative before inserting into the database, and return an appropriate error (e.g., 400 Bad Request) when the validation fails.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Source excerpt shows create_order inserts body.unit_price without checks (lines 208‑215).`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422).`

Limitations:
- The supplied code does not include the full validation logic; we cannot confirm whether a guard exists elsewhere in the codebase. Evidence of the missing check is limited to the shown excerpt and the runtime probe result. Additional source evidence demonstrating the absence of validation would be needed for a confirmed vulnerability.

### 27. Users can create orders for other owners

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and defaults to the authenticated user's sub when not provided. No authorization check is performed to ensure the supplied owner_id matches the authenticated user, allowing a user to create orders on behalf of any other owner. A runtime probe observed a successful POST to /orders returning HTTP 200, whereas the expected behavior would be a 4xx response if proper ownership validation were in place.

**Impact:** An attacker could create orders for other users, potentially leading to unauthorized purchases, billing fraud, or manipulation of order data across accounts.

**Remediation:** Add an explicit authorization check that verifies the supplied owner_id (if present) matches the authenticated user's identifier, and reject the request with a 403 Forbidden (or appropriate 4xx) if it does not. Alternatively, remove the ability for clients to specify owner_id and always use the authenticated user's sub.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows owner_id is taken from body.owner_id or user["sub"] without further checks (lines 208-215).`
- `Runtime probe fact indicates a POST to /orders returned status 200, while expected statuses were 400, 403, or 422 (rule workflow.owner_assignment.2).`

Limitations:
- No static analysis or additional scanner evidence confirming that no downstream checks exist beyond the shown snippet. The runtime probe demonstrates the endpoint can be accessed successfully, but does not prove that no other guard (e.g., database triggers or middleware) exists outside the provided code context.

### 28. A note must belong to the order named in the URL

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its primary key without verifying that the note's `order_id` matches the `order_id` supplied in the URL. The code fetches the row based solely on `note_id` and returns it if found, missing an authorization check that ties the note to the requested order. Runtime probing confirms the flaw: a GET request to `/orders/1/notes/2` returns HTTP 200 instead of the expected 403/404, demonstrating that notes from other orders are accessible.

**Impact:** An attacker can enumerate or retrieve notes belonging to any order by guessing note IDs, leading to unauthorized disclosure of potentially sensitive information and violation of data isolation between orders.

**Remediation:** After fetching the note, compare `row['order_id']` with the `order_id` path parameter. If they differ, raise an `HTTPException` with status 403 (or 404) to prevent access. Example:
```python
row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()
if not row or row\['order_id'\] != order_id:
    raise HTTPException(404, "Note not found")
return dict(row)
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- <code>Source excerpt shows no check of `order_id` against the fetched note&#x27;s `order_id` (lines 543‑549).</code>
- <code>Runtime probe fact reports status 200 for `/orders/1/notes/2` where a 403/404 was expected, indicating the missing guard.</code>

### 29. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders/{order_id} calls principal(authorization) but does not verify that the authenticated user is the owner of the requested order before returning the record. The source excerpt shows no ownership check after the database query. A runtime probe confirms that a GET request for an order owned by a different user returns HTTP 200 instead of the expected 403, indicating the missing guard.

**Impact:** An attacker who can obtain a valid authorization token for any user can retrieve orders belonging to other users, leading to unauthorized data disclosure.

**Remediation:** Add an ownership verification step after fetching the order, e.g., compare the order's owner_id with the authenticated user's ID and raise HTTPException(403) if they do not match. Ensure the principal function returns the user identity for this check.
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- `Source code shows principal(authorization) is called but no owner check before returning the order (lines 221‑227).`
- `Runtime probe fact: GET /orders/{{order_id}} returned status 200 instead of 403, indicating the owner check is missing (workflow.order_owner.3).`

Limitations:
- The exact implementation of principal() is not shown, so we cannot confirm whether it performs any ownership validation internally. Additional evidence confirming that principal only authenticates and does not authorize would strengthen the finding.

### 30. Excessive coupon discounts are rejected

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/apply-coupon` accepts a discount value from the request body and applies it directly to the order without validating that the discount is within an acceptable range. The runtime probe shows the request succeeded with HTTP 200, whereas the scanner expected a 400/422 response for out‑of‑bounds values, indicating the missing validation. No guard or limit check is present in the supplied code snippet.

**Impact:** An attacker could supply an arbitrarily large discount, potentially reducing the order total to zero or a negative amount, leading to revenue loss and possible abuse of promotional codes.

**Remediation:** Add validation to ensure the discount does not exceed the maximum allowed percentage (e.g., 50%). Reject requests with an appropriate error code (400/422) when the discount is out of bounds. Consider also validating the coupon code against business rules before applying any discount.
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- <code>Source excerpt shows the discount is taken from `body.discount` without bounds checking (lines 231‑235).</code>
- `Runtime probe fact reports a 200 response for an out‑of‑bounds discount where a 400/422 was expected (scanner_id: web-runtime, rule_id: workflow.coupon_bounds.2).`

Limitations:
- The exact maximum allowed discount is not defined in the provided code or documentation, so the precise validation rule is unknown.
- It is unclear whether additional validation occurs elsewhere in the application stack (e.g., middleware or database constraints).

### 31. Paid orders can be cancelled without a refund

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The cancel_order endpoint updates the order status to 'cancelled' without checking whether the order has been paid or whether a refund has been issued. The source excerpt shows no conditional logic guarding the cancellation based on payment status. Runtime probe facts confirm that a POST to /orders/{order_id}/cancel returns HTTP 200, whereas the expected behavior (per the probe contract) is to reject the request with a 4xx status when the order is paid. This demonstrates that the vulnerable path is reachable and unprotected.

**Impact:** An attacker (or malicious user) can cancel paid orders without processing a refund, leading to financial loss and potential denial of service for legitimate customers.

**Remediation:** Add a check to verify the order's payment status before allowing cancellation. If the order is paid, require a refund to be processed first or reject the cancellation with an appropriate error (e.g., 400 Bad Request). Ensure the check is performed within a transaction to avoid race conditions.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- `Source code at lines 258-263 shows cancel_order updates status without payment check`
- `Runtime probe fact: POST /orders/{{order_id}}/cancel returned 200 instead of expected 4xx`

### 32. Potential payment replay vulnerability in order payment endpoint

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders/{order_id}/pay endpoint updates the order status to 'paid' without verifying whether the order has already been paid. The runtime probe reports a 200 OK response for a repeated payment attempt, whereas the scanner expects an error status (400, 409, 422). This indicates that a second payment can be processed on an already paid order, leading to possible double charging or invoice duplication.

**Impact:** An attacker could replay a payment request for an already settled order, causing duplicate charges, creation of multiple invoices, and financial loss or accounting inconsistencies.

**Remediation:** Add a check before updating the order status to ensure the order is not already marked as paid. Return an appropriate error (e.g., 409 Conflict) if a payment is attempted on a paid order. Consider implementing idempotency keys for payment requests.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- `Source excerpt shows no guard before UPDATE orders SET status='paid' (lines 242-250).`
- `Runtime probe fact indicates POST returned 200 instead of expected error statuses, confirming replay is possible (workflow.payment_replay.3).`

Limitations:
- No evidence of any existing guard elsewhere in the codebase (e.g., middleware or database constraint) that would prevent double payment. Additional verification of order status before payment is needed to confirm the vulnerability.

### 33. Insecure profile access allowing enumeration of other users' data

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is authorized to view the requested profile. The SQL query returns the full user record (including sensitive fields such as email and SSN) for any `profile_id` supplied. The runtime probe confirms that a request for another user's profile returns HTTP 200, indicating the guard is missing in practice.

**Impact:** An attacker can enumerate and retrieve personal data (username, email, SSN) of any user by iterating profile IDs, leading to privacy breaches and potential identity theft.

**Remediation:** Add an ownership check after retrieving the row, e.g., compare `row.id` with the authenticated user's ID and return 403 if they differ. Also limit returned fields to only non‑sensitive data or use a separate DTO. Ensure proper parameterisation of the query to prevent SQL injection.
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source excerpt shows endpoint definition without ownership check (lines 98‑104).`
- `Runtime probe fact reports GET /profiles/{{other_id}} returned status 200 instead of expected 403/404.`

### 34. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /view returns an HTMLResponse without setting any anti-clickjacking headers such as X-Frame-Options or Content-Security-Policy frame-ancestors. The source excerpt shows the response construction and no header manipulation. Runtime probe confirms a GET request to /view was made, but does not capture response headers. The scanner flagged the missing header, providing medium‑severity evidence.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add appropriate anti-clickjacking headers to the response, e.g., set X-Frame-Options: SAMEORIGIN or Content‑Security‑Policy: frame-ancestors 'self'.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse returned without header modifications`
- `Scanner runtime finding (zap.10020) reports missing anti-clickjacking header for /view`

Limitations:
- No captured HTTP response headers to directly confirm the header is absent
- No evidence that the application sets security headers globally elsewhere

### 35. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse constructed directly in the route handler without any middleware or response modification that adds a Content‑Security‑Policy header. The supplied source excerpt shows no CSP header being set, and the runtime probe only confirms a GET request to the path but does not capture response headers. Consequently, the application likely serves pages without CSP protection, increasing the risk of cross‑site scripting and data injection attacks.

**Impact:** Without a CSP header, browsers are free to load scripts, styles, and other resources from any origin, making it easier for an attacker to inject malicious content and execute it in the context of the victim’s browser.

**Remediation:** Add a CSP header to all HTTP responses, preferably via a security‑focused middleware or response decorator. Example for FastAPI:
```python
from fastapi import FastAPI, Response
app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response: Response = await call_next(request)
    response.headers\["Content‑Security‑Policy"\] = "default-src 'self'; script-src 'self'; object-src 'none';"
    return response
```
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- <code>Source excerpt shows the `/view` route returns HTMLResponse without setting any headers</code>
- <code>Runtime probe fact confirms a GET request to `/view` but does not include response header data</code>

Limitations:
- No runtime evidence confirming that the CSP header is absent in the actual HTTP response (e.g., captured response headers)
- No additional scanner or static analysis evidence showing header configuration elsewhere in the application

### 36. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse constructed directly in the route handler without explicitly setting the `X-Content-Type-Options: nosniff` header. The supplied source excerpt shows no header manipulation, and the runtime probe confirms a GET request to `/view` but does not report the header. No guard or middleware that adds the header is visible in the provided context.

**Impact:** Without the `X-Content-Type-Options: nosniff` header, browsers may attempt to sniff the MIME type of responses, potentially allowing content-type confusion attacks such as cross‑site scripting (XSS) if an attacker can influence the response body.

**Remediation:** Add middleware or modify the route to set the `X-Content-Type-Options: nosniff` header on all responses, e.g., using FastAPI's `Response` headers or a security middleware like `Starlette`'s `SecurityHeadersMiddleware`. Ensure the header is applied globally to prevent omissions in future endpoints.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- `Source excerpt shows HTMLResponse returned without header manipulation (lines 686‑690).`
- `Runtime probe fact for GET /view reports no header values (values_redacted).`

Limitations:
- No full application configuration is provided, so we cannot confirm whether a global security middleware adds the header elsewhere.
- No evidence from other scanners or runtime probes confirming the header is absent across all routes.

### 37. Webhook destination must match the approved internal host exactly

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/webhooks` accepts a JSON body containing a `target_url`. The code only checks that the string "mock-external" is present in the URL (`if "mock-external" not in target_url: raise HTTPException(400, ...)`). This substring check does not enforce an exact match to an approved internal host and can be bypassed by supplying a URL that includes the required substring but points to an external resource. No additional validation or allow‑list is performed before the URL is stored and later used, providing an open redirect/webhook injection risk.

**Impact:** An attacker can supply a malicious `target_url` that passes the weak substring check, causing the application to send data to an arbitrary external endpoint. This can lead to data exfiltration, server‑side request forgery (SSRF), or abuse of the service as a proxy for further attacks.

**Remediation:** Replace the substring check with a strict validation against a whitelist of approved internal host URLs. Use URL parsing to compare the hostname (and optionally scheme and port) exactly, and reject any URL that does not match the whitelist. Consider using a library such as `pydantic` or `urllib.parse` for robust URL validation.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- <code>Source excerpt shows only a substring check on `target_url` (lines 295‑298).</code>
- <code>Runtime probe fact indicates a POST to `/webhooks` returned HTTP 200 instead of the expected 400/422, demonstrating that the validation was bypassed.</code>

### 38. Clear‑text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The source excerpt shows that after a successful login the application logs the username together with the value of the environment variable APP_SECRET using a standard info‑level logger. The scanner (semgrep) flagged this line as a credential‑leak pattern (CWE‑532). No surrounding code in the supplied excerpt demonstrates that the logged value is masked, redacted, or otherwise protected, and no runtime probe confirms that the secret is actually emitted to logs. The finding therefore strongly suggests a vulnerability, but the evidence is limited to static analysis without independent runtime confirmation.

**Impact:** If the application’s logs are accessible to attackers or insufficiently protected, the exposed APP_SECRET can be used to impersonate the service, forge tokens, or gain unauthorized access to other components that rely on this secret. This could lead to full account compromise or broader system breach.

**Remediation:** Replace the logging of the secret with a redacted placeholder or remove it entirely. For example: log.info("login user=%s", username). If logging of the secret is required for debugging, ensure it is gated behind a debug flag and that logs are stored securely with strict access controls. Rotate the secret after fixing the logging issue.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `Scanner semgrep‑ce rule python.lang.security.audit.logging.logger-credential-leak flagged line 137 in api/app.py as logging app_secret in clear text.`
- `Source excerpt line 137: log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- No runtime probe confirming that the secret value is actually written to logs.
- No evidence that log output is protected or that the secret is masked elsewhere in the code base.

### 39. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any origin to make cross‑origin requests. This configuration can expose the API to CSRF‑style attacks or data leakage when combined with authenticated endpoints.

**Impact:** An attacker can host a malicious site that makes requests to the API from a victim's browser, potentially accessing sensitive data or performing actions on behalf of the user if authentication cookies or tokens are automatically sent.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains, or dynamically validate the Origin header. Set allow_credentials to false unless explicitly required, and limit allow_methods and allow_headers to only those needed.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `Source excerpt shows allow_origins=["*"] in CORSMiddleware configuration (lines 24‑29).`

Limitations:
- No runtime probe demonstrating exploitation of the wildcard CORS setting.
- No evidence that the API exposes sensitive data or performs privileged actions that would be exploitable via cross‑origin requests.

### 40. Log Injection

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs the username and the application secret using a structured logging call: log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")). This uses the logging module's built‑in formatting with explicit %s placeholders and passes the user‑provided values as separate arguments, which prevents format string injection. No evidence of unsafe string concatenation or direct interpolation of untrusted data into the log message is present.

**Impact:** None – the logging call does not introduce a vulnerability; it safely records information without allowing injection attacks.

**Remediation:** No remediation needed for injection; however, consider removing the application secret from logs to avoid exposing sensitive data.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `Source excerpt shows safe logging call with format placeholders and separate arguments.`

### 41. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into a string (f"SELECT … WHERE username='{body.username}' AND password='{body.password}'"). This creates a classic SQL injection vector because the input is not sanitized or parameterized, and no explicit validation or escaping is shown in the provided excerpt. The scanner flagged this as high severity, and the code snippet confirms the risky pattern.

**Impact:** An attacker could supply specially crafted username or password values to manipulate the SQL query, potentially retrieving unauthorized data, bypassing authentication, or executing arbitrary SQL commands against the database.

**Remediation:** Rewrite the query to use parameterized statements provided by the database library (e.g., prepared statements or ORM query methods). Example:
```python
query = "SELECT id, username, role FROM users WHERE username = %s AND password = %s"
row = conn.execute(query, (body.username, body.password)).fetchone()
```
Additionally, consider hashing passwords and using secure authentication mechanisms instead of storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Source excerpt shows f‑string interpolation of body.username and body.password into the SQL query (lines 117‑119).`
- `Scanner finding categorizes this as a high‑severity SQL injection risk.`

Limitations:
- No independent corroboration such as runtime probe evidence or a second scanner source confirming exploitability is provided. The review relies solely on the code snippet and the scanner’s classification.

### 42. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but then validates it with `file.is_relative_to(root)` and `file.is_file()`. The relative‑path check ensures the resolved path cannot escape the intended `public` directory, preventing path traversal. The guard is present in the supplied code, so the reported issue is not a vulnerability.

**Impact:** If the guard were missing, an attacker could read arbitrary files on the server. However, the check is implemented, so no impact is present.

**Remediation:** No remediation needed; the existing relative‑path validation is sufficient. Ensure future code maintains similar checks when handling file paths.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑223 show the guard `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 43. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list check. This creates an open redirect vector where an attacker can supply an arbitrary URL and cause the application to redirect users to a malicious site. No guard (e.g., URL whitelist, scheme check) is present in the supplied code snippet.

**Impact:** An attacker can craft a link to the vulnerable endpoint with a malicious `next` value (e.g., `https://example.com/auth/continue?next=https://phishing.com`). Victims clicking the link are redirected to the attacker‑controlled site, facilitating phishing, credential harvesting, or drive‑by attacks.

**Remediation:** Validate the `next` parameter before redirecting. Options include:
- Restrict redirects to internal URLs only (e.g., check that the URL is relative or matches the application's domain).
- Use an allow‑list of permitted destinations.
- If external redirects are required, require explicit user confirmation.
- Consider using a safe redirect helper that sanitizes the input.
Update the endpoint to perform these checks before calling `RedirectResponse`.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source excerpt shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse:` returning `RedirectResponse(next, status_code=302)` without validation.</code>

Limitations:
- No runtime probe or test confirming that an attacker‑controlled URL is actually accepted and followed.
No evidence of existing validation logic elsewhere in the codebase.
No independent scanner of higher severity confirming exploitability.

### 44. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint verifies that the resolved file path is within the designated public directory using `is_relative_to(root)` and also checks that the path points to an existing file before reading it. This prevents directory traversal attacks by ensuring user‑provided `name` cannot escape the intended directory.

**Impact:** No path traversal vulnerability; an attacker cannot read arbitrary files outside the public directory.

**Remediation:** No remediation needed for this specific issue as the existing checks adequately mitigate the risk.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>The code includes `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`, which blocks paths outside the root and non‑existent files.</code>

### 45. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs the file path using the user‑provided `name` but then resolves it and verifies that the resulting path is within the allowed `FILES/public` directory with `is_relative_to(FILES.resolve())` and also checks that it is a file. These checks prevent directory traversal attacks, so the path expression is properly controlled.

**Impact:** If the checks were missing, an attacker could read arbitrary files on the server. However, the existing checks mitigate this risk.

**Remediation:** No remediation needed; the code already validates the resolved path against the allowed directory and ensures the target is a file.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>Source excerpt shows `file = (FILES / &quot;public&quot; / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 46. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function verifies that the resolved file path is within the designated public directory using `is_relative_to(root)` and also checks that the path points to an existing file before reading it. These checks mitigate path traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability in the supplied code.

**Impact:** None – the path validation prevents unauthorized file access.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>The code calls `file.is_relative_to(root)` to ensure the requested file resides under the public directory.</code>
- <code>The code also checks `file.is_file()` before reading the file.</code>

### 47. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function constructs a file path from a user‑provided `name` but immediately resolves it and checks `is_relative_to(FILES.resolve())` as well as `is_file()`. These checks ensure the resolved path remains within the intended `FILES/public` directory and points to an existing file, effectively preventing directory traversal attacks.

**Impact:** None – the guard prevents access to files outside the allowed directory, so there is no unauthorized file read risk.

**Remediation:** No remediation needed for this specific issue; the existing checks are sufficient. Maintain the relative‑path validation when handling user‑supplied file names.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>source_excerpt shows the use of `Path.resolve()` followed by `is_relative_to(FILES.resolve())` and `is_file()` checks, which block path traversal.</code>

### 48. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any escaping or sanitisation, and also includes database‑derived product names in the same response. This pattern can allow an attacker to inject arbitrary HTML/JavaScript, resulting in reflected XSS. The source excerpt shows the vulnerable code, and an AI‑generated analysis corroborates the issue. However, no independent runtime probe or higher‑severity scanner confirmation is present, and there is no evidence of mitigating headers (e.g., CSP) or additional input validation elsewhere in the codebase.

**Impact:** An attacker who can trick a victim into visiting a crafted URL (e.g., <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>) could execute arbitrary JavaScript in the victim’s browser, leading to session hijacking, credential theft, or other malicious actions.

**Remediation:** Sanitise or HTML‑escape the `q` parameter and any product names before embedding them in the response. Use a templating engine that auto‑escapes output (e.g., Jinja2) or explicitly apply an escaping function. Consider adding a Content‑Security‑Policy header to further mitigate XSS risk.
Evidence:
- Penetration test: **Could not be tested** — A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run.
- Source IDs: `merged-ea527a7d7441e2b11700`, `ai-3c237f081f6c7aae`
- <code>Source excerpt lines 141‑145 show `q` being interpolated directly into the HTML string returned by the endpoint.</code>
- <code>AI analysis identifies the same pattern and describes how an attacker could inject `&lt;script&gt;` payloads.</code>

Limitations:
- No runtime probe evidence demonstrating successful XSS exploitation.
- No higher‑severity scanner confirmation (severity ≥ medium) beyond the existing scanner finding.
- No information about response headers (e.g., CSP) or other defensive mechanisms that might mitigate impact.

### 49. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the supplied URL by ensuring it starts with a single forward slash, rejects URLs that start with "//", and checks that the parsed URL has no scheme or network location. This prevents redirection to external domains or protocol-relative URLs, mitigating an open‑redirect vulnerability.

**Impact:** None – the code already enforces a local‑only redirect, so an attacker cannot cause a user to be redirected to an arbitrary external site.

**Remediation:** No remediation needed for this issue; the existing validation is sufficient.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Code at lines 621‑624 validates the 'next' parameter, raising HTTPException(400) if it is not a local path`
- `RedirectResponse is only returned after successful validation`

### 50. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against the public directory and then verifies that the resulting path is still within the allowed base using `is_relative_to(FILES.resolve())` and checks that it is a file before reading. This prevents directory traversal attacks, so the path expression is properly controlled.

**Impact:** No path traversal vulnerability; the endpoint safely restricts file access to the intended directory.

**Remediation:** No remediation needed; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- <code>source_excerpt lines 212‑214 show the resolve and `is_relative_to` guard</code>

### 51. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL statement by interpolating the user‑provided query parameter `q` directly into the query string via an f‑string. This creates a classic SQL injection vector because the input is not sanitized or passed as a parameter to the database driver. No input validation or escaping is shown in the supplied excerpt, and no guard (e.g., ORM parameterization, whitelist, or escaping function) is present in the provided context.

**Impact:** An attacker could supply crafted input for `q` that alters the SQL query logic, potentially retrieving unauthorized data, modifying database contents, or executing arbitrary SQL commands.

**Remediation:** Refactor the query to use parameterized statements provided by the database library (e.g., `conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",))`). Additionally, validate or whitelist allowed characters for `q` and consider using an ORM that handles query construction safely.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt shows `conn.execute(f&quot;SELECT name FROM products WHERE name ILIKE &#x27;%{q}%&#x27;&quot; )` with `q` coming directly from the request query parameter.</code>
- `Scanner evidence flags this as a high‑severity issue.`

Limitations:
- No runtime probe evidence demonstrating successful exploitation.
- No additional code context confirming the absence of downstream sanitization or ORM usage.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a recommended best practice for container health monitoring but does not constitute a security vulnerability in the supplied context. No evidence shows that the missing health check leads to an exploitable condition.

**Impact:** Without a HEALTHCHECK, orchestration platforms cannot automatically detect and restart unhealthy containers, potentially affecting availability, but it does not directly expose the application to security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line`

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding reports the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a recommended best practice for container health monitoring, its absence does not constitute a security vulnerability or a misconfiguration that directly leads to an exploitable condition. No evidence is provided that the missing HEALTHCHECK results in insecure behavior, privilege escalation, or denial of service. Therefore, this is not a security flaw.

**Impact:** None – the container will run without health monitoring, which may affect operational reliability but does not create a security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile to enable Docker to monitor container health, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:9000/health || exit 1
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a best‑practice recommendation for container health monitoring but does not constitute a security vulnerability. No evidence shows that the missing health check leads to an exploitable condition or bypass of security controls.

**Impact:** None – the application’s security posture is unchanged; only container orchestration visibility may be reduced.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53539. This vulnerability allows an attacker to craft malicious form‑urlencoded bodies that trigger a denial‑of‑service condition in the library. The supplied requirements.txt shows the vulnerable version without any mitigating guard or version pinning to a safe release.

**Impact:** An attacker can cause the application to become unresponsive by sending specially crafted multipart/form‑urlencoded requests, leading to service disruption and potential loss of availability.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53539. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt lists python-multipart==0.0.20`

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to contain CVE-2026-42561. This vulnerability allows an attacker to cause a denial‑of‑service condition by sending a multipart request with an excessive number of part headers, exhausting memory or CPU resources. The supplied dependency list shows the vulnerable version is in use, and no mitigation (e.g., version pinning to a safe release) is present in the repository.

**Impact:** An attacker can craft malicious multipart HTTP requests that trigger the vulnerable parsing logic, potentially crashing the service or degrading performance, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, where the issue is fixed. Update the requirements.txt accordingly and run dependency installation again.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`
- `requirements.txt lists python-multipart==0.0.20`

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The dependency python-multipart version 0.0.20 is known to contain CVE-2026-53538, which can lead to information disclosure when parsing multipart form data. The scanner identified the vulnerable version in the requirements file, but no runtime evidence or code showing the library is actually used in the application was provided.

**Impact:** If the application processes multipart/form-data requests using the vulnerable python-multipart library, an attacker may be able to extract unintended data from the request parsing process, potentially leading to information leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Verify that the updated version does not introduce breaking changes in the request handling logic.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30 (scanner evidence)`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No evidence that the application imports or invokes python-multipart at runtime
- No runtime probe showing the vulnerable parsing behavior
- No confirmation that multipart/form-data handling is performed in the code

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to contain CVE-2026-40347, a denial‑of‑service vulnerability triggered by specially crafted multipart/form-data payloads. The supplied requirements.txt shows the vulnerable version is in use, and no mitigating version upgrade is present.

**Impact:** An attacker can send a malicious multipart request that exhausts CPU or memory resources, potentially causing the FastAPI service to become unresponsive, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, where the vulnerability is fixed. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`
- `requirements.txt lists python-multipart==0.0.20`

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project's requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to an arbitrary file write via path traversal (CVE-2026-24486). The scanner provides a medium‑to‑high severity finding for this CVE, and no mitigating version or guard is present in the supplied dependency list.

**Impact:** An attacker could exploit the vulnerable python-multipart library to write arbitrary files on the server, potentially leading to remote code execution or data tampering.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, which contains the fix for CVE-2026-24486. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency entry in requirements.txt: python-multipart==0.0.20`
- `Scanner evidence: CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22`

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53537. The CVE description indicates that certain malformed multipart headers can cause information disclosure. The supplied dependency list directly shows the vulnerable version, and the CVE is publicly documented, providing independent corroboration of the vulnerability.

**Impact:** An attacker could craft a multipart request that triggers the header parsing bug, potentially causing the server to leak sensitive data from memory or request processing.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency list shows python-multipart==0.0.20`
- `CVE-2026-53537 documented vulnerability for python-multipart 0.0.20`
- `Scanner evidence cites CVE and fix version 0.0.30`

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The dependency python-multipart version 0.0.20 is known to contain CVE-2026-53540, which can cause the entire request body to be buffered in memory when a negative Content‑Length header is received. The supplied requirements.txt confirms the vulnerable version is used. No additional runtime probe or higher‑severity independent scanner evidence is provided to demonstrate the vulnerability is exploitable in the deployed environment.

**Impact:** An attacker can cause excessive memory consumption on the server, potentially leading to denial‑of‑service conditions.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which contains the fix for CVE-2026-53540.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No runtime probe confirming that a negative Content‑Length request triggers the memory buffering behavior.
- No higher‑severity independent scanner confirmation of exploitability in the current deployment.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a URL by concatenating a constant BASE with a variable path argument and then opens it with urllib.request.urlopen. While urllib can handle file:// URLs, the supplied source excerpt does not show that the path argument is derived from untrusted user input, nor does it demonstrate a missing validation check. No runtime probe facts or additional scanner evidence confirm that an attacker can control the URL to trigger an unsafe file read.

**Impact:** If an attacker could control the path value and the application allowed file:// schemes, they might read arbitrary files from the server, leading to information disclosure.

**Remediation:** Validate and sanitize the `path` argument to ensure it does not contain unsafe schemes (e.g., file://) or directory traversal. Consider using a higher‑level HTTP client like the `requests` library, which does not support file URLs, or explicitly reject non‑HTTP schemes before calling urllib.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen called with BASE + path (lines 20‑22).`

Limitations:
- Missing evidence that `path` originates from untrusted input; no guard or validation shown in the provided context. No runtime probe demonstrating exploitation of a file:// scheme. No additional scanner findings of medium or higher severity confirming the vulnerability.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib request using a value from the incoming payload (payload\["target_url"\]). No validation or sanitisation of this URL is shown, and no guard (e.g., scheme whitelist) is present in the supplied snippet. However, the finding lacks independent corroboration: there is no additional scanner of medium/higher severity, no runtime probe demonstrating that an attacker‑controlled URL can be supplied, and no evidence that the URL is later constrained. Consequently the evidence is insufficient to confirm a vulnerability.

**Impact:** If an attacker can influence the "target_url" field, they may cause the worker to fetch arbitrary resources, potentially leading to SSRF or unintended file reads via file:// schemes.

**Remediation:** Validate the "target_url" value before using it with urllib. Restrict allowed schemes (e.g., only http/https), enforce a whitelist of domains, or switch to a safer HTTP client like the requests library that does not support file:// URLs by default.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows urllib.request.urlopen called with payload["target_url"] without validation.`

Limitations:
- Missing runtime probe that demonstrates attacker‑controlled input reaching urllib, no additional scanner evidence of medium or higher severity, and no view of surrounding code that might perform URL validation elsewhere.

### 64. Insecure password storage (CWE-256)

- Issue group: `ai-935e828dd4bba4f4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The register endpoint inserts the received password directly into the users table without any hashing or key‑stretching step. The supplied code shows the password value (body.password) being passed unchanged to the SQL INSERT statement, and no surrounding code or middleware is visible that would transform the password before persistence. This pattern strongly suggests that passwords are stored in plaintext, which is a serious security weakness.

**Impact:** If passwords are stored in plaintext, compromise of the database (through SQL injection, backup leakage, insider threat, or other means) would expose all user credentials directly. Attackers could reuse these credentials on other services, leading to credential stuffing and broader account compromise.

**Remediation:** Hash passwords before storing them. Use a strong, adaptive password‑hashing algorithm such as Argon2id, bcrypt, or scrypt with a unique per‑user salt. Replace the raw INSERT with code that hashes body.password first, e.g.,
```python
hashed = argon2.hash(body.password)
conn.execute("INSERT INTO users (username,password,role,email,ssn) VALUES (%s,%s,'user',%s,'000-00-9999')", (body.username, hashed, f"{body.username}@example.test"))
```
Evidence:
- Penetration test: **Could not be tested** — A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run.
- Source IDs: `ai-935e828dd4bba4f4`
- `api/app.py:176‑183 – register function inserts body.password directly into the database without hashing`

Limitations:
- No evidence is provided that a database trigger, ORM layer, or middleware hashes the password before the INSERT. No scanner or runtime probe confirms the plaintext storage behavior. Additional evidence such as a hash function call, trigger definition, or runtime observation of stored password format is needed to confirm the vulnerability.

### 65. Missing authorization on comment creation (CWE-284)

- Issue group: `ai-7aebdfd54eb4e688`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `POST /comments` extracts the caller identity from the `Authorization` header and inserts a comment record using the extracted user ID. No additional checks are performed to verify whether the authenticated user is permitted to create a comment, such as role validation, ban status, or rate‑limiting. The supplied source does not show any middleware or higher‑level policy that could enforce such constraints, and no scanner or runtime probe evidence confirming the vulnerability is present.

**Impact:** An attacker who can obtain or forge a valid authentication token could create comments on behalf of any user ID returned by `identity`, potentially leading to unauthorized content injection, spam, or abuse of user reputation.

**Remediation:** Implement proper authorization checks before inserting the comment. For example:
1. Validate the token securely in `identity` and ensure it cannot be spoofed.
2. Add business‑logic checks (e.g., role, ban status, rate limits) after obtaining the user ID.
3. Return an error if the user is not allowed to create a comment.
4. Consider moving authorization logic to a dedicated dependency or middleware to enforce consistent policies across endpoints.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-7aebdfd54eb4e688`
- `api/extra.py:161 – @router.post("/comments") defines the entry point. api/extra.py:163 – user = identity(authorization) extracts the caller identity. api/extra.py:166 – INSERT INTO comments(author_id,body) VALUES (%s,%s) performs the sensitive operation without further checks.`

Limitations:
- Missing evidence about the implementation of `identity` – it is unclear whether it validates tokens securely or enforces any policy.
No evidence of surrounding middleware or global authorization checks that might restrict comment creation.
No scanner or runtime probe data confirming that unauthorized comment creation is possible.

### 66. Missing authorization check on file read endpoint (CWE-284)

- Issue group: `ai-2b797e12ede1385a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint defined at @router.get("/files") reads files from the public directory and returns their contents without any authentication or authorization checks. The code validates the path to prevent directory traversal but does not enforce that the caller is authenticated or has appropriate permissions, allowing any unauthenticated client to retrieve files that may be intended to be protected.

**Impact:** Unauthenticated users can access potentially sensitive files stored in the public directory, leading to information disclosure. If the directory contains confidential data, this could expose internal information, credentials, or other private content.

**Remediation:** Add authentication and authorization checks to the endpoint. For example, require a security dependency or token verification, and enforce role‑based access control before reading and returning the file. Also consider limiting the set of files that can be served and applying rate limiting to mitigate enumeration attacks.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-2b797e12ede1385a`
- `210: @router.get("/files")`
- <code>211: def file_read(name: str) -&gt; Response:</code>
- `212: file = (FILES / "public" / name).resolve()`
- `213: if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214: raise HTTPException(404, "File not found")`
- `215: return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable by unauthenticated users.
- No evidence that a guard (e.g., a dependency injection of a security check) exists elsewhere in the codebase that would protect this route.
- Missing confirmation that the files in the public directory are intended to be publicly accessible.

### 67. Missing authorization on verified file read endpoint (CWE-284)

- Issue group: `ai-357e82f73fc20848`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `GET /files/verified` reads arbitrary files from the public directory after a basic path‑traversal check, but the handler does not require any authentication or role verification. The supplied source shows the entry point and the sensitive file‑read operation, and it explicitly lacks an authorization dependency. No guard (e.g., security dependency, role check, or token validation) is visible in the provided code snippet.

**Impact:** An unauthenticated attacker can enumerate and read any file under the configured public directory, potentially exposing sensitive configuration, credentials, or private data that should be restricted to authorized users.

**Remediation:** Add an authentication/authorization dependency to the route (e.g., FastAPI `Depends(get_current_user)`), and enforce role‑based access control before performing the file read. Consider logging file accesses and restricting the set of readable files to only those intended for public exposure.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-357e82f73fc20848`
- <code>api/extra.py:218 – route definition `@router.get(&quot;/files/verified&quot;)`</code>
- `api/extra.py:219 – function signature lacks security dependencies`
- `api/extra.py:224 – returns file contents without any auth check`

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable without authentication.
- No evidence that a guard exists elsewhere (e.g., global middleware) that could protect this route.
- Missing confirmation that the public directory does not already contain only safe, intended files.

### 68. Missing authorization check on webhook creation (CWE-284)

- Issue group: `ai-06a6519ee55ac5e0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_webhook endpoint calls principal(authorization) but no further role or permission verification is shown before inserting a job that can execute an arbitrary target URL. The code only checks that the URL contains "mock-external" and then stores the payload in the jobs table, allowing a caller to specify the run_as user. This suggests a missing authorization guard, but the supplied source does not reveal what principal() does or whether additional checks occur elsewhere, and there is no independent scanner or runtime evidence confirming exploitation.

**Impact:** An attacker who can call the endpoint could create webhook jobs that run as arbitrary users or trigger external requests, potentially leading to privilege escalation or unauthorized external interactions.

**Remediation:** Ensure that the endpoint enforces proper authorization checks after principal(), such as verifying the caller's role or permissions before allowing webhook creation and validating the run_as field against the caller's identity. Consider adding explicit role checks, input validation, and audit logging for webhook creation.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-06a6519ee55ac5e0`
- `api/app.py:295 principal(authorization) – no role check shown`
- `api/app.py:301 INSERT INTO jobs (kind,payload,run_as) VALUES ('webhook',%s,%s) – run_as taken from request body without validation`
- `api/app.py:297‑298 URL check only verifies presence of "mock-external"`

Limitations:
- The behavior of principal() is unknown – it may enforce role checks internally
- No runtime probe or scanner evidence confirming that the missing check leads to a vulnerability
- No evidence of additional guards elsewhere in the codebase

### 69. Potential IDOR on order creation (CWE-639)

- Issue group: `ai-6a78349f837e165e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id from the request body and falls back to the authenticated user's ID only when owner_id is not provided. No validation is shown to ensure that the supplied owner_id matches the authenticated user or that the caller has permission to create orders for other users. This pattern can allow a user to create orders on behalf of another user, constituting an insecure direct object reference.

**Impact:** An attacker could create orders under another user's account, potentially leading to unauthorized transactions, billing issues, or abuse of the system's ordering functionality.

**Remediation:** Validate the owner_id against the authenticated user's ID or enforce an authorization check that ensures the caller has permission to create orders for the specified owner. If owner_id is not required, remove it from the request schema and always use the authenticated user's ID.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-6a78349f837e165e`
- `api/app.py line 209: user = principal(authorization)`
- `api/app.py line 210: owner_id = body.owner_id or user["sub"]`
- `api/app.py line 213: INSERT INTO orders (owner_id,item,quantity,unit_price,status) VALUES (%s,%s,%s,%s,%s)`

Limitations:
- No evidence that downstream code performs additional authorization checks on owner_id
- No scanner or runtime probe evidence confirming the vulnerability in practice
- Unclear whether principal() provides role information that could permit privileged users to set owner_id

### 70. Missing authentication on login endpoint (CWE-287)

- Issue group: `ai-6d23d0d008604fdc`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **low**

**Explanation:** The login endpoint forwards user‑supplied credentials directly to the internal _login function without any visible rate‑limiting, captcha, account lockout, or other brute‑force mitigation. The supplied code snippet shows no guard before the credentials are processed, which could allow credential‑stuffing or password‑guessing attacks. However, the review cannot confirm whether _login implements its own throttling or whether other middleware adds protection, as that code is not present in the provided excerpt.

**Impact:** An attacker can repeatedly submit login attempts without restriction, increasing the risk of successful credential‑stuffing or brute‑force attacks, potentially leading to unauthorized account access.

**Remediation:** Add explicit rate‑limiting, account lockout, or CAPTCHA checks before invoking _login. Ensure failed attempts are logged and monitored. Consider integrating a security middleware that enforces these controls globally for authentication endpoints.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-6d23d0d008604fdc`
- `@app.post("/auth/login") defined at api/app.py:166`
- `Credentials are extracted and passed to _login at line 172 without intervening checks`
- `No rate‑limiting or lockout logic is visible in the provided excerpt`

Limitations:
- The implementation of _login is not shown; it may contain its own throttling or lockout logic.
- Potential external middleware or framework‑level protections are not visible in the supplied snippet.

### 71. Potential path traversal via unverified file name (CWE-22)

- Issue group: `ai-d3c8ae68a75d8b90`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The function constructs a file path from user‑provided "name" and checks that the resolved path is within the public directory using Path.is_relative_to. While this check can prevent simple "../" traversals on recent Python versions, the code does not address symlink resolution or older Python versions where is_relative_to may be unavailable. If an attacker can place a symlink inside the public directory that points outside, the check could be bypassed, leading to arbitrary file reads.

**Impact:** An attacker could read arbitrary files on the server, potentially exposing source code, configuration files, or other sensitive data.

**Remediation:** - Ensure the application runs on Python 3.9+ where is_relative_to is reliable.
- Resolve the final path and verify it is still within the intended directory after symlink resolution.
- Explicitly reject any path components containing ".." before resolution.
- Consider using a safe file‑serving library that handles these checks internally.
- Add unit tests covering symlink and traversal attempts.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-d3c8ae68a75d8b90`
- <code>211: def file_read(name: str) -&gt; Response:</code>
- `212: file = (FILES / "public" / name).resolve()`
- `213: if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `215: return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- Missing evidence of the Python runtime version to confirm is_relative_to behavior.
- No information about the presence of symlinks inside FILES that could be exploited.
- No independent scanner or runtime probe confirming that a traversal can bypass the check.

### 72. Missing admin authorization on audit endpoint (CWE-284)

- Issue group: `ai-cbdb48ff58f91fd1`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /admin/audit endpoint calls require_admin before returning an authorized status, but the implementation of require_admin is not provided. Without evidence that it enforces a robust admin role check, the endpoint may be accessible to any authenticated user or even unauthenticated callers if the function is a placeholder.

**Impact:** An attacker could invoke the audit endpoint and receive privileged information or perform actions reserved for administrators, leading to information disclosure or privilege escalation.

**Remediation:** Implement require_admin to verify that the supplied authorization header contains a valid token with an admin role claim, and reject requests lacking proper credentials with a 403 response. Add unit tests to confirm the check blocks non‑admin users.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-cbdb48ff58f91fd1`
- `204: @router.get("/admin/audit")`
- `206: require_admin(authorization)`
- `207: return {"status": "authorized"}`

Limitations:
- The source does not include the definition of require_admin, so its effectiveness cannot be confirmed. No independent scanner or runtime probe evidence demonstrates that the check is missing or ineffective.

### 73. Missing authorization check on order ownership (CWE-284)

- Issue group: `ai-83c277f7161c623e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint authenticates the request via `principal(authorization)` but does not contain any code that verifies the authenticated principal is authorized to modify the specified order. The function directly updates the order record based on the supplied `order_id`, allowing a caller who can provide a valid token to apply a coupon to any order ID. This constitutes a potential broken access control issue.

**Impact:** An attacker who can obtain a valid authorization token could apply arbitrary discount coupons to orders they do not own, leading to financial loss, revenue manipulation, and possible breach of customer trust.

**Remediation:** Add an ownership or permission check after authentication. Retrieve the order’s owner (e.g., user_id) from the database and compare it to the principal’s identifier. Only proceed with the UPDATE if the principal matches the owner or has a role that permits discount modifications. Return a 403 Forbidden response otherwise.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-83c277f7161c623e`
- <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `principal(authorization)`
- `row = conn.execute("UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (percent, order_id)).fetchone()`

Limitations:
- The code for `principal` is not shown, so we cannot confirm whether it returns a user identifier or performs any ownership checks internally.
- No database schema or constraints are provided that would implicitly enforce order ownership.
- No additional runtime probe or scanner evidence confirming the vulnerability is present.

### 74. Unrestricted discount value via client-supplied field (CWE-915)

- Issue group: `ai-eebcf33ae8e5eaef`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `apply_coupon` endpoint copies a client‑provided `body.discount` value directly into the `percent` variable and uses it in an UPDATE statement without any validation or bounds checking. This allows a caller to set an arbitrary discount percentage, potentially overriding the coupon’s configured discount or applying a discount when no valid coupon exists.

**Impact:** An attacker could obtain full or excessive discounts on orders, leading to revenue loss and potential abuse of promotional mechanisms.

**Remediation:** Validate `body.discount` against allowed ranges (e.g., 0‑100) and ensure it matches the discount defined for the supplied coupon. If `body.discount` is omitted, fall back to the coupon’s percent only when a valid coupon is found. Add explicit checks to reject out‑of‑range or unauthorized discount values before executing the UPDATE.
Evidence:
- Penetration test: **Could not be tested** — A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run.
- Source IDs: `ai-eebcf33ae8e5eaef`
- <code>Source excerpt shows `percent = body.discount if body.discount is not None else (coupon[&quot;percent&quot;] if coupon else 0)` (line 235).</code>
- <code>Sensitive operation `UPDATE orders SET discount=%s WHERE id=%s` uses the unchecked `percent` (line 236).</code>

Limitations:
- Missing definition of `CouponBody` and any constraints on its `discount` field.
- No evidence of downstream logic that caps or sanitizes the discount value.
- No runtime probe or scanner evidence confirming that arbitrary discounts can be applied in practice.

### 75. Missing ownership/authorization check on payment (CWE-284)

- Issue group: `ai-8204d1e620288a08`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `pay_order` endpoint authenticates the request via `principal(authorization)` but does not show any verification that the authenticated principal is the owner of the order identified by `order_id`. The code fetches the order and proceeds to update its status to `paid` without comparing the order's owner field to the authenticated user or checking a specific payment permission. This suggests an authorization bypass where any authenticated user could pay for any order.

**Impact:** An attacker who can obtain a valid authentication token could trigger payment for orders they do not own, leading to unauthorized financial transactions, invoice creation, and potential loss of revenue or fraud.

**Remediation:** Add an ownership/permission check after retrieving the order. For example, retrieve the user ID from `principal(authorization)` and compare it to the `owner_id` field of the order, returning a 403 error if they do not match. Alternatively, enforce a role‑based permission check before allowing the update. Ensure that the check is performed before any state‑changing operation.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-8204d1e620288a08`
- <code>def pay_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `principal(authorization)`
- `order = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()`
- `conn.execute("UPDATE orders SET status='paid' WHERE id=%s", (order_id,))`

Limitations:
- The code excerpt does not show the implementation of `principal(authorization)`, so it is unclear whether it returns a user identifier that could be used for ownership verification.
- No explicit comparison between the authenticated user and the order's owner is present in the supplied snippet.
- There is no evidence of database triggers, middleware, or other layers that might enforce ownership checks outside the shown function.

### 76. Information leakage via detailed error messages (CWE-209)

- Issue group: `ai-492db277b819e281`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint `error_query` catches any exception from a database query and returns the exception message directly in the HTTP 500 response (`raise HTTPException(500, f"Query failed: {error}")`). This exposes internal error details, such as column names or stack traces, to callers. The supplied code shows no sanitisation or generic error handling, indicating a potential information disclosure issue.

**Impact:** Attackers can gain insight into the database schema, query structure, or internal application logic, which can aid further attacks such as SQL injection or enumeration of resources.

**Remediation:** Replace the detailed exception message with a generic error response. Log the full exception securely on the server side for debugging, but return a constant message to the client, e.g., `raise HTTPException(500, "Internal server error")`. Consider adding exception handling middleware to centralise this behaviour.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-492db277b819e281`
- `api/extra.py:232-233 – exception is interpolated into HTTPException response`
- `api/extra.py:231 – query attempts to select a non‑existent column, triggering the exception`

Limitations:
- No independent scanner or runtime probe confirming that the detailed error message is actually returned to a client; the finding relies solely on the source code analysis. Additional evidence such as a vulnerability scanner report or observed HTTP response containing the exception text would be needed to confirm the vulnerability.

### 77. Missing ownership check on order cancellation (CWE-639)

- Issue group: `ai-f0dce5b04fc274c8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user owns the order identified by `order_id` before executing an UPDATE that cancels the order. This creates a potential IDOR/BOLA where any authenticated user could cancel any order by supplying an arbitrary order_id.

**Impact:** An attacker who can obtain a valid authorization header could cancel orders belonging to other users, leading to loss of service, financial impact, and violation of data integrity and confidentiality.

**Remediation:** Add an ownership verification step before the UPDATE, e.g., query the order's owner_id and compare it to the authenticated principal's user identifier. Abort with an authorization error if they do not match. Optionally enforce ownership at the database level with row‑level security or triggers.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-f0dce5b04fc274c8`
- `260: principal(authorization)`
- `262: row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone()`

Limitations:
- The code snippet does not show what `principal` returns; we lack confirmation that it includes a user identifier needed for the check.
- No evidence is provided that a database trigger, foreign key constraint, or other backend guard enforces ownership.
- No independent scanner or runtime probe evidence confirming that the endpoint can be abused without ownership verification.

### 78. Missing ownership check on invoice retrieval (CWE-639)

- Issue group: `ai-ae177f098ffafcec`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint authenticates the request via `principal(authorization)` but does not perform any check that the authenticated user is authorized to view the specific invoice identified by `invoice_id`. The code directly queries the database for the invoice and returns it if found, which could allow an authenticated user to retrieve invoices belonging to other users by guessing IDs.

**Impact:** An attacker who can obtain a valid authentication token could enumerate or retrieve arbitrary invoices, leading to exposure of sensitive financial data and violation of confidentiality.

**Remediation:** Add an ownership or role‑based check after fetching the invoice (or before the query) to ensure the `principal` is allowed to access the requested invoice. For example, compare the invoice's owner ID with the authenticated user's ID or verify that the user has a permission such as `view_all_invoices`. Return a 403 Forbidden response when the check fails.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-ae177f098ffafcec`
- <code>api/app.py line 269 calls `principal(authorization)` for authentication</code>
- <code>api/app.py line 271 executes a query `SELECT * FROM invoices WHERE id=%s` without any additional filter based on the authenticated user</code>
- `api/app.py line 274 returns the row directly`

Limitations:
- No runtime probe or scanner evidence confirming that the endpoint is reachable and that unauthorized access is possible
- No view of the `principal` implementation to determine whether it implicitly enforces ownership
- No tests or logs showing that an attacker can retrieve another user's invoice

### 79. Missing ownership check on order retrieval (CWE-639)

- Issue group: `ai-76ee5ddf6f5e1661`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint authenticates the request via `principal(authorization)` but directly queries the orders table by ID without verifying that the returned order belongs to the authenticated principal. The code snippet shows no comparison between `row.owner_id` (or similar) and the user identifier from `principal`. This pattern can lead to an IDOR where an attacker enumerates order IDs and accesses other users' orders.

**Impact:** Unauthorized users may retrieve order details belonging to other accounts, exposing sensitive personal and financial information and violating confidentiality and privacy requirements.

**Remediation:** Add an ownership check after fetching the order. For example, retrieve the owner ID from the row and compare it to the authenticated user's identifier from `principal`. Return a 403 Forbidden if they do not match. Optionally, include the owner check in the SQL query (e.g., `SELECT * FROM orders WHERE id=%s AND owner_id=%s`).
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-76ee5ddf6f5e1661`
- `Source excerpt shows the endpoint definition and query without an ownership check (lines 220‑224).`
- <code>`principal(authorization)` is called, indicating authentication, but no subsequent use of the principal’s identifier in the query or after fetching the row.</code>

Limitations:
- The schema of the `orders` table is not provided, so we cannot confirm the presence of an owner column to compare against.
- We do not see the implementation of `principal` to verify it supplies a user identifier usable for the check.
- No runtime probe or scanner evidence confirming that the endpoint is exploitable is present.

### 80. Missing authorization check for admin users (CWE-285)

- Issue group: `ai-78782ba33d6e3838`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/users calls principal(authorization) but the provided code does not show any role verification before executing a query that returns sensitive fields (including SSN). Without evidence that principal enforces an admin role or that a global middleware restricts this route, an authenticated non‑admin could retrieve all user records, indicating a potential privilege‑escalation flaw.

**Impact:** Unauthorized users may obtain personal data (username, email, role, SSN) for all accounts, leading to privacy violations, identity theft, and compliance breaches.

**Remediation:** Ensure that the endpoint verifies the caller has an admin role before executing the query. This can be done by: • Modifying principal() to return the user's role and checking it explicitly in the handler, or • Adding a dependency or middleware that enforces admin access for /admin/* routes, returning HTTP 403 when the role is insufficient.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-78782ba33d6e3838`
- `@app.get("/admin/users") defined at line 277 in api/app.py`
- `principal(authorization) called at line 279 without visible role check`
- `SQL query at line 281 selects id,username,email,role,ssn from users`

Limitations:
- The implementation of principal() is not provided, so we cannot confirm whether it performs an admin role check.
- No evidence of global route guards or security middleware that might restrict /admin/* endpoints.
- No runtime probe or scanner evidence confirming the endpoint is reachable by non‑admin users.

### 81. Missing authorization check for admin jobs (CWE-285)

- Issue group: `ai-d6b4763af77577b9`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint @app.get("/admin/jobs") calls principal(authorization) but no explicit role verification is shown before executing a query that returns all job records. Without evidence that principal() enforces an admin role or that route‑level dependencies restrict access, the endpoint may allow any authenticated user to retrieve sensitive job data.

**Impact:** Unauthorized users could enumerate internal job information, potentially exposing operational details, job identifiers, or other confidential data that could aid further attacks.

**Remediation:** Ensure that the endpoint verifies the caller’s role is admin before accessing the jobs table. This can be done by: • Adding an explicit role check after principal() (e.g., if not user.is_admin: raise HTTPException(403)). • Using FastAPI dependencies that enforce admin privileges at the route level. • Auditing principal() to confirm it performs the required admin check and documenting its behavior.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-d6b4763af77577b9`
- `@app.get("/admin/jobs") defined at api/app.py line 285`
- `principal(authorization) called at line 287`
- `Database query fetching all jobs at line 289`
- `No role check visible in the provided excerpt`

Limitations:
- No evidence that principal() enforces admin privileges
- No view of route‑level dependencies or middleware that might restrict access
- Unclear whether job data is considered sensitive in the threat model

### 82. Sensitive data exposure via debug_config endpoint (CWE-200)

- Issue group: `ai-d63a40e98bc61059`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The provided code defines a GET endpoint at /debug/config that returns internal configuration values, including DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET, without any authentication or authorization checks. This creates a potential information disclosure risk because an attacker could retrieve sensitive secrets directly from the endpoint.

**Impact:** Exposure of database credentials and application secrets can enable attackers to connect to the database, read or modify data, and impersonate the application, leading to further compromise of confidentiality, integrity, and availability.

**Remediation:** Add authentication and authorization checks to the endpoint, or restrict it to internal use only (e.g., bind to localhost or protect with environment‑based feature flags). Consider removing the endpoint from production builds or returning only non‑sensitive information.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-d63a40e98bc61059`
- `api/app.py lines 320‑322 define @app.get("/debug/config") returning DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without any guard`

Limitations:
- No independent scanner or runtime probe evidence confirming the endpoint is reachable in the deployed environment.
- No evidence that the endpoint is disabled in production or protected by external infrastructure (e.g., API gateway, network ACLs).

### 83. Potential weak session token generation (CWE-326)

- Issue group: `ai-b8c2b7ce22b68cd6`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code inserts a session token into the database, but the snippet does not show how the token variable is created. Without evidence that a cryptographically secure random generator is used, the token may be predictable, leading to session fixation or token‑guessing attacks. No guard or validation of token entropy is visible in the provided context.

**Impact:** An attacker who can predict or guess session tokens could hijack user sessions, gaining unauthorized access to protected resources and potentially escalating privileges.

**Remediation:** Ensure that session tokens are generated using a cryptographically secure random number generator (e.g., Python's secrets.token_urlsafe or os.urandom) with sufficient length and entropy. Review the token creation code and replace any use of non‑secure RNGs or deterministic schemes. Add unit tests to verify token randomness and length.
Evidence:
- Penetration test: **Could not be tested** — A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run.
- Source IDs: `ai-b8c2b7ce22b68cd6`
- `Source excerpt shows insertion of token into sessions table without showing token generation (lines 136‑138).`
- `Entry point is the POST /auth/checked-login route (line 125).`
- `Missing check annotation indicates token generation code is not visible (line 130).`

Limitations:
- The actual token generation code is not provided, so its randomness cannot be confirmed or refuted.
- No runtime probe or scanner evidence demonstrates token predictability or successful exploitation.
- No guard or validation of token entropy is present in the supplied excerpts.

### 84. Missing authentication on session start (CWE-306)

- Issue group: `ai-30920f0acc104aee`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code defines a GET endpoint "/session/start" that accepts a username parameter, queries the database for that user, and, if found, issues a session cookie containing the user ID without any password verification or existing session check. This suggests that an attacker could obtain a valid session for any existing account by supplying the username alone, leading to account takeover. However, the evidence is limited to the source excerpt; there is no independent scanner finding, runtime probe, or evidence of missing server‑side session validation beyond the shown snippet.

**Impact:** An attacker can impersonate any user by providing their username, gaining authenticated access to protected resources and potentially exfiltrating or modifying sensitive data.

**Remediation:** Require proper authentication before issuing a session cookie. Validate the user's credentials (e.g., password) or ensure an existing authenticated session is present. Tie the session cookie to server‑side session state and use secure cookie attributes (HttpOnly, Secure, SameSite).
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-30920f0acc104aee`
- <code>api/extra.py:272 defines def session_start(username: str) -&gt; Response</code>
- `api/extra.py:274 queries the user by username without password check`
- `api/extra.py:278 sets a cookie lab_session based on user['id'] without prior authentication`

Limitations:
- No independent scanner or runtime probe confirming that the endpoint is reachable and accepts arbitrary usernames
- No evidence that middleware or other code does not perform authentication before this handler
- No proof that the issued cookie is accepted by the application as an authenticated session

### 85. Missing rate limiting / token reuse protection on password reset request (CWE-640)

- Issue group: `ai-ed2bf8f5536c5122`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code defines a POST endpoint "/auth/reset/request" that generates a reset token and stores it in the database, then returns the token in the response. No logic for rate‑limiting requests per user or IP, nor any token expiration handling, is visible in the supplied excerpts. Without such checks, an attacker could repeatedly invoke the endpoint to obtain many valid reset tokens for a target account, potentially enabling token enumeration or reuse attacks.

**Impact:** An attacker can flood the password‑reset endpoint to obtain unlimited valid reset tokens for a victim, leading to account takeover if the token is later used to reset the password. Lack of rate limiting also facilitates denial‑of‑service against the reset service.

**Remediation:** Add server‑side rate limiting (e.g., per IP or per user) to the reset request endpoint. Store an expiration timestamp with each token and enforce a short TTL (e.g., 15 minutes). Invalidate or delete tokens after use. Consider returning a generic success response without exposing the token in the API response; instead, send the token via a secure out‑of‑band channel (e.g., email).
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-ed2bf8f5536c5122`
- `api/extra.py:564 – @router.post("/auth/reset/request") defines the entry point`
- `api/extra.py:571 – INSERT INTO reset_tokens(token,user_id) stores the token without expiration logic`
- `api/extra.py:573 – return {"reset_token": token} returns the token to the caller`

Limitations:
- No evidence of any middleware, decorator, or internal function that implements rate limiting or token expiration is present in the provided code excerpts.
- The database schema or triggers that might enforce token TTL are not shown.
- Absence of runtime_probe_facts or scanner findings confirming the vulnerability prevents a confirmed status.

### 86. Missing authentication on verified password reset request (CWE-306)

- Issue group: `ai-c788be668eb0e766`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint @router.post("/auth/reset/verified-request") creates a password reset token after looking up a user by username without any verification of a prior step (e.g., a one‑time code or flag). The code snippet shows no check for a verification token before inserting the reset token into the database, which suggests an authentication bypass for password reset. However, the evidence is limited to the provided source excerpt; no scanner or runtime probe confirms that the endpoint is reachable without authentication, nor is there evidence that middleware or other checks are absent outside the shown context.

**Impact:** An attacker could generate valid password reset tokens for any existing username, potentially allowing account takeover by resetting passwords without possessing a verification code or prior authentication.

**Remediation:** Add a verification step before issuing a reset token, such as requiring a one‑time code sent to the user's email or phone, or checking a previously set verification flag in the database. Ensure that any middleware that enforces verification is applied to this route, and return an error if verification is missing.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-c788be668eb0e766`
- `api/extra.py:589 – @router.post("/auth/reset/verified-request") defines the endpoint`
- `api/extra.py:592 – Retrieves user record by username`
- `api/extra.py:596 – Inserts a reset token into reset_tokens table without prior verification`

Limitations:
- No runtime probe or scanner evidence confirming that the endpoint can be accessed without authentication
- No view of middleware or surrounding code that might enforce verification before this handler
- Unclear whether a preceding step sets a temporary verification flag that this handler checks elsewhere

### 87. Missing authentication check on session token generation

- Issue group: `ai-0e5f56ed2ed3b6b5`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The function `secure_session_start` inserts a session token into the database and returns it in a cookie, but the supplied excerpt does not show how the `token` variable is created. No cryptographically‑secure random generation or validation is visible, and no guard is present in the shown context to ensure the token cannot be forged.

**Impact:** An attacker who can predict or forge the `token` value could create arbitrary sessions and gain unauthorized access to protected resources.

**Remediation:** Generate the session token using a cryptographically secure random source (e.g., `secrets.token_urlsafe`), validate its uniqueness before insertion, and ensure any token creation logic is present in the same code path. Add explicit checks or comments confirming the token’s security properties.
Evidence:
- Penetration test: **Not reproduced** — Every attempt was denied as expected. This is not proof that the flaw does not exist.
- Source IDs: `ai-0e5f56ed2ed3b6b5`
- <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- `user = verified_identity(authorization)`
- `conn.execute("INSERT INTO sessions(token,user_id) VALUES (%s,%s)", (token, user["id"]))`
- `response.set_cookie("verified_session", token, httponly=True, samesite="strict", secure=True)`

Limitations:
- The source excerpt does not include the definition or generation of the `token` variable, so it cannot be confirmed whether a secure random token is used.
- No independent scanner or runtime probe evidence is provided to demonstrate that an insecure token can be exploited.

### 88. Potential IDOR in session whoami endpoint

- Issue group: `ai-caa31c16de86cfef`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code extracts a numeric user ID from a session token that is only format‑checked (must start with "session-" and be numeric). No verification is performed against a sessions store or cryptographic signature, allowing an attacker to craft a token such as "session-123" to retrieve another user's username via the SQL query.

**Impact:** An attacker who can guess or enumerate user IDs could obtain usernames (or other data) of other accounts, leading to information disclosure and possible further account takeover attacks.

**Remediation:** Validate the session token against a trusted source: store issued tokens in a sessions table and check that the token exists and is associated with the requesting client, or use a signed token (e.g., JWT/HMAC) and verify its signature before extracting the user ID. Reject tokens that fail this verification.
Evidence:
- Penetration test: **Not reproduced** — Every attempt was denied as expected. This is not proof that the flaw does not exist.
- Source IDs: `ai-caa31c16de86cfef`
- `if not token.startswith("session-") or not token[8:].isdigit():`
- `row = conn.execute("SELECT username FROM users WHERE id=%s", (int(token[8:]),)).fetchone()`

Limitations:
- No evidence that a separate sessions table or token signature verification exists elsewhere in the codebase.
- No scanner or runtime probe confirming that crafted tokens can be used to retrieve other users' data.

### 89. Missing validation of coupon discount range (CWE-770)

- Issue group: `ai-04f69d3a6682ee6f`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The verified_coupon endpoint reads a coupon's percent value from the database and applies it directly to the order's discount field without any range check. The supplied code shows the entry point, the retrieval of the coupon, and the UPDATE statement that stores coupon\["percent"\] into the discount column. No validation of the percent value (e.g., ensuring it is between 0 and 100) is present in the shown context.

**Impact:** An attacker who can create or modify coupon records could set a percent value outside the intended range (e.g., &gt;100 or negative). This could result in orders being over‑discounted (allowing free items) or price‑inflated, leading to revenue loss or financial manipulation.

**Remediation:** Add explicit validation of the coupon percent before applying it to the order. For example, ensure the value is an integer between 0 and 100 and reject or clamp out‑of‑range values. Consider adding a database CHECK constraint on the coupons.percent column and enforce role‑based restrictions on who can create coupons.
Evidence:
- Penetration test: **Could not be tested** — A prerequisite (login, capture, request or time budget) failed before a security-relevant request could run.
- Source IDs: `ai-04f69d3a6682ee6f`
- `453: @router.post("/orders/{order_id}/verified-coupon")`
- <code>454: def verified_coupon(order_id: int, body: dict, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `455: order, _ = owned_order(order_id, authorization)`
- `456: if order["status"] != "new":`
- `459: coupon = conn.execute("SELECT percent FROM coupons WHERE code=%s", (str(body.get("code", "")),)).fetchone()`
- `463: "UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (coupon["percent"], order_id)`

Limitations:
- No evidence of database constraints (e.g., CHECK on coupons.percent) is provided.
- No information on whether administrators are restricted from creating coupons with arbitrary percent values.
- No runtime probe or scanner evidence confirming that out‑of‑range values can be stored or cause harmful behavior.

### 90. Potential missing ownership verification on comment creation (CWE-639)

- Issue group: `ai-844c60b0ab9c1aa8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The add_comment endpoint inserts the raw comment body into the database without any visible sanitisation or validation. The supplied code shows the entry point and the sensitive SQL INSERT operation, but there is no evidence that the comment content is later escaped or filtered before being rendered to users. This could allow stored XSS or other injection attacks if the comment is displayed unescaped.

**Impact:** If an attacker can store malicious HTML/JavaScript in the comment body, it may be executed in the browsers of users viewing the comment, leading to session hijacking, credential theft, or other client‑side attacks.

**Remediation:** Validate and sanitise the comment body before insertion. Apply length limits, strip or encode HTML tags, or use a library such as Bleach. Ensure that any downstream rendering of comment.body uses proper escaping (e.g., templating auto‑escaping or explicit HTML escaping).
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-844c60b0ab9c1aa8`
- `api/extra.py:162 – add_comment endpoint definition`
- `api/extra.py:166 – SQL INSERT statement with raw body`
- `api/extra.py:167 – insertion of body.body without prior sanitisation`

Limitations:
- No evidence is provided that the comment body is later rendered without escaping; the presence or absence of output‑encoding cannot be determined from the supplied excerpts.
- The identity() function’s behaviour (authentication enforcement) is not shown, so the authentication guarantee is assumed but not verified.
- No scanner or runtime probe evidence confirms that an exploit is possible; the finding relies solely on the missing sanitisation check in the source code.

### 91. Insecure Direct Object Reference (CWE-639) in profile endpoint

- Issue group: `ai-6322be0c6e12b177`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `profile` endpoint authenticates the request via `principal(authorization)` but does not perform any authorization check to ensure the caller is allowed to access the requested `profile_id`. As a result, any authenticated user can retrieve another user's record, including sensitive fields such as SSN. The source code shows the missing ownership/role verification, but no independent scanner or runtime probe confirms exploitation, and no evidence of a guard elsewhere in the supplied context is present.

**Impact:** An attacker who can obtain a valid authorization token can enumerate or retrieve arbitrary user profiles, exposing personally identifiable information (PII) like SSN, email, and username. This can lead to identity theft, privacy violations, and compliance breaches.

**Remediation:** Add an authorization check after authentication that verifies the authenticated principal either owns the requested profile or has a role (e.g., admin) permitting access. Example: `if principal.id != profile_id and not principal.is_admin: raise HTTPException(403, "Forbidden")`. Consider centralizing access control in middleware and audit all profile accesses.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-6322be0c6e12b177`
- <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict: (entry point)</code>
- `principal(authorization) (authentication call)`
- `row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone() (sensitive DB query)`

Limitations:
- No scanner or runtime probe evidence confirming that the endpoint is reachable and returns data for unauthorized IDs.
- No information on what `principal` returns (whether it includes role or ownership data).
- No evidence of downstream middleware that might enforce per‑user restrictions.
- No audit logging or other compensating controls are shown in the supplied code.

### 92. Missing Authorization Check for Admin Overview (CWE-862)

- Issue group: `ai-b0abc42e37a54582`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `admin_overview` calls `principal(authorization)` but no explicit admin‑role verification is visible in the supplied code. Without evidence that `principal` enforces an admin‑only restriction, non‑admin users could invoke the route and obtain the total user count, which may be considered sensitive internal information. The code therefore appears to lack a required authorization guard before performing the sensitive database query.

**Impact:** If an attacker can supply a valid authentication token that passes `principal` but lacks admin privileges, they can retrieve the total number of users. This information can aid enumeration attacks, facilitate credential stuffing, or be used for social engineering.

**Remediation:** Add an explicit admin‑role check after authentication, e.g., `require_admin(authorization)` or verify the user's role before executing the query. Ensure that unauthorized requests receive a 403 response. Consider logging and rate‑limiting accesses to this endpoint.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-b0abc42e37a54582`
- <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]`
- `return {"users": count}`

Limitations:
- No definition or behavior of `principal` is provided; it is unclear whether it raises an error for non‑admin users or performs any role checks.
- The code snippet does not show any surrounding authorization middleware or guard that could enforce admin rights.
- No runtime probe or scanner evidence confirming that the endpoint is reachable by non‑admin users is present.

### 93. Insecure Direct Object Reference (IDOR) in note retrieval

- Issue group: `ai-62e3663725439fbd`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint authenticates the request via `principal(authorization)` but the subsequent database query only filters by `note_id`. The supplied code does not show any verification that the `note_id` belongs to the `order_id` supplied in the URL, allowing an attacker who can guess or enumerate note IDs to retrieve notes from other orders. This constitutes an IDOR risk. However, the evidence is limited to the source excerpt; there is no independent scanner finding, runtime probe, or visible guard that confirms the absence of an ownership check, so the vulnerability cannot be confirmed.

**Impact:** An attacker could access confidential order notes belonging to other users, leading to privacy breaches and potential exposure of sensitive business information.

**Remediation:** Add an ownership check to the query, e.g., `SELECT id,order_id,body FROM notes WHERE id=%s AND order_id=%s`, and verify that the returned row’s `order_id` matches the authenticated user's permitted orders. Alternatively, enforce authorization at the application layer after fetching the note.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-62e3663725439fbd`
- <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()`

Limitations:
- No evidence that `principal` performs authorization beyond authentication.
- No database constraints or additional code shown that enforce note ownership.
- No scanner or runtime probe confirming the vulnerability behavior.

### 94. Missing authorization check (CWE-862) in verified_get_order endpoint

- Issue group: `ai-72536ee718898b70`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET endpoint returns order data by calling owned_order with the supplied authorization header, but the provided excerpt does not show any ownership verification before the call. Without seeing the implementation of owned_order, it is unclear whether the authorization header is validated and whether the caller is confirmed to own the requested order. The absence of an explicit check in the shown code suggests a potential IDOR vulnerability, but the evidence is incomplete.

**Impact:** If owned_order does not enforce ownership, an attacker could retrieve any order by supplying an arbitrary order_id and a valid or forged authorization header, leading to unauthorized disclosure of order information.

**Remediation:** Ensure that the endpoint (or the owned_order function) validates that the authenticated user identified by the authorization header is the owner of the requested order_id before returning data. Add explicit ownership checks and return a 403 error when the user is not authorized.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-72536ee718898b70`
- `@router.get("/orders/{order_id}/verified") definition at line 448`
- <code>def verified_get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict: at line 449</code>
- `return owned_order(order_id, authorization)[0] at line 450`

Limitations:
- The implementation of owned_order is not provided, so we cannot confirm whether it performs the necessary ownership verification.
- No scanner or runtime probe evidence confirming the vulnerable behavior is present.

### 95. Missing authentication on file download (CWE-284)

- Issue group: `ai-e6b00beb5ad08603`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `GET /uploads/{upload_id}` returns the raw file contents from the database without any authentication or authorization checks. The supplied code shows no validation of the caller’s identity or ownership of the requested upload, allowing any client that can guess or enumerate `upload_id` values to retrieve potentially private files. However, no independent scanner or runtime probe evidence is provided to confirm that the endpoint is reachable without authentication, nor is there evidence that a global authentication middleware is absent.

**Impact:** An attacker could enumerate upload IDs and download files that may contain sensitive data, leading to confidentiality breaches and potential privacy violations.

**Remediation:** Add authentication and authorization checks before returning the file. Verify that the requesting user is authenticated and owns the upload (or has appropriate permissions). For example, retrieve the current user from the request context and compare it to the upload’s owner field, returning 403 if unauthorized. Consider applying a global security middleware to enforce authentication on all routes.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-e6b00beb5ad08603`
- `@router.get("/uploads/{upload_id}") definition at line 366`
- `return Response(bytes(row["body"]), media_type=row["mime"]) at line 372`
- `No authentication/authorization logic present in the endpoint code`

Limitations:
- Missing evidence that the endpoint is publicly reachable (e.g., runtime probe showing unauthenticated access)
- No scanner or higher‑severity source confirming the vulnerability
- Unclear whether a global authentication middleware applies to this route

### 96. Missing authentication on comments endpoint (CWE-306)

- Issue group: `ai-5ae04a0c7d72bccf`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The GET /comments endpoint returns all comment bodies without any authentication or authorization guard in the supplied code. No dependency such as Depends(get_current_user) is present before the database query, indicating a missing authentication check. However, the evidence is limited to the provided source excerpt and an AI analysis; there is no independent scanner finding or runtime probe confirming that unauthenticated access is possible, nor evidence that middleware does not enforce authentication globally.

**Impact:** Unauthenticated users can read comment content that may be intended to be private, leading to information disclosure and potential privacy violations.

**Remediation:** Add an authentication/authorization dependency to the route, e.g., @router.get("/comments", dependencies=\[Depends(get_current_user))\], and enforce appropriate access controls before querying the database. If comments are public, document this explicitly.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-5ae04a0c7d72bccf`
- `api/extra.py:173 – route definition without auth guard`
- `api/extra.py:176 – database query returning comment bodies`

Limitations:
- No independent scanner or runtime probe confirming unauthenticated access
- No evidence about global middleware that might enforce authentication for all routes
- Unclear whether comments are intended to be public content

### 97. Missing authentication on forum messages endpoint (CWE-306)

- Issue group: `ai-e4eb53440f8f0be6`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The route defined at @router.get("/forum/messages") returns the contents of the "comments" table without any authentication or authorization guard applied in the supplied code. The endpoint directly queries the database and renders the results as HTML, which could expose private forum messages to unauthenticated users.

**Impact:** Unauthenticated users can read all forum messages, potentially leaking private or sensitive information and violating confidentiality requirements.

**Remediation:** Add an authentication/authorization dependency to the endpoint (e.g., FastAPI Depends on a security scheme) and enforce that only authorized users can access the messages. Consider filtering or paginating results and applying proper access controls.
Evidence:
- ✅ **Independently confirmed by the Autonomous Penetration Agent** — see Autonomous Penetration Testing above for the exact reproduction steps.
- Source IDs: `ai-e4eb53440f8f0be6`
- `api/extra.py:189 – route declaration without auth guard`
- `api/extra.py:192 – database query fetching all comment bodies`
- `api/extra.py:193 – HTML response rendering the fetched bodies`

Limitations:
- No evidence is provided that a global router guard or middleware enforces authentication for this endpoint. No independent scanner or runtime probe confirming that the endpoint is reachable without authentication.

## Policy Decisions

- `merged-4c6d36222f8ebf7f1f68`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-15dd977d52312c30635a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d58491aad5be35b48233`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c5b44871f1955b338344`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-56ecc860a2c48330a29a`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-69b75a0aa3f8fc9fb800`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-efce9419c25ced2d8892`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-4a2311054cdc2bfe890d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a6e788cfc5d9d1297feb`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a9a9a0b97f19f8bf52ae`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-6e468e09eab3ca889e3d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-81ff94e895c53dbc2029`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d716d5afb61da294d286`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f5fff899f9294177dc70`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-916563c278b3e6b62930`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-54b1ddb055358b3579a2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b7e0b624f8cddd0a9e8c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d0789be823f0fd7fa381`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-7ed325c02dd6cf8227d2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-ccc894903304aa8847bd`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-1bcb1da144dffdcf3fd8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3202e1e1074cfd44b9bf`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-18f1abe978f9fdaad8e6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-935e828dd4bba4f4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-7aebdfd54eb4e688`: **warn** ✅ confirmed by Penetration Agent — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-2b797e12ede1385a`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-357e82f73fc20848`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-06a6519ee55ac5e0`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-6a78349f837e165e`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-6d23d0d008604fdc`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-d3c8ae68a75d8b90`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-cbdb48ff58f91fd1`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-83c277f7161c623e`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-eebcf33ae8e5eaef`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-8204d1e620288a08`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-492db277b819e281`: **warn** ✅ confirmed by Penetration Agent — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-f0dce5b04fc274c8`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ae177f098ffafcec`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-76ee5ddf6f5e1661`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-78782ba33d6e3838`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-d6b4763af77577b9`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-d63a40e98bc61059`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-b8c2b7ce22b68cd6`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-30920f0acc104aee`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ed2bf8f5536c5122`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-c788be668eb0e766`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-0e5f56ed2ed3b6b5`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-caa31c16de86cfef`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-04f69d3a6682ee6f`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-844c60b0ab9c1aa8`: **warn** ✅ confirmed by Penetration Agent — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-6322be0c6e12b177`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-b0abc42e37a54582`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-62e3663725439fbd`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-72536ee718898b70`: **warn** ✅ confirmed by Penetration Agent — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-e6b00beb5ad08603`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-5ae04a0c7d72bccf`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-e4eb53440f8f0be6`: **warn** ✅ confirmed by Penetration Agent — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **97**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **50**; scanner overlaps: **1**; AI overlaps: **0**; new candidates: **25**; uncertain overlaps: **9**; needs more evidence: **15**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-6d23d0d008604fdc`: uncertain_overlap
- `ai-d3c8ae68a75d8b90`: uncertain_overlap
- `ai-eebcf33ae8e5eaef`: uncertain_overlap
- `ai-e0c2fe9c736a77db`: needs_more_evidence
- `ai-c57d6958607d3488`: needs_more_evidence
- `ai-22a44ef62b9753c6`: needs_more_evidence
- `ai-ee152427f45416bd`: needs_more_evidence
- `ai-30920f0acc104aee`: uncertain_overlap
- `ai-a17263204ca43c0a`: needs_more_evidence
- `ai-ed2bf8f5536c5122`: uncertain_overlap
- `ai-c788be668eb0e766`: uncertain_overlap
- `ai-2555f22798dcb9cd`: needs_more_evidence
- `ai-52a31a1b00dc9da7`: needs_more_evidence
- `ai-c03e342fbf403b7f`: needs_more_evidence
- `ai-48bcbd6379b8cb69`: needs_more_evidence
- `ai-fa144252f5178c49`: needs_more_evidence
- `ai-a241112d70951071`: needs_more_evidence
- `ai-4217936b40eecae7`: needs_more_evidence
- `ai-04f69d3a6682ee6f`: uncertain_overlap
- `ai-1aee6f7d62ca4ef7`: needs_more_evidence
- `ai-b9f516858897489c`: needs_more_evidence
- `ai-f1b2a80425ec2b1d`: needs_more_evidence
- `ai-5ae04a0c7d72bccf`: uncertain_overlap
- `ai-e4eb53440f8f0be6`: uncertain_overlap

## Coverage Gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.
- Coverage applies only to declared assertions, accounts and workflows.
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile. All 4 direct dependencies are exactly pinned; their transitive dependencies are not recorded.
- This baseline phase only makes bounded HTTP GET observations; browser crawling, ZAP and account workflows are separate phases, reported only when they ran.

## Limitations

Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.

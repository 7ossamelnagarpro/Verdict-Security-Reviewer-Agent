# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-14T17:58:38.830037+00:00`
- Policy status: **failed**
- Review status: **partial**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **71/71**; model calls: **10**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.

The agent reviewed **81** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **84**; reviewed: **81**; pending: **3**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **51**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **completed**; pages visited: **1**.
- ZAP: **completed**; engine: <code>zap-passive</code>; alerts: **14**.
- Account and business workflows: **completed**; executed: **40**; contract violations: **20**.
- These observations do not prove complete vulnerability coverage or exploitation.

## Autonomous Penetration Testing — Reproduction Steps

Hypotheses tested: **21**; total attempts: **28**; total requests: **17**; exploitation confirmed: **14**.
Every probe below is read-only (GET/HEAD) against an isolated test stack with test accounts; nothing here mutated real data. Re-run the same method and path after a fix and confirm the response status changes to a denial status.

### Hypothesis `ai-bed84194d5313af2` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /profiles/{profile_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}/verified")`
- Target: `/profiles/{profile_id}/verified`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no attempts have been made, using the authorization_matrix template will systematically test variations of authentication and profile_id values to confirm whether the endpoint improperly authorizes access.
  - Step 1: `GET /profiles/{profile_id}/verified` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}/verified")`
- Target: `/profiles/{profile_id}/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior unauthenticated_access attempt has been made, and the hypothesis concerns whether the endpoint can be accessed without proper authentication, so trying that template is the next logical step.
  - Step 1: `GET /profiles/{profile_id}/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /profiles/{profile_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-4a14d82a7cc9c5d6` — outcome: **not_reproduced**

authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no tests have been run, the simplest way to verify missing admin checks is to attempt access without authentication, directly probing the /admin/audit endpoint.
  - Step 1: `GET /admin/audit` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The only prior test was an unauthenticated request which was correctly denied; we now need to see if an authenticated non‑admin user can bypass the admin check, which authorization_matrix can evaluate.
  - Step 1: `GET /admin/audit` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-d3c8ae68a75d8b90` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no tests have been run, the simplest check is whether the /files endpoint can be accessed without authentication, which could immediately reveal the traversal issue.
  - Step 1: `GET /files` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-e8ec08f388c6f0b9` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/refresh as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/auth/refresh")`
- Target: `/auth/refresh`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no attempts exist, testing whether the refresh endpoint can be invoked without a valid token will directly assess the hypothesized insecure token handling.
  - Step 1: `GET /auth/refresh` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/refresh as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-1826d2fcbfeb295d` — outcome: **blocked**

authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing ownership checks after authentication, so testing with the authorization_matrix template will verify whether applying a coupon to another user's order is allowed.
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-f0dce5b04fc274c8` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/cancel`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: We need to verify whether the cancel_order endpoint enforces ownership or role checks, so the authorization_matrix template is the appropriate next test.
  - Step 1: `GET /orders/{order_id}/cancel` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/cancel`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No unauthenticated test has been run yet; trying this template can determine if the endpoint allows cancellation without any token, addressing the missing ownership check.
  - Step 1: `GET /orders/{order_id}/cancel` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-2610f6087fbda613` — outcome: **blocked**

authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no tests have been run, the next step is to verify whether non‑admin authenticated users can access the admin/users endpoint, which directly tests the missing role enforcement.
  - Step 1: `GET /admin/users` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-1dd6334868544586` — outcome: **not_reproduced**

unauthenticated_access: the request was correctly denied (HTTP 401).

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns missing role checks on the admin jobs endpoint, so testing role enforcement with the authorization_matrix template is the most direct next step.
  - Step 1: `GET /admin/jobs` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns missing role checks for authenticated users; testing unauthenticated access will confirm the endpoint correctly rejects requests without a token before exploring role enforcement.
  - Step 1: `GET /admin/jobs` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-ae177f098ffafcec` — outcome: **blocked**

authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/invoices/{invoice_id}")`
- Target: `/invoices/{invoice_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The issue concerns lack of ownership verification after authentication, so testing with multiple user contexts using the authorization_matrix template will reveal IDOR behavior.
  - Step 1: `GET /invoices/{invoice_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-8f2e97ab78cee25c` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/orders/{order_id}")`
- Target: `/orders/{order_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no attempts exist and the issue is about missing ownership checks, the authorization_matrix template will directly test whether different users can access others' orders.
  - Step 1: `GET /orders/{order_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/orders/{order_id}")`
- Target: `/orders/{order_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The only prior attempt did not reach the security-relevant request, so trying unauthenticated access could reveal whether the endpoint enforces authentication before ownership checks.
  - Step 1: `GET /orders/{order_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-d30ea28564e18126` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/debug/config")`
- Target: `/debug/config`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns an unauthenticated endpoint leaking secrets, so the unauthenticated_access template directly tests that behavior.
  - Step 1: `GET /debug/config` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-f6a68f3e73ee86ba` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def session_start(username: str) -&gt; Response:</code>
- Target: `/session/start`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns creating a session without any authentication, so the unauthenticated_access template directly tests if the endpoint issues a session cookie for arbitrary usernames.
  - Step 1: `GET /session/start` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-f10815aecca0a812` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/reset/request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def request_reset(body: dict) -&gt; dict:</code>
- Target: `/auth/reset/request`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns the reset endpoint allowing token generation without authentication or limits, so the unauthenticated_access template directly tests if the reset can be invoked without credentials.
  - Step 1: `GET /auth/reset/request` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/reset/request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-93787ef734989eda` — outcome: **not_reproduced**

unauthenticated_access: the request was correctly denied (HTTP 401).

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis concerns a missing admin role check, so testing various role/permission combinations with the authorization_matrix template will directly verify if non‑admin users can access the admin endpoint.
  - Step 1: `GET /admin/overview` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No unauthenticated test has been run yet; trying unauthenticated_access will reveal whether the admin endpoint can be accessed without any credentials, directly addressing the missing admin role check.
  - Step 1: `GET /admin/overview` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-fbb70c87492b9215` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/profiles/{profile_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The hypothesis mentions only a generic authentication check without proper ownership verification, so testing the authorization matrix will reveal if the endpoint improperly allows access to other users' SSNs.
  - Step 1: `GET /profiles/{profile_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/profiles/{profile_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No unauthenticated test has been performed yet; trying the unauthenticated_access template can verify if the endpoint leaks SSNs without valid credentials.
  - Step 1: `GET /profiles/{profile_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-8b80c3773de74246` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: The issue concerns insufficient ownership verification after authentication, so testing the authorization matrix will reveal if notes can be accessed without proper ownership checks.
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No unauthenticated access test has been run yet; trying it may reveal whether the endpoint can be accessed without proper authentication, directly testing the missing ownership check.
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-7da0208dca8f390c` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/uploads/{upload_id}")`
- Target: `/uploads/{upload_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no tests have been run, the first step is to see if the upload endpoint can be accessed without authentication, directly confirming the IDOR risk.
  - Step 1: `GET /uploads/{upload_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-2b29d4ee02a18f9b` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/uploads/{upload_id}")`
- Target: `/uploads/{upload_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: Since no attempts exist, first verify if uploads can be accessed without authentication, which is needed to exploit the mirrored MIME type for XSS.
  - Step 1: `GET /uploads/{upload_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-b94262d4b5d7ef8e` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /integrations/hook as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/integrations/hook")`
- Target: `/integrations/hook`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns an unauthenticated POST endpoint, so the unauthenticated_access template directly tests whether the webhook can be invoked without credentials.
  - Step 1: `GET /integrations/hook` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /integrations/hook as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-981d194322a5245a` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /forum/messages as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/forum/messages", response_class=HTMLResponse)`
- Target: `/forum/messages`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior tests exist and the hypothesis concerns lack of authentication on the /forum/messages endpoint, so the unauthenticated_access template directly validates this claim.
  - Step 1: `GET /forum/messages` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /forum/messages as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-118e8dd460abde2d` — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No attempt could be planned or executed for this hypothesis._

## Scanner Execution

- <code>trivy</code>: <code>completed</code>
- <code>gitleaks</code>: <code>completed</code>
- <code>trivy</code>: <code>skipped</code>
- <code>semgrep-ce</code>: <code>completed</code>
- <code>codeql-cli</code>: <code>completed</code>
- <code>trivy</code>: <code>completed</code>

## Scanner and DAST Observations (Pre-Review)

**63** merged observation record(s): **37** DAST-related and **26** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

1. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:119</code>; severity: **high**; confidence: high; risk: 79/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-18f1abe978f9fdaad8e6</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-5e7b731c6445970909c9</code>.
2. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:144</code>; severity: **high**; confidence: high; risk: 79/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-f60fee7d82fbca512208</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-7605384fbc7aee3bcd8a</code>.
3. **Reflected server-side cross-site scripting** — scanner from codeql-cli; location: <code>api/extra.py:145</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-ea527a7d7441e2b11700</code>; rule(s): <code>py/reflective-xss</code>; source evidence: <code>finding-a8c8d9148f5e4ee9d3fd</code>.
4. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:212</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-f4eaf141df049c63545d</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-480ccba498d117b3450e</code>.
5. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:213</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-83d97da4516adf20e20f</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-26bd24fa5794fd60d9e9</code>.
6. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:215</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-b527b3ed30e57aac5ec5</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-aa95c189edc76290622b</code>.
7. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:221</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-24d14609e3893220ea16</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-ac18ed89b1a00ae2c8bf</code>.
8. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:222</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-794dcb4921076779cef0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-2f756e27fddc389636a8</code>.
9. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:224</code>; severity: **high**; confidence: high; risk: 75/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-b3c734b4cef8dd70fce0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-603f6a08a677ccbb0c42</code>.
10. **python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: 69/100 (high); disposition: <code>standard_report</code>.
    - Record: <code>merged-8ce42d9c8b52a95b109d</code>; rule(s): <code>CVE-2026-24486</code>; source evidence: <code>finding-555e67f97039217aa153</code>.
11. **Clear-text logging of sensitive information** — scanner from codeql-cli, semgrep-ce; location: <code>api/app.py:137</code>; severity: **high**; confidence: high; risk: 65/100 (high); disposition: <code>deep_review</code>.
    - Record: <code>merged-3202e1e1074cfd44b9bf</code>; rule(s): <code>py/clear-text-logging-sensitive-data, python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure</code>; source evidence: <code>finding-cfe66151dbff24377948</code>, <code>finding-2e982654735c1187197b</code>.
12. **python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: 61/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-051697f9b8567d596874</code>; rule(s): <code>CVE-2026-53539</code>; source evidence: <code>finding-2626e4bc8eef02153f32</code>.
13. **python-multipart: python-multipart: Denial of Service via excessive multipart part headers** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: 61/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-3503f2dec888990b31f2</code>; rule(s): <code>CVE-2026-42561</code>; source evidence: <code>finding-d5a70d23b67803614b8f</code>.
14. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: 59/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
15. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: 52/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
16. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: 52/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
17. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-15dd977d52312c30635a</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-9285679b6f926a0d1c0a44d2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_jobs&quot;}</code>.
18. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-d58491aad5be35b48233</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-2a9764dfddf0c017eff71be0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;stale_role&quot;}</code>.
19. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-c5b44871f1955b338344</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-946a5bf2b3aeb375da4de266</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_users&quot;}</code>.
20. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-efce9419c25ced2d8892</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-18719503314710a3e71c38c9</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;reset_replay&quot;}</code>.
21. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f5fff899f9294177dc70</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-e929732019082549893b68d0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [401, 403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;debug_access&quot;}</code>.
22. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-b98074828fe298997980</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-267f3aec1133283c14739667</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 401, 403], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;unsigned_hook&quot;}</code>.
23. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-54b1ddb055358b3579a2</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-bc7d0d0a77b4619ba22d0b25</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;invoice_owner&quot;}</code>.
24. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-b7e0b624f8cddd0a9e8c</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-d47d5c27b4e143571ef5f9e3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;worker_role&quot;}</code>.
25. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-218d6fc43fe64432894a</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-19ac26bfd96baf1f15d8f0f0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200, 201], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;price_catalog&quot;}</code>.
26. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-5a7c783c30e11426af42</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-97a2403badc5307e87389e70</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_initial_state&quot;}</code>.
27. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-767d54ff7a729b156819</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-289a562cf581d69d3a6c7d63</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;negative_price&quot;}</code>.
28. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-d0789be823f0fd7fa381</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-e6fad5bfce7f957806254d9e</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;owner_assignment&quot;}</code>.
29. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-0f6fe31b81367808748c</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-22221f4054533f30bbaf73ba</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;nested_note&quot;}</code>.
30. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-fe4ca713f11faf9b96d6</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-ed0dc0a1678724040424e4a2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_owner&quot;}</code>.
31. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-7ed325c02dd6cf8227d2</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-3143beb445281415043c6a2c</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;coupon_bounds&quot;}</code>.
32. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-ccc894903304aa8847bd</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-128e83b73f127060c05a7721</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;paid_cancel&quot;}</code>.
33. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-1bcb1da144dffdcf3fd8</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-12d8f92bbda0b009c94e4b17</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;payment_replay&quot;}</code>.
34. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-18063ba27bc289f53c8a</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-3982bc4eac58ce8d5c2fe5ad</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;profile_owner&quot;}</code>.
35. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8cdc677a9810b317840f</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-79fa84ef4d90b0b35afc2e33</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;webhook_destination&quot;}</code>.
36. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: 40/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
37. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-69b75a0aa3f8fc9fb800</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-b6f705aa38e255df58e01591</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
38. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-4a2311054cdc2bfe890d</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-f7770e55aa48cd4e79a67974</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
39. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-81ff94e895c53dbc2029</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-c2674e7dbbea535e39dafdce</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
40. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-a4473061f97f0a366678</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-7a357b5bf54222b07b45d1ba</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
41. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-56ecc860a2c48330a29a</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d193f3d7b6fa58812879e8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
42. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-a9a9a0b97f19f8bf52ae</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d2c2e1a1a3392fa7d24831ad</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
43. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-6e468e09eab3ca889e3d</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-b9a6116c922e7e3c213c2404</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
44. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-c0dcf73e8d7a6a1fbf02</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-dfd12f00e32f16e74be8fee3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;excessive_data&quot;}</code>.
45. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-4ae7658c2abfbf689e2b</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-ac5e6859c324c2e40526210b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
46. **python-multipart: Python-Multipart: Information disclosure due to parser differential in form data handling** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: 25/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-74bb99c1ff3b5ed1fea8</code>; rule(s): <code>CVE-2026-53538</code>; source evidence: <code>finding-37828c3c6f1de39a916e</code>.
47. **multipart: Python-Multipart: Information disclosure via header parsing discrepancy** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: 25/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-e76230cbef200116e4ae</code>; rule(s): <code>CVE-2026-53537</code>; source evidence: <code>finding-0f80f106ffc0aeace60b</code>.
48. **python-multipart: Python-Multipart: Negative Content-Length in parse\_form buffers the entire body in memory** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: 25/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-f15e42abb7b2acd921f1</code>; rule(s): <code>CVE-2026-53540</code>; source evidence: <code>finding-b593d9dd6684fb6a9511</code>.
49. **Missing Content-Security-Policy header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 22/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-19f4a13e0b2d4f7413d0</code>; rule(s): <code>web.missing-content-security-policy</code>; source evidence: <code>runtime-4d5cb0113b221c088986a91b</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
50. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 22/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
51. **Missing X-Content-Type-Options header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 22/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-bbf1646deeb18d1e95db</code>; rule(s): <code>web.missing-content-type-protection</code>; source evidence: <code>runtime-a9347cabd53ecd99e38108cc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
52. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: 22/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
53. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-4c6d36222f8ebf7f1f68</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-06b259c78fa19fa5d06a773c</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
54. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-0bcbb317cfb96e7d5505</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-a39e9179918dd476f1e5dab4</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
55. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-a6e788cfc5d9d1297feb</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-2f9dcf012b09704cb4324d5b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
56. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-d716d5afb61da294d286</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-678ec39654e40601b76ef8f6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
57. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-916563c278b3e6b62930</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ad2c3148445dc879b11b7580</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
58. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-cad468186f9fd0b4e99b</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-c9199ae9fe5021a5d3738696</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
59. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
60. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
61. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
62. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: 12/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
63. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: 0/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.

## Security Review Agent Verdicts

### 1. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The source excerpt shows that after successful authentication the application logs the username and the value of the environment variable APP_SECRET using a standard info‑level logger. The scanner (semgrep) flags this as a credential disclosure (CWE‑532). No guard or redaction logic is present in the supplied snippet, so the secret is emitted to logs in clear text. However, there is no independent runtime probe confirming that the secret actually appears in log output, nor is there evidence that the logging configuration suppresses or masks the value. Consequently the finding is plausible but not definitively proven.

**Impact:** If the application logs the secret value, an attacker who can access log files (e.g., via compromised host, backup leakage, or log aggregation service) could obtain the APP_SECRET, potentially allowing token forgery, API abuse, or other privileged actions.

**Remediation:** Remove the secret from log statements. Either omit the APP_SECRET from logs entirely or replace it with a masked value (e.g., only log the first/last few characters). Use structured logging with redaction for sensitive fields, and ensure log storage is protected with proper access controls.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) – line 137 in api/app.py (scanner semgrep rule python.lang.security.audit.logging.logger-credential-leak)`

Limitations:
- No runtime probe confirming that the secret value is written to logs
- No evidence that logging configuration filters or masks the APP_SECRET
- No demonstration that an attacker can access the log output

### 2. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string without using parameterised queries or escaping. This creates a clear injection vector where an attacker can supply crafted input to manipulate the SQL statement.

**Impact:** An attacker could execute arbitrary SQL commands, potentially reading, modifying, or deleting data, bypassing authentication, or escalating privileges.

**Remediation:** Refactor the query to use parameterised statements (e.g., prepared statements) provided by the database library, and avoid string interpolation for user inputs. Example: `query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"; row = conn.execute(query, (body.username, body.password)).fetchone()`. Also consider hashing passwords instead of storing them in plain text.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- <code>Source excerpt shows f‑string interpolation of `body.username` and `body.password` into the SQL query (lines 117‑119).</code>
- `Scanner finding flagged this as a high‑severity issue.`

Limitations:
- No runtime probe evidence confirming that injection is exploitable in the running application.
- No evidence of existing input validation or sanitisation guards in the supplied context.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)`. This guard ensures the resulting path cannot escape the designated `public` directory, preventing path traversal. The subsequent `file.is_file()` check further validates the target. Thus the code safely handles the user input.

**Impact:** No path traversal vulnerability; an attacker cannot access files outside the intended directory.

**Remediation:** No remediation needed for path traversal; maintain the existing relative path check.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑223 show the use of `Path.resolve()` and `is_relative_to(root)` guard</code>

### 4. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint verifies that the resolved file path is a sub‑path of the designated public directory using `is_relative_to(root)` and also checks that the target is a regular file before reading it. This prevents directory‑traversal attacks despite the user‑controlled `name` parameter.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server. The existing guard mitigates that risk.

**Remediation:** No remediation needed for path traversal; ensure the guard remains unchanged and consider adding logging for denied attempts.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>source_excerpt lines 220‑223 show the `is_relative_to` and `is_file` checks that enforce the directory constraint.</code>

### 5. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against the known base directory and then verifies that the resulting path is still within that base using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** No impact; the endpoint safely restricts file access to the intended public directory.

**Remediation:** No remediation needed; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>The function builds the path with `(FILES / &quot;public&quot; / name).resolve()` and then checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404)` which blocks traversal and non‑file accesses.</code>

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the path expression is properly controlled.

**Impact:** No path traversal vulnerability; the file read is confined to the intended public directory.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>The code uses `root = (FILES / &quot;public&quot;).resolve()` and `file = (root / name).resolve()` followed by `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`, which ensures the resolved path stays within the public directory and refers to a file.</code>

### 7. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against the trusted base directory (FILES / "public") and then verifies that the resolved path is still within that base using `is_relative_to`. This check prevents directory traversal attacks, and the subsequent `is_file` guard ensures the target exists before reading. Consequently, the path expression is safely constrained and does not constitute a vulnerability.

**Impact:** None – the code correctly restricts file access to the intended directory, mitigating path traversal risks.

**Remediation:** No remediation needed; the existing checks are appropriate. Maintain the `is_relative_to` and `is_file` validations if the code is modified.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>Source excerpt shows `file = (FILES / &quot;public&quot; / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)` which enforces the directory constraint.</code>

### 8. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response (<code>&lt;h1&gt;Results for {q}&lt;/h1&gt;...</code>). No escaping or sanitisation is performed before the value is embedded in the page, allowing an attacker to inject arbitrary HTML/JavaScript that will be reflected back to the client. The same unsanitised value is also used in a raw SQL string, indicating a potential additional injection vector, but the XSS issue alone is sufficient for this finding.

**Impact:** An attacker can craft a URL such as <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> that, when visited, executes arbitrary JavaScript in the victim's browser. This can lead to session hijacking, credential theft, defacement, or further malicious actions against users of the application.

**Remediation:** - Validate and sanitise the `q` parameter before using it in any output. Use a templating engine that automatically escapes HTML, or explicitly escape special characters (e.g., `html.escape`).
- Use parameterised queries or an ORM to avoid SQL injection risks when incorporating `q` into database queries.
- Consider applying a Content Security Policy (CSP) to mitigate the impact of any reflected XSS that might slip through.
- Add unit/integration tests that verify proper escaping of user input in responses.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- <code>Source excerpt shows `q` directly embedded in HTML response without escaping (lines 142‑145).</code>
- `Scanner flagged this as a reflected XSS finding.`

Limitations:
- No runtime probe evidence confirming that injected payloads are actually executed in a browser context.
- No independent scanner of medium or higher severity beyond the original finding.
- No explicit guard or sanitisation logic is present in the supplied code snippet, but the surrounding code context is not fully visible; additional checks could exist elsewhere.

### 9. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks both that the resulting path is within the allowed directory (is_relative_to(FILES.resolve())) and that it points to an existing file (is_file()). These checks mitigate path traversal attacks, ensuring that only files under the designated public directory can be accessed.

**Impact:** If the checks were absent, an attacker could read arbitrary files on the server. However, the present checks prevent such unauthorized access, so no vulnerability is present.

**Remediation:** No remediation needed; the existing relative‑path check and file existence verification adequately protect against path traversal.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Source excerpt shows the use of Path.resolve() followed by is_relative_to(FILES.resolve()) and is_file() checks, which together enforce that the accessed file resides within the intended directory and exists.`

### 10. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` concatenates the query parameter `q` directly into an SQL statement using an f‑string. This creates a path where attacker‑controlled input reaches the database without any apparent sanitization, parameterization, or escaping, which is a classic SQL injection vector. No guard (e.g., input validation, ORM parameter binding, or allowlist) is visible in the supplied snippet.

**Impact:** An attacker could inject arbitrary SQL fragments (e.g., `' OR '1'='1`) to retrieve, modify, or delete data from the `products` table, potentially leading to data leakage, data corruption, or privilege escalation.

**Remediation:** Replace the string‑interpolated query with a parameterized query using the database driver’s placeholders (e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`). Additionally, validate or whitelist the `q` parameter to ensure it conforms to expected patterns.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt shows `conn.execute(f&quot;SELECT name FROM products WHERE name ILIKE &#x27;%{q}%&#x27;&quot;)` where `q` is a request query parameter.</code>
- `Scanner finding flagged the line as user‑controlled SQL construction.`

Limitations:
- No runtime probe evidence confirming that malicious input is actually executed.
- No evidence of existing input sanitization or ORM usage elsewhere in the codebase.
- No guard checks are visible in the provided context, but they could exist outside the excerpt.

### 11. X-Content-Type-Options Header Missing

- Issue group: `merged-4c6d36222f8ebf7f1f68`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for the root path (/) does not include the X-Content-Type-Options header. The provided source excerpt shows the FastAPI endpoint implementation but does not set any response headers, and no middleware or configuration is shown that would add this security header. Without explicit code adding the header, the finding is plausible, but the evidence is limited to the scanner observation; no independent code proof is present.

**Impact:** Absence of the X-Content-Type-Options: nosniff header allows browsers to perform MIME type sniffing, potentially enabling content injection attacks such as cross-site scripting (XSS) when content is misinterpreted.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options header on all responses, e.g., by adding a middleware that sets `response.headers['X-Content-Type-Options'] = 'nosniff'` or by using a security library such as `starlette.middleware` or `secure` to add the header globally.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Scanner runtime probe (zap.10021) observed a GET request to '/' with no X-Content-Type-Options header in the response.`

Limitations:
- No source code fragment showing header injection or middleware configuration is provided, so the absence of the header cannot be confirmed from the code alone. Additional evidence such as the full FastAPI app configuration or middleware setup is needed to verify whether the header is truly missing.

### 12. Job listing requires admin role

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs endpoint calls a function principal(authorization) but the provided source excerpt does not show any verification that the caller has an admin role before accessing the job listings. The runtime probe indicates that an unauthenticated GET request receives a 200 OK response, whereas the scanner expected a 403/404, suggesting the endpoint is accessible without proper authorization.

**Impact:** An attacker could retrieve the full list of jobs, potentially exposing sensitive internal data or enabling further privilege escalation.

**Remediation:** Ensure that the principal function validates that the authenticated user possesses the required admin role before executing the database query. Add explicit role checks and return 403 Forbidden for unauthorized users.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs endpoint calling principal without visible role verification (lines 285‑290).`
- `Runtime probe fact: GET /admin/jobs returned status 200 instead of expected 403/404 (web-runtime rule workflow.admin_jobs.2).`

Limitations:
- The implementation of principal(authorization) is not provided, so it is unclear whether it performs an admin role check internally. Confirmation requires reviewing that function or additional evidence that role enforcement is absent.

### 13. A demoted administrator must lose administrative access

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/token-report checks the role in the provided token and returns 403 if the role is not "admin". However, a runtime probe observed a successful 200 response for a GET request, indicating that a token belonging to a demoted administrator was still accepted as having admin privileges. The source code does not show how the token is created or validated, so it is unclear whether the role check is effective. The observed behavior suggests a privilege escalation issue, but the evidence is incomplete.

**Impact:** A user whose administrative privileges have been revoked may still be able to access admin‑only functionality, leading to unauthorized actions and potential data compromise.

**Remediation:** Ensure that token issuance and validation correctly reflect the current role of the user. Invalidate or re‑issue tokens when a user's role changes, and verify the role claim against the authoritative user store on each request.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check at line 663‑664 and raises HTTPException(403) for non‑admin tokens.`
- `Runtime probe fact from web-runtime scanner reports a GET to /admin/token-report returned status 200 instead of the expected 403.`

Limitations:
- Missing evidence of how the token is generated and whether the role claim is updated when an administrator is demoted.
- No view of the authentication/authorization middleware that populates the token used by principal().
- Unable to confirm that the token presented in the probe truly belonged to a demoted administrator.

### 14. User listing endpoint may lack proper admin authorization check

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users endpoint calls a function principal(authorization) but the provided excerpt does not show any verification that the caller has an admin role before returning the full user list, which includes sensitive fields such as SSN. Runtime probing observed a successful GET request returning HTTP 200, contrary to the expected 403/404, indicating the endpoint is reachable without proper restriction. However, the implementation of principal is not included, so it is unclear whether it performs the necessary role check.

**Impact:** If an unauthenticated or non‑admin user can access this endpoint, they could retrieve all user records, including personally identifiable information (PII) such as SSNs, leading to privacy breaches and potential regulatory violations.

**Remediation:** Ensure that the endpoint enforces an admin‑only check before querying and returning user data. For example, verify the caller’s role inside principal or add an explicit role check in admin_users and return 403 for non‑admin users. Also consider limiting the fields returned to only those necessary.
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source excerpt shows admin_users calls principal but no visible admin role verification`
- `Runtime probe fact: GET /admin/users returned status 200 instead of expected 403/404`

Limitations:
- Implementation of principal(authorization) is not provided, so we cannot confirm whether it enforces admin role checks
- No additional scanner evidence confirming the absence of authorization logic beyond the observed 200 response

### 15. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code sets a session cookie (lab_session) without specifying the HttpOnly attribute, which can allow client‑side scripts to access the cookie. The source excerpt shows the set_cookie call without HttpOnly, and the runtime probe confirms the POST endpoint is reachable, but there is no evidence that the missing flag is exploitable in the current context.

**Impact:** An attacker who can inject JavaScript (e.g., via XSS) could read the session cookie and hijack the user’s session.

**Remediation:** Set the HttpOnly flag when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)`. Consider also adding Secure and SameSite attributes.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- <code>source_excerpt line 300 shows `response.set_cookie(&quot;lab_session&quot;, f&quot;session-{row[&#x27;id&#x27;]}&quot;)` without HttpOnly</code>
- `runtime_probe_facts indicates a POST request to /auth/form-login was observed`

Limitations:
- No evidence that client‑side script execution is possible in the application (no XSS proof)
- No observation that the cookie is transmitted over insecure channels (e.g., HTTP)
- No scanner finding of medium or higher severity confirming exploitation

### 16. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reports that the response from the /auth/form-login endpoint does not include an anti-clickjacking header (e.g., X-Frame-Options or Content‑Security‑Policy frame‑ancestors). The provided source excerpt shows the endpoint implementation but does not set any such header on the returned HTMLResponse. No guard or header‑setting logic is visible in the supplied code.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and perform clickjacking attacks, potentially tricking users into submitting credentials to the attacker’s site.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, for example:
```python
response = HTMLResponse(f"Signed in as {html.escape(row\['username'\])}")
response.headers\['X-Frame-Options'\] = 'DENY'  # or SAMEORIGIN
# or use a CSP header: response.headers\['Content-Security-Policy'\] = "frame-ancestors 'none'"
return response
```
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Scanner runtime fact (zap.10020) indicates a POST request to /auth/form-login without the anti‑clickjacking header.`

Limitations:
- No direct observation of the actual HTTP response headers from the running application; the finding relies solely on the scanner’s detection. Confirming the header is truly missing requires runtime capture of the response or code that explicitly sets the header.

### 17. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The supplied source excerpt shows the login endpoint implementation but does not include any logic that sets a Content‑Security‑Policy header on the response. The runtime probe fact from the ZAP scanner reports that a POST request to /auth/form‑login was made and the CSP header was not observed. No code is present that adds such a header, and no other evidence (e.g., middleware, framework defaults) is provided.

**Impact:** Without a CSP header, the application is vulnerable to certain cross‑site scripting (XSS) and data‑injection attacks because browsers are not instructed to restrict the sources from which scripts, styles, or other resources may be loaded.

**Remediation:** Add a CSP header to the HTTP response for all relevant endpoints, preferably via a security‑focused middleware or response‑header configuration. For example, set a header like `Content‑Security‑Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and ensure it is applied consistently across the application.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Runtime probe fact from ZAP (scanner_id: web-runtime, rule_id: zap.10038) indicates the CSP header was missing on a POST request to /auth/form-login.`
- <code>Source excerpt shows no call to `response.headers` or middleware that would set a CSP header.</code>

Limitations:
- The review is based on the provided code snippet and a single scanner observation; full header configuration (e.g., global middleware) was not visible. Confirmation would require observing the actual HTTP response headers from the running application or reviewing the complete application configuration to ensure no CSP header is set elsewhere.

### 18. Password reset tokens must be single use

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The confirm_reset endpoint retrieves a reset token from the database and, if valid, updates the user's password without any check that the token has not been used before or without invalidating the token after use. The runtime probe shows that a POST to /auth/reset/confirm returns HTTP 200 on a reused token, confirming that the token can be replayed. This demonstrates a missing guard (single‑use enforcement) and an exploitable path to reset a password multiple times with the same token.

**Impact:** An attacker who obtains a valid password‑reset token can reuse it to reset the victim's password repeatedly, leading to account takeover and loss of confidentiality and integrity of the user’s account.

**Remediation:** Invalidate or delete the reset token after a successful password change, and enforce a one‑time‑use check before processing the reset. Example: after updating the password, execute a DELETE on the reset_tokens table for the used token, and ensure the token is marked as used before any password change operation.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup and password update without token invalidation (lines 577‑585).`
- `Runtime probe fact indicates POST /auth/reset/confirm returned 200 instead of expected error codes, confirming token replay is possible (workflow.reset_replay.3).`

### 19. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /catalog/query returns HTML content but the supplied source excerpt and runtime probe do not show any HTTP response headers being set. No code is present that adds a CSP header, and the runtime probe only records the request method without header details. This suggests the CSP header may be missing, which is a security concern, but there is no direct evidence (e.g., captured response headers) confirming its absence.

**Impact:** Without a CSP header, the application is vulnerable to cross‑site scripting (XSS) and other content injection attacks, allowing an attacker to execute malicious scripts in the context of the user’s browser.

**Remediation:** Add a CSP header to the response, for example by using FastAPI's middleware or setting the header in the route handler: `response.headers['Content‑Security‑Policy'] = "default-src 'self'"`. Ensure the policy covers script, style, and other resource sources as appropriate.
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Source excerpt shows the route returns HTML without setting any security headers.`
- `Runtime probe fact records a GET request to /catalog/query but does not include response header data.`

Limitations:
- Missing captured HTTP response showing that the CSP header is absent.
- No evidence from a scanner or runtime probe that explicitly confirms the header is not present.

### 20. X-Content-Type-Options Header Missing

- Issue group: `merged-a6e788cfc5d9d1297feb`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime scanner observed that the HTTP response for GET /catalog/query does not include the X-Content-Type-Options header. The source code does not set this header anywhere, and no configuration evidence was provided that it is added by middleware or a reverse proxy. The missing header can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks.

**Impact:** An attacker could craft a response that causes the browser to interpret content as a different MIME type (e.g., executing HTML/JavaScript from a JSON endpoint), increasing the risk of cross‑site scripting or drive‑by attacks.

**Remediation:** Add the X-Content-Type-Options: nosniff header to all HTTP responses. This can be done by: • Adding a FastAPI middleware that sets the header on every response, or • Configuring the web server/reverse proxy (e.g., Nginx, Apache) to include the header globally.
Evidence:
- Source IDs: `merged-a6e788cfc5d9d1297feb`
- `Runtime scanner (zap.10021) reported missing X-Content-Type-Options header on GET /catalog/query`

Limitations:
- No deployment configuration was supplied to confirm whether a reverse‑proxy or external middleware might already add the header. The finding relies solely on the scanner observation; additional runtime checks or server config review would confirm the header is truly absent.

### 21. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting any X-Frame-Options or Content-Security-Policy frame-ancestors directives. The source excerpt shows the response is constructed and returned directly, and the runtime probe confirms a GET request to this path. No code is present that adds anti-clickjacking headers, and no guard or configuration is shown in the supplied context.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti-clickjacking headers to the response, e.g., set X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self'. This can be done globally via middleware or per‑endpoint using FastAPI's Response headers.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact indicates a GET request to /catalog/query with no header evidence`

Limitations:
- No evidence was provided that the application sets anti-clickjacking headers elsewhere (e.g., middleware, server configuration). The review cannot confirm whether a header might be added outside the shown code.

### 22. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns an HTML response without an `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header. The scanner flagged this as a missing anti‑clickjacking header. No code in the provided excerpt sets response headers, and the runtime probe only confirms the GET request succeeded, not that the header is present or absent.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into unintended actions.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP `frame-ancestors 'none'` in the FastAPI response middleware.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Scanner finding: Missing Anti-clickjacking Header (zap.10020) for path /comments`
- `Source excerpt shows HTMLResponse returned without header manipulation`

Limitations:
- No runtime observation of the actual HTTP response headers confirming the header is absent
- No evidence that the application sets security headers elsewhere (e.g., global middleware)

### 23. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns HTML content without any indication that a Content‑Security‑Policy header is added to the response. The source excerpt shows the function builds an HTML string and returns it directly, and the runtime probe confirms a GET request to this path but does not report CSP headers. No code is present that sets security headers, and no guard or middleware is shown in the supplied context.

**Impact:** Without a CSP header, browsers are free to execute inline scripts or load resources from any origin, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks.

**Remediation:** Add a CSP header to the response, either by configuring the FastAPI application to include security headers globally (e.g., using `Starlette` middleware) or by setting the header explicitly in the `show_comments` endpoint before returning the HTML.
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- `Source excerpt shows HTML is returned without header handling (lines 173‑177).`
- <code>Runtime probe fact confirms a GET request to `/comments` but does not include CSP header information.</code>

Limitations:
- No evidence is provided that the application sets CSP headers elsewhere (e.g., global middleware, reverse‑proxy configuration).
- The runtime probe does not capture response headers, so the absence of CSP cannot be definitively confirmed.

### 24. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content without setting the `X-Content-Type-Options: nosniff` header. The source excerpt shows the response is built and returned directly, and no header-setting code is present. A runtime probe from ZAP flags the missing header, providing scanner evidence of the issue. However, the evidence does not include an actual captured response showing the header absence, and the scanner finding is low severity, so the confirmation criteria are not fully met.

**Impact:** Without the `X-Content-Type-Options` header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response. In FastAPI this can be done with a middleware or by setting the header in the route, e.g., `return Response(content=html, media_type="text/html", headers={"X-Content-Type-Options": "nosniff"})`.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- <code>Source excerpt shows `/comments` endpoint returns HTML without header logic (lines 173‑177).</code>
- `Runtime probe fact from ZAP (zap.10021) flags missing X-Content-Type-Options on GET /comments.`

Limitations:
- No captured HTTP response headers confirming the header is absent.
- Scanner severity is low; higher‑confidence evidence (e.g., a medium/high severity scanner or independent runtime test) is missing.

### 25. Debug configuration is exposed without authentication

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /debug/config returns sensitive configuration values (database URL, mock external URL, app secret) without any access control checks. The source excerpt shows the function returns these values directly. A runtime probe confirms that an unauthenticated GET request receives a 200 response, whereas the expected statuses were 401/403/404, indicating the endpoint is publicly accessible.

**Impact:** An attacker can retrieve internal configuration data, including database connection strings and secret keys, enabling further attacks such as database compromise, credential reuse, or service manipulation.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint. Ensure it returns a 401/403 response for unauthenticated or unauthorized requests, and consider removing or restricting exposure of sensitive values in production environments.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source code defines debug_config() at /debug/config that returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks`
- `Runtime probe fact: GET /debug/config returned status 200 (expected 401/403/404)`

### 26. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe for the /healthz endpoint returned a 200 response without a Content‑Security‑Policy header. The source code for the endpoint does not show any logic that adds security headers, and no other evidence of a header‑setting middleware is provided. This suggests the application may be serving responses without CSP protection, which can allow injection of malicious scripts in browsers that consume the API responses.

**Impact:** Absence of a CSP header reduces defense‑in‑depth against cross‑site scripting (XSS) and data‑injection attacks when the endpoint is rendered in a browser context or when its responses are embedded in other pages.

**Remediation:** Add a Content‑Security‑Policy header to all HTTP responses, either by configuring the FastAPI app with a middleware (e.g., Starlette's SecurityHeadersMiddleware) or by setting the header explicitly in each route. Ensure the policy is appropriate for the content served.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Runtime probe fact: path "/healthz" returned status 200 with no Content‑Security‑Policy header (web.missing-content-security-policy)`

Limitations:
- The review lacks a full view of the application's middleware stack; a global security‑header middleware could be adding CSP elsewhere. The actual response headers were not captured in the provided data, so the missing header is inferred from the probe rather than directly observed. Confirmation requires inspecting the complete HTTP response headers or the code that configures response headers.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response but no evidence of X-Frame-Options or Content-Security-Policy headers that would prevent clickjacking. The scanner rule flags the missing header, and the source code does not set any such header. However, the runtime probe only reports the status code and does not capture response headers, so the absence of the protection header is not directly observed.

**Impact:** An attacker could embed the /healthz page in a malicious site using an iframe, potentially tricking users into interacting with the endpoint in a clickjacking scenario.

**Remediation:** Add appropriate clickjacking protection headers (e.g., X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self') to the response for the /healthz endpoint, either globally via middleware or within the endpoint handler.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner rule web.missing-clickjacking-protection flagged /healthz`
- `Source code shows /healthz endpoint without header logic`

Limitations:
- Runtime probe did not capture response headers, so the missing header is not directly verified; need header inspection evidence.

### 28. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a JSON payload but the supplied source code and runtime probe do not show any HTTP response header configuration. No evidence is provided that the X-Content-Type-Options header is set, which is required to mitigate MIME‑type sniffing attacks. The scanner flagged the missing header, but without seeing the actual response headers or code that adds them, the finding cannot be fully confirmed.

**Impact:** An attacker could exploit MIME‑type sniffing to execute malicious content in the context of the application, potentially leading to cross‑site scripting or other client‑side attacks.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to include the header, e.g., using a middleware that adds `X-Content-Type-Options: nosniff` to all responses, or set it explicitly in the route response.
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Source excerpt shows the /healthz route implementation without any header manipulation.`
- `Runtime probe fact (zap.10021) indicates a GET request to /healthz but does not include response header data.`

Limitations:
- Missing concrete evidence of the actual HTTP response headers for /healthz.
- No code or configuration snippet that sets or omits the X-Content-Type-Options header.
- No independent scanner result of medium or higher severity confirming the header is absent.

### 29. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports that the /healthz endpoint does not include the X-Content-Type-Options header. The source code shows the endpoint returns a JSON payload but does not set any response headers. No runtime probe data confirming the absence of the header is provided, only a 200 status code. Without direct evidence of the missing header, the finding remains a likely vulnerability.

**Impact:** Absence of the X-Content-Type-Options header can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks.

**Remediation:** Add the header to the response, e.g., `Response(headers={"X-Content-Type-Options": "nosniff"})` or configure the framework to include it globally.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Scanner report: Missing X-Content-Type-Options header on /healthz`
- `Source excerpt shows endpoint implementation without header manipulation`

Limitations:
- No runtime probe or network capture confirming the header is absent
- No evidence that the application framework automatically adds the header

### 30. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/integrations/hook` accepts a POST request, reads the raw body, and stores it directly in the database without any verification of a cryptographic signature or authentication token. The supplied source excerpt shows no signature validation logic before the data is persisted. A runtime probe sent a POST request to this endpoint and received a 200 OK response, whereas the probe contract expected a 4xx response for unsigned requests, indicating the endpoint processes unauthenticated payloads.

**Impact:** An attacker can craft arbitrary webhook payloads and submit them to the endpoint, causing unauthorized data insertion, potential injection attacks, or abuse of downstream processing that trusts the stored data. This may lead to data corruption, privilege escalation, or further exploitation of the system.

**Remediation:** Implement verification of a request signature (e.g., HMAC with a shared secret) or require authentication (e.g., API key, JWT) before processing the payload. Return a 4xx error for requests that fail verification. Additionally, validate and sanitize the payload before inserting it into the database.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- <code>Source excerpt shows direct insertion of `body` into `visits` table without signature check (lines 629‑633).</code>
- <code>Runtime probe fact: POST to `/integrations/hook` returned status 200, while expected statuses for unsigned requests were 400, 401, 403.</code>

Limitations:
- No evidence is provided that signature verification is performed elsewhere (e.g., middleware, upstream proxy). The runtime probe only demonstrates a single successful unauthenticated request; additional probes confirming consistent behavior would strengthen the case.

### 31. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice before returning the data. The code fetches the invoice row solely by ID and returns it if found, without any ownership check. Runtime probe evidence shows that a GET request to this endpoint returns HTTP 200 (success) instead of the expected 403 (forbidden) when the requester is not the owner, confirming the missing access control.

**Impact:** An attacker who can authenticate (or possibly without authentication if `principal` does not enforce it) can retrieve any invoice by ID, leading to exposure of sensitive financial information and violation of confidentiality.

**Remediation:** Add an ownership check after retrieving the invoice row, e.g., compare the invoice's `owner_id` with the authenticated user's ID and raise `HTTPException(403)` if they do not match. Ensure `principal` returns the user identity and that the check is enforced for all access paths.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- `Source excerpt shows no ownership verification before returning the invoice (lines 268‑274).`
- `Runtime probe fact indicates the request returned status 200 instead of 403, demonstrating the lack of access control.`

### 32. Insufficient authorization check on job creation endpoint

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint calls `principal(authorization)` but does not verify that the authenticated principal has permission to create admin jobs. The runtime probe shows the endpoint returns HTTP 200 for a request that should be rejected (expected 400/403/422), indicating the missing authorization guard. No additional scanner or code evidence demonstrates a role check before the INSERT operation.

**Impact:** An attacker who can obtain or forge an authorization header could create arbitrary jobs, potentially with elevated privileges, leading to unauthorized actions or data manipulation within the system.

**Remediation:** Add explicit role/permission validation after extracting the principal, ensuring only authorized users can create admin jobs. Return appropriate error codes (e.g., 403) when the check fails, and log unauthorized attempts.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- <code>Source excerpt shows `principal(authorization)` called without subsequent role verification before inserting into the jobs table.</code>
- `Runtime probe fact: POST /jobs returned status 200, while expected statuses were 400, 403, or 422, indicating the request was accepted without proper validation.`

Limitations:
- Missing explicit code evidence of a role check or guard in the supplied snippet; need to see the implementation of `principal` and any downstream authorization logic.
- No independent scanner finding of medium or higher severity confirming the flaw; only the runtime probe and source snippet are available.

### 33. Identity endpoint may expose SSN

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The source excerpt shows that the /me endpoint queries the users table for the ssn column and returns the entire row as a dictionary, which would include the social security number. No access control or redaction logic is present in the supplied code. A runtime probe indicates the request succeeded (status 200) but only notes that values were redacted, without showing the actual payload, so the presence of the SSN in the response is not independently confirmed.

**Impact:** If the SSN is returned to the client, an attacker who can call /me could obtain sensitive personal information, leading to identity theft and regulatory compliance violations.

**Remediation:** Modify the endpoint to exclude the ssn field from the returned data or explicitly redact it before returning the response. Implement proper access controls to ensure only authorized users can view sensitive fields.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source code selects ssn column and returns dict(row) (lines 200-204)`
- `Runtime probe shows GET /me returns 200 with values_redacted flag but does not reveal actual content`

Limitations:
- Missing concrete response data showing whether the SSN is present or redacted
- No evidence of additional guard checks (e.g., role‑based filtering or field‑level masking) outside the provided snippet

### 34. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price value directly from the request body into the database without any server‑side validation or lookup against a trusted price catalog. No guard or check is visible in the supplied code snippet. A runtime probe indicates mixed assertion results for the price‑catalog workflow, but it does not conclusively demonstrate that a client‑supplied price is accepted and persisted.

**Impact:** An attacker could submit an order with a manipulated unit_price, potentially purchasing items at a reduced cost or inflating prices for fraudulent billing, leading to financial loss and integrity violations.

**Remediation:** Implement server‑side price determination: retrieve the official price for the requested item from a trusted catalog or database and ignore any client‑provided unit_price. Validate and sanitize all order fields before insertion. Add appropriate logging and authorization checks.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt shows unit_price taken directly from body and inserted into DB (lines 213‑215).`
- `Runtime probe facts report mixed assertion results for the price_catalog workflow, indicating the check may be missing or ineffective.`

Limitations:
- Missing concrete proof that a client can submit an arbitrary price and have it stored (e.g., a successful exploit test or detailed scanner finding confirming the vulnerability).
- No evidence of existing guard logic elsewhere in the codebase that might enforce price integrity.

### 35. New orders can be created with arbitrary status

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts a new order using the status value supplied in the request body without any validation. The runtime probe shows that a POST to /orders returned HTTP 200 instead of the expected 400/422, confirming that the endpoint accepts the request and creates the order with the provided status, including potentially a paid status. This demonstrates an unchecked path to a sensitive operation (order creation with status control).

**Impact:** An attacker can create orders marked as paid without completing the payment workflow, leading to financial fraud, inventory inconsistencies, and potential revenue loss.

**Remediation:** Validate the order status on creation. Reject or ignore any status other than the allowed initial state (e.g., "pending"). Implement server‑side checks to enforce that only the payment service can set a paid status, and return 400/422 for invalid status values.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- `Source excerpt shows create_order inserts the status field directly from the request body (lines 208‑215).`
- `Runtime probe fact: POST /orders returned status 200 when a 400/422 was expected, indicating the endpoint accepted the request without validation.`

### 36. Negative order prices are not rejected

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the supplied unit_price directly into the database without any validation. A runtime probe attempted to submit a negative price and received a 200 OK response, while the scanner expected a 400/422 error. No input‑validation guard is visible in the supplied code snippet, indicating that negative prices may be accepted and stored.

**Impact:** An attacker could create orders with negative prices, potentially leading to unauthorized refunds, inventory manipulation, or financial loss.

**Remediation:** Add validation for the unit_price (and any other numeric fields) to ensure it is non‑negative before executing the INSERT. Return a 4xx error if validation fails.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`
- `Source excerpt shows no validation before database insert`

Limitations:
- The provided excerpt does not include any surrounding middleware or decorator that might perform validation, so the presence of a guard elsewhere cannot be ruled out. Additional code (e.g., request models, validators, or global request hooks) needs to be reviewed to confirm the absence of checks.

### 37. Users can create orders for another owner

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and defaults to the authenticated user's sub when not provided. No authorization check is performed to ensure the supplied owner_id belongs to the caller. The runtime probe confirms that a POST to /orders with a different owner_id returns HTTP 200 instead of the expected 4xx, demonstrating the missing guard in practice.

**Impact:** An attacker can create orders on behalf of any user, leading to unauthorized transactions, potential financial loss, and abuse of the ordering system.

**Remediation:** Validate that the owner_id in the request matches the authenticated user's identifier (user\["sub"\]). Reject the request with 403/401 if they differ, or remove the owner_id field entirely and always use the caller's identity.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows create_order uses owner_id = body.owner_id or user["sub"] without further checks`
- `Runtime probe fact: POST /orders returned status 200 when owner_id was set to a different user, contrary to expected 4xx`

### 38. A note must belong to the order named in the URL

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID without verifying that the note's `order_id` matches the `order_id` supplied in the URL. The source excerpt shows the query selects the note solely by `note_id` and returns it if found, with no additional ownership check. A runtime probe confirms the flaw: a GET request to `/orders/1/notes/2` returns HTTP 200 instead of the expected 403 or 404, indicating the missing validation is exploitable.

**Impact:** An attacker can enumerate or retrieve notes belonging to other orders by guessing note IDs, leading to unauthorized disclosure of potentially sensitive information.

**Remediation:** Add a check that the `order_id` of the retrieved note matches the `order_id` path parameter. If they differ, return a 403 Forbidden (or 404 to avoid information leakage). Example:
```python
row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()
if not row or row\["order_id"\] != order_id:
    raise HTTPException(403, "Forbidden")
return dict(row)
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- <code>Source code shows note fetched only by `note_id` without order validation (lines 543‑549).</code>
- <code>Runtime probe fact: GET `/orders/1/notes/2` returned status 200, while expected statuses were 403 or 404 (rule `workflow.nested_note.1`).</code>

### 39. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}` calls `principal(authorization)` but does not verify that the authenticated user is the owner of the requested order before returning the record. The source excerpt shows no ownership check after the database query. A runtime probe for the same path returned HTTP 200 for a request that should have been denied (expected 403), confirming that the missing check is exploitable.

**Impact:** An attacker who can obtain a valid authorization header can retrieve any order by ID, leading to unauthorized disclosure of potentially sensitive order data.

**Remediation:** Add an ownership verification step after fetching the order, e.g., compare the order's `owner_id` with the authenticated principal and raise HTTP 403 if they differ. Ensure the check is performed before returning the order data.
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- <code>Source excerpt shows `principal(authorization)` is called but no ownership validation before returning the order (lines 221‑227).</code>
- <code>Runtime probe fact `workflow.order_owner.3` reports a GET request to `/orders/{{order_id}}` returned status 200 instead of the expected 403, indicating the owner check is missing.</code>

### 40. Insufficient validation of coupon discount values

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/apply-coupon` accepts a user‑supplied `discount` value and falls back to the coupon's stored percent. No validation is performed to ensure the resulting discount is within acceptable bounds (e.g., not exceeding 100% or a business‑defined maximum). The runtime probe shows the request returning HTTP 200 instead of the expected 400/422 when an excessive discount is supplied, indicating the check is missing.

**Impact:** An attacker could apply arbitrarily large discounts to orders, potentially resulting in revenue loss or unauthorized free purchases.

**Remediation:** Add explicit validation of the `percent`/`discount` value before updating the order. Reject values that exceed the allowed maximum (e.g., &gt; 100 % or a configured limit) and return a 4xx error. Consider centralising discount validation in a helper function and logging rejected attempts.
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- <code>Source excerpt shows no bounds check on `percent` before the UPDATE statement (lines 231‑237).</code>
- `Runtime probe fact reports a 200 response for an excessive discount where a 400/422 was expected (rule workflow.coupon_bounds.2).`

Limitations:
- Missing explicit test cases confirming the maximum allowed discount value.
- No evidence of server‑side configuration that might enforce discount limits elsewhere in the codebase.

### 41. Paid orders can be cancelled without refund

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The cancel_order endpoint updates the order status to 'cancelled' without verifying whether the order has been paid or whether a refund has been issued. The source excerpt shows no check of payment status before the UPDATE statement. Runtime probe evidence reports a successful 200 response for a paid‑cancel workflow step that should have been rejected (expected 400/409/422). This independent runtime observation corroborates the scanner finding, satisfying the criteria for a confirmed vulnerability.

**Impact:** An attacker can cancel paid orders and potentially avoid refund processing, leading to financial loss and unauthorized order state changes.

**Remediation:** Add logic to verify that the order is unpaid or that a refund has been processed before allowing cancellation. Return an appropriate error (e.g., 400 Bad Request) if the order is already paid without a refund. Ensure the check is performed before the UPDATE statement.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- `Source excerpt shows cancel_order endpoint directly updates order status without payment check (lines 259‑263).`
- `Runtime probe fact: method POST to /orders/{{order_id}}/cancel returned status 200 when a 400/409/422 was expected for a paid‑cancel workflow step.`

### 42. Potential payment replay vulnerability in order payment endpoint

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders/{order_id}/pay endpoint updates the order status to 'paid' without checking whether the order has already been paid. The source excerpt shows the status is set unconditionally after retrieving the order. A runtime probe observed a successful 200 response for a repeated payment attempt, whereas the scanner expected error statuses (400, 409, 422). This indicates the endpoint may allow a second payment on an already paid order, but no evidence of a guard elsewhere in the supplied code was found.

**Impact:** An attacker could replay a payment request to cause double charging, generate duplicate invoices, or otherwise manipulate order state, leading to financial loss and data integrity issues.

**Remediation:** Add a check before updating the order status to verify that the order is not already marked as 'paid'. Return an appropriate error (e.g., 409 Conflict) if a payment is attempted on a paid order. Ensure the check is performed within the same transaction to avoid race conditions.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- `Source excerpt shows unconditional status update at line 249`
- `Runtime probe fact reports POST returned 200 instead of expected error status`

Limitations:
- No evidence was provided that a guard check exists elsewhere in the codebase (e.g., middleware or database constraint). The runtime probe is the only independent confirmation of the flaw.

### 43. Insecure profile access allows reading other users' data

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /profiles/{profile_id} endpoint retrieves user data based solely on the supplied profile_id after calling principal(authorization) but does not verify that the authenticated user owns the requested profile. The runtime probe confirms that a request for another user's profile returns HTTP 200 instead of the expected 403/404, demonstrating the missing ownership check in practice.

**Impact:** An attacker who can obtain a valid authorization token can enumerate and read sensitive information (username, email, SSN) of any user by iterating profile IDs, leading to privacy breaches and potential identity theft.

**Remediation:** Add an ownership check after fetching the row to ensure the authenticated user's ID matches the profile_id before returning data. Return 403 Forbidden or 404 Not Found when the user is not authorized to view the profile. Example:
```python
user_id = get_user_id_from_token(authorization)
if row\['id'\] != user_id:
    raise HTTPException(403, "Forbidden")
```
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source code shows endpoint without ownership verification (lines 98-104)`
- `Runtime probe fact indicates GET /profiles/{{other_id}} returned status 200 instead of 403/404`

### 44. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /view endpoint returns an HTMLResponse without any X-Frame-Options or Content-Security-Policy frame-ancestors directives, indicating the anti-clickjacking header is missing. No evidence of a header being set elsewhere in the supplied code or runtime probe is present.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add an appropriate X-Frame-Options header (e.g., "DENY" or "SAMEORIGIN") or a Content-Security-Policy with a frame-ancestors directive to the response in the view_home handler.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse returned without security headers (lines 686-690).`
- `Runtime probe fact confirms a GET request to /view was made (web-runtime zap.10020).`
- `Scanner evidence flagged missing anti-clickjacking header.`

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /view returns an HTMLResponse without setting a Content‑Security‑Policy header. The source excerpt shows the response is constructed directly and no header is added. A scanner flagged the missing CSP header, providing an independent indication of the issue, but there is no runtime probe confirming that the header is absent in actual responses.

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, and other resources can be loaded, increasing the risk of cross‑site scripting (XSS) and data‑injection attacks.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response headers or a middleware that injects a strict‑CSP policy. Example:
```python
from fastapi import Response

@router.get("/view")
def view_home() -&gt; Response:
    html = "..."
    return Response(content=html, media_type="text/html", headers={"Content‑Security‑Policy": "default-src 'self'; script-src 'self'; style-src 'self'"})
```
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- `Source excerpt shows HTMLResponse returned without CSP header`
- `Scanner finding "Content Security Policy (CSP) Header Not Set"`

Limitations:
- No runtime observation confirming that the CSP header is missing in actual HTTP responses; a probe that captures response headers would be needed to confirm the vulnerability.

### 46. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /view returns an HTMLResponse without explicitly setting the X-Content-Type-Options header. The source excerpt shows the response construction, and no code is present that adds security headers. A runtime probe observed a GET request to /view, but did not capture response headers to confirm the header is absent.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may incorrectly sniff content types, potentially allowing content injection attacks such as cross-site scripting.

**Remediation:** Add the X-Content-Type-Options header with the value "nosniff" to the response, e.g., by using a middleware or setting the header directly in the view function.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- `Source excerpt shows HTMLResponse returned without header configuration (lines 686-690).`
- `Runtime probe fact indicates a GET request to /view was made (web-runtime zap.10021).`

Limitations:
- Missing captured response headers to definitively prove the header is absent.
- No evidence that a global middleware might be adding the header elsewhere in the application.

### 47. Insufficient validation of webhook destination URL

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /webhooks endpoint only checks that the submitted target_url contains the substring "mock-external" and otherwise raises a 400 error. This allows any URL that includes that substring, including potentially attacker‑controlled internal addresses, to be accepted and stored in the database. The runtime probe shows a POST request receiving a 200 response, indicating the check did not block the request in practice. However, the supplied evidence does not demonstrate that an attacker can reach a sensitive internal host or cause harmful behavior (e.g., SSRF).

**Impact:** An attacker could supply a crafted target_url that passes the weak substring check and cause the service to issue requests to internal resources, leading to SSRF, data exfiltration, or other downstream attacks.

**Remediation:** Validate the target_url against an explicit whitelist of approved internal hosts or use a strict URL parsing/validation library. Reject any URL that does not exactly match the approved host, and avoid substring checks. Consider normalizing the URL and comparing the hostname component.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- `Source excerpt lines 293‑298 showing the substring check on target_url`
- `Runtime probe fact: POST to /webhooks returned status 200 despite expected 400/422`

Limitations:
- Missing proof that an attacker can supply a malicious URL that both contains "mock-external" and points to an internal resource
- No evidence that the stored URL is later used to make outbound requests, which would confirm an SSRF risk

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds a CORS middleware with `allow_origins=["*"]`, which permits any website to make cross‑origin requests to the API. The supplied source excerpt shows this configuration and no additional runtime checks or origin validation are present in the provided context.

**Impact:** An attacker can host a malicious site that interacts with the API from a user's browser, potentially exfiltrating data or performing actions on behalf of authenticated users if credentials are sent with requests.

**Remediation:** Restrict `allow_origins` to a whitelist of trusted domains, or implement dynamic origin validation. If credentials are required, ensure `allow_credentials` is only true for trusted origins. Consider using more granular `allow_methods` and `allow_headers` settings.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py lines 24‑30 show CORS middleware with allow_origins=["*"]`

Limitations:
- No runtime evidence confirming that the API is exposed to untrusted origins or that credentials are accepted from any origin. Lack of information about authentication mechanisms and whether additional origin checks are performed elsewhere.

### 49. Log Injection / Sensitive Data Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs a user‑provided value (username) together with the application secret (APP_SECRET). The log statement is directly constructed from user input without sanitisation, which can lead to log injection and unintended disclosure of sensitive data. No guard or sanitisation is visible in the supplied context.

**Impact:** An attacker who can trigger a login attempt can cause the secret to be written to application logs, potentially exposing it to anyone with log access and facilitating further attacks such as token forgery or credential compromise.

**Remediation:** Do not log sensitive values such as secrets. Remove the APP_SECRET from the log message and sanitise or avoid logging user‑controlled data. Use structured logging with proper redaction for any user‑provided fields.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- No independent scanner or runtime probe evidence confirming exploitation; no observed log‑tampering or secret leakage in practice. Additional evidence such as logs showing the secret being written or a guard that sanitises user input would be needed to confirm the vulnerability.

### 50. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter supplied by the user and directly passes it to `RedirectResponse` without any validation or allow‑list check. This creates an open redirect vector that can be abused for phishing or malicious link forwarding. The supplied source excerpt shows no sanitization or safe‑redirect logic.

**Impact:** An attacker can craft a URL such as `https://example.com/auth/continue?next=https://malicious.com` and cause victims to be redirected to a malicious site, facilitating phishing attacks, credential harvesting, or drive‑by downloads.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the target URL is whitelisted and use a safe‑redirect helper that enforces this check.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source excerpt shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse: return RedirectResponse(next, status_code=302)` with no validation.</code>

Limitations:
- No runtime probe evidence demonstrating an actual open‑redirect exploit. No additional scanner or manual analysis confirming that the redirect can be abused in the deployed environment. Absence of code showing any guard or allow‑list check prevents confirming the vulnerability.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the supplied URL by ensuring it starts with a single '/' and rejects any scheme, network location, or double-slash prefix, raising HTTP 400 for invalid inputs. This prevents redirection to external or untrusted URLs, mitigating an open‑redirect vulnerability.

**Impact:** If the validation were missing, an attacker could craft a URL that redirects users to a malicious external site, facilitating phishing or drive‑by attacks. The existing checks block such behavior.

**Remediation:** No remediation needed; the code already enforces a local‑path‑only redirect. Ensure any future modifications preserve these validation checks.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Source excerpt shows explicit checks for leading '/' and rejects scheme or netloc before returning RedirectResponse`

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which could allow the container to remain unhealthy without detection. However, the supplied evidence only notes the absence and does not demonstrate any actual impact or exploitation scenario.

**Impact:** Potentially undetected container failures, leading to reduced reliability and availability of the service.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically checks the health of the application, e.g., using curl or a custom script, and configure appropriate start‑period, interval, timeout, and retries.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- No runtime probe or scanner evidence confirming that the missing HEALTHCHECK leads to a real failure scenario; no demonstration of impact on service availability.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile excerpt does not contain a HEALTHCHECK instruction, confirming the scanner's finding of a missing health check. While adding a HEALTHCHECK is a best practice, its absence does not constitute a security vulnerability, only a potential operational oversight.

**Impact:** Without a HEALTHCHECK, container orchestration systems cannot automatically detect unhealthy containers, which may lead to reduced availability but does not directly expose the application to a security breach.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD curl -f http://localhost:9000/health || exit 1
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile lines 1-6 show no HEALTHCHECK instruction`

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile excerpt shows no HEALTHCHECK instruction, which is a best‑practice recommendation rather than a security vulnerability. The finding does not demonstrate an exploitable condition, only a missing optional hardening step.

**Impact:** Without a HEALTHCHECK, container orchestration may not detect a hung or unhealthy process, potentially leading to reduced availability, but no direct security breach is implied.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the worker process is responsive, e.g., `HEALTHCHECK --interval=30s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile lines 1‑7 contain no HEALTHCHECK directive.`

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The requirements file includes python-multipart==0.0.20, which is known to be vulnerable to CVE-2026-53539 (Denial of Service via crafted form‑urlencoded bodies). The scanner provides a medium‑or‑higher severity finding that directly references this CVE and notes that the issue is fixed in version 0.0.30. No mitigating guard or version pinning is present in the supplied context, and the vulnerable version is actively used, satisfying both required conditions for a confirmed vulnerability.

**Impact:** An attacker can send specially crafted form‑urlencoded payloads that trigger excessive resource consumption, potentially leading to service disruption or crash of the application.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt lists python-multipart==0.0.20`

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The requirements file pins python-multipart at version 0.0.20, which is known to contain CVE-2026-42561. The scanner flags this as a high‑severity dependency vulnerability. However, the supplied artifacts do not show any code that imports or uses python-multipart, nor do they demonstrate that multipart parsing is exercised at runtime. Without evidence that the application actually invokes the vulnerable library, the finding remains a likely vulnerability rather than confirmed.

**Impact:** An attacker could craft a multipart request with a large number of part headers, causing the vulnerable python-multipart version to consume excessive resources and potentially lead to a denial‑of‑service condition.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, which contains the fix for CVE‑2026‑42561. Verify that the updated version is included in the deployment artifacts and run dependency checks again.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency list shows python-multipart==0.0.20 (source_excerpt).`
- `Scanner evidence cites CVE‑2026‑42561 affecting python-multipart 0.0.20 and fixed in 0.0.27.`

Limitations:
- No code evidence that python-multipart is imported or used in the application.
- No runtime probe showing multipart parsing behavior or exploitation of the CVE.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The requirements file lists python-multipart==0.0.20, which is known to be vulnerable to CVE-2026-53538. The scanner evidence cites this CVE and notes it is fixed in 0.0.30. No guard or mitigation is visible in the supplied context.

**Impact:** An attacker could exploit the parser differential to extract or manipulate form data, potentially leading to information disclosure.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and verify that the application’s form handling works as expected after the upgrade.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency line in requirements.txt shows python-multipart==0.0.20`
- `Scanner evidence: "Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30."`

Limitations:
- No runtime probe confirming the vulnerability is exploitable in the deployed application
- No code showing how form data is parsed or any mitigations applied

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to contain CVE-2026-40347, a denial‑of‑service vulnerability triggered by specially crafted multipart/form-data payloads. The scanner identified this vulnerable version and reported the CVE. No mitigating guard or version pinning is present in the supplied dependency list, confirming the vulnerable code path is included in the build.

**Impact:** An attacker can send a malicious multipart request that exhausts CPU or memory resources, potentially causing the FastAPI service to become unresponsive, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, which contains the fix for CVE-2026-40347. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`

### 59. python-multipart: Arbitrary file write via path traversal vulnerability

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The project declares a dependency on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-24486 (arbitrary file write via path traversal). The scanner flagged this as a high‑severity issue. However, the supplied repository data does not show any import or usage of python-multipart, nor does it demonstrate a code path that would trigger the vulnerable functionality. Without evidence that the vulnerable library is actually invoked, the finding remains a potential risk rather than a confirmed exploit path.

**Impact:** If the vulnerable version of python-multipart is used to process uploaded files, an attacker could craft a malicious filename containing path‑traversal sequences (e.g., "../../etc/passwd") to write arbitrary files on the server, potentially leading to code execution or data compromise.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, which contains the fix for CVE-2026-24486. Verify that the updated version is compatible with the application and run the test suite after upgrading.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- No evidence that python-multipart is imported or used in the application code.
- No runtime probe or code path demonstrating that the vulnerable function can be reached.

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53537. The scanner identified this dependency mismatch, but no runtime probe or code path demonstrating the header parsing issue is provided.

**Impact:** An attacker could exploit the header parsing discrepancy to obtain unintended information from HTTP requests, potentially leading to information disclosure.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency version 0.0.20 of python-multipart is listed in requirements.txt`
- `Scanner report cites CVE-2026-53537 affecting python-multipart 0.0.20`

Limitations:
- No runtime evidence showing the header parsing discrepancy in action
- No code snippet demonstrating the vulnerable code path within the application

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The requirements file pins python-multipart at version 0.0.20, which is known to contain CVE-2026-53540. The scanner flagged this dependency as vulnerable and notes that the issue is fixed in version 0.0.31. No runtime probe or higher‑severity independent scanner evidence is provided, so the vulnerability cannot be confirmed solely from the supplied data.

**Impact:** An attacker could exploit the negative Content‑Length handling to cause the server to buffer the entire request body in memory, potentially leading to denial‑of‑service or memory exhaustion.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later in the requirements.txt and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31 (scanner evidence).`

Limitations:
- No runtime probe demonstrating the vulnerable behavior.
- No independent scanner finding of medium or higher severity confirming exploitability.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a URL by concatenating a base constant with a path argument and then uses urllib.request.urlopen to perform the request. While urllib supports file:// schemes, the supplied source does not demonstrate that the `path` parameter can be controlled by an attacker, nor does it show that a malicious value could reach a file scheme. No guard or validation of the `path` argument is visible in the provided excerpt, but the absence of such a check cannot be confirmed without broader context.

**Impact:** If an attacker could control `path` and supply a file:// URL, they might cause the application to read arbitrary files from the server's filesystem, leading to information disclosure.

**Remediation:** Validate and sanitize the `path` argument before constructing the URL. Restrict allowed schemes to http/https, or switch to a higher‑level HTTP client such as the `requests` library that does not support file URLs by default. Consider adding explicit checks that reject or escape any file:// prefixes.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- <code>Source excerpt shows dynamic construction of the request URL using `BASE + path` and a call to `urllib.request.urlopen` (lines 20‑22).</code>

Limitations:
- No evidence that `path` is attacker‑controlled or that a file:// scheme can be injected. The surrounding code that calls `request` is not provided, so we cannot determine whether input validation or other safeguards exist elsewhere.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib request using a URL taken directly from the job payload (payload\["target_url"\]). If an attacker can influence this value, they could cause the worker to make arbitrary HTTP requests or potentially access file URLs (e.g., "file://"). The finding is based on static analysis of the source excerpt; no runtime probe or independent scanner of medium/higher severity confirms exploitable behavior. No guard or validation of the URL is visible in the supplied context.

**Impact:** An attacker who can control the "target_url" field may trigger server‑side request forgery (SSRF) or read arbitrary files via a "file://" scheme, leading to information disclosure or further network‑based attacks.

**Remediation:** Validate and sanitize the "target_url" value before using it with urllib. Restrict allowed schemes to http/https, reject or safely handle file URLs, and consider using a higher‑level HTTP library (e.g., requests) that enforces safer defaults. Implement explicit allow‑list checks and log any rejected inputs.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows urllib.request.urlopen called with payload["target_url"] without prior validation (lines 17‑23).`

Limitations:
- Missing evidence that the "target_url" can be supplied by an untrusted user, and no runtime probe demonstrating an actual SSRF or file read. No independent scanner of medium or higher severity confirms exploitability.

### 64. Potential IDOR on verified profile endpoint (CWE-639)

- Issue group: `ai-bed84194d5313af2`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint compares the requested profile_id with the id returned by verified_identity(). The implementation of verified_identity() is not provided, so it is unclear whether the Authorization header is strongly validated (e.g., signature, expiration, revocation). Without evidence that the token is properly verified, an attacker who can forge or manipulate the Authorization header might obtain another user's verification status.

**Impact:** If an attacker can bypass or spoof the authentication performed by verified_identity(), they could retrieve verification information for arbitrary user profiles, leading to unauthorized disclosure of user data.

**Remediation:** Ensure that verified_identity() performs full token validation, including signature verification, expiration checks, and revocation handling. Consider using a well‑tested authentication library or framework. Add explicit checks for token validity before using the returned user object, and log authentication failures.
Evidence:
- Source IDs: `ai-bed84194d5313af2`
- `api/extra.py:107-111 defines the endpoint and performs a simple id equality check`
- `dynamic_penetration_agent reported unauthenticated request to /profiles/{profile_id}/verified returned HTTP 422 instead of expected denial codes`

Limitations:
- The code of verified_identity() is not available, so its strength cannot be confirmed
- No runtime probe shows a successful unauthorized access; the only probe shows a 422 response for an anonymous request, which does not prove the endpoint is vulnerable
- No additional guard (e.g., role checks, rate limiting) is visible in the supplied snippet

### 65. Missing admin role verification on audit endpoint (CWE-862)

- Issue group: `ai-4a14d82a7cc9c5d6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/audit endpoint calls require_admin() before returning an authorized response, but the implementation of require_admin() is not provided. Without evidence that it performs robust token signature validation and role checks, the endpoint may allow unauthorized access.

**Impact:** If require_admin() does not properly verify that the caller possesses an admin role, an attacker could invoke the endpoint and obtain privileged information or perform admin actions, leading to confidentiality and integrity breaches.

**Remediation:** Implement require_admin() to validate the Authorization header using a trusted authentication mechanism (e.g., JWT verification with signature checking) and enforce that the token contains an admin role claim. Add explicit logging and rate‑limiting for admin endpoint access.
Evidence:
- Source IDs: `ai-4a14d82a7cc9c5d6`
- `api/extra.py:204 – @router.get("/admin/audit") defines the admin audit endpoint`
- `api/extra.py:206 – require_admin(authorization) is called but its implementation is not shown`
- `api/extra.py:207 – returns {"status": "authorized"} after the call`

Limitations:
- Missing source code for require_admin() to confirm it enforces admin role checks
- No scanner or runtime probe evidence demonstrating unauthorized access is possible
- No observed guard checks (e.g., role validation, token signature verification) in the supplied context

### 66. Potential path traversal via unverified file name (CWE-22)

- Issue group: `ai-d3c8ae68a75d8b90`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint @router.get("/files") builds a file path by joining the user‑supplied name with a public directory and then calling .resolve() before checking that the resulting path is relative to the base directory. This check can be bypassed if an attacker can place a symlink inside the public directory that points outside the base, because resolve() follows symlinks before the relative check. Additionally, on Python versions prior to 3.9 the is_relative_to method is unavailable, which could cause a runtime error or different behavior. The provided runtime probe shows that an unauthenticated request to /files returned HTTP 422 instead of the expected 404/403/401, indicating the check did not behave as intended for the tested input.

**Impact:** An attacker who can influence the 'name' parameter or create symlinks in the public directory may read arbitrary files on the server, potentially exposing source code, configuration files, or other sensitive data.

**Remediation:** Validate and sanitize the filename before joining it with the base path. Prefer using a whitelist of allowed filenames or extensions. Perform the relative path check on the un‑resolved path, or explicitly reject any path components like "..". Additionally, disable or restrict symlink creation in the public directory and ensure the code runs on Python 3.9+ where is_relative_to is reliable.
Evidence:
- Source IDs: `ai-d3c8ae68a75d8b90`
- `api/extra.py:210-214 defines the endpoint and the path check`
- `dynamic_penetration_agent reported unauthenticated request to /files returned HTTP 422, not a denial status`

Limitations:
- Missing information about the runtime Python version (affects availability of is_relative_to)
- No evidence whether symlinks are allowed or present in the public directory
- Unclear definition and initialization of FILES variable (whether it points to the intended safe directory)

### 67. Potential insecure token handling in refresh endpoint (CWE-613)

- Issue group: `ai-e8ec08f388c6f0b9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The refresh endpoint creates a new access token based solely on the Authorization header without verifying that the presented token is a valid refresh token or checking revocation status. The code calls `principal(authorization)` and then issues a new token via `make_token(row)`, but no explicit check of token type, expiration, or revocation list is visible in the supplied snippet. This could allow token replay or misuse of an access token as a refresh token.

**Impact:** An attacker who obtains a valid access token could repeatedly call the refresh endpoint to obtain new tokens, extending the session indefinitely and bypassing token expiration controls.

**Remediation:** Implement proper validation in the refresh endpoint: ensure the incoming token is a refresh token, verify its expiration and revocation status, and enforce token rotation policies. Consider adding a token revocation list check and separate handling for access vs. refresh tokens.
Evidence:
- Source IDs: `ai-e8ec08f388c6f0b9`
- `api/app.py:189-196 shows the refresh endpoint issuing a new token without additional checks`
- `principal() is called but its implementation and token type validation are not shown`
- `no revocation or expiration checks are present in the provided code`

Limitations:
- Missing implementation details of `principal()` – cannot confirm whether it validates token type or revocation
- No evidence of a revocation list or token expiration check elsewhere in the codebase
- Runtime probe did not confirm successful token refresh; only an unauthenticated request returned 405, which does not prove the endpoint is vulnerable

### 68. Missing ownership verification in coupon application

- Issue group: `ai-1826d2fcbfeb295d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user owns the order identified by `order_id` before updating the order's discount. This creates a potential IDOR where an attacker could apply a coupon to any order they know the ID of.

**Impact:** An attacker who can guess or enumerate order IDs could apply arbitrary discounts to other users' orders, leading to unauthorized financial benefits and potential revenue loss.

**Remediation:** Add a check that retrieves the order's owner (e.g., `SELECT owner_id FROM orders WHERE id=%s`) and verifies it matches the authenticated principal before performing the UPDATE. Return an error if the check fails. Consider also validating coupon applicability and discount limits.
Evidence:
- Source IDs: `ai-1826d2fcbfeb295d`
- `source_excerpt lines 230‑238 show the endpoint definition, authentication call, coupon lookup, and order update without an ownership check`

Limitations:
- No runtime probe or scanner evidence confirming that the endpoint can be abused in practice.
- No evidence that the application performs an ownership check elsewhere (e.g., in middleware) or that other safeguards exist.

### 69. Missing ownership check on order cancellation (CWE-639)

- Issue group: `ai-f0dce5b04fc274c8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint updates the order status without verifying that the authenticated user owns the order or has a role that permits cancellation. The code calls `principal(authorization)` but does not use the returned principal to check ownership before executing the UPDATE statement. This constitutes a potential IDOR vulnerability.

**Impact:** An attacker who can obtain a valid authentication token could cancel any order by supplying an arbitrary `order_id`, potentially causing financial loss, denial of service, or audit inconsistencies.

**Remediation:** Add an ownership or role check after retrieving the principal and before performing the UPDATE. For example, fetch the order's `user_id` and compare it to `principal['sub']`, or verify that the principal has an admin role. Return 403/401 if the check fails.
Evidence:
- Source IDs: `ai-f0dce5b04fc274c8`
- <code>api/app.py:259 – endpoint definition `def cancel_order(order_id: int, authorization: str | None = Header(default=None))`</code>
- <code>api/app.py:260 – call to `principal(authorization)` without using its result</code>
- `api/app.py:262 – UPDATE statement executed without ownership verification`

Limitations:
- No independent scanner or runtime probe confirming that an unauthorized user can successfully cancel another user's order.
- Dynamic penetration test reported a 405 response for an unauthenticated request, but no evidence for an authenticated unauthorized request is provided.

### 70. Missing role enforcement on admin user listing (CWE-284)

- Issue group: `ai-2610f6087fbda613`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint @app.get("/admin/users") calls principal(authorization) but does not verify that the authenticated principal has an admin role before executing a query that returns all user records, including sensitive fields such as SSN. The supplied source shows the missing role check, indicating a potential authorization flaw.

**Impact:** An attacker with any valid authentication token could retrieve the full list of users and their SSNs, violating confidentiality and potentially enabling further attacks such as identity theft or targeted phishing.

**Remediation:** Add an explicit role check after principal() to ensure the caller has the required admin role before performing the database query. For example, retrieve the role from the principal object and raise HTTPException(403) if the role is not 'admin'.
Evidence:
- Source IDs: `ai-2610f6087fbda613`
- `@app.get("/admin/users") definition at api/app.py line 277`
- `principal(authorization) call at line 279 without role verification`
- `Database query returning sensitive fields at line 281`

Limitations:
- No runtime evidence (e.g., scanner or probe) confirming that the endpoint is reachable by non‑admin users
- Unclear whether principal() returns role information; the code snippet does not show the principal object's structure
- No additional sources (scanner, test, or runtime probe) corroborating the vulnerability

### 71. Missing role enforcement on admin job listing (CWE-284)

- Issue group: `ai-1dd6334868544586`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint @app.get("/admin/jobs") calls principal(authorization) to verify a token but does not perform any role check before executing a query that returns all job records. The supplied source shows the missing admin role verification, indicating a potential authorization flaw. However, there is no independent scanner or runtime probe evidence confirming that non‑admin users can access this data, so the vulnerability cannot be confirmed.

**Impact:** An attacker with a valid authentication token but without admin privileges could retrieve the full list of jobs, potentially exposing sensitive internal information.

**Remediation:** Add a role check after principal(authorization) to ensure the caller has an admin role before executing the query, e.g., verify that the decoded token includes a role claim of "admin" and return 403 otherwise.
Evidence:
- Source IDs: `ai-1dd6334868544586`
- `@app.get("/admin/jobs") definition at api/app.py line 285`
- `principal(authorization) called without subsequent role verification at line 287`
- `SQL query fetching all jobs at line 289`

Limitations:
- No scanner or runtime probe evidence demonstrating unauthorized access
- No view of the principal function implementation to confirm it does not perform role checks
- No tests showing that a non‑admin token can reach this endpoint and receive data

### 72. Missing ownership check on invoice retrieval (CWE-639)

- Issue group: `ai-ae177f098ffafcec`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` authenticates the request via `principal(authorization)` but does not verify that the retrieved invoice belongs to the authenticated user before returning it. This could allow an authenticated attacker to enumerate or view other users' invoices by guessing IDs (IDOR). The supplied code shows the query and return path, but no ownership validation is present in the excerpt.

**Impact:** An attacker who can obtain a valid authentication token could retrieve any invoice by ID, exposing confidential financial data of other users and violating privacy and data protection requirements.

**Remediation:** Add an ownership check after fetching the invoice, e.g., compare `row['user_id']` (or the appropriate column) with the authenticated principal's identifier and return a 403 error if they do not match. If the invoices table lacks a user identifier, redesign the schema to associate invoices with owners.
Evidence:
- Source IDs: `ai-ae177f098ffafcec`
- `@app.get("/invoices/{invoice_id}") definition at api/app.py:267`
- `principal(authorization) call at api/app.py:269`
- `SQL query fetching invoice by ID at api/app.py:271`
- `No ownership verification code present in the provided excerpt`

Limitations:
- The code excerpt does not show the schema of the `invoices` table, so it is unclear whether a user identifier column exists to perform the check.
- No runtime or scanner evidence confirming that the endpoint is reachable without ownership validation.
- No evidence that other parts of the application perform a global ownership guard for this route.

### 73. Missing ownership check on generic order retrieval (CWE-639)

- Issue group: `ai-8f2e97ab78cee25c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint @app.get("/orders/{order_id}") authenticates the request via principal(authorization) but does not verify that the authenticated user owns the requested order before returning the row from the database. The code fetches the order solely by its primary key and returns it if found, without any ownership comparison.

**Impact:** An authenticated user (or potentially an unauthenticated request, as the dynamic probe observed a 422 response rather than a proper denial) can enumerate or retrieve orders belonging to other users, leading to unauthorized disclosure of order details.

**Remediation:** Add an ownership check after retrieving the order, e.g., compare the order's user_id column with the principal's subject identifier and return 403/404 if they do not match. If the orders table lacks a user_id column, introduce one and enforce the relationship.
Evidence:
- Source IDs: `ai-8f2e97ab78cee25c`
- `Source excerpt shows the endpoint definition and database query without an ownership check (lines 220‑224).`
- `Dynamic penetration agent report indicates that a request to /orders/{order_id} as anonymous did not receive an expected denial status (401/403/404), suggesting the check is missing.`

Limitations:
- Missing evidence that the orders table contains a user_id column to compare against the principal.
- No runtime probe confirming that an authenticated user can successfully retrieve another user's order; the observed 422 response may be due to input validation rather than authorization logic.

### 74. Debug configuration endpoint exposes secret (CWE-200)

- Issue group: `ai-d30ea28564e18126`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint defined at @app.get("/debug/config") returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without any authentication or authorization guard. The source code shows no check before returning these values, and a runtime penetration probe confirmed that an unauthenticated request to /debug/config receives HTTP 200 with the secret data, demonstrating the vulnerable path in practice.

**Impact:** An attacker can retrieve database credentials and application secrets, enabling further compromise such as database access, credential reuse, or full system takeover.

**Remediation:** Restrict the /debug/config endpoint to authorized users only. Add authentication/authorization checks (e.g., OAuth, API keys) before returning sensitive configuration, or remove the endpoint from production deployments. Consider moving secret handling to a secure vault and never expose them via HTTP responses.
Evidence:
- Source IDs: `ai-d30ea28564e18126`
- `Source excerpt shows the endpoint definition and return of secrets (lines 320‑322).`
- `Dynamic penetration agent report: unauthenticated request to /debug/config returned HTTP 200 with secret data, confirming exposure.`

### 75. Insecure Session Creation (CWE-284)

- Issue group: `ai-f6a68f3e73ee86ba`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `session_start` endpoint creates a session cookie based solely on a supplied username without any password or other credential verification. The code fetches the user record, checks only that the user exists, and then sets a `lab_session` cookie containing the user ID. No authentication check is performed before the sensitive operation of issuing a session token.

**Impact:** An attacker can obtain a valid session cookie for any existing user by supplying that user's username, potentially leading to account takeover and unauthorized access to protected resources.

**Remediation:** Add proper authentication (e.g., verify a password or other credential) before creating a session. Generate session tokens using a securely random secret rather than embedding the user ID directly, and validate the token on subsequent requests. Consider moving session creation behind a login endpoint that enforces credential checks.
Evidence:
- Source IDs: `ai-f6a68f3e73ee86ba`
- `api/extra.py:271 – @router.get("/session/start")`
- <code>api/extra.py:272 – def session_start(username: str) -&gt; Response:</code>
- `api/extra.py:274 – user = conn.execute("SELECT id FROM users WHERE username=%s", (username,)).fetchone()`
- `api/extra.py:277 – response = Response("session started")`
- `api/extra.py:278 – response.set_cookie("lab_session", f"session-{user['id']}")`

Limitations:
- No independent scanner or runtime probe confirming that the endpoint can be accessed without authentication (the dynamic probe returned HTTP 422, not a definitive success).
- No evidence of upstream middleware that might enforce authentication before this handler.

### 76. Password Reset Token Lacks Expiration and Rate Limiting (CWE-640)

- Issue group: `ai-f10815aecca0a812`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The supplied source shows that the /auth/reset/request endpoint creates a reset token and stores it in the reset_tokens table without any visible expiration timestamp or any throttling logic for repeated requests. The code snippet does not include a check for token age or a counter limiting how often a user may request a reset, which are required mitigations for CWE‑640. However, no independent scanner or runtime probe evidence confirming exploitable behavior is present, and the AI source is the only indicator of the issue, so the finding is classified as a likely vulnerability.

**Impact:** An attacker could repeatedly request password‑reset tokens for a target account, obtain multiple valid tokens, and reuse them indefinitely to reset the account password, leading to account takeover. Absence of expiration also enables token replay attacks over an unlimited time window.

**Remediation:** Add an expiration column to the reset_tokens table and populate it with a short‑lived timestamp when inserting a new token. Enforce a check that rejects tokens older than the configured lifetime. Implement rate‑limiting per user (e.g., allow only N requests per hour) and return an appropriate error when the limit is exceeded. Consider logging reset requests and notifying users of recent activity.
Evidence:
- Source IDs: `ai-f10815aecca0a812`
- `564: @router.post("/auth/reset/request")`
- <code>565: def request_reset(body: dict) -&gt; dict:</code>
- `567: user = conn.execute("SELECT id FROM users WHERE username=%s", (str(body.get("username", "")),)).fetchone()`
- `571: conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"]))`
- `572: conn.commit()`
- `573: return {"reset_token": token}`

Limitations:
- No evidence that the reset_tokens table includes an expiration column or that such a column is ever populated.
- No runtime or scanner evidence demonstrating that tokens can be reused indefinitely or that rate‑limiting is absent.
- The token generation method is not shown, so its cryptographic strength cannot be confirmed.

### 77. Missing admin authorization (CWE-284)

- Issue group: `ai-93787ef734989eda`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `admin_overview` is exposed under the `/admin` path and calls `principal(authorization)`, which appears to only verify authentication. No explicit role or admin check is present in the supplied code before the sensitive database query that returns the total user count. Without evidence that `principal` enforces admin privileges or that downstream middleware restricts this route, an authenticated non‑admin user could potentially access the user count, indicating a possible authorization bypass.

**Impact:** An attacker with a valid authentication token could retrieve aggregate user statistics, which may aid further enumeration or privacy violations. If the user count is considered sensitive, this constitutes a confidentiality breach and could be leveraged for targeted attacks.

**Remediation:** Add an explicit admin‑role verification before performing the sensitive operation, e.g., `require_admin(authorization)` or check the user's role after `principal`. Ensure that the route is protected by middleware that enforces admin‑only access. Document the required permissions for the endpoint.
Evidence:
- Source IDs: `ai-93787ef734989eda`
- <code>api/extra.py:197 – endpoint definition `@router.get(&quot;/admin/overview&quot;)`</code>
- <code>api/extra.py:198 – call to `principal(authorization)` without further checks</code>
- <code>api/extra.py:200 – execution of `SELECT count(*) FROM users` query</code>
- `verification notes – dynamic penetration agent attempt was denied with HTTP 401, indicating authentication is required but not confirming admin restriction`

Limitations:
- The behavior of `principal` is unknown; it may perform role checks that are not visible in the excerpt.
- No runtime probe or scanner evidence confirms that non‑admin users can reach this endpoint and obtain the count.
- No middleware or additional code is provided that could enforce admin‑only access for `/admin` routes.

### 78. Insecure direct object reference exposing SSN (CWE-639)

- Issue group: `ai-fbb70c87492b9215`
- Verdict: **likely_vulnerability**
- Severity: **critical**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` returns the `ssn` field from the database after only a generic authentication call (`principal`). No ownership or role‑based check is visible in the supplied code, so a caller can request any `profile_id`. A runtime probe attempted an unauthenticated request and received HTTP 422 instead of an expected denial status (401/403/404), indicating the request was processed rather than blocked. However, the probe did not confirm that the SSN value was actually returned, and it is unclear whether `principal` performs additional per‑profile authorization.

**Impact:** An attacker who can guess or enumerate user IDs could retrieve Social Security Numbers of arbitrary users, leading to severe privacy violations, identity theft, and regulatory non‑compliance.

**Remediation:** Add explicit authorization checks after `principal` to verify that the authenticated user is allowed to view the requested profile (e.g., compare `profile_id` with the user's own ID or check a role/permission). Return only non‑sensitive fields (omit `ssn`) unless absolutely required, and enforce least‑privilege data exposure.
Evidence:
- Source IDs: `ai-fbb70c87492b9215`
- `api/extra.py:97 – route definition exposing profile_id`
- `api/extra.py:99 – call to principal without further checks`
- `api/extra.py:101 – SQL query selects ssn column`
- `runtime_probe: unauthenticated request to /profiles/{profile_id} returned HTTP 422, not a denial status`

Limitations:
- Missing concrete proof that the SSN value is returned in the response; the probe only shows the request is not blocked. Unclear whether `principal` implements per‑profile authorization internally. No guard checks are visible in the provided snippet beyond the generic authentication call.

### 79. Missing ownership check on note retrieval (CWE-639)

- Issue group: `ai-8b80c3773de74246`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint retrieves a note by `note_id` after a generic authentication call (`principal`). It does not verify that the note belongs to the supplied `order_id` nor that the authenticated user owns the order, creating a potential IDOR. The code snippet shows no comparison between `order_id` and the `order_id` column of the fetched note, nor any ownership check against the principal.

**Impact:** An attacker who can authenticate (or possibly bypass authentication) could enumerate or read notes belonging to other users by guessing note IDs, leading to disclosure of potentially sensitive information.

**Remediation:** Add a check that the `order_id` in the URL matches the `order_id` field of the retrieved note and that the authenticated principal has permission to access that order. Example: after fetching the row, verify `row['order_id'] == order_id` and that the principal’s user ID matches the order’s owner before returning the note. Return 403/404 on mismatch.
Evidence:
- Source IDs: `ai-8b80c3773de74246`
- `api/extra.py:542 – route definition includes both order_id and note_id`
- `api/extra.py:544 – calls principal(authorization) for generic auth`
- `api/extra.py:546 – fetches note solely by note_id without using order_id`
- `api/extra.py:549 – returns the note without ownership validation`

Limitations:
- No independent scanner or high‑severity source confirming exploitation
- Runtime probe shows an unauthenticated request returned HTTP 422, not a successful data leak, so exploitability is not demonstrated
- Unclear what `principal` enforces; it may already perform order ownership checks, but this is not visible in the provided excerpt

### 80. Insecure Direct Object Reference (IDOR) on file upload view (CWE-639)

- Issue group: `ai-7da0208dca8f390c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `view_upload` endpoint returns the raw file contents for a given `upload_id` without any ownership or permission verification. The supplied source shows the endpoint and the database query, and no guard is present in the examined code. A dynamic probe attempted to access the endpoint anonymously and received HTTP 422 instead of an expected denial status, indicating that the request was processed rather than blocked.

**Impact:** An attacker could enumerate or guess upload IDs and retrieve files belonging to other users, potentially exposing private or sensitive data.

**Remediation:** Add an authorization check that verifies the requesting user owns the upload or has the required role before returning the file. For example, retrieve the uploader's user ID with the upload record and compare it to the authenticated user's ID, returning 403/404 on mismatch. Ensure the router is protected by an authentication dependency.
Evidence:
- Source IDs: `ai-7da0208dca8f390c`
- `Source excerpt shows endpoint definition and query without any permission check`
- `Dynamic probe result: anonymous request to /uploads/{upload_id} returned HTTP 422, not a denial status`

Limitations:
- No evidence whether a global authentication dependency is applied to the router
- No information about database‑level row‑level security or triggers that might enforce ownership
- No runtime evidence confirming that an authenticated user can retrieve another user's file

### 81. Potential unsafe content type handling leading to XSS (CWE-79)

- Issue group: `ai-2b29d4ee02a18f9b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint `/uploads/{upload_id}` returns the raw file bytes with the MIME type stored in the database. No allow‑list validation or sanitisation of the `mime` field is performed before it is used as the response `media_type`. If an attacker can upload a payload with a MIME type such as `text/html` or `application/javascript`, the browser may interpret the content as executable code, resulting in stored or reflected XSS. The supplied source excerpt shows the response construction but does not include any upload‑time checks or database constraints that would prevent malicious MIME types.

**Impact:** An attacker who can control the uploaded file and its MIME type could cause a victim’s browser to execute arbitrary JavaScript when the victim accesses the URL, leading to session hijacking, credential theft, or other malicious actions in the context of the vulnerable application.

**Remediation:** Validate the MIME type of uploaded files against a strict allow‑list before storing it, and enforce the same allow‑list when serving files. Alternatively, serve all uploaded content with a safe generic MIME type (e.g., `application/octet‑stream`) and force download, or sanitise HTML content before storage. Ensure the database schema enforces MIME type constraints if applicable.
Evidence:
- Source IDs: `ai-2b29d4ee02a18f9b`
- `return Response(bytes(row["body"]), media_type=row["mime"]) (api/extra.py:372)`
- `@router.get("/uploads/{upload_id}") endpoint defined at api/extra.py:366`
- `dynamic_penetration_agent: exploitation_confirmed — unauthenticated request to /uploads/{upload_id} returned HTTP 422 (not a denial status)`

Limitations:
- No evidence that the upload endpoint restricts MIME types or validates file content before storage.
- No runtime probe showing that a malicious HTML/JS payload can be uploaded and later served with an executable MIME type.
- No independent scanner or higher‑severity finding confirming the exploit path.

## Policy Decisions

- `merged-3202e1e1074cfd44b9bf`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-18f1abe978f9fdaad8e6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-4c6d36222f8ebf7f1f68`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-15dd977d52312c30635a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d58491aad5be35b48233`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c5b44871f1955b338344`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-56ecc860a2c48330a29a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-69b75a0aa3f8fc9fb800`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-efce9419c25ced2d8892`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4a2311054cdc2bfe890d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a6e788cfc5d9d1297feb`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a9a9a0b97f19f8bf52ae`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-6e468e09eab3ca889e3d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-81ff94e895c53dbc2029`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d716d5afb61da294d286`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f5fff899f9294177dc70`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-916563c278b3e6b62930`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-54b1ddb055358b3579a2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b7e0b624f8cddd0a9e8c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d0789be823f0fd7fa381`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-7ed325c02dd6cf8227d2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-ccc894903304aa8847bd`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-1bcb1da144dffdcf3fd8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-bed84194d5313af2`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-4a14d82a7cc9c5d6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-d3c8ae68a75d8b90`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-e8ec08f388c6f0b9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1826d2fcbfeb295d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-f0dce5b04fc274c8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-2610f6087fbda613`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-1dd6334868544586`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ae177f098ffafcec`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-8f2e97ab78cee25c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-d30ea28564e18126`: **block** — RG-001: high confirmed vulnerability is AI claim confirmed against the cited source by deterministic checks; blocking severities are critical, high.
- `ai-f6a68f3e73ee86ba`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-f10815aecca0a812`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-93787ef734989eda`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-fbb70c87492b9215`: **warn** — RG-003: critical likely vulnerability requires manual review; not auto-confirmed.
- `ai-8b80c3773de74246`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-7da0208dca8f390c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-2b29d4ee02a18f9b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **84**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **38**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **17**; uncertain overlaps: **4**; needs more evidence: **17**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-e42cbca7f84d6eae`: needs_more_evidence
- `ai-d3c8ae68a75d8b90`: uncertain_overlap
- `ai-eb33fbefb86b87d2`: needs_more_evidence
- `ai-e8ec08f388c6f0b9`: uncertain_overlap
- `ai-23b97c0090929eb8`: needs_more_evidence
- `ai-2e196d6bab5427c0`: needs_more_evidence
- `ai-079e75dcf14f91a8`: needs_more_evidence
- `ai-9076c561b9f4f9db`: needs_more_evidence
- `ai-f10815aecca0a812`: uncertain_overlap
- `ai-ef134b384e616736`: needs_more_evidence
- `ai-7efa66b32b8aa71e`: needs_more_evidence
- `ai-96473a6b7da1cf0c`: needs_more_evidence
- `ai-566d1aaed3b9bcca`: needs_more_evidence
- `ai-9754798dd354f31c`: needs_more_evidence
- `ai-e7fb3d015898f5f9`: needs_more_evidence
- `ai-90fabfa5626d27dd`: needs_more_evidence
- `ai-898d5cb5922e446d`: needs_more_evidence
- `ai-059ccb76c6b286f3`: needs_more_evidence
- `ai-151dd4fdecd4573d`: needs_more_evidence
- `ai-3b4f492446748f7f`: needs_more_evidence
- `ai-b94262d4b5d7ef8e`: uncertain_overlap

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Pending Security Reviews

- `ai-b94262d4b5d7ef8e`
- `ai-981d194322a5245a`
- `ai-118e8dd460abde2d`

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

# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-23T22:41:32.722940+00:00`
- Policy status: **incomplete**
- Review status: **blocked**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **71/71**; model calls: **17**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.
- AI Discovery warning: 6 duplicate AI candidate(s) were merged into 6 stronger one(s): ai-4af78a4240e9e89d &lt;- ai-893c2a9e4e3a07bc; ai-0c354e1132e37f93 &lt;- ai-fdefe4e2bcff2310; ai-971eceba12c66dbc &lt;- ai-ef665237550d0679; ai-ddb52b4e1786df39 &lt;- ai-bb7ee05f140f2c33; ai-29d3995de39748d4 &lt;- ai-6af1e6d2a336ad67; ai-5d4c30816d85620a &lt;- ai-74777cd533f6eb3c

No Security Review Agent verdicts were produced. **63** scanner/DAST observation record(s) are listed below for investigation. This does not mean the project is secure.
Issue groups expected: **99**; reviewed: **0**; pending: **99**.

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

Hypotheses tested: **38**; total attempts: **69**; total requests: **47**; exploitation confirmed: **34**.
Every probe below is read-only (GET/HEAD) against an isolated test stack with test accounts; nothing here mutated real data. Re-run the same method and path after a fix and confirm the response status changes to a denial status.

### Hypothesis `ai-af9496dfdf758e33` — outcome: **exploitation_confirmed**

head_method_bypass: request to /profiles/{profile_id}/verified as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}/verified")`
- Target: `/profiles/{profile_id}/verified`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in? AI planner: Since no tests exist, we should first probe the endpoint with different authenticated user IDs to see if the authorization check can be bypassed, directly addressing the potential IDOR.
  - Step 1: `GET /profiles/{profile_id}/verified` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>trailing_slash_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}/verified")`
- Target: `/profiles/{profile_id}/verified`
- Plan: Does toggling the trailing slash (/profiles/{profile_id}/verified/) reach a route a naive string check missed? AI planner: Since the endpoint may perform verification after the main logic, a trailing slash could alter routing or processing order and reveal an IDOR, and no such bypass has been attempted yet.
  - Step 1: `GET /profiles/{profile_id}/verified/` as `anonymous` → `307` (expected one of [401, 403, 404])
- Observation: trailing_slash_bypass: the response (HTTP 307) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis. AI interpretation: The 307 response does not match any of the expected denial codes (401, 403, 404), so the result is inconclusive and warrants additional probing with alternative payloads or request variations.
- Next action: **next_test**

**Attempt 3 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}/verified")`
- Target: `/profiles/{profile_id}/verified`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET? AI planner: Previous attempts were inconclusive; using HEAD may bypass the post‑verification check and reveal whether the endpoint enforces the IDOR restriction on authenticated requests.
  - Step 1: `HEAD /profiles/{profile_id}/verified` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /profiles/{profile_id}/verified as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which differs from the expected denial codes, indicates a potential IDOR and merits further probing with alternative methods.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-4af78a4240e9e89d` — outcome: **blocked**

No applicable template could be planned with the accounts and evidence on hand.

_No scenario could be planned for this hypothesis._

### Hypothesis `ai-01e6577ef8d123d5` — outcome: **cannot_test**

No HTTP route was resolved for this candidate; no safe test exists.

_No scenario could be planned for this hypothesis._

### Hypothesis `ai-56e2d5863800b409` — outcome: **cannot_test**

No HTTP route was resolved for this candidate; no safe test exists.

_No scenario could be planned for this hypothesis._

### Hypothesis `ai-a4d0c1438b124a1b` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def file_read(name: str) -&gt; Response:</code>
- Target: `/files`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior tests exist; the hypothesis concerns lack of authentication, so the unauthenticated_access template directly validates this condition.
  - Step 1: `GET /files` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response, which is not among the expected denial codes, confirms a missing authentication check on the file read endpoint, indicating a real vulnerability that should be further examined for exploitation.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-8a91bb360da5c822` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def verified_file_read(name: str) -&gt; Response:</code>
- Target: `/files/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior attempts exist and the hypothesis concerns lack of authentication, so the unauthenticated_access template directly tests that condition.
  - Step 1: `GET /files/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 422 response, which is not among the expected denial codes, confirms a missing authentication check on the verified file read endpoint, indicating it is likely exploitable and should be further examined.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-0cff1c5b0a98f32b` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/comments")`
- Target: `/comments`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No tests exist yet and the hypothesis concerns creating comments without a valid token, so the unauthenticated_access template directly probes whether the endpoint allows comment creation without authentication.
  - Step 1: `GET /comments` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The request succeeded with HTTP 200 instead of the expected denial codes, confirming an IDOR vulnerability on comment creation; further testing can focus on exploiting or mitigating this issue.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-a079b7e3e1360616` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/refresh as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/auth/refresh")`
- Target: `/auth/refresh`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No prior tests exist; the hypothesis concerns missing checks on the refresh endpoint, so the simplest next test is to attempt an unauthenticated token refresh to see if it succeeds.
  - Step 1: `GET /auth/refresh` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/refresh as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response, which is not among the expected denial codes, confirms a missing authorization check on the token refresh endpoint, indicating a genuine vulnerability that should be further examined.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-86bcc4c6513e492e` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>path_normalization_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does a dot-segment detour (/x/../files, proven to normalize to /files) reach a route whose access check compares the raw, un-normalized path? AI planner: The hypothesis concerns path traversal via symbolic links, which is a form of path normalization bypass; testing with the path_normalization_bypass template is the most relevant next step.
  - Step 1: `GET /x/../files` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: path_normalization_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The test was correctly denied with a 404, confirming that this specific path‑normalization bypass does not succeed; while this vector appears mitigated, other traversal techniques may still be worth exploring.
- Next action: **next_test**

**Attempt 2 — <code>trailing_slash_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does toggling the trailing slash (/files/) reach a route a naive string check missed? AI planner: Since the prior path‑normalization test was denied, trying a trailing‑slash bypass may affect how the symlink resolution and relative check behave, potentially exposing the traversal flaw.
  - Step 1: `GET /files/` as `anonymous` → `307` (expected one of [401, 403, 404])
- Observation: trailing_slash_bypass: the response (HTTP 307) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis. AI interpretation: The 307 response does not match any of the expected denial codes, so the result remains inconclusive and the vector may merit additional probing with alternative techniques.
- Next action: **next_test**

**Attempt 3 — <code>case_sensitivity_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does re-casing the path (/FILES) reach a route a case-sensitive check missed? AI planner: Previous attempts only covered generic path normalization and trailing slash; a case‑sensitivity bypass could reveal a symlink traversal that evades the is_relative_to check, so it adds new evidence.
  - Step 1: `GET /FILES` as `anonymous` → `404` (expected one of [401, 403, 404])
- Observation: case_sensitivity_bypass: the request was correctly denied (HTTP 404).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with a 404, confirming that this case‑sensitivity bypass did not expose a path‑traversal vulnerability, so retesting the same vector is unlikely to yield a different result.
- Next action: **next_test**

**Attempt 4 — <code>case_sensitivity_bypass</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does re-casing the path (/FILES) reach a route a case-sensitive check missed?
  - Step 1: `ZAP_ACTIVE_SCAN /files` as `anonymous` → `passed`
- Observation: case_sensitivity_bypass_corroboration: ZAP active scan completed and reported no alert at this exact path.
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The passed result indicates that the path traversal via symbolic links appears viable, as the scan found no alert at the tested path. This suggests the issue should be probed further with additional payloads to confirm exploitability.
- Next action: **next_test**

**Attempt 5 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: No attempts have yet checked whether the file endpoint is protected at all; confirming unauthenticated access could reveal a trivial way to exploit the symlink traversal.
  - Step 1: `GET /files` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The unexpected 422 response indicates the test triggered behavior outside the normal denial codes, confirming a violation and suggesting that further probing of the path traversal vector is warranted.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-971eceba12c66dbc` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def create_order(body: OrderBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders`
- Plan: Cheapest, safest first probe: does the route respond without any session at all? AI planner: The hypothesis concerns missing authorization on order creation, so testing whether the endpoint can be called without authentication directly validates the flaw.
  - Step 1: `GET /orders` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200. AI interpretation: The 405 response instead of the expected denial codes confirms the missing authorization check, indicating the endpoint can be accessed without authentication and should be further examined for exploitation.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.
- <code>idor_parameter_pollution</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-ddb52b4e1786df39` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /webhooks as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/webhooks")`
- Target: `/webhooks`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges? AI planner: The hypothesis concerns an unchecked run_as field that could let an attacker execute actions as a privileged account, directly matching a privilege escalation test.
  - Step 1: `GET /webhooks` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/webhooks")`
- Target: `/webhooks`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /webhooks` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/webhooks")`
- Target: `/webhooks`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /webhooks` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /webhooks as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-6d23d0d008604fdc` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/login as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>async def login(request: Request) -&gt; dict[str, Any]:</code>
- Target: `/auth/login`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /auth/login` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/login as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-29d3995de39748d4` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/apply-coupon as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges?
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def apply_coupon(order_id: int, body: CouponBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/apply-coupon as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-5d4c30816d85620a` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/pay as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def pay_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/pay`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/pay` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def pay_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/pay`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/pay` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/pay as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-a24a1251367745da` — outcome: **cannot_test**

No HTTP route was resolved for this candidate; no safe test exists.

_No scenario could be planned for this hypothesis._

### Hypothesis `ai-f0dce5b04fc274c8` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/cancel`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/cancel` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}/cancel`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/cancel` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-76ee5ddf6f5e1661` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/orders/{order_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-ae177f098ffafcec` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /invoices/{invoice_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def invoice(invoice_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/invoices/{invoice_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /invoices/{invoice_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def invoice(invoice_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/invoices/{invoice_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /invoices/{invoice_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /invoices/{invoice_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-ecf531ac657f5eee` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /jobs as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def create_job(body: JobBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/jobs`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges?
  - Step 1: `GET /jobs` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def create_job(body: JobBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/jobs`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /jobs` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def create_job(body: JobBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- Target: `/jobs`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /jobs` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /jobs as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-977152a429a6be98` — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/users as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges?
  - Step 1: `GET /admin/users` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/users` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/users` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 4 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/users")`
- Target: `/admin/users`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /admin/users` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/users as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-1c96865ffd2139a6` — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/jobs as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/jobs` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/jobs` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 3 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/admin/jobs")`
- Target: `/admin/jobs`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /admin/jobs` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/jobs as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-3dfb81137310f24a` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.get("/debug/config")`
- Target: `/debug/config`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /debug/config` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-b0aa75c08377bc22` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/session/start")`
- Target: `/session/start`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /session/start` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-5c26e3944c7d42d2` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/reset/request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/auth/reset/request")`
- Target: `/auth/reset/request`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /auth/reset/request` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/reset/request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-d9fcf0a0e754f60a` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /auth/reset/verified-request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/auth/reset/verified-request")`
- Target: `/auth/reset/verified-request`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /auth/reset/verified-request` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /auth/reset/verified-request as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-161393c7a9326942` — outcome: **exploitation_confirmed**

head_method_bypass: request to /session/whoami as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def session_whoami(request: Request) -&gt; dict:</code>
- Target: `/session/whoami`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /session/whoami` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 2 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def session_whoami(request: Request) -&gt; dict:</code>
- Target: `/session/whoami`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /session/whoami` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /session/whoami as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-704ae0696dee2199` — outcome: **exploitation_confirmed**

head_method_bypass: request to /session/secure-start as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- Target: `/session/secure-start`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges?
  - Step 1: `GET /session/secure-start` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- Target: `/session/secure-start`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /session/secure-start` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- Target: `/session/secure-start`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /session/secure-start` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 4 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def secure_session_start(authorization: str | None = Header(default=None)) -&gt; Response:</code>
- Target: `/session/secure-start`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /session/secure-start` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /session/secure-start as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-33b6a471ed602632` — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/token-report as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def token_report(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/token-report`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/token-report` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 2 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def token_report(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/token-report`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /admin/token-report` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/token-report as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-6322be0c6e12b177` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}")`
- Target: `/profiles/{profile_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /profiles/{profile_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/profiles/{profile_id}")`
- Target: `/profiles/{profile_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /profiles/{profile_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-90110660457c36b4` — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/overview as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/overview")`
- Target: `/admin/overview`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/overview` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/overview")`
- Target: `/admin/overview`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/overview` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 3 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/overview")`
- Target: `/admin/overview`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /admin/overview` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/overview as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-9817b61171b7f73f` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-f1b47b3c5879f0cc` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/orders/{order_id}/verified")`
- Target: `/orders/{order_id}/verified`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/verified` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/orders/{order_id}/verified")`
- Target: `/orders/{order_id}/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)

**Other scenarios the agent drew up but could not execute at all (never sent a single request):**

- <code>idor</code>: No cited evidence names a concrete resource id belonging to a different account; the agent does not invent one.


### Hypothesis `ai-9a75189936f87550` — outcome: **exploitation_confirmed**

head_method_bypass: request to /admin/current-report as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>privilege_escalation</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/current-report")`
- Target: `/admin/current-report`
- Plan: Does the non-admin account (user_a) reach an endpoint that should require admin privileges?
  - Step 1: `GET /admin/current-report` as `user_a` → `blocked`
- Observation: privilege_escalation: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/current-report")`
- Target: `/admin/current-report`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/current-report` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/current-report")`
- Target: `/admin/current-report`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/current-report` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all. AI interpretation: The request was correctly denied with HTTP 401, confirming that unauthenticated access is blocked; this suggests no further probing of missing admin authorization is needed via this unauthenticated path.
- Next action: **next_test**

**Attempt 4 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/current-report")`
- Target: `/admin/current-report`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /admin/current-report` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /admin/current-report as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-093946d18faa4afa` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /integrations/hook as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/integrations/hook")`
- Target: `/integrations/hook`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /integrations/hook` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /integrations/hook as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-537f833f6b0afa71` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/uploads/{upload_id}")`
- Target: `/uploads/{upload_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /uploads/{upload_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /uploads/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-ce60f9b4b3468077` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /documents/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/documents/{upload_id}")`
- Target: `/documents/{upload_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /documents/{upload_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /documents/{upload_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-5670f781c98ace32` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def show_comments() -&gt; str:</code>
- Target: `/comments`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /comments` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-118e8dd460abde2d` — outcome: **exploitation_confirmed**

head_method_bypass: request to /errors/query as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/errors/query")`
- Target: `/errors/query`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /errors/query` as `anonymous` → `500` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the response (HTTP 500) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis.
- Next action: **next_test**

**Attempt 2 — <code>head_method_bypass</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/errors/query")`
- Target: `/errors/query`
- Plan: Does a HEAD request reach the route when a hand-wired auth check only covers GET?
  - Step 1: `HEAD /errors/query` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: head_method_bypass: request to /errors/query as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


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

No agent verdicts were produced. The pre-review observations above remain visible but have not been cleared or confirmed by the agent.

## Policy Decisions


## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **99**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **62**; scanner overlaps: **2**; AI overlaps: **0**; new candidates: **27**; uncertain overlaps: **9**; needs more evidence: **24**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-e42cbca7f84d6eae`: needs_more_evidence
- `ai-4b421e6c6049ce19`: needs_more_evidence
- `ai-3ea530f13ef0bc16`: needs_more_evidence
- `ai-2edfc8f205ad877b`: needs_more_evidence
- `ai-56e2d5863800b409`: uncertain_overlap
- `ai-0c354e1132e37f93`: needs_more_evidence
- `ai-86bcc4c6513e492e`: uncertain_overlap
- `ai-6d23d0d008604fdc`: uncertain_overlap
- `ai-753faea430490d3b`: needs_more_evidence
- `ai-350573badc0f420f`: needs_more_evidence
- `ai-a24a1251367745da`: uncertain_overlap
- `ai-70e062492a597692`: needs_more_evidence
- `ai-6b81e38d34e9ec10`: needs_more_evidence
- `ai-9c197d3022a9263a`: needs_more_evidence
- `ai-ed9bb4c40cf22c4d`: needs_more_evidence
- `ai-6b3555cd794b0b64`: needs_more_evidence
- `ai-d1c2c71535d2f7c8`: needs_more_evidence
- `ai-b0aa75c08377bc22`: uncertain_overlap
- `ai-88c84894edd652a0`: needs_more_evidence
- `ai-e1cbf24313c0c279`: needs_more_evidence
- `ai-5c26e3944c7d42d2`: uncertain_overlap
- `ai-d9fcf0a0e754f60a`: uncertain_overlap
- `ai-86d4d708f0641ee3`: needs_more_evidence
- `ai-a919508223616e45`: needs_more_evidence
- `ai-a4e4f7bde1002d95`: needs_more_evidence
- `ai-72d7311c2edc03db`: needs_more_evidence
- `ai-ee75b61283e20b4f`: needs_more_evidence
- `ai-9746c3e142b5e980`: needs_more_evidence
- `ai-6779a1bd8afba759`: needs_more_evidence
- `ai-6e6509f3f5bf9004`: needs_more_evidence
- `ai-33b6a471ed602632`: uncertain_overlap
- `ai-c17e8bd932e8595c`: needs_more_evidence
- `ai-ce60f9b4b3468077`: uncertain_overlap

## Pending Security Reviews

- `merged-3202e1e1074cfd44b9bf`
- `merged-18f1abe978f9fdaad8e6`
- `merged-24d14609e3893220ea16`
- `merged-794dcb4921076779cef0`
- `merged-83d97da4516adf20e20f`
- `merged-b3c734b4cef8dd70fce0`
- `merged-b527b3ed30e57aac5ec5`
- `merged-ea527a7d7441e2b11700`
- `merged-f4eaf141df049c63545d`
- `merged-f60fee7d82fbca512208`
- `merged-4c6d36222f8ebf7f1f68`
- `merged-15dd977d52312c30635a`
- `merged-d58491aad5be35b48233`
- `merged-c5b44871f1955b338344`
- `merged-0bcbb317cfb96e7d5505`
- `merged-56ecc860a2c48330a29a`
- `merged-69b75a0aa3f8fc9fb800`
- `merged-efce9419c25ced2d8892`
- `merged-4a2311054cdc2bfe890d`
- `merged-a6e788cfc5d9d1297feb`
- `merged-a9a9a0b97f19f8bf52ae`
- `merged-6e468e09eab3ca889e3d`
- `merged-81ff94e895c53dbc2029`
- `merged-d716d5afb61da294d286`
- `merged-f5fff899f9294177dc70`
- `merged-19f4a13e0b2d4f7413d0`
- `merged-87e0399272a390813ea5`
- `merged-916563c278b3e6b62930`
- `merged-bbf1646deeb18d1e95db`
- `merged-b98074828fe298997980`
- `merged-54b1ddb055358b3579a2`
- `merged-b7e0b624f8cddd0a9e8c`
- `merged-c0dcf73e8d7a6a1fbf02`
- `merged-218d6fc43fe64432894a`
- `merged-5a7c783c30e11426af42`
- `merged-767d54ff7a729b156819`
- `merged-d0789be823f0fd7fa381`
- `merged-0f6fe31b81367808748c`
- `merged-fe4ca713f11faf9b96d6`
- `merged-7ed325c02dd6cf8227d2`
- `merged-ccc894903304aa8847bd`
- `merged-1bcb1da144dffdcf3fd8`
- `merged-18063ba27bc289f53c8a`
- `merged-4ae7658c2abfbf689e2b`
- `merged-a4473061f97f0a366678`
- `merged-cad468186f9fd0b4e99b`
- `merged-8cdc677a9810b317840f`
- `merged-70f8087c412d06924742`
- `merged-9c6fcf61fc01168b15e2`
- `merged-51bf51abe866bf8d3d67`
- `merged-f41fd10802e7c4dd22bb`
- `merged-58377a692410b6446bbd`
- `merged-0de42012099941c48e01`
- `merged-df83daf10f817c7aa965`
- `merged-051697f9b8567d596874`
- `merged-3503f2dec888990b31f2`
- `merged-74bb99c1ff3b5ed1fea8`
- `merged-8a5f28db4eebc517239e`
- `merged-8ce42d9c8b52a95b109d`
- `merged-e76230cbef200116e4ae`
- `merged-f15e42abb7b2acd921f1`
- `merged-7711056ee3332442a201`
- `merged-c150b78349615dd9bc2d`
- `ai-af9496dfdf758e33`
- `ai-56e2d5863800b409`
- `ai-a4d0c1438b124a1b`
- `ai-8a91bb360da5c822`
- `ai-0cff1c5b0a98f32b`
- `ai-a079b7e3e1360616`
- `ai-86bcc4c6513e492e`
- `ai-971eceba12c66dbc`
- `ai-ddb52b4e1786df39`
- `ai-6d23d0d008604fdc`
- `ai-29d3995de39748d4`
- `ai-5d4c30816d85620a`
- `ai-a24a1251367745da`
- `ai-f0dce5b04fc274c8`
- `ai-76ee5ddf6f5e1661`
- `ai-ae177f098ffafcec`
- `ai-ecf531ac657f5eee`
- `ai-977152a429a6be98`
- `ai-1c96865ffd2139a6`
- `ai-3dfb81137310f24a`
- `ai-b0aa75c08377bc22`
- `ai-5c26e3944c7d42d2`
- `ai-d9fcf0a0e754f60a`
- `ai-161393c7a9326942`
- `ai-704ae0696dee2199`
- `ai-33b6a471ed602632`
- `ai-6322be0c6e12b177`
- `ai-90110660457c36b4`
- `ai-9817b61171b7f73f`
- `ai-f1b47b3c5879f0cc`
- `ai-9a75189936f87550`
- `ai-093946d18faa4afa`
- `ai-537f833f6b0afa71`
- `ai-ce60f9b4b3468077`
- `ai-5670f781c98ace32`
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

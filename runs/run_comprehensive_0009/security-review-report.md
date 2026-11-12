# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-12T12:50:29.190223+00:00`
- Policy status: **failed**
- Review status: **partial**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **71/71**; model calls: **12**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.
- AI Discovery warning: 6 duplicate AI candidate(s) were merged into 6 stronger one(s): ai-48e38dce185c919c &lt;- ai-a4d0c1438b124a1b; ai-9e0c4cc6cdfc1570 &lt;- ai-4b421e6c6049ce19; ai-956884683be69033 &lt;- ai-7efa66b32b8aa71e; ai-68813298dd460aa9 &lt;- ai-9d9a433a406655ce; ai-ad40fdf26de7ccce &lt;- ai-d754cc95f13b9885; ai-6e6d20cb31a8d0de &lt;- ai-3f2b2699ce8b8cbf

The agent reviewed **71** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **89**; reviewed: **71**; pending: **18**.

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

Hypotheses tested: **28**; total attempts: **52**; total requests: **34**; exploitation confirmed: **22**.
Every probe below is read-only (GET/HEAD) against an isolated test stack with test accounts; nothing here mutated real data. Re-run the same method and path after a fix and confirm the response status changes to a denial status.

### Hypothesis `ai-48e38dce185c919c` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /files` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files")`
- Target: `/files`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /files` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-0cff1c5b0a98f32b` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/comments")`
- Target: `/comments`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /comments` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/comments")`
- Target: `/comments`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /comments` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /comments as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-357e82f73fc20848` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /files/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files/verified")`
- Target: `/files/verified`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /files/verified` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/files/verified")`
- Target: `/files/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /files/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /files/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-a1aee7bddc21a663` — outcome: **not_reproduced**

unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/audit` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/audit` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: `@router.get("/admin/audit")`
- Target: `/admin/audit`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /admin/audit` as `anonymous` → `passed`
- Observation: unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-c16d37bee59101c7` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /catalog/search as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def catalog_search(q: str = &quot;&quot;) -&gt; str:</code>
- Target: `/catalog/search`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /catalog/search` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /catalog/search as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-a815919b2f2f9d7a` — outcome: **exploitation_confirmed**

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


### Hypothesis `ai-abc2a7ff34f5274c` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/apply-coupon as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@app.post("/orders/{order_id}/apply-coupon")`
- Target: `/orders/{order_id}/apply-coupon`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/apply-coupon` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/apply-coupon as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-37a36c685565c325` — outcome: **exploitation_confirmed**

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


### Hypothesis `ai-3758edde98f7e9e2` — outcome: **exploitation_confirmed**

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


### Hypothesis `ai-3e7bb5628df0321c` — outcome: **exploitation_confirmed**

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


### Hypothesis `ai-20c43f5be4958e67` — outcome: **cannot_test**

No HTTP route was resolved for this candidate; no safe test exists.

_No attempt could be planned or executed for this hypothesis._

### Hypothesis `ai-6a259d8eb9f37894` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def debug_config() -&gt; dict[str, Any]:</code>
- Target: `/debug/config`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /debug/config` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /debug/config as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-fd71518f0577d542` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def session_start(username: str) -&gt; Response:</code>
- Target: `/session/start`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /session/start` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /session/start as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-6564d370b52ece9f` — outcome: **not_reproduced**

unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def session_whoami(request: Request) -&gt; dict:</code>
- Target: `/session/whoami`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /session/whoami` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: <code>def session_whoami(request: Request) -&gt; dict:</code>
- Target: `/session/whoami`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /session/whoami` as `anonymous` → `passed`
- Observation: unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-f81369b539293f50` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /webhooks/verified as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/webhooks/verified")`
- Target: `/webhooks/verified`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /webhooks/verified` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/webhooks/verified")`
- Target: `/webhooks/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /webhooks/verified` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /webhooks/verified as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-6c75550620dc33f8` — outcome: **not_reproduced**

unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/token-report")`
- Target: `/admin/token-report`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/token-report` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/admin/token-report")`
- Target: `/admin/token-report`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/token-report` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: `@router.get("/admin/token-report")`
- Target: `/admin/token-report`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /admin/token-report` as `anonymous` → `passed`
- Observation: unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-ad40fdf26de7ccce` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/profiles/{profile_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /profiles/{profile_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/profiles/{profile_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /profiles/{profile_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /profiles/{profile_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-b85430abb087460a` — outcome: **exploitation_confirmed**

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


### Hypothesis `ai-6e6d20cb31a8d0de` — outcome: **not_reproduced**

unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /admin/overview` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /admin/overview` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/admin/overview`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /admin/overview` as `anonymous` → `passed`
- Observation: unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-8980cb77b67b1fa8` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/verified-cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def verified_cancel(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/verified-cancel`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/verified-cancel` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def verified_cancel(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/verified-cancel`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/verified-cancel` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/verified-cancel as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-0b7b33bc954e559f` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/orders/{order_id}/notes/{note_id}")`
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/orders/{order_id}/notes/{note_id}")`
- Target: `/orders/{order_id}/notes/{note_id}`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/notes/{note_id}` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/notes/{note_id} as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-58db1e8887b2fb7c` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /orders/{order_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def verified_get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/orders/{order_id}/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /orders/{order_id}/verified` as `anonymous` → `422` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /orders/{order_id}/verified as anonymous returned HTTP 422, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-18095c8e393238b1` — outcome: **not_reproduced**

unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: <code>def verified_me(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/me/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /me/verified` as `anonymous` → `401` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the request was correctly denied (HTTP 401).
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: <code>def verified_me(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- Target: `/me/verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /me/verified` as `anonymous` → `passed`
- Observation: unauthenticated_access_corroboration: ZAP active scan completed and reported no alert at this exact path.
- Reasoning: Access was denied as expected; this attempt did not reproduce the hypothesis, which is not by itself conclusive proof that no exploitable path exists at all.
- Next action: **stop** (no_further_strategy)


### Hypothesis `ai-a0f6a99211967bdc` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /integrations/hook as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/integrations/hook")`
- Target: `/integrations/hook`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /integrations/hook` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /integrations/hook as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-861e82ee574e8e6d` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /integrations/hook-verified as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/integrations/hook-verified")`
- Target: `/integrations/hook-verified`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /integrations/hook-verified` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.post("/integrations/hook-verified")`
- Target: `/integrations/hook-verified`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /integrations/hook-verified` as `anonymous` → `405` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /integrations/hook-verified as anonymous returned HTTP 405, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-8e9b4463612bf8db` — outcome: **exploitation_confirmed**

unauthenticated_access: request to /forum/messages as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/forum/messages", response_class=HTMLResponse)`
- Target: `/forum/messages`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /forum/messages` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/forum/messages", response_class=HTMLResponse)`
- Target: `/forum/messages`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /forum/messages` as `anonymous` → `200` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: request to /forum/messages as anonymous returned HTTP 200, not one of the expected denial statuses \[401, 403, 404\].
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-7ab23a266d8c8a55` — outcome: **exploitation_confirmed**

unauthenticated_access_corroboration: ZAP active scan reported 1 alert(s) at this exact path, highest severity low: Application Error Disclosure.

**Attempt 1 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/errors/query")`
- Target: `/errors/query`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /errors/query` as `anonymous` → `500` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the response (HTTP 500) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: `@router.get("/errors/query")`
- Target: `/errors/query`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /errors/query` as `anonymous` → `violation`
- Observation: unauthenticated_access_corroboration: ZAP active scan reported 1 alert(s) at this exact path, highest severity low: Application Error Disclosure.
- Reasoning: The response failed the template's designed denial assertion; this is treated as evidence of exploitability for this specific probe, not as a bare, unexamined HTTP 200.
- Next action: **stop** (exploitation_confirmed)


### Hypothesis `ai-9f67cfc96698db68` — outcome: **exploitation_confirmed**

unauthenticated_access_corroboration: ZAP active scan reported 1 alert(s) at this exact path, highest severity low: Application Error Disclosure.

**Attempt 1 — <code>authorization_matrix</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/errors/checked")`
- Target: `/errors/checked`
- Plan: Does an authenticated account (admin) that is not the resource owner still get in?
  - Step 1: `GET /errors/checked` as `admin` → `blocked`
- Observation: authorization_matrix: the attempt could not complete (Request, capture or budget could not be completed; response values withheld).
- Reasoning: A prerequisite (login, capture or the request/time budget) failed before the security-relevant request could run; this is not evidence either way.
- Next action: **next_test**

**Attempt 2 — <code>unauthenticated_access</code> via <code>runtime_workflows</code>**

- Source entry point: `@router.get("/errors/checked")`
- Target: `/errors/checked`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `GET /errors/checked` as `anonymous` → `500` (expected one of [401, 403, 404])
- Observation: unauthenticated_access: the response (HTTP 500) was a server error or an ambiguous status.
- Reasoning: A 5xx or ambiguous status cannot by itself prove or disprove the hypothesis.
- Next action: **next_test**

**Attempt 3 — <code>unauthenticated_access</code> via <code>zap</code>, <code>playwright</code>**

- Source entry point: `@router.get("/errors/checked")`
- Target: `/errors/checked`
- Plan: Cheapest, safest first probe: does the route respond without any session at all?
  - Step 1: `ZAP_ACTIVE_SCAN /errors/checked` as `anonymous` → `violation`
- Observation: unauthenticated_access_corroboration: ZAP active scan reported 1 alert(s) at this exact path, highest severity low: Application Error Disclosure.
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
55. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-3913d8f00a297cfbf214</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ae2cae22d3790709c188f8d7</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
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

### 1. Clear‑text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The source excerpt shows that after a successful login the application logs the username together with the value of the environment variable APP_SECRET using a standard logger call (log.info). The scanner (semgrep) flags this as a credential‑leak pattern (CWE‑532). No surrounding code in the supplied excerpt demonstrates that the logged value is masked, redacted, or that logging is disabled in production. Consequently the code appears to expose a secret in clear text to whatever log sink is configured.

**Impact:** If log files are accessible to unauthorized users or forwarded to external logging services, the application secret (APP_SECRET) can be disclosed. An attacker who obtains the secret could impersonate the application, forge tokens, or gain other privileged access depending on how the secret is used elsewhere.

**Remediation:** Replace the logging of the secret with a redacted placeholder or remove it entirely. For example: log.info("login user=%s", username). If logging of the secret is required for debugging, ensure it is gated behind a debug flag and that production deployments have that flag disabled. Consider using a structured logger that can filter sensitive fields automatically.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) – line 137 in api/app.py (scanner semgrep rule python.lang.security.audit.logging.logger-credential-leak)`

Limitations:
- No evidence that a runtime guard (e.g., debug flag check) prevents this logging in production. No runtime probe confirming that the secret actually appears in logs. Absence of code showing that logging is disabled or that the secret is masked elsewhere.

### 2. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string without any sanitization or parameterization. This creates a classic SQL injection vector where an attacker can manipulate the query by supplying crafted input values. The supplied source excerpt shows the vulnerable string interpolation, and the scanner flagged this as a high‑severity issue. However, there is no independent runtime probe or additional scanner evidence confirming that the injection can be successfully exploited in the deployed environment.

**Impact:** An attacker could bypass authentication, retrieve or modify arbitrary data in the users table, or execute arbitrary SQL commands, potentially leading to full database compromise.

**Remediation:** Rewrite the query to use parameterized statements or an ORM that safely handles user input. For example, use a prepared statement with placeholders: `query = "SELECT id, username, role FROM users WHERE username=? AND password=?"` and pass `body.username` and `body.password` as parameters to the execute call. Additionally, consider hashing passwords instead of storing them in plain text.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- <code>Source excerpt shows string interpolation of `body.username` and `body.password` into the SQL query (lines 117‑119).</code>
- `Scanner flagged this as a high‑severity SQL injection finding.`

Limitations:
- No runtime probe or additional independent scanner evidence demonstrating successful exploitation.
- No evidence that input validation or escaping is performed elsewhere in the code base.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` guard ensures the resolved path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent existence check further validates the target. Thus the code includes the necessary safety checks, and the scanner’s finding is a false positive.

**Impact:** If the guard were missing, an attacker could read arbitrary files on the server, leading to data disclosure. However, the guard is present, so this risk is mitigated.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient. Ensure future code follows the same pattern when handling user‑controlled paths.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑224 show the use of `Path.is_relative_to` to enforce the file stays within the `public` directory and a file existence check.</code>

### 4. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint verifies that the resolved file path is a sub‑path of the intended root directory using `is_relative_to(root)` and also checks that the target is a regular file before reading it. This prevents directory‑traversal attacks despite the user‑controlled `name` parameter.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server. The existing guard mitigates that risk.

**Remediation:** No remediation needed; the current path validation is sufficient. Ensure future changes retain the `is_relative_to` and `is_file` checks.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>source_excerpt lines 220‑223 show the `is_relative_to` guard and file existence check.</code>

### 5. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory and then verifies that the resulting path is still within that base using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** No impact; the endpoint safely restricts file access to the intended public directory.

**Remediation:** No remediation needed; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>source_excerpt shows use of `resolve()` and `is_relative_to(FILES.resolve())` to ensure the path stays within the allowed directory</code>
- <code>source_excerpt includes `if not file.is_relative_to(... ) or not file.is_file(): raise HTTPException(404)` which blocks out‑of‑bounds or non‑file paths</code>

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function verifies that the resolved file path is within the designated public directory using `is_relative_to(root)` and also checks that the target is an existing file with `is_file()`. These checks prevent directory traversal and ensure only legitimate files are served, mitigating the reported uncontrolled data usage.

**Impact:** No impact as the path is properly validated, preventing unauthorized file access.

**Remediation:** No remediation needed; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>The code includes `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)` which blocks paths outside the public directory and non‑existent files.</code>

### 7. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against the trusted base directory (FILES / "public") and then verifies that the resulting path is still within that base directory using `is_relative_to(FILES.resolve())`. It also checks that the target is a regular file before reading it. These checks mitigate path traversal, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None – the file read operation is safely constrained to the intended public directory, preventing unauthorized file access.

**Remediation:** No remediation needed for this finding; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>The function constructs the path with `(FILES / &quot;public&quot; / name).resolve()` and then checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)` which blocks traversal and non‑file paths.</code>

### 8. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint returns an HTML response that directly interpolates the user‑controlled query parameter `q` into the page title and into the generated HTML without any escaping or sanitisation. This creates a reflected XSS risk because an attacker can craft a URL such as <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> and the script tag would be reflected in the response body. The source excerpt shows the vulnerable code, and the AI candidate highlights the missing HTML‑escape check. No evidence of a defensive mechanism (e.g., output encoding, CSP, or input validation) is present in the supplied context.

**Impact:** An attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, or other malicious actions against users of the affected endpoint.

**Remediation:** Encode or escape the `q` parameter before embedding it in the HTML response. Use a templating engine that auto‑escapes, or explicitly apply an HTML‑escaping function (e.g., `html.escape(q)`). Additionally, consider adding a Content‑Security‑Policy header to mitigate script execution and validate input length/characters as appropriate.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`, `ai-c16d37bee59101c7`
- <code>Source excerpt lines 141‑145 show `def catalog_search(q: str = &quot;&quot;) -&gt; str:` and the return statement that embeds `q` directly into HTML.</code>
- <code>AI candidate identifies the missing HTML‑escape check for `q`.</code>

Limitations:
- No runtime probe confirms that the injected payload is executed in a browser context; the evidence is limited to static code analysis. No information is provided about existing response headers (e.g., CSP) or downstream middleware that might perform automatic escaping.

### 9. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename and then verifies that the resulting path is within the allowed directory using `is_relative_to(FILES.resolve())` and also checks that it is a file. These checks prevent directory traversal and ensure only files under the public directory are served.

**Impact:** If the checks were missing, an attacker could read arbitrary files on the server. However, the presence of the relative‑path check mitigates this risk.

**Remediation:** No remediation needed; the existing checks are appropriate. Ensure that `FILES` is correctly set to the intended base directory and that the runtime environment does not alter path resolution semantics.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- <code>Source excerpt shows `file = (FILES / &quot;public&quot; / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 10. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL query by directly interpolating the user‑provided parameter `q` into the query string using an f‑string. This creates a potential SQL injection vector because the input is not sanitized, escaped, or passed as a parameter to a prepared statement. The supplied source excerpt shows the vulnerable code, but there is no evidence of a guard (e.g., input validation, ORM parameterization) in the provided context, nor any runtime probe confirming exploitation.

**Impact:** An attacker could supply crafted input for `q` to manipulate the SQL query, potentially retrieving unauthorized data, modifying database contents, or executing arbitrary SQL commands, leading to data breach or loss of integrity.

**Remediation:** Refactor the query to use parameterized statements or an ORM that handles escaping, e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`. Additionally, validate and sanitize user input and consider limiting the length of `q`.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt shows f‑string interpolation of `q` into SQL query at line 144</code>
- `Scanner finding flagged this as high severity`

Limitations:
- No runtime probe evidence demonstrating successful injection
- No visible input sanitization or use of prepared statements in the provided snippet

### 11. X-Content-Type-Options Header Missing

- Issue group: `merged-4c6d36222f8ebf7f1f68`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for the root path (GET /) does not include the X-Content-Type-Options header. The supplied source excerpt shows only the FastAPI route definitions and does not contain any middleware or response configuration that would set this header. No runtime probe evidence demonstrates the header being absent or present, and there is no additional scanner evidence of higher severity confirming the issue.

**Impact:** If the header is indeed missing, browsers may perform MIME type sniffing, potentially allowing content-type confusion attacks such as cross‑site scripting in certain edge cases.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a middleware that sets the header or using a security library that adds it automatically.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Scanner runtime fact (zap.10021) reports GET / without X-Content-Type-Options header`

Limitations:
- The provided code does not show any response header handling, so it cannot be confirmed whether the header is set elsewhere (e.g., in middleware, server configuration, or deployment settings). No runtime probe directly verifies the header’s presence or absence. Additional evidence such as full response headers from the running service or code that sets security headers is required.

### 12. Job listing requires admin role

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs endpoint calls the principal() function with the provided Authorization header but does not perform any further role check to ensure the caller has an admin role before returning the full list of jobs. The runtime probe confirms that an unauthenticated request receives a 200 OK response, indicating the missing access control.

**Impact:** Unauthenticated or non‑admin users can retrieve the complete job listing, potentially exposing sensitive internal data and enabling further attacks such as data harvesting or privilege escalation.

**Remediation:** Add an explicit admin‑role check after principal() verification, returning 403 Forbidden for non‑admin users. Example: if not principal.is_admin: raise HTTPException(status_code=403).
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs endpoint calling principal() without role verification (lines 285‑290).`
- `Runtime probe fact: GET /admin/jobs returned status 200 when 403/404 were expected (rule workflow.admin_jobs.2).`

### 13. Demoted administrator retains access to /admin/token-report

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint checks the role field in the token and returns 403 only if the role is not "admin". The runtime probe shows a GET request to /admin/token-report returned 200 instead of the expected 403, indicating that a token belonging to a demoted administrator was still accepted as valid. The source code does not show any mechanism that invalidates or refreshes tokens when a user's role changes, so the check may be ineffective for stale tokens.

**Impact:** A user whose administrative privileges have been revoked could continue to access privileged functionality, potentially exposing sensitive data or allowing unauthorized actions.

**Remediation:** Implement token revocation or short-lived tokens with server‑side validation of the current user role on each request. Ensure that role changes invalidate existing tokens or that the token validation logic re‑checks the user's role against the current database state.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check but no token freshness logic (lines 660‑664).`
- `Runtime probe fact: GET /admin/token-report returned status 200 when 403 was expected (workflow.stale_role.3).`

Limitations:
- Missing evidence about how the token is issued and whether it is refreshed or revoked on role changes. No view of the principal() implementation to confirm it validates current role. Unable to confirm if the observed 200 response was due to a stale token or another factor.

### 14. User listing endpoint lacks admin authorization check

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source code for the /admin/users endpoint calls a generic principal() function but does not perform any role‑based check to ensure the caller has an admin role before querying and returning all user records, including sensitive fields such as SSN. A runtime probe confirms that an unauthenticated GET request to /admin/users returns HTTP 200 with data, whereas the expected behavior (per the scanner rule) would be a 403/404 response. This demonstrates that the endpoint is accessible without proper admin authorization.

**Impact:** An attacker can enumerate all user accounts and retrieve sensitive personal information (including SSN), leading to privacy violations, identity theft, and potential further attacks against user accounts.

**Remediation:** Add an explicit admin role check after principal() verification, e.g.,:
```python
if not principal_has_role(authorization, "admin"):
    raise HTTPException(status_code=403, detail="Forbidden")
``` 
Ensure that only users with the admin role can access the endpoint and that sensitive fields are filtered or masked as appropriate.
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source excerpt shows admin_users endpoint without role check (lines 278‑282).`
- `Runtime probe fact indicates GET /admin/users returned status 200 instead of 403/404 (web-runtime rule workflow.admin_users.2).`

### 15. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a session cookie (lab_session) without specifying the HttpOnly attribute, and the runtime probe confirms the endpoint is reachable via POST. No evidence is provided that the cookie is later marked HttpOnly or that a security middleware adds the flag.

**Impact:** An attacker who can execute JavaScript in the victim's browser could read the session cookie, potentially leading to session hijacking.

**Remediation:** Set the HttpOnly flag when creating the cookie, e.g., response.set_cookie("lab_session", f"session-{row\['id'\]}", httponly=True).
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- `Source excerpt shows response.set_cookie("lab_session", f"session-{row['id']}") without HttpOnly flag (lines 299-300).`
- `Runtime probe fact confirms POST request to /auth/form-login (scanner_id: web-runtime, rule_id: zap.10010).`

Limitations:
- Missing evidence that the HttpOnly flag is added elsewhere (e.g., via middleware or later response modification).
- No runtime observation confirming the cookie is sent without HttpOnly.

### 16. X-Content-Type-Options Header Missing

- Issue group: `merged-3913d8f00a297cfbf214`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /auth/form-login returns an HTML response but the supplied source excerpt and runtime probe do not show the X-Content-Type-Options header being set. Absence of this header allows browsers to perform MIME type sniffing, which can lead to content injection attacks.

**Impact:** An attacker could craft a response that is interpreted as a different MIME type (e.g., executable script) by the browser, potentially enabling cross‑site scripting or drive‑by download attacks.

**Remediation:** Add the header to all responses, e.g., `response.headers['X-Content-Type-Options'] = 'nosniff'` or configure the framework/middleware to set it globally.
Evidence:
- Source IDs: `merged-3913d8f00a297cfbf214`
- <code>Source excerpt shows the response is created with `HTMLResponse` but no header is set.</code>
- `Runtime probe fact indicates a POST request to /auth/form-login but does not report the X-Content-Type-Options header.`

Limitations:
- No captured HTTP response showing the missing header; need concrete response evidence from a scanner or runtime probe that confirms the header is absent.

### 17. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reports that the response from the /auth/form-login endpoint does not include an anti-clickjacking header (e.g., X-Frame-Options or Content‑Security‑Policy frame‑ancestors). The source excerpt shows the endpoint implementation but does not set any such header on the returned HTMLResponse. No guard or header‑setting logic is visible in the supplied code.

**Impact:** An attacker could embed the login page in a malicious site using an iframe, potentially tricking users into submitting credentials (clickjacking).

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP frame‑ancestors directive.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Scanner runtime finding (zap.10020) reports missing anti‑clickjacking header for POST /auth/form-login`
- `Source code excerpt shows no header being set on the HTMLResponse`

Limitations:
- No direct observation of the response headers from a runtime probe confirming the header is absent
- No evidence that the application sets a global security middleware that might add the header automatically

### 18. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /auth/form-login processes a POST request containing user credentials but no evidence is provided that the HTTP response includes a Content‑Security‑Policy header. The scanner flagged the missing CSP header, and the runtime probe confirms the endpoint is reachable, but the supplied source excerpt and probe data do not contain the response headers needed to confirm the absence of CSP. Without explicit header inspection, the finding remains plausible but unproven.

**Impact:** Without a CSP header, the application is vulnerable to certain cross‑site scripting (XSS) and data‑injection attacks that could be mitigated by restricting the sources from which scripts, styles, and other resources may be loaded.

**Remediation:** Configure the web framework or reverse‑proxy to add a strict Content‑Security‑Policy header to all responses, e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self'; object-src 'none';` and ensure it is applied to the /auth/form-login route.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `runtime_probe_facts indicates a POST request to /auth/form-login was observed (scanner_id: web-runtime, rule_id: zap.10038).`
- `source_excerpt shows the implementation of the form_login endpoint but contains no header‑setting logic.`

Limitations:
- No captured HTTP response headers to demonstrate that CSP is missing.
- No additional scanner or runtime evidence directly confirming the header absence.

### 19. Password reset tokens must be single use

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The confirm_reset endpoint retrieves a reset token from the database and, if valid, updates the user's password without invalidating or deleting the token. No check is performed to ensure the token is single‑use. A runtime probe confirms that a POST to /auth/reset/confirm with a reused token returns HTTP 200 instead of the expected error codes (400, 409, 422), demonstrating that the token can be replayed.

**Impact:** An attacker who obtains a valid password reset token can reuse it to reset the victim's password multiple times, leading to account takeover.

**Remediation:** Invalidate or delete the reset token after a successful password change. Add a check to ensure the token has not been used before, and enforce a single‑use policy in the database (e.g., a used flag or delete the row).
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source code at lines 577‑585 shows token lookup and password update without token invalidation`
- `Runtime probe fact: POST /auth/reset/confirm with reused token returned status 200, contrary to expected error statuses`

### 20. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/query` returns HTML content without any indication that a Content‑Security‑Policy header is added to the response. The source excerpt shows only the HTML generation logic and does not set response headers. The runtime probe confirms the endpoint is reachable via GET but does not provide header information. No guard or configuration that would add a CSP header is visible in the supplied context.

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, or other resources can be loaded, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Configure the FastAPI application (or the specific router) to include a CSP header in responses, e.g., using a middleware that adds `Content‑Security‑Policy: default-src 'self';` or a more restrictive policy appropriate to the application.
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Source excerpt shows HTML response generation without header handling`
- `Runtime probe fact confirms GET request to /catalog/query but does not show CSP header`

Limitations:
- Missing concrete evidence of response headers from the running application (e.g., captured HTTP response showing absence of CSP)
- No information about global middleware or server configuration that might add CSP headers automatically

### 21. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting any X-Frame-Options or Content-Security-Policy frame-ancestors directives. The source excerpt shows the response is built and returned directly, and no header-setting code is present in the surrounding module. The runtime probe confirms the endpoint is reachable via GET, but does not capture response headers. No guard or defensive header logic is visible in the supplied context.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add an appropriate anti-clickjacking header (e.g., X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self') to the response for this endpoint, either globally via middleware or locally in the route handler.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact confirms GET request to /catalog/query`

Limitations:
- No captured response headers to confirm the header is indeed missing at runtime
- No evidence that a global middleware might be adding the header elsewhere in the application

### 22. Missing Anti-clickjacking Header on /comments endpoint

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns HTML content without setting any anti-clickjacking headers (e.g., X-Frame-Options or Content-Security-Policy frame-ancestors). The source code shows a plain HTML string being returned, and the runtime probe confirms that a GET request to /comments does not include these security headers. No defensive check or header injection is present in the supplied context.

**Impact:** An attacker can embed the page in a malicious iframe, enabling clickjacking attacks that could trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti-clickjacking headers to the response, such as:
```python
from fastapi.responses import HTMLResponse
from fastapi import Response

@router.get("/comments", response_class=HTMLResponse)
def show_comments(response: Response):
    response.headers\["X-Frame-Options"\] = "DENY"
    # or Content-Security-Policy: frame-ancestors 'none';
    ...
```
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Source code at lines 173-177 returns HTML without setting security headers`
- `Runtime probe fact (zap.10020) shows GET /comments response missing anti-clickjacking header`

### 23. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns an HTML page constructed from database content without adding any security‑related HTTP headers. The source excerpt shows the response is built directly and returned as a plain string, and no CSP header is set in the code. A runtime probe confirms the endpoint is reachable via GET, but it does not capture response headers, so the absence of a CSP header is not directly proven. Consequently, the finding is plausible but lacks definitive proof that the header is missing in actual responses.

**Impact:** Without a CSP header, browsers are free to execute inline scripts or load resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks.

**Remediation:** Add a CSP header to the response, either globally via middleware or specifically for this route. For example, in FastAPI you can use a `Response` object and set `headers={'Content‑Security‑Policy': "default-src 'self'"}` or configure Starlette middleware to add the header to all responses.
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- <code>Source excerpt shows `/comments` endpoint returns HTML without setting headers</code>
- `Runtime probe fact indicates the endpoint is reachable via GET`

Limitations:
- No captured HTTP response headers confirming the CSP header is absent
- No evidence that a global middleware or server configuration might already add a CSP header

### 24. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content but the source code does not set the `X-Content-Type-Options: nosniff` header. The runtime probe confirms a GET request to this path, and the scanner flagged the missing header. No defensive header is added in the provided code, and no other evidence of a guard is present.

**Impact:** Without the `X-Content-Type-Options` header browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response, e.g., by configuring the FastAPI app or the specific route to include the header in the response object.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- `Runtime probe observed a GET request to /comments with no X-Content-Type-Options header (zap.10021)`

Limitations:
- Missing direct observation of the response headers from the running service; need captured HTTP response showing the header is absent.

### 25. Debug configuration is exposed without authentication

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /debug/config returns sensitive configuration values (database URL, mock external URL, app secret) without any authentication or access control checks. The source code shows the function directly returns these values, and a runtime probe confirms that an unauthenticated GET request receives a 200 response, whereas a 401/403/404 was expected.

**Impact:** An attacker can retrieve internal configuration data, potentially leading to credential leakage, database compromise, or further privilege escalation.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint, ensuring only authorized users can access it. Consider removing sensitive data from the response or protecting it behind environment‑specific feature flags.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source code defines debug_config() at line 321 returning DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks`
- `Runtime probe fact: GET /debug/config returned HTTP 200 (unexpected)`

### 26. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime probe reports a 200 response from /healthz without a Content‑Security‑Policy header. The source code for the endpoint does not set any security headers, and no other evidence (e.g., middleware, server configuration) is provided that would add the header. Therefore the finding is plausible but not definitively proven.

**Impact:** Absence of a CSP header allows browsers to load resources (scripts, styles, etc.) from any origin, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Configure the application or web server to include a strong Content‑Security‑Policy header on all responses, e.g., via FastAPI middleware or server settings.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Runtime probe fact: path "/healthz" returned status 200 with no CSP header (web.missing-content-security-policy).`
- `Source excerpt shows the healthz endpoint implementation without header manipulation.`

Limitations:
- No direct observation of the response headers from the running service is provided; the probe only indicates the rule was triggered.
- Potential middleware or server‑level configuration that adds CSP is not visible in the supplied code.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports that the /healthz endpoint does not include a X-Frame-Options or Content‑Security‑Policy frame‑ancestors header. The provided source code shows the endpoint implementation but does not reveal any response‑header logic. No runtime probe data confirming the absence of the header is included, only a 200 status code. Therefore the claim is plausible but not definitively proven by the supplied evidence.

**Impact:** An attacker could embed the /healthz page in a malicious site using an iframe, potentially facilitating clickjacking attacks that trick users into interacting with the page without their knowledge.

**Remediation:** Add a clickjacking protection header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP `frame-ancestors 'none'`. Ensure the header is set for all endpoints, including /healthz.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner rule web.missing-clickjacking-protection reported missing header on /healthz`
- `Source excerpt shows /healthz endpoint implementation without header handling`

Limitations:
- No runtime probe showing the actual response headers; the scanner’s finding is not independently corroborated by observed data.

### 28. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the /healthz endpoint does not include the X-Content-Type-Options header. The provided source code shows the endpoint implementation but does not reveal response header handling. No runtime probe response data confirming the absence of the header is included.

**Impact:** Without the X-Content-Type-Options header, browsers may perform MIME type sniffing, potentially allowing content injection attacks.

**Remediation:** Configure the web framework or middleware to add the header, e.g., `response.headers['X-Content-Type-Options'] = 'nosniff'` for all responses.
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Scanner finding: X-Content-Type-Options Header Missing for /healthz`

Limitations:
- No captured HTTP response showing the header is absent; header configuration in the application is not visible in the supplied code.

### 29. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response but the observed runtime probe does not show the X-Content-Type-Options header. The source code defines the endpoint but does not set any security headers, and the scanner flagged the missing header. While this suggests a potential issue, the evidence does not include a full HTTP response header dump to confirm the header is absent, nor does it show any middleware that might add the header elsewhere.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may incorrectly sniff content types, potentially enabling certain cross‑site scripting or drive‑by download attacks.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to include the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a middleware that sets this header globally or by using a security‑headers library.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Source excerpt defines the /healthz endpoint (lines 154‑158) without setting security headers`
- `Runtime probe fact shows a 200 status for /healthz but no header information`

Limitations:
- No captured HTTP response headers to definitively prove the header is missing
- No evidence of global middleware that might add the header elsewhere in the application

### 30. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/integrations/hook` accepts POST requests, reads the raw request body, and directly inserts it into the `visits` table with `accepted=true` without any verification of a cryptographic signature or authentication token. The runtime probe confirms that a POST request to this path returns HTTP 200, whereas a secure implementation would return a client error (e.g., 400, 401, 403). This demonstrates an unauthenticated, unsigned webhook acceptance, allowing an attacker to submit arbitrary data that is persisted as an accepted visit.

**Impact:** An attacker can forge webhook payloads, causing arbitrary data injection into the database. This may be used to spoof visits, trigger downstream logic, or perform further injection attacks, leading to data integrity loss and potential escalation of privileges.

**Remediation:** Implement signature verification for incoming webhook requests. Require a shared secret or public‑key signature (e.g., HMAC, JWT) and validate it before processing the payload. Return a 4xx error when verification fails. Additionally, sanitize and validate the payload before inserting it into the database.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- <code>Source excerpt shows the `/integrations/hook` endpoint inserts the raw request body into the database without any signature check (lines 629‑633).</code>
- <code>Runtime probe fact reports a POST to `/integrations/hook` returned status 200, while expected secure statuses are 400, 401, or 403 (rule `workflow.unsigned_hook.1`).</code>

### 31. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not perform any check that the authenticated user is the owner of the requested invoice. The subsequent database query retrieves the invoice by its ID without filtering by the user’s identifier. The runtime probe confirms that an unauthorized request receives a 200 OK response instead of the expected 403/404, indicating that the ownership check is missing.

**Impact:** An attacker who can obtain a valid authorization token for any user can retrieve invoices belonging to other users, leading to confidentiality breaches of financial data.

**Remediation:** Add an ownership verification step after retrieving the invoice, e.g., compare `row['owner_id']` (or equivalent) with the authenticated principal’s user ID and return a 403 error if they do not match. Ensure the database query includes a condition that limits results to invoices owned by the requester.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- <code>Source excerpt shows `principal(authorization)` is called but no owner check before returning the invoice (lines 268‑274).</code>
- <code>Runtime probe fact reports a GET request to `/invoices/{{invoice_id}}` returned status 200 instead of the expected 403/404, indicating the endpoint is accessible without ownership validation.</code>

Limitations:
- The supplied code does not show the implementation of `principal` or any surrounding middleware that might enforce ownership; we cannot confirm that no such guard exists elsewhere in the application. Additional evidence from the full codebase or logs showing the absence of an ownership check would be needed to confirm the vulnerability definitively.

### 32. Unauthorized job submission endpoint allows admin jobs

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint calls `principal(authorization)` but does not perform any further authorization check before inserting a job record with the supplied `run_as` value. The runtime probe observed a successful 200 response for a POST request, whereas the expected responses for unauthorized or malformed requests were 400, 403, or 422. This demonstrates that an attacker can submit jobs with arbitrary `run_as` values, potentially gaining elevated privileges.

**Impact:** An attacker can create jobs that run with elevated privileges or as other users, leading to privilege escalation, unauthorized code execution, or data exfiltration.

**Remediation:** Add explicit authorization checks after `principal(authorization)` to verify that the authenticated principal has permission to create jobs of the requested kind or to specify the `run_as` field. Return 403/401 for unauthorized attempts.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- <code>Source excerpt shows `principal(authorization)` called without further role checks before inserting into jobs table (lines 309‑317).</code>
- `Runtime probe fact: POST /jobs returned status 200, while expected unauthorized statuses were 400, 403, 422 (scanner_id: web-runtime, rule_id: workflow.worker_role.1).`

### 33. Identity endpoint may expose sensitive SSN data

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table and selects the ssn column, then returns the row as a dictionary. No access control or data filtering is shown in the supplied code, so the SSN could be included in the response. The runtime probe indicates that values were redacted, but it does not confirm that the SSN field is omitted or masked. The scanner finding flags this as excessive data exposure.

**Impact:** If an attacker can call /me and obtain a valid authorization token, they may receive the user's social security number, leading to identity theft and privacy violations.

**Remediation:** Modify the endpoint to exclude the ssn field from the returned data or mask it before sending the response. Implement proper access controls to ensure only authorized personnel can view sensitive fields.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source excerpt shows SELECT id,username,role,email,ssn FROM users ... and return dict(row)`
- `Runtime probe fact indicates values_redacted true but does not specify which fields were redacted`

Limitations:
- Missing confirmation whether the SSN value is actually redacted or masked in the response
- No evidence of additional guard checks (e.g., role‑based filtering) outside the provided snippet

### 34. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price value directly from the request body into the database without any apparent server‑side validation or override. The runtime probe shows the endpoint returns a 200 status for a POST to /orders, but it does not demonstrate that the supplied price is accepted unchanged. The scanner finding flags this as a potential issue, but independent proof that the price can be manipulated is not present in the supplied data.

**Impact:** An attacker could submit an order with a manipulated unit_price, potentially purchasing items at a lower price than intended, leading to revenue loss and inventory inconsistencies.

**Remediation:** Validate and enforce the unit_price on the server side, e.g., by looking up the official price from a trusted catalog and ignoring any client‑provided price field. Remove the unit_price field from the request schema or replace its value with the catalog price before inserting into the database.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt shows the unit_price field from the request body is stored directly (lines 213‑215).`
- `Runtime probe fact indicates the POST /orders endpoint returns a 200 status, confirming the endpoint is reachable.`

Limitations:
- No concrete runtime evidence that a client‑supplied price is accepted unchanged (e.g., a test showing a lower price results in a successful order).
- No guard or validation logic is visible in the provided code to confirm the price is overridden or checked.

### 35. New orders can be created with arbitrary initial status

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders endpoint directly inserts the order into the database using the status value supplied in the request body without any validation or restriction. The source excerpt shows that the `status` field from `body.status` is passed straight to the INSERT statement. The runtime probe confirms that a POST request to /orders returns HTTP 200 instead of the expected 400/422, demonstrating that the endpoint accepts the request and creates the order with the provided status. This combination of source code and observed behavior satisfies the criteria for a confirmed vulnerability.

**Impact:** An attacker can create orders with a paid status or any other privileged state, potentially bypassing payment workflows, causing financial discrepancies, and enabling fraud or unauthorized access to privileged order operations.

**Remediation:** Validate the `status` field in the request body to ensure only allowed initial states (e.g., 'pending') are accepted. Reject or sanitize any disallowed values with a 400 Bad Request response. Consider using an enum or server‑side default for the initial order status rather than trusting client input.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- <code>Source excerpt lines 208‑215 show the `status` field from the request body being inserted without validation.</code>
- `Runtime probe fact: POST /orders returned HTTP 200 when a status other than allowed was supplied, whereas the expected responses were 400 or 422.`

### 36. Negative order prices are accepted without validation

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the supplied unit_price directly into the database without any validation. The runtime probe observed a POST to /orders with a negative price resulting in HTTP 200, while the expected behavior was a 4xx error. This demonstrates that negative prices are accepted, leading to potential financial manipulation.

**Impact:** An attacker can create orders with negative unit_price values, effectively crediting their account or causing accounting inconsistencies, which can be exploited for fraud or denial of service.

**Remediation:** Add input validation to ensure unit_price (and other monetary fields) are non‑negative and within acceptable ranges before inserting into the database. Return a 4xx error if validation fails.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Source excerpt shows create_order inserts body.unit_price without checks (lines 208‑215).`
- `Runtime probe fact: POST /orders with negative price returned status 200 instead of expected 400/422 (scanner_id: web-runtime, rule_id: workflow.negative_price.1).`

### 37. Missing ownership check on order creation

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and defaults to the authenticated user's sub when omitted. No validation is performed to ensure that a supplied owner_id matches the authenticated user, allowing a user to create orders on behalf of another owner. The runtime probe confirms that a POST to /orders succeeds with status 200, whereas a secure implementation would return 400/403/422 when the owner_id does not belong to the caller.

**Impact:** An attacker can create or manipulate orders for other users, leading to unauthorized transactions, potential financial loss, and violation of data integrity.

**Remediation:** Validate that the owner_id provided in the request body matches the authenticated user's identifier (user\["sub"\]). If they differ, reject the request with an appropriate error (e.g., 403 Forbidden). Alternatively, remove the ability for clients to specify owner_id and always use the authenticated user's ID.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows owner_id is set from body.owner_id without validation (lines 208-210).`
- `Runtime probe fact indicates a POST to /orders returned 200 instead of expected error codes (status 200, expected_statuses [400,403,422]).`

Limitations:
- No evidence is provided that additional authorization checks exist elsewhere in the codebase (e.g., middleware or database constraints). Confirmation requires independent corroboration such as a scanner of medium or higher severity or additional runtime probes demonstrating the vulnerability across varied inputs.

### 38. Insecure direct object reference for notes endpoint

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `order_note` handler retrieves a note by `note_id` without verifying that the note's `order_id` matches the `order_id` supplied in the URL. No authorization check is performed after the database query, allowing any authenticated user to access notes belonging to other orders. Runtime probing confirms the endpoint returns HTTP 200 for a note that does not belong to the requested order, indicating the missing ownership check is exploitable.

**Impact:** An attacker can enumerate or read notes from orders they do not own, leading to information disclosure and potential privacy violations.

**Remediation:** Validate that the `order_id` of the fetched note matches the `order_id` path parameter before returning the note. Return 403 (Forbidden) or 404 (Not Found) if the IDs do not match. Example:
```python
row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()
if not row or row\["order_id"\] != order_id:
    raise HTTPException(404, "Note not found")
return dict(row)
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- `Source code shows note fetched without order_id check (lines 543‑548).`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200 instead of expected 403/404.`

### 39. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders/{order_id} calls principal(authorization) but does not verify that the authenticated user is the owner of the requested order before returning the record. The source excerpt shows no ownership check after the database query. A runtime probe for the same path returned HTTP 200 for a request that should have been denied (expected 403), confirming that the missing check is exploitable.

**Impact:** An attacker who can obtain a valid authorization token can retrieve any order by ID, leading to unauthorized disclosure of potentially sensitive order data.

**Remediation:** Add an ownership verification step after fetching the order, e.g., compare the order's owner_id with the authenticated user's ID and return HTTP 403 if they do not match. Ensure the principal function returns the user identity for this comparison.
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- `Source excerpt lines 221‑227 show the endpoint without an ownership check`
- `Runtime probe fact: GET /orders/{{order_id}} returned status 200 when a 403 was expected (workflow.order_owner.3)`

### 40. Excessive coupon discounts are rejected

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint accepts a discount value from the request body and applies it directly to the order without validating that the discount is within acceptable bounds. The runtime probe shows that a request with an excessive discount receives a 200 OK response instead of the expected 400/422 error, indicating the missing validation. No guard or limit check is present in the supplied code snippet.

**Impact:** An attacker could submit a coupon with an arbitrarily large discount, potentially reducing order totals to zero or negative values, leading to financial loss.

**Remediation:** Add validation to ensure the discount does not exceed the maximum allowed percentage (e.g., compare the requested discount against the coupon's percent or a configured maximum) and return an error (400/422) if it does. Also log or audit such attempts.
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- `Source excerpt shows discount applied without bounds check (lines 231-237).`
- `Runtime probe fact indicates POST to /orders/{{order_id}}/apply-coupon returned status 200 when a 400/422 was expected for excessive discount.`

Limitations:
- Missing explicit test cases demonstrating the maximum allowed discount value and the system's response when that limit is exceeded. No evidence of any external guard (e.g., middleware) that might enforce discount limits outside the shown function.

### 41. Paid orders can be cancelled without refund

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/cancel` updates the order status to `cancelled` without any check for the order's payment state. The source excerpt shows the function directly executes the UPDATE statement after authentication, with no validation that the order has been paid or that a refund has been processed. Runtime probe facts confirm the endpoint returns HTTP 200 for a paid order, whereas the expected behavior is to reject the request with a client error (e.g., 400/409/422). This demonstrates that a paid order can be cancelled without a refund, constituting a business‑logic vulnerability.

**Impact:** An attacker (or a malicious user) can cancel paid orders and potentially receive goods or services without providing a refund, leading to financial loss and inventory inconsistencies.

**Remediation:** Add a check before cancelling an order to verify that the order is either unpaid or that a refund has been successfully processed. Return an appropriate error (e.g., 400 or 409) if the order is paid and no refund exists. Ensure the check is performed after authentication and before the UPDATE statement.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- `Source excerpt shows cancel_order endpoint updates order status without payment check`
- `Runtime probe fact shows POST to /orders/{{order_id}}/cancel returned 200 instead of expected error codes`

### 42. Potential payment replay vulnerability in order payment endpoint

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The pay_order endpoint updates the order status to 'paid' without checking whether the order has already been paid. The supplied source shows the update occurs unconditionally after retrieving the order, and the runtime probe indicates a POST to this endpoint returns HTTP 200 instead of the expected error codes (400, 409, 422) for a replay attempt. This suggests a second payment could be accepted for an already‑paid order, but the evidence lacks an explicit guard check or independent scanner confirmation of the flaw.

**Impact:** An attacker could submit a second payment request for an order that has already been settled, potentially causing double charging, inventory inconsistencies, or financial loss.

**Remediation:** Add a check before updating the order status to verify that the order is not already marked as 'paid'. Return an appropriate error (e.g., 409 Conflict) if a payment replay is attempted. Ensure the status check and error handling are covered by tests.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- `Source excerpt shows the endpoint updates status to 'paid' without prior paid‑status verification (lines 242‑250).`
- `Runtime probe fact reports the POST request returned 200 instead of the expected error codes, indicating the replay was not blocked.`

Limitations:
- Missing explicit evidence of a guard check for already‑paid orders in the supplied code.
- No independent high‑severity scanner finding confirming the issue; only a runtime observation is present.

### 43. Insecure profile access allows reading other users' data

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is authorized to view the requested `profile_id`. The SQL query returns the full user record (including sensitive fields such as SSN) for any `profile_id` supplied, and the subsequent check only verifies that a row exists, not that it belongs to the caller. The runtime probe confirms the flaw: a GET request for another user's profile returned HTTP 200 instead of the expected 403/404, demonstrating that the access control check is missing.

**Impact:** An attacker who can obtain a valid authorization token can enumerate or retrieve arbitrary users' personal information, including usernames, emails, and social security numbers, leading to privacy violations and potential identity theft.

**Remediation:** Add an ownership check after retrieving the profile: compare the `profile_id` with the authenticated user's identifier (e.g., `principal_user_id`). Return HTTP 403 if they do not match. Also limit the selected columns to only non‑sensitive data unless explicitly needed, and use parameterized queries to prevent injection.
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source excerpt shows endpoint definition without ownership check (lines 98‑104).`
- `Runtime probe fact: GET /profiles/{{other_id}} returned status 200 when 403/404 were expected (rule workflow.profile_owner.2).`

### 44. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The source code for the `/view` endpoint returns an HTMLResponse without setting any anti-clickjacking headers such as `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`. No guard or header injection is visible in the supplied snippet. A runtime probe observed a GET request to `/view`, but it did not capture response headers, so the absence of the header is inferred from the code rather than confirmed at runtime.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `return HTMLResponse(content, headers={"X-Frame-Options": "DENY"})` or configure a CSP `frame-ancestors 'none'`. Ensure the header is applied globally or to all relevant routes.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse returned without header configuration (lines 686‑690).`
- <code>Runtime probe fact indicates a GET request to `/view` was made (web-runtime zap.10020).</code>

Limitations:
- No runtime capture of actual response headers to confirm the header is missing.
- No evidence that a middleware or server configuration elsewhere adds the header.
- No independent scanner of higher severity confirming the issue.

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /view returns an HTMLResponse without any CSP header. The scanner flagged the missing CSP header, and the source code shows no explicit header being set. No runtime probe evidence confirming the header is absent is provided, and no application logic adds the header elsewhere in the supplied context.

**Impact:** Without a CSP header, the application is vulnerable to cross‑site scripting (XSS) and other content injection attacks, allowing an attacker to execute malicious scripts in the victim’s browser.

**Remediation:** Configure the FastAPI application or the specific route to include a strong Content‑Security‑Policy header (e.g., using a middleware or response headers) that restricts script sources, object sources, and other content types.
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- `Source excerpt shows HTMLResponse returned without CSP header (lines 686‑690).`
- `Scanner evidence reports "Content Security Policy (CSP) Header Not Set" for /view.`

Limitations:
- No runtime response captured that demonstrates the CSP header is actually missing in the HTTP response.
- No evidence that the application sets CSP headers globally via middleware or server configuration.

### 46. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse without explicitly setting the `X-Content-Type-Options: nosniff` header. The source excerpt shows only the HTML payload and no header manipulation. The scanner flagged the missing header, and the runtime probe observed a GET request to the path, but no response header data was provided to confirm the absence.

**Impact:** Without the `X-Content-Type-Options` header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response content type.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response, e.g., by configuring the FastAPI/Starlette response middleware or setting the header directly in the endpoint before returning the HTMLResponse.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- <code>Source excerpt shows the `/view` endpoint returning HTMLResponse without header handling</code>
- `Scanner flagged "X-Content-Type-Options Header Missing" for path /view`
- `Runtime probe observed a GET request to /view`

Limitations:
- No captured response headers confirming the header is absent
- No evidence that the application sets the header globally via middleware or server configuration

### 47. Improper validation of webhook destination URL

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint validates the target_url by only allowing values that contain the string "mock-external" and rejects all others with a 400 error. This logic does not enforce that the destination matches an approved internal host; instead it restricts to a mock external host, which may permit unintended destinations if the check is bypassed or misused. The runtime probe observed a successful 200 response for a POST request, indicating the validation may not be effective in practice.

**Impact:** An attacker could potentially supply a malicious webhook URL that bypasses the intended restriction, leading to SSRF or data exfiltration via the webhook mechanism.

**Remediation:** Replace the string containment check with an explicit allow‑list validation that compares the target_url against the exact approved internal host (e.g., using URL parsing and host comparison). Ensure the check is performed before any database insertion.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- <code>Source line 296‑298: target_url is extracted and checked with `if &quot;mock-external&quot; not in target_url: raise HTTPException(400, ...)`</code>
- `Runtime probe fact: POST to /webhooks returned status 200 despite expected 400/422`

Limitations:
- No concrete evidence that a malicious external URL (outside the mock host) is accepted and processed successfully; the probe only shows a 200 response but does not reveal the URL used. Additional testing with a non‑mock URL is needed to confirm exploitation.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds a CORS middleware with `allow_origins=["*"]`, which permits any website to make cross‑origin requests to the API. The supplied source shows the configuration but does not provide evidence of additional safeguards (e.g., authentication, request validation) that might mitigate the risk.

**Impact:** An attacker can embed malicious scripts on a victim site that interact with the API, potentially leading to credential leakage, data exfiltration, or CSRF‑style attacks if the API relies on cookies or other automatic credentials.

**Remediation:** Restrict `allow_origins` to a whitelist of trusted domains, enable `allow_credentials` only for those origins, and consider using more granular `allow_methods` and `allow_headers`. Review the API’s authentication and authorization mechanisms to ensure they are not bypassed by cross‑origin requests.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- <code>api/app.py: line 26 – `allow_origins=[&quot;*&quot;]`</code>

Limitations:
- No runtime probe or additional scanner evidence confirming exploitation. Lack of context about whether the API is intended for public use or protected by authentication, which could mitigate the impact.

### 49. Log Injection

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs the supplied username and the application secret without sanitization: `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`. This creates a potential log injection or information disclosure issue because attacker‑controlled data is written directly to logs and the secret value is exposed.

**Impact:** An attacker could inject malicious content into log files, potentially corrupting log parsing or obscuring malicious activity. Additionally, the application secret is written to logs, which may be accessible to unauthorized parties, leading to credential compromise.

**Remediation:** Avoid logging sensitive values such as secrets. Sanitize or omit user‑controlled data from log messages, e.g., log only a hashed identifier or omit the secret entirely. Use structured logging with proper escaping if logging user input is required.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- <code>Source line 137 logs `username` and `APP_SECRET` directly without sanitization.</code>

Limitations:
- No runtime probe demonstrates that the logged secret is actually exposed to an attacker, and no evidence of a guard or sanitization mechanism elsewhere in the code base. Independent scanner confirmation of exploitability is absent.

### 50. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter supplied by the user and directly passes it to `RedirectResponse` without any validation or allow‑list check. This creates an open redirect vulnerability, allowing an attacker to craft URLs that redirect victims to arbitrary external sites.

**Impact:** An attacker can use the open redirect to facilitate phishing attacks, drive‑by downloads, or bypass security controls that rely on trusted redirects, potentially leading to credential theft or malware infection.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a safe redirect mechanism (e.g., a confirmation page).
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source excerpt shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse:` followed by `return RedirectResponse(next, status_code=302)` with no validation.</code>

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the provided URL by ensuring it starts with a single '/' and rejects any scheme, network location, or double-slash prefix, raising an HTTPException for invalid inputs. This prevents open redirects to external domains.

**Impact:** No impact; the redirect is limited to local paths only.

**Remediation:** No remediation needed as the code already enforces safe local redirects.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `The source code checks that the 'next' parameter starts with '/' and not '//' and that urlsplit(next) yields no scheme or netloc, raising HTTPException(400) otherwise.`

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not include a HEALTHCHECK instruction, which is a recommended best practice to allow Docker to monitor container health. However, the supplied evidence does not demonstrate that the absence of a health check leads to a concrete security impact or operational failure in this specific deployment.

**Impact:** Potentially reduced observability of container health, which could delay detection of failures but does not directly constitute a security vulnerability.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- No runtime_probe_facts or operational logs showing that the lack of a health check caused a failure or security issue. No evidence that the container is monitored by external systems that would be impacted.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a health check is a best practice for container reliability, its absence does not constitute a security vulnerability. The finding is a configuration recommendation rather than evidence of exploitable behavior.

**Impact:** None – the container will run, but orchestration systems cannot automatically detect unhealthy instances.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile for the worker service does not include a HEALTHCHECK instruction. While this is not directly exploitable code, the absence of a health check can lead to undetected container failures and reduced operational reliability.

**Impact:** Containers that become unhealthy may continue running without detection, potentially causing service outages or degraded performance.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the health of the worker process, e.g., using curl or a custom script, and configure appropriate retry and timeout settings.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- No runtime probe or operational data demonstrating that the lack of a health check leads to actual failures; no evidence of impact on service availability.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project declares a dependency on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53539 (Denial of Service). The scanner flagged this as a high‑severity issue. However, the supplied repository data does not show whether the vulnerable code path is actually exercised by the application (e.g., whether FastAPI endpoints accept multipart/form‑urlencoded bodies that would trigger the flaw). Without evidence of usage, the vulnerability remains plausible but not definitively present in the running service.

**Impact:** If the application processes multipart/form‑urlencoded requests using the vulnerable python-multipart version, an attacker could craft a malicious payload that triggers excessive resource consumption, leading to denial‑of‑service conditions.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53539. Verify that the updated version does not introduce breaking changes in request handling.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency declaration in requirements.txt includes python-multipart==0.0.20`
- `Scanner report cites CVE‑2026‑53539 affecting python-multipart 0.0.20`
- `Severity marked as high by the scanner`

Limitations:
- No code evidence showing that the application imports or invokes python-multipart functionality
- No runtime probe confirming that multipart/form‑urlencoded bodies are processed

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The requirements file pins python-multipart at version 0.0.20, which is known to contain CVE-2026-42561 that can cause a denial‑of‑service when processing multipart requests with many part headers. The scanner identified this vulnerable version, but no code evidence was provided showing that the application actually imports or uses python-multipart, nor is there runtime proof that the vulnerable code path is reachable.

**Impact:** If an attacker can send a crafted multipart request to the service, the vulnerable library could consume excessive resources and cause the application to become unresponsive, leading to a denial‑of‑service condition.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, which contains the fix for CVE‑2026‑42561. Update the requirements file and redeploy the application.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- No evidence that python-multipart is imported or used in the application code.
- No runtime probe showing the vulnerable multipart handling path is exercised.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **high**

**Explanation:** The finding is based solely on the presence of python-multipart version 0.0.20, which is known to have CVE-2026-53538. No code or runtime evidence is provided that the vulnerable parser is actually invoked by the application, nor is there any indication that the vulnerable code path is reachable in the deployed environment.

**Impact:** If the vulnerable version is exercised, an attacker could craft multipart/form-data requests that cause the parser to leak internal data, potentially leading to information disclosure.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency list shows python-multipart==0.0.20 (source_excerpt).`
- `Scanner report cites CVE-2026-53538 affecting python-multipart 0.0.20.`

Limitations:
- No runtime probe or code usage evidence demonstrating that the vulnerable multipart parser is invoked.
- No trace of form‑data handling in the application code to confirm exposure.
- Absence of guard checks or mitigations in the supplied context cannot be verified.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE‑2026‑40347 (Denial of Service). The scanner flagged this dependency as vulnerable and notes that the issue is fixed in 0.0.26. No runtime probe or additional guard checks are provided to confirm whether the vulnerable code path is exercised or mitigated in the application.

**Impact:** An attacker could send specially crafted multipart/form-data requests that trigger excessive resource consumption, potentially leading to service disruption or denial of service.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, and verify that the updated version resolves the CVE. Re‑run dependency scans after the upgrade to ensure no further vulnerable versions remain.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26 (scanner evidence).`
- `requirements.txt pins python-multipart==0.0.20.`

Limitations:
- No runtime probe confirming the vulnerable code path is reachable in the deployed application.
- No evidence that the application actually processes multipart/form-data requests in a way that would trigger the DoS condition.

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to an arbitrary file write via path traversal (CVE-2026-24486). The scanner identified this vulnerable dependency and notes that the issue is fixed in version 0.0.22. No code in the supplied repository demonstrates the vulnerable code path being exercised, nor is there runtime evidence that the vulnerable functionality is reachable in the deployed application.

**Impact:** If an attacker can trigger the vulnerable multipart handling code, they could craft a malicious request that writes files to arbitrary locations on the server’s filesystem, potentially leading to remote code execution, data corruption, or privilege escalation.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version is installed by checking the lock file or the installed package list.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22 (scanner evidence).`
- `requirements.txt lists python-multipart==0.0.20.`

Limitations:
- No runtime probe or code‑level evidence showing that the vulnerable multipart parsing code is actually invoked by the application.
- No guard or input validation checks are visible in the supplied source to confirm the vulnerability is mitigated.

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53537. The scanner identified this dependency mismatch, indicating a potential information disclosure issue. However, no runtime evidence or proof-of-concept is provided to demonstrate that the vulnerable code path is reachable in the deployed application.

**Impact:** An attacker could exploit the header parsing discrepancy to obtain unintended information from the server, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537. Verify the application builds and tests pass after the upgrade.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30 (scanner finding)`

Limitations:
- No runtime probe or exploit demonstration showing the vulnerable code path is exercised in the application.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The dependency python-multipart version 0.0.20 is known to contain CVE-2026-53540, which can cause the entire request body to be buffered in memory when a negative Content‑Length header is received. The supplied requirements.txt confirms the vulnerable version is used. No additional evidence (e.g., runtime probe demonstrating the behavior) is provided, and no guard or mitigation is visible in the supplied context.

**Impact:** An attacker can cause excessive memory consumption on the server, potentially leading to denial‑of‑service conditions.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which resolves CVE‑2026‑53540.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No runtime probe confirming the negative Content‑Length handling behavior.
- No evidence of a guard or input validation that would mitigate the issue in the application code.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code builds a URL by concatenating a constant BASE with a variable path and then passes it to urllib.request.urlopen. If the path argument can be influenced by an attacker, they could craft a URL with a scheme such as "file://" to read arbitrary files or otherwise trigger unintended requests. The snippet does not show any validation or sanitisation of the path parameter, nor any restriction on allowed schemes.

**Impact:** An attacker who can control the `path` argument may cause the application to request arbitrary resources, potentially leading to information disclosure (e.g., reading local files via file://) or SSRF-like behavior.

**Remediation:** Validate and sanitise the `path` argument before constructing the URL. Restrict allowed schemes to http/https, reject or safely encode any user‑controlled input, or switch to a higher‑level HTTP client like the `requests` library that does not support file URLs by default.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- <code>Source excerpt shows dynamic construction of the request URL using `BASE + path` and passing it directly to `urllib.request.urlopen` without visible validation.</code>

Limitations:
- No evidence is provided that the `path` argument is attacker‑controlled; the surrounding code that supplies `path` is not shown. No runtime probe demonstrates an actual exploit (e.g., a request to a file:// URL succeeding). No guard or validation logic is present in the supplied snippet, but it may exist elsewhere in the codebase.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code builds a urllib request using a URL taken directly from the job payload (payload\["target_url"\]). No validation or sanitization of this value is shown, which could allow an attacker to supply a malicious URL (e.g., a file:// scheme) and cause the worker to read arbitrary files or perform unintended network requests. However, the supplied excerpt does not demonstrate that the value is attacker‑controlled nor that any guard exists elsewhere in the codebase.

**Impact:** If an attacker can control the target_url, they may trigger server‑side request forgery (SSRF) or read local files via file:// URLs, potentially leading to data disclosure or further compromise.

**Remediation:** Validate and sanitize the target_url before using it with urllib. Restrict allowed schemes to http/https, enforce a whitelist of domains, or switch to a higher‑level library like requests with built‑in safety checks. Consider adding explicit input validation and error handling.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `source_excerpt: lines 18‑23 show payload["target_url"] passed directly to urllib.request.Request without validation`

Limitations:
- Missing evidence that payload\["target_url"\] can be supplied by an untrusted user
- No view of surrounding code to confirm whether validation occurs elsewhere
- No runtime probe demonstrating an actual SSRF or file read

### 64. Missing authorization on file read endpoint (CWE-284)

- Issue group: `ai-48e38dce185c919c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /files endpoint is defined without any authentication or authorization checks in the provided source excerpt. The code resolves a file path under a public directory and returns its contents directly. No decorator or guard is visible that would restrict access to authorized users. A dynamic probe attempted an unauthenticated request and received HTTP 422, which does not demonstrate proper denial (e.g., 401/403) and does not confirm that the file content was returned, leaving the authorization status uncertain.

**Impact:** An attacker could potentially retrieve arbitrary files from the server's public directory, leading to information disclosure of sensitive data if the directory contains such files.

**Remediation:** Add authentication and authorization checks to the endpoint, e.g., require a logged‑in user or specific role before resolving and returning the file. Consider using a dependency that enforces auth for all routes or applying a @requires_auth decorator to this handler.
Evidence:
- Source IDs: `ai-48e38dce185c919c`
- `210: @router.get("/files")`
- <code>211: def file_read(name: str) -&gt; Response:</code>
- `212: file = (FILES / "public" / name).resolve()`
- `213: if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214: raise HTTPException(404, "File not found")`
- `215: return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`
- `dynamic_penetration_agent: exploitation_confirmed — unauthenticated request to /files returned HTTP 422 (no denial status)`

Limitations:
- No evidence that a global authentication dependency applies to this route.
- Probe did not retrieve file contents; it only observed a 422 response, which may be due to request validation rather than authorization.
- Absence of a scanner or higher‑severity independent confirmation prevents a confirmed_vulnerability verdict.

### 65. Potential IDOR on comment creation (CWE-639)

- Issue group: `ai-0cff1c5b0a98f32b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The endpoint creates a comment using the user ID returned by the identity() function without any additional verification that the token is authentic, unexpired, or that the caller is authorized to act as that user. The code shows the entry point and the sensitive SQL insert, but the implementation of identity() is not provided, so it is unclear whether proper authentication checks occur. No guard or role check is visible in the supplied context.

**Impact:** If the identity function can be bypassed or a token can be forged, an attacker could create comments on behalf of other users, leading to unauthorized content creation and potential abuse of user reputation or spam.

**Remediation:** Ensure that the identity() function validates token signatures, expiration, and audience. Add explicit authorization checks to confirm the caller is allowed to post comments as the identified user, and consider role‑based access control. Validate the token before using its user ID in the INSERT statement.
Evidence:
- Source IDs: `ai-0cff1c5b0a98f32b`
- `api/extra.py:161 – @router.post("/comments") defines the entry point`
- `api/extra.py:163 – user = identity(authorization) – token handling is opaque`
- `api/extra.py:166 – INSERT INTO comments(author_id,body) VALUES (%s,%s) – author_id taken directly from identity output`

Limitations:
- The implementation of identity() is not provided, so we cannot confirm whether it performs proper authentication and token validation
- No evidence of additional authorization or role checks in the surrounding code
- No scanner or runtime probe evidence of exploitation beyond a single unauthenticated request returning 200, which does not prove the vulnerability is exploitable

### 66. Missing authorization on verified file read endpoint (CWE-284)

- Issue group: `ai-357e82f73fc20848`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The route `@router.get("/files/verified")` serves file contents based solely on a user‑provided filename after a path‑traversal check. No authentication or role check is performed in the supplied code, and the dynamic probe shows an unauthenticated request did not receive a standard denial status (401/403/404) but returned HTTP 422, indicating the endpoint is reachable without explicit access control. However, the evidence does not confirm whether a global security middleware or external network restriction might enforce authorization, nor does the probe demonstrate successful retrieval of file data.

**Impact:** An attacker could potentially enumerate and read arbitrary files within the `public` directory without authentication, leading to disclosure of sensitive information or application logic.

**Remediation:** Add authentication and authorization checks before accessing the file, e.g., require a logged‑in user with appropriate permissions, or protect the route with a security middleware that enforces access control. Also validate that the filename parameter is supplied and authorized.
Evidence:
- Source IDs: `ai-357e82f73fc20848`
- `api/extra.py:218 – @router.get("/files/verified")`
- `api/extra.py:220 – root = (FILES / "public").resolve()`
- `api/extra.py:221 – file = (root / name).resolve()`
- `api/extra.py:222 – if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`
- `api/extra.py:224 – return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`
- `dynamic_penetration_agent: unauthenticated request to /files/verified returned HTTP 422 (no denial status)`

Limitations:
- No evidence that a global authentication/authorization middleware is applied to this route
- No proof that the endpoint actually returns file contents to an unauthenticated attacker (probe returned 422, not file data)
- Missing confirmation that external network controls restrict access

### 67. Potential missing admin authorization check in admin audit endpoint (CWE-284)

- Issue group: `ai-a1aee7bddc21a663`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint `/admin/audit` calls `require_admin(authorization)` before returning an authorized status. The implementation of `require_admin` is not provided, so it cannot be confirmed that the function properly verifies the caller’s admin role or enforces token freshness/revocation. Without evidence of a robust check, the endpoint may be reachable by non‑admin users.

**Impact:** If the admin check is ineffective, an attacker could invoke the `/admin/audit` endpoint and obtain privileged information or perform actions reserved for administrators, leading to confidentiality and integrity breaches.

**Remediation:** Implement or verify that `require_admin` performs a strict role check against a trusted authentication source, validates token integrity, expiration, and revocation, and returns an error for non‑admin callers. Add explicit unit tests and runtime checks to ensure the guard cannot be bypassed.
Evidence:
- Source IDs: `ai-a1aee7bddc21a663`
- `api/extra.py:204 – @router.get("/admin/audit") defines the entry point`
- `api/extra.py:206 – require_admin(authorization) is called but its definition is missing`
- `api/extra.py:207 – return {"status": "authorized"} reveals the sensitive operation`

Limitations:
- Missing source code for `require_admin` prevents confirmation that admin verification is performed
- No independent scanner or runtime probe evidence demonstrating successful unauthorized access

### 68. Missing ownership verification on order payment (CWE-639)

- Issue group: `ai-a815919b2f2f9d7a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `pay_order` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the order before updating its status to `paid`. The code fetches the order record and proceeds directly to the update without comparing `order["owner_id"]` (or similar) to the principal’s identifier. This creates an authorization bypass where any authenticated user (or potentially an unauthenticated request, depending on `principal` implementation) can pay any order by supplying its ID.

**Impact:** An attacker could pay, modify, or trigger downstream effects (e.g., invoice generation) for orders they do not own, leading to financial fraud, unauthorized transactions, and potential denial of service for legitimate owners.

**Remediation:** Add an ownership check after retrieving the order: compare the order’s owner identifier with the authenticated principal’s user ID (or role) and reject the request with a 403 error if they do not match. Also ensure that privileged roles (e.g., admin) are explicitly authorized if they are allowed to perform this action.
Evidence:
- Source IDs: `ai-a815919b2f2f9d7a`
- <code>api/app.py:242 – entry point definition for `pay_order`</code>
- `api/app.py:245 – order fetched without ownership check`
- <code>api/app.py:249 – order status updated to `paid` without verification</code>

Limitations:
- No independent scanner or runtime probe evidence confirming the vulnerability is exploitable.
- The behavior of `principal(authorization)` is not shown; it may embed role checks that could mitigate the issue, but this is not evident in the supplied code.

### 69. Missing validation of coupon discount limits (CWE-770)

- Issue group: `ai-abc2a7ff34f5274c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The apply_coupon endpoint reads a discount value directly from the request body (body.discount) and uses it in an UPDATE statement without any range validation. The code snippet shows the value is taken as‑is and stored in the orders table, which could allow a client to set an excessively high discount (e.g., 100 % or more). No guard or business‑rule check is visible in the supplied context.

**Impact:** An attacker could obtain free or heavily discounted orders by submitting a coupon payload with a large discount value, leading to revenue loss and potential abuse of promotional mechanisms.

**Remediation:** Add explicit validation that the discount percent is within an acceptable range (e.g., 0‑100) and that it does not exceed the percentage defined by the coupon. Reject or clamp values outside the range and log the attempt. Consider making the discount immutable from the client side and enforce the coupon’s configured percent server‑side.
Evidence:
- Source IDs: `ai-abc2a7ff34f5274c`
- `api/app.py:235 – percent = body.discount if body.discount is not None else (coupon["percent"] if coupon else 0)`
- `api/app.py:236 – row = conn.execute("UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (percent, order_id)).fetchone()`

Limitations:
- No independent scanner or runtime probe confirming that an over‑large discount can be persisted.
- No evidence of a guard elsewhere in the codebase (e.g., middleware, database constraints) that would prevent excessive discounts.
- No test or runtime observation showing the effect of sending a high discount value.

### 70. Insecure Direct Object Reference (IDOR) on order cancellation

- Issue group: `ai-37a36c685565c325`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The cancel_order endpoint authenticates the request via `principal(authorization)` but does not contain any check that the authenticated user owns the order identified by `order_id`. The code directly updates the order status based on the supplied identifier, which could allow an attacker to cancel orders they do not own.

**Impact:** An attacker who can supply arbitrary order IDs could cancel any user's order, leading to unauthorized state changes, potential financial loss, and loss of trust in the system.

**Remediation:** Add an ownership verification step after authentication. Retrieve the order's owner from the database and compare it to the authenticated principal's user ID. Only proceed with the cancellation if they match; otherwise return an appropriate error (e.g., 403 Forbidden).
Evidence:
- Source IDs: `ai-37a36c685565c325`
- `api/app.py:259 defines the cancel_order endpoint with authentication via principal(authorization).`
- `api/app.py:262 performs an UPDATE on orders without any ownership check.`
- `No code present that compares the authenticated principal to the order's owner.`

Limitations:
- Missing evidence of how `principal` represents the user (e.g., user ID).
- No database schema or constraints shown that might enforce ownership automatically.
- No runtime probe confirming that an unauthorized user can successfully cancel another user's order.

### 71. Insecure Direct Object Reference (IDOR) on order retrieval

- Issue group: `ai-3758edde98f7e9e2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The get_order endpoint authenticates the request via the principal function but does not perform any ownership check before returning the order record. An authenticated user can supply an arbitrary order_id and retrieve the corresponding row, potentially exposing other users' orders. The code snippet shows the query execution without verifying that the order belongs to the authenticated principal.

**Impact:** Unauthorized disclosure of order details, leading to privacy violations and potential abuse of sensitive customer information.

**Remediation:** After authenticating the request, retrieve the user identifier from the principal and verify that the order's user_id matches this identifier before returning the record. Return a 403 or 404 if the ownership check fails.
Evidence:
- Source IDs: `ai-3758edde98f7e9e2`
- <code>api/app.py:221 – def get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `api/app.py:222 – principal(authorization) (authentication only)`
- `api/app.py:224 – row = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone() (no ownership validation)`

Limitations:
- No evidence that the orders table includes a user_id column for ownership checks.
- No visible middleware or global guard that might enforce ownership beyond this function.
- No scanner or runtime probe confirming that an unauthorized request can retrieve another user's order.

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
- `merged-4c6d36222f8ebf7f1f68`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-15dd977d52312c30635a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d58491aad5be35b48233`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c5b44871f1955b338344`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-3913d8f00a297cfbf214`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-56ecc860a2c48330a29a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-69b75a0aa3f8fc9fb800`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-efce9419c25ced2d8892`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4a2311054cdc2bfe890d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a9a9a0b97f19f8bf52ae`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-6e468e09eab3ca889e3d`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-81ff94e895c53dbc2029`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d716d5afb61da294d286`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f5fff899f9294177dc70`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-916563c278b3e6b62930`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-54b1ddb055358b3579a2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-b7e0b624f8cddd0a9e8c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d0789be823f0fd7fa381`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-7ed325c02dd6cf8227d2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-ccc894903304aa8847bd`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-1bcb1da144dffdcf3fd8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-051697f9b8567d596874`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-3503f2dec888990b31f2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-48e38dce185c919c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-0cff1c5b0a98f32b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-357e82f73fc20848`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-a1aee7bddc21a663`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-a815919b2f2f9d7a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-abc2a7ff34f5274c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-37a36c685565c325`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-3758edde98f7e9e2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **89**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **39**; scanner overlaps: **1**; AI overlaps: **1**; new candidates: **22**; uncertain overlaps: **4**; needs more evidence: **11**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-9e0c4cc6cdfc1570`: needs_more_evidence
- `ai-4af78a4240e9e89d`: needs_more_evidence
- `ai-fdb73441313bbd62`: needs_more_evidence
- `ai-00b2526c34788f70`: needs_more_evidence
- `ai-abc2a7ff34f5274c`: uncertain_overlap
- `ai-8fa28125b04eb573`: needs_more_evidence
- `ai-fd71518f0577d542`: uncertain_overlap
- `ai-956884683be69033`: needs_more_evidence
- `ai-68813298dd460aa9`: needs_more_evidence
- `ai-287c05c6ac29cece`: needs_more_evidence
- `ai-fa368a014cee9da8`: needs_more_evidence
- `ai-996f0a23078bba52`: needs_more_evidence
- `ai-8a0cbd8d58a066f3`: needs_more_evidence
- `ai-18095c8e393238b1`: uncertain_overlap
- `ai-861e82ee574e8e6d`: uncertain_overlap

## Pending Security Reviews

- `ai-3e7bb5628df0321c`
- `ai-20c43f5be4958e67`
- `ai-6a259d8eb9f37894`
- `ai-fd71518f0577d542`
- `ai-6564d370b52ece9f`
- `ai-f81369b539293f50`
- `ai-6c75550620dc33f8`
- `ai-ad40fdf26de7ccce`
- `ai-b85430abb087460a`
- `ai-6e6d20cb31a8d0de`
- `ai-8980cb77b67b1fa8`
- `ai-58db1e8887b2fb7c`
- `ai-18095c8e393238b1`
- `ai-a0f6a99211967bdc`
- `ai-861e82ee574e8e6d`
- `ai-8e9b4463612bf8db`
- `ai-7ab23a266d8c8a55`
- `ai-9f67cfc96698db68`

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

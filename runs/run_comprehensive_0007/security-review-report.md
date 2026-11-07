# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-07T12:14:09.858275+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **70/70**; model calls: **11**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.
- AI Discovery warning: 4 duplicate AI candidate(s) were merged into 4 stronger one(s): ai-827cbbfd5e460c8b &lt;- ai-d40782fbc8de084b; ai-db9083db72a7fa38 &lt;- ai-8ecee9f0a4a5c273; ai-ee09ae47f04438e1 &lt;- ai-a374e4f904033a5e; ai-1010035e8f9ad623 &lt;- ai-4b7439452be1c659

The agent reviewed **83** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **83**; reviewed: **83**; pending: **0**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **51**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **completed**; pages visited: **1**.
- ZAP: **completed**; engine: <code>zap-passive</code>; alerts: **14**.
- Account and business workflows: **completed**; executed: **40**; contract violations: **20**.
- These observations do not prove complete vulnerability coverage or exploitation.

## Scanner Execution

- <code>trivy</code>: <code>completed</code>
- <code>gitleaks</code>: <code>completed</code>
- <code>trivy</code>: <code>skipped</code>
- <code>semgrep-ce</code>: <code>completed</code>
- <code>codeql-cli</code>: <code>completed</code>
- <code>trivy</code>: <code>completed</code>

## Scanner and DAST Observations (Pre-Review)

**63** merged observation record(s): **37** DAST-related and **26** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

1. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:119</code>; severity: **high**; confidence: high; risk: 74/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-18f1abe978f9fdaad8e6</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-5e7b731c6445970909c9</code>.
2. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:144</code>; severity: **high**; confidence: high; risk: 74/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-f60fee7d82fbca512208</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-7605384fbc7aee3bcd8a</code>.
3. **Reflected server-side cross-site scripting** — scanner from codeql-cli; location: <code>api/extra.py:145</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-ea527a7d7441e2b11700</code>; rule(s): <code>py/reflective-xss</code>; source evidence: <code>finding-a8c8d9148f5e4ee9d3fd</code>.
4. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:212</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-f4eaf141df049c63545d</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-480ccba498d117b3450e</code>.
5. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:213</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-83d97da4516adf20e20f</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-26bd24fa5794fd60d9e9</code>.
6. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:215</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-b527b3ed30e57aac5ec5</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-aa95c189edc76290622b</code>.
7. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:221</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-24d14609e3893220ea16</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-ac18ed89b1a00ae2c8bf</code>.
8. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:222</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-794dcb4921076779cef0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-2f756e27fddc389636a8</code>.
9. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:224</code>; severity: **high**; confidence: high; risk: 70/100 (high); disposition: <code>deep_review</code>.
   - Record: <code>merged-b3c734b4cef8dd70fce0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-603f6a08a677ccbb0c42</code>.
10. **python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: 69/100 (high); disposition: <code>standard_report</code>.
    - Record: <code>merged-8ce42d9c8b52a95b109d</code>; rule(s): <code>CVE-2026-24486</code>; source evidence: <code>finding-555e67f97039217aa153</code>.
11. **python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: 61/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-051697f9b8567d596874</code>; rule(s): <code>CVE-2026-53539</code>; source evidence: <code>finding-2626e4bc8eef02153f32</code>.
12. **python-multipart: python-multipart: Denial of Service via excessive multipart part headers** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: 61/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-3503f2dec888990b31f2</code>; rule(s): <code>CVE-2026-42561</code>; source evidence: <code>finding-d5a70d23b67803614b8f</code>.
13. **Clear-text logging of sensitive information** — scanner from codeql-cli, semgrep-ce; location: <code>api/app.py:137</code>; severity: **high**; confidence: high; risk: 60/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-3202e1e1074cfd44b9bf</code>; rule(s): <code>py/clear-text-logging-sensitive-data, python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure</code>; source evidence: <code>finding-cfe66151dbff24377948</code>, <code>finding-2e982654735c1187197b</code>.
14. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: 54/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
15. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-15dd977d52312c30635a</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-9285679b6f926a0d1c0a44d2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_jobs&quot;}</code>.
16. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-d58491aad5be35b48233</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-2a9764dfddf0c017eff71be0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;stale_role&quot;}</code>.
17. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-c5b44871f1955b338344</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-946a5bf2b3aeb375da4de266</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_users&quot;}</code>.
18. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-efce9419c25ced2d8892</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-18719503314710a3e71c38c9</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;reset_replay&quot;}</code>.
19. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f5fff899f9294177dc70</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-e929732019082549893b68d0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [401, 403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;debug_access&quot;}</code>.
20. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-b98074828fe298997980</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-267f3aec1133283c14739667</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 401, 403], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;unsigned_hook&quot;}</code>.
21. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-54b1ddb055358b3579a2</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-bc7d0d0a77b4619ba22d0b25</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;invoice_owner&quot;}</code>.
22. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-b7e0b624f8cddd0a9e8c</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-d47d5c27b4e143571ef5f9e3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;worker_role&quot;}</code>.
23. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-218d6fc43fe64432894a</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-19ac26bfd96baf1f15d8f0f0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200, 201], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;price_catalog&quot;}</code>.
24. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-5a7c783c30e11426af42</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-97a2403badc5307e87389e70</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_initial_state&quot;}</code>.
25. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-767d54ff7a729b156819</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-289a562cf581d69d3a6c7d63</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;negative_price&quot;}</code>.
26. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-d0789be823f0fd7fa381</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-e6fad5bfce7f957806254d9e</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;owner_assignment&quot;}</code>.
27. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-0f6fe31b81367808748c</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-22221f4054533f30bbaf73ba</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;nested_note&quot;}</code>.
28. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-fe4ca713f11faf9b96d6</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-ed0dc0a1678724040424e4a2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_owner&quot;}</code>.
29. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-7ed325c02dd6cf8227d2</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-3143beb445281415043c6a2c</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;coupon_bounds&quot;}</code>.
30. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-ccc894903304aa8847bd</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-128e83b73f127060c05a7721</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;paid_cancel&quot;}</code>.
31. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-1bcb1da144dffdcf3fd8</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-12d8f92bbda0b009c94e4b17</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;payment_replay&quot;}</code>.
32. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-18063ba27bc289f53c8a</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-3982bc4eac58ce8d5c2fe5ad</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;profile_owner&quot;}</code>.
33. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8cdc677a9810b317840f</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-79fa84ef4d90b0b35afc2e33</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;webhook_destination&quot;}</code>.
34. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
35. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
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
52. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-4c6d36222f8ebf7f1f68</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-06b259c78fa19fa5d06a773c</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
53. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-0bcbb317cfb96e7d5505</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-a39e9179918dd476f1e5dab4</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
54. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-3913d8f00a297cfbf214</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ae2cae22d3790709c188f8d7</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
55. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-a6e788cfc5d9d1297feb</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-2f9dcf012b09704cb4324d5b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
56. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-d716d5afb61da294d286</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-678ec39654e40601b76ef8f6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
57. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-cad468186f9fd0b4e99b</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-c9199ae9fe5021a5d3738696</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
58. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
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

### 1. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `legacy_login` constructs an SQL query by directly interpolating `body.username` and `body.password` into the query string using an f‑string. This creates a classic SQL injection vector because the input is not sanitized or parameterized before being sent to the database. No defensive checks (e.g., input validation, prepared statements) are visible in the provided excerpt.

**Impact:** An attacker could supply specially crafted username or password values to manipulate the SQL query, potentially retrieving unauthorized data, bypassing authentication, or executing arbitrary SQL commands on the database.

**Remediation:** Replace the string interpolation with a parameterized query using the database driver’s placeholder syntax (e.g., `SELECT ... WHERE username=? AND password=?`) and pass the user inputs as parameters. Additionally, consider hashing passwords and using constant‑time comparison for authentication.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `api/extra.py:117-119 – query = f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"`
- `api/extra.py:119 – row = conn.execute(query).fetchone()`

Limitations:
- No runtime probe evidence confirming that injection is exploitable in the running application.
- No independent scanner of medium or higher severity beyond the merged finding.
- No visible input validation or use of prepared statements in the supplied code context.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` guard ensures the resolved path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent existence check further validates the target. Thus the code includes the necessary safety checks, and the scanner’s finding is a false positive.

**Impact:** If the guard were missing, an attacker could read arbitrary files on the server. However, the guard is present, so no impact is present.

**Remediation:** No remediation needed; the existing `is_relative_to` check correctly mitigates path traversal. Ensure this pattern is consistently used for any file‑system access based on user input.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑224 show the guard `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404)`</code>

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint validates the user‑provided filename by constructing an absolute path (root / name) and then calling `is_relative_to(root)`. This check ensures the resulting path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent `is_file()` check also guarantees the target exists before it is read. Because the code contains explicit safeguards, the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server. However, the present guard mitigates that risk, so no impact is present.

**Remediation:** No remediation needed; the existing relative‑path check is sufficient. Maintain this validation if the code is modified.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>source_excerpt lines 218‑224 show the use of `is_relative_to(root)` and `is_file()` checks preventing directory traversal.</code>

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory and then verifies that the resulting path is still within that base using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server. However, the existing checks mitigate this risk.

**Remediation:** No remediation needed; the current validation is appropriate. Ensure that `FILES` is a trusted absolute path and that the Python version supports `Path.is_relative_to`.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>source_excerpt lines 211‑214 show the resolve and `is_relative_to` checks</code>
- `source_symbol confirms the same logic`

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the data is not uncontrolled in the path expression.

**Impact:** No path traversal vulnerability; the file read is confined to the intended public directory.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>The code uses `root = (FILES / &quot;public&quot;).resolve()` and `file = (root / name).resolve()`.</code>
- <code>It then validates `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`.</code>
- `Only after these checks does it read the file content.`

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function constructs the file path using the user‑provided `name` but immediately resolves it and checks `file.is_relative_to(FILES.resolve())`. This guard ensures the resolved path remains within the intended `FILES/public` directory, preventing directory‑traversal attacks. The subsequent `file.is_file()` check also ensures the target exists before reading. Therefore the code safely validates the user input before accessing the filesystem.

**Impact:** No path‑traversal vulnerability; an attacker cannot read arbitrary files outside the designated directory.

**Remediation:** No remediation needed for this specific issue; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>source excerpt shows `file = (FILES / &quot;public&quot; / name).resolve()`</code>
- <code>`if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 7. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any escaping or sanitisation. The returned string <code>&quot;&lt;h1&gt;Results for {q}&lt;/h1&gt;&quot; + ...</code> is sent to the client as raw HTML, allowing an attacker to inject arbitrary markup or script tags that will be rendered by the browser. No input validation or output encoding is visible in the supplied excerpt, and no guard (e.g., templating engine auto‑escaping, explicit HTML sanitisation, CSP headers) is present in the provided context.

**Impact:** An attacker can craft a URL such as <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> that, when visited, executes arbitrary JavaScript in the victim’s browser. This can lead to session hijacking, credential theft, or other malicious actions against users of the application.

**Remediation:** - Use a templating engine that automatically escapes variables, or explicitly HTML‑escape `q` before embedding it in the response.
- Consider returning JSON data and letting the client render it safely.
- Apply a Content‑Security‑Policy (CSP) header that restricts script execution.
- Validate and sanitise query parameters on input.
- Review other endpoints for similar patterns.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- <code>Source excerpt shows `q` interpolated directly into HTML response at line 145 without escaping.</code>
- `Scanner flagged this as a reflected XSS finding.`

Limitations:
- No runtime probe evidence confirming that injected payloads are executed in a browser context.
No evidence of existing sanitisation or escaping mechanisms elsewhere in the codebase.
No guard checks (e.g., CSP headers, framework auto‑escaping) are visible in the supplied context.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks both that the resulting path is within the allowed directory (is_relative_to(FILES.resolve())) and that it points to an existing file (is_file()). These checks prevent directory traversal and arbitrary file reads, mitigating the reported issue.

**Impact:** If the checks were absent, an attacker could read arbitrary files on the server. However, the code includes proper validation, so the risk is mitigated.

**Remediation:** No remediation needed for this specific finding as the code already implements the necessary path validation.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Source excerpt shows the use of Path.resolve() followed by is_relative_to(FILES.resolve()) and is_file() checks, which together block path traversal.`

### 9. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` concatenates the query parameter `q` directly into an SQL statement using an f‑string. This creates a path where attacker‑controlled input reaches the database without any apparent sanitization or use of parameterized queries. No guard (e.g., input validation, escaping, or prepared statements) is visible in the supplied snippet.

**Impact:** An attacker could inject arbitrary SQL fragments via the `q` parameter, potentially retrieving, modifying, or deleting data from the `products` table or executing other database commands.

**Remediation:** Refactor the query to use parameterized statements (e.g., `conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",))`) or employ an ORM that handles escaping. Additionally, validate or whitelist allowed characters for `q` before using it in the query.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt shows `conn.execute(f&quot;SELECT name FROM products WHERE name ILIKE &#x27;%{q}%&#x27;&quot; )` with `q` taken directly from the request query string.</code>

Limitations:
- No runtime_probe_facts confirming that injection is exploitable in the running application. No evidence of existing input validation or escaping elsewhere in the codebase. Independent scanner corroboration beyond the merged finding is absent.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-4c6d36222f8ebf7f1f68`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner observed that the HTTP response for the root path ("/") does not include the X-Content-Type-Options header, which can allow MIME type sniffing attacks. The provided source excerpt shows only the FastAPI route definitions and does not reveal any middleware or response‑header configuration that might add this header.

**Impact:** An attacker could trick a browser into interpreting non‑HTML content as HTML/JavaScript, potentially enabling cross‑site scripting or content injection attacks.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a middleware that sets this header or using Starlette's SecurityHeaders middleware.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Scanner runtime probe (zap.10021) reported missing X-Content-Type-Options header on GET /`

Limitations:
- No direct view of the actual HTTP response headers from the running application; need server‑side configuration or runtime capture to confirm the header is absent.

### 11. Job listing requires admin role

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/jobs calls a function principal(authorization) before accessing the database, but the provided source excerpt does not show any role verification or access control logic. A runtime probe observed that a GET request to this endpoint returned HTTP 200 instead of the expected 403/404, indicating that the authorization check may be ineffective or missing. However, without the implementation of principal or additional guard checks, the vulnerability cannot be confirmed.

**Impact:** An attacker could retrieve the full list of jobs, potentially exposing sensitive internal data or enabling further exploitation.

**Remediation:** Implement proper role-based access control in the principal function or add explicit admin-role checks before returning job data. Ensure unauthorized requests receive a 403 response.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs endpoint calling principal without visible role checks (lines 285-287).`
- `Runtime probe fact: GET /admin/jobs returned status 200, while expected statuses were 403 or 404 (web-runtime rule workflow.admin_jobs.2).`

Limitations:
- Missing implementation details of the principal function to verify whether it enforces admin role checks.
- No additional guard checks or logs confirming access control enforcement.

### 12. A demoted administrator must lose administrative access

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/token-report contains a role check that raises HTTP 403 when the token role is not "admin". However, a runtime probe observed a successful GET request returning HTTP 200, indicating the check did not block access in practice. The source code alone shows the guard, but the observed behavior suggests it is ineffective or bypassed.

**Impact:** A user whose admin role has been revoked could still access an administrative endpoint, potentially exposing sensitive token information or privileged actions.

**Remediation:** Investigate why the role check is not enforced at runtime (e.g., token parsing, header handling, or middleware). Ensure the principal function correctly extracts the role and that the guard executes before returning data. Add comprehensive tests for role enforcement.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check and HTTPException raise on non‑admin (lines 661‑664).`
- `Runtime probe fact from scanner "web-runtime" reports status 200 for GET /admin/token-report where a 403 was expected.`

Limitations:
- The exact reason the guard fails at runtime is not shown (e.g., token extraction bug, middleware override). Additional logs or code around the principal function are needed to confirm the root cause.

### 13. User listing requires admin role

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/admin/users` calls `principal(authorization)` but does not verify that the authenticated principal has an admin role before querying and returning all user records, including sensitive fields such as SSN. A runtime probe confirms that an unauthenticated GET request receives a 200 response instead of the expected 403/404, demonstrating that the access control check is missing in practice.

**Impact:** Any attacker who can supply a request to `/admin/users` can retrieve the full list of users with personal data (id, username, email, role, SSN), leading to privacy violations and potential identity theft.

**Remediation:** Add an explicit role check after `principal(authorization)` to ensure the caller has the admin role, e.g., `if principal.role != "admin": raise HTTPException(status_code=403)`. Also consider limiting returned fields to only non‑sensitive data or implementing pagination and audit logging.
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- <code>Source code shows `admin_users` endpoint calls `principal(authorization)` but lacks role verification before database query.</code>
- <code>Runtime probe fact: GET `/admin/users` returned status 200 instead of 403/404, indicating no access control enforcement.</code>

### 14. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a cookie (lab_session) without specifying the HttpOnly attribute, which can allow client‑side scripts to access the cookie. The runtime probe confirms the endpoint is reachable via POST but does not capture the Set‑Cookie header, so the missing HttpOnly flag is not directly observed.

**Impact:** An attacker who can inject JavaScript into the page could read the session cookie and potentially hijack the user’s session.

**Remediation:** Set the HttpOnly flag when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)`. Consider also adding Secure and SameSite attributes as appropriate.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- <code>Source excerpt shows `response.set_cookie(&quot;lab_session&quot;, f&quot;session-{row[&#x27;id&#x27;]}&quot;)` without HttpOnly.</code>
- <code>Runtime probe fact confirms the `/auth/form-login` POST endpoint is reachable.</code>

Limitations:
- No captured response headers confirming the cookie lacks the HttpOnly attribute.
- No evidence that the application sets HttpOnly elsewhere or that a middleware adds it automatically.

### 15. X-Content-Type-Options Header Missing

- Issue group: `merged-3913d8f00a297cfbf214`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the response from /auth/form-login does not include the X-Content-Type-Options header. The provided source excerpt shows the endpoint implementation but does not set any security headers, and no configuration evidence is supplied that would add the header automatically.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may incorrectly sniff the MIME type of resources, potentially enabling content injection attacks such as drive‑by downloads or cross‑site scripting.

**Remediation:** Add the X-Content-Type-Options header (e.g., "nosniff") to the response for this endpoint, either by setting it in the route handler (response.headers\["X-Content-Type-Options"\] = "nosniff") or by configuring the web framework/middleware to include it globally.
Evidence:
- Source IDs: `merged-3913d8f00a297cfbf214`
- `Scanner runtime fact (zap.10021) indicates a POST request to /auth/form-login with no X-Content-Type-Options header observed.`

Limitations:
- No direct server response captured in the supplied data confirming the header is absent; the evidence relies on the scanner report. Additional runtime observation of the actual HTTP response headers is needed to confirm the omission.

### 16. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from the POST /auth/form-login endpoint does not include an anti-clickjacking header (e.g., X-Frame-Options or Content‑Security‑Policy frame‑ancestors). The provided source excerpt shows the endpoint implementation but does not contain any code that sets such a header on the response. No runtime probe fact confirming the absence of the header was supplied, only that a POST request was made. Therefore the finding is plausible but not definitively proven by the supplied evidence.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and trick users into submitting credentials, leading to credential theft or session fixation attacks.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP `frame-ancestors 'none'`. Ensure the header is set for all routes that render HTML content.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Scanner runtime fact (zap.10020) indicating a POST to /auth/form-login without header evidence`

Limitations:
- No captured HTTP response headers showing the header is missing; the scanner’s finding is not corroborated by runtime probe data. Additional evidence such as a network trace or a probe that records response headers is required to confirm the vulnerability.

### 17. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The source code defines a POST endpoint at /auth/form-login that returns an HTMLResponse but does not set any security‑related HTTP headers. The scanner report flags the missing CSP header, and the runtime probe confirms the endpoint is reachable via POST. No code is present that adds a CSP header to the response, and no guard or configuration is shown that would set it elsewhere.

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, or other resources can be loaded. This can enable cross‑site scripting (XSS) or data‑injection attacks if malicious content is reflected or injected into the response.

**Remediation:** Add a CSP header to the response, e.g., `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'"`. Consider using a middleware or framework feature to apply the header globally to all responses.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Scanner finding: "Content Security Policy (CSP) Header Not Set" for path /auth/form-login`
- `Source excerpt shows response creation without header manipulation`
- `Runtime probe fact: POST request to /auth/form-login observed`

Limitations:
- No captured HTTP response headers to directly verify the CSP header is absent
- No evidence that a global middleware or server configuration might add the CSP header outside the shown code

### 18. Password reset tokens must be single use

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The confirm_reset endpoint retrieves a reset token from the database and, if found, updates the user's password without any check that the token has already been used. The source excerpt shows no deletion or invalidation of the token after use. A runtime probe for the same endpoint returned HTTP 200 on a repeated POST, whereas the scanner expected error statuses (400, 409, 422). This demonstrates that the token can be reused, confirming the vulnerability.

**Impact:** An attacker who obtains a valid password reset token can reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity.

**Remediation:** Invalidate or delete the reset token after a successful password change, and enforce a one‑time‑use check before processing the reset. Additionally, consider adding a short expiration time and rate‑limiting on reset attempts.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup and password update without token invalidation (lines 577‑585).`
- `Runtime probe fact indicates POST to /auth/reset/confirm returned 200 on a replayed request, contrary to expected error codes, confirming token reuse.`

### 19. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /catalog/query returns HTML content without any indication that a Content‑Security‑Policy header is added to the response. The source excerpt shows only the HTML generation logic and does not set response headers. The runtime probe records a GET request but does not capture response headers, so the absence of CSP cannot be confirmed definitively.

**Impact:** Without a CSP header, browsers may allow execution of unsafe inline scripts or loading of resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response object or a middleware to set a strict policy such as "default-src 'self'; script-src 'self'; object-src 'none';".
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Source excerpt shows HTML response generation without header manipulation`
- `Runtime probe fact records a GET request to /catalog/query but does not include response header data`

Limitations:
- Missing runtime observation of actual response headers to confirm CSP is absent
- No evidence that the application sets CSP elsewhere (e.g., via middleware or server configuration)

### 20. X-Content-Type-Options Header Missing

- Issue group: `merged-a6e788cfc5d9d1297feb`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for GET /catalog/query does not include the X-Content-Type-Options header. The provided source code shows the endpoint returns an HTMLResponse but does not set any security‑related response headers. No additional runtime probe or independent scanner evidence confirming the header’s absence is supplied.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks such as cross‑site scripting or drive‑by downloads.

**Remediation:** Add the X-Content-Type-Options header to the response, e.g., by configuring FastAPI’s response middleware or setting the header explicitly in the endpoint:
```python
from fastapi.responses import HTMLResponse

@router.get("/catalog/query", response_class=HTMLResponse)
def catalog_query(q: str = ""):
    # ... existing logic ...
    response = HTMLResponse(content=generated_html)
    response.headers\["X-Content-Type-Options"\] = "nosniff"
    return response
```
Evidence:
- Source IDs: `merged-a6e788cfc5d9d1297feb`
- `Scanner finding: X-Content-Type-Options Header Missing for /catalog/query (zap.10021)`
- `Source excerpt shows endpoint returns HTMLResponse without setting security headers`

Limitations:
- No runtime probe confirming the header is absent in actual responses
- No independent scanner of medium or higher severity confirming the issue

### 21. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting any X-Frame-Options or Content-Security-Policy frame-ancestors directives. The scanner flagged the missing anti-clickjacking header, and the runtime probe confirms the endpoint is reachable via GET. However, no response header data is provided to confirm the header is absent, nor is there evidence of any server-side logic that adds such a header.

**Impact:** An attacker could embed the page in a malicious iframe, potentially enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Configure the application or web server to include an X-Frame-Options header (e.g., SAMEORIGIN or DENY) or a Content-Security-Policy with a frame-ancestors directive for all HTML responses, especially for the /catalog/query endpoint.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Scanner finding: Missing Anti-clickjacking Header`
- `Runtime probe fact: GET request to /catalog/query succeeded`

Limitations:
- No captured response headers to verify the header is indeed missing
- No code evidence showing header injection or omission

### 22. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /comments returns HTML content without setting an X-Frame-Options or Content-Security-Policy frame-ancestors header. The runtime probe confirms a GET request to /comments was made, but no header information is provided. No code shows a response header being set, and no guard is visible in the supplied context.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add an appropriate anti-clickjacking header (e.g., X-Frame-Options: SAMEORIGIN or Content‑Security‑Policy: frame‑ancestors 'self') to the response for the /comments endpoint, preferably via a middleware or response decorator.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Runtime probe fact: GET request to /comments observed (web-runtime zap.10020)`

Limitations:
- Missing explicit evidence that the response lacks the X-Frame-Options or CSP header (e.g., captured response headers).
- No scanner of higher severity confirming the header omission.

### 23. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns an HTML response constructed from database content without setting a Content‑Security‑Policy header. The supplied source excerpt shows the response is built and returned directly, and the runtime probe confirms the endpoint is reachable via GET. No code is present that adds security‑related response headers, and the scanner flagged the missing CSP header.

**Impact:** Without a CSP header, browsers are free to execute inline scripts or load resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response object or a middleware that sets `Content‑Security‑Policy: default-src 'self';` (adjust directives as needed). Ensure the header is applied to all HTML responses.
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- `Source excerpt shows the /comments handler returns raw HTML without setting headers`
- `Runtime probe fact confirms a GET request to /comments was made`

Limitations:
- No direct observation of the actual HTTP response headers to confirm the CSP header is absent
- No evidence of server‑level or middleware configuration that might add CSP headers automatically

### 24. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content generated from database rows, but the source code does not set the `X-Content-Type-Options: nosniff` header. The scanner flagged the missing header, and a runtime probe observed a GET request to the path, but no response header data was provided to confirm the omission.

**Impact:** Without the `X-Content-Type-Options: nosniff` header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks such as cross‑site scripting (XSS) if an attacker can influence the response body.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response for the `/comments` endpoint (e.g., via a middleware or directly in the route handler).
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- `Scanner reported "X-Content-Type-Options Header Missing" for /comments`
- <code>Source code for `/comments` endpoint does not set any security headers</code>
- `Runtime probe performed a GET request to /comments`

Limitations:
- No captured HTTP response headers to definitively prove the header is absent
- No evidence that the application sets security headers globally via middleware or server configuration

### 25. Debug configuration is unavailable anonymously

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source excerpt defines a GET endpoint at /debug/config that returns sensitive configuration values (database URL, mock external URL, and application secret) without any authentication or authorization checks. The runtime probe confirms that an unauthenticated GET request to this path receives a 200 OK response, whereas the expected secure responses would be 401/403/404. This demonstrates an exposed configuration endpoint accessible to any client.

**Impact:** An attacker can retrieve critical application secrets and infrastructure details, enabling further attacks such as database compromise, credential reuse, or service manipulation.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint, or restrict it to internal use only. Ensure that sensitive configuration values are not exposed via public APIs. Consider removing the endpoint from production deployments.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source code shows /debug/config endpoint returning DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks (lines 320-322).`
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404 (web-runtime rule workflow.debug_access.1).`

### 26. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without a Content‑Security‑Policy header. The scanner runtime probe observed the missing header, indicating the application does not set CSP for this route. While the absence of CSP can allow certain injection attacks in browsers, the provided evidence does not show whether other defenses (e.g., frame‑ancestors, script‑src restrictions) are applied elsewhere, nor does it demonstrate an actual exploit.

**Impact:** Without a CSP header, browsers may allow execution of malicious scripts or loading of unsafe resources if the endpoint is ever rendered in a browser context, increasing the risk of XSS or data exfiltration.

**Remediation:** Configure the FastAPI application (or underlying web server) to include a Content‑Security‑Policy header on all responses, e.g., using a middleware that adds `Content-Security-Policy: default-src 'self';` or a more restrictive policy appropriate for the application.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Runtime probe fact from scanner web-runtime indicates a 200 response from /healthz with no Content‑Security‑Policy header`

Limitations:
- No evidence that the endpoint is ever rendered in a browser context, so the practical exploitability is unclear. No information on whether other security headers or defenses are present elsewhere in the application.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe shows that the /healthz endpoint returns HTTP 200, but it does not provide any information about the presence or absence of X‑Frame‑Options or Content‑Security‑Policy headers. The source code for the endpoint does not set any response headers related to clickjacking protection. Without explicit evidence that the header is missing (e.g., captured response headers from a scanner or runtime probe), the finding cannot be confirmed.

**Impact:** If the endpoint can be embedded in a malicious site without X‑Frame‑Options or an appropriate CSP, an attacker could perform clickjacking attacks against users who visit the malicious site while authenticated to the API.

**Remediation:** Add a clickjacking protection header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP that disallows framing. Ensure the header is applied to all relevant routes, including /healthz.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe fact: status 200 for /healthz (no header information provided)`
- `Source excerpt shows no header manipulation in the healthz handler`

Limitations:
- No captured response headers confirming the header is absent
- No scanner evidence that explicitly reports the missing X‑Frame‑Options or CSP header

### 28. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a 200 response but no evidence is provided that the X-Content-Type-Options header is set. The runtime probe confirms the endpoint is reachable, but does not capture response headers. Without explicit header data, the missing‑header claim relies on the scanner finding alone.

**Impact:** Absence of the X-Content-Type-Options: nosniff header can allow browsers to perform MIME type sniffing, potentially enabling content‑type confusion attacks.

**Remediation:** Configure the web framework or middleware to add the X-Content-Type-Options: nosniff header to all responses, e.g., using FastAPI's Response headers or a security middleware.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe fact: status 200 for /healthz (web-runtime rule web.missing-content-type-protection)`

Limitations:
- No captured response headers confirming the header is absent
- No independent scanner evidence of header omission beyond the initial finding
- No runtime probe that explicitly checks for X-Content-Type-Options header

### 29. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/integrations/hook` accepts POST requests, reads the raw request body, and directly inserts it into the database as an accepted visit without any verification of a signature or authentication token. The runtime probe confirms that a POST request to this endpoint returns HTTP 200, whereas the expected secure behavior would be to reject unsigned requests with 4xx responses. This demonstrates an exploitable path where an attacker can submit arbitrary webhook payloads that are treated as trusted.

**Impact:** An attacker can forge webhook events, causing the application to record false visits or trigger downstream logic that assumes the webhook is authentic. This may lead to data integrity issues, unauthorized actions, or further exploitation depending on how the stored data is used.

**Remediation:** Implement verification of a cryptographic signature (e.g., HMAC) or other authentication mechanism on incoming webhook requests before processing. Reject requests lacking a valid signature with an appropriate 4xx response (e.g., 401 Unauthorized). Log verification failures for monitoring.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- <code>Source code shows the `/integrations/hook` handler inserts the raw request body into the database without validation</code>
- <code>Runtime probe fact reports POST to `/integrations/hook` returned status 200 instead of expected 400/401/403</code>

### 30. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated user owns the requested invoice before returning it. The code fetches the invoice by ID and returns it if found, without any ownership check. A runtime probe confirms that a GET request to this endpoint returns HTTP 200 instead of the expected 403 when the requester is not the owner, indicating the missing access control.

**Impact:** An attacker who can authenticate can retrieve any invoice by ID, exposing sensitive financial information of other users.

**Remediation:** Add an ownership verification step after fetching the invoice, e.g., compare the invoice's owner field with the authenticated principal and raise a 403 HTTPException if they do not match.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- `Source excerpt shows endpoint definition without ownership check (lines 268-274).`
- `Runtime probe fact: GET /invoices/{{invoice_id}} returned status 200 instead of 403, indicating lack of owner enforcement.`

### 31. Insufficient authorization check on job creation endpoint

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint calls `principal(authorization)` but does not verify that the authenticated principal has permission to create admin jobs. The runtime probe shows the endpoint returns HTTP 200 for a request that should be rejected (expected 400/403/422), indicating the missing authorization guard. No additional scanner evidence or code showing a role check is present in the supplied excerpt.

**Impact:** An attacker who can obtain or forge an authorization header could create arbitrary jobs, potentially escalating privileges or executing unauthorized workloads.

**Remediation:** Add explicit role/permission verification after extracting the principal, e.g., check that the user has an admin or worker role before inserting the job. Return appropriate error codes (403) when the check fails.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- <code>Source excerpt shows `principal(authorization)` is called without subsequent role validation.</code>
- `Runtime probe fact: POST /jobs returned status 200, while expected statuses were 400, 403, or 422, indicating the request was accepted without proper authorization checks.`

Limitations:
- Missing explicit code that checks the user's role or permissions after `principal(authorization)`. No independent high‑severity scanner finding confirming the flaw.

### 32. Identity endpoint may expose SSN

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table including the ssn column and returns the row as a dictionary without any filtering or masking. No access control or data‑sanitization is shown in the supplied code. A runtime probe observed a 200 response for a GET to /me, but the probe indicates "values_redacted": true, leaving it unclear whether the SSN is actually omitted from the response.

**Impact:** If the SSN is returned to the client, an attacker who can authenticate as a user could obtain sensitive personal information, leading to identity theft and privacy violations.

**Remediation:** Modify the endpoint to exclude sensitive fields such as ssn from the response or mask them. Implement proper authorization checks and ensure only non‑sensitive user data is returned.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source code line 203 selects ssn and returns the full row`
- `Scanner finding flags excessive data exposure`
- `Runtime probe observed a successful GET to /me`

Limitations:
- The runtime probe does not confirm whether the SSN value is present or redacted in the actual response. Additional testing of the response payload is needed to verify exposure.

### 33. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint POST /orders inserts the order record using the value supplied in body.unit_price directly into the database. No server‑side validation or lookup of the official catalog price is shown in the provided excerpt, and the runtime probe indicates mixed assertion results for the price‑related workflow. This suggests that a client could manipulate the unit_price field to affect order totals.

**Impact:** An attacker could submit orders with arbitrary unit_price values, leading to under‑charging for goods, revenue loss, or potential exploitation of downstream billing logic.

**Remediation:** Implement server‑side price verification: retrieve the canonical price for the ordered item from the product catalog and compare it to the supplied unit_price, rejecting or correcting mismatches. Optionally, remove unit_price from the client payload and compute it internally.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt shows direct insertion of body.unit_price into the SQL INSERT statement (lines 213‑215).`
- `Runtime probe fact for rule workflow.price_catalog.1 reports mixed assertion results, indicating the price workflow may be bypassed.`

Limitations:
- No explicit guard or price‑lookup logic is present in the supplied code, but the surrounding code context is missing, so we cannot confirm whether validation occurs elsewhere.
- The runtime probe provides only a binary true/false assertion result without detailed proof of exploitation; independent scanner corroboration of medium or higher severity is absent.

### 34. New orders cannot start as paid

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The supplied source shows the create_order endpoint inserts the order with the status value provided by the client without any validation or restriction. However, the finding concerns a business‑logic issue (orders starting with a paid status) rather than a security vulnerability such as unauthorized access, data leakage, or code execution. No evidence is presented that this behavior can be exploited to compromise confidentiality, integrity, or availability, nor is there any indication of missing authentication or authorization checks. Consequently, the issue does not constitute a security flaw.

**Impact:** No direct security impact; the problem is limited to incorrect order state handling, which may affect business processes but does not expose the system to attack.

**Remediation:** Validate the `status` field in the request body, ensuring that newly created orders cannot be set to a paid or completed state without appropriate payment processing. Reject or coerce disallowed statuses with a 400/422 response.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- `Source excerpt shows the status field is taken directly from the request body and inserted into the database (lines 213‑215).`
- `Runtime probe fact indicates the endpoint returned 200 instead of the expected 400/422, confirming the lack of validation.`

### 35. Negative order prices are accepted without validation

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the supplied unit_price directly into the database without any validation. The runtime probe shows that a POST request with a negative price receives a 200 OK response instead of the expected 400/422 error, confirming that the negative price is accepted. No guard or validation check is present in the supplied code snippet.

**Impact:** An attacker can create orders with negative prices, potentially leading to unauthorized refunds, inventory manipulation, or financial loss.

**Remediation:** Add input validation to ensure unit_price is non‑negative before inserting into the database, and return an appropriate error response (e.g., 400 Bad Request) when the validation fails.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Source excerpt shows unit_price is inserted without checks (lines 208‑215)`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`

### 36. Users cannot create orders for another owner

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and defaults to the authenticated user's sub claim when omitted. No authorization check is performed to ensure that the supplied owner_id (if any) belongs to the authenticated user. The runtime probe confirms that a POST to /orders succeeds with HTTP 200, whereas the scanner expected a failure status (400, 403, or 422). This indicates that an attacker can supply an arbitrary owner_id and create orders on behalf of other users.

**Impact:** An attacker can create orders for any user, potentially leading to unauthorized purchases, billing fraud, or resource exhaustion under another user's account.

**Remediation:** Validate that the owner_id in the request body matches the authenticated user's identifier (user\["sub"\]). If the client must not specify owner_id, remove it from the request schema entirely. Return an error (e.g., 403 Forbidden) when the IDs do not match.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows owner_id is set from body.owner_id without validation (lines 208‑212).`
- `Runtime probe fact shows POST /orders returned status 200, contrary to expected error statuses, indicating the missing check.`

Limitations:
- No evidence is provided that any external guard (e.g., middleware, database trigger) enforces ownership checks outside the shown function. Additional verification that no other layer validates owner_id would be needed for a confirmed vulnerability.

### 37. A note must belong to the order named in the URL

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID without verifying that the note's `order_id` matches the `order_id` supplied in the URL. The code fetches the note row and, if found, returns it directly, lacking any check that the note belongs to the requested order. This allows an attacker to access notes belonging to other orders by guessing note IDs.

**Impact:** Unauthorized disclosure of notes belonging to other orders, leading to information leakage and potential privacy violations.

**Remediation:** Add a check after fetching the note to verify that `row['order_id']` equals the `order_id` path parameter. If they differ, return a 403 Forbidden or 404 Not Found response. Example:
```python
if row\['order_id'\] != order_id:
    raise HTTPException(403, "Forbidden")
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- `Source excerpt shows note fetched without order_id validation (lines 543-548).`
- <code>Runtime probe fact indicates a GET to `/orders/1/notes/2` returned 200 instead of the expected 403/404, confirming unauthorized access.</code>

### 38. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders/{order_id} calls a generic principal() function but does not verify that the authenticated user is the owner of the requested order before returning the record. The source excerpt shows no ownership check after the database query. A runtime probe for the same path returned HTTP 200 for a request that should have been denied (expected 403), indicating the missing guard is exploitable.

**Impact:** An attacker who can obtain a valid authorization token can retrieve any order by ID, leading to unauthorized disclosure of order details.

**Remediation:** Add an ownership verification step after fetching the order, e.g., compare the order's owner_id with the authenticated user's ID and raise HTTPException(403) if they differ.
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- `Source excerpt shows principal(authorization) called but no owner check before returning the order`
- `Runtime probe fact: GET /orders/{{order_id}} returned status 200 where 403 was expected`

Limitations:
- The implementation of principal() is not shown, so it cannot be confirmed whether it performs ownership validation internally
- No explicit scanner finding with medium or higher severity confirming the issue

### 39. Excessive coupon discounts are rejected

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/apply-coupon` accepts a coupon code and an optional discount value. The implementation retrieves the coupon's default percent and then uses the client‑supplied `body.discount` if present, without any validation of the discount range. The runtime probe confirms that an excessively large discount is accepted (HTTP 200) when a 400/422 error was expected, demonstrating that the missing bounds check is exploitable. No guard or validation logic is present in the supplied code snippet.

**Impact:** An attacker can apply arbitrarily large discounts to orders, leading to unauthorized price reductions, revenue loss, and potential abuse of promotional systems.

**Remediation:** Add server‑side validation to ensure the discount does not exceed a defined maximum (e.g., the coupon's percent or a business‑defined cap). Return a 400/422 error when the supplied discount is out of bounds. Consider removing the ability for clients to specify a discount value altogether and rely solely on the coupon's stored percent.
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- <code>Source excerpt shows `percent = body.discount if body.discount is not None else (coupon[&quot;percent&quot;] if coupon else 0)` with no range check (lines 231‑235).</code>
- `Runtime probe fact reports status 200 for an excessive discount where 400/422 was expected (rule workflow.coupon_bounds.2).`

### 40. Paid orders require a refund before cancellation

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/cancel` updates the order status to "cancelled" without verifying whether the order has been paid or whether a refund has been issued. The source excerpt shows no check of payment status before the UPDATE statement. Runtime probe facts confirm the endpoint returns HTTP 200 (success) for a paid order, whereas the expected behavior would be an error status (400, 409, 422). This demonstrates an insecure workflow that allows cancellation of paid orders without a refund, constituting a confirmed vulnerability.

**Impact:** An attacker or malicious user could cancel paid orders and potentially receive refunds later, leading to financial loss and abuse of the order management system.

**Remediation:** Add a check before cancelling an order to verify that the order is unpaid or that a refund has been processed. Return an appropriate error status (e.g., 400 or 409) if the order is paid and no refund exists. Ensure the logic is enforced consistently across all cancellation paths.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- `Source code at lines 258‑263 shows the cancel_order function updates order status without payment checks`
- `Runtime probe fact shows POST to /orders/{{order_id}}/cancel returned 200 instead of expected error statuses`

### 41. Payment replay vulnerability on order payment endpoint

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders/{order_id}/pay endpoint updates the order status to 'paid' without checking whether the order has already been paid. The source excerpt shows the status is set unconditionally after retrieving the order. A runtime probe confirms that a second payment request returns HTTP 200 instead of the expected error codes (400, 409, 422), demonstrating that the replay is possible in practice.

**Impact:** An attacker can replay a payment request for an already paid order, causing duplicate charges, financial loss, and potential inventory inconsistencies.

**Remediation:** Add a check before updating the order status to ensure the order is not already marked as paid. Return an appropriate error (e.g., 409 Conflict) if a payment is attempted on a paid order. Optionally, implement idempotency keys to safely handle retries.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- `Source code lines 241-250 show the payment endpoint updates order status without prior paid check`
- `Runtime probe fact: POST to /orders/{{order_id}}/pay returned status 200, while expected error statuses were 400, 409, or 422`

### 42. Unauthorized profile access

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` calls `principal(authorization)` but does not verify that the authenticated user is authorized to view the requested profile. The subsequent SQL query retrieves any user's data by ID without an ownership check, and the code only raises a 404 if no row is found. Runtime probing shows a GET request for another user's profile returned HTTP 200, confirming the lack of access control.

**Impact:** An attacker can enumerate or view other users' personal information, including usernames, emails, and SSNs, leading to privacy violations and potential identity theft.

**Remediation:** Add an ownership check after retrieving the profile, e.g., compare the authenticated user's ID with `profile_id` and return 403 if they differ. Alternatively, include the user ID in the query condition to restrict results to the requesting user.
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source code at lines 98-104 shows no ownership verification before returning profile data.`
- `Runtime probe fact: GET /profiles/{{other_id}} returned status 200 instead of expected 403/404, indicating unauthorized access is possible.`

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /view endpoint returns an HTMLResponse without setting any anti-clickjacking headers such as X-Frame-Options or Content‑Security‑Policy frame‑ancestors. The source excerpt shows the raw HTML being returned and no header manipulation is present. A runtime probe confirms the endpoint is reachable via GET, but no response header data is provided to prove the header is absent.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add an appropriate anti‑clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame‑ancestors` directive) to the response in the view_home handler or via a global middleware.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse returned without header configuration`
- `Runtime probe fact confirms GET request to /view`

Limitations:
- No captured HTTP response headers to definitively show the header is missing
- No evidence that a global middleware might add the header elsewhere

### 44. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The source excerpt shows the `/view` endpoint returns an HTMLResponse constructed directly in code with no indication that a CSP header is added to the response. The runtime probe confirms the endpoint is reachable via GET, but does not capture response headers to verify the absence of CSP. No guard or middleware that sets security headers is visible in the supplied context.

**Impact:** Without a CSP header, the application is vulnerable to cross‑site scripting (XSS) and other content injection attacks, allowing an attacker to execute malicious scripts in a user's browser.

**Remediation:** Add a CSP header to the response, either by setting it directly in the view function or by using middleware that injects security headers for all responses. Example (FastAPI):
```python
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\['Content‑Security‑Policy'\] = "default-src 'self'"
        return response
```
Or set the header in `view_home` before returning the HTMLResponse.
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- `Source excerpt shows HTMLResponse returned without header manipulation (lines 686‑690).`
- <code>Runtime probe fact confirms GET request to `/view` (scanner_id: web-runtime, rule_id: zap.10038).</code>

Limitations:
- Missing captured HTTP response headers that explicitly show the CSP header is absent.
- No evidence of global security‑header middleware that might add CSP elsewhere in the application.

### 45. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse without explicitly setting the `X-Content-Type-Options: nosniff` header. The source excerpt shows no header manipulation, and the runtime probe only records the request method without capturing response headers. This suggests the header may be absent, which is a security best‑practice issue, but the evidence is incomplete.

**Impact:** Without the `X-Content-Type-Options: nosniff` header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response, e.g., by configuring the FastAPI/Starlette response middleware or setting the header directly in the route handler.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- <code>Source excerpt shows the `/view` route returns HTMLResponse without header configuration.</code>
- <code>Runtime probe fact records a GET request to `/view` but does not include response headers.</code>

Limitations:
- Missing runtime observation of actual response headers to confirm the header is absent.
- No evidence that the application sets the header globally via middleware or server configuration outside the shown code.

### 46. Webhook destination must match the approved internal host exactly

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/webhooks` accepts a `target_url` parameter and only rejects URLs containing the string "mock-external". Any other external URL passes the check and is stored in the database, allowing arbitrary webhook destinations. The runtime probe confirms that a POST request with a non‑mock URL receives a 200 response, demonstrating the missing validation in practice.

**Impact:** An attacker can supply an arbitrary URL, causing the application to send data to external services, leading to data exfiltration, SSRF, or other malicious actions.

**Remediation:** Validate `target_url` against a whitelist of approved internal hosts or enforce exact match to the expected internal host. Reject any URL that does not match the approved host and consider using URL parsing to prevent bypasses.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- `Source code shows only a check for "mock-external" and raises 400 otherwise (lines 295‑298).`
- `Runtime probe fact: POST to /webhooks with a non‑mock URL returned status 200, indicating the request was accepted.`

### 47. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The source excerpt shows that the application logs the value of the environment variable APP_SECRET in clear text using a standard logger call. No surrounding code or configuration is provided that masks or redacts this value, nor is there evidence of a guard that prevents logging of sensitive data. The finding is supported by a semgrep scanner rule that flags credential disclosure in log statements, but there is no independent runtime probe confirming that the secret is actually emitted to logs in a production environment.

**Impact:** If log files are accessible to unauthorized users or forwarded to external logging services, the exposed APP_SECRET could be used to compromise the application’s security mechanisms, such as token generation or encryption, leading to account takeover or data breach.

**Remediation:** Remove the secret from the log statement or replace it with a placeholder. Use a dedicated secure logging library that supports redaction of sensitive fields, or ensure that the logger is configured to filter out secrets before writing to log files. Example: `log.info("login user=%s", username)` without including `app_secret`.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- <code>Source line 137 logs `app_secret` in clear text: `log.info(&quot;login user=%s app_secret=%s&quot;, username, os.environ.get(&quot;APP_SECRET&quot;, &quot;lab-only&quot;))`</code>
- <code>Semgrep rule `python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure` flagged the same line as a credential disclosure.</code>

Limitations:
- No runtime probe confirming that the secret appears in actual log output.
- No evidence that a logging configuration or external guard sanitizes the secret before it is written.
- No demonstration of the impact (e.g., log file exposure) in the supplied context.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any origin to make cross‑origin requests. This configuration can expose the API to CSRF-like attacks or data leakage when combined with authenticated endpoints.

**Impact:** An attacker from any domain can interact with the API, potentially abusing authenticated sessions or exfiltrating data if the API returns sensitive information to browsers.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains, or dynamically validate origins. If credentials are required, set allow_credentials to false or ensure proper CSRF protections are in place.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `Source excerpt shows allow_origins=["*"] at line 26 in api/app.py`

Limitations:
- Missing information about authentication mechanisms, sensitive endpoints, and whether the API is publicly exposed. Without knowing if authenticated routes exist or if additional origin checks are performed elsewhere, the full risk cannot be confirmed.

### 49. Log Injection

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The log statement uses structured logging with format placeholders ("%s") and passes the user‑provided username and environment variable as separate arguments. This pattern prevents log injection because the logging library does not perform string interpolation on the user data before writing the log entry. No evidence shows that the log output is later interpreted or rendered in a way that could lead to injection attacks.

**Impact:** Even if an attacker controls the username, the logging framework will treat it as a literal value, so there is no risk of log injection affecting log parsing or downstream systems.

**Remediation:** No remediation needed for log injection; the current logging approach is safe. Continue using parameterized logging calls for any user‑controlled data.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

### 50. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` (default "/") and directly passes its value to `RedirectResponse` without any validation or allow‑list check. This creates an open redirect where an attacker can supply an arbitrary URL and cause the application to redirect users to a malicious site.

**Impact:** An attacker can craft a link to the vulnerable endpoint with a malicious `next` value (e.g., `/auth/continue?next=https://phishing.example.com`). Victims clicking the link are redirected to the attacker‑controlled site, facilitating phishing, credential harvesting, or drive‑by attacks.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths before performing the redirect. If only internal redirects are needed, ensure the value is a relative path and reject absolute URLs. Alternatively, use a safe redirect helper that enforces such checks.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source excerpt shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse: return RedirectResponse(next, status_code=302)` with no validation.</code>

Limitations:
- No runtime probe or additional scanner evidence confirming exploitation. No evidence of existing validation or guard logic elsewhere in the codebase. Confirmation requires observation of the redirect being reachable by an attacker or a test demonstrating the open redirect.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the provided URL by ensuring it starts with a single '/' and rejects any scheme, network location, or double-slash prefix. This prevents redirection to external domains or protocol-relative URLs, mitigating open‑redirect risk. The code returns a RedirectResponse only for safe, local paths.

**Impact:** If the validation were bypassed, an attacker could redirect users to malicious external sites, leading to phishing or drive‑by attacks. The existing checks block such misuse, so the impact is mitigated.

**Remediation:** No remediation needed for this specific issue; the validation logic is appropriate. Continue to ensure any future changes preserve these checks.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- <code>The code checks `if not next.startswith(&quot;/&quot;) or next.startswith(&quot;//&quot;) or parts.scheme or parts.netloc:` and raises HTTPException for invalid inputs, ensuring only local paths are allowed.</code>

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a health check is a best practice for container reliability, the absence of a HEALTHCHECK does not constitute a security vulnerability in the supplied context. No evidence is provided that this misconfiguration leads to an exploitable condition.

**Impact:** None identified – the container will run, but orchestration systems may lack automatic health monitoring.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- No runtime or scanner evidence indicating that the missing health check leads to a security breach or denial‑of‑service scenario.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a HEALTHCHECK is a best practice for container health monitoring, its absence does not constitute a security vulnerability in the supplied context.

**Impact:** Without a HEALTHCHECK, container orchestration systems may not detect unhealthy containers promptly, potentially leading to reduced availability, but no direct security impact is demonstrated.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:9000/health || exit 1
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile lines show no HEALTHCHECK instruction`

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a best‑practice recommendation but does not constitute a security vulnerability in the supplied context. No evidence shows that the missing health check leads to an exploitable condition.

**Impact:** None – the container will run without health monitoring, but this does not create a direct security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK CMD curl --fail http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53539 (Denial of Service via crafted form‑urlencoded bodies). The scanner evidence explicitly cites this CVE and notes that the vulnerability is fixed in version 0.0.30. No mitigating guard or version override is present in the supplied context, and the scanner source is of high severity, providing independent corroboration.

**Impact:** An attacker can send specially crafted form‑urlencoded payloads that trigger a denial‑of‑service condition, potentially rendering the FastAPI service unavailable.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later in requirements.txt and redeploy the application.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt pins python-multipart==0.0.20`

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE‑2026‑42561 (Denial‑of‑Service via excessive multipart part headers). The scanner flagged this dependency version as vulnerable. However, the supplied artifacts do not show whether the application actually imports or uses python-multipart, nor is there any runtime probe evidence demonstrating the vulnerable behavior in the running service. Without evidence of an execution path that reaches the vulnerable multipart parsing code, the finding cannot be confirmed as a definite vulnerability in this code base.

**Impact:** If the application processes multipart/form‑data requests using the vulnerable python-multipart version, an attacker could craft a request with many part headers to exhaust memory or CPU, leading to a denial‑of‑service condition.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, which contains the fix for CVE‑2026‑42561. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27 (scanner evidence).`
- `requirements.txt pins python-multipart==0.0.20.`

Limitations:
- No code evidence showing python-multipart is imported or used in the application.
- No runtime probe or test demonstrating the DoS behavior.
- No confirmation that multipart handling code paths are reachable in the deployed service.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53538. The CVE describes an information‑disclosure vulnerability caused by a differential parsing behavior when handling multipart form data. The supplied requirements.txt explicitly lists python-multipart==0.0.20, confirming the vulnerable version is present in the code base.

**Impact:** An attacker who can supply crafted multipart form data may cause the application to leak sensitive information from request processing, potentially exposing user data or internal state.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt lists python-multipart==0.0.20`

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE‑2026‑40347. This CVE describes a denial‑of‑service condition triggered by specially crafted multipart/form-data payloads. The scanner’s finding provides independent corroboration of the vulnerability, and the source excerpt confirms the vulnerable version is in use.

**Impact:** An attacker can send a malicious multipart request that exhausts server resources, potentially causing the FastAPI application to become unresponsive or crash, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, which contains the fix for CVE‑2026‑40347. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`
- `requirements.txt pins python-multipart==0.0.20`

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project declares a dependency on python-multipart version 0.0.20, which is known to contain CVE-2026-24486 – an arbitrary file write via path traversal. The scanner identified this vulnerable version in the requirements.txt. No source code is provided that demonstrates the library being imported or used, so the presence of an exploitable code path cannot be confirmed from the supplied artifacts.

**Impact:** If the vulnerable python-multipart library is exercised at runtime, an attacker could craft a multipart request with a malicious filename containing path traversal sequences (e.g., "../../etc/passwd") to cause arbitrary file writes on the server, potentially leading to privilege escalation or code execution.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, which contains the fix for CVE-2026-24486. Verify that the updated version is reflected in requirements.txt and that the application is redeployed with the patched dependency.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency entry in requirements.txt: python-multipart==0.0.20`
- `Scanner report citing CVE-2026-24486 affecting python-multipart 0.0.20`

Limitations:
- No evidence that the python-multipart library is actually imported or used in the application code.
- No runtime probe or test confirming that a path‑traversal payload can reach the vulnerable code path.

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to have CVE-2026-53537. The supplied evidence lists the vulnerability and a fixed version, indicating a potential information disclosure issue. However, no runtime probe or additional independent scanner evidence is provided to demonstrate that the vulnerable code is actually executed in this deployment.

**Impact:** Potential leakage of sensitive information through malformed multipart header parsing when the vulnerable library is used.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency list shows python-multipart==0.0.20`
- `Scanner report cites CVE-2026-53537 affecting python-multipart 0.0.20`

Limitations:
- No runtime evidence that the vulnerable code path is exercised
- No independent scanner confirmation beyond the initial finding
- No verification that the application actually processes multipart data using the vulnerable library

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53540. The scanner identified this vulnerable version in the requirements.txt. No additional runtime or code‑level evidence was provided to demonstrate that the vulnerable code path is exercised in the application.

**Impact:** An attacker could send a request with a negative Content‑Length header, causing the library to buffer the entire request body in memory, potentially leading to denial‑of‑service or memory exhaustion.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which contains the fix for CVE-2026-53540. Update the requirements.txt and reinstall dependencies.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31 (scanner evidence)`

Limitations:
- No runtime probe or code‑path evidence showing that the vulnerable parse_form function is actually invoked by the application. Confirmation of exploitation requires observing the vulnerable behavior in execution or a higher‑severity scanner confirmation.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a URL by concatenating a constant BASE with a variable path and then passes it to urllib.request.urlopen. While urllib can handle file:// URLs, the supplied source does not show whether the `path` argument can be influenced by an attacker, nor does it demonstrate a missing validation check. No runtime probe or additional scanner evidence confirms that an attacker can control the URL to trigger an unsafe file read.

**Impact:** If an attacker can control `path`, they might craft a file:// URL to read arbitrary files from the server's filesystem, leading to information disclosure.

**Remediation:** Validate and sanitize the `path` argument to ensure it does not contain dangerous schemes (e.g., file://) or unexpected characters. Consider using a higher‑level HTTP client like the `requests` library, which does not support file URLs, or explicitly reject non‑HTTP schemes before calling urllib.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows dynamic URL construction with urllib (lines 20‑21).`
- `Scanner finding flagged the pattern as potentially unsafe.`

Limitations:
- No evidence that `path` is attacker‑controlled.
- No proof that a guard or validation step exists elsewhere in the code.
- No runtime probe demonstrating exploitation or a higher‑severity scanner confirmation.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload\["target_url"\]). No validation or sanitisation of this value is shown, meaning an attacker who can influence the payload could supply a malicious URL (e.g., a file:// scheme) that urllib will open. The scanner flagged this pattern as potentially unsafe. No guard (such as URL scheme validation, allowlist, or sandboxing) is present in the supplied excerpt.

**Impact:** If an attacker can control the target_url, they may cause the worker to read arbitrary files via a file:// URL or trigger SSRF-like behavior, potentially exposing internal services or data.

**Remediation:** Validate the target_url before using it with urllib. Restrict allowed schemes to http/https, enforce an allow‑list of trusted domains, or switch to a higher‑level library like requests that makes such misuse harder. Consider adding explicit error handling for unexpected URL schemes.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `source_excerpt lines 18‑23 show payload["target_url"] passed directly to urllib.request.Request without validation`

Limitations:
- No runtime probe demonstrates an actual exploit (e.g., a request that reads a file). No additional scanner evidence of confirmed SSRF or file read. No code elsewhere is provided that might perform URL validation, so the presence of a guard cannot be confirmed.

### 64. Unauthenticated file read endpoint

- Issue group: `ai-827cbbfd5e460c8b`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /files endpoint returns the contents of any file under the configured public directory based solely on a user‑supplied name. The code does not perform any authentication or authorization checks before reading and returning the file. This pattern can allow an unauthenticated attacker to enumerate and read files that are not meant to be publicly exposed.

**Impact:** Sensitive files placed in the public directory (or path‑traversal‑controlled files) could be disclosed to any remote client, leading to information leakage, credential exposure, or further exploitation of the system.

**Remediation:** Add authentication and authorization checks before accessing the file. Validate the requested filename against an allow‑list or restrict the endpoint to a safe subset of files. Consider serving only intended static assets via a dedicated static file server rather than exposing arbitrary file reads.
Evidence:
- Source IDs: `ai-827cbbfd5e460c8b`
- `api/extra.py:210 – @router.get("/files") defines an unauthenticated GET endpoint`
- `api/extra.py:212 – file path is built from user‑supplied "name" without any auth check`
- `api/extra.py:215 – file contents are returned directly in the response`

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable without authentication
- No deployment configuration showing whether the public directory is intended to be fully exposed
- No guard checks observed in the supplied snippet; external middleware or global dependencies could enforce authentication, but this is not visible in the provided context

### 65. Unauthenticated verified file read endpoint

- Issue group: `ai-db9083db72a7fa38`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint serves files from the designated public directory and includes a path‑traversal guard (`is_relative_to(root)`) and a file‑existence check before returning the content. No authentication is performed, but the route is explicitly named “verified” and appears intended for public file access. The supplied code does not indicate that sensitive files are stored in this directory, and the existing checks mitigate typical file‑read attacks. Consequently, the lack of authentication is not necessarily a vulnerability in this context.

**Impact:** If sensitive files were inadvertently placed in the public directory, they could be disclosed without authentication. However, the code restricts access to files within the public folder and verifies existence, limiting exposure to intended public content.

**Remediation:** Ensure that only non‑sensitive files are stored in the `public` directory. If any confidential data might reside there, add authentication/authorization checks before serving files. Document the intended public nature of this endpoint to avoid confusion.
Evidence:
- Source IDs: `ai-db9083db72a7fa38`
- <code>api/extra.py:218 – route definition `@router.get(&quot;/files/verified&quot;)`</code>
- <code>api/extra.py:220 – resolves `root` to the public directory</code>
- `api/extra.py:221 – resolves requested file path`
- <code>api/extra.py:222 – checks `is_relative_to(root)` and `is_file()`</code>
- <code>api/extra.py:224 – returns file content via `Response`</code>

### 66. Potential IDOR in profile verification endpoint

- Issue group: `ai-f651aa6cb2413d9a`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint verifies that the requested profile_id matches the authenticated user's id before returning profile data. This equality check prevents unauthorized users from accessing other users' profiles, which mitigates an IDOR. The concern raised about missing role‑based checks pertains to business‑logic requirements, not a direct access control flaw in the supplied code.

**Impact:** No direct unauthorized data exposure is possible based on the provided logic; the endpoint correctly restricts access to the owner’s profile.

**Remediation:** If the application’s policy requires administrators or other privileged roles to access additional profiles, implement explicit role‑based access control checks in addition to the existing ID check. Otherwise, no changes are needed.
Evidence:
- Source IDs: `ai-f651aa6cb2413d9a`
- `api/extra.py:107 – endpoint definition @router.get("/profiles/{profile_id}/verified")`
- `api/extra.py:109 – user = verified_identity(authorization)`
- `api/extra.py:110 – if profile_id != user["id"]: raise HTTPException(403)`
- `api/extra.py:112 – return {"id": user["id"], "username": user["username"], "email": user["email"]}`

### 67. Missing authorization on coupon application

- Issue group: `ai-d0bd0cf4e664f11f`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint authenticates the request via the principal function but does not perform any check that the authenticated user owns the order identified by order_id. The code updates the order's discount directly, allowing any authenticated user to modify any order's price by supplying its ID.

**Impact:** An attacker who can obtain a valid authentication token can apply arbitrary coupons or discounts to any user's order, potentially resulting in unauthorized price reductions, revenue loss, and abuse of promotional codes.

**Remediation:** Add an ownership or permission check before updating the order. For example, query the order's owner_id and compare it to the user ID extracted from the principal, or enforce role‑based access control that restricts who may modify the order. Return an error if the check fails.
Evidence:
- Source IDs: `ai-d0bd0cf4e664f11f`
- `source_excerpt shows principal(authorization) called without subsequent ownership verification`
- `sensitive_operation excerpt shows UPDATE orders SET discount where id=%s executed without guard`

Limitations:
- No evidence that a database trigger or other external constraint enforces ownership
- No runtime probe demonstrating that an unauthorized user can successfully modify another user's order

### 68. Missing ownership verification on order payment

- Issue group: `ai-3b4a9d4c62593325`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The pay_order endpoint authenticates the request via the principal() call but does not verify that the authenticated user is the owner of the order before updating the order status to 'paid'. The code fetches the order record and directly executes an UPDATE without checking order\["owner_id"\] against the caller's identity. This pattern suggests an authorization flaw where any authenticated user could pay for any order by supplying its ID.

**Impact:** An attacker who can obtain a valid authentication token could pay for orders they do not own, potentially causing financial loss, unauthorized charges, or denial of service for legitimate owners. The lack of ownership verification also undermines auditability and could be abused for fraud.

**Remediation:** Add an explicit ownership check after retrieving the order and before performing the update. For example:
```python
user_id = get_user_id_from_token(authorization)
if order\["owner_id"\] != user_id:
    raise HTTPException(403, "Not authorized to pay for this order")
```
Ensure that the check is performed for all code paths that modify order state. Consider centralizing authorization logic and adding audit logging for payment actions.
Evidence:
- Source IDs: `ai-3b4a9d4c62593325`
- `source_excerpt lines 241‑249 show the endpoint definition, principal() call, order retrieval, and the UPDATE without an ownership check`
- `candidate description identifies the missing check at line 245`
- `code snippet confirms no comparison between order["owner_id"] and the authenticated user`

Limitations:
- No independent scanner or runtime probe evidence confirming the vulnerability in practice
- No evidence that other parts of the application (e.g., middleware, database triggers) enforce ownership checks
- No information about external payment gateway validation that might mitigate the issue

### 69. Potential path traversal via unverified file name in /files endpoint

- Issue group: `ai-f3fefb54ee3cb0c0`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint constructs a file path using the user‑supplied name, resolves it, and then checks that the resolved path is relative to the public directory and that the file exists before reading it. Because resolve() follows symlinks, an attacker who can place a symlink inside the public directory that points outside the intended directory could bypass the is_relative_to check and cause the server to read arbitrary files. The code does not include any explicit guard against symlink traversal or other filesystem tricks, so a path‑traversal vector remains possible.

**Impact:** If an attacker can exploit the symlink bypass, they may read arbitrary files on the server, potentially exposing source code, configuration files, credentials, or other sensitive data.

**Remediation:** Validate the user‑supplied filename without using resolve() on the combined path, or explicitly reject any path components that resolve outside the public directory. Consider using a safe join that does not follow symlinks, or check the file’s realpath after ensuring it is not a symlink. Additionally, enforce filesystem permissions or mount options that disallow following symlinks from the public directory.
Evidence:
- Source IDs: `ai-f3fefb54ee3cb0c0`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- No evidence that an attacker can upload a symlink into the public directory.
- No runtime probe showing that a crafted name actually leads to reading a file outside the public directory.
- No scanner or other independent source confirming exploitation; the finding relies solely on the AI analysis of the code.

### 70. Missing ownership check on order cancellation

- Issue group: `ai-de70ebb6230142e0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user owns the order being cancelled. The code directly updates the order status based solely on the supplied `order_id`, which can allow an attacker to cancel any order if they know its identifier (potential IDOR). No evidence of additional middleware or database constraints that would enforce ownership is present in the supplied excerpts.

**Impact:** An attacker who can guess or enumerate order IDs could cancel other users' orders, leading to denial of service for legitimate customers, financial loss, and loss of trust in the system.

**Remediation:** Add an ownership verification step before performing the update. For example, query the order's `user_id` and compare it to the authenticated principal's ID, returning an error if they do not match. Ensure that any middleware or database policies also enforce this check.
Evidence:
- Source IDs: `ai-de70ebb6230142e0`
- <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `principal(authorization)`
- `row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone()`

Limitations:
- The schema of the `orders` table is not provided; we cannot confirm the presence of a `user_id` column to enforce ownership.
- No runtime probe or scanner evidence confirming that the endpoint is reachable without an ownership check.
- Potential middleware or database-level row‑level security that could enforce ownership is not visible in the supplied context.

### 71. Missing role-based access control on admin user listing

- Issue group: `ai-9879663fa926587d`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/admin/users` authenticates the request via `principal(authorization)` but does not verify that the authenticated principal has an admin role before returning all user records, including sensitive fields such as SSN. The supplied code shows no role check after authentication, and no global dependency restricting `/admin/*` routes is visible in the provided context.

**Impact:** Any authenticated user could enumerate all user accounts and view sensitive personal data (including SSN), leading to privacy violations and potential identity theft.

**Remediation:** Add an explicit authorization check that verifies the authenticated user's role is `admin` before executing the query and returning data. For example, retrieve the user's role from `principal` and raise `HTTPException(403)` if the role is not admin. Consider centralizing admin‑only route protection via a dependency or middleware.
Evidence:
- Source IDs: `ai-9879663fa926587d`
- `@app.get("/admin/users") definition at line 277`
- `principal(authorization) called without role verification at line 279`
- `SQL query returning SSN at line 281`

Limitations:
- The implementation of `principal` is not shown; it may already include role verification. No scanner or runtime probe evidence confirming the endpoint is reachable by non‑admin users is provided. Absence of a global admin‑only dependency cannot be confirmed from the excerpt.

### 72. Missing role-based access control on admin job listing

- Issue group: `ai-f52e7301e5e5de98`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint @app.get("/admin/jobs") authenticates the request via `principal(authorization)` but does not verify that the caller has an administrative role before executing a query that returns all job records. The supplied code shows the entry point and the sensitive database query, and the AI analysis flags the absence of a role check as a potential authorization flaw.

**Impact:** An attacker who can obtain a valid authentication token could retrieve the full list of jobs, potentially exposing confidential job details or enabling further attacks such as data harvesting or business intelligence leakage.

**Remediation:** Add an explicit role check after authentication, e.g., verify that the principal's role is "admin" before performing the query. Return a 403 Forbidden response if the role is insufficient. Consider centralizing authorization logic to avoid similar omissions.
Evidence:
- Source IDs: `ai-f52e7301e5e5de98`
- `@app.get("/admin/jobs") defined at api/app.py line 285`
- `principal(authorization) called at line 287 without subsequent role verification`
- `Database query fetching all jobs at line 289`

Limitations:
- No evidence is provided that the `principal` function performs role verification; it appears to only authenticate.
- No runtime or scanner evidence confirms that the endpoint is reachable without admin privileges.
- Missing information about whether other middleware or external policy enforcement might protect this route.

### 73. Insecure session cookie attributes on /session/start

- Issue group: `ai-46240ed0abe60ad2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The code sets a session cookie without HttpOnly, Secure, or SameSite flags. This could allow client‑side scripts or network attackers to read or manipulate the cookie, increasing the risk of session hijacking. No evidence is provided that the cookie is later protected (e.g., transmitted only over HTTPS or validated for integrity).

**Impact:** An attacker who can intercept or access the cookie may impersonate the user’s session, leading to unauthorized actions and data exposure.

**Remediation:** When setting the session cookie, include security attributes, e.g., `response.set_cookie("lab_session", f"session-{user['id']}", httponly=True, secure=True, samesite="Lax")`. Ensure the application enforces HTTPS and validates the session token on each request.
Evidence:
- Source IDs: `ai-46240ed0abe60ad2`
- `api/extra.py:278 – response.set_cookie("lab_session", f"session-{user['id']}")`

Limitations:
- No evidence that the cookie is transmitted over HTTPS only (Secure flag).
- No evidence that the session token is validated for integrity or that additional server‑side protections (e.g., SameSite) are applied elsewhere.

### 74. Potential missing rate limiting on password reset request

- Issue group: `ai-65b6aa0d4acf5f5a`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The `request_reset` endpoint inserts a password‑reset token for a valid user without any visible rate‑limiting, captcha, or other throttling mechanism. The supplied code shows the entry point and the sensitive database insert, and no check for request frequency is present in the excerpt. However, no additional scanner or runtime probe evidence confirms that a global middleware does not apply rate limiting, and the code snippet alone cannot prove the absence of such a guard elsewhere in the application.

**Impact:** An attacker could repeatedly invoke the password‑reset endpoint to enumerate valid usernames (via the 404 response) or flood the `reset_tokens` table, potentially leading to denial‑of‑service or facilitating credential‑reset attacks if tokens are predictable or not sufficiently protected.

**Remediation:** Add explicit rate limiting or CAPTCHA verification for the password‑reset request endpoint. This can be done via middleware (e.g., FastAPI‑RateLimiter) or by implementing per‑IP request counters with exponential back‑off. Ensure that token generation is cryptographically secure and consider limiting the number of active tokens per user.
Evidence:
- Source IDs: `ai-65b6aa0d4acf5f5a`
- <code>api/extra.py:565‑572 shows the `request_reset` function handling a POST to `/auth/reset/request` and inserting a token into `reset_tokens` without any rate‑limiting logic.</code>
- `The code checks only for user existence and raises a 404 if not found; no throttling or request count checks are visible.`

Limitations:
- No evidence is provided that a global rate‑limiting middleware is absent; the review cannot confirm whether such a guard exists elsewhere in the codebase.
- No scanner or runtime probe data demonstrates actual abuse or the lack of rate limiting.
- The snippet does not show the full request handling pipeline, so the presence of external protections cannot be ruled out.

### 75. Potential IDOR in profile endpoint

- Issue group: `ai-1010035e8f9ad623`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `profile` endpoint authenticates the request via `principal(authorization)` but does not show any ownership or role check before querying the database for the requested `profile_id`. The query returns sensitive fields (username, email, SSN) based solely on the supplied identifier, allowing an authenticated user to retrieve another user’s data if no additional access control is applied downstream.

**Impact:** An attacker who can obtain a valid authorization token could enumerate or guess other users' profile IDs and retrieve their personal information, including SSN, leading to privacy breaches and potential identity theft.

**Remediation:** Implement an explicit authorization check after `principal(authorization)`. Verify that the authenticated user’s ID (or role) matches the `profile_id` or that the user has sufficient privileges to view the requested profile. Example: `user = principal(authorization); if user.id != profile_id and not user.is_admin: raise HTTPException(403, "Forbidden")`. Consider centralizing ownership checks in middleware to ensure consistent enforcement across similar endpoints.
Evidence:
- Source IDs: `ai-1010035e8f9ad623`
- <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone()`

Limitations:
- The implementation of `principal` is not provided, so it is unclear whether it returns the user ID or performs additional access checks.
- No evidence of downstream middleware or decorators that might enforce ownership for this route.
- No runtime probe or scanner evidence confirming that the endpoint is reachable without an ownership check.

### 76. Missing admin authorization on admin overview endpoint

- Issue group: `ai-0ec93b5ff3ce9af9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `admin_overview` endpoint calls `principal(authorization)` but does not show any explicit admin‑role verification before executing a query that returns the total number of users. The supplied source excerpt confirms the absence of a direct `require_admin` or similar check in the function body. However, it is unclear whether `principal` performs role checks internally or whether a global route guard applies to this endpoint, so the vulnerability cannot be confirmed.

**Impact:** If any authenticated user can access this endpoint, they could obtain the total user count, which may aid enumeration attacks or disclose sensitive operational metrics.

**Remediation:** Add an explicit admin‑role verification step (e.g., `require_admin(authorization)` or check the user's role after `principal`) before performing the sensitive query, or ensure a global guard restricts the route to admin users only.
Evidence:
- Source IDs: `ai-0ec93b5ff3ce9af9`
- <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]`

Limitations:
- The implementation of `principal` is not provided, so we cannot determine if it enforces admin privileges internally.
- No evidence of a global route guard or decorator that restricts this endpoint to admins is present in the supplied excerpt.

### 77. Potential IDOR in order note retrieval

- Issue group: `ai-a814e72d3f3e01fb`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user owns the order or that the `note_id` belongs to the supplied `order_id`. The SQL query selects a note solely by its primary key, allowing an attacker who can guess a valid `note_id` to retrieve notes from other orders.

**Impact:** Unauthorized disclosure of note contents from other users' orders, which may contain sensitive business or personal information.

**Remediation:** Add an ownership check after retrieving the row (or in the query) that verifies `row['order_id'] == order_id` and that the authenticated principal is authorized to view that order. Return 403 if the check fails. Optionally, include the user ID in the query condition to enforce row‑level security.
Evidence:
- Source IDs: `ai-a814e72d3f3e01fb`, `ai-a93eccda04574b8f`
- <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()`

Limitations:
- The implementation of `principal` is not shown, so we cannot confirm whether it returns order ownership information.
- No database constraints or additional query filters are visible that would prevent cross‑order access.
- No runtime probe or scanner evidence of the vulnerability was provided.

### 78. Potential missing authentication check in user verification endpoint

- Issue group: `ai-954b7b39e9807014`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint `verified_me` extracts an optional Authorization header and passes it to `verified_identity` without any explicit validation of the token's presence or correctness before using the returned user object. If `verified_identity` returns a guest user, None, or does not raise an error for invalid tokens, the function will still return user fields, potentially exposing sensitive information to unauthenticated callers.

**Impact:** Unauthenticated or improperly authenticated requests could retrieve user identifiers and role information, leading to information disclosure and possible privilege escalation if the role data is trusted elsewhere in the application.

**Remediation:** Add explicit validation of the Authorization header before calling `verified_identity`. Ensure `verified_identity` raises an exception or returns an error response (e.g., HTTP 401) for missing or invalid tokens, and handle that case in the endpoint to prevent returning user data without proper authentication.
Evidence:
- Source IDs: `ai-954b7b39e9807014`
- <code>api/extra.py:406-409 defines the `verified_me` endpoint and calls `verified_identity` without a preceding token check</code>

Limitations:
- The behavior of `verified_identity` for missing or invalid tokens is not shown in the supplied code; it is unclear whether it raises an exception, returns None, or returns a default guest user object. Without this information, we cannot confirm that the endpoint is vulnerable.

### 79. Possible IDOR in order retrieval endpoint

- Issue group: `ai-fb702671e0c4dc03`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **low**

**Explanation:** The `verified_get_order` endpoint returns the first element of `owned_order(order_id, authorization)` without any explicit check that the authenticated user actually owns the requested `order_id`. The surrounding code snippet shows a `raise HTTPException(403, "Not your order")` in a different context, but no such guard is present in this function. If `owned_order` merely filters by `order_id` and does not enforce ownership, an attacker could retrieve another user's order by guessing IDs, indicating a potential IDOR flaw.

**Impact:** An attacker who can guess or enumerate order IDs may obtain sensitive order details belonging to other users, leading to privacy breaches and potential misuse of order information.

**Remediation:** Ensure that `owned_order` validates the `authorization` token against the owner of the `order_id` and returns an error (e.g., HTTP 403) when the requester does not own the order. Alternatively, add an explicit ownership check in `verified_get_order` before returning the result.
Evidence:
- Source IDs: `ai-fb702671e0c4dc03`
- <code>def verified_get_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `return owned_order(order_id, authorization)[0]`

Limitations:
- The implementation of `owned_order` is not provided, so we cannot confirm whether it enforces ownership or raises an exception on unauthorized access.
- No runtime probe or scanner evidence demonstrating that the endpoint returns data for unauthorized users.

### 80. Missing security headers on raw file download

- Issue group: `ai-5d2eb62e7e456dde`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The endpoint returns raw file bytes with the stored MIME type but does not set security‑related response headers such as `X-Content-Type-Options` or `Content‑Disposition`. Without these headers a client may sniff the content type or inadvertently execute the file. The code snippet shows the response being constructed directly, and no header manipulation is present in the provided excerpt.

**Impact:** An attacker could exploit MIME‑sniffing to cause the browser to interpret the file as executable content (e.g., HTML or JavaScript), potentially leading to cross‑site scripting or drive‑by download attacks. Lack of a `Content‑Disposition` header may also allow the file to be displayed inline when it should be forced to download, increasing exposure of sensitive data.

**Remediation:** Add appropriate security headers before returning the response, for example:
```python
from fastapi.responses import Response

headers = {
    "X-Content-Type-Options": "nosniff",
    "Content-Disposition": f"attachment; filename=upload_{upload_id}"  # or appropriate filename
}
return Response(content=bytes(row\["body"\]), media_type=row\["mime"\], headers=headers)
```
Consider using a middleware that injects these headers globally for all file downloads, and validate that the stored MIME type is trusted or sanitized before use.
Evidence:
- Source IDs: `ai-5d2eb62e7e456dde`
- <code>def view_upload(upload_id: int) -&gt; Response:</code>
- `row = conn.execute("SELECT mime,body FROM uploads WHERE id=%s", (upload_id,)).fetchone()`
- `return Response(bytes(row["body"]), media_type=row["mime"])`

Limitations:
- No evidence of middleware that might automatically add security headers.
- No verification that the MIME type stored in the database is validated or safe.
- No runtime probe showing how a client interprets the response or whether browsers sniff the content.

### 81. Reflected XSS in comments listing endpoint

- Issue group: `ai-84f7e165c73a051c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The show_comments endpoint returns comment bodies directly embedded in HTML without any escaping or sanitization. This creates a path where attacker‑controlled data can be reflected in the response, leading to stored XSS. No evidence of output encoding, CSP headers, or input sanitization is present in the supplied excerpts.

**Impact:** An attacker who can submit a comment containing malicious JavaScript can have that script executed in the browsers of any user viewing the comments page, potentially leading to session hijacking, credential theft, or other malicious actions.

**Remediation:** Encode comment bodies before inserting them into the HTML response (e.g., use html.escape or a templating engine with auto‑escaping). Consider adding a Content‑Security‑Policy header that restricts script execution. Validate and sanitize comment input on creation as an additional defense-in-depth measure.
Evidence:
- Source IDs: `ai-84f7e165c73a051c`, `ai-fea69c35c039be5c`
- `api/extra.py:174‑177 shows comment bodies concatenated into an HTML string without escaping`

Limitations:
- No evidence is provided that comment bodies are sanitized at input time elsewhere in the codebase.
- No information about response headers (e.g., CSP) that might mitigate XSS impact.

### 82. Missing authorization check on file upload view

- Issue group: `ai-72374f449675e390`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The view_upload endpoint returns the raw file contents based solely on the supplied upload_id. The supplied code excerpt shows no ownership or permission verification before returning the file. However, there is no evidence in the provided context of a global authentication requirement, an owner_id column, or any other guard that might restrict access, so the vulnerability cannot be confirmed.

**Impact:** An attacker could retrieve arbitrary uploaded files, potentially exposing sensitive data or private user content.

**Remediation:** Add an authorization check that verifies the requesting user has permission to access the requested upload (e.g., compare the upload's owner_id with the authenticated user ID) or restrict the endpoint to privileged roles. Return a 403 error when access is denied.
Evidence:
- Source IDs: `ai-72374f449675e390`
- <code>def view_upload(upload_id: int) -&gt; Response:</code>
- `row = conn.execute("SELECT mime,body FROM uploads WHERE id=%s", (upload_id,)).fetchone()`
- `return Response(bytes(row["body"]), media_type=row["mime"])`

Limitations:
- No evidence that the uploads table includes an owner_id or similar field for ownership checks.
- No evidence of a global authentication/authorization dependency applied to the router that could protect this endpoint.
- No runtime probe or scanner evidence confirming that unauthorized access is possible.

### 83. Potential Information Disclosure via detailed error messages

- Issue group: `ai-e88439567759e848`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `/errors/query` endpoint catches any exception from a database query and returns the exception message directly in the HTTP response (`raise HTTPException(500, f"Query failed: {error}")`). This can expose internal details such as SQL error messages or stack traces to unauthenticated callers. No evidence of a guard (e.g., authentication, sanitization, generic error handling) is present in the supplied code excerpt.

**Impact:** Attackers could gain insight into the database schema, query structure, or other internal implementation details, facilitating further attacks such as SQL injection or targeted reconnaissance.

**Remediation:** Replace the detailed exception message with a generic error response. Log the full exception internally for debugging, and consider restricting the endpoint to authenticated/authorized users. Example: `raise HTTPException(500, "Internal server error")` and log `error` securely.
Evidence:
- Source IDs: `ai-e88439567759e848`
- `api/extra.py line 233: raise HTTPException(500, f"Query failed: {error}") from error`

Limitations:
- Only the code snippet is provided; there is no information about surrounding authentication/authorization checks, logging configuration, or whether a global error handler sanitizes responses. Independent scanner or runtime probe evidence confirming the disclosure is absent.

## Policy Decisions

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
- `merged-c5b44871f1955b338344`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-3913d8f00a297cfbf214`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
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
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-54b1ddb055358b3579a2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b7e0b624f8cddd0a9e8c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-767d54ff7a729b156819`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d0789be823f0fd7fa381`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-7ed325c02dd6cf8227d2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-ccc894903304aa8847bd`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-1bcb1da144dffdcf3fd8`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3202e1e1074cfd44b9bf`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-827cbbfd5e460c8b`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-db9083db72a7fa38`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `ai-f651aa6cb2413d9a`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `ai-d0bd0cf4e664f11f`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-3b4a9d4c62593325`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-f3fefb54ee3cb0c0`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-de70ebb6230142e0`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-9879663fa926587d`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-f52e7301e5e5de98`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-46240ed0abe60ad2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-65b6aa0d4acf5f5a`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1010035e8f9ad623`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-0ec93b5ff3ce9af9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-a814e72d3f3e01fb`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-954b7b39e9807014`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-fb702671e0c4dc03`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-5d2eb62e7e456dde`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-84f7e165c73a051c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-72374f449675e390`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-e88439567759e848`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **83**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **36**; scanner overlaps: **0**; AI overlaps: **2**; new candidates: **16**; uncertain overlaps: **4**; needs more evidence: **14**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-827cbbfd5e460c8b`: uncertain_overlap
- `ai-db9083db72a7fa38`: uncertain_overlap
- `ai-ee09ae47f04438e1`: needs_more_evidence
- `ai-3c559642a7f39bbc`: needs_more_evidence
- `ai-a7a082041e0d3b70`: needs_more_evidence
- `ai-a865da888a172436`: needs_more_evidence
- `ai-f3fefb54ee3cb0c0`: uncertain_overlap
- `ai-3b2212c5e5e0ac1a`: needs_more_evidence
- `ai-e3862e2fce213457`: needs_more_evidence
- `ai-179165c1cf368671`: needs_more_evidence
- `ai-547e929267940b52`: needs_more_evidence
- `ai-ab38f58c60904d7a`: needs_more_evidence
- `ai-534d732ae5a4fa8a`: needs_more_evidence
- `ai-65b6aa0d4acf5f5a`: uncertain_overlap
- `ai-fa144252f5178c49`: needs_more_evidence
- `ai-35e708395f2d23f4`: needs_more_evidence
- `ai-a68ca72962b98004`: needs_more_evidence
- `ai-6581110ad653ecec`: needs_more_evidence

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

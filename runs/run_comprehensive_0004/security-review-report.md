# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-05T11:50:14.688879+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **35/35**; model calls: **6**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.

The agent reviewed **80** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **80**; reviewed: **80**; pending: **0**.

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
    - Record: <code>merged-17a5197f906426a224ef</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-210f1029720d2c4e6e3e993a</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_jobs&quot;}</code>.
16. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-da0f922505b4c0c7fed1</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-afddc086f33f2e8a8fa222be</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;stale_role&quot;}</code>.
17. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-38e7cf77bdf9145d2ae4</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-c0e1afff107bb0eb4f9995fc</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_users&quot;}</code>.
18. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-d9421dbfc4162d6dea91</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-6e6caeab05225e629344552e</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;reset_replay&quot;}</code>.
19. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-e7caea540245938b275b</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-0dc83bd580f54eb0cd2941b9</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [401, 403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;debug_access&quot;}</code>.
20. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8e21db3fe42adbf58979</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-3f8d9dc38e0f642bbc4291d3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 401, 403], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;unsigned_hook&quot;}</code>.
21. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-d5c3b6b8d8dad90c4d3c</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-b2db6b94c587ff6fb7d08426</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;invoice_owner&quot;}</code>.
22. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-a5ea8ca4c36bd6c25e2a</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-5ea37fc15cb39757603b7cd7</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;worker_role&quot;}</code>.
23. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-1ba9f8276fc6dae95df8</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-05d2f624905d2e8204ceb2b2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;owner_assignment&quot;}</code>.
24. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-2d4a81712313b5f2f621</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-b9165f8e58d7def0d12de985</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_initial_state&quot;}</code>.
25. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8946f8391fc9049cbb58</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-78580a62c3793f37f5e1f001</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;negative_price&quot;}</code>.
26. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-cc8a9ed20905505868f0</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-b082e5735b56669c3ad0c27e</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200, 201], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;price_catalog&quot;}</code>.
27. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-b4c1c4d005665a5249a7</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-95408e1a46c05125661f435c</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;nested_note&quot;}</code>.
28. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-a9e9047867c909f567ad</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-5f52b3ddf5cb11e03bcb0999</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_owner&quot;}</code>.
29. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-7da23d65adeef42d71a6</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-80c8d131ef8da2487a54950d</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;coupon_bounds&quot;}</code>.
30. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-e683a977084f2bbcee2e</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-b2a4f197f469e50923cacdff</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;paid_cancel&quot;}</code>.
31. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-dd64ece99563dbbb173a</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-4ed77a8cbe072385df677726</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;payment_replay&quot;}</code>.
32. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-2b80ed0c48c0c70a93a4</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-075b1c7547b453cbe6b18b34</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;profile_owner&quot;}</code>.
33. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-65f25bcf14fa2ab91271</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-3165b0fcf5e0b47c5b31d6bd</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;webhook_destination&quot;}</code>.
34. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
35. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
36. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: 40/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
37. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-41e99a7ce6d803bedda1</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-3ae18a34f0a5708c74b36a77</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
38. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-5fe9a08fc103085427f9</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-22ca4c07bddeba21e02773f1</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
39. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-fbfa546bfd43886d2b10</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-5503aaa4e28201d1d3085645</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
40. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: 37/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-dfd8d33b4f84ccf0c23f</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-cc2918cb425bae3d180daa14</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
41. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-553cfc223024a5e03f34</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-197bc06e62c71419a6984565</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
42. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-9b32fbabacaa9f45b768</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-1d3f2eae9b270c563eb2842c</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
43. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-fe76cc1a4803fb50214c</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-fe06d42de0122c9df52f951f</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
44. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-65c41e5a25b6337fec07</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-30173b60257e41bdd229851f</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;excessive_data&quot;}</code>.
45. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: 32/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-50485291173e2448f7c7</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-905604ee346a77ad8a33b929</code>.
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
    - Record: <code>merged-bdfe7542047da39c6151</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-d6fe23474b5bf05b50a68dd9</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
53. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-ec17a70b00fa38747671</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-666123a1a4379f9b0ecad8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
54. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7457580a7c7bb31a32cd</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-f9b4bb2665a94ef114ba70a0</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
55. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-16678dc11308a0a16a81</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8e20c6e4b7bf9daa87ca68c5</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
56. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7c9406875347cad8b1ce</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-7308dae08a226093934e5a0d</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
57. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-ade7b890a037d8c82a1f</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8aa093668e36a5e692db4f28</code>.
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
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string without any sanitisation or parameterisation. This enables an attacker to inject arbitrary SQL code via the username or password fields, leading to authentication bypass or data exfiltration.

**Impact:** An attacker can perform SQL injection to bypass authentication, retrieve or modify user records, and potentially execute arbitrary database commands, compromising confidentiality, integrity, and availability of the application data.

**Remediation:** Refactor the query to use parameterised statements (e.g., prepared statements) provided by the database library. Example: `query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"; row = conn.execute(query, (body.username, body.password)).fetchone()`. Additionally, consider hashing passwords and using secure authentication mechanisms.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117 constructs the query with f‑string interpolation of `body.username` and `body.password``
- `The query string is executed directly via `conn.execute(query)` without sanitisation`

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., input validation elsewhere) was not observed.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter, but it immediately resolves the path and checks `is_relative_to(root)` before accessing the file. This check ensures the resulting path cannot escape the designated `public` directory, effectively mitigating path traversal. The scanner’s generic pattern flagged the use of user input in a path expression, but the subsequent safety check makes the finding non‑exploitable.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server. However, the existing `is_relative_to` guard prevents this, so no confidentiality breach is possible via this endpoint.

**Remediation:** No remediation required for path traversal; the current validation is sufficient. Ensure future code maintains similar checks when constructing file system paths from user input.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 219‑224 show the use of `Path.resolve()` and `is_relative_to(root)` to enforce the file stays within the public directory.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If the runtime uses an older version where this method is unavailable, the check would fail, potentially reintroducing the vulnerability.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks `file.is_relative_to(root)` before accessing the file. This check ensures the resolved path cannot escape the designated `public` directory, effectively mitigating path traversal. The scanner flagged the use of user input in a path expression, but the subsequent safety check makes the finding non‑exploitable.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server. Because the check is present, no unauthorized file disclosure is possible.

**Remediation:** No remediation required; the existing `is_relative_to` guard correctly prevents directory traversal. Ensure future code maintains similar validation when handling user‑controlled paths.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `Source excerpt shows `root = (FILES / "public").resolve()` and `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")` which blocks traversal.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If run on an older version, this method would not exist and the check could be bypassed.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory (FILES / "public") and then checks both that the resolved path is still within that base directory (is_relative_to) and that the target is an existing file (is_file). These checks prevent directory traversal and arbitrary file reads, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** If the checks were bypassed, an attacker could read arbitrary files, but the existing safeguards mitigate this risk.

**Remediation:** No remediation needed; the current validation is appropriate. Ensure that FILES is correctly set to the intended directory and that the runtime environment does not alter path resolution semantics.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Source excerpt shows use of Path.resolve(), is_relative_to(FILES.resolve()), and is_file() checks.`

Limitations:
- The analysis assumes that FILES is a trusted absolute path and that the underlying filesystem respects the semantics of resolve() and is_relative_to. If symbolic links or mount tricks are possible, additional validation may be required.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to(root)`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability in this context.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to data disclosure. However, the existing checks mitigate this risk.

**Remediation:** No remediation needed for this finding; the current implementation correctly validates the path. Maintain the `is_relative_to` and `is_file` checks if the code is modified.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `Source excerpt shows `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")` which blocks paths outside the `public` directory.`
- `The response only returns the file contents after these checks.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If an older runtime is used, this method may not exist, potentially altering behavior. No runtime probe facts were provided to confirm the actual execution environment.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a known base directory and then verifies that the resolved path is still within that base using `is_relative_to`. This prevents directory traversal attacks despite the scanner flagging the use of user input in a path expression. The subsequent `is_file` check also ensures the target exists before reading it.

**Impact:** If an attacker could bypass the path checks, they might read arbitrary files, but the existing checks mitigate this risk.

**Remediation:** No remediation required; the current implementation correctly validates the resolved path. Maintain the use of `resolve()` and `is_relative_to()` for future path handling.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `Source excerpt shows `file = (FILES / "public" / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")` which enforces the path stays within the public directory.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If run on an older version, this check would fail, potentially reintroducing a traversal risk.

### 7. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any escaping or sanitization. The value is also embedded in a SQL query, but the primary issue is that the returned HTML includes `<h1>Results for {q}</h1>` and `<p>{row['name']}</p>` constructed via f‑strings, allowing an attacker to inject arbitrary HTML/JavaScript that will be reflected to the victim's browser.

**Impact:** An attacker can craft a URL such as `/catalog/search?q=<script>alert(1)</script>` which, when visited by a victim, will execute the injected script in the victim's context. This can lead to session hijacking, credential theft, or other malicious actions against users of the application.

**Remediation:** Properly escape or encode user‑provided data before including it in HTML. Use a templating engine that auto‑escapes, or explicitly HTML‑escape `q` and any database‑derived values before insertion. Additionally, employ parameterized queries for the SQL statement to prevent SQL injection.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt shows `def catalog_search(q: str = "") -> str:` with `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)``

Limitations:
- The review is based solely on static code analysis; runtime behavior (e.g., input validation layers) was not observed. No evidence was provided regarding existing output encoding mechanisms elsewhere in the codebase.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory and then checks that the resulting path is still within that base directory using is_relative_to(). This mitigates path traversal, so the finding is a false positive.

**Impact:** None – the path traversal check prevents unauthorized file access.

**Remediation:** No remediation needed; the existing relative path check is sufficient.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- Only static code analysis was considered; runtime behavior was not observed.

### 9. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL statement by directly interpolating the query parameter `q` into the query string using an f‑string. This allows an attacker to supply crafted input that can alter the SQL syntax, leading to SQL injection. The code does not use parameterized queries or any sanitization.

**Impact:** An attacker could execute arbitrary SQL commands, potentially reading, modifying, or deleting data in the `products` table and beyond, leading to data breach, data loss, or privilege escalation.

**Remediation:** Replace the f‑string with a parameterized query using the database driver’s placeholder syntax (e.g., `WHERE name ILIKE %s` with a bound parameter) and validate/escape the input. Consider using an ORM or query builder that enforces safe query construction.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Line 144: `conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'")` directly embeds the user‑provided `q` into the SQL statement.`

Limitations:
- No runtime probe data is available to confirm exploitation; the assessment is based solely on static code analysis.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scan reports that the HTTP response for the root path ("/") does not include the X-Content-Type-Options header, which can allow browsers to perform MIME type sniffing and potentially lead to content injection attacks. The runtime probe confirms a GET request to "/" was made, but no header evidence is provided, indicating the header is indeed absent in the observed response.

**Impact:** An attacker could exploit MIME type sniffing to execute malicious scripts or deliver crafted content that bypasses intended content-type restrictions, increasing the risk of cross-site scripting (XSS) or drive‑by download attacks.

**Remediation:** Configure the web server or application framework to include the header in all responses, e.g., `X-Content-Type-Options: nosniff`. In FastAPI, add a middleware that sets this header for every response.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=zap.10021, path=/, method=GET, values_redacted=true`

Limitations:
- The evidence does not include the actual response headers, only that the probe observed a GET request. Absence of the header is inferred from the scanner finding, not directly verified from the runtime data.

### 11. Unauthorized access to admin job listings

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** A runtime probe accessed the /admin/jobs endpoint with a GET request and received a 200 OK response, whereas the expected statuses for proper access control are 403 or 404. The source code calls a principal() function for authorization, but the probe result indicates that this check did not prevent access, suggesting a missing or ineffective authorization enforcement for this endpoint.

**Impact:** An attacker could retrieve the full list of job entries, potentially exposing sensitive internal data and enabling further enumeration or abuse of administrative functionality.

**Remediation:** Ensure that the principal() function correctly validates the user's role and returns an appropriate error (e.g., 403 Forbidden) when the requester lacks admin privileges. Add explicit role checks before returning job data, and consider returning a generic error to avoid information leakage.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Runtime probe fact: method GET to /admin/jobs returned status 200 (expected 403/404)`
- `Source excerpt shows admin_jobs endpoint calls principal(authorization) but no explicit role verification shown`

Limitations:
- The implementation of principal() is not provided, so it is unclear whether it performs role checks or raises exceptions internally
- Only a single probe request was observed; additional testing with varied credentials would strengthen confidence

### 12. Improper access control on /admin/token-report endpoint

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The token_report handler checks the role of the authenticated token and raises HTTPException(403) only when the role is not "admin". However, runtime probing observed a GET request to /admin/token-report returning HTTP 200, indicating that the role check was bypassed or the token was still considered "admin" after demotion. The source excerpt confirms the role check logic, and the runtime_probe_facts show the assertion result was false (expected 403/404, got 200).

**Impact:** A user whose administrative privileges have been revoked can still access the token-report endpoint and retrieve potentially sensitive information, leading to privilege escalation and data leakage.

**Remediation:** Ensure that role changes are immediately reflected in token validation. Invalidate or re‑issue tokens when a user's role is changed, and verify the role check against the latest user state before granting access. Additionally, add comprehensive tests to confirm that demoted users receive a 403 response.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Source code lines 660‑664 enforce admin role check`
- `runtime_probe_facts: assertion_results false, expected_statuses [403,404] but got status 200`

Limitations:
- Evidence is limited to a single runtime probe of the GET method; other HTTP methods or edge cases were not tested. The probe does not show the exact token used, so the root cause (stale token vs. logic bug) is not definitively identified.

### 13. Improper Access Control on /admin/users endpoint

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users route returns a full list of user records, including sensitive fields such as SSN, without verifying that the authenticated principal has an admin role. The code only calls `principal(authorization)` which appears to validate authentication but does not enforce authorization for admin privileges. Runtime probing observed a 200 OK response for an unauthenticated GET request, whereas the expected statuses were 403 or 404, confirming the lack of proper access control.

**Impact:** An attacker who can obtain or guess a valid authentication token (or exploit any other authentication bypass) can retrieve all user data, including personally identifiable information (PII) and SSNs, leading to privacy violations, identity theft, and compliance breaches.

**Remediation:** Implement role‑based access control (RBAC) on the endpoint. After authenticating the request, verify that the principal's role is 'admin' before executing the database query. Return 403 Forbidden for non‑admin users. Optionally, limit the fields returned to only those necessary for the admin view.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Source excerpt shows the endpoint returns all user columns including ssn without role check (lines 277‑282).`
- `Runtime probe fact reports status 200 for GET /admin/users, while expected statuses were 403 or 404, indicating missing authorization enforcement.`

Limitations:
- The `principal` function's internal logic is not shown; it may perform role checks, but no evidence of such checks is present in the provided excerpt.
- Evidence is limited to a single runtime probe; additional testing with varied authentication states would strengthen confidence.

### 14. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the /auth/form-login endpoint does not include a Content Security Policy header. The source excerpt shows a typical login form implementation but does not reveal any response header configuration. Absence of CSP increases the risk of cross‑site scripting (XSS) and data injection attacks because the browser is not instructed to restrict the sources of scripts, styles, and other resources. Since no explicit evidence of a CSP header being set elsewhere in the codebase was found, the finding is treated as a likely vulnerability.

**Impact:** Without a CSP header, an attacker who can inject malicious script content (e.g., via reflected or stored XSS) may execute arbitrary JavaScript in the victim's browser, leading to credential theft, session hijacking, or other malicious actions.

**Remediation:** Add a strong Content‑Security‑Policy header to the response for the login endpoint (and ideally all application endpoints). For example, set `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';` and adjust directives as needed for the application’s functionality. Ensure the header is added in the response generation code or via middleware.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner evidence: "Content Security Policy (CSP) Header Not Set" for path /auth/form-login`

Limitations:
- The review is based solely on scanner output; actual response headers were not captured during runtime, so the header might be set elsewhere (e.g., via a reverse proxy or framework middleware). No runtime probe data confirming the header's absence was provided.

### 15. Missing Anti-clickjacking Header on Login Page

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /auth/form-login endpoint returns an HTMLResponse without setting any anti-clickjacking headers such as X-Frame-Options or Content-Security-Policy frame-ancestors. The source code shows the response is constructed with `HTMLResponse(...)` and no header is added, and the runtime probe confirms a POST request to this path. This omission allows the page to be embedded in a malicious iframe, enabling clickjacking attacks.

**Impact:** An attacker could embed the login page in a hidden iframe and trick users into submitting credentials, potentially leading to credential theft or session hijacking.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP with `frame-ancestors 'none'`. Ensure all HTML responses include this protection.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Source code at lines 288-301 constructs an HTMLResponse without setting X-Frame-Options or CSP headers.`
- `Runtime probe fact: method POST to /auth/form-login with no header evidence.`

Limitations:
- Evidence is limited to this single endpoint; other endpoints were not examined for similar header omissions.
- The scanner did not capture response headers directly, so the absence is inferred from code rather than observed in live traffic.

### 16. Cookie Missing HttpOnly Flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The form_login endpoint sets a session cookie (lab_session) without specifying the HttpOnly attribute, which can allow client-side scripts to access the cookie. The source excerpt shows response.set_cookie("lab_session", ...) with no HttpOnly flag. The runtime probe confirms the endpoint is reachable via POST, but does not provide additional cookie attribute data.

**Impact:** An attacker who can execute JavaScript in the victim's browser could read the session cookie and potentially hijack the user's session.

**Remediation:** Set the HttpOnly flag when creating the session cookie, e.g., response.set_cookie("lab_session", value, httponly=True).
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `Source excerpt line 300: response.set_cookie("lab_session", f"session-{row['id']}")`

Limitations:
- No runtime observation confirming the HttpOnly attribute is absent; the analysis is based solely on static code.

### 17. Password reset token reuse possible

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe for the POST /auth/reset/confirm endpoint returned HTTP 200, indicating that the provided reset token was accepted and the password was changed. The probe contract expected error statuses (400, 409, 422) for invalid or already‑used tokens, but the observed 200 response suggests the token can be reused, violating the single‑use requirement.

**Impact:** An attacker who intercepts or guesses a valid password‑reset token could reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity of user accounts.

**Remediation:** Enforce single‑use semantics for reset tokens: after a successful password change, delete or invalidate the token in the database. Additionally, return an error (e.g., 400) for any attempt to use a token that has already been consumed.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Runtime probe returned status 200 for POST /auth/reset/confirm with a token that should have been invalid after first use (runtime_probe_facts)`

Limitations:
- The probe observed a single request; it does not confirm that the token was previously used, only that the endpoint accepted the token without error. Additional testing with multiple sequential uses of the same token would strengthen confidence.

### 18. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reports that the /catalog/query endpoint does not include a Content Security Policy header. The source code shows the endpoint returns an HTMLResponse but does not set any security headers. However, without runtime evidence confirming the response headers, it is unclear whether a CSP header might be added by middleware, a reverse proxy, or a web server configuration outside the application code. Additional runtime probing of the actual HTTP response headers is required to confirm the absence of CSP.

**Impact:** Without a CSP header, browsers may allow execution of unsafe inline scripts or loading of resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Configure the application or its deployment environment to include a CSP header on all HTML responses. This can be done by adding middleware that sets the header, configuring the web server (e.g., Nginx, Apache) to add it, or using a framework feature to define a default security policy.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Scanner evidence: Content Security Policy (CSP) Header Not Set`

Limitations:
- No runtime capture of actual response headers was provided; the finding relies solely on static analysis. The presence of external middleware or reverse‑proxy configuration that adds CSP cannot be ruled out.

### 19. Missing X-Content-Type-Options Header on /catalog/query

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for GET /catalog/query does not include the X-Content-Type-Options header. The source code shows the endpoint returns an HTMLResponse without explicitly setting security headers, and no evidence was found that a middleware or framework adds this header automatically. Therefore the finding is plausible, though the scanner alone does not prove the header is absent in all deployment configurations.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response. An attacker who can influence the response content could cause the browser to interpret HTML as a different type (e.g., script), potentially enabling cross‑site scripting or drive‑by download attacks.

**Remediation:** Configure the application or web server to add the header to all responses, e.g., in FastAPI use a middleware: `app.add_middleware(SecurityHeadersMiddleware, x_content_type_options="nosniff")` or set it in the reverse proxy (nginx, Apache).
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Scanner report: X-Content-Type-Options Header Missing on /catalog/query`
- `Source excerpt shows endpoint returns HTMLResponse without header manipulation`

Limitations:
- The review relies on the absence of explicit header setting in the provided code; a global middleware or external proxy could add the header, which is not visible in the snippet. No runtime probe confirmed the header presence or absence beyond the scanner observation.

### 20. Missing Anti-clickjacking Header on /catalog/query

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content via FastAPI's HTMLResponse without setting any X-Frame-Options or Content-Security-Policy frame-ancestors directives. This omission allows the page to be embedded in a foreign site, enabling clickjacking attacks. The scanner flagged the missing header, and the source code excerpt confirms the response is generated without explicit header manipulation.

**Impact:** An attacker could embed the results page in a malicious site and trick users into interacting with it, potentially leading to unauthorized actions or data disclosure.

**Remediation:** Add an appropriate anti-clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response. In FastAPI, this can be done with a middleware or by setting headers in the route handler.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Source excerpt shows HTMLResponse returned without header configuration (lines 148‑153).`
- `Scanner runtime probe reported a GET request to /catalog/query with no evidence of anti-clickjacking headers (web-runtime zap.10020).`

Limitations:
- Only header presence was examined; the application may set security headers globally via middleware not visible in the excerpt.
- No runtime verification of header values beyond the scanner's observation.

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for GET /comments does not include the X-Content-Type-Options header. The source excerpt shows the endpoint returns an HTML string without any explicit response header configuration, and no evidence was found that the header is added globally (e.g., via middleware). This omission can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks.

**Impact:** An attacker could exploit MIME type sniffing to execute malicious scripts if they can influence the response body, increasing the risk of cross‑site scripting or content injection.

**Remediation:** Configure the application to send the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a middleware component or setting the header in the FastAPI response object.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Scanner finding: X-Content-Type-Options Header Missing for path /comments (zap.10021)`

Limitations:
- The review is based solely on the provided source excerpt; the header might be added elsewhere in the codebase (e.g., a global response hook) which was not visible in the excerpt. No runtime probe confirmed the header's presence or absence beyond the scanner report.

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /comments returns HTML content without a Content‑Security‑Policy header. Absence of CSP allows browsers to load scripts, styles, or other resources from any origin, increasing the risk of cross‑site scripting (XSS) and data injection attacks. The scanner flagged this as a missing security header, and the runtime probe confirms the endpoint is reachable via GET.

**Impact:** An attacker who can inject malicious content into comment bodies could execute arbitrary JavaScript in a victim's browser, leading to credential theft, session hijacking, or further compromise of the user’s interaction with the site.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to include a CSP header on all responses, e.g., using Starlette's Middleware or a custom response header: `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"`. Ensure the policy is appropriate for the site’s functionality and test it with security tools.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Scanner evidence: "Content Security Policy (CSP) Header Not Set" for /comments`
- `Runtime probe fact: GET request to /comments returned HTML without CSP header`

Limitations:
- The finding is based on header presence only; it does not confirm that an XSS vector exists in comment data. Additional testing is needed to verify whether comment bodies can be manipulated to inject script content.

### 23. Missing Anti-clickjacking Header on /comments endpoint

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /comments endpoint returns an HTML page constructed from database content without setting any anti-clickjacking headers such as X-Frame-Options or Content‑Security‑Policy frame‑ancestors. The scanner flagged the absence of these headers, and the runtime probe confirms the endpoint is reachable via GET. No evidence was found that the application adds the required headers elsewhere.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into unintended actions or data disclosure.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP `frame-ancestors 'none'`. Ensure the header is applied to all HTML responses, including the /comments route.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Source code for /comments endpoint returns HTML without setting security headers (lines 173‑177).`
- `Runtime probe fact shows a GET request to /comments with no header evidence (scanner_id: web-runtime, rule_id: zap.10020).`

Limitations:
- The review is based on static code and a single runtime probe; it does not verify whether a reverse proxy or middleware might add the header after the application response. No test of actual HTTP response headers was performed.

### 24. Debug configuration endpoint exposed without authentication

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /debug/config endpoint returns internal configuration values (database URL, mock external URL, app secret) on an unauthenticated GET request with HTTP 200. The runtime probe confirms the endpoint is reachable and returns data, while the scanner expected only 401/403/404. This constitutes an information disclosure vulnerability.

**Impact:** An attacker can retrieve sensitive configuration data, including database connection strings and application secrets, enabling further attacks such as database compromise, credential reuse, or service manipulation.

**Remediation:** Restrict access to the /debug/config endpoint to authorized personnel only. Implement authentication and authorization checks (e.g., require admin role) and return a 403/401 for unauthorized requests. Alternatively, remove the endpoint from production deployments.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Source code shows the endpoint returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without any access control (lines 320‑322).`
- `Runtime probe fact: GET /debug/config returned status 200, contradicting expected 401/403/404.`
- `Scanner evidence flagged the endpoint as exposed anonymously.`

Limitations:
- Evidence is limited to a single runtime probe and static code review; does not show whether any external network controls (e.g., firewall) block access in production. No verification of whether the returned values are redacted in the actual response.

### 25. Missing Content-Security-Policy header on /healthz endpoint

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without a Content-Security-Policy (CSP) header. CSP helps mitigate XSS and data injection attacks. Its absence does not constitute an immediate exploit but reduces defense-in-depth.

**Impact:** Potential for client-side script injection attacks if the endpoint is ever served to a browser, especially if future changes introduce reflective content.

**Remediation:** Configure the application or web server to include a strong Content-Security-Policy header on all responses, e.g., `Content-Security-Policy: default-src 'self';`
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=web.missing-content-security-policy, path=/healthz, facts={"status":200}`

Limitations:
- Evidence is limited to a single endpoint (/healthz); other endpoints may already set CSP. No proof that the endpoint is rendered in a browser context.

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner observed that the /healthz endpoint does not include the X-Content-Type-Options header in its response. The source excerpt shows the endpoint returns a JSON payload without any explicit header manipulation, and no evidence was found that the header is set elsewhere in the application. While the missing header is a security‑hardening issue rather than a direct exploit, it reduces protection against MIME type sniffing attacks.

**Impact:** Clients may incorrectly sniff the content type of the response, potentially leading to cross‑site scripting or content injection if the response is interpreted as HTML or another executable type.

**Remediation:** Add the X-Content-Type-Options: nosniff header to all responses, e.g., configure the FastAPI app or the underlying web server to include this header globally or set it explicitly in the healthz endpoint response.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `Scanner runtime probe (zap.10021) reported missing X-Content-Type-Options header on GET /healthz`

Limitations:
- Only the /healthz endpoint was examined; other endpoints may already set the header. No runtime logs or server configuration were provided to confirm header handling elsewhere.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The finding reports that the /healthz endpoint does not include an X-Frame-Options or Content‑Security‑Policy header to prevent clickjacking. This endpoint returns a simple JSON health status and is intended for machine‑to‑machine monitoring, not for rendering in a browser. Clickjacking protection is primarily relevant for HTML content that could be embedded in a frame. The source code shows a straightforward FastAPI route returning JSON, and no HTML is served. No evidence is provided that this endpoint is ever rendered in a browser context, nor that an attacker could exploit framing to perform a clickjacking attack. Consequently, the missing header does not constitute a security vulnerability in this context.

**Impact:** If the endpoint were mistakenly exposed to browsers and embedded in a malicious page, an attacker could potentially trick a user into interacting with the health check response, but the response contains no actionable UI and thus poses negligible risk.

**Remediation:** If organizational policy requires clickjacking protection on all endpoints, add a middleware or response header (e.g., X-Frame-Options: DENY) to the FastAPI application. Otherwise, no remediation is needed for this JSON‑only health endpoint.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Source excerpt shows the /healthz route returns JSON without setting any security headers.`
- `Runtime probe fact indicates a 200 response from /healthz but does not include header information.`

Limitations:
- No runtime observation of response headers was captured; the probe only recorded status code.
- The assessment assumes the endpoint is not served to browsers; if it were, missing headers could be relevant.

### 28. Missing X-Content-Type-Options header on /healthz endpoint

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without the X-Content-Type-Options header. This header helps mitigate MIME type sniffing attacks. While the endpoint returns a simple JSON payload, the absence of the header is a deviation from security‑hardening best practices.

**Impact:** An attacker could potentially influence the browser to interpret the response as a different MIME type, leading to content sniffing attacks such as cross‑site scripting in certain contexts.

**Remediation:** Configure the FastAPI application or the underlying web server to include the header, e.g., add `app.add_middleware(SecurityHeadersMiddleware, x_content_type_options="nosniff")` or set the header in the response within the `healthz` handler.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe fact: status 200 returned from /healthz without X-Content-Type-Options header (web.missing-content-type-protection)`

Limitations:
- The finding is based on a single runtime observation; the header might be added by a reverse proxy not visible in the probe. No source code evidence shows explicit header handling, so the issue could be mitigated elsewhere.

### 29. Incoming webhook events accept unauthenticated requests

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /integrations/hook endpoint processes POST requests without verifying a signature or any form of authentication. Runtime probing observed a successful 200 response for an unsigned request, whereas the expected secure responses were 400, 401, or 403. The source code inserts the raw request body into the database, confirming that no validation occurs before persisting data.

**Impact:** An attacker can craft arbitrary webhook payloads and trigger the endpoint, causing unauthorized data insertion, potential SQL injection (if the body is not properly sanitized), and abuse of any downstream processing that relies on trusted webhook data.

**Remediation:** Implement request signature verification (e.g., HMAC) or another authentication mechanism for the webhook endpoint. Reject requests lacking a valid signature with a 401/403 response. Additionally, sanitize and validate the request body before inserting it into the database, and use parameterized queries to prevent SQL injection.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Source excerpt shows the endpoint directly reads the request body and inserts it into the database without validation (lines 629‑633).`
- `Runtime probe fact: POST to /integrations/hook returned status 200, while expected secure statuses were 400/401/403 (assertion_results false).`

Limitations:
- The analysis is based on a single runtime probe and static code view; it does not confirm whether downstream processing validates the data further. No evidence was provided about existing rate‑limiting or other network‑level protections.

### 30. Missing authorization check on invoice endpoint

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The runtime probe accessed /invoices/{invoice_id} with a GET request and received a 200 OK response, while the expected behavior for an unauthorized request is a 403 or 404. The source code shows a call to `principal(authorization)` but no explicit verification that the authenticated user owns the requested invoice before returning the record. This indicates that any authenticated user (or possibly unauthenticated if `authorization` is None) can retrieve any invoice by ID, violating the intended owner‑only access control.

**Impact:** An attacker who can obtain or guess invoice IDs can read sensitive invoice data belonging to other users, leading to confidentiality breaches and potential financial fraud.

**Remediation:** Implement a proper ownership check after retrieving the invoice record, e.g., compare the invoice's owner ID with the authenticated principal and return 403 if they do not match. Ensure that the `principal` function validates the token and that unauthorized access is blocked before returning data.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Runtime probe fact: GET /invoices/{{invoice_id}} returned status 200 when 403/404 were expected (assertion_results: false).`
- `Source excerpt shows `principal(authorization)` is called but no subsequent ownership verification before `return dict(row)`.`

Limitations:
- The probe does not show the value of the `authorization` header; if the endpoint requires a valid token and the probe used one belonging to the invoice owner, the result may be legitimate. The code snippet does not reveal the implementation of `principal`, so it is unclear whether it performs ownership checks internally. Further testing with different user contexts is needed to confirm the vulnerability.

### 31. Unauthorized job creation endpoint allows admin jobs

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint accepts a request with an Authorization header, calls principal(authorization) but does not enforce role checks before inserting the job. A runtime probe observed a successful 200 response when submitting a job, whereas the scanner expected a 400/403/422 response for unauthorized attempts. This indicates that an unauthenticated or improperly authorized user can create jobs with arbitrary "run_as" values, including admin privileges.

**Impact:** An attacker can create jobs that run with elevated privileges, potentially leading to privilege escalation, data exfiltration, or execution of malicious payloads within the system.

**Remediation:** Implement proper authorization checks in the create_job handler to verify that the caller has the required role before inserting the job. Validate the "run_as" field against allowed values and reject requests from users without admin rights with a 403 response.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Source excerpt shows create_job calls principal(authorization) but no role validation before DB insert`
- `Runtime probe fact: POST /jobs returned status 200, while expected statuses were 400, 403, 422`

Limitations:
- Evidence is based on a single runtime probe; additional testing with varied credentials is needed to confirm role enforcement behavior
- The source code snippet does not show the implementation of principal(), so its effectiveness cannot be fully assessed

### 32. SSN disclosed in /me endpoint response

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint returns the database row for the authenticated user, including the "ssn" column. The source excerpt shows the SELECT query retrieving the ssn field and the returned dict is sent directly to the client. Runtime probe confirms a 200 response from GET /me, indicating the data is reachable. This constitutes exposure of sensitive personal information.

**Impact:** An attacker who can obtain a valid authentication token can retrieve the victim's social security number, leading to identity theft, fraud, and regulatory compliance violations.

**Remediation:** Remove the ssn column from the response payload. Modify the SELECT query to exclude ssn or filter the fields before returning the dict. Implement a data‑privacy policy that only returns necessary user attributes.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Source excerpt line 203: SELECT id,username,role,email,ssn FROM users WHERE id=%s`
- `Runtime probe fact: GET /me returned status 200 with values_redacted true indicating data was returned`

Limitations:
- The finding assumes the requester possesses a valid Authorization header; without authentication the endpoint may be inaccessible. The probe does not show the actual SSN value, only that data was returned. Further testing is needed to confirm that the SSN is not masked or omitted in production configurations.

### 33. Improper owner assignment allows order creation for other users

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `create_order` endpoint assigns `owner_id` from the request body without verifying that it matches the authenticated user's identifier. The code `owner_id = body.owner_id or user["sub"]` permits a caller to specify any `owner_id`, effectively allowing creation of orders on behalf of other users. The runtime probe observed a successful POST to `/orders` returning HTTP 200, whereas the expected statuses included 400, 403, or 422, indicating the missing authorization check.

**Impact:** An attacker can create, modify, or inflate orders for other users, leading to unauthorized transactions, potential financial loss, and violation of data integrity and privacy policies.

**Remediation:** Validate that `owner_id` in the request body matches the authenticated user's `sub` claim, or remove the ability for the client to specify `owner_id` altogether. Example: `if body.owner_id and body.owner_id != user["sub"]: raise HTTPException(status_code=403, detail="Forbidden")`. Alternatively, set `owner_id = user["sub"]` unconditionally.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Source excerpt lines 208-215 show `owner_id = body.owner_id or user["sub"]` without further checks.`
- `Runtime probe fact: method POST to /orders returned status 200, while expected statuses included 400, 403, 422.`

Limitations:
- The review assumes no additional authorization middleware intervenes after this function. If downstream checks exist, the vulnerability may be mitigated. No evidence was provided regarding database constraints or audit logging that could limit impact.

### 34. Order creation endpoint accepts invalid state without proper validation

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a POST request to /orders returned HTTP 200, whereas the scanner expected a 400 or 422 response for invalid input. This indicates that the create_order handler does not enforce required validation or state checks before inserting the order into the database, allowing orders to be created in an unintended state (e.g., not marked as paid).

**Impact:** An attacker could create orders with arbitrary parameters, potentially bypassing payment requirements, leading to financial loss, inventory manipulation, or fraudulent order creation.

**Remediation:** Add input validation and business‑logic checks in the create_order endpoint: verify required fields, enforce allowed status values, and ensure payment is confirmed before persisting the order. Return appropriate error codes (400/422) for invalid requests.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `Runtime probe fact: POST /orders returned status 200 (expected 400/422)`
- `Source excerpt shows create_order inserts directly into DB without prior validation`

Limitations:
- The probe only exercised a single request scenario; other validation paths may exist but were not triggered
- No direct evidence of payment logic being bypassed, only that status code deviates from expectation

### 35. Negative order prices are accepted instead of rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe for the POST /orders endpoint returned HTTP 200 when a negative unit_price was supplied, contradicting the expected 400/422 error. The source code shows the order is inserted without validation of body.unit_price, allowing negative pricing. The scanner’s finding that negative prices should be rejected is therefore not enforced in practice.

**Impact:** An attacker can create orders with negative prices, potentially resulting in credit to the attacker’s account or manipulation of inventory and financial records.

**Remediation:** Add input validation to reject negative unit_price values (e.g., raise HTTPException with status 400 if body.unit_price < 0) before inserting into the database.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Runtime probe fact: method POST to /orders with negative price returned status 200 (assertion_results false)`

Limitations:
- Only a single runtime probe observed; additional tests with varied negative values and different user contexts are needed to confirm consistency.

### 36. Client-controlled unit_price in order creation

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price value directly from the request body into the database without server-side validation or enforcement of catalog pricing. This allows a client to specify arbitrary prices for items, violating the requirement that catalog price must be set by the server.

**Impact:** An attacker can manipulate order prices to underpay for goods or overcharge, leading to financial loss, inventory discrepancies, and potential fraud.

**Remediation:** Enforce server-side pricing by retrieving the official price for the requested item from the product catalog and using that value for unit_price. Reject or ignore any unit_price supplied by the client. Optionally, add validation to ensure the supplied price matches the catalog price before inserting the order.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Source excerpt shows body.unit_price is passed directly to the INSERT statement (lines 213-215).`
- `Runtime probe fact indicates the POST /orders request succeeded with status 200, confirming the endpoint is reachable and processes the supplied data.`

Limitations:
- The review assumes no later middleware or database triggers override the supplied price; such mechanisms were not observed in the provided code.
- No evidence was found regarding additional validation layers outside the shown function.

### 37. Improper authorization check on nested note endpoint

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The GET /orders/{order_id}/notes/{note_id} endpoint retrieves a note by its ID without verifying that the note belongs to the order specified in the URL. The source code shows a query that selects the note solely by note_id and returns it if found, ignoring the order_id parameter. Runtime probing confirms that a request to /orders/1/notes/2 returns HTTP 200, whereas the expected behavior (per the scanner rule) would be a 403 or 404 when the note does not belong to the requested order.

**Impact:** An attacker can enumerate or access notes belonging to other orders by guessing note IDs, leading to unauthorized data disclosure (IDOR). This may expose sensitive order-related information and violate confidentiality requirements.

**Remediation:** Modify the query to include the order_id in the WHERE clause (e.g., SELECT ... FROM notes WHERE id=%s AND order_id=%s) and ensure that a 403/404 is returned when the note does not belong to the specified order. Additionally, add unit/integration tests to verify proper authorization for nested resources.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Source excerpt shows note fetched only by note_id (line 546) and no order_id check`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200, while expected statuses were 403 or 404`

Limitations:
- The review is based on a single code path and one runtime probe; other access control layers (e.g., middleware) could enforce the check, but no evidence of such is present in the provided excerpt.

### 38. Missing ownership check on order retrieval endpoint

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint returns a 200 OK response for a request that should be restricted to the order owner. Runtime probe evidence shows the endpoint responded with status 200 instead of the expected 403 or 404, indicating that the principal() function does not enforce ownership before returning the order data. The scanner finding and source excerpt confirm that the endpoint fetches the order without verifying that the authenticated user owns it.

**Impact:** An attacker who can guess or enumerate order IDs can retrieve any user's order details, leading to unauthorized disclosure of personal and potentially sensitive information.

**Remediation:** Implement an ownership check after retrieving the order record. Compare the authenticated user's identifier (extracted from the Authorization header) with the order's owner field and return 403 Forbidden if they do not match. Example:
```python
order = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
if not order:
    raise HTTPException(404, "order not found")
if order["owner_id"] != get_user_id_from_token(authorization):
    raise HTTPException(403, "forbidden")
return dict(order)
```
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Source excerpt shows endpoint returns order without ownership verification (lines 221-227).`
- `Runtime probe fact: method GET to /orders/{{order_id}} returned status 200, while expected statuses were 403 or 404 (assertion_results false).`

Limitations:
- Evidence is limited to a single runtime probe request; additional testing with different users is needed to confirm that the lack of ownership check is consistent across all cases. The principal() function's internal behavior is not fully visible, so it is possible it performs checks not captured in the probe.

### 39. Excessive coupon discounts are accepted

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe for the POST /orders/{order_id}/apply-coupon endpoint returned HTTP 200 instead of the expected 400/422 when an excessive discount was supplied. The scanner evidence shows that the application updates the order discount with the supplied percent without enforcing upper bounds, allowing a user to apply arbitrarily large discounts. The source excerpt confirms that the discount value is taken directly from the request (or the coupon record) and written to the database without validation.

**Impact:** An attacker can obtain orders with discounts far beyond intended limits, potentially reducing revenue to zero or negative values, and may be able to exploit this to obtain free products or cause accounting inconsistencies.

**Remediation:** Add validation logic to enforce a maximum allowable discount percentage (e.g., <= 50%). Return a 400 Bad Request when the supplied discount exceeds this limit. Ensure that coupon records also enforce bounds on the stored percent value.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Runtime probe fact: method POST, status 200 returned for excessive discount where expected statuses are 400 or 422 (web-runtime rule workflow.coupon_bounds.2).`
- `Source code lines 230-237 show discount is assigned from request body or coupon record without bounds checking.`

Limitations:
- The probe only demonstrates one request scenario; other input validation paths were not exercised. The scanner evidence does not show whether additional business‑logic checks exist elsewhere in the code base.

### 40. Paid orders can be cancelled without refund

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint updates the order status to `cancelled` directly after authorisation, without verifying whether the order has been paid or whether a refund has been issued. The runtime probe observed a successful 200 response for a POST to `/orders/{{order_id}}/cancel`, which contradicts the expected statuses (400, 409, 422) for invalid cancellation attempts, indicating the business rule is not enforced.

**Impact:** An attacker or malicious user could cancel paid orders and potentially receive goods or services without paying or receiving a refund, leading to financial loss and inventory inconsistencies.

**Remediation:** Add logic to verify the order's payment status before allowing cancellation. If the order is paid, require a refund operation to complete successfully before changing the status to `cancelled`. Return appropriate error codes (e.g., 400, 409, 422) when cancellation is not permitted.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Source code shows direct UPDATE of orders status without payment check (lines 258‑263).`
- `Runtime probe fact reports a 200 response for a POST to the cancel endpoint, while expected error statuses were 400, 409, 422.`

Limitations:
- The review assumes the `principal` function only validates authentication and does not enforce payment rules. No explicit check for refund logic is present in the provided snippet, but the full application context is not available.

### 41. Payment replay allowed on already paid order

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The runtime probe observed that a POST to /orders/{order_id}/pay on an order that is already marked as paid returned HTTP 200 instead of an error status such as 400, 409, or 422. The source code shows the endpoint updates the order status to 'paid' without checking whether the order is already in that state before performing the update, allowing a second payment request to succeed and generate a new invoice.

**Impact:** An attacker (or a legitimate user) can submit multiple payment requests for the same order, resulting in duplicate charges, creation of multiple invoices, and potential financial loss or accounting inconsistencies.

**Remediation:** Add a check before processing the payment to verify that the order's status is not already 'paid'. If it is, return an appropriate error (e.g., 409 Conflict). Ensure the payment operation is idempotent, possibly by using a unique payment reference or transaction token and checking for its existence before creating a new invoice.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Runtime probe fact: POST /orders/{{order_id}}/pay returned status 200 (expected 400/409/422)`
- `Source excerpt shows no status check for already‑paid orders before updating status and creating invoice`

Limitations:
- The evidence is limited to a single runtime probe observation; it does not confirm that the endpoint is reachable in all deployment configurations. No information on whether additional business‑logic checks (e.g., payment gateway validation) exist elsewhere in the codebase.

### 42. Insecure Direct Object Reference in profile endpoint

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe accessed /profiles/{{other_id}} with a valid authentication token for a different user and received HTTP 200 with the target user's data. The source code shows the endpoint queries the database by the supplied profile_id without verifying that the authenticated principal owns or is authorized to view that profile. The scanner evidence and runtime observation both indicate that access control is missing, confirming an IDOR vulnerability.

**Impact:** An attacker can retrieve any user's profile information, including username, email, and SSN, leading to privacy breaches, identity theft, and potential further attacks such as phishing or credential stuffing.

**Remediation:** Implement proper authorization checks after extracting the authenticated principal. Verify that the requested profile_id matches the principal's ID or that the principal has explicit permission to view the target profile before executing the query. Return 403 or 404 for unauthorized requests.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `Runtime probe fact: GET /profiles/{{other_id}} returned status 200 (expected 403/404)`
- `Source excerpt shows no ownership check before DB query`
- `Scanner finding flagged missing access control`

Limitations:
- Evidence is limited to a single runtime probe request; additional testing across different roles would strengthen confidence. The probe does not show whether other mitigations (e.g., database row-level security) are in place.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /view endpoint returns an HTML page without any X-Frame-Options or Content‑Security‑Policy frame‑ancestors directives. The source excerpt shows the raw HTML response being returned directly via FastAPI's HTMLResponse, and the runtime probe confirms a GET request to /view was made. No header injection is observed in the code, indicating the anti‑clickjacking header is not set.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into unintended actions such as submitting orders or revealing sensitive information.

**Remediation:** Add an appropriate anti‑clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response. In FastAPI this can be done with a middleware or by setting headers on the HTMLResponse object.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Source excerpt shows HTMLResponse returned without header configuration`
- `runtime_probe_facts indicate a GET request to /view with no header evidence`

Limitations:
- Only the /view endpoint was examined; other endpoints may already set the header globally
- The analysis assumes default FastAPI behavior; custom middleware not shown could add the header

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /view does not include an X-Content-Type-Options header. The source code shows a simple HTMLResponse returned without explicit header manipulation, which is typical for frameworks that may add default security headers based on configuration. No evidence was provided that the application deliberately disables this header, and the runtime probe only captured method and redacted values, not header details. Without concrete proof that the header is absent in actual responses, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header were truly missing, browsers could perform MIME type sniffing, potentially leading to content injection attacks. However, the lack of definitive evidence means the risk cannot be established.

**Remediation:** Ensure the web framework or middleware is configured to add `X-Content-Type-Options: nosniff` to all responses, e.g., by using Starlette/FastAPI middleware or setting the header manually in the response object.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner reported missing X-Content-Type-Options header for GET /view`

Limitations:
- No captured response headers from runtime probe; only method and redacted values were observed
- The source excerpt does not show header handling, and framework defaults are unknown

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/view` returns an HTML page without a `Content‑Security‑Policy` header. The source excerpt shows the response is constructed with `HTMLResponse` and no header manipulation is evident. The runtime probe confirms a GET request to `/view` was made, but no CSP header was observed. Absence of CSP allows injection of malicious scripts and reduces protection against XSS attacks.

**Impact:** Without a CSP header, browsers will not enforce script‑source restrictions, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks against users of the `/view` page.

**Remediation:** Add a CSP header to the response, e.g., `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'"` or configure the framework to include a secure CSP globally for all HTML responses.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Source excerpt shows HTMLResponse returned without header modifications (lines 687‑690).`
- `Runtime probe fact for GET /view reports no header values (values_redacted true).`

Limitations:
- The review is based solely on the provided source snippet and runtime probe; other middleware or reverse‑proxy configurations might add CSP headers that are not visible in this context.

### 46. Webhook destination validation correctly restricts to approved host

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The code explicitly checks that the provided target_url contains the string "mock-external" and raises an HTTP 400 error otherwise. This enforces that only the approved internal mock destination is accepted, matching the intended security policy. The runtime probe shows a 200 response for a request that likely satisfied the check, confirming the validation is functional.

**Impact:** No impact; the endpoint correctly prevents unauthorized webhook destinations.

**Remediation:** No remediation needed; the existing validation is sufficient.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `source_excerpt lines 294-298 show the explicit check and exception raise`
- `runtime_probe_facts indicates the endpoint returned 200 only when the check passed`

Limitations:
- The review assumes the mock-external host is the only approved destination; changes to allowed hosts would require code updates.

### 47. Clear-text logging of application secret

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the value of the environment variable APP_SECRET in clear text using the standard logger. This is confirmed by the source excerpt at line 137, which shows `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`. Logging sensitive secrets can expose them to log aggregation systems, file system access, or accidental disclosure, violating confidentiality best practices (CWE-532).

**Impact:** If an attacker gains read access to the application logs—through compromised host, backup leakage, or log shipping pipelines—they can retrieve the application secret. The secret may be used to forge tokens, decrypt data, or gain privileged access, leading to full system compromise.

**Remediation:** Remove the secret from log statements. Log only non-sensitive identifiers (e.g., username) and avoid interpolating environment secrets. If debugging is required, use a dedicated debug flag and ensure logs are protected with strict access controls. Consider rotating the secret after fixing the logging issue.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `Source excerpt line 137 logs `app_secret=%s` with the value from `os.environ.get("APP_SECRET", "lab-only")`.`
- `Semgrep finding (python.lang.security.audit.logging.logger-credential-leak) flags line 137 as credential disclosure.`

Limitations:
- The review is based solely on static code analysis; it does not verify whether log files are adequately protected at runtime. No runtime probe facts were provided to confirm that the secret is actually written to logs in production.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds a CORSMiddleware with allow_origins set to "*" and also permits all methods and headers. This configuration enables any website to make cross‑origin requests to the API, which can expose sensitive data or allow CSRF‑style attacks if the API relies on cookies or authentication tokens.

**Impact:** An attacker can host a malicious site that reads responses from the API using a victim's browser, potentially leaking data or performing unintended actions on behalf of the user.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains, set allow_methods and allow_headers to only those required, and consider disabling allow_credentials unless explicitly needed. Example: 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted.example.com"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=False,
)
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py line 26: allow_origins=["*"]`
- `api/app.py lines 27-29: allow_credentials=True, allow_methods=["*"], allow_headers=["*"]`

Limitations:
- The snippet does not show how authentication is handled; if the API is completely public and does not rely on cookies or tokens, the risk may be lower. No runtime probe data is available to confirm actual exploitation.

### 49. Potential Log Injection via user-controlled values

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs the username supplied by the client and the application secret without any sanitization. An attacker can craft a username containing control characters or log formatting sequences that may corrupt log files or inject misleading entries. The inclusion of the secret further amplifies the risk if logs are exposed.

**Impact:** Successful log injection can obscure audit trails, facilitate log forgery, or cause denial-of-service on logging infrastructure. Exposure of the APP_SECRET in logs could lead to credential leakage if logs are accessed by unauthorized parties.

**Remediation:** Sanitize or encode user-supplied values before logging. Avoid logging sensitive secrets such as APP_SECRET. Use structured logging with safe parameter handling provided by the logging framework.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- The severity assumes logs are stored in a location accessible to attackers; if logs are strictly internal and protected, impact may be reduced. The logging library may already perform safe formatting, but no explicit sanitization is shown.

### 50. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list checking. An attacker can supply an arbitrary URL, causing the application to redirect users to a malicious site after authentication.

**Impact:** Phishing attacks, credential harvesting, and drive‑by malware distribution can be facilitated by tricking users into following a trusted domain that immediately redirects to an attacker‑controlled site.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a safe whitelist before issuing the redirect.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source excerpt shows `def continue_to(next: str = "/") -> RedirectResponse: return RedirectResponse(next, status_code=302)` at lines 616‑617, indicating the raw user input is used for redirection.`

Limitations:
- The review is based solely on static code analysis; runtime behavior (e.g., additional middleware that might sanitize the parameter) was not observed. No runtime probe facts were provided to confirm actual exploitation.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the 'next' parameter by ensuring it starts with a single '/' and rejects URLs that start with '//' or contain a scheme or netloc. This prevents redirection to external domains, mitigating an open redirect vulnerability.

**Impact:** None, as the code correctly restricts redirects to local paths only.

**Remediation:** No remediation needed; the existing validation is sufficient.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Code checks: if not next.startswith("/") or next.startswith("//") or parts.scheme or parts.netloc: raise HTTPException(400, "Local path required")`

Limitations:
- The analysis assumes the function is the sole entry point for redirects; if other redirect mechanisms exist elsewhere, they are not covered here.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a Docker HEALTHCHECK instruction. While adding a health check is a best practice for container reliability, its omission does not constitute a security vulnerability. The scanner’s evidence is limited to the Dockerfile content and does not demonstrate an exploitable condition.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health monitoring, potentially affecting availability monitoring rather than security.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile lines show no HEALTHCHECK instruction.`

Limitations:
- The assessment is based solely on Dockerfile content; runtime behavior or external health‑check mechanisms are not examined. No direct security impact is demonstrated.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container health monitoring, its absence does not constitute a security vulnerability. It does not directly expose the application to attack, nor does it affect confidentiality, integrity, or availability in a demonstrable way. Therefore, the issue is classified as a false positive in the context of security vulnerability assessment.

**Impact:** No direct security impact; containers may not be automatically restarted on failure, which could affect reliability but not security.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile to monitor container health, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- The assessment is based solely on the Dockerfile content; runtime health monitoring could be implemented externally, which this review cannot verify.

### 54. Missing HEALTHCHECK in Dockerfile

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner flagged the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container observability, its absence does not constitute a security vulnerability by itself. No runtime evidence or exploit path is demonstrated, and the Dockerfile otherwise follows standard patterns.

**Impact:** No direct security impact; containers may not be automatically monitored for liveness or failure, potentially affecting operational reliability rather than confidentiality, integrity, or availability.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`. This improves monitoring but is not required for security.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile snippet shows no HEALTHCHECK line`

Limitations:
- Assessment based solely on static Dockerfile content; no runtime probe data provided to confirm impact. The finding is a configuration recommendation, not a proven exploit vector.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies (CVE-2026-53539)

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53539. The CVE describes a denial‑of‑service condition triggered by specially crafted form‑urlencoded request bodies. The scanner evidence directly cites this CVE and notes that the vulnerability is fixed in version 0.0.30. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can send a maliciously crafted request to the FastAPI application, causing the python-multipart parser to consume excessive resources and potentially crash or become unresponsive, leading to service disruption.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version is installed by checking the lock file or running `pip freeze`.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies on the scanner’s CVE mapping; no runtime probe confirming exploitation was available.

### 56. Denial of Service via excessive multipart part headers in python-multipart 0.0.20

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by crafted multipart requests with an excessive number of part headers. The scanner evidence directly references this CVE and notes that the issue is fixed in version 0.0.27. No mitigating controls or runtime checks were observed that would prevent exploitation.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially causing the FastAPI service to become unresponsive, leading to service outage and loss of availability.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later. Update the requirements.txt entry accordingly and redeploy the application. Optionally add input validation or rate limiting for multipart uploads as defense‑in‑depth.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- The review relies on the scanner’s CVE mapping; no runtime probe confirming exploitation was available.

### 57. python-multipart: Information disclosure due to parser differential in form data handling (CVE-2026-53538)

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The CVE describes an information disclosure issue caused by differential handling of multipart form data parsing. The scanner identified this dependency and the associated CVE, and no mitigating version is used.

**Impact:** An attacker could craft multipart requests that cause the library to leak sensitive data from memory or request bodies, potentially exposing user credentials or other confidential information processed by the application.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The finding is based solely on the declared dependency version; no runtime evidence of exploitation was observed.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-40347, a denial‑of‑service issue triggered by specially crafted multipart/form-data payloads. The scanner identified this dependency and the associated CVE. No evidence was found that the application upgrades or patches this library, nor that it is unused, so the vulnerability remains present in the dependency tree.

**Impact:** An attacker could send a malicious multipart request that exhausts server resources, potentially causing service disruption or crash of the FastAPI application.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, which contains the fix for CVE-2026-40347. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`

Limitations:
- The review assumes the listed dependency is installed and used at runtime; if the package is never imported or is overridden by another version, the impact may be reduced. No runtime probe confirms the vulnerable code path is reachable.

### 59. python-multipart 0.0.20 contains CVE-2026-24486 (arbitrary file write via path traversal)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project's requirements.txt pins python-multipart at version 0.0.20. This version is known to be vulnerable to CVE-2026-24486, which allows an attacker to perform arbitrary file writes through crafted multipart filenames that include path traversal sequences. The scanner identified this CVE and noted that the issue is fixed in version 0.0.22.

**Impact:** An attacker who can influence multipart upload filenames could write files to arbitrary locations on the server's filesystem, potentially leading to remote code execution, privilege escalation, or defacement of the application.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, and verify that the new version is included in the requirements.txt and installed in the deployment environment. Optionally, add validation of uploaded filenames to reject path traversal patterns as a defense-in-depth measure.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- No runtime probe evidence was provided to confirm exploitation in the running application. The finding relies solely on the known vulnerability of the pinned library version.

### 60. python-multipart 0.0.20 contains CVE-2026-53537 (information disclosure)

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to be vulnerable to CVE-2026-53537, which allows information disclosure via header parsing discrepancies. The scanner evidence directly references this CVE and notes that the issue is fixed in version 0.0.30.

**Impact:** An attacker could craft multipart requests that cause the server to leak sensitive header information, potentially exposing authentication tokens or other confidential data.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, and verify that the new version resolves the CVE. Update the requirements.txt accordingly and run dependency reconciliation.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies on the scanner's CVE mapping; no runtime probe was performed to confirm exploitability in the specific application context.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53540. The vulnerability allows an attacker to supply a negative Content‑Length header, causing the library to allocate the full request body in memory, leading to potential denial‑of‑service. The scanner identified this exact version and the associated CVE, and no mitigating version is present in the requirements.

**Impact:** An attacker can trigger excessive memory consumption on the server, potentially exhausting resources and causing service disruption or crash.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, where the CVE is fixed. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`

Limitations:
- The review relies on the scanner's CVE mapping; no runtime probe was performed to confirm the vulnerable code path is exercised. No additional context about usage of python-multipart in the codebase was provided.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **low**

**Explanation:** The finding flags a urllib request that concatenates a constant BASE URL with a path argument. No evidence is provided that the path value can be attacker‑controlled, nor that the request ever uses a file:// scheme. The code appears to be part of an internal test helper that sends JSON payloads to a known API endpoint. Without proof of untrusted input reaching the URL, the risk of arbitrary file reads is speculative.

**Impact:** If an attacker could influence the path and cause a file:// URL, they might read local files. In the current code there is no demonstrated path injection, so the impact is unproven.

**Remediation:** Review the request function to confirm that `path` is never derived from untrusted user input. If there is any possibility of external control, switch to the `requests` library or validate/sanitize the URL before use. Otherwise, no changes are required.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows a static BASE constant combined with a `path` argument; no dynamic scheme handling is present.`

Limitations:
- No runtime probe data confirming attacker‑controlled values
- No evidence that the function is exposed to external input
- Finding based solely on heuristic detection of urllib usage

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a urllib.request.urlopen call that uses a URL taken from payload["target_url"]. While urllib can handle file:// URLs, there is no evidence that the input is attacker‑controlled or that file:// schemes are allowed. No runtime probe facts or additional context confirm that an untrusted user can influence the URL value, nor that the request is used in a security‑critical context. Therefore the finding cannot be confirmed as a vulnerability without further analysis of input validation and allowed URL schemes.

**Impact:** If an attacker could supply a malicious URL, they might trigger server‑side request forgery (SSRF) or read local files via file://, potentially leading to data disclosure or internal network access. However, the current evidence does not demonstrate that such control exists.

**Remediation:** Review the code that populates payload["target_url"] and ensure it validates or sanitizes the value, restricting schemes to http/https and rejecting file:// or other unsafe schemes. Consider using a higher‑level HTTP library (e.g., requests) that does not support file:// by default, and add explicit checks before making the request.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows urllib.request.urlopen called with payload["target_url"] (lines 17‑23).`
- `Scanner evidence notes dynamic value may allow arbitrary file reads.`

Limitations:
- No runtime probe data confirming attacker‑controlled input.
- No evidence of scheme validation or whitelist enforcement.
- No context about how payload is sourced (trusted internal service vs. external user).

### 64. Potential missing admin role verification in admin_audit endpoint

- Issue group: `ai-acc4ae3d9aae07c9`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The admin_audit endpoint calls require_admin but the implementation of require_admin is not present in the provided repository snapshot. Without seeing how require_admin validates the authorization header, it cannot be confirmed that non‑admin users are prevented from accessing this endpoint. The evidence shows the call exists, but the role check is unverified.

**Impact:** If require_admin does not correctly enforce admin role checks, an attacker could invoke /admin/audit and gain unauthorized access to administrative audit functionality, potentially exposing sensitive system information or enabling further privileged actions.

**Remediation:** Locate and review the implementation of require_admin. Ensure it validates the provided token or header, extracts the user's role, and explicitly denies access unless the role is 'admin'. Add unit tests and code comments to make the enforcement clear. If missing, implement proper role verification and return appropriate HTTP 403 responses for unauthorized access.
Evidence:
- Source IDs: `ai-acc4ae3d9aae07c9`
- `204: @router.get("/admin/audit")`
- `205: def admin_audit(authorization: str | None = Header(default=None)) -> dict:`
- `206:     require_admin(authorization)`
- `207: return {"status": "authorized"}`

Limitations:
- The source does not include the definition of require_admin, so its behavior is unknown.
- No runtime observations or tests confirming that non‑admin requests are rejected.

### 65. Potential missing authentication check in file_read endpoint

- Issue group: `ai-3094736a8dbd903e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /files endpoint serves files from the public directory without any explicit authentication or authorization checks in the examined code. While the path validation prevents directory traversal, any client can request arbitrary files that exist under the public folder, which may contain sensitive data if such files are placed there. The surrounding code snippet shows a require_admin call earlier, but it is not applied to this route, and no global middleware evidence is provided.

**Impact:** Unauthorized users could retrieve files that are intended to be private, leading to information disclosure of potentially sensitive content stored in the public directory.

**Remediation:** Add authentication and authorization checks to the /files endpoint (e.g., depend on a security dependency or decorator). Consider restricting the served directory to only intended public assets and ensure no sensitive files reside there. If a global auth middleware is intended, verify it is applied to this router.
Evidence:
- Source IDs: `ai-3094736a8dbd903e`
- `210: @router.get("/files")`
- `211: def file_read(name: str) -> Response:`
- `212:     file = (FILES / "public" / name).resolve()`
- `213:     if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214:         raise HTTPException(404, "File not found")`
- `215:     return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The review cannot confirm whether a global authentication middleware protects this route, as no such evidence is present in the provided excerpt.
- The analysis assumes the public directory is not intended to expose all files; if it is deliberately public, the risk may be mitigated.

### 66. Potential missing authentication on verified_file_read endpoint

- Issue group: `ai-ffdf7e41dd3fadea`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint @router.get("/files/verified") returns the contents of a file from the public directory without any visible authentication or authorization checks in the function body. However, the repository may apply authentication globally via middleware, dependencies, or route-level security that is not shown in the excerpt. Without confirming the presence or absence of such controls, the risk cannot be definitively assessed.

**Impact:** If unauthenticated users can access this endpoint, they may read arbitrary files within the configured public directory, potentially exposing sensitive information.

**Remediation:** Ensure that access to the verified_file_read endpoint is protected by appropriate authentication and authorization checks, either within the handler or via globally applied security middleware. Validate the requested file name against an allow‑list if only specific files should be exposed.
Evidence:
- Source IDs: `ai-ffdf7e41dd3fadea`
- `api/extra.py lines 218‑224 define the route and return file contents without any auth checks`

Limitations:
- No evidence was found regarding global authentication middleware or dependencies that might protect the route
- The analysis is limited to the provided code excerpt; additional project configuration could affect the actual security posture

### 67. Sensitive user data exposure in /me endpoint

- Issue group: `ai-6328790674377ad5`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /me endpoint returns the full user record including the SSN field after authenticating the request via the principal() function. No additional authorization, role check, or data minimization is performed before returning the record, allowing any authenticated user to retrieve their own SSN and potentially other users' SSNs if the token can be spoofed or compromised. This constitutes an information disclosure risk for highly sensitive personal data.

**Impact:** Exposure of Social Security Numbers can lead to identity theft, fraud, and regulatory non‑compliance (e.g., GDPR, HIPAA). Even if only the owner’s SSN is returned, the practice of exposing such data via an API increases attack surface and may be leveraged in credential‑theft scenarios.

**Remediation:** - Remove the SSN field from the response payload unless absolutely required.
- Implement fine‑grained authorization checks (e.g., role‑based access control) before returning sensitive fields.
- Apply data minimization: only return non‑sensitive attributes (id, username, email) by default.
- Log access to sensitive fields and monitor for anomalous patterns.
- Review and harden the principal() token validation to ensure it cannot be spoofed.
Evidence:
- Source IDs: `ai-6328790674377ad5`
- `199: @app.get("/me")`
- `200: def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `201:     user = principal(authorization)`
- `202:     with connection() as conn:`
- `203:         row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()`
- `204:     return dict(row or {})`

Limitations:
- The review assumes principal() correctly authenticates the caller but does not verify its implementation; if principal() enforces stricter checks, the risk may be reduced.
- The code snippet does not show whether downstream middleware masks or strips SSN before serialization; absence of such logic is inferred from the provided excerpt.

### 68. Missing ownership check in order retrieval endpoint

- Issue group: `ai-739e3bff94113c81`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint authenticates the request via the principal() call but does not verify that the authenticated user is the owner of the requested order. The code directly queries the order by ID and returns the row without any ownership validation, allowing any authenticated user to retrieve any other user's order data.

**Impact:** Unauthorized disclosure of order details (personal information, purchase history, payment data) across user accounts, leading to privacy violations and potential fraud.

**Remediation:** Add an ownership check after fetching the row, e.g., compare row["owner_id"] (or equivalent) with the user identifier extracted from the authorization token. Return 403 Forbidden if the IDs do not match. Consider centralising this check in middleware or a helper function and enforce role‑based exceptions for admin users if required.
Evidence:
- Source IDs: `ai-739e3bff94113c81`
- `220: @app.get("/orders/{order_id}")`
- `222: principal(authorization)`
- `224: row = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()`
- `227: return dict(row)`

Limitations:
- The review assumes the order table contains an owner identifier column; the actual schema is not shown.
- Potential role‑based access control could be applied elsewhere (e.g., middleware) which is not visible in the provided excerpt.

### 69. Missing ownership check in order creation (owner_id override)

- Issue group: `ai-236fbac4ed9d5a06`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and falls back to the authenticated user's sub only when owner_id is falsy. No validation is performed to ensure that a non‑admin caller cannot supply a different owner_id. This allows a user to create orders on behalf of any other user, leading to an authorization bypass. The source excerpt shows the assignment `owner_id = body.owner_id or user["sub"]` and the subsequent INSERT without any role check.

**Impact:** An attacker can create orders for other users, potentially causing unauthorized charges, data pollution, or escalation to further actions tied to those orders. If order IDs are later used for access control, this could lead to broader privilege escalation.

**Remediation:** Add a check that either (a) body.owner_id is omitted or matches the authenticated user's sub, or (b) the caller has an admin/privileged role before allowing a different owner_id. Example: `if body.owner_id and body.owner_id != user["sub"] and not user_has_role(user, "admin"): raise HTTPException(status_code=403, detail="Forbidden")`. Also consider removing owner_id from the request schema for regular users and deriving it solely from the token.
Evidence:
- Source IDs: `ai-236fbac4ed9d5a06`
- `api/app.py line 210: `owner_id = body.owner_id or user["sub"]``
- `api/app.py line 213: INSERT statement uses `owner_id` directly from the request`
- `source_excerpt shows no validation of owner_id against the principal`

Limitations:
- The review assumes no other middleware or decorator enforces role checks for this endpoint; such checks were not present in the provided excerpts. If a global authorization layer exists elsewhere, the risk may be mitigated. No runtime probe data was provided to confirm actual enforcement.

### 70. Potential path traversal bypass in verified_file_read

- Issue group: `ai-89c3110b383d7890`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The function attempts to prevent directory traversal by using pathlib.Path.is_relative_to after resolving the requested path. This method is only available in Python 3.9+, and the code does not include a fallback for older versions, which could raise an AttributeError and skip the check. Additionally, the check does not account for symbolic links that could point outside the intended root directory. However, the repository does not specify the Python runtime version, nor does it show whether symlinks exist in the public directory. Without concrete evidence of the runtime environment or filesystem layout, the presence of a bypass cannot be confirmed.

**Impact:** If an attacker can supply a crafted filename that causes is_relative_to to fail or bypass the check, they may read arbitrary files on the server, potentially exposing sensitive configuration or data.

**Remediation:** Ensure the service runs on Python 3.9+ or add a fallback check for older versions (e.g., compare the commonpath of root and file). Resolve symlinks safely and verify that the final resolved path remains within the root directory. Consider using a dedicated safe file serving library that handles these edge cases.
Evidence:
- Source IDs: `ai-89c3110b383d7890`
- `api/extra.py lines 218-224 show the use of is_relative_to without additional realpath validation`
- `The code resolves both root and file before the check, but does not resolve symlinks beyond that`
- `No runtime version information is provided in the repository`

Limitations:
- Cannot confirm the Python version used at runtime
- Cannot determine presence of symlinks in FILES/public
- The check may be sufficient on supported Python versions; lack of evidence prevents a definitive vulnerability claim

### 71. Missing admin role enforcement on /admin/users endpoint

- Issue group: `ai-941733c28c13fe84`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/users calls `principal(authorization)` which appears to only authenticate the request. No subsequent check verifies that the authenticated principal has an admin role before returning all user records, including sensitive fields such as SSN. This could allow any authenticated user to enumerate all users and view sensitive data.

**Impact:** Unauthorized disclosure of user data, including personally identifiable information (SSN), and potential abuse of admin‑only functionality by non‑admin users.

**Remediation:** Add an explicit role check after authentication, e.g., verify that `principal(authorization)` returns a role of "admin" and raise HTTPException(403) otherwise. Ensure that the SSN column is only returned to authorized admin users or remove it from the response.
Evidence:
- Source IDs: `ai-941733c28c13fe84`, `ai-a5f542dc452c245f`
- `def admin_users(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:`
- `principal(authorization)`
- `rows = conn.execute("SELECT id,username,email,role,ssn FROM users ORDER BY id").fetchall()`

Limitations:
- The actual implementation of `principal` is not shown; it may include role verification internally, but no evidence of that is present in the provided source excerpt. No global middleware or decorator evidence is available to confirm additional authorization checks.

### 72. Missing admin role enforcement on /admin/jobs endpoint

- Issue group: `ai-ba4ddfef5910e1bb`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs endpoint authenticates the request via `principal(authorization)` but does not perform any explicit check that the authenticated principal has an administrative role before returning all job records. Without such a check, any valid user token could retrieve internal job data, constituting an authorization flaw.

**Impact:** Unauthorized users may enumerate or view all job records, potentially exposing sensitive operational information and enabling further attacks based on job data.

**Remediation:** Add a role check after extracting the principal, e.g., verify that `principal.role == "admin"` and return HTTP 403 for non‑admin users. Consider applying a decorator or middleware that enforces admin access for all `/admin/*` routes.
Evidence:
- Source IDs: `ai-ba4ddfef5910e1bb`, `ai-89d0c339ce05b350`
- `def admin_jobs(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:`
- `principal(authorization)`
- `rows = conn.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()`

Limitations:
- The review does not have visibility into the implementation of `principal`; it may embed role information, but no role verification is observed in this function.
- Potential global middleware or route guards could enforce admin checks, but no evidence of such mechanisms is present in the provided excerpts.

### 73. Missing ownership check on order cancellation endpoint

- Issue group: `ai-ac4f3ad1dab9581a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated principal owns the order or has a role that permits cancellation. The SQL UPDATE is executed unconditionally for any supplied `order_id`, allowing any authenticated user to cancel arbitrary orders.

**Impact:** An attacker who can obtain a valid authentication token can cancel any user's order, leading to denial of service, financial loss, and potential abuse of business processes.

**Remediation:** Add an ownership/authorization check before performing the UPDATE, e.g., retrieve the order's `owner_id` and compare it to the principal's user ID or required role, and return HTTP 403 if the check fails. Consider using parameterized queries and enforcing row‑level security in the database.
Evidence:
- Source IDs: `ai-ac4f3ad1dab9581a`, `ai-67905af39b9db57f`
- `def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `principal(authorization)`
- `row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone()`

Limitations:
- The actual implementation of `principal` is unknown; it may embed ownership checks internally, but no evidence is present in the source excerpt.
- Database schema and triggers are not visible; there could be a trigger enforcing ownership, but this is not demonstrated.

### 74. Missing ownership check on invoice retrieval

- Issue group: `ai-a2d45197e47f7713`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated principal is authorized to access the specific invoice identified by `invoice_id`. The code fetches the invoice row directly from the database and returns it without checking an owner identifier or role, which could allow any authenticated user to retrieve other users' invoices if they know the IDs.

**Impact:** Unauthorized disclosure of invoice data, potentially exposing sensitive financial information of other users and violating confidentiality requirements.

**Remediation:** Add an ownership/authorization check after retrieving the row, e.g., compare `row["user_id"]` (or similar) with the authenticated principal's ID or verify the principal has an admin role. Return HTTP 403 if the check fails. Consider centralizing access control in a policy layer.
Evidence:
- Source IDs: `ai-a2d45197e47f7713`, `ai-53b178d929004de2`
- `api/app.py:268 – endpoint definition `def invoice(invoice_id: int, authorization: str | None = Header(default=None))``
- `api/app.py:269 – call to `principal(authorization)` (authentication only)`
- `api/app.py:271 – database query `SELECT * FROM invoices WHERE id=%s` without additional filters`
- `api/app.py:274 – returns `dict(row)` directly`

Limitations:
- The review assumes the `invoices` table contains a user identifier column; the source does not show its schema. It is possible that a downstream policy layer (not shown) enforces ownership checks, but no evidence of such a layer is present in the provided excerpts. Further code review is needed to confirm the absence of hidden checks.

### 75. Missing ownership check on profile endpoint may expose other users' SSN

- Issue group: `ai-bd653994d51dcb96`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The `profile` endpoint retrieves a user record (including SSN) based solely on the supplied `profile_id` after calling `principal(authorization)`. No code is shown that verifies the authenticated user's identity matches `profile_id` or that the caller has a role permitting access to other users' profiles. If `principal` only checks token presence, an attacker could supply arbitrary `profile_id` values and obtain sensitive data of other accounts, constituting an IDOR risk.

**Impact:** Unauthorized disclosure of personally identifiable information (PII), including SSN, could lead to identity theft, regulatory violations, and reputational damage.

**Remediation:** Enforce ownership or permission checks before querying the database. For example, compare the authenticated user's ID (extracted from the token in `principal`) with `profile_id`, or require a role check that authorizes viewing other users' profiles. Return a 403 Forbidden when the check fails.
Evidence:
- Source IDs: `ai-bd653994d51dcb96`
- `api/extra.py:98 defines `def profile(profile_id: int, authorization: str | None = Header(default=None)) -> dict:``
- `api/extra.py:99 calls `principal(authorization)` with no further checks`
- `api/extra.py:101 executes `SELECT id,username,email,ssn FROM users WHERE id=%s` using the supplied `profile_id``
- `api/extra.py:104 returns `dict(row)` containing the SSN`

Limitations:
- The behavior of `principal` is not shown; it may perform additional authorization checks not visible in the excerpt
- Potential global middleware or decorators could enforce access control, but no evidence is provided in the supplied context

### 76. Potential missing verification of reset token generation entropy

- Issue group: `ai-7d60b89d619d5b85`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code inserts a reset token into the database and returns it, but the snippet does not show how the `token` variable is generated. Without evidence that a cryptographically secure random function (e.g., secrets.token_urlsafe) is used, it cannot be confirmed that the token has sufficient entropy. The source excerpt confirms the insertion and return of the token, but the generation step is omitted, leaving uncertainty about token strength and any expiration or one‑time‑use enforcement.

**Impact:** If the reset token is generated with low entropy, an attacker could guess valid tokens and reset user passwords, leading to account takeover.

**Remediation:** Ensure the reset token is generated using a cryptographically secure random generator such as `secrets.token_urlsafe` or `os.urandom`, enforce sufficient length/entropy, store a hash of the token if possible, and implement expiration and one‑time use checks.
Evidence:
- Source IDs: `ai-7d60b89d619d5b85`
- `Source excerpt shows insertion of `token` into `reset_tokens` table and return of the token (lines 571‑573).`
- `No code for token generation is present in the provided excerpt, leaving the method of creation unknown.`

Limitations:
- The review is based solely on the provided code excerpt; the actual token generation may be secure elsewhere in the file or imported module.
- No runtime or probe data is available to confirm the token's entropy or usage policies.

### 77. Potential missing rate limiting on password reset request endpoint

- Issue group: `ai-fb4cd22a266134f9`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code creates a password‑reset tokens for any supplied username without any visible throttling, captcha, or other rate‑limiting mechanism. While this could allow an attacker to enumerate usernames or flood the `reset_tokens` table, the repository does not show any global middleware or decorator that might apply rate limiting, nor does it show token expiration logic. Without confirming the presence or absence of such protections, the risk cannot be definitively assessed.

**Impact:** If unmitigated, an attacker could repeatedly invoke the endpoint to enumerate valid usernames (by observing the 404 vs success response) and insert a large number of rows into `reset_tokens`, potentially exhausting database storage or causing denial‑of‑service conditions.

**Remediation:** Add explicit rate‑limiting (e.g., per‑IP request counters) or captcha to the `/auth/reset/request` endpoint. Ensure reset tokens have a short TTL and are cleaned up regularly. Document any global rate‑limiting middleware so reviewers can verify its coverage.
Evidence:
- Source IDs: `ai-fb4cd22a266134f9`
- `api/extra.py lines 564‑573 show the endpoint definition and insertion into `reset_tokens` without any surrounding rate‑limit logic`
- `source excerpt confirms no conditional check for request frequency or captcha`

Limitations:
- The scan does not include the full application configuration; a global FastAPI middleware or external gateway could enforce rate limiting
- Token expiration and cleanup logic may exist elsewhere in the codebase and were not examined

### 78. Missing rate limiting / token reuse check on password reset request

- Issue group: `ai-616314bbe2231399`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code creates a password‑reset token for any existing username without any apparent rate‑limiting, token‑reuse, or cooldown checks. This could allow an attacker to generate many tokens for a user, potentially leading to email flooding or token enumeration. However, the repository excerpt does not show any surrounding logic (e.g., background cleanup jobs, global rate‑limit middleware, or token‑entropy checks) that might mitigate the issue. Without evidence of such controls, the impact cannot be confirmed.

**Impact:** If an attacker can repeatedly trigger the endpoint, they may overwhelm a user with reset emails or increase the chance of guessing a valid token, leading to account compromise or denial‑of‑service for the password‑reset flow.

**Remediation:** Implement a rate‑limit on the password‑reset request endpoint (e.g., per IP or per user) and enforce a cooldown period before a new token can be issued. Store a timestamp with each token and reject requests that would create a new token within the cooldown window. Additionally, ensure token generation uses sufficient entropy and consider expiring old tokens automatically.
Evidence:
- Source IDs: `ai-616314bbe2231399`
- `@router.post("/auth/reset/request") at api/extra.py:564`
- `def request_reset(body: dict) -> dict: at api/extra.py:565`
- `conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"])) at api/extra.py:571`

Limitations:
- The snippet does not include any surrounding middleware or configuration that might enforce rate limiting.
- No information is provided about token cleanup jobs or token entropy generation.
- The repository context is untrusted; conclusions are based solely on the shown code excerpt.

### 79. Missing verification of reset token ownership in verified reset request endpoint

- Issue group: `ai-e6cabdc356e8e7ba`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `verified_reset_request` handler creates a password‑reset token for a user based solely on a supplied username. The code selects the user record and then inserts a new token without checking any prior proof that the requester owns the reset request (e.g., a valid reset token, email link click, or other out‑of‑band verification). This allows an attacker who knows a valid username to obtain a reset token arbitrarily, potentially leading to account takeover.

**Impact:** An attacker can generate valid password‑reset tokens for any existing user account, enabling password reset and full account compromise without needing prior authentication or token possession.

**Remediation:** Add a verification step before token issuance, such as requiring a valid, unexpired reset token that was sent to the user's email, or implement a separate email‑based confirmation flow. Ensure the endpoint validates that the request originates from a trusted source and that the user has completed the required verification step before inserting a new token.
Evidence:
- Source IDs: `ai-e6cabdc356e8e7ba`
- `@router.post("/auth/reset/verified-request") (line 589)`
- `def verified_reset_request(body: dict) -> dict: (line 590)`
- `user = conn.execute("SELECT id FROM users WHERE username=%s", (str(body.get("username", "")),)).fetchone() (line 592)`
- `conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"])) (line 596)`

Limitations:
- The review is based only on the provided source excerpt; there may be middleware or other application logic not shown that performs additional verification.
- The exact contents of the `[REDACTED]` section (line 595) are unknown and could contain relevant checks.
- No runtime or deployment context was provided to confirm how the endpoint is invoked in production.

### 80. Potential overexposure of user SSN in profile endpoint

- Issue group: `ai-be02fd3e481ad3ea`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /profiles/{profile_id} endpoint queries the users table and returns the SSN field in the response without any ownership or role‑based access control check after authentication. The only guard present is a call to principal(authorization), which validates the token but does not appear to restrict access to the SSN. This pattern can allow any authenticated user to retrieve another user’s SSN, constituting a privacy breach.

**Impact:** Unauthorized disclosure of Social Security Numbers can lead to identity theft, fraud, and regulatory non‑compliance (e.g., GDPR, HIPAA).

**Remediation:** Add an authorization check that ensures the requester is either the owner of the profile or has a role that permits viewing SSNs. Alternatively, remove the SSN column from the SELECT statement and provide a separate, tightly controlled endpoint for privileged access. Ensure that principal() returns role information that can be used for such checks.
Evidence:
- Source IDs: `ai-be02fd3e481ad3ea`
- `@router.get("/profiles/{profile_id}") at api/extra.py:97`
- `principal(authorization) at api/extra.py:99`
- `row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone() at api/extra.py:101`
- `return dict(row) at api/extra.py:104`

Limitations:
- The implementation of principal() is not shown; it might embed role information that could be used for downstream checks.
- There may be downstream middleware or response filters that strip the SSN before sending it to the client, but no evidence of such filtering is present in the provided excerpts.

## Policy Decisions

- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-bdfe7542047da39c6151`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-17a5197f906426a224ef`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-da0f922505b4c0c7fed1`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a5ea8ca4c36bd6c25e2a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-65c41e5a25b6337fec07`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-1ba9f8276fc6dae95df8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-cc8a9ed20905505868f0`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-b4c1c4d005665a5249a7`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a9e9047867c909f567ad`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-7da23d65adeef42d71a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e683a977084f2bbcee2e`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-dd64ece99563dbbb173a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2b80ed0c48c0c70a93a4`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-50485291173e2448f7c7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ade7b890a037d8c82a1f`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-dfd8d33b4f84ccf0c23f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-65f25bcf14fa2ab91271`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-acc4ae3d9aae07c9`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-3094736a8dbd903e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-ffdf7e41dd3fadea`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-6328790674377ad5`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-739e3bff94113c81`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-236fbac4ed9d5a06`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-89c3110b383d7890`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-941733c28c13fe84`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ba4ddfef5910e1bb`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ac4f3ad1dab9581a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-a2d45197e47f7713`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-bd653994d51dcb96`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-7d60b89d619d5b85`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-fb4cd22a266134f9`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-616314bbe2231399`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-e6cabdc356e8e7ba`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-be02fd3e481ad3ea`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **80**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **29**; scanner overlaps: **0**; AI overlaps: **4**; new candidates: **12**; uncertain overlaps: **5**; needs more evidence: **8**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-07682f951082c8e4`: needs_more_evidence
- `ai-b326ddb6694ef010`: needs_more_evidence
- `ai-89c3110b383d7890`: uncertain_overlap
- `ai-a3719f0b8802ff85`: needs_more_evidence
- `ai-841c70d21cbb8b88`: needs_more_evidence
- `ai-29abb79eab5aecff`: needs_more_evidence
- `ai-7d60b89d619d5b85`: uncertain_overlap
- `ai-43095f2278edaed0`: needs_more_evidence
- `ai-fb4cd22a266134f9`: uncertain_overlap
- `ai-5d2ea1578b27fd8e`: needs_more_evidence
- `ai-3c441ce5c9871180`: needs_more_evidence
- `ai-616314bbe2231399`: uncertain_overlap
- `ai-be02fd3e481ad3ea`: uncertain_overlap

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

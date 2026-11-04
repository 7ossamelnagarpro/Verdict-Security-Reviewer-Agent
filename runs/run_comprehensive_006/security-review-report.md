# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-02T12:31:40.090847+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **4**.
- AI Discovery warning: Discovery batch 2: AI provider request failed with HTTP 400 (json\_validate\_failed); model output 0 chars, not valid JSON; retrying with a smaller request.

The agent reviewed **68** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **68**; reviewed: **68**; pending: **0**.

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
53. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-5230c114e62065082a9b</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-726acbb49bc074d3b384aea7</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
54. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-ec17a70b00fa38747671</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-666123a1a4379f9b0ecad8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
55. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7457580a7c7bb31a32cd</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-f9b4bb2665a94ef114ba70a0</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
56. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-16678dc11308a0a16a81</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8e20c6e4b7bf9daa87ca68c5</code>.
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

### 1. SQL Injection in legacy_login endpoint

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login function constructs an SQL query by directly interpolating the user‑provided username and password into the query string without any sanitisation or parameterisation. This allows an attacker to inject arbitrary SQL code via the username or password fields, potentially retrieving or modifying data in the users table.

**Impact:** An attacker could bypass authentication, retrieve user credentials, modify or delete records, and potentially execute further database commands, leading to data breach and loss of integrity.

**Remediation:** Refactor the query to use parameterised statements provided by the database library (e.g., prepared statements or ORM query methods). Example: `query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"; row = conn.execute(query, (body.username, body.password)).fetchone()`. Additionally, consider hashing passwords and using secure authentication mechanisms.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Source excerpt shows f‑string interpolation of `body.username` and `body.password` into the SQL query (lines 117‑119).`
- `Scanner categorised this as a SQL injection risk (group_family: sql_injection).`

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., input validation elsewhere) was not observed. No runtime_probe_facts were provided to confirm exploitation.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code constructs a file path from a user‑provided `name` and then resolves it against a known root directory. It subsequently checks `file.is_relative_to(root)` and `file.is_file()` before reading the file. These checks prevent directory traversal and ensure the target is an existing file within the intended directory, mitigating the reported path‑traversal risk.

**Impact:** If the checks were bypassed, an attacker could read arbitrary files, leading to information disclosure. However, the built‑in `Path.is_relative_to` guard correctly blocks paths that escape the `public` directory, so the vulnerability does not materialize.

**Remediation:** No remediation required for this specific finding; the existing validation is sufficient. Maintain the `is_relative_to` check and consider adding explicit sanitization or a whitelist of allowed filenames for defense‑in‑depth.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 219‑224 show the use of `root = (FILES / "public").resolve()` and `file = (root / name).resolve()` followed by `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- The analysis assumes the Python version provides `Path.is_relative_to` (Python 3.9+). If an older runtime is used, this method may not exist, potentially altering behavior. No runtime probe facts were provided to confirm the actual execution environment.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks `file.is_relative_to(root)` before accessing the file. This check ensures the resolved path cannot escape the designated `public` directory, effectively mitigating path traversal. The scanner’s generic pattern flagged the use of user input in a path expression, but the code includes proper containment logic.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server, leading to information disclosure. However, the existing `is_relative_to` guard prevents this, so no impact is present.

**Remediation:** No remediation needed for path traversal; the current relative‑path check is sufficient. Ensure future modifications retain this guard and consider adding explicit validation of allowed filename characters for defense‑in‑depth.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source_excerpt lines 218‑224 show the use of `Path.resolve()` and `is_relative_to(root)` to enforce the file stays within the public directory.`

Limitations:
- The review assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If run on an older interpreter, this method would not exist, potentially causing a runtime error and bypassing the check.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory (FILES / "public") and then checks both that the resolved path is still within that base directory using `is_relative_to(FILES.resolve())` and that the target is an existing file with `is_file()`. These checks prevent directory traversal attacks, so the scanner’s finding is not indicative of a vulnerability.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server. However, the explicit relative‑path and file‑existence checks mitigate this risk.

**Remediation:** No remediation required; the existing checks are appropriate. Ensure that `FILES` is correctly set to the intended public directory and that the application runs with least‑privilege file permissions.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Source lines 211‑214 show the path resolution and safety checks: `file = (FILES / "public" / name).resolve(); if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- The review assumes `FILES` is a trusted absolute path and that the filesystem semantics of `is_relative_to` are reliable on the target platform.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the scanner’s warning is not applicable here.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, potentially exposing sensitive data. However, the implemented checks mitigate this risk.

**Remediation:** No remediation needed for this finding; the existing path validation is sufficient. Ensure that future code maintains similar checks when handling user‑supplied paths.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `source_excerpt lines 220‑224 show the use of `root = (FILES / "public").resolve()` and `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")` which correctly restricts access to files within the public directory.`

Limitations:
- The review assumes that `FILES` is correctly set to the intended public directory and that the Python version supports `Path.is_relative_to`. If either assumption is false, the protection could be bypassed.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory (FILES / "public") and then verifies that the resulting path is still within that base directory using is_relative_to(FILES.resolve()) and that it points to an existing file. These checks prevent directory traversal attacks, making the scanner’s path‑traversal finding inaccurate.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to data disclosure. However, the explicit relative‑path check mitigates this risk.

**Remediation:** No remediation required; the existing validation is sufficient. Ensure that the FILES constant is correctly set to the intended public directory and that resolve() does not follow symlinks that could bypass the check.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `Source excerpt shows the use of Path.resolve() followed by is_relative_to(FILES.resolve()) and is_file() checks.`

Limitations:
- The analysis assumes that FILES is a trusted absolute path and that resolve() does not introduce symlink‑resolution issues. If symlinks inside the public directory point outside, additional checks may be needed.

### 7. Reflected XSS in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint returns an HTML response that directly interpolates the user‑controlled query parameter `q` into the page without any escaping or sanitisation. This allows an attacker to craft a request such as `/catalog/search?q=<script>alert(1)</script>` and have the payload reflected in the `<h1>` element, leading to script execution in the victim's browser.

**Impact:** An attacker can execute arbitrary JavaScript in the context of the vulnerable application, enabling session hijacking, credential theft, defacement, or further attacks against users of the site.

**Remediation:** Validate and sanitise the `q` parameter before embedding it in HTML. Use a templating engine that auto‑escapes output or explicitly HTML‑escape the value (e.g., `html.escape(q)`). Consider implementing a Content‑Security‑Policy header that restricts script execution. If the endpoint is intended to return plain text, switch to a non‑HTML response type.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`, `ai-1b53ee3c5be1bee0`
- `api/extra.py:142 defines `catalog_search(q: str = "")``
- `api/extra.py:144 executes a raw SQL query with `q` interpolated`
- `api/extra.py:145 returns `f"<h1>Results for {q}</h1>" + ...` without escaping`

Limitations:
- No information was provided about global response headers such as Content‑Security‑Policy that might mitigate script execution
- The surrounding code does not show any downstream sanitisation of `q` before the return statement

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` and then calls `Path.resolve()` followed by a check `is_relative_to(FILES.resolve())` and `is_file()`. These checks ensure the resolved path is inside the allowed `FILES/public` directory and that the target exists, mitigating path‑traversal exploitation. No evidence shows the checks can be bypassed (e.g., via symlinks or race conditions).

**Impact:** If the checks were bypassed, an attacker could read arbitrary files on the server, leading to information disclosure. However, the current logic appears to prevent such access.

**Remediation:** No remediation required for path traversal; maintain the existing relative‑path validation and consider adding additional hardening such as symlink resolution checks or operating‑system level file access controls.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `api/extra.py:212-215 shows the path is resolved and validated with `is_relative_to` and `is_file` checks.`

Limitations:
- The analysis assumes `Path.is_relative_to` correctly prevents directory escape and that no race conditions or symlink tricks are present. Runtime behavior (e.g., filesystem permissions) is not verified.

### 9. Potential SQL Injection in catalog_search endpoint

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function catalog_search constructs an SQL query by directly interpolating the user‑controlled parameter `q` into the query string using an f‑string. This allows an attacker to inject arbitrary SQL syntax, which will be executed by the database when `conn.execute` runs the query.

**Impact:** An attacker could manipulate the `q` parameter to retrieve unauthorized data, modify or delete records, or execute database commands, leading to data breach, data loss, or privilege escalation.

**Remediation:** Use parameterized queries or prepared statements instead of string interpolation. For example, replace the f‑string with a query that uses placeholders and passes `q` as a parameter, ensuring proper escaping. Also consider validating or sanitizing input and limiting the returned fields.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt shows f‑string interpolation of `q` into SQL query at line 144: `conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'")``

Limitations:
- No runtime probe data is available to confirm exploitation; the assessment is based solely on static code analysis.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding reports that the HTTP response for the root path (GET /) does not include the X-Content-Type-Options header. The source excerpt shows only the FastAPI route implementation and does not reveal any middleware or response configuration that would add security headers. No runtime probe evidence confirms the header is absent; the probe only records the request method and redacted values. Without concrete evidence that the header is missing in actual responses, the issue cannot be confirmed as a vulnerability.

**Impact:** If the header were truly missing, browsers could perform MIME type sniffing, potentially leading to content injection attacks. However, the lack of evidence means the impact cannot be established.

**Remediation:** Ensure that the application adds the X-Content-Type-Options: nosniff header to all responses, e.g., by using Starlette/FastAPI middleware or configuring the web server to set the header.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `Source excerpt shows only route definitions; no header handling is visible.`
- `Runtime probe fact records a GET request to '/' but does not include response headers.`

Limitations:
- No captured response headers to verify the header's presence or absence.
- The scanner evidence is limited to a rule match without concrete response data.

### 11. Improper access control on /admin/jobs endpoint

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs route calls a principal() function but does not enforce an admin role check before returning job data. Runtime probing observed a successful GET request returning HTTP 200 instead of the expected 403/404, indicating that unauthorized users can access administrative job listings.

**Impact:** Unauthorized users can view, enumerate, and potentially infer sensitive job information, leading to information disclosure and facilitating further attacks such as targeted phishing or privilege escalation.

**Remediation:** Implement proper role-based access control: verify that the authenticated principal has an admin role before querying and returning job data, and return HTTP 403 for non‑admin requests. Consider using a dedicated dependency or decorator to enforce admin checks consistently.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Runtime probe fact: GET /admin/jobs returned status 200 (expected 403/404)`
- `Source code shows admin_jobs endpoint calls principal() but lacks explicit admin role verification`

Limitations:
- The principal() function implementation is not shown; it may perform checks internally, but the observed 200 response suggests it does not reject non‑admin users
- Only a single runtime probe was performed; additional testing with varied credentials would strengthen confidence

### 12. Improper access control on /admin/token-report endpoint

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The token_report endpoint checks the role of the caller and raises a 403 when the role is not "admin". However, runtime probing observed a 200 OK response for a GET request to /admin/token-report, indicating that the role check was bypassed or not enforced, allowing a demoted administrator (or any user) to obtain an authorized response. This constitutes an access control flaw where a non‑admin can access an admin‑only resource.

**Impact:** An attacker without administrative privileges can retrieve the token report or other sensitive information intended for administrators, potentially leading to privilege escalation or exposure of confidential data.

**Remediation:** Enforce proper role verification before returning any data. Ensure that the token's role is validated and that a 403 response is returned for non‑admin users. Consider adding additional authorization middleware and unit tests to verify that only admin roles receive a 200 response.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Source code shows role check at line 663‑664 with HTTPException(403) for non‑admin`

### 13. User listing endpoint exposes sensitive data without proper authorization

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users endpoint returns a full list of user records, including sensitive fields such as SSN, when accessed with a valid request. Runtime probing observed a 200 OK response where a 403/404 was expected, indicating that the authorization check (principal) does not enforce admin-only access for this route. The source code shows the endpoint calls principal(authorization) but no explicit role verification before querying the database, allowing any authenticated (or possibly unauthenticated) request to retrieve all user data.

**Impact:** An attacker can enumerate all user accounts and obtain personally identifiable information (PII) and sensitive identifiers (e.g., SSN), leading to privacy violations, identity theft, and potential further attacks against user accounts.

**Remediation:** Implement strict role-based access control on the /admin/users endpoint: verify that the authenticated principal has an admin role before executing the database query. Return 403 Forbidden for non-admin users. Additionally, limit the fields returned to only those necessary for the admin view, and consider masking or omitting highly sensitive data such as SSN.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Runtime probe returned status 200 for GET /admin/users, while expected statuses were 403 or 404 (assertion_results: false).`
- `Source excerpt shows endpoint definition without role check: def admin_users(...): principal(authorization) ... return all user rows.`

Limitations:
- The exact behavior of principal() is not shown; it may perform some checks not visible in the excerpt. The probe did not test unauthenticated requests, so the impact on unauthenticated users is uncertain. Further testing is needed to confirm whether any authentication token is required.

### 14. Missing Content Security Policy (CSP) Header

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scan reports that the response for the /auth/form-login endpoint does not include a Content Security Policy header. The provided source excerpt shows the endpoint implementation but contains no code that sets security headers such as Content‑Security‑Policy. Without a CSP, the application is vulnerable to injection of malicious scripts via reflected or stored content, potentially enabling cross‑site scripting attacks.

**Impact:** An attacker who can inject HTML or JavaScript into pages served by this endpoint could execute arbitrary code in the victim's browser, leading to credential theft, session hijacking, or other malicious actions.

**Remediation:** Add a strict Content‑Security‑Policy header to all responses, preferably via a middleware or response‑processing hook. Example (FastAPI):
```python
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
        return response
```
Ensure the policy is tailored to the application's legitimate resource needs and test thoroughly.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner finding: Content Security Policy (CSP) Header Not Set for /auth/form-login`
- `Source code excerpt shows no header being set in the form_login handler`

Limitations:
- The review is based solely on the absence of explicit CSP header setting in the provided code snippet and the scanner report; it does not confirm that a global middleware or reverse‑proxy might be adding the header elsewhere. Additional runtime verification would be needed to rule out external header injection.

### 15. X-Content-Type-Options Header Missing

- Issue group: `merged-5230c114e62065082a9b`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner reports that the response from /auth/form-login does not include the X-Content-Type-Options header. The provided source excerpt shows the login endpoint implementation but does not reveal any response header handling. No runtime probe facts confirm the header’s presence or absence beyond the scanner’s observation. Additional evidence such as actual HTTP responses captured during testing is required to confirm the finding.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of resources, potentially allowing content‑type confusion attacks.

**Remediation:** Ensure that all HTTP responses include the header `X-Content-Type-Options: nosniff`. This can be added globally via middleware or per‑route response handling.
Evidence:
- Source IDs: `merged-5230c114e62065082a9b`
- `Scanner reported missing X-Content-Type-Options header on POST /auth/form-login`

Limitations:
- No direct runtime observation of response headers was provided; the claim relies solely on scanner output. The source code excerpt does not show header manipulation, so the absence cannot be confirmed without captured traffic.

### 16. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The form_login endpoint returns an HTMLResponse without setting the X-Frame-Options or Content-Security-Policy frame-ancestors directives, which are required to mitigate clickjacking attacks. The source code shows no call to response.headers.add or similar to add these headers.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and trick users into submitting credentials, leading to credential theft or session hijacking.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., response.headers['X-Frame-Options'] = 'DENY' or configure a Content-Security-Policy with frame-ancestors 'none'. Ensure this is applied to all HTML responses.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `source_excerpt indicates response = HTMLResponse(...) without header manipulation`

Limitations:
- No runtime HTTP response was captured to confirm the header is absent; the assessment is based solely on static code analysis.

### 17. Cookie missing HttpOnly flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The form_login endpoint creates a session cookie using response.set_cookie("lab_session", ...) without specifying the HttpOnly attribute. This allows client-side scripts to access the cookie, increasing the risk of theft via XSS. The scanner flagged the missing HttpOnly flag and the source excerpt confirms the cookie is set without HttpOnly.

**Impact:** An attacker who can inject JavaScript into the application could read the session cookie and hijack user sessions, leading to unauthorized access.

**Remediation:** Set the HttpOnly flag when creating the session cookie, e.g., response.set_cookie("lab_session", ..., httponly=True). Consider also adding Secure and SameSite attributes.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `source_symbol line 300: response.set_cookie("lab_session", f"session-{row['id']}")`

Limitations:
- The code snippet does not show other cookie attributes; if HttpOnly is set elsewhere (e.g., via middleware) this finding may be a false positive. No runtime observation confirms the cookie is sent without HttpOnly.

### 18. Password reset tokens may be reusable

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code retrieves a reset token from the database and, if it exists, updates the user's password without invalidating or deleting the token. No evidence is present that the token is marked as used or removed after a successful reset, allowing an attacker who obtains a valid token to reuse it for multiple password changes.

**Impact:** An attacker who intercepts or guesses a valid reset token could reset the victim's password repeatedly, leading to account takeover and loss of confidentiality and integrity of user data.

**Remediation:** Invalidate or delete the reset token after a successful password reset. Implement a one‑time‑use flag in the reset_tokens table and enforce a check that the token has not been used before proceeding with the password change.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Source excerpt shows token is selected and, if found, password is updated without token invalidation (lines 579‑585).`
- `Runtime probe fact indicates the POST to /auth/reset/confirm returned status 200 instead of expected error codes, suggesting the workflow allowed the reset without rejecting reused tokens.`

Limitations:
- The snippet does not show the full lifecycle of the token (e.g., possible triggers elsewhere that delete or expire it).
- No explicit evidence that the token is not deleted in a separate function or database trigger.

### 19. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the HTTP response for GET /catalog/query does not include a Content‑Security‑Policy header. The source code shows the endpoint returns an HTMLResponse built from user‑controlled query parameters, but there is no explicit setting of CSP headers in the route or globally in the application. Absence of CSP allows injection of malicious scripts into the rendered page, increasing XSS risk.

**Impact:** Without a CSP header, an attacker who can influence the query string or database content may inject malicious JavaScript that browsers will execute, leading to data theft, session hijacking, or other client‑side attacks.

**Remediation:** Configure a CSP header either globally via middleware (e.g., Starlette's `BaseHTTPMiddleware` or FastAPI's `add_middleware`) or per‑route using `Response.headers['Content‑Security‑Policy'] = "default-src 'self'"`. Ensure the policy restricts script sources and disallows unsafe inline scripts.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Scanner runtime probe (zap.10038) observed a GET request to /catalog/query with no CSP header present.`

Limitations:
- Evidence is limited to a single scanner observation; no additional runtime or manual verification of response headers was performed. The finding does not confirm whether other middleware or reverse proxies might add CSP headers downstream.

### 20. X-Content-Type-Options Header Missing

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the X-Content-Type-Options header is absent on the /catalog/query endpoint. The provided source code shows the endpoint returns HTML but does not set response headers. However, without observing an actual HTTP response (runtime_probe_facts only indicate a GET request without header details), we cannot confirm whether the header is truly missing or omitted by the scanner. Additional runtime evidence (e.g., captured response headers) is required.

**Impact:** If the header is indeed missing, browsers may perform MIME type sniffing, potentially leading to content injection attacks such as cross‑site scripting.

**Remediation:** Configure the FastAPI response to include the header, e.g., using `Response(headers={"X-Content-Type-Options": "nosniff"})` or a middleware that adds the header to all responses.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Scanner reported missing X-Content-Type-Options header for GET /catalog/query`

Limitations:
- No captured HTTP response showing actual headers; runtime probe does not include header data. Unable to verify header presence or absence from code alone.

### 21. Missing Anti-clickjacking Header on /catalog/query

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting the X-Frame-Options or Content-Security-Policy frame-ancestors directives, which are used to prevent clickjacking attacks. The scanner flagged the absence of these headers, and the source code shows a direct HTMLResponse without any header manipulation.

**Impact:** An attacker could embed the page in a hidden iframe on a malicious site and trick users into performing unintended actions, potentially leading to credential theft or other user‑initiated attacks.

**Remediation:** Add appropriate anti‑clickjacking headers to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP with `frame-ancestors 'none'`. Ensure the headers are set for all HTML responses.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Source excerpt shows HTMLResponse returned without header modifications (lines 148‑153).`
- `Runtime probe fact indicates a GET request to /catalog/query was observed (scanner_id:web-runtime, rule_id:zap.10020).`

Limitations:
- The review is based on static code analysis and a single runtime probe; it does not confirm that other middleware might add the headers later in the request chain.

### 22. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for GET /comments does not include the X-Content-Type-Options header. The source excerpt shows the endpoint returns an HTML string without any explicit response header manipulation, and no middleware or framework configuration is visible that would add security headers. This suggests the header is indeed absent, which can allow browsers to perform MIME type sniffing and potentially lead to content injection attacks.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may incorrectly interpret the content type of the response, increasing the risk of cross‑site scripting (XSS) or other injection attacks if an attacker can influence the response body.

**Remediation:** Configure the application or web server to include the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a middleware component, setting the header in the FastAPI response, or configuring the reverse proxy (nginx, Apache) to add the header globally.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Scanner runtime probe (zap.10021) observed a GET request to /comments with no X-Content-Type-Options header`

Limitations:
- The source excerpt does not show the full application stack; headers could be added by upstream middleware, a reverse proxy, or a framework setting not visible in the provided code. Further verification of the actual HTTP response headers in the deployed environment is required.

### 23. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns HTML content without a Content‑Security‑Policy header. The source excerpt shows the route returns a raw HTML string and no middleware or response modification adds security headers. The runtime probe confirms a GET request to /comments was made, but no CSP header was observed. Absence of CSP increases the risk of cross‑site scripting (XSS) and data‑injection attacks because browsers have no policy restricting script sources.

**Impact:** An attacker who can inject malicious JavaScript into comment bodies could execute that script in the browsers of users viewing the page, leading to session hijacking, credential theft, or other client‑side attacks.

**Remediation:** Configure the application to send a strong CSP header on all responses, e.g., using FastAPI middleware or a reverse‑proxy (nginx, Apache) to add: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';` Adjust directives as needed for legitimate resources.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Source excerpt shows HTML is returned directly without CSP header handling`
- `Runtime probe fact for GET /comments shows no CSP header present`

Limitations:
- The review is based on static code and a single runtime probe; it does not confirm whether a reverse‑proxy or external service might add CSP headers in production
- No evidence of actual script injection in comment data was found

### 24. Missing Anti-clickjacking Header

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /comments endpoint returns an HTML response without an X-Frame-Options or Content‑Security‑Policy frame‑ancestors directive. The source excerpt shows the route returns raw HTML strings and no header manipulation is evident. The runtime probe confirms a GET request to /comments was made, but no anti‑clickjacking headers were observed.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into unintended actions or data disclosure.

**Remediation:** Add an appropriate X-Frame-Options header (e.g., SAMEORIGIN or DENY) or a CSP frame‑ancestors directive to the response. This can be done globally via middleware or specifically for the /comments route.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Source excerpt lines 173‑177 show the HTML response is constructed without setting security headers.`
- `Runtime probe fact for path /comments indicates a GET request was made and no header values were reported.`

Limitations:
- The review is based on the provided snippet; headers might be added elsewhere in the application stack (e.g., middleware) that is not shown in the excerpt.

### 25. Debug configuration endpoint exposes sensitive data

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /debug/config endpoint returns a JSON object containing DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without any authentication or authorization checks. Runtime probing observed a 200 OK response for an unauthenticated GET request, whereas the expected behavior was a 401/403/404. This confirms that sensitive configuration data is publicly accessible.

**Impact:** An attacker can retrieve database connection strings and application secrets, enabling database compromise, credential reuse, and further lateral movement within the environment.

**Remediation:** Restrict access to the /debug/config endpoint by adding authentication and authorization checks, or remove the endpoint from production deployments. Ensure that sensitive values are not exposed in responses and consider using environment‑specific configuration that is not exposed via HTTP.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Source excerpt shows the endpoint returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET (lines 321‑322).`
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404 (assertion_results false).`

Limitations:
- Evidence is limited to the observed runtime response; does not assess whether additional internal checks might be applied elsewhere in the code base.

### 26. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The finding reports that the /healthz endpoint does not include a Content-Security-Policy header. The source code shows a simple health‑check endpoint that returns a JSON payload and does not set any security headers. While adding CSP is a best practice for pages that render HTML/JS, it is not required for a JSON‑only health endpoint and many services omit CSP on such endpoints. No evidence was provided that the lack of CSP poses a concrete risk for this specific route.

**Impact:** Minimal – the endpoint returns static JSON and is not rendered in a browser, so the absence of CSP does not expose the application to typical CSP‑related attacks such as script injection.

**Remediation:** If a CSP header is desired for consistency, add it via a middleware or response header configuration for all routes, but it is not strictly necessary for a JSON health‑check endpoint.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Runtime probe observed HTTP 200 response from /healthz without CSP header (web.missing-content-security-policy rule)`

Limitations:
- The review is limited to the provided source excerpt and runtime probe; it does not assess other endpoints that might serve HTML content where CSP would be relevant.

### 27. Missing clickjacking protection header on /healthz endpoint

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without any clickjacking protection headers (e.g., X-Frame-Options or Content-Security-Policy frame-ancestors). The source code shows a simple FastAPI route that returns JSON and does not set security headers. While the endpoint is low‑risk, the absence of clickjacking mitigation could allow the response to be embedded in a malicious frame, potentially facilitating UI redressing attacks.

**Impact:** An attacker could embed the /healthz JSON response in a hidden iframe on a malicious site, potentially tricking users or automated tools into interacting with the API in unintended ways. The impact is limited due to the low‑sensitivity nature of the health check, but it still represents a security hygiene issue.

**Remediation:** Configure the FastAPI application to include appropriate clickjacking protection headers for all responses, e.g., add X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self'. This can be done via middleware or response headers configuration.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe fact: status 200 returned from /healthz with no clickjacking protection header (web.missing-clickjacking-protection)`

Limitations:
- The finding is based on a single runtime observation; the header might be added dynamically in other environments or via a reverse proxy not captured in this scan. No evidence was found that the endpoint is served to browsers, so the practical risk may be minimal.

### 28. Missing X-Content-Type-Options header on /healthz endpoint

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without the X-Content-Type-Options header, which browsers use to prevent MIME type sniffing. The scanner observed the missing header directly from the runtime probe. While the endpoint is informational, the absence of this defense-in-depth header can allow content type confusion attacks if the response were ever interpreted as executable content.

**Impact:** An attacker could exploit MIME sniffing to execute malicious scripts if the response were served with an ambiguous content type, potentially leading to cross‑site scripting or other injection vectors in certain client contexts.

**Remediation:** Configure the web framework or reverse proxy to include the header, e.g., `X-Content-Type-Options: nosniff` for all responses, or set it specifically for the /healthz route.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe fact: path /healthz returned status 200 without X-Content-Type-Options header (web.missing-content-type-protection)`

Limitations:
- The finding is limited to the /healthz endpoint; other endpoints may already set the header. The impact depends on client behavior and content type handling, which may be mitigated by other headers or server configurations.

### 29. Missing signature verification on incoming webhook endpoint

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /integrations/hook POST endpoint accepts arbitrary request bodies and stores them directly in the database without validating a cryptographic signature. Runtime probing observed a successful 200 response for an unsigned request, whereas the expected secure behavior would be to reject the request with 400/401/403. This confirms that the endpoint processes unauthenticated webhook events.

**Impact:** An attacker can craft arbitrary webhook payloads, causing unauthorized data insertion, potential SQL injection (if input is not sanitized), and abuse of the system's workflow logic. This may lead to data corruption, privilege escalation, or denial‑of‑service.

**Remediation:** Implement signature verification for all incoming webhook requests. Reject requests lacking a valid HMAC or other cryptographic signature with an appropriate error code (e.g., 401 Unauthorized). Additionally, validate and sanitize the payload before inserting it into the database.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Source code shows no signature check before inserting the request body into the database (lines 629‑633).`
- `Runtime probe fact: method POST to /integrations/hook returned status 200, while expected statuses were 400, 401, 403 (assertion_results false).`

Limitations:
- The review is based on a single runtime probe; additional testing with varied payloads is recommended to ensure the fix covers all attack vectors.

### 30. Improper access control on invoice endpoint

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /invoices/{invoice_id} endpoint retrieves invoice data after only calling principal(authorization), which validates the requester's authentication but does not verify that the authenticated user is the owner of the requested invoice. Runtime probing observed a successful 200 response for a request that should have been denied (expected 403 or 404), confirming that unauthorized users can read invoices they do not own.

**Impact:** An attacker who can obtain a valid authentication token can enumerate or retrieve any invoice by ID, leading to exposure of sensitive financial information and violation of data privacy regulations.

**Remediation:** Implement an ownership check after fetching the invoice record, e.g., compare the invoice's owner_id with the authenticated user's ID and return 403 if they do not match. Ensure that error responses do not disclose existence of invoices to unauthorized users.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Source excerpt shows no ownership verification before returning invoice data`
- `Runtime probe fact: status 200 returned for unauthorized access attempt (expected 403/404)`

Limitations:
- The analysis assumes principal() does not perform ownership checks; if it does, the vulnerability may be mitigated. No additional logs or tests were provided to confirm the behavior across different user roles.

### 31. Potential unauthorized job creation via POST /jobs

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed a successful 200 response to a POST request on /jobs, whereas the scanner expected error statuses (400, 403, 422). The endpoint calls `principal(authorization)` before inserting a job, but the observed response suggests that the authorization check may be bypassed or ineffective, allowing job creation without proper privileges.

**Impact:** An attacker could create arbitrary jobs, potentially escalating privileges or executing unauthorized actions within the system.

**Remediation:** Ensure that `principal(authorization)` correctly validates the caller's role and returns an appropriate error (e.g., 403) when the user lacks admin rights. Add explicit permission checks before inserting into the jobs table and return error codes for unauthorized attempts.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Source excerpt shows `principal(authorization)` is called before inserting the job (lines 309‑311).`
- `Runtime probe fact reports a POST to /jobs returned status 200, contrary to expected 400/403/422 (scanner_id: web-runtime, rule_id: workflow.worker_role.1).`

Limitations:
- Only a single runtime probe observation is available; the endpoint may behave differently under other conditions or with different inputs.
- The actual implementation of `principal` is not shown, so it is unclear whether it performs sufficient role validation.

### 32. Sensitive personal data (SSN) disclosed via /me endpoint

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table and returns the columns id, username, role, email, and ssn. The returned dictionary is sent directly to the client without filtering out the ssn field. Runtime probing confirms a successful GET request to /me returns a 200 status and the values are redacted in the probe output, indicating that data was present but masked for the probe, which aligns with the source code that includes the ssn column.

**Impact:** An attacker who can authenticate as a valid user can retrieve the social security number of that user (or potentially other users if ID enumeration is possible). Exposure of SSNs can lead to identity theft, fraud, and regulatory non‑compliance (e.g., GDPR, HIPAA).

**Remediation:** Modify the /me endpoint to exclude sensitive fields such as ssn from the response. Implement a whitelist of safe attributes or explicitly remove ssn before returning the dict. Consider adding role‑based access controls if the ssn must be available to privileged users only, and ensure it is transmitted over TLS only.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Source excerpt shows SELECT ... ssn FROM users and return dict(row) at line 204`
- `Runtime probe fact: GET /me returned 200 with values_redacted true, indicating data was present`

Limitations:
- The probe redacted the actual SSN value, so the exact content was not observed directly in runtime; however, the code clearly includes the ssn column in the response. No evidence was found that additional filtering occurs elsewhere (e.g., middleware).

### 33. Improper owner assignment allows order creation for other users

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders` accepts an `owner_id` in the request body and falls back to the authenticated user's ID only when `owner_id` is falsy. There is no validation that the supplied `owner_id` matches the authenticated principal, enabling a user to create orders on behalf of any other owner by providing an arbitrary `owner_id`. The runtime probe observed a successful POST request (status 200) despite the expected restriction to 400/403/422, confirming the missing check.

**Impact:** An attacker can create, modify, or manipulate orders for other users, leading to unauthorized transactions, potential financial loss, and violation of data integrity and confidentiality.

**Remediation:** Validate that `owner_id` from the request body matches the authenticated user's identifier (`user["sub"]`). If they differ, reject the request with a 403 Forbidden response. Alternatively, remove the `owner_id` field from the request schema and always use the authenticated user's ID for order creation.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Source code lines 208-215 show `owner_id = body.owner_id or user["sub"]` without further checks.`
- `Runtime probe fact: POST to /orders returned status 200, while the probe expected 400/403/422 for improper owner assignment.`

Limitations:
- The evidence is limited to static code analysis and a single runtime probe; additional testing (e.g., attempting to create an order with another user's ID) would further confirm exploitability. No information on downstream authorization checks beyond this endpoint.

### 34. Order creation endpoint returns success for invalid input

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a POST to /orders returned HTTP 200, while the scanner's rule expects a 400 or 422 response for invalid input. The code inserts the order without validating the initial status field, allowing orders to be created in an unintended state. This mismatch indicates a potential logic flaw that could let malicious or malformed orders be processed as paid.

**Impact:** Attackers could create orders with arbitrary status values, potentially bypassing payment checks, causing financial discrepancies, or triggering downstream business logic errors.

**Remediation:** Validate the order status before insertion. Reject requests with invalid or unauthorized status values by returning 400/422. Implement server‑side checks to ensure only allowed status transitions are permitted.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.order_initial_state.1, path=/orders, method=POST, observed status=200, expected_statuses=[400,422]`
- `source_excerpt shows create_order inserts row without status validation`

Limitations:
- Evidence is limited to a single runtime probe; other request paths or validation layers were not examined.
- The probe did not confirm the exact request payload, so the presence of an invalid status value is inferred rather than directly observed.

### 35. Negative order prices are accepted instead of being rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The runtime probe sent a POST request to /orders with a negative unit_price and received an HTTP 200 response, while the scanner expected a 400/422 error. The assertion result was false, indicating the application did not reject the negative price as intended. The source code shows the order is inserted directly into the database without validation of unit_price, confirming the lack of a check.

**Impact:** An attacker can create orders with negative prices, potentially resulting in credit to the victim's account or manipulation of inventory/value calculations, leading to financial loss or abuse of the system.

**Remediation:** Add input validation for the unit_price field in the create_order endpoint to ensure it is non‑negative (e.g., raise HTTPException with status 400 if unit_price < 0). Consider using Pydantic validators or explicit checks before executing the INSERT statement.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Runtime probe fact: POST /orders with negative price returned status 200 (assertion_results false, expected 400/422)`
- `Source excerpt shows no validation of body.unit_price before database insertion`

Limitations:
- The probe only exercised a single negative value; other validation paths (e.g., database constraints) were not observed. The evidence is limited to this runtime request and does not confirm whether other layers (e.g., ORM, DB triggers) might reject the value in different configurations.

### 36. Client-controlled unit_price in order creation

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price field directly from the request body into the database without any server-side validation or enforcement of catalog pricing. This allows a client to specify arbitrary prices for items, violating the expectation that prices are set by the server.

**Impact:** An attacker can manipulate order prices to underpay for goods or overcharge others, leading to financial loss, inventory discrepancies, and potential fraud.

**Remediation:** Validate the unit_price against the server's price catalog before inserting the order. Reject or correct any client-supplied price that does not match the official price for the given item, and consider removing the unit_price field from the request schema entirely.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Source excerpt shows unit_price taken from body and inserted into DB (lines 213-215)`

Limitations:
- No additional runtime checks or database constraints were observed; cannot confirm if later logic validates the price. Further evidence needed to determine if downstream validation mitigates the issue.

### 37. Improper authorization check on nested note endpoint

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id}/notes/{note_id} endpoint retrieves a note by its ID without verifying that the note belongs to the specified order. The runtime probe observed a 200 OK response for /orders/1/notes/2, even though the note's order_id does not match the URL, indicating an authorization bypass.

**Impact:** An attacker can enumerate or access notes belonging to other orders by guessing note IDs, leading to unauthorized data disclosure and potential privacy violations.

**Remediation:** Validate that the note's order_id matches the order_id path parameter before returning the note. Return 403 Forbidden or 404 Not Found when the IDs do not correspond.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Source code shows no check of row['order_id'] against the order_id parameter (lines 543-549).`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200, while expected statuses were 403 or 404 (assertion_results: false).`

Limitations:
- Evidence is limited to a single runtime probe request; additional testing is needed to confirm the behavior across different notes and orders.

### 38. Improper access control on order retrieval endpoint

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint returns a 200 OK response for a request without proper ownership verification, whereas the runtime probe expected a 403 or 404. The source code shows a call to `principal(authorization)` but no subsequent check that the authenticated user owns the requested order before returning the record. This suggests that any authenticated user (or possibly unauthenticated if `authorization` is None) can read any order by ID, violating the intended owner‑only access policy.

**Impact:** An attacker can enumerate and read orders belonging to other users, leading to exposure of sensitive order details and potential privacy violations.

**Remediation:** Implement an ownership check after retrieving the order record, e.g., compare the order's `owner_id` with the authenticated user's ID and return 403 if they do not match. Ensure that unauthorized users cannot access order data.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Runtime probe returned status 200 for GET /orders/{{order_id}} where expected 403/404 (workflow.order_owner.3)`

Limitations:
- Only a single runtime probe was performed; the test did not provide an authentication token to verify behavior for different users. The `principal` function's implementation is not shown, so its effectiveness cannot be confirmed. Additional testing with varied user contexts is needed.

### 39. Excessive coupon discounts are accepted

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/orders/{order_id}/apply-coupon` applies a discount value taken from the request body (`body.discount`) without enforcing an upper bound. Runtime probing observed a 200 OK response when an excessively large discount was supplied, whereas the scanner expected a 400/422 error. This indicates that the application accepts and persists arbitrary discount percentages, potentially allowing a user to obtain free or negative‑price orders.

**Impact:** An attacker can submit a coupon with an arbitrarily high discount, causing orders to be charged at a reduced price or for free. This leads to direct revenue loss and can be exploited to create fraudulent orders at scale.

**Remediation:** Validate the discount value on the server side before applying it. Enforce that the discount is within an acceptable range (e.g., 0 % – 100 %). Reject requests with out‑of‑range values with a 400 Bad Request response. Consider also validating that the supplied coupon code exists and that its configured percent is not overridden by user input.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Source excerpt shows `percent = body.discount if body.discount is not None else (coupon["percent"] if coupon else 0)` – user‑controlled discount is used directly.`
- `Runtime probe fact: method POST to `/orders/{{order_id}}/apply-coupon` returned status 200 with excessive discount, while expected statuses were 400 or 422.`

Limitations:
- The review is based on a single runtime probe; additional testing is needed to confirm the exact discount bounds and whether other business rules (e.g., maximum order total) mitigate the impact. The scanner evidence does not indicate whether authentication/authorization checks beyond `principal(authorization)` prevent unauthorized users from exploiting the endpoint.

### 40. Order cancellation does not enforce refund for paid orders

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /orders/{order_id}/cancel endpoint updates the order status to "cancelled" without checking whether the order has been paid or whether a refund has been issued. Runtime probing shows the endpoint returns HTTP 200, whereas the security rule expects error codes (400, 409, 422) when cancellation is disallowed for paid orders. This indicates that a client can cancel a paid order without first processing a refund, violating business logic and potentially leading to financial loss.

**Impact:** An attacker or malicious user could cancel paid orders and retain the payment, resulting in revenue loss and possible disputes with customers. It also undermines auditability of order state transitions.

**Remediation:** Add business‑logic checks before performing the cancellation: verify the order's payment status, ensure any required refund has been processed, and return an appropriate error (e.g., 400 Bad Request) if cancellation is not permitted. Update the database transaction to reflect only allowed state changes.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Source code shows cancel_order directly executes UPDATE orders SET status='cancelled' without payment checks (lines 258‑263).`
- `Runtime probe fact: method POST to /orders/{{order_id}}/cancel returned status 200, while expected statuses were 400, 409, 422 (rule workflow.paid_cancel.3).`

Limitations:
- The review is based on static code and a single runtime probe; it does not confirm the presence or absence of additional checks elsewhere in the application (e.g., middleware, database triggers).
- The probe does not show the order's payment state; the vulnerability assumes the tested order was paid. Further testing with varied order states would strengthen confidence.

### 41. Potential payment replay vulnerability on order payment endpoint

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a POST to /orders/{order_id}/pay returned HTTP 200 even when the order was already marked as paid, whereas the expected statuses for a replay attempt are 400, 409, or 422. The source code shows the endpoint updates the order status to 'paid' without checking if the order is already in that state before creating a new invoice, indicating a possible lack of idempotency or replay protection.

**Impact:** An attacker could repeatedly invoke the payment endpoint for an already paid order, potentially generating multiple invoices and causing financial discrepancies or denial-of-service through resource exhaustion.

**Remediation:** Add a check to verify the order's current payment status before processing a new payment. Return an appropriate error (e.g., 409 Conflict) if the order is already paid, and ensure the operation is idempotent.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Runtime probe fact: method=POST, path=/orders/{{order_id}}/pay, observed status=200, expected statuses=[400,409,422]`
- `Source excerpt shows order status is set to 'paid' without prior status verification`

Limitations:
- Evidence is based on a single runtime probe observation; additional testing is needed to confirm consistent behavior across different orders and inputs.

### 42. Insecure Direct Object Reference on profile endpoint

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /profiles/{profile_id} endpoint retrieves user data based solely on the supplied profile_id without verifying that the authenticated principal is authorized to access that specific record. The runtime probe observed a successful GET request to another user's profile returning HTTP 200, indicating the access control check is missing.

**Impact:** An attacker can enumerate and retrieve sensitive information (username, email, SSN) of any user by iterating profile IDs, leading to privacy breaches and potential identity theft.

**Remediation:** Implement an authorization check that ensures the authenticated user can only access their own profile or has appropriate permissions. For example, compare the profile_id with the user ID from the principal and return 403 if they differ, or use role‑based access control.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `Source code shows no ownership check before querying the database (lines 98‑101).`
- `Runtime probe fact: GET request to /profiles/{{other_id}} returned status 200 instead of expected 403/404.`

Limitations:
- The review assumes the principal function only authenticates but does not enforce ownership; actual implementation details of principal are not provided.
- Only one runtime probe observation is available; additional testing may be needed to confirm consistency across different inputs.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /view returns an HTMLResponse without any X-Frame-Options or Content-Security-Policy frame-ancestors directives. The scanner flagged the absence of anti-clickjacking headers, and the runtime probe confirms a GET request to /view was made, showing the response content. No evidence was found that the application sets these headers elsewhere (e.g., via middleware).

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti-clickjacking headers, such as `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, preferably via a global response middleware so all HTML responses include them.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Source excerpt shows HTMLResponse returned without headers (lines 687-690).`
- `Runtime probe fact: GET request to /view confirmed the endpoint is reachable (web-runtime zap.10020).`

Limitations:
- The review only examined this specific route; other routes or middleware might add the header globally, which was not observed in the provided excerpt.
- Header presence was not verified in actual HTTP response headers; only the response body was inspected.

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reported that the response from GET /view does not include the X-Content-Type-Options header. The source code shows the endpoint returns a static HTMLResponse without explicitly setting security headers. However, many frameworks (e.g., FastAPI) add default security headers via middleware or server configuration, which may not be visible in the code snippet. Without confirming the actual HTTP response headers from a runtime probe, the finding remains unverified.

**Impact:** If the header is truly absent, browsers could perform MIME type sniffing, potentially leading to content injection attacks. The risk is low given the endpoint serves static HTML and the header is a defense‑in‑depth measure.

**Remediation:** Configure the application or web server to include `X-Content-Type-Options: nosniff` on all responses, e.g., add a FastAPI middleware or set the header in the response object.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner reported missing X-Content-Type-Options on GET /view`

Limitations:
- No runtime HTTP response captured to confirm header presence or absence
- Header may be added by external middleware not visible in source code
- Finding is based solely on static analysis without network evidence

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/view` returns an HTML page without a `Content-Security-Policy` header. The source excerpt shows the response is constructed with `HTMLResponse` and no header manipulation is evident. The runtime probe confirms a GET request to `/view` was made, but no CSP header was observed. Absence of CSP reduces protection against cross‑site scripting and data injection attacks.

**Impact:** Without a CSP header, browsers will not enforce restrictions on script sources, inline scripts, or other potentially unsafe content, increasing the risk of XSS and data exfiltration.

**Remediation:** Add a CSP header to the response, e.g., `response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"`, or configure the framework to include a default CSP for all HTML responses.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Source excerpt shows HTMLResponse returned without header modifications`
- `Runtime probe fact for GET /view with no CSP header observed`

Limitations:
- Only the `/view` endpoint was examined; other routes may set CSP globally
- The scan does not verify if middleware or a reverse proxy adds CSP headers after the application response

### 46. Improper webhook destination validation

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /webhooks validates the target_url by checking for the substring "mock-external" and raises a 400 error if it is not present. This logic is the opposite of the intended policy that the webhook destination must match an approved internal host. As a result, the service will accept arbitrary external URLs that contain the string "mock-external" and reject legitimate internal URLs, violating the security requirement.

**Impact:** An attacker can supply a malicious external URL that includes the string "mock-external" to bypass the validation and cause the application to send data to an uncontrolled destination, leading to data exfiltration or further exploitation.

**Remediation:** Replace the substring check with a strict comparison against a whitelist of approved internal host URLs. For example, store the allowed internal host in a configuration variable and compare target_url directly, rejecting any URL that does not exactly match the allowed host. Consider using URL parsing to validate scheme, host, and path.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `source_excerpt lines 294-298 show the inverted validation logic`
- `runtime_probe_facts indicates a POST to /webhooks returned status 200 when a 400 was expected, confirming the check is ineffective`

Limitations:
- Analysis is based on the provided code snippet; other surrounding validation logic may exist but was not shown
- The runtime probe does not include the exact payload used, so the full exploitability cannot be fully demonstrated

### 47. Clear‑text logging of application secret

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the value of the environment variable APP_SECRET at INFO level each time a user logs in. Logging secrets in clear text can expose them to anyone with access to log files, log aggregation services, or backup archives. The finding is supported by both the scanner rule (semgrep‑ce) and the source excerpt showing the log statement on line 137.

**Impact:** If an attacker can read the application logs, they can obtain the APP_SECRET, which may be used for token signing, encryption, or other privileged operations, leading to token forgery, data leakage, or further compromise of the system.

**Remediation:** Remove the secret from the log statement. Log only non‑sensitive identifiers (e.g., username) and ensure that any required debugging information is logged at a lower level (DEBUG) or behind a feature flag. Consider using a structured logger that can filter sensitive fields automatically.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) (api/app.py:137)`
- `semgrep‑ce rule python.lang.security.audit.logging.logger-credential-leak flagged line 137`

Limitations:
- The review assumes log files are accessible to potential attackers; if logs are strictly isolated and encrypted, risk is reduced but not eliminated. The environment variable fallback "lab-only" is also logged, which may reveal that the application is running in a lab environment. No runtime probe confirms whether logging is actually enabled at INFO level in production.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any website to make cross‑origin requests to the API. This configuration can expose the service to CSRF‑style attacks and data leakage when credentials are allowed.

**Impact:** An attacker-controlled site could interact with the API using the victim's credentials (cookies, HTTP auth, etc.) and potentially exfiltrate sensitive data or perform unauthorized actions.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. If credentials must be allowed, ensure only specific origins are permitted and consider enabling CSRF protections where applicable.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `Source excerpt lines 24‑29 show CORSMiddleware configured with allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]`

Limitations:
- The finding assumes the API is publicly accessible; if the service is internal‑only or intended for unrestricted use, the risk may be mitigated. No runtime probe data is available to confirm actual exploitation.

### 49. Potential Log Injection via user-controlled log entry

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs the supplied username directly into a structured log message (log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))). Because the username originates from client input, an attacker could craft a value containing log control characters (e.g., newlines, log delimiters) that may corrupt log integrity or facilitate log injection attacks. The presence of the application secret in the same log entry further raises the risk of accidental secret exposure if log injection is exploited.

**Impact:** Successful log injection could allow an attacker to manipulate log files, obscure malicious activity, or inject malicious payloads that downstream log parsers or monitoring tools might execute. Exposure of the APP_SECRET in logs also increases the risk of credential leakage.

**Remediation:** Sanitize or encode user-supplied values before logging. Use a safe logging library that escapes control characters, or avoid logging raw user input altogether. Consider removing sensitive data (APP_SECRET) from log statements.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `Source line 137 logs the username and APP_SECRET without sanitization.`

Limitations:
- The analysis assumes that the logging backend does not automatically escape control characters; actual behavior depends on the logger configuration. No runtime probe confirms whether log injection is exploitable in the deployed environment.

### 50. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list checking. This enables an attacker to supply an arbitrary URL, causing the server to issue a 302 redirect to a potentially malicious external site.

**Impact:** An attacker can craft a link that appears to originate from the trusted domain, tricking users into visiting phishing sites or malicious pages, facilitating credential theft or drive‑by attacks.

**Remediation:** Validate the `next` parameter against an allow‑list of internal URLs or paths, or restrict redirects to relative paths only. If external redirects are required, require explicit confirmation and use a safe redirect mechanism.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source excerpt shows `def continue_to(next: str = "/") -> RedirectResponse: return RedirectResponse(next, status_code=302)` which uses the user‑provided `next` value directly in the redirect.`

Limitations:
- The review is based solely on the provided code snippet; additional validation may exist elsewhere in the codebase that is not shown. No runtime probe data is available to confirm actual redirect behavior.

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
- `The code checks `if not next.startswith("/") or next.startswith("//") or parts.scheme or parts.netloc:` and raises HTTPException for invalid inputs, ensuring only local paths are allowed.`

Limitations:
- The review assumes the function is the sole entry point for redirects; if other redirect mechanisms exist elsewhere, they are not covered.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a Docker HEALTHCHECK instruction. While adding a health check is a best practice for container reliability, its omission does not constitute a security vulnerability. The scanner’s evidence is limited to the Dockerfile content and does not demonstrate any exploitable condition.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health monitoring.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile lines show no HEALTHCHECK instruction.`

Limitations:
- The assessment is based solely on Dockerfile content; runtime behavior or external monitoring setups are not examined.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a recommended best practice for container health monitoring, its absence does not constitute a security vulnerability by itself. No evidence is provided that the missing HEALTHCHECK leads to exploitable conditions such as denial‑of‑service or unauthorized access. Therefore, this is treated as a false positive in the context of security vulnerability assessment.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health monitoring.

**Remediation:** Add a suitable HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- The assessment does not consider operational policies that might require health checks; it only evaluates security impact.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile for the worker service does not contain a HEALTHCHECK instruction. While adding a health check is recommended for operational robustness, its absence does not constitute a security vulnerability. The finding is a misconfiguration advisory rather than an exploitable issue.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health monitoring, potentially affecting availability monitoring.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8080/health || exit 1
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt lines 1‑7 show no HEALTHCHECK instruction`

Limitations:
- The absence of a HEALTHCHECK is a best‑practice recommendation, not a proven security flaw. No runtime evidence indicates exploitation or impact.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-53539, a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded request bodies. The scanner evidence directly references this CVE and notes that the issue is fixed starting with version 0.0.30. No contradictory evidence was provided, and the runtime probe did not observe any mitigations. Therefore the vulnerability is confirmed for the deployed code base.

**Impact:** An attacker can send a maliciously crafted request to the FastAPI application, causing the python-multipart parser to consume excessive resources and potentially crash or become unresponsive, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later in requirements.txt and redeploy the application. Verify that the new version does not introduce breaking changes in request handling.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- No runtime probe confirming the vulnerability is currently exploitable; assessment relies on known CVE data.

### 56. Denial of Service in python-multipart 0.0.20 (CVE-2026-42561)

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by processing multipart requests with an excessive number of part headers. The scanner evidence directly references this CVE and notes that the issue is fixed in version 0.0.27. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can craft a multipart request that consumes excessive CPU or memory, potentially crashing the service or rendering it unavailable to legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version is installed by checking the lock file or runtime environment.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- The review is based solely on the declared dependency version; no runtime instrumentation or additional guard checks were provided to confirm whether the vulnerable code is exercised.

### 57. python-multipart information disclosure (CVE-2026-53538)

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The vulnerability allows information disclosure due to differential parsing of multipart form data. The scanner identified this dependency and the associated CVE, and no mitigating version is used.

**Impact:** An attacker could craft multipart requests that cause the server to leak sensitive data from processed form fields, potentially exposing user information or internal configuration.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The finding is based solely on the declared dependency version; no runtime evidence of exploitation was observed.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-40347. This CVE allows an attacker to trigger a denial‑of‑service condition by sending specially crafted multipart/form-data payloads. The scanner evidence cites the vulnerable version and notes that the issue is fixed starting with version 0.0.26, which is not used in the project.

**Impact:** An attacker who can upload or submit multipart/form-data to the application could cause the service to become unresponsive, leading to loss of availability and potential disruption of legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version does not introduce breaking changes in the multipart handling logic.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`

Limitations:
- The review is based solely on the declared dependency version; runtime behavior of the application (e.g., whether multipart handling is actually exercised) was not observed. No additional runtime probe data was provided.

### 59. python-multipart 0.0.20 contains CVE-2026-24486 (arbitrary file write via path traversal)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project's requirements.txt pins python-multipart at version 0.0.20. Public vulnerability databases list CVE-2026-24486 for this version, describing an arbitrary file write via crafted multipart filenames that traverse directories. The vulnerability is fixed starting with version 0.0.22. No evidence contradicts this finding, and the scanner's evidence directly references the CVE.

**Impact:** An attacker who can influence multipart form data (e.g., file upload endpoints) could write files to arbitrary locations on the server, potentially leading to code execution, privilege escalation, or service disruption.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later. Update the requirements.txt entry and run the dependency manager to install the patched version. Verify that the application functions correctly after the upgrade.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- The review relies on publicly reported CVE data; no runtime probe confirms exploitation in this specific deployment.

### 60. python-multipart 0.0.20 contains CVE-2026-53537

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to be vulnerable to CVE-2026-53537, an information disclosure issue caused by header parsing discrepancies. The vulnerability is documented and fixed in version 0.0.30. No evidence was found that the project applies a mitigation or uses a patched version.

**Impact:** An attacker could exploit the header parsing flaw to obtain sensitive information from HTTP requests processed by the application, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry and run the dependency manager to install the patched version.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review is based solely on the declared dependency version; runtime behavior was not observed. No additional context about custom mitigations or code-level fixes was available.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53540. The vulnerability allows an attacker to supply a negative Content‑Length header, causing the library to allocate the full request body in memory, leading to potential denial‑of‑service. The scanner identified this dependency and the associated CVE, and no mitigating controls were observed in the repository.

**Impact:** An attacker can trigger excessive memory consumption on the server, potentially causing crashes or service disruption, especially for large uploads.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, where the issue is fixed. Update the requirements.txt accordingly and rebuild the application image.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`

Limitations:
- No runtime probe data confirming the vulnerable code path is exercised; the finding is based solely on the declared dependency.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged the use of urllib with a dynamically constructed URL, but the code builds the URL by concatenating a constant base (BASE) with a path argument that is not shown to be attacker-controlled. No runtime evidence demonstrates that untrusted input reaches urllib, and the function appears to be an internal helper for API calls. Without proof of external input influencing the URL, the finding does not constitute a confirmed vulnerability.

**Impact:** If an attacker could control the URL, they might exploit urllib's support for file:// schemes to read arbitrary files. However, no such control vector is evident in the provided code.

**Remediation:** Review the call sites of the `request` function to ensure that the `path` argument is never derived from untrusted user input. If there is any possibility of external control, sanitize or validate the path, or switch to a higher‑level HTTP library such as `requests` that does not support file URLs by default.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen called with BASE + path, where BASE is a constant and path is a parameter without demonstrated external origin.`

Limitations:
- No runtime probe data confirming unsafe input flow.
- No evidence that path originates from user‑controlled data.
- Scanner heuristic may over‑alert on any dynamic string usage with urllib.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a urllib request that uses a value from the payload (payload["target_url"]). However, the code does not show that this value is attacker-controlled; it originates from an internal job definition. No evidence is provided that untrusted input can reach this field, nor is there any indication of a file:// scheme being used. Without proof of external control, the finding lacks sufficient grounding to be considered a vulnerability.

**Impact:** If an attacker could control the URL, they might exploit urllib's support for file:// to read arbitrary files. In the current context, no such control path is demonstrated, so the impact is speculative.

**Remediation:** Review the source of the "target_url" field to ensure it cannot be influenced by untrusted users. If external input can reach it, validate or sanitize the URL and consider using the 'requests' library, which does not support file:// schemes by default.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows urllib.request.urlopen called with payload["target_url"] without validation.`

Limitations:
- No runtime_probe_facts confirming attacker-controlled input.
- No additional scanner evidence linking this usage to a concrete exploit scenario.

### 64. Potential insufficient path traversal protection on file read endpoint

- Issue group: `ai-9a1294ca022bd523`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint builds a path using the user‑supplied `name` and resolves it, then checks `is_relative_to(FILES.resolve())` and `is_file()`. This check may be bypassed on Python versions where `Path.is_relative_to` is unavailable or behaves unexpectedly, and it does not protect against symbolic links or encoded traversal sequences. Additionally, the file is read without size limits, which could lead to information disclosure or denial‑of‑service.

**Impact:** An attacker could retrieve arbitrary files outside the intended public directory or cause the service to read large files, leading to data leakage or resource exhaustion.

**Remediation:** Normalize and validate the filename against an explicit whitelist or allowed pattern, reject paths containing traversal sequences, resolve symlinks safely, and enforce a maximum file size before reading. Consider using a dedicated static file serving library that handles these checks.
Evidence:
- Source IDs: `ai-9a1294ca022bd523`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `raise HTTPException(404, "File not found")`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The analysis assumes Python 3.9+ where `Path.is_relative_to` exists; behavior on older versions is unknown.
- Effectiveness of the relative‑path check depends on whether symbolic links are present in the `public` directory, which is not verified in the provided data.

### 65. Potential missing authorization on file read endpoint

- Issue group: `ai-8e18c1206f5af1f7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The /files endpoint is defined without any visible authentication or authorization guard. The code checks only that the requested file resides within the public directory and exists, then returns its contents. No dependency or decorator indicating user authentication is present in the shown snippet, and no evidence of a global FastAPI dependency that would protect this route is provided.

**Impact:** Unauthenticated users could retrieve arbitrary files from the server's public directory, potentially exposing sensitive information or enabling further attacks such as information disclosure.

**Remediation:** Add authentication and authorization checks to the endpoint, e.g., by applying a FastAPI dependency that validates the user session or role, or by moving the route under a router with a security dependency. Ensure only authorized users can access files.
Evidence:
- Source IDs: `ai-8e18c1206f5af1f7`
- `@router.get("/files") definition at line 210`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain") at line 215`
- `Absence of any authentication/authorization guard in the excerpt`

Limitations:
- The review is based solely on the provided code excerpt; a global FastAPI dependency or middleware could enforce authentication for all routes, which is not visible here. No runtime or deployment context confirming the presence or absence of such guards is available.

### 66. Sensitive personal data (SSN) disclosed via /me endpoint

- Issue group: `ai-5d5c7a5f1036f123`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /me endpoint executes a SQL query that selects the 'ssn' column and returns the entire row directly to the client without filtering or masking. This results in exposure of a highly sensitive identifier to any authenticated user who can call the endpoint. No evidence of downstream sanitization or access controls specific to the SSN field is present in the provided code.

**Impact:** Attackers who can obtain a valid authentication token can retrieve Social Security Numbers of any user, leading to identity theft, fraud, and violation of privacy regulations (e.g., GDPR, HIPAA).

**Remediation:** Modify the query to exclude the 'ssn' column or mask it before returning the response. Implement principle‑of‑least‑privilege data exposure by only returning fields required for client functionality. If the SSN is needed internally, keep it server‑side and do not include it in API responses. Add documentation and code comments to enforce this policy.
Evidence:
- Source IDs: `ai-5d5c7a5f1036f123`
- `api/app.py line 203 selects id,username,role,email,ssn from users`
- `api/app.py line 204 returns dict(row or {}) directly to the client`

Limitations:
- The review is based solely on static code analysis; runtime behavior (e.g., conditional masking) cannot be ruled out without execution evidence.
- No information is provided about authentication/authorization checks beyond the principal() call, so the scope of exposure to different user roles is unknown.

### 67. Unauthenticated file read endpoint allows arbitrary file access

- Issue group: `ai-c006b1ace34bf219`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /files endpoint serves files from the server's public directory based solely on a user‑supplied 'name' parameter. The handler does not perform any authentication or authorization checks before reading the file. While a relative‑path check is present, any file placed in the public directory can be retrieved by an unauthenticated client, which may expose internal documents or configuration data.

**Impact:** An attacker can enumerate and download any file that resides in the configured public folder, potentially leaking sensitive information, internal configuration, or proprietary assets.

**Remediation:** Add authentication and authorization checks before serving files. Restrict the set of files that can be served (e.g., whitelist specific filenames or extensions). Consider moving sensitive files out of the public directory and implement proper access controls. Log accesses and apply rate limiting to mitigate abuse.
Evidence:
- Source IDs: `ai-c006b1ace34bf219`
- `@router.get("/files") at api/extra.py:210`
- `def file_read(name: str) -> Response: at api/extra.py:211`
- `file = (FILES / "public" / name).resolve() at api/extra.py:212`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): at api/extra.py:213`

Limitations:
- The review assumes that the public directory may contain sensitive files; the actual content of that directory is not known from the provided data. The relative‑path check prevents path traversal outside the public folder, but does not mitigate exposure of files intentionally placed there. No runtime observations (e.g., actual file requests) are provided to confirm exploitation.

### 68. Potential open redirect via unchecked `next` parameter in form_login

- Issue group: `ai-9b22f1a91f224f4b`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The reviewed code shows a login handler that processes credentials and returns an HTML response containing the signed‑in username. No redirect logic, such as reading a `next` parameter from the request or issuing an HTTP redirect, is present in the examined excerpts. The claim of a missing check is based on the absence of observed redirect handling, not on evidence of an actual vulnerable redirect. Without code that uses a user‑controlled URL for redirection, the risk of an open redirect cannot be confirmed.

**Impact:** If a redirect were performed without validation, an attacker could send victims to malicious sites after login, facilitating phishing or session fixation. However, the current code does not perform such a redirect, so this impact does not apply.

**Remediation:** If future code adds redirect functionality, ensure any `next` or similar parameter is validated against an allowlist of trusted URLs or use relative paths only. Implement explicit checks before performing redirects.
Evidence:
- Source IDs: `ai-9b22f1a91f224f4b`
- `api/extra.py lines 288‑301 show the form_login endpoint handling credentials and returning an HTMLResponse without any redirect logic.`

Limitations:
- The review is limited to the provided source excerpts; downstream functions or middleware that might perform redirects based on request data were not examined.

## Policy Decisions

- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-bdfe7542047da39c6151`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-17a5197f906426a224ef`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-5230c114e62065082a9b`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-65c41e5a25b6337fec07`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-1ba9f8276fc6dae95df8`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-cc8a9ed20905505868f0`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-b4c1c4d005665a5249a7`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-a9e9047867c909f567ad`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-7da23d65adeef42d71a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e683a977084f2bbcee2e`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-dd64ece99563dbbb173a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2b80ed0c48c0c70a93a4`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-50485291173e2448f7c7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ade7b890a037d8c82a1f`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-dfd8d33b4f84ccf0c23f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-65f25bcf14fa2ab91271`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3202e1e1074cfd44b9bf`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
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
- `merged-7711056ee3332442a201`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-c150b78349615dd9bc2d`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `ai-9a1294ca022bd523`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-8e18c1206f5af1f7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-5d5c7a5f1036f123`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-c006b1ace34bf219`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-9b22f1a91f224f4b`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **68**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **9**; scanner overlaps: **1**; AI overlaps: **0**; new candidates: **3**; uncertain overlaps: **2**; needs more evidence: **3**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-1f853b488df2c4df`: needs_more_evidence
- `ai-9a1294ca022bd523`: uncertain_overlap
- `ai-c006b1ace34bf219`: uncertain_overlap
- `ai-8dd0ad62c9518115`: needs_more_evidence
- `ai-0b534f64164f47c9`: needs_more_evidence

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

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

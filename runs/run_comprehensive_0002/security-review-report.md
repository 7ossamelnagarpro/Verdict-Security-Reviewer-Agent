# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-04T08:45:36.756329+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **5**.

The agent reviewed **69** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **69**; reviewed: **69**; pending: **0**.

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

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the `username` and `password` fields from the request body into the query string without any sanitization or parameterization. This allows an attacker to inject arbitrary SQL code via these fields, leading to authentication bypass or data exfiltration.

**Impact:** An attacker can perform SQL injection to bypass authentication, retrieve or modify user records, and potentially execute arbitrary database commands, compromising confidentiality, integrity, and availability of the application data.

**Remediation:** Refactor the query to use parameterized statements or an ORM that safely handles user input. For example, use `conn.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (body.username, body.password))`. Additionally, hash passwords with a strong algorithm and compare hashes instead of storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117 constructs the query with f-string interpolation of `body.username` and `body.password``
- `The query is executed directly with `conn.execute(query)` without sanitization`

Limitations:
- The review is based solely on static code analysis; runtime behavior such as input validation layers not visible in the snippet could affect exploitability.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided name, but it resolves the path and then checks `is_relative_to(root)` before accessing the file. This check ensures the resulting path remains within the intended `public` directory, effectively preventing directory traversal attacks. The scanner’s generic pattern flagged the use of user input in a path, but the code includes proper validation.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server. However, the existing `is_relative_to` guard mitigates this risk, so no impact is present.

**Remediation:** No remediation needed for path traversal; ensure the `is_relative_to` check remains in place and that the Python version supports it. Consider adding explicit input sanitization or limiting allowed filename characters for defense‑in‑depth.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 219‑224 show the resolve and `is_relative_to` check`
- `source_symbol confirms the same logic`

Limitations:
- The analysis assumes the runtime environment uses a Python version where `Path.is_relative_to` is available and behaves as expected
- If symbolic links inside `public` point outside the directory, `resolve` may still allow traversal; additional checks may be required

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but then calls `Path.is_relative_to(root)` and checks `is_file()` before reading the file. The `is_relative_to` guard ensures the resolved path remains within the intended `root` directory, effectively preventing directory‑traversal attacks. The scanner’s generic pattern flagged the use of user input in a path, but the code includes proper validation.

**Impact:** If the guard were absent, an attacker could read arbitrary files on the server. Because the guard is present, the risk is mitigated.

**Remediation:** No remediation needed; the existing `is_relative_to` check is sufficient. Ensure future path handling follows the same pattern.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source_excerpt lines 218‑224 show the `is_relative_to` check and file existence verification.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If run on an older version, this method would not exist and the check would fail, potentially re‑introducing the vulnerability.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code constructs the file path using a user‑provided `name` but then validates it with `is_relative_to(FILES.resolve())` and `is_file()`. These checks ensure the resolved path stays within the intended directory and points to an existing file, mitigating path traversal. No evidence of bypass was observed in the provided source or runtime probes.

**Impact:** If the validation were bypassable, an attacker could read arbitrary files, leading to data disclosure. However, the current checks appear to prevent such access.

**Remediation:** No remediation required for the reported issue; the existing validation is appropriate. Continue to monitor for any changes that might weaken the checks.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Source lines 212‑214 show the path is resolved and then checked with `is_relative_to` and `is_file` before being returned.`

Limitations:
- No runtime probe data confirming the checks cannot be bypassed.
- Only static analysis was performed; dynamic testing could provide additional confidence.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a fixed root directory and then verifies that the resulting path is a descendant of that root (is_relative_to) and that it points to an existing file. These checks effectively prevent directory traversal attacks, so the scanner’s finding is not indicative of a vulnerability.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server. However, the explicit relative‑path check mitigates this risk.

**Remediation:** No remediation required; the existing path validation is sufficient. Ensure the Python version supports Path.is_relative_to (Python 3.9+) or replace with an equivalent check for older versions.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `source_excerpt lines 220‑224 show root resolution and is_relative_to check`

Limitations:
- The analysis assumes the runtime environment uses a Python version where Path.is_relative_to correctly enforces the relative path constraint. If an older Python version is used, the method may be unavailable, potentially altering behavior.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a known base directory and then verifies that the resolved path is still within that base using `is_relative_to`. This prevents directory traversal attacks despite the user input being incorporated into the path. The scanner flagged the use of user data in a path expression, but the subsequent safety checks mitigate the risk.

**Impact:** If the checks were ineffective, an attacker could read arbitrary files, leading to information disclosure. However, the code correctly enforces the base directory constraint, so no impact is present.

**Remediation:** No remediation needed; the existing `resolve` and `is_relative_to` checks adequately protect against path traversal. Ensure the `FILES` constant is correctly set to the intended public directory and that the Python version supports `is_relative_to`.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `source_excerpt lines 211‑215 show the resolve and `is_relative_to` checks`
- `scanner evidence flagged user‑provided value but did not account for the safety checks`

Limitations:
- The analysis assumes the runtime environment uses a Python version where `Path.is_relative_to` is available and behaves as expected
- If `FILES` is a symlink or the filesystem permits path manipulation after resolution, additional checks may be required

### 7. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint interpolates the user‑controlled query parameter `q` directly into an HTML response without any sanitisation or encoding. The returned string includes `<h1>Results for {q}</h1>` and a list of product names, allowing an attacker to inject arbitrary HTML/JavaScript that will be reflected back to the victim's browser.

**Impact:** An attacker can craft a URL such as `/catalog/search?q=<script>alert(1)</script>` that, when visited, executes arbitrary JavaScript in the context of the vulnerable site. This can lead to session hijacking, credential theft, or other malicious actions against users of the application.

**Remediation:** Validate and encode the `q` parameter before including it in the response. Use a templating engine that auto‑escapes HTML, or explicitly HTML‑escape the value (e.g., `html.escape(q)`). Additionally, consider using parameterised queries for the SQL statement to prevent SQL injection, and encode product names when rendering them.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt shows `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)` with no sanitisation of `q`.`
- `Scanner evidence flagged this line as a reflected XSS risk.`

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., content‑security‑policy headers) was not observed. No runtime probe facts were provided to confirm execution of injected scripts.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided name, but it immediately resolves the path and checks both that the resolved path is within the allowed directory (is_relative_to(FILES.resolve())) and that the target is a regular file (is_file()). These checks effectively prevent directory traversal attacks, making the scanner's finding a false positive.

**Impact:** If the checks were bypassed, an attacker could read arbitrary files, but the current implementation blocks such traversal, so no impact is present.

**Remediation:** No remediation needed for path traversal; the existing validation is sufficient. Ensure that FILES is a trusted base directory and that resolve() does not follow symlinks to unintended locations.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- The analysis assumes that FILES is a fixed, trusted directory and that resolve() does not introduce symlink‑related bypasses. If symlinks inside the public directory point outside, additional checks may be required.

### 9. Potential SQL Injection in catalog_search endpoint

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `catalog_search` constructs an SQL query by directly embedding the user‑controlled parameter `q` into the query string using an f‑string. This allows an attacker to inject arbitrary SQL syntax, which will be executed by the database when `conn.execute` runs. The finding is corroborated by the source excerpt showing the vulnerable line (line 144).

**Impact:** An attacker could manipulate the query to retrieve unauthorized data, modify or delete records, or execute database‑specific commands, leading to data breach, data loss, or privilege escalation.

**Remediation:** Use parameterized queries or prepared statements instead of string interpolation. For example, replace the f‑string with a query that uses placeholders and passes `q` as a parameter (e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`). Additionally, validate and sanitize input where appropriate and enforce least‑privilege database permissions.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt line 144 shows `conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'")``

Limitations:
- No runtime probe data is available to confirm exploitation; the assessment relies solely on static code analysis. The surrounding code does not indicate any input sanitization or ORM usage that might mitigate the risk.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response for GET / does not include the X-Content-Type-Options header. The runtime probe only confirms the request method and that values were redacted; it does not provide the actual response headers. Without concrete evidence of the missing header, the finding cannot be confirmed.

**Impact:** If the header were truly missing, browsers could perform MIME type sniffing, potentially leading to content injection attacks. However, no direct evidence of the header's absence is available.

**Remediation:** Ensure that the HTTP response includes `X-Content-Type-Options: nosniff` for all endpoints, typically by configuring the web framework or reverse proxy to add this header globally.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `runtime_probe_facts indicate a GET request to '/' but no header data was captured.`

Limitations:
- No actual response headers were observed; the scanner's claim is unverified. The probe redacted values, preventing confirmation of header presence or absence.

### 11. Improper access control on /admin/jobs endpoint

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs route is intended for administrative use but returns a 200 OK response with job data when accessed without proper authorization. The runtime probe attempted to access the endpoint without credentials, expecting a 403/404, but received a 200, indicating the access control check (principal) does not enforce admin restrictions effectively.

**Impact:** Unauthenticated users can enumerate, view, and potentially infer sensitive job information, leading to information disclosure and facilitating further attacks such as targeted phishing or privilege escalation.

**Remediation:** Enforce strict role‑based access control on the /admin/jobs endpoint. Ensure the `principal` function validates the token and verifies the user has an admin role before executing the query. Return 403 Forbidden for unauthorized requests.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Source code shows the endpoint calls `principal(authorization)` but still returns data (lines 285‑290).`
- `Runtime probe fact: expected status 403/404 but observed 200 for GET /admin/jobs without credentials (scanner_id:web-runtime, rule_id:workflow.admin_jobs.2).`

Limitations:
- The review assumes `principal` does not raise an exception or abort the request; actual implementation details of `principal` are not provided.
- Only a single unauthenticated request was observed; additional testing with varied tokens could further confirm the access control failure.

### 12. Improper access control on /admin/token-report endpoint

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/token-report endpoint checks the role of the token and raises a 403 error when the role is not "admin". However, runtime probing observed a GET request to this endpoint returning HTTP 200, indicating that the role check was bypassed or the token was still considered admin despite the user being demoted. This mismatch between expected (403) and observed (200) responses suggests an access‑control flaw that allows a demoted administrator to retain administrative access.

**Impact:** An attacker with a previously valid admin token could continue to access privileged administrative functionality after their role has been revoked, potentially leading to unauthorized data exposure, configuration changes, or further privilege escalation.

**Remediation:** Ensure that role revocation is enforced at token validation time. Invalidate or re‑issue tokens when a user's role changes, and verify the role against a current authoritative source (e.g., database) on each request. Return appropriate HTTP 403 responses for non‑admin users.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Source code shows role check and HTTPException(403) for non‑admin users (lines 661‑664).`
- `Runtime probe fact: expected_statuses [403,404] but observed status 200 for GET /admin/token-report (workflow.stale_role.3).`

Limitations:
- Evidence is limited to a single runtime probe of the GET method; other HTTP methods or request variations were not tested.
- The probe does not show the exact token used; it is possible the token presented was still valid with admin role, though the workflow expects a demoted role.

### 13. Improper access control on /admin/users endpoint

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users route returns a full list of user records, including sensitive fields such as email, role, and SSN, without verifying that the requester has an administrative role. The source code shows only a call to `principal(authorization)` which appears to validate authentication but does not enforce authorization checks for admin privileges. Runtime probing confirms that an unauthenticated GET request receives a 200 response, contrary to the expected 403/404, indicating the access control check is missing or ineffective.

**Impact:** An attacker can enumerate all user accounts and retrieve personally identifiable information (PII) and sensitive identifiers (SSN). This enables credential stuffing, targeted phishing, and further privilege escalation attacks.

**Remediation:** Implement proper role‑based access control: after authenticating the request, verify that the authenticated principal has the required admin role before querying and returning user data. Return 403 (Forbidden) for non‑admin users. Additionally, limit the fields returned to only those necessary for the admin view and consider pagination or rate limiting.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Source excerpt shows admin_users endpoint returns all user fields without role check (lines 277‑282).`
- `Runtime probe fact: GET /admin/users returned status 200 when a 403/404 was expected (assertion_results false).`

Limitations:
- The `principal` function implementation is not shown; it may perform role checks internally, though the surrounding code provides no evidence of such behavior. The probe only exercised a single request scenario; different authentication headers might yield different results.

### 14. Missing Content Security Policy (CSP) Header on /auth/form-login

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The runtime probe indicates a POST request to /auth/form-login and the source excerpt shows the endpoint returns an HTMLResponse without explicitly setting any security headers. No evidence was found that a CSP header is added elsewhere (e.g., via middleware). The scanner flagged the absence of a CSP header, which is a common mitigation against cross‑site scripting and data injection attacks. While the code does escape the username when rendering, the lack of a CSP header leaves the application vulnerable to injected scripts that could bypass server‑side escaping in other contexts.

**Impact:** Without a CSP header, an attacker who can inject malicious script content (e.g., via reflected or stored XSS vectors) may execute arbitrary JavaScript in the victim's browser, leading to credential theft, session hijacking, or other malicious actions.

**Remediation:** Configure the application to send a strong Content‑Security‑Policy header on all responses, especially for authentication pages. For example, add middleware or set the header in the response object: `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"`. Review and tighten the policy to suit the app's needs while blocking inline scripts and untrusted sources.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner finding: Content Security Policy (CSP) Header Not Set`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact: POST request to /auth/form-login with redacted values`

Limitations:
- The review is based solely on the provided source excerpt; the application might apply CSP globally via middleware not shown in the snippet.
- No runtime observation of response headers was provided, so the absence of CSP is inferred from code, not directly observed.

### 15. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /auth/form-login returns an HTMLResponse without setting any anti-clickjacking headers such as X-Frame-Options or Content-Security-Policy frame-ancestors. The source excerpt shows the response is created with `HTMLResponse(...)` and no header manipulation is performed. The scanner flagged the missing header, and no contradictory evidence was found in the provided code.

**Impact:** An attacker could embed the login page in a malicious site using an iframe, potentially tricking users into submitting credentials (clickjacking).

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP with `frame-ancestors 'none'`. Ensure all HTML responses include this protection.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Source excerpt shows response creation without header setting: `response = HTMLResponse(...); return response``

Limitations:
- Only a fragment of the file is provided; the header might be added by middleware not shown. No runtime response capture is available to confirm the header is absent.

### 16. Cookie missing HttpOnly flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The form_login endpoint creates a session cookie using response.set_cookie("lab_session", ...) without specifying the HttpOnly attribute. This allows client-side scripts to access the cookie, increasing the risk of theft via XSS.

**Impact:** An attacker who can inject JavaScript into the application could read the session cookie and hijack user sessions.

**Remediation:** Set the HttpOnly flag when creating the cookie, e.g., response.set_cookie("lab_session", value, httponly=True). Consider also adding Secure and SameSite attributes.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `source_symbol line 300 shows response.set_cookie("lab_session", f"session-{row['id']}") without HttpOnly`
- `runtime_probe_facts indicates POST to /auth/form-login`

Limitations:
- Only the shown code path is analyzed; other code may set HttpOnly elsewhere
- No runtime confirmation that the cookie is sent without HttpOnly in actual responses

### 17. Password reset tokens may be reusable

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe exercised the password‑reset confirmation endpoint with a token that should have been invalid after first use. The probe observed a 200 OK response (instead of the expected 400/409/422) indicating the token was accepted again, suggesting the token is not single‑use as required.

**Impact:** An attacker who obtains a valid reset token could reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity of user data.

**Remediation:** Ensure that reset tokens are marked as used and removed or invalidated in the database after a successful password change. Add a check that rejects any subsequent use of the same token with an appropriate error response (e.g., 400 Bad Request).
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Runtime probe fact: POST /auth/reset/confirm returned status 200 when reusing a token (expected statuses 400, 409, 422).`
- `Source excerpt shows token lookup but no explicit invalidation after password update.`

Limitations:
- Only a single runtime probe was performed; the test does not confirm whether the token is invalidated in all code paths or under concurrent requests.
- The probe does not verify whether other safeguards (e.g., token expiration, one‑time flag) exist elsewhere in the application.

### 18. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /catalog/query returns HTML content without setting a Content Security Policy header. The source excerpt shows the response is constructed directly from user‑controlled input (the query parameter) and returned as an HTMLResponse. No CSP header is added in the code, and the runtime probe did not observe any CSP header in the HTTP response. Absence of CSP reduces protection against reflected XSS and other content injection attacks.

**Impact:** An attacker who can influence the query parameter could inject malicious scripts that would be executed in the victim's browser, potentially leading to credential theft, session hijacking, or other client‑side attacks.

**Remediation:** Add a strict CSP header to the response, e.g., `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'"`. Consider using FastAPI middleware or a response class that automatically includes security headers. Also ensure any dynamic content is properly escaped (which is already done with `html.escape`).
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Runtime probe fact: GET request to /catalog/query returned without CSP header (zap.10038)`
- `Source code returns HTMLResponse without setting security headers`

Limitations:
- The analysis assumes the observed runtime response is representative of production; configuration or reverse proxies could add CSP headers not visible in the probe. No evidence was found about any external middleware that might inject CSP.

### 19. X-Content-Type-Options Header Missing

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /catalog/query does not include the X-Content-Type-Options header. The source code shows the endpoint returns an HTMLResponse but does not set security headers explicitly. No contradictory evidence was found in the runtime probe facts or other scanners. While the missing header is a known best‑practice issue, the evidence is limited to a single scanner observation, so the finding is treated as likely rather than confirmed.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks such as cross‑site scripting in certain edge cases.

**Remediation:** Configure the FastAPI application (or the underlying Starlette response) to include the header, e.g., by adding a middleware that sets `X-Content-Type-Options: nosniff` for all responses or by specifying it in the response headers for this endpoint.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Scanner reported missing X-Content-Type-Options header on GET /catalog/query`

Limitations:
- Only a single scanner observation; no runtime probe confirming header absence, no server configuration review, and no evidence that the header might be added elsewhere (e.g., reverse proxy).

### 20. Missing Anti-clickjacking Header on /catalog/query

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns an HTMLResponse constructed from user‑controlled input without setting any X‑Frame‑Options or Content‑Security‑Policy frame‑ancestors directives. The scanner flagged the absence of an anti‑clickjacking header, and the source excerpt shows the raw HTML being returned with no header manipulation. While the code does escape user input, it does not add protective response headers, which could allow the page to be embedded in a malicious iframe.

**Impact:** An attacker could embed the page in a hidden iframe on a malicious site and trick users into performing unintended actions (clickjacking), potentially leading to credential theft or unauthorized actions if the page includes state‑changing functionality.

**Remediation:** Add appropriate anti‑clickjacking headers to the response, e.g., set `X-Frame-Options: SAMEORIGIN` or a CSP `frame‑ancestors` directive, or configure the FastAPI router to include these headers for HTML responses.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Source excerpt shows HTMLResponse returned without header manipulation (lines 148‑153).`
- `Runtime probe fact indicates a GET request to /catalog/query was observed (scanner_id: web-runtime, rule_id: zap.10020).`

Limitations:
- The finding is based on the absence of explicit header setting in the examined code; the application might add security headers globally via middleware not shown in the excerpt.
- No runtime evidence confirms that the response indeed lacks the header; only the scanner’s observation is available.

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The GET /comments endpoint returns HTML content without the X-Content-Type-Options: nosniff header. Absence of this header allows browsers to perform MIME type sniffing, which can be leveraged by an attacker to execute malicious content delivered with an incorrect Content-Type.

**Impact:** An attacker could craft a response that causes the browser to interpret untrusted data as executable script, potentially leading to cross‑site scripting (XSS) or drive‑by download attacks.

**Remediation:** Configure the FastAPI application or the underlying ASGI server to include the X-Content-Type-Options: nosniff header on all responses, e.g., using a middleware that adds the header globally or setting it explicitly in the route response.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Source excerpt shows the /comments route returns raw HTML without header manipulation (lines 173‑177).`
- `Runtime probe fact confirms a GET request to /comments was observed (scanner_id: web-runtime, rule_id: zap.10021).`

Limitations:
- The scan does not show whether a global security‑header middleware is applied elsewhere in the codebase; the missing header may be added by infrastructure outside the examined source file.
- Only a single request was observed; additional runtime probes would be needed to confirm consistent header omission across all responses.

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns HTML without a Content‑Security‑Policy header. Absence of CSP allows an attacker to inject malicious scripts that the browser will execute, increasing XSS risk. The scanner flagged this directly and the runtime probe confirms the endpoint is reachable via GET.

**Impact:** An attacker who can influence comment content could execute arbitrary JavaScript in a victim's browser, leading to session hijacking, credential theft, or other malicious actions.

**Remediation:** Add a CSP header to the response, e.g., `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'"`. Ensure the header is applied globally or at least for the /comments route.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Scanner evidence: Content Security Policy (CSP) Header Not Set`
- `Runtime probe fact: GET request to /comments observed (web-runtime zap.10038)`

Limitations:
- The finding is based on header observation; if the application adds CSP headers later in middleware not captured in this scan, the issue may be mitigated. No direct proof of exploitable script injection is present.

### 23. Missing Anti-clickjacking Header

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content without setting an anti-clickjacking header such as `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`. The source excerpt shows the route returns a raw HTML string, and the runtime probe confirms a GET request to this path but does not report any security headers. This aligns with the scanner finding of a missing anti-clickjacking header.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, preferably via middleware or response headers configuration in the FastAPI application.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Source excerpt shows `/comments` returns raw HTML without header handling`
- `Runtime probe fact for GET /comments confirms request but no header data`

Limitations:
- The review is based on static code and a single runtime probe; it does not capture any framework-level default headers that might be added elsewhere in the application.

### 24. Unauthenticated access to debug configuration exposing secrets

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /debug/config endpoint returns a JSON object containing DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without any authentication check. Runtime probing observed a 200 OK response for an unauthenticated GET request, while the scanner expected 401/403/404. This confirms that the debug configuration is publicly accessible.

**Impact:** Attackers can retrieve database connection strings and application secrets, enabling credential theft, database compromise, and further lateral movement within the environment.

**Remediation:** Restrict access to the /debug/config endpoint to authorized users only. Add authentication/authorization checks (e.g., require admin role) or remove the endpoint from production builds. Ensure that secret values are not exposed in responses and consider using environment‑only storage without runtime exposure.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Source code shows the endpoint returns secrets at lines 321‑322`
- `Runtime probe fact: method GET to /debug/config returned status 200 (expected 401/403/404)`

Limitations:
- Evidence is limited to a single runtime request; additional testing across environments would confirm consistency. The review assumes the code snippet reflects the deployed version.

### 25. Missing Content-Security-Policy header on health endpoint

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The finding reports that the /healthz endpoint does not include a Content-Security-Policy header. The source excerpt shows only application logic returning a JSON payload and does not indicate any response header configuration. The runtime probe confirms a 200 response but provides no evidence of header omission beyond the scanner's rule. Health check endpoints often intentionally omit security headers to reduce overhead and are not exposed to browsers, so the lack of CSP is not necessarily a vulnerability.

**Impact:** Minimal impact; the endpoint is intended for internal health monitoring and does not serve HTML content to browsers, so CSP enforcement is irrelevant.

**Remediation:** If CSP is desired for consistency, add the appropriate header in the response middleware for all endpoints, including /healthz. Otherwise, document that the endpoint is internal-only and exempt from CSP requirements.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `runtime_probe_facts: scanner_id web-runtime reported status 200 for /healthz without CSP header`

Limitations:
- No direct inspection of response headers beyond the scanner's observation; cannot confirm whether CSP is intentionally omitted or misconfigured. The assessment assumes /healthz is not publicly exposed.

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for GET /healthz does not include the X-Content-Type-Options header. The source code for the healthz endpoint does not show any explicit setting of security headers, and no runtime probe evidence confirms the header is present. While the absence of this header is a known security best‑practice issue, the finding relies solely on scanner observation without additional verification.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to MIME‑sniff the response, potentially allowing content‑type confusion attacks such as cross‑site scripting in certain edge cases.

**Remediation:** Add the X-Content-Type-Options header (e.g., `response.headers['X-Content-Type-Options'] = 'nosniff'`) to the healthz endpoint or configure a global middleware to set it for all responses.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `Scanner runtime probe (zap.10021) reported missing X-Content-Type-Options header on GET /healthz`

Limitations:
- No direct inspection of the actual HTTP response was performed; the finding is based solely on scanner output.
- The source excerpt does not show header handling, but the application may add headers via middleware not visible in the snippet.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the /healthz endpoint does not include a clickjacking protection header (e.g., X-Frame-Options or Content-Security-Policy frame-ancestors). The only runtime probe fact captured is the HTTP 200 status; no response headers were recorded, and the source code excerpt does not show any header manipulation. Without concrete evidence that the header is absent, the finding cannot be confirmed.

**Impact:** If the endpoint can be embedded in a malicious site, an attacker could potentially trick users into performing unintended actions, leading to clickjacking attacks.

**Remediation:** Add appropriate clickjacking protection headers (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response for the /healthz endpoint and any other relevant endpoints.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner reported missing clickjacking protection header for /healthz`

Limitations:
- No response header data captured in runtime_probe_facts; source code does not explicitly set or omit the header; cannot confirm absence of protection without additional observation.

### 28. Missing X-Content-Type-Options header on /healthz

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without the X-Content-Type-Options header, which is a recommended security header to prevent MIME type sniffing. The scanner flagged this as missing, and no contradictory evidence was found in the source code or other runtime observations.

**Impact:** An attacker could potentially exploit MIME type sniffing to execute content in an unintended context, leading to cross‑site scripting or content injection attacks, especially if the endpoint ever serves user‑controlled data.

**Remediation:** Configure the FastAPI application or the underlying web server to include the header, e.g., add `Response(headers={"X-Content-Type-Options": "nosniff"})` to the healthz response or set the header globally via middleware or server configuration.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=web.missing-content-type-protection, path=/healthz, facts={"status":200}`

Limitations:
- Evidence is limited to a single runtime probe of the /healthz endpoint; other endpoints may already set the header.
- The source excerpt does not show any header manipulation, but the absence of explicit header code does not guarantee the header is not added elsewhere (e.g., via middleware).

### 29. Missing signature verification on incoming webhook endpoint

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /integrations/hook endpoint accepts POST requests and stores the raw request body in the database without validating a cryptographic signature. Runtime probing observed a successful 200 response for an unsigned request, while the scanner expected a 400/401/403 response. This indicates the endpoint does not enforce signature verification, allowing unauthenticated actors to submit arbitrary data.

**Impact:** An attacker can craft arbitrary webhook payloads and cause the application to process or store malicious data, potentially leading to injection attacks, data corruption, or unauthorized actions triggered by downstream processing of the stored payloads.

**Remediation:** Implement signature verification for all incoming webhook requests. Reject requests lacking a valid signature with a 401 or 403 response. Use a constant‑time comparison for the signature and log verification failures. Optionally, rate‑limit the endpoint to mitigate abuse.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Source excerpt shows the endpoint reads the request body and inserts it directly into the database without any signature check.`
- `Runtime probe fact: method=POST, status=200, assertion_results=[false], expected_statuses=[400,401,403] indicating the request succeeded despite missing a signature.`

Limitations:
- Evidence is limited to a single runtime probe and static code excerpt; does not show whether signature verification might be performed elsewhere (e.g., middleware). No information on downstream processing of the stored payload, so impact is inferred from typical webhook misuse.

### 30. Missing invoice ownership check allows unauthorized read

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice before returning the record. Runtime probing shows a successful GET returns HTTP 200 for a non‑owner, whereas the security rule expects a 403 or 404. This indicates that any authenticated user (or possibly unauthenticated if `principal` permits) can read any invoice by ID.

**Impact:** Unauthorized disclosure of invoice data, potentially exposing sensitive financial information of other users, leading to privacy violations and compliance breaches.

**Remediation:** Add an ownership check after retrieving the invoice row, e.g., compare `row['owner_id']` with the authenticated user's ID and raise `HTTPException(403)` if they differ. Ensure the `principal` function returns the user identity and that the check is enforced before returning data.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Source excerpt shows no ownership validation after fetching the invoice row (lines 268‑274).`
- `Runtime probe fact: request to `/invoices/{{invoice_id}}` returned status 200 instead of expected 403/404 (rule workflow.invoice_owner.3).`

Limitations:
- The review assumes `principal` only validates authentication and does not perform ownership checks; the actual implementation of `principal` is not shown.
- Runtime probe provides a single observation; additional testing with different users would strengthen confidence.

### 31. Improper authorization on job creation endpoint

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint executes a database insert after calling principal(authorization) but the runtime probe observed a 200 OK response, whereas the scanner expected error statuses (400, 403, 422). This indicates that the authorization check may be ineffective, allowing unauthenticated or unauthorized users to create jobs.

**Impact:** An attacker could create arbitrary jobs, potentially escalating privileges or executing unwanted workloads on the system.

**Remediation:** Ensure that the principal() function enforces proper authentication and role checks before allowing the INSERT operation. Return appropriate error codes (e.g., 403 Forbidden) when the user lacks the required permissions.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Runtime probe fact: POST /jobs returned status 200 (expected 400/403/422)`
- `Source excerpt shows create_job calls principal(authorization) then inserts into jobs table without further checks`

Limitations:
- The review is based on a single runtime probe observation; additional testing is needed to confirm that the endpoint consistently bypasses authorization. The exact behavior of principal() is not visible in the provided excerpt.

### 32. SSN disclosed in /me endpoint response

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table and returns all selected columns, including the "ssn" field, directly to the client without redaction. The source excerpt shows the SQL query selecting "ssn" and the returned dict being sent as the response. Runtime probe confirms a successful GET request to /me returning status 200, indicating the data is exposed when the endpoint is accessed with valid authorization.

**Impact:** An attacker who obtains a valid authentication token can retrieve the social security numbers of any user, leading to identity theft, fraud, and violation of privacy regulations (e.g., GDPR, HIPAA).

**Remediation:** Modify the endpoint to exclude sensitive fields such as SSN from the response or mask them. Implement a view model that only returns necessary user attributes (e.g., id, username, role, email). If SSN is required for internal processing, ensure it is never sent to the client. Add audit logging for access to sensitive data.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Source excerpt line 203: SELECT id,username,role,email,ssn FROM users WHERE id=%s`
- `Source excerpt line 204: return dict(row or {})`
- `Runtime probe fact: GET /me returned status 200`

Limitations:
- The finding assumes the requester possesses a valid Authorization header; the vulnerability is exploitable only with a valid token. No evidence is provided about additional access controls that might restrict which users can call /me or whether the SSN field is ever populated.

### 33. Improper owner assignment allows order creation for arbitrary owners

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint assigns the order's owner_id from the request body if provided, otherwise defaults to the authenticated user's sub. This permits a malicious user to specify any owner_id in the request body, creating orders on behalf of other users without authorization checks. The runtime probe observed a successful POST to /orders returning HTTP 200, contrary to the expected 400/403/422 statuses for unauthorized owner assignments, confirming the flaw.

**Impact:** An attacker can create orders for other users, leading to unauthorized resource consumption, potential billing fraud, and data integrity issues across user accounts.

**Remediation:** Validate that the owner_id in the request body matches the authenticated user's identifier or restrict the field entirely. Return an error (e.g., 403 Forbidden) when a mismatch is detected, and consider removing the ability for clients to set owner_id directly.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Source excerpt shows owner_id = body.owner_id or user["sub"] allowing client-supplied owner_id`
- `Runtime probe fact: POST /orders returned status 200 instead of expected 400/403/422`

Limitations:
- The review is based on static code analysis and a single runtime probe; additional testing may be needed to confirm enforcement across all code paths and authentication mechanisms.

### 34. Order creation endpoint returns success for invalid input

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a POST request to /orders returned HTTP 200, while the scanner's rule expects a 400 or 422 response for invalid input. The code inserts the order directly without validating the initial status field, allowing orders to be created in an unintended state. This mismatch indicates a potential logic flaw that could let malicious or malformed orders be processed as paid or otherwise valid.

**Impact:** Attackers could create orders with arbitrary status values, potentially bypassing payment checks, causing financial discrepancies, inventory mismanagement, or triggering downstream workflows with incorrect state.

**Remediation:** Validate the 'status' field (and any other business-critical fields) before inserting into the database. Enforce that new orders start with a safe default status (e.g., 'pending') and reject or correct invalid values with a 400/422 response. Add input validation and unit tests for the order creation workflow.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.order_initial_state.1, observed status=200, expected_statuses=[400,422]`
- `source_excerpt shows create_order inserts row without status validation`

Limitations:
- Evidence is limited to a single runtime probe observation; other request variations may behave differently.
- No direct proof that the returned order is marked as paid; the probe only indicates unexpected success status.

### 35. Negative order prices accepted instead of rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** A runtime probe sent a POST request to /orders with a negative unit_price. The application returned HTTP 200 and inserted the record, whereas the expected behavior (per the probe contract) was to reject the request with a 4xx status. The source excerpt shows the endpoint directly inserts the supplied unit_price into the database without validation, confirming the lack of a check for negative values.

**Impact:** An attacker can create orders with negative prices, potentially leading to unauthorized credit, inventory manipulation, or financial loss for the system owner.

**Remediation:** Add input validation to ensure unit_price is non‑negative before inserting into the database. Return a 400/422 response when validation fails. Consider using database constraints (e.g., CHECK (unit_price >= 0)) as a defense‑in‑depth measure.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`
- `Source code excerpt shows no validation of body.unit_price before DB insertion`

Limitations:
- The probe only exercised a single negative price value; other validation paths were not tested.
- The evidence is limited to runtime behavior; static analysis of input sanitization elsewhere in the codebase was not performed.

### 36. Client-controlled price in order creation

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price value received from the request body directly into the database without any server-side validation or enforcement of catalog pricing. This allows a malicious client to specify arbitrary prices for items, violating the requirement that the catalog price must be set by the server.

**Impact:** An attacker can manipulate order totals, potentially causing financial loss, unauthorized discounts, or overcharging customers. This can be exploited to obtain goods at reduced cost or to disrupt billing systems.

**Remediation:** Implement server-side price lookup based on the item identifier and ignore or override any unit_price supplied by the client. Validate that the price matches the catalog entry before inserting the order, and consider removing unit_price from the request schema entirely.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Source excerpt shows body.unit_price is passed directly to the INSERT statement (lines 213-215).`
- `Runtime probe fact indicates a POST to /orders returned status 200, confirming the endpoint is reachable and processes the request.`

Limitations:
- The review is based on the provided code snippet; additional validation may exist elsewhere in the codebase that was not included. No evidence was found regarding any later price verification before order finalization.

### 37. Improper Authorization Check on Nested Note Resource

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID without verifying that the note's `order_id` matches the `order_id` supplied in the URL. The runtime probe confirms that a request to `/orders/1/notes/2` returned HTTP 200, whereas the security rule expected a 403 or 404, indicating missing access control. This allows an attacker to access notes belonging to other orders by guessing note IDs.

**Impact:** An attacker can enumerate or read notes from orders they do not own, leading to exposure of potentially sensitive information and violation of data confidentiality.

**Remediation:** Add a check after fetching the note to ensure `row['order_id'] == order_id`. If the IDs do not match, return a 403 Forbidden or 404 Not Found response. Example:
```python
row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()
if not row or row['order_id'] != order_id:
    raise HTTPException(404, "Note not found")
return dict(row)
```
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Source excerpt shows no order_id verification (lines 543-548).`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200, violating expected 403/404 (workflow.nested_note.1).`

Limitations:
- The review is based on a single runtime probe; additional testing may be needed to confirm consistency across different notes and orders. No information on authentication/authorization mechanisms beyond the `principal` call is provided.

### 38. Missing authorization check on order retrieval

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders/{order_id} calls principal(authorization) but does not enforce that the authenticated user is the owner of the requested order before returning the record. Runtime probing observed a successful 200 response for a request that should have been denied (expected 403 or 404), indicating the owner check is ineffective.

**Impact:** An attacker who can guess or enumerate order IDs can retrieve any user's order details, exposing personal and potentially sensitive information.

**Remediation:** Validate that the authenticated principal matches the order's owner before returning the record. For example, query the order's owner_id and compare it to the user ID extracted from the Authorization header, returning 403 if they differ.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Source excerpt shows get_order calls principal(authorization) but no ownership verification before returning the row`
- `Runtime probe fact: method GET to /orders/{{order_id}} returned status 200 where expected 403/404 (assertion_results false)`

Limitations:
- The review is based on a single runtime probe; additional testing with varied user contexts would strengthen confidence
- The principal function's implementation is not shown, so it is unclear if it performs any hidden checks

### 39. Missing discount bounds validation in apply_coupon endpoint

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The apply_coupon handler directly uses the discount value supplied in the request body (or the coupon's stored percent) without enforcing any upper limit. Runtime probing observed a successful 200 response for a request that should have been rejected (expected 400/422), indicating that excessive discount values are accepted. This lack of validation can allow attackers to apply arbitrarily large discounts to orders.

**Impact:** An attacker can obtain orders with discounts far exceeding intended limits, potentially resulting in financial loss or inventory depletion.

**Remediation:** Add validation to ensure the discount percentage does not exceed a defined maximum (e.g., 100% or business‑defined cap). Return a 400/422 error when the supplied discount is out of bounds. Consider sanitizing and validating the coupon code lookup as well.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Source code shows no upper‑bound check on the discount value (lines 231‑235).`
- `Runtime probe fact: assertion_results false, expected_statuses [400,422] but actual status 200 for POST /orders/{{order_id}}/apply-coupon.`

Limitations:
- The exact business rule for maximum allowed discount is not provided, so the severity assumes any unbounded discount is undesirable. No evidence of additional guard checks elsewhere in the codebase.

### 40. Paid orders can be cancelled without prior refund

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders/{order_id}/cancel endpoint updates the order status to "cancelled" and returns a 200 response regardless of the order's payment state. The runtime probe indicates the endpoint returned 200 (assertion_results false for expected 400/409/422), suggesting the required business rule (refund before cancellation) is not enforced.

**Impact:** An attacker or malicious user could cancel paid orders without processing a refund, leading to financial loss and potential abuse of the order management system.

**Remediation:** Implement a check that verifies the order's payment status and requires a successful refund before allowing cancellation. Return appropriate error codes (e.g., 400, 409, or 422) when the precondition is not met.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Source code shows cancel_order directly updates status to 'cancelled' and commits without refund logic (lines 259-263).`
- `Runtime probe fact: method POST to /orders/{{order_id}}/cancel returned status 200, while expected statuses were 400, 409, 422 (assertion_results false).`

Limitations:
- No additional context confirms whether other parts of the application enforce refund checks before this endpoint is called.
- The probe does not show the order's payment state, so the exact condition triggering the flaw is not fully verified.

### 41. Payment replay possible on /orders/{order_id}/pay endpoint

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The pay_order handler updates the order status to 'paid' without verifying whether the order has already been paid. The runtime probe observed a successful 200 response for a second POST to the same endpoint, while the scanner expected error statuses (400, 409, 422). This indicates that an attacker could replay a payment request and receive a new invoice, potentially causing double charging or fraudulent invoicing.

**Impact:** An attacker can submit multiple payment requests for the same order, resulting in duplicate charges, creation of multiple invoices, and financial loss or accounting inconsistencies.

**Remediation:** Add a check before processing the payment to verify that the order's status is not already 'paid'. Return an appropriate error (e.g., 409 Conflict) if a payment has already been recorded. Consider implementing idempotency keys or transaction tokens to prevent replay attacks.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Source code lines 242-250 show the order is fetched and then status is set to 'paid' without prior status check.`
- `Runtime probe fact: method POST to /orders/{{order_id}}/pay returned status 200, whereas the scanner expected 400/409/422, indicating the endpoint accepted a second payment.`

Limitations:
- The review is based on static code and a single runtime probe; it does not confirm whether other parts of the application (e.g., middleware) enforce payment state checks.
- No evidence was found regarding database constraints or external payment gateway safeguards that might mitigate replay.

### 42. Improper Access Control on User Profiles

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` retrieves user data based solely on the supplied `profile_id` after calling `principal(authorization)`, but does not verify that the authenticated principal is authorized to access the requested profile. The runtime probe observed a successful GET request to another user's profile returning HTTP 200, indicating that the access control check is missing or ineffective.

**Impact:** An attacker who can obtain a valid authentication token can enumerate or retrieve other users' personal information (username, email, SSN), leading to privacy violations and potential identity theft.

**Remediation:** Enforce ownership checks after authentication, e.g., compare the authenticated user's ID with `profile_id` and return 403 if they differ. Alternatively, implement role‑based access control to restrict profile access to the owner or authorized roles.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `Source code line 98‑104 shows the profile endpoint returns data without ownership verification.`
- `Runtime probe fact: request to `/profiles/{{other_id}}` returned status 200 instead of the expected 403/404.`

Limitations:
- The `principal` function's implementation is not shown; it may perform checks that are not reflected in the snippet. Additional testing is needed to confirm that no other middleware enforces access control.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /view returns an HTMLResponse without setting any X-Frame-Options or Content‑Security‑Policy frame‑ancestors directives. The source excerpt shows the raw HTML being returned and no header manipulation is present. The runtime probe confirms a GET request to /view was made, but no header evidence is provided, indicating the header is absent.

**Impact:** An attacker could embed the page in a malicious iframe, potentially tricking users into unintended actions (clickjacking).

**Remediation:** Add an appropriate anti‑clickjacking header, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, to the response in the view_home handler.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Source excerpt lines 686‑690 show HTMLResponse returned without header logic`
- `Runtime probe fact for GET /view (web-runtime zap.10020) indicates request was made`

Limitations:
- Only the absence of header is observed; no proof that the page is actually framed in a victim's browser
- No evidence of successful clickjacking exploitation

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime probe observed a GET request to /view and the response lacked the X-Content-Type-Options header. The source code shows the endpoint returns a raw HTMLResponse without setting security headers. While the scanner flagged this as low severity, the absence of the header can allow MIME type sniffing attacks.

**Impact:** An attacker could influence the browser to interpret the response as a different MIME type, potentially leading to cross‑site scripting or content injection.

**Remediation:** Add the X-Content-Type-Options: nosniff header to the response, e.g., by configuring a middleware or setting the header explicitly in the view_home function.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Runtime probe fact: GET /view response missing X-Content-Type-Options header (web-runtime zap.10021)`

Limitations:
- The evidence is limited to a single observed response; other routes or middleware may add the header in different environments. No confirmation whether the application sets security headers globally elsewhere.

### 45. Missing Content Security Policy (CSP) Header on /view

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /view returns an HTMLResponse constructed directly from a string literal and does not set any HTTP security headers. No runtime probe evidence shows a CSP header being added, and the source excerpt confirms the response is generated without header manipulation. While the absence of a CSP header is a security concern, the scanner alone cannot confirm exploitation, so the finding is treated as a likely vulnerability.

**Impact:** Without a CSP header, browsers may allow execution of inline scripts or loading of resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data injection attacks against users of the /view page.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response headers or a middleware, specifying a restrictive policy such as `default-src 'self'; script-src 'self'; object-src 'none';` and ensure it is applied to all HTML responses.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Source excerpt shows HTMLResponse returned without header configuration (lines 687‑690).`
- `Runtime probe fact indicates a GET request to /view but no header values are reported (values_redacted).`

Limitations:
- No runtime capture of actual response headers; the scanner did not provide concrete header data.
- The analysis assumes no other middleware sets CSP globally; if such middleware exists elsewhere in the codebase, the finding may be a false positive.

### 46. Webhook destination validation correctly enforced

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The source code explicitly checks that the provided target_url contains the string "mock-external" and raises an HTTP 400 error otherwise. The runtime probe observed a 200 response, which is consistent with a request that used an allowed mock destination. There is no evidence of an unrestricted webhook destination or SSRF vulnerability.

**Impact:** None, as the endpoint enforces the approved internal host and rejects other URLs.

**Remediation:** No remediation required; the validation logic is appropriate.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `source line 296-298 enforce mock-external check`
- `runtime probe fact shows status 200 for allowed input`

Limitations:
- Only a single request scenario was observed; other inputs were not tested, but the code path clearly rejects non‑mock URLs.

### 47. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code at api/app.py line 137 logs the application secret (APP_SECRET) in clear text using log.info. This exposes a credential in logs, which can be accessed by anyone with log access and may be stored unencrypted, violating confidentiality best practices.

**Impact:** Exposure of the application secret can lead to credential compromise, allowing attackers to impersonate the service, forge tokens, or access protected resources.

**Remediation:** Remove the secret from log statements. Avoid logging sensitive values altogether or mask/redact them. Use structured logging with redaction for any required debugging information.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `api/app.py:137 logs "login user=%s app_secret=%s" with os.environ.get("APP_SECRET", "lab-only")`

Limitations:
- The finding is based on static code analysis; runtime behavior may differ if logging configuration suppresses this message, but the code still contains the insecure logging statement.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any website to make cross‑origin requests to the API. This configuration can expose the service to CSRF-like attacks or data leakage when credentials are allowed, as allow_credentials is also set to true. While the scanner flagged this, the code snippet directly confirms the permissive settings.

**Impact:** An attacker-controlled website could interact with the API on behalf of a logged‑in user, potentially exfiltrating sensitive data or performing unauthorized actions if the API relies on cookies or other credentials.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. If credentials must be allowed, ensure only specific origins are permitted and consider removing allow_credentials if not required. Example:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted.example.com"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py lines 24‑29 show allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]`

Limitations:
- The finding assumes the API is publicly accessible; if the service is intended for internal use only, the risk may be reduced. No runtime probe data is available to confirm actual exploitation.

### 49. Potential Log Injection and Secret Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs a user‑provided username directly into the application log without sanitization and also logs the value of the APP_SECRET environment variable. This creates two issues: (1) an attacker can inject newline or control characters via the username to manipulate log entries (log injection/forgery), and (2) the secret value is written to logs, potentially exposing it to anyone with log access.

**Impact:** An attacker could corrupt log integrity, hide malicious activity, or cause denial‑of‑service by flooding logs. Exposure of APP_SECRET may enable further attacks such as token forgery or unauthorized access if logs are accessed by unauthorized parties.

**Remediation:** Sanitize or encode user‑controlled values before logging (e.g., escape newlines and control characters). Avoid logging sensitive secrets; remove APP_SECRET from log statements or mask it. Consider using structured logging with separate fields for safe data.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- The severity assessment assumes logs are stored where they could be accessed by an attacker; if logs are strictly internal and protected, impact may be reduced. The code does not show further processing of the log output, so the exact exploitability of log injection cannot be fully determined without runtime context.

### 50. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` that is directly passed to `RedirectResponse` without any validation or allow‑list checking. An attacker can supply an arbitrary URL, causing the application to redirect users to a malicious site after authentication.

**Impact:** Facilitates phishing attacks, credential harvesting, and can be used to bypass security controls by redirecting victims to malicious domains.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to relative paths only. If external URLs are required, ensure they are whitelisted and use safe URL construction methods.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source line 616 defines `continue_to(next: str = "/")` and line 617 returns `RedirectResponse(next, status_code=302)` without validation.`

Limitations:
- The code snippet does not show any surrounding middleware or global redirect validation that might mitigate the issue. Additional context is needed to confirm whether the `next` value is sanitized elsewhere.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the 'next' parameter by ensuring it starts with a single '/' and rejects URLs that start with '//' or contain a scheme or netloc. This prevents open redirects to external domains. The scanner’s generic warning about untrusted URL redirection is not applicable because the code enforces a local‑path constraint before issuing the RedirectResponse.

**Impact:** If the validation were bypassable, an attacker could redirect users to malicious sites, leading to phishing or drive‑by attacks. However, the implemented checks mitigate this risk.

**Remediation:** No remediation needed; the existing validation is sufficient. Maintain the strict check and consider adding unit tests for edge cases (e.g., encoded characters) to ensure continued protection.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Code at lines 621‑624 validates the 'next' parameter: it requires a leading '/' and rejects schemes, netlocs, and double slashes.`

Limitations:
- The review assumes the surrounding framework does not modify the 'next' value after validation. If additional processing occurs elsewhere, it could affect safety.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner flagged the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK can improve container observability, its absence does not constitute a security vulnerability. The Dockerfile otherwise follows best practices and does not expose insecure configurations.

**Impact:** Minimal. Without a HEALTHCHECK, container orchestration may not automatically detect unhealthy containers, but this does not directly expose the application to attack.

**Remediation:** Add a suitable HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`. This enhances operational reliability but is not required for security.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile lines show no HEALTHCHECK instruction`

Limitations:
- The assessment assumes no external policies mandate a HEALTHCHECK. If organizational compliance requires it, the finding may be relevant.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a best‑practice recommendation for container health monitoring but does not by itself constitute a security vulnerability. The absence may affect operational reliability, not confidentiality, integrity, or availability of the application.

**Impact:** Potentially reduced observability of container health, leading to delayed detection of failures; no direct security impact.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Source excerpt shows Dockerfile lines 1‑6 with no HEALTHCHECK instruction.`

Limitations:
- The finding is based solely on Dockerfile content; no runtime evidence indicates exploitation or security impact.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile for the worker service does not contain a HEALTHCHECK instruction. While adding a health check is recommended for operational robustness, its absence does not constitute a security vulnerability. The finding is based solely on static analysis of the Dockerfile and does not indicate an exploitable condition.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health monitoring, which is an operational concern rather than a security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD curl -f http://localhost/health || exit 1

This improves observability but is not required for security.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- The assessment is based on static file content; no runtime behavior was observed. The absence of a health check is a best‑practice issue, not a proven security flaw.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies (CVE-2026-53539)

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-53539, a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded request bodies. The scanner evidence directly references this CVE and notes that the issue is fixed starting with version 0.0.30. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can send a maliciously crafted request that causes the application to consume excessive CPU or memory, leading to service degradation or complete outage. Because FastAPI commonly uses python-multipart for handling file uploads, the vulnerability can be exploited in any endpoint that processes multipart/form‑data or url‑encoded bodies.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and rebuild/redeploy the application. Verify that the new version is installed by checking the lock file or the container image after rebuild.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt pins python-multipart==0.0.20`

Limitations:
- No runtime probe data was provided to confirm whether the vulnerable code path is exercised in the current deployment.
- The review assumes the listed dependency is actually installed; build‑time overrides or alternative installation mechanisms could change the effective version.

### 56. Denial of Service via excessive multipart part headers in python-multipart 0.0.20

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by crafted multipart requests with an excessive number of part headers. The scanner evidence directly references this CVE and notes that the issue is fixed in version 0.0.27. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially crashing the FastAPI service or rendering it unresponsive, leading to service outage.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later. Update the requirements.txt entry and rebuild/redeploy the application. Optionally add input validation or size limits for multipart uploads as defense‑in‑depth.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- The review is based solely on the declared dependency version; no runtime instrumentation or additional guard checks were provided.

### 57. python-multipart: Information disclosure due to parser differential in form data handling (CVE-2026-53538)

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The scanner identified this CVE and noted that it is fixed in version 0.0.30. No additional evidence was found indicating that the vulnerable code path is exercised or mitigated in the application.

**Impact:** If an attacker can supply crafted multipart/form-data requests, they may trigger the parser differential and cause unintended information disclosure, potentially exposing sensitive request data.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and verify that the application functions correctly after the upgrade. Consider running dependency scanning and testing to ensure no regressions.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt pins python-multipart==0.0.20`

Limitations:
- The finding is based solely on the presence of the vulnerable version in the dependency list; no runtime evidence confirms the vulnerable code path is reachable.
- No information on whether the application actually processes multipart/form-data inputs.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-40347 – a denial‑of‑service issue triggered by specially crafted multipart/form-data payloads. The scanner identified this dependency and the associated CVE. While the presence of the library does not guarantee it is exercised in the application, the risk remains because any endpoint that parses multipart requests could be affected.

**Impact:** An attacker could send a malicious multipart request that exhausts CPU or memory, causing the service to become unresponsive and potentially leading to a denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, which contains the fix for CVE-2026-40347. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`

Limitations:
- The review does not confirm whether the application actually processes multipart/form-data requests; if no such functionality exists, the practical exploitability may be reduced. No runtime probe data was available to verify the presence of vulnerable code paths.

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to contain CVE-2026-24486, a path‑traversal flaw that allows an attacker to write arbitrary files on the server when processing multipart/form‑data. The scanner identified the vulnerable version and the CVE reference, and no mitigating controls were observed in the repository.

**Impact:** An attacker who can upload crafted multipart requests could write files to arbitrary locations, potentially achieving remote code execution, defacement, or data exfiltration.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, which includes the fix for CVE-2026-24486. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- The review relies on the version declaration in requirements.txt; it does not verify whether the application actually processes multipart uploads or applies additional sanitization.

### 60. python-multipart 0.0.20 contains CVE-2026-53537

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to be vulnerable to CVE-2026-53537, an information disclosure issue caused by header parsing discrepancies. The vulnerability is documented and fixed in version 0.0.30. No evidence was found that the project applies a mitigation or uses a patched version.

**Impact:** An attacker could exploit the header parsing flaw to obtain sensitive information from HTTP requests processed by the application, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry and rebuild/redeploy the application to incorporate the patched library.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies on the listed dependency version; if the runtime environment overrides this version, the finding may not apply. No runtime probe confirms the vulnerability is exploitable in the current deployment.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner identified CVE‑2026‑53540 affecting python‑multipart version 0.0.20. The vulnerability description states that a negative Content‑Length header can cause the entire request body to be buffered in memory, leading to potential denial‑of‑service. The project’s requirements.txt pins python‑multipart at 0.0.20, which is the vulnerable version. No evidence was provided that the application mitigates or patches this behavior, and the fix is available in version 0.0.31.

**Impact:** An attacker can craft a request with a malformed Content‑Length header, causing the server to allocate unbounded memory and potentially crash or become unresponsive, resulting in denial‑of‑service.

**Remediation:** Upgrade python‑multipart to version 0.0.31 or later, which contains the fix for CVE‑2026‑53540. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`

Limitations:
- The review is based solely on the declared dependency version; runtime behavior was not observed. No additional context (e.g., custom patches or mitigations) was available.

### 62. Dynamic urllib usage may allow unsafe URL construction

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner flagged the use of urllib.request with a dynamically constructed URL (BASE + path). While urllib can handle file:// schemes, the code appears to build the URL from a constant base and a path argument. Without evidence that the path argument can be influenced by an attacker, the risk of arbitrary file read or SSRF cannot be confirmed. The finding is low severity and the scanner confidence is low, so additional context (e.g., validation of the path parameter, allowed schemes, or runtime observations) is required to determine if this is a true vulnerability.

**Impact:** If an attacker can control the path value and the application permits file:// URLs, they could potentially read arbitrary files on the server or perform SSRF attacks, leading to data disclosure or internal network probing.

**Remediation:** Validate and sanitize the `path` argument to ensure it does not contain malicious input or unsupported schemes. Prefer using higher‑level HTTP libraries such as `requests` that do not support file:// by default, or explicitly restrict the URL scheme to http/https. Consider constructing URLs with safe utilities (e.g., `urllib.parse.urljoin`) and enforce a whitelist of allowed endpoints.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen called with `BASE + path` without apparent input sanitization.`

Limitations:
- No runtime probe data confirming attacker‑controlled input to `path`. The code context does not reveal validation or restriction of URL schemes. The scanner’s confidence is low, and no additional evidence (e.g., tests, logs) is provided.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a urllib request built from a dynamic value (payload["target_url"]). While urllib can handle file:// URLs, there is no evidence that the "target_url" field is attacker-controlled or that file URLs are permitted. No runtime probe facts or additional evidence confirm exploitation potential.

**Impact:** If an attacker can control the URL and supply a file:// scheme, they could read arbitrary files on the host, leading to information disclosure.

**Remediation:** Validate and sanitize the "target_url" input to ensure only allowed schemes (e.g., https) are used, or switch to a safer HTTP client library such as requests. Consider adding explicit scheme checks and reject or whitelist URLs.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Detected a dynamic value being used with urllib at worker/worker.py line 23.`

Limitations:
- No runtime observations confirming attacker-controlled input or file:// usage.
- No additional scanner or AI evidence linking this to a concrete vulnerability.

### 64. Potential missing CSRF protection on comment creation endpoint

- Issue group: `ai-4196b29d917ef3c8`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The POST /comments endpoint inserts a comment using the authenticated user identity but the source code shows no explicit CSRF token validation or anti‑CSRF middleware invocation. In cookie‑based authentication scenarios this could allow a forged request from another site to create comments on behalf of the victim. However, the repository does not reveal whether a global CSRF protection layer (e.g., FastAPI middleware, SameSite cookie settings, or a custom dependency) is applied elsewhere, so the finding cannot be confirmed as a definite vulnerability.

**Impact:** If an attacker can trick a logged‑in user into submitting a forged POST request, they could create arbitrary comments linked to the victim’s account, leading to content pollution, potential defacement, or escalation of trust in user‑generated content.

**Remediation:** Add CSRF protection for state‑changing endpoints. Options include: • Enabling FastAPI’s CSRF middleware or integrating a third‑party solution that validates a token sent in a custom header or hidden form field. • If using cookie‑based auth, set the SameSite attribute to "Strict" or "Lax" and ensure cookies are marked HttpOnly. • Alternatively, switch to a token‑based authentication scheme (e.g., Bearer JWT) that is not vulnerable to CSRF.
Evidence:
- Source IDs: `ai-4196b29d917ef3c8`
- `api/extra.py:161 – @router.post("/comments") defines the POST endpoint`
- `api/extra.py:162 – function signature lacks any CSRF‑related parameter`
- `api/extra.py:165‑168 – database INSERT performed without prior CSRF check`

Limitations:
- No visibility into application‑wide middleware configuration; a global CSRF guard could already protect this route
- Authentication method is unclear (could be bearer token in Authorization header, which is not vulnerable to CSRF)
- SameSite cookie attributes or other client‑side mitigations are not shown in the provided files

### 65. Potential insecure file path handling in file_read endpoint

- Issue group: `ai-78673854a96cfd0a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint builds a file path from a user‑supplied "name" parameter, resolves it (following symlinks), and then checks that the resolved path is within the public directory using Path.is_relative_to. This check occurs after resolution, so a crafted name that traverses into a symlink pointing outside the public directory could bypass the restriction. Additionally, is_relative_to is only available on Python 3.9+, and its behavior with symlinks may not prevent directory escape. The code does not perform any pre‑validation of traversal sequences (e.g., "../").

**Impact:** An attacker could retrieve arbitrary files on the server filesystem that are reachable via symlinks or other path tricks, potentially exposing source code, configuration, or sensitive data.

**Remediation:** Validate the "name" parameter before path resolution (e.g., reject ".." components), use a safe join that does not follow symlinks, or resolve the path and then compare the resolved parent directory without following symlinks (e.g., using pathlib.Path.resolve(strict=False) and checking against a whitelist). Consider disabling symlink following or normalizing the path with os.path.normpath and ensuring it stays within the intended directory.
Evidence:
- Source IDs: `ai-78673854a96cfd0a`
- `212: file = (FILES / "public" / name).resolve()`
- `213: if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214: raise HTTPException(404, "File not found")`

Limitations:
- The runtime Python version is not confirmed; behavior of Path.is_relative_to may differ on older versions.
- The presence of symlinks inside the public directory is unknown, which affects exploitability.
- No additional validation of the "name" parameter elsewhere in the codebase was observed.

### 66. Potential missing admin authorization check in admin_audit endpoint

- Issue group: `ai-13b4fb7004145655`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The admin_audit endpoint calls require_admin but the implementation of require_admin is not present in the repository snapshot. Without confirming that require_admin validates the token and enforces an admin role, it cannot be determined whether the endpoint is protected. The evidence shows the call exists, but the lack of source code for the check prevents a definitive vulnerability determination.

**Impact:** If require_admin does not correctly enforce admin privileges, any authenticated or unauthenticated user could invoke /admin/audit and receive a response indicating authorized status, potentially exposing privileged information or enabling further unauthorized actions.

**Remediation:** Locate the definition of require_admin and verify that it: (1) validates the provided token, (2) checks that the token’s role is admin, (3) handles missing or malformed tokens with appropriate error responses, and (4) logs unauthorized access attempts. If the function is missing or insufficient, implement proper role‑based access control and return HTTP 403 for non‑admin callers.
Evidence:
- Source IDs: `ai-13b4fb7004145655`
- `205: def admin_audit(authorization: str | None = Header(default=None)) -> dict:`
- `206:     require_admin(authorization)`
- `207:     return {"status": "authorized"}`

Limitations:
- The source code for require_admin is not available, so its behavior cannot be confirmed.
- No runtime observations (e.g., request/response logs) are provided to show whether unauthorized calls are rejected.

### 67. Potential exposure of sensitive user data (SSN) via /me endpoint

- Issue group: `ai-74d29c546a00c466`
- Verdict: **likely_vulnerability**
- Severity: **critical**
- Confidence: **medium**

**Explanation:** The /me endpoint returns all columns from the users table, including the SSN field, for the user identified by the token passed to the principal function. The implementation of principal is not provided, so it cannot be confirmed that it enforces authentication, token validation, or restricts the returned fields. If principal fails to verify the token or allows token substitution, an attacker could retrieve arbitrary users' SSNs by supplying a crafted Authorization header.

**Impact:** Disclosure of Social Security Numbers can lead to identity theft, fraud, and severe privacy violations. Exposure of this highly sensitive PII is a critical security breach.

**Remediation:** - Ensure the principal function validates the Authorization header, checks token integrity, expiration, and that the token’s subject matches the authenticated user.
- Limit the fields returned by the /me endpoint to only those necessary (e.g., exclude SSN). Use explicit column selection or a DTO that omits sensitive data.
- Add role‑based access control to restrict who can view SSN, if any role requires it.
- Consider encrypting SSN at rest and never returning it in API responses.
- Add comprehensive unit and integration tests for authentication and data exposure logic.
Evidence:
- Source IDs: `ai-74d29c546a00c466`
- `199: @app.get("/me")`
- `200: def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `201:     user = principal(authorization)`
- `202:     with connection() as conn:`
- `203:         row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()`
- `204:     return dict(row or {})`

Limitations:
- The source code for the principal function is not available, so its security guarantees cannot be verified.
- No runtime probe data confirming that unauthorized requests can retrieve another user's SSN.
- The review assumes the database query returns the SSN field as stored; encryption or masking at the DB layer is not known.

### 68. Potential information disclosure via /me endpoint

- Issue group: `ai-c8716ef14f271f4b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint returns all user fields including email and SSN without any filtering or additional authorization checks beyond extracting the token payload. If an attacker can obtain a valid token for another user, they could retrieve sensitive personal data such as email addresses and Social Security Numbers.

**Impact:** Exposure of personally identifiable information (PII) can lead to identity theft, fraud, and privacy violations, and may violate regulatory requirements (e.g., GDPR, HIPAA).

**Remediation:** Implement proper scope/consent checks to ensure the requesting user is authorized to view sensitive fields. Consider omitting or masking PII (e.g., SSN) in responses, and add audit logging for accesses to this endpoint.
Evidence:
- Source IDs: `ai-c8716ef14f271f4b`
- `199: @app.get("/me")`
- `201: user = principal(authorization)`
- `203: row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()`
- `204: return dict(row or {})`

Limitations:
- The review assumes the principal function does not perform additional authorization or field‑level masking; this was not verified in the provided excerpts.
- No evidence was found regarding audit logging or rate‑limiting for this endpoint.

### 69. Potential path traversal bypass in verified_file_read endpoint

- Issue group: `ai-c8bdb64644878d8f`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint builds a file path using Path.resolve() and then checks file.is_relative_to(root) before reading the file. While this check prevents simple "../" traversal, it does not guarantee protection against symlink attacks where an attacker places a symlink inside the public directory that points outside the root. The code does not perform a second realpath check after following symlinks, nor does it explicitly forbid symlinks. However, the review lacks concrete evidence that such symlinks can be created in the deployment environment, that the filesystem is case‑insensitive, or that additional validation (e.g., whitelist) is in place. Without runtime observations or deployment‑specific constraints, the presence of a vulnerability cannot be confirmed.

**Impact:** If an attacker can place a symlink in the public directory, they could read arbitrary files on the server, potentially exposing source code, configuration secrets, or other sensitive data.

**Remediation:** - Reject or resolve symlinks after constructing the final path (e.g., use pathlib.Path.resolve(strict=True) after the is_relative_to check). 
- Consider using a whitelist of allowed filenames or extensions. 
- Ensure the deployment environment disallows creation of symlinks in the public directory or runs the service with reduced privileges. 
- Add unit tests that attempt to traverse via symlinks and verify the request is rejected.
Evidence:
- Source IDs: `ai-c8bdb64644878d8f`
- `api/extra.py lines 218‑224 show the path resolution and is_relative_to check`
- `The code reads the file directly after the check without additional symlink validation`

Limitations:
- No runtime probe confirming whether symlinks can be created in the public directory
- No evidence about filesystem case‑sensitivity or Unicode normalization handling
- No information about additional validation layers (whitelists, ACLs) that might mitigate the issue

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
- `merged-17a5197f906426a224ef`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-65c41e5a25b6337fec07`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-1ba9f8276fc6dae95df8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-cc8a9ed20905505868f0`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-b4c1c4d005665a5249a7`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a9e9047867c909f567ad`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-7da23d65adeef42d71a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e683a977084f2bbcee2e`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-dd64ece99563dbbb173a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2b80ed0c48c0c70a93a4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-50485291173e2448f7c7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ade7b890a037d8c82a1f`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
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
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-4196b29d917ef3c8`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-78673854a96cfd0a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-13b4fb7004145655`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-74d29c546a00c466`: **warn** — RG-003: critical likely vulnerability requires manual review; not auto-confirmed.
- `ai-c8716ef14f271f4b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-c8bdb64644878d8f`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **69**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **13**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **4**; uncertain overlaps: **2**; needs more evidence: **7**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-d1c75a3ea36e4e95`: needs_more_evidence
- `ai-79b22888b770beda`: needs_more_evidence
- `ai-091e17e523a79451`: needs_more_evidence
- `ai-1c91333bfe5bde49`: needs_more_evidence
- `ai-e60791da246d7bce`: needs_more_evidence
- `ai-78673854a96cfd0a`: uncertain_overlap
- `ai-c8bdb64644878d8f`: uncertain_overlap
- `ai-8e1e7fd5d3d55837`: needs_more_evidence
- `ai-c687fb9837a9b62d`: needs_more_evidence

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

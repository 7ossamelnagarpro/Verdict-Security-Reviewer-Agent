# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-03T11:23:52.430677+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **2**.

The agent reviewed **67** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **67**; reviewed: **67**; pending: **0**.

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

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string without any sanitisation or parameterisation. This allows an attacker to inject arbitrary SQL syntax via the username or password fields, leading to authentication bypass or data exfiltration.

**Impact:** An attacker can perform SQL injection to bypass authentication, retrieve or modify user records, and potentially execute arbitrary database commands, compromising confidentiality, integrity, and availability of the application data.

**Remediation:** Refactor the query to use parameterised statements (e.g., prepared statements) provided by the database library. Example: `query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"; row = conn.execute(query, (body.username, body.password)).fetchone()`. Additionally, hash passwords with a strong algorithm and compare hashes instead of storing plain text passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117 constructs the query with f‑string interpolation of `body.username` and `body.password``
- `The query string is executed directly via `conn.execute(query)` without sanitisation`

Limitations:
- No runtime probe data was provided to confirm exploitation, but the code pattern is a well‑known SQL injection vector.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known root directory and then checks both that the resulting path is still within that root (is_relative_to) and that it points to an existing file (is_file). These checks prevent directory traversal attacks, so the finding that user input is used in a path expression does not constitute a vulnerability in this context.

**Impact:** If the checks were bypassable, an attacker could read arbitrary files. However, the combined use of resolve() and is_relative_to() effectively blocks path traversal, so no impact is present.

**Remediation:** No remediation required; the existing validation is sufficient. Ensure the Python version supports Path.is_relative_to (Python 3.9+) and that FILES points to the intended public directory.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 220‑223 show the root resolution and the is_relative_to check`
- `source_symbol confirms the same logic`

Limitations:
- The analysis assumes the runtime environment uses a Python version where Path.is_relative_to correctly enforces the relative path check. If an older Python version is used, the method may be unavailable, which could affect security.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks `file.is_relative_to(root)` before accessing the file. This check ensures the resolved path cannot escape the designated `public` directory, effectively mitigating path traversal. The scanner flagged the use of user input in a path expression, but the subsequent safety check makes the finding non‑exploitable.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server. Because the check is present and correctly used, no confidentiality breach is possible via this endpoint.

**Remediation:** No remediation required; the existing `is_relative_to` guard is sufficient. Ensure future code maintains similar directory traversal protections when handling user‑supplied paths.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source_excerpt lines 218‑224 show the use of `Path.resolve()` and `is_relative_to(root)` guard`
- `source_symbol confirms the same logic`

Limitations:
- The review assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If an older runtime is used, the guard may not exist, which could reintroduce risk.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The code constructs the file path using a user‑provided `name` but then resolves it and checks both that the resolved path is within the allowed `FILES/public` directory (`is_relative_to(FILES.resolve())`) and that the target is an existing file (`is_file()`). These checks prevent directory traversal and arbitrary file reads, so the scanner’s finding is not a true vulnerability.

**Impact:** If the check were bypassed, an attacker could read arbitrary files, but the existing checks mitigate this risk.

**Remediation:** No remediation needed; the current validation is sufficient. Ensure that `FILES` is correctly set to the intended base directory and that symbolic links cannot be used to escape the directory.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Line 212 constructs the path with `(FILES / "public" / name).resolve()``
- `Line 213 checks `not file.is_relative_to(FILES.resolve())` to enforce the file stays within the base directory`
- `Line 213 also checks `not file.is_file()` to ensure the target exists`

Limitations:
- The review assumes `FILES` is a trusted absolute path and that the runtime environment does not allow symlink attacks that could bypass `is_relative_to`. No runtime probe facts were provided to confirm behavior under attack conditions.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a fixed root directory and then verifies that the resulting path is a descendant of that root (is_relative_to) and that it points to an existing file. These checks effectively prevent directory traversal attacks, so the scanner’s finding is not indicative of a vulnerability.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to data disclosure. However, the implemented checks mitigate this risk.

**Remediation:** No remediation needed for this specific issue; the existing path validation is sufficient. Ensure future code follows the same pattern when handling user‑controlled file paths.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `source_excerpt lines 220‑224 show resolution of root and file, followed by is_relative_to(root) and is_file() checks before reading the file.`

Limitations:
- The analysis assumes that the Python version supports Path.is_relative_to (Python 3.9+). If running on an older version, this method would not exist, potentially altering behavior. No runtime probe data was provided to confirm execution path.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory and then verifies that the resulting path is still within that base directory (is_relative_to) and that it points to an existing file (is_file). These checks prevent directory traversal attacks, making the reported uncontrolled path usage ineffective as a vulnerability.

**Impact:** If the checks were bypassed, an attacker could read arbitrary files, but the explicit relative‑path validation mitigates this risk.

**Remediation:** No remediation needed; the existing path validation is sufficient. Ensure that the FILES constant is correctly set to the intended public directory and that resolve() does not follow symlinks that could escape the base path.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `Source excerpt shows use of Path.resolve() followed by is_relative_to(FILES.resolve()) and is_file() checks.`

Limitations:
- The analysis assumes that FILES is a trusted absolute path and that resolve() does not introduce symlink‑related escape vectors. If symlinks are present within the public directory, additional checks may be required.

### 7. Reflected XSS in catalog search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `catalog_search` endpoint reflects the user‑controlled query parameter `q` directly into an HTML response without any escaping or sanitisation. The returned string is constructed with an f‑string that inserts `q` into an `<h1>` element and then concatenates product names. This allows an attacker to supply a payload such as `<script>alert(1)</script>` which will be rendered by the browser, resulting in reflected cross‑site scripting. No evidence was found that the response is later processed by a templating engine that auto‑escapes, nor that CSP headers mitigate script execution.

**Impact:** An attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, or other malicious actions against users of the affected endpoint.

**Remediation:** Validate and sanitise the `q` parameter before embedding it in the HTML response. Use a proper templating engine that auto‑escapes output, or explicitly HTML‑escape the value (e.g., `html.escape(q)`). Consider adding a Content‑Security‑Policy header that restricts script execution.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`, `ai-4cc4fb67df96e43d`
- `api/extra.py:142 defines `catalog_search(q: str = "")` and returns `f"<h1>Results for {q}</h1>" + ...` without escaping`
- `api/extra.py:144 executes a raw SQL query with `q` interpolated, but the XSS issue is the later HTML response at line 145`
- `AI evidence notes the missing HTML‑escape check at line 145`

Limitations:
- The review does not confirm whether downstream middleware or a templating layer might apply automatic escaping
- No runtime probe data was available to demonstrate actual script execution or CSP enforcement

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" but immediately resolves it and checks that the resulting path is within the allowed "FILES/public" directory using `is_relative_to(FILES.resolve())` and verifies the file exists. This effectively prevents directory traversal attacks, so the scanner’s finding is not a true vulnerability.

**Impact:** None – the path is safely constrained, preventing unauthorized file access.

**Remediation:** No remediation needed; the existing relative‑path check is sufficient. Ensure the check remains in place if the code is modified.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Source excerpt shows the use of `Path.resolve()` and `is_relative_to(FILES.resolve())` to enforce the file stays within the intended directory.`

Limitations:
- The analysis assumes `FILES` is correctly defined and immutable at runtime. If `FILES` could be altered or symlinks are present, additional checks may be required.

### 9. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL statement by directly interpolating the query parameter `q` into the query string using an f‑string. This allows an attacker to control part of the SQL command, leading to a classic SQL injection vulnerability. The code does not use parameterised queries or any sanitisation before executing the statement.

**Impact:** An attacker can inject arbitrary SQL, potentially reading, modifying, or deleting data from the `products` table or other tables in the database. This could lead to data leakage, data corruption, or privilege escalation depending on database permissions.

**Remediation:** Replace the f‑string with a parameterised query using the database driver’s placeholder syntax (e.g., `SELECT name FROM products WHERE name ILIKE %s` with a bound parameter). Additionally, validate and sanitise the `q` input, and consider limiting the length of the parameter.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt shows f‑string interpolation of `q` into SQL at line 144: `conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'")``
- `Scanner evidence flagged the query as built from a user‑provided value`

Limitations:
- No runtime probe data is available to confirm exploitation in the deployed environment. The review is based solely on static code analysis of the provided excerpt.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scan reports that the HTTP response for the root path (GET /) does not include the X-Content-Type-Options header. The source excerpt shows the FastAPI endpoint implementation, which does not set any security headers. No runtime probe evidence contradicts this finding. Absence of this header can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks.

**Impact:** An attacker could exploit MIME type sniffing to execute malicious scripts if the application serves user‑controlled content with ambiguous types, increasing the risk of XSS or drive‑by attacks.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options: nosniff header on all responses, e.g., using Starlette's Middleware or a custom response header injection. Verify the header is present in production responses.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `Runtime probe fact: GET / request observed without X-Content-Type-Options header (scanner_id: web-runtime, rule_id: zap.10021)`

Limitations:
- Evidence is limited to a single observed request; other endpoints may behave differently. The scan does not confirm whether a reverse proxy or CDN might add the header downstream.

### 11. Unauthorized access to admin job listings

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /admin/jobs endpoint returns HTTP 200 and the job data without requiring an admin role. The runtime probe expected a 403/404 response but observed a 200, indicating the principal() authorization check does not block non‑admin users.

**Impact:** An attacker can enumerate, view, and potentially infer internal job information, leading to information disclosure and facilitating further attacks such as targeted phishing or privilege escalation.

**Remediation:** Enforce proper role‑based access control on the /admin/jobs endpoint. Ensure the principal() function validates that the caller has an admin role before querying the database, and return 403 for unauthorized requests.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Runtime probe: GET /admin/jobs returned status 200 (expected 403/404)`
- `Source code shows admin_jobs calls principal(authorization) but no explicit admin role check before returning data`

Limitations:
- The probe only verifies the response for a single request; additional testing with varied credentials would confirm that the lack of role enforcement is consistent across users.

### 12. Improper access control on /admin/token-report endpoint

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a GET request to /admin/token-report returned HTTP 200 instead of the expected 403 for a non‑admin role, indicating that the role check is not enforced correctly. The source code shows a role check, but the observed behavior contradicts it, suggesting a logic flaw or misconfiguration that allows demoted administrators to retain access.

**Impact:** An attacker who can obtain or retain a non‑admin token could access administrative functionality, potentially exposing sensitive data or allowing privileged actions.

**Remediation:** Ensure that the role verification correctly denies access for non‑admin users. Verify that the token parsing and role extraction logic works as intended, and add comprehensive tests for role‑based access control. Consider adding logging and monitoring for unauthorized access attempts.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Runtime probe (web-runtime) observed status 200 for GET /admin/token-report when token.role != "admin" (expected 403)`

Limitations:
- Evidence is based on a single runtime probe; additional testing is needed to confirm consistency across environments and request variations. The source excerpt shows the intended check, but the actual token handling may differ.

### 13. Unauthorized user listing endpoint

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users endpoint returns a full list of user records, including sensitive fields such as email, role, and SSN, after calling principal(authorization) but without any explicit role check. Runtime probing observed a 200 OK response for an unauthenticated request, whereas the expected statuses were 403 or 404, indicating that the access control is insufficient.

**Impact:** An attacker can enumerate all user accounts and retrieve personally identifiable information (PII) and sensitive identifiers, facilitating further attacks such as credential stuffing, phishing, or identity theft.

**Remediation:** Enforce proper authorization checks in the admin_users handler, ensuring that only users with an admin role can access the endpoint. Verify the principal function returns role information and add a role check before querying the database. Consider returning only non-sensitive fields or implementing pagination and rate limiting.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Source code shows admin_users endpoint returns all user rows without role verification (lines 278-282).`
- `Runtime probe fact: GET /admin/users returned status 200, while expected statuses were 403/404 (scanner_id:web-runtime, rule_id:workflow.admin_users.2).`

Limitations:
- The exact behavior of the principal() function is not shown; it may perform role validation internally, but no evidence is present in the provided excerpt. Further testing with valid admin credentials is needed to confirm the access control gap.

### 14. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /auth/form-login returns responses without a Content Security Policy header. Absence of CSP allows browsers to load resources and execute inline scripts without restriction, increasing the risk of cross‑site scripting (XSS) and data injection attacks. The scanner flagged this omission, and no contradictory evidence was found in the source code or runtime probes.

**Impact:** An attacker who can inject malicious JavaScript into pages served by this endpoint could execute code in the context of the victim's browser, potentially stealing session cookies, performing actions on behalf of the user, or exfiltrating sensitive data.

**Remediation:** Configure the application or web server to include a strong CSP header on all responses, e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self'; object-src 'none';` and consider adding `report-uri` or `report-to` directives for monitoring. Review any inline scripts and adjust the policy accordingly.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner evidence: "Content Security Policy (CSP) Header Not Set" for path /auth/form-login`

Limitations:
- The finding is based solely on header inspection; no runtime probe confirmed the header's absence beyond the scanner's observation. No evidence was found of inline script usage that would be exploitable, so the actual exploitability may vary.

### 15. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The scanner flagged a missing anti-clickjacking header (e.g., X-Frame-Options) for the /auth/form-login endpoint, but the provided source excerpt only shows the login handling code and does not include any response header configuration. No runtime probe facts or response header data were supplied to confirm the header is absent. Without evidence that the server omits the header, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header were truly missing, an attacker could embed the login page in a malicious iframe to perform clickjacking attacks, potentially leading to credential theft.

**Remediation:** Ensure that responses from the /auth/form-login endpoint include an appropriate anti-clickjacking header such as `X-Frame-Options: SAMEORIGIN` or `Content-Security-Policy: frame-ancestors 'self'`. This can be set globally in the FastAPI middleware or per‑response before returning the HTMLResponse.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Missing Anti-clickjacking Header (scanner finding)`

Limitations:
- No response header data was provided; the source code excerpt does not show header handling. The scanner finding alone is insufficient to confirm the vulnerability.

### 16. Cookie missing HttpOnly flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The form_login endpoint sets a session cookie (lab_session) without specifying the HttpOnly attribute. This allows client‑side scripts to read the cookie, increasing the risk of theft via XSS. The finding is based on runtime probe evidence that the endpoint returns a Set-Cookie header without HttpOnly, and the source code shows response.set_cookie called without HttpOnly parameters.

**Impact:** An attacker who can inject JavaScript into pages served by the application could read the session cookie and hijack user sessions, leading to unauthorized access.

**Remediation:** Set the HttpOnly flag when creating the session cookie, e.g., response.set_cookie("lab_session", f"session-{row['id']}", httponly=True). Also consider adding Secure and SameSite attributes.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `response.set_cookie("lab_session", f"session-{row['id']}") in source code (lines 299‑301)`
- `runtime probe fact: POST /auth/form-login returned Set-Cookie without HttpOnly (scanner_id:web-runtime, rule_id:zap.10010)`

Limitations:
- The review assumes the Set-Cookie header is sent as observed; the probe does not capture other cookie attributes that might be set elsewhere (e.g., middleware). No evidence of HttpOnly being added later in the response chain.

### 17. Password reset tokens may be reusable

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe exercised the password reset confirmation endpoint with a token and observed a 200 OK response, whereas the security rule expects error statuses (400, 409, 422) for invalid or reused tokens. This indicates that the token was accepted and the password was changed, suggesting the token is not single‑use as required.

**Impact:** An attacker who obtains a valid reset token could reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity of user data.

**Remediation:** Implement a one‑time use check for reset tokens: after a successful password reset, delete or invalidate the token in the database, and ensure subsequent uses of the same token return an error (e.g., 400).
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Runtime probe returned status 200 for POST /auth/reset/confirm with a token that should be invalid after first use (runtime_probe_facts).`
- `Source code shows token lookup but no explicit deletion or invalidation of the token after use.`

Limitations:
- The probe does not show whether the token was previously used in this test session; it only demonstrates that a token can be accepted without error. Additional testing is needed to confirm that the token remains valid after a successful reset.

### 18. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the HTTP response for GET /catalog/query does not include a Content‑Security‑Policy header. The provided source excerpt shows that the endpoint returns an HTMLResponse built from user‑controlled query parameters, but no middleware or response modification is shown that would add CSP headers. The runtime probe confirms a GET request was made, but does not capture response headers, so the absence of CSP cannot be disproven.

**Impact:** Without a CSP header, browsers are free to execute any inline scripts or load resources from arbitrary origins, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks, especially given that the endpoint reflects user input into the HTML response.

**Remediation:** Configure the FastAPI application to include a CSP header on all responses, e.g., using Starlette's `Middleware` or a custom response class:
```python
from starlette.middleware.base import BaseHTTPMiddleware
class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
        return response
app.add_middleware(CSPMiddleware)
```
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Scanner evidence: "Content Security Policy (CSP) Header Not Set" for path /catalog/query`
- `Source code shows HTMLResponse returned without CSP handling`
- `Runtime probe fact: GET request to /catalog/query (no header data captured)`

Limitations:
- The runtime probe does not capture response headers, so the finding relies solely on the scanner's header analysis; the application could set CSP elsewhere (e.g., via a reverse proxy) which is not visible in the provided code. No direct evidence confirms the header is absent in production.

### 19. X-Content-Type-Options Header Missing

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /catalog/query does not include the X-Content-Type-Options header. The source code shows the endpoint returns an HTMLResponse but does not set security headers explicitly. No contradictory evidence (e.g., middleware adding the header) was found in the provided excerpts or runtime probe facts. Therefore the finding is plausible, though confirmation would require observing an actual response or checking global response‑header configuration.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Configure the FastAPI application (or the ASGI server) to add the X-Content-Type-Options header with the value "nosniff" for all responses, e.g., using Starlette's Middleware or a custom response‑header decorator.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Scanner evidence: X-Content-Type-Options Header Missing (zap.10021) for path /catalog/query`
- `Source code defines GET endpoint without setting security headers`

Limitations:
- No runtime capture of actual response headers was provided; the finding relies solely on scanner observation.
- Potential global middleware that adds the header is not visible in the excerpt, so the absence cannot be definitively proven.

### 20. Missing Anti-clickjacking Header on /catalog/query

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting any anti-clickjacking header such as X-Frame-Options or Content‑Security‑Policy frame‑ancestors. The source excerpt shows the FastAPI route returning an HTMLResponse directly, and the runtime probe confirms a GET request was made to this path. No header injection is observed in the code, indicating the header is likely omitted at runtime.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., set X-Frame-Options: SAMEORIGIN or configure a Content‑Security‑Policy with frame‑ancestors. In FastAPI this can be done via a middleware or by customizing the response headers in the route.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Source excerpt shows HTMLResponse returned without header manipulation (lines 148‑153).`
- `Runtime probe fact from scanner web-runtime (zap.10020) indicates a GET request to /catalog/query was observed.`

Limitations:
- The analysis relies on static code inspection and a single runtime probe; it does not capture dynamic header setting elsewhere in the application (e.g., global middleware).
- No explicit test confirms the header is absent in all responses, only that it was not set in the examined code path.

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the GET /comments endpoint does not include the X-Content-Type-Options header. The source code shows the endpoint returns HTML content without explicitly setting security headers. While the missing header is a known best‑practice issue, the evidence is limited to a single scanner finding and no runtime verification of response headers was provided.

**Impact:** Browsers may perform MIME type sniffing, potentially allowing content‑type confusion attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to add the header, e.g., using a middleware that sets `X-Content-Type-Options: nosniff` for all responses.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Scanner evidence: X-Content-Type-Options Header Missing on GET /comments`

Limitations:
- No runtime probe confirming the header is absent; only scanner observation.
- Only one source of evidence; no independent verification or test of header presence.

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns an HTML page generated from database content without setting a Content‑Security‑Policy header. The scanner flagged the missing CSP header, and the runtime probe confirms the endpoint is reachable via a GET request. Absence of CSP allows an attacker to inject malicious scripts into the rendered page (e.g., via stored XSS in comment bodies) and have the browser execute them without restriction.

**Impact:** An attacker who can store or influence comment content could execute arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, or further compromise of the user’s interaction with the site.

**Remediation:** Add a strong CSP header to the response, e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';` and ensure it is applied to all HTML responses, including the `/comments` endpoint. Consider using a middleware or framework feature to set security headers globally.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Source excerpt shows the `/comments` handler returns raw HTML without setting any security headers.`
- `Runtime probe fact from scanner `web-runtime` confirms a GET request to `/comments` was made, indicating the endpoint is live.`

Limitations:
- The evidence only confirms the header is missing for this specific endpoint; other endpoints may set CSP.
- The scan does not verify whether comment bodies are properly escaped, so the actual exploitability depends on additional input validation.

### 23. Missing Anti-clickjacking Header

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content without the `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` headers that mitigate clickjacking. The source excerpt shows the route returns raw HTML, and the runtime probe confirms a GET request to this path. No evidence was found that the application adds anti‑clickjacking headers elsewhere in the response chain.

**Impact:** An attacker could embed the page in a hidden iframe on a malicious site and trick users into interacting with it, potentially leading to unauthorized actions or credential theft if the page includes state‑changing functionality.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors 'self'`. This can be done globally via middleware or specifically for the `/comments` route.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Source excerpt shows HTML response generation without header handling`
- `Runtime probe fact: GET request to /comments observed (web-runtime zap.10020)`

Limitations:
- The review is based solely on the provided source excerpt and runtime probe; it does not verify whether a reverse proxy or external middleware might inject the required headers. No full header dump was provided to confirm their absence.

### 24. Sensitive debug configuration exposed via unauthenticated endpoint

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The application defines a GET endpoint at /debug/config that returns internal configuration values such as DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET. Runtime probing observed an HTTP 200 response for an unauthenticated request, whereas the expected statuses were 401, 403, or 404. This demonstrates that the endpoint is publicly accessible and leaks sensitive information.

**Impact:** Attackers can retrieve database connection strings, external service URLs, and the application secret, enabling credential theft, further system compromise, and potential data exfiltration.

**Remediation:** Restrict access to the /debug/config endpoint to authorized personnel only. Implement authentication and authorization checks (e.g., require admin role) or remove the endpoint from production builds. Ensure that secret values are never returned in API responses.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Source code defines /debug/config endpoint returning DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET (lines 320‑322).`
- `Runtime probe returned status 200 for GET /debug/config, contradicting expected 401/403/404 (runtime_probe_facts).`

Limitations:
- Evidence is limited to a single runtime probe; additional testing in different environments would confirm consistency. The finding assumes the deployed code matches the inspected source.

### 25. Missing Content-Security-Policy header on /healthz endpoint

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without a Content-Security-Policy header. While the endpoint returns only a simple JSON status, the absence of CSP means that if the endpoint were ever expanded to serve HTML or if an attacker can inject content, there would be no browser-enforced policy to mitigate XSS or data injection attacks.

**Impact:** Potential for cross‑site scripting or data injection if the endpoint ever serves HTML or is reflected in a browser context, reducing defense‑in‑depth.

**Remediation:** Configure the application or web server to include a Content‑Security‑Policy header on all responses, e.g., `Content-Security-Policy: default-src 'self';` or a suitable policy for the service.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=web.missing-content-security-policy, path=/healthz, facts={"status":200}`

Limitations:
- Evidence is limited to the /healthz endpoint; other endpoints may have CSP headers.
- The finding is based on a header check and does not confirm exploitation or impact in the current JSON response.

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime scan observed that the /healthz endpoint responded without the X-Content-Type-Options header. This header helps mitigate MIME type sniffing attacks. The finding is based on a single scanner observation and no additional evidence was provided to confirm that the header is set elsewhere in the application.

**Impact:** An attacker could potentially perform MIME type confusion attacks, leading to cross‑site scripting or content injection in browsers that rely on content sniffing.

**Remediation:** Configure the web framework or reverse proxy to include the header, e.g., `X-Content-Type-Options: nosniff` on all responses, or add middleware that sets the header globally.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `Scanner runtime probe (zap.10021) reported missing X-Content-Type-Options on GET /healthz`

Limitations:
- Evidence is limited to a single endpoint; other endpoints may already set the header.
- No verification of server configuration or code that might add the header dynamically.
- The finding relies solely on scanner output without manual confirmation.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without an X-Frame-Options or Content‑Security‑Policy frame‑ancestors directive. The scanner identified this omission, and the runtime probe confirms the endpoint is reachable. While the endpoint is informational, the lack of clickjacking protection could allow the response to be embedded in a malicious frame, potentially facilitating UI redressing attacks.

**Impact:** An attacker could embed the health check page in a hidden iframe on a malicious site and attempt UI redressing, though the impact is limited due to the endpoint's low‑risk content.

**Remediation:** Add an appropriate clickjacking protection header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response for the /healthz endpoint, or configure a global security middleware to set the header for all responses.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe fact: path /healthz returned status 200 without clickjacking protection header (web.missing-clickjacking-protection)`

Limitations:
- The finding is based solely on header presence; the actual risk depends on how the health endpoint is used in the broader application context. No evidence of the header being set elsewhere in the codebase was found.

### 28. Missing X-Content-Type-Options header on /healthz endpoint

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without the X-Content-Type-Options header. This header mitigates MIME type sniffing attacks. The source code shows a simple FastAPI endpoint that returns JSON, but no middleware or response headers are set to include X-Content-Type-Options. While the endpoint is low‑risk, the missing header is a deviation from security best practices.

**Impact:** An attacker could exploit MIME type sniffing to execute content in an unexpected context, potentially leading to cross‑site scripting or content injection, especially if the endpoint is later expanded to serve user‑controlled data.

**Remediation:** Add middleware or configure the FastAPI application to include the X-Content-Type-Options: nosniff header on all responses, e.g., using Starlette's SecurityHeadersMiddleware or a custom response header injection.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe fact: status 200 from /healthz without X-Content-Type-Options header`
- `Source excerpt shows the /healthz handler does not set response headers`

Limitations:
- Evidence is limited to a single runtime probe; other layers (e.g., reverse proxy) might add the header transparently
- The finding is based on observed response; no guarantee the header is never added in other environments

### 29. Incoming webhook events accept unauthenticated requests

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /integrations/hook endpoint processes POST requests without verifying a signature or any form of authentication. Runtime probing observed a successful 200 response for an unsigned request, while the expected secure statuses were 400, 401, or 403. The code inserts the raw request body into the database and returns "accepted": true, confirming that unauthenticated actors can trigger the workflow.

**Impact:** An attacker can craft arbitrary webhook payloads and cause the application to record or act upon them, potentially leading to data injection, unauthorized actions, or further exploitation of downstream services that trust these webhook events.

**Remediation:** Implement signature verification or another authentication mechanism for incoming webhook requests. Reject requests lacking a valid signature with a 401/403 response. Validate and sanitize the request body before any database interaction.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Runtime probe fact: POST to /integrations/hook returned status 200 (unexpected)`
- `Source excerpt shows no signature check before inserting request body into database`

Limitations:
- Evidence is limited to a single runtime probe; additional testing with varied payloads and signatures would strengthen confidence. The scanner evidence does not provide details on signature schemes, so remediation must be designed to match the intended webhook provider.

### 30. Missing authorization check on invoice retrieval

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not use the resulting user identity to restrict the database query. The query selects the invoice by ID alone, allowing any authenticated user to retrieve any invoice. Runtime probing observed a 200 OK response for an invoice that should be inaccessible, confirming the lack of an owner check.

**Impact:** An attacker who can authenticate can enumerate and read invoices belonging to other users, leading to confidentiality breaches of sensitive financial data.

**Remediation:** Modify the query to include the owner identifier, e.g., `SELECT * FROM invoices WHERE id=%s AND owner_id=%s`, and ensure `principal` returns the authenticated user's ID for use in the query. Additionally, enforce proper error handling to return 403 when the user is not the owner.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Source excerpt shows no owner filter in the SQL query (lines 270‑271).`
- `Runtime probe fact: status 200 returned instead of expected 403/404 for unauthorized access (rule workflow.invoice_owner.3).`

Limitations:
- The review assumes `principal` does not internally enforce ownership; if it raises an exception or modifies the connection context, the vulnerability may be mitigated. No direct evidence of the `principal` implementation is provided.

### 31. Improper authorization on job creation endpoint

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint executes a database INSERT without enforcing sufficient authorization checks beyond the call to `principal(authorization)`. The runtime probe observed a successful 200 response where the scanner expected error statuses (400, 403, 422), indicating that unauthorized users may be able to create jobs, potentially with elevated privileges (e.g., admin jobs).

**Impact:** An attacker could create arbitrary jobs, including privileged admin jobs, leading to unauthorized code execution, data manipulation, or escalation of privileges within the system.

**Remediation:** Implement strict role‑based access control for the `/jobs` endpoint. Verify that the authenticated principal has the required permissions before performing the INSERT, and return appropriate error codes (e.g., 403 Forbidden) for unauthorized attempts.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Source excerpt shows the endpoint inserts into `jobs` table after calling `principal(authorization)` without further checks (lines 309‑317).`
- `Runtime probe fact reports a 200 status for a POST to /jobs, contrary to expected error statuses, suggesting the request succeeded without proper authorization.`

Limitations:
- The exact behavior of `principal(authorization)` is not visible; it may already enforce sufficient checks, but this cannot be confirmed from the provided excerpt.
- No information on role definitions or database constraints that might prevent privilege escalation.

### 32. SSN disclosed in /me endpoint response

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table and returns all columns including the ssn field, then serialises the row to a dictionary that is sent to the client. The source excerpt shows the SQL SELECT includes the ssn column and the returned row is directly converted to a dict without filtering. Runtime probe facts confirm a successful GET request to /me returned a 200 status and that values were redacted in the probe output, indicating the endpoint is reachable and returns data. This behavior can expose users' social security numbers to any authenticated caller, and potentially to unauthenticated callers if the principal function does not enforce strict authentication.

**Impact:** Unauthorized disclosure of personally identifiable information (PII) such as social security numbers can lead to identity theft, fraud, and regulatory non‑compliance (e.g., GDPR, HIPAA).

**Remediation:** Modify the /me endpoint to exclude sensitive fields like ssn from the response. Either select only non‑PII columns in the SQL query or filter the row dictionary before returning it. Implement proper access controls to ensure only authorized roles can view sensitive data, and consider encrypting or hashing SSNs at rest.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Source excerpt line 203: SELECT id,username,role,email,ssn FROM users WHERE id=%s`
- `Source symbol shows the row is returned via dict(row or {})`
- `Runtime probe fact: GET /me returned 200 with values_redacted true, indicating data was present`

Limitations:
- The review assumes the principal function validates the Authorization header; if it rejects unauthenticated requests, exposure is limited to authenticated users. The runtime probe redacted values, so the exact presence of SSN in the response is inferred from the code, not directly observed. No evidence was provided about additional response filtering middleware that might strip SSN.

### 33. Improper owner assignment allows order creation for other users

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint assigns the order's owner_id from the request body if provided, otherwise defaults to the authenticated user's sub. This permits a malicious user to specify an arbitrary owner_id and create orders on behalf of other users, bypassing access controls. The runtime probe observed a successful POST to /orders returning HTTP 200, whereas the expected protective statuses (400, 403, 422) were not returned, indicating the missing validation.

**Impact:** An attacker can create, modify, or trigger actions on orders belonging to other users, leading to unauthorized transactions, data leakage, and potential financial loss.

**Remediation:** Enforce that owner_id is derived exclusively from the authenticated principal and ignore any owner_id supplied in the request body. Remove the fallback to body.owner_id or validate that the supplied owner_id matches the authenticated user's sub, returning 403 on mismatch.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Source excerpt lines 207-215 show owner_id = body.owner_id or user["sub"] allowing override`
- `Runtime probe fact: POST /orders returned status 200 instead of expected 400/403/422`

Limitations:
- The review is based on the provided code snippet; additional downstream checks or database constraints could mitigate the issue but are not visible in the excerpt. No information on authentication enforcement beyond the principal function is available.

### 34. Order creation endpoint allows invalid initial status

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders endpoint inserts the order with the client‑provided status field without validation. Runtime probing shows the endpoint returns HTTP 200 for a request that should be rejected (expected 400/422), indicating the server accepts an arbitrary status such as "paid" at creation time. This behavior contradicts the intended workflow where orders must start in a non‑paid state and transition to paid only after payment processing.

**Impact:** An attacker or malicious client can create orders that are already marked as paid, bypassing payment verification and potentially causing financial loss, inventory inconsistencies, or fraud.

**Remediation:** Validate the `status` field on order creation to ensure only allowed initial states (e.g., "pending", "draft") are accepted. Reject or coerce any attempt to set the status to "paid" or other terminal states. Implement server‑side checks and unit tests for the workflow enforcement.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `Source code line 208‑215 shows the `status` value from the request body is directly inserted into the database.`
- `Runtime probe fact: POST /orders returned status 200 while the probe expected 400 or 422, indicating the request was accepted despite an invalid initial state.`

Limitations:
- Evidence is limited to a single runtime probe and static code inspection; no authentication or authorization checks were observed in the snippet.
- The probe did not verify whether additional business‑logic checks (e.g., payment service calls) occur later in the request handling.
- Only one request scenario was tested; other inputs or configurations might affect behavior.

### 35. Negative order prices are accepted instead of rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe for the POST /orders endpoint returned HTTP 200 when a negative unit_price was submitted, contradicting the expected 400/422 error. The source code shows the order is inserted without validation of body.unit_price, allowing negative pricing. The scanner's claim that negative prices are rejected is not supported by observed behavior.

**Impact:** An attacker can create orders with negative prices, potentially resulting in crediting the attacker’s account or causing financial loss for the system by exploiting the lack of price validation.

**Remediation:** Add input validation to reject negative unit_price values (e.g., raise HTTPException with status 400 if body.unit_price < 0) before inserting into the database.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Runtime probe observed status 200 for negative_price workflow (web-runtime rule workflow.negative_price.1)`
- `Source excerpt shows no validation of body.unit_price before database insertion`

Limitations:
- Evidence limited to a single runtime probe request; additional testing with varied inputs is needed to confirm consistent behavior. The scanner's evidence was not corroborated.

### 36. Client-controlled price in order creation

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price value received from the request body directly into the database without server-side validation or enforcement of catalog pricing. This allows a malicious client to specify arbitrary prices for items, violating the requirement that the catalog price must be set by the server.

**Impact:** An attacker can manipulate order totals, potentially causing financial loss, inventory discrepancies, or unauthorized discounts. This can be exploited to obtain goods at reduced cost or cause revenue leakage.

**Remediation:** Enforce server-side pricing by retrieving the official price for the requested item from the product catalog and using that value for the unit_price field. Reject or ignore any client-supplied price, and optionally log discrepancies for audit.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Source excerpt shows body.unit_price is passed directly to the INSERT statement (lines 213-215).`
- `Runtime probe fact indicates the POST /orders request succeeded with status 200, confirming the endpoint is reachable and processes the supplied payload.`

Limitations:
- The review is based on the provided code snippet; if downstream logic later overrides or validates unit_price, it is not visible here. No additional scanner or runtime evidence confirms whether the price is later corrected.

### 37. Improper authorization check on nested note endpoint

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID without verifying that the note belongs to the specified order. Runtime probing shows a GET request to `/orders/1/notes/2` returned HTTP 200, whereas the expected behavior (per the scanner rule) is a 403 or 404 when the note does not belong to the order. This indicates an access control bypass allowing enumeration or disclosure of notes across orders.

**Impact:** An attacker can access notes of other orders by guessing note IDs, leading to unauthorized data exposure and potential privacy violations.

**Remediation:** Validate that the `order_id` in the URL matches the `order_id` field of the retrieved note before returning the data. Return 403 or 404 if the IDs do not match.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Source excerpt shows no check of `order_id` against the fetched note record (lines 543-548).`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200, while expected statuses were 403 or 404 (rule workflow.nested_note.1).`

Limitations:
- Evidence is limited to a single runtime probe and static code review; further testing is needed to confirm that the issue is exploitable across all note IDs and orders.

### 38. Missing authorization check on order retrieval

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}` calls `principal(authorization)` but does not enforce that the authenticated user is the owner of the requested order before returning the record. Runtime probing observed a successful 200 response for a request that should have been denied (expected 403/404), indicating the owner check is ineffective.

**Impact:** An attacker can retrieve any order by guessing or enumerating order IDs, exposing sensitive customer data and violating confidentiality.

**Remediation:** Implement a proper ownership verification after fetching the order, e.g., compare the order's `owner_id` with the authenticated user's ID and return 403 if they do not match. Ensure the `principal` function enforces this check or add explicit validation before returning the order data.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Source excerpt shows `principal(authorization)` is called but no further ownership validation before returning the order.`
- `Runtime probe fact: method GET to `/orders/{{order_id}}` returned status 200 where expected 403/404, assertion_results false.`

Limitations:
- The exact behavior of `principal` is not shown; it may perform authentication but not authorization. No additional scanner evidence was provided beyond the runtime probe.

### 39. Excessive coupon discounts are accepted instead of being rejected

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The runtime probe for the POST /orders/{order_id}/apply-coupon endpoint returned HTTP 200 when an excessive discount was supplied, while the scanner expected a 400 or 422 response. The source code shows that the discount value is taken directly from the request body (or the coupon record) and written to the orders table without validation of upper bounds. This indicates that the application accepts arbitrarily large discount percentages, potentially allowing a user to obtain free or negative‑price orders.

**Impact:** An attacker can submit a coupon with an excessively high discount (e.g., 100% or more) and have the order total reduced accordingly, leading to revenue loss, inventory abuse, or denial of service through order manipulation.

**Remediation:** Add server‑side validation to enforce a maximum allowable discount percentage (e.g., <= 50%). Return a 400/422 error when the supplied discount exceeds this limit. Also consider validating the coupon code against business rules and ensuring the discount field is stored as a bounded numeric type.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Source excerpt shows discount is assigned without bounds (lines 231‑235).`
- `Runtime probe fact: method POST, status 200 returned for excessive discount, expected 400/422 (scanner_id web-runtime, rule_id workflow.coupon_bounds.2).`

Limitations:
- The probe only demonstrates one request scenario; it does not prove that all excessive discounts are accepted in every context. No information on any existing business‑logic checks elsewhere in the codebase. The severity assumes the discount can be set to 100% or higher, which may not be the case if database constraints exist.

### 40. Paid orders can be cancelled without refund

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders/{order_id}/cancel endpoint updates the order status to 'cancelled' unconditionally after authorisation, without verifying whether the order has been paid or whether a refund has been processed. The runtime probe observed a successful 200 response for this workflow step, indicating the cancellation succeeded even when the expected statuses (400, 409, 422) were not returned. This matches the scanner's finding that paid orders require a refund before cancellation.

**Impact:** An attacker or malicious user could cancel paid orders and potentially avoid refund processing, leading to financial loss for the business and unauthorized order state changes.

**Remediation:** Add business‑logic checks before performing the cancellation: verify the order's payment status, ensure any required refund has been completed, and return appropriate error codes (e.g., 400, 409, 422) when cancellation is not allowed. Consider separating the refund and cancellation flows and enforce proper authorisation checks.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Source excerpt shows the cancel_order function directly executes an UPDATE to set status='cancelled' without payment checks (lines 259‑263).`
- `Runtime probe fact reports a 200 status for the POST /orders/{{order_id}}/cancel request, while expected error statuses were not observed.`

Limitations:
- The review is based on static code and a single runtime probe; it does not confirm the presence or absence of additional checks elsewhere in the application (e.g., middleware, database triggers).
- The authorization header handling is assumed correct; the probe does not verify the identity or privileges of the caller.

### 41. Payment replay possible on /orders/{order_id}/pay endpoint

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The pay_order handler updates the order status to 'paid' and creates an invoice without first verifying whether the order has already been paid. The runtime probe observed a successful POST (HTTP 200) when attempting a second payment, whereas the scanner expected a rejection status (400, 409, or 422). This indicates that an attacker could replay a payment request to generate additional invoices or cause double‑charging.

**Impact:** An attacker who can trigger a second POST to the same order can cause duplicate payments, generate fraudulent invoices, and potentially lead to financial loss or accounting inconsistencies.

**Remediation:** Add a check before updating the order status to ensure the order is not already marked as 'paid'. Return an appropriate error (e.g., 409 Conflict) if a payment has already been processed. Consider implementing idempotency keys or transaction tokens to prevent replay attacks.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Source excerpt shows no check for existing paid status before UPDATE (lines 242‑250).`
- `Runtime probe fact: method POST to /orders/{{order_id}}/pay returned status 200, while expected rejection statuses were 400, 409, 422 (rule workflow.payment_replay.3).`

Limitations:
- Evidence is limited to the observed runtime response and static code analysis; does not confirm whether business logic elsewhere prevents duplicate payments. No information on database constraints or additional application-level guards that might mitigate the issue.

### 42. Insecure Direct Object Reference in profile endpoint

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /profiles/{profile_id} endpoint retrieves user data based solely on the supplied profile_id without verifying that the requester owns or is authorized to view that profile. Runtime probing returned a 200 OK for a request using another user's ID, while the expected behavior was a 403 or 404. This demonstrates that an authenticated user can access another user's sensitive information (username, email, SSN).

**Impact:** An attacker who can authenticate can enumerate or retrieve personal data of any user, leading to privacy violations, potential identity theft, and compliance breaches (e.g., GDPR).

**Remediation:** Add an authorization check to ensure the authenticated principal matches the requested profile_id or has appropriate permissions. Return 403 Forbidden for unauthorized access. Consider using parameterized queries with proper access control logic.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `Source code shows no ownership check before DB query (lines 98-101).`
- `Runtime probe fact: method GET to /profiles/{{other_id}} returned status 200, while expected statuses were 403 or 404 (assertion_results false).`

Limitations:
- Evidence is limited to a single runtime probe; additional testing across different user roles would strengthen confidence. No review of surrounding authentication middleware was performed.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint /view returns an HTML page without an X-Frame-Options or Content-Security-Policy frame-ancestors directive. The scanner flagged this as a missing anti-clickjacking header. However, the provided source excerpt does not show any response header configuration, and no runtime probe evidence confirms the absence of these headers. Without explicit evidence of missing headers, the finding cannot be confirmed.

**Impact:** If the page can be embedded in an attacker-controlled iframe, it may be susceptible to clickjacking attacks, potentially leading to unauthorized actions by users who trust the site.

**Remediation:** Configure the web framework or middleware to include an appropriate X-Frame-Options header (e.g., SAMEORIGIN) or a CSP frame-ancestors directive on all responses, especially for the /view endpoint.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Source excerpt shows HTML response generation but no header handling.`

Limitations:
- No runtime probe data confirming header absence; header may be added by upstream middleware not shown in the excerpt.

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /view does not include an X-Content-Type-Options header. The source code shows the endpoint returns a static HTMLResponse without explicitly setting security headers. However, the runtime environment (e.g., FastAPI/Starlette) may add default security headers via middleware that was not captured in the scan. No direct evidence from the runtime probe confirms the header is absent; the probe only reports method and redacted values. Without concrete observation that the header is missing in an actual response, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header were truly missing, browsers could perform MIME type sniffing, potentially leading to content injection attacks. Given the low severity and lack of definitive evidence, the risk is minimal.

**Remediation:** Add a security middleware or explicitly set the X-Content-Type-Options header to "nosniff" on all responses, e.g., using Starlette's SecurityHeadersMiddleware or FastAPI's response headers configuration.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner reported missing X-Content-Type-Options header for GET /view`

Limitations:
- No runtime response captured showing the header is absent; middleware may add the header automatically
- Evidence is based solely on scanner heuristic without direct observation

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /view returns an HTMLResponse without a Content‑Security‑Policy header. The scanner detected the absence of this security header, which can allow injection of malicious scripts if other vulnerabilities exist. No evidence was found that the application sets CSP elsewhere, and the source excerpt confirms the response is generated directly without header manipulation.

**Impact:** Without a CSP header, browsers will not enforce restrictions on script sources, inline scripts, or other potentially unsafe content, increasing the risk of cross‑site scripting (XSS) and data exfiltration attacks.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to include a CSP header on all responses, e.g., using a middleware that adds `Content‑Security‑Policy: default-src 'self';` or a more restrictive policy appropriate to the app’s needs.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Scanner report: Content Security Policy (CSP) Header Not Set on GET /view`
- `Source excerpt shows HTMLResponse returned without header manipulation`

Limitations:
- The review is based solely on the static source excerpt and scanner observation; runtime behavior could add headers via middleware not visible in the excerpt. No runtime probe of actual response headers was provided.

### 46. Webhook destination validation correctly restricts to mock host

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint checks that the provided target_url contains the string "mock-external" and raises an HTTP 400 error otherwise, enforcing that only the approved mock internal host is used. The scanner’s rule expecting an exact match to an internal host is satisfied by this logic. The runtime probe showing a 200 response likely exercised a request that already met the condition, not indicating a bypass.

**Impact:** No impact; the webhook destination is properly constrained, preventing arbitrary external URLs.

**Remediation:** No remediation needed; the existing validation is appropriate.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `source_excerpt line 296-298 shows the check for "mock-external" and the raise of HTTPException(400) when the condition fails`

Limitations:
- The runtime probe reported a 200 status, but it does not prove that the validation can be bypassed; it only reflects a request that satisfied the check. No evidence of alternative paths or missing validation was found.

### 47. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code at api/app.py line 137 logs the application secret (APP_SECRET) using log.info, which writes the secret value in clear text to the application logs. This is directly observable in the source excerpt and is flagged by the semgrep rule for credential disclosure. Logging secrets can lead to exposure through log aggregation, backup, or unauthorized access to log files.

**Impact:** If an attacker gains read access to the logs, they can retrieve the application secret, potentially allowing them to forge tokens, access protected resources, or compromise other services that rely on the secret.

**Remediation:** Remove the secret from log statements. Avoid logging sensitive values altogether, or mask/redact them before logging. Use structured logging with redaction, and ensure that environment variables like APP_SECRET are only used in secure contexts.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `api/app.py line 137 logs "login user=%s app_secret=%s" with the value of os.environ.get("APP_SECRET", "lab-only")`

Limitations:
- The review is based on static code analysis; runtime behavior (e.g., log level configuration) could affect whether the log entry is actually emitted. No runtime probe facts were provided to confirm log emission.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds a CORS middleware with `allow_origins=["*"]`, `allow_methods=["*"]`, and `allow_headers=["*"]`. This configuration permits any website to make cross‑origin requests to the API, which can expose sensitive data to untrusted origins and facilitate CSRF‑style attacks when credentials are allowed.

**Impact:** An attacker-controlled website could read responses from the API (including any data returned to authenticated users, since `allow_credentials=True`) and potentially exploit the API’s functionality from a malicious origin.

**Remediation:** Restrict `allow_origins` to a whitelist of trusted domains, limit `allow_methods` and `allow_headers` to only those required, and set `allow_credentials` to `false` unless absolutely necessary. Example:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted.example.com"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=False,
)
```
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `Source excerpt lines 24‑29 show `allow_origins=["*"]`, `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]` in `api/app.py`.`

Limitations:
- The snippet does not indicate whether the API returns sensitive data or requires authentication; the real risk depends on the broader application behavior and deployment context. No runtime probe data is available to confirm actual exploitation.

### 49. Log Injection finding is not a vulnerability

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The code logs the username and the application secret using a safe parameterized logging call (log.info with "%s" placeholders). This prevents format string injection, and the log entry does not execute user‑controlled content. While logging the secret may be an information‑leak concern, it does not constitute log injection as defined by the scanner. No evidence of log parsing or command execution based on log contents is present.

**Impact:** None – the log entry does not lead to code execution or privilege escalation. The only risk is potential exposure of the APP_SECRET in logs, which is a separate confidentiality issue.

**Remediation:** If the APP_SECRET should not appear in logs, remove it from the log statement or mask it. Consider reviewing logging policies for sensitive data.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `Source excerpt shows log.info called with "%s" placeholders and the username and APP_SECRET values are passed as arguments, not interpolated into the format string.`

Limitations:
- The review does not assess broader confidentiality concerns about logging secrets, only the specific claim of log injection. No runtime probe data was provided to confirm log handling behavior.

### 50. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list checking. This enables an attacker to supply an arbitrary URL, causing the application to redirect users to external sites.

**Impact:** An attacker can craft a link that appears to point to the legitimate service but redirects victims to a malicious site, facilitating phishing, credential harvesting, or drive‑by attacks.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a safe redirect mechanism.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source line 616 defines `def continue_to(next: str = "/") -> RedirectResponse:``
- `Source line 617 returns `RedirectResponse(next, status_code=302)` without validation`

Limitations:
- No additional runtime observations confirm exploitation
- Only static code analysis; actual behavior depends on how the endpoint is used in the application

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function `verified_continue` validates the `next` parameter by ensuring it starts with a single leading slash, does not start with a double slash, and contains no scheme or network location. This effectively restricts redirects to local paths only, preventing open‑redirect attacks from user‑controlled URLs. The scanner’s generic pattern flagged the use of `RedirectResponse` without recognizing the preceding validation logic.

**Impact:** If the validation were bypassable, an attacker could craft a redirect to a malicious external site, leading to phishing or credential‑theft. However, the implemented checks mitigate this risk.

**Remediation:** No remediation needed for this specific endpoint; maintain the existing validation and ensure similar checks are applied to any other redirect logic.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Source code lines 621‑624 enforce that `next` must be a local path and reject schemes, netlocs, or double‑slash prefixes, followed by a safe `RedirectResponse` on line 625.`

Limitations:
- The review covers only the `verified_continue` function; other parts of the application might perform redirects without comparable validation.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container health monitoring, its absence does not constitute a security vulnerability nor does it directly expose the application to attack. The scanner’s evidence is limited to the Dockerfile content and does not demonstrate any exploitable condition.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health verification, potentially leading to delayed detection of runtime failures.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD curl -f http://localhost:8091/health || exit 1
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile lines 1-8 show no HEALTHCHECK instruction`

Limitations:
- The assessment is based solely on static Dockerfile analysis; no runtime behavior or orchestration context was observed. Absence of a HEALTHCHECK may be acceptable in environments where external monitoring is employed.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK can improve container observability, its lack does not constitute a security vulnerability. The Dockerfile otherwise follows best practices and there is no evidence that the missing HEALTHCHECK leads to exploitable conditions.

**Impact:** Minimal; primarily affects operational monitoring rather than security. No direct attack vector is introduced by the omission.

**Remediation:** Add a suitable HEALTHCHECK instruction to the Dockerfile if container health monitoring is required, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`. This is optional for security hardening.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- The assessment assumes no external requirements for health checks. If the deployment environment relies on container health status for security decisions, the absence could be more significant. No runtime probe data was provided to confirm impact.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile for the worker service does not include a HEALTHCHECK instruction, which means the container runtime cannot automatically verify that the service is healthy after startup. This is a common best‑practice misconfiguration that can lead to undetected service failures.

**Impact:** Without a health check, orchestration platforms (e.g., Docker Swarm, Kubernetes) cannot automatically restart or replace unhealthy containers, potentially causing prolonged downtime or degraded service availability.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, for example:

```
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1
```
Adjust the endpoint and parameters to match the worker’s actual health endpoint.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Source excerpt shows Dockerfile lines 1‑7 with no HEALTHCHECK instruction.`

Limitations:
- The finding is based on static analysis of the Dockerfile; no runtime evidence confirms that the lack of a health check leads to actual service failures in this deployment.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies (CVE-2026-53539)

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to contain CVE-2026-53539 – a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded request bodies. The scanner evidence directly cites this CVE and notes that the issue is fixed starting with version 0.0.30. No mitigating controls or runtime checks were observed that would prevent exploitation of this flaw.

**Impact:** An attacker can send a maliciously crafted request to any endpoint that parses multipart/form‑data, causing the application to consume excessive CPU or memory and potentially become unresponsive, leading to service disruption.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version is installed by running `pip freeze` or similar after deployment.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies on the scanner’s CVE mapping; no runtime probe confirmed the vulnerability’s presence in the running service.

### 56. Denial of Service via excessive multipart part headers in python-multipart 0.0.20

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20 as shown in the requirements.txt excerpt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by crafted multipart requests with an excessive number of part headers. The scanner evidence cites this CVE and notes that the issue is fixed starting with version 0.0.27. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can send a malicious multipart request that consumes excessive memory or CPU on the server, potentially causing service disruption or crash of the FastAPI application.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later. Update the requirements.txt entry and rebuild/redeploy the application. Optionally add input validation or request size limits as defense‑in‑depth.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`
- `requirements.txt shows python-multipart==0.0.20`

Limitations:
- No runtime probe data confirming exploitation or mitigation; assessment based solely on dependency version and known CVE.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53538 causing information disclosure. The scanner identified this CVE and noted that it is fixed in version 0.0.30. No additional runtime evidence was observed, but the presence of the vulnerable version in the requirements file is sufficient to consider the vulnerability likely present.

**Impact:** An attacker could craft multipart/form-data requests that trigger the parser differential, potentially extracting unintended data from the application, leading to information leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, and verify that the updated version resolves the CVE. Rebuild and redeploy the application after updating the dependency.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- No runtime probe confirms the vulnerability is exploitable in the current deployment configuration. The assessment relies solely on the presence of the vulnerable version in the requirements file.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-40347. This CVE allows an attacker to trigger a denial‑of‑service condition by sending specially crafted multipart/form-data payloads. The scanner identified the vulnerable version and the fix introduced in 0.0.26.

**Impact:** An attacker can cause the application to become unresponsive or crash by sending malicious multipart requests, leading to service disruption and potential loss of availability for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version does not introduce breaking changes in request handling.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`

Limitations:
- The review relies on the version listed in requirements.txt; it assumes the deployed environment uses this exact version without overrides. No runtime probe data was provided to confirm the vulnerable code is executed.

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-24486, a path‑traversal flaw that allows an attacker to write arbitrary files on the server when processing multipart/form‑data. The vulnerability is documented and fixed in version 0.0.22. No evidence was found that the application upgrades or patches this dependency at runtime.

**Impact:** An attacker could exploit the multipart handling endpoint to write files to arbitrary locations, potentially achieving remote code execution, defacement, or data exfiltration.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later and rebuild/redeploy the application. Verify that the updated dependency is included in the final image or environment.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- No runtime probe confirms the vulnerable code path is exercised. The finding relies on static dependency analysis of requirements.txt.

### 60. python-multipart 0.0.20 contains CVE-2026-53537

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to be vulnerable to CVE-2026-53537, an information disclosure issue caused by header parsing discrepancies. The scanner evidence directly references the CVE and notes that the vulnerability is fixed in version 0.0.30.

**Impact:** An attacker could exploit the header parsing flaw to obtain sensitive information from HTTP requests processed by the application, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, and update the requirements.txt accordingly. Rebuild and redeploy the application after the upgrade.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies on the scanner's CVE mapping; no runtime probe confirms exploitation. No additional context about whether the vulnerable code path is exercised in the application.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner identified a known vulnerability (CVE-2026-53540) in python-multipart version 0.0.20, which is used by the project as declared in requirements.txt. The vulnerability description matches the finding: a negative Content-Length can cause the entire request body to be buffered in memory, leading to potential denial‑of‑service. The evidence is directly from the dependency list and the scanner’s CVE mapping.

**Impact:** An attacker could craft a request with a malformed Content-Length header, causing the server to allocate excessive memory and potentially crash or become unresponsive, affecting availability of the service.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which contains the fix for CVE-2026-53540. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- The finding relies on the scanner’s CVE mapping; no runtime probe confirms exploitation.

### 62. Dynamic urllib usage may allow URL manipulation

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a request URL by concatenating a base URL with a path argument and passes it to urllib.request.urlopen. If the path parameter can be influenced by an attacker, this could lead to SSRF or unintended file access via urllib's support for file:// schemes. However, the current evidence does not show that the path value is attacker-controlled, nor is there proof of unsafe schemes being used. Additional context about input validation for the path argument is required to confirm a vulnerability.

**Impact:** If an attacker can control the path, they may be able to request internal services or read local files, potentially leading to data disclosure or further exploitation.

**Remediation:** Validate and sanitize the `path` argument to ensure it cannot contain malicious schemes or traversal sequences. Prefer using higher‑level HTTP libraries such as `requests` that do not support file URLs, or explicitly restrict URLs to allowed schemes and domains.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen called with BASE + path (lines 20‑22).`

Limitations:
- No evidence that `path` is derived from untrusted input.
- No runtime probe data confirming unsafe URL usage.
- Severity and confidence are low based on static analysis alone.

### 63. Potential SSRF via dynamic urllib request

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload["target_url"]). If an attacker can influence this payload, they may control the destination URL, leading to Server-Side Request Forgery (SSRF). The scanner flagged this as a dynamic urllib use, which is a known risk vector because urllib supports file:// and other schemes that could be abused to read local files or access internal services.

**Impact:** An attacker could cause the worker to make arbitrary HTTP or file requests, potentially exposing internal services, reading sensitive files, or performing port scanning within the network.

**Remediation:** Validate and whitelist the target URL before using it with urllib. Restrict allowed schemes (e.g., only https://), enforce domain whitelisting, or switch to a higher-level library like requests with built‑in safety checks. Consider adding a timeout and error handling, and avoid passing untrusted data directly to urllib.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows payload["target_url"] is passed directly to urllib.request.Request without validation (lines 17‑23).`

Limitations:
- No runtime probe evidence confirming that an attacker can control payload["target_url"].
- The severity assessment is limited to code analysis; actual exploitability depends on how job payloads are sourced and validated elsewhere in the application.

### 64. Potential insufficient path traversal protection in file read endpoint

- Issue group: `ai-9a1294ca022bd523`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code attempts to prevent directory traversal by resolving the requested path and checking `is_relative_to` against the public directory. However, the analysis notes that `Path.is_relative_to` may not be available on older Python versions, which could raise an exception and bypass the check. Additionally, symbolic links inside the public directory could allow access to files outside the intended root. The current evidence does not confirm whether the runtime Python version supports this method, whether symlinks exist, or whether additional validation (e.g., realpath resolution) is performed. Without this information, the presence of a true vulnerability cannot be confirmed.

**Impact:** If an attacker can bypass the relative‑path check, they may read arbitrary files on the server, potentially exposing source code, configuration, or sensitive data.

**Remediation:** Ensure the runtime uses Python 3.9+ or replace `is_relative_to` with a compatible check. Resolve symlinks and enforce that the final resolved path is within the allowed directory (e.g., using `os.path.realpath` and explicit prefix comparison). Add explicit handling for symbolic links and consider rejecting paths that traverse outside the public directory before reading the file.
Evidence:
- Source IDs: `ai-9a1294ca022bd523`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `raise HTTPException(404, "File not found")`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- No information on the Python version used at runtime
- No data about presence of symbolic links in the public directory
- The check relies on `Path.is_relative_to` which may raise on older versions, but this behavior is not observed in the provided code
- No runtime tests confirming bypass of the check

### 65. Potential insecure token issuance on refresh without audience validation

- Issue group: `ai-f86829b37959f769`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The refresh endpoint calls `principal` to obtain a user identifier and then issues a new access token without visible checks for token signature, audience, expiration, or revocation. Because the implementation of `principal` is not shown, it is unclear whether it performs sufficient validation. Without evidence that the incoming token is fully validated, the risk of token forgery or replay cannot be confirmed.

**Impact:** If an attacker can present a forged or expired token to the refresh endpoint, they may obtain a fresh access token, potentially leading to unauthorized access to protected resources.

**Remediation:** Ensure that the refresh endpoint validates the incoming token's signature, expiration, audience, and revocation status before issuing a new token. Consider separating refresh tokens from access tokens and checking a revocation list or token store. Document the behavior of `principal` or replace it with explicit validation logic.
Evidence:
- Source IDs: `ai-f86829b37959f769`
- `api/app.py lines 189-196 show the refresh endpoint calling `principal` and then issuing a token via `make_token(row)` without additional checks.`

Limitations:
- The internal behavior of `principal` is unknown; it may already perform the required validation. No runtime observations or tests confirm token validation or revocation handling. The severity assessment is limited to the static code view.

### 66. Unauthenticated public file read endpoint

- Issue group: `ai-197f881c81af25e7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /files endpoint reads files from the server's public directory and returns their contents without performing any authentication or authorization checks. The code resolves the requested path, verifies it is within the public directory and that it is a file, then returns the file contents as plain text. No guard such as a token validation or role check is present before the file is read, allowing any unauthenticated client to enumerate and retrieve files that reside in the public folder.

**Impact:** An attacker can retrieve arbitrary files from the public directory, potentially exposing sensitive configuration, source code, or other confidential data. This information disclosure can aid further attacks, such as credential harvesting or exploitation of other vulnerabilities.

**Remediation:** Add authentication and authorization checks before accessing the file. For example, require a valid JWT or session token and verify the user has the appropriate role or permission to read files. Consider limiting the endpoint to a whitelist of allowed filenames or serving files through a static file server with proper access controls. Log accesses for audit purposes.
Evidence:
- Source IDs: `ai-197f881c81af25e7`
- `@router.get("/files") (line 210)`
- `def file_read(name: str) -> Response: (line 211)`
- `file = (FILES / "public" / name).resolve() (line 212)`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found") (lines 213‑214)`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain") (line 215)`

Limitations:
- The repository does not contain explicit documentation stating whether the public directory is intended to be fully exposed, so the finding assumes that unrestricted access is unintended. No evidence of existing logging or monitoring for this endpoint is present. The relative‑path check prevents simple path traversal, but without broader context it cannot be confirmed that additional mitigations are absent.

### 67. Unauthenticated verified file read endpoint

- Issue group: `ai-db9083db72a7fa38`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The route @router.get("/files/verified") returns the contents of any file under the public directory without performing any authentication or authorization checks. The handler only validates that the requested path is within the public directory and that the file exists, then reads and returns the file as plain text. This allows any unauthenticated client to retrieve arbitrary public files, which may include sensitive information if the directory is mis‑configured or if an attacker can place files there via other functionality.

**Impact:** Potential disclosure of files that should be protected, enabling information leakage, enumeration of file names, and further attacks based on the exposed data.

**Remediation:** Add proper authentication and authorization checks before serving the file. Verify the requester’s permissions, enforce least‑privilege access, and consider limiting the endpoint to a whitelist of allowed files. Additionally, implement logging and rate‑limiting for the endpoint.
Evidence:
- Source IDs: `ai-db9083db72a7fa38`
- `@router.get("/files/verified") (line 218)`
- `def verified_file_read(name: str) -> Response: (line 219)`
- `root = (FILES / "public").resolve() (line 220)`
- `file = (root / name).resolve() (line 221)`
- `if not file.is_relative_to(root) or not file.is_file(): (line 222)`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain") (line 224)`

Limitations:
- The code only serves files from the "public" directory; if that directory is intended to be fully public, the impact may be limited. No explicit evidence of additional authentication elsewhere in the codebase was found, but the absence of a guard in this handler alone does not prove that other layers (e.g., global middleware) are not enforcing access control.

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
- `merged-bdfe7542047da39c6151`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-17a5197f906426a224ef`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
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
- `merged-50485291173e2448f7c7`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-ade7b890a037d8c82a1f`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-dfd8d33b4f84ccf0c23f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-65f25bcf14fa2ab91271`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-9a1294ca022bd523`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-f86829b37959f769`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-197f881c81af25e7`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-db9083db72a7fa38`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **67**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **6**; scanner overlaps: **1**; AI overlaps: **0**; new candidates: **2**; uncertain overlaps: **2**; needs more evidence: **1**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-07402fda843415c8`: needs_more_evidence
- `ai-9a1294ca022bd523`: uncertain_overlap
- `ai-f86829b37959f769`: uncertain_overlap

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

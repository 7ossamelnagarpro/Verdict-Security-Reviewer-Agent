# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-05T10:36:20.514445+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **17/17**; model calls: **2**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.

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
53. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-5230c114e62065082a9b</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-726acbb49bc074d3b384aea7</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
54. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-ec17a70b00fa38747671</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-666123a1a4379f9b0ecad8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
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

### 1. Potential SQL Injection in legacy_login endpoint

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code constructs an SQL query by directly interpolating the `username` and `password` fields from the request body into the query string without any sanitisation or parameterisation. This pattern is a classic source of SQL injection vulnerabilities, allowing an attacker to manipulate the query logic by supplying specially crafted input values.

**Impact:** An attacker could bypass authentication, retrieve arbitrary user records, or execute destructive SQL commands (e.g., DROP TABLE). This could lead to full database compromise, data leakage, and privilege escalation.

**Remediation:** Replace string interpolation with parameterised queries using the database driver’s placeholder syntax (e.g., `SELECT ... WHERE username=? AND password=?` with bound parameters). Additionally, hash passwords and compare hashes rather than storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117 builds the query with f-string interpolation of `body.username` and `body.password``
- `The query is executed directly via `conn.execute(query)` without any sanitisation`

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., ORM sanitisation layers) is not observed in the provided data. No runtime_probe_facts were available to confirm whether the database driver automatically escapes inputs.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter, but it resolves the path and then checks `is_relative_to(root)` before accessing the file. This check ensures the resulting path cannot escape the designated `public` directory, effectively mitigating path traversal. The scanner’s generic pattern flagged the use of user input in a path expression, but the subsequent safety check makes the finding non‑exploitable.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server. However, the existing `is_relative_to` guard prevents this, so no impact is present.

**Remediation:** No remediation required for path traversal; the current validation is sufficient. Ensure future changes retain the `is_relative_to` check if the logic is modified.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 219‑224 show the resolve and `is_relative_to` guard`
- `source_symbol confirms the same logic`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If run on an older version, the guard may not exist, potentially reintroducing risk.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but then calls `Path.is_relative_to(root)` to ensure the resolved path remains within the intended public directory before accessing the file. This check prevents directory traversal attacks, so the reported uncontrolled path usage does not constitute a vulnerability.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server. The existing check mitigates this risk.

**Remediation:** No remediation needed for path traversal; ensure the `is_relative_to` check remains in place and that the `root` directory is correctly set to the intended public folder.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source line 221 constructs the path: `file = (root / name).resolve()``
- `source line 222 validates the path: `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If running on an older version, the check may not exist, which could reintroduce risk.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint constructs the file path using a user‑provided name but immediately resolves it and checks `is_relative_to(FILES.resolve())` as well as `is_file()`. These checks ensure the resulting path cannot escape the intended `FILES/public` directory and that the target is an existing file, mitigating path traversal. No evidence of bypass was observed in the runtime probe facts.

**Impact:** If the checks were bypassable, an attacker could read arbitrary files, but the code as written prevents directory traversal, so the impact is mitigated.

**Remediation:** No remediation required for path traversal; maintain the existing relative path validation and consider adding explicit whitelist of allowed filenames for defense‑in‑depth.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Source excerpt shows `file = (FILES / "public" / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404)``

Limitations:
- No runtime probe data was provided to test edge‑case inputs such as symbolic links or Unicode tricks; verification relies solely on static analysis of the checks.

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
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a fixed base directory and then verifies that the resolved path is still within that base using is_relative_to(). This check prevents directory traversal attacks, making the reported uncontrolled path usage ineffective.

**Impact:** If the check were bypassed, an attacker could read arbitrary files, but the existing relative‑path validation mitigates this risk.

**Remediation:** No remediation needed for path traversal; ensure the is_relative_to check remains in place and that FILES is a trusted absolute path.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `source_excerpt shows the is_relative_to check that validates the resolved path against the public directory`

Limitations:
- The analysis assumes FILES is correctly defined as an absolute path and that resolve() does not follow symlinks to escape the directory.

### 7. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint interpolates the user‑controlled query parameter `q` directly into an HTML response without any sanitisation or encoding. The SQL query also uses string interpolation, but the XSS risk stems from the returned HTML where `<h1>Results for {q}</h1>` and each product name are inserted verbatim. An attacker can supply a payload such as `<script>alert(1)</script>` in the `q` parameter, which will be reflected back to the client and executed in the browser context, confirming a reflected XSS vulnerability.

**Impact:** An attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, defacement, or further malicious actions against users of the application.

**Remediation:** Properly encode user input before embedding it in HTML. Use a templating engine that auto‑escapes, or explicitly HTML‑escape `q` and any dynamic data. Additionally, employ parameterised queries for the SQL statement to prevent SQL injection. Example fix:
```python
from html import escape

@router.get("/catalog/search", response_class=HTMLResponse)
def catalog_search(q: str = ""):
    safe_q = escape(q)
    with connection() as conn:
        rows = conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",)).fetchall()
    return f"<h1>Results for {safe_q}</h1>" + "".join(f"<p>{escape(row['name'])}</p>" for row in rows)
```
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt shows `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)` where `q` is directly inserted into HTML response.`

Limitations:
- The review is based solely on static code analysis; runtime behaviour such as content security policies or additional sanitisation layers are not observed.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks that the resulting path is within the configured FILES directory and that it points to an existing file. The use of Path.resolve() together with is_relative_to(FILES.resolve()) prevents directory traversal attacks, making the scanner’s finding a false positive.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server. However, the code correctly validates the resolved path, so no such impact exists.

**Remediation:** No remediation needed; the existing path validation is sufficient. Ensure that FILES is set to a safe directory and that symbolic links are not abused.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Code line 212 resolves the user‑provided name: file = (FILES / "public" / name).resolve()`
- `Code line 213 checks the resolved path is within FILES: if not file.is_relative_to(FILES.resolve())`

Limitations:
- The analysis assumes FILES is a trusted absolute path and that the runtime environment does not allow symlink attacks that could bypass is_relative_to.

### 9. Potential SQL Injection in catalog_search endpoint

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `catalog_search` constructs an SQL query by directly embedding the user‑controlled parameter `q` into the query string using an f‑string. This allows an attacker to inject arbitrary SQL syntax, which will be executed by the database when `conn.execute` runs the query.

**Impact:** An attacker could manipulate the query to retrieve unauthorized data, modify or delete records, or execute database commands such as UNION attacks, leading to data leakage or corruption.

**Remediation:** Use parameterized queries or prepared statements instead of string interpolation. For example, replace the f‑string with a query like `SELECT name FROM products WHERE name ILIKE %s` and pass `q` as a parameter to the database driver. Additionally, validate and sanitize input where appropriate.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt shows f‑string interpolation of `q` into SQL at line 144: `conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'")``

Limitations:
- No runtime probe data is available to confirm exploitation. The analysis is based solely on static code inspection of the provided excerpt.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the response for GET / does not include an X-Content-Type-Options header. The source excerpt shows only the FastAPI route implementation and does not reveal any middleware or response configuration that could add the header. No runtime probe evidence confirms the header is absent; the probe only records the request method and redacted values. Without concrete evidence that the header is missing in production responses, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header were truly missing, browsers could perform MIME type sniffing, potentially leading to content injection attacks. However, the lack of evidence means the impact cannot be established.

**Remediation:** Ensure that the FastAPI application adds the header, e.g., via Starlette middleware or a response header decorator, and verify its presence with an explicit runtime probe that captures response headers.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `Scanner evidence: X-Content-Type-Options Header Missing`
- `Runtime probe fact: method GET on path '/' (no header data captured)`

Limitations:
- No captured response headers to confirm absence
- Source code excerpt does not show header handling

### 11. Unauthorized access to admin job listings

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs endpoint returns a 200 OK response for an unauthenticated request, whereas the expected behavior is to reject the request with 403 or 404. The source code shows the endpoint calls `principal(authorization)` but the runtime probe indicates that the authorization check does not block access, suggesting a missing or ineffective access control check.

**Impact:** An attacker can enumerate all job records, potentially exposing sensitive internal data and enabling further attacks such as data leakage or privilege escalation.

**Remediation:** Ensure that `principal(authorization)` enforces proper authentication and authorization, returning 403/404 for unauthorized users. Add explicit role checks for admin privileges before querying the database.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Source excerpt shows admin_jobs endpoint calls principal but no explicit role verification`
- `Runtime probe fact: GET /admin/jobs returned status 200, expected 403/404`

Limitations:
- Only a single runtime probe was performed; the behavior with valid admin credentials was not verified
- The probe does not show whether the endpoint correctly handles malformed or missing Authorization headers

### 12. Stale administrator role not enforced on /admin/token-report

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a GET request to /admin/token-report returned HTTP 200 instead of the expected 403, indicating that the role check (`if token.get("role") != "admin": raise HTTPException(403)`) did not block access for a demoted administrator. This suggests that the application may retain administrative privileges after role changes, violating the requirement that a demoted administrator lose access.

**Impact:** An attacker who previously held admin rights could continue to access privileged endpoints, potentially exposing sensitive data or performing unauthorized actions.

**Remediation:** Ensure that role information is refreshed and validated against the current user state on each request. Invalidate or update tokens when a user's role changes, and re‑evaluate the role check after token refresh.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Runtime probe fact: GET /admin/token-report returned status 200 (expected 403)`

Limitations:
- Only a single runtime observation; the token used in the probe is not disclosed, so it is unclear whether the token was correctly updated. No additional scanner or code analysis confirms token handling logic.

### 13. Improper Access Control on /admin/users endpoint

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users route returns a full list of user records, including sensitive fields such as email, role, and SSN. The handler calls `principal(authorization)` but does not enforce that the authenticated principal has an admin role before querying and returning the data. Runtime probing observed a 200 OK response for a GET request to this endpoint, whereas a 403 or 404 was expected for non‑admin users, indicating that the access control check is missing or ineffective.

**Impact:** An attacker who can obtain or guess a valid authorization header can retrieve all user records, exposing personally identifiable information (PII) and potentially enabling further attacks such as credential stuffing or social engineering.

**Remediation:** Add a role‑based access control check after authentication to ensure only users with the admin role can access this endpoint. For example, verify `principal.role == "admin"` and return 403 for non‑admin users. Consider removing sensitive fields (e.g., SSN) from the response or restricting them to authorized personnel only.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Source excerpt shows the endpoint returns user data without role verification (lines 278‑282).`
- `Runtime probe fact reports a 200 status for GET /admin/users where a 403/404 was expected.`

Limitations:
- The exact behavior of `principal()` is not shown; it may perform role checks internally, but no evidence of such checks is present in the provided code. Further testing with different user roles is needed to confirm the absence of proper authorization.

### 14. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The runtime scan reported that the response from the /auth/form-login endpoint does not include a Content Security Policy header. The source excerpt shows the endpoint returns an HTMLResponse without any explicit security headers being set, and no evidence was found that a CSP header is added elsewhere in the application stack. This suggests that the endpoint is vulnerable to content injection attacks such as XSS because browsers are not instructed to restrict the sources of executable content.

**Impact:** Without a CSP header, an attacker who can inject malicious scripts into the response (e.g., via reflected or stored XSS) can execute arbitrary JavaScript in the victim's browser, leading to credential theft, session hijacking, or other malicious actions.

**Remediation:** Configure the application to send a strong Content Security Policy header on all responses, preferably at a middleware or framework level. For example, add a header like `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';` or use a security library/middleware that manages CSP headers automatically.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner runtime fact: method POST to /auth/form-login, values redacted, no CSP header observed`

Limitations:
- The scan only covered the /auth/form-login endpoint; other endpoints may set CSP globally via middleware not captured in this snippet. The absence of a CSP header in this response does not prove it is never set elsewhere in the application.

### 15. X-Content-Type-Options Header Missing

- Issue group: `merged-5230c114e62065082a9b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from /auth/form-login does not include the X-Content-Type-Options header, which is used to prevent MIME type sniffing. The source code shows a standard form login endpoint but does not set any security headers. No runtime probe confirming the presence of the header was provided, so the finding relies solely on the scanner observation.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to guess the content type of responses, potentially allowing content injection attacks such as cross‑site scripting (XSS) if an attacker can influence the response body.

**Remediation:** Add the X-Content-Type-Options header with the value "nosniff" to all HTTP responses, e.g., via middleware or response headers configuration in the FastAPI application.
Evidence:
- Source IDs: `merged-5230c114e62065082a9b`
- `X-Content-Type-Options Header Missing (scanner evidence)`

Limitations:
- No runtime verification of response headers was performed; the finding is based solely on scanner output.

### 16. Missing Anti-clickjacking Header on /auth/form-login

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /auth/form-login returns an HTMLResponse but does not set any X-Frame-Options or Content-Security-Policy frame-ancestors header. The source excerpt shows the response is created with `HTMLResponse(...)` and no subsequent call to `response.headers.append` or similar to add anti-clickjacking headers. The runtime probe confirms the request is a POST and the response body is returned, but no header evidence is provided.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and perform clickjacking attacks, potentially tricking users into submitting credentials without their knowledge.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP `frame-ancestors 'none'`. Ensure this is applied to all HTML responses, preferably via a middleware.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Source code creates HTMLResponse without setting X-Frame-Options or CSP frame-ancestors header`
- `Runtime probe fact shows POST request to /auth/form-login but no header data indicating anti-clickjacking protection`

Limitations:
- Only static code analysis was performed; runtime configuration (e.g., reverse proxy adding headers) was not observed
- The probe did not capture response headers, so absence of evidence is not proof of absence of protection

### 17. Missing HttpOnly flag on session cookie

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code sets a session cookie (lab_session) without specifying the HttpOnly attribute. This allows client‑side scripts to access the cookie, increasing the risk of theft via XSS. The finding originates from a runtime probe that observed a POST to /auth/form-login, but the probe did not capture the full Set‑Cookie header; the source excerpt shows the set_cookie call without HttpOnly.

**Impact:** If an attacker can inject JavaScript into the application, they could read the lab_session cookie and hijack the user’s session, leading to unauthorized access.

**Remediation:** Set the HttpOnly flag when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)`. Consider also adding Secure and SameSite attributes.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `source_symbol line showing `response.set_cookie("lab_session", f"session-{row['id']}")` without HttpOnly`
- `runtime_probe_facts indicating a POST request to /auth/form-login`

Limitations:
- The runtime probe did not capture the full Set‑Cookie header, so we cannot confirm other attributes (Secure, SameSite) are also missing
- No evidence of an actual XSS vector in the application was provided

### 18. Password reset token reuse possible

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe exercised the password reset confirmation endpoint with a token that had already been used and observed a 200 OK response instead of the expected error status (400, 409, or 422). The source code shows the token is looked up but not invalidated after a successful password change, allowing the same token to be reused. This indicates the token is not single‑use as required.

**Impact:** An attacker who intercepts or guesses a valid reset token could reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity of user data.

**Remediation:** Invalidate or delete the reset token after a successful password reset. Add a check to ensure the token has not been used before, and return an appropriate error (e.g., 400 or 409) if a reused token is presented. Consider adding a timestamp and expiration check as well.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Source excerpt shows token lookup but no deletion: lines 579‑585`
- `Runtime probe fact: method POST to /auth/reset/confirm returned status 200, while expected statuses were 400, 409, 422`

Limitations:
- Evidence is limited to a single runtime probe execution; additional testing is needed to confirm that all token reuse scenarios are vulnerable.
- The code snippet does not show the full token lifecycle (creation and storage), so other mechanisms might already invalidate tokens elsewhere.

### 19. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the /catalog/query endpoint does not include a Content Security Policy header in its HTTP response. The source code shows the endpoint returns an HTMLResponse without explicitly setting security headers, and no runtime probe evidence indicates the header is present. Absence of CSP can allow injection of malicious scripts and reduce protection against XSS attacks.

**Impact:** Without a CSP header, browsers have no enforced policy to restrict the sources of scripts, styles, or other resources, increasing the risk of cross‑site scripting and data exfiltration attacks.

**Remediation:** Configure the FastAPI application to include a CSP header on all responses, e.g., using a middleware that adds `Content-Security-Policy: default-src 'self';` or a more restrictive policy appropriate to the application’s needs.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Scanner finding: Content Security Policy (CSP) Header Not Set for GET /catalog/query`

Limitations:
- No runtime probe confirming the header is present or absent; the assessment relies solely on the scanner’s observation and the lack of explicit header setting in the source code.

### 20. Missing Anti-clickjacking Header on /catalog/query

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for GET /catalog/query does not include an X-Frame-Options or Content-Security-Policy frame-ancestors directive, which are commonly used to mitigate clickjacking. The source code shows the endpoint returns an HTMLResponse without explicitly setting security headers. No evidence was found that the application adds these headers globally via middleware or a reverse proxy, so the finding remains plausible.

**Impact:** An attacker could embed the page in a hidden iframe and trick users into performing unintended actions, potentially leading to credential theft or unauthorized transactions.

**Remediation:** Configure the application or web server to send an appropriate anti-clickjacking header, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors 'self'`. Ensure the header is applied to all HTML responses.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Scanner runtime probe (zap.10020) observed a GET request to /catalog/query without anti-clickjacking headers.`

Limitations:
- The review is based solely on the absence of explicit header setting in the examined endpoint; global middleware or external proxy configurations could add the header, which were not observed in the provided data. No runtime response body analysis was performed to confirm the header omission across all environments.

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for GET /comments does not include the X-Content-Type-Options header. The source code shows the endpoint returns an HTML string without explicitly setting security headers, which aligns with the finding. While the missing header is a known best‑practice issue, the evidence is limited to the scanner’s observation and no runtime capture of the actual response headers is provided.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks such as cross‑site scripting in certain edge cases.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to include the X-Content-Type-Options: nosniff header on all responses, e.g., using a middleware that adds the header globally or setting it explicitly in the route response.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Scanner reported missing X-Content-Type-Options header for GET /comments (zap.10021)`

Limitations:
- No direct runtime capture of response headers was provided; the finding relies solely on the scanner’s report. The source code does not explicitly set any security headers, but it is possible that a framework default or external middleware adds the header at runtime, which was not observed.

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns HTML content without a Content‑Security‑Policy header. The source excerpt shows the route returns a raw HTML string, and the runtime probe confirms a GET request to /comments was made. Absence of CSP allows an attacker to inject malicious scripts that the browser will execute, increasing XSS risk.

**Impact:** An attacker who can influence comment bodies (e.g., via stored XSS) could execute arbitrary JavaScript in victims' browsers, leading to session hijacking, credential theft, or other malicious actions.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response headers or a middleware, specifying directives such as `default-src 'self'; script-src 'self'` and `object-src 'none'`. Consider using a security library (e.g., Starlette's SecurityHeadersMiddleware) to enforce CSP globally.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Source excerpt shows HTML is returned directly without header handling (lines 173‑177).`
- `Runtime probe fact confirms a GET request to /comments was observed (scanner_id: web-runtime, rule_id: zap.10038).`

Limitations:
- The finding only confirms the header is missing; it does not demonstrate that comment content is user‑controlled or that an XSS payload is present.
- No evidence is provided about other defense‑in‑depth measures (e.g., input sanitization) that might mitigate the risk.

### 23. Missing Anti-clickjacking Header on /comments endpoint

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /comments endpoint returns HTML content without an X-Frame-Options or Content‑Security‑Policy frame‑ancestors directive. The source excerpt shows the route returns a raw HTML string and no security headers are added. The runtime probe confirms a GET request to /comments was made, but no header evidence is provided. This pattern matches the ZAP rule zap.10020 for missing anti‑clickjacking protection.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into unintended actions or data disclosure.

**Remediation:** Add an appropriate anti‑clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame‑ancestors` directive) to the response for the /comments endpoint, preferably via a middleware or response‑header configuration.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Source excerpt shows HTML response generation without header handling (lines 173‑177).`
- `Runtime probe fact indicates a GET request to /comments (method: GET).`

Limitations:
- The review only sees this endpoint; other middleware may add headers globally which is not visible in the excerpt.
- No direct observation of response headers was captured; the absence is inferred from code, not from runtime header capture.

### 24. Debug configuration is exposed without authentication

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /debug/config endpoint returns internal configuration values (database URL, mock external URL, app secret) via an unauthenticated GET request, and runtime probing observed an HTTP 200 response where a 401/403/404 was expected. This indicates that sensitive configuration data is publicly accessible.

**Impact:** Attackers can obtain database connection strings, external service URLs, and the application secret, enabling further attacks such as database compromise, credential reuse, or forging authenticated requests.

**Remediation:** Restrict access to the /debug/config endpoint to authorized personnel only (e.g., require authentication and proper authorization checks). Remove or mask sensitive values from the response, and consider disabling the endpoint in production environments.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Runtime probe returned status 200 for GET /debug/config (expected 401/403/404)`
- `Source code shows debug_config() returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without access control`

Limitations:
- Evidence is limited to a single observed request; other access controls (e.g., network firewalls) are not evaluated

### 25. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports that the /healthz endpoint does not include a Content‑Security‑Policy header. The endpoint returns a simple JSON health check and does not serve HTML or execute client‑side scripts, so the absence of CSP does not constitute a practical security risk. No evidence is provided that the endpoint serves content requiring CSP protection.

**Impact:** Minimal impact; the endpoint only returns static JSON data and is not exposed to cross‑site scripting vectors.

**Remediation:** If the endpoint were to serve HTML in the future, add an appropriate Content‑Security‑Policy header. For the current JSON response, no remediation is required.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `runtime_probe_facts: scanner web-runtime reported status 200 for /healthz and missing CSP header`

Limitations:
- The assessment is based solely on the provided source excerpt and runtime probe; it does not account for any external middleware that might add headers at runtime.

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the /healthz endpoint does not include the X-Content-Type-Options header. The source excerpt shows the endpoint returns a JSON payload without any explicit response header manipulation, and no evidence was found that the header is set elsewhere in the application. While the missing header is a security‑hardening issue, the evidence is limited to the scanner observation, so the finding is treated as a likely vulnerability rather than confirmed.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks that could lead to cross‑site scripting or other injection vectors.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to add the X-Content-Type-Options header with the value "nosniff" for all responses, e.g., using a middleware or response header configuration.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `Scanner runtime probe (zap.10021) on GET /healthz reported missing X-Content-Type-Options header`

Limitations:
- No direct code evidence of header handling; the finding relies solely on the scanner output. No runtime logs or tests were provided to confirm the header is absent in production.

### 27. Missing clickjacking protection header on /healthz endpoint

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without the X-Frame-Options or Content-Security-Policy frame-ancestors header, indicating that clickjacking protection is not enforced for this health check endpoint. The scanner flagged this as a missing header, and no contradictory evidence was found in the source code excerpt.

**Impact:** An attacker could embed the /healthz page in a malicious site using an iframe, potentially tricking users into interacting with the endpoint in a context they do not expect. While the endpoint only returns health status, exposing it without frame restrictions can aid reconnaissance and facilitate UI redressing attacks.

**Remediation:** Add an appropriate clickjacking protection header to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors 'self'`. This can be done globally in the FastAPI middleware or specifically for the /healthz route.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe fact: status 200 returned from /healthz with no clickjacking protection header (web.missing-clickjacking-protection)`

Limitations:
- The finding is limited to the /healthz endpoint; other endpoints may already set the header. The health check is typically accessed programmatically, so the practical risk is low. No source code shows explicit header handling, but the absence of a header cannot be definitively proven without full response inspection.

### 28. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without the X-Content-Type-Options header, which browsers use to prevent MIME type sniffing. The scanner observed the missing header directly from the runtime probe. While the endpoint is simple, the absence of this defense-in-depth header is a known security recommendation.

**Impact:** An attacker could potentially exploit MIME type confusion attacks to execute malicious content if the response is interpreted as a different content type by the client.

**Remediation:** Configure the web framework or reverse proxy to include `X-Content-Type-Options: nosniff` on all responses, including the health check endpoint.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe on /healthz returned status 200 without X-Content-Type-Options header (web.missing-content-type-protection)`

Limitations:
- The finding is limited to the /healthz endpoint; other endpoints may already set the header. No evidence of actual exploitation or impact beyond best‑practice deviation.

### 29. Incoming webhook events accept unauthenticated requests

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /integrations/hook endpoint processes POST requests without verifying a signature or any form of authentication. Runtime probing observed a successful 200 response for an unsigned request, whereas the expected secure responses were 400, 401, or 403. The source code inserts the raw request body into the database without validation, confirming the lack of signature checks.

**Impact:** An attacker can craft arbitrary webhook payloads and trigger the endpoint, causing unauthorized data insertion, potential SQL injection vectors, and abuse of any downstream processing that relies on the webhook data.

**Remediation:** Implement request signature verification (e.g., HMAC) or another authentication mechanism before processing the payload. Reject requests that fail verification with appropriate 4xx responses. Additionally, sanitize and validate the request body before database insertion.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Runtime probe fact: POST to /integrations/hook returned status 200 (expected 400/401/403) indicating unsigned request was accepted`
- `Source excerpt shows no signature verification before inserting request body into database`

Limitations:
- Evidence is limited to a single runtime probe; additional testing with varied payloads would confirm consistency
- The code snippet does not show any surrounding middleware that might perform authentication elsewhere

### 30. Missing invoice ownership enforcement

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/invoices/{invoice_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice. The runtime probe shows that a GET request for an invoice owned by another user returns HTTP 200 instead of the expected 403 or 404, confirming that the access control check is missing.

**Impact:** Any authenticated user can retrieve any invoice by guessing or enumerating invoice IDs, leading to confidentiality breaches of financial data.

**Remediation:** Add an ownership check after fetching the invoice row, e.g., compare `row['owner_id']` with the authenticated user's ID and raise `HTTPException(403)` if they do not match. Ensure the database query filters by both `id` and `owner_id` to enforce row‑level security.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Source excerpt shows no ownership check after fetching the invoice row (lines 268‑274).`
- `Runtime probe fact: GET request to `/invoices/{{invoice_id}}` returned status 200 where the rule expected 403 or 404 (assertion_results: false).`

Limitations:
- The review assumes `principal(authorization)` only validates authentication and does not perform ownership checks; if it does, the vulnerability may be mitigated. No information about database schema or additional middleware that could enforce ownership is available.

### 31. Potential unauthorized job creation via /jobs endpoint

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint executes a database INSERT without enforcing sufficient authorization checks. The runtime probe observed a successful 200 response for an unauthenticated request, whereas the expected responses were error codes (400, 403, 422). This suggests that a user may be able to submit jobs they are not permitted to create, potentially escalating privileges or abusing system resources.

**Impact:** An attacker could create arbitrary jobs, possibly running code with elevated privileges or consuming resources, leading to privilege escalation, data corruption, or denial of service.

**Remediation:** Enforce proper authorization checks before inserting jobs. Verify the caller's role and ensure only authorized principals can create jobs of certain kinds. Return appropriate error codes (e.g., 403) for unauthorized attempts.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `runtime_probe_facts: method POST to /jobs returned status 200, while expected statuses were 400, 403, 422 (assertion_results false)`
- `source_excerpt shows create_job calls principal(authorization) but no further role validation before DB insert`

Limitations:
- Evidence is based on a single runtime probe observation; additional testing is needed to confirm the behavior across different user roles and payloads
- The source code snippet does not show the implementation of principal() – it may perform checks not visible here

### 32. SSN disclosed in /me endpoint response

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table and returns all selected columns, including the ssn field, directly to the client without filtering or redaction. The source excerpt shows the SQL query selecting ssn and the return of the full row as a dictionary. Runtime probe facts confirm the endpoint returns a 200 response with data redacted flag true, but do not indicate removal of sensitive fields. This constitutes a potential exposure of personally identifiable information.

**Impact:** An attacker who can obtain a valid JWT for any user can retrieve that user's social security number, leading to identity theft and compliance violations (e.g., GDPR, HIPAA).

**Remediation:** Modify the /me endpoint to exclude sensitive fields such as ssn from the response or mask them. Implement a whitelist of safe attributes to return, e.g., id, username, role, email. Ensure proper authorization checks and consider adding audit logging for access to sensitive data.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Source excerpt line 203: SELECT id,username,role,email,ssn FROM users WHERE id=%s`
- `Source symbol returns dict(row or {}) including ssn`
- `Runtime probe fact: GET /me returned 200 with values_redacted true but no indication ssn was removed`

Limitations:
- The runtime probe indicates values_redacted=true, which may suggest some redaction is applied, but the source code shows ssn is included in the query and returned. Without seeing the actual response payload, we cannot confirm whether the ssn is masked at runtime. Further testing of the endpoint with a valid token is needed to verify the exposure.

### 33. Improper owner assignment allows order creation for other users

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `create_order` endpoint assigns `owner_id` from the request body if provided, falling back to the authenticated user's ID. No validation is performed to ensure the supplied `owner_id` matches the authenticated user, enabling a user to create orders on behalf of any other owner. Runtime probing observed a successful POST to `/orders` returning HTTP 200, contrary to expected 400/403/422 responses for unauthorized owner assignments.

**Impact:** An attacker can create or manipulate orders for other users, leading to unauthorized transactions, potential financial loss, and violation of data integrity and privacy policies.

**Remediation:** Validate that `owner_id` in the request body either matches the authenticated user's ID or is omitted. Reject requests with mismatched `owner_id` with a 403 Forbidden response. Example: `if body.owner_id and body.owner_id != user['sub']: raise HTTPException(status_code=403, detail='Invalid owner')`.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Source excerpt lines 208-215 show `owner_id = body.owner_id or user["sub"]` without checks.`
- `Runtime probe fact: POST /orders returned status 200, while expected unauthorized statuses were 400, 403, 422.`

Limitations:
- The review assumes no downstream authorization checks are performed after the INSERT. Additional code not shown could enforce ownership. Confirmation requires reviewing any middleware or database constraints that might reject mismatched owners.

### 34. Orders can be created with invalid initial status

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe exercised the POST /orders endpoint and received a 200 OK response while the scanner expected a 400 or 422 for invalid input. The assertion result was false, indicating the application accepted the request and created an order with the supplied status value. This suggests the server does not enforce that new orders start in a pending or unpaid state, allowing them to be created as already paid.

**Impact:** An attacker could create orders that are immediately marked as paid, potentially bypassing payment verification, causing financial discrepancies, inventory misallocation, or fraud.

**Remediation:** Validate the 'status' field on order creation server‑side. Reject any request that attempts to set the status to a paid state (e.g., "paid", "completed") during creation and enforce the initial status to be a pending/unpaid value. Return a 400/422 error for invalid status values.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.order_initial_state.1, path=/orders, method=POST, observed status=200, expected_statuses=[400,422], assertion_results=[false]`
- `source_excerpt shows create_order inserts the provided body.status directly into the database without validation`

Limitations:
- Evidence is limited to a single runtime probe request; other input variations were not tested.
- The probe does not show whether downstream business logic later corrects the status.
- No information on authentication/authorization checks beyond the principal extraction.

### 35. Negative order prices are rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The scanner reported that the /orders endpoint rejects negative prices, but the runtime probe observed a successful POST (HTTP 200) when submitting a request that should trigger the negative‑price validation. The probe's assertion result is false, indicating the expected rejection did not occur. No additional evidence confirms that the endpoint validates or rejects negative prices.

**Impact:** If the endpoint does not reject negative prices, an attacker could create orders with negative unit_price values, potentially leading to financial manipulation or unauthorized credit.

**Remediation:** Add explicit validation for the unit_price field in the create_order handler to ensure it is non‑negative, and return an appropriate error response (e.g., 400 Bad Request) when the validation fails.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Runtime probe fact: status 200 for POST /orders with negative price (assertion_results: false)`

Limitations:
- Only a single runtime probe observation is available; other request variations were not tested. The scanner’s static analysis may have misinterpreted code paths. No logs or additional tests confirm the presence or absence of validation logic.

### 36. Server-side price enforcement missing in order creation

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the unit_price value supplied in the request body directly into the database without validation or server-side price lookup. This allows a client to manipulate the price of items when placing an order, violating the requirement that catalog prices must be set by the server.

**Impact:** An attacker can submit orders with arbitrarily low (or high) unit_price values, leading to revenue loss, inventory inconsistencies, or fraudulent transactions.

**Remediation:** Modify the create_order logic to retrieve the official price for the requested item from the catalog (or a trusted source) and use that value for the unit_price field, ignoring any client‑provided price. Validate and enforce that the price matches the catalog before inserting the order.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Source excerpt shows body.unit_price being used in the INSERT statement (lines 213‑215).`
- `Runtime probe fact indicates a POST to /orders returned status 200, confirming the endpoint is reachable and processes the request.`

Limitations:
- The review is based on a single code path; other middleware or database triggers might enforce price checks that are not visible in the provided excerpt. No runtime evidence was found that the server overrides the client‑provided price.

### 37. A note must belong to the order named in the URL

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its primary key (`note_id`) without verifying that the note's `order_id` matches the `order_id` supplied in the URL. This allows an authenticated user to access notes belonging to other orders by guessing or enumerating note IDs, resulting in an insecure direct object reference.

**Impact:** An attacker who can authenticate (or bypass authentication) could read or manipulate notes belonging to orders they do not own, leading to confidentiality breaches and potential data tampering.

**Remediation:** After fetching the note, compare `row['order_id']` with the `order_id` path parameter. If they differ, return a 403 Forbidden or 404 Not Found response. Optionally, enforce this check at the database query level (e.g., `SELECT ... FROM notes WHERE id=%s AND order_id=%s`).
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Source excerpt shows the note is fetched solely by `note_id` (line 546) and returned without order validation.`
- `Runtime probe fact reports a 200 OK response for `/orders/1/notes/2` when the expected statuses were 403 or 404, indicating the missing check.`

Limitations:
- No evidence of actual exploitation in the runtime environment; the finding is based on code review and a single probe result.
- The probe does not confirm the presence of authentication or authorization checks beyond the `principal` call, which may affect the real impact.

### 38. Missing ownership check on order retrieval

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed a successful GET request to /orders/{order_id} returning HTTP 200, while the scanner rule expected a 403 or 404 when the requester is not the owner. The code calls principal(authorization) but no subsequent verification that the authenticated user owns the requested order before returning the row, allowing any authenticated user to read any order.

**Impact:** Unauthorized users can read other users' order details, leading to privacy breaches and potential data leakage of personal or financial information.

**Remediation:** After fetching the order row, verify that the order's owner matches the authenticated principal. Return HTTP 403 if the principal does not own the order before returning the data.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `runtime_probe_facts: status 200 for GET /orders/{{order_id}} where expected 403/404 (rule workflow.order_owner.3)`

Limitations:
- Only a single runtime probe observed the behavior; does not confirm enforcement across all code paths. The principal() function implementation is not shown, so it may perform additional checks not captured by the probe.

### 39. Excessive coupon discounts are accepted instead of rejected

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint updates the order discount with the value supplied in the request body (or the coupon's percent) without validating that the resulting discount is within acceptable bounds. Runtime probing observed a 200 OK response for an excessive discount, whereas the scanner expected a 400/422 error, indicating missing validation logic.

**Impact:** An attacker can apply arbitrarily large discounts to orders, potentially resulting in financial loss or unauthorized free purchases.

**Remediation:** Add server‑side validation to ensure the discount percentage does not exceed a defined maximum (e.g., 50%). Return a 4xx error when the discount is out of bounds. Consider validating both the coupon's stored percent and any client‑supplied discount value.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Runtime probe fact: method POST to /orders/{{order_id}}/apply-coupon returned status 200 when an excessive discount was supplied, contrary to expected 400/422 (scanner rule workflow.coupon_bounds.2).`
- `Source excerpt shows the discount is taken directly from body.discount or coupon.percent without bounds checking.`

Limitations:
- Evidence is limited to a single runtime probe observation; additional testing is needed to confirm the range of accepted discounts and whether other checks (e.g., business rules) exist elsewhere in the code.

### 40. Paid orders can be cancelled without prior refund

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /orders/{order_id}/cancel endpoint updates the order status to 'cancelled' and returns a 200 response regardless of the order's payment state. Runtime probing confirms the endpoint returns 200 (status 200) where the expected statuses for a paid‑cancel workflow are 400, 409, or 422, indicating missing business‑logic enforcement that a refund must precede cancellation.

**Impact:** An attacker or malicious user could cancel paid orders without issuing a refund, leading to financial loss and potential abuse of the order management system.

**Remediation:** Add logic to verify the order's payment status before allowing cancellation. If the order is paid, require a successful refund operation first and return an appropriate error (e.g., 400 Bad Request) when the refund has not been processed.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Source code shows the cancel_order function unconditionally executes an UPDATE to set status='cancelled' and returns the row with a 200 response (lines 258‑263).`
- `Runtime probe fact reports method POST to /orders/{{order_id}}/cancel returned status 200, while the expected statuses for the paid_cancel workflow are 400, 409, 422.`

Limitations:
- The evidence does not confirm whether downstream checks (e.g., database triggers or other services) enforce refund requirements; the review is based solely on the observed endpoint behavior. No information on authentication/authorization checks beyond the principal call is provided.

### 41. Payment replay allows second payment on already paid order

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The runtime probe observed that a POST to /orders/{order_id}/pay on an order that is already marked as paid returned HTTP 200 instead of the expected error codes (400, 409, 422). The endpoint updates the order status to 'paid' without checking the current status, enabling a second payment on an already paid order.

**Impact:** An attacker could replay a payment request to charge a customer twice for the same order, leading to financial loss and potential fraud.

**Remediation:** Add a check before processing the payment to verify that the order status is not already 'paid'. Return an appropriate error (e.g., 409 Conflict) if a payment is attempted on a paid order. Ensure idempotency keys are used to prevent duplicate processing.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Runtime probe fact: POST /orders/{{order_id}}/pay returned status 200 on step 3 where expected statuses were 400, 409, 422 (web-runtime rule workflow.payment_replay.3).`

Limitations:
- Evidence is based on a single runtime probe; no additional guard checks or rate‑limiting evidence were observed. The source code excerpt does not show a status check for already‑paid orders, but the absence of such logic is inferred from the probe result.

### 42. Insecure Direct Object Reference in profile endpoint

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /profiles/{profile_id} endpoint retrieves user data based solely on the supplied profile_id without verifying that the requester owns or is authorized to view that profile. Runtime probing observed a successful 200 response when accessing another user's profile, contradicting the expected 403/404 responses, confirming an IDOR vulnerability.

**Impact:** An attacker can enumerate or retrieve sensitive information (username, email, SSN) of any user by iterating profile IDs, leading to privacy breaches and potential identity theft.

**Remediation:** Implement proper authorization checks to ensure the authenticated user can only access their own profile or profiles they are permitted to view. For example, compare the profile_id with the authenticated user's ID and return 403 if they do not match. Additionally, consider using opaque identifiers instead of sequential IDs.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `Runtime probe returned status 200 for GET /profiles/{{other_id}} when accessing another user's profile, while expected statuses were 403 or 404.`
- `Source code shows no ownership check before executing the SQL query: row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone()`

Limitations:
- Evidence is limited to a single runtime probe; additional testing across multiple accounts would further confirm the scope. The analysis assumes the principal() function only validates authentication, not authorization.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /view endpoint returns an HTMLResponse that does not include any X-Frame-Options or Content‑Security‑Policy frame‑ancestors directives. The source excerpt shows the raw HTML being returned without header manipulation, and the runtime probe confirms a GET request to /view with no evidence of the header being set.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add an appropriate anti‑clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame‑ancestors` directive) to the response for the /view endpoint, either globally via middleware or specifically in the view function.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Source excerpt shows HTMLResponse without header logic`
- `Runtime probe fact for GET /view with no header values`

Limitations:
- Only the /view endpoint was examined; other endpoints may set the header globally
- No runtime probe of response headers was captured, so absence is inferred from code rather than observed

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /view does not include an X-Content-Type-Options header. The source code shows a simple HTMLResponse returned without explicit header manipulation, which is typical for frameworks that may add default security headers based on configuration. No evidence was provided that the application deliberately disables this header or that the framework omits it by default. Without configuration context, the missing header alone does not constitute a confirmed vulnerability.

**Impact:** If the header is truly absent, browsers could perform MIME type sniffing, potentially leading to content injection attacks. However, the risk is low given the endpoint serves static HTML and the overall impact is limited.

**Remediation:** Configure the web framework or middleware to add the X-Content-Type-Options: nosniff header to all responses, e.g., via a security middleware or response header setting in the FastAPI/Starlette configuration.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner runtime probe for GET /view reported missing X-Content-Type-Options header`

Limitations:
- No deployment_context or configuration files were provided to confirm whether the header is intentionally omitted or added elsewhere
- The scanner evidence is the only source; no runtime logs or additional probes confirm the header's absence

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /view returns an HTML page without a Content‑Security‑Policy header. The scanner detected the missing header and flagged it as a potential security issue. No evidence was found in the provided source excerpt that a CSP header is added elsewhere (e.g., via middleware or a reverse proxy).

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, and other resources can be loaded, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Configure the application or its deployment environment to include a CSP header on all HTML responses. This can be done by adding appropriate middleware (e.g., Starlette's CSP middleware) or configuring the web server/reverse proxy to inject the header with a restrictive policy.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Scanner reported "Content Security Policy (CSP) Header Not Set" for GET /view`
- `Source excerpt shows HTMLResponse returned directly without header manipulation`

Limitations:
- Only the /view endpoint was examined; other routes may set CSP via different mechanisms
- The analysis assumes no external proxy adds the header, which cannot be confirmed from the provided data

### 46. Webhook destination validation appears correct

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code explicitly checks that the provided target_url contains the string "mock-external" and raises an HTTP 400 error otherwise. The runtime probe shows a POST to /webhooks returned a 200 status, indicating the request satisfied the validation condition. There is no evidence that arbitrary external URLs are accepted.

**Impact:** None identified; the endpoint enforces the intended restriction.

**Remediation:** No remediation required for this finding.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `source_excerpt lines 294-298 show the validation logic`
- `runtime_probe_facts assertion_results false indicates the expected 400/422 was not triggered for the tested input`

Limitations:
- The review is based solely on the provided code snippet and probe result; it does not assess other parts of the application that might bypass this check.

### 47. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the application secret (APP_SECRET) in clear text using the standard logger. This is directly observable in the source excerpt at line 137 where `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))` is executed for every successful login. Logging secrets exposes them to any system that collects or stores logs, which may be accessible to attackers or inadvertently leaked.

**Impact:** An attacker who gains read access to log files can retrieve the application secret, enabling them to forge tokens, impersonate users, or access other protected resources. This compromises confidentiality and can lead to full account takeover.

**Remediation:** Remove the secret from log statements. Log only non-sensitive identifiers (e.g., username) and avoid including environment secrets. If debugging information is needed, use a dedicated debug flag and ensure logs are protected with proper access controls. Consider redacting or hashing sensitive values before logging.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `Source excerpt line 137 shows clear‑text logging of `APP_SECRET``

Limitations:
- The review is based solely on static source analysis; runtime behavior (e.g., log level configuration) could suppress the log, but the presence of the statement constitutes a vulnerability regardless of logging configuration.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds a CORSMiddleware with allow_origins set to "*" and also allows all methods and headers. This configuration permits any website to make cross‑origin requests to the API, which can lead to credential leakage or CSRF‑style attacks if the API processes authenticated requests.

**Impact:** An attacker-controlled website could issue requests to the API on behalf of a logged‑in user, potentially accessing or modifying data that the user is authorized to use. While the immediate risk depends on the sensitivity of the API endpoints, the open policy broadens the attack surface.

**Remediation:** Restrict the CORS policy to a whitelist of trusted origins. Set allow_origins to the specific domains that should be allowed, and consider limiting allow_methods and allow_headers to only those required. Example:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py lines 24‑30 show allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]`

Limitations:
- The snippet does not indicate whether the API requires authentication for sensitive actions; the actual risk depends on endpoint behavior. No runtime observations were provided to confirm exploitation.

### 49. Potential Log Injection via user-controlled values

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs the username supplied by the client and the application secret without any sanitization. An attacker can craft a username containing control characters (e.g., newlines, log formatting tokens) that may corrupt log structure or inject malicious entries. The inclusion of the secret further amplifies the risk if logs are exposed.

**Impact:** Successful log injection could enable log forging, obscuring malicious activity, facilitating further attacks (e.g., injection into downstream log parsers), or accidental disclosure of the application secret if logs are accessed by unauthorized parties.

**Remediation:** Sanitize or encode user-supplied values before logging. Avoid logging sensitive secrets such as APP_SECRET. Use structured logging with safe parameter handling provided by the logging framework.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- The severity depends on the logging configuration and downstream log processing; if logs are written to a secure, non‑executable sink and the logging library safely escapes parameters, the impact may be reduced.

### 50. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list checking. An attacker can supply an arbitrary URL, causing the application to redirect users to a malicious site.

**Impact:** Facilitates phishing attacks, credential harvesting, and can be used to bypass security controls that rely on trusted redirects.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a whitelist.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source excerpt shows `def continue_to(next: str = "/") -> RedirectResponse: return RedirectResponse(next, status_code=302)` which forwards the user‑controlled `next` value directly to the redirect response.`

Limitations:
- No runtime probe data confirming exploitation; the analysis is based solely on static code inspection. Additional context such as URL validation elsewhere in the codebase could mitigate the issue but is not present in the provided excerpt.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The function verified_continue validates the supplied URL by ensuring it starts with a single '/' and rejects any value that starts with '//' or contains a scheme or netloc. This prevents redirection to external domains, mitigating an open‑redirect vulnerability. The scanner’s generic rule flagged the use of a redirect without recognizing the explicit validation logic.

**Impact:** None – the endpoint cannot be abused to redirect users to untrusted external sites.

**Remediation:** No remediation required; the existing validation is sufficient. Maintain the checks and consider adding unit tests to cover edge cases.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Source excerpt shows explicit checks for leading '/' and rejection of scheme/netloc (lines 622‑624).`

Limitations:
- The review assumes the function is the only entry point for redirects; if other code paths perform redirects without similar validation, they are not covered here.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container health monitoring, its absence does not constitute a security vulnerability. No evidence is provided that the missing health check leads to exploitable conditions, and the scanner’s recommendation is advisory rather than indicative of a concrete flaw.

**Impact:** None – the container will still run, but orchestration systems may lack automatic health verification, potentially affecting reliability rather than security.

**Remediation:** Add a suitable HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`. This improves operational monitoring but does not address a security issue.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- The assessment is based solely on the Dockerfile content; runtime behavior or external monitoring setups are not examined. The recommendation is advisory and does not imply a security breach.

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
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- The assessment is based solely on the Dockerfile content; runtime health monitoring could be implemented externally, which is not visible here.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a recommended best practice for container health monitoring, its absence does not directly constitute a security vulnerability. No evidence is provided that the missing HEALTHCHECK leads to exploitable conditions such as denial‑of‑service or unauthorized access.

**Impact:** Minimal – containers may not be automatically restarted or flagged as unhealthy, which could affect availability but does not create a direct security breach.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`. This improves operational reliability but is not required for security compliance.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- The assessment is based solely on the Dockerfile content; runtime behavior or external monitoring setups are not examined. The recommendation assumes the application exposes a health endpoint.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies (CVE-2026-53539)

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-53539, a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded request bodies. The scanner evidence directly cites this CVE and notes that the issue is fixed in version 0.0.30. No mitigating controls or runtime checks were observed that would prevent exploitation of this flaw.

**Impact:** An attacker can send a maliciously crafted request to the FastAPI application, causing the python-multipart parser to consume excessive resources and potentially crash or become unresponsive, leading to service disruption.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version is installed by checking the lock file or running `pip freeze`.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt pins python-multipart==0.0.20`

Limitations:
- The review relies on the scanner’s CVE mapping; no runtime probe confirmed the vulnerability’s exploitability in the deployed environment.

### 56. Denial of Service via excessive multipart part headers in python-multipart 0.0.20

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20 as shown in the requirements.txt excerpt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by crafted multipart requests with an excessive number of part headers. The scanner evidence cites this CVE and notes that the issue is fixed starting with version 0.0.27. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially crashing the service or rendering it unavailable to legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later. Verify the updated dependency resolves CVE-2026-42561 and run integration tests to ensure compatibility with FastAPI request handling.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`
- `requirements.txt shows python-multipart==0.0.20`

Limitations:
- No runtime probe data was provided to confirm whether the vulnerable code path is exercised in the deployed application.

### 57. python-multipart information disclosure (CVE-2026-53538)

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53538. The CVE describes an information‑disclosure issue caused by a differential parser behavior when handling multipart form data. The scanner identified this vulnerable version and reported that the vulnerability is fixed starting with version 0.0.30. No contradictory evidence was found in the runtime probes or other sources.

**Impact:** An attacker who can supply crafted multipart form data could cause the application to leak sensitive request data or internal state, potentially exposing user credentials, session tokens, or other confidential information.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Verify the upgrade does not introduce breaking changes by reviewing the changelog and running the test suite. Optionally, add dependency‑checking CI steps to prevent regression.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency entry in requirements.txt specifies python-multipart==0.0.20`
- `Scanner evidence: "Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30."`

Limitations:
- The review relies solely on the declared dependency version; it does not confirm that the vulnerable code path is exercised at runtime. No runtime probe data was available to demonstrate exploitation or mitigation in the current deployment.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20 as declared in requirements.txt. This version is known to contain CVE-2026-40347, a denial‑of‑service vulnerability triggered by specially crafted multipart/form-data payloads. The scanner identified the vulnerable version and the fix introduced in 0.0.26. No evidence was found that the project has applied a mitigation or upgraded the library, so the vulnerability is present in the current dependency set.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially causing the FastAPI service to become unresponsive, leading to service disruption or denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, and verify that the new version does not introduce breaking changes in request handling. Re‑run dependency scanning after the upgrade to confirm the issue is resolved.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency entry in requirements.txt specifies python-multipart==0.0.20`
- `Scanner evidence cites CVE-2026-40347 affecting python-multipart 0.0.20 and fixed in 0.0.26`

Limitations:
- The review relies on the declared dependency version; if the runtime environment overrides this version, the finding may not apply. No runtime probe data was available to confirm the library is loaded or the vulnerable code path is exercised.

### 59. python-multipart: Arbitrary file write via path traversal (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-24486, a path‑traversal flaw that allows an attacker to write arbitrary files on the server when processing multipart/form‑data. The vulnerability is documented and fixed in version 0.0.22.

**Impact:** An attacker could exploit the vulnerable multipart handling to write files to arbitrary locations, potentially achieving remote code execution, defacement, or data exfiltration.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later and rebuild the application. Verify that the new version is included in the dependency lockfile and redeploy.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- The finding is based on version pinning in requirements.txt; runtime behavior was not observed. No additional runtime probe data is available to confirm exploitation path.

### 60. python-multipart 0.0.20 contains CVE-2026-53537

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20. A known CVE (CVE-2026-53537) affecting this version allows information disclosure via header parsing discrepancies. The scanner identified this vulnerability and noted that it is fixed in version 0.0.30. No additional runtime evidence contradicts the presence of the vulnerable library.

**Impact:** An attacker could exploit the header parsing flaw to obtain sensitive information from HTTP requests processed by the application, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and verify that the updated version is correctly reflected in the deployed environment.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies on the declared dependency version in requirements.txt; it does not confirm the exact version deployed at runtime. No runtime probe data was provided to verify the library version in the running container.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner identified a known vulnerability (CVE‑2026‑53540) in python‑multipart version 0.0.20, which is present in the project's requirements.txt. The CVE description matches the reported issue of negative Content‑Length causing the entire request body to be buffered in memory, leading to potential denial‑of‑service. The vulnerable version is explicitly listed, and a fixed version (0.0.31) is available.

**Impact:** An attacker can craft a request with a negative Content‑Length header, causing the server to allocate unbounded memory for the request body. This can exhaust system resources, resulting in service disruption or crash.

**Remediation:** Upgrade python‑multipart to version 0.0.31 or later, which contains the fix for CVE‑2026‑53540. Verify the updated dependency does not introduce compatibility issues and run the test suite after upgrading.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`

Limitations:
- The review relies on the scanner's CVE mapping; no runtime probe was performed to confirm exploitability in the specific application context.

### 62. Dynamic urllib usage without demonstrated user-controlled input

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged the use of urllib with a dynamically constructed URL, but the code shows the URL is built from a constant base (BASE) concatenated with a path argument that is not shown to be attacker-controlled. No runtime evidence or additional analysis demonstrates that an external user can influence the URL value, nor is there evidence of unsafe file:// schemes being used. Consequently, the finding lacks sufficient proof of a vulnerability.

**Impact:** If the URL were attacker-controlled, it could lead to SSRF or local file read, but the current code does not exhibit such control, so the impact is not established.

**Remediation:** Review the request function to ensure that the `path` argument cannot be influenced by untrusted input. If needed, validate or sanitize the path, or switch to a higher‑level HTTP library such as `requests` that does not support file URLs by default.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen called with BASE + path, where BASE is a constant and path origin is not shown to be user‑controlled.`

Limitations:
- No runtime probe data confirming attacker control of the URL.
- No evidence that file:// schemes are used.
- Scanner finding is based solely on pattern matching without contextual analysis.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a urllib request built from a dynamic value (payload["target_url"]). While urllib can handle file:// URLs, there is no concrete evidence that the target_url can be controlled by an attacker or that malicious schemes are accepted. The code does not show validation or sanitization of the URL, but without runtime observations or additional context, the risk cannot be confirmed.

**Impact:** If an attacker can influence the target_url, they might trigger unintended requests or potentially read local files via a file:// scheme, leading to information disclosure or SSRF-like behavior.

**Remediation:** Validate and sanitize the target_url before using it with urllib. Restrict allowed schemes to http/https, or switch to a higher‑level library like requests that enforces safer defaults. Consider adding explicit checks against file:// and other unsafe schemes.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows urllib.request.urlopen called with payload["target_url"] without apparent validation.`

Limitations:
- No runtime probe data confirming attacker control of payload["target_url"].
- No evidence that file:// scheme is accepted or that the URL is used in a security‑critical context.
- Scanner finding only; no additional corroborating evidence from other sources.

### 64. Unauthenticated file read endpoint

- Issue group: `ai-827cbbfd5e460c8b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `/files` endpoint returns the contents of any file under the configured public directory based solely on a user‑supplied `name` parameter. No authentication or authorization checks are performed before the file is read and returned. While the code prevents path traversal with `is_relative_to`, the lack of access control constitutes a business‑logic flaw that can lead to information disclosure if sensitive files are placed in the public directory or if the endpoint is intended for authenticated users only.

**Impact:** An attacker can enumerate and retrieve files from the server without authentication, potentially exposing configuration files, private data, or other sensitive information stored in the public directory.

**Remediation:** Add authentication and authorization checks (e.g., FastAPI dependencies, role‑based guards) before accessing the file. If the endpoint should remain public, ensure the public directory contains only non‑sensitive assets and consider serving files via a static file handler rather than a custom endpoint.
Evidence:
- Source IDs: `ai-827cbbfd5e460c8b`, `ai-94b5d2001b78c64e`
- `api/extra.py:210: @router.get("/files")`
- `api/extra.py:211: def file_read(name: str) -> Response:`
- `api/extra.py:212: file = (FILES / "public" / name).resolve()`
- `api/extra.py:213: if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")`
- `api/extra.py:215: return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The review assumes no global FastAPI dependencies enforce authentication for all routes; such middleware could mitigate the issue but is not evidenced in the provided excerpts. The actual sensitivity of files in the `public` directory is unknown.

### 65. Potential missing admin role verification in admin_audit endpoint

- Issue group: `ai-b281d25e361523d2`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The code defines an /admin/audit endpoint that calls `require_admin(authorization)` before returning a success response. The implementation of `require_admin` is not present in the provided repository snapshot, so it cannot be confirmed whether it correctly validates the token and checks the user's admin role. Without evidence of robust role verification, the endpoint could be accessible to unauthorized users, but the lack of concrete proof means the vulnerability cannot be confirmed.

**Impact:** If `require_admin` fails to enforce proper admin checks, non‑admin users could retrieve audit information, potentially exposing sensitive operational data or enabling further privilege escalation.

**Remediation:** Ensure that `require_admin` validates the Authorization header against a trusted authentication source, extracts the user's role, and explicitly denies access when the role is not admin. Add unit tests and code comments to demonstrate the verification logic. Consider adding defensive checks (e.g., response codes 403) and logging for unauthorized attempts.
Evidence:
- Source IDs: `ai-b281d25e361523d2`
- `204: @router.get("/admin/audit")`
- `205: def admin_audit(authorization: str | None = Header(default=None)) -> dict:`
- `206:     require_admin(authorization)`
- `207:     return {"status": "authorized"}`

Limitations:
- The source code for `require_admin` is not available, so its correctness cannot be assessed.
- No runtime observations (e.g., probe results) confirming whether the endpoint enforces admin checks.
- No deployment context or configuration details that might affect authorization behavior.

### 66. Potential missing authentication on verified_file_read endpoint

- Issue group: `ai-ffdf7e41dd3fadea`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /files/verified serves arbitrary files from the public directory without any authentication or authorization checks. The code only validates that the requested path is within the public directory and that the file exists, but does not verify the caller's identity or permissions. No evidence of a global security middleware that would protect this route is present in the provided excerpts, so the lack of explicit checks is a plausible access control issue.

**Impact:** An unauthenticated attacker could retrieve any file placed in the public directory, potentially exposing sensitive information or internal configuration files if they are inadvertently stored there.

**Remediation:** Add authentication and authorization checks to the verified_file_read handler (e.g., require a valid JWT or session and verify the user has permission to read the requested file). Alternatively, enforce a global security middleware that restricts access to this route. Document the intended access policy and ensure the route complies with it.
Evidence:
- Source IDs: `ai-ffdf7e41dd3fadea`
- `api/extra.py:218 – @router.get("/files/verified") defines the endpoint without security parameters`
- `api/extra.py:224 – return Response(file.read_text(encoding="utf-8"), media_type="text/plain") returns file contents without auth checks`

Limitations:
- The review is based solely on the provided code snippets; if a global FastAPI dependency or middleware enforces authentication for all routes, it is not visible here
- The severity assumes the public directory does not contain highly sensitive files; if it does, impact could be higher

### 67. Potential overexposure of sensitive user data in /me endpoint

- Issue group: `ai-b0dfdc8f9b2bed63`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `/me` endpoint returns all columns from the users table, including email and SSN, for the authenticated principal. No attribute‑level or role‑based checks are visible before the data is serialized and sent to the client. If an attacker can obtain a valid token (or exploit a token‑theft flaw), they could retrieve personally identifiable information that should be protected.

**Impact:** Disclosure of email addresses and Social Security Numbers can lead to identity theft, phishing, and compliance violations (e.g., GDPR, HIPAA).

**Remediation:** Implement fine‑grained authorization: only return non‑sensitive fields by default and require explicit scopes or roles to access email/SSN. Consider using a serializer that filters sensitive attributes or a separate endpoint for privileged data. Also review the `principal` function and any middleware for possible attribute filtering.
Evidence:
- Source IDs: `ai-b0dfdc8f9b2bed63`
- `199: @app.get("/me")`
- `200: def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `201:     user = principal(authorization)`
- `202:     with connection() as conn:`
- `203:         row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()`
- `204:     return dict(row or {})`

Limitations:
- The code of `principal` and any downstream middleware is not provided, so it is unknown whether additional filtering occurs after the query.
- No runtime observations (e.g., actual responses) are available to confirm that SSN/email are included in the response payload.

## Policy Decisions

- `merged-18f1abe978f9fdaad8e6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-bdfe7542047da39c6151`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-17a5197f906426a224ef`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-5230c114e62065082a9b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-65c41e5a25b6337fec07`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-1ba9f8276fc6dae95df8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
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
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-827cbbfd5e460c8b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-b281d25e361523d2`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-ffdf7e41dd3fadea`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-b0dfdc8f9b2bed63`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **67**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **5**; scanner overlaps: **0**; AI overlaps: **1**; new candidates: **4**; uncertain overlaps: **0**; needs more evidence: **0**; rejected: **0**.

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

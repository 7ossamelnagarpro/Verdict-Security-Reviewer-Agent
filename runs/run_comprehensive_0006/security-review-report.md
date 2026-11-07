# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-06T17:24:03.437456+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>completed</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **69/69**; model calls: **10**.
- AI Discovery warning: 3 empty source file(s) were skipped; they contain nothing to review.
- AI Discovery warning: The duplicate-avoidance list in the discovery prompt was trimmed; candidates are de-duplicated against scanner findings downstream.
- AI Discovery warning: Some background coverage gaps were not sent to the model; they remain in the report's coverage gaps.
- AI Discovery warning: 2 duplicate AI candidate(s) were merged into 2 stronger one(s): ai-8911a8c11e463193 &lt;- ai-171eefd0f03fff68; ai-46708a4888648bdc &lt;- ai-ee480c239612665b

The agent reviewed **88** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **88**; reviewed: **88**; pending: **0**.

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

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string without any sanitisation or parameterisation. This allows an attacker to inject arbitrary SQL code via the username or password fields, leading to authentication bypass or data exfiltration.

**Impact:** An attacker can perform SQL injection to bypass authentication, retrieve or modify user records, and potentially execute arbitrary database commands, compromising confidentiality, integrity, and availability of the application data.

**Remediation:** Refactor the query to use parameterised statements or an ORM that safely escapes user input. For example, use prepared statements with placeholders (e.g., `SELECT id, username, role FROM users WHERE username = ? AND password = ?`) and pass the user values as parameters. Additionally, hash passwords with a strong algorithm and compare hashes instead of storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117 constructs the query with f‑string interpolation of `body.username` and `body.password``
- `Line 119 executes the raw query via `conn.execute(query)``

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., input validation elsewhere) was not observed.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter, but it resolves the path and then checks `is_relative_to(root)` and `is_file()` before reading. This prevents directory traversal attacks by ensuring the resolved path stays within the intended directory. The scanner’s generic pattern flags any user‑controlled path usage, but the explicit safety checks mitigate the risk.

**Impact:** If the checks were bypassed, an attacker could read arbitrary files, but the current logic correctly blocks such attempts, so no impact is present.

**Remediation:** No remediation needed; the existing `resolve()` and `is_relative_to()` checks provide proper path validation. Maintain these checks if the code is modified.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 220‑223 show the resolve and `is_relative_to` check`
- `source_symbol confirms the same logic`

Limitations:
- Static analysis cannot guarantee that `FILES` is correctly set to a safe directory at runtime; if `FILES` were misconfigured, the check could be ineffective. No runtime probe data is available to confirm behavior under attack conditions.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but then validates it with `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` check ensures the resolved path remains within the intended `root` directory, effectively preventing directory traversal. Consequently, the reported uncontrolled data usage does not lead to a path traversal vulnerability.

**Impact:** None – the validation prevents access to files outside the public directory.

**Remediation:** No remediation required for path traversal; the existing checks are sufficient. Maintain the `is_relative_to` validation and ensure future changes preserve this logic.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source_excerpt lines 218‑224 show the use of `is_relative_to(root)` to enforce the file stays within the public directory.`

Limitations:
- The analysis assumes the `FILES` constant points to a safe base directory and that no other code modifies the path after this check.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided name but immediately resolves it and checks `is_relative_to(FILES.resolve())` as well as `is_file()`. These checks ensure the resulting path stays within the intended directory and points to an existing file, effectively mitigating path traversal. The scanner’s generic pattern flagged the use of user input in a path expression, but the code includes proper validation, so no vulnerability is present.

**Impact:** None – the request cannot access files outside the designated public directory.

**Remediation:** No remediation needed; the existing relative‑path check is sufficient. Maintain the validation logic if the code changes.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Line 212 constructs the path using `FILES / "public" / name` and resolves it.`
- `Line 213 checks `is_relative_to(FILES.resolve())` to enforce directory confinement.`
- `Line 213 also checks `is_file()` to ensure the target exists.`

Limitations:
- The review assumes the `FILES` constant is correctly set to the intended base directory and that no symbolic link attacks bypass `is_relative_to`.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user-provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to(root)`. It also checks that the path points to an existing file before reading it. These safeguards prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None, as the path is properly validated and constrained to the intended directory.

**Remediation:** No remediation required for this finding; the existing checks are sufficient. Maintain the current validation logic for future changes.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `The function uses `root = (FILES / "public").resolve()` and `file = (root / name).resolve()` followed by `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")` which blocks traversal and non‑existent files.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` and that `FILES` is correctly set to the intended public directory. If the environment changes, the validation should be re‑verified.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory (FILES / "public") and then verifies that the resulting path is still within that base directory using `is_relative_to(FILES.resolve())` and that it points to an existing file with `is_file()`. These checks effectively prevent directory traversal attacks, making the scanner’s path‑traversal finding unwarranted.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to data disclosure. However, the implemented checks mitigate this risk.

**Remediation:** No remediation needed; the existing path validation is sufficient. Ensure that `FILES` is a trusted absolute path and that the Python version supports `Path.is_relative_to` (Python 3.9+).
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `Source excerpt shows the use of `Path.resolve()` followed by `is_relative_to(FILES.resolve())` and `is_file()` checks, which together block traversal to parent directories.`
- `The function raises `HTTPException(404)` for any path that fails these checks, preventing exposure of unintended files.`

Limitations:
- The analysis assumes `FILES` is correctly defined as an absolute directory and that the runtime environment uses a Python version where `is_relative_to` behaves as expected.

### 7. Reflected server-side cross-site scripting

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/search` interpolates the user‑controlled query parameter `q` directly into the HTML response without any escaping or sanitisation. The value is used both in a SQL query (potentially leading to SQL injection) and in the returned HTML (`<h1>Results for {q}</h1>` and `<p>{row['name']}</p>`), enabling an attacker to inject arbitrary script content that will be reflected to the victim's browser.

**Impact:** An attacker can craft a URL containing malicious JavaScript in the `q` parameter. When a victim follows the link, the script executes in the victim's browser context, allowing session hijacking, credential theft, or other malicious actions.

**Remediation:** Properly escape or encode user input before embedding it in HTML. Use a templating engine that auto‑escapes, or explicitly HTML‑escape `q` (e.g., `html.escape(q)`). Additionally, employ parameterised queries for the database access to prevent SQL injection.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt shows `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)` which directly injects `q` into the response.`

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., content‑security‑policy headers) was not observed.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks that the resulting path is within the allowed directory (FILES / "public") using is_relative_to. It also verifies that the path points to an existing file before returning its contents. These safeguards mitigate typical path‑traversal attacks, so the scanner’s finding is likely a false positive.

**Impact:** If the checks were bypassed, an attacker could read arbitrary files, but the current logic prevents directory escape, so no impact is present.

**Remediation:** No remediation needed for path traversal; ensure the is_relative_to check remains and consider adding explicit validation of the "name" parameter (e.g., whitelist allowed filenames) for defense‑in‑depth.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Source excerpt shows resolve() and is_relative_to(FILES.resolve()) check on line 213, and file existence check on line 213 before reading the file.`

Limitations:
- The review assumes the Python version supports Path.is_relative_to (Python 3.9+). If running on an older version, the check may not behave as intended. Additionally, the review does not account for potential side‑effects of resolve() with symlinks.

### 9. SQL injection via unsanitized query construction

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `GET /catalog/search` builds an SQL statement by directly interpolating the user‑controlled query parameter `q` into a string literal using an f‑string. This allows an attacker to inject arbitrary SQL syntax into the `WHERE name ILIKE '%{q}%'` clause, potentially retrieving or modifying data beyond the intended scope.

**Impact:** An attacker could enumerate product names, extract sensitive data, or perform destructive actions such as data deletion if additional statements are concatenated. The vulnerability may lead to data breach, integrity loss, or privilege escalation depending on database permissions.

**Remediation:** Use parameterised queries or an ORM that safely escapes user input. For example, replace the f‑string with a prepared statement: `rows = conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",)).fetchall()`. Validate and sanitise the `q` parameter if only certain patterns are allowed.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt shows f‑string interpolation of `q` into SQL at line 144.`
- `Candidate metadata lists the finding as "SQL query built from user‑controlled sources" with high confidence.`

Limitations:
- No runtime probe data is available to confirm exploitation, but the code pattern is a known injection vector.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scan reports that the HTTP response for the root path (GET /) does not include the X-Content-Type-Options header. The source excerpt shows the FastAPI endpoint implementation, which does not set any security headers. No runtime probe evidence contradicts this finding. Absence of this header can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks.

**Impact:** An attacker could exploit MIME type sniffing to execute malicious scripts if the application serves user-controlled content with ambiguous MIME types, increasing the risk of cross-site scripting (XSS).

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options: nosniff header on all responses, e.g., using Starlette's Middleware or a custom response header injection.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `X-Content-Type-Options Header Missing reported by scanner (zap.10021) for GET /`

Limitations:
- The review is based solely on the scanner report and source code excerpt; no runtime probe of actual response headers was provided, so the header might be added by external middleware not visible in the excerpt.

### 11. Improper Access Control on /admin/jobs endpoint

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/jobs route returns a list of jobs with HTTP 200 status even when accessed without proper authorization. The runtime probe expected a 403 or 404 response but observed 200, indicating that the principal() check does not enforce admin restrictions for this endpoint.

**Impact:** An attacker can enumerate all job listings, potentially exposing sensitive internal data and enabling further attacks such as data leakage or privilege escalation.

**Remediation:** Enforce proper authorization checks in the admin_jobs handler. Ensure that the principal() function validates the user's role and returns a 403 Forbidden response for non‑admin users. Consider adding explicit role checks and returning appropriate error codes.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Runtime probe for GET /admin/jobs returned status 200 (expected 403/404)`

Limitations:
- Only a single runtime probe was performed; the behavior with different Authorization header values was not observed. The source code snippet shows a call to principal() but its implementation is not shown, so the exact cause of the bypass cannot be confirmed without further analysis.

### 12. Improper access control on /admin/token-report endpoint

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/token-report endpoint returns a 200 OK response even when the authenticated user does not have the admin role, violating the intended access control check that should raise a 403 error for non‑admin users. Runtime probe evidence shows the endpoint responded with status 200 instead of the expected 403/404, indicating a stale role check.

**Impact:** An attacker who has been demoted from admin (or any non‑admin user) can still access administrative token information, potentially exposing sensitive tokens or allowing privilege escalation.

**Remediation:** Ensure the role check correctly denies access for non‑admin users. Return HTTP 403 (or 404) when token.get("role") != "admin" and verify that the endpoint cannot be accessed without proper admin credentials.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Runtime probe fact: method GET to /admin/token-report returned status 200, expected statuses [403,404] (rule workflow.stale_role.3)`

Limitations:
- Evidence is based on a single runtime probe; additional testing with varied tokens and authentication headers is needed to confirm consistent behavior across all scenarios.

### 13. Improper access control on /admin/users endpoint

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users endpoint returns a full list of user records, including sensitive fields such as SSN, without enforcing an admin role check. The runtime probe observed a 200 OK response for an unauthenticated request, whereas the expected statuses were 403 or 404, indicating a missing authorization enforcement.

**Impact:** An attacker can enumerate all user accounts and retrieve sensitive personal information (e.g., SSN), leading to privacy violations and potential identity theft.

**Remediation:** Implement proper role‑based access control: verify that the requester has an admin role before querying and returning user data. Return 403 Forbidden for non‑admin requests and limit returned fields to non‑sensitive information.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Source code shows admin_users endpoint calls principal(authorization) but no explicit role check before returning all user rows`
- `Runtime probe fact: method GET to /admin/users returned status 200, while expected statuses were 403 or 404`

Limitations:
- The exact behavior of principal() is not shown; it may perform role checks internally, but the observed 200 response suggests it does not block non‑admin access in this context

### 14. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /auth/form-login endpoint returns an HTMLResponse without setting a Content‑Security‑Policy header. No evidence of CSP configuration was found in the source excerpt or runtime probe facts, indicating the header is likely omitted.

**Impact:** Without CSP, the page is vulnerable to client‑side injection attacks such as reflected XSS, which could allow an attacker to execute arbitrary JavaScript in a victim's browser and steal session cookies or perform actions on behalf of the user.

**Remediation:** Configure the FastAPI response to include a CSP header that restricts script, style, and other resource sources to trusted origins. For example, add `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"` before returning the response, and ensure the policy is applied globally via middleware if appropriate.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Source excerpt shows HTMLResponse returned without any header manipulation at line 299‑300.`
- `Runtime probe fact from web-runtime scanner (zap.10038) reports a POST request to /auth/form-login but does not include CSP header information.`

Limitations:
- The analysis is based on static code and a single runtime probe; the application might add CSP headers elsewhere (e.g., via middleware not shown in the excerpt).
- No full response headers were captured, so the absence of CSP cannot be definitively confirmed.

### 15. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /auth/form-login returns an HTMLResponse without setting the X-Frame-Options header or any equivalent anti-clickjacking directive. The source excerpt shows the response is constructed and returned, but no header is added. Runtime probe facts confirm the request is a POST to this path, but no header evidence is provided. This aligns with the scanner finding of a missing anti-clickjacking header.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and trick users into submitting credentials (clickjacking), potentially leading to credential theft or session hijacking.

**Remediation:** Add an appropriate X-Frame-Options header (e.g., "DENY" or "SAMEORIGIN") or Content‑Security‑Policy frame‑ancestors directive to the response before returning it. For example: `response.headers['X-Frame-Options'] = 'DENY'`.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Source excerpt shows HTMLResponse is created without setting X-Frame-Options header`
- `Runtime probe fact confirms POST request to /auth/form-login but no header data`

Limitations:
- No direct observation of response headers; conclusion is based on absence of header-setting code in the provided source. The runtime probe does not capture header values, so the header might be added by middleware not shown in the excerpt.

### 16. Cookie missing HttpOnly attribute

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The response sets a "lab_session" cookie without specifying the HttpOnly attribute, allowing client‑side scripts to access the cookie value. The source excerpt shows `response.set_cookie("lab_session", f"session-{row['id']}")` with no HttpOnly flag. This aligns with the scanner finding (zap.10010) indicating a missing HttpOnly flag on a session cookie.

**Impact:** An attacker who can inject JavaScript into the application (e.g., via XSS) could read the session cookie and hijack the user’s authenticated session.

**Remediation:** Set the HttpOnly attribute when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)` or configure the framework to apply HttpOnly by default for session cookies.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `source_symbol line 300 shows cookie set without HttpOnly`
- `scanner finding "Cookie No HttpOnly Flag"`

Limitations:
- Only one code path is shown; other middleware might add HttpOnly later, but no evidence is present
- No runtime observation confirming the cookie lacks HttpOnly attribute

### 17. Password reset token reuse may be allowed

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe for the POST /auth/reset/confirm endpoint returned HTTP 200 instead of the expected error codes (400, 409, 422) when the same reset token was reused. The source excerpt shows that the token is looked up but not invalidated after a successful password change, allowing the same token to be used again. This indicates the token is not single‑use as required.

**Impact:** An attacker who obtains a valid password‑reset token could reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity of user data.

**Remediation:** Invalidate or delete the reset token after a successful password reset. Ensure the token is marked as used in the database and reject any subsequent attempts with a 400/409/422 response. Add unit and integration tests to verify single‑use behavior.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Runtime probe returned status 200 for a reused reset token (expected 400/409/422)`
- `Source code does not delete or mark the token as used after password change`

Limitations:
- The probe only exercised one reuse scenario; additional testing is needed to confirm behavior across different token values and edge cases
- No evidence of rate‑limiting or additional guard checks around the reset endpoint

### 18. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the HTTP response for GET /catalog/query does not include a Content‑Security‑Policy header. The source code shows the endpoint returns an HTMLResponse but does not set any security headers. While the absence of CSP does not guarantee an exploit, it reduces protection against cross‑site scripting and data injection attacks.

**Impact:** Without a CSP header, browsers will not enforce a default policy restricting script sources, inline scripts, or other potentially unsafe resources, increasing the risk of XSS or data exfiltration if other vulnerabilities exist.

**Remediation:** Configure the FastAPI application (or the ASGI server) to include a CSP header on all responses, e.g., using a middleware that adds `Content‑Security‑Policy: default-src 'self';` or a more restrictive policy appropriate to the application’s needs.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Scanner runtime probe (zap.10038) observed a GET request to /catalog/query with no CSP header present.`

Limitations:
- The finding is based solely on header absence; no direct exploitation was observed. The test environment may differ from production where headers could be added by a reverse proxy.

### 19. X-Content-Type-Options Header Missing

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /catalog/query does not include the X-Content-Type-Options header, which can allow MIME type sniffing attacks. The source code shows the endpoint returns HTML content without explicitly setting security headers, and no evidence was found that the framework adds this header automatically.

**Impact:** An attacker could trick the browser into interpreting the response as a different MIME type, potentially leading to cross‑site scripting or content injection attacks.

**Remediation:** Configure the FastAPI application or the ASGI server to add the header, e.g., using a middleware that sets `X-Content-Type-Options: nosniff` for all responses.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Scanner runtime probe (zap.10021) on /catalog/query reported missing X-Content-Type-Options header`

Limitations:
- Evidence is based solely on a scanner observation; no runtime verification of header presence was performed. The code snippet does not show header handling, but the framework could add defaults not visible in the excerpt.

### 20. Missing Anti-clickjacking Header on /catalog/query

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for GET /catalog/query does not include an anti-clickjacking header (e.g., X-Frame-Options or Content-Security-Policy frame-ancestors). The source code shows the endpoint returns an HTMLResponse constructed from user‑controlled input, which could be embedded in a malicious frame if not protected. No evidence was found in the code that such a header is set globally or per‑response.

**Impact:** An attacker could embed the page in a hidden iframe and perform clickjacking attacks, potentially tricking users into unintended actions on the site.

**Remediation:** Add an appropriate anti‑clickjacking header, such as `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, to the response for this endpoint or configure the framework to apply it globally.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Source excerpt shows HTMLResponse returned without header manipulation (lines 148‑153).`
- `Scanner runtime probe indicates a GET request to /catalog/query with no header evidence.`

Limitations:
- The review relies on the absence of explicit header setting in the examined code; headers could be added by middleware not shown in the excerpt.
- No runtime verification of response headers was provided beyond the scanner’s observation.

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /comments returns HTML content without the X-Content-Type-Options: nosniff header. This header helps browsers prevent MIME type sniffing attacks, reducing the risk of content injection or cross‑site scripting exploitation. The scanner flagged the absence, and the source code shows a plain HTML response being returned, confirming the condition.

**Impact:** An attacker could potentially induce a browser to interpret non‑HTML content as HTML/JavaScript, facilitating XSS or drive‑by download attacks, especially if other injection vectors exist.

**Remediation:** Add the X-Content-Type-Options header with the value "nosniff" to the response for the /comments endpoint, e.g., using a middleware or setting the header directly in the FastAPI route.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Source excerpt shows the /comments route returning HTML without setting security headers.`
- `Scanner runtime probe reports a GET request to /comments with no X-Content-Type-Options header.`

Limitations:
- The finding is based on header absence; actual exploitability depends on other factors such as content injection points.
- No runtime probe confirms that the header is never set elsewhere (e.g., via global middleware).

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns HTML content without a Content‑Security‑Policy header. Absence of CSP allows an attacker to inject malicious scripts that can be executed in the victim’s browser, leading to XSS or data exfiltration. The scanner flagged this and the source code shows the endpoint directly renders comment bodies without sanitisation or CSP enforcement.

**Impact:** An attacker who can influence comment content could execute arbitrary JavaScript in users’ browsers, potentially stealing session cookies, performing actions on behalf of the user, or delivering further malware.

**Remediation:** Add a strict CSP header to the response, e.g., `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'"`. Consider sanitising comment bodies or using a templating engine that escapes HTML. Deploy middleware or framework features to set security headers globally.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Scanner finding: Content Security Policy (CSP) Header Not Set (zap.10038) for GET /comments`
- `Source excerpt shows HTML is returned directly without header handling (lines 173‑177)`

Limitations:
- The review is based on the absence of CSP in the observed response; it does not verify whether other security headers are present or if downstream proxies add CSP. No evidence of actual XSS payload injection was observed.

### 23. Missing Anti-clickjacking Header on /comments endpoint

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /comments endpoint returns HTML content without an X-Frame-Options or Content‑Security‑Policy frame‑ancestors directive. The source excerpt shows the route returns a raw HTML string and no security headers are added. The runtime probe confirms a GET request to /comments was made, but no header evidence is provided. This pattern matches the ZAP rule zap.10020 for missing anti‑clickjacking protection.

**Impact:** An attacker could embed the page in a malicious iframe and perform clickjacking attacks, potentially tricking users into submitting unintended actions or revealing sensitive information displayed on the comments page.

**Remediation:** Add an appropriate anti‑clickjacking header, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, to the response for the /comments endpoint. Ensure the header is set globally or within this route before returning the HTML.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Source excerpt shows the /comments route returns HTML without setting security headers (lines 173‑177).`
- `Runtime probe fact indicates a GET request to /comments was observed (scanner_id: web-runtime, rule_id: zap.10020).`

Limitations:
- The review only inspects this specific route; other middleware or server configuration might add the header globally, which is not visible in the provided excerpt.
- No direct evidence of the header’s absence is captured; the conclusion relies on the lack of header-setting code in the shown snippet.

### 24. Sensitive debug configuration exposed via unauthenticated endpoint

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /debug/config endpoint returns database URL, mock external URL, and application secret without any authentication check. Runtime probe observed a 200 OK response for an unauthenticated GET request, while the scanner expected 401/403/404. This indicates that sensitive configuration data is publicly accessible, which can be leveraged by an attacker to compromise the application and its data stores.

**Impact:** An attacker can obtain database connection strings and secret keys, enabling unauthorized database access, data exfiltration, and potential full system compromise.

**Remediation:** Restrict access to the /debug/config endpoint to authorized personnel only. Implement authentication and authorization checks (e.g., require admin role) before returning any configuration data. Alternatively, remove the endpoint from production deployments or guard it behind a debug mode flag that is disabled in production.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Source code shows /debug/config returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks (lines 320-322).`
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404.`

Limitations:
- The review is based on a single runtime probe and source excerpt; additional environment-specific protections (e.g., network firewalls) are not visible in the provided data.

### 25. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reported that the /healthz endpoint does not include a Content-Security-Policy header. The endpoint returns a simple JSON health check and is not intended to serve user‑generated content or execute scripts in a browser. No evidence was found that this endpoint is rendered in a browser context, nor that the lack of CSP poses a risk to the application. Consequently, the missing header is unlikely to constitute a security vulnerability in this context.

**Impact:** Minimal to none; the endpoint is used for internal health monitoring and does not expose attack surfaces that CSP mitigates.

**Remediation:** If the endpoint might ever be accessed via a browser, consider adding a CSP header with a restrictive policy (e.g., default-src 'none';). Otherwise, document that the endpoint is internal‑only and does not require CSP.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Scanner runtime probe reported status 200 for /healthz and missing Content-Security-Policy header`

Limitations:
- No runtime request showed the endpoint being rendered in a browser; the finding is based solely on header absence without context of exposure.

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the /healthz endpoint does not include the X-Content-Type-Options header. The source code shown defines the endpoint but does not demonstrate any response header manipulation. No additional runtime probe or configuration evidence confirms whether the header is omitted or added elsewhere (e.g., middleware, server configuration). Without concrete evidence of the header's absence in the actual response, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header is truly missing, browsers may perform MIME type sniffing, potentially leading to content injection attacks. However, the endpoint returns a simple JSON payload, limiting the practical risk.

**Remediation:** Ensure that the X-Content-Type-Options: nosniff header is set for all responses, either via FastAPI middleware, a response decorator, or server configuration (e.g., using Starlette's Middleware or configuring the reverse proxy).
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `X-Content-Type-Options Header Missing reported by scanner (zap.10021) for GET /healthz`

Limitations:
- No runtime response capture showing header presence or absence
- No evidence of global middleware that might add the header
- Only a single source excerpt; does not reflect full application configuration

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without an X-Frame-Options or Content‑Security‑Policy frame‑ancestors directive. The scanner detected the absence of clickjacking protection headers. No evidence in the provided source excerpt shows these headers being set, and the runtime probe confirms the endpoint is reachable. While the endpoint is low‑risk, the missing header could allow the response to be embedded in a malicious site, constituting a clickjacking risk.

**Impact:** An attacker could embed the /healthz page in a hidden iframe on a malicious site and potentially trick users into interacting with it, leading to confusion or further exploitation if the endpoint were expanded to perform state‑changing actions.

**Remediation:** Add an appropriate clickjacking protection header to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors 'self'`. Ensure the header is applied globally or at least for the /healthz route.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Missing clickjacking protection header reported by scanner`
- `Runtime probe fact: status 200 for /healthz`

Limitations:
- The finding is limited to the /healthz endpoint; other endpoints may already set the header
- No evidence that the endpoint is used in a context where clickjacking would be exploitable

### 28. Missing X-Content-Type-Options header on /healthz endpoint

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from the /healthz endpoint without the X-Content-Type-Options header. This header is recommended to prevent MIME type sniffing attacks. The source code shows a simple FastAPI endpoint that returns JSON, but no middleware or response headers are added to enforce this protection.

**Impact:** An attacker could exploit MIME type sniffing to execute content in an unexpected context, potentially leading to cross‑site scripting or other content injection attacks, especially if the endpoint is later extended to serve user‑controlled data.

**Remediation:** Add middleware or configure the FastAPI application to include the X-Content-Type-Options: nosniff header on all responses, e.g., using Starlette's `Response` headers or a security middleware package such as `secure` or `fastapi‑middleware‑security`.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe fact: status 200 returned from /healthz without X-Content-Type-Options header (web.missing-content-type-protection)`

Limitations:
- The finding is based solely on the observed response header; it does not assess whether downstream content could be exploited. The endpoint currently returns static JSON, so the practical risk may be limited until dynamic content is introduced. No evidence was found regarding other security headers or overall response hardening.

### 29. Incoming webhook events require a valid signature

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /integrations/hook accepts POST requests and processes the raw body without verifying a signature before inserting it into the database. Runtime probing observed a successful 200 response for an unsigned request, whereas the expected secure responses are 400, 401, or 403. This indicates the webhook is vulnerable to unauthenticated requests and potential injection attacks.

**Impact:** An attacker can send crafted webhook payloads to the endpoint, causing arbitrary data insertion, possible SQL injection, or other malicious actions, leading to data integrity loss or further system compromise.

**Remediation:** Implement signature verification for incoming webhook requests. Reject requests lacking a valid signature with appropriate HTTP status codes (e.g., 401 Unauthorized). Additionally, sanitize and validate the payload before database insertion, and use parameterized queries to prevent SQL injection.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Runtime probe fact: POST to /integrations/hook returned status 200 (expected 400/401/403) indicating unsigned request accepted.`
- `Source excerpt shows body is read and directly inserted into the database without validation or signature check.`

Limitations:
- The review is based on observed runtime behavior and source code excerpt; does not confirm exploitation of SQL injection but highlights lack of authentication. Further testing is needed to verify if payload can be leveraged for injection or other attacks.

### 30. Missing invoice ownership enforcement

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice. The runtime probe observed a successful 200 response for a request that should have been denied (expected 403 or 404), indicating that any authenticated user can read any invoice ID they know.

**Impact:** An attacker who can obtain or guess invoice IDs can retrieve sensitive invoice data belonging to other users, leading to confidentiality breaches and potential privacy violations.

**Remediation:** Add an ownership check after retrieving the invoice row, e.g., compare the invoice's `owner_id` with the authenticated principal's user ID and raise a 403 error if they do not match. Ensure the check is performed before returning the invoice data.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Source excerpt shows no ownership check after fetching the invoice row (lines 268-274).`
- `Runtime probe fact: status 200 returned for GET /invoices/{{invoice_id}} where expected statuses were 403 or 404 (assertion_results false).`

Limitations:
- The review assumes `principal` only validates authentication and does not perform ownership checks; if `principal` internally enforces ownership, the vulnerability may not exist. No direct evidence of the `principal` implementation is provided.

### 31. Potential unauthorized job creation endpoint

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The POST /jobs endpoint returns HTTP 200 for a request that the runtime probe expected to be rejected (400, 403, or 422). The code calls a principal() function to enforce authorization, but the implementation and effectiveness of this check are not visible in the provided excerpt. Without confirming that principal() correctly validates the Authorization header and enforces role restrictions, it cannot be determined whether unauthenticated or improperly authorized users can create jobs.

**Impact:** If the authorization check is ineffective, an attacker could create arbitrary jobs, potentially escalating privileges or executing unauthorized workloads.

**Remediation:** Review and harden the principal() implementation to ensure it validates the Authorization header, enforces proper role checks, and returns appropriate error codes (e.g., 403) for unauthorized requests. Add explicit input validation and return 4xx responses for malformed or unauthorized payloads.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `runtime_probe_facts shows POST /jobs returned status 200 when 400/403/422 were expected`

Limitations:
- No visibility into the principal() function logic
- No evidence of authentication token validation
- Only a single runtime probe observation; does not confirm consistent behavior across inputs

### 32. Sensitive SSN data exposed via /me endpoint

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The source excerpt shows that the /me endpoint queries the users table and includes the "ssn" column in the result set, which is then returned to the caller. This indicates that a caller with a valid token can retrieve Social Security Numbers. The runtime probe confirms the endpoint returns a 200 response, though the probe reports values_redacted, meaning the actual data was not captured but the presence of data was observed. The combination of static code evidence and runtime behavior suggests a potential data exposure vulnerability.

**Impact:** An attacker who obtains a valid authentication token could retrieve users' Social Security Numbers, leading to identity theft, fraud, and regulatory compliance violations (e.g., GDPR, HIPAA).

**Remediation:** Remove the SSN field from the response payload. If the SSN is needed internally, fetch it without returning it, or apply strict access controls and masking. Implement response filtering to exclude sensitive fields from public APIs.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Source code line 203 selects the "ssn" column and returns the row as a dict`
- `Runtime probe fact: GET /me returned 200 with values_redacted true, indicating data was present`

Limitations:
- The runtime probe redacted the actual SSN values, so the exact content was not observed
- No evidence was provided about authentication enforcement beyond the token check, so the ease of obtaining a valid token is unknown

### 33. Improper owner assignment allows order creation for other users

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint assigns the order's owner_id from the request body without verifying that the supplied owner_id matches the authenticated user's identifier. This permits an authenticated user to specify any owner_id and create orders on behalf of other users, violating access control expectations.

**Impact:** An attacker can create, modify, or inflate orders for other users, potentially leading to unauthorized purchases, financial fraud, or resource exhaustion.

**Remediation:** Enforce that owner_id is derived exclusively from the authenticated principal (e.g., always use user["sub"]), or add an explicit check that rejects requests where body.owner_id differs from the authenticated user's ID, returning 403/400.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Source excerpt shows owner_id = body.owner_id or user["sub"] without further validation (lines 208-210).`
- `Runtime probe observed a successful POST to /orders returning HTTP 200, while the probe expected failure statuses (400, 403, 422).`

Limitations:
- The analysis assumes the principal function correctly authenticates the user; if principal returns elevated privileges or is misimplemented, the impact may differ. No additional context about downstream authorization checks was provided.

### 34. Order creation endpoint allows invalid initial status

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe exercised the POST /orders endpoint with a request that should have been rejected (expected status 400 or 422) but received a 200 OK response. The source code shows the endpoint directly inserts the supplied status value into the database without validation, allowing an order to be created with an arbitrary initial status such as "paid". This indicates a logic flaw that can be exploited to create orders in an unintended state.

**Impact:** An attacker could create orders that are immediately marked as paid, bypassing payment processing, leading to financial loss, inventory inconsistencies, and potential fraud.

**Remediation:** Validate the 'status' field in the request body against an allow‑list of permissible initial states (e.g., "pending"). Reject or coerce any disallowed values with a 400/422 response. Add unit tests to verify that invalid statuses are rejected. Consider database constraints to enforce allowed status values.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `Runtime probe fact: POST /orders returned status 200 when expected 400/422 (assertion_results: false)`
- `Source excerpt shows status value is inserted directly into orders table without validation (lines 213‑215)`

Limitations:
- The probe only exercised a single request scenario; other valid inputs may still be handled correctly.
- No evidence is provided about downstream payment verification logic, so the full impact on financial flow is inferred rather than observed.

### 35. Negative order prices accepted instead of being rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** A runtime probe sent a POST request to /orders with a negative unit_price. The application responded with HTTP 200 and created the order, whereas the scanner expected a 400/422 response. The source code shows the endpoint directly inserts the provided unit_price into the database without validation, confirming the observed behavior.

**Impact:** An attacker can create orders with negative prices, potentially leading to unauthorized credit, inventory manipulation, or financial loss for the business.

**Remediation:** Add input validation to reject negative unit_price values (e.g., raise HTTPException with status 400). Consider using Pydantic validators or explicit checks before database insertion.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`
- `Source excerpt shows create_order inserts body.unit_price without validation`

Limitations:
- Evidence is limited to a single runtime probe; additional testing (e.g., with different payloads) would strengthen confidence
- The scanner did not provide full request details, so exact payload is inferred

### 36. Server trusts client‑provided unit_price allowing price tampering

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The create_order endpoint inserts the value of body.unit_price directly into the orders table without any server‑side validation or lookup against the product catalog. An attacker can supply an arbitrary unit_price in the request body, causing the order to be recorded with a manipulated price.

**Impact:** Allows malicious users to purchase items at reduced prices or inflate prices for fraudulent purposes, leading to revenue loss and potential accounting inconsistencies.

**Remediation:** Remove the unit_price field from the client‑supplied OrderBody. Retrieve the correct price from the product catalog on the server side based on the item identifier and use that value when inserting the order. Optionally, validate that the supplied price matches the catalog price and reject mismatches.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Source excerpt shows body.unit_price being passed directly to the SQL INSERT (lines 213‑215).`
- `Runtime probe fact indicates a POST to /orders returned status 200, confirming the endpoint is reachable and processes the request.`

Limitations:
- The review is based solely on the provided code snippet and runtime probe; it does not assess additional business logic that might later adjust the price. No database constraints or triggers were examined.

### 37. Improper access control for nested note resource

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID without verifying that the note's `order_id` matches the `order_id` supplied in the URL. The source excerpt shows the query selects the note solely by `note_id` and returns it if found, ignoring the parent order context. Runtime probing confirms that a request to `/orders/1/notes/2` returns HTTP 200, whereas the security rule expects a 403 or 404 when the note does not belong to the specified order, indicating the access control check is missing.

**Impact:** An attacker can enumerate or access notes belonging to other orders by guessing note IDs, leading to unauthorized disclosure of potentially sensitive information and violation of data isolation guarantees.

**Remediation:** Modify the query to include the `order_id` in the WHERE clause (e.g., `SELECT id,order_id,body FROM notes WHERE id=%s AND order_id=%s`) and ensure that a 404 is returned when no matching record exists. Additionally, enforce authorization checks after retrieving the note to confirm the requester has permission to view notes for the specified order.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Source excerpt shows query `SELECT id,order_id,body FROM notes WHERE id=%s` without order_id filter (lines 543-547).`
- `Runtime probe fact: GET `/orders/1/notes/2` returned status 200, while expected statuses were 403 or 404 (rule workflow.nested_note.1).`

Limitations:
- The review is based on a single code path and one runtime probe; other code paths or middleware could enforce the check elsewhere, which was not observed in the provided excerpt. No information about additional authorization layers or database constraints was available.

### 38. Improper access control on order retrieval endpoint

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint calls `principal(authorization)` but does not enforce that the authenticated user is the owner of the requested order before returning the record. Runtime probing observed a successful 200 response for a request that should have been denied (expected 403 or 404), indicating that the ownership check is ineffective.

**Impact:** An attacker who can guess or enumerate order IDs can retrieve any user's order details, exposing sensitive personal and transaction information.

**Remediation:** Implement a proper ownership check after fetching the order, e.g., compare the order's `user_id` with the authenticated principal and return 403 if they do not match. Ensure the check runs before any data is returned.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Source excerpt shows `principal(authorization)` is called but no subsequent owner verification before returning the row.`
- `Runtime probe fact: method GET to /orders/{{order_id}} returned status 200 where the rule expected 403 or 404 (assertion_results: false).`

Limitations:
- The review is based on a single runtime probe and source excerpt; it does not confirm whether additional middleware or downstream checks might exist elsewhere in the codebase. No evidence was found regarding how `principal` validates the user or whether other layers enforce ownership.

### 39. Excessive coupon discounts are accepted

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe exercised the /orders/{order_id}/apply-coupon endpoint with a POST request that supplied a discount value exceeding the allowed coupon percent. The probe expected a 400 or 422 response but received a 200 status, indicating the application accepted the excessive discount and updated the order. The source excerpt shows the discount is taken directly from the request body (body.discount) without validation against the coupon's maximum percent, and the database update is performed unconditionally.

**Impact:** An attacker can apply arbitrarily large discounts to orders, potentially resulting in financial loss, unauthorized free purchases, or depletion of inventory value.

**Remediation:** Validate the discount value against the coupon's allowed percent before applying it. Reject requests where body.discount exceeds the coupon's percent or is otherwise out of bounds, returning a 400/422 error. Ensure the discount is derived solely from the stored coupon data when present.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Runtime probe fact: method POST to /orders/{{order_id}}/apply-coupon returned status 200 instead of expected 400/422 (assertion_results false).`
- `Source code lines 231‑236 show discount taken from body.discount without bounds checking and directly written to the orders table.`

Limitations:
- The probe only exercised a single input scenario; other validation paths may exist but were not observed.
- The evidence is limited to the provided code snippet and runtime probe; additional business‑logic checks elsewhere in the application could mitigate the issue but are not visible.

### 40. Paid orders can be cancelled without refund

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed that a POST to /orders/{order_id}/cancel returned HTTP 200, whereas the expected behavior for a paid order is to reject the cancellation with a client error (e.g., 400, 409, 422). The endpoint updates the order status to 'cancelled' without any check for payment status or refund processing, indicating that paid orders may be cancelled without first issuing a refund.

**Impact:** Allows customers to cancel paid orders without receiving a refund, potentially leading to financial loss and abuse of the ordering system.

**Remediation:** Add logic to verify the payment status of the order before allowing cancellation and enforce that a refund is processed prior to changing the order status. Return appropriate error codes when cancellation is not permitted.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Runtime probe fact: method POST to /orders/{{order_id}}/cancel returned status 200 (expected statuses: 400, 409, 422)`

Limitations:
- Evidence is based on a single runtime probe; does not confirm behavior across all order states or authentication contexts. The source code excerpt does not show any payment status checks, but the absence of such checks in this snippet is not definitive proof of the overall application logic.

### 41. Payment replay allows second payment on already paid order

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint /orders/{order_id}/pay processes a payment without checking the current order status. The runtime probe observed a successful POST (HTTP 200) on a second payment attempt, while the scanner expects a client error (400, 409, or 422). This indicates that the application does not prevent payment replay, allowing a paid order to be paid again.

**Impact:** An attacker (or a malicious user) can submit multiple payment requests for the same order, resulting in duplicate charges, financial loss, and potential accounting inconsistencies.

**Remediation:** Add a check before processing the payment to verify that the order status is not already 'paid'. Return an appropriate error (e.g., 409 Conflict) if a payment has already been recorded. Ensure the status check and update are performed atomically within a transaction to avoid race conditions.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Runtime probe fact: POST to /orders/{{order_id}}/pay returned HTTP 200 on a second payment attempt (expected 400/409/422).`
- `Source code shows no status check before updating order status to 'paid' (lines 245‑249).`

Limitations:
- Evidence is limited to a single runtime probe observation; additional testing may be needed to confirm consistency across different orders and concurrency scenarios. The scanner’s expected statuses are based on typical patterns but not a formal specification for this application.

### 42. Unauthorized profile access

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/profiles/{profile_id}` returns a user record without verifying that the authenticated principal owns the requested profile. Runtime probing observed a 200 OK response when accessing a profile belonging to another user, whereas the expected responses were 403 Forbidden or 404 Not Found. The source code shows a call to `principal(authorization)` but no subsequent check that `profile_id` matches the authenticated user's ID before querying the database.

**Impact:** An attacker who can obtain a valid authentication token can enumerate and read other users' personal data, including usernames, emails, and SSNs, leading to privacy violations and potential identity theft.

**Remediation:** Add an authorization check after retrieving the authenticated user's identifier and compare it to `profile_id`. Return 403 Forbidden if they do not match. Example:
```python
user_id = get_user_id_from_token(authorization)
if profile_id != user_id:
    raise HTTPException(403, "Forbidden")
```
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `Runtime probe returned status 200 for `/profiles/{{other_id}}` (expected 403/404)`
- `Source excerpt shows no ownership check before DB query`

Limitations:
- The review is based on a single runtime probe; additional testing across different roles and inputs would strengthen confidence. The exact behavior of `principal(authorization)` is unknown and may perform checks not visible in the excerpt.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTML page without any anti-clickjacking headers such as `X-Frame-Options` or a CSP `frame-ancestors` directive. The source code shows a direct `HTMLResponse` construction and the runtime probe confirms a GET request to this path, but no header evidence is present.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP header with `frame-ancestors 'self'`. This can be done globally via middleware or per‑route response headers.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Source excerpt defines `view_home` returning raw HTML without header manipulation`
- `Runtime probe fact shows a GET request to `/view` with no header data indicating the presence of anti‑clickjacking protection`

Limitations:
- The review is based on static code and a single runtime probe; the application might add security headers elsewhere (e.g., middleware) that were not captured in the provided excerpt

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from GET /view does not include the X-Content-Type-Options header. The source code shows the endpoint returns a static HTMLResponse without explicitly setting security headers. However, the deployment context is unknown and the application may add default security headers via middleware or a reverse proxy, which is not visible in the provided code. Without evidence of the actual runtime response headers, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header is truly absent, browsers could perform MIME type sniffing, potentially leading to content injection attacks. The risk is low given the endpoint serves static HTML.

**Remediation:** Ensure that the application or its hosting environment adds the X-Content-Type-Options: nosniff header to all responses, e.g., via FastAPI middleware or web server configuration.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner runtime probe for GET /view reported missing X-Content-Type-Options header`

Limitations:
- No runtime response header capture beyond the scanner report
- Deployment context is null, so middleware or proxy‑added headers cannot be verified
- Only a single source excerpt; other routes or global settings may add the header

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/view` returns an HTMLResponse constructed directly from a string without adding any security-related HTTP headers. No evidence was found that a Content‑Security‑Policy header is set for this response, either in the source code or in the runtime probe facts. Absence of CSP allows browsers to load resources (scripts, styles, iframes) from any origin, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Impact:** An attacker who can inject malicious content into the page (e.g., via reflected or stored XSS elsewhere in the application) could execute arbitrary JavaScript in the victim's browser, potentially stealing session cookies, performing actions on behalf of the user, or exfiltrating data.

**Remediation:** Configure the FastAPI application to include a CSP header on all HTML responses. This can be done by adding a middleware that sets `Content‑Security‑Policy` with a restrictive policy (e.g., `default-src 'self'; script-src 'self'; style-src 'self'`) or by using a library such as `starlette‑csp`. Ensure the policy is tested to avoid breaking legitimate functionality.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact shows a GET request to /view but no header data indicating CSP`

Limitations:
- No runtime capture of response headers was provided, so the absence of CSP is inferred from static code only
- The scanner finding does not confirm that the header is never added elsewhere (e.g., via a global middleware not shown in the excerpt)

### 46. Webhook destination validation correctly restricts to approved mock host

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint /webhooks validates the provided target_url and raises an HTTP 400 error unless the URL contains the string "mock-external", which is the approved mock destination. This logic enforces the required restriction, contradicting the scanner's claim of a vulnerability.

**Impact:** No impact; the application already prevents unauthorized webhook destinations.

**Remediation:** No remediation needed; the existing validation satisfies the security requirement.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `source_excerpt lines 294-298 show the check for "mock-external" in target_url and the raising of HTTPException(400) when the condition is not met.`

Limitations:
- The review assumes that "mock-external" represents the approved internal host as defined by the application's security policy. If the policy differs, the conclusion may change.

### 47. Clear-text logging of application secret

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the environment variable APP_SECRET in clear text using the standard logger. This exposes a credential that should remain confidential, and the log output may be stored or transmitted without protection, creating a credential leakage risk.

**Impact:** An attacker with access to log files can retrieve the application secret, potentially allowing them to forge tokens, access protected resources, or compromise other services that rely on the secret.

**Remediation:** Remove the secret from log statements. If debugging information is needed, use a masked version or omit the secret entirely. Ensure logging configuration does not write sensitive data to insecure destinations.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) at api/app.py:137`
- `Scanner semgrep-ce rule python.lang.security.audit.logging.logger-credential-leak flagged line 137`

Limitations:
- Evidence is limited to static code analysis; runtime behavior (e.g., whether logging level includes INFO) is not verified. No runtime probe confirms that the log entry is actually emitted in production.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any website to make cross‑origin requests to the API. This configuration can expose the service to CSRF‑style attacks or data leakage when credentials are allowed, especially since allow_credentials is True. While the scanner flagged this, the code confirms the permissive setting.

**Impact:** An attacker-controlled website could interact with the API on behalf of a logged‑in user, potentially performing unauthorized actions or exfiltrating data returned by the API.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. If credentials must be allowed, ensure only specific origins are permitted and consider removing allow_credentials if not required.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py: line 26 sets allow_origins=["*"] with allow_credentials=True, allow_methods=["*"], allow_headers=["*"]`

Limitations:
- The finding assumes the API is publicly accessible; if the service is intended for internal use only, the risk may be lower. No runtime probe data is available to confirm actual exploitation.

### 49. Potential Log Injection / Sensitive Data Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs a user‑provided username together with the application secret (APP_SECRET). Logging user input can lead to log injection if the log processing system interprets special characters, and logging the secret directly exposes sensitive configuration data. While the log statement itself does not appear to be parsed by downstream components, the presence of uncontrolled input and secret data in logs constitutes a security concern.

**Impact:** An attacker who can trigger a login attempt can cause the secret value to be written to application logs, potentially exposing it to anyone with log access. If log aggregation or monitoring tools parse log entries, crafted usernames could manipulate log format or inject malicious content.

**Remediation:** Avoid logging sensitive values such as APP_SECRET. Sanitize or omit user‑controlled data from log messages, and ensure that logs are not parsed by downstream systems in a way that could be abused. Use structured logging with proper escaping and consider redacting secrets before logging.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- The finding does not demonstrate that logs are parsed or that an attacker can read them; the risk depends on log storage and access controls. No evidence is provided that the logged secret is subsequently exposed to unauthorized parties.

### 50. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list checking. An attacker can supply an arbitrary URL, causing the application to redirect users to a malicious site after authentication.

**Impact:** Facilitates phishing attacks, credential harvesting, and can be used to bypass security controls that rely on trusted redirects, potentially leading to user compromise and loss of trust.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a safe scheme (e.g., https).
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source excerpt shows `def continue_to(next: str = "/") -> RedirectResponse: return RedirectResponse(next, status_code=302)` which uses the raw `next` value for redirection.`

Limitations:
- The review is based solely on the provided code snippet; additional context (e.g., upstream validation, framework-level safeguards) is not available. No runtime probe data was provided to confirm actual redirect behavior.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the provided URL by ensuring it starts with a single '/' and rejects any value that starts with '//' or contains a scheme or network location. This prevents redirection to external domains, mitigating an open‑redirect vulnerability. The scanner’s generic pattern flagged the use of RedirectResponse, but the explicit checks make the finding inaccurate.

**Impact:** If the validation were bypassed, an attacker could redirect users to malicious sites, leading to phishing or drive‑by attacks. However, the code’s safeguards block such misuse, so no impact is present.

**Remediation:** No remediation required; the existing validation is sufficient. Maintain the checks and consider adding unit tests to verify that external URLs are rejected.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `source_excerpt lines 621‑624 enforce local‑path only redirects`
- `source_symbol shows the same validation logic`

Limitations:
- The review assumes the function is always used for redirects and that no other code bypasses these checks. If future changes alter the validation, the assessment would need revisiting.

### 52. Missing HEALTHCHECK instruction

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The Dockerfile lacks a HEALTHCHECK directive. While adding a health check is a recommended best practice for container orchestration, its absence does not constitute a security vulnerability in itself. No evidence is provided that this misconfiguration leads to an exploitable condition or impacts the confidentiality, integrity, or availability of the application.

**Impact:** None – the application will continue to run, but orchestration tools may not be able to automatically detect unhealthy containers.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD curl -f http://localhost:8091/health || exit 1
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- Assessment based solely on the Dockerfile content; does not consider external orchestration policies that might enforce health checks.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a recommended best practice for container reliability, its absence does not directly constitute a security vulnerability. No evidence is provided that the missing health check can be exploited to compromise the container or host.

**Impact:** None confirmed; the container will continue to run without health monitoring, which may affect operational visibility but does not create a security breach.

**Remediation:** Add a suitable HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- The assessment is based solely on the Dockerfile content; no runtime behavior or exploit scenario is demonstrated.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile excerpt does not contain a HEALTHCHECK instruction. While adding a health check is a best practice, its absence does not constitute a security vulnerability, only a potential operational improvement. The scanner flag is therefore treated as a false positive in the context of security impact.

**Impact:** No direct security impact; containers may not be automatically monitored for liveness, which could affect availability monitoring but not confidentiality or integrity.

**Remediation:** Consider adding a HEALTHCHECK instruction to the Dockerfile to enable Docker to monitor container health, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Source excerpt shows Dockerfile lines 1-7 with no HEALTHCHECK instruction.`

Limitations:
- The absence of a HEALTHCHECK is a configuration recommendation, not a proven security flaw. The impact depends on the specific application’s need for health monitoring.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-53539, a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded request bodies. The scanner evidence directly cites this CVE and notes that the issue is fixed starting with version 0.0.30. No contradictory evidence was found in the runtime probes or deployment context.

**Impact:** An attacker can send a maliciously crafted request that causes the application to consume excessive CPU or memory, leading to service degradation or complete outage. Because the vulnerable library is used by FastAPI for handling multipart/form‑data, any endpoint that processes uploads or form submissions is potentially affected.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and rebuild/redeploy the application. Verify that the new version does not introduce breaking changes in multipart handling.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review relies solely on the declared dependency version; it assumes the application actually uses the library at runtime. No runtime probe confirming the vulnerable code path was observed.

### 56. Denial of Service via excessive multipart part headers in python-multipart 0.0.20

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by crafted multipart requests with an excessive number of part headers. The scanner evidence directly cites this CVE and notes that the issue is fixed in version 0.0.27. No mitigating controls or runtime checks were observed in the provided data.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially crashing the FastAPI service or rendering it unresponsive, leading to service disruption.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later. Update the requirements.txt entry and rebuild/redeploy the application. Verify that the new version is installed by checking the lock file or runtime environment.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- No runtime probe data was provided to confirm whether the vulnerable code path is exercised in the deployed application.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20, which is known to contain CVE-2026-53538. The CVE describes an information disclosure vulnerability caused by differences in how multipart form data is parsed. The scanner evidence directly references this CVE and notes that the issue is fixed in version 0.0.30. No contradictory evidence was provided in the runtime probes or other sources.

**Impact:** An attacker could craft multipart requests that cause the application to leak sensitive data from processed form fields, potentially exposing user credentials or other confidential information.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, and update the requirements.txt accordingly. Rebuild and redeploy the application to ensure the patched library is used.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The finding relies on the presence of the vulnerable version in requirements.txt; actual runtime version was not independently verified via probes. No evidence was provided that the vulnerable code path is exercised in the application.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project's requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-40347. This CVE allows an attacker to trigger a denial‑of‑service condition by sending specially crafted multipart/form-data payloads that cause excessive memory or CPU consumption. The scanner identified this vulnerability and the evidence confirms the vulnerable version is present in the dependency list.

**Impact:** An attacker who can upload or submit multipart/form-data requests to the application could cause the service to become unresponsive, leading to downtime and potential loss of availability for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, which contains the fix for CVE-2026-40347. Update the requirements.txt entry accordingly and rebuild/redeploy the application to ensure the patched version is used.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- The review assumes the listed dependencies are installed as declared; if the runtime uses a different lockfile or overrides the version, the vulnerability may not be present. No runtime probe confirms the vulnerable code is actually executed.

### 59. Arbitrary file write via path traversal in python-multipart 0.0.20

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in requirements.txt. This version is known to contain CVE-2026-24486, a path‑traversal flaw that allows an attacker to write arbitrary files on the server when processing multipart/form‑data. The scanner identified this CVE and noted that it is fixed in version 0.0.22. No evidence was found that the application upgrades or patches this dependency at runtime.

**Impact:** An attacker who can upload crafted multipart requests could traverse directories and write files to arbitrary locations, potentially leading to remote code execution, credential theft, or service disruption.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later. Verify the lockfile or deployment pipeline reflects the updated version and rebuild/redeploy the application. Optionally add runtime checks to validate multipart filenames and enforce a safe upload directory.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

Limitations:
- Evidence is limited to the static requirements file; runtime environment may have a different version if overridden during build or deployment. No runtime probe confirms the vulnerable code is executed.

### 60. python-multipart 0.0.20 contains CVE-2026-53537

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20. This version is known to be vulnerable to CVE-2026-53537, an information‑disclosure issue caused by inconsistent header parsing. The scanner evidence directly references the CVE and notes that the vulnerability is fixed in version 0.0.30. No contradictory evidence was provided, and the runtime probe did not observe any mitigating controls.

**Impact:** An attacker could craft multipart requests that cause the server to leak request headers or other sensitive data, potentially exposing authentication tokens or internal configuration values.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- No runtime probe data confirming exploitation; the assessment relies on the known CVE and the pinned vulnerable version.

### 61. python-multipart: Negative Content-Length buffers entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner identified a known vulnerability (CVE-2026-53540) in python-multipart version 0.0.20, which can cause the entire request body to be buffered in memory when a negative Content-Length is encountered. The project pins python-multipart at the vulnerable version in requirements.txt, providing direct evidence of exposure.

**Impact:** An attacker can trigger excessive memory consumption on the server, potentially leading to denial-of-service conditions.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, where the issue is fixed. Update the requirements.txt and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`

Limitations:
- No runtime probe confirming the vulnerability is exercised in the deployed application. The finding relies on static dependency analysis alone.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a urllib request that concatenates a base URL with a path variable. While urllib can handle file:// schemes, the code does not show that the path is user‑controlled or that untrusted input reaches the request. Without evidence that an attacker can influence the URL, the finding remains unsubstantiated.

**Impact:** If an attacker could control the path, they might craft a URL to read local files via a file:// scheme or trigger SSRF, potentially exposing sensitive data.

**Remediation:** Validate and sanitize any user‑provided path components before concatenating them with BASE. Prefer using higher‑level HTTP libraries (e.g., requests) that do not support file:// URLs, or explicitly reject such schemes.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen used with BASE + path; no indication of input source.`

Limitations:
- No runtime probe data confirming attacker‑controlled input.
- No evidence that the path can contain file:// or other dangerous schemes.
- Scanner finding is based solely on pattern matching without contextual analysis.

### 63. Potential SSRF via dynamic urllib request

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload["target_url"]). If an attacker can control this field, they may cause the service to make arbitrary HTTP requests, potentially accessing internal services or reading files via file:// URLs. The scanner flagged this as a dynamic urllib use, which is a known pattern for SSRF vulnerabilities. While no concrete exploit is demonstrated, the data flow from untrusted input to network request warrants attention.

**Impact:** An attacker could exploit this to perform Server-Side Request Forgery (SSRF), accessing internal network resources, metadata services, or reading local files via file:// schemes, leading to data leakage or further compromise.

**Remediation:** Validate and sanitize the "target_url" field before using it in urllib calls. Restrict allowed schemes to http/https, enforce a whitelist of permitted domains, and consider using a higher-level HTTP library (e.g., requests) with built‑in safety checks. Additionally, implement network‑level egress controls to limit outbound requests.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows payload["target_url"] passed directly to urllib.request.Request without validation (lines 18‑23).`

Limitations:
- No runtime probe confirms that an attacker can supply a malicious URL; the finding is based on static analysis of data flow. No evidence of actual exploitation in the repository.

### 64. Potential missing authorization check on admin audit endpoint

- Issue group: `ai-1550abf709023a18`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The endpoint /admin/audit calls a function require_admin to enforce admin privileges, but the implementation of require_admin is not present in the provided repository snapshot. Without seeing how require_admin validates the authorization header, it cannot be determined whether non‑admin users can access the endpoint. The code snippet shows the call, but no evidence of proper role verification, token parsing, or error handling is available.

**Impact:** If require_admin does not correctly verify admin rights, an attacker could retrieve the audit status response and potentially discover or infer sensitive administrative information, leading to privilege escalation or information disclosure.

**Remediation:** Locate the definition of require_admin and verify that it: • Parses the Authorization header (e.g., JWT, Bearer token) • Validates the token signature and expiration • Checks that the token contains an admin role claim or performs a database lookup for admin status • Returns an appropriate HTTP 403 response for unauthorized callers. If the function is missing or incomplete, implement proper authorization checks or replace the call with a framework‑provided dependency that enforces role‑based access control.
Evidence:
- Source IDs: `ai-1550abf709023a18`
- `204: @router.get("/admin/audit")`
- `205: def admin_audit(authorization: str | None = Header(default=None)) -> dict:`
- `206:     require_admin(authorization)`
- `207:     return {"status": "authorized"}`

Limitations:
- The source excerpt does not include the implementation of require_admin, so its behavior is unknown.
- No runtime observations (e.g., probe results) are provided to confirm whether the endpoint rejects unauthorized requests.
- No tests or logs are available to demonstrate enforcement or lack thereof.

### 65. Unauthenticated file read endpoint may expose sensitive data

- Issue group: `ai-4335c2f227b20f8c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /files endpoint returns the contents of any file located under the configured public directory without requiring authentication or authorization. Although a path‑traversal check prevents escaping the public folder, any client can request arbitrary files within that folder, which could contain sensitive information if such files are placed there inadvertently.

**Impact:** Potential disclosure of confidential files (e.g., configuration, secrets, internal documents) to unauthenticated users, leading to information leakage and possible further attacks.

**Remediation:** Restrict access to the endpoint by adding authentication/authorization checks, or limit the served files to a whitelist of safe resources. Consider moving sensitive files out of the public directory and applying rate‑limiting to mitigate abuse.
Evidence:
- Source IDs: `ai-4335c2f227b20f8c`
- `210: @router.get("/files")`
- `211: def file_read(name: str) -> Response:`
- `212:     file = (FILES / "public" / name).resolve()`
- `213:     if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214:         raise HTTPException(404, "File not found")`
- `215:     return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The intended design of the public directory is not known; it may be meant to be fully exposed. No explicit policy or comment indicates whether authentication was deliberately omitted. No runtime evidence confirms that sensitive files are present in the public folder.

### 66. Potential missing authentication on verified file read endpoint

- Issue group: `ai-b0b82e8cd9d25449`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `/files/verified` route returns the contents of files under the public directory without any authentication or authorization checks. The code snippet shows the endpoint definition and the response construction, and there is no visible middleware or guard that would restrict access based on user identity or permissions. While the route name suggests a "verified" status, the implementation does not enforce any such verification, allowing any caller to retrieve arbitrary files that pass the path‑traversal check.

**Impact:** An attacker could enumerate and read any file placed in the public directory, potentially exposing sensitive data or configuration files that were intended to be accessible only to authorized users.

**Remediation:** Add authentication and authorization checks before serving the file. For example, require a valid JWT or session token and verify the caller has the appropriate role or permission to access the requested file. Consider moving public files to a truly public static directory and separating them from files that require protection.
Evidence:
- Source IDs: `ai-b0b82e8cd9d25449`
- `218: @router.get("/files/verified")`
- `219: def verified_file_read(name: str) -> Response:`
- `220:     root = (FILES / "public").resolve()`
- `221:     file = (root / name).resolve()`
- `222:     if not file.is_relative_to(root) or not file.is_file():`
- `224:     return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The review is based solely on the provided source excerpt; there may be application‑wide middleware or dependency‑injected guards not visible in this file that enforce authentication.
- No runtime or deployment context was supplied to confirm whether the endpoint is exposed in production or behind additional access controls.

### 67. Potential privilege escalation via owner_id override in order creation

- Issue group: `ai-7ef28a27beffa9f8`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The create_order endpoint assigns the order's owner_id from the request body if provided, otherwise falling back to the authenticated user's sub claim. No validation is performed to ensure the supplied owner_id matches the authenticated principal or that the caller has permission to act on behalf of another user. This allows an authenticated attacker to create orders on behalf of any user by specifying an arbitrary owner_id in the request payload.

**Impact:** An attacker could create, modify, or trigger downstream processes for orders owned by other users, potentially leading to unauthorized resource consumption, billing fraud, or escalation of privileges if order processing grants further rights based on ownership.

**Remediation:** Validate that the owner_id in the request either matches the authenticated user's identifier or that the caller possesses an explicit permission/role to create orders for other users. If the API should never allow client-supplied owner_id, remove the field from the request schema and always use the principal's sub claim. Add explicit authorization checks before inserting the record.
Evidence:
- Source IDs: `ai-7ef28a27beffa9f8`
- `source_excerpt lines 208-212 show owner_id = body.owner_id or user["sub"] without further checks`
- `sensitive_operation excerpt confirms the owner_id value is directly used in the INSERT statement`

Limitations:
- The actual definition of OrderBody is not provided, so it is unclear if owner_id is optional or constrained
- We lack runtime observations confirming that mismatched owner_id values are accepted by the database (e.g., foreign key constraints)
- No evidence is presented about additional downstream authorization checks after insertion

### 68. Missing authorization enforcement on webhook creation endpoint

- Issue group: `ai-01752b2720398cda`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **low**

**Explanation:** The create_webhook handler calls principal(authorization) but does not use its return value or raise on failure, and no explicit role/permission check is performed before inserting a webhook job into the database. This suggests that any authenticated user (or possibly unauthenticated if principal tolerates None) could create arbitrary webhook jobs, potentially leading to privilege escalation via the run_as field.

**Impact:** An attacker could create webhook jobs that execute payloads with arbitrary run_as values, allowing actions to be performed as other users or system accounts, which may lead to data exfiltration, service disruption, or further compromise.

**Remediation:** Modify the endpoint to validate the result of principal(authorization) and enforce a specific permission or role before proceeding. Example: 
```python
user = principal(authorization)
if not user.has_permission('create_webhook'):
    raise HTTPException(status_code=403, detail='Forbidden')
``` Additionally, validate and restrict the run_as parameter to allowed values.
Evidence:
- Source IDs: `ai-01752b2720398cda`
- `api/app.py:293-295 – endpoint definition and call to principal without using its result`
- `api/app.py:300-304 – insertion of webhook job without prior permission check`

Limitations:
- The actual implementation of principal() is not visible; it may raise on insufficient privileges or perform checks internally. Without runtime observation of its behavior, the missing check cannot be confirmed definitively.

### 69. Potential insecure coupon discount manipulation

- Issue group: `ai-1e343df69b02c985`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The apply_coupon endpoint allows a client‑supplied discount value (body.discount) to override the coupon's stored percent without any apparent authorization or validation checks. While this could enable unauthorized discount escalation, the code does call principal(authorization), and it is unclear whether that function enforces that the caller owns the coupon or is permitted to set custom discounts. No explicit check of body.discount against the coupon's percent or user permissions is visible in the provided excerpt.

**Impact:** If an attacker can supply an arbitrary discount value, they may obtain excessive discounts on orders, leading to financial loss or abuse of promotional mechanisms.

**Remediation:** Add validation to ensure that body.discount is either omitted or matches the coupon's percent, and enforce that the authenticated principal is authorized to apply the coupon (e.g., owns the coupon or has a role permitting discount overrides). Reject or sanitize any out‑of‑range discount values before updating the order.
Evidence:
- Source IDs: `ai-1e343df69b02c985`
- `percent = body.discount if body.discount is not None else (coupon["percent"] if coupon else 0)`
- `row = conn.execute("UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (percent, order_id)).fetchone()`
- `principal(authorization) is called but no further checks on discount or coupon ownership are shown`

Limitations:
- The analysis is based solely on the static code excerpt; runtime behavior of principal() and any downstream validation is unknown.
- No information on database constraints (e.g., max discount) or additional middleware that might enforce limits.
- Without seeing the full request handling or authorization policies, we cannot confirm whether the discount can be arbitrarily set.

### 70. Missing ownership check on order cancellation endpoint

- Issue group: `ai-de70ebb6230142e0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the order or has a role that permits cancellation. The SQL update is executed unconditionally for the supplied `order_id`, allowing any authenticated user to cancel any order.

**Impact:** An attacker who can obtain a valid authorization token can cancel arbitrary orders, leading to denial of service for legitimate customers, potential financial loss, and loss of audit integrity.

**Remediation:** Add an authorization check after `principal(authorization)` that verifies the caller's user ID matches the order's owner or that the caller has an admin/manager role before executing the UPDATE. Example: retrieve the order's owner ID from the database and compare it to `principal`'s user ID, returning 403 if they do not match. Consider using parameterized queries and database row‑level security as additional safeguards.
Evidence:
- Source IDs: `ai-de70ebb6230142e0`
- `@app.post("/orders/{order_id}/cancel") (line 258)`
- `principal(authorization) (line 260)`
- `row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone() (line 262)`

Limitations:
- The exact return value and semantics of `principal` are unknown; it may include role or ownership information that is not shown in the excerpt.
- No database constraints or triggers are visible that could prevent unauthorized updates.
- The code snippet does not show any surrounding middleware or decorators that might enforce additional checks.

### 71. Missing ownership check on order retrieval

- Issue group: `ai-1058a3d986e0c953`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated principal is authorized to access the specific order identified by `order_id`. The code directly queries the `orders` table and returns the row without checking ownership or role, allowing any authenticated user to retrieve any order.

**Impact:** Unauthorized disclosure of order details, potentially exposing sensitive customer information and violating confidentiality requirements.

**Remediation:** Add an ownership or role check after retrieving the order (or before the query) that compares the order's `user_id` (or equivalent) to the authenticated principal's identifier, and enforce role‑based access control for privileged users. Return a 403 error if the check fails.
Evidence:
- Source IDs: `ai-1058a3d986e0c953`
- `def get_order(order_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `principal(authorization)`
- `row = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()`

Limitations:
- The review assumes the `orders` table contains a column linking orders to users (e.g., `user_id`). If such a column does not exist, the appropriate access control model may differ. The code snippet does not show any subsequent authorization logic, but it is possible that downstream middleware enforces ownership; this cannot be confirmed from the provided excerpt.

### 72. Admin endpoints expose sensitive user data without role enforcement

- Issue group: `ai-18e48e9ca03a01ac`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `/admin/users` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated principal has an admin role before executing a query that returns all user records, including SSNs. The same pattern is present for `/admin/jobs`. Without a role check, any authenticated user (or potentially an unauthenticated request if `principal` does not raise) can retrieve sensitive personal information, constituting an authorization flaw.

**Impact:** Unauthorized disclosure of personally identifiable information (PII) such as SSNs, email addresses, and usernames. This can lead to identity theft, privacy violations, and regulatory non‑compliance (e.g., GDPR, HIPAA).

**Remediation:** Add explicit role verification after authentication, e.g., `if principal.role != "admin": raise HTTPException(403)`. Ensure that the `principal` function returns a role attribute and that all admin‑only routes enforce this check before accessing sensitive data. Consider centralising authorization logic via a dependency or decorator.
Evidence:
- Source IDs: `ai-18e48e9ca03a01ac`
- `@app.get("/admin/users") defined at api/app.py line 277`
- `principal(authorization) called at line 279 without subsequent role check`
- `rows = conn.execute("SELECT id,username,email,role,ssn FROM users ORDER BY id").fetchall() at line 281 returns SSNs`
- `Similar pattern observed for @app.get("/admin/jobs")`

Limitations:
- The review assumes `principal` only authenticates and does not perform role checks; the actual implementation of `principal` is not shown. If `principal` internally enforces admin role, the finding would be a false positive. No runtime evidence (e.g., request logs) is provided to confirm that non‑admin users can access the endpoint.

### 73. Cookie set without HttpOnly and Secure flags in form login

- Issue group: `ai-8911a8c11e463193`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The form_login endpoint creates a session cookie using response.set_cookie without specifying security attributes such as HttpOnly, Secure, or SameSite. This allows client‑side scripts to read the cookie and may permit it to be transmitted over insecure channels, increasing the risk of session hijacking via XSS or network eavesdropping.

**Impact:** An attacker who can inject JavaScript (e.g., via reflected or stored XSS) could read the "lab_session" cookie and impersonate the user. If the application is accessed over HTTP, the cookie could be captured in transit.

**Remediation:** Set the cookie with appropriate flags, e.g., response.set_cookie("lab_session", f"session-{row['id']}", httponly=True, secure=True, samesite="lax"). Ensure the application enforces HTTPS and consider using SameSite='strict' where appropriate.
Evidence:
- Source IDs: `ai-8911a8c11e463193`
- `response.set_cookie("lab_session", f"session-{row['id']}") (api/extra.py:300)`

Limitations:
- The review does not know whether the deployment enforces HTTPS globally; external proxies might add security flags; the code snippet does not show any later middleware that could modify cookie attributes.

### 74. Potential brute-force enumeration on password reset request

- Issue group: `ai-4ee7d1a217f1e5bf`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code creates a password reset token for a supplied username without any visible rate‑limiting, CAPTCHA, or other abuse‑prevention checks in the examined snippet. However, the presence or absence of global middleware, external rate‑limiting services, or background cleanup jobs cannot be confirmed from the provided excerpts. Consequently, the risk of enumeration or token‑flooding cannot be definitively established.

**Impact:** If an attacker can repeatedly invoke the endpoint without restriction, they may enumerate valid usernames (by observing the 404 vs success response) and generate a large number of reset tokens, potentially facilitating credential‑reset attacks or denial‑of‑service on token storage.

**Remediation:** Implement rate limiting (e.g., per IP or per account) and/or CAPTCHA on the password‑reset request endpoint. Ensure generic error responses that do not reveal account existence. Consider adding token‑expiry and cleanup mechanisms, and audit any global middleware that might already provide protection.
Evidence:
- Source IDs: `ai-4ee7d1a217f1e5bf`
- `@router.post("/auth/reset/request") defined at line 564 without surrounding rate‑limit logic`
- `INSERT INTO reset_tokens executed at line 571 after user lookup`
- `No explicit rate‑limit or CAPTCHA checks observed in the snippet`

Limitations:
- Only local file excerpts were examined; global application middleware or external services may provide rate limiting that is not visible here
- The code may rely on framework‑level protections not shown in the excerpt
- Absence of evidence is not evidence of absence; further review of the full application configuration is required

### 75. Potential privilege escalation via limited_login endpoint

- Issue group: `ai-f3266e260c02792a`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The limited_login endpoint forwards authentication to the same checked_login function used by the regular login flow without any visible role or permission checks. While this could allow a user to obtain a token with the same privileges as a normal login, the repository code does not show whether checked_login internally enforces role‑based restrictions or whether downstream logic differentiates tokens issued via limited_login. Without evidence of the intended purpose of the endpoint or internal checks, the risk cannot be confirmed.

**Impact:** If the endpoint is intended to provide a restricted authentication path and it does not enforce additional constraints, an attacker could obtain full‑privilege tokens, leading to unauthorized access to privileged resources.

**Remediation:** Review the design of the limited_login endpoint. If it should restrict privileges, add explicit role or permission checks before calling checked_login, or ensure checked_login applies different policies based on the caller. Document the intended behavior and add tests to verify enforcement.
Evidence:
- Source IDs: `ai-f3266e260c02792a`
- `@router.post("/auth/limited-login") at api/extra.py line 247`
- `return checked_login(body) at api/extra.py line 268`

Limitations:
- The code excerpt does not show the implementation of checked_login, so internal role checks cannot be assessed.
- No documentation or comments clarify the intended purpose of limited_login.
- No runtime observations (e.g., token contents) are provided to confirm privilege levels.

### 76. Password reset token disclosed in API response

- Issue group: `ai-c489ae9273acf684`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `request_reset` endpoint returns the newly generated password‑reset token directly in the JSON response (`return {"reset_token": token}` at line 573). This allows any client that can invoke the endpoint to obtain a valid reset token without any out‑of‑band verification, creating a straightforward path to account takeover if the response is intercepted or logged.

**Impact:** An attacker who can trigger the password‑reset request can capture the token and use it to reset the victim's password, leading to full account compromise.

**Remediation:** Do not include the reset token in the API response. Instead, send the token to the user via a secure out‑of‑band channel (e.g., email or SMS) and return only a generic success message. Implement rate‑limiting and audit logging for reset requests.
Evidence:
- Source IDs: `ai-c489ae9273acf684`
- `api/extra.py:573:return {"reset_token": token}`
- `api/extra.py:564:@router.post("/auth/reset/request")`

Limitations:
- The code snippet does not show whether the token is also sent via a secure channel such as email; if it is, the risk is reduced but still present due to the token being exposed in the API response.
- Rate‑limiting or other abuse‑prevention mechanisms for the reset endpoint are not visible in the provided excerpt, so their presence cannot be confirmed.

### 77. Missing CSRF protection on state‑changing endpoint

- Issue group: `ai-31b3d2d986bb3103`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The POST /documents endpoint accepts file uploads and inserts them into the database without any visible CSRF token validation. While this could allow a CSRF attack if the endpoint is used from a browser session, the code does not indicate whether the API is intended for browser‑based clients or for programmatic access only. No same‑origin checks, custom headers, or other mitigations are shown, but the absence of a CSRF token alone is not definitive proof of a vulnerability in this context.

**Impact:** If the endpoint is reachable from a user's browser session and the user is authenticated, an attacker could induce the user to upload arbitrary files, potentially leading to stored XSS, defacement, or other injection attacks.

**Remediation:** Implement CSRF protection appropriate to the client model: for browser‑based usage, require a validated CSRF token (e.g., double‑submit cookie or SameSite cookie). For API‑only usage, enforce authentication via tokens and consider requiring a custom header (e.g., X‑Requested‑With) or using SameSite=Lax cookies to mitigate CSRF.
Evidence:
- Source IDs: `ai-31b3d2d986bb3103`
- `@router.post("/documents") definition at line 375`
- `INSERT statement at line 387 without preceding CSRF check`

Limitations:
- The review cannot confirm whether the endpoint is ever accessed via a browser session; the code may be intended for API clients only.
- No runtime observations of CSRF token handling or same‑origin policies are available.
- Absence of explicit CSRF checks does not guarantee that other mitigations (e.g., SameSite cookies, custom auth headers) are not in place elsewhere in the application.

### 78. Predictable session token format may allow enumeration

- Issue group: `ai-44598314a1ca5e08`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code validates a session token by checking it starts with "session-" and that the remainder is numeric. It then directly uses the numeric part as a user ID in a database query. This suggests session identifiers are predictable and may be guessable, potentially enabling session fixation or enumeration attacks. However, the repository does not show how tokens are generated elsewhere, so the risk cannot be fully confirmed.

**Impact:** An attacker who can guess or enumerate numeric IDs could obtain valid session tokens, impersonate other users, and access their data.

**Remediation:** Generate session tokens using a cryptographically secure random generator with sufficient entropy. Store tokens server‑side and validate them without exposing raw user IDs. Consider using signed JWTs or opaque tokens tied to a server‑side session store.
Evidence:
- Source IDs: `ai-44598314a1ca5e08`
- `api/extra.py:313 – token format check: if not token.startswith("session-") or not token[8:].isdigit()`
- `api/extra.py:316 – token numeric part used directly in SQL query: row = conn.execute("SELECT username FROM users WHERE id=%s", (int(token[8:]),)).fetchone()`

Limitations:
- The code snippet does not show how the token is originally created; it may include additional entropy not visible here.
- No evidence of rate‑limiting or additional authentication checks beyond the simple format validation.

### 79. Session cookie set without security attributes

- Issue group: `ai-46708a4888648bdc`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code creates a session cookie using response.set_cookie without specifying HttpOnly, Secure, or SameSite attributes. This allows client‑side scripts to read the cookie and permits transmission over insecure connections, increasing the risk of session hijacking.

**Impact:** An attacker who can execute JavaScript in the victim's browser or intercept network traffic could steal the session cookie and impersonate the user, leading to unauthorized access to protected resources.

**Remediation:** Set appropriate cookie flags when creating the session cookie, e.g., response.set_cookie("lab_session", f"session-{user['id']}", httponly=True, secure=True, samesite="lax"). Ensure the application is served over HTTPS in production.
Evidence:
- Source IDs: `ai-46708a4888648bdc`
- `response.set_cookie("lab_session", f"session-{user['id']}") (lines 277‑278)`

Limitations:
- The deployment context does not confirm whether the service runs over HTTPS, which affects the necessity of the Secure flag.
- Potential downstream code may rely on JavaScript access to the cookie, which could justify the omission of HttpOnly, but this is not evidenced in the provided material.

### 80. Potential privilege escalation via webhook job insertion

- Issue group: `ai-1465d175b36afff4`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The code inserts a job record with a `run_as` field set to the caller's role without an explicit check that only privileged roles may specify elevated values. If the downstream job executor trusts this field for privilege decisions, a non‑admin user could cause a job to run with higher privileges. However, the repository does not contain evidence of how the `run_as` value is later used or validated, nor does it show any enforcement of role claims in JWT handling. Without confirming that the job runner enforces `run_as` or that role claims cannot be forged, the risk cannot be confirmed.

**Impact:** If an attacker can cause jobs to execute with elevated privileges, they may gain unauthorized access to sensitive resources, execute arbitrary code, or modify data beyond their intended permissions.

**Remediation:** Add explicit authorization checks before inserting the job to ensure only allowed roles (e.g., admin) can set privileged `run_as` values. Validate and sanitize the role claim from the JWT, and enforce the `run_as` policy in the job runner regardless of the stored value. Consider removing the `run_as` field from user‑controlled input altogether.
Evidence:
- Source IDs: `ai-1465d175b36afff4`
- `Source excerpt shows insertion of `run_as` directly from `user["role"]` without a preceding role check (lines 528‑536).`
- `The endpoint is reachable via POST /webhooks/verified (line 526).`

Limitations:
- No evidence is provided about how the job runner processes the `run_as` field; it may ignore it or enforce its own checks.
- The verification of JWT integrity and role claim is not shown; the possibility of role forgery is unknown.
- Only static code analysis is available; runtime behavior and configuration (e.g., database constraints, additional middleware) are not examined.

### 81. Missing CSRF protection on state‑changing POST endpoints

- Issue group: `ai-db41fdfbedf12559`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The identified POST routes use an Authorization header to authenticate the request. In token‑based APIs (e.g., Bearer tokens in the Authorization header) CSRF attacks are not applicable because browsers do not automatically include these headers in cross‑origin requests. FastAPI does not provide built‑in CSRF protection for such endpoints, and the lack of a CSRF token does not constitute a vulnerability in this context. No evidence was found of cookie‑based authentication or SameSite cookie usage that would require CSRF mitigation.

**Impact:** If the application were to switch to cookie‑based authentication, the absence of CSRF defenses could allow an attacker to forge state‑changing requests from a victim’s browser. Under the current token‑based scheme, the risk is negligible.

**Remediation:** If future changes introduce cookie‑based sessions, add CSRF tokens or enforce SameSite=Lax/Strict on authentication cookies. Document the authentication model and confirm that token‑based requests are not vulnerable to CSRF.
Evidence:
- Source IDs: `ai-db41fdfbedf12559`
- `@router.post("/comments") definition in api/extra.py line 161`
- `Authorization header used as the sole authentication mechanism`
- `INSERT statement executed after token validation`

Limitations:
- Assessment assumes the Authorization header carries a bearer token and that no cookies are used for authentication; if cookies are introduced elsewhere, the conclusion may change. No runtime request logs were examined to confirm header usage.

### 82. Potential SSN exposure via profile endpoint

- Issue group: `ai-4b7439452be1c659`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /profiles/{profile_id} endpoint returns the full user record including the SSN column after only calling principal(authorization). No explicit ownership or role‑based check is shown to ensure the requester is allowed to view that specific user's sensitive data. This could allow any authenticated user to retrieve another user's SSN if principal() does not enforce such restrictions.

**Impact:** Unauthorized disclosure of Social Security Numbers can lead to identity theft, fraud, and severe privacy violations for affected users.

**Remediation:** Add an authorization check that verifies the authenticated user is permitted to access the requested profile (e.g., compare profile_id to the user's own ID or check a role/permission). Alternatively, omit the SSN field from the response or mask it unless the caller has explicit clearance.
Evidence:
- Source IDs: `ai-4b7439452be1c659`
- `99: principal(authorization)`
- `101: row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone()`
- `104: return dict(row)`

Limitations:
- It is not confirmed whether principal() performs any role‑based access control beyond authentication.
- No evidence was found about downstream filtering that might remove the ssn field before returning the response.

### 83. Potential authorization bypass in admin overview endpoint

- Issue group: `ai-e98f3d026454b459`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /admin/overview calls principal(authorization) which authenticates the request but does not appear to enforce an admin role check. The code then returns the total user count, a privileged statistic, to any authenticated user. Without evidence that principal() performs admin verification, this constitutes a likely authorization bypass.

**Impact:** An attacker who can obtain a valid authentication token could retrieve the total number of users, potentially aiding enumeration attacks or exposing sensitive operational metrics.

**Remediation:** Add an explicit admin role verification (e.g., require_admin(authorization) or a role‑based access control check) before executing the sensitive query and returning the result.
Evidence:
- Source IDs: `ai-e98f3d026454b459`
- `198: principal(authorization)`
- `200: count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]`
- `201: return {"users": count}`

Limitations:
- The behavior of principal() is not shown; it may already enforce admin privileges. Further code review or runtime testing is required to confirm its enforcement.

### 84. Missing ownership verification on order note retrieval

- Issue group: `ai-2a19509aa4f994e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint retrieves a note by its ID after only calling `principal(authorization)`. No check is performed to ensure that the note's `order_id` matches the `order_id` supplied in the URL or that the authenticated user owns that order. This allows any authenticated user to access notes belonging to other users if they can guess or enumerate note IDs.

**Impact:** An attacker who can obtain or guess a valid `note_id` could read the contents of notes belonging to other users, potentially exposing sensitive order information and violating confidentiality.

**Remediation:** Add an ownership check after fetching the row, e.g., verify that `row['order_id'] == order_id` and that the authenticated user (derived from `principal`) is authorized for that order. Return 403 if the check fails. Consider using parameterized queries that also filter by `order_id` to enforce the relationship at the database level.
Evidence:
- Source IDs: `ai-2a19509aa4f994e2`
- `544: principal(authorization)`
- `546: row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()`
- `549: return dict(row)`

Limitations:
- The behavior of `principal()` is not known; it might perform additional context checks.
- Database schema constraints (e.g., foreign keys) are not visible, so it is unclear if the query implicitly restricts notes to the given order.

### 85. Missing authorization on file download endpoint

- Issue group: `ai-24c3421657a70844`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `view_upload` endpoint returns the raw file contents for any `upload_id` without performing any authentication or ownership verification. The code snippet shows the endpoint is publicly accessible (`@router.get("/uploads/{upload_id}")`) and directly queries the database for the file data, returning it if found. This allows an attacker to enumerate or guess upload IDs and retrieve files belonging to other users, leading to unauthorized data disclosure.

**Impact:** Unauthorized users can download arbitrary uploaded files, potentially exposing sensitive personal or business data. If upload IDs are sequential or predictable, the impact is amplified through mass enumeration.

**Remediation:** Add authentication and authorization checks before accessing the file. Verify that the requesting user is authenticated and owns the upload or has a role that permits access. Consider using a helper function to enforce ownership, and return a 403 Forbidden response when access is denied. Additionally, make upload IDs non‑predictable (e.g., UUIDs) to mitigate enumeration.
Evidence:
- Source IDs: `ai-24c3421657a70844`
- `@router.get("/uploads/{upload_id}") (line 366)`
- `def view_upload(upload_id: int) -> Response: (line 367)`
- `row = conn.execute("SELECT mime,body FROM uploads WHERE id=%s", (upload_id,)).fetchone() (line 369)`
- `return Response(bytes(row["body"]), media_type=row["mime"]) (line 372)`

Limitations:
- The review is based solely on static code analysis; runtime behavior (e.g., middleware that might enforce auth) is not observed. No evidence was found of a separate authorization layer applied elsewhere, so the conclusion assumes none exists. The predictability of `upload_id` values is not confirmed; if IDs are random, enumeration risk is reduced.

### 86. Detailed exception messages exposed in HTTP 500 response

- Issue group: `ai-5398135ba4d05e3f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/errors/query` catches any exception from a deliberately faulty SQL query and returns the exception object interpolated into the HTTP 500 response (`raise HTTPException(500, f"Query failed: {error}")`). This can reveal internal database schema details, table/column names, or other implementation information to any client that triggers the error.

**Impact:** An attacker can enumerate database structure or infer internal logic, facilitating further attacks such as SQL injection, privilege escalation, or targeted phishing.

**Remediation:** Replace the detailed error message with a generic response (e.g., `raise HTTPException(500, "Internal server error")`). Log the full exception server‑side for debugging. Consider adding a custom exception handler that sanitizes error output before sending it to clients.
Evidence:
- Source IDs: `ai-5398135ba4d05e3f`
- `api/extra.py:231 – `conn.execute("SELECT unavailable_column FROM products")` triggers a database error`
- `api/extra.py:233 – `raise HTTPException(500, f"Query failed: {error}") from error` interpolates the raw exception into the response`

Limitations:
- Evidence is limited to static code analysis; runtime behavior (whether the exception message is actually sent to the client) is not observed. No information on existing logging or error‑handling middleware that might mask the message.

### 87. Potential missing authorization check before database operation

- Issue group: `ai-f16179fcea40c0fe`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /errors/checked executes a raw SQL query without an explicit authentication or role check in the shown code. However, the review cannot confirm whether a global FastAPI dependency, router-level security guard, or the connection() context manager enforces authorization. Without evidence of such safeguards, the risk of unauthorized users triggering the query remains uncertain.

**Impact:** If unauthenticated users can invoke this endpoint, they may cause unnecessary database load, trigger error messages that reveal internal details, or infer the existence of tables/columns via timing or error responses, leading to information disclosure or denial‑of‑service conditions.

**Remediation:** Add an explicit authorization dependency to the route (e.g., FastAPI Depends on a current_user check) or ensure that the connection() manager performs permission validation. Document and enforce that only privileged roles can access this endpoint.
Evidence:
- Source IDs: `ai-f16179fcea40c0fe`
- `@router.get("/errors/checked") defined at api/extra.py line 237`
- `SQL execution conn.execute("SELECT unavailable_column FROM products") at line 241`
- `No inline authentication/authorization guard visible in the excerpt`

Limitations:
- The snippet does not show any router‑level dependencies or global middleware that might enforce authentication
- The connection() context manager's internal implementation is unknown and may contain permission checks
- Potential that a FastAPI dependency injection elsewhere adds a security guard not captured in this excerpt

### 88. Potential information leakage via exception handling

- Issue group: `ai-5abca5802e76fd0e`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code catches a generic exception and re‑raises it as an HTTPException with the original exception chained ("from error"). If FastAPI is running with debug mode enabled or if the exception handling middleware includes the original traceback in the response, internal details could be exposed. However, the provided data does not confirm the runtime configuration (debug=False) or the behavior of the HTTPException handling, so the risk cannot be definitively assessed.

**Impact:** If internal stack traces or database query details are returned to clients, an attacker could gain insight into the application's internals, facilitating further attacks such as targeted SQL injection or enumeration of database schema.

**Remediation:** Configure FastAPI with debug=False in production and ensure that exception handlers strip any internal traceback before sending responses. Log the original error server‑side without exposing it to the client, and consider raising a generic error message without chaining the original exception.
Evidence:
- Source IDs: `ai-5abca5802e76fd0e`
- `api/extra.py:239‑243 shows the try/except block with "raise HTTPException(500, \"Operation failed\") from error"`
- `entry point defined at api/extra.py line 237 with @router.get("/errors/checked")`

Limitations:
- No evidence about the FastAPI debug setting or custom exception handlers
- Cannot confirm whether the HTTPException response includes the chained traceback

## Policy Decisions

- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-bdfe7542047da39c6151`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-17a5197f906426a224ef`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-da0f922505b4c0c7fed1`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-19f4a13e0b2d4f7413d0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-65c41e5a25b6337fec07`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-1ba9f8276fc6dae95df8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-cc8a9ed20905505868f0`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b4c1c4d005665a5249a7`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a9e9047867c909f567ad`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-7da23d65adeef42d71a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e683a977084f2bbcee2e`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-dd64ece99563dbbb173a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2b80ed0c48c0c70a93a4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
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
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1550abf709023a18`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-4335c2f227b20f8c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-b0b82e8cd9d25449`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-7ef28a27beffa9f8`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-01752b2720398cda`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-1e343df69b02c985`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-de70ebb6230142e0`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-1058a3d986e0c953`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-18e48e9ca03a01ac`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-8911a8c11e463193`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-4ee7d1a217f1e5bf`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-f3266e260c02792a`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-c489ae9273acf684`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-31b3d2d986bb3103`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-44598314a1ca5e08`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-46708a4888648bdc`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1465d175b36afff4`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-db41fdfbedf12559`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `ai-4b7439452be1c659`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-e98f3d026454b459`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-2a19509aa4f994e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-24c3421657a70844`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-5398135ba4d05e3f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-f16179fcea40c0fe`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-5abca5802e76fd0e`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **88**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **36**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **19**; uncertain overlaps: **6**; needs more evidence: **11**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-76da29c37dce5201`: needs_more_evidence
- `ai-1e343df69b02c985`: uncertain_overlap
- `ai-5d7702dfe27924fb`: needs_more_evidence
- `ai-ba8c8d802ab6a76e`: needs_more_evidence
- `ai-2aa651d476b44649`: needs_more_evidence
- `ai-6b0a60d56c2c9cbd`: needs_more_evidence
- `ai-8911a8c11e463193`: uncertain_overlap
- `ai-4ee7d1a217f1e5bf`: uncertain_overlap
- `ai-1817ad204d27eacd`: needs_more_evidence
- `ai-2f41ffe134a171a9`: needs_more_evidence
- `ai-c489ae9273acf684`: uncertain_overlap
- `ai-44598314a1ca5e08`: uncertain_overlap
- `ai-c03e342fbf403b7f`: needs_more_evidence
- `ai-b9507ae47902f25e`: needs_more_evidence
- `ai-d2dd13aa5c509c7e`: needs_more_evidence
- `ai-fbe22a886dd42499`: needs_more_evidence
- `ai-5abca5802e76fd0e`: uncertain_overlap

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

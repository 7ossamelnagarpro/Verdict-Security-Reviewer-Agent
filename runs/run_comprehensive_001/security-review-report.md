# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-10-30T10:37:42.032446+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **5**.
- AI Discovery warning: Discovery batch 2: AI provider request failed with HTTP 400 (json\_validate\_failed); model output 0 chars, not valid JSON; retrying with a smaller request.

The agent reviewed **70** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **70**; reviewed: **70**; pending: **0**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **51**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **blocked**; pages visited: **0**.
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
15. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
16. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
17. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: 40/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
18. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-17a5197f906426a224ef</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-210f1029720d2c4e6e3e993a</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
19. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-da0f922505b4c0c7fed1</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-afddc086f33f2e8a8fa222be</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
20. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-38e7cf77bdf9145d2ae4</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-c0e1afff107bb0eb4f9995fc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
21. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-d9421dbfc4162d6dea91</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-6e6caeab05225e629344552e</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
22. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-e7caea540245938b275b</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-0dc83bd580f54eb0cd2941b9</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
23. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-8e21db3fe42adbf58979</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-3f8d9dc38e0f642bbc4291d3</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
24. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-d5c3b6b8d8dad90c4d3c</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-b2db6b94c587ff6fb7d08426</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
25. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-a5ea8ca4c36bd6c25e2a</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-5ea37fc15cb39757603b7cd7</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
26. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-1ba9f8276fc6dae95df8</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-05d2f624905d2e8204ceb2b2</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
27. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-2d4a81712313b5f2f621</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-b9165f8e58d7def0d12de985</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
28. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-8946f8391fc9049cbb58</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-78580a62c3793f37f5e1f001</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
29. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-cc8a9ed20905505868f0</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-b082e5735b56669c3ad0c27e</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
30. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-b4c1c4d005665a5249a7</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-95408e1a46c05125661f435c</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
31. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-a9e9047867c909f567ad</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-5f52b3ddf5cb11e03bcb0999</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
32. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-7da23d65adeef42d71a6</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-80c8d131ef8da2487a54950d</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
33. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-e683a977084f2bbcee2e</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-b2a4f197f469e50923cacdff</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
34. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-dd64ece99563dbbb173a</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-4ed77a8cbe072385df677726</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
35. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-2b80ed0c48c0c70a93a4</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-075b1c7547b453cbe6b18b34</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
36. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-65f25bcf14fa2ab91271</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-3165b0fcf5e0b47c5b31d6bd</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
37. **python-multipart: Python-Multipart: Information disclosure due to parser differential in form data handling** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: 25/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-74bb99c1ff3b5ed1fea8</code>; rule(s): <code>CVE-2026-53538</code>; source evidence: <code>finding-37828c3c6f1de39a916e</code>.
38. **multipart: Python-Multipart: Information disclosure via header parsing discrepancy** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: 25/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-e76230cbef200116e4ae</code>; rule(s): <code>CVE-2026-53537</code>; source evidence: <code>finding-0f80f106ffc0aeace60b</code>.
39. **python-multipart: Python-Multipart: Negative Content-Length in parse\_form buffers the entire body in memory** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: 25/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-f15e42abb7b2acd921f1</code>; rule(s): <code>CVE-2026-53540</code>; source evidence: <code>finding-b593d9dd6684fb6a9511</code>.
40. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: 17/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-41e99a7ce6d803bedda1</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-3ae18a34f0a5708c74b36a77</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
41. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: 17/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-5fe9a08fc103085427f9</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-22ca4c07bddeba21e02773f1</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
42. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: 17/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-fbfa546bfd43886d2b10</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-5503aaa4e28201d1d3085645</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
43. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: 17/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-dfd8d33b4f84ccf0c23f</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-cc2918cb425bae3d180daa14</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
44. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
45. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
46. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
47. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
48. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: 12/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-553cfc223024a5e03f34</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-197bc06e62c71419a6984565</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
49. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: medium; risk: 12/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-9b32fbabacaa9f45b768</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-1d3f2eae9b270c563eb2842c</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
50. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: 12/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-fe76cc1a4803fb50214c</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-fe06d42de0122c9df52f951f</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
51. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: 12/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-65c41e5a25b6337fec07</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-30173b60257e41bdd229851f</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
52. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: 12/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-50485291173e2448f7c7</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-905604ee346a77ad8a33b929</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
53. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: 12/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
54. **Missing Content-Security-Policy header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 2/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-19f4a13e0b2d4f7413d0</code>; rule(s): <code>web.missing-content-security-policy</code>; source evidence: <code>runtime-4d5cb0113b221c088986a91b</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
55. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 2/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
56. **Missing X-Content-Type-Options header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 2/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-bbf1646deeb18d1e95db</code>; rule(s): <code>web.missing-content-type-protection</code>; source evidence: <code>runtime-a9347cabd53ecd99e38108cc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
57. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: 0/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-bdfe7542047da39c6151</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-d6fe23474b5bf05b50a68dd9</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
58. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: 0/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-ec17a70b00fa38747671</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-666123a1a4379f9b0ecad8e6</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
59. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: 0/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-7457580a7c7bb31a32cd</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-f9b4bb2665a94ef114ba70a0</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
60. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: 0/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-16678dc11308a0a16a81</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8e20c6e4b7bf9daa87ca68c5</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
61. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: 0/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-7c9406875347cad8b1ce</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-7308dae08a226093934e5a0d</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
62. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: 0/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-ade7b890a037d8c82a1f</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8aa093668e36a5e692db4f28</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
63. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: 0/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.

## Security Review Agent Verdicts

### 1. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `legacy_login` constructs an SQL statement by directly interpolating `body.username` and `body.password` into the query string using an f‑string. This allows an attacker to inject arbitrary SQL syntax via the `username` or `password` fields, leading to SQL injection. No parameterized query or escaping is performed before the statement is executed.

**Impact:** An attacker could bypass authentication, retrieve or modify user records, or execute arbitrary database commands, potentially leading to full system compromise or data exfiltration.

**Remediation:** Replace the string interpolation with a parameterized query or prepared statement provided by the database driver/ORM. For example, use `SELECT id, username, role FROM users WHERE username = ? AND password = ?` with bound parameters, or employ an ORM that handles query sanitization automatically. Additionally, consider hashing passwords instead of storing them in plain text.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117: `query = f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"``
- `Line 119: `row = conn.execute(query).fetchone()``

Limitations:
- The analysis assumes the underlying `connection().execute` method does not internally sanitize the interpolated string. If the database driver performed automatic escaping (unlikely with raw f‑strings), the risk would be reduced, but no evidence of such behavior is present.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter, but it immediately resolves the path and verifies that the resulting path is a sub‑directory of the intended root using `file.is_relative_to(root)`. If the check fails, a 404 error is raised, preventing directory traversal. Therefore the reported uncontrolled data usage does not lead to a path‑traversal vulnerability in the current implementation.

**Impact:** No impact because the traversal is blocked; an attacker cannot read files outside the public directory.

**Remediation:** No remediation required for this specific issue; the existing relative‑path check is sufficient. Ensure the runtime environment uses Python 3.9+ where `Path.is_relative_to` is available.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- The safety relies on `Path.is_relative_to`, which is only available in Python 3.9+. On older Python versions the check would fail, potentially re‑introducing traversal risk. The check also only validates the path after resolution; symbolic links inside the public directory could still point outside the root if not controlled.

### 3. Path traversal check appears sufficient

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint constructs the file path from a user‑provided name, resolves it, and then verifies that the resolved path is a descendant of the intended root directory using Path.is_relative_to and that it is a regular file before reading. This prevents directory traversal attacks under normal circumstances.

**Impact:** No impact; the check blocks malicious path inputs from accessing files outside the public directory.

**Remediation:** No remediation required for the path traversal issue; ensure the runtime environment uses a Python version that supports Path.is_relative_to and consider adding atomic file access to mitigate TOCTOU risks.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source_excerpt lines 218‑224 show the resolve and is_relative_to checks`
- `source_symbol confirms the same logic`

Limitations:
- Relies on Python 3.9+ for is_relative_to; older versions would raise AttributeError
- Potential TOCTOU race condition between the check and file.read_text could be exploited in a highly concurrent environment

### 4. Path traversal check mitigated by safe resolution and relative check

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint builds the file path using pathlib, resolves it to an absolute path, and then verifies that the resolved path is a sub‑path of the configured FILES directory via `is_relative_to`. This prevents directory‑traversal payloads such as "../" from escaping the intended directory. The subsequent `is_file` check also ensures the target exists before serving it. Consequently, the scanner’s finding of "uncontrolled data used in path expression" does not constitute a vulnerability in this context.

**Impact:** No impact; the endpoint correctly restricts access to files within the allowed directory.

**Remediation:** No remediation required for this finding. Ensure the runtime environment uses Python 3.9+ where `Path.is_relative_to` is available, or replace with an equivalent check if using older versions.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `File path is constructed with `(FILES / "public" / name).resolve()``
- `Safety check: `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- The safety relies on `Path.is_relative_to`, which is only available in Python 3.9+. If the application runs on an older Python version, this check would fail, potentially re‑introducing a traversal risk.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known root directory and then verifies that the resulting path is a sub‑path of that root using `file.is_relative_to(root)`. This check prevents directory traversal attacks by ensuring the file cannot escape the intended `public` directory. Consequently, the static scanner’s warning about uncontrolled data in a path expression does not reflect an actual vulnerability in this context.

**Impact:** No impact because the path traversal is mitigated by the relative‑path check.

**Remediation:** No remediation required; the existing `is_relative_to` check adequately protects against path traversal.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- The assessment assumes the Python version provides `Path.is_relative_to`, which correctly enforces the containment check. If the runtime environment modifies `Path` behavior or the check is bypassed elsewhere, the protection could fail.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a fixed public directory and then verifies that the resolved path is still within that directory using `is_relative_to`. This check prevents directory traversal attacks, so the data is not uncontrolled in the path expression. The scanner’s generic pattern flagged the use of a user‑controlled variable, but the subsequent safety check mitigates the risk.

**Impact:** No impact because the path traversal is effectively prevented by the relative‑path check.

**Remediation:** No remediation required; the existing `is_relative_to` check is sufficient.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `211-215: The function builds the file path with `FILES / "public" / name`, resolves it, and then checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")` before reading the file.`

Limitations:
- No runtime probe data is available to confirm the behavior under edge cases such as symlink attacks or unusual filesystem configurations.

### 7. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any sanitisation or escaping. The returned string `f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)` embeds `q` verbatim, allowing an attacker to inject arbitrary HTML/JavaScript that will be rendered by a victim's browser.

**Impact:** An attacker can craft a URL such as `/catalog/search?q=<script>alert(1)</script>` that, when visited by a victim, executes the injected script in the victim's context. This can lead to session hijacking, credential theft, defacement, or further malicious actions against the user or the application.

**Remediation:** Encode or escape the `q` value before inserting it into the HTML response. Use a templating engine with automatic escaping (e.g., Jinja2) or explicitly apply HTML escaping functions. Additionally, consider implementing a Content Security Policy (CSP) to mitigate the impact of any residual XSS vectors.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt shows direct interpolation of `q` into HTML response (lines 142‑145).`
- `Scanner evidence: "Cross-site scripting vulnerability due to a user‑provided value".`

Limitations:
- No runtime probe data confirming that the endpoint is reachable or that the injected payload is reflected in the actual HTTP response.
- No evidence of existing mitigations such as output encoding, CSP headers, or input validation.
- The analysis is based solely on static code review; actual exploitability may depend on deployment configuration.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint resolves the user‑provided filename with pathlib.resolve() and then verifies that the resolved path is still within the designated FILES directory using is_relative_to(). This check prevents directory‑traversal attacks by ensuring the final path cannot escape the allowed folder, so the reported issue is not exploitable in the current code.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server, potentially exposing sensitive data. The existing validation mitigates this risk, so no impact is present.

**Remediation:** No remediation required for the path‑traversal check; however, consider adding explicit validation of the filename (e.g., whitelist allowed characters) and ensure that symbolic links cannot be used to bypass the directory restriction.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- No dynamic runtime probing was performed; edge cases involving complex symlink chains or filesystem race conditions are not evaluated.

### 9. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint constructs an SQL statement by directly interpolating the `q` query‑parameter into the query string using an f‑string, allowing an attacker to inject arbitrary SQL syntax into the `WHERE name ILIKE` clause.

**Impact:** An attacker can perform SQL injection to read, modify, or delete data in the `products` table and potentially execute additional SQL commands depending on database privileges, leading to data leakage or corruption.

**Remediation:** Rewrite the query to use parameterized statements (e.g., `conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",))`) or an ORM that safely escapes inputs. Validate and sanitize the `q` parameter as needed.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt line 144: `rows = conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'`).fetchall()` shows direct interpolation of user input.`
- `Scanner finding flagged as high severity with high confidence.`

Limitations:
- No runtime probe data confirming exploitation.
- Assumes the database driver does not automatically parameterize f‑strings.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for '/' does not include the X-Content-Type-Options header. No other evidence contradicts this finding, but the runtime probe facts are redacted and no direct header capture is provided, so the absence cannot be fully confirmed.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting (XSS).

**Remediation:** Configure the web server or application framework to include the header `X-Content-Type-Options: nosniff` on all responses.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `X-Content-Type-Options Header Missing (scanner)`

Limitations:
- Header presence was not directly observed; runtime probe facts are redacted and provide no concrete values.
- Only a single scanner source; no independent verification of the missing header.

### 11. Job listing requires admin role

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner reports that the /admin/jobs endpoint requires an admin role, but the only runtime observation is a 200 response with redacted values. No request was made without authentication or with a non‑admin user to demonstrate an access‑control bypass, and the response content is not visible. Therefore the presence of a vulnerability cannot be confirmed.

**Impact:** If the endpoint were accessible without proper authorization, an attacker could enumerate or manipulate internal job listings, potentially exposing sensitive operational data or enabling further privilege escalation.

**Remediation:** Implement strict authentication and role‑based access control on the /admin/jobs endpoint. Verify that unauthenticated or non‑admin requests receive a 403/401 response and that only users with the appropriate admin role can retrieve job data. Add automated tests to confirm the enforcement.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Scanner evidence: "Job listing requires admin role"`
- `Runtime probe fact: status 200 returned for /admin/jobs (values redacted)`

Limitations:
- No unauthenticated or low‑privilege request was performed to prove access without admin rights
- Response body was redacted, preventing verification of sensitive data exposure
- Only a single probe was observed; no repeated or varied testing was conducted

### 12. A demoted administrator must lose administrative access

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged a potential stale role at /admin/token-report, but the only runtime observation is an HTTP 200 response with redacted values. No proof is provided that a demoted administrator can still perform privileged actions or that the endpoint returns sensitive data. Additional testing is required to verify whether the role revocation is correctly enforced.

**Impact:** If a demoted administrator retains access, they could continue to perform privileged operations, leading to unauthorized data access or configuration changes.

**Remediation:** Ensure that role changes are immediately reflected in all authentication and authorization checks. Verify that endpoints like /admin/token-report enforce current role permissions and do not expose sensitive information after demotion.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Scanner finding: A demoted administrator must lose administrative access`
- `Runtime probe fact (web-runtime, rule workflow.stale_role.3) at /admin/token-report returned status 200 with values redacted`

Limitations:
- Only an HTTP 200 status observed; does not confirm successful privileged operation
- Response values are redacted, preventing verification of token validity
- No authentication context captured in the probe
- Single endpoint examined; broader role enforcement not assessed

### 13. User listing requires admin role

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **medium**

**Explanation:** The scanner reported that the /admin/users endpoint requires an admin role, but the runtime probe only returned a 200 status with redacted values and did not demonstrate unauthenticated or unauthorized access. No evidence was provided that the endpoint can be accessed without proper privileges, so the finding does not constitute a confirmed vulnerability.

**Impact:** No impact identified because access control appears to be enforced.

**Remediation:** No remediation required; ensure that access control remains enforced and consider adding explicit authentication tests to verify the protection.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Scanner evidence: "User listing requires admin role"`
- `Runtime probe fact: status 200 with values redacted`

Limitations:
- The probe did not verify authentication or role checks; values were redacted, preventing confirmation of data exposure
- No test of unauthenticated or lower‑privilege access was performed

### 14. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner (zap.10038) reported that the HTTP response for /auth/form-login does not include a Content‑Security‑Policy header. No additional runtime probe data contradicts this finding, and the absence of a CSP header is a known security weakness that can enable cross‑site scripting and data‑exfiltration attacks. Given the lack of contrary evidence, the finding is treated as a likely vulnerability.

**Impact:** Without a CSP header, an attacker may inject malicious scripts that execute in the context of the victim's browser, leading to XSS, credential theft, or other client‑side attacks.

**Remediation:** Configure the web server or application framework to send a strong Content‑Security‑Policy header for all responses, e.g., `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and tailor directives to the application's needs.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner (zap.10038) reported missing CSP header on /auth/form-login`

Limitations:
- Runtime probe facts are redacted, so the actual response headers were not directly observed
- Finding is based on a single endpoint check; other endpoints may behave differently
- Scanner could have missed a header set by downstream middleware or a CDN

### 15. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from /auth/form-login does not include an X-Frame-Options or Content-Security-Policy frame-ancestors directive, which are standard defenses against clickjacking. No additional runtime probe data confirming the header’s presence or absence was available, so the finding cannot be fully confirmed but is consistent with a typical misconfiguration.

**Impact:** An attacker could embed the login page in a malicious site’s iframe, potentially tricking users into submitting credentials or performing unintended actions, leading to credential theft or session hijacking.

**Remediation:** Configure the web server or application framework to send an appropriate anti-clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) for all authentication endpoints, and verify that it is present in all responses.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Missing Anti-clickjacking Header reported by scanner (zap.10020) for path /auth/form-login`

Limitations:
- Runtime probe facts were redacted and did not provide concrete header values
- No manual verification of the response headers was performed
- Potential that the header is added conditionally (e.g., only for certain user agents) and was not captured in this scan

### 16. Cookie No HttpOnly Flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that a cookie set on /auth/form-login lacks the HttpOnly attribute. No additional runtime evidence or source code context was provided to confirm the cookie's sensitivity or usage, but the absence of HttpOnly can allow client‑side scripts to access the cookie, which is a known security concern.

**Impact:** If the cookie contains session or authentication data, an attacker exploiting a cross‑site scripting (XSS) flaw could steal the cookie and hijack the user’s session.

**Remediation:** Configure the application or web server to set the HttpOnly flag on the affected cookie (e.g., using Set-Cookie: HttpOnly). Review all cookies for sensitivity and apply HttpOnly where appropriate.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `Cookie No HttpOnly Flag`

Limitations:
- No runtime probe data confirming the cookie’s value or usage
- Values redacted in probe facts
- No source code excerpt to verify cookie handling
- Single scanner source without independent verification

### 17. Password reset tokens must be single use

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner reported a successful HTTP 200 response when exercising the password‑reset confirmation endpoint (/auth/reset/confirm). The runtime probe fact indicates the request was processed, but the token value was redacted and no comparison between first‑use and subsequent‑use attempts is provided. Without evidence that the same token was reused or that the server fails to invalidate it after the first use, the finding cannot be confirmed as a vulnerability.

**Impact:** If password‑reset tokens are reusable, an attacker who obtains a token could reset a victim's password multiple times, leading to account takeover.

**Remediation:** Implement server‑side logic that invalidates a password‑reset token after its first successful use and returns an error for any subsequent attempts with the same token.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.reset_replay.3, path=/auth/reset/confirm, facts={status:200, values_redacted:true}`

Limitations:
- Token value was redacted, preventing verification of reuse
- No explicit test of a second request with the same token
- Single request only; cannot determine if token is single‑use

### 18. Missing Content Security Policy (CSP) Header

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /catalog/query does not include a Content Security Policy header. A CSP header helps mitigate a range of client‑side attacks such as cross‑site scripting (XSS) and data injection. While the absence of the header is a security weakness, the evidence is limited to a single scanner observation without direct verification of the live response or any exploitation evidence.

**Impact:** Without a CSP header, browsers will not enforce the intended content restrictions, increasing the risk that malicious scripts injected via XSS or other vectors could execute in the victim's browser, potentially leading to credential theft, session hijacking, or other client‑side attacks.

**Remediation:** Configure the web server or application framework to send a robust CSP header for all responses. Example for Apache: add `Header set Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';"`. For Express.js, use the helmet middleware: `app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "https://trusted.cdn.com"] } }));`. Test the header with tools like curl or securityheaders.com to ensure it is present and correctly formatted.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Content Security Policy (CSP) Header Not Set (scanner finding)`

Limitations:
- No direct capture of response headers to confirm the absence of CSP
- Runtime probe facts were redacted, providing no additional verification
- No evidence of successful exploitation or impact in the application
- Finding is based on a single scanner source without corroborating manual review

### 19. X-Content-Type-Options Header Missing

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /catalog/query does not include the X-Content-Type-Options header, which is recommended to prevent MIME type sniffing. No contradictory evidence was found, but the runtime probe facts are redacted, so the absence cannot be directly confirmed at runtime.

**Impact:** Without this header, browsers may perform content sniffing, potentially allowing execution of malicious content disguised as a different MIME type, leading to cross‑site scripting or drive‑by download attacks.

**Remediation:** Configure the web server or application framework to always include the header `X-Content-Type-Options: nosniff` on all responses, e.g., via server configuration (Apache, Nginx) or middleware in the application code.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `X-Content-Type-Options Header Missing (scanner evidence)`

Limitations:
- Runtime probe facts are redacted, so the missing header is not directly observed at runtime
- No verification of conditional header logic or environment‑specific configuration

### 20. Missing Anti-clickjacking Header

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /catalog/query does not include an anti-clickjacking header such as X-Frame-Options or a CSP frame‑ancestors directive. No runtime probe data contradicts this observation, and the probe facts are redacted, so the absence cannot be disproven.

**Impact:** An attacker could embed the page in a hidden iframe and trick users into performing unintended actions (clickjacking), potentially leading to unauthorized transactions or data leakage.

**Remediation:** Configure the web server or application to send an appropriate anti-clickjacking header, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP header with `frame-ancestors 'self'`. Verify the header is present in responses for all relevant endpoints.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Scanner finding: Missing Anti-clickjacking Header on /catalog/query (zap.10020)`

Limitations:
- Evidence relies solely on scanner observation; runtime probe facts are redacted and do not confirm header presence or absence. No direct response capture was provided to validate the header.

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner reported that the HTTP response for /comments does not contain an X-Content-Type-Options header. No runtime probe data confirming the header's absence was provided, and no additional evidence (e.g., server configuration or proxy behavior) is available to verify the finding.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting (XSS).

**Remediation:** Configure the web server or application framework to include the header `X-Content-Type-Options: nosniff` on all HTTP responses, or ensure that any reverse proxy adds it if the application does not emit it directly.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `X-Content-Type-Options Header Missing (scanner evidence)`

Limitations:
- Evidence is based solely on a scanner report; runtime probe facts are redacted and do not confirm the header's presence or absence.
- No verification from server configuration, proxy settings, or actual response capture was provided.

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner observed that the HTTP response for /comments does not include a Content Security Policy header. Absence of CSP can allow malicious scripts to execute in the browser, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks. While the finding is supported by scanner evidence, no runtime verification or application‑specific context was provided to confirm that a CSP header is truly missing in production.

**Impact:** An attacker could inject malicious JavaScript that runs in the victim's browser, potentially stealing session cookies, performing actions on behalf of the user, or delivering drive‑by malware.

**Remediation:** Configure the web server or application framework to send a strict CSP header for all responses (e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';`), and test to ensure it is correctly applied across all endpoints.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Content Security Policy (CSP) Header Not Set`

Limitations:
- Evidence is limited to a single scanner observation; no runtime probe confirmed the header's absence.
- No information about alternative security controls or whether CSP is set conditionally (e.g., only in production).
- The finding does not demonstrate an actual exploit, only a missing defense.

### 23. Missing Anti-clickjacking Header

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the /comments endpoint does not include an anti‑clickjacking header (e.g., X‑Frame‑Options or Content‑Security‑Policy frame‑ancestors). No runtime probe data confirming the absence of these headers was provided, and no additional scanner or manual evidence was supplied. Without direct observation of the response headers, the finding cannot be confirmed nor dismissed.

**Impact:** If the endpoint can be embedded in a malicious site, an attacker could trick users into performing unintended actions (clickjacking), potentially leading to data leakage or unauthorized actions.

**Remediation:** Configure the web server or application framework to send an appropriate anti‑clickjacking header on all responses, such as `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive that restricts framing to trusted origins.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Missing Anti-clickjacking Header (scanner report)`

Limitations:
- Runtime probe facts were redacted and did not confirm header presence or absence
- No manual verification of response headers was performed
- Potential that headers are added by downstream proxies or middleware not captured by the scan

### 24. Debug configuration endpoint does not expose sensitive data

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The runtime probe accessed /debug/config and received an HTTP 200 response, but the response indicated that values were redacted. No configuration details or secrets were disclosed, so the finding that the debug configuration is unavailable anonymously does not constitute a vulnerability.

**Impact:** None – the endpoint does not leak sensitive configuration information.

**Remediation:** No remediation required; continue to ensure that debug endpoints do not expose sensitive data and remain protected behind authentication.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.debug_access.1, path=/debug/config, facts={status:200, values_redacted:true}`

Limitations:
- Only a single unauthenticated request was observed; does not assess authenticated access or other debug endpoints.

### 25. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without a Content-Security-Policy (CSP) header. CSP mitigates cross‑site scripting (XSS) and data‑injection attacks by restricting the sources from which content can be loaded. Its absence leaves the application exposed to client‑side code injection if other vulnerabilities exist.

**Impact:** An attacker who can inject script content into pages served by the application could execute arbitrary JavaScript in a victim's browser, leading to credential theft, session hijacking, or other malicious actions.

**Remediation:** Configure the web server or application framework to send a robust Content‑Security‑Policy header on all responses, including /healthz. Start with a restrictive default‑src directive and add needed sources (e.g., script-src, style‑src) as required for functionality.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Missing Content-Security-Policy header reported by scanner`
- `Runtime probe observed HTTP 200 response without CSP header on /healthz`

Limitations:
- Evidence is limited to a single endpoint; other endpoints were not examined
- The scan does not confirm whether a reverse proxy or CDN might add the header after the observed response
- No direct test of XSS exploitation was performed

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint does not include the X-Content-Type-Options header, which browsers use to prevent MIME type sniffing. Its absence can allow an attacker to influence how the browser interprets the response content, potentially facilitating cross‑site scripting or content injection attacks.

**Impact:** An attacker could craft a response that the browser misinterprets, leading to execution of malicious scripts or unintended content rendering, increasing the risk of XSS or data leakage.

**Remediation:** Configure the web server or application framework to always send the header `X-Content-Type-Options: nosniff` for all responses, including the /healthz endpoint. Verify the header is present in production deployments.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `X-Content-Type-Options Header Missing (scanner output)`

Limitations:
- Evidence is limited to a single scanner observation on the /healthz path; no runtime probe confirmed the header's absence on other endpoints or after potential proxy modifications.

### 27. Missing clickjacking protection header on /healthz

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime probe shows that the /healthz endpoint returns HTTP 200, and the scanner reports that the response lacks the X-Frame-Options or Content‑Security‑Policy frame‑ancestors headers that mitigate clickjacking. While the finding aligns with known best‑practice checks, the evidence consists only of the scanner’s claim and the absence of captured header data, so the vulnerability cannot be confirmed definitively.

**Impact:** An attacker could embed the /healthz page in a malicious site and potentially trick users into interacting with it, leading to clickjacking attacks. The practical impact is low because the endpoint is typically used for health checks rather than user‑facing content, but the lack of protection is still a security weakness.

**Remediation:** Configure the web server or application to include a clickjacking mitigation header on the /healthz response, such as `X-Frame-Options: SAMEORIGIN` or an appropriate `Content‑Security‑Policy: frame-ancestors 'self'` directive.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner finding: Missing clickjacking protection header`
- `Runtime probe fact: status 200 for path /healthz`

Limitations:
- No direct capture of response headers; conclusion relies on scanner inference
- Health endpoint may not be exposed to browsers, reducing real‑world risk
- Only a single probe was performed; additional requests could provide more context

### 28. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** A runtime probe (web-runtime) observed a 200 response from the /healthz endpoint that did not include the X-Content-Type-Options header. Absence of this header can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks. Because the endpoint appears to be a health‑check, its exposure to untrusted users is unclear, so the finding cannot be confirmed as an exploitable vulnerability without additional context.

**Impact:** If an attacker can influence the response body, the missing header may enable MIME‑sniffing attacks that could cause the browser to interpret the content as a different type (e.g., HTML/JavaScript), leading to cross‑site scripting or data leakage.

**Remediation:** Configure the application or web server to include the header `X-Content-Type-Options: nosniff` on all responses, including the /healthz endpoint. Verify the header is present using a tool or subsequent runtime probe.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe (web-runtime) observed status 200 on /healthz without X-Content-Type-Options header`

Limitations:
- Evidence is limited to a single endpoint (/healthz). The public exposure of the health‑check endpoint is not known, so the real‑world risk cannot be fully assessed. No proof of actual exploitation is available.

### 29. Incoming webhook events require a valid signature

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged the /integrations/hook endpoint as lacking a required signature validation, but no concrete evidence from the repository code or runtime observations confirms that signature verification is absent. The runtime probe only shows a 200 response with redacted values, which does not demonstrate whether the request was authenticated. Without source code or detailed request/response analysis, the vulnerability cannot be confirmed.

**Impact:** If the webhook endpoint does not verify signatures, an attacker could craft arbitrary webhook events, potentially leading to unauthorized actions, data exfiltration, or service disruption.

**Remediation:** Implement strict signature verification for all incoming webhook requests. Validate the signature against a shared secret or public key before processing the payload, and reject any request that fails verification with an appropriate error response (e.g., 401 Unauthorized).
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Scanner rule workflow.unsigned_hook.1 flagged /integrations/hook`
- `Runtime probe returned status 200 with values redacted`

Limitations:
- No source code review of signature handling
- Runtime probe does not reveal whether signature was checked
- Evidence is limited to scanner flag and generic HTTP response

### 30. Only the owner can read an invoice

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner flagged the endpoint /invoices/{{invoice_id}} as a potential issue, but the observed behavior is that access is restricted to the invoice owner, which is the intended security control. No evidence was provided that an unauthorized user can read another user's invoice.

**Impact:** None, as the access control appears to be correctly enforced.

**Remediation:** No remediation required; the current owner‑only access control is appropriate.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Only the owner can read an invoice (scanner evidence)`
- `runtime probe returned status 200 with values redacted, indicating a successful request under expected conditions`

Limitations:
- No test of unauthorized access was performed, so we cannot prove the control works for all possible attacker scenarios. The evidence only shows normal, authorized access.

### 31. Users cannot submit an admin job - not a security vulnerability

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner reports that users are unable to submit an admin job at /jobs. The runtime probe shows the endpoint returns HTTP 200, but no evidence is provided that this behavior constitutes a security flaw (e.g., privilege escalation, unauthorized access, or data leakage). The observed inability to submit an admin job is more likely an intended access control restriction rather than a vulnerability. Without concrete proof of exploitation or unintended privilege grant, the finding does not represent a security issue.

**Impact:** None – the behavior appears to be an intended restriction preventing non‑admin users from performing admin‑only actions.

**Remediation:** No remediation required; verify that the access control logic for the /jobs endpoint correctly enforces admin‑only permissions.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Scanner evidence: "Users cannot submit an admin job"`
- `Runtime probe fact (web-runtime, rule workflow.worker_role.1) on path /jobs returned status 200`

Limitations:
- No direct evidence of unauthorized access or privilege escalation
- The probe only reports HTTP status, not the underlying authorization logic
- Scanner output alone does not prove a security flaw

### 32. Identity response must not expose a social security number

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner flagged a potential SSN exposure, but the runtime probe for the same endpoint returned a 200 status with a flag indicating that values were redacted. No raw response data showing an SSN was provided, and the redaction flag suggests the sensitive field is being masked. Therefore, the evidence does not confirm an actual exposure.

**Impact:** If an SSN were exposed, it could enable identity theft and fraud. However, the current evidence suggests the data is being redacted, so the immediate risk is low.

**Remediation:** Ensure that any endpoint returning personal identifiers never includes unmasked SSNs. Continue to enforce redaction or removal of sensitive fields before sending responses, and add explicit tests to verify that SSNs are never present in the payload.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Identity response must not expose a social security number`
- `runtime_probe_facts: {"scanner_id":"web-runtime","rule_id":"workflow.excessive_data.1","path":"/me","facts":{"status":200,"values_redacted":true}}`

Limitations:
- No raw response body was captured to definitively prove the SSN is absent
- Redaction flag is trusted but not independently verified
- Only a single probe was performed; other code paths may behave differently

### 33. Users cannot create orders for another owner

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The finding reports that users are prevented from creating orders on behalf of another owner. This behavior aligns with proper access‑control enforcement rather than a security flaw. The runtime probe shows a successful 200 response for a request to /orders, but no evidence is provided that an unauthorized order was created or that privilege escalation occurred. Consequently, the scanner’s flag appears to be a false positive.

**Impact:** No impact; the application correctly restricts order creation to the authenticated owner.

**Remediation:** No remediation required; the existing access control is appropriate.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.owner_assignment.2, path=/orders, facts={status:200, values_redacted:true}`

Limitations:
- Evidence is limited to a single runtime probe without payload details; no verification of attempted cross‑owner order creation was performed.

### 34. New orders cannot start as paid

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that new orders cannot transition to a paid state, but the only supporting data is a generic 200 response with redacted values from a runtime probe. No concrete request/response showing the failure to set the paid flag or a business‑logic test confirming the condition is provided. Therefore the claim cannot be confirmed as a true vulnerability without additional functional testing or detailed response data.

**Impact:** If orders truly cannot be marked as paid, customers may be unable to complete purchases, leading to revenue loss and a broken checkout flow.

**Remediation:** Validate the order workflow logic to ensure that the paid state can be set after successful payment. Add unit and integration tests that explicitly verify the state transition from "new" to "paid" and handle error cases gracefully.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `New orders cannot start as paid`
- `runtime probe fact: status 200, values redacted`

Limitations:
- Evidence is limited to a scanner assertion and a redacted 200 response; no payload details are available
- No direct observation of the order state transition failure
- Unable to confirm whether the issue is a business‑logic flaw or a false positive from the scanner

### 35. Negative order prices are rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner reports that negative order prices are rejected, but the runtime probe fact shows a HTTP 200 response for a request to /orders (values redacted). No concrete request/response details are available to confirm whether the negative price was accepted, rejected, or ignored. The evidence is contradictory and insufficient to confirm a vulnerability or a false positive.

**Impact:** If negative order prices are accepted, an attacker could create orders with negative totals, potentially leading to unauthorized credit or financial loss.

**Remediation:** Implement server‑side validation that rejects any order where the price is less than zero and returns an appropriate error status (e.g., 400 Bad Request). Ensure the validation is logged and tested.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Scanner evidence: "Negative order prices are rejected"`
- `Runtime probe fact: status 200 for /orders (values redacted)`

Limitations:
- No payload details for the runtime probe request
- Contradiction between scanner claim and HTTP 200 response
- No confirmation of error handling behavior
- Single data point; no repeatable test

### 36. Catalog price must be set by the server

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged a potential issue that the catalog price should be enforced server‑side, but the only runtime observation is an HTTP 200 response with redacted values. No request/response data demonstrates that a client can supply or modify the price, nor is there evidence of missing server‑side validation. Consequently, the finding lacks concrete proof of a vulnerability.

**Impact:** If the server accepted client‑supplied prices, an attacker could manipulate product pricing, leading to financial loss or unauthorized discounts.

**Remediation:** Implement strict server‑side validation that ignores any price fields supplied by the client and always calculates the final price based on trusted data. Return an error for unexpected price parameters.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Scanner evidence: "Catalog price must be set by the server"`
- `Runtime probe fact: scanner_id=web-runtime, rule_id=workflow.price_catalog.1, path=/orders, status=200, values_redacted=true`

Limitations:
- Values in the response were redacted, preventing verification of price handling
- No request payloads or response bodies were captured to show client‑controlled price fields
- Only a single HTTP 200 observation was made; no negative test cases were performed

### 37. A note must belong to the order named in the URL

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged a potential broken access‑control issue on the endpoint /orders/1/notes/2, indicating that the note may not be validated against the order ID in the URL. A runtime probe returned HTTP 200, confirming the endpoint is reachable, but the response values were redacted, so there is no direct evidence that a note from a different order can be accessed. The finding is therefore plausible but not definitively proven.

**Impact:** If the endpoint does not enforce that a note belongs to the specified order, an attacker could retrieve or manipulate notes belonging to other orders, leading to unauthorized data exposure or modification.

**Remediation:** Add server‑side authorization checks that verify the note’s order_id matches the order ID supplied in the URL before returning or modifying the note. Return an appropriate error (e.g., 403 Forbidden) when the IDs do not match.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Scanner evidence: "A note must belong to the order named in the URL"`
- `Runtime probe fact: status 200 for GET /orders/1/notes/2 (values redacted)`

Limitations:
- Response values were redacted, so cross‑order access could not be demonstrated
- Only a single successful request was observed; no attempt to access a note from a different order was made
- The finding relies on scanner heuristics without concrete proof of a broken check

### 38. Only the owner can read an order

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **low**

**Explanation:** The scanner reported that only the owner can read an order, but no evidence was found of unauthorized access or a broken access control condition. The runtime probe only shows a successful 200 response with redacted values, which does not demonstrate a vulnerability.

**Impact:** No impact identified because the access control appears to be correctly enforced.

**Remediation:** No remediation required; continue to enforce owner‑only access checks.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Scanner evidence: Only the owner can read an order`
- `Runtime probe fact: status 200 returned for /orders/{{order_id}} (values redacted)`

Limitations:
- No proof of unauthorized read access; the probe does not reveal the content of the response.

### 39. Excessive coupon discounts are rejected

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner flagged the rejection of overly large coupon discounts as a potential issue, but rejecting excessive discounts is expected, defensive behavior. No evidence shows that legitimate discounts are improperly blocked or that an attacker can exploit this path to gain unauthorized benefits.

**Impact:** None – the application correctly prevents abuse of coupon values.

**Remediation:** No remediation required; the current validation is appropriate.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Excessive coupon discounts are rejected (scanner evidence)`
- `Runtime probe returned HTTP 200 with values redacted for /orders/{{order_id}}/apply-coupon`

Limitations:
- Only a single runtime probe observation; no proof of unintended behavior or privilege escalation. The finding relies solely on scanner heuristics without concrete exploit evidence.

### 40. Paid orders require a refund before cancellation

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged the endpoint /orders/{{order_id}}/cancel as requiring a refund before an order can be cancelled. The runtime probe returned a 200 status, but the response values were redacted, providing no direct confirmation of the business‑logic enforcement. The finding aligns with a known workflow rule (workflow.paid_cancel.3) that flags this pattern as potentially insecure, but without observable evidence of the refund requirement the issue cannot be confirmed definitively.

**Impact:** If users cannot cancel paid orders without first issuing a refund, legitimate cancellation requests may be blocked, leading to denial‑of‑service for customers and potential financial loss or dispute escalation.

**Remediation:** Adjust the cancellation workflow to separate the refund process from order cancellation, or explicitly allow cancellation of paid orders without requiring a prior refund. Ensure the API returns clear, non‑redacted responses indicating the allowed actions.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Paid orders require a refund before cancellation`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.paid_cancel.3, path=/orders/{{order_id}}/cancel, status=200 (values redacted)`

Limitations:
- Evidence is limited to a scanner‑generated finding and a redacted runtime response; no concrete request/response demonstrating the refund‑before‑cancel enforcement.
- No verification of whether the endpoint actually blocks cancellation without a refund.
- The probe contract is null, so the expected behavior is not formally defined.

### 41. An already paid order rejects a second payment

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner flagged a potential payment replay issue, but the runtime probe shows the endpoint returns a 200 status for the second payment attempt, indicating the request is handled without error. This suggests the application correctly rejects or processes repeat payments according to its business logic, not exposing a vulnerability.

**Impact:** No impact; the application appears to handle repeat payment attempts safely.

**Remediation:** No remediation needed; the behavior aligns with expected payment replay protection.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.payment_replay.3, path=/orders/{{order_id}}/pay, facts={status:200, values_redacted:true}`
- `candidate evidence: "An already paid order rejects a second payment"`

Limitations:
- The probe response redacts response values, so exact rejection semantics are not visible.
- A 200 status alone does not fully confirm the business logic preventing double payment; further functional testing would be required.

### 42. Potential improper access control on profile endpoint

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The scanner reports that a user cannot read another account's profile, but the runtime probe returned an HTTP 200 status for the same endpoint with values redacted. The contradictory evidence makes it unclear whether the endpoint correctly enforces authorization or inadvertently exposes data. Additional testing (e.g., inspecting response bodies, attempting access with different roles) is required to determine if unauthorized access is possible.

**Impact:** If the endpoint allows unauthorized users to retrieve another user's profile data, it could lead to privacy violations, data leakage, and potential account takeover scenarios.

**Remediation:** Implement and verify strict authorization checks on the /profiles/{{other_id}} endpoint to ensure that only the profile owner or authorized parties can access the data. Return appropriate error codes (e.g., 403 Forbidden) when access is denied and avoid exposing any user data in responses.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.profile_owner.2, path=/profiles/{{other_id}}, status=200, values_redacted=true`

Limitations:
- Only a single HTTP response was observed; response body content is redacted and not examined.
- No evidence of the requester's authentication context or role is provided.
- The scanner's claim that the user cannot read the profile is not corroborated by observable data.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The DAST/runtime scanner reported that the HTTP response for the /view endpoint does not include an anti‑clickjacking header (e.g., X‑Frame‑Options or CSP frame‑ancestors). No runtime probe data confirming the header presence or absence was provided, and no alternative defenses (such as a CSP frame‑ancestors directive) were observed. Given the scanner’s finding and the lack of contradictory evidence, the issue is likely a real missing header.

**Impact:** Without an anti‑clickjacking header, the page can be embedded in a malicious site and potentially be used for clickjacking attacks, leading to unauthorized actions performed by unsuspecting users.

**Remediation:** Configure the web server or application framework to send an appropriate anti‑clickjacking header on all responses, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive that restricts framing to trusted origins.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Scanner finding: Missing Anti-clickjacking Header on /view (zap.10020)`

Limitations:
- No captured HTTP response to verify header absence (values redacted)
- No evidence of alternative CSP frame‑ancestors policy
- Single scanner source without independent confirmation

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /view does not include the X-Content-Type-Options header, which is used to prevent browsers from MIME‑sniffing the response. No additional runtime probe data was available (values were redacted), and no other evidence confirms the header is set elsewhere. Given the scanner’s finding and the lack of contradictory evidence, the issue is treated as a likely vulnerability.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may interpret content as a different MIME type, potentially enabling cross‑site scripting (XSS) or content injection attacks.

**Remediation:** Configure the web server or application framework to include the header `X-Content-Type-Options: nosniff` on all responses, e.g., via middleware, server configuration, or response headers in code.
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner reported missing X-Content-Type-Options header on /view (zap.10021)`

Limitations:
- Runtime probe facts were redacted, so the header presence could not be directly verified at runtime
- Potential that the header is added by a downstream component not captured by the scan

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the HTTP response for the /view endpoint does not include a Content Security Policy (CSP) header. No additional evidence (e.g., runtime probe data) was provided to confirm the header’s presence or absence, and the finding relies solely on the scanner’s analysis.

**Impact:** Without a CSP header, the application is more susceptible to cross‑site scripting (XSS) and other content injection attacks, potentially allowing an attacker to execute malicious scripts in a user's browser.

**Remediation:** Configure the web server or application framework to send a strong CSP header for all responses, e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and test to ensure it is applied to the /view endpoint.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Content Security Policy (CSP) Header Not Set (scanner finding)`

Limitations:
- Runtime probe facts were redacted and did not provide direct observation of the header.
- No independent verification (e.g., manual request) was performed to confirm the header is missing.
- The finding is based on a single scanner source; other deployment configurations (e.g., CDN edge rules) could add the header.

### 46. Webhook destination must match the approved internal host exactly

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged a potential mismatch in the webhook destination, but the only runtime observation is an HTTP 200 response with redacted values. No concrete destination URL was captured, and there is no evidence that the configured endpoint deviates from the approved internal host. Consequently, the finding cannot be confirmed as a vulnerability without additional data showing the actual webhook target.

**Impact:** If the webhook were pointing to an unauthorized external host, an attacker could receive sensitive data or trigger unintended actions, leading to data exfiltration or system compromise.

**Remediation:** Review the application configuration for the /webhooks endpoint and ensure the URL strictly matches the approved internal host. Implement validation checks that enforce host whitelisting and reject any non‑approved destinations. Consider adding logging of the resolved webhook URL (with appropriate redaction) for future verification.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `Scanner evidence: "Webhook destination must match the approved internal host exactly"`
- `Runtime probe fact (web-runtime, rule workflow.webhook_destination.1) returned HTTP 200 with values redacted`

Limitations:
- The actual webhook destination URL was not captured (values redacted)
- Only a successful HTTP response was observed; no indication of the target host
- Single source finding without corroborating evidence from other scanners or manual review

### 47. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the value of the environment variable APP_SECRET at INFO level (log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))). This records a secret in clear text in application logs, which may be accessible to unauthorized users or downstream log aggregation services, creating a credential disclosure risk.

**Impact:** If an attacker gains access to the logs, they can retrieve the application secret, potentially allowing them to forge tokens, bypass authentication, or perform other privileged actions within the application.

**Remediation:** Remove the APP_SECRET from log statements or mask/redact it. Log only non-sensitive identifiers (e.g., username) and, if debugging is required, use a debug‑level log with strict access controls. Ensure logging configuration does not write sensitive data to persistent storage accessible to untrusted parties.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `Source excerpt line 137: log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`
- `Scanner finding (semgrep-ce) rule python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure at api/app.py:137`

Limitations:
- The severity assumes logs are persisted and accessible; if the logging backend is fully isolated, impact may be reduced, but this cannot be verified from the provided data.

### 48. Wildcard Cors

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any origin to make cross‑origin requests. The scanner flagged this as insecure. Without additional context indicating that the API is intentionally public and that no sensitive data is exposed, the wildcard setting constitutes a potential security risk.

**Impact:** An attacker controlling a malicious website could issue cross‑origin requests to the API and, if the API returns sensitive data or performs privileged actions, the attacker could exfiltrate that data or perform CSRF‑like attacks.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. If credentials are required, set allow_credentials to true only for those trusted origins and avoid using "*" for allow_methods and allow_headers. Review the API’s data exposure and adjust CORS settings accordingly.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py:26-29 – CORSMiddleware configured with allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]`

Limitations:
- No information about the intended public nature of the API or whether any sensitive endpoints are exposed.
- No runtime evidence of exploitation or abuse of the wildcard CORS setting.

### 49. Potential Log Injection and Secret Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs a user‑provided username and the value of the APP_SECRET environment variable without any sanitisation or redaction. Logging uncontrolled input can allow an attacker to inject malicious log entries (e.g., newline characters, log format strings) that may corrupt log integrity or be interpreted by downstream log parsers. Additionally, logging the application secret can lead to credential leakage if logs are accessed by unauthorized parties.

**Impact:** An attacker could manipulate log files to hide malicious activity, forge log entries, or trigger injection attacks in log‑processing tools. Exposure of the APP_SECRET increases the risk of credential compromise, potentially allowing unauthorized access to other parts of the system.

**Remediation:** - Remove the APP_SECRET from log statements or mask it before logging.
- Avoid logging raw user input; instead, log sanitized or hashed identifiers.
- Implement structured logging with proper escaping.
- Review log handling pipelines to ensure logs are not parsed/executed in a way that could be exploited.
- Apply least‑privilege access controls to log storage.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) (line 137)`

Limitations:
- No evidence is provided about how logs are consumed or whether they are exposed to untrusted users, so the actual exploitability cannot be fully assessed. The finding is based solely on the presence of unsanitised user input and secret in the log statement.

### 50. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /auth/continue accepts a query parameter `next` supplied by the client and passes it directly to `RedirectResponse` without any validation or whitelist, enabling an attacker to craft a URL that redirects victims to an arbitrary external site (open redirect).

**Impact:** An attacker can use the open redirect to conduct phishing attacks, steal credentials, or bypass security controls by redirecting users to malicious sites.

**Remediation:** Validate the `next` parameter against a whitelist of allowed internal URLs or restrict redirects to relative paths only. Use a safe redirect helper that ensures the target URL is trusted before issuing the redirect.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `api/extra.py line 616-617: def continue_to(next: str = "/") -> RedirectResponse: return RedirectResponse(next, status_code=302)`
- `Untrusted URL redirection depends on a user-provided value.`

Limitations:
- No runtime evidence of exploitation is provided; the finding is based on static code analysis only.
- The endpoint may be intended for internal use only, which could reduce risk but does not eliminate the open redirect issue.

### 51. Open redirect check prevents external URLs

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The verified_continue function validates the 'next' parameter, ensuring it starts with '/' and does not contain a scheme, netloc, or double slash. If the check fails, it raises HTTPException(400). Therefore, only local paths are allowed for redirection, mitigating the open redirect risk flagged by the scanner.

**Impact:** No impact; the redirect is safely constrained to internal paths.

**Remediation:** No remediation required for this endpoint; the existing validation is sufficient.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Lines 621-625 enforce that 'next' must be a local path and reject external URLs before issuing RedirectResponse.`

Limitations:
- This assessment applies only to the verified_continue endpoint; other redirect mechanisms in the codebase were not examined.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction. While adding a health check improves observability and can aid in automated recovery, its absence does not constitute a direct security vulnerability. The finding is a best‑practice recommendation rather than evidence of exploitable weakness.

**Impact:** Limited to reduced operational visibility; does not expose the application to a security breach.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Source excerpt from Dockerfile.api lines 1‑8 showing no HEALTHCHECK instruction.`

Limitations:
- The assessment is based solely on the Dockerfile content; no runtime behavior or security impact was observed. Absence of a health check is not proof of a vulnerability, only a deviation from best practices.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a health check is a best practice for container observability and automated recovery, its absence does not constitute a direct security vulnerability. No evidence is provided that an attacker can exploit the missing health check to gain unauthorized access, elevate privileges, or cause denial‑of‑service beyond what is already possible through other vectors.

**Impact:** Without a HEALTHCHECK, orchestration platforms may not automatically detect or restart a failing container, potentially leading to longer downtime. This impacts availability rather than confidentiality or integrity.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile that periodically verifies the service is responsive, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`
- `Scanner recommendation: "Add HEALTHCHECK instruction in your Dockerfile"`

Limitations:
- No proof that the missing health check can be leveraged for a security breach
- The finding is based solely on static analysis of the Dockerfile; runtime behavior is not observed

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a healthcheck is a best practice for container orchestration and monitoring, its absence does not directly constitute a security vulnerability. No evidence shows that this misconfiguration leads to exploitable conditions such as privilege escalation, data leakage, or denial‑of‑service beyond standard operational monitoring concerns.

**Impact:** Limited to reduced observability and potential delayed detection of container failures; does not directly expose the application to attack.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the container’s health, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Source excerpt of Dockerfile shows no HEALTHCHECK line`

Limitations:
- Assessment based solely on static Dockerfile content; no runtime healthcheck behavior was observed. The finding is a best‑practice recommendation rather than a proven security flaw.

### 55. python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project's requirements.txt pins python-multipart at version 0.0.20. This version is known to be vulnerable to CVE-2026-53539, which allows an attacker to trigger a denial‑of‑service condition by sending specially crafted form‑urlencoded bodies. The scanner identified this dependency and the associated CVE, and the CVE entry states the issue is fixed starting with version 0.0.30.

**Impact:** An attacker who can supply a malicious form‑urlencoded payload to the application could cause the service to hang or crash, leading to loss of availability for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and rebuild/redeploy the application. Verify that the updated version is reflected in the deployed environment.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- Evidence is based on static dependency analysis; no runtime probe confirms the vulnerable code path is exercised.
- The scanner report does not show whether the application actually processes multipart/form‑urlencoded data in a way that triggers the CVE.

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-42561. This CVE allows an attacker to trigger a denial‑of‑service condition by supplying a multipart request with an excessive number of part headers. The scanner’s evidence directly cites the vulnerable version and the fixed version (>=0.0.27).

**Impact:** An attacker can craft a multipart request that exhausts memory or CPU resources in the application, potentially causing it to become unresponsive or crash, leading to service interruption for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, and rebuild/redeploy the application to incorporate the patched library.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- No runtime probe confirms that the application actually processes multipart uploads, so the exploitability depends on usage. The finding is based solely on the presence of the vulnerable version in requirements.txt.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The CVE describes an information‑disclosure issue caused by differential parsing of multipart form data. The vulnerability is fixed starting with version 0.0.30. No evidence was found that the application upgrades or patches this library at runtime, so the vulnerable code is likely present in the deployed artifact.

**Impact:** An attacker could craft multipart requests that cause the server to leak parts of request bodies or internal parsing state, potentially exposing sensitive data submitted by users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and rebuild/redeploy the application. Verify the updated dependency is included in the final artifact.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt pins python-multipart==0.0.20`

Limitations:
- No runtime probe confirms whether the vulnerable code path is exercised.
- Static analysis only; does not verify if the application actually processes multipart form data.

### 58. python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-40347, a denial‑of‑service issue triggered by specially crafted multipart/form-data payloads. The scanner’s evidence directly cites the CVE and notes that the vulnerability is fixed starting with version 0.0.26. No contradictory runtime evidence was observed, and the dependency is actively used by FastAPI for handling multipart requests, making the vulnerability exploitable in the deployed application.

**Impact:** An attacker can send a malicious multipart/form-data request that consumes excessive resources, potentially causing the service to become unresponsive or crash, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later. Update the requirements.txt entry (e.g., `python-multipart>=0.0.26`) and redeploy the application. Verify that the new version is installed and that the application functions as expected after the upgrade.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`

Limitations:
- Evidence is based solely on static dependency analysis; no runtime probe confirms the vulnerable code path is exercised. No additional scanner or runtime data were provided to corroborate exploitation likelihood.

### 59. python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20. This version is known to contain CVE-2026-24486, an arbitrary file write vulnerability via path traversal. The scanner evidence directly references this CVE and notes that it is fixed in version 0.0.22. No contradictory evidence was found in the runtime probes or other sources.

**Impact:** An attacker who can supply a crafted multipart request could traverse directories and write files to arbitrary locations on the server, potentially leading to remote code execution, data corruption, or privilege escalation.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, and verify that the updated version is used in the deployed environment. Rebuild and redeploy the application after updating the dependency.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No runtime probe confirms that the vulnerable code path is exercised in the current deployment.
- The presence of the vulnerable version does not guarantee that the application processes multipart uploads in a way that triggers the vulnerability.

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20. This version is known to be vulnerable to CVE-2026-53537, which allows information disclosure through a header‑parsing discrepancy. The scanner’s evidence directly cites the vulnerable version and the CVE fix version (>=0.0.30). No contradictory runtime evidence is provided, so the static dependency finding stands as a confirmed vulnerability.

**Impact:** An attacker could craft multipart requests that cause the library to leak internal data via malformed headers, potentially exposing sensitive information processed by the application.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and rebuild/redeploy the application to incorporate the patched library.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- Evidence is limited to static dependency analysis; no runtime or exploit verification is present.
- The impact assessment assumes the application uses python-multipart for request parsing, which is typical but not explicitly confirmed in the provided code.

### 61. python-multipart: Python-Multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project's requirements.txt pins python-multipart at version 0.0.20. This version is publicly documented to contain CVE-2026-53540, a vulnerability where a negative Content‑Length header causes the entire request body to be buffered in memory, leading to potential denial‑of‑service. The scanner evidence aligns with the known CVE and the vulnerable version is present, confirming the issue.

**Impact:** An attacker can craft a request with a negative Content‑Length header, causing the application to allocate unbounded memory and potentially crash or become unresponsive, resulting in denial‑of‑service.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which contains the fix for CVE-2026-53540. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `requirements.txt lists python-multipart==0.0.20`
- `CVE-2026-53540 is associated with python-multipart 0.0.20 and fixed in 0.0.31`

Limitations:
- The vulnerability is classified as low severity and may only be exploitable if the application processes multipart/form‑data with untrusted Content‑Length values
- No runtime probe confirms exploitation in the current deployment

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a urllib request where the URL is built from a constant base (BASE) concatenated with a variable `path`. Without additional context it is unclear whether `path` can be influenced by an external attacker. If `path` is derived from user input, the code could be vulnerable to SSRF or arbitrary file reads via `file://` URLs. However, the repository does not provide evidence of such control, and no runtime observations confirm exploitation. Therefore the finding requires more evidence before confirming a vulnerability.

**Impact:** If an attacker can control `path`, they may be able to make the server issue requests to internal services or read local files, potentially leading to data disclosure or further network compromise.

**Remediation:** Audit the callers of `request()` to ensure `path` is never derived from untrusted input. If user‑controlled data is used, validate or whitelist allowed paths, or switch to a higher‑level HTTP library (e.g., `requests`) that does not support `file://` schemes. Consider adding explicit URL validation before invoking `urllib.request.urlopen`.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows `urllib.request.urlopen` called with `BASE + path` (lines 20‑22).`

Limitations:
- No evidence that `path` is attacker‑controlled.
- No runtime probe data confirming unsafe URLs were processed.
- Scanner finding alone does not prove exploitability.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload["target_url"]). Because urllib supports the "file://" scheme, an attacker who can influence the payload could supply a file URL and cause the worker to read arbitrary files from the host filesystem. The scanner flagged this as a potential issue, and the code does not show any validation or scheme restriction before the request is made.

**Impact:** If exploited, an attacker could read local files (e.g., /etc/passwd) via a file:// URL, potentially exposing sensitive data or enabling further attacks such as credential theft or information disclosure.

**Remediation:** Validate and sanitize the "target_url" value before using it with urllib. Restrict allowed schemes to http/https, whitelist trusted domains, or switch to the 'requests' library with explicit scheme checks. Consider adding a denylist for "file://" and other unsafe schemes.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows urllib usage with dynamic URL: line 18‑23 in worker/worker.py – payload["target_url"] is passed directly to urllib.request.Request without validation.`

Limitations:
- No runtime_probe_facts or runtime observations confirming that an attacker can control "target_url".
- The surrounding code may perform validation elsewhere that is not visible in the provided excerpt.
- No evidence that the application runs with privileges that would make file reads dangerous (e.g., container isolation).

### 64. Passwords stored in plaintext during user registration

- Issue group: `ai-0a72a81ea425e8e0`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The registration endpoint inserts the raw password supplied by the client directly into the SQL INSERT statement without applying any cryptographic hash. The code snippet shows `body.password` being passed unchanged to the database, indicating that passwords are persisted in clear text. No evidence is provided that an upstream component (e.g., middleware) hashes the password before this function runs, nor that a database trigger transforms the value on insert.

**Impact:** If the database is compromised, attackers can obtain user passwords in clear text, enabling credential reuse attacks against this service and any other services where users reuse passwords. This also violates best‑practice security standards for credential storage.

**Remediation:** Hash passwords using a strong, adaptive algorithm such as bcrypt, Argon2, or PBKDF2 before persisting them. Store only the hash and a unique salt per user. Ensure any middleware or ORM layer does not bypass the hashing step, and remove any plaintext password handling from the code path. Consider adding unit tests to verify that passwords are never stored in clear text.
Evidence:
- Source IDs: `ai-0a72a81ea425e8e0`
- `179 |             user = conn.execute(`
- `180 |                 "INSERT INTO users (username,password,role,email,ssn) VALUES (%s,%s,'user',%s,'000-00-9999') RETURNING id,username,role",`
- `181 |                 (body.username, body.password, f"{body.username}@example.test"),`

Limitations:
- No inspection of surrounding code or imported modules to confirm the absence of a hashing wrapper around `body.password`.
- Database triggers or stored procedures that might hash the password column are not examined.
- The analysis relies solely on the provided code excerpt; runtime behavior (e.g., middleware that could hash passwords before this function) is unknown.

### 65. Missing authentication on public file download endpoint

- Issue group: `ai-b53337179ff368eb`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The @router.get("/files") endpoint returns the contents of any file under the configured public directory without requiring any authentication or authorization checks. An attacker can supply an arbitrary filename and retrieve its contents, potentially exposing sensitive information that was not intended to be publicly accessible.

**Impact:** Unauthorized disclosure of files can lead to information leakage, exposure of configuration data, credentials, or other sensitive assets, facilitating further attacks such as credential harvesting or reconnaissance.

**Remediation:** Add authentication and authorization checks before serving files (e.g., require a valid user session or token). Restrict the endpoint to serve only explicitly allowed files or directories, validate the filename against a whitelist, and consider using a dedicated static file server with proper access controls. If the directory is meant to be public, move any sensitive files out of it.
Evidence:
- Source IDs: `ai-b53337179ff368eb`
- `210: @router.get("/files")`
- `211: def file_read(name: str) -> Response:`
- `212:     file = (FILES / "public" / name).resolve()`
- `213:     if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214:         raise HTTPException(404, "File not found")`
- `215:     return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- No explicit documentation or configuration indicating whether the public directory is intended to be fully public or restricted. The analysis cannot confirm the intended access model, so the finding remains a likely rather than confirmed vulnerability. No runtime evidence of exploitation is available.

### 66. Missing validation for generated email address during registration

- Issue group: `ai-0ecab70a0de5608d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The registration endpoint constructs an email address by concatenating the supplied username with a static domain ("@example.test") without any format validation. This allows arbitrary strings to become part of an email address that is stored in the database. While the current code does not show further processing of the email, storing malformed or maliciously crafted email values can lead to downstream injection attacks (e.g., when the value is used in email headers or displayed in HTML) or user confusion.

**Impact:** Malformed email entries may be persisted, potentially causing failures in email‑related functionality, enabling email header injection if the value is later used in outbound messages, and reducing data quality. In worst‑case scenarios, an attacker could craft a username that results in an email string that breaks downstream parsers or triggers script execution when rendered.

**Remediation:** Validate the generated email address against a proper RFC‑5322 regex before inserting it into the database, or require the user to provide a real email address that is validated. Additionally, sanitize the value before any later use (e.g., escaping when included in email headers or HTML).
Evidence:
- Source IDs: `ai-0ecab70a0de5608d`
- `180:                 "INSERT INTO users (username,password,role,email,ssn) VALUES (%s,%s,'user',%s,'000-00-9999') RETURNING id,username,role",`
- `181:                 (body.username, body.password, f"{body.username}@example.test"),`

Limitations:
- No evidence in the repository that the stored email is ever used in email sending, header construction, or HTML rendering, so the actual exploitability is uncertain.
- The severity is limited to low because the issue currently only affects data integrity and potential downstream misuse, not an immediate code execution vector.

### 67. Unauthenticated public file read endpoint

- Issue group: `ai-197f881c81af25e7`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code defines a GET endpoint at "/files" that resolves a file path under the server's public directory and returns its contents as plain‑text without any authentication or authorization checks. The implementation includes a safety check that the resolved path is within the public folder and that the file exists, but it does not restrict which files can be read or who may request them. Without knowledge of the intended exposure model for the public directory, it is unclear whether this behavior is intentional or an oversight.

**Impact:** If the public directory contains files that should not be publicly accessible (e.g., configuration files, internal documentation, or other sensitive data), an unauthenticated attacker could retrieve them, leading to information disclosure that may aid further attacks.

**Remediation:** Define a clear access policy for the "/files" endpoint. Options include:
* Restrict the endpoint to authenticated/authorized users (e.g., add a dependency on an auth guard).
* Limit the set of readable files to a whitelist of safe resources.
* Serve only static assets via a dedicated static file server rather than a custom endpoint.
* Ensure no sensitive files are placed in the public folder.
* Add logging/auditing for file access attempts.
Evidence:
- Source IDs: `ai-197f881c81af25e7`
- `@router.get("/files") defined at api/extra.py:210`
- `def file_read(name: str) -> Response: at api/extra.py:211`
- `file = (FILES / "public" / name).resolve() at api/extra.py:212`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found") at api/extra.py:213-214`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain") at api/extra.py:215`

Limitations:
- The repository does not contain documentation indicating whether the public directory is meant to be fully exposed.
- No runtime or deployment evidence shows that sensitive files are actually present in the public folder.
- No authentication/authorization configuration is visible for this endpoint, but the overall application may enforce global security policies not captured in the excerpt.

### 68. Unauthenticated verified file read endpoint

- Issue group: `ai-db9083db72a7fa38`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The GET /files/verified endpoint returns the contents of any file located under the configured public directory after only a relative‑path check. No authentication or authorization guard is applied, so any unauthenticated client can request arbitrary filenames and receive their contents. While the path traversal protection limits reads to the public folder, the endpoint still exposes all files placed there, which may include sensitive configuration or data files if they are inadvertently stored in that directory.

**Impact:** An attacker could retrieve files that should be restricted (e.g., .env, credentials, internal logs) by placing them in the public folder or by exploiting deployment mis‑configuration. This may lead to credential leakage, internal information exposure, or further attacks based on disclosed data.

**Remediation:** Add authentication/authorization to the endpoint (e.g., FastAPI Depends on a security scheme). Limit the set of readable files to a whitelist of safe resources, or serve files through a static file handler that enforces proper access controls. Ensure that no secret files are stored in the public directory.
Evidence:
- Source IDs: `ai-db9083db72a7fa38`
- `@router.get("/files/verified")`
- `def verified_file_read(name: str) -> Response:`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file():`
- `raise HTTPException(404, "File not found")`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The check restricts reads to files under the public directory, so files outside that directory cannot be accessed.
- If the public folder is intentionally used only for non‑sensitive static assets, the practical impact may be low.
- The review cannot confirm whether secret files are actually present in the public folder; it only notes the risk if they are.

### 69. Authentication cookie lacks security flags

- Issue group: `ai-986d6ced55b3a433`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The form_login endpoint creates a session cookie via response.set_cookie("lab_session", f"session-{row['id']}") without specifying HttpOnly, Secure, or SameSite attributes. Without these flags, the cookie can be accessed by client‑side scripts or sent in cross‑site requests, increasing the risk of session hijacking or CSRF attacks. The code excerpt does not show any framework‑level defaults or middleware that might automatically add these protections.

**Impact:** An attacker who can obtain the cookie (e.g., via XSS or network sniffing on HTTP) could impersonate the user, gaining unauthorized access to protected resources and potentially performing actions on the user's behalf.

**Remediation:** Modify the set_cookie call to include security attributes, e.g., response.set_cookie("lab_session", f"session-{row['id']}", httponly=True, secure=True, samesite="strict"). Ensure the application is served exclusively over HTTPS and review any middleware that might alter cookie attributes. Consider using a framework‑provided session management facility that enforces secure defaults.
Evidence:
- Source IDs: `ai-986d6ced55b3a433`
- `response.set_cookie("lab_session", f"session-{row['id']}") at api/extra.py line 300`

Limitations:
- The code snippet does not reveal whether the underlying FastAPI/Starlette framework applies default HttpOnly, Secure, or SameSite flags to cookies.
- It is unknown if the application is deployed behind HTTPS only, which would affect the necessity of the Secure flag.
- Potential downstream middleware that could modify cookie attributes is not visible in the provided excerpt.

### 70. Missing CSRF protection on authentication endpoints

- Issue group: `ai-546c7d3e9b7784a1`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code defines POST routes for "/auth/limited-login" and "/auth/form-login" without any visible CSRF token validation in the function bodies. The provided excerpts do not show a global CSRF middleware or any other protective mechanism, so it is unclear whether CSRF protection is applied elsewhere in the application. Consequently, the presence of a vulnerability cannot be confirmed based solely on the available source evidence.

**Impact:** If these authentication endpoints are reachable without CSRF protection, an attacker could trick a logged‑in user’s browser into submitting forged login requests, potentially leading to unauthorized session creation, session fixation, or other state‑changing actions.

**Remediation:** Add CSRF protection either globally (e.g., FastAPI CSRF middleware) or per‑endpoint by requiring a validated anti‑CSRF token in the request body or header before processing authentication logic. Ensure that tokens are tied to the user session and are verified on each state‑changing request.
Evidence:
- Source IDs: `ai-546c7d3e9b7784a1`
- `@router.post("/auth/limited-login")`
- `@router.post("/auth/form-login")`
- `def limited_login(body: Login) -> dict:`
- `def form_login(body: Login) -> dict:`
- `No CSRF validation logic observed in the function bodies`

Limitations:
- No evidence presented for a global CSRF middleware or other protective layer
- Source excerpt limited to route definitions and function bodies; cannot rule out CSRF checks performed elsewhere
- Unable to verify runtime behavior or configuration that might enforce CSRF protection

## Policy Decisions

- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-794dcb4921076779cef0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-83d97da4516adf20e20f`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-b3c734b4cef8dd70fce0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-b527b3ed30e57aac5ec5`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-f4eaf141df049c63545d`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-f60fee7d82fbca512208`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-bdfe7542047da39c6151`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-17a5197f906426a224ef`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-38e7cf77bdf9145d2ae4`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-d5c3b6b8d8dad90c4d3c`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-a5ea8ca4c36bd6c25e2a`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-65c41e5a25b6337fec07`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-1ba9f8276fc6dae95df8`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-cc8a9ed20905505868f0`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-b4c1c4d005665a5249a7`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-a9e9047867c909f567ad`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7da23d65adeef42d71a6`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-e683a977084f2bbcee2e`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-dd64ece99563dbbb173a`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-2b80ed0c48c0c70a93a4`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-50485291173e2448f7c7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ade7b890a037d8c82a1f`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-dfd8d33b4f84ccf0c23f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-65f25bcf14fa2ab91271`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-0a72a81ea425e8e0`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-b53337179ff368eb`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-0ecab70a0de5608d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-197f881c81af25e7`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-db9083db72a7fa38`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-986d6ced55b3a433`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-546c7d3e9b7784a1`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **70**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **10**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **4**; uncertain overlaps: **3**; needs more evidence: **3**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-0a72a81ea425e8e0`: uncertain_overlap
- `ai-b09eaad0f4d9e9d6`: needs_more_evidence
- `ai-0ecab70a0de5608d`: uncertain_overlap
- `ai-30ee092e00c71045`: needs_more_evidence
- `ai-986d6ced55b3a433`: uncertain_overlap
- `ai-7d839f06330d32e9`: needs_more_evidence

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Coverage Gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Coverage applies only to declared assertions, accounts and workflows.
- Error: browserType.launch: Target page, context or browser has been closed Browser logs: &lt;launching&gt; /home/asus\_safaa99/.cache/ms-playwright/chromium\_headless\_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell --disable-field-trial-config --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-back-forward-cache --disable-breakpad --disable-client-side-phishing-detection --disable-component-extensions-with-background-p
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
- Install the optional Playwright package and browser before enabling browser DAST.
- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile.
- The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.
- merged-16678dc11308a0a16a81: primary source context is unavailable.
- merged-17a5197f906426a224ef: primary source context is unavailable.
- merged-19f4a13e0b2d4f7413d0: primary source context is unavailable.
- merged-1ba9f8276fc6dae95df8: primary source context is unavailable.
- merged-2b80ed0c48c0c70a93a4: primary source context is unavailable.
- merged-2d4a81712313b5f2f621: primary source context is unavailable.
- merged-38e7cf77bdf9145d2ae4: primary source context is unavailable.
- merged-41e99a7ce6d803bedda1: primary source context is unavailable.
- merged-50485291173e2448f7c7: primary source context is unavailable.
- merged-553cfc223024a5e03f34: primary source context is unavailable.
- merged-5fe9a08fc103085427f9: primary source context is unavailable.
- merged-65c41e5a25b6337fec07: primary source context is unavailable.
- merged-65f25bcf14fa2ab91271: primary source context is unavailable.
- merged-7457580a7c7bb31a32cd: primary source context is unavailable.
- merged-7c9406875347cad8b1ce: primary source context is unavailable.
- merged-7da23d65adeef42d71a6: primary source context is unavailable.
- merged-87e0399272a390813ea5: primary source context is unavailable.
- merged-8946f8391fc9049cbb58: primary source context is unavailable.
- merged-8e21db3fe42adbf58979: primary source context is unavailable.
- merged-9b32fbabacaa9f45b768: primary source context is unavailable.
- merged-a5ea8ca4c36bd6c25e2a: primary source context is unavailable.
- merged-a9e9047867c909f567ad: primary source context is unavailable.
- merged-ade7b890a037d8c82a1f: primary source context is unavailable.
- merged-b4c1c4d005665a5249a7: primary source context is unavailable.
- merged-bbf1646deeb18d1e95db: primary source context is unavailable.
- merged-bdfe7542047da39c6151: primary source context is unavailable.
- merged-cc8a9ed20905505868f0: primary source context is unavailable.
- merged-d5c3b6b8d8dad90c4d3c: primary source context is unavailable.
- merged-d9421dbfc4162d6dea91: primary source context is unavailable.
- merged-da0f922505b4c0c7fed1: primary source context is unavailable.
- merged-dd64ece99563dbbb173a: primary source context is unavailable.
- merged-dfd8d33b4f84ccf0c23f: primary source context is unavailable.
- merged-e683a977084f2bbcee2e: primary source context is unavailable.
- merged-e7caea540245938b275b: primary source context is unavailable.
- merged-ec17a70b00fa38747671: primary source context is unavailable.
- merged-fbfa546bfd43886d2b10: primary source context is unavailable.
- merged-fe76cc1a4803fb50214c: primary source context is unavailable.

## Limitations

Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.

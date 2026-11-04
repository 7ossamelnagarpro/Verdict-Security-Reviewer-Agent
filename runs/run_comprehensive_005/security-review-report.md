# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-10-31T11:18:11.713519+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **4**.
- AI Discovery warning: Discovery batch 2: AI provider JSON fallback did not match the discovery response schema; retrying with a smaller request.

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

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string without any sanitisation or parameterisation. This enables an attacker to inject arbitrary SQL payloads, potentially bypassing authentication or extracting data.

**Impact:** An attacker can perform authentication bypass, retrieve or modify user records, and execute arbitrary database commands, leading to data breach and privilege escalation.

**Remediation:** Replace string interpolation with parameterised queries or an ORM that safely handles user input. For example, use prepared statements: `SELECT id, username, role FROM users WHERE username = ? AND password = ?` and bind `body.username` and `body.password` as parameters. Additionally, hash passwords and compare hashes instead of storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Source excerpt shows f"SELECT ... WHERE username='{body.username}' AND password='{body.password}'" at line 117.`
- `Scanner categorised this as a SQL injection finding (group_family: sql_injection).`

Limitations:
- The review assumes the database driver executes the query as shown; if the connection layer internally sanitises inputs, the risk may be mitigated, but no such evidence is provided.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code constructs a file path from a user‑provided `name` and then resolves it against a known root directory. It subsequently checks `file.is_relative_to(root)` and `file.is_file()` before reading the file. These checks prevent directory traversal and ensure the target is an existing file within the intended directory, mitigating the reported path traversal risk.

**Impact:** If the checks were ineffective, an attacker could read arbitrary files on the server, leading to data disclosure. However, the use of `Path.is_relative_to` after resolution provides a robust containment check, so the impact is not realized.

**Remediation:** No remediation needed for this specific finding; the existing checks are appropriate. Maintain the use of `Path.resolve()` and `Path.is_relative_to()` for path containment, and ensure the Python version supports these methods.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source_excerpt lines 219‑224 show the containment check `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- The analysis assumes the runtime environment uses a Python version where `Path.is_relative_to` correctly enforces path containment. If an older Python version is used, this method may be unavailable, which could affect the check. No runtime probe facts were provided to confirm actual execution behavior.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks `file.is_relative_to(root)` before accessing the file. This check ensures the resolved path cannot escape the designated `public` directory, effectively mitigating path traversal. The scanner flagged the use of user input in a path expression, but the subsequent safety check makes the finding non‑exploitable.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server. Because the check is present and correctly used, no impact is realized.

**Remediation:** No remediation required; the existing `is_relative_to` guard is sufficient. Ensure future code maintains similar directory traversal protections when handling user‑supplied paths.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `source_excerpt lines 218‑224 show the use of `Path.resolve()` and `is_relative_to(root)` guard`
- `source_symbol confirms the same logic`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` (Python 3.9+). If run on an older version, the guard may not exist, potentially altering security posture. No runtime probe facts were provided to confirm actual execution behavior.

### 4. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename and then checks that the resulting path is within the allowed directory using `is_relative_to(FILES.resolve())` and also verifies that the path points to a regular file. These checks prevent directory traversal attacks, so the scanner’s finding is not indicative of a vulnerability.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to data disclosure. However, the implemented checks mitigate this risk.

**Remediation:** No remediation needed; the existing path validation is appropriate. Ensure that `FILES` is a trusted base directory and that the Python version supports `Path.is_relative_to` (Python 3.9+).
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Source excerpt shows `file = (FILES / "public" / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")` which validates the resolved path against the base directory and confirms it is a file.`

Limitations:
- The analysis assumes the runtime environment uses a Python version where `Path.is_relative_to` correctly enforces the directory constraint. If an older Python version is used, this method would not exist and the check could be bypassed.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user-provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to(root)`. It also checks that the path points to an existing file before reading it. These safeguards prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None, as the path is properly validated and constrained to the intended directory.

**Remediation:** No remediation required for this finding; the existing checks are sufficient. Ensure future file access code follows the same pattern of path resolution and containment checks.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `source_excerpt lines 220-224 show resolution of `root` and `file`, followed by `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404)` which blocks traversal.`

Limitations:
- The analysis assumes the Python `pathlib` methods behave as documented in the runtime environment. If the runtime were altered or an older Python version lacking `is_relative_to` were used, the protection might not apply. No runtime probe data was provided to confirm actual behavior.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a fixed base directory and then verifies that the resolved path is still within that base using `is_relative_to(FILES.resolve())`. This check prevents directory traversal, making the scanner's path‑traversal warning unwarranted.

**Impact:** If the check were ineffective, an attacker could read arbitrary files, but the code correctly enforces the base directory constraint, so no impact is present.

**Remediation:** No remediation needed; the existing `is_relative_to` check is sufficient. Ensure the `FILES` constant is correctly set to the intended public directory.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `Source excerpt shows the use of `Path.resolve()` and `is_relative_to` to enforce the file resides under the public directory.`

Limitations:
- The analysis assumes `FILES` is a trusted absolute path and that the Python version supports `Path.is_relative_to`. If either assumption is violated, the protection could fail.

### 7. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any sanitisation or encoding. The returned string includes `<h1>Results for {q}</h1>` and `<p>{row['name']}</p>` constructed via f‑strings, allowing an attacker to inject arbitrary HTML/JavaScript that will be rendered by the client.

**Impact:** An attacker can craft a URL such as `/catalog/search?q=<script>alert(1)</script>` which, when visited, will execute the injected script in the victim's browser. This can lead to session hijacking, credential theft, or other malicious actions against users of the application.

**Remediation:** Properly escape or encode user input before embedding it in HTML. Use a templating engine that auto‑escapes, or manually apply HTML escaping (e.g., `html.escape(q)`). Additionally, consider using parameterised queries for the SQL part to avoid SQL injection, and enforce a content security policy (CSP) to mitigate XSS impact.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt lines 141‑145 show the `catalog_search` function returning user‑controlled `q` directly in HTML response.`

Limitations:
- The review is based solely on static code analysis; runtime behaviour (e.g., additional middleware that might sanitise output) was not observed. No runtime_probe_facts were provided to confirm execution flow.

### 8. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided name but immediately resolves it and checks that the resulting path is within the allowed directory using `is_relative_to(FILES.resolve())` and verifies that it is a regular file. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None – the path is validated before access, preventing unauthorized file reads.

**Remediation:** No remediation required for this finding; the existing validation is sufficient.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Source excerpt shows `file = (FILES / "public" / name).resolve()` followed by `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")` which enforces directory confinement.`

Limitations:
- The analysis assumes the Python version supports `Path.is_relative_to` and that `FILES` is correctly defined as the base directory. If the runtime environment differs, the safety guarantee may not hold.

### 9. Potential SQL Injection in catalog_search endpoint

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function catalog_search constructs an SQL query by directly interpolating the user‑controlled parameter `q` into the query string using an f‑string. This allows an attacker to inject arbitrary SQL syntax into the `WHERE` clause, potentially modifying the query logic or extracting data beyond the intended scope.

**Impact:** An attacker could manipulate the `q` parameter to execute unintended SQL commands, leading to data disclosure, data modification, or denial of service. For example, supplying `q=%' OR '1'='1` would cause the query to return all product names, bypassing intended filtering.

**Remediation:** Use parameterized queries or a query builder that safely escapes user input. For example, replace the f‑string with a prepared statement: `rows = conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",)).fetchall()`. Additionally, validate and sanitize the `q` parameter to enforce length and character constraints.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt shows f‑string interpolation of `q` into SQL at line 144: `conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'")``

Limitations:
- The review is based solely on static code analysis; runtime behavior, such as ORM sanitization layers or database driver protections, was not observed. No runtime_probe_facts were provided to confirm actual query execution path.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scan reports that the HTTP response for the root path does not include the X-Content-Type-Options header. This header is used to prevent browsers from MIME-sniffing a response away from the declared Content-Type, mitigating certain cross‑site scripting (XSS) attacks. The finding is based on a runtime probe (zap.10021) that observed the header absence. No contradictory evidence was provided, and the scanner’s observation is directly relevant to the claim.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may interpret content as a different MIME type than intended, potentially allowing injected scripts to execute in the context of the site, leading to XSS or data leakage.

**Remediation:** Configure the web server or application framework to include the header in all responses, e.g., add `X-Content-Type-Options: nosniff` via server configuration (Apache, Nginx) or application middleware. Verify the header is present after deployment.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `Runtime probe (zap.10021) observed missing X-Content-Type-Options header on path '/'`

Limitations:
- The finding is limited to the observed request path; other endpoints may behave differently. No proof is provided that the missing header leads to an exploitable XSS in this specific application. The scan does not indicate whether other mitigations (e.g., CSP) are in place.

### 11. Job listing requires admin role

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe observed a successful HTTP 200 response from the /admin/jobs endpoint without any indication that authentication or authorization was performed. The scanner flagged this as requiring an admin role, but the probe did not capture any auth challenge (e.g., redirect to login, 401/403). This suggests the endpoint may be exposed to unauthenticated users, representing a potential privilege escalation risk.

**Impact:** An attacker could enumerate, view, or manipulate job listings intended for administrators, potentially leading to information disclosure or unauthorized actions within the application.

**Remediation:** Implement proper access control on the /admin/jobs endpoint: require authentication, verify the user's role, and return appropriate error codes (401/403) for unauthorized access. Conduct a review of all admin‑only routes to ensure consistent enforcement.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Runtime probe fact: scanner_id=web-runtime, rule_id=workflow.admin_jobs.2, path=/admin/jobs, status=200, values_redacted=true`

Limitations:
- The probe did not capture request headers or authentication tokens, so it cannot definitively prove the absence of auth checks. The evidence is limited to a single request/response observation and does not account for possible conditional checks (e.g., IP‑based restrictions).

### 12. Potential stale admin role not confirmed

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **low**

**Explanation:** The only evidence is a runtime probe that returned HTTP 200 for /admin/token-report with redacted values. No content was observed that demonstrates the demoted administrator still retains access, nor is there proof of an authorization flaw. The scanner finding lacks concrete proof of a vulnerability, so it is treated as a false positive pending further evidence.

**Impact:** If the role were still active, an attacker could perform privileged actions, but no such behavior is demonstrated.

**Remediation:** Verify role revocation logic in the application and ensure that demoted administrators cannot access admin endpoints. Add explicit tests for role checks and audit logs for access attempts.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Runtime probe returned status 200 for /admin/token-report (values redacted)`

Limitations:
- No response body content to confirm unauthorized access
- No proof that the endpoint exposes privileged functionality
- Scanner finding lacks concrete exploit evidence

### 13. User listing requires admin role

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that the /admin/users endpoint returns a 200 response, but provides no evidence that the request was made without authentication or with a non‑admin user. Without confirming that the endpoint is accessible to unauthorized users, the finding cannot be confirmed as a vulnerability. Additional testing (e.g., unauthenticated request, role‑based access checks) is required to determine whether the endpoint improperly exposes user data.

**Impact:** If the endpoint is accessible to non‑admin users, attackers could enumerate all user accounts, facilitating further attacks such as credential stuffing or targeted phishing.

**Remediation:** Enforce proper access controls on the /admin/users endpoint, ensuring that only authenticated users with the admin role can retrieve the user list. Verify role checks in the application code and add tests to confirm enforcement.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `runtime_probe_facts: scanner web-runtime observed a 200 response for path /admin/users (status 200, values_redacted true)`

Limitations:
- The observed 200 response does not indicate the authentication context of the request; no proof of access without admin privileges is provided.

### 14. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the response from /auth/form-login does not include a Content Security Policy header. A missing CSP header can allow injection of malicious scripts and increase the risk of cross‑site scripting attacks. No additional evidence was provided to confirm the header is intentionally omitted or that alternative mitigations are in place.

**Impact:** Without a CSP header, an attacker who can inject content into the page may execute arbitrary JavaScript in the victim's browser, leading to credential theft, session hijacking, or other malicious actions.

**Remediation:** Configure the web server or application framework to send a strong CSP header for all responses, e.g., `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and test to ensure it is present on the /auth/form-login endpoint.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Scanner runtime probe (zap.10038) reported missing CSP header on /auth/form-login`

Limitations:
- The finding relies solely on a single scanner observation; no manual verification of the header was performed. The application may dynamically set CSP headers under certain conditions not captured by the probe.

### 15. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the response from /auth/form-login does not include an X-Frame-Options or Content‑Security‑Policy frame‑ancestors directive. This indicates that the page could be embedded in a foreign site, potentially enabling clickjacking attacks. No contradictory evidence was provided, and the runtime probe did not capture header values, so the finding remains plausible but unconfirmed.

**Impact:** An attacker could embed the login form in a malicious page and trick users into submitting credentials, leading to credential theft or session hijacking.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors 'self'`. Verify that the header is present in all relevant endpoints, including /auth/form-login.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Missing Anti-clickjacking Header reported by scanner (zap.10020) for path /auth/form-login`

Limitations:
- The runtime probe did not capture the actual header values (values_redacted:true), so the absence of the header cannot be definitively proven from the provided data.
- No manual verification of the response was performed; the finding relies solely on scanner output.

### 16. Cookie No HttpOnly Flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that a cookie set on /auth/form-login lacks the HttpOnly attribute. The only evidence is the scanner flag; no runtime probe data or response headers are provided to confirm the presence or absence of HttpOnly. Without captured Set-Cookie headers or a reproducible request/response showing the flag missing, the finding cannot be confirmed.

**Impact:** If the cookie is accessible to client‑side scripts, it could be stolen via XSS, leading to session hijacking. However, the actual risk cannot be quantified without confirming the flag is indeed missing.

**Remediation:** Ensure that all authentication cookies are set with the HttpOnly attribute (e.g., Set-Cookie: sessionid=...; HttpOnly; Secure; SameSite=Strict). Verify the change by inspecting response headers after login.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `Scanner reported "Cookie No HttpOnly Flag" for path /auth/form-login`

Limitations:
- No captured HTTP response headers showing the Set-Cookie value
- Runtime probe facts are redacted and contain no concrete data
- No manual verification of cookie attributes

### 17. Password reset tokens must be single use

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged the password‑reset confirmation endpoint as potentially allowing token replay, but the only runtime observation is a 200 response with redacted values. No evidence shows that the same token can be reused or that the server enforces single‑use semantics. Without a request that replays a previously issued token and demonstrates acceptance, the vulnerability cannot be confirmed.

**Impact:** If reset tokens were reusable, an attacker who intercepts or guesses a token could reset a victim's password multiple times, leading to account takeover.

**Remediation:** Ensure that reset tokens are stored with a one‑time flag and invalidated after the first successful password change. Return an error for any subsequent use of the same token.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.reset_replay.3, path=/auth/reset/confirm, status=200 (values redacted)`

Limitations:
- No replay attempt was observed; the finding relies solely on scanner heuristics. The response does not prove token reuse is possible.

### 18. Missing Content Security Policy (CSP) Header

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scan reports that the HTTP response for /catalog/query does not include a Content Security Policy header. A CSP header helps mitigate cross‑site scripting (XSS) and data injection attacks by restricting the sources from which scripts, styles, and other resources may be loaded. The absence of this header leaves the application exposed to client‑side injection attacks if any other injection vector exists.

**Impact:** An attacker who can inject malicious script content into pages served at /catalog/query could execute arbitrary JavaScript in the victim's browser, leading to credential theft, session hijacking, or further compromise of user data.

**Remediation:** Configure the web server or application framework to send a CSP header on all responses. A recommended baseline is:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';
```
Adjust directives to match required third‑party resources while keeping the policy as restrictive as possible. Test the policy in report‑only mode before enforcing it.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Runtime probe fact from scanner web-runtime (zap.10038) indicates CSP header not present for path /catalog/query`

Limitations:
- The finding is based solely on a runtime observation; it does not confirm whether any script injection vectors exist in the application. The scan did not verify if other security controls (e.g., input sanitization) mitigate XSS risk. No evidence was provided about server configuration or framework defaults that might add CSP elsewhere.

### 19. Missing X-Content-Type-Options Header

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /catalog/query does not include the X-Content-Type-Options header. This header instructs browsers to disable MIME type sniffing, mitigating certain content‑type confusion attacks. The finding is based on a runtime probe (web‑runtime, rule zap.10021) that observed the header absence. No contradictory evidence was provided.

**Impact:** Without the header, browsers may sniff the content type and interpret responses as executable scripts, potentially enabling cross‑site scripting (XSS) or drive‑by download attacks if an attacker can influence the response body.

**Remediation:** Configure the web server or application framework to add `X-Content-Type-Options: nosniff` to all HTTP responses, preferably via a global security header configuration or middleware.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Runtime probe (web-runtime) reported missing X-Content-Type-Options header for path /catalog/query (zap.10021)`

Limitations:
- The finding relies on a single runtime observation; the header might be added conditionally (e.g., only in production mode) and was not captured during the probe. No source code or configuration files were examined to confirm header settings.

### 20. Missing Anti-clickjacking Header

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The scanner reports that the response from /catalog/query lacks an X-Frame-Options or Content-Security-Policy frame-ancestors directive. No runtime probe data or additional evidence is provided to confirm the header is truly absent across all environments. Without corroborating observations (e.g., captured HTTP responses, server configuration, or multiple scans), the finding remains unverified.

**Impact:** If the endpoint can be embedded in a malicious site, an attacker could perform clickjacking attacks, potentially leading to unauthorized actions by users.

**Remediation:** Configure the web server or application framework to include an appropriate anti-clickjacking header (e.g., X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self'). Verify the header is present in responses from all relevant endpoints.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Scanner report (zap.10020) indicates missing anti-clickjacking header for /catalog/query`

Limitations:
- No captured HTTP response showing the header state
- No runtime probe confirming header presence or absence
- Single scanner source without independent verification

### 21. X-Content-Type-Options Header Missing

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported the absence of the X-Content-Type-Options header on the /comments endpoint, but no runtime probe data confirming the header is missing was provided. Without concrete evidence from the application response, the finding cannot be confirmed as a vulnerability.

**Impact:** If the header were truly missing, it could allow MIME type sniffing attacks, potentially leading to content injection. However, the lack of verified response data means the impact cannot be established.

**Remediation:** Ensure that the server includes the X-Content-Type-Options: nosniff header in all HTTP responses, particularly for endpoints serving user-controlled content.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Scanner reported missing X-Content-Type-Options header on /comments`

Limitations:
- No runtime response captured to verify header presence or absence
- Evidence relies solely on scanner output without corroborating request/response data

### 22. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanner reported that the HTTP response for the /comments endpoint does not include a Content Security Policy header. A CSP header helps mitigate cross‑site scripting (XSS) and data injection attacks by restricting the sources from which content can be loaded. The runtime probe fact from the web‑runtime scanner (zap.10038) also indicates that the header value was redacted, implying it was not present. No contradictory evidence was provided.

**Impact:** Without a CSP header, browsers will not enforce content‑source restrictions, increasing the risk that malicious scripts injected via XSS or other injection vectors can execute in the victim's browser, potentially leading to credential theft, session hijacking, or data exfiltration.

**Remediation:** Configure the web server or application framework to send a CSP header on all responses. For example, add `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` to the HTTP response headers. Test the policy with report‑only mode before enforcing it fully.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Scanner evidence: "Content Security Policy (CSP) Header Not Set" for path /comments`
- `Runtime probe fact from scanner web-runtime (zap.10038) indicating values_redacted=true for the same path`

Limitations:
- The finding relies on scanner observation; the actual server configuration was not manually inspected.
- The runtime probe did not capture the full header set, only indicating absence/redaction of CSP.
- No evidence was provided that a CSP header is set elsewhere (e.g., via a reverse proxy) that might apply to this endpoint.

### 23. Missing Anti-clickjacking Header

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP responses for the /comments endpoint do not include an X-Frame-Options or Content-Security-Policy frame-ancestors directive, which are commonly used to mitigate clickjacking attacks. No additional runtime or deployment evidence was provided to confirm the header is present elsewhere or that other mitigations are in place.

**Impact:** An attacker could embed the vulnerable page in a hidden iframe on a malicious site and trick users into performing unintended actions, potentially leading to credential theft or unauthorized actions on behalf of the user.

**Remediation:** Configure the web server or application framework to send an appropriate anti-clickjacking header, such as `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive that restricts framing to trusted origins.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Scanner report (zap.10020) indicates missing anti-clickjacking header on /comments`

Limitations:
- No runtime probe confirming the actual HTTP response headers were observed; the finding relies solely on scanner analysis. The deployment context is unknown, so it is possible that a reverse proxy adds the header at a later stage.

### 24. Debug configuration is unavailable anonymously

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe returned HTTP 200 for /debug/config but the response indicated that the values are redacted. No concrete data exposing debug settings was observed, and the scanner’s finding is based solely on the endpoint’s existence, not on disclosed sensitive information. Without evidence that the configuration details are actually exposed, the claim of a vulnerability is unsubstantiated.

**Impact:** If debug configuration were exposed, an attacker could gain insight into internal settings, potentially facilitating further attacks. However, the redacted response suggests that no actionable information is disclosed, limiting impact.

**Remediation:** Ensure that the /debug/config endpoint either requires authentication or returns a generic 404/403 response when accessed anonymously. Verify that no sensitive configuration values are included in any response.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `Runtime probe fact: scanner_id=web-runtime, rule_id=workflow.debug_access.1, path=/debug/config, status=200, values_redacted=true`

Limitations:
- The probe only indicates that the endpoint exists and returns a redacted response; it does not confirm the absence of sensitive data in other contexts. No source code or configuration files were examined to verify access controls.

### 25. Missing Content-Security-Policy header on /healthz

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from /healthz without a Content-Security-Policy header. While the endpoint is typically used for health checks and may not render user-supplied content, the absence of CSP could allow injection attacks if the endpoint ever serves HTML or is reflected elsewhere.

**Impact:** If an attacker can influence the response body, the lack of CSP may enable execution of malicious scripts, leading to XSS or data exfiltration.

**Remediation:** Add a Content-Security-Policy header to the /healthz response (e.g., `Content-Security-Policy: default-src 'none';`), or ensure the endpoint only returns plain text/JSON without any HTML content.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=web.missing-content-security-policy, path=/healthz, status=200`

Limitations:
- The finding is based on a single health check endpoint which may not be exposed to end‑users; no evidence that the endpoint returns HTML or reflects user input.

### 26. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime probe and scanner report that the /healthz endpoint does not include the X-Content-Type-Options header, which can allow MIME type sniffing attacks. No contradictory evidence was found.

**Impact:** An attacker could trick the browser into interpreting content as a different MIME type, potentially leading to cross‑site scripting or content injection.

**Remediation:** Configure the web server or application framework to add the header `X-Content-Type-Options: nosniff` on all responses, including the health check endpoint.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `Scanner report (zap.10021) indicates missing X-Content-Type-Options header on /healthz`

Limitations:
- The finding is based solely on a scanner observation; the actual runtime response was redacted, so verification of the header's absence is indirect.

### 27. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from /healthz without the X-Frame-Options or Content-Security-Policy frame-ancestors directives, indicating the application does not provide clickjacking protection for this endpoint. The scanner flagged this as a missing header, and no contradictory evidence was found.

**Impact:** An attacker could embed the /healthz page in a malicious site using an iframe, potentially tricking users into unintended actions or exposing internal health information.

**Remediation:** Configure the web server or application framework to send an appropriate clickjacking protection header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) for all responses, including the /healthz endpoint.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe fact: status 200 from /healthz with no clickjacking protection header (web.missing-clickjacking-protection)`

Limitations:
- The finding is based on a single endpoint and does not confirm whether other endpoints set the header; further scanning of additional routes is needed to assess overall coverage.

### 28. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed a 200 response from /healthz without the X-Content-Type-Options header, which is a known defense-in-depth header that prevents MIME type sniffing. The scanner flagged this omission, and no evidence was found that the header is added elsewhere in the application stack.

**Impact:** An attacker could potentially trick browsers into interpreting content as a different MIME type, leading to cross‑site scripting or content injection attacks, especially if other vulnerabilities exist.

**Remediation:** Configure the web server or application framework to include the header, e.g., `X-Content-Type-Options: nosniff` for all responses, or add it via middleware if using a framework.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=web.missing-content-type-protection, path=/healthz, status=200 (header missing)`

Limitations:
- Evidence is limited to a single HTTP GET request to /healthz; other endpoints may behave differently. No source code review was performed to confirm header configuration.

### 29. Incoming webhook events may lack signature validation

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged the /integrations/hook endpoint as requiring a valid signature for incoming webhook events. The only runtime observation is an HTTP 200 response with redacted values, which does not demonstrate that signature verification is performed. No additional evidence (e.g., code checks, explicit signature validation logic, or test cases) was provided to confirm the presence of proper verification. Consequently, the finding remains a likely vulnerability pending further verification.

**Impact:** If webhook signatures are not validated, an attacker could craft malicious webhook payloads and trigger unauthorized actions within the application, potentially leading to data manipulation, privilege escalation, or service disruption.

**Remediation:** Implement explicit verification of webhook signatures before processing any payload. This includes: • Defining a shared secret or public key for signature generation. • Validating the signature on each incoming request and rejecting requests with missing or invalid signatures (e.g., returning HTTP 401/403). • Adding unit and integration tests that confirm rejection of unsigned or tampered requests. • Documenting the required signature format for external services.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Runtime probe observed HTTP 200 response from /integrations/hook (values redacted)`

Limitations:
- The probe does not reveal whether signature checks were performed; it only shows a successful response. No source code or test artifacts were examined to confirm signature validation logic. The finding relies solely on the scanner's heuristic without corroborating evidence.

### 30. Access control correctly restricts invoice reading to owner

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The finding states "Only the owner can read an invoice" which indicates that the application enforces proper authorization checks on the /invoices/{{invoice_id}} endpoint. No evidence of unauthorized access or bypass is presented. The runtime probe shows a 200 response for a request, but does not demonstrate that a non‑owner can retrieve the invoice. Therefore, this is not a vulnerability.

**Impact:** None, as the endpoint appears to enforce correct access controls.

**Remediation:** No remediation required; continue to ensure that ownership checks remain enforced for all invoice accesses.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Only the owner can read an invoice (scanner evidence)`
- `Runtime probe returned status 200 for authorized request`

Limitations:
- No evidence of unauthorized access attempts
- The probe does not confirm behavior for non‑owner requests

### 31. Users cannot submit an admin job

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The scanner reports that users cannot submit an admin job, but the runtime probe for the same endpoint (/jobs) returned an HTTP 200 status, indicating the request succeeded. No additional evidence (e.g., error messages, permission checks, or failed submissions) is provided to substantiate the claim. The single runtime observation contradicts the scanner finding, and there is no corroborating source code or configuration evidence of a permission enforcement flaw.

**Impact:** If the finding were true, legitimate admin job submissions could be blocked, potentially disrupting administrative workflows. However, the observed successful response suggests no functional impact.

**Remediation:** No remediation is required based on current evidence. Continue monitoring the endpoint and consider adding explicit permission checks if admin‑only functionality is intended.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Runtime probe returned HTTP 200 for /jobs (web-runtime, workflow.worker_role.1)`

Limitations:
- Only a single successful request was observed; the probe does not test unauthorized user contexts or edge‑case inputs. Additional testing with varied user roles would be needed to fully rule out a permission issue.

### 32. Potential SSN exposure not confirmed

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The scanner flagged the /me endpoint for exposing a social security number, but the runtime probe indicates that the response values are redacted. No concrete evidence of an SSN being returned is present, and the finding relies solely on the scanner's heuristic without supporting data.

**Impact:** If the endpoint were to expose an SSN, it would constitute a privacy breach and could lead to identity theft. However, the current evidence does not demonstrate such exposure.

**Remediation:** Verify that the /me endpoint properly redacts or omits sensitive personal identifiers such as SSNs. Implement explicit checks to ensure no PII is included in responses and add tests to confirm redaction.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `runtime_probe_facts: status 200, values_redacted true`

Limitations:
- No actual response payload was provided; the assessment relies on the redaction flag reported by the runtime probe. The scanner's heuristic may produce false positives in the absence of concrete data.

### 33. Improper Authorization on Order Creation

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that users are unable to create orders for another owner, which suggests that the application may be enforcing ownership checks incorrectly or inconsistently. The runtime probe returned a 200 response for a request to /orders, but the response values were redacted, providing no direct confirmation of the vulnerability. Given the scanner's finding and the lack of concrete runtime evidence, the issue is treated as a likely vulnerability pending further verification.

**Impact:** If an attacker can manipulate order creation to affect other users' accounts, they could perform unauthorized transactions, cause financial loss, or corrupt data integrity across multiple user accounts.

**Remediation:** Implement strict server‑side authorization checks that verify the authenticated user's identity against the owner field of the order before processing creation requests. Ensure that any client‑side hints are never trusted for access control decisions. Add comprehensive unit and integration tests for ownership enforcement.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Scanner evidence: "Users cannot create orders for another owner"`
- `Runtime probe fact: status 200 returned for /orders request (values redacted)`

Limitations:
- The runtime probe does not reveal the actual response content, so it cannot confirm whether the order creation succeeded or was correctly rejected.
- No additional scanner or manual testing evidence is provided to demonstrate exploitation.
- The finding is based on a single source; further testing (e.g., attempting to create an order with a different owner ID) is required to confirm the vulnerability.

### 34. New orders cannot start as paid

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that new orders cannot start as paid and a runtime probe returned a 200 response for the /orders endpoint, but no concrete evidence shows that the order state transition to 'paid' fails. The probe does not include details of the order payload or response content, and there is no additional corroborating evidence (e.g., logs, error messages, or transaction records) to confirm the reported issue.

**Impact:** If orders cannot be marked as paid, customers may be unable to complete purchases, leading to revenue loss and a poor user experience.

**Remediation:** Investigate the order processing workflow, add logging around state transitions, and verify that the payment handling code correctly updates order status. Include tests that simulate successful payments and confirm the order reaches the 'paid' state.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.order_initial_state.1, path=/orders, facts={status:200, values_redacted:true}`

Limitations:
- The probe only confirms the endpoint is reachable (HTTP 200) and does not reveal the order state or payment processing outcome. No payload or response details are available, and no other sources corroborate the finding.

### 35. Negative order prices are rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that the application rejects negative order prices, but the runtime probe for the same endpoint returned an HTTP 200 status, indicating the request was processed successfully. This discrepancy suggests that negative price values may not be properly validated, representing a potential business logic flaw.

**Impact:** An attacker could submit orders with negative prices, potentially causing financial loss, inventory inconsistencies, or credit exploitation.

**Remediation:** Implement server‑side validation to ensure the price field is non‑negative and return an appropriate error (e.g., HTTP 400) for invalid input. Add unit and integration tests for price validation.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Scanner evidence: "Negative order prices are rejected"`
- `Runtime probe fact: status 200 for /orders with negative price (values_redacted)`

Limitations:
- The runtime probe redacted the actual request payload, so the exact negative value is unknown.
- Only a single runtime observation is available; further testing is needed to confirm consistent behavior across different inputs.

### 36. Catalog price must be set by the server

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The finding is based solely on a scanner rule that expects the server to enforce catalog pricing. The only evidence provided is the scanner’s generic message and a runtime probe indicating a 200 response with redacted values. No concrete observation shows that the price can be overridden by a client, that the server returns user‑controlled price data, or that an attacker can manipulate the price field. Without explicit proof of client‑controlled input affecting the price, the claim remains unsubstantiated.

**Impact:** If the price were client‑controlled, an attacker could purchase items at arbitrary prices, leading to revenue loss. However, no evidence of such behavior is present, so the impact cannot be confirmed.

**Remediation:** Ensure that the server validates and sets the final price for catalog items regardless of any client‑provided values. Implement server‑side checks that ignore or overwrite any price fields supplied in the request payload.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Runtime probe fact: scanner_id=web-runtime, rule_id=workflow.price_catalog.1, path=/orders, status=200, values_redacted=true`

Limitations:
- No direct observation of client‑supplied price being accepted or reflected in the response
- Only a generic scanner rule triggered; no payload or response data demonstrating the vulnerability
- Absence of additional evidence such as request/response logs, code review, or security tests confirming price manipulation

### 37. A note must belong to the order named in the URL

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding is based solely on a scanner rule that expects a note resource to be tied to the order ID in the URL. No runtime evidence demonstrates that the application incorrectly allows notes to be accessed or modified across orders, nor is there any proof of an authorization bypass. The only observed runtime fact is a successful 200 response for the request, which is expected for a valid note retrieval. Without concrete evidence of improper access control, the issue cannot be confirmed as a vulnerability.

**Impact:** If the endpoint were vulnerable, an attacker could read or modify notes belonging to other orders, leading to data leakage or tampering. However, no such behavior is demonstrated.

**Remediation:** Ensure that the server validates that the note ID belongs to the order ID specified in the URL before returning or modifying the note. Implement proper authorization checks and return an error (e.g., 403) when the association is invalid.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Runtime probe returned status 200 for GET /orders/1/notes/2, indicating normal operation.`

Limitations:
- No evidence of cross‑order note access or modification was observed. The scanner rule alone does not prove a flaw.

### 38. Only the owner can read an order

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The finding reports that the endpoint "/orders/{{order_id}}" returns data only to the order owner. This behavior is a security control, not a vulnerability. The scanner’s evidence does not indicate any unauthorized access or missing authorization checks.

**Impact:** No impact; the access control appears to be correctly enforced.

**Remediation:** No remediation required; continue to enforce owner‑based authorization for order retrieval.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `Scanner runtime probe returned HTTP 200 with redacted values, indicating successful authorized access.`

Limitations:
- The probe does not show how the system behaves for unauthorized users; however, the finding itself asserts owner‑only access, which aligns with expected security behavior.

### 39. Potential improper handling of excessive coupon discounts

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged that excessive coupon discounts are rejected, and a runtime probe observed a 200 response for the coupon application endpoint. The evidence suggests the endpoint may accept or incorrectly process large discount values, but the probe did not confirm rejection behavior. Further testing is needed to determine if the application enforces discount limits correctly.

**Impact:** If discount limits are not enforced, attackers could apply arbitrarily large coupons, leading to financial loss and unauthorized free purchases.

**Remediation:** Implement server‑side validation to enforce maximum discount values and ensure that requests exceeding these bounds return an appropriate error (e.g., 400 Bad Request). Add unit and integration tests for coupon limit enforcement.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Scanner evidence: "Excessive coupon discounts are rejected"`
- `Runtime probe fact: status 200 returned from /orders/{{order_id}}/apply-coupon`

Limitations:
- The runtime probe only shows a successful HTTP status and does not verify the actual discount applied or rejection logic.
- No direct observation of the discount amount or error messages; the scanner's claim is not independently validated.

### 40. Paid orders require a refund before cancellation

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that the endpoint returns HTTP 200 and indicates a business rule that paid orders must be refunded before they can be cancelled. This behavior is a logical workflow constraint, not an insecure implementation. No evidence shows that an attacker can bypass the refund requirement or cause unauthorized cancellations. The runtime probe only confirms the endpoint responds with 200; it does not demonstrate a security flaw.

**Impact:** If the rule were unintended, it could inconvenience users, but it does not expose data, allow privilege escalation, or enable unauthorized actions.

**Remediation:** If the behavior is undesired, adjust the application logic to allow cancellation without a prior refund, or clearly document the requirement for legitimate users. No security‑specific remediation is required.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.paid_cancel.3, path=/orders/{{order_id}}/cancel, facts={status:200, values_redacted:true}`

Limitations:
- The finding is based solely on a business‑logic rule; no exploit path or insecure code was observed.
- The scanner’s description does not provide proof of a vulnerability, only that the rule exists.

### 41. Already paid order rejects a second payment

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The finding reports that a second payment attempt on an already paid order is rejected. The observed runtime probe shows a 200 HTTP status, but the scanner’s description indicates the request is correctly rejected, which is expected behavior for preventing duplicate payments. No evidence of unintended acceptance or financial loss is present.

**Impact:** None – the application correctly prevents duplicate payments, so no financial impact is introduced.

**Remediation:** No remediation required; the current behavior aligns with intended business logic.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Runtime probe fact from scanner web-runtime: rule workflow.payment_replay.3 returned status 200 for /orders/{{order_id}}/pay`

Limitations:
- The probe does not show the response body or exact rejection message, limiting confirmation of the exact handling logic. No additional context (e.g., transaction logs) is available to verify that duplicate payments are truly blocked.

### 42. Unauthorized profile access possible

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** Runtime probe returned HTTP 200 for a request to /profiles/{{other_id}}, indicating that the endpoint returns data for a profile that does not belong to the authenticated user. The scanner finding aligns with this observation, suggesting an access control flaw.

**Impact:** An attacker can view or harvest personal information from other users' profiles, leading to privacy breaches and potential credential harvesting.

**Remediation:** Implement proper authorization checks to ensure that the profile endpoint only returns data for the authenticated user's own profile. Verify the ownership of the requested profile ID before responding.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.profile_owner.2, path=/profiles/{{other_id}}, facts={status:200, values_redacted:true}`

Limitations:
- The probe does not show the actual response content; it only indicates a 200 status. Further testing is needed to confirm that sensitive data is exposed.

### 43. Missing Anti-clickjacking Header

- Issue group: `merged-50485291173e2448f7c7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for the /view endpoint does not include an X-Frame-Options or Content-Security-Policy frame-ancestors directive, which are commonly used to mitigate clickjacking attacks. No additional runtime or deployment evidence was provided to confirm the header is present elsewhere or that other mitigations are in place.

**Impact:** An attacker could embed the vulnerable page in a hidden iframe on a malicious site and trick users into performing unintended actions, potentially leading to credential theft or unauthorized transactions.

**Remediation:** Configure the web server or application framework to send an appropriate anti-clickjacking header, such as `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive that restricts framing to trusted origins.
Evidence:
- Source IDs: `merged-50485291173e2448f7c7`
- `Scanner runtime probe (zap.10020) reported missing anti-clickjacking header for path /view`

Limitations:
- The finding is based solely on a scanner observation; no runtime logs or application code were examined to verify header configuration. The deployment context is unknown, so it is possible that a reverse proxy adds the header in production. Further manual testing or code review is needed to confirm the absence of the header.

### 44. X-Content-Type-Options Header Missing

- Issue group: `merged-ade7b890a037d8c82a1f`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scan reports that the HTTP response for /view does not include the X-Content-Type-Options header, which can allow browsers to perform MIME type sniffing and potentially lead to content injection attacks. No contradictory evidence was provided, and the finding originates from a runtime scanner (zap.10021).

**Impact:** An attacker could exploit MIME type sniffing to execute malicious scripts or deliver crafted content, potentially leading to cross-site scripting (XSS) or data leakage, especially when combined with other weaknesses.

**Remediation:** Configure the web server or application framework to include the header `X-Content-Type-Options: nosniff` on all responses, preferably via a global security middleware or server configuration (e.g., in Apache, Nginx, or application code).
Evidence:
- Source IDs: `merged-ade7b890a037d8c82a1f`
- `Scanner runtime probe (zap.10021) reported missing X-Content-Type-Options header on /view`

Limitations:
- The evidence is limited to a single runtime probe; no manual verification of the header presence was performed. The scan did not provide full response details, and the finding may be a false positive if the header is added conditionally or in a later middleware layer.

### 45. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-dfd8d33b4f84ccf0c23f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /view does not include a Content Security Policy header. No runtime probe data confirming the header’s presence or absence was provided, and there is no contradictory evidence from the application code or deployment configuration. Absence of CSP can allow injection attacks such as XSS to execute without restriction, so the finding warrants attention even though it is not directly verified at runtime.

**Impact:** Without a CSP header, browsers will not enforce restrictions on script sources, inline scripts, or other potentially unsafe content, increasing the risk of cross‑site scripting and data exfiltration attacks.

**Remediation:** Configure the web server or application framework to send a CSP header on all responses. For example, in an Express.js app use `app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } }));` or configure the appropriate header in Nginx/Apache. Ensure the policy is tested to avoid breaking legitimate functionality.
Evidence:
- Source IDs: `merged-dfd8d33b4f84ccf0c23f`
- `Scanner report (zap.10038) indicates CSP header missing on /view`

Limitations:
- No runtime probe confirming the header is absent; the finding relies solely on scanner observation. The scanner’s redacted values prevent verification of the exact response. No code or configuration review was performed to confirm that CSP is not set elsewhere.

### 46. Webhook destination must match the approved internal host exactly

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged a potential mismatch in the webhook destination, but the only runtime observation is an HTTP 200 response with redacted values. No concrete evidence shows that the destination deviates from the approved internal host, and the source excerpt is empty. Additional verification of the actual webhook URL is required to confirm the issue.

**Impact:** If the webhook were to point to an unauthorized external host, it could exfiltrate sensitive data or allow unauthorized actions, leading to data leakage or system compromise.

**Remediation:** Validate the webhook configuration to ensure the destination URL exactly matches the approved internal host. Implement strict validation in the application and enforce it via configuration management or environment variables.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `Runtime probe returned HTTP 200 for /webhooks with values redacted`

Limitations:
- No actual webhook URL observed; values are redacted, preventing confirmation of mismatch. Scanner evidence alone is insufficient without concrete destination data.

### 47. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the application secret (APP_SECRET) in clear text using the standard logger. This is directly observable in the source excerpt at line 137 where `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))` is executed for every successful login. Logging secrets exposes them to log aggregation systems, file storage, and potentially to attackers who can read log files.

**Impact:** An attacker who gains read access to application logs can retrieve the APP_SECRET value, which may be used to forge authentication tokens, decrypt data, or perform other privileged actions within the application, leading to full account compromise.

**Remediation:** Remove the secret from log statements. Log only non-sensitive identifiers (e.g., username) and avoid including environment secrets. If debugging is required, use a dedicated debug flag and ensure that secret values are never emitted. Consider redacting or hashing sensitive fields before logging.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) at api/app.py:137`

Limitations:
- The review is based solely on static source evidence; runtime behavior (e.g., log level configuration) may affect whether the statement is actually emitted. No runtime probe confirms log output.

### 48. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any website to make cross‑origin requests to the API. This configuration can expose the service to CSRF‑style attacks or data leakage when credentials are allowed, especially since allow_credentials is True. While the scanner flagged this, the code itself confirms the permissive setting.

**Impact:** An attacker can host a malicious site that issues requests to the API on behalf of a victim's browser, potentially accessing sensitive data returned by the API when credentials are included.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. If credentials must be allowed, set allow_credentials to False or ensure the origins list does not contain "*". Example: allow_origins=["https://example.com","https://app.example.com"].
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py line 26: allow_origins=["*"]`
- `api/app.py line 27: allow_credentials=True`

Limitations:
- The finding assumes the API returns sensitive data to authenticated users; if the API is entirely public and returns no confidential information, the risk is reduced. The scanner evidence alone does not prove exploitation, and the project's threat model may accept a permissive CORS policy.

### 49. Potential Log Injection and Sensitive Data Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs a user‑provided value (username) and the application secret (APP_SECRET) using a formatted log statement. An attacker can control the username parameter, which may allow log injection if the logging backend does not properly sanitize messages. Additionally, logging the secret value exposes sensitive configuration data to log storage, increasing the risk of credential leakage.

**Impact:** If log injection is successful, an attacker could corrupt log files, obscure malicious activity, or execute log‑parsing tools that interpret crafted input. Exposure of the APP_SECRET can enable credential reuse attacks, token forgery, or other privileged actions if the logs are accessed by unauthorized parties.

**Remediation:** Avoid logging raw user input; sanitize or omit it. Do not log sensitive configuration values such as APP_SECRET. Use structured logging with safe parameter handling, and ensure logs are stored with appropriate access controls.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- The severity assessment assumes the logging backend does not automatically escape user input. If the logger sanitizes messages, injection risk may be reduced. The impact of secret exposure depends on log access controls; if logs are strictly internal, risk may be lower. No runtime probe data was provided to confirm actual log handling behavior.

### 50. Open redirect via unvalidated URL parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list checking. An attacker can supply an arbitrary URL, causing the application to redirect users to a malicious site after authentication.

**Impact:** Phishing attacks, credential harvesting, and user trust erosion by redirecting victims to attacker‑controlled domains.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, require explicit confirmation and use a safe redirect mechanism.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source excerpt shows `def continue_to(next: str = "/") -> RedirectResponse:` and `return RedirectResponse(next, status_code=302)` with no validation.`

Limitations:
- No runtime probe data confirming exploitation; the analysis is based solely on static code inspection.

### 51. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the provided URL by ensuring it starts with a single '/' and rejects any value that starts with '//' or contains a scheme or network location. This prevents redirection to external domains, mitigating an open‑redirect vulnerability. The scanner’s generic rule flagged the use of RedirectResponse, but the explicit checks make the finding inaccurate.

**Impact:** If the validation were bypassed, an attacker could redirect users to malicious sites, leading to phishing or drive‑by attacks. However, the code as written blocks such URLs, so the risk is not present.

**Remediation:** No remediation needed; the existing validation is sufficient. Ensure future changes preserve these checks and consider adding unit tests for edge cases (e.g., encoded URLs).
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `Code at lines 621‑624 enforces local‑path only redirects: it raises HTTPException for URLs not starting with '/' or that start with '//' or contain a scheme/netloc.`
- `RedirectResponse is only called after the validation passes, guaranteeing a safe internal redirect.`

Limitations:
- The review assumes the function is the sole entry point for redirects; if other redirect mechanisms exist elsewhere without similar validation, they could be vulnerable.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container health monitoring, its omission does not constitute a security vulnerability by itself. No evidence is provided that the lack of health checks leads to exploitable conditions or service disruption in this context.

**Impact:** Minimal – the container may not be automatically restarted or flagged as unhealthy, but this does not directly expose the application to security threats.

**Remediation:** Add a suitable HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- No runtime probe data confirming that health checks are required for this service. The recommendation is based on general best‑practice guidance rather than a demonstrated exploit.

### 53. Missing HEALTHCHECK instruction

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK directive. While adding a health check is a best practice for container reliability and can aid in detecting unhealthy containers, its absence does not constitute a security vulnerability by itself. No evidence is provided that the missing health check leads to an exploitable condition or compromises confidentiality, integrity, or availability.

**Impact:** Limited to reduced observability of container health; does not directly expose the application to attack.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:9000/health || exit 1
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- Assessment based solely on Dockerfile content; does not consider external orchestration tools that might provide health monitoring. No runtime evidence of impact.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding flags the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a recommended best practice for container reliability, its absence does not directly constitute a security vulnerability. No evidence is provided that the lack of a health check leads to an exploitable condition or reduces the security posture of the application.

**Impact:** Minimal to none; containers may remain running even if the service becomes unhealthy, but this does not inherently expose the system to attack.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the worker process is responsive, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line (lines 1-7).`

Limitations:
- The assessment is based solely on the Dockerfile content; runtime behavior or external monitoring is not examined. The absence of a health check is not proven to be exploitable.

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53539 – a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded request bodies. The scanner evidence cites this CVE and notes that the issue is fixed starting with version 0.0.30. No mitigating controls or runtime checks were observed that would prevent exploitation of this flaw.

**Impact:** An attacker can send a maliciously crafted request to the FastAPI service, causing the python-multipart parser to consume excessive resources and potentially crash or become unresponsive, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Verify the updated dependency does not introduce breaking changes with existing request handling logic, and run the test suite after the upgrade.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The review is based solely on the declared dependency version in requirements.txt; runtime configuration or input validation that might mitigate the issue was not observed. No additional runtime probe data was provided.

### 56. Denial of Service in python-multipart 0.0.20 (CVE-2026-42561)

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to contain CVE-2026-42561, a denial‑of‑service vulnerability triggered by crafted multipart requests with an excessive number of part headers. The vulnerability is fixed starting with version 0.0.27. No evidence was found that the application upgrades or patches this dependency at build or runtime.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially crashing the service or rendering it unavailable to legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later and rebuild/redeploy the application. Verify the updated dependency is included in the final image or deployment artifact.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27 (scanner evidence).`
- `requirements.txt pins python-multipart==0.0.20.`

Limitations:
- No runtime probe confirms the vulnerable code is executed in the deployed service.
- No additional scanner or runtime evidence beyond the static dependency listing.

### 57. python-multipart: Information disclosure due to parser differential in form data handling (CVE-2026-53538)

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The vulnerability allows information disclosure through differential parsing of multipart form data. The scanner identified this dependency and the associated CVE, and the finding was merged without contradictory evidence.

**Impact:** An attacker could craft multipart requests that cause the server to leak sensitive data from processed form fields, potentially exposing user information or internal data structures.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- No runtime evidence that the vulnerable code path is exercised in the deployed application.
- The finding relies solely on the presence of the vulnerable version in requirements.txt; actual exploitability depends on how multipart data is processed in the code base.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests (CVE-2026-40347)

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project directly depends on python-multipart version 0.0.20 as shown in the requirements.txt excerpt. This version is known to contain CVE-2026-40347, a denial‑of‑service vulnerability triggered by specially crafted multipart/form-data payloads. The scanner evidence cites the CVE and notes that the issue is fixed starting with version 0.0.26. No mitigating controls or patches are observed in the repository.

**Impact:** An attacker can send a malicious multipart request that consumes excessive CPU or memory, potentially rendering the FastAPI service unavailable and causing service disruption for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later. Update the requirements.txt entry and run the dependency manager to install the patched version. Optionally add a test to verify that the upgraded library is used.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`
- `requirements.txt shows python-multipart==0.0.20`

Limitations:
- The review relies on the version declaration in requirements.txt; if the runtime uses a different resolved version (e.g., via a lock file) the finding may not apply. No runtime probe confirms the vulnerable code is executed.

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20 in its requirements.txt. This version is known to be vulnerable to CVE-2026-24486, a path‑traversal issue that allows arbitrary file write. The vulnerability is fixed starting with version 0.0.22, which is not used. No evidence was found that the application mitigates this flaw at runtime.

**Impact:** An attacker who can influence multipart form data could craft a payload that writes files to arbitrary locations on the server, potentially leading to code execution, data corruption, or privilege escalation.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later and retest the application. Verify that the new version is compatible with the rest of the stack. Optionally, add runtime validation of uploaded file paths as defense‑in‑depth.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `requirements.txt pins python-multipart==0.0.20`
- `CVE-2026-24486 advisory indicates arbitrary file write in python-multipart 0.0.20`
- `Scanner evidence cites the CVE and notes the fix in 0.0.22`

Limitations:
- The review assumes the vulnerable code path is reachable; actual exploitation depends on how multipart handling is used in the application. No runtime probe data was available to confirm the vulnerability is present in the deployed environment.

### 60. python-multipart 0.0.20 contains CVE-2026-53537

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53537, an information disclosure issue caused by header parsing discrepancies. The scanner identified this CVE and noted that it is fixed in version 0.0.30. No additional evidence contradicts this finding, and the dependency is directly included in the requirements file.

**Impact:** An attacker could exploit the header parsing flaw to obtain sensitive information from HTTP requests processed by the application, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later and update the requirements.txt accordingly. Rebuild and redeploy the application after the upgrade.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`

Limitations:
- The CVE details are based on external scanner data; no runtime probe confirms exploitation in the current deployment.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports a known vulnerability (CVE‑2026‑53540) in python‑multipart version 0.0.20, which is present in the project's requirements.txt. The vulnerability is documented to cause the entire request body to be buffered in memory when a negative Content‑Length header is processed, leading to potential denial‑of‑service. The finding is corroborated by the explicit evidence line in the requirements file and the scanner’s CVE reference.

**Impact:** An attacker can craft a request with a malformed Content‑Length header, causing the server to allocate excessive memory and potentially crash or become unresponsive, affecting availability of the service.

**Remediation:** Upgrade python‑multipart to version 0.0.31 or later, which contains the fix for CVE‑2026‑53540. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- The review relies on the scanner’s CVE mapping; no runtime probe confirms exploitation. No additional context about how the application handles multipart requests is provided.

### 62. Dynamic urllib usage may allow unsafe URL construction

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged the use of urllib.request with a dynamically constructed URL (BASE + path). While urllib can handle file:// schemes, the code appears to build the URL from a constant base and a path argument. Without evidence that the path parameter can be influenced by an attacker, the risk of arbitrary file read or SSRF cannot be confirmed. Further analysis of how `path` is sourced and validated is required.

**Impact:** If an attacker can control `path` and cause a file:// URL, they could read arbitrary files on the server or trigger SSRF attacks, potentially leading to data disclosure or internal network access.

**Remediation:** Validate and sanitize the `path` argument to ensure it cannot contain malicious schemes or traversal sequences. Prefer using higher‑level HTTP libraries such as `requests` that do not support file URLs, or explicitly reject non‑http/https schemes before constructing the request.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows urllib.request.urlopen called with BASE + path, without apparent validation of `path`.`
- `Scanner evidence notes potential risk of file:// scheme usage.`

Limitations:
- No runtime probe data confirming exploitable input control over `path`.
- No evidence that `path` originates from user‑controlled input.
- Severity and confidence remain low pending further code‑base analysis.

### 63. Potential SSRF via dynamic urllib request

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload["target_url"]). If an attacker can influence this payload, they can control the destination URL, potentially causing server‑side request forgery (SSRF) or unintended file reads via file:// schemes. The scanner flagged this as a dynamic urllib use, which is a known risk vector. No additional runtime evidence disproves the possibility, so the finding is treated as a likely vulnerability.

**Impact:** An attacker-controlled URL could cause the service to make arbitrary network requests, access internal services, or read local files via file://, leading to data leakage, privilege escalation, or further compromise.

**Remediation:** Validate and sanitize the "target_url" value before using it in urllib.request.Request. Restrict allowed schemes (e.g., only https://), enforce a whitelist of permitted domains, or switch to a safer HTTP client library like requests with explicit timeout and verification settings. Consider adding network‑level egress controls to limit outbound requests.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows payload["target_url"] passed directly to urllib.request.Request without validation (lines 17‑23).`
- `Scanner evidence notes dynamic urllib usage may allow file:// scheme exploitation.`

Limitations:
- No runtime probe data confirming whether the payload can be attacker‑controlled in practice.
- The severity assessment relies on code‑level analysis; actual impact depends on deployment network configuration and input validation elsewhere.

### 64. Potential directory traversal via symbolic links in file_read endpoint

- Issue group: `ai-10db57c90eb2c229`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code resolves a user‑supplied filename within the public directory and then checks that the resolved path is relative to the public root. Because the resolve() call follows symbolic links before the relative‑path check, a symlink placed inside the public directory that points outside could bypass the check and expose arbitrary files. However, the review lacks concrete evidence that such symlinks can be created by an attacker or that the filesystem does not block them. Without confirmation of symlink creation privileges or additional validation of the 'name' parameter, the exploitability remains uncertain.

**Impact:** If an attacker can place a malicious symlink, they may read files outside the intended public directory, potentially exposing sensitive configuration or credential files.

**Remediation:** Disallow following symlinks when validating paths, e.g., by checking the user‑supplied path components before resolution or by using a safe join that does not follow symlinks. Alternatively, enforce a whitelist of allowed filenames or store files in a location where symlink creation is prohibited.
Evidence:
- Source IDs: `ai-10db57c90eb2c229`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `The resolve() call follows symlinks before the is_relative_to check.`

Limitations:
- No evidence that attackers can create symlinks in the public directory
- Filesystem symlink restrictions are unknown
- No additional validation of the 'name' parameter is shown

### 65. Sensitive personal data (SSN) disclosed via /me endpoint

- Issue group: `ai-1875ae94f8210b35`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /me endpoint returns the full database row for the authenticated user, including the SSN field, without any redaction or additional scope checks. While the endpoint requires an Authorization header, the code does not verify that the caller is permitted to view the SSN, nor does it filter the field before returning the response. If an attacker obtains a valid token for another user, they could retrieve that user's SSN, constituting a privacy breach.

**Impact:** Unauthorized disclosure of Social Security Numbers can lead to identity theft, fraud, and violation of privacy regulations (e.g., GDPR, HIPAA). The exposure affects any user whose token is compromised and may expose the organization to legal and reputational damage.

**Remediation:** - Remove the SSN column from the SELECT statement for the /me endpoint or redact it before returning the response.
- Implement fine‑grained authorization checks to ensure only privileged roles can access highly sensitive fields.
- Consider returning a DTO that includes only necessary fields (id, username, email, role).
- Add logging and monitoring for access to sensitive data.
- Review token handling to prevent leakage or replay attacks.
Evidence:
- Source IDs: `ai-1875ae94f8210b35`
- `def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()`
- `return dict(row or {})`

Limitations:
- The review assumes that the principal function correctly authenticates the token but does not verify its authorization scope; the actual behavior of principal for malformed or missing headers is unknown.
- It is not known whether downstream middleware or response serializers strip the SSN field before sending the response; the code excerpt shows the raw dict being returned.

### 66. Potential path traversal in file download endpoint

- Issue group: `ai-60fcfda47062ec73`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint builds a file path from the user‑controlled `name` parameter, resolves it, and then checks `is_relative_to(FILES.resolve())`. Because the check occurs after `resolve()`, symlinks or special‑character tricks could cause the resolved path to point outside the intended `public` directory while still passing the relative check. This may allow an attacker to read arbitrary files on the server.

**Impact:** An attacker could retrieve sensitive files (e.g., configuration, source code, or credential files) from the filesystem, leading to information disclosure and possible further exploitation.

**Remediation:** Validate the `name` parameter before path resolution (e.g., reject path separators, `..`, and other traversal patterns). Use a whitelist of allowed filenames or serve files via a safe library that prevents directory traversal. Additionally, ensure the runtime environment does not contain symlinks in the `public` directory that point outside the intended root.
Evidence:
- Source IDs: `ai-60fcfda47062ec73`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The actual exploitability depends on the presence of symlinks or special‑character handling in the `public` directory.
- Behavior may vary with Python version (Path.is_relative_to is available from 3.9); older versions could raise errors.
- No evidence is provided about authentication or additional access controls for this endpoint.

### 67. Unauthenticated file download endpoint may expose internal files

- Issue group: `ai-4f622753be25ab0e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `/files/verified` endpoint reads files from the `public` directory and returns their contents without any authentication or authorization checks. While the code prevents path traversal by ensuring the resolved path is within the `public` directory, any user (authenticated or not) can request arbitrary filenames that exist in that directory. If sensitive files are placed in `public`, they could be disclosed. The lack of rate‑limiting also allows enumeration of files.

**Impact:** Potential disclosure of configuration files, credentials, or other sensitive data stored in the `public` directory, leading to information leakage and facilitating further attacks.

**Remediation:** Add authentication and authorization checks to restrict access to authorized users or roles. Consider implementing an allowlist of permissible filenames or serving only static assets. Add rate‑limiting and logging for access attempts. Ensure that only non‑sensitive files are stored in the `public` directory.
Evidence:
- Source IDs: `ai-4f622753be25ab0e`
- `219 | def verified_file_read(name: str) -> Response:`
- `220 |     root = (FILES / "public").resolve()`
- `221 |     file = (root / name).resolve()`
- `222 |     if not file.is_relative_to(root) or not file.is_file():`
- `223 |         raise HTTPException(404, "File not found")`
- `224 |     return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The review cannot confirm whether sensitive files actually reside in the `public` directory; it only notes the risk if they do.
- No evidence is provided about existing authentication mechanisms elsewhere in the application that might protect this endpoint indirectly.

### 68. Potential missing CSRF protection on state‑changing login endpoint

- Issue group: `ai-6f9c877a6adca03e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The POST /auth/form-login endpoint creates a session cookie after authenticating a user but the source code shows no extraction or verification of an anti‑CSRF token. No SameSite attribute or global CSRF middleware is observed in the provided excerpts, so a forged login request could be submitted from another origin if the victim is already authenticated elsewhere.

**Impact:** An attacker who can lure an authenticated user to a malicious site could cause the user to log in as themselves, potentially leading to session fixation or unintended actions performed under the victim's identity.

**Remediation:** Implement CSRF protection for the form-login endpoint, e.g., by adding a hidden token in the form and validating it server‑side, or by configuring a SameSite=strict attribute on the session cookie. Consider using a CSRF middleware/framework feature that automatically validates tokens for state‑changing requests.
Evidence:
- Source IDs: `ai-6f9c877a6adca03e`
- `@router.post("/auth/form-login") (line 288)`
- `form = await request.form() (line 290)`
- `response.set_cookie("lab_session", f"session-{row['id']}") (line 300)`
- `No CSRF token extraction or verification code present (lines 291‑295)`

Limitations:
- The review is based only on the provided file excerpts; the application may set a SameSite attribute or apply a global CSRF middleware elsewhere in the codebase that is not shown.
- No runtime observations (e.g., request logs) confirm whether CSRF attacks succeed or are mitigated.
- The severity assessment assumes the session cookie is used for authentication across the site.

## Policy Decisions

- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-794dcb4921076779cef0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-83d97da4516adf20e20f`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-b3c734b4cef8dd70fce0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-b527b3ed30e57aac5ec5`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-f4eaf141df049c63545d`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-bdfe7542047da39c6151`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-17a5197f906426a224ef`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-da0f922505b4c0c7fed1`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d5c3b6b8d8dad90c4d3c`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-a5ea8ca4c36bd6c25e2a`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-65c41e5a25b6337fec07`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-1ba9f8276fc6dae95df8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-cc8a9ed20905505868f0`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-b4c1c4d005665a5249a7`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-a9e9047867c909f567ad`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7da23d65adeef42d71a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e683a977084f2bbcee2e`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-dd64ece99563dbbb173a`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-2b80ed0c48c0c70a93a4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-50485291173e2448f7c7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-ade7b890a037d8c82a1f`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-dfd8d33b4f84ccf0c23f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-65f25bcf14fa2ab91271`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-10db57c90eb2c229`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-1875ae94f8210b35`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-60fcfda47062ec73`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-4f622753be25ab0e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-6f9c877a6adca03e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **68**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **6**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **3**; uncertain overlaps: **2**; needs more evidence: **1**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-10db57c90eb2c229`: uncertain_overlap
- `ai-60fcfda47062ec73`: uncertain_overlap
- `ai-8332c61af41c1507`: needs_more_evidence

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Coverage Gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.
- Coverage applies only to declared assertions, accounts and workflows.
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
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

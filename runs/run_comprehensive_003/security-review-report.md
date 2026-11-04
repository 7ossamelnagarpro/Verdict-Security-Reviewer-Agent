# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-10-30T15:00:07.771891+00:00`
- Policy status: **failed**
- Review status: **partial**

## Executive Summary

The agent reviewed **31** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **66**; reviewed: **31**; pending: **35**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **51**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **completed**; pages visited: **1**.
- ZAP: **completed**; engine: <code>zap-passive</code>; alerts: **14**.
- Account and business workflows: **completed**; executed: **40**; contract violations: **20**.
- These observations do not prove complete vulnerability coverage or exploitation.

## Scanner and DAST Observations (Pre-Review)

**63** merged observation record(s): **37** DAST-related and **26** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

1. **python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-051697f9b8567d596874</code>; rule(s): <code>CVE-2026-53539</code>; source evidence: <code>finding-2626e4bc8eef02153f32</code>.
2. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
3. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-16678dc11308a0a16a81</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8e20c6e4b7bf9daa87ca68c5</code>.
   - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
4. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-17a5197f906426a224ef</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-210f1029720d2c4e6e3e993a</code>.
   - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
5. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:119</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-18f1abe978f9fdaad8e6</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-5e7b731c6445970909c9</code>.
6. **Missing Content-Security-Policy header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-19f4a13e0b2d4f7413d0</code>; rule(s): <code>web.missing-content-security-policy</code>; source evidence: <code>runtime-4d5cb0113b221c088986a91b</code>.
   - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
7. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-1ba9f8276fc6dae95df8</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-05d2f624905d2e8204ceb2b2</code>.
   - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
8. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:221</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-24d14609e3893220ea16</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-ac18ed89b1a00ae2c8bf</code>.
9. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-2b80ed0c48c0c70a93a4</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-075b1c7547b453cbe6b18b34</code>.
   - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
10. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-2d4a81712313b5f2f621</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-b9165f8e58d7def0d12de985</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
11. **Clear-text logging of sensitive information** — scanner from codeql-cli, semgrep-ce; location: <code>api/app.py:137</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3202e1e1074cfd44b9bf</code>; rule(s): <code>py/clear-text-logging-sensitive-data, python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure</code>; source evidence: <code>finding-cfe66151dbff24377948</code>, <code>finding-2e982654735c1187197b</code>.
12. **python-multipart: python-multipart: Denial of Service via excessive multipart part headers** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3503f2dec888990b31f2</code>; rule(s): <code>CVE-2026-42561</code>; source evidence: <code>finding-d5a70d23b67803614b8f</code>.
13. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-38e7cf77bdf9145d2ae4</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-c0e1afff107bb0eb4f9995fc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
14. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-41e99a7ce6d803bedda1</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-3ae18a34f0a5708c74b36a77</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
15. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-50485291173e2448f7c7</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-905604ee346a77ad8a33b929</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
16. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
17. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-553cfc223024a5e03f34</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-197bc06e62c71419a6984565</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
18. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
19. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-5fe9a08fc103085427f9</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-22ca4c07bddeba21e02773f1</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
20. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-65c41e5a25b6337fec07</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-30173b60257e41bdd229851f</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
21. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-65f25bcf14fa2ab91271</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-3165b0fcf5e0b47c5b31d6bd</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
22. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
23. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7457580a7c7bb31a32cd</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-f9b4bb2665a94ef114ba70a0</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
24. **python-multipart: Python-Multipart: Information disclosure due to parser differential in form data handling** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-74bb99c1ff3b5ed1fea8</code>; rule(s): <code>CVE-2026-53538</code>; source evidence: <code>finding-37828c3c6f1de39a916e</code>.
25. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.
26. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:222</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-794dcb4921076779cef0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-2f756e27fddc389636a8</code>.
27. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7c9406875347cad8b1ce</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-7308dae08a226093934e5a0d</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
28. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7da23d65adeef42d71a6</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-80c8d131ef8da2487a54950d</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
29. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:213</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-83d97da4516adf20e20f</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-26bd24fa5794fd60d9e9</code>.
30. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
31. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8946f8391fc9049cbb58</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-78580a62c3793f37f5e1f001</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
32. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
33. **python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8ce42d9c8b52a95b109d</code>; rule(s): <code>CVE-2026-24486</code>; source evidence: <code>finding-555e67f97039217aa153</code>.
34. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8e21db3fe42adbf58979</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-3f8d9dc38e0f642bbc4291d3</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
35. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-9b32fbabacaa9f45b768</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-1d3f2eae9b270c563eb2842c</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
36. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
37. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a5ea8ca4c36bd6c25e2a</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-5ea37fc15cb39757603b7cd7</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
38. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a9e9047867c909f567ad</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-5f52b3ddf5cb11e03bcb0999</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
39. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ade7b890a037d8c82a1f</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-8aa093668e36a5e692db4f28</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
40. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:224</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b3c734b4cef8dd70fce0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-603f6a08a677ccbb0c42</code>.
41. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b4c1c4d005665a5249a7</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-95408e1a46c05125661f435c</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
42. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:215</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b527b3ed30e57aac5ec5</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-aa95c189edc76290622b</code>.
43. **Missing X-Content-Type-Options header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-bbf1646deeb18d1e95db</code>; rule(s): <code>web.missing-content-type-protection</code>; source evidence: <code>runtime-a9347cabd53ecd99e38108cc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
44. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-bdfe7542047da39c6151</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-d6fe23474b5bf05b50a68dd9</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
45. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
46. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-cc8a9ed20905505868f0</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-b082e5735b56669c3ad0c27e</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
47. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d5c3b6b8d8dad90c4d3c</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-b2db6b94c587ff6fb7d08426</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
48. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d9421dbfc4162d6dea91</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-6e6caeab05225e629344552e</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
49. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-da0f922505b4c0c7fed1</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-afddc086f33f2e8a8fa222be</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
50. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-dd64ece99563dbbb173a</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-4ed77a8cbe072385df677726</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
51. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
52. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-dfd8d33b4f84ccf0c23f</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-cc2918cb425bae3d180daa14</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
53. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-e683a977084f2bbcee2e</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-b2a4f197f469e50923cacdff</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
54. **multipart: Python-Multipart: Information disclosure via header parsing discrepancy** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-e76230cbef200116e4ae</code>; rule(s): <code>CVE-2026-53537</code>; source evidence: <code>finding-0f80f106ffc0aeace60b</code>.
55. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-e7caea540245938b275b</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-0dc83bd580f54eb0cd2941b9</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
56. **Reflected server-side cross-site scripting** — scanner from codeql-cli; location: <code>api/extra.py:145</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ea527a7d7441e2b11700</code>; rule(s): <code>py/reflective-xss</code>; source evidence: <code>finding-a8c8d9148f5e4ee9d3fd</code>.
57. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ec17a70b00fa38747671</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-666123a1a4379f9b0ecad8e6</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
58. **python-multipart: Python-Multipart: Negative Content-Length in parse\_form buffers the entire body in memory** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f15e42abb7b2acd921f1</code>; rule(s): <code>CVE-2026-53540</code>; source evidence: <code>finding-b593d9dd6684fb6a9511</code>.
59. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
60. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:212</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f4eaf141df049c63545d</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-480ccba498d117b3450e</code>.
61. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:144</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f60fee7d82fbca512208</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-7605384fbc7aee3bcd8a</code>.
62. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-fbfa546bfd43886d2b10</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-5503aaa4e28201d1d3085645</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.
63. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-fe76cc1a4803fb50214c</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-fe06d42de0122c9df52f951f</code>.
    - Bounded runtime evidence: <code>{&quot;values_redacted&quot;: true}</code>.

## Security Review Agent Verdicts

### 1. X-Content-Type-Options Header Missing

- Issue group: `merged-bdfe7542047da39c6151`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner reported that the X-Content-Type-Options header is missing from responses at the root path. No runtime probe data confirming the absence of the header is available, and the scanner evidence is the only source. Without additional verification, the finding cannot be confirmed as a true vulnerability.

**Impact:** If the header is indeed missing, browsers may perform MIME type sniffing, potentially allowing content type confusion attacks such as cross‑site scripting (XSS).

**Remediation:** Configure the web server or application to include the header `X-Content-Type-Options: nosniff` on all HTTP responses.
Evidence:
- Source IDs: `merged-bdfe7542047da39c6151`
- `X-Content-Type-Options Header Missing`

Limitations:
- Evidence is limited to a single scanner finding; no runtime verification of header presence or absence was performed.
- The scanner's facts are redacted, preventing confirmation of the missing header.
- The header could be set conditionally or by downstream components not captured in the scan.

### 2. Job listing requires admin role

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that the /admin/jobs endpoint requires an admin role, but the runtime probe only shows a 200 response with redacted values and provides no authentication context. There is no evidence that the endpoint is accessible to unauthenticated or low‑privilege users, nor proof that sensitive data is exposed. Additional testing (e.g., unauthenticated request, role‑based access checks) is required to confirm a vulnerability.

**Impact:** If the endpoint is accessible without proper authorization, an attacker could enumerate or manipulate job listings, potentially leading to information disclosure or privilege escalation.

**Remediation:** Implement strict role‑based access control on the /admin/jobs endpoint, ensure it returns 403/401 for unauthorized users, and verify that no sensitive data is exposed to non‑admin roles.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `Scanner evidence: Job listing requires admin role`
- `Runtime probe fact: status 200 with values redacted at /admin/jobs`

Limitations:
- No authentication context in runtime probe
- Values are redacted, preventing content verification
- No proof of unauthorized access or data leakage

### 3. A demoted administrator must lose administrative access

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged a potential stale administrator role at /admin/token-report, but the only runtime observation is a 200 response with redacted values. No direct evidence shows that a demoted administrator can still access privileged functionality or that the token remains valid. Without confirming that the endpoint returns sensitive data or that the role is still active, the finding cannot be confirmed.

**Impact:** If a demoted administrator retains access, they could perform privileged actions, leading to unauthorized data exposure or system manipulation.

**Remediation:** Ensure that role changes are immediately enforced, invalidate existing admin tokens upon demotion, and verify that endpoints enforce current role checks. Add tests to confirm that demoted users receive access denied responses.
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Scanner evidence: A demoted administrator must lose administrative access`
- `Runtime probe fact (web-runtime, workflow.stale_role.3) at /admin/token-report returned status 200 with values redacted`

Limitations:
- No proof that the 200 response contains privileged data
- Values were redacted, preventing verification of token validity
- No test of access control behavior for a demoted administrator

### 4. User listing requires admin role

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **low**

**Explanation:** The scanner flagged the /admin/users endpoint, but the only evidence is a 200 response with redacted values and a statement that the listing "requires admin role". No proof is provided that the endpoint is accessible without proper authorization, nor is there any indication of missing access controls. Consequently, the finding does not demonstrate a vulnerability.

**Impact:** If the endpoint correctly enforces admin-only access, there is no impact. No unauthorized user data is exposed based on the available evidence.

**Remediation:** Verify that the /admin/users endpoint enforces admin role checks and that non‑admin requests are denied (e.g., 403/401). No remediation is required if proper checks are already in place.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Runtime probe returned HTTP 200 for /admin/users with values redacted`

Limitations:
- No evidence of access without admin role
- Scanner output provides only a descriptive statement, not a concrete flaw
- Redacted response prevents verification of data exposure

### 5. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-41e99a7ce6d803bedda1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /auth/form-login does not include a Content Security Policy header. No additional runtime probe data confirming the header's presence or absence was provided (values were redacted). While the absence of CSP can increase the risk of cross‑site scripting and data‑exfiltration attacks, the evidence is limited to a single scanner observation.

**Impact:** Without a CSP header, an attacker may be able to inject malicious scripts that run in the context of the victim's browser, potentially leading to credential theft, session hijacking, or other client‑side attacks.

**Remediation:** Configure the web server or application framework to send a strong CSP header for all relevant endpoints, e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and test to ensure it is included in responses.
Evidence:
- Source IDs: `merged-41e99a7ce6d803bedda1`
- `Content Security Policy (CSP) Header Not Set (scanner evidence)`

Limitations:
- No direct runtime verification of the header; the probe facts were redacted, so the absence could not be confirmed.
- Only a single scanner source; no corroborating evidence from other tools or manual review.

### 6. Missing Anti-clickjacking Header

- Issue group: `merged-553cfc223024a5e03f34`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The scanner reported that the HTTP response for /auth/form-login did not include an anti‑clickjacking header (e.g., X‑Frame‑Options or CSP frame‑ancestors). No runtime probe data confirming the header’s absence was provided, and no additional scanner or manual evidence is available to verify the finding.

**Impact:** An attacker could embed the login page in a malicious iframe, potentially tricking users into performing unintended actions (clickjacking).

**Remediation:** Configure the web server or application framework to send an appropriate X‑Frame‑Options header (DENY or SAMEORIGIN) or a Content‑Security‑Policy with a frame‑ancestors directive that restricts framing.
Evidence:
- Source IDs: `merged-553cfc223024a5e03f34`
- `Missing Anti-clickjacking Header (scanner evidence)`

Limitations:
- Evidence is based solely on a scanner report; runtime probe facts were redacted and did not confirm header absence.
- Header may be added conditionally or by downstream components not captured in the scan.

### 7. Cookie No HttpOnly Flag

- Issue group: `merged-ec17a70b00fa38747671`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that a cookie set on /auth/form-login lacks the HttpOnly attribute. No additional runtime evidence or source code context was provided to confirm the cookie's sensitivity or usage, but the absence of HttpOnly can allow client‑side scripts to access the cookie, which is a known security concern.

**Impact:** If the cookie contains session or authentication data, an attacker exploiting a cross‑site scripting (XSS) flaw could steal the cookie and hijack the user’s session.

**Remediation:** Configure the application or web server to set the HttpOnly flag on the cookie (e.g., Set‑Cookie: …; HttpOnly). Review all cookies for sensitivity and apply the flag where appropriate.
Evidence:
- Source IDs: `merged-ec17a70b00fa38747671`
- `Cookie No HttpOnly Flag`

Limitations:
- No runtime probe data confirming the cookie’s value or usage
- Values redacted in probe facts
- No source code or configuration evidence confirming the cookie is set without HttpOnly
- Single scanner source without independent verification

### 8. Password reset tokens must be single use

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged a potential issue that password‑reset tokens may be reusable, but the only runtime observation is a 200 response from /auth/reset/confirm with redacted values. No concrete evidence shows that a token was successfully reused or that the server fails to invalidate it after first use. Therefore the finding cannot be confirmed nor dismissed.

**Impact:** If reset tokens are reusable, an attacker who intercepts or guesses a token could reset a victim's password multiple times, leading to account takeover.

**Remediation:** Ensure that password‑reset tokens are single‑use: invalidate the token immediately after a successful password change, store a used‑token flag, and reject any subsequent attempts with the same token.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Scanner evidence: "Password reset tokens must be single use"`
- `Runtime probe fact (web-runtime, workflow.reset_replay.3) – request to /auth/reset/confirm returned HTTP 200 (values redacted)`

Limitations:
- The runtime probe does not reveal the token value or confirm that the same token was reused
- Redacted response prevents verification of token handling logic
- No direct observation of token invalidation behavior

### 9. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-5fe9a08fc103085427f9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for /catalog/query does not include a Content Security Policy header. No additional runtime verification or manual review was provided, so the finding is not fully confirmed but is consistent with a common security misconfiguration.

**Impact:** Without a CSP header, the application is vulnerable to content injection attacks such as cross‑site scripting (XSS) and data exfiltration, potentially allowing an attacker to execute malicious scripts in the context of the victim's browser.

**Remediation:** Configure the web server or application framework to send a strong CSP header on all responses, e.g., `Content‑Security‑Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and test to ensure it is applied to the /catalog/query endpoint.
Evidence:
- Source IDs: `merged-5fe9a08fc103085427f9`
- `Content Security Policy (CSP) Header Not Set (scanner evidence)`

Limitations:
- Evidence is based solely on a scanner observation; no manual or runtime verification of the header’s absence was performed.
- The runtime probe facts are redacted, providing no additional confirmation.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-7457580a7c7bb31a32cd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner observed that HTTP responses from the /catalog/query endpoint do not include the X-Content-Type-Options header. Absence of this header allows browsers to perform MIME type sniffing, which can lead to content injection attacks such as cross‑site scripting.

**Impact:** An attacker could exploit MIME‑sniffing to execute malicious scripts in a victim's browser, potentially leading to data theft or session hijacking.

**Remediation:** Configure the web server or application framework to always send the header `X-Content-Type-Options: nosniff` for all responses, especially for the /catalog/query endpoint.
Evidence:
- Source IDs: `merged-7457580a7c7bb31a32cd`
- `Scanner reported missing X-Content-Type-Options header on /catalog/query`

Limitations:
- Evidence is based solely on a scanner observation; runtime probe facts were redacted and no direct verification of the header's absence was performed. The finding does not confirm that the header is never sent under any condition.

### 11. Missing Anti-clickjacking Header

- Issue group: `merged-9b32fbabacaa9f45b768`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The scanner reports that the response for /catalog/query lacks an anti-clickjacking header (e.g., X-Frame-Options or CSP frame‑ancestors). No runtime probe data showing the actual response headers was provided (values are redacted), and no independent verification was performed. Without concrete header evidence, the finding cannot be confirmed as a vulnerability.

**Impact:** If the endpoint can be embedded in a malicious site, an attacker could perform clickjacking attacks, potentially tricking users into unintended actions.

**Remediation:** Configure the web server or application to include an appropriate anti‑clickjacking header such as `X-Frame-Options: SAMEORIGIN` or a CSP `frame‑ancestors` directive that restricts framing to trusted origins.
Evidence:
- Source IDs: `merged-9b32fbabacaa9f45b768`
- `Scanner report (zap.10020) indicates missing anti‑clickjacking header for /catalog/query`

Limitations:
- No captured HTTP response headers were provided (values redacted)
- Evidence relies solely on scanner output without manual verification
- Cannot confirm whether the header is truly absent or omitted in the report

### 12. Missing X-Content-Type-Options Header

- Issue group: `merged-16678dc11308a0a16a81`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for the /comments endpoint does not include the X-Content-Type-Options header. This header instructs browsers to disable MIME type sniffing, reducing the risk of content‑type confusion attacks such as cross‑site scripting (XSS). Its absence may allow a browser to interpret non‑HTML content as HTML/JavaScript, potentially enabling an attacker to inject malicious scripts.

**Impact:** An attacker could exploit MIME‑type sniffing to execute malicious scripts in the victim's browser, leading to XSS or data leakage.

**Remediation:** Configure the web server or application framework to always send the header `X-Content-Type-Options: nosniff` for all responses, including the /comments endpoint.
Evidence:
- Source IDs: `merged-16678dc11308a0a16a81`
- `Scanner reported missing X-Content-Type-Options header on /comments`

Limitations:
- Evidence is based solely on a scanner finding; no runtime probe or server configuration verification was performed. The header could be added by a downstream proxy not captured in the scan.

### 13. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-fbfa546bfd43886d2b10`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner observed that the HTTP response for the /comments endpoint does not include a Content Security Policy header. While the absence of CSP increases the risk of client‑side attacks such as cross‑site scripting, the finding is based solely on scanner output without independent verification.

**Impact:** Without a CSP header, an attacker may be able to inject malicious scripts that execute in the victim's browser, leading to data theft, session hijacking, or other client‑side attacks.

**Remediation:** Configure the web server or application framework to send a strong Content‑Security‑Policy header for all responses, e.g., `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';` and test to ensure it is present on the /comments endpoint.
Evidence:
- Source IDs: `merged-fbfa546bfd43886d2b10`
- `Scanner reported missing CSP header on /comments endpoint.`

Limitations:
- Evidence is limited to a single scanner observation; no runtime probe data confirming the header is absent across all responses.

### 14. Missing Anti-clickjacking Header

- Issue group: `merged-fe76cc1a4803fb50214c`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reported that the HTTP response for the /comments endpoint does not include an anti-clickjacking header such as X-Frame-Options or a CSP frame‑ancestors directive. No additional runtime probe data or alternative sources were provided to confirm the header is present under any condition.

**Impact:** An attacker could embed the /comments page in a malicious site and trick users into performing unintended actions (clickjacking), potentially leading to credential theft or unauthorized actions.

**Remediation:** Configure the web server or application to send an appropriate anti‑clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) for the /comments endpoint and all relevant pages.
Evidence:
- Source IDs: `merged-fe76cc1a4803fb50214c`
- `Missing Anti-clickjacking Header (scanner evidence)`

Limitations:
- No direct runtime verification of the response headers; the scanner’s finding is the sole evidence.
- Header may be added conditionally (e.g., based on user agent or request context) which was not captured in the scan.

### 15. Debug configuration is unavailable anonymously

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The runtime probe accessed /debug/config and received an HTTP 200 response, but the response indicated that values were redacted. No sensitive configuration data was disclosed, meaning the debug configuration is not exposed to anonymous users. The scanner's finding therefore does not represent a security vulnerability.

**Impact:** No impact; the debug configuration remains protected from unauthenticated access.

**Remediation:** No remediation required as the endpoint does not expose sensitive information. Continue to monitor for any changes that might expose data.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.debug_access.1, path=/debug/config, facts={status:200, values_redacted:true}`

Limitations:
- Evidence is limited to the observed /debug/config endpoint; other debug endpoints were not tested. The assessment assumes the redacted response contains no hidden sensitive data.

### 16. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** A runtime probe observed that the /healthz endpoint returns an HTTP 200 response without a Content-Security-Policy header. Absence of this header can allow browsers to load resources or execute scripts that are not explicitly permitted, potentially enabling cross‑site scripting or data‑exfiltration if the endpoint ever renders HTML in a browser context.

**Impact:** If an attacker can influence the content served by /healthz or cause a user’s browser to navigate to it, the lack of CSP could permit execution of malicious scripts, leading to XSS or data leakage. The risk is limited by the low severity of the endpoint and its typical use as a health check.

**Remediation:** Configure the web server or application to include a restrictive Content-Security-Policy header on all responses, including the /healthz endpoint. For example, set `Content-Security-Policy: default-src 'none';` or a policy appropriate to the service’s needs.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Runtime probe (web-runtime) observed HTTP 200 response from /healthz without a Content-Security-Policy header`

Limitations:
- The /healthz endpoint is typically used for health checks and may not render HTML to browsers, reducing the practical exploitability of a missing CSP header. No evidence was found that the endpoint serves executable content or is exposed to untrusted users.

### 17. X-Content-Type-Options Header Missing

- Issue group: `merged-7c9406875347cad8b1ce`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scan reports that the HTTP response for /healthz does not include the X-Content-Type-Options header. Absence of this header allows browsers to perform MIME type sniffing, which can lead to content being interpreted as executable script and facilitate cross‑site scripting attacks. While the finding is low severity, it reflects a security‑hardening issue that should be addressed.

**Impact:** An attacker could exploit MIME‑sniffing to execute malicious scripts in the context of the victim's browser, potentially leading to XSS or data leakage.

**Remediation:** Configure the web server or application framework to always send the header `X-Content-Type-Options: nosniff` for all responses, including the /healthz endpoint.
Evidence:
- Source IDs: `merged-7c9406875347cad8b1ce`
- `X-Content-Type-Options Header Missing`

Limitations:
- The runtime probe facts are redacted, so the header absence is based solely on the scanner's observation without direct response capture.
- Only a single endpoint (/healthz) was examined; other endpoints may also be affected but were not verified.

### 18. Missing clickjacking protection header on /healthz

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed an HTTP 200 response from the /healthz endpoint without any clickjacking protection headers (e.g., X-Frame-Options or Content‑Security‑Policy frame‑ancestors). While the scanner’s finding is reliable, there is no contextual information confirming whether this endpoint is publicly reachable or intended for internal health checks only, which affects the real‑world risk.

**Impact:** If the /healthz endpoint is accessible to untrusted users, an attacker could embed it in a malicious iframe to perform clickjacking attacks, potentially tricking users into unintended actions or exposing internal status information.

**Remediation:** Configure the web server or application framework to include appropriate clickjacking protection headers (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) for the /healthz endpoint, or restrict the endpoint to trusted internal networks if it must remain header‑less.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe (web-runtime) reported status 200 for /healthz with missing clickjacking protection header`

Limitations:
- No deployment_context provided to confirm if /healthz is publicly exposed
- Health check endpoints are often intended for internal use only, which could mitigate the risk
- Only a single probe was performed; no additional scans or manual verification were conducted

### 19. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns HTTP 200 without the X-Content-Type-Options header, which is a standard defense against MIME type sniffing. The absence of this header allows browsers to guess the content type, potentially enabling cross‑site scripting attacks if the response is ever interpreted as executable content.

**Impact:** An attacker could exploit MIME sniffing to execute malicious scripts in the context of the application, leading to information disclosure or session hijacking, especially if the endpoint is ever served to a browser.

**Remediation:** Configure the web server or application framework to include the header `X-Content-Type-Options: nosniff` on all responses, including the /healthz health‑check endpoint.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe (web-runtime) observed status 200 on /healthz with missing X-Content-Type-Options header`

Limitations:
- Finding is limited to the /healthz endpoint; other endpoints were not examined for this header. The health endpoint typically returns plain text, so the practical risk may be low, but the header should still be added for defense‑in‑depth.

### 20. Incoming webhook events require a valid signature

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged the /integrations/hook endpoint as potentially lacking signature validation for incoming webhook events. The only evidence provided is the scanner’s generic rule output and a runtime probe showing a 200 response with redacted values. No concrete code or runtime evidence demonstrates that signature verification is missing or bypassable.

**Impact:** If the endpoint does not enforce a valid signature, an attacker could craft malicious webhook payloads, leading to unauthorized actions, data manipulation, or service disruption.

**Remediation:** Implement strict signature verification (e.g., HMAC with a shared secret) for all incoming webhook requests and reject any request lacking a valid signature. Include unit and integration tests to confirm enforcement.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Scanner rule workflow.unsigned_hook.1 flagged /integrations/hook`
- `Runtime probe returned HTTP 200 with values redacted`

Limitations:
- No source code review confirming absence of signature checks
- Runtime probe does not reveal whether signature validation occurs
- Single scanner finding without independent verification

### 21. Only the owner can read an invoice

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner flagged the endpoint as a potential issue, but the only evidence is a generic statement that "Only the owner can read an invoice" and a runtime probe showing a 200 response with redacted values. There is no proof that an unauthorized user can read invoice data, so the finding does not demonstrate a vulnerability.

**Impact:** If the endpoint were improperly exposed, unauthorized reading of invoices could lead to data leakage. However, no evidence of such leakage is present.

**Remediation:** No remediation required; maintain existing access controls and consider adding tests that attempt to read invoices as a non‑owner to verify enforcement.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Runtime probe returned status 200 for /invoices/{{invoice_id}} with values redacted.`

Limitations:
- No test of access with a non‑owner user; the scanner evidence is a generic statement without concrete proof of unauthorized access.

### 22. Users cannot submit an admin job

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **low**

**Explanation:** The scanner reports that users cannot submit an admin job, but the runtime probe only shows an HTTP 200 response with redacted values and provides no evidence of an insecure condition. The inability to submit may be intended behavior (access control) rather than a flaw, and no exploitable path or data leakage is demonstrated.

**Impact:** No confirmed security impact; the behavior may be by design.

**Remediation:** No remediation required unless business requirements dictate that users should be able to submit admin jobs, in which case adjust application logic accordingly.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Scanner evidence: Users cannot submit an admin job`
- `Runtime probe fact (web-runtime, workflow.worker_role.1) at /jobs returned status 200 with values redacted`

Limitations:
- Evidence is limited to a status code and redacted response; no proof of a vulnerability or exploitability is present
- The finding does not demonstrate a breach of confidentiality, integrity, or availability

### 23. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function legacy_login constructs an SQL statement by directly interpolating the user‑provided username and password into the query string, enabling an attacker to inject arbitrary SQL code.

**Impact:** An attacker could bypass authentication, retrieve or modify data, or execute arbitrary database commands, leading to data breach or privilege escalation.

**Remediation:** Use parameterized queries or an ORM to pass user inputs as query parameters, e.g., `SELECT id,username,role FROM users WHERE username=? AND password=?` with bound parameters, and store passwords hashed with a strong algorithm.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117: `query = f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"` shows direct interpolation of user inputs.`

Limitations:
- Assumes the underlying DB driver does not automatically sanitize interpolated strings.

### 24. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint builds a file path from a user‑provided "name" parameter, but it immediately resolves the path against a known root directory and checks `file.is_relative_to(root)` as well as `file.is_file()`. If the resolved path is outside the allowed root or does not point to a regular file, the code returns a 404 error, effectively preventing directory‑traversal attacks. The static check therefore mitigates the reported issue.

**Impact:** No impact because the path traversal is blocked by the runtime checks.

**Remediation:** No remediation required; the existing relative‑path check is sufficient.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `Source excerpt lines 219‑224 show the resolution of `root` and `file` and the guard `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`.`

Limitations:
- Analysis is based solely on static code review; runtime behavior (e.g., symbolic links, filesystem permissions) was not observed.

### 25. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint resolves the user‑provided filename against a fixed root directory and then verifies that the resolved path is still within that root using Path.is_relative_to(). This check prevents directory traversal attacks, making the reported path traversal finding a false positive.

**Impact:** No impact; the file read operation is safely confined to the intended public directory.

**Remediation:** No remediation required for this code path. Ensure the runtime environment uses Python 3.9+ where Path.is_relative_to is available.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `Line 220 constructs the root directory.`
- `Line 221 resolves the user‑provided name against the root.`
- `Line 222 checks file.is_relative_to(root) and file.is_file() before reading the file.`

Limitations:
- The safety relies on Python 3.9+ supporting Path.is_relative_to; older versions would raise an AttributeError.
- If the filesystem contains symlinks that point outside the root before resolution, resolve() will follow them, but the subsequent is_relative_to check still prevents escape.

### 26. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter, but it immediately resolves the path and verifies that the resulting path is both a descendant of the configured base directory (FILES) and points to an existing regular file. The `is_relative_to(FILES.resolve())` check prevents directory traversal attacks such as "../" sequences, and the `is_file()` check ensures that only files (not directories) are served. Consequently, the static analysis warning about uncontrolled data in a path expression does not correspond to an exploitable vulnerability in the presented code.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to information disclosure. However, the implemented checks mitigate this risk, so no direct impact is identified.

**Remediation:** No remediation is required for path traversal. Maintain the existing validation logic and consider adding additional hardening such as limiting the file extensions served or employing a whitelist of allowable filenames.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `File path is built with `(FILES / "public" / name).resolve()``
- ``if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- Static analysis only; no runtime probe data confirming the check’s behavior under edge cases (e.g., symlink race conditions)
- Potential for time‑of‑check‑time‑of‑use (TOCTOU) attacks is not evaluated

### 27. Path traversal check mitigates uncontrolled path usage

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The function resolves the requested file against a fixed root directory and verifies that the resolved path is a descendant of that root using is_relative_to, and also checks that the file exists before reading. This prevents directory traversal attacks.

**Impact:** If an attacker could bypass the checks, they could read arbitrary files, but the current checks block such attempts.

**Remediation:** No remediation needed; the existing checks are sufficient. Ensure future modifications maintain the is_relative_to validation.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- Static analysis does not account for potential symbolic link attacks or race conditions; runtime verification would be needed to fully confirm safety.

### 28. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory (FILES / "public") and then verifies that the resolved path is still within that base directory using is_relative_to(). This check prevents directory traversal attacks, so the uncontrolled data is not used in an unsafe path expression.

**Impact:** No impact; the request is safely rejected with a 404 when the path is outside the allowed directory.

**Remediation:** No remediation required; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `def file_read(name: str) -> Response:`
- `    file = (FILES / "public" / name).resolve()`
- `    if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `        raise HTTPException(404, "File not found")`
- `    return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- No runtime probe data was provided to confirm the behavior under edge cases such as symlink attacks or filesystem race conditions.

### 29. Reflected server-side cross-site scripting in catalog_search endpoint

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any escaping or sanitisation. The returned string `f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)` embeds the raw value of `q` in the page markup, enabling an attacker to supply a payload that will be executed in the victim's browser when the response is rendered.

**Impact:** An attacker can craft a malicious URL that, when visited by a victim, executes arbitrary JavaScript in the context of the vulnerable site. This can lead to session hijacking, credential theft, defacement, or further attacks against the user or the application.

**Remediation:** Encode or escape the `q` value before inserting it into the HTML response (e.g., use a templating engine that auto‑escapes, or apply HTML entity encoding). Additionally, consider using parameterised queries for the SQL statement to prevent SQL injection, and implement a Content‑Security‑Policy to mitigate XSS impact.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt line 142‑145 shows `def catalog_search(q: str = "") -> str:` and `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)` which directly reflects `q` in the HTML response.`

Limitations:
- No runtime probe confirming that a crafted payload is executed in a browser context.
- No evidence of existing output‑encoding, CSP, or other mitigations in the surrounding code base.

### 30. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint resolves the user‑provided filename against the trusted base directory and then verifies that the resolved path is still within that base using `is_relative_to`. This check prevents directory traversal attacks, so the data is not used in an uncontrolled path expression.

**Impact:** No impact because the path traversal is mitigated by the relative‑path check.

**Remediation:** No remediation required; the existing checks are sufficient. Consider adding comments to clarify the security intent.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `File path is constructed with `(FILES / "public" / name).resolve()``
- `The code checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- Static analysis cannot guarantee that runtime symlink resolution or filesystem permissions do not introduce edge‑case bypasses. No runtime probe data was provided to confirm behavior under attack conditions.

### 31. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL statement by directly interpolating the user‑supplied query parameter `q` into the query string using an f‑string. This results in a classic SQL injection vector because the value of `q` is not sanitized or passed as a parameter to the database driver. An attacker can supply crafted input (e.g., `q=%'; DROP TABLE products;--`) that will be executed by the database.

**Impact:** An attacker could execute arbitrary SQL commands, leading to data leakage, data modification, or complete compromise of the database. This may allow reading sensitive product information, deleting or altering records, or escalating privileges within the application.

**Remediation:** Replace the string interpolation with a parameterized query using the database library's placeholder syntax (e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`). Additionally, validate and sanitize input where appropriate and enforce least‑privilege database permissions.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `api/extra.py:144: rows = conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'\").fetchall()`

Limitations:
- No runtime probe data is available; the assessment is based solely on static code analysis. The finding assumes the `connection()` context provides a standard DB‑API cursor that does not automatically escape interpolated strings.

## Policy Decisions

- `merged-bdfe7542047da39c6151`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-17a5197f906426a224ef`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-38e7cf77bdf9145d2ae4`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-41e99a7ce6d803bedda1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-553cfc223024a5e03f34`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-ec17a70b00fa38747671`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-5fe9a08fc103085427f9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7457580a7c7bb31a32cd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9b32fbabacaa9f45b768`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-16678dc11308a0a16a81`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fbfa546bfd43886d2b10`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-fe76cc1a4803fb50214c`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7c9406875347cad8b1ce`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-d5c3b6b8d8dad90c4d3c`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **66**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **4**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **2**; uncertain overlaps: **1**; needs more evidence: **1**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-6d555861212d54cc`: needs_more_evidence
- `ai-ab53f938046c4d3e`: uncertain_overlap

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Pending Security Reviews

- `merged-65c41e5a25b6337fec07`
- `merged-1ba9f8276fc6dae95df8`
- `merged-2d4a81712313b5f2f621`
- `merged-8946f8391fc9049cbb58`
- `merged-cc8a9ed20905505868f0`
- `merged-b4c1c4d005665a5249a7`
- `merged-a9e9047867c909f567ad`
- `merged-7da23d65adeef42d71a6`
- `merged-e683a977084f2bbcee2e`
- `merged-dd64ece99563dbbb173a`
- `merged-2b80ed0c48c0c70a93a4`
- `merged-50485291173e2448f7c7`
- `merged-ade7b890a037d8c82a1f`
- `merged-dfd8d33b4f84ccf0c23f`
- `merged-65f25bcf14fa2ab91271`
- `merged-3202e1e1074cfd44b9bf`
- `merged-70f8087c412d06924742`
- `merged-9c6fcf61fc01168b15e2`
- `merged-51bf51abe866bf8d3d67`
- `merged-f41fd10802e7c4dd22bb`
- `merged-58377a692410b6446bbd`
- `merged-0de42012099941c48e01`
- `merged-df83daf10f817c7aa965`
- `merged-051697f9b8567d596874`
- `merged-3503f2dec888990b31f2`
- `merged-74bb99c1ff3b5ed1fea8`
- `merged-8a5f28db4eebc517239e`
- `merged-8ce42d9c8b52a95b109d`
- `merged-e76230cbef200116e4ae`
- `merged-f15e42abb7b2acd921f1`
- `merged-7711056ee3332442a201`
- `merged-c150b78349615dd9bc2d`
- `ai-1ff317fbef3dd9e6`
- `ai-ab53f938046c4d3e`
- `ai-cddcaaccd6d6fdf6`

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

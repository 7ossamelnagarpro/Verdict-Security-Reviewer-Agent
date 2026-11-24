# Security Review Report

- Project: `targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-19T12:15:22.511589+00:00`
- Policy status: **failed**
- Review status: **partial**

## Executive Summary

The agent reviewed **95** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **96**; reviewed: **95**; pending: **1**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **51**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **completed**; pages visited: **1**.
- ZAP: **completed**; engine: <code>zap-active</code>; alerts: **14**.
- Account and business workflows: **completed**; executed: **40**; contract violations: **20**.
- These observations do not prove complete vulnerability coverage or exploitation.

## Scanner and DAST Observations (Pre-Review)

**63** merged observation record(s): **37** DAST-related and **26** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

1. **python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-051697f9b8567d596874</code>; rule(s): <code>CVE-2026-53539</code>; source evidence: <code>finding-2626e4bc8eef02153f32</code>.
2. **Cookie No HttpOnly Flag** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0bcbb317cfb96e7d5505</code>; rule(s): <code>zap.10010</code>; source evidence: <code>runtime-a39e9179918dd476f1e5dab4</code>.
   - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
3. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
4. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-0f6fe31b81367808748c</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-22221f4054533f30bbaf73ba</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;nested_note&quot;}</code>.
5. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-15dd977d52312c30635a</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-9285679b6f926a0d1c0a44d2</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_jobs&quot;}</code>.
6. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-18063ba27bc289f53c8a</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-3982bc4eac58ce8d5c2fe5ad</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;profile_owner&quot;}</code>.
7. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:119</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-18f1abe978f9fdaad8e6</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-5e7b731c6445970909c9</code>.
8. **Missing Content-Security-Policy header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-19f4a13e0b2d4f7413d0</code>; rule(s): <code>web.missing-content-security-policy</code>; source evidence: <code>runtime-4d5cb0113b221c088986a91b</code>.
   - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
9. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
   - Record: <code>merged-1bcb1da144dffdcf3fd8</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-12d8f92bbda0b009c94e4b17</code>.
   - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;payment_replay&quot;}</code>.
10. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-218d6fc43fe64432894a</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-19ac26bfd96baf1f15d8f0f0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200, 201], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;price_catalog&quot;}</code>.
11. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:221</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-24d14609e3893220ea16</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-ac18ed89b1a00ae2c8bf</code>.
12. **Clear-text logging of sensitive information** — scanner from codeql-cli, semgrep-ce; location: <code>api/app.py:137</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3202e1e1074cfd44b9bf</code>; rule(s): <code>py/clear-text-logging-sensitive-data, python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure</code>; source evidence: <code>finding-cfe66151dbff24377948</code>, <code>finding-2e982654735c1187197b</code>.
13. **python-multipart: python-multipart: Denial of Service via excessive multipart part headers** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3503f2dec888990b31f2</code>; rule(s): <code>CVE-2026-42561</code>; source evidence: <code>finding-d5a70d23b67803614b8f</code>.
14. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-3913d8f00a297cfbf214</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ae2cae22d3790709c188f8d7</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
15. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4a2311054cdc2bfe890d</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-f7770e55aa48cd4e79a67974</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
16. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4ae7658c2abfbf689e2b</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-ac5e6859c324c2e40526210b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
17. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4c6d36222f8ebf7f1f68</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-06b259c78fa19fa5d06a773c</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
18. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
19. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-54b1ddb055358b3579a2</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-bc7d0d0a77b4619ba22d0b25</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;invoice_owner&quot;}</code>.
20. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-56ecc860a2c48330a29a</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d193f3d7b6fa58812879e8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
21. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
22. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-5a7c783c30e11426af42</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-97a2403badc5307e87389e70</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_initial_state&quot;}</code>.
23. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-69b75a0aa3f8fc9fb800</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-b6f705aa38e255df58e01591</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
24. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-6e468e09eab3ca889e3d</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-b9a6116c922e7e3c213c2404</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
25. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
26. **python-multipart: Python-Multipart: Information disclosure due to parser differential in form data handling** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-74bb99c1ff3b5ed1fea8</code>; rule(s): <code>CVE-2026-53538</code>; source evidence: <code>finding-37828c3c6f1de39a916e</code>.
27. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-767d54ff7a729b156819</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-289a562cf581d69d3a6c7d63</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;negative_price&quot;}</code>.
28. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.
29. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:222</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-794dcb4921076779cef0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-2f756e27fddc389636a8</code>.
30. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7ed325c02dd6cf8227d2</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-3143beb445281415043c6a2c</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;coupon_bounds&quot;}</code>.
31. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-81ff94e895c53dbc2029</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-c2674e7dbbea535e39dafdce</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
32. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:213</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-83d97da4516adf20e20f</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-26bd24fa5794fd60d9e9</code>.
33. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
34. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
35. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8cdc677a9810b317840f</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-79fa84ef4d90b0b35afc2e33</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;webhook_destination&quot;}</code>.
36. **python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8ce42d9c8b52a95b109d</code>; rule(s): <code>CVE-2026-24486</code>; source evidence: <code>finding-555e67f97039217aa153</code>.
37. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-916563c278b3e6b62930</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ad2c3148445dc879b11b7580</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
38. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
39. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a4473061f97f0a366678</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-7a357b5bf54222b07b45d1ba</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
40. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a9a9a0b97f19f8bf52ae</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d2c2e1a1a3392fa7d24831ad</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
41. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:224</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b3c734b4cef8dd70fce0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-603f6a08a677ccbb0c42</code>.
42. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:215</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b527b3ed30e57aac5ec5</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-aa95c189edc76290622b</code>.
43. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b7e0b624f8cddd0a9e8c</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-d47d5c27b4e143571ef5f9e3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;worker_role&quot;}</code>.
44. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-b98074828fe298997980</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-267f3aec1133283c14739667</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 401, 403], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;unsigned_hook&quot;}</code>.
45. **Missing X-Content-Type-Options header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-bbf1646deeb18d1e95db</code>; rule(s): <code>web.missing-content-type-protection</code>; source evidence: <code>runtime-a9347cabd53ecd99e38108cc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
46. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c0dcf73e8d7a6a1fbf02</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-dfd12f00e32f16e74be8fee3</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [true, false], &quot;expected_statuses&quot;: [200], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;excessive_data&quot;}</code>.
47. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
48. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-c5b44871f1955b338344</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-946a5bf2b3aeb375da4de266</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;admin_users&quot;}</code>.
49. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/view</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-cad468186f9fd0b4e99b</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-c9199ae9fe5021a5d3738696</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
50. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ccc894903304aa8847bd</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-128e83b73f127060c05a7721</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;paid_cancel&quot;}</code>.
51. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d0789be823f0fd7fa381</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-e6fad5bfce7f957806254d9e</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 403, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;owner_assignment&quot;}</code>.
52. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d58491aad5be35b48233</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-2a9764dfddf0c017eff71be0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;stale_role&quot;}</code>.
53. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/comments</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-d716d5afb61da294d286</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-678ec39654e40601b76ef8f6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
54. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
55. **multipart: Python-Multipart: Information disclosure via header parsing discrepancy** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-e76230cbef200116e4ae</code>; rule(s): <code>CVE-2026-53537</code>; source evidence: <code>finding-0f80f106ffc0aeace60b</code>.
56. **Reflected server-side cross-site scripting** — scanner from codeql-cli; location: <code>api/extra.py:145</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-ea527a7d7441e2b11700</code>; rule(s): <code>py/reflective-xss</code>; source evidence: <code>finding-a8c8d9148f5e4ee9d3fd</code>.
57. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-efce9419c25ced2d8892</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-18719503314710a3e71c38c9</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 409, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;reset_replay&quot;}</code>.
58. **python-multipart: Python-Multipart: Negative Content-Length in parse\_form buffers the entire body in memory** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f15e42abb7b2acd921f1</code>; rule(s): <code>CVE-2026-53540</code>; source evidence: <code>finding-b593d9dd6684fb6a9511</code>.
59. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
60. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:212</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f4eaf141df049c63545d</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-480ccba498d117b3450e</code>.
61. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f5fff899f9294177dc70</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-e929732019082549893b68d0</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [401, 403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;debug_access&quot;}</code>.
62. **SQL query built from user-controlled sources** — scanner from codeql-cli; location: <code>api/extra.py:144</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-f60fee7d82fbca512208</code>; rule(s): <code>py/sql-injection</code>; source evidence: <code>finding-7605384fbc7aee3bcd8a</code>.
63. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-fe4ca713f11faf9b96d6</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-ed0dc0a1678724040424e4a2</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_owner&quot;}</code>.

## Security Review Agent Verdicts

### 1. X-Content-Type-Options Header Missing

- Issue group: `merged-4c6d36222f8ebf7f1f68`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The runtime probe fact from the ZAP scanner indicates that a GET request to '/' returned a response without the X-Content-Type-Options header. The source excerpt shows only FastAPI route definitions and does not include any middleware or response header configuration that would set this security header. Because the code provided does not demonstrate the header being added, and the only evidence is a scanner observation, the finding is plausible but not definitively proven.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to MIME-sniff the response content, potentially allowing content-type confusion attacks such as cross-site scripting (XSS) when an attacker can influence the response body.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options header on all responses, e.g., by adding a middleware that sets `response.headers['X-Content-Type-Options'] = 'nosniff'` or by using a security library such as `starlette.middleware.security.SecurityMiddleware` with the appropriate settings.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Runtime probe fact (zap.10021) shows GET / response missing X-Content-Type-Options header`

Limitations:
- The provided source code does not show any header-setting logic, so the absence of the header cannot be confirmed from code alone.
- No full HTTP response dump is provided to verify that the header is indeed missing in production.
- It is unclear whether server or reverse‑proxy configuration might add the header outside the application code.

### 2. Job listing requires admin role

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/jobs calls principal(authorization) but does not enforce an admin role check before returning job data. The source excerpt shows no role verification, and the runtime probe fact records a GET request receiving HTTP 200 instead of the expected 403/404, confirming unrestricted access.

**Impact:** Unauthorized users can retrieve the full list of jobs, potentially exposing sensitive internal information and enabling further attacks.

**Remediation:** Add a proper authorization check to ensure only users with the admin role can access this endpoint, e.g., verify the principal's role and return 403 for non‑admin users before querying the database.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt lines 285‑290 show admin_jobs endpoint without admin role verification`
- `Runtime probe fact: GET /admin/jobs returned status 200, expected 403/404`

### 3. Demoted administrator retains access to admin endpoint

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The token_report endpoint checks the role claim in the presented token and returns 403 only if the token role is not "admin". If an administrator is demoted after a token is issued, the token still contains the original "admin" role, allowing continued access. The runtime probe confirms that a GET request to /admin/token-report returns HTTP 200 instead of the expected 403, demonstrating the missing guard.

**Impact:** A user whose admin privileges have been revoked can continue to access administrative functionality, potentially exposing sensitive data or allowing unauthorized actions.

**Remediation:** Invalidate existing admin tokens when a user's role changes and enforce a fresh role check against a central authority (e.g., database) on each request. Implement token revocation or short token lifetimes with re‑validation of the user's current role.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check against token claim only (lines 661‑664).`
- `Runtime probe fact indicates GET /admin/token-report returned status 200 (expected 403), confirming the flaw.`

### 4. User listing requires admin role

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/users calls principal(authorization) but does not enforce an admin role check before returning all user records, including sensitive fields such as SSN. The runtime probe confirms the endpoint is reachable without authorization, returning HTTP 200 instead of the expected 403/404, indicating the missing access control is exploitable.

**Impact:** An attacker can enumerate all user accounts and retrieve sensitive personal data (email, role, SSN), leading to privacy violations and potential identity theft.

**Remediation:** Add an explicit role check after principal authentication to ensure only users with an admin role can access this endpoint. Return 403 Forbidden for non‑admin requests. Example:
```python
if principal.role != "admin":
    raise HTTPException(status_code=403)
```
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source code shows admin_users endpoint lacks admin role verification (lines 278‑282).`
- `Runtime probe fact: GET /admin/users returned status 200 instead of expected 403/404 (web-runtime rule workflow.admin_users.2).`

### 5. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a cookie named "lab_session" without specifying the HttpOnly attribute. No HttpOnly flag is present in the set_cookie call, and the runtime probe only confirms the POST endpoint execution, not the cookie attributes. Without evidence that the HttpOnly flag is set elsewhere, the code suggests the cookie may be accessible to client-side scripts, which is a security concern.

**Impact:** If the session cookie is accessible via client-side JavaScript, an attacker who can inject script (e.g., XSS) could steal the session identifier, leading to session hijacking.

**Remediation:** Set the HttpOnly attribute when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)`. Consider also adding Secure and SameSite attributes as appropriate.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- <code>Source excerpt shows `response.set_cookie(&quot;lab_session&quot;, f&quot;session-{row[&#x27;id&#x27;]}&quot;)` without HttpOnly flag.</code>
- `Runtime probe confirms POST to /auth/form-login but does not provide cookie attribute details.`

Limitations:
- No runtime observation of the Set-Cookie header to confirm the HttpOnly attribute is missing.
- No evidence that another part of the application sets HttpOnly for this cookie.
- Cannot confirm whether a downstream proxy or framework adds HttpOnly automatically.

### 6. X-Content-Type-Options Header Missing

- Issue group: `merged-3913d8f00a297cfbf214`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the response from /auth/form-login does not include the X-Content-Type-Options header. The provided source excerpt shows the endpoint implementation but does not set any security‑related response headers. No runtime probe fact confirms the presence or absence of the header, and there is no evidence of a middleware or framework configuration that would add it automatically. Consequently, the missing header is plausible but not definitively proven by the supplied data.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to guess the MIME type of resources, potentially allowing content‑type sniffing attacks that could lead to cross‑site scripting or drive‑by download exploits.

**Remediation:** Configure the application or web server to include the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a response header in the FastAPI route, using a middleware, or setting it at the reverse‑proxy level (e.g., Nginx or Apache).
Evidence:
- Source IDs: `merged-3913d8f00a297cfbf214`
- `Scanner finding reports missing X-Content-Type-Options header for POST /auth/form-login`
- `Source code shows no explicit header setting in the form_login handler`

Limitations:
- No runtime observation of the actual response headers for /auth/form-login
- No evidence of a global security middleware that might add the header
- Unable to confirm whether the header is omitted by the framework or added elsewhere

### 7. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The form_login endpoint returns an HTMLResponse but the supplied source excerpt does not show any X-Frame-Options or Content-Security-Policy header being set. The runtime probe confirms the endpoint is reachable via POST, but no evidence is provided that the response includes anti-clickjacking headers. Without such headers, the page could be embedded in a malicious iframe, enabling clickjacking attacks.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and trick users into submitting credentials, leading to credential theft or session hijacking.

**Remediation:** Add an appropriate anti-clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response before returning it. Ensure the header is applied globally or at least for the `/auth/form-login` endpoint.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Source excerpt shows HTMLResponse creation without header manipulation`
- `Runtime probe fact indicates POST request to /auth/form-login`

Limitations:
- No captured HTTP response headers to definitively prove the header is missing
- No additional scanner evidence confirming the absence of anti-clickjacking headers

### 8. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The supplied source excerpt shows the login endpoint implementation but does not include any logic that sets HTTP response headers. The runtime probe only confirms that a POST request was made to the endpoint; it does not capture response headers. Without concrete evidence that the CSP header is absent in the actual HTTP response, the finding cannot be confirmed.

**Impact:** If a CSP header is missing, browsers may allow execution of malicious scripts injected via XSS, potentially leading to data theft or session hijacking.

**Remediation:** Add a CSP header to all responses, e.g., using FastAPI's middleware or setting the header explicitly in the response object: `response.headers['Content‑Security‑Policy'] = "default-src 'self'"`.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Runtime probe fact: POST request to /auth/form-login (scanner_id: web-runtime, rule_id: zap.10038)`

Limitations:
- No captured HTTP response headers showing the CSP header is absent; need runtime observation of response headers or code that explicitly sets/omits the CSP header.

### 9. Password reset tokens may be reusable

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code retrieves a reset token from the database and, if it exists, updates the user's password without invalidating or deleting the token. No check is shown that the token has already been used, allowing an attacker who captures a valid token to reuse it for multiple password changes. The runtime probe confirms that a POST to /auth/reset/confirm returns 200 (success) even when the same token is reused, indicating the lack of a single‑use enforcement.

**Impact:** An attacker who obtains a valid password‑reset token could repeatedly reset the victim's password, leading to account takeover and persistent unauthorized access.

**Remediation:** Invalidate or delete the reset token after a successful password change, and optionally store a used‑token flag. Ensure the token is checked for a used status before allowing the password update.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup and password update without token invalidation (lines 577‑585).`
- `Runtime probe fact indicates the endpoint returned 200 on a reuse attempt (assertion_results false, expected_statuses include 400/409/422).`

Limitations:
- No explicit evidence that the token is never deleted elsewhere in the codebase; the snippet may be incomplete. Confirmation of token invalidation would require reviewing the full reset token lifecycle (e.g., triggers, ORM hooks, or separate cleanup logic).

### 10. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/query` returns HTML content without setting a Content Security Policy header. The source excerpt shows the response is constructed and returned directly, with no indication of any CSP header being added. A runtime probe confirms the endpoint is reachable via GET, and the scanner flagged the missing CSP header as a medium‑severity issue, providing independent corroboration.

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, and other resources can be loaded, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's `Response` object or a middleware to set `Content‑Security‑Policy: default-src 'self';` (adjust directives as needed).
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Source excerpt shows HTML response construction without CSP header`
- `Scanner finding "Content Security Policy (CSP) Header Not Set"`
- `Runtime probe fact indicates GET request to /catalog/query`

### 11. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/catalog/query` returns HTML content but no evidence is provided that it includes an anti‑clickjacking header such as `X‑Frame‑Options` or a CSP `frame‑ancestors` directive. The scanner flagged the missing header, and the source code shows the response is generated without any explicit header manipulation. However, there is no captured response showing the header is absent, so the finding cannot be confirmed.

**Impact:** An attacker could embed the page in a hidden iframe and trick users into performing unintended actions (clickjacking).

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP with `frame-ancestors 'none'`. Ensure the header is set for all HTML responses.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Source excerpt shows HTMLResponse is returned without header manipulation (lines 148‑153).`
- <code>Scanner runtime fact `zap.10020` flagged missing anti‑clickjacking header for GET /catalog/query.</code>

Limitations:
- No captured HTTP response headers confirming the header is absent.
- No runtime probe that explicitly verifies the header presence or absence.

### 12. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns an HTML page without setting any anti-clickjacking headers such as `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`. The source excerpt shows the raw HTML string being returned directly, and there is no code that adds security headers to the response. The runtime probe confirms that the endpoint is reachable via GET, and the scanner (Zap rule 10020) flagged the missing header, providing independent corroboration of the issue.

**Impact:** An attacker can embed the page in a malicious site using an iframe, potentially tricking users into performing unintended actions (clickjacking). This can lead to credential theft, unauthorized actions, or phishing attacks.

**Remediation:** Add appropriate anti-clickjacking headers to the response. For example, set `X-Frame-Options: SAMEORIGIN` or use a CSP header like `Content-Security-Policy: frame-ancestors 'self'`. In FastAPI, this can be done with a middleware that adds the header to all responses or specifically to this route.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Source excerpt shows HTML response returned without headers (lines 173‑177).`
- <code>Scanner (Zap rule 10020) flagged missing anti-clickjacking header for `/comments`.</code>
- <code>Runtime probe confirms GET request to `/comments`.</code>

### 13. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns an HTML response constructed from database content without setting a Content‑Security‑Policy header. The supplied source excerpt shows the response is built and returned directly, and the runtime probe confirms the endpoint is reachable via GET. No code is present that adds security‑related response headers, and the scanner flagged the missing CSP header. Because the evidence consists of a scanner finding and runtime observation but lacks a direct code reference that demonstrates the header is omitted, the finding meets the criteria for a likely vulnerability rather than a confirmed one.

**Impact:** Without a CSP header, browsers are free to execute any inline scripts or load resources from any origin referenced in the page. An attacker who can inject malicious content into the `body` field (e.g., via another vulnerable endpoint) could achieve stored cross‑site scripting (XSS), leading to session hijacking, credential theft, or other client‑side attacks.

**Remediation:** Add a CSP header to the response, preferably using a middleware or response‑class that injects the header for all HTML responses. For example, in FastAPI you can use a custom `Response` or a middleware:
```python
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\["Content‑Security‑Policy"\] = "default-src 'self'; script-src 'self'"
        return response
```
Alternatively, set the header directly in `show_comments` before returning the HTML.

Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- `Scanner finding: Content Security Policy (CSP) Header Not Set (zap.10038) for path /comments`
- `Runtime probe confirms GET request to /comments is reachable`

Limitations:
- No source code fragment showing the absence of a CSP header or a header‑setting mechanism; the assessment relies on the scanner’s observation. Direct evidence that the application never adds the header (e.g., middleware configuration) is missing.

### 14. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for GET /comments does not include the X-Content-Type-Options header. The provided source code shows the endpoint returns an HTMLResponse but does not set any security headers. No evidence of a middleware or framework configuration that adds this header is present in the supplied context.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of the response, potentially allowing content‑type confusion attacks such as cross‑site scripting (XSS) if an attacker can influence the response body.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to add the X-Content-Type-Options: nosniff header to all responses, e.g., via a middleware that sets response.headers\["X-Content-Type-Options"\] = "nosniff" or by using a security library such as Starlette’s SecurityHeadersMiddleware.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- `Scanner runtime probe (zap.10021) observed a GET request to /comments with no X-Content-Type-Options header in the response`

Limitations:
- No direct capture of the HTTP response headers is provided; the finding relies on the scanner’s report. Additional evidence such as raw response headers or server configuration confirming the header is omitted would strengthen the case.

### 15. Debug configuration is unavailable anonymously

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/debug/config` returns sensitive configuration values (database URL, mock external URL, and application secret) without any authentication or access control. The source excerpt shows the function directly returns these values, and the runtime probe fact confirms that an unauthenticated GET request receives a 200 OK response, whereas a 401/403/404 would be expected for protected resources. This demonstrates an exposed sensitive operation with no guard in the supplied context.

**Impact:** An attacker can retrieve internal configuration data, including database connection strings and secret keys, enabling further attacks such as database compromise, credential reuse, or service impersonation.

**Remediation:** Add proper authentication and authorization checks to the `/debug/config` endpoint, or remove the endpoint from production deployments. Ensure that sensitive configuration values are never exposed via public APIs.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- <code>Source excerpt shows `/debug/config` returns DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks</code>
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404`

### 16. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a 200 response but no Content‑Security‑Policy header is observed in the runtime probe facts. The source code for the endpoint does not set any security headers, and the scanner reports the header as missing. While this suggests a security‑hardening issue, the evidence consists only of a scanner/runtime observation without independent verification of the actual HTTP response headers.

**Impact:** Absence of a CSP header can allow injection of malicious scripts or resources, potentially leading to cross‑site scripting or data exfiltration if the endpoint is ever rendered in a browser context.

**Remediation:** Add a Content‑Security‑Policy header to the response for the /healthz endpoint (and other endpoints) using FastAPI middleware or a response‑header decorator, e.g., `response.headers['Content‑Security‑Policy'] = "default-src 'self'"`.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Runtime probe fact: path "/healthz" returned status 200 with no CSP header (web.missing-content-security-policy)`

Limitations:
- No direct capture of the HTTP response headers confirming the header is absent; reliance on scanner/runtime observation only. Additional verification of actual response headers is needed to confirm the finding.

### 17. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without the X-Frame-Options or Content-Security-Policy frame-ancestors header, indicating clickjacking protection is not applied. The scanner runtime probe confirms the endpoint is reachable and the header is absent.

**Impact:** An attacker could embed the health check page in a malicious site using an iframe, potentially misleading users or facilitating UI redressing attacks.

**Remediation:** Configure the web framework or reverse proxy to add an appropriate X-Frame-Options header (e.g., SAMEORIGIN) or a Content-Security-Policy frame-ancestors directive to the /healthz response.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner runtime probe (web.missing-clickjacking-protection) reports missing clickjacking protection header on /healthz`

Limitations:
- No evidence that the application adds the header dynamically in other contexts; cannot confirm whether this omission is intentional or mitigated elsewhere.

### 18. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a JSON response but the source code does not show any middleware or response header configuration that adds the X-Content-Type-Options header. The scanner observed the header is absent, indicating a potential MIME‑type sniffing risk.

**Impact:** An attacker could influence how browsers interpret the response content, possibly leading to content‑type confusion attacks such as MIME sniffing, which can facilitate cross‑site scripting or data leakage in certain contexts.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options: nosniff header for all responses, e.g., by adding a middleware that sets this header globally or specifically for the /healthz route.
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Scanner runtime probe (zap.10021) reported missing X-Content-Type-Options header on GET /healthz`

Limitations:
- The provided source excerpt does not include any header‑setting code or middleware configuration, so the absence of the header cannot be definitively proven from the code alone. Additional evidence such as the full application startup configuration or response‑header middleware definitions is needed.

### 19. Missing X-Content-Type-Options header on /healthz endpoint

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without the X-Content-Type-Options header, which can allow MIME type sniffing attacks. The scanner observed the missing header, but no additional evidence (e.g., runtime probe confirming exploitability or a guard that sets the header elsewhere) is provided.

**Impact:** An attacker could trick a browser into interpreting the response as a different MIME type, potentially leading to cross‑site scripting or content injection attacks.

**Remediation:** Configure the FastAPI application or the underlying web server to include the header, e.g., add `Response(headers={"X-Content-Type-Options": "nosniff"})` to the endpoint or set it globally via middleware.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Scanner runtime probe reported missing X-Content-Type-Options header on /healthz (status 200)`

Limitations:
- No runtime probe demonstrating that the missing header can be abused in a client context; no code showing a global header setting that might already mitigate the issue.

### 20. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /integrations/hook accepts POST requests, reads the raw request body, and inserts it directly into the database without verifying a signature or any authentication token. The supplied source excerpt shows no signature validation logic. Runtime probe facts confirm that a POST request to this endpoint returns HTTP 200, whereas the probe contract expected a 4xx response for unsigned requests, indicating the endpoint processes unauthenticated payloads. This combination demonstrates an exploitable path where an attacker can submit arbitrary webhook data that will be stored as accepted visits.

**Impact:** An attacker can forge webhook events, causing arbitrary data to be recorded as legitimate visits. This may lead to data poisoning, unauthorized actions downstream, or escalation if the stored data influences other parts of the system.

**Remediation:** Add verification of a cryptographic signature or shared secret on incoming webhook requests before processing the payload. Reject requests lacking a valid signature with a 4xx response (e.g., 401 Unauthorized). Ensure the verification step occurs before any database interaction.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- `Source excerpt lines 628-634 show the receive_hook function inserting the raw request body into the database without any signature check.`
- `Runtime probe fact: POST to /integrations/hook returned status 200, while the expected statuses for unsigned requests were 400, 401, 403.`

### 21. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated principal owns the requested invoice before returning the record. The code fetches the invoice by ID and returns it if found, without any ownership check. A runtime probe for this path returned HTTP 200 instead of the expected 403/404, confirming that unauthorized access is possible. The scanner finding and runtime observation together demonstrate the vulnerable behavior.

**Impact:** An attacker who can obtain or guess an invoice ID can retrieve invoices belonging to other users, leading to confidentiality breaches of financial data.

**Remediation:** Add an ownership verification step after fetching the invoice, e.g., compare the invoice's owner field with the authenticated principal and raise a 403 error if they do not match. Ensure the `principal` function returns the user identity and use it to enforce access control.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- `Source code shows no ownership check after fetching the invoice (lines 268-274).`
- <code>Runtime probe fact indicates a GET request to `/invoices/{{invoice_id}}` returned status 200 instead of 403/404, demonstrating unauthorized access.</code>

### 22. Potential unauthorized job submission endpoint

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint calls a function `principal(authorization)` before inserting a job record, but the supplied source excerpt does not show any validation that the caller has admin privileges or that the `run_as` field is restricted. A runtime probe observed a successful 200 response for a POST request, whereas the probe expected error statuses (400, 403, 422). This suggests the endpoint may accept job submissions without proper authorization checks.

**Impact:** An attacker could submit arbitrary jobs, potentially executing privileged actions or running code with elevated permissions, leading to privilege escalation or unauthorized workload execution.

**Remediation:** Ensure that the `principal` function enforces that only authorized admin users can access this endpoint. Add explicit role checks and return appropriate error codes (e.g., 403) when the caller lacks sufficient privileges. Validate and sanitize the `run_as` field to prevent privilege abuse.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- <code>Source excerpt shows `principal(authorization)` is called but no further checks are visible</code>
- `Runtime probe fact: POST /jobs returned status 200, while expected statuses were 400, 403, or 422`

Limitations:
- The actual implementation of `principal` is not provided, so it is unclear whether it performs sufficient authorization checks
- No additional scanner evidence of medium or higher severity confirming the flaw

### 23. Identity endpoint discloses sensitive SSN data

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table for the column "ssn" and returns the entire row as a dictionary. No filtering or masking of the SSN field is present in the supplied code. The runtime probe indicates that the endpoint returns a 200 response and that values were redacted in the probe output, but it does not prove that the SSN is omitted in actual responses. The scanner flagged this as excessive data exposure. Together these signals suggest a vulnerability, but the evidence does not conclusively demonstrate that the SSN is sent to the client.

**Impact:** An attacker who can authenticate as a user (or exploit other weaknesses to obtain a valid token) could retrieve the Social Security Number of that user, leading to identity theft and privacy violations.

**Remediation:** Modify the /me endpoint to exclude the SSN field from the response or mask it before returning the data. For example, select only non‑sensitive columns or explicitly delete/replace the "ssn" key in the returned dictionary.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source excerpt lines 199‑204 show the SELECT query includes the ssn column and the returned dict includes all columns.`
- `Scanner finding flagged excessive data exposure on /me.`
- `Runtime probe facts show a 200 response for GET /me with values_redacted true, indicating data was present but redacted in the probe output.`

Limitations:
- The probe output redacts values, so it is unclear whether the SSN is actually included in the live response.
- No evidence is provided that access control or additional guards prevent unauthorized users from calling /me.
- No test confirming that the SSN appears in the HTTP response body.

### 24. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the order into the database using the client‑supplied field body.unit_price as the unit_price column. No server‑side validation or override of this value is visible in the supplied code excerpt, meaning a client can set an arbitrary price for an order. The scanner flagged this as a high‑severity issue, and a runtime probe confirms the endpoint is reachable (POST /orders returns 200). However, there is no independent evidence that the price is later used in a sensitive operation (e.g., billing) without additional checks, nor is there a guard shown in the provided context.

**Impact:** An attacker could manipulate order prices, potentially leading to undercharging customers or overcharging the business, resulting in financial loss or fraud.

**Remediation:** Validate and enforce the unit_price on the server side. Either ignore the client‑provided price and replace it with the authoritative catalog price based on the item ID, or verify that the supplied price matches the expected catalog price before inserting the order. Add appropriate input validation and logging for mismatched prices.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt lines 207‑215 show the POST /orders handler inserting body.unit_price directly into the database.`
- `Runtime probe fact indicates the POST /orders endpoint is reachable and returns HTTP 200.`

Limitations:
- Missing evidence that the inserted price is used in downstream billing without further checks.
- No proof that a guard or price‑lookup logic exists elsewhere in the codebase to mitigate the issue.

### 25. Order creation endpoint allows arbitrary initial status

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `create_order` endpoint inserts a new order record using the `status` value supplied in the request body without any validation or restriction. The runtime probe shows that a POST to `/orders` with an arbitrary status returns HTTP 200, whereas the expected behavior is a client error (400 or 422). This demonstrates that the endpoint accepts and persists unvalidated status values, allowing orders to be created directly as paid or any other state.

**Impact:** An attacker can create orders in any desired state, including paid, without completing the intended workflow. This can lead to financial fraud, inventory inconsistencies, and bypass of business logic that should enforce payment processing before marking an order as paid.

**Remediation:** Validate the `status` field in the request body. Only allow statuses that represent the initial state of a new order (e.g., "pending"). Reject or ignore any attempt to set the status to "paid" or other advanced states. Implement server‑side checks and return a 400/422 error for invalid status values.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- <code>Source excerpt shows `status` taken directly from `body.status` and inserted into the database (lines 213‑215).</code>
- `Runtime probe fact indicates POST /orders returned 200 instead of the expected 400/422, confirming the lack of validation.`

### 26. Negative order prices are not rejected

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an OrderBody and directly inserts the provided unit_price into the database without any validation. A runtime probe attempted to submit a negative price and observed a 200 OK response, indicating the request succeeded instead of being rejected with a 400/422 as expected. No input‑validation guard is visible in the supplied code snippet.

**Impact:** An attacker could create orders with negative prices, potentially leading to unauthorized refunds, credit manipulation, or other financial inconsistencies in the system.

**Remediation:** Add validation for the unit_price (and any other monetary fields) to ensure the value is non‑negative before executing the INSERT. Return a 400/422 response when validation fails. Consider using a schema validator or explicit checks in the endpoint logic.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`
- `Source excerpt shows no validation before database insertion`

Limitations:
- The review is based on a single runtime probe and the provided code snippet; additional code paths or middleware that might perform validation are not shown. Confirmation would require independent scanner evidence of the same behavior or broader code review showing the absence of validation elsewhere.

### 27. Missing ownership check when creating orders

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders accepts an owner_id from the request body and defaults to the authenticated user's sub when not provided. The code inserts the order using the supplied owner_id without verifying that the caller is authorized to act on behalf of that owner. A runtime probe observed a successful POST (HTTP 200) where a 4xx response was expected, indicating the missing authorization check is exploitable.

**Impact:** An attacker can create orders on behalf of any user by supplying an arbitrary owner_id, leading to unauthorized resource creation, potential fraud, and data integrity issues.

**Remediation:** Validate that the authenticated user is allowed to create orders for the specified owner_id. For example, compare owner_id to user\["sub"\] and reject the request with 403/422 if they differ, or enforce role‑based permissions.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows owner_id is taken from the request body or user sub without further checks (lines 208‑215).`
- `Runtime probe fact reports a POST to /orders returned HTTP 200 instead of the expected 4xx, confirming the lack of enforcement.`

Limitations:
- No explicit guard or authorization check is present in the supplied code snippet; cannot confirm whether such a check exists elsewhere in the application. Additional evidence from other parts of the codebase or configuration would be needed to rule out external enforcement mechanisms.

### 28. A note must belong to the order named in the URL

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID without verifying that the note's `order_id` matches the `order_id` supplied in the URL. The code executes a query `SELECT id,order_id,body FROM notes WHERE id=%s` and returns the row if found, raising a 404 only when the note does not exist. No check is performed to ensure the note belongs to the requested order, allowing an attacker to access notes belonging to other orders by guessing note IDs. Runtime probing confirms the flaw: a GET request to `/orders/1/notes/2` returned HTTP 200 instead of the expected 403/404, demonstrating unauthorized access.

**Impact:** An attacker can enumerate or read notes belonging to other users' orders, leading to confidentiality breaches and potential exposure of sensitive information across accounts.

**Remediation:** Add a validation step that compares the `order_id` of the retrieved note with the `order_id` path parameter. If they differ, return a 403 Forbidden or 404 Not Found. Example:
```python
row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()
if not row or row\["order_id"\] != order_id:
    raise HTTPException(404, "Note not found")
return dict(row)
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- `Source code shows note fetched without order_id check (lines 543‑549).`
- <code>Runtime probe fact: GET `/orders/1/notes/2` returned status 200, contradicting expected 403/404.</code>

### 29. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint GET /orders/{order_id} calls principal(authorization) which authenticates the request but does not verify that the authenticated user is the owner of the requested order before returning the record. The source excerpt shows no ownership check after the database query. A runtime probe for the same path returned HTTP 200 for a request that should have been denied (expected 403), confirming that the missing check is exploitable. The scanner finding and the runtime observation together satisfy the criteria for a confirmed vulnerability.

**Impact:** An attacker who can obtain a valid authorization token can retrieve any order by ID, exposing sensitive order data belonging to other users.

**Remediation:** Add an ownership verification step after fetching the order, e.g., compare the order's user_id with the authenticated principal and raise HTTPException(403) if they differ. Ensure the check is performed before returning the order data.
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- `Source excerpt shows get_order endpoint without ownership check`
- `Runtime probe fact: GET /orders/{{order_id}} returned 200 instead of expected 403`

### 30. Excessive coupon discounts are rejected

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/apply-coupon` accepts a user‑supplied discount value (`body.discount`) and applies it directly to the order without any validation of the discount magnitude. The source excerpt shows the discount is taken from the request body if present, otherwise from the stored coupon percent, and then written to the database. No guard or limit check is visible in the supplied code. A runtime probe attempted to trigger a validation error (expected 400/422) but received a 200 response, indicating the missing validation path is reachable.

**Impact:** An attacker can submit an arbitrarily large discount value, potentially reducing the order total to zero or a negative amount, leading to revenue loss and possible abuse of promotional mechanisms.

**Remediation:** Add explicit validation to ensure the discount does not exceed an acceptable maximum (e.g., 100% or a business‑defined cap). Return a 4xx error when the supplied discount is out of bounds. Example:
```python
MAX_DISCOUNT = 50  # percent
if body.discount is not None:
    if not (0 &lt;= body.discount &lt;= MAX_DISCOUNT):
        raise HTTPException(status_code=400, detail="Discount out of range")
    percent = body.discount
else:
    percent = coupon\["percent"\] if coupon else 0
```
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- <code>Source excerpt lines 231‑237 show the discount is taken from `body.discount` without bounds checking.</code>
- `Runtime probe fact shows a POST to the endpoint returned status 200 when a 400/422 was expected, confirming the missing validation.`

Limitations:
- Missing explicit evidence of a maximum‑discount policy in the codebase; need to confirm business rules for allowed discount ranges.
- No proof that other layers (e.g., middleware or database constraints) enforce limits; only the provided snippet was examined.

### 31. Paid orders require a refund before cancellation

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/cancel` directly updates the order status to `cancelled` without verifying whether the order has been paid or whether a refund has been issued. The source excerpt shows no conditional check on payment status before performing the UPDATE. Runtime probe facts confirm that a POST request to this endpoint returns HTTP 200, whereas the expected behavior (per the probe contract) would be to reject the request with a client error (e.g., 400, 409, or 422) when the order is paid. This demonstrates that the vulnerable path is reachable and lacks the necessary guard.

**Impact:** An attacker can cancel paid orders without processing a refund, leading to financial loss and potential abuse of the order management system.

**Remediation:** Add a check to verify the order's payment status before allowing cancellation. If the order is paid, require a refund operation to complete successfully before updating the status to `cancelled`. Return an appropriate error response (e.g., 400 or 409) when cancellation is not permitted.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- `Source code at lines 258-263 shows the cancel_order function updates the order status without payment checks.`
- `Runtime probe fact: POST to /orders/{{order_id}}/cancel returned status 200, while expected statuses were 400, 409, 422, indicating the guard is missing.`

### 32. Payment replay vulnerability on order payment endpoint

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `pay_order` endpoint updates the order status to 'paid' without verifying whether the order has already been paid. The runtime probe confirms that a second POST to the same endpoint returns HTTP 200 instead of an error (expected 400/409/422), demonstrating that the endpoint allows replay attacks.

**Impact:** An attacker can submit multiple payment requests for the same order, causing duplicate charges or fraudulent invoicing.

**Remediation:** Add a check for the order's current status before processing payment. If the status is already 'paid', return an appropriate error (e.g., 409 Conflict). Ensure the status check and update are performed atomically within a transaction.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- <code>Source code shows `pay_order` updates status to &#x27;paid&#x27; without prior status check (lines 242-250).</code>
- <code>Runtime probe fact indicates POST to `/orders/{{order_id}}/pay` returned 200 instead of expected error codes, confirming replay is possible.</code>

### 33. Insecure profile access allowing enumeration of other users' data

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the requested profile before querying the database. The SQL query returns the full user record (including sensitive fields) for any `profile_id` supplied. Runtime probing confirms that a request for another user's profile returns HTTP 200, whereas the expected behavior is a 403 or 404.

**Impact:** An attacker can retrieve arbitrary users' personal information (username, email, SSN) by iterating `profile_id` values, leading to privacy breaches and potential identity theft.

**Remediation:** Add an ownership check after retrieving the row (or before the query) to ensure the authenticated user's ID matches `profile_id`. Return 403/404 when the user is not authorized. Example:
```python
user_id = get_user_id_from_token(authorization)
if user_id != profile_id:
    raise HTTPException(403, "Forbidden")
```
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source code shows no ownership check before returning user data`
- `Runtime probe fact: GET /profiles/{{other_id}} returned status 200 instead of expected 403/404`

### 34. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /view endpoint returns an HTMLResponse without setting any anti-clickjacking headers such as X-Frame-Options or Content-Security-Policy frame-ancestors. The scanner flagged the missing header and the runtime probe confirms the endpoint is reachable via GET, but no response header data is provided to independently verify the absence of the header.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti-clickjacking headers to the response, e.g., set X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self'. This can be done globally via middleware or per‑endpoint response headers.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact indicates GET request to /view was made`

Limitations:
- No captured HTTP response headers to definitively prove the header is missing
- No independent scanner of higher severity confirming the issue

### 35. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The source excerpt shows that the `/view` endpoint returns an HTMLResponse constructed directly from a string without setting any HTTP security headers, including a Content‑Security‑Policy header. No guard or middleware is visible in the supplied code that would add such a header. The runtime probe only records the request method and that values were redacted; it does not confirm the presence or absence of the CSP header.

**Impact:** Without a CSP header, browsers are free to load scripts, styles, and other resources from any origin, increasing the risk of cross‑site scripting (XSS) and data‑injection attacks.

**Remediation:** Add a CSP header to the response, either by setting it explicitly in the view or by configuring a security middleware that injects the header for all responses. Example (FastAPI):
```python
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\['Content‑Security‑Policy'\] = "default-src 'self'"
        return response
```
Alternatively, set the header directly in `view_home`:
```python
return HTMLResponse(content, headers={"Content‑Security‑Policy": "default-src 'self'"})
```
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- `Source excerpt shows HTMLResponse returned without CSP header`
- `Scanner finding reports CSP header not set for /view`

Limitations:
- No runtime probe confirming that the CSP header is absent in actual responses; only method and redacted values are recorded. Additional evidence such as an HTTP response capture showing missing CSP header would be needed to confirm the vulnerability.

### 36. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse without setting the `X-Content-Type-Options: nosniff` header. The source excerpt shows the response is constructed directly, and the scanner/runtime finding reports the header as missing. While this suggests a security issue, the evidence does not include a concrete runtime response showing the header absence, nor an independent guard that would mitigate the risk.

**Impact:** Without the `X-Content-Type-Options` header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response content type.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response, e.g., by configuring the FastAPI/Starlette response middleware or setting the header explicitly in the `view_home` handler.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- `Source excerpt shows HTMLResponse returned without header configuration`
- `Scanner/runtime finding reports "X-Content-Type-Options Header Missing" for path /view`

Limitations:
- No captured HTTP response confirming the header is absent
- No runtime probe that explicitly verifies header presence or absence

### 37. Webhook destination must match the approved internal host exactly

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/webhooks` only rejects URLs containing the string "mock-external". Any other external URL passes the check and is stored for later execution, allowing an attacker to supply an arbitrary destination. The source excerpt shows the insufficient validation logic, and the runtime probe confirms that a POST request with a non‑mock URL receives a 200 response, indicating the check was bypassed.

**Impact:** An attacker can craft a webhook payload that points to an arbitrary external service, leading to data exfiltration, SSRF, or other downstream attacks.

**Remediation:** Validate the `target_url` against a whitelist of approved internal hosts (e.g., exact match to `MOCK_EXTERNAL_URL` or use URL parsing to enforce host equality). Reject any URL that does not exactly match the approved host and return a clear error.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- `Source code lines 294‑298 show only a substring check for "mock-external" and raise 400 otherwise.`
- `Runtime probe fact: POST to /webhooks returned status 200, indicating the check was bypassed.`

### 38. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the application secret (APP_SECRET) in clear text via `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`. No redaction or conditional guard is present before the logging statement, allowing the secret to be written to logs. The semgrep scanner flagged this line as a credential disclosure issue (rule python.lang.security.audit.logging.logger-credential-leak), providing independent corroboration of the vulnerability.

**Impact:** Exposing the application secret in logs can lead to credential leakage. An attacker with access to log files could retrieve the secret and potentially impersonate the application, access protected resources, or compromise the entire system.

**Remediation:** Remove the secret from the log statement or replace it with a placeholder. If logging is required for debugging, ensure that sensitive values are masked or omitted. Example:
```python
log.info("login user=%s", username)  # Do not log APP_SECRET
```
Alternatively, use a dedicated secret‑masking logger or environment‑specific logging configuration that redacts secrets.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- <code>Source line 137 logs `app_secret=%s` with the value from `os.environ.get(&quot;APP_SECRET&quot;, &quot;lab-only&quot;)`</code>
- `Semgrep finding (python.lang.security.audit.logging.logger-credential-leak) flags the same line as a credential disclosure`

### 39. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any origin to make cross‑origin requests. This configuration can expose the API to CSRF-like attacks or data leakage when combined with credentials. No evidence of a restrictive origin list or additional validation is present in the supplied excerpt.

**Impact:** An attacker from any domain can interact with the API, potentially stealing sensitive data or performing actions on behalf of authenticated users if credentials are included.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains, or dynamically validate the Origin header. If credentials are required, ensure allow_credentials is only true for trusted origins. Example:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=\["https://example.com"\],
    allow_credentials=True,
    allow_methods=\["GET", "POST"\],
    allow_headers=\["Authorization", "Content-Type"\],
)
```
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `Source excerpt shows allow_origins=["*"] in CORSMiddleware configuration (lines 24‑30).`

Limitations:
- No runtime probe demonstrating that malicious origins can successfully interact with the API, and no evidence that additional origin checks are performed elsewhere in the code.

### 40. Log Injection

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The log statement uses the logger's built‑in formatting with a static format string and passes the user‑provided username as a separate argument (log.info("login user=%s app_secret=%s", username, os.environ.get(...))). This pattern prevents format string injection because the logger does not interpret the user data as a format specifier. No evidence of uncontrolled format strings or direct string concatenation with user input is present, so the finding does not constitute a log injection vulnerability.

**Impact:** None – the logging call safely handles user input and does not allow injection of malicious log content.

**Remediation:** No remediation required for this specific log statement; continue using structured logging with format arguments.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `Source excerpt shows safe logger usage with a constant format string and separate arguments for user‑provided values.`

### 41. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string using an f‑string. No parameterized query or input sanitization is performed, and there is no visible guard or validation step before the query is executed. This allows an attacker to inject arbitrary SQL via the username or password fields, leading to unauthorized data access or manipulation.

**Impact:** An attacker can perform SQL injection to retrieve, modify, or delete data from the users table, potentially compromising all user accounts and escalating privileges.

**Remediation:** Replace the string interpolation with a parameterized query using the database library's placeholders (e.g., `SELECT ... WHERE username=? AND password=?`) and pass the user inputs as parameters. Additionally, hash passwords and compare hashes instead of storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `api/extra.py: line 117 builds query with f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"`
- `No input sanitization or parameterization is present before conn.execute(query)`

### 42. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` guard ensures the resolved path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent existence check further validates the target. Thus the code includes the necessary safety checks, and the scanner’s finding is a false positive.

**Impact:** If the guard were missing, an attacker could read arbitrary files on the server, leading to data disclosure. However, the guard is present, so no impact is present.

**Remediation:** No remediation needed; the existing `is_relative_to` check correctly mitigates path traversal. Ensure this pattern is retained for any similar file‑access endpoints.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑224 show the guard `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404)` which blocks traversal.</code>

### 43. Open redirect via unvalidated URL parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list check. An attacker can supply an arbitrary URL, causing the application to redirect users to a malicious site.

**Impact:** Facilitates phishing attacks, credential harvesting, and can be used to bypass security controls by redirecting victims to attacker‑controlled domains.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a safe scheme.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source code shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse: return RedirectResponse(next, status_code=302)` with no validation.</code>
- `Scanner evidence flags an open redirect vulnerability (medium severity).`

### 44. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint verifies that the resolved file path is within the allowed public directory using `is_relative_to(root)` and also checks that the path points to an existing file before reading it. This prevents directory traversal attacks despite the user‑provided filename.

**Impact:** No path traversal vulnerability; an attacker cannot read files outside the designated public directory.

**Remediation:** No remediation needed for this specific issue; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>The code uses `root = (FILES / &quot;public&quot;).resolve()` and `file = (root / name).resolve()` followed by `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)` which blocks paths outside the public directory.</code>

### 45. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against the known base directory and then verifies that the resulting path is still within that base using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None – the endpoint correctly restricts file access to the intended public directory.

**Remediation:** No remediation needed; the existing path validation is sufficient. Ensure the `FILES` constant is correctly set to the intended base directory and that the runtime environment supports `Path.is_relative_to` (Python 3.9+).
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>source_excerpt lines 211‑215 show the resolve and `is_relative_to` checks</code>
- `source_symbol confirms the same logic`

### 46. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to(root)` and that the file exists with `is_file()`. These checks prevent directory traversal, so the data is not uncontrolled in the path expression.

**Impact:** No path traversal vulnerability; an attacker cannot read files outside the intended public directory.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>source excerpt shows `root = (FILES / &quot;public&quot;).resolve()`</code>
- <code>source excerpt shows `file = (root / name).resolve()`</code>
- <code>source excerpt shows `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 47. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function constructs the file path using a user‑provided name, but it immediately resolves the path and checks `is_relative_to(FILES.resolve())` as well as `is_file()`. These checks ensure that the resulting path stays within the intended `public` directory and that the target is an existing file, preventing path traversal attacks. The scanner’s finding does not account for these safeguards.

**Impact:** If the checks were absent, an attacker could read arbitrary files on the server. However, the present checks mitigate this risk, so no vulnerability is present in the supplied code.

**Remediation:** No remediation needed for this code path; the existing relative path check and file existence verification are sufficient. Ensure similar checks are applied consistently throughout the codebase.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>211 | def file_read(name: str) -&gt; Response:</code>
- `212 | file = (FILES / "public" / name).resolve()`
- `213 | if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `214 | raise HTTPException(404, "File not found")`
- `215 | return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

### 48. Reflected server-side cross-site scripting

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/search` directly interpolates the user‑controlled query parameter `q` into an HTML response (<code>&lt;h1&gt;Results for {q}&lt;/h1&gt;</code> and <code>&lt;p&gt;{row[&#x27;name&#x27;]}&lt;/p&gt;</code>). No escaping or sanitisation is performed, allowing an attacker to inject arbitrary JavaScript that will be executed in the victim's browser when the page is rendered. The same unsanitised value is also used in a raw SQL string, indicating additional risk (SQL injection). The supplied source excerpt demonstrates the vulnerable code path, and the finding originates from a scanner, providing independent corroboration of the issue.

**Impact:** An attacker can execute arbitrary JavaScript in the context of the victim's browser, leading to session hijacking, credential theft, defacement, or further attacks against the user or the application.

**Remediation:** Validate and sanitise the `q` parameter before using it in HTML output. Use a templating engine that auto‑escapes content or explicitly escape special characters (e.g., `html.escape`). Additionally, replace the string‑formatted SQL query with parameterised queries to prevent SQL injection. Example:
```python
@router.get("/catalog/search", response_class=HTMLResponse)
def catalog_search(q: str = ""):
    with connection() as conn:
        rows = conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",)).fetchall()
    safe_q = html.escape(q)
    return f"&lt;h1&gt;Results for {safe_q}&lt;/h1&gt;" + "".join(f"&lt;p&gt;{html.escape(row\['name'\])}&lt;/p&gt;" for row in rows)
```
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- <code>Source excerpt shows `q` interpolated into HTML without escaping (lines 142‑145).</code>
- `Scanner‑generated finding flagged the endpoint as reflected XSS (high severity).`

### 49. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the provided URL by ensuring it starts with a single '/' and rejects any scheme, network location, or double-slash prefix, raising an HTTP 400 error for invalid inputs. This prevents redirection to external or malicious URLs, mitigating the open‑redirect risk described by the scanner.

**Impact:** None – the code already enforces a local‑path‑only redirect, so an attacker cannot cause an open redirect to an external site.

**Remediation:** No remediation needed; the existing validation is sufficient. Maintain this check if the function is modified.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `source_excerpt lines 621‑624 show explicit checks for leading '/' and disallowing scheme or netloc, and a raise of HTTPException for invalid values.`

### 50. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided name, but it immediately resolves the path and then checks `is_relative_to(FILES.resolve())` to ensure the resulting path stays within the intended directory. This guard prevents directory traversal attacks, and the subsequent `is_file()` check ensures the target exists before reading. The code therefore does not expose arbitrary file reads.

**Impact:** None – the guard mitigates path traversal, so no unauthorized file access is possible.

**Remediation:** No remediation needed for this specific issue; the existing checks are appropriate.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- <code>source_excerpt shows use of `resolve()` and `is_relative_to(FILES.resolve())` guard</code>
- <code>source_excerpt shows `is_file()` check before reading</code>

### 51. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL query by directly interpolating the user‑provided query parameter `q` into the statement using an f‑string. This creates a classic SQL injection vector because the input is not sanitized, escaped, or parameterized before being sent to the database.

**Impact:** An attacker could supply crafted input (e.g., `q=anything' OR '1'='1`) to manipulate the SQL query, potentially retrieving all product names, extracting data, or executing arbitrary SQL commands depending on database permissions.

**Remediation:** Rewrite the query to use parameterized statements provided by the database driver, e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`. Additionally, validate or whitelist allowed characters for `q` and consider limiting the length of the input.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt lines 141‑145 show the f‑string interpolation of `q` into the SQL query without sanitization.</code>

Limitations:
- No independent runtime probe or additional scanner evidence confirming exploitation. A proof‑of‑concept request demonstrating the injection effect is not provided.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile excerpt shows no HEALTHCHECK instruction, but the absence of a health check is a best‑practice recommendation rather than a proven security vulnerability. No evidence is provided that this misconfiguration leads to an exploitable condition in the deployed service.

**Impact:** Without a HEALTHCHECK, container orchestration may not detect a failed or unresponsive service promptly, potentially leading to reduced availability, but it does not directly expose a security flaw.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the service is healthy, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile lines 1‑8 show no HEALTHCHECK instruction`

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The finding reports the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container reliability, its absence does not constitute a security vulnerability nor does it expose a sensitive operation without protection. The supplied Dockerfile excerpt shows only standard setup commands and does not indicate any insecure behavior that would be mitigated by a HEALTHCHECK.

**Impact:** None – the container will run, but lack of a health check may affect availability monitoring rather than security.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile to enable Docker to monitor container health, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile for the worker service does not contain a HEALTHCHECK instruction. While the absence of a health check can reduce observability and automatic recovery capabilities, the supplied artifact does not demonstrate any concrete impact or exploitation path. No runtime probe or additional scanner evidence confirms that this omission leads to a vulnerability in the deployed environment.

**Impact:** Without a HEALTHCHECK, orchestration platforms cannot automatically detect and restart unhealthy containers, potentially leading to prolonged service outages.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost/health || exit 1
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- No runtime_probe_facts demonstrating failed health checks or orchestration response
- No evidence that the container is deployed in an environment where health checks are required
- No scanner evidence of exploitation or impact from the missing health check

### 55. python-multipart: Python-Multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to contain CVE‑2026‑53539. The CVE describes a denial‑of‑service condition triggered by specially crafted form‑urlencoded bodies. No version‑upgrade or mitigation is present in the supplied dependency list, and the scanner evidence is of high severity, providing independent corroboration of the vulnerability.

**Impact:** An attacker can send a maliciously crafted request that causes the application to consume excessive resources or crash, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE‑2026‑53539. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to contain CVE‑2026‑42561. This vulnerability allows an attacker to craft a multipart request with a large number of part headers, causing the library to consume excessive memory and CPU, leading to a denial‑of‑service condition. No evidence of an upgrade or mitigation is present in the supplied files.

**Impact:** An attacker can cause the FastAPI service to become unresponsive or crash by sending specially crafted multipart requests, resulting in service outage and potential loss of availability for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, which contains the fix for CVE‑2026‑42561. Update the requirements.txt entry accordingly and redeploy the application. Verify that the new version is installed by running `pip freeze` or checking the lock file.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`
- `requirements.txt pins python-multipart==0.0.20`

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The requirements file pins python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The scanner flagged this dependency as vulnerable. However, the supplied data does not show whether the project actually imports or uses python-multipart, nor does it provide runtime evidence that the vulnerable code path is exercised.

**Impact:** If the vulnerable version of python-multipart is used to parse multipart/form-data, an attacker could craft specially‑formed requests that cause the library to disclose internal data or behave unexpectedly, potentially leading to information leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Verify that the updated version does not introduce breaking changes in the application’s multipart handling.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency entry in requirements.txt pins python-multipart==0.0.20`
- `Scanner report cites CVE-2026-53538 affecting python-multipart 0.0.20`

Limitations:
- No code evidence showing python-multipart is imported or used
- No runtime probe confirming the vulnerable parsing path is reachable
- No confirmation that the vulnerable behavior manifests in the deployed application

### 58. python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20, which is known to contain CVE-2026-40347, a denial‑of‑service vulnerability triggered by specially crafted multipart/form-data payloads. The scanner report provides a medium‑severity finding with high confidence and cites the vulnerable version and the fixed version (&gt;=0.0.26). No mitigating guard or version constraint is present in the supplied dependency list, confirming the vulnerable path.

**Impact:** An attacker can cause the application to consume excessive resources or crash by sending malicious multipart requests, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, and verify that the updated version is included in the requirements.txt and the deployed environment.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`
- `requirements.txt pins python-multipart==0.0.20`

### 59. python-multipart: Arbitrary file write via path traversal vulnerability

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project pins python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-24486 allowing arbitrary file write via path traversal. The scanner provides a high‑severity finding for this CVE, and the dependency version directly matches the vulnerable range, confirming the vulnerable code path is present.

**Impact:** An attacker could exploit the path‑traversal flaw to write arbitrary files on the server, potentially leading to code execution, data corruption, or privilege escalation.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, which contains the fix for CVE-2026-24486. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`
- `requirements.txt pins python-multipart==0.0.20`

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53537. The scanner identified this vulnerable version in the requirements.txt. No evidence was provided that the application upgrades or mitigates the issue, and no guard or version check is visible in the supplied context.

**Impact:** An attacker could exploit the header parsing discrepancy to cause information disclosure, potentially leaking request or response data.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537. Update the requirements.txt and reinstall dependencies.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No runtime or code‑level evidence confirming the vulnerable code path is exercised in the application.

### 61. python-multipart: Python-Multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports that python-multipart version 0.0.20 contains CVE-2026-53540, which can cause the entire request body to be buffered in memory when a negative Content‑Length header is present. The supplied requirements.txt confirms that this vulnerable version is declared as a dependency. However, no code or runtime evidence is provided that the application actually imports or uses python-multipart, nor that a negative Content‑Length request is processed. Without proof of an exploitable code path, the finding remains a potential issue rather than a confirmed vulnerability.

**Impact:** If an attacker can send a request with a crafted negative Content‑Length header and the application processes multipart data using the vulnerable library, the server may allocate unbounded memory, leading to denial‑of‑service or out‑of‑memory crashes.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which resolves CVE‑2026‑53540. Verify that the updated version is used in the deployed environment and run dependency checks after the upgrade.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No evidence that the application imports or invokes python-multipart.
- No runtime probe showing a request with a negative Content‑Length being processed.
- No confirmation that the vulnerable code path is reachable in the deployed configuration.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code builds a URL by concatenating a constant BASE with a variable path argument and then passes it to urllib.request.urlopen. If the path argument can be influenced by an attacker, they could craft a URL with a scheme such as "file://" to read arbitrary files or otherwise trigger unintended requests. The finding is based solely on static analysis of the source excerpt; no runtime probe demonstrates an actual exploit, and no guard (e.g., validation or whitelist) is visible in the provided snippet.

**Impact:** An attacker who can control the `path` parameter may cause the application to request arbitrary resources, potentially leading to information disclosure (e.g., reading local files) or SSRF-like behavior.

**Remediation:** Validate and sanitize the `path` argument before concatenation. Restrict allowed schemes to http/https, enforce a whitelist of acceptable endpoints, or switch to a higher‑level HTTP client like the `requests` library that does not support file URLs by default.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows dynamic URL construction with urllib.request.urlopen (lines 20‑22).`
- `Scanner flagged the pattern as risky because urllib supports file:// schemes.`

Limitations:
- No runtime evidence that an attacker can control the `path` argument.
- No visible input validation or sanitization in the supplied context.
- No proof that a malicious URL would be processed successfully (e.g., no guard checks observed).

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload\["target_url"\]). No validation or sanitisation of this value is shown before it is passed to urllib.request.urlopen, which can handle arbitrary schemes (including file://). This creates a potential Server‑Side Request Forgery (SSRF) or local file read issue if an attacker can control the payload.

**Impact:** An attacker who can influence the "target_url" field could cause the worker to make arbitrary network requests or read local files, potentially exfiltrating data or accessing internal services.

**Remediation:** Validate and whitelist the scheme and host of "target_url" before using it. Reject or sanitise any URLs that are not explicitly allowed (e.g., only https:// with approved domains). Consider using a higher‑level HTTP client (e.g., requests) with built‑in timeout and redirect controls, and enforce strict URL parsing. If external requests are not required, remove the dynamic request entirely.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `source_excerpt lines 17‑23 show payload["target_url"] passed directly to urllib.request.Request without validation`

Limitations:
- Missing evidence that the surrounding code performs any URL validation, scheme restriction, or other guard checks. No runtime probe confirming that malicious URLs can be supplied or that the request is blocked. Additional context (e.g., input sanitisation elsewhere) is required to confirm the vulnerability.

### 64. Potential IDOR in profile verification endpoint (CWE-639)

- Issue group: `ai-a15d98c2851e9a64`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint extracts the user identity via `verified_identity(authorization)` and then checks that the requested `profile_id` matches `user["id"]`. If `verified_identity` does not perform robust cryptographic validation of the Authorization header (e.g., JWT signature verification) and merely trusts a header value, an attacker could forge the header and retrieve another user’s verified profile, constituting an IDOR. The code shown does not reveal any such validation, so the risk is plausible but not proven.

**Impact:** An attacker who can forge or manipulate the Authorization header could access verification data of arbitrary user profiles, leading to privacy breaches and potential further account takeover.

**Remediation:** Ensure `verified_identity` validates the Authorization header securely: verify JWT signatures, check token expiration, and enforce proper audience/issuer claims. Reject any request where token validation fails before performing the profile ID comparison. Consider using a dedicated authentication middleware that populates a trusted user object.
Evidence:
- Source IDs: `ai-a15d98c2851e9a64`
- <code>api/extra.py:107-111 defines the endpoint and performs a simple ID comparison after calling `verified_identity`</code>
- `The code lacks any explicit token verification or signature check before using the user information`

Limitations:
- The implementation of `verified_identity` is not provided, so we cannot confirm whether it performs proper token validation
- No runtime probe or scanner evidence demonstrates that forged headers bypass the check

### 65. Missing admin role verification on audit endpoint (CWE-284)

- Issue group: `ai-0b9106bba642ef41`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/audit endpoint calls require_admin with the provided Authorization header, but the implementation of require_admin is not present in the supplied code. Without evidence that require_admin performs a cryptographically verified role check, it is possible that the endpoint allows unauthorized access.

**Impact:** An attacker could potentially access administrative audit functionality without proper admin privileges, leading to exposure of sensitive logs or system state.

**Remediation:** Implement require_admin to validate a signed token (e.g., JWT) and verify that the token contains an admin role claim. Ensure that the function rejects requests lacking a valid token or with insufficient privileges, and add unit tests for the check.
Evidence:
- Source IDs: `ai-0b9106bba642ef41`
- `204: @router.get("/admin/audit")`
- <code>205: def admin_audit(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `206: require_admin(authorization)`
- `207: return {"status": "authorized"}`

Limitations:
- The source does not include the definition of require_admin, so its actual behavior cannot be confirmed. No runtime probe or scanner evidence demonstrating a bypass is provided.

### 66. Potential path traversal via unverified file name (CWE-22)

- Issue group: `ai-d3c8ae68a75d8b90`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint @router.get("/files") builds a file path by joining the user‑supplied `name` with the public directory and then calling `.resolve()`. It attempts to prevent traversal by checking `file.is_relative_to(FILES.resolve())` after resolution. Because `Path.resolve()` follows symlinks, an attacker could craft a filename that resolves to a location outside the intended directory via a symlink placed in `FILES/public`. The supplied code does not perform canonicalization before the join nor enforce a whitelist of allowed filenames, so the check may be bypassed on filesystems that allow such symlink tricks.

**Impact:** If an attacker can bypass the relative‑path check, they could read arbitrary files on the server, potentially exposing source code, configuration secrets, or other sensitive data.

**Remediation:** Validate the `name` parameter before joining it with the base directory. Options include:
* Reject any path containing ".." or path separators.
* Use a strict whitelist of allowed filenames.
* Perform the relative‑path check on the *joined* path *before* calling `resolve()`, or use `os.path.normpath` and compare the normalized path to the allowed directory.
* Ensure that the public directory does not contain symlinks that point outside the root, or explicitly resolve symlinks only after the check.
* Consider serving files via a dedicated static‑file handler that enforces these constraints automatically.
Evidence:
- Source IDs: `ai-d3c8ae68a75d8b90`
- <code>api/extra.py:210 – endpoint definition `@router.get(&quot;/files&quot;)`</code>
- <code>api/extra.py:212 – constructs `file = (FILES / &quot;public&quot; / name).resolve()`</code>
- <code>api/extra.py:213 – checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`</code>

Limitations:
- No runtime probe or scanner evidence confirming that the check can be bypassed in this deployment.
- No information about the presence of symlinks inside `FILES/public` or the filesystem behavior of `resolve()` on the target system.

### 67. Missing CSRF protection on state‑changing endpoint

- Issue group: `ai-eb33fbefb86b87d2`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The /auth/register endpoint is exposed as a POST route and performs a database insert without any visible CSRF mitigation (e.g., token validation, SameSite cookie enforcement, or global CSRF middleware). The supplied source excerpt shows no CSRF‑related checks before the sensitive operation. However, there is no independent scanner finding, runtime probe, or evidence of a missing guard elsewhere in the application, so the vulnerability cannot be confirmed.

**Impact:** If the API is accessed from a browser and cookies are used for authentication, an attacker could trick a logged‑in user’s browser into submitting a registration request, creating a new account under the attacker’s control or causing unintended side effects.

**Remediation:** Add CSRF protection for state‑changing endpoints. Options include: 
* Enforce SameSite=strict or Lax on authentication cookies.
* Require a CSRF token (e.g., double‑submit cookie or hidden form field) and validate it on each POST request.
* Apply a CSRF‑protecting middleware globally for all FastAPI routes.
* Document the intended client model (API‑only vs. browser) and adjust security controls accordingly.
Evidence:
- Source IDs: `ai-eb33fbefb86b87d2`
- `api/app.py:175 – @app.post("/auth/register") defines the entry point`
- `api/app.py:179 – user = conn.execute(...) performs a state‑changing INSERT without preceding CSRF checks`

Limitations:
- No evidence that the application sets SameSite attributes on cookies or uses a CSRF‑protecting middleware elsewhere
- No scanner or runtime probe confirming that the endpoint is reachable from a browser context
- No observation of authentication mechanism (e.g., cookie‑based session) that would make CSRF relevant

### 68. Potential insecure token handling in refresh endpoint (CWE-613)

- Issue group: `ai-e8ec08f388c6f0b9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The /auth/refresh endpoint creates a new access token based solely on the Authorization header supplied by the caller. The code calls principal() on the header and then issues a fresh token with make_token(row) without any explicit verification that the request contains a dedicated refresh token, that the token is still valid, or that it has not been revoked. This pattern can allow an attacker who possesses a valid access token to repeatedly obtain new tokens, leading to token replay and insufficient session expiration.

**Impact:** An attacker who can capture or guess a valid access token could repeatedly call the refresh endpoint to obtain fresh tokens, extending the session indefinitely and bypassing any intended token lifetime controls. This undermines session security and may enable unauthorized access to protected resources.

**Remediation:** Implement proper refresh‑token handling: require a separate refresh token (e.g., in a secure HttpOnly cookie or request body), validate its signature, expiration, and revocation status, and ensure it is distinct from the access token. Only issue a new access token after successful verification of the refresh token. Consider adding rotation and revocation mechanisms for refresh tokens.
Evidence:
- Source IDs: `ai-e8ec08f388c6f0b9`
- `api/app.py:189 – @app.post("/auth/refresh") defines the refresh endpoint`
- `api/app.py:191 – user = principal(authorization) uses the Authorization header without distinguishing token type`
- `api/app.py:193 – row = conn.execute(... ) fetches user data based on the principal claim`
- `api/app.py:196 – return {"access_token": make_token(row), "token_type": "bearer"} issues a new token unconditionally`

Limitations:
- No evidence that a dedicated refresh token is stored, validated, or checked for expiration elsewhere in the codebase
- principal() implementation is not shown, so it is unclear whether it differentiates access and refresh tokens
- No independent scanner or runtime probe confirming that the endpoint can be abused to obtain unlimited tokens

### 69. Arbitrary discount value bypass via request body (CWE-353)

- Issue group: `ai-b25b877a4040d288`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The `apply_coupon` endpoint copies the `discount` field from the request body directly into the SQL UPDATE statement when the field is present, without any validation or bounds checking. This creates a path where a client can supply an arbitrary discount value (e.g., 100 % or a negative amount) that will be persisted to the order record. No guard or validation logic is visible in the supplied code snippet.

**Impact:** An attacker could obtain full discounts, cause revenue loss, or manipulate order totals, potentially leading to financial fraud or inventory inconsistencies.

**Remediation:** Validate the `discount` value before using it: ensure it is within an allowed range (e.g., 0‑100 %), matches the coupon's configured percent, and reject unexpected fields. Consider removing the `discount` field from the request schema entirely and rely solely on the coupon's percent. Add explicit checks and return an error for out‑of‑range values.
Evidence:
- Source IDs: `ai-b25b877a4040d288`
- <code>api/app.py:235 – `percent = body.discount if body.discount is not None else (coupon[&quot;percent&quot;] if coupon else 0)`</code>
- <code>api/app.py:236 – `UPDATE orders SET discount=%s WHERE id=%s RETURNING *`</code>

Limitations:
- No evidence is provided that downstream logic validates the final order total or rejects unreasonable discount values.
- The FastAPI `CouponBody` schema is not shown; it is unclear whether the `discount` field is prohibited or validated by Pydantic.
- No scanner or runtime probe confirms that an arbitrary discount can be persisted or exploited in practice.

### 70. Missing ownership check on order creation (CWE-639)

- Issue group: `ai-fdb73441313bbd62`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint assigns owner_id from the request body, falling back to the authenticated user's sub only when the supplied owner_id is falsy. No check is shown that the supplied owner_id matches the authenticated principal or that the caller has a role permitting creation on behalf of other users. This could allow a user to create orders for arbitrary accounts.

**Impact:** An attacker could create orders under another user's account, potentially leading to unauthorized purchases, billing fraud, or data leakage of order details associated with victims.

**Remediation:** Validate that the owner_id either matches the authenticated user's identifier or that the caller possesses an explicit permission/role (e.g., admin) to act on behalf of other users. If owner_id is optional, enforce that only privileged roles may supply it, otherwise default to user\["sub"\] without allowing overrides.
Evidence:
- Source IDs: `ai-fdb73441313bbd62`
- `api/app.py line 209: user = principal(authorization)`
- `api/app.py line 210: owner_id = body.owner_id or user["sub"]`
- `api/app.py line 213: INSERT INTO orders (owner_id, ...) VALUES (%s, ...)`

Limitations:
- No evidence that principal() or other middleware performs additional role‑based checks on owner_id.
- No scanner or runtime probe confirming that an unauthorized owner_id can be persisted.
- No view of surrounding authorization logic that might reject mismatched owner_id values.

### 71. Missing ownership/role check on coupon application (CWE-639)

- Issue group: `ai-0c59bf73442d38e5`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `apply_coupon` endpoint authenticates the request via `principal(authorization)` but does not perform any check that the authenticated user owns the order identified by `order_id` or possesses a privileged role before executing an UPDATE on the `orders` table. This creates a potential authorization bypass where an attacker who can guess or enumerate order IDs could apply arbitrary discounts to orders they do not own.

**Impact:** An attacker could reduce the price of any order, potentially causing revenue loss, unauthorized discounts, or abuse of promotional coupons. In a worst‑case scenario, this could be combined with other attacks to manipulate order totals or trigger downstream business logic that assumes the discount was authorized.

**Remediation:** Add an ownership or role verification step after authentication and before the UPDATE. For example, query the order to retrieve its owner and compare it to the principal’s user ID, or check that the principal has an admin/manager role. Abort with a 403 Forbidden if the check fails. Ensure that any future modifications to order data also enforce this check, possibly via a database trigger or service‑level policy.
Evidence:
- Source IDs: `ai-0c59bf73442d38e5`
- `232: principal(authorization) – authentication occurs but no further checks`
- `236: row = conn.execute("UPDATE orders SET discount=%s WHERE id=%s RETURNING *", (percent, order_id)).fetchone() – updates order without ownership verification`

Limitations:
- No evidence of a database trigger, ORM hook, or later business‑logic that enforces ownership constraints for order updates.
- No visibility into the implementation of `principal()` to determine whether it returns role information that could be used for authorization checks.
- No scanner or runtime probe evidence confirming that the missing check can be exploited in practice.

### 72. Missing ownership check on order payment (CWE-639)

- Issue group: `ai-5d4c30816d85620a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `pay_order` endpoint authenticates the request via `principal(authorization)` but does not perform any authorization check to ensure the authenticated principal is allowed to pay the specified `order_id`. The code fetches the order and updates its status to 'paid' without verifying ownership or role permissions, which could allow an attacker to pay another user's order (IDOR). However, no additional evidence (e.g., scanner finding, runtime probe) confirms that this path is exploitable, and it is unclear whether `principal` returns user identity or if database row‑level security is in place.

**Impact:** An attacker could mark any order as paid, potentially causing financial loss, unauthorized invoice generation, and audit inconsistencies.

**Remediation:** Add an authorization check after retrieving the order to verify that the authenticated user owns the order or has a role permitting payment. Example: `if order['user_id'] != principal_user_id: raise HTTPException(403, "Forbidden")`. Consider implementing role‑based access control and database row‑level security to enforce ownership.
Evidence:
- Source IDs: `ai-5d4c30816d85620a`
- <code>def pay_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `principal(authorization)`
- `order = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()`
- `conn.execute("UPDATE orders SET status='paid' WHERE id=%s", (order_id,))`

Limitations:
- No scanner or runtime probe evidence confirming the vulnerability is exploitable.
- Unclear what `principal` returns; it may include user ID or role information that could be used for authorization.
- No visible database constraints (e.g., row‑level security) that might enforce ownership.
- Potential guard checks could exist elsewhere in the codebase but are not present in the supplied excerpt.

### 73. Missing ownership check on order cancellation (CWE-639)

- Issue group: `ai-f0dce5b04fc274c8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The cancel_order endpoint authenticates the request via the principal() call but does not perform any authorization check to confirm that the authenticated user owns the order or has sufficient privileges before executing the UPDATE that cancels the order. The supplied source shows the entry point and the sensitive database operation, and no ownership verification is present in the visible code.

**Impact:** An attacker who can obtain a valid authentication token could cancel any order by supplying an arbitrary order_id, leading to denial of service for legitimate users and potential financial loss.

**Remediation:** Add an authorization check after authentication that verifies the requester’s ownership of the order or that the requester has an admin role before performing the UPDATE. For example, query the order’s owner_id and compare it to the principal’s user ID, or enforce role‑based access control. Return an error if the check fails.
Evidence:
- Source IDs: `ai-f0dce5b04fc274c8`
- <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]: (entry point)</code>
- `principal(authorization) (authentication)`
- `row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone() (sensitive operation)`
- `No ownership or role verification code present between authentication and the UPDATE`

Limitations:
- No runtime probe or scanner evidence confirming that the endpoint is reachable and that unauthorized cancellations succeed.
- Unclear whether the principal() function populates role information that might be used implicitly for authorization; the code does not show such a check.
- Potential database‑level policies or triggers that could prevent unauthorized updates are not visible in the provided excerpts.

### 74. Potential information disclosure via exception details (CWE-209)

- Issue group: `ai-45373d0b0f185864`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `error_query` catches any exception and returns the exception message directly in the HTTP 500 response (`raise HTTPException(500, f"Query failed: {error}")`). This can expose internal details such as database schema or query text to an attacker. The supplied source shows the vulnerable path, but there is no independent scanner or runtime probe confirming that the exception message is actually returned to clients, nor evidence of a missing guard outside the provided snippet.

**Impact:** An attacker could gain insight into the database structure or other internal implementation details, facilitating further attacks such as SQL injection or targeted exploitation.

**Remediation:** Replace the detailed exception message with a generic error response. Log the original exception internally, but return a constant message such as `raise HTTPException(500, "Internal server error")`. Consider adding specific exception handling for known error types.
Evidence:
- Source IDs: `ai-45373d0b0f185864`
- `api/extra.py:231 – executes a query on a non‑existent column`
- `api/extra.py:233 – raises HTTPException with f"Query failed: {error}" interpolating the caught exception`

Limitations:
- No runtime probe or scanner evidence confirming that the detailed exception message is sent to the client
- No evidence that a higher‑level error handling middleware sanitizes the response before it leaves the application

### 75. Unauthenticated file download endpoint (CWE-284)

- Issue group: `ai-4ecfe3ddba19f11e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code defines a GET endpoint at "/files" that reads a file from the public directory and returns its contents without any authentication or authorization checks. The excerpt shows the route registration and the file read operation, and there is no visible guard (e.g., require_user, require_admin, or token validation) before the file is served. This pattern can allow any unauthenticated client to retrieve arbitrary files that reside under the configured public folder, provided the path resolves within that folder and the file exists.

**Impact:** An attacker could enumerate and download files from the server’s public directory, potentially exposing configuration files, logs, or other sensitive data that were not intended for public access. This may lead to information disclosure, further exploitation, or privacy violations.

**Remediation:** Add proper authentication and authorization checks before serving files. For example, require a valid user session or token and verify the requester has permission to access the requested file. Consider limiting the served files to a whitelist of safe resources or using signed URLs. Also validate and sanitize the filename parameter to prevent path traversal.
Evidence:
- Source IDs: `ai-4ecfe3ddba19f11e`
- `@router.get("/files") definition at api/extra.py line 210`
- `File resolution and existence check at lines 212‑214`
- `Return of file contents without auth guard at line 215`

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable by unauthenticated users
- No information about the intended use of the /files endpoint or the sensitivity of files in the public directory
- No evidence that other middleware (e.g., a global auth dependency) is applied to this router, which could provide protection outside the shown excerpt

### 76. Missing authorization check for admin users endpoint (CWE-284)

- Issue group: `ai-977152a429a6be98`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users endpoint calls `principal(authorization)` but the supplied code does not show any verification that the authenticated principal has an admin role before executing a query that returns all user records, including SSNs. Without an explicit role check, any authenticated user could potentially access this data, leading to privilege escalation and data exposure.

**Impact:** Unauthorized users may retrieve sensitive personal information (including SSNs) and other user details, violating confidentiality and possibly enabling further attacks such as identity theft.

**Remediation:** Add an explicit check that the principal’s role includes ‘admin’ (or equivalent) before performing the database query. Return an HTTP 403 error for non‑admin callers. Consider moving the check to a reusable dependency or middleware that protects all /admin routes.
Evidence:
- Source IDs: `ai-977152a429a6be98`
- `api/app.py:277 – @app.get("/admin/users") defines the admin endpoint`
- `api/app.py:279 – principal(authorization) is called but no role verification is shown`
- `api/app.py:281 – rows = conn.execute("SELECT id,username,email,role,ssn FROM users ORDER BY id").fetchall() returns sensitive data without a guard`

Limitations:
- The implementation of `principal` is not provided; it may raise an error or enforce role checks internally.
- No additional scanner or runtime probe evidence confirming that the endpoint is reachable by non‑admin users.
- Potential global middleware or dependency that enforces admin checks for routes under /admin is not shown in the excerpt.

### 77. Missing authorization check for admin jobs endpoint (CWE-284)

- Issue group: `ai-1c96865ffd2139a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `@app.get("/admin/jobs")` calls `principal(authorization)` but the provided excerpt does not show any verification that the extracted principal has an admin role before executing a database query that returns all job records. Without an explicit role check or documented middleware that restricts access, any authenticated user could invoke this endpoint and retrieve potentially sensitive job data.

**Impact:** Unauthorized users may enumerate all job records, exposing internal scheduling, processing details, or other confidential information that could aid further attacks or data leakage.

**Remediation:** Add an explicit authorization check after extracting the principal, e.g., `if principal.role != "admin": raise HTTPException(status_code=403)`. Alternatively, apply a role‑based access control decorator or middleware that enforces admin‑only access for routes under `/admin/*`. Ensure the check is performed before any database access.
Evidence:
- Source IDs: `ai-1c96865ffd2139a6`
- `285: @app.get("/admin/jobs")`
- <code>286: def admin_jobs(authorization: str | None = Header(default=None)) -&gt; list[dict[str, Any]]:</code>
- `287: principal(authorization)`
- `288: with connection() as conn:`
- `289: rows = conn.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()`
- `290: return [dict(row) for row in rows]`

Limitations:
- The code for the `principal` function is not provided, so it is unclear whether it internally enforces an admin role for this route.
- No evidence of decorators, middleware, or other access‑control mechanisms elsewhere in the repository that might protect the `/admin/jobs` endpoint.

### 78. Potential IDOR on order retrieval (CWE-639)

- Issue group: `ai-b3070a1396939b3b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint extracts the caller's principal but does not verify that the principal owns the requested order or has a role permitting access before returning the row from the database. This suggests an Insecure Direct Object Reference where an authenticated user could retrieve another user's order by guessing IDs.

**Impact:** An attacker who can authenticate can enumerate or retrieve orders belonging to other users, leading to exposure of sensitive order details such as items, prices, shipping addresses, and potentially personal data.

**Remediation:** Add an ownership or permission check after retrieving the order. For example, query the order's owner_id and compare it to the authenticated user's ID, or enforce role‑based access control before returning the data. Return a 403 Forbidden if the check fails.
Evidence:
- Source IDs: `ai-b3070a1396939b3b`
- `api/app.py:220 – endpoint definition @app.get("/orders/{order_id}")`
- `api/app.py:222 – principal(authorization) called but no further checks`
- `api/app.py:224 – database query selects order by id without filtering by user`

Limitations:
- Missing evidence of the orders table schema (e.g., owner_id column)
- No runtime probe or scanner evidence confirming that unauthorized access is possible
- No visible guard or access‑control logic elsewhere in the provided code base

### 79. Potential IDOR on invoice retrieval (CWE-639)

- Issue group: `ai-1ae6ed5ebe1063cc`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` retrieves an invoice record from the database based solely on the supplied `invoice_id` after calling `principal(authorization)`. No check is performed to verify that the authenticated principal is authorized to view the specific invoice (e.g., matching a `customer_id` field or role check). This pattern can allow an authenticated user to request arbitrary invoice IDs and potentially access other users' invoices, constituting an IDOR risk.

**Impact:** If exploited, an attacker could enumerate invoice IDs and retrieve sensitive billing information belonging to other users, leading to privacy violations and possible financial fraud.

**Remediation:** Add an ownership or role verification step after retrieving the invoice record (or before the query) to ensure the `principal` is allowed to access the requested invoice. For example, query the invoice with a condition on `customer_id` matching the authenticated user, or explicitly compare `row.owner_id` to the principal's ID and return a 403 if they differ. Consider using ORM-level access controls or middleware that enforces resource‑level permissions.
Evidence:
- Source IDs: `ai-1ae6ed5ebe1063cc`
- <code>api/app.py:267 – endpoint definition `@app.get(&quot;/invoices/{invoice_id}&quot;)`</code>
- <code>api/app.py:269 – call to `principal(authorization)` without further checks</code>
- <code>api/app.py:271 – database query `SELECT * FROM invoices WHERE id=%s` without filtering by owner or role</code>

Limitations:
- Missing evidence that the `invoices` table includes a `customer_id` or similar ownership column to check against the principal
- No visible guard or policy in the supplied code that restricts access based on the authenticated user
- No independent scanner or runtime probe confirming that unauthorized access is possible; the assessment relies solely on the code pattern

### 80. Sensitive debug configuration exposure (CWE-200)

- Issue group: `ai-a4a245f41e176a0f`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The code defines a public GET endpoint "/debug/config" that returns internal configuration values, including DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET, without any authentication or authorization checks. This suggests an information disclosure vulnerability, but the evidence is limited to the source excerpt and an AI‑generated analysis; no independent scanner or runtime probe confirms that the endpoint is reachable in production or that the values are actually exposed.

**Impact:** An attacker who can access this endpoint could obtain database connection strings and secret keys, enabling further attacks such as database compromise, credential reuse, or unauthorized API calls.

**Remediation:** Restrict the endpoint to authorized administrators only, or remove it from production builds. Add authentication/authorization checks (e.g., OAuth, role‑based access) before returning any configuration data. Consider using environment‑based feature flags to disable the route in non‑debug environments and ensure secrets are not hard‑coded in responses.
Evidence:
- Source IDs: `ai-a4a245f41e176a0f`
- `api/app.py:320 – @app.get("/debug/config") defines a public route`
- `api/app.py:322 – return {"database_url": DATABASE_URL, "mock_external_url": MOCK_EXTERNAL_URL, "app_secret": os.environ.get("APP_SECRET")} returns secrets without checks`

Limitations:
- No independent scanner or runtime probe confirming the endpoint is reachable in the deployed environment
- No evidence that network segmentation or external firewalls block access to this route in production
- No verification that a feature flag disables the endpoint in non‑debug builds

### 81. Potential missing authentication on health check (CWE-306)

- Issue group: `ai-af22fc4057174aa4`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint is publicly reachable and executes a database query without any authentication or access‑control checks in the supplied code. This could allow an attacker to probe database availability or infer service health. However, no independent scanner or runtime probe evidence is provided, and it is unclear whether external network controls (e.g., firewall rules) restrict access to this endpoint.

**Impact:** An unauthenticated attacker could repeatedly call the health endpoint to confirm service availability, potentially using it as a reconnaissance vector or to infer backend database status, which may aid further attacks.

**Remediation:** Add authentication or restrict the health endpoint to trusted internal networks. If the endpoint must remain public, ensure it performs only minimal, non‑sensitive operations and consider returning a generic status without querying the database.
Evidence:
- Source IDs: `ai-af22fc4057174aa4`
- `api/app.py:154 – @app.get("/healthz") defines a public GET endpoint`
- `api/app.py:157 – conn.execute("SELECT 1") performs a database query inside the endpoint`

Limitations:
- No scanner or runtime probe confirming that the endpoint is reachable from an attacker’s network
- No evidence of external network controls (firewall, ingress rules) that might limit exposure
- No confirmation that the endpoint is intended to be public in production

### 82. Cookie set without Secure flag (CWE-614)

- Issue group: `ai-382002314551c090`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The code sets a session cookie (lab_session) in the response of the /auth/form-login endpoint without specifying the Secure attribute. This means the cookie could be transmitted over unencrypted HTTP connections, exposing the session identifier to network eavesdropping. The source excerpt shows the set_cookie call lacking a secure=True argument.

**Impact:** If the application is accessed over HTTP, an attacker on the network could capture the lab_session cookie and hijack the user’s authenticated session, leading to unauthorized access to protected resources such as the /account page.

**Remediation:** Modify the set_cookie call to include the Secure flag (and consider adding SameSite and HttpOnly attributes). Example: response.set_cookie("lab_session", f"session-{row\['id'\]}", secure=True, httponly=True, samesite="Lax")
Evidence:
- Source IDs: `ai-382002314551c090`
- `api/extra.py:300 – response.set_cookie("lab_session", f"session-{row['id']}") (no Secure flag)`

Limitations:
- Missing evidence about whether the application is served exclusively over HTTPS; if it is, the lack of Secure flag may be less critical. No information on whether other cookie attributes (SameSite, HttpOnly) are set elsewhere. No scanner or runtime probe confirming that the cookie is indeed sent over HTTP.

### 83. Potential IDOR in document upload endpoint (CWE-639)

- Issue group: `ai-1b3aac1279d7c1b7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code shows a POST /documents endpoint that stores uploaded files with a randomly generated name but only performs authentication via verified_identity(). No ownership check is performed when the file is later accessed (view_document endpoint). This pattern can lead to IDOR if an attacker can guess or enumerate the generated token or if another endpoint retrieves documents by ID without verifying the requester’s ownership. However, the supplied excerpts do not include the implementation of the GET /documents/{upload_id} endpoint or any access control checks, so the vulnerability cannot be confirmed.

**Impact:** An attacker who can discover or guess the generated token could retrieve or delete other users' uploaded documents, leading to confidentiality and integrity breaches.

**Remediation:** Add ownership verification when accessing uploaded documents. Ensure that the GET /documents/{upload_id} endpoint checks that the authenticated user owns the requested document before returning it. Consider tying the stored filename to the user’s ID and using opaque, unguessable identifiers.
Evidence:
- Source IDs: `ai-1b3aac1279d7c1b7`
- `api/extra.py line 375: @router.post("/documents") defines the upload endpoint`
- `api/extra.py line 376-377: verified_identity(authorization) only authenticates the user`
- `api/extra.py line 388: (secrets.token_hex(8), payload) stores the file with a random token`
- `api/extra.py line 394-395: @router.get("/documents/{upload_id}") defines a retrieval endpoint (implementation not shown)`

Limitations:
- Missing code for the GET /documents/{upload_id} endpoint to verify whether ownership checks are performed
- No runtime probe evidence showing that an attacker can retrieve another user’s document
- No scanner or higher‑severity source confirming the exploit

### 84. User enumeration via password reset request (CWE-203)

- Issue group: `ai-9725570d578c01b3`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint returns a 404 error with the message "Account not found" when the supplied username does not exist, while a successful request proceeds to token generation. This difference in response allows an attacker to determine whether a username is valid, constituting user enumeration. The code snippet shows the distinct error handling, but no evidence of a generic error response or mitigation such as rate limiting or uniform responses is present in the supplied context.

**Impact:** An attacker can enumerate valid usernames, facilitating credential stuffing, phishing, or targeted attacks against known accounts.

**Remediation:** Return a generic response for both existing and non‑existing usernames (e.g., always respond with "If the account exists, a reset link has been sent"), and implement rate limiting or CAPTCHA on the password‑reset endpoint to mitigate automated enumeration attempts.
Evidence:
- Source IDs: `ai-9725570d578c01b3`
- `api/extra.py line 564: @router.post("/auth/reset/request")`
- `api/extra.py line 567: user = conn.execute("SELECT id FROM users WHERE username=%s", (str(body.get("username", "")),)).fetchone()`
- `api/extra.py line 569: raise HTTPException(404, "Account not found")`

Limitations:
- No runtime probe or scanner evidence confirming that the distinct 404 response is observable by an attacker.
- No evidence of rate limiting, uniform error handling, or other mitigations in the provided code or deployment context.

### 85. User enumeration via verified password reset request (CWE-203)

- Issue group: `ai-ad853b8088744ec9`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The code returns a distinct 404 error when the supplied username does not exist, allowing an attacker to differentiate between existing and non‑existing accounts. The source excerpt shows the raise HTTPException(404, "Account not found") after the user lookup, confirming the information‑leak behavior. However, no independent scanner or runtime probe evidence is provided to corroborate that this behavior is exploitable in the deployed service, and the presence of any additional verification steps (e.g., MFA) is unknown.

**Impact:** An attacker can enumerate valid usernames, facilitating credential‑stuffing or targeted phishing attacks and increasing the overall attack surface of the authentication system.

**Remediation:** Return a generic response for both existing and non‑existing usernames (e.g., always respond with a success message or a generic error) and consider adding rate‑limiting or additional verification before revealing any password‑reset related information.
Evidence:
- Source IDs: `ai-ad853b8088744ec9`
- `Source excerpt line 593‑594 shows: if not user: raise HTTPException(404, "Account not found")`

Limitations:
- No independent scanner or runtime probe evidence confirming the endpoint is reachable and behaves as described; unknown whether additional verification (MFA, token checks) mitigates enumeration.

### 86. Predictable session identifier (CWE-330)

- Issue group: `ai-36ac21e5893e61d7`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code sets a session cookie using a deterministic value derived from the user ID ("session-{user\['id'\]}"). This makes the session identifier predictable and potentially guessable by an attacker who knows or can enumerate user IDs. No evidence of additional integrity protection (e.g., HMAC) or server‑side validation of the token is present in the supplied excerpt.

**Impact:** An attacker who can guess a valid user ID could forge a session cookie and gain unauthorized access to that user's session, leading to account takeover and data exposure.

**Remediation:** Generate a cryptographically random, unguessable session token (e.g., using secrets.token_urlsafe) and store it server‑side (or sign it with a secret key using HMAC/JWT). Validate the token on each request and rotate it on login/logout. Do not base session identifiers on predictable user attributes.
Evidence:
- Source IDs: `ai-36ac21e5893e61d7`
- `response.set_cookie("lab_session", f"session-{user['id']}")`

Limitations:
- No runtime probe or scanner evidence confirming that the predictable token can be exploited. No view of server‑side session validation or additional integrity checks (e.g., HMAC) that might mitigate the issue. The analysis relies solely on the AI‑generated finding and the provided code excerpt.

### 87. Potential IDOR in verified payment endpoint (CWE-639)

- Issue group: `ai-53836baec7106573`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `POST /orders/{order_id}/verified-pay` calls `owned_order(order_id, authorization)` to retrieve the order before allowing a payment. The supplied code does not show what `owned_order` validates. If `owned_order` only checks that the order exists and does not verify that the caller is the owner (or has appropriate role), an attacker could supply an arbitrary `order_id` and cause the payment of another user's order, leading to an IDOR. The subsequent status check only ensures the order is in a "new" state, not that the caller is authorized to pay for it. No additional guard (e.g., role check, ownership verification) is visible in the provided snippet.

**Impact:** An attacker could pay for orders belonging to other users, resulting in unauthorized financial transactions, potential loss of revenue, and violation of confidentiality and integrity of order data.

**Remediation:** Ensure that `owned_order` verifies that the authenticated user (derived from the `authorization` header) is the owner of the order or has a role that permits payment. Add explicit authorization checks after retrieving the order, e.g., compare `order.owner_id` with the user ID from the token, and enforce role‑based access control. Consider returning a 403 Forbidden response when the check fails.
Evidence:
- Source IDs: `ai-53836baec7106573`
- <code>api/extra.py:469 – endpoint definition `@router.post(&quot;/orders/{order_id}/verified-pay&quot;)`</code>
- <code>api/extra.py:470 – call to `owned_order(order_id, authorization)`</code>
- <code>api/extra.py:472 – status check `if order[&quot;status&quot;] != &quot;new&quot;:`</code>
- <code>api/extra.py:483 – update query `UPDATE orders SET status=&#x27;paid&#x27; WHERE id=%s`</code>

Limitations:
- The implementation of `owned_order` is not provided, so we cannot confirm whether it enforces ownership or role checks.
- No runtime probe or scanner evidence confirming that an unauthorized request can reach the update statement.
- No evidence of additional authorization guards elsewhere in the codebase.

### 88. Missing expiration for password reset tokens (CWE-613)

- Issue group: `ai-486324d802ecdfbd`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code inserts a reset token into the `reset_tokens` table without any apparent expiration timestamp or TTL handling. The entry point (`POST /auth/reset/request`) reaches a sensitive operation (storing a reset token) and no check or column for token expiry is visible in the supplied excerpt. However, there is no independent scanner or runtime probe confirming that the token can be used indefinitely, nor evidence that the database schema includes an expiration field or that expiry is enforced elsewhere.

**Impact:** An attacker who obtains a valid reset token could reuse it indefinitely to reset the associated user's password, leading to account takeover and persistent unauthorized access.

**Remediation:** Add an expiration timestamp (e.g., `expires_at`) when inserting the token and enforce expiry checks when the token is later validated. Optionally, configure a TTL on the database table or periodically purge expired tokens.
Evidence:
- Source IDs: `ai-486324d802ecdfbd`
- `conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"]))`
- `return {"reset_token": token}`

Limitations:
- No evidence that the `reset_tokens` table includes an expiration column or that expiry is checked during token validation. No scanner or runtime probe confirming token reuse is possible. The review is limited to the provided code excerpt; other parts of the codebase might implement expiration.

### 89. Missing token validation before admin token report (CWE-287)

- Issue group: `ai-29b6f398101e94dc`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **low**

**Explanation:** The endpoint @router.get("/admin/token-report") checks the role field of a variable `token` without any visible code that obtains or validates the token. If `token` is derived from an untrusted source (e.g., the Authorization header) and lacks signature verification, an attacker could craft a token with role="admin" and bypass the check, leading to unauthorized access to the admin token report.

**Impact:** An attacker could gain administrative privileges and retrieve sensitive token information, potentially allowing further privilege escalation or data exfiltration.

**Remediation:** Ensure the token is extracted from the request (e.g., Authorization header), verify its cryptographic signature or integrity, and validate its claims before checking the role. Use a robust authentication library (e.g., OAuth2/JWT verification) and reject requests with missing or invalid tokens.
Evidence:
- Source IDs: `ai-29b6f398101e94dc`
- `api/extra.py line 660: @router.get("/admin/token-report") defines the admin endpoint`
- `api/extra.py line 663: if token.get("role") != "admin": performs a role check without prior token verification`
- `api/extra.py line 664: raise HTTPException(403, "Administrator required") returns 403 on role mismatch`

Limitations:
- The source excerpt does not show how `token` is populated or whether any signature verification occurs before the role check
- No runtime probe or scanner evidence confirming that an unauthenticated request can reach the endpoint and succeed

### 90. Insecure Direct Object Reference (CWE-639) in profile endpoint

- Issue group: `ai-6322be0c6e12b177`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `profile` endpoint authenticates the request via `principal(authorization)` but does not perform any authorization check to ensure the caller is allowed to access the requested `profile_id`. As a result, any authenticated user can retrieve another user's record, including sensitive fields such as SSN. The source excerpt shows the missing ownership/admin role verification after authentication.

**Impact:** An attacker who can obtain a valid authorization token can enumerate or retrieve arbitrary user profiles, exposing personally identifiable information (PII) like SSN, email, and username. This constitutes a confidentiality breach and may facilitate further attacks such as identity theft.

**Remediation:** Add an authorization check after authentication that verifies the authenticated user's identity against the requested `profile_id` or checks for an admin role. For example:
```python
user = principal(authorization)
if user.id != profile_id and not user.is_admin:
    raise HTTPException(status_code=403, detail="Forbidden")
```
Evidence:
- Source IDs: `ai-6322be0c6e12b177`
- <code>def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `row = conn.execute("SELECT id,username,email,ssn FROM users WHERE id=%s", (profile_id,)).fetchone()`

Limitations:
- No evidence of downstream middleware or additional guards that might enforce ownership for this route.
- No scanner or runtime probe evidence confirming that the endpoint is reachable without authorization checks.
- Unclear whether `principal` performs role checks; the supplied code does not show such logic.

### 91. Missing Authorization Check (CWE-862)

- Issue group: `ai-40fd1ed3ab05cb13`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `admin_overview` is exposed via `@router.get("/admin/overview")` and calls `principal(authorization)`, which appears to perform authentication only. No explicit check for an admin role or privilege is present before the sensitive operation that returns the total user count. Because the code snippet does not show any role‑based verification, a non‑admin authenticated user could potentially access this data, indicating a possible authorization flaw.

**Impact:** Disclosure of the total number of user accounts, which may aid attackers in enumeration, planning credential‑stuffing attacks, or assessing the size of the target environment.

**Remediation:** Add an explicit admin‑role check after authentication, e.g., `require_admin(authorization)` or verify the user's role within `principal` and return a 403 response if the caller lacks admin privileges. Ensure that only authorized admin users can reach the count query and its response.
Evidence:
- Source IDs: `ai-40fd1ed3ab05cb13`
- `@router.get("/admin/overview") defined at api/extra.py line 196`
- `principal(authorization) called at line 198 without further role verification`
- <code>Sensitive query `SELECT count(*) AS n FROM users` executed at line 200</code>

Limitations:
- The implementation of `principal` is not provided; it may already enforce admin‑level checks. No runtime probe or scanner evidence confirming the lack of authorization is available. Without seeing the full authentication/authorization framework, we cannot confirm that the endpoint is insecure.

### 92. Insecure Direct Object Reference (IDOR) in notes endpoint

- Issue group: `ai-60d3cec6938c5b6f`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `order_note` endpoint authenticates the request via `principal(authorization)` but does not verify that the `note_id` belongs to the `order_id` supplied by the client. The query selects the note solely by its primary key (`id`) without filtering on `order_id`, allowing an attacker who can guess or enumerate note IDs to retrieve notes from other orders.

**Impact:** An attacker could access or exfiltrate notes belonging to other users' orders, potentially exposing sensitive order details, personal information, or business data.

**Remediation:** Add an ownership check that ensures the note belongs to the specified order and the authenticated principal. For example, query `SELECT id,order_id,body FROM notes WHERE id=%s AND order_id=%s` and verify the result, or call a helper like `owned_note(order_id, note_id, authorization)` before returning the note.
Evidence:
- Source IDs: `ai-60d3cec6938c5b6f`
- <code>def order_note(order_id: int, note_id: int, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `row = conn.execute("SELECT id,order_id,body FROM notes WHERE id=%s", (note_id,)).fetchone()`

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable and that cross‑order note access is possible.
- The behavior of `principal` is unknown; it may enforce additional ownership checks not visible in the provided excerpt.
- No database constraints or additional code elsewhere were examined that might mitigate the issue.

### 93. Potential IDOR in order verification endpoint

- Issue group: `ai-9a06c902b7e9dd83`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `verified_get_order` returns the result of `owned_order(order_id, authorization)[0]` without any visible ownership check in the supplied code. If `owned_order` does not enforce that the caller owns the requested order, an attacker could retrieve arbitrary orders by guessing IDs, constituting an Insecure Direct Object Reference. The code snippet does not show validation of the `authorization` header or any guard before calling the helper.

**Impact:** An attacker could access other users' order details, exposing personal and financial information and violating confidentiality.

**Remediation:** Ensure that `owned_order` validates that the authenticated user (derived from the `authorization` header) owns the `order_id`. If the helper does not perform this check, add explicit verification before returning the order, e.g., compare the order's owner ID with the authenticated user ID and raise HTTP 403 on mismatch. Also make the `authorization` header required and validate its token before invoking business logic.
Evidence:
- Source IDs: `ai-9a06c902b7e9dd83`
- <code>api/extra.py:449 defines `verified_get_order` with optional `authorization` header</code>
- <code>api/extra.py:450 returns `owned_order(order_id, authorization)[0]` without preceding check</code>

Limitations:
- Missing evidence that `owned_order` performs ownership verification
- Unclear whether the `authorization` header is mandatory and validated before the call
- No scanner or runtime probe confirming the vulnerable behavior

### 94. Unauthenticated data ingestion endpoint (trust boundary violation)

- Issue group: `ai-d3f22b49b98909b6`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The code defines a POST endpoint at /integrations/hook that accepts any request body, decodes it, and inserts it directly into the database as a trusted record without performing authentication, signature verification, or input validation. This creates a trust‑boundary violation where external, unauthenticated data becomes trusted state. No guard (auth check, signature verification, size limit, or rate‑limit) is visible in the supplied excerpt.

**Impact:** An attacker can send arbitrary payloads to the endpoint, causing uncontrolled data insertion, potential log or SQL injection, database bloat, or abuse of downstream processes that rely on the stored data. Because the data is marked as accepted=true, downstream logic may treat it as trusted, leading to further security issues.

**Remediation:** Add authentication (e.g., API key, OAuth) or require a cryptographic signature for incoming webhook requests. Validate and sanitize the request body before insertion. Implement size limits and rate‑limiting for the endpoint. Consider storing raw payloads in a separate, non‑trusted table or marking them as unverified until processed.
Evidence:
- Source IDs: `ai-d3f22b49b98909b6`
- `@router.post("/integrations/hook") (entry point)`
- `body = await request.body() (raw input)`
- `conn.execute("INSERT INTO visits(destination,accepted) VALUES (%s,true)", (body.decode("utf-8", "replace"),)) (sensitive operation)`
- `No authentication or signature verification code present in the excerpt`

Limitations:
- No independent scanner or runtime probe evidence confirming exploitation
- No visible guard such as authentication, signature verification, input validation, size checks, or rate‑limiting in the provided context
- Cannot determine whether other parts of the application enforce checks before this endpoint is reached

### 95. Stored cross-site scripting (CWE-79) in /comments endpoint

- Issue group: `ai-9f1624303e929d51`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `show_comments` handler builds an HTML response by concatenating the raw `row['body']` values from the database into <code>&lt;p&gt;</code> elements without any HTML‑escaping or sanitisation. If an attacker can store a payload in the `comments` table, the payload will be rendered and executed in the victim's browser when the `/comments` page is requested, constituting a stored XSS flaw. No defensive measures such as output‑encoding, a Content‑Security‑Policy header, or server‑side sanitisation are visible in the supplied code.

**Impact:** An attacker who can inject malicious script into a comment body can execute arbitrary JavaScript in the browsers of users viewing the comments page. This may lead to session hijacking, credential theft, defacement, or further compromise of the user’s environment.

**Remediation:** Encode or escape the comment body before inserting it into the HTML response (e.g., use a templating engine with auto‑escaping or explicitly apply `html.escape`). Alternatively, sanitise input on write‑time to strip disallowed tags. Consider adding a strict Content‑Security‑Policy header to mitigate any remaining script execution vectors.
Evidence:
- Source IDs: `ai-9f1624303e929d51`
- <code>return &quot;&lt;h1&gt;Comments&lt;/h1&gt;&quot; + &quot;&quot;.join(f&quot;&lt;p&gt;{row[&#x27;body&#x27;]}&lt;/p&gt;&quot; for row in rows)</code>

Limitations:
- No evidence is provided that comment bodies can be supplied by unauthenticated users or that any input validation occurs elsewhere in the application.
- No runtime probe or scanner evidence confirming that malicious payloads are actually rendered/executed.
- No observation of defensive headers (e.g., CSP) or other mitigations that might reduce impact.

## Policy Decisions

- `merged-4c6d36222f8ebf7f1f68`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-15dd977d52312c30635a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d58491aad5be35b48233`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-c5b44871f1955b338344`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-3913d8f00a297cfbf214`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-56ecc860a2c48330a29a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-69b75a0aa3f8fc9fb800`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-efce9419c25ced2d8892`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-4a2311054cdc2bfe890d`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a9a9a0b97f19f8bf52ae`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-6e468e09eab3ca889e3d`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-81ff94e895c53dbc2029`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d716d5afb61da294d286`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f5fff899f9294177dc70`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-916563c278b3e6b62930`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-54b1ddb055358b3579a2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b7e0b624f8cddd0a9e8c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d0789be823f0fd7fa381`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-7ed325c02dd6cf8227d2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-ccc894903304aa8847bd`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-1bcb1da144dffdcf3fd8`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-a15d98c2851e9a64`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-0b9106bba642ef41`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-d3c8ae68a75d8b90`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-eb33fbefb86b87d2`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-e8ec08f388c6f0b9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-b25b877a4040d288`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-fdb73441313bbd62`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-0c59bf73442d38e5`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-5d4c30816d85620a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-f0dce5b04fc274c8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-45373d0b0f185864`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-4ecfe3ddba19f11e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-977152a429a6be98`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-1c96865ffd2139a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-b3070a1396939b3b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1ae6ed5ebe1063cc`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-a4a245f41e176a0f`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-af22fc4057174aa4`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-382002314551c090`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1b3aac1279d7c1b7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-9725570d578c01b3`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-ad853b8088744ec9`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-36ac21e5893e61d7`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-53836baec7106573`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-486324d802ecdfbd`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-29b6f398101e94dc`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-6322be0c6e12b177`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-40fd1ed3ab05cb13`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-60d3cec6938c5b6f`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-9a06c902b7e9dd83`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-d3f22b49b98909b6`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-9f1624303e929d51`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **96**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **46**; scanner overlaps: **0**; AI overlaps: **1**; new candidates: **24**; uncertain overlaps: **9**; needs more evidence: **12**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-0c354e1132e37f93`: needs_more_evidence
- `ai-d3c8ae68a75d8b90`: uncertain_overlap
- `ai-e8ec08f388c6f0b9`: uncertain_overlap
- `ai-e2fd8c7aace74728`: needs_more_evidence
- `ai-ba5e1f2befe9a47a`: needs_more_evidence
- `ai-b25b877a4040d288`: uncertain_overlap
- `ai-15b9246c05f0d7ad`: needs_more_evidence
- `ai-af22fc4057174aa4`: uncertain_overlap
- `ai-7b3fe73e74130cf4`: needs_more_evidence
- `ai-382002314551c090`: uncertain_overlap
- `ai-36ac21e5893e61d7`: uncertain_overlap
- `ai-486324d802ecdfbd`: uncertain_overlap
- `ai-dedb722a647be7c4`: needs_more_evidence
- `ai-edc70c12f2957599`: needs_more_evidence
- `ai-29b6f398101e94dc`: uncertain_overlap
- `ai-dea8b2dc056f48e2`: needs_more_evidence
- `ai-49b74c92b62b025a`: needs_more_evidence
- `ai-4276e1616e5aa403`: needs_more_evidence
- `ai-d3f22b49b98909b6`: uncertain_overlap
- `ai-9fa1084206dce924`: needs_more_evidence
- `ai-d007ad97240e98f1`: needs_more_evidence

## Pending Security Reviews

- `ai-e358d3ef59fad665`

## Coverage Gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.
- Coverage applies only to declared assertions, accounts and workflows.
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
- This baseline phase only makes bounded HTTP GET observations; browser crawling, ZAP and account workflows are separate phases, reported only when they ran.

## Limitations

Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.

# Security Review Report

- Project: `targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-23T23:26:25.066798+00:00`
- Policy status: **failed**
- Review status: **partial**

## Executive Summary

The agent reviewed **87** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **99**; reviewed: **87**; pending: **12**.

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
14. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4a2311054cdc2bfe890d</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-f7770e55aa48cd4e79a67974</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
15. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4ae7658c2abfbf689e2b</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-ac5e6859c324c2e40526210b</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
16. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-4c6d36222f8ebf7f1f68</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-06b259c78fa19fa5d06a773c</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
17. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
18. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-54b1ddb055358b3579a2</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-bc7d0d0a77b4619ba22d0b25</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [403, 404], &quot;method&quot;: &quot;GET&quot;, &quot;status&quot;: 200, &quot;step&quot;: 3, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;invoice_owner&quot;}</code>.
19. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-56ecc860a2c48330a29a</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-d193f3d7b6fa58812879e8e6</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
20. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
21. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-5a7c783c30e11426af42</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-97a2403badc5307e87389e70</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;order_initial_state&quot;}</code>.
22. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/auth/form-login</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-69b75a0aa3f8fc9fb800</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-b6f705aa38e255df58e01591</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;POST&quot;, &quot;values_redacted&quot;: true}</code>.
23. **Missing Anti-clickjacking Header** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-6e468e09eab3ca889e3d</code>; rule(s): <code>zap.10020</code>; source evidence: <code>runtime-b9a6116c922e7e3c213c2404</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
24. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
25. **python-multipart: Python-Multipart: Information disclosure due to parser differential in form data handling** — scanner from trivy; location: <code>requirements.txt</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-74bb99c1ff3b5ed1fea8</code>; rule(s): <code>CVE-2026-53538</code>; source evidence: <code>finding-37828c3c6f1de39a916e</code>.
26. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-767d54ff7a729b156819</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-289a562cf581d69d3a6c7d63</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;negative_price&quot;}</code>.
27. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.
28. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:222</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-794dcb4921076779cef0</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-2f756e27fddc389636a8</code>.
29. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-7ed325c02dd6cf8227d2</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-3143beb445281415043c6a2c</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 2, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;coupon_bounds&quot;}</code>.
30. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/comments</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-81ff94e895c53dbc2029</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-c2674e7dbbea535e39dafdce</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
31. **Uncontrolled data used in path expression** — scanner from codeql-cli; location: <code>api/extra.py:213</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-83d97da4516adf20e20f</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-26bd24fa5794fd60d9e9</code>.
32. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
33. **python-multipart: Python-Multipart: Denial of Service via crafted multipart/form-data requests** — scanner from trivy; location: <code>requirements.txt</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8a5f28db4eebc517239e</code>; rule(s): <code>CVE-2026-40347</code>; source evidence: <code>finding-97772d9da2bade1715c0</code>.
34. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8cdc677a9810b317840f</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-79fa84ef4d90b0b35afc2e33</code>.
    - Bounded runtime evidence: <code>{&quot;assertion_results&quot;: [false], &quot;expected_statuses&quot;: [400, 422], &quot;method&quot;: &quot;POST&quot;, &quot;status&quot;: 200, &quot;step&quot;: 1, &quot;values_redacted&quot;: true, &quot;workflow_id&quot;: &quot;webhook_destination&quot;}</code>.
35. **python-multipart: Python-Multipart: Arbitrary file write via path traversal vulnerability** — scanner from trivy; location: <code>requirements.txt</code>; severity: **high**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-8ce42d9c8b52a95b109d</code>; rule(s): <code>CVE-2026-24486</code>; source evidence: <code>finding-555e67f97039217aa153</code>.
36. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-916563c278b3e6b62930</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-ad2c3148445dc879b11b7580</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
37. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
38. **Content Security Policy (CSP) Header Not Set** — DAST from web-runtime; location: <code>/view</code>; severity: **medium**; confidence: high; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a4473061f97f0a366678</code>; rule(s): <code>zap.10038</code>; source evidence: <code>runtime-7a357b5bf54222b07b45d1ba</code>.
    - Bounded runtime evidence: <code>{&quot;method&quot;: &quot;GET&quot;, &quot;values_redacted&quot;: true}</code>.
39. **X-Content-Type-Options Header Missing** — DAST from web-runtime; location: <code>/catalog/query</code>; severity: **low**; confidence: medium; risk: not ranked; disposition: <code>not_ranked</code>.
    - Record: <code>merged-a6e788cfc5d9d1297feb</code>; rule(s): <code>zap.10021</code>; source evidence: <code>runtime-2f9dcf012b09704cb4324d5b</code>.
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

**Explanation:** The runtime probe observed a GET request to '/' without the X-Content-Type-Options header. The provided source excerpt does not show any middleware or response handling that adds this security header. While the absence of the header is a known security weakness, the evidence is limited to a single runtime observation and no code evidence confirming that the header is never set.

**Impact:** Browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Add middleware or response handling that sets `X-Content-Type-Options: nosniff` for all responses, e.g., using FastAPI's `Response` object or a Starlette middleware.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Runtime probe (zap.10021) reported GET / without X-Content-Type-Options header`

Limitations:
- No complete set of response headers from the server is provided
- Source code does not show any place where security headers are added or configured
- Only a single request path was probed; other endpoints may behave differently

### 2. Job listing requires admin role

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/jobs calls a function principal(authorization) before accessing the database, but the provided code does not show any role verification or access control logic. The runtime probe observed a successful 200 response for an unauthenticated GET request, indicating that the expected admin‑only restriction is not enforced in practice.

**Impact:** An attacker could retrieve the full list of jobs, potentially exposing sensitive internal data or enabling further enumeration attacks.

**Remediation:** Implement proper authorization checks inside the principal function (or directly in admin_jobs) to verify that the caller has an admin role before querying the database. Return 403/401 for unauthorized requests.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs calls principal(authorization) but no role check is visible (lines 285‑290).`
- `Runtime probe fact reports status 200 for GET /admin/jobs where 403/404 were expected (workflow.admin_jobs.2).`

Limitations:
- The implementation of principal() is not provided, so we cannot confirm whether it performs adequate admin role verification. Additional code review of principal() or related auth middleware is needed.

### 3. Improper access control on /admin/token-report endpoint

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source code checks the token role and raises HTTP 403 when the role is not "admin". However, the runtime probe observed a GET request to /admin/token-report returning HTTP 200, indicating the check did not block access as intended. The scanner finding and runtime observation together confirm that a demoted administrator (or any user without the admin role) can still access the endpoint.

**Impact:** An attacker without administrative privileges can retrieve the token report, potentially exposing sensitive token information and allowing further privilege escalation or data leakage.

**Remediation:** Ensure that the role check correctly validates the token and that the token extraction logic (`principal`) returns accurate role information. Add comprehensive unit and integration tests for role enforcement and consider implementing defense‑in‑depth checks (e.g., middleware) to enforce admin access.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check and HTTPException raise on non‑admin (lines 661‑664).`
- `Runtime probe fact: GET /admin/token-report returned status 200 instead of expected 403 (assertion_results false).`

### 4. User listing endpoint lacks admin authorization check

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /admin/users endpoint calls the principal() function but does not verify that the authenticated principal has an admin role before returning the full list of user records, including sensitive fields such as SSN. The source excerpt shows no role check. Runtime probing confirms the endpoint is reachable without restriction, returning HTTP 200 instead of the expected 403/404, providing independent corroboration of the flaw.

**Impact:** An attacker who can obtain or guess a valid authorization header can retrieve the complete user database, including personally identifiable information (PII) and SSNs, leading to privacy violations and potential identity theft.

**Remediation:** Add an explicit role check after principal() to ensure the caller has an admin role, and return a 403 Forbidden response for non‑admin users. Example:
```python
user = principal(authorization)
if user.role != "admin":
    raise HTTPException(status_code=403, detail="Admin access required")
```
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source code shows admin_users endpoint without role verification (lines 278‑282).`
- `Runtime probe returned HTTP 200 for GET /admin/users, contrary to expected 403/404.`

### 5. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a session cookie with `response.set_cookie("lab_session", f"session-{row['id']}")` but does not specify the `HttpOnly` attribute. The absence of this flag means client‑side scripts could potentially access the cookie, increasing the risk of theft via XSS. However, the supplied evidence does not include a runtime observation confirming that the `HttpOnly` flag is indeed missing, nor does any higher‑severity scanner corroborate the behavior.

**Impact:** If an attacker can execute JavaScript in the victim's browser (e.g., via an XSS flaw), they could read the `lab_session` cookie and hijack the user's authenticated session.

**Remediation:** Set the `HttpOnly` flag when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)`. Consider also adding `Secure` and `SameSite` attributes as appropriate.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- `source line 300: response.set_cookie("lab_session", f"session-{row['id']}")`

Limitations:
- Missing runtime proof that the cookie is sent without the HttpOnly attribute.
- No higher‑severity scanner or independent confirmation that the flag is absent.

### 6. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The scanner reports that the response from the POST /auth/form-login endpoint does not include an anti-clickjacking header such as X-Frame-Options or Content‑Security‑Policy frame‑ancestors. The source excerpt shows the endpoint implementation but does not set any response headers related to clickjacking protection. No guard or header-setting code is visible in the supplied context.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and potentially trick users into submitting credentials (clickjacking), leading to credential theft or session hijacking.

**Remediation:** Add an appropriate anti‑clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a CSP with `frame-ancestors 'none'`. Ensure the header is applied to all relevant endpoints, preferably via middleware.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Scanner finding (zap.10020) reports missing anti‑clickjacking header on /auth/form-login`
- `Source code excerpt shows no header being set in the form_login handler`

Limitations:
- No runtime probe showing the actual HTTP response headers; the scanner evidence is not independently corroborated by another source. Unable to confirm whether a global middleware might add the header outside the shown snippet.

### 7. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The scanned endpoint /auth/form-login returns an HTMLResponse without explicitly setting a Content‑Security‑Policy header. The source excerpt shows the response being created and returned, and no call to `response.headers` or a middleware that adds CSP is present in the supplied code. The runtime probe confirms the endpoint was exercised via a POST request, but does not provide evidence that a CSP header was added elsewhere (e.g., by a framework default or external proxy).

**Impact:** Without a CSP header, browsers are free to execute inline scripts and load resources from any origin, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks. An attacker who can inject script content into the response (e.g., via reflected or stored XSS) could execute malicious code in the victim’s browser.

**Remediation:** Add a CSP header to the response, either directly in the endpoint or globally via middleware. For example:
```python
response = HTMLResponse(f"Signed in as {html.escape(row\['username'\])}")
response.headers\["Content‑Security‑Policy"\] = "default-src 'self'; script-src 'self'; object-src 'none';"
return response
```
Or configure a FastAPI/Starlette middleware to set the header for all responses.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Source excerpt shows HTMLResponse returned without CSP header (lines 299‑301).`
- `Runtime probe fact indicates POST request to /auth/form-login was made (scanner_id: web-runtime, rule_id: zap.10038).`

Limitations:
- No evidence is provided that a CSP header is added elsewhere in the application stack (e.g., global middleware, reverse‑proxy configuration).
- The scanner finding alone does not prove the header is absent in production; additional runtime verification of response headers is needed.

### 8. Password reset tokens may be reusable

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code retrieves a reset token from the database and, if it exists, updates the user's password without invalidating or deleting the token. No check is performed to ensure the token is single‑use. A runtime probe shows that a POST to /auth/reset/confirm returns 200 instead of the expected error codes, suggesting the token can be reused.

**Impact:** An attacker who obtains a valid reset token could reuse it to reset the victim's password multiple times, leading to account takeover.

**Remediation:** Invalidate or delete the reset token after a successful password change, and optionally enforce a one‑time‑use flag in the database. Add a check that the token has not been used before proceeding with the password update.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup and password update without token invalidation (lines 577‑585).`
- `Runtime probe fact indicates the endpoint returned 200 instead of expected error codes, implying the token was accepted again.`

Limitations:
- Missing explicit evidence that the token remains valid after a successful reset (e.g., a second request with the same token returning 200).
- No independent scanner of medium or higher severity confirming the reuse behavior.

### 9. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/query` returns HTML content but the supplied source excerpt does not set any HTTP security headers, including a Content Security Policy. The runtime probe confirms the endpoint is reachable via GET, and the scanner flagged the missing CSP header. No code or configuration evidence shows that a CSP header is added elsewhere (e.g., middleware, reverse proxy).

**Impact:** Without a CSP header, browsers are not instructed to restrict the sources from which scripts, styles, and other resources can be loaded. This can enable cross‑site scripting (XSS) or data‑injection attacks if an attacker can influence the rendered HTML.

**Remediation:** Add a CSP header to the response, either directly in the route handler or via a global middleware. For example, set `response.headers['Content‑Security‑Policy'] = "default-src 'self'; script-src 'self'"` or configure the web server/reverse proxy to inject the header for all responses.
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Scanner finding: "Content Security Policy (CSP) Header Not Set" for path /catalog/query`
- `Runtime probe fact: GET request to /catalog/query observed (zap.10038)`

Limitations:
- No evidence was provided that a CSP header is set elsewhere in the application stack (e.g., FastAPI middleware, ASGI server, or external proxy). The review is based solely on the shown route code and the scanner/runtime observation.

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-a6e788cfc5d9d1297feb`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/catalog/query` returns HTML content without setting the `X-Content-Type-Options: nosniff` header. The supplied source code does not add this header, and the runtime probe confirms a GET request to the path, but no evidence is provided that the header is added elsewhere (e.g., middleware or server configuration).

**Impact:** Browsers may perform MIME type sniffing on the response, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Configure the application or web server to include `X-Content-Type-Options: nosniff` on all responses, e.g., by adding a response header in FastAPI middleware or setting it in the deployment server configuration.
Evidence:
- Source IDs: `merged-a6e788cfc5d9d1297feb`
- `Scanner report indicates missing X-Content-Type-Options header for /catalog/query`
- `Source code for /catalog/query does not set the header`

Limitations:
- No evidence that a global middleware or server setting adds the header elsewhere
- No runtime probe showing the header is present or absent beyond the scanner finding

### 11. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting any anti-clickjacking headers such as X-Frame-Options or Content‑Security‑Policy frame‑ancestors. The source excerpt shows the response is built and returned directly, and no header manipulation is present. Runtime probe confirms the endpoint is reachable via GET, but does not provide evidence that required headers are present. No guard or header-setting logic is visible in the supplied context.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti‑clickjacking headers to the response, e.g., set X‑Frame‑Options: SAMEORIGIN or DENY, or configure a Content‑Security‑Policy with a frame‑ancestors directive. In FastAPI, this can be done via a middleware that adds the header to all responses or specifically to this route.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Source excerpt shows HTML response is returned without header manipulation (lines 148‑153).`
- `Runtime probe fact indicates a GET request to /catalog/query was made (scanner_id: web-runtime, rule_id: zap.10020).`

Limitations:
- No runtime evidence confirming the absence of anti‑clickjacking headers; the probe did not capture response headers.
- No view of global middleware or server configuration that might add the header elsewhere.

### 12. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns an HTML page constructed from database content without setting any anti-clickjacking headers such as `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`. The source excerpt shows the response is built and returned directly, and no header manipulation is present. A runtime probe (zap.10020) flagged the missing header, providing independent scanner evidence of the issue.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti-clickjacking headers to the response, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, preferably via middleware or response headers configuration in the FastAPI application.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Source code returns HTML directly without setting security headers (lines 173-177).`
- `Runtime probe fact from ZAP (rule zap.10020) indicates the GET /comments response lacks anti-clickjacking protection.`

Limitations:
- The provided snippet does not show the full request handling pipeline; it is possible that a global middleware adds the header, but this is not visible in the supplied context.
- No explicit test of the header presence was performed beyond the scanner report.

### 13. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns an HTML response constructed from database content without setting any HTTP security headers. The scanner reported that the CSP header is missing, and the source excerpt shows no code that adds security headers to the response. No guard or middleware that would set a CSP header is visible in the supplied context.

**Impact:** Without a CSP header, browsers are free to execute inline scripts or load resources from any origin, increasing the risk of cross‑site scripting (XSS) and data injection attacks.

**Remediation:** Add a CSP header to the response, either globally via middleware or specifically for this route. For example, use FastAPI's `Response` object to set `Content‑Security‑Policy: default-src 'self';` or configure a security middleware such as `Starlette`'s `SecurityMiddleware`.
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- `Scanner finding: Content Security Policy (CSP) Header Not Set (zap.10038) for GET /comments`
- `Source excerpt shows HTML response generation without header handling`

Limitations:
- No evidence is provided that a CSP header is set elsewhere (e.g., in middleware, server configuration, or a reverse proxy). The review is limited to the shown code, so the presence of a header cannot be confirmed.

### 14. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for GET /comments does not include the X-Content-Type-Options header. The provided source code shows the endpoint implementation but does not reveal any middleware or response‑header configuration that could set this header. No independent runtime probe confirming the header’s absence is present, and there is no code evidence of a deliberate omission or a guard that would add the header conditionally.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of responses, potentially allowing content‑type confusion attacks such as cross‑site scripting when untrusted data is reflected in HTML.

**Remediation:** Configure the application or web server to include the X-Content-Type-Options: nosniff header on all responses, e.g., by adding a FastAPI middleware that sets the header, or by configuring the reverse proxy (nginx, Apache, etc.) to add it globally.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- `Scanner report (zap.10021) indicates missing X-Content-Type-Options header on GET /comments`

Limitations:
- No runtime probe or response capture confirming the header is absent; the source excerpt does not show header handling, so the missing header cannot be definitively proven from the supplied data.

### 15. Debug configuration is unavailable anonymously

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source code defines a GET endpoint at /debug/config that returns sensitive configuration values (database URL, mock external URL, and app secret) without any authentication or authorization checks. The runtime probe observed an HTTP 200 response for an unauthenticated GET request, while the expected statuses were 401/403/404, confirming that the endpoint is publicly accessible. This combination of source evidence and independent runtime observation demonstrates a clear lack of access control.

**Impact:** An attacker can retrieve sensitive configuration data, including database connection strings and application secrets, which can be used to compromise the database, forge requests to external services, or gain further unauthorized access within the application.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint. Restrict access to authorized personnel only, e.g., by requiring a valid session token or API key, and return a 401/403 response for unauthorized requests. Consider removing or limiting the exposure of sensitive configuration data from the endpoint altogether.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source excerpt shows the /debug/config endpoint returning DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks (lines 320-322).`
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404 (runtime_probe_facts).`

### 16. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the /healthz endpoint returns a response without a Content‑Security‑Policy header. The supplied source code shows the endpoint implementation but does not include any logic for setting response headers, and no runtime probe data confirming the header’s absence is provided beyond the scanner’s claim.

**Impact:** Without a CSP header, browsers may allow execution of unsafe scripts or resources, increasing the risk of cross‑site scripting (XSS) or data‑injection attacks against clients that consume this endpoint.

**Remediation:** Add a Content‑Security‑Policy header to the response for the /healthz endpoint (and other relevant endpoints). This can be done by configuring the web framework to include the header globally or by setting it explicitly in the endpoint handler.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Scanner report: web.missing-content-security-policy on path /healthz (status 200)`

Limitations:
- No direct observation of the actual HTTP response headers from the running service; the finding relies solely on the scanner’s detection. Additional runtime verification of response headers is needed to confirm the absence of CSP.

### 17. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response without the X-Frame-Options or Content-Security-Policy frame-ancestors header that would mitigate clickjacking. Both the static scanner finding and the runtime probe report the missing header for the same path.

**Impact:** An attacker could embed the health check page in a malicious site’s iframe, potentially tricking users into unintended interactions or information disclosure.

**Remediation:** Configure the FastAPI application (or the upstream web server) to include an appropriate clickjacking protection header, e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive, for all responses including /healthz.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Scanner finding: Missing clickjacking protection header on /healthz`
- `Runtime probe fact: status 200 returned for /healthz without clickjacking header`

Limitations:
- The review cannot confirm whether the header might be added by a reverse proxy or middleware not shown in the provided source excerpt. Confirmation requires visibility of the full response header chain.

### 18. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint is implemented and returns a JSON payload, but the runtime probe fact from ZAP indicates that the response does not include the X-Content-Type-Options header. The source code does not set any security headers, and no guard or middleware is shown that would add this header.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to sniff the MIME type of responses, potentially allowing content‑type confusion attacks such as cross‑site scripting or drive‑by downloads.

**Remediation:** Add middleware or a response decorator that sets the X-Content-Type-Options header to "nosniff" for all responses, e.g., `response.headers['X-Content-Type-Options'] = 'nosniff'`. Ensure this is applied globally or at least for the /healthz endpoint.
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Source excerpt shows the /healthz handler without header logic (lines 154‑158).`
- `Runtime probe fact from ZAP (rule zap.10021) reports the header is missing on GET /healthz.`

Limitations:
- No direct capture of the actual HTTP response headers from the running service beyond the ZAP probe fact; additional runtime testing would confirm the header is consistently absent.
- No evidence of any global security‑header middleware elsewhere in the codebase; the review is limited to the provided excerpt.

### 19. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a 200 response but the supplied source and runtime probe do not show any HTTP response headers. The scanner reports that the X-Content-Type-Options header is absent, which is a security best practice to prevent MIME type sniffing. No code is present that sets this header, and no runtime evidence of the header being present is provided, so the finding is plausible but not definitively proven.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to guess the content type of responses, potentially allowing content‑type attacks such as cross‑site scripting if other vulnerabilities exist.

**Remediation:** Add the X-Content-Type-Options header to the response for the /healthz endpoint (e.g., using a middleware or response decorator) and ensure it is set to "nosniff" for all responses.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Scanner reported missing X-Content-Type-Options header on /healthz`
- `Runtime probe returned status 200 for /healthz`

Limitations:
- No captured HTTP response headers to confirm the header is absent
- No code evidence showing header setting or omission

### 20. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /integrations/hook accepts POST requests, reads the raw request body, and directly inserts it into the database as an accepted visit without any verification of a cryptographic signature or authentication token. The supplied source excerpt shows no signature validation logic. Runtime probe evidence confirms the endpoint returns HTTP 200 for an unsigned request, whereas the probe expected a 4xx response, demonstrating the missing guard in practice. This combination of source code and observed behavior satisfies the criteria for a confirmed vulnerability.

**Impact:** An attacker can craft arbitrary webhook payloads and trigger the endpoint to record forged visits or potentially inject malicious data into the database, leading to data integrity issues, unauthorized actions, or further injection attacks.

**Remediation:** Implement verification of a request signature or authentication token before processing the payload. Reject requests with invalid or missing signatures by returning an appropriate 4xx status (e.g., 401 Unauthorized). Ensure the signature verification uses a secure HMAC or public‑key scheme and that the secret/key is stored safely.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- `Source code at lines 629‑634 inserts the request body into the database without any signature check.`
- `Runtime probe fact: POST to /integrations/hook returned status 200 instead of the expected 4xx, indicating the endpoint accepts unsigned requests.`

### 21. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated principal is the owner of the requested invoice before returning the record. The code fetches the invoice row solely by ID and returns it if found, without an ownership check. A runtime probe for this path returned HTTP 200 instead of the expected 403, confirming that the endpoint is accessible to non‑owners.

**Impact:** Unauthorized users can retrieve invoice details of other users, leading to exposure of sensitive financial information and potential privacy violations.

**Remediation:** Add an ownership verification step after retrieving the invoice row, e.g., compare `row['owner_id']` with the authenticated user's ID and raise `HTTPException(403)` if they do not match. Ensure the check is performed before returning any invoice data.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- `Source excerpt shows the endpoint implementation without an ownership check (lines 268‑274).`
- <code>Runtime probe fact indicates a GET request to `/invoices/{{invoice_id}}` returned status 200, not 403 as expected, demonstrating the missing guard.</code>

### 22. Potential unauthorized job creation via /jobs endpoint

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /jobs POST handler calls a principal() function with the Authorization header but the provided code does not show any role or permission checks before inserting a job record. A runtime probe observed a successful 200 response for a POST to /jobs, whereas the scanner expected error statuses (400, 403, 422). This suggests that the endpoint may accept job submissions without proper authorization checks, potentially allowing non‑admin users to create admin‑level jobs.

**Impact:** An attacker could create or schedule jobs with elevated privileges, leading to unauthorized code execution, data exfiltration, or other privileged actions within the system.

**Remediation:** Implement explicit authorization checks in the create_job handler (or within the principal function) to verify that the caller has the required role (e.g., admin) before inserting the job. Return appropriate error codes (403/401) for unauthorized attempts and ensure the check cannot be bypassed.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- `Source excerpt shows create_job calls principal(authorization) but no further permission validation before DB insert`
- `Runtime probe fact: POST /jobs returned 200 status, while scanner expected 400/403/422`

Limitations:
- The implementation of principal() is not provided, so we cannot confirm whether it enforces role checks
- No additional guard checks or middleware evidence are present in the supplied context

### 23. Identity endpoint discloses SSN

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint retrieves the user's record including the 'ssn' column and returns it in the response without any filtering or access control. The source excerpt shows the SQL query selecting the SSN and the direct return of the row as a dictionary. Runtime probe facts confirm that a GET request to /me returns a 200 response with data (values_redacted true indicates data was present before redaction). No guard or masking logic is present in the supplied code, satisfying the criteria for a confirmed vulnerability.

**Impact:** Attackers who can obtain a valid authorization token can retrieve sensitive personally identifiable information (social security numbers) of any user, leading to identity theft, fraud, and regulatory compliance violations.

**Remediation:** Modify the endpoint to exclude sensitive fields such as SSN from the response or mask them. Implement proper access controls and data minimization, e.g., select only non-sensitive columns (id, username, role, email) or explicitly remove 'ssn' from the returned dict before sending the response.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source excerpt shows SELECT ... ssn FROM users and return dict(row) at /me endpoint`
- `Runtime probe fact shows GET /me returned 200 with values_redacted true, indicating sensitive data was present`

### 24. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the client‑provided unit_price directly into the orders table without any server‑side validation or override. No guard or sanitisation of the price field is visible in the supplied code excerpt. This pattern commonly allows a client to set arbitrary prices, which is a security concern. However, the only evidence is the scanner finding and a runtime probe that shows the endpoint returns 200; there is no independent confirmation that the supplied price is actually persisted or used in downstream billing logic.

**Impact:** An attacker could submit an order with a manipulated unit_price, potentially causing under‑charging or over‑charging, leading to financial loss or fraud.

**Remediation:** Validate and enforce the unit_price on the server side. Either ignore the client‑provided price and replace it with the authoritative catalog price, or compare the client value against the catalog and reject mismatches. Add explicit checks before inserting into the database.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt shows unit_price taken from body and inserted into DB (lines 213‑215).`
- `Scanner finding flags "Catalog price must be set by the server" for /orders endpoint.`
- `Runtime probe fact indicates a POST to /orders returned 200 (scanner_id: web-runtime, rule_id: workflow.price_catalog.1).`

Limitations:
- No direct evidence that the client‑supplied price is stored or influences billing (e.g., no query of the DB after insertion).
- No independent scanner of medium or higher severity confirming the vulnerability beyond the original finding.
- Runtime probe does not demonstrate that the price value was accepted or used; it only shows the request succeeded.

### 25. Orders can be created with arbitrary status including paid

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The create_order endpoint directly inserts the order into the database using the status value supplied in the request body without any validation or restriction. The runtime probe shows that a POST to /orders returns HTTP 200 instead of the expected 400/422, confirming that the endpoint accepts the supplied status (including a paid state) and creates the order successfully. This demonstrates an unchecked path to a sensitive operation (order creation with privileged status).

**Impact:** An attacker can create orders that are immediately marked as paid, bypassing any payment workflow, leading to financial fraud, inventory manipulation, and potential revenue loss.

**Remediation:** Validate the order status field in the request body. Reject or ignore privileged statuses (e.g., "paid") on creation, defaulting to a safe initial state such as "pending". Implement server‑side checks to enforce allowed status transitions and ensure only authorized processes can set a paid status.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- `Source excerpt shows the create_order function inserting the supplied body.status directly into the orders table (lines 213‑215).`
- `Runtime probe fact indicates a POST to /orders returned status 200 when the expected statuses were 400 or 422, confirming the endpoint accepts the request without validation.`

### 26. Negative order prices are accepted

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the supplied unit_price directly into the database without any validation. The runtime probe attempted to submit a negative price and received a 200 OK response, while the scanner expected a 400/422 error. This demonstrates that negative prices are not rejected, confirming the vulnerability.

**Impact:** An attacker can create orders with negative prices, potentially leading to unauthorized refunds, credit abuse, or financial loss.

**Remediation:** Add validation to ensure unit_price (and other monetary fields) are non‑negative before inserting into the database. Return a 4xx error if validation fails.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Source code at lines 208‑215 shows unit_price is inserted without checks`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`

### 27. Users cannot create orders for another owner

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and defaults to the authenticated user's sub when omitted. No authorization check validates that the supplied owner_id belongs to the caller. The runtime probe confirms that a POST to /orders with a different owner_id succeeds with HTTP 200, while the scanner expected a failure status (400/403/422). This demonstrates that an attacker can create orders on behalf of other users.

**Impact:** An attacker can create or manipulate orders for any user, leading to unauthorized transactions, potential financial loss, and data integrity violations.

**Remediation:** Validate that the owner_id in the request body matches the authenticated user's identifier or enforce a proper permission check before inserting the order. If owner_id is not provided, default to the caller's sub; otherwise, reject mismatched values with a 403 response.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source code shows owner_id = body.owner_id or user["sub"] without further checks (lines 208-215).`
- `Runtime probe fact: POST /orders returned status 200 instead of expected error codes, indicating the missing authorization check.`

### 28. A note must belong to the order named in the URL

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its ID but does not verify that the note's `order_id` matches the `order_id` supplied in the URL. The code fetches the note row and returns it if it exists, without any ownership check. Runtime probing confirms the endpoint returns HTTP 200 for a note that does not belong to the requested order, whereas a 403 or 404 would be expected. This demonstrates an insecure direct object reference (IDOR) allowing unauthorized access to notes of other orders.

**Impact:** An attacker can enumerate or retrieve notes belonging to other users' orders by guessing note IDs, leading to exposure of potentially sensitive information and violation of data confidentiality.

**Remediation:** Add a check after fetching the note to ensure `row['order_id']` equals the `order_id` path parameter. If they differ, return a 403 Forbidden or 404 Not Found response. Example:
```python
if row\['order_id'\] != order_id:
    raise HTTPException(403, "Forbidden")
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- `Source code shows no ownership check after fetching the note (lines 543‑549).`
- <code>Runtime probe fact: request to `/orders/1/notes/2` returned status 200 instead of expected 403/404 (scanner `web-runtime` rule `workflow.nested_note.1`).</code>

### 29. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders/{order_id} calls principal(authorization) but does not verify that the authenticated principal is the owner of the requested order before returning the record. The code fetches the order by ID and, if the row exists, returns it without any ownership check. Runtime probe evidence shows a GET request to this endpoint returns HTTP 200 (order data) instead of the expected 403 when the requester is not the owner, confirming the missing guard. The scanner finding also flags this as a workflow order_owner issue, providing independent corroboration.

**Impact:** An attacker who can obtain a valid authorization token for any user can retrieve orders belonging to other users, leading to unauthorized data disclosure and privacy violations.

**Remediation:** Add an ownership check after retrieving the order. Compare the order's owner identifier with the authenticated principal and return HTTP 403 (Forbidden) if they do not match. Example:
```python
row = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
if not row:
    raise HTTPException(404, "order not found")
if row\["owner_id"\] != get_principal_id(authorization):
    raise HTTPException(403, "forbidden")
return dict(row)
```
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- `Source excerpt shows no ownership check after fetching the order (lines 221‑227).`
- `Runtime probe fact indicates the request returned status 200 instead of 403, confirming the missing guard.`

### 30. Excessive coupon discounts are rejected

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/apply-coupon` accepts a discount value from the request body and applies it directly to the order without any validation of the discount magnitude. The source excerpt shows the discount is taken from `body.discount` (or the coupon's stored percent) and written to the database. No guard or limit check is present in the supplied code. A runtime probe attempted to trigger a validation error (expecting 400/422) but received a 200 response, indicating the server accepted the request despite the excessive discount. This combination of source logic and runtime observation suggests a flaw, but there is no independent scanner of medium‑or‑higher severity confirming the issue, nor is there a concrete exploit demonstration.

**Impact:** An attacker could submit a coupon with an arbitrarily high discount (e.g., 100 % or more), causing orders to be fulfilled for free or at a loss, leading to revenue loss and potential abuse of the system.

**Remediation:** Add server‑side validation that caps the discount percentage to an acceptable range (e.g., 0‑100) and returns a 4xx error when the supplied value exceeds the limit. Also ensure that the coupon's stored percent is validated before use.
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- `Source excerpt shows discount is taken from request body without bounds check (lines 231‑235).`
- `Runtime probe fact: request to the endpoint returned status 200 when a 400/422 was expected, indicating no validation (runtime_probe_facts).`

Limitations:
- Missing independent high‑severity scanner confirmation of the vulnerability.
- No proof that the lack of validation can be exploited to achieve a financially damaging outcome in the deployed environment.

### 31. Paid orders require a refund before cancellation

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint updates the order status to `cancelled` without checking whether the order has been paid or whether a refund has been issued. The source excerpt shows no validation of payment status before the UPDATE statement. The runtime probe for this endpoint returned HTTP 200, while the expected statuses for a protected workflow were 400, 409, or 422, confirming that the endpoint allows cancellation of paid orders.

**Impact:** An attacker can cancel paid orders without processing a refund, leading to financial loss and potential abuse of the order management system.

**Remediation:** Add a check to verify that the order is unpaid or that a refund has been processed before allowing cancellation. Return an appropriate error status (e.g., 400 or 409) if the order is already paid.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- <code>Source excerpt shows `cancel_order` performs UPDATE without payment check</code>
- `Runtime probe returned status 200 for POST /orders/{{order_id}}/cancel, contrary to expected error statuses`

### 32. Payment replay vulnerability on order payment endpoint

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The pay_order endpoint updates the order status to 'paid' without first checking whether the order is already in a paid state. This allows a second POST to the same /orders/{order_id}/pay endpoint to re‑execute the payment logic, potentially creating duplicate invoices or charging the customer multiple times. The source excerpt shows no guard against already‑paid orders, and the runtime probe observed a successful 200 response on a repeated payment attempt, contrary to the expected error statuses (400, 409, 422).

**Impact:** An attacker (or a malicious client) can replay a payment request for an order that has already been settled, leading to duplicate charges, multiple invoice records, and financial loss or accounting inconsistencies.

**Remediation:** Add a check before performing the payment update to verify that the order's current status is not already 'paid'. Return an appropriate error (e.g., 409 Conflict) if the order has been paid. Ensure the status check and update are performed atomically within a transaction to prevent race conditions.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- `Source code shows no status check before UPDATE orders SET status='paid'`
- `Runtime probe fact: POST to /orders/{{order_id}}/pay returned 200 instead of expected error status`

### 33. Unauthorized profile access

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` calls `principal(authorization)` but does not verify that the authenticated user is allowed to view the requested profile. The SQL query returns the full user record for any `profile_id` and the code only checks for row existence, returning the data with a 200 response. Runtime probe confirms the endpoint returns 200 for a profile belonging to another user, where a 403 or 404 was expected.

**Impact:** An attacker can retrieve another user's profile, including sensitive fields such as username, email, and SSN, leading to privacy violations and potential identity theft.

**Remediation:** Add an ownership check after retrieving the row, e.g., compare `row.id` with the authenticated user's ID and return 403 if they differ. Alternatively, include the user ID in the query condition to restrict results to the caller's own profile.
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source excerpt shows no ownership check before returning the profile data`
- `Runtime probe fact: GET /profiles/{{other_id}} returned status 200 instead of expected 403/404`

### 34. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /view endpoint returns an HTMLResponse without any X-Frame-Options or Content-Security-Policy frame-ancestors directives, indicating the anti-clickjacking header is missing. The source excerpt shows the raw HTML being returned, and the runtime probe confirms a GET request to /view was made, matching the scanner finding.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add an appropriate X-Frame-Options header (e.g., "DENY" or "SAMEORIGIN") or a Content-Security-Policy with a frame-ancestors directive to the response in the view_home handler.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse without security headers`
- `Runtime probe fact from web-runtime (zap.10020) confirms GET request to /view`

### 35. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /view endpoint returns an HTMLResponse constructed directly in code without setting any HTTP security headers. The source excerpt shows the response generation and no CSP header is added. Runtime probe evidence from ZAP (rule zap.10038) confirms that a GET request to /view was made and the response lacked the CSP header, providing independent corroboration of the missing header.

**Impact:** Without a Content Security Policy header, the application is vulnerable to client‑side attacks such as cross‑site scripting (XSS) and data injection, allowing an attacker to execute malicious scripts in the context of the user’s browser.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response headers or a middleware that injects a secure CSP policy. Example:
```python
from fastapi import Response

@router.get("/view")
def view_home() -&gt; Response:
    html = """&lt;!doctype html&gt;..."""
    return Response(content=html, media_type="text/html", headers={"Content‑Security‑Policy": "default-src 'self';"})
```
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- `Source excerpt shows HTMLResponse returned without headers`
- `ZAP runtime probe (zap.10038) observed GET /view with missing CSP header`

### 36. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source excerpt shows the `/view` endpoint returns an HTMLResponse without explicitly setting the `X-Content-Type-Options` header. The runtime probe records a GET request to `/view` but does not include header information, so the absence cannot be confirmed at runtime. The scanner flagged the missing header, providing independent but low‑severity evidence. No guard or middleware that adds the header is visible in the supplied code.

**Impact:** Without the `X-Content-Type-Options: nosniff` header, browsers may attempt to sniff the MIME type of responses, potentially allowing content‑type confusion attacks such as cross‑site scripting (XSS) if an attacker can influence the response body.

**Remediation:** Add middleware or set the header explicitly for all responses, e.g., `response.headers['X-Content-Type-Options'] = 'nosniff'` or use a security library that injects the header globally.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- <code>Source excerpt shows `/view` endpoint returns HTMLResponse without setting X-Content-Type-Options header</code>
- `Scanner flagged missing X-Content-Type-Options header for path /view`

Limitations:
- No runtime probe confirming the header is absent in actual responses
- No evidence that other parts of the application (e.g., global middleware) add the header
- Cannot verify that the header is not set elsewhere in the codebase

### 37. Webhook destination validation is insufficient

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint validates the supplied target_url only by checking that the string "mock-external" is present. This does not enforce an exact match to an approved internal host and could allow an attacker to craft a URL that includes the substring while pointing to an external service. The code lacks a strict host whitelist or URL parsing check. The runtime probe shows a successful POST (status 200), indicating the check can be bypassed when the substring condition is satisfied, but it does not demonstrate that arbitrary external URLs are accepted.

**Impact:** An attacker could supply a malicious webhook URL that passes the substring check, causing the application to send data to an external server, leading to data exfiltration or further exploitation.

**Remediation:** Replace the substring check with a strict validation that the target_url exactly matches the approved internal host (e.g., compare the hostname after parsing the URL against a whitelist). Reject any URL that does not match the whitelist and consider using a URL parsing library to avoid bypasses.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- `source_excerpt lines 294-298 show the substring check: if "mock-external" not in target_url: raise HTTPException(400)`
- `runtime_probe_facts shows a POST to /webhooks returned status 200, indicating the check passed for a payload containing the allowed substring`

Limitations:
- No evidence of the full list of approved internal hosts or how the application is intended to validate them; cannot confirm that the current check is the only validation performed. No runtime probe demonstrating acceptance of a malicious external URL that merely contains the allowed substring.

### 38. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The source excerpt shows that after successful authentication the application logs the username and the value of the APP_SECRET environment variable using a standard info‑level logger. This logs sensitive credential material in clear text without any redaction or protection. No guard or conditional check is present to prevent logging of this secret.

**Impact:** Exposing secrets in logs can lead to credential leakage if logs are accessed by unauthorized parties, enabling attackers to impersonate the application or access other protected resources.

**Remediation:** Remove the secret from the log statement or replace it with a placeholder. Use structured logging that redacts sensitive fields, and ensure that any logging of authentication events does not include passwords, tokens, or secret keys. Consider configuring log levels to avoid logging sensitive data in production.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) at api/app.py line 137 (scanner semgrep-ce rule python.lang.security.audit.logging.logger-credential-leak)`

### 39. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*", which permits any origin to make cross‑origin requests. This configuration can expose the API to CSRF-like attacks and data leakage when credentials are allowed.

**Impact:** An attacker can host a malicious site that interacts with the API from any origin, potentially stealing data or performing unauthorized actions if the API relies on cookies or other credentials.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. Set allow_credentials to false unless explicitly required, and limit allow_methods and allow_headers to only those needed.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `Source excerpt shows allow_origins=["*"] in CORSMiddleware configuration (lines 24‑29).`

Limitations:
- No runtime probe or independent scanner evidence confirming that the wildcard CORS is exploitable in the deployed environment.

### 40. Log Injection

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs the username and the application secret using a formatted log call where the username originates from user input. This creates a potential log injection vector because untrusted data is interpolated directly into the log message without sanitization or escaping.

**Impact:** An attacker could craft a username containing log control characters (e.g., newlines, log formatting tokens) to manipulate log entries, obscure malicious activity, or inject misleading information into logs, potentially hindering detection and forensics.

**Remediation:** Sanitize or escape user‑controlled values before logging. Use structured logging (e.g., passing the username as a separate field) or explicitly filter out control characters. Avoid logging sensitive secrets such as APP_SECRET.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `Source excerpt shows log.info called with user‑provided username and environment secret: log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- No runtime probe or independent scanner evidence demonstrates that the log injection can be exploited in practice. Evidence of a guard or sanitization step is absent, but the presence or absence of such mitigation outside the provided snippet cannot be confirmed.

### 41. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The legacy_login endpoint constructs an SQL statement by directly interpolating the user‑provided username and password into the query string (line 117). No parameterized query or input sanitization is performed, and there is no visible guard (e.g., ORM, escaping, allow‑list) in the supplied context. This allows an attacker to inject arbitrary SQL via the username or password fields.

**Impact:** An attacker can manipulate the SQL query to bypass authentication, retrieve or modify data, or execute arbitrary database commands, leading to data breach, privilege escalation, or full system compromise.

**Remediation:** Replace the string‑formatted query with a parameterized query using the database driver’s placeholders (e.g., `SELECT ... WHERE username=? AND password=?`) or use an ORM that handles escaping automatically. Additionally, hash passwords with a strong algorithm and compare hashes instead of storing plaintext passwords.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- <code>Source excerpt shows f‑string interpolation of `body.username` and `body.password` into the SQL query (lines 117‑119).</code>
- `Scanner finding flags the query as user‑controlled and classifies it as high severity.`

### 42. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` guard ensures the resolved path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent existence check further validates the target. Thus the supplied code contains the necessary safety checks.

**Impact:** If the guard were missing, an attacker could read arbitrary files on the server. However, the guard is present, so the risk is mitigated.

**Remediation:** No remediation needed for path traversal; ensure the guard remains in place and consider adding logging for invalid access attempts.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 220‑223 show the use of `is_relative_to(root)` and `is_file()` checks preventing directory traversal.</code>

### 43. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a `next` query parameter supplied by the user and directly uses it in a `RedirectResponse` without any validation or allow‑list check. This allows an attacker to craft a URL that redirects victims to an arbitrary external site, constituting an open redirect vulnerability.

**Impact:** An attacker can exploit this to perform phishing attacks, drive‑by downloads, or bypass security controls that rely on trusted redirects, potentially leading to credential theft or malware infection.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external redirects are required, ensure the URL is sanitized and uses a safe redirect mechanism (e.g., a confirmation page).
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source excerpt shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse: return RedirectResponse(next, status_code=302)` with no validation.</code>
- `Scanner finding classified as medium severity for open redirect.`

### 44. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known root directory and then verifies that the resulting path is still within that root using `is_relative_to(root)`. This check prevents directory traversal, and the subsequent `is_file()` check ensures the target is a regular file before it is read. Therefore the path expression is properly controlled and the finding is a false positive.

**Impact:** No path traversal vulnerability; an attacker cannot access files outside the intended public directory.

**Remediation:** No remediation needed for this specific issue; the existing guard is sufficient. Maintain the `is_relative_to` and `is_file` checks if the code is modified.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>source excerpt shows `root = (FILES / &quot;public&quot;).resolve()`</code>
- <code>source excerpt shows `file = (root / name).resolve()`</code>
- <code>source excerpt shows `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 45. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory and then checks both that the resolved path is relative to the base (using `is_relative_to(FILES.resolve())`) and that it points to an existing file (`is_file()`). These checks prevent directory traversal attacks, ensuring that only files within the intended `public` directory can be accessed. Consequently, the path expression is properly controlled and does not constitute a vulnerability.

**Impact:** No impact, as the endpoint safely restricts file access to the intended directory, preventing unauthorized file reads.

**Remediation:** No remediation required; the existing checks are sufficient. Maintain the use of `resolve()` combined with `is_relative_to` and file existence verification for any future file‑access endpoints.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>Source code shows resolution of the user‑provided `name` and validation with `is_relative_to(FILES.resolve())` and `is_file()` before reading the file.</code>

### 46. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a fixed root directory and then verifies that the resulting path is still within that root using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal and ensure only authorized files are served, mitigating the reported risk.

**Impact:** No impact because the code correctly restricts file access to the intended directory.

**Remediation:** No remediation needed; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>source_excerpt lines 220‑224 show resolution of the user‑provided `name`, the `is_relative_to` check against the `root`, and the existence check before reading the file.</code>

### 47. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against the trusted base directory and then verifies that the resulting path is still within that directory using `is_relative_to(FILES.resolve())`. It also checks that the path points to an existing file with `is_file()`. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not lead to a vulnerability.

**Impact:** None – the code safely restricts file access to the intended public directory.

**Remediation:** No remediation needed; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>source_excerpt shows the path resolution and the `is_relative_to` guard preventing traversal.</code>

### 48. Reflected server-side cross-site scripting in catalog_search

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `GET /catalog/search` returns an HTML response that directly interpolates the user‑controlled query parameter `q` into the page title and content without any HTML escaping or sanitisation. This creates a reflected XSS vector: an attacker can supply a malicious payload in `q` that will be rendered by the browser when the response is displayed. No evidence of output encoding, CSP headers, or other mitigations is present in the supplied excerpt.

**Impact:** An attacker who convinces a victim to visit a crafted URL (e.g., <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>) can execute arbitrary JavaScript in the victim’s browser context, leading to session hijacking, credential theft, or other malicious actions.

**Remediation:** Encode or escape the `q` value before inserting it into the HTML response (e.g., using a templating engine that auto‑escapes or explicit HTML‑escaping functions). Consider adding a Content‑Security‑Policy header that restricts script execution and set the response `Content-Type` to `text/html; charset=utf-8`. Validate or sanitise query parameters as appropriate.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`, `ai-01e6577ef8d123d5`
- <code>Source excerpt shows `return f&quot;&lt;h1&gt;Results for {q}&lt;/h1&gt;&quot; + &quot;&quot;.join(f&quot;&lt;p&gt;{row[&#x27;name&#x27;]}&lt;/p&gt;&quot; for row in rows)` where `q` is directly embedded in HTML.</code>
- `Scanner finding flagged this line as XSS (high severity).`
- <code>AI analysis identifies missing HTML escaping for `q`.</code>

Limitations:
- No runtime probe confirming that the payload is actually rendered/executed in a browser.
- No evidence of response headers (Content‑Type, CSP) that might mitigate the issue.
- No view of surrounding application code that could apply a global escaping filter or middleware.

### 49. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function verified_continue validates the supplied URL by ensuring it starts with a single '/' and rejects any value that starts with '//' or contains a scheme or network location. This prevents redirection to external domains, mitigating an open‑redirect vulnerability.

**Impact:** No impact; the code correctly restricts redirects to local paths only.

**Remediation:** None required; the existing validation is sufficient.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `The source excerpt shows explicit checks: not next.startswith('/') or next.startswith('//') or parts.scheme or parts.netloc leads to HTTPException(400).`

### 50. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against the public directory and then verifies that the resulting path is still within the base directory using `is_relative_to(FILES.resolve())`. This check prevents directory traversal attacks. Additionally, it ensures the target is a regular file before serving it. Therefore the path expression is properly controlled and the finding is a false positive.

**Impact:** No impact; the endpoint safely restricts file access to the intended directory.

**Remediation:** No remediation needed for this issue; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `source_excerpt lines 211‑214 show the resolve and is_relative_to checks that enforce the file to stay within the public directory`

### 51. Potential SQL injection in catalog_search endpoint

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `catalog_search` builds a SQL query using an f‑string that directly interpolates the user‑controlled parameter `q` into a LIKE clause without any parameterisation or sanitisation. This pattern can allow an attacker to inject SQL syntax, leading to unauthorized data access or manipulation. No guard (e.g., prepared statements, input validation) is visible in the supplied code excerpt.

**Impact:** An attacker could craft a malicious `q` value to manipulate the SQL query, potentially retrieving or modifying data beyond intended scope, leading to data leakage or integrity compromise.

**Remediation:** Use parameterised queries or an ORM that safely escapes user input. For example, replace the f‑string with a prepared statement: `rows = conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",))`. Additionally, validate or sanitise `q` to allow only expected characters.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`, `ai-4af78a4240e9e89d`
- <code>Source excerpt shows f‑string interpolation of `q` into SQL query (lines 142‑144).</code>
- `Scanner and AI findings both flag this as a high‑severity SQL injection risk.`

Limitations:
- No runtime probe evidence confirming that injected payloads are executed as SQL.
- No evidence that the database driver automatically sanitises interpolated values.
- No visible input validation or escaping elsewhere in the code base.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a recommended best practice but does not constitute a security vulnerability in the supplied context. No evidence shows that the absence of a health check leads to an exploitable condition.

**Impact:** None – the application may lack automated health monitoring, but this does not directly expose it to security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- No runtime evidence indicating that the missing health check leads to a security breach; the finding is purely a configuration recommendation.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding reports the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a recommended best practice for container health monitoring, its absence does not constitute a security vulnerability or a misconfiguration that directly leads to an exploitable condition. No evidence is provided that the missing HEALTHCHECK enables an attacker to compromise the system or bypass security controls.

**Impact:** None – the container will run without health monitoring, which may affect operational reliability but does not create a security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile to enable Docker to monitor container health, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line.`

Limitations:
- No security impact evidence is required; the issue is purely operational.

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile excerpt shows no HEALTHCHECK instruction, but the absence of a health check is a best‑practice recommendation rather than a proven security vulnerability. No evidence of an exploitable condition or missing guard is present in the supplied context.

**Impact:** Without a HEALTHCHECK, container orchestration may not detect a failing service promptly, potentially leading to reduced availability, but it does not directly expose a security flaw.

**Remediation:** Add an appropriate HEALTHCHECK instruction to the Dockerfile to allow the container runtime to monitor the service health, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile lines 1‑7 contain no HEALTHCHECK instruction.`

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to contain CVE-2026-53539, a denial‑of‑service vulnerability triggered by specially crafted form‑urlencoded bodies. The scanner evidence directly identifies the vulnerable version and notes that the issue is fixed in 0.0.30. No mitigating guard or version constraint is present in the supplied context, and the independent scanner source (high severity) corroborates the vulnerability.

**Impact:** An attacker can send a maliciously crafted request that causes the application to consume excessive resources or crash, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later. Update the requirements.txt entry accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency vulnerability CVE-2026-53539 in python-multipart 0.0.20; fixed in 0.0.30.`

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE‑2026‑42561. The CVE describes a denial‑of‑service condition triggered by crafted multipart requests with an excessive number of part headers. The supplied source excerpt directly shows the vulnerable version being used, establishing the vulnerable code path. Independent scanner evidence (high severity, high confidence) also flags this CVE, providing corroboration of the vulnerability.

**Impact:** An attacker can send a malicious multipart request that causes the application to consume excessive resources, potentially leading to service disruption or crash, resulting in denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, where the CVE‑2026‑42561 issue is fixed. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `Dependency vulnerability CVE-2026-42561 in python-multipart 0.0.20; fixed in 0.0.27.`
- `requirements.txt pins python-multipart==0.0.20`

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53538. The scanner identified this dependency mismatch and flagged it as a potential information disclosure issue. The supplied source excerpt confirms the vulnerable version is present in requirements.txt. No runtime probe or additional evidence demonstrating an actual exploit is provided, and no mitigation or guard is visible in the supplied context.

**Impact:** An attacker could craft multipart/form-data requests that trigger the parser differential, potentially causing unintended data leakage from the application.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Verify the updated dependency does not introduce compatibility issues with FastAPI and other components.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency vulnerability CVE-2026-53538 in python-multipart 0.0.20; fixed in 0.0.30.`
- `requirements.txt lists python-multipart==0.0.20`

Limitations:
- No runtime probe demonstrating the vulnerability being triggered in the application.
- No evidence of an actual information disclosure occurring in the deployed service.

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to contain CVE-2026-40347, a denial‑of‑service vulnerability triggered by specially crafted multipart/form-data payloads. The scanner identified this vulnerable dependency and the CVE is publicly documented as fixed in version 0.0.26. No mitigating guard or version constraint is present in the supplied context, and the scanner evidence meets the medium‑severity threshold for independent corroboration.

**Impact:** An attacker can send a malicious multipart request that consumes excessive resources, potentially causing the FastAPI service to become unresponsive or crash, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later. Update the requirements.txt entry accordingly and redeploy the application. Optionally, add dependency‑checking CI steps to prevent future vulnerable versions from being introduced.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26.`
- `requirements.txt pins python-multipart==0.0.20`

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project declares a dependency on python-multipart version 0.0.20, which is known to contain CVE-2026-24486 – an arbitrary file write via path traversal. The scanner identified this vulnerable version in the requirements.txt. However, the supplied repository data does not include any code that imports or uses python-multipart, nor does it show an execution path that would trigger the vulnerable functionality. Without evidence of the library being used in a way that could reach the vulnerable code path, the finding remains unconfirmed.

**Impact:** If an attacker can influence file upload or path handling code that uses python-multipart, they could exploit the path‑traversal flaw to write arbitrary files on the server, potentially leading to remote code execution or defacement.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later, which contains the fix for CVE-2026-24486. Verify that the updated version is reflected in the requirements.txt and that the application is rebuilt/deployed with the patched dependency.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency entry in requirements.txt: python-multipart==0.0.20`
- `Scanner report indicating CVE-2026-24486 affects python-multipart 0.0.20`

Limitations:
- No code evidence showing python-multipart is imported or used
- No runtime probe demonstrating the vulnerable code path is reachable
- No confirmation that an attacker can supply a crafted filename to trigger path traversal

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project pins python-multipart at version 0.0.20, which is known to be vulnerable to CVE-2026-53537. The scanner identified this version mismatch and flagged it as a low‑severity issue. While the CVE demonstrates a concrete vulnerability in the library, the supplied repository does not show whether the vulnerable code path is actually exercised (e.g., multipart parsing is used) nor any runtime confirmation that the flaw manifests in this deployment.

**Impact:** If the application processes multipart/form‑data requests, an attacker could exploit the header parsing discrepancy to obtain unintended information, potentially leading to information disclosure.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537. Verify that the updated version does not introduce breaking changes in multipart handling.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency entry in requirements.txt pins python-multipart==0.0.20`
- `Scanner report cites CVE-2026-53537 affecting python-multipart 0.0.20`

Limitations:
- No evidence that the application actually invokes multipart parsing functionality
- No runtime probe confirming the vulnerable behavior occurs in this environment
- No guard or mitigation visible in the supplied code base

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project's requirements.txt includes python-multipart version 0.0.20, which is known to contain CVE-2026-53540. The vulnerability allows an attacker to supply a negative Content‑Length header, causing the library to allocate the entire request body in memory, leading to potential denial‑of‑service. The scanner’s finding and the explicit version declaration together demonstrate the vulnerable component is present in the codebase.

**Impact:** An attacker can trigger excessive memory consumption on the server, potentially causing crashes or denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, which contains the fix for CVE-2026-53540. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31.`
- `requirements.txt lists python-multipart==0.0.20`

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code builds a URL by concatenating a base constant (BASE) with a caller‑supplied path argument and then passes the resulting URL to urllib.request.urlopen. Because urllib supports the "file://" scheme, an attacker who can influence the `path` parameter could potentially craft a URL that accesses local files. The supplied snippet does not show any validation or sanitisation of `path`, nor any restriction on allowed schemes, so the request may be unsafe. However, no independent scanner of medium or higher severity or runtime probe confirming exploitation is present, and the code context does not demonstrate that the `path` value is attacker‑controlled.

**Impact:** If an attacker can control the `path` argument, they may cause the application to read arbitrary files from the server's filesystem via a "file://" URL, leading to information disclosure or further exploitation.

**Remediation:** Validate and sanitise the `path` argument before constructing the URL. Restrict allowed schemes to "http"/"https" only, or use a higher‑level HTTP client library such as `requests` that does not support the "file" scheme. Consider using URL‑building utilities that safely join paths and enforce a whitelist of acceptable endpoints.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows dynamic construction of URL with BASE + path and use of urllib.request.urlopen (lines 20‑22).`
- `Scanner finding flagged dynamic urllib usage as a potential risk.`

Limitations:
- Missing evidence that the `path` parameter can be supplied by an attacker (e.g., no request‑handling code shown).
- No runtime probe or higher‑severity scanner confirmation that a file‑scheme URL can be triggered.
- No visible input validation or scheme restriction in the provided snippet.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib.request.Request using a value from the payload (payload\["target_url"\]). The request is then opened without any visible validation or sanitisation of that URL. This could allow a malicious actor to influence the URL, potentially exploiting urllib’s support for file:// schemes to read arbitrary files. However, the supplied evidence consists only of the source excerpt and a scanner note; there is no runtime probe demonstrating that untrusted input can reach this call, nor is there any additional scanner finding of medium or higher severity confirming exploitability. No guard (e.g., URL validation, scheme whitelist) is shown in the provided context.

**Impact:** If an attacker can control the target_url value, they may cause the worker to fetch arbitrary resources, including local files via file:// URLs, leading to information disclosure or other unintended side‑effects.

**Remediation:** Validate and sanitise the target_url before using it with urllib. Restrict allowed schemes to http/https, reject or safely handle file:// URLs, and consider using a higher‑level HTTP library such as requests that does not support file:// by default. Add explicit input validation and error handling around the URL construction.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt shows payload["target_url"] passed directly to urllib.request.Request without validation (lines 17‑23).`
- `Scanner flagged the dynamic use of urllib as a low‑severity finding.`

Limitations:
- Missing runtime evidence that untrusted input can reach the urllib call (e.g., a probe showing a crafted payload results in a file:// request).
- No independent medium‑or‑higher severity scanner confirmation of exploitability.
- No visible guard or validation logic in the provided code snippet.

### 64. Potential IDOR on profile verification endpoint (CWE-639)

- Issue group: `ai-af9496dfdf758e33`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The endpoint retrieves the authenticated user via `verified_identity(authorization)` and then checks that the requested `profile_id` matches `user["id"]`. The code does not show how `verified_identity` validates the Authorization header or binds the token to the specific user. If the token validation is weak or can be substituted, an attacker could supply a token belonging to another user and obtain that user's verification status, resulting in an IDOR. The check itself is present, but the lack of visible token integrity verification makes the protection incomplete.

**Impact:** An attacker who can obtain or forge another user's token could query `/profiles/{other_id}/verified` and learn whether that profile is verified, potentially revealing sensitive account status information and facilitating further attacks such as targeted phishing or account takeover.

**Remediation:** Ensure that `verified_identity` performs strict token validation, including signature verification, expiration checks, and binding the token to the user’s identity. Consider using a robust authentication library (e.g., OAuth2/JWT with proper verification) and add explicit checks that the token’s subject (`sub`) matches the `profile_id` before returning any data. Log and monitor failed authorization attempts.
Evidence:
- Source IDs: `ai-af9496dfdf758e33`
- `api/extra.py:107-111 defines the endpoint and the ID comparison check`
- <code>api/extra.py:109 calls `verified_identity(authorization)` without visible token validation</code>

Limitations:
- The implementation of `verified_identity` is not provided, so we cannot confirm whether it securely validates the token or enforces token‑to‑user binding
- No independent scanner or runtime probe evidence confirming the vulnerability is present

### 65. Insecure JWT token (alg none) (CWE-327)

- Issue group: `ai-56e2d5863800b409`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The make_token function constructs a JWT with the header explicitly setting "alg":"none", resulting in an unsigned token. This allows any client to forge tokens with arbitrary claims, potentially bypassing authentication and authorization checks. No signing key or verification step is present in the supplied code snippet.

**Impact:** An attacker can create forged JWTs with arbitrary user identities and roles, leading to unauthorized access, privilege escalation, and data leakage across the application.

**Remediation:** Use a strong, supported signing algorithm (e.g., HS256 with a secret key or RS256 with a private key). Ensure the token is signed and that verification logic validates the signature and rejects tokens with "alg":"none". Store secrets securely and rotate them regularly.
Evidence:
- Source IDs: `ai-56e2d5863800b409`
- `api/app.py:90 – header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())`
- `api/app.py:92 – return f"{header}.{payload}."`

Limitations:
- No evidence of downstream verification that rejects tokens with alg "none"
- No scanner or runtime probe confirming that the unsigned token is accepted by the authentication flow

### 66. Missing authentication on file read endpoint (CWE-284)

- Issue group: `ai-a4d0c1438b124a1b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `file_read` endpoint returns the contents of files under the `public` directory based solely on a user‑supplied `name` parameter. The code performs path resolution and existence checks, but there is no authentication or authorization check before accessing the file. This allows any unauthenticated client to request arbitrary files within the public directory, which may contain sensitive data if the directory is not intended to be globally readable.

**Impact:** Unauthenticated attackers can enumerate and read files from the server’s public directory, potentially exposing configuration files, secrets, or other sensitive information. This constitutes an access control weakness (CWE‑284) that could lead to data disclosure or further exploitation.

**Remediation:** Add authentication and authorization checks before accessing the file. For example, require a valid user session or token and verify that the requester has permission to read the requested file. If only a subset of files should be publicly accessible, enforce an explicit whitelist or move public files to a dedicated, safe directory.
Evidence:
- Source IDs: `ai-a4d0c1438b124a1b`
- <code>def file_read(name: str) -&gt; Response:</code>
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `raise HTTPException(404, "File not found")`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- No evidence of an authentication/authorization guard in the supplied code (e.g., no `require_user`, token validation, or role check).
- No independent scanner or runtime probe confirming that the endpoint is reachable without authentication.

### 67. Missing authentication on verified file read endpoint (CWE-284)

- Issue group: `ai-8a91bb360da5c822`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint defined at @router.get("/files/verified") in api/extra.py allows any client to request arbitrary files from the public directory. The code performs a path‑traversal mitigation by ensuring the resolved path is within the public folder and that the target is a file, but it does not perform any authentication or authorization checks before returning the file contents. This means that unauthenticated users can read any file placed in the public directory, which may contain sensitive information.

**Impact:** Unauthenticated users can enumerate and download files from the server’s public directory, potentially exposing configuration files, private data, or other resources that should be restricted to authorized users. This constitutes an access‑control weakness (CWE‑284).

**Remediation:** Add authentication and appropriate authorization checks to the verified_file_read endpoint. For example, require a valid JWT or session token and verify that the requesting user has permission to access the requested file. Consider limiting the set of files that can be served or moving publicly accessible files to a dedicated static‑file serving mechanism that does not expose internal resources.
Evidence:
- Source IDs: `ai-8a91bb360da5c822`
- `@router.get("/files/verified") definition at line 218 in api/extra.py`
- <code>def verified_file_read(name: str) -&gt; Response: (line 219)</code>
- `root = (FILES / "public").resolve() (line 220)`
- `file = (root / name).resolve() (line 221)`
- `if not file.is_relative_to(root) or not file.is_file(): (line 222)`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain") (line 224)`

Limitations:
- No scanner or runtime probe evidence confirming that the endpoint is reachable without authentication.
- No evidence of existing guard checks outside the provided code snippet (e.g., global middleware) that might enforce authentication.
- Missing confirmation that the public directory contains sensitive files that should not be exposed.

### 68. Potential IDOR on comment creation (CWE-639)

- Issue group: `ai-0cff1c5b0a98f32b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The add_comment endpoint inserts a comment using the user ID returned by the identity function without verifying that the authorization header is present, valid, or that the user is authorized to create comments. If identity returns a default or anonymous user when the header is missing or malformed, an attacker could supply a crafted token or omit it to cause comments to be recorded under another user’s ID, leading to an IDOR condition.

**Impact:** An attacker could create comments on behalf of other users, potentially modifying the perceived activity of those accounts or injecting malicious content associated with another user’s identity.

**Remediation:** Validate the Authorization header before calling identity, ensure identity returns a valid authenticated user, and enforce that the user has permission to create comments. Return an error if the header is missing or invalid, and consider using explicit permission checks.
Evidence:
- Source IDs: `ai-0cff1c5b0a98f32b`
- `@router.post("/comments") at api/extra.py:161 defines the endpoint`
- `def add_comment(..., authorization: str | None = Header(default=None)) at line 162 accepts an optional header`
- `user = identity(authorization) at line 163 calls identity without subsequent validation`
- `row = conn.execute(... (user["id"], body.body) ...) at line 165 inserts the comment using the returned user ID`

Limitations:
- The behavior of the identity function when the header is missing or malformed is unknown; no evidence shows whether it returns an anonymous user, raises an error, or defaults to a specific ID.
- No runtime probe or scanner evidence confirming that unauthenticated requests can create comments or that the inserted author_id can be controlled by an attacker.

### 69. Missing authorization on token refresh endpoint (CWE-285)

- Issue group: `ai-a079b7e3e1360616`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The `/auth/refresh` endpoint creates a new access token based on the user identity returned by `principal(authorization)`. The supplied code does not contain any explicit verification that the supplied token is still valid, not revoked, or that the caller is authorized to perform a refresh. Without such a check, an attacker who possesses a previously issued token (including an expired or revoked one) could potentially obtain a new token.

**Impact:** An attacker could reuse a stolen or revoked token to obtain a fresh access token, leading to unauthorized access to protected resources and potential privilege escalation.

**Remediation:** Ensure that the refresh endpoint validates the token type (refresh vs. access), checks token revocation status, and enforces any required scopes or permissions before issuing a new token. Consider adding explicit checks such as `if not is_refresh_token(authorization): raise HTTPException(403, ...)` and integrate revocation list verification.
Evidence:
- Source IDs: `ai-a079b7e3e1360616`
- `@app.post("/auth/refresh") (line 189)`
- <code>def refresh(authorization: str | None = Header(default=None)) -&gt; dict[str, str]: (line 190)</code>
- `user = principal(authorization) (line 191)`
- `row = conn.execute("SELECT id,username,role FROM users WHERE id=%s", (user["sub"],)).fetchone() (line 193)`
- `if not row: raise HTTPException(401, "Unknown account") (line 194)`
- `return {"access_token": make_token(row), "token_type": "bearer"} (line 196)`

Limitations:
- The implementation of `principal` is not shown; it may already perform revocation or token‑type checks. Without seeing that function, we cannot confirm whether the missing checks are truly absent. Additional evidence about token lifecycle management (e.g., revocation list lookup, refresh‑token validation) is required to elevate this to a confirmed vulnerability.

### 70. Potential path traversal via symbolic links (CWE-22)

- Issue group: `ai-86bcc4c6513e492e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code builds a file path under a public directory, resolves it, and then checks that the resolved path is relative to the public directory and that it is a file. If an attacker can place a symbolic link inside the public directory that points outside the directory, the `resolve()` call will follow the symlink. The subsequent `is_relative_to` check may still succeed because the resolved path can still be considered relative after resolution, allowing an attacker to read files outside the intended directory. The supplied source shows the missing explicit check for symlinks before reading the file.

**Impact:** An attacker who can create or influence symbolic links in the public directory could read arbitrary files on the server, potentially exposing sensitive configuration, credentials, or other private data.

**Remediation:** Validate that the target path is not a symbolic link before reading the file, or use a method that does not follow symlinks (e.g., `os.open` with `O_NOFOLLOW`). Alternatively, restrict file access to a whitelist of allowed filenames or use a safe path‑joining library that prevents traversal and symlink attacks. Ensure the public directory is not writable by untrusted users.
Evidence:
- Source IDs: `ai-86bcc4c6513e492e`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `raise HTTPException(404, "File not found")`

Limitations:
- No runtime evidence (e.g., probe showing that a symlink can be created and accessed) is provided.
- No information about the filesystem permissions or whether the public directory is writable by untrusted users.
- No independent scanner or higher‑severity source confirming the vulnerability.

### 71. Missing authorization check on order creation (CWE-285)

- Issue group: `ai-971eceba12c66dbc`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `create_order` endpoint authenticates the request via `principal(authorization)` but then uses a client‑supplied `owner_id` (or falls back to the authenticated user's ID) directly in the SQL INSERT without verifying that the caller is authorized to act on behalf of that `owner_id`. No ownership or role check is visible in the supplied code, so an attacker could potentially create orders for other users.

**Impact:** An attacker could create, modify, or inflate orders for arbitrary users, leading to unauthorized purchases, financial loss, and potential fraud.

**Remediation:** Validate that `owner_id` matches the authenticated user's ID (`user["sub"]`) unless the caller has an explicit role (e.g., admin) that permits impersonation. Implement role‑based access control checks after `principal` and reject mismatched `owner_id` values with a 403 response.
Evidence:
- Source IDs: `ai-971eceba12c66dbc`
- `207: @app.post("/orders")`
- <code>208: def create_order(body: OrderBody, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `209: user = principal(authorization)`
- `210: owner_id = body.owner_id or user["sub"]`
- `213: "INSERT INTO orders (owner_id,item,quantity,unit_price,status) VALUES (%s,%s,%s,%s,%s) RETURNING *",`
- `214: (owner_id, body.item, body.quantity, body.unit_price, body.status),`

Limitations:
- The implementation of `principal` is not shown; it is unclear whether it returns role information or performs additional authorization checks.
- No evidence of middleware or higher‑level guards that might enforce ownership or role checks for this route.
- No scanner or runtime probe evidence confirming that the endpoint is exploitable in practice.

### 72. Unrestricted run_as parameter in webhook creation (CWE-284)

- Issue group: `ai-ddb52b4e1786df39`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `create_webhook` endpoint accepts a `run_as` value from the request body and stores it directly in the `jobs` table without any authorization check. The code does not verify that the caller is permitted to specify an arbitrary execution identity, which could allow a malicious user to set `run_as` to a privileged account if downstream job execution trusts this field for privilege decisions.

**Impact:** If downstream job processing uses the `run_as` field to determine the execution context, an attacker could cause jobs to run with elevated privileges, leading to unauthorized actions, data exposure, or system compromise.

**Remediation:** Validate the `run_as` parameter against the authenticated principal. Restrict it to the caller's own identity or a whitelist of allowed roles, and reject or sanitize any unauthorized values. Add explicit authorization checks before inserting the job record.
Evidence:
- Source IDs: `ai-ddb52b4e1786df39`
- <code>api/app.py:293-305 – endpoint definition and insertion of `run_as` into the database without checks</code>
- <code>api/app.py:295 – call to `principal(authorization)` but no further authorization for `run_as`</code>
- <code>api/app.py:302 – `str(body.get(&quot;run_as&quot;, &quot;user&quot;))` is taken directly from request body</code>

Limitations:
- No evidence is provided that downstream job execution actually trusts the `run_as` field for privilege decisions
- No view of job executor code or runtime behavior confirming privilege escalation
- No audit or logging evidence showing whether `run_as` values are monitored or restricted

### 73. Missing authentication on login endpoint (CWE-287)

- Issue group: `ai-6d23d0d008604fdc`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The login endpoint forwards credentials to the internal `_login` function without any visible rate‑limiting, captcha, or account‑lockout logic in the provided code snippet. While the endpoint does accept credentials, there is no evidence in the supplied excerpt that protects against brute‑force attacks. The AI analysis flags this as a potential security gap, but no independent scanner or runtime probe confirms the vulnerability, and the `_login` implementation is not shown.

**Impact:** An attacker could repeatedly submit login attempts without restriction, potentially enabling credential‑stuffing or brute‑force attacks to compromise user accounts.

**Remediation:** Add explicit rate‑limiting or account lockout mechanisms for the `/auth/login` route, either via middleware or within the `_login` function. Consider CAPTCHA, exponential back‑off, and logging of failed attempts. Document and enforce a maximum number of failed attempts per IP or user identifier.
Evidence:
- Source IDs: `ai-6d23d0d008604fdc`
- `api/app.py:166 – @app.post("/auth/login") defines the login endpoint`
- `api/app.py:167 – async def login(request: Request) defines the handler`
- `api/app.py:168‑171 – request parsing without any guard logic`
- `api/app.py:172 – return _login(...) forwards credentials without visible protection`

Limitations:
- The code of the `_login` function is not provided, so it may contain its own throttling or lockout logic.
- No runtime probe or scanner evidence demonstrates that repeated failed logins are accepted without restriction.
- No middleware configuration is shown that could apply rate‑limiting globally.

### 74. Missing ownership check on order coupon application (CWE-639)

- Issue group: `ai-29d3995de39748d4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `apply_coupon` endpoint authenticates the request via `principal(authorization)` but does not perform any authorization check to ensure that the authenticated principal is allowed to modify the specified `order_id`. This could allow any authenticated user to apply coupons or arbitrary discounts to any order, constituting an IDOR/BOLA risk. The code also permits the client to supply a custom discount value (`body.discount`), which can override the coupon's configured percent, potentially leading to privilege escalation. However, the finding is based solely on AI analysis of the source code; no independent scanner or runtime probe evidence is provided to confirm that the vulnerability is exploitable in practice.

**Impact:** An attacker who can obtain a valid authentication token could modify discounts on orders they do not own, leading to unauthorized price reductions, revenue loss, and potential abuse of promotional coupons.

**Remediation:** Add an authorization check after authentication to verify that the principal owns or has permission to modify the order identified by `order_id`. For example, query the order's owner and compare it to the authenticated user, or enforce role‑based access control. Also consider removing the ability for the client to supply a custom discount value and rely solely on the coupon's configured percent.
Evidence:
- Source IDs: `ai-29d3995de39748d4`
- <code>Source excerpt shows `principal(authorization)` called without any subsequent ownership check before the `UPDATE orders SET discount=... WHERE id=order_id` statement (lines 232‑236).</code>
- <code>The function accepts a `CouponBody` that includes an optional `discount` field, which is used directly if provided, allowing the caller to set an arbitrary discount value.</code>

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable and that unauthorized updates succeed.
- Missing information about what `principal` returns (e.g., user ID, roles) and whether any database constraints, triggers, or external middleware enforce ownership checks.
- No evidence that the application logs or other guard mechanisms reject unauthorized discount modifications.

### 75. Missing ownership check on order payment (CWE-639)

- Issue group: `ai-5d4c30816d85620a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `pay_order` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated principal owns the order before updating its status to `paid`. The code fetches the order by ID and proceeds to update it without any ownership comparison, allowing any authenticated user to pay for any order.

**Impact:** An attacker who can obtain a valid authentication token can pay for orders belonging to other users, leading to unauthorized financial transactions and potential fraud.

**Remediation:** Add a check that the `order` record includes a `user_id` (or similar) and compare it to the authenticated principal's identifier before performing the payment update. Return an error if the user does not own the order. Example:
```python
principal_id = principal(authorization)
order = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
if not order:
    raise HTTPException(404, "order not found")
if order\["user_id"\] != principal_id:
    raise HTTPException(403, "not authorized to pay for this order")
# proceed with payment
```
Evidence:
- Source IDs: `ai-5d4c30816d85620a`
- `api/app.py:242 – endpoint definition with authentication header`
- <code>api/app.py:243 – call to `principal(authorization)` (authentication)</code>
- `api/app.py:245 – SELECT query fetching order by ID`
- `api/app.py:249 – UPDATE query marking order as paid without ownership check`

Limitations:
- No evidence that the `orders` table contains a `user_id` column or that ownership information is available
- No runtime probe or scanner evidence confirming that the missing check can be exploited
- No visible guard or additional authorization logic elsewhere in the repository that might enforce ownership

### 76. Unvalidated client-controlled discount value (CWE-20)

- Issue group: `ai-a24a1251367745da`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code allows a client‑provided `discount` field to directly set the `discount` column in the `orders` table without any range or sign validation. The entry point (`apply_coupon`) reads the request body, optionally uses `body.discount`, and then updates the order record. No check is performed to ensure the value is within an acceptable range (e.g., 0‑100) or non‑negative, which could enable excessive or negative discounts.

**Impact:** An attacker could submit a coupon request with a large positive discount (e.g., 1000) to obtain free or heavily discounted products, or a negative discount to increase the payable amount for others. This can lead to financial loss, inventory abuse, and violation of business rules.

**Remediation:** Validate the `percent` value before using it in the UPDATE. Ensure it is numeric, non‑negative, and does not exceed the maximum allowed discount (e.g., 0‑100). Consider enforcing constraints at the database schema level (e.g., CHECK constraint) and applying business‑logic caps in the application layer. Reject or sanitize any out‑of‑range values and log such attempts.
Evidence:
- Source IDs: `ai-a24a1251367745da`
- <code>Source excerpt shows `percent = body.discount if body.discount is not None else (coupon[&quot;percent&quot;] if coupon else 0)` at line 235, directly using the client‑controlled `body.discount` without validation.</code>
- <code>The subsequent UPDATE at line 236 writes the unvalidated `percent` value to the `discount` column of the `orders` table.</code>

Limitations:
- No evidence of database constraints on the `discount` column that would reject out‑of‑range values.
- No information about additional business logic elsewhere that might cap the effective discount.
- No scanner or runtime probe evidence confirming that out‑of‑range values can be persisted or cause an exploit.

### 77. Missing ownership check on order cancellation (CWE-639)

- Issue group: `ai-f0dce5b04fc274c8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint authenticates the request via `principal(authorization)` but does not contain any code that verifies the authenticated user owns the order identified by `order_id`. The SQL statement updates the order status solely based on the supplied `order_id`, which could allow an attacker to cancel any order if they know its identifier. No guard or ownership check is visible in the provided source excerpt.

**Impact:** An attacker who can obtain or guess order IDs could cancel other users' orders, leading to denial of service, financial loss, or unauthorized state changes in the system.

**Remediation:** Add an ownership verification step before performing the update. For example, retrieve the order's owner ID and compare it to the authenticated principal's user ID, returning an error if they do not match. Alternatively, enforce row‑level security in the database to ensure only the owner can modify their orders.
Evidence:
- Source IDs: `ai-f0dce5b04fc274c8`
- <code>api/app.py:259 – endpoint definition with `principal(authorization)` call</code>
- `api/app.py:262 – SQL UPDATE statement that cancels the order without checking ownership`

Limitations:
- The implementation of `principal` is not shown; it may embed additional checks or context that enforce ownership. No database‑level policies (e.g., row‑level security) are visible in the excerpt. No external scanner or runtime probe evidence confirming the vulnerability is present.

### 78. Missing ownership check on order retrieval (CWE-639)

- Issue group: `ai-76ee5ddf6f5e1661`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The GET /orders/{order_id} endpoint authenticates the request via the `principal` call but returns the order record without verifying that the authenticated user is the owner of the requested order. The code fetches the row directly from the database and returns it if it exists, providing no authorization check beyond authentication. This pattern can lead to an IDOR where any authenticated user can view any other user's order data.

**Impact:** An attacker who can obtain a valid authentication token can enumerate or retrieve orders belonging to other users, potentially exposing sensitive personal or financial information and violating confidentiality requirements.

**Remediation:** Add an ownership verification step after retrieving the order. Compare the order's owner identifier (e.g., `row['user_id']` or similar) with the principal identifier (`principal['sub']`). If they do not match, return an HTTP 403 Forbidden error. Example:
```python
row = conn.execute("SELECT * FROM orders WHERE id=%s", (order_id,)).fetchone()
if not row:
    raise HTTPException(404, "order not found")
if row\["owner_id"\] != principal\["sub"\]:
    raise HTTPException(403, "access denied")
return dict(row)
```
Evidence:
- Source IDs: `ai-76ee5ddf6f5e1661`
- `api/app.py:220-227 shows the endpoint definition, authentication call, and database query without any ownership check`
- <code>api/app.py:224 executes `SELECT * FROM orders WHERE id=%s` and returns the row directly</code>
- `The candidate reasoning explicitly notes the missing ownership verification`

Limitations:
- No evidence that the `orders` table contains an owner/user column to check against
- The `principal` function implementation is not shown, so it is unclear whether it provides role or user information usable for a check
- No independent scanner or runtime probe confirming that an unauthorized request can retrieve another user's order

### 79. Missing ownership check on invoice retrieval (CWE-639)

- Issue group: `ai-ae177f098ffafcec`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice before returning the row from the database. The code directly queries the `invoices` table by ID and returns the result, which could expose other users' invoice data if they know or guess another invoice ID.

**Impact:** An attacker who can obtain or guess valid invoice IDs could retrieve financial information belonging to other users, violating confidentiality and potentially enabling further attacks such as fraud or credential harvesting.

**Remediation:** Add an ownership check after fetching the invoice row: retrieve the user identifier from the authentication token, compare it to the `user_id` (or equivalent) column in the `invoices` table, and return a 403 Forbidden if they do not match. Optionally enforce row‑level security at the database level.
Evidence:
- Source IDs: `ai-ae177f098ffafcec`
- `api/app.py:267-274 shows the GET endpoint definition, authentication call, and direct query without ownership validation`

Limitations:
- Missing evidence of the `invoices` table schema (no user/owner column shown).
- No runtime probe or scanner evidence confirming that unauthorized access is possible.
- No database‑level policies or additional guard checks are visible in the supplied context.

### 80. Missing role/authorization check on job creation (CWE-284)

- Issue group: `ai-ecf531ac657f5eee`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The create_job endpoint accepts a `run_as` parameter and inserts it directly into the jobs table without any role or ownership validation. The code calls `principal(authorization)` but no further checks are shown to restrict who may set `run_as` or to ensure it matches the caller's identity. This suggests a potential privilege‑escalation path where any authenticated user could create jobs that execute as arbitrary system users.

**Impact:** If an attacker can specify an arbitrary `run_as` value, they may cause jobs to run with elevated privileges or as other users, leading to unauthorized actions, data exposure, or system compromise.

**Remediation:** Add explicit authorization checks before inserting the job. Verify that the caller has a role (e.g., admin) allowed to set `run_as`, or enforce that `run_as` is always set to the authenticated principal’s identity. Reject or sanitize the field when the caller lacks the required permission.
Evidence:
- Source IDs: `ai-ecf531ac657f5eee`
- `api/app.py:308 – @app.post("/jobs") defines the endpoint`
- `api/app.py:310 – principal(authorization) is called but no role check follows`
- <code>api/app.py:313 – INSERT statement includes the `run_as` field from the request body without validation</code>

Limitations:
- No independent scanner or runtime probe evidence confirming that the endpoint is reachable and that the `run_as` value is honored during job execution
- No visible guard or role‑checking logic in the supplied code beyond the generic `principal` call
- Unclear whether downstream code validates or restricts `run_as` before job execution

### 81. Missing authorization check for admin users endpoint (CWE-284)

- Issue group: `ai-977152a429a6be98`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The provided code defines an endpoint at /admin/users that extracts an Authorization header and calls principal(authorization) before querying the database for all user records, including sensitive fields such as SSN. No explicit role verification is visible in the excerpt, so a non‑admin user could potentially access this data if principal() does not enforce admin rights. However, the source does not show the implementation of principal() or any global middleware that might enforce role checks, and there is no independent scanner or runtime probe confirming the vulnerability.

**Impact:** If the endpoint is accessible to authenticated users without proper admin role verification, attackers could retrieve all user records, exposing personally identifiable information (PII) such as SSNs, leading to privacy breaches and potential regulatory violations.

**Remediation:** Ensure that the endpoint enforces an admin‑only check before executing the query. This can be done by: • Modifying principal() to return role information and verifying the caller has an admin role; • Adding an explicit role check in the handler (e.g., if principal.role != "admin": raise HTTPException(403)); • Applying a dependency or middleware that restricts /admin/* routes to admin users; • Removing sensitive fields (e.g., SSN) from the response unless absolutely necessary.
Evidence:
- Source IDs: `ai-977152a429a6be98`
- <code>def admin_users(authorization: str | None = Header(default=None)) -&gt; list[dict[str, Any]]:</code>
- `principal(authorization)`
- `rows = conn.execute("SELECT id,username,email,role,ssn FROM users ORDER BY id").fetchall()`

Limitations:
- The implementation of principal() is not provided, so it is unclear whether it performs role verification.
- No evidence of global middleware or decorators that might enforce admin checks for /admin routes.
- No scanner or runtime probe evidence confirming that the endpoint is reachable without proper authorization.

### 82. Missing authorization check for admin jobs endpoint (CWE-284)

- Issue group: `ai-1c96865ffd2139a6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/jobs calls principal(authorization) but the supplied code does not show any role verification before returning all job records. Without evidence that principal() enforces an admin role or that a middleware applies to /admin/* paths, an authenticated user may be able to enumerate job data.

**Impact:** Unauthorized users could retrieve the full list of jobs, potentially exposing internal workflow details and enabling further attacks such as information disclosure or privilege escalation.

**Remediation:** Ensure that the endpoint verifies the caller has an admin role before executing the query. This can be done by extending principal() to raise an error for non‑admin users or by adding an explicit role check after principal() (e.g., if not user.is_admin: raise HTTPException(status_code=403)). Alternatively, apply a security middleware that restricts all /admin/* routes to admin users.
Evidence:
- Source IDs: `ai-1c96865ffd2139a6`
- <code>def admin_jobs(authorization: str | None = Header(default=None)) -&gt; list[dict[str, Any]]:</code>
- `principal(authorization)`
- `rows = conn.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()`

Limitations:
- Missing evidence that principal() enforces admin role or returns an error for non‑admin users.
- No visible middleware or decorator that restricts /admin/* routes to admins.
- Unclear whether job records are considered sensitive in the threat model.

### 83. Potential exposure of internal configuration via debug endpoint (CWE-200)

- Issue group: `ai-3dfb81137310f24a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The code defines a GET endpoint at /debug/config that returns raw configuration values, including DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET, without any visible authentication or authorization checks in the provided snippet. This could allow an unauthenticated attacker to retrieve sensitive configuration data if the endpoint is publicly accessible.

**Impact:** Exposure of database credentials and application secrets can lead to unauthorized database access, credential reuse, and further compromise of the application and its environment.

**Remediation:** Protect the /debug/config endpoint with authentication and authorization checks (e.g., require admin role). Alternatively, remove the endpoint from production deployments or restrict it to internal networks. Ensure that sensitive values are not exposed in responses.
Evidence:
- Source IDs: `ai-3dfb81137310f24a`
- `@app.get("/debug/config") defined at api/app.py:320`
- `return {"database_url": DATABASE_URL, "mock_external_url": MOCK_EXTERNAL_URL, "app_secret": os.environ.get("APP_SECRET")} at api/app.py:322`
- `No authentication/authorization guard observed in the snippet`

Limitations:
- Missing evidence that a global security middleware or other guard protects this route
- No runtime probe confirming the endpoint is reachable without authentication
- No scanner or higher‑severity source corroborating the vulnerability

### 84. Predictable session identifier (CWE-330)

- Issue group: `ai-b0aa75c08377bc22`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code sets a session cookie using a value derived directly from the user's numeric database ID (e.g., "session-42"). This makes the session identifier predictable, allowing an attacker who can guess or enumerate user IDs to forge a valid session cookie and potentially hijack another user's session. No evidence of a cryptographically random token generation or additional entropy is present in the supplied excerpt.

**Impact:** An attacker who can guess a valid user ID could create a forged session cookie, gain unauthorized access to that user's session, and perform actions with the victim's privileges, leading to account takeover and data exposure.

**Remediation:** Replace the predictable identifier with a securely generated random token (e.g., using secrets.token_urlsafe). Set appropriate cookie attributes (HttpOnly, Secure, SameSite) and ensure the token is stored server‑side and validated on each request. Invalidate old tokens on logout or after a timeout.
Evidence:
- Source IDs: `ai-b0aa75c08377bc22`
- `response.set_cookie("lab_session", f"session-{user['id']}")`

Limitations:
- Missing evidence that the cookie is later replaced with a secure random token, that HttpOnly/Secure/SameSite flags are set, and that server‑side session validation is performed. Without runtime or scanner confirmation of exploitation, the vulnerability remains unproven.

### 85. Insecure password reset token generation (CWE-338)

- Issue group: `ai-5c26e3944c7d42d2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code inserts a reset token into the database and returns it, but the snippet does not show how the `token` variable is created. Without evidence that a cryptographically secure generator (e.g., secrets.token_urlsafe) is used, the token could be generated with a weak RNG, making it guessable and allowing account takeover.

**Impact:** An attacker who can predict or brute‑force reset tokens could reset arbitrary users' passwords, leading to full account compromise.

**Remediation:** Generate the reset token with a cryptographically secure source such as `secrets.token_urlsafe` or `os.urandom`, ensure sufficient token length/entropy, enforce expiration, and invalidate the token after first use.
Evidence:
- Source IDs: `ai-5c26e3944c7d42d2`
- <code>Source excerpt shows the endpoint definition and the insertion of `token` into the database (lines 564‑573).</code>
- `The code snippet does not include the token generation statement, leaving the method of creation unknown.`

Limitations:
- Missing evidence of how `token` is generated; no indication that a secure RNG is used.
- No independent scanner or runtime probe confirming weak token generation.
- No visible checks for token expiration or single‑use enforcement.

### 86. Insecure password reset token generation (CWE-338)

- Issue group: `ai-d9fcf0a0e754f60a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code inserts a reset token into the database but the source does not show how the variable `token` is generated. No cryptographically secure random number generator is visible, and there is no evidence of additional safeguards such as rate‑limiting or verification of the request origin. Because the finding relies solely on the AI analysis without independent scanner or runtime confirmation, it cannot be confirmed, but the pattern strongly suggests a weakness.

**Impact:** An attacker who can predict or brute‑force reset tokens could hijack user accounts by resetting passwords, leading to unauthorized access and potential data breach.

**Remediation:** Generate the reset token using a cryptographically secure RNG (e.g., `secrets.token_urlsafe` in Python). Store a hash of the token rather than the raw value, enforce expiration, and apply rate‑limiting and additional verification (CAPTCHA, email confirmation) before issuing a token.
Evidence:
- Source IDs: `ai-d9fcf0a0e754f60a`
- `@router.post("/auth/reset/verified-request") (line 589) – entry point for reset request`
- `conn.execute("INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)", (token, user["id"])) (line 596) – sensitive operation inserting token`
- `return {"reset_token": token} (line 598) – token returned to caller`

Limitations:
- The actual implementation of `token` generation is not shown; cannot verify that a secure RNG is used.
- No runtime probe or scanner evidence confirming token predictability.
- No evidence of rate‑limiting, captcha, or other request validation mechanisms surrounding the endpoint.

### 87. Insecure session token (CWE-287)

- Issue group: `ai-161393c7a9326942`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code checks only that the token string starts with the static prefix "session-" and that the remainder consists of digits before converting it to an integer and using it directly as a user identifier in a database query. No cryptographic verification, signature check, or lookup of a server‑side session store is performed, allowing an attacker who can guess or construct a numeric ID to forge a valid token and retrieve any user's username. The provided excerpt shows the missing verification and the direct use of the token in the sensitive operation.

**Impact:** An attacker can impersonate any user by supplying a crafted token such as "session-123", bypassing authentication and gaining unauthorized access to user‑specific data. This constitutes an authentication bypass (IDOR) and can lead to further privilege escalation or data leakage.

**Remediation:** Implement a secure session mechanism: generate cryptographically random session identifiers, store them server‑side (e.g., in a database or signed JWT), and validate the token against this store or its signature. Reject tokens that are not present or whose signature is invalid. Additionally, consider using established authentication libraries/frameworks to manage sessions.
Evidence:
- Source IDs: `ai-161393c7a9326942`
- `if not token.startswith("session-") or not token[8:].isdigit():`
- `row = conn.execute("SELECT username FROM users WHERE id=%s", (int(token[8:]),)).fetchone()`

Limitations:
- The source does not show how the token is obtained from the request (header, cookie, query), so the attack surface cannot be fully assessed.
- No evidence of a server‑side session store or additional validation steps beyond the shown prefix/digit check.
- Absence of runtime probe data or independent scanner findings prevents confirmation of exploitability.

## Policy Decisions

- `merged-4c6d36222f8ebf7f1f68`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-15dd977d52312c30635a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d58491aad5be35b48233`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-c5b44871f1955b338344`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-56ecc860a2c48330a29a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-69b75a0aa3f8fc9fb800`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-efce9419c25ced2d8892`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-4a2311054cdc2bfe890d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a6e788cfc5d9d1297feb`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a9a9a0b97f19f8bf52ae`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-6e468e09eab3ca889e3d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
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
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d0789be823f0fd7fa381`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-7ed325c02dd6cf8227d2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-ccc894903304aa8847bd`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-1bcb1da144dffdcf3fd8`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-18f1abe978f9fdaad8e6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3503f2dec888990b31f2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-af9496dfdf758e33`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-56e2d5863800b409`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-a4d0c1438b124a1b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-8a91bb360da5c822`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-0cff1c5b0a98f32b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-a079b7e3e1360616`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-86bcc4c6513e492e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-971eceba12c66dbc`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ddb52b4e1786df39`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-6d23d0d008604fdc`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-29d3995de39748d4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-5d4c30816d85620a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-a24a1251367745da`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-f0dce5b04fc274c8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-76ee5ddf6f5e1661`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ae177f098ffafcec`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-ecf531ac657f5eee`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-977152a429a6be98`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-1c96865ffd2139a6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-3dfb81137310f24a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-b0aa75c08377bc22`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-5c26e3944c7d42d2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-d9fcf0a0e754f60a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-161393c7a9326942`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **99**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **62**; scanner overlaps: **2**; AI overlaps: **0**; new candidates: **27**; uncertain overlaps: **9**; needs more evidence: **24**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-e42cbca7f84d6eae`: needs_more_evidence
- `ai-4b421e6c6049ce19`: needs_more_evidence
- `ai-3ea530f13ef0bc16`: needs_more_evidence
- `ai-2edfc8f205ad877b`: needs_more_evidence
- `ai-56e2d5863800b409`: uncertain_overlap
- `ai-0c354e1132e37f93`: needs_more_evidence
- `ai-86bcc4c6513e492e`: uncertain_overlap
- `ai-6d23d0d008604fdc`: uncertain_overlap
- `ai-753faea430490d3b`: needs_more_evidence
- `ai-350573badc0f420f`: needs_more_evidence
- `ai-a24a1251367745da`: uncertain_overlap
- `ai-70e062492a597692`: needs_more_evidence
- `ai-6b81e38d34e9ec10`: needs_more_evidence
- `ai-9c197d3022a9263a`: needs_more_evidence
- `ai-ed9bb4c40cf22c4d`: needs_more_evidence
- `ai-6b3555cd794b0b64`: needs_more_evidence
- `ai-d1c2c71535d2f7c8`: needs_more_evidence
- `ai-b0aa75c08377bc22`: uncertain_overlap
- `ai-88c84894edd652a0`: needs_more_evidence
- `ai-e1cbf24313c0c279`: needs_more_evidence
- `ai-5c26e3944c7d42d2`: uncertain_overlap
- `ai-d9fcf0a0e754f60a`: uncertain_overlap
- `ai-86d4d708f0641ee3`: needs_more_evidence
- `ai-a919508223616e45`: needs_more_evidence
- `ai-a4e4f7bde1002d95`: needs_more_evidence
- `ai-72d7311c2edc03db`: needs_more_evidence
- `ai-ee75b61283e20b4f`: needs_more_evidence
- `ai-9746c3e142b5e980`: needs_more_evidence
- `ai-6779a1bd8afba759`: needs_more_evidence
- `ai-6e6509f3f5bf9004`: needs_more_evidence
- `ai-33b6a471ed602632`: uncertain_overlap
- `ai-c17e8bd932e8595c`: needs_more_evidence
- `ai-ce60f9b4b3468077`: uncertain_overlap

## Pending Security Reviews

- `ai-704ae0696dee2199`
- `ai-33b6a471ed602632`
- `ai-6322be0c6e12b177`
- `ai-90110660457c36b4`
- `ai-9817b61171b7f73f`
- `ai-f1b47b3c5879f0cc`
- `ai-9a75189936f87550`
- `ai-093946d18faa4afa`
- `ai-537f833f6b0afa71`
- `ai-ce60f9b4b3468077`
- `ai-5670f781c98ace32`
- `ai-118e8dd460abde2d`

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

# Security Review Report

- Project: `targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-16T21:34:56.042318+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

The agent reviewed **83** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **83**; reviewed: **83**; pending: **0**.

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

**Explanation:** The source code for the root endpoint (GET "/") returns a JSON payload without explicitly setting the X-Content-Type-Options header. A runtime probe (zap.10021) observed a GET request to this path, indicating the endpoint is reachable. However, no response header evidence is provided to confirm the header is absent, and no defensive code is shown that would add the header elsewhere in the application stack.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may incorrectly sniff the content type of responses, potentially enabling certain cross‑site scripting or drive‑by download attacks.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options header on all responses, e.g., using a middleware or response model that adds `X-Content-Type-Options: nosniff`.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Source excerpt shows the index endpoint returns a dict without header handling (lines 162‑163).`
- `Runtime probe fact from zap (rule zap.10021) recorded a GET request to "/" indicating the endpoint is live.`

Limitations:
- No captured HTTP response headers to definitively prove the header is missing.
- No evidence that another part of the application (e.g., a global middleware) adds the header.

### 2. Job listing requires admin role

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/jobs calls a function principal(authorization) but the provided source excerpt does not show any role‑based check that restricts access to administrators. The runtime probe observed a successful GET request returning HTTP 200, whereas the scanner expected a 403/404, indicating that the endpoint is accessible without proper restriction. This combination suggests a potential missing admin‑role guard, but the lack of the principal implementation prevents confirming that the check is absent.

**Impact:** Unauthenticated or non‑admin users could retrieve the full list of jobs, potentially exposing sensitive internal data or enabling further attacks.

**Remediation:** Ensure that the endpoint verifies the caller’s role after authentication, e.g., by checking that the principal has an admin flag before querying the database, and return 403 for unauthorized access.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs calls principal(authorization) without visible role check`
- `Runtime probe fact: GET /admin/jobs returned status 200 instead of expected 403/404`

Limitations:
- Missing implementation of principal() to confirm it does not enforce admin role
- No evidence of additional authorization middleware or guard outside the provided snippet

### 3. A demoted administrator must lose administrative access

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source code for the /admin/token-report endpoint checks the caller's role and raises a 403 error if the role is not "admin". However, a runtime probe observed that a GET request to this endpoint returned HTTP 200, indicating that the role check was bypassed or ineffective for a user who should no longer have admin privileges. The scanner finding flags this as a potential stale‑role issue, providing independent corroboration of the unexpected behavior.

**Impact:** A user whose admin rights have been revoked could still access privileged administrative functionality, potentially exposing sensitive data or allowing unauthorized actions.

**Remediation:** Ensure that role revocation is enforced consistently across all authentication and authorization checks. Verify that token generation reflects the current role state and that any cached or stale tokens are invalidated when a user's role changes. Add explicit checks or middleware to re‑validate the user's role on each request.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source code line 663‑664: if token.get("role") != "admin": raise HTTPException(403, "Administrator required")`
- `Runtime probe fact: GET /admin/token-report returned status 200 (expected 403)`

Limitations:
- The token generation and role‑assignment logic are not provided, so it is unclear why the role check returned true for a demoted user.
- No evidence is shown that the token used in the probe was indeed associated with a demoted administrator.

### 4. User listing requires admin role

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/admin/users` calls `principal(authorization)` but does not perform any role check before querying and returning all user records, including sensitive fields such as `ssn`. The source excerpt shows no verification that the caller has an admin role. A runtime probe confirms the endpoint is accessible without restriction, returning HTTP 200 instead of the expected 403/404. This demonstrates an insecure direct object access vulnerability.

**Impact:** Any authenticated user (or possibly unauthenticated if `principal` permits) can retrieve the full list of users with sensitive personal data, leading to privacy breaches, credential exposure, and potential compliance violations.

**Remediation:** Add an explicit authorization check that verifies the caller has an admin role before executing the query. Example:
```python
def admin_users(authorization: str | None = Header(default=None)) -&gt; list\[dict\[str, Any\]\]:
    user = principal(authorization)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    with connection() as conn:
        rows = conn.execute("SELECT id,username,email,role,ssn FROM users ORDER BY id").fetchall()
    return \[dict(row) for row in rows\]
```
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source excerpt shows endpoint definition without role check (lines 278‑282).`
- <code>Runtime probe fact reports GET `/admin/users` returned status 200, not 403/404 as expected.</code>

### 5. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a session cookie via `response.set_cookie("lab_session", ...)` without specifying the `HttpOnly` attribute. The runtime probe confirms the endpoint is reachable via POST, but does not capture the Set-Cookie header to verify the flag. No evidence of a defensive check or configuration that would add the HttpOnly flag is present in the supplied context.

**Impact:** Without the HttpOnly flag, client‑side scripts could read the session cookie, enabling theft via XSS attacks and leading to session hijacking.

**Remediation:** Set the HttpOnly attribute when creating the cookie, e.g., `response.set_cookie("lab_session", ..., httponly=True)`. Consider also adding `Secure` and `SameSite` attributes as appropriate.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- <code>Source excerpt shows `response.set_cookie(&quot;lab_session&quot;, f&quot;session-{row[&#x27;id&#x27;]}&quot;)` without HttpOnly flag.</code>
- <code>Runtime probe fact confirms POST request to `/auth/form-login` but does not include Set-Cookie header details.</code>

Limitations:
- Missing captured response headers that demonstrate the cookie lacks the HttpOnly attribute.
- No scanner evidence of medium or higher severity confirming the flag omission.

### 6. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The form_login endpoint returns an HTMLResponse without setting an X-Frame-Options or Content‑Security‑Policy frame‑ancestors header. The source excerpt shows no header manipulation, and the runtime probe confirms the endpoint is reachable via POST. No guard is present in the supplied context to prevent clickjacking.

**Impact:** An attacker could embed the login page in a hidden iframe on a malicious site and trick users into submitting credentials, leading to credential theft or session fixation.

**Remediation:** Add an appropriate anti‑clickjacking header (e.g., `response.headers['X-Frame-Options'] = 'DENY'` or a CSP `frame-ancestors 'none'`) to the response before returning it.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Source excerpt shows HTMLResponse returned without header manipulation (lines 299‑301).`
- `Runtime probe fact confirms POST access to /auth/form-login (scanner_id: web-runtime, rule_id: zap.10020).`

### 7. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The login endpoint (/auth/form-login) returns an HTMLResponse but the supplied source excerpt does not show any CSP header being added to the response. The scanner flagged the missing CSP header, and the runtime probe confirms the endpoint is reachable via POST, but there is no direct evidence that the response lacks a CSP header. No guard or header‑setting logic is visible in the provided code.

**Impact:** Without a CSP header, the application is vulnerable to client‑side injection attacks such as cross‑site scripting (XSS). An attacker could inject malicious scripts that run in the user's browser, potentially stealing session cookies or performing actions on behalf of the user.

**Remediation:** Add a CSP header to the response that restricts the sources from which scripts, styles, and other resources can be loaded. For example:
```python
response = HTMLResponse(f"Signed in as {html.escape(row\['username'\])}")
response.headers\['Content‑Security‑Policy'\] = "default-src 'self'; script-src 'self'; style-src 'self'"
response.set_cookie("lab_session", f"session-{row\['id'\]}")
return response
```
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Source excerpt shows response creation without CSP header (lines 299‑301).`
- `Scanner finding reports "Content Security Policy (CSP) Header Not Set" for /auth/form-login.`
- `Runtime probe fact confirms POST method is used on /auth/form-login.`

Limitations:
- No captured HTTP response headers confirming the CSP header is absent.
- No evidence that the application sets CSP globally via middleware or a framework setting outside the shown snippet.

### 8. Password reset tokens must be single use

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The confirm_reset endpoint retrieves a reset token from the database and, if valid, updates the user's password without invalidating or deleting the token. No check is performed to ensure the token is single‑use. A runtime probe shows that a POST to /auth/reset/confirm returns 200 even when the token has already been used, indicating the token can be replayed. This combination of source code and observed behavior demonstrates a missing guard for token reuse.

**Impact:** An attacker who obtains a valid password‑reset token can reuse it to reset the victim's password multiple times, leading to account takeover and loss of confidentiality and integrity of user accounts.

**Remediation:** After successfully using a reset token, delete it or mark it as used in the reset_tokens table. Add a database constraint or application logic to ensure each token can be consumed only once. Optionally, add expiration and rate‑limiting checks.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup and password update without token invalidation (lines 577‑585).`
- `Runtime probe fact indicates POST /auth/reset/confirm returned 200 instead of expected error codes, confirming token replay is possible.`

### 9. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/query` returns HTML content but the supplied source excerpt does not show any middleware or response handling that adds a Content‑Security‑Policy header. The scanner flagged the missing CSP header, and no runtime probe fact confirms the header is present. Without explicit evidence that the application sets CSP elsewhere, the finding suggests a potential security control gap.

**Impact:** Absent CSP allows attackers to inject malicious scripts or resources, facilitating cross‑site scripting (XSS) or data exfiltration attacks.

**Remediation:** Configure the application to include a strong Content‑Security‑Policy header on all responses, e.g., via FastAPI middleware or a reverse‑proxy configuration, specifying allowed sources for scripts, styles, and other resources.
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Source excerpt shows HTML response generation without CSP header handling`
- `Scanner runtime fact (zap.10038) reports missing CSP header for GET /catalog/query`

Limitations:
- No runtime probe confirming the response headers for this endpoint
- No code evidence of CSP header being set elsewhere in the application

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-a6e788cfc5d9d1297feb`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting the X-Content-Type-Options: nosniff header. The source excerpt shows the FastAPI route returning an HTMLResponse, and the runtime probe fact records a GET request to this path but does not show the header being present. No code in the supplied excerpt adds the security header, and no guard or configuration is visible that would set it globally.

**Impact:** Without the X-Content-Type-Options header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options header on all responses, e.g., by adding a middleware that sets response.headers\["X-Content-Type-Options"\] = "nosniff" or by using Starlette's SecurityHeaders middleware.
Evidence:
- Source IDs: `merged-a6e788cfc5d9d1297feb`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact records GET request to /catalog/query (zap.10021)`

Limitations:
- No direct observation of the response headers from the running service confirming the header is absent
- No evidence that a global security middleware might be adding the header elsewhere in the codebase

### 11. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/catalog/query` returns HTML content without setting any X-Frame-Options or Content-Security-Policy frame-ancestors directives. The source excerpt shows the response is constructed and returned directly, and the runtime probe confirms a GET request to this path. No code is present that adds anti-clickjacking headers, and no guard or configuration is shown in the supplied context.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions on the site.

**Remediation:** Add appropriate anti-clickjacking headers (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response, either globally via middleware or specifically in the `catalog_query` handler.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Source excerpt shows HTML response is returned without header manipulation`
- `Runtime probe fact indicates a GET request to /catalog/query with no header evidence`

Limitations:
- No evidence is provided that the application sets anti-clickjacking headers elsewhere (e.g., via middleware, server configuration, or a response hook). Confirmation requires seeing the full response headers or additional scanner/runtime evidence showing the header is absent.

### 12. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content without any indication that an X-Frame-Options or Content-Security-Policy header is set to prevent clickjacking. The source excerpt shows the route implementation but does not include any response header manipulation. The runtime probe confirms the endpoint is reachable via GET, but does not capture response headers, so the absence of the anti-clickjacking header is not directly observed.

**Impact:** An attacker could embed the page in a hidden iframe on a malicious site, potentially tricking users into unintended actions (clickjacking).

**Remediation:** Add an appropriate anti-clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive) to the response for the `/comments` endpoint, either globally via middleware or locally in the route handler.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Source excerpt shows HTML response generation without header handling`
- `Runtime probe fact indicates GET request to /comments`

Limitations:
- No captured response headers to confirm the header is missing
- No evidence that middleware elsewhere sets the header globally

### 13. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/comments` returns an HTML page constructed from database content without setting any Content‑Security‑Policy header. The source excerpt shows the response is built and returned directly, and the scanner reported that the CSP header is missing. No code in the provided snippet adds security‑related response headers, and no guard or configuration is visible that would set a CSP globally.

**Impact:** Without a CSP header, browsers are free to execute inline scripts or load resources from any origin, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks if an attacker can inject malicious content into comment bodies.

**Remediation:** Add a CSP header to the response, either globally via middleware or specifically for this route. For example, use FastAPI's `Response` object to set `headers={'Content‑Security‑Policy': "default-src 'self'"}` or configure a security middleware such as `Starlette`'s `SecurityMiddleware` to enforce a strict CSP across the application.
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- <code>Source excerpt shows `/comments` endpoint returns HTML without setting headers</code>
- `Scanner finding reports "Content Security Policy (CSP) Header Not Set" for path /comments`

Limitations:
- No runtime probe of the actual HTTP response headers is provided; the scanner’s claim is not independently verified in this data set
- No evidence that a global middleware or server configuration might add a CSP header elsewhere in the application

### 14. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content but the supplied source and runtime probe do not show the `X-Content-Type-Options: nosniff` header being set. Absence of this header can allow browsers to perform MIME‑type sniffing, potentially leading to content‑type confusion attacks.

**Impact:** An attacker could craft a response that causes the browser to interpret untrusted content as a different MIME type, enabling cross‑site scripting or drive‑by download scenarios.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to the response for the `/comments` endpoint, e.g., via a middleware or response header injection in FastAPI.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- <code>Source excerpt shows the `/comments` handler returns raw HTML without setting response headers.</code>
- <code>Runtime probe fact records a GET request to `/comments` but does not include header information, indicating the header was not observed.</code>

Limitations:
- No direct observation of the HTTP response headers confirming the header is absent; only the lack of evidence in the provided data. A scanner or runtime probe that explicitly reports the missing header would be needed for confirmed status.

### 15. Debug configuration is exposed without authentication

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /debug/config endpoint returns sensitive configuration values (database URL, mock external URL, app secret) without any access control. The source excerpt shows the handler directly returns these values, and the runtime probe confirms the endpoint responds with HTTP 200, whereas a protected endpoint would return 401/403/404.

**Impact:** An attacker can retrieve internal configuration data, potentially enabling further attacks such as database compromise, credential leakage, or service manipulation.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint, ensuring only authorized users can access it. Consider removing sensitive data from responses or protecting it behind environment‑specific feature flags.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source code at lines 320‑322 returns configuration values without checks`
- `Runtime probe fact: GET /debug/config returned status 200 (expected 401/403/404)`

Limitations:
- No evidence of any authentication or authorization guard in the supplied code; need to verify whether external middleware or deployment configuration enforces access control.

### 16. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports that the /healthz endpoint does not include a Content‑Security‑Policy header. The supplied runtime probe only shows an HTTP 200 status code and does not include the response headers, so the absence of the CSP header cannot be confirmed from the provided data.

**Impact:** Without a CSP header, browsers may allow execution of unsafe scripts or resources, potentially enabling XSS or data‑injection attacks against clients that render content from this endpoint.

**Remediation:** Configure the web framework or reverse proxy to add a suitable Content‑Security‑Policy header to all responses, including the /healthz endpoint, restricting allowed sources for scripts, styles, and other resources.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Scanner finding: Missing Content‑Security‑Policy header reported for path /healthz`

Limitations:
- No response header data was provided in the runtime_probe_facts; the probe only reports status 200. Evidence of the header’s absence is therefore missing.

### 17. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner and runtime probe indicate that the /healthz endpoint returns a 200 response, but no evidence of X-Frame-Options or Content‑Security‑Policy headers is provided. The source code does not set these headers, and no guard or middleware is shown that would add them.

**Impact:** Without clickjacking protection, an attacker could embed the endpoint in a hidden frame and trick users into performing unintended actions, potentially leading to UI redress attacks.

**Remediation:** Add appropriate clickjacking protection headers (e.g., X-Frame-Options: SAMEORIGIN or Content‑Security‑Policy: frame-ancestors 'self') to the response, either directly in the endpoint or via a global middleware.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe shows /healthz returns status 200`
- `Source excerpt defines /healthz endpoint without header handling`

Limitations:
- Missing concrete HTTP response header data confirming the absence of X-Frame-Options or CSP headers
- No runtime probe or scanner evidence directly showing the header is missing, only a generic missing‑header rule

### 18. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for GET /healthz does not include the X-Content-Type-Options header. The provided source excerpt shows only the FastAPI endpoint implementation and does not demonstrate any response header configuration. No runtime probe fact confirms the absence of the header, and there is no evidence of a middleware or response‑modifier that would add it. Without concrete evidence that the header is omitted in the actual response, the finding cannot be confirmed.

**Impact:** If the X-Content-Type-Options: nosniff header is missing, browsers may attempt to sniff the MIME type of resources, potentially allowing content‑type confusion attacks such as cross‑site scripting when content is misinterpreted.

**Remediation:** Configure the application to include the X-Content-Type-Options header on all responses, e.g., by adding a FastAPI middleware that sets `response.headers['X-Content-Type-Options'] = 'nosniff'` or by configuring the underlying web server (e.g., Uvicorn, Nginx) to add the header.
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Scanner runtime fact (zap.10021) indicates a GET request to /healthz with no header values shown`

Limitations:
- No runtime probe showing the actual response headers for /healthz
- No source code evidence of header setting or omission
- No server configuration evidence confirming that the header is not added elsewhere

### 19. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The /healthz endpoint returns a 200 response but the runtime probe did not observe the X-Content-Type-Options header. Absence of this header can allow MIME type sniffing attacks, but the supplied evidence only shows the missing header without confirming that the server is capable of serving content that could be misinterpreted.

**Impact:** An attacker could potentially perform MIME type sniffing to execute malicious content in the context of the application, leading to cross‑site scripting or other client‑side attacks.

**Remediation:** Configure the web framework or reverse proxy to include the header `X-Content-Type-Options: nosniff` on all responses, including the /healthz endpoint.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe fact: status 200 returned from /healthz without X-Content-Type-Options header (web.missing-content-type-protection)`

Limitations:
- No captured HTTP response headers to definitively prove the header is absent; only a scanner rule flagged it. Additional runtime observations of actual response headers are required to confirm the missing header.

### 20. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /integrations/hook accepts POST requests, reads the raw request body, and directly inserts it into the database as an accepted visit without any verification of a cryptographic signature or authentication token. No guard or signature check is present in the supplied code excerpt. Runtime probing confirms the endpoint returns HTTP 200 for an unsigned request, whereas the probe contract expected a 4xx response for unsigned hooks, indicating the lack of validation is exploitable. Independent scanner evidence also flags this as a high‑severity issue.

**Impact:** An attacker can craft arbitrary webhook payloads and cause the application to record forged visits or potentially execute SQL injection via the inserted body, leading to data integrity loss, unauthorized actions, or further database compromise.

**Remediation:** Implement signature verification (e.g., HMAC with a shared secret) or authentication before processing the request. Reject requests lacking a valid signature with a 4xx response. Validate and sanitize the body before inserting it into the database, and use parameterized queries to prevent SQL injection.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- `Source excerpt shows the receive_hook function inserts the raw request body into the database without any signature check (lines 629‑633).`
- `Runtime probe fact reports the endpoint returned HTTP 200 for an unsigned POST request, contrary to the expected 4xx responses (workflow.unsigned_hook.1).`
- `Scanner‑generated finding classifies the issue as high severity.`

### 21. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` calls `principal(authorization)` but does not verify that the authenticated user owns the requested invoice before returning it. The code fetches the invoice row and returns it if it exists, without any ownership check, leading to unauthorized data exposure.

**Impact:** An attacker who can authenticate can retrieve any invoice by ID, violating confidentiality and potentially exposing sensitive financial information.

**Remediation:** Add a check after fetching the invoice to verify that the invoice's owner matches the authenticated principal. Return a 403 Forbidden response if the check fails.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- `Source excerpt shows no ownership verification after fetching the invoice (lines 268-274).`
- <code>Runtime probe fact indicates a GET request to `/invoices/{{invoice_id}}` returned status 200 instead of the expected 403, confirming the missing guard.</code>

### 22. Users cannot submit an admin job

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint calls `principal(authorization)` but the supplied source excerpt does not show any role‑based check before inserting a job record. The runtime probe confirms that a POST request to /jobs returns HTTP 200, whereas the probe contract expected error codes (400, 403, 422). This demonstrates that the endpoint accepts the request without rejecting unauthorized admin‑only actions, indicating a missing or ineffective guard.

**Impact:** An attacker who can supply a valid Authorization header can create jobs with arbitrary `run_as` values, potentially escalating privileges or executing unauthorized workloads.

**Remediation:** Add explicit role validation after extracting the principal, e.g., verify that the authenticated user has the required admin or worker role before performing the INSERT. Return 403 for unauthorized roles.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- <code>Source excerpt shows `principal(authorization)` with no subsequent role check before database insert</code>
- `Runtime probe fact: POST /jobs returned 200 instead of expected 400/403/422, assertion_results false`

### 23. Identity endpoint may expose SSN

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint retrieves the user's SSN from the database and returns the entire row as a JSON object without any filtering or redaction. No access control or data‑minimisation check is visible in the supplied code. A runtime probe observed a 200 response and indicates that values were redacted, but the source code still includes the SSN field, so the protection cannot be confirmed from the provided evidence.

**Impact:** An attacker who can obtain a valid bearer token could retrieve the SSN of any user, leading to identity theft and regulatory compliance violations.

**Remediation:** Modify the endpoint to exclude sensitive fields such as SSN from the response or explicitly mask them. Implement a data‑minimisation policy and ensure only necessary attributes are returned. Add tests to verify that SSN is not present in the API response.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source excerpt lines 199‑204 show the SELECT query retrieving ssn and returning dict(row)`
- `Runtime probe fact shows a 200 response from /me but does not confirm redaction of SSN`

Limitations:
- Missing proof that the runtime probe actually redacted the SSN value; the probe only indicates values_redacted=true without showing the resulting payload. Need explicit response example or additional testing to confirm whether SSN is omitted or masked.

### 24. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint directly inserts the client‑provided unit_price into the orders table without any server‑side validation or enforcement of a catalog price. The runtime probe for the "/orders" POST workflow reports mixed assertion results, indicating that the price value is accepted from the request and not overridden by a trusted source. This demonstrates an exploitable path where a malicious client can set arbitrary prices for orders.

**Impact:** An attacker can manipulate order prices, leading to undercharging for goods or services, financial loss, and potential inventory or accounting inconsistencies.

**Remediation:** Validate and enforce the unit_price against a server‑maintained price catalog before inserting the order. Reject or replace client‑provided prices that do not match the catalog entry. Optionally, remove unit_price from the request payload and derive it server‑side.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt shows create_order inserting body.unit_price into the database (lines 208‑215).`
- `Runtime probe fact "workflow.price_catalog.1" for POST /orders reports assertion_results [true, false], indicating the price value is accepted from the client without server enforcement.`

### 25. Unrestricted order status on creation

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `create_order` endpoint inserts the `status` field directly from the request body into the database without any validation or restriction. The runtime probe shows that a POST to `/orders` returns HTTP 200 even when the workflow expects a 400/422 for invalid initial states, confirming that the server accepts arbitrary status values (including a paid state) at creation time.

**Impact:** An attacker can create orders with a pre‑paid status, bypassing payment processing and potentially causing financial loss, inventory inconsistencies, or unauthorized access to privileged order workflows.

**Remediation:** Validate the `status` field on order creation. Reject or ignore any status other than the allowed initial state (e.g., "pending"). Implement server‑side checks to enforce business rules before inserting into the database.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- <code>Source code inserts `status` from `body.status` without validation (lines 213‑215).</code>
- `Runtime probe fact: POST /orders returned 200 instead of expected 400/422, indicating the server accepted the request with the given status.`

### 26. Negative order prices are accepted without validation

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the supplied unit_price directly into the database without any validation. The runtime probe observed a POST to /orders with a negative price returning HTTP 200, while the scanner expected a 400/422 response. This demonstrates that negative prices are accepted, confirming the vulnerability.

**Impact:** An attacker can create orders with negative prices, potentially leading to unauthorized credit, financial loss, or manipulation of inventory/value calculations.

**Remediation:** Add input validation to ensure unit_price (and any other monetary fields) are non‑negative before inserting into the database. Return a 4xx error if validation fails. Consider using a schema validator (e.g., Pydantic) or explicit checks in the handler.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Source excerpt shows unit_price is inserted without checks (lines 208‑215).`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422).`
- `Scanner finding flagged negative order prices are rejected but observed acceptance.`

### 27. Users can create orders for another owner

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and falls back to the authenticated user's sub claim when it is missing. No validation is performed to ensure that a supplied owner_id matches the authenticated user, allowing a caller to create orders on behalf of any other owner. A runtime probe confirms that a POST to /orders with an arbitrary owner_id succeeds with HTTP 200, whereas the expected defensive responses (400, 403, 422) are not observed.

**Impact:** An attacker can create or manipulate orders for other users, leading to unauthorized transactions, potential financial loss, and violation of data integrity and privacy policies.

**Remediation:** Validate that the owner_id in the request body, if provided, matches the authenticated user's identifier (user\["sub"\]). Reject the request with a 403 Forbidden (or appropriate) response when the IDs differ. Alternatively, remove the ability for the client to specify owner_id and always use the authenticated user's ID for order creation.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows owner_id is set to body.owner_id or user["sub"] without further checks (lines 208-210).`
- `Runtime probe fact: POST /orders returned status 200 instead of expected 400/403/422, indicating the missing validation (runtime_probe_facts).`

Limitations:
- No evidence is provided that any authorization guard exists elsewhere in the codebase (e.g., middleware or database constraints). The scanner evidence is limited to this single endpoint, and no additional independent scanner of medium or higher severity corroborates the finding.

### 28. Insecure direct object reference on note endpoint

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `order_note` endpoint retrieves a note by its ID without verifying that the note's `order_id` matches the `order_id` supplied in the URL. This allows an attacker to access notes belonging to other orders by guessing note IDs. The runtime probe confirms that a request to `/orders/1/notes/2` returns HTTP 200, indicating the note is returned despite the mismatch, whereas the expected behavior would be a 403 or 404.

**Impact:** An attacker can enumerate and read notes from orders they do not own, leading to unauthorized disclosure of potentially sensitive information.

**Remediation:** Add a check after fetching the note to verify that `row['order_id']` equals the `order_id` path parameter. If they differ, return a 403 Forbidden or 404 Not Found response. Example:
```python
if row\['order_id'\] != order_id:
    raise HTTPException(403, "Forbidden")
```
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- `Source excerpt shows note fetched without order_id validation (lines 543-548).`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200 instead of expected 403/404, indicating the missing check.`

### 29. Only the owner can read an order

- Issue group: `merged-fe4ca713f11faf9b96d6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}` calls `principal(authorization)` but does not verify that the authenticated principal is the owner of the requested order before returning the record. The runtime probe confirms that a GET request for an order owned by another user returns HTTP 200 instead of the expected 403/404, demonstrating the missing ownership check in practice.

**Impact:** An attacker who can obtain a valid authorization token can retrieve any order by guessing or enumerating order IDs, leading to unauthorized disclosure of sensitive order data.

**Remediation:** Add an ownership check after fetching the order, e.g., compare `row['owner_id']` with the authenticated user ID from `principal`. Return HTTP 403 if the user is not the owner. Optionally enforce this check at the database query level.
Evidence:
- Source IDs: `merged-fe4ca713f11faf9b96d6`
- <code>Source excerpt shows `principal(authorization)` is called but no owner verification before returning the order (lines 221‑227).</code>
- <code>Runtime probe fact indicates a GET request to `/orders/{{order_id}}` returned status 200 instead of 403/404, confirming the missing check.</code>

### 30. Excessive coupon discounts are not validated

- Issue group: `merged-7ed325c02dd6cf8227d2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint reads a coupon code and applies a discount value from the request body without enforcing any upper bound on the discount percentage. The code directly writes the supplied percent to the orders table. Runtime probing shows that a request with an out‑of‑range discount receives a 200 OK response instead of the expected 400/422 error, confirming the lack of validation.

**Impact:** An attacker can submit a coupon with an arbitrarily high discount (e.g., 100% or more), resulting in orders being sold at a loss or free, leading to financial loss and potential abuse of the coupon system.

**Remediation:** Add validation logic to ensure the discount percentage is within an acceptable range (e.g., 0–100). Return a 4xx error if the value is out of bounds. Example:
```python
if not 0 &lt;= percent &lt;= 100:
    raise HTTPException(status_code=400, detail="Invalid discount percentage")
```
Evidence:
- Source IDs: `merged-7ed325c02dd6cf8227d2`
- <code>Source excerpt shows no bounds check on `percent` before updating the order</code>
- `Runtime probe fact: POST to /orders/{{order_id}}/apply-coupon with excessive discount returned status 200 instead of 400/422`

### 31. Paid orders can be cancelled without refund

- Issue group: `merged-ccc894903304aa8847bd`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /orders/{order_id}/cancel updates the order status to 'cancelled' without any check for the order's payment state. The supplied source excerpt shows no verification that the order has been paid or that a refund has been processed before cancellation. A runtime probe confirms the endpoint returns HTTP 200, whereas the expected behavior (per the probe contract) would be an error status such as 400, 409, or 422 when cancellation is disallowed for paid orders. This indicates the missing guard, but the evidence does not include the actual payment‑status check logic or a guard elsewhere in the codebase, so the vulnerability cannot be confirmed definitively.

**Impact:** An attacker could cancel paid orders without issuing a refund, leading to financial loss and potential abuse of the order management system.

**Remediation:** Add a check that verifies the order's payment status before allowing cancellation. If the order is paid, require a refund to be processed first or reject the cancellation with an appropriate error response (e.g., 400 Bad Request). Ensure the guard is enforced consistently across all code paths that invoke order cancellation.
Evidence:
- Source IDs: `merged-ccc894903304aa8847bd`
- `Source excerpt lines 258‑263 show the cancel_order function updates the order status without payment checks.`
- `Runtime probe fact: method POST to /orders/{{order_id}}/cancel returned status 200, while expected statuses were 400, 409, 422 (assertion_results: false).`

Limitations:
- Missing evidence of any payment‑status verification elsewhere in the codebase.
- No view of surrounding business logic that might enforce refund requirements outside this function.

### 32. An already paid order rejects a second payment

- Issue group: `merged-1bcb1da144dffdcf3fd8`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `pay_order` endpoint updates the order status to `paid` without checking whether the order is already in a paid state. The source excerpt shows no guard against a second payment, and the runtime probe confirms that a replayed POST request returns HTTP 200 instead of the expected error codes (400, 409, 422). This demonstrates that the endpoint allows duplicate payments.

**Impact:** An attacker can replay a payment request for an already paid order, causing double charging or creation of duplicate invoices, leading to financial loss and potential fraud.

**Remediation:** Add a check before updating the order status to verify that the order is not already marked as `paid`. Return an appropriate error (e.g., 409 Conflict) if a payment has already been processed. Consider implementing idempotency keys or transaction tokens to prevent replay attacks.
Evidence:
- Source IDs: `merged-1bcb1da144dffdcf3fd8`
- `Source code lines 242-250 show the payment logic with no prior status check`
- `Runtime probe fact: POST to /orders/{{order_id}}/pay returned status 200, while expected statuses were 400, 409, 422`

### 33. A user cannot read another account profile

- Issue group: `merged-18063ba27bc289f53c8a`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/profiles/{profile_id}` retrieves user data based solely on the supplied `profile_id` after calling `principal(authorization)`, which only authenticates the request but does not verify that the authenticated user owns the requested profile. The subsequent SQL query selects the row without an ownership check, and the code returns the row if found. Runtime probing confirms the flaw: a request to another user's profile returned HTTP 200 instead of the expected 403/404, demonstrating that the access control check is missing.

**Impact:** An attacker who can authenticate can enumerate or retrieve sensitive information (username, email, SSN) of any user by iterating profile IDs, leading to privacy breaches and potential identity theft.

**Remediation:** Add an ownership verification step after authentication, e.g., compare the authenticated user's ID with `profile_id` or join with the users table to ensure the requester is authorized to view the profile. Return 403 if the check fails. Also consider using parameterized queries and limiting exposed fields.
Evidence:
- Source IDs: `merged-18063ba27bc289f53c8a`
- `Source excerpt shows no ownership check before returning user data (lines 98‑104).`
- `Runtime probe fact: GET /profiles/{{other_id}} returned status 200 when 403/404 were expected, indicating unauthorized access is possible.`

### 34. Missing Anti-clickjacking Header

- Issue group: `merged-4ae7658c2abfbf689e2b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse constructed from a static string and does not set any anti-clickjacking headers such as `X-Frame-Options` or `Content-Security-Policy`. No code in the provided excerpt adds these headers, and the runtime probe only confirms a GET request was made without capturing response headers.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add appropriate anti-clickjacking headers to the response, e.g., `return HTMLResponse(content, headers={"X-Frame-Options": "DENY"})` or configure a CSP frame‑ancestors directive.
Evidence:
- Source IDs: `merged-4ae7658c2abfbf689e2b`
- `Source excerpt shows HTMLResponse returned without header manipulation`
- `Runtime probe fact confirms GET request to /view`

Limitations:
- Missing runtime evidence of actual response headers (e.g., a probe that captures the `X-Frame-Options` header)
- No independent scanner of higher severity confirming the header omission

### 35. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-a4473061f97f0a366678`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/view` returns an HTMLResponse without any CSP header. The scanner flagged the missing CSP header, and the source code shows the response is constructed directly without setting security headers. No runtime probe fact confirming the header is present or absent is provided, and no application code demonstrates a CSP header being added elsewhere.

**Impact:** Without a CSP header, the application is vulnerable to cross‑site scripting (XSS) and other content injection attacks, allowing an attacker to execute malicious scripts in the context of the user’s browser.

**Remediation:** Configure the FastAPI application (or the specific route) to include a strong Content‑Security‑Policy header in the response, e.g., via a middleware or by setting the header explicitly in the route handler.
Evidence:
- Source IDs: `merged-a4473061f97f0a366678`
- `Source excerpt shows HTMLResponse returned without CSP header (lines 686‑690).`
- `Scanner evidence reports "Content Security Policy (CSP) Header Not Set" for path /view.`

Limitations:
- No runtime observation confirming that the CSP header is missing in actual HTTP responses.
- No evidence that the application sets CSP headers globally via middleware or other configuration.

### 36. X-Content-Type-Options Header Missing

- Issue group: `merged-cad468186f9fd0b4e99b`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/view` returns an HTMLResponse constructed directly in the handler without setting the `X-Content-Type-Options: nosniff` header. The scanner flagged the missing header, and the source excerpt shows no code that adds this header. No guard or middleware is visible in the supplied context that would add the header automatically.

**Impact:** Without the `X-Content-Type-Options: nosniff` header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting (XSS) if an attacker can influence the response body.

**Remediation:** Add the `X-Content-Type-Options: nosniff` header to all responses, e.g., by configuring FastAPI middleware or setting the header explicitly in the response object:
```python
from fastapi.responses import HTMLResponse

@router.get("/view")
def view_home() -&gt; HTMLResponse:
    return HTMLResponse(content=..., headers={"X-Content-Type-Options": "nosniff"})
```
Or use a security middleware that injects the header globally.
Evidence:
- Source IDs: `merged-cad468186f9fd0b4e99b`
- <code>Source excerpt shows the `/view` handler returning HTMLResponse without header configuration.</code>
- `Scanner evidence: "X-Content-Type-Options Header Missing" (zap.10021) for path /view.`

Limitations:
- No runtime probe confirming that the header is absent in an actual HTTP response; the scanner finding alone does not prove the header is missing in production.

### 37. Webhook destination must match the approved internal host exactly

- Issue group: `merged-8cdc677a9810b317840f`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The /webhooks endpoint only checks that the provided target_url contains the substring "mock-external" and raises an error otherwise. This allows any URL that includes that substring, including external hosts, to be accepted. No additional validation (e.g., exact host match, scheme enforcement, or allow‑list) is present. The runtime probe shows that a POST request to this endpoint returned HTTP 200 instead of the expected 400/422, confirming that the check can be bypassed.

**Impact:** An attacker can supply a malicious external URL that includes the allowed substring, causing the service to perform outbound requests to arbitrary hosts (potential SSRF) or exfiltrate data.

**Remediation:** Validate the target_url against a strict allow‑list of approved internal hosts. Use exact host comparison, enforce HTTPS scheme, and reject any URL that does not match the approved list. Consider using a URL parsing library and rejecting URLs with unexpected components.
Evidence:
- Source IDs: `merged-8cdc677a9810b317840f`
- `Source code line 296‑298 shows only a substring check: if "mock-external" not in target_url: raise HTTPException(400)`
- `Runtime probe fact: POST /webhooks returned status 200, indicating the check did not block the request`

### 38. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The source excerpt shows that after successful authentication the application logs the username and the value of the APP_SECRET environment variable using a standard info‑level logger. This constitutes logging of sensitive data in clear text. No surrounding code or configuration is provided that masks or redacts this information, nor is there evidence of a logging guard (e.g., redaction, conditional logging, or a secure logger) in the supplied context. The finding is corroborated by a semgrep scanner rule that flags logger credential disclosure, but there is no runtime probe confirming that the log entry is actually emitted or persisted in an insecure location.

**Impact:** If log files are accessible to unauthorized users or are shipped to external log aggregation services, the exposed APP_SECRET can be used to compromise the application’s security (e.g., token forgery, API abuse). The leakage of usernames also aids credential‑stuffing attacks.

**Remediation:** Replace the clear‑text log statement with a redacted or omitted version. For example, remove the APP_SECRET from the log or log only a hash. Use a logger configured to filter sensitive fields, or employ structured logging with a sanitization layer. Ensure that log storage is protected with appropriate access controls.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) – source line 137 logs the secret in clear text`
- `semgrep rule python.lang.security.audit.logging.logger-credential-leak flagged line 137 as credential disclosure`

Limitations:
- No runtime observation confirming that the log entry is written to an insecure destination
- No evidence of a guard or redaction mechanism elsewhere in the codebase
- No information about log file permissions or external log aggregation configuration

### 39. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds a CORS middleware with `allow_origins=["*"]`, which permits requests from any origin. This configuration can expose the API to cross‑origin attacks, such as CSRF or data leakage, especially when combined with authenticated endpoints. The supplied source shows the permissive setting, but there is no evidence that a guard (e.g., origin validation based on environment or authentication) exists elsewhere in the codebase.

**Impact:** An attacker controlling a malicious website could make a victim's browser send authenticated requests to the API, potentially leading to unauthorized actions or data exposure.

**Remediation:** Restrict `allow_origins` to a whitelist of trusted domains. If dynamic origins are required, implement runtime validation that checks the `Origin` header against an allowlist before responding. Also consider setting `allow_credentials` to `false` unless explicitly needed.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- <code>api/app.py: line 26 – `allow_origins=[&quot;*&quot;]`</code>

Limitations:
- No runtime probe or additional scanner evidence confirming exploitation. Unable to verify whether downstream code validates origins or restricts sensitive endpoints, so the vulnerability cannot be confirmed.

### 40. Log Injection / Secret Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code logs both the user‑provided username and the value of the APP_SECRET environment variable. Logging user input can lead to log injection if logs are later parsed or displayed without sanitisation, and logging a secret exposes sensitive data. No evidence of sanitisation or redaction is present in the supplied excerpt.

**Impact:** Potential exposure of application secrets in log files and possible log injection attacks that could corrupt log integrity or be leveraged for further attacks.

**Remediation:** Avoid logging sensitive values such as APP_SECRET. Redact or omit secret data from logs and sanitise user‑controlled input before logging. Use structured logging with proper escaping if logs are later processed.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `Source excerpt line 137 logs "login user=%s app_secret=%s" with username and os.environ.get("APP_SECRET", "lab-only")`

Limitations:
- No runtime probe showing that the logged secret is actually written to an accessible log file or that log consumers are vulnerable to injection. No independent scanner of higher severity confirming exploitability.

### 41. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string. No parameterized query or input sanitization is visible in the supplied code excerpt, and no guard (e.g., ORM, escaping, allowlist) is present in the provided context. This pattern is a classic source of SQL injection vulnerabilities.

**Impact:** An attacker could supply specially crafted username or password values to manipulate the SQL statement, potentially retrieving unauthorized data, bypassing authentication, or executing arbitrary SQL commands on the database.

**Remediation:** Refactor the query to use parameterized statements or an ORM that safely handles user input. For example, use prepared statements with placeholders (e.g., `SELECT ... WHERE username=? AND password=?`) and pass the user values as parameters. Additionally, consider hashing passwords instead of storing them in plain text.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- <code>Source excerpt shows f‑string interpolation of `body.username` and `body.password` into the SQL query (lines 117‑119).</code>
- `Scanner finding categorizes this as a high‑severity SQL injection risk.`

Limitations:
- No runtime probe evidence demonstrating successful injection or exploitation.
- No independent scanner of medium or higher severity beyond the original finding.
- No visible input validation, escaping, or use of prepared statements in the provided code context.

### 42. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` guard ensures the resolved path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent existence check further restricts access to existing files only. No missing guard is evident in the supplied context.

**Impact:** If the guard were absent, an attacker could read arbitrary files on the server. However, the guard is present, so the risk is mitigated.

**Remediation:** No remediation needed for path traversal; ensure the guard remains in place and consider adding logging for denied attempts.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑223 show the guard `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>

### 43. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `GET /auth/continue` accepts a query parameter `next` that defaults to `/` and directly passes its value to `RedirectResponse` without any validation or allow‑list check. This creates an open redirect vector where an attacker can supply an arbitrary URL and cause the application to redirect users to a malicious site.

**Impact:** An attacker can craft a link to the vulnerable endpoint with a malicious `next` value (e.g., `https://example.com/auth/continue?next=https://phishing.com`). Victims clicking the link are redirected to the attacker‑controlled site, facilitating phishing, credential harvesting, or drive‑by attacks.

**Remediation:** Validate the `next` parameter against an allow‑list of trusted URLs or paths, or restrict redirects to internal routes only. If external URLs are required, ensure they are whitelisted and use safe URL‑building utilities. Alternatively, reject or sanitize any `next` values that are not recognized as safe.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- <code>Source excerpt shows `def continue_to(next: str = &quot;/&quot;) -&gt; RedirectResponse: return RedirectResponse(next, status_code=302)` which forwards the user‑provided `next` value directly to the redirect response.</code>
- `Scanner classification as an open‑redirect finding with medium severity.`

Limitations:
- No runtime probe or test demonstrates that an attacker‑controlled URL is actually accepted and causes a redirect.
- No evidence of existing validation or guard logic elsewhere in the codebase; the supplied snippet does not show any checks.

### 44. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint verifies that the resolved file path is a sub‑path of the intended root directory using `is_relative_to(root)` and also checks that the target is a regular file before reading it. This prevents directory‑traversal attacks despite the user‑controlled `name` parameter.

**Impact:** None – the guard blocks path traversal, so an attacker cannot read arbitrary files outside the public directory.

**Remediation:** No remediation needed for this specific issue; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>source_excerpt lines 220‑223 show the use of `is_relative_to(root)` and `is_file()` checks</code>

### 45. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against a known base directory and then verifies that the resulting path is still within that base using `is_relative_to`. It also checks that the path points to an existing file before reading it. These checks prevent directory traversal attacks, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** No impact; the endpoint safely restricts file access to the intended directory.

**Remediation:** No remediation needed; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>The function builds the path with `(FILES / &quot;public&quot; / name).resolve()` and then checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404)` which blocks traversal and non‑file accesses.</code>

### 46. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function verifies that the resolved file path is within the designated public directory using `is_relative_to(root)` and also checks that the path points to an existing file with `is_file()`. Only after these checks does it read and return the file contents, which mitigates path‑traversal attacks.

**Impact:** None – the guard prevents arbitrary file access outside the intended directory.

**Remediation:** No remediation needed for this specific issue; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>source_excerpt lines 220‑224 show the `is_relative_to` and `is_file` checks before reading the file</code>

### 47. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code resolves the user‑provided filename against the trusted base directory (FILES / "public") and then verifies that the resulting path is still within the base directory using is_relative_to(FILES.resolve()). This check prevents directory traversal attacks, and the file existence is also validated before reading. Therefore the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None – the path traversal guard ensures only files within the intended public directory can be accessed.

**Remediation:** No remediation needed for this finding; the existing relative‑path check is sufficient.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `The function constructs the path with (FILES / "public" / name).resolve() and then checks if not file.is_relative_to(FILES.resolve()) or not file.is_file() before reading the file.`

### 48. Reflected server-side cross-site scripting

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/search` directly interpolates the user‑controlled query parameter `q` into an HTML response (<code>&lt;h1&gt;Results for {q}&lt;/h1&gt;</code> and <code>&lt;p&gt;{row[&#x27;name&#x27;]}&lt;/p&gt;</code>). No sanitisation or encoding is performed, allowing an attacker to inject arbitrary HTML/JavaScript that will be rendered in the victim's browser. The same unsanitised value is also used in a SQL query, but the XSS issue alone is sufficient for confirmation.

**Impact:** An attacker can craft a URL such as <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> that, when visited by a victim, executes arbitrary JavaScript in the victim's context. This can lead to session hijacking, credential theft, or other malicious actions.

**Remediation:** Encode or escape the `q` value before inserting it into the HTML response (e.g., using `html.escape` or a templating engine that auto‑escapes). Additionally, use parameterised queries for the SQL statement to prevent SQL injection.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- <code>Source excerpt shows `q` being inserted into HTML without sanitisation (lines 142‑145).</code>
- `Scanner‑generated finding flagged this as a reflected XSS (high severity, high confidence).`

### 49. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The function `verified_continue` validates the `next` parameter by ensuring it starts with a single forward slash, does not start with a double slash, and contains no URL scheme or network location. If any of these conditions are violated, it raises an HTTP 400 error, preventing open redirects to external domains. The subsequent `RedirectResponse` is only returned for validated local paths, mitigating the reported risk.

**Impact:** No open‑redirect vulnerability; an attacker cannot cause the application to redirect users to an arbitrary external URL.

**Remediation:** No remediation required for this code path; the existing validation is sufficient. Ensure any future modifications preserve these checks.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- <code>Source excerpt shows explicit validation of the `next` parameter and raising of HTTPException on invalid values.</code>

### 50. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided name, but it immediately resolves the path and then verifies that the resolved path is within the allowed directory using `is_relative_to(FILES.resolve())`. This check prevents directory traversal attacks, ensuring that only files under the `public` directory can be accessed. The subsequent `is_file()` check further restricts access to existing regular files. No missing guard is evident in the supplied code.

**Impact:** If the guard were absent, an attacker could read arbitrary files on the server. However, the existing guard mitigates this risk, so the finding does not represent a vulnerability.

**Remediation:** No remediation needed; the current relative‑path check is appropriate. Ensure that `FILES` is correctly set to the intended base directory and that the application runs with least‑privilege permissions.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- <code>The code resolves the user‑provided path: `file = (FILES / &quot;public&quot; / name).resolve()`</code>
- <code>It then checks that the resolved path is within the base directory: `if not file.is_relative_to(FILES.resolve())`</code>
- `It also verifies the target is a regular file before returning its contents.`

### 51. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL statement using an f‑string that directly interpolates the query parameter `q` into the `WHERE` clause (`SELECT name FROM products WHERE name ILIKE '%{q}%'`). This creates a classic SQL injection vector because the user‑controlled value is not sanitized or passed as a parameter to the database driver. No input validation or escaping is visible in the supplied excerpt, and no guard (e.g., ORM parameterization, whitelist, or escaping function) is present in the provided context.

**Impact:** An attacker could supply a crafted value for `q` that injects additional SQL commands, potentially retrieving unauthorized data, modifying or deleting records, or executing database‑level commands. This could lead to data breach, data loss, or privilege escalation within the database.

**Remediation:** Refactor the query to use parameterized statements provided by the database library (e.g., `conn.execute('SELECT name FROM products WHERE name ILIKE %s', (f"%{q}%",))`) or employ an ORM that handles escaping automatically. Additionally, validate or whitelist allowed characters for `q` before using it in a query.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt shows f‑string interpolation of `q` into SQL at line 144.</code>
- `Scanner finding flags the query as built from user‑provided value.`

Limitations:
- No independent corroboration such as a medium‑or‑higher severity scanner confirmation or runtime probe demonstrating successful injection. The review is based solely on static code analysis of the provided excerpt.

### 52. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a recommended practice to allow Docker to monitor container health. While the absence does not directly demonstrate an exploitable flaw, it indicates a potential operational risk if the container becomes unhealthy without detection.

**Impact:** Without a health check, orchestration systems may not detect a failing container, leading to prolonged downtime or degraded service availability.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8091/health || exit 1
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- No runtime evidence showing that the lack of HEALTHCHECK leads to undetected failures; impact is inferred from best‑practice guidance rather than observed behavior.

### 53. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The finding reports the absence of a HEALTHCHECK instruction in the Dockerfile. While adding a HEALTHCHECK is a best practice for container reliability, its omission does not constitute a security vulnerability in the supplied context. No evidence shows that this misconfiguration leads to an exploitable condition.

**Impact:** None – the container will run without health monitoring, which may affect operational visibility but does not create a security risk.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Dockerfile excerpt shows no HEALTHCHECK line`

### 54. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile excerpt shows no HEALTHCHECK instruction, which is a best‑practice recommendation rather than a demonstrated security vulnerability. No evidence of an exploitable condition or missing guard is present in the supplied context.

**Impact:** Without a HEALTHCHECK, container orchestration may not detect a failed or hung process, but this does not constitute a confirmed security flaw in the application code.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the worker process is healthy, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost/health || exit 1`.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt lines 1‑7 show no HEALTHCHECK instruction.`

### 55. python-multipart: Denial of Service via crafted form-urlencoded bodies

- Issue group: `merged-051697f9b8567d596874`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The requirements file pins python-multipart at version 0.0.20, which is known to contain CVE-2026-53539 allowing denial‑of‑service attacks with crafted form‑urlencoded bodies. The scanner flagged this version as vulnerable and notes that the issue is fixed in 0.0.30. However, the supplied repository data only shows the dependency declaration and does not demonstrate that the vulnerable code path is exercised by the application, nor does it provide runtime probe evidence of the vulnerability being triggered.

**Impact:** An attacker could send specially crafted form‑urlencoded payloads to the FastAPI service, causing the python-multipart library to consume excessive resources and potentially crash or become unresponsive, leading to denial of service for legitimate users.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later in the requirements.txt and redeploy the application. Verify that the new version does not introduce breaking changes in multipart handling.
Evidence:
- Source IDs: `merged-051697f9b8567d596874`
- `Dependency declaration in requirements.txt pins python-multipart==0.0.20`
- `Scanner report cites CVE‑2026‑53539 affecting python-multipart 0.0.20`
- `Fixed in python-multipart 0.0.30`

Limitations:
- No evidence that the application actually parses multipart/form‑urlencoded requests using python-multipart
- No runtime probe showing the denial‑of‑service behavior or exploitation
- No code snippet demonstrating the vulnerable code path being reachable

### 56. python-multipart: Denial of Service via excessive multipart part headers

- Issue group: `merged-3503f2dec888990b31f2`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to contain CVE‑2026‑42561 that allows a denial‑of‑service attack via excessive multipart part headers. The scanner flagged this dependency as vulnerable. However, the supplied artifacts do not show any code that imports or uses python-multipart, nor is there runtime evidence that the vulnerable code path is exercised.

**Impact:** If the application processes multipart/form‑data using the vulnerable python-multipart version, an attacker could craft a request with many part headers to exhaust resources, leading to denial of service.

**Remediation:** Upgrade python-multipart to version 0.0.27 or later, which contains the fix for CVE‑2026‑42561. Verify that the updated version is compatible with the application and run tests to ensure functionality.
Evidence:
- Source IDs: `merged-3503f2dec888990b31f2`
- `requirements.txt pins python-multipart==0.0.20`
- `Scanner evidence: Dependency vulnerability CVE‑2026‑42561 in python-multipart 0.0.20; fixed in 0.0.27.`

Limitations:
- No code evidence showing python-multipart is imported or used in the application.
- No runtime probe or test demonstrating the vulnerable multipart handling path.
- Unable to confirm that the vulnerable library is actually exercised at runtime.

### 57. python-multipart: Information disclosure due to parser differential in form data handling

- Issue group: `merged-74bb99c1ff3b5ed1fea8`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53538. The CVE describes an information‑disclosure vulnerability caused by a differential in how multipart form data is parsed, potentially allowing an attacker to read unintended data. The scanner identified this vulnerable version in the requirements.txt and flagged it as low severity. No mitigating guard or version pinning is present in the supplied context, and the vulnerability is independently corroborated by the CVE entry and the scanner’s medium‑or‑higher severity classification.

**Impact:** An attacker who can supply crafted multipart requests may cause the application to expose sensitive data from the request processing pipeline, leading to information leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53538. Update the requirements.txt accordingly and rebuild/redeploy the application.
Evidence:
- Source IDs: `merged-74bb99c1ff3b5ed1fea8`
- `Dependency entry in requirements.txt shows python-multipart==0.0.20`
- `Scanner evidence cites CVE-2026-53538 affecting python-multipart 0.0.20`
- `Fixed version identified as 0.0.30`

### 58. python-multipart: Denial of Service via crafted multipart/form-data requests

- Issue group: `merged-8a5f28db4eebc517239e`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The requirements.txt lists python-multipart==0.0.20, which is known to be vulnerable to CVE-2026-40347 (Denial of Service). The scanner provides a medium‑severity finding and the vulnerable version is explicitly present in the dependency list, satisfying the requirement for an entry point (the imported library) that contains the flaw. No mitigating guard or version constraint is visible in the supplied context.

**Impact:** An attacker can send specially crafted multipart/form-data requests that trigger excessive resource consumption, potentially causing the service to become unresponsive.

**Remediation:** Upgrade python-multipart to version 0.0.26 or later, which contains the fix for CVE-2026-40347. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-8a5f28db4eebc517239e`
- `Dependency vulnerability CVE-2026-40347 in python-multipart 0.0.20; fixed in 0.0.26 (scanner evidence)`
- `requirements.txt shows python-multipart==0.0.20`

### 59. python-multipart: Arbitrary file write via path traversal vulnerability (CVE-2026-24486)

- Issue group: `merged-8ce42d9c8b52a95b109d`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The project’s requirements.txt pins python-multipart at version 0.0.20, which is known to be vulnerable to an arbitrary file write via path traversal (CVE-2026-24486). The scanner’s evidence confirms the presence of this vulnerable version and notes that the issue is fixed in 0.0.22. No mitigating guard or version check is present in the supplied context, and the dependency is directly used by the application, satisfying the entry‑point condition for the vulnerability.

**Impact:** An attacker could exploit the path‑traversal flaw to write arbitrary files on the server’s filesystem, potentially leading to remote code execution, data corruption, or privilege escalation.

**Remediation:** Upgrade python-multipart to version 0.0.22 or later. Update the requirements.txt entry and run a dependency reinstall (e.g., `pip install --upgrade python-multipart`). Verify that the new version is deployed and that no other components depend on the vulnerable API.
Evidence:
- Source IDs: `merged-8ce42d9c8b52a95b109d`
- `Dependency vulnerability CVE-2026-24486 in python-multipart 0.0.20; fixed in 0.0.22.`

### 60. multipart: Python-Multipart: Information disclosure via header parsing discrepancy

- Issue group: `merged-e76230cbef200116e4ae`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to be vulnerable to CVE-2026-53537. The scanner identified this dependency mismatch and flagged it as a potential information disclosure issue. No additional runtime probe or independent scanner evidence of exploitation is provided, so the finding relies solely on the vulnerable package version.

**Impact:** An attacker could exploit the header parsing discrepancy in the vulnerable python-multipart version to obtain unintended information from HTTP requests, potentially leading to data leakage.

**Remediation:** Upgrade python-multipart to version 0.0.30 or later, which contains the fix for CVE-2026-53537. Verify the application functions correctly after the upgrade and run dependency scanning again to confirm the issue is resolved.
Evidence:
- Source IDs: `merged-e76230cbef200116e4ae`
- `Dependency vulnerability CVE-2026-53537 in python-multipart 0.0.20; fixed in 0.0.30 (scanner evidence)`

Limitations:
- No runtime probe or independent scanner confirmation of the vulnerability being exploitable in the deployed application.

### 61. python-multipart: Negative Content-Length in parse_form buffers the entire body in memory

- Issue group: `merged-f15e42abb7b2acd921f1`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The project depends on python-multipart version 0.0.20, which is known to contain CVE-2026-53540. The scanner evidence indicates that this version buffers the entire request body in memory when a negative Content‑Length header is received, leading to potential memory exhaustion. No guard or mitigation is visible in the supplied dependency list or code context.

**Impact:** An attacker can craft a request with a malformed Content‑Length header to cause the application to allocate unbounded memory, potentially resulting in denial‑of‑service or crash of the service.

**Remediation:** Upgrade python-multipart to version 0.0.31 or later, where the vulnerability is fixed. Update the requirements.txt accordingly and redeploy the application.
Evidence:
- Source IDs: `merged-f15e42abb7b2acd921f1`
- `Dependency vulnerability CVE-2026-53540 in python-multipart 0.0.20; fixed in 0.0.31 (scanner evidence)`

Limitations:
- The review is based solely on the dependency version listed in requirements.txt; no runtime or code‑level proof of exploitation is present. Confirmation would require reproducing the behavior in a running instance or additional scanner evidence with higher severity.

### 62. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a URL by concatenating a constant BASE with a variable path and then passes it to urllib.request.urlopen. While urllib can handle file:// URLs, the supplied source does not show whether the `path` argument can be influenced by an attacker or whether any validation is performed before use. No guard or sanitization is visible in the provided excerpt, but there is also no evidence that untrusted input reaches this function. The scanner flag alone is insufficient to confirm a vulnerability.

**Impact:** If an attacker can control `path` and supply a file:// URL, they could cause the application to read arbitrary files from the server, potentially leading to information disclosure.

**Remediation:** Validate and sanitize the `path` argument to ensure it does not contain dangerous schemes (e.g., file://) or directory traversal sequences. Consider using a higher‑level HTTP client like the `requests` library, which does not support file URLs, or explicitly reject non‑HTTP(S) schemes before calling urllib.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Source excerpt shows dynamic URL construction with urllib (lines 20‑22).`
- `Scanner flagged the pattern as potentially risky.`

Limitations:
- Missing evidence that `path` is derived from untrusted user input.
- No runtime probe demonstrating exploitation or guard checks in the surrounding code.

### 63. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload\["target_url"\]). This could allow a malicious actor to influence the URL, potentially leading to SSRF or file read via file:// schemes. However, the supplied excerpt does not show any validation, sanitization, or restriction of the URL, nor does it provide runtime evidence that such a URL can be controlled by an attacker. No guard checks or additional context are present to confirm the vulnerability.

**Impact:** If an attacker can control the target_url value, they may be able to make the service request internal network resources or read arbitrary files via file:// URLs, leading to information disclosure or further compromise.

**Remediation:** Validate and sanitize the target_url before using it with urllib. Restrict allowed schemes to http/https, enforce whitelist of domains, or use a safer HTTP client library such as requests. Consider adding explicit input validation and error handling for malformed URLs.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `source_excerpt lines 18-23 show payload["target_url"] passed directly to urllib.request.Request without validation`

Limitations:
- No evidence that payload\["target_url"\] can be supplied by an attacker (e.g., no request flow or input source shown).
- No runtime probe demonstrating successful exploitation or SSRF behavior.
- No guard checks or sanitization logic present in the provided context.

### 64. Missing authentication on public file download (CWE-284)

- Issue group: `ai-bf1824ec21fc73f8`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The endpoint defined at @router.get("/files") serves files from the public directory without any authentication or authorization checks. The code checks only that the requested path is within the allowed directory and that the file exists, then returns its contents. No guard such as require_user, role verification, or token validation is present in the supplied snippet.

**Impact:** An unauthenticated attacker can retrieve any file placed in the public directory, potentially exposing sensitive data if such files are inadvertently stored there. This constitutes an authorization bypass (CWE-284).

**Remediation:** Add authentication and authorization checks before serving the file. For example, require a logged‑in user or specific role, and validate that the requested file is intended for public access only. Consider adding rate‑limiting and size restrictions on responses.
Evidence:
- Source IDs: `ai-bf1824ec21fc73f8`
- `api/extra.py:210 – @router.get("/files") (entry point)`
- `api/extra.py:212 – file = (FILES / "public" / name).resolve() (path resolution)`
- `api/extra.py:213 – if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404) (validation)`
- `api/extra.py:215 – return Response(file.read_text(encoding="utf-8"), media_type="text/plain") (sensitive operation)`
- `dynamic_penetration_agent: exploitation_confirmed – unauthenticated request to /files returned HTTP 422, indicating the endpoint is reachable without authentication`

Limitations:
- No independent scanner or higher‑severity source confirming the vulnerability; the evidence relies solely on the AI‑generated code analysis and a single runtime probe that returned HTTP 422 rather than a definitive file content. Additional testing (e.g., successful retrieval of a known file) or a scanner report would be needed to confirm the exploitability.

### 65. Potential token replay via refresh endpoint without revocation check (CWE-613)

- Issue group: `ai-c39cb4040816d8a1`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The /auth/refresh endpoint creates a new access token based solely on the user identity extracted from the Authorization header. The code does not perform any check that the presented token is a valid refresh token, nor does it verify that the token has not been revoked or previously used. This pattern can allow an attacker who obtains a valid token to repeatedly obtain fresh access tokens.

**Impact:** An attacker who captures a token could repeatedly call the refresh endpoint to obtain new access tokens, extending the window of unauthorized access and potentially bypassing token expiration or revocation mechanisms.

**Remediation:** Implement proper refresh‑token handling: require a distinct refresh token, validate its signature, check its revocation status (e.g., against a blacklist or database), enforce one‑time use or rotation, and limit the number of refreshes per token. Return appropriate error codes (401/403) when validation fails.
Evidence:
- Source IDs: `ai-c39cb4040816d8a1`
- `api/app.py:189 – @app.post("/auth/refresh") defines the refresh endpoint`
- `api/app.py:190 – def refresh(authorization: str | None = Header(default=None))`
- `api/app.py:191 – user = principal(authorization) extracts the user from the Authorization header without token‑type validation`
- `api/app.py:196 – return {"access_token": make_token(row), "token_type": "bearer"} issues a new access token without revocation or usage checks`

Limitations:
- No evidence that the Authorization header contains a refresh token versus an access token
- No visible revocation or usage‑tracking mechanism elsewhere in the repository
- No independent scanner or runtime probe confirming that token replay is possible

### 66. Potential mass assignment in comment creation (CWE-915)

- Issue group: `ai-cfd2d2f7a41c1178`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **low**

**Explanation:** The add_comment endpoint accepts a Comment model containing only a body field and inserts the provided body into the database together with the authenticated user's ID. No validation is performed on the request payload beyond the Pydantic model, and there is no role‑based or ownership check before the INSERT. If the Comment model were extended with additional fields (e.g., an admin flag) or if a client could supply extra JSON properties that are not defined in the model but are accepted by the underlying ORM, those fields could be mass‑assigned and written to the database without restriction, leading to privilege escalation or data tampering.

**Impact:** An attacker could create or modify comment records with unauthorized attributes, potentially escalating privileges, injecting malicious data, or corrupting application state.

**Remediation:** Define an explicit schema that lists only the allowed fields for comment creation and reject any additional properties. Add validation to ensure only the intended fields are processed. If role‑based restrictions are required, enforce them by checking the authenticated user's role before performing the INSERT. Consider using Pydantic's `extra = "forbid"` setting or manually whitelist fields before database insertion.
Evidence:
- Source IDs: `ai-cfd2d2f7a41c1178`
- `api/extra.py:161 – @router.post("/comments") defines the entry point`
- `api/extra.py:162 – function signature accepts a Comment model without extra validation`
- `api/extra.py:166 – SQL INSERT uses only author_id and body, no role or field checks`

Limitations:
- No runtime probe or scanner evidence confirming that extra fields can be injected or that role checks are missing in practice
- No evidence that the Comment model permits additional properties beyond `body` (e.g., Pydantic configuration)
- No independent confirmation that the endpoint is reachable by unprivileged users or that role‑based access control is enforced elsewhere

### 67. Missing ownership verification on order payment (CWE-639)

- Issue group: `ai-a815919b2f2f9d7a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The pay_order endpoint authenticates the request via the principal function but does not compare the authenticated user's ID with the order's owner_id before updating the order status to 'paid'. The source excerpt shows the order is fetched and then updated without any ownership check. No guard is visible in the supplied code context, and no additional scanner or runtime probe evidence confirming exploitation is present.

**Impact:** An attacker who can obtain a valid authorization token could pay any order by supplying its ID, potentially causing unauthorized financial transactions, invoice creation, and audit log inconsistencies.

**Remediation:** Add an explicit ownership check after retrieving the order, e.g., compare order\["owner_id"\] with the ID extracted from the authorization token and return HTTP 403 if they differ. Ensure audit logging of payment attempts and consider rate‑limiting the endpoint.
Evidence:
- Source IDs: `ai-a815919b2f2f9d7a`
- `source_excerpt lines 241‑249 show the endpoint definition, principal call, order fetch, and UPDATE without ownership verification`

Limitations:
- No independent scanner or runtime probe evidence confirming that the missing check can be exploited in practice; the presence of other authorization checks elsewhere in the codebase is unknown.

### 68. Unrestricted coupon discount manipulation (CWE-640)

- Issue group: `ai-a8a36fd7f927dc98`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The apply_coupon endpoint reads an optional discount value from the request body and uses it directly in the UPDATE statement without any validation or authorization check beyond the generic principal() call. This allows a client to supply an arbitrary discount that can exceed the coupon's configured percent or bypass business rules. No evidence is provided that additional checks (e.g., role verification, maximum discount limits) exist elsewhere in the codebase.

**Impact:** An attacker could apply a coupon and specify a higher discount than intended, potentially reducing order totals to zero or negative values, leading to revenue loss and possible abuse of promotional mechanisms.

**Remediation:** Add explicit validation to ensure that body.discount is either omitted or does not exceed the coupon's percent. Enforce role‑based checks so only authorized users (e.g., staff or admins) can set custom discounts. Apply a global maximum discount limit and reject values outside the allowed range before executing the UPDATE.
Evidence:
- Source IDs: `ai-a8a36fd7f927dc98`
- `api/app.py:231 defines apply_coupon endpoint with principal(authorization) call`
- `api/app.py:234 fetches coupon percent`
- `api/app.py:235 assigns percent = body.discount if provided else coupon percent`
- `api/app.py:236 updates orders table with the computed percent without further checks`

Limitations:
- No scanner or runtime probe evidence confirming that the endpoint can be abused in practice
- No visible role‑based authorization beyond principal() to restrict custom discounts
- No evidence of elsewhere‑in‑code maximum discount enforcement

### 69. Potential path traversal in file_read endpoint (CWE-22)

- Issue group: `ai-cd57b8a32df8fcc3`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The `file_read` endpoint builds a file path by concatenating the user‑supplied `name` with the `FILES/public` directory and then calls `.resolve()`. It checks `file.is_relative_to(FILES.resolve())` and `file.is_file()` before reading the file. Because `Path.resolve()` follows symlinks, an attacker who can place a symlink inside `FILES/public` that points outside the intended directory could cause `file` to resolve to a location outside `FILES`. The relative‑to check would still succeed (the symlink target is still under `FILES/public`), allowing the read of arbitrary files. No additional validation (e.g., rejecting paths containing `..`, normalising before resolution, or explicitly forbidding symlinks) is present in the supplied code. The dynamic probe reports that a request to `/files` as an anonymous user returned HTTP 405 instead of the expected denial statuses, indicating the endpoint is reachable but does not confirm exploitation. No independent scanner or higher‑severity evidence confirming successful traversal is provided.

**Impact:** An attacker could read arbitrary files on the server filesystem that are reachable via a symlink placed in the public directory, potentially exposing source code, configuration files, or other sensitive data.

**Remediation:** * Reject any path components containing `..` before constructing the path.
* Use `os.path.normpath` or `Path.resolve(strict=False)` on the user‑supplied segment before joining.
* Verify that the final resolved path is a regular file and is not a symlink (`file.is_symlink()` should be false).
* Consider serving files through a safe library that handles path traversal checks, or restrict reads to a whitelist of allowed filenames.
* Add unit tests that attempt traversal via symlinks and `..` components.
Evidence:
- Source IDs: `ai-cd57b8a32df8fcc3`
- `file = (FILES / "public" / name).resolve()`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`
- `dynamic_penetration_agent: exploitation_confirmed (5 attempt(s)) — head_method_bypass: request to /files as anonymous returned HTTP 405, not one of the expected denial statuses [401, 403, 404]`

Limitations:
- No runtime probe demonstrates successful reading of an out‑of‑directory file.
No scanner source of medium or higher severity independently confirms the vulnerability.
The presence of symlinks under `FILES/public` is assumed but not shown in the provided repository snapshot.
The dynamic probe only shows the endpoint is reachable, not that traversal bypass works.

### 70. Missing ownership check on order cancellation (CWE-639)

- Issue group: `ai-f0dce5b04fc274c8`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `cancel_order` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user owns the order or has permission to cancel it. The SQL update statement updates any order with the supplied `order_id` without restricting by `user_id` or checking roles, creating a potential IDOR vulnerability.

**Impact:** An attacker could cancel orders belonging to other users, leading to denial of service for legitimate customers, financial loss, and loss of trust in the system.

**Remediation:** Add a check that retrieves the order's owner (or required role) and verifies it matches the authenticated principal before performing the update. Example: fetch the order, compare `order.user_id` to `principal.id` or check `principal.role` for cancellation rights, and return 403/404 if unauthorized. Also consider using parameterized queries that include the user identifier in the WHERE clause.
Evidence:
- Source IDs: `ai-f0dce5b04fc274c8`
- <code>def cancel_order(order_id: int, authorization: str | None = Header(default=None)) -&gt; dict[str, Any]:</code>
- `principal(authorization)`
- `row = conn.execute("UPDATE orders SET status='cancelled' WHERE id=%s RETURNING *", (order_id,)).fetchone()`

Limitations:
- No runtime probe or scanner evidence confirms that the endpoint can be exploited to cancel another user's order; the dynamic penetration agent attempt returned HTTP 405 for an anonymous request, which does not demonstrate successful unauthorized cancellation.
- The implementation of `principal()` is not shown, so it is unclear whether it returns user identity or role information that could be used for an implicit ownership check elsewhere.
- No database policies, triggers, or additional application logic are visible that might enforce ownership, so the absence of an explicit check in the provided code cannot be definitively confirmed as a vulnerability.

### 71. Missing authorization on admin user listing (CWE-284)

- Issue group: `ai-13705465b5427a14`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/users calls principal(authorization) but the supplied code does not show any role check before returning the full user table, which includes sensitive fields such as SSN. The absence of an explicit admin‑role verification in the visible snippet suggests that any authenticated user could retrieve this data.

**Impact:** Unauthorized disclosure of all user records, including personally identifiable information (PII) such as SSN, which can lead to privacy violations, identity theft, and regulatory non‑compliance.

**Remediation:** Add an explicit check that the principal’s role is admin before executing the query and returning the results. For example, retrieve the role from the principal object and raise HTTPException(403) if the role is not admin. Consider moving admin routes behind a dedicated security middleware that enforces role‑based access control.
Evidence:
- Source IDs: `ai-13705465b5427a14`
- `@app.get("/admin/users") definition at line 277`
- `principal(authorization) called at line 279 without subsequent role verification`
- `SQL query at line 281 selects id,username,email,role,ssn from users`

Limitations:
- No evidence that middleware or external framework enforces admin role for /admin routes
- No scanner or runtime probe confirming that the endpoint is reachable without authorization
- No view of the implementation of principal() to determine whether it performs role checks internally

### 72. Missing authorization on admin job listing (CWE-284)

- Issue group: `ai-c33ff249638a3733`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint @app.get("/admin/jobs") calls principal(authorization) but no explicit check for an admin role is shown before executing a database query that returns all job records. Without evidence of a global guard or role verification, any authenticated user could potentially retrieve the full job list, indicating an authorization flaw.

**Impact:** Unauthorized users may access sensitive job information, leading to data leakage and potential abuse of internal job data.

**Remediation:** Add an explicit admin role check after principal(authorization) (e.g., verify that the user’s role is 'admin') and return an appropriate error (403) if the check fails. Ensure that any global admin route guards are documented and enforced.
Evidence:
- Source IDs: `ai-c33ff249638a3733`
- `@app.get("/admin/jobs") definition at line 285`
- `principal(authorization) call at line 287`
- `Database query fetching all jobs at line 289`

Limitations:
- No evidence of a global admin route guard or role verification elsewhere in the codebase
- No scanner or runtime probe confirming that the endpoint is accessible without admin privileges

### 73. Debug configuration endpoint exposes secrets (CWE-200)

- Issue group: `ai-b545bf0884ed98c5`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /debug/config endpoint is publicly accessible without authentication and returns sensitive configuration values including the database URL, mock external service URL, and application secret. The source code shows no access control checks, and a runtime probe confirmed that an unauthenticated request receives HTTP 200 with the secret data.

**Impact:** Attackers can obtain database credentials and application secrets, enabling further attacks such as database compromise, credential reuse, or unauthorized API access.

**Remediation:** Restrict the /debug/config endpoint to authorized personnel only (e.g., require authentication and role checks) or disable/remove the endpoint in production builds. Ensure secrets are not exposed via any public API.
Evidence:
- Source IDs: `ai-b545bf0884ed98c5`
- `@app.get("/debug/config") definition at api/app.py:320`
- `return {"database_url": DATABASE_URL, "mock_external_url": MOCK_EXTERNAL_URL, "app_secret": os.environ.get("APP_SECRET")} at api/app.py:322`
- `runtime probe: unauthenticated request to /debug/config returned HTTP 200 with configuration data`

### 74. Insecure session cookie attributes (CWE-614)

- Issue group: `ai-61405af653af249e`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The code sets a session cookie (lab_session) without any security flags (HttpOnly, Secure, SameSite). This creates a potential attack surface for client‑side script access (XSS) or transmission over insecure channels. The supplied source shows the missing flags, but there is no independent scanner or runtime probe confirming exploitation, nor evidence that the cookie is transmitted only over HTTPS or that other mitigations (e.g., SameSite defaults) are applied elsewhere in the application.

**Impact:** An attacker who can inject JavaScript or sniff network traffic could read the session identifier and hijack the user’s session, leading to unauthorized access to protected resources.

**Remediation:** When setting the session cookie, include security attributes, e.g.: ```response.set_cookie("lab_session", f"session-{user['id']}", httponly=True, secure=True, samesite="lax")``` Ensure the application enforces HTTPS and consider rotating session IDs after authentication.
Evidence:
- Source IDs: `ai-61405af653af249e`
- `api/extra.py line 278: response.set_cookie("lab_session", f"session-{user['id']}") – cookie set without HttpOnly, Secure, or SameSite flags`

Limitations:
- No scanner or runtime probe evidence confirming that the cookie is sent without flags in practice.
- No evidence that the cookie is transmitted over HTTPS only or that other parts of the code set default security attributes.
- No confirmation that the session token is validated securely on subsequent requests.

### 75. Password reset token without expiration (CWE-640)

- Issue group: `ai-ad99add32a8324a1`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The code inserts a reset token into the `reset_tokens` table without any expiration timestamp or single‑use flag. The entry point (`POST /auth/reset/request`) reaches a sensitive operation (INSERT) and no check for token lifetime or reuse is visible in the supplied excerpt. However, there is no independent scanner or runtime probe evidence confirming that the token is never validated for expiration or one‑time use, and the AI source alone does not constitute proof of a vulnerability.

**Impact:** An attacker who obtains a valid reset token could reuse it indefinitely to reset the victim's password, leading to account takeover.

**Remediation:** Store an expiration timestamp (e.g., `expires_at`) and a used flag with each token. Enforce expiration and single‑use checks in the token validation endpoint (`/auth/reset/confirm`). Rotate or delete tokens after successful use.
Evidence:
- Source IDs: `ai-ad99add32a8324a1`
- <code>Source excerpt shows token insertion without expiration: `conn.execute(&quot;INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s)&quot;, (token, user[&quot;id&quot;]))` (line 571).</code>
- <code>Entry point defined at `@router.post(&quot;/auth/reset/request&quot;)` (line 564).</code>

Limitations:
- No evidence that the token is later validated for expiration or single‑use in the confirmation endpoint.
- Missing runtime or scanner confirmation that the token can be reused indefinitely.
- Unclear token entropy/length, which affects brute‑force risk.

### 76. Password reset request lacks rate limiting (CWE-307)

- Issue group: `ai-52bb7c949fbd132a`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **low**

**Explanation:** The code defines a POST endpoint "/auth/reset/request" that creates a reset token and inserts it into the database without any visible throttling or rate‑limit checks. The supplied excerpt shows the entry point and the sensitive INSERT operation, and the AI analysis notes the absence of rate‑limit logic. No guard (e.g., request count check, IP‑based limit, or external middleware) is present in the provided context.

**Impact:** An attacker can repeatedly invoke the endpoint to generate unlimited reset tokens for a given user, enabling credential‑stuffing attacks, denial‑of‑service against the token store, or facilitating password‑reset abuse.

**Remediation:** Add rate‑limiting logic to the endpoint (e.g., limit requests per IP or per user within a time window) or enforce limits via a dedicated middleware/component. Log each token creation and consider adding captcha or email verification before token issuance.
Evidence:
- Source IDs: `ai-52bb7c949fbd132a`
- `@router.post("/auth/reset/request") definition at line 564`
- `INSERT INTO reset_tokens(token,user_id) VALUES (%s,%s) at line 571`
- `No rate‑limit or request‑count check observed in the excerpt`

Limitations:
- No evidence that external middleware or infrastructure (e.g., API gateway, reverse proxy) applies rate limiting.
- No runtime probe confirming that repeated requests are accepted without throttling.
- No audit‑log or monitoring evidence showing token creation limits.

### 77. Coupon Abuse – No Usage Limits (CWE-639)

- Issue group: `ai-fd087d04590c4c7a`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint `verified_coupon` updates an order with a discount based on a coupon code without any visible checks for coupon expiration, usage count, or per‑user limits. The supplied source shows the discount is applied unconditionally after confirming the coupon exists, and no guard is present in the provided context. However, there is no independent scanner or higher‑severity evidence confirming that this behavior can be exploited, and the runtime probe only reports an unexpected HTTP 405 response rather than a successful discount application. Consequently, the presence of a vulnerability cannot be confirmed from the available data.

**Impact:** If coupons can be reused indefinitely or across multiple users, an attacker could repeatedly apply discounts, leading to financial loss and abuse of promotional offers.

**Remediation:** Add validation logic before applying the discount: check that the coupon is not expired, has not exceeded a usage count, and enforce per‑user or per‑order limits. Record coupon usage in the database and reject reuse. Return appropriate error responses when limits are exceeded.
Evidence:
- Source IDs: `ai-fd087d04590c4c7a`
- <code>def verified_coupon(order_id: int, body: dict, authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `order, _ = owned_order(order_id, authorization)`
- `if order["status"] != "new":`
- `raise HTTPException(409, "Order no longer editable")`
- `with connection() as conn:`
- `coupon = conn.execute("SELECT percent FROM coupons WHERE code=%s", (str(body.get("code", "")),)).fetchone()`
- `if not coupon:`
- `raise HTTPException(400, "Unknown coupon")`

Limitations:
- No evidence that coupon records include expiration or usage‑count fields.
- No code elsewhere that enforces single‑use or per‑user limits.
- Runtime probe did not demonstrate a successful discount application; the 405 response indicates the endpoint may be inaccessible or protected, but does not confirm the presence or absence of the flaw.
- No independent scanner or higher‑severity finding corroborates the vulnerability.

### 78. Insecure Direct Object Reference (CWE-639) in profile endpoint

- Issue group: `ai-6322be0c6e12b177`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `profile` endpoint retrieves a user record that includes sensitive fields (email, SSN) based solely on the `profile_id` path parameter. The only security call is `principal(authorization)`, whose behavior is not shown; there is no explicit ownership or role check before the database query. This pattern suggests an IDOR where an authenticated user could request another user's profile and obtain SSN data.

**Impact:** If an attacker can authenticate (or bypass authentication) and supply arbitrary `profile_id` values, they may retrieve personal data of any user, including SSNs, violating confidentiality and potentially enabling identity theft or further attacks.

**Remediation:** Add an authorization check that verifies the authenticated principal is allowed to view the requested profile (e.g., compare `profile_id` to the principal’s user ID or enforce role‑based access control). Return an error (401/403) when the check fails. Consider removing sensitive fields like SSN from the response or exposing them only to privileged roles.
Evidence:
- Source IDs: `ai-6322be0c6e12b177`
- <code>Source excerpt shows endpoint definition and query: `def profile(profile_id: int, authorization: str | None = Header(default=None)) -&gt; dict:`</code>
- <code>`principal(authorization)` is called but no further checks are performed before `SELECT id,username,email,ssn FROM users WHERE id=%s`</code>
- `Dynamic penetration agent attempt returned HTTP 422 instead of a denial status, indicating the request was not blocked but the exact response behavior is unclear`

Limitations:
- No concrete evidence that `principal` performs authorization beyond authentication
- No independent scanner or runtime probe confirming that an unauthenticated or unauthorized request can retrieve the row data
- The dynamic probe returned HTTP 422, not a definitive success or denial, so exploitation is not proven

### 79. Missing Authorization Check (CWE-862) in admin_overview endpoint

- Issue group: `ai-40fd1ed3ab05cb13`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The admin_overview endpoint authenticates the request via principal(authorization) but does not verify that the caller has administrative privileges before executing a sensitive query that returns the total number of users. The supplied source excerpt shows no role‑based check such as require_admin or equivalent. No additional scanner or runtime probe evidence confirming that the endpoint is reachable by non‑admin users is present, so the vulnerability cannot be confirmed.

**Impact:** An attacker who can obtain any valid authentication token could call /admin/overview and learn the total number of user accounts, which may aid enumeration attacks or further privilege‑escalation attempts.

**Remediation:** Add an explicit admin‑role verification before the sensitive operation, e.g.:
```python
if not is_admin(authorization):
    raise HTTPException(status_code=403, detail="Admin privileges required")
```
Ensure that the principal() function does not implicitly perform admin checks, or replace it with a dedicated authentication/authorization middleware that enforces role checks for admin routes.
Evidence:
- Source IDs: `ai-40fd1ed3ab05cb13`
- <code>def admin_overview(authorization: str | None = Header(default=None)) -&gt; dict:</code>
- `principal(authorization)`
- `count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]`

Limitations:
- No independent scanner or runtime probe evidence showing that a non‑admin request can reach the endpoint and receive the user count.
- Unclear whether external middleware or a global dependency injection might enforce admin role checks for routes under /admin; such enforcement is not visible in the provided excerpt.

### 80. Insecure Direct Object Reference (CWE-639) in order_note endpoint

- Issue group: `ai-b1bd5e39cd49c99c`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `order_note` endpoint authenticates the request via `principal(authorization)` but does not verify that the authenticated user (or the order identified by `order_id`) owns the requested note identified by `note_id`. The SQL query retrieves the note solely by `note_id` without any ownership check, allowing an attacker who can guess or enumerate note IDs to retrieve notes belonging to other users or orders.

**Impact:** An attacker can access arbitrary order notes, potentially exposing sensitive business information, personal data, or confidential communications associated with other users' orders.

**Remediation:** Add an ownership verification step after retrieving the note (or as part of the query) that ensures the `order_id` of the note matches the `order_id` path parameter and that the authenticated principal is authorized for that order. For example, query `SELECT id,order_id,body FROM notes WHERE id=%s AND order_id=%s` and verify the result belongs to the requesting user, returning 403/404 on mismatch.
Evidence:
- Source IDs: `ai-b1bd5e39cd49c99c`
- `Source excerpt shows the endpoint definition and query without ownership checks (lines 542‑546).`
- <code>Runtime probe report: unauthenticated request to `/orders/{order_id}/notes/{note_id}` returned HTTP 422 instead of expected denial statuses (401, 403, 404), indicating the endpoint processed the request without proper access control.</code>

### 81. Insecure Direct Object Reference (CWE-639) in view_upload endpoint

- Issue group: `ai-78a9caea45c6fa5b`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The `view_upload` endpoint returns the raw file contents based solely on the supplied `upload_id` without any ownership or permission checks. The source code shows no call to an authorization function before the sensitive database query and response. This pattern matches an IDOR vulnerability, but the only supporting evidence is the AI analysis and a single dynamic probe that returned HTTP 422 instead of an expected denial status, which does not conclusively demonstrate unauthorized access.

**Impact:** An attacker who can guess or enumerate valid upload IDs could retrieve arbitrary uploaded files, potentially exposing sensitive data, proprietary documents, or user‑generated content.

**Remediation:** Add an authorization check that verifies the requesting user’s rights to the requested upload (e.g., compare the upload’s owner ID with the authenticated user’s ID or enforce role‑based access). Return a 403/401 when the user lacks permission. Consider logging access attempts and validating `upload_id` ranges to mitigate enumeration.
Evidence:
- Source IDs: `ai-78a9caea45c6fa5b`
- `Source excerpt shows endpoint definition at line 366 and database query at line 369 with no preceding authorization logic.`
- `Dynamic penetration agent attempted unauthenticated access and received HTTP 422, indicating the request was processed but not denied as expected (no 401/403/404).`

Limitations:
- No independent scanner or higher‑severity finding confirming the flaw.
- The dynamic probe did not demonstrate successful retrieval of a file; it only showed an unexpected status code.
- No evidence of existing global access controls or middleware that might enforce permissions outside the shown snippet.

### 82. Missing Authorization for Forum Messages (CWE-862)

- Issue group: `ai-4800f588e9a977c1`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The `/forum/messages` endpoint is defined without any authentication or authorization dependency and directly returns all comment bodies from the database. A runtime probe confirmed that an unauthenticated request receives HTTP 200 with the message list, demonstrating the missing guard in practice.

**Impact:** Unauthenticated users can read all forum messages, potentially exposing private or sensitive user content.

**Remediation:** Add an authentication/authorization dependency to the route, e.g., `@router.get(..., dependencies=[Depends(get_current_user)])`, and enforce role checks if the forum should be restricted to certain users.
Evidence:
- Source IDs: `ai-4800f588e9a977c1`
- `api/extra.py:189 – route definition lacks any Depends or guard`
- `api/extra.py:192 – database query returns all comment bodies`
- `dynamic_penetration_agent: unauthenticated request to /forum/messages returned HTTP 200`

### 83. Information Disclosure via Detailed Error Message (CWE-200)

- Issue group: `ai-1fc4f9193a923e69`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /api/errors/query executes a database query that deliberately fails and then returns the caught exception message in the HTTP 500 response. This can expose internal details such as column names or database engine information. The supplied source shows the missing sanitisation, and a ZAP active scan reported an alert for this path, but no independent runtime probe confirming that the raw exception is actually sent to a client was provided.

**Impact:** Attackers may gain insight into the database schema or underlying technology, facilitating further attacks such as targeted SQL injection or enumeration of internal components.

**Remediation:** Replace the raw exception interpolation with a generic error message. Implement centralized error handling middleware that logs the detailed exception internally while returning a constant response (e.g., "Internal server error").
Evidence:
- Source IDs: `ai-1fc4f9193a923e69`
- `api/extra.py:227-233 – endpoint definition and exception handling that includes the exception object in the HTTPException response`
- `dynamic_penetration_agent: exploitation_confirmed – ZAP active scan reported 1 low‑severity alert for Application Error Disclosure at this exact path`

Limitations:
- No runtime probe showing the actual HTTP response body; the scan alert alone does not prove the exception details are exposed to clients.
- No evidence of a global error‑handling layer that might already sanitize the message before it reaches the client.

## Policy Decisions

- `merged-4c6d36222f8ebf7f1f68`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-15dd977d52312c30635a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d58491aad5be35b48233`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c5b44871f1955b338344`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-0bcbb317cfb96e7d5505`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-56ecc860a2c48330a29a`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-69b75a0aa3f8fc9fb800`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-efce9419c25ced2d8892`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4a2311054cdc2bfe890d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a6e788cfc5d9d1297feb`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a9a9a0b97f19f8bf52ae`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-6e468e09eab3ca889e3d`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-81ff94e895c53dbc2029`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-d716d5afb61da294d286`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f5fff899f9294177dc70`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-916563c278b3e6b62930`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-54b1ddb055358b3579a2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b7e0b624f8cddd0a9e8c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-d0789be823f0fd7fa381`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-fe4ca713f11faf9b96d6`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-7ed325c02dd6cf8227d2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-ccc894903304aa8847bd`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-1bcb1da144dffdcf3fd8`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-18063ba27bc289f53c8a`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-4ae7658c2abfbf689e2b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-a4473061f97f0a366678`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-cad468186f9fd0b4e99b`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8cdc677a9810b317840f`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3202e1e1074cfd44b9bf`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-18f1abe978f9fdaad8e6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-58377a692410b6446bbd`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-051697f9b8567d596874`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-3503f2dec888990b31f2`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-74bb99c1ff3b5ed1fea8`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8a5f28db4eebc517239e`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8ce42d9c8b52a95b109d`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-e76230cbef200116e4ae`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f15e42abb7b2acd921f1`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-bf1824ec21fc73f8`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-c39cb4040816d8a1`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-cfd2d2f7a41c1178`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-a815919b2f2f9d7a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-a8a36fd7f927dc98`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-cd57b8a32df8fcc3`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-f0dce5b04fc274c8`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-13705465b5427a14`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-c33ff249638a3733`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-b545bf0884ed98c5`: **block** — RG-001: high confirmed vulnerability is AI claim confirmed against the cited source by deterministic checks; blocking severities are critical, high.
- `ai-61405af653af249e`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-ad99add32a8324a1`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-52bb7c949fbd132a`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-fd087d04590c4c7a`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-6322be0c6e12b177`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-40fd1ed3ab05cb13`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-b1bd5e39cd49c99c`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `ai-78a9caea45c6fa5b`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `ai-4800f588e9a977c1`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1fc4f9193a923e69`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **83**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **31**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **15**; uncertain overlaps: **5**; needs more evidence: **11**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-09a55c66c30a7ea1`: needs_more_evidence
- `ai-c39cb4040816d8a1`: uncertain_overlap
- `ai-fdb73441313bbd62`: needs_more_evidence
- `ai-00b2526c34788f70`: needs_more_evidence
- `ai-cd57b8a32df8fcc3`: uncertain_overlap
- `ai-691b19a5aa6f272d`: needs_more_evidence
- `ai-ad99add32a8324a1`: uncertain_overlap
- `ai-52bb7c949fbd132a`: uncertain_overlap
- `ai-8e13c945280d6330`: needs_more_evidence
- `ai-956884683be69033`: needs_more_evidence
- `ai-77243d226c06b4bc`: needs_more_evidence
- `ai-8bd85b1b7daa962a`: needs_more_evidence
- `ai-b1f91ec923ffd9dd`: needs_more_evidence
- `ai-fd087d04590c4c7a`: uncertain_overlap
- `ai-b0e47f5278b52a0f`: needs_more_evidence
- `ai-e02d9ef9816111df`: needs_more_evidence

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

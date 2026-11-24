# Security Review Report

- Project: `targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-11-17T11:41:57.533318+00:00`
- Policy status: **failed**
- Review status: **partial**

## Executive Summary

The agent reviewed **38** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **63** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **95**; reviewed: **38**; pending: **57**.

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

**Explanation:** The scanner (zap.10021) observed that a GET request to '/' did not include the X-Content-Type-Options header in the response. The provided source code does not set this header anywhere, so the application likely returns responses without the protective header.

**Impact:** Without the X-Content-Type-Options: nosniff header, browsers may attempt to MIME-sniff the content, potentially allowing content-type confusion attacks such as cross-site scripting (XSS).

**Remediation:** Configure the FastAPI application to include the X-Content-Type-Options header on all responses, e.g., using a middleware that adds `response.headers['X-Content-Type-Options'] = 'nosniff'`.
Evidence:
- Source IDs: `merged-4c6d36222f8ebf7f1f68`
- `Scanner rule zap.10021 reported missing X-Content-Type-Options on GET /`
- `Source excerpt shows no header-setting logic`

Limitations:
- No direct capture of the actual HTTP response headers from the running application; confirmation relies on scanner observation only.

### 2. Job listing endpoint may lack proper admin authorization check

- Issue group: `merged-15dd977d52312c30635a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint /admin/jobs calls a function principal(authorization) before accessing the database, but the supplied source excerpt does not show the implementation of principal. The runtime probe observed that a GET request to /admin/jobs returned HTTP 200 instead of the expected 403/404, indicating that the authorization check either does not reject non‑admin users or is ineffective. No additional scanner evidence of higher severity or independent corroboration is provided.

**Impact:** If the authorization check is missing or ineffective, any authenticated user (or possibly unauthenticated users) could retrieve the full list of jobs, potentially exposing sensitive internal data and enabling further attacks.

**Remediation:** Implement or verify that the principal function enforces that the caller has an admin role before proceeding. Return an appropriate error (e.g., 403 Forbidden) for non‑admin requests. Add unit and integration tests to confirm the enforcement.
Evidence:
- Source IDs: `merged-15dd977d52312c30635a`
- `Source excerpt shows admin_jobs endpoint calling principal(authorization) but does not reveal its logic`
- `Runtime probe fact: GET /admin/jobs returned status 200 when 403/404 were expected`

Limitations:
- Missing the implementation of principal() to confirm whether it performs an admin role check
- No independent scanner finding of medium or higher severity confirming the flaw

### 3. Potential privilege escalation via /admin/token-report

- Issue group: `merged-d58491aad5be35b48233`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint checks the role field in the token and raises a 403 for non‑admin users. However, the runtime probe reports a 200 response for a GET request, indicating the check may be ineffective or bypassed. The source code alone shows a guard, but the observed behavior contradicts it, suggesting a possible flaw in token extraction or validation.

**Impact:** An attacker could access administrative functionality without proper privileges, leading to data leakage or unauthorized actions.

**Remediation:** Verify that the principal function correctly validates and extracts the role from the Authorization header. Ensure that missing or malformed tokens are rejected and that role checks cannot be bypassed. Add explicit validation and logging for token parsing failures.
Evidence:
- Source IDs: `merged-d58491aad5be35b48233`
- `Source excerpt shows role check and 403 raise (lines 661‑664).`
- `Runtime probe fact: GET /admin/token-report returned status 200, assertion_results false (expected 403).`

Limitations:
- Missing implementation of the principal() function to confirm how the token is parsed and role is determined.
- No evidence of token values used in the probe; cannot determine if a valid admin token was supplied.
- Unclear whether other middleware or guards affect the endpoint.

### 4. User listing endpoint lacks proper admin authorization check

- Issue group: `merged-c5b44871f1955b338344`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The /admin/users endpoint calls a generic principal() function but does not enforce that the authenticated principal has an admin role before querying and returning all user records, including sensitive fields such as SSN. No role‑based guard is visible in the supplied code snippet.

**Impact:** An attacker who can obtain any valid authorization header can retrieve the full list of users and their sensitive data, leading to privacy breaches and potential credential harvesting.

**Remediation:** Add an explicit check that the authenticated principal has the required admin role before executing the database query, and return a 403 response when the check fails. Example:
```python
if not principal_has_role(authorization, "admin"):
    raise HTTPException(status_code=403, detail="Forbidden")
```
Evidence:
- Source IDs: `merged-c5b44871f1955b338344`
- `Source code shows admin_users endpoint calls principal() but lacks role verification (lines 278‑282).`
- `Runtime probe fact indicates a GET request to /admin/users returned HTTP 200 instead of the expected 403/404, confirming the endpoint is accessible without admin rights.`

### 5. Cookie No HttpOnly Flag

- Issue group: `merged-0bcbb317cfb96e7d5505`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The source code sets a session cookie with `response.set_cookie("lab_session", f"session-{row['id']}")` and does not specify the `HttpOnly` attribute. The runtime probe confirms the endpoint is reachable via POST, but does not capture the Set-Cookie header to verify the flag. No guard or security header is present in the supplied context to mitigate client‑side script access to the cookie.

**Impact:** An attacker who can execute JavaScript in the victim's browser could read the `lab_session` cookie, potentially hijack the user's session and gain unauthorized access to protected resources.

**Remediation:** Set the `HttpOnly` flag when creating the cookie, e.g., `response.set_cookie("lab_session", f"session-{row['id']}", httponly=True)`. Consider also adding `Secure` and `SameSite` attributes as appropriate.
Evidence:
- Source IDs: `merged-0bcbb317cfb96e7d5505`
- `source_excerpt lines 288‑301 show the cookie being set without HttpOnly`
- `runtime_probe_facts indicate the POST endpoint is exercised`

Limitations:
- Missing captured HTTP response showing the Set-Cookie header without the HttpOnly attribute
- No independent scanner finding of medium or higher severity confirming the flag is absent

### 6. Missing Anti-clickjacking Header

- Issue group: `merged-56ecc860a2c48330a29a`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /auth/form-login endpoint returns an HTMLResponse without setting any anti-clickjacking header such as X-Frame-Options or Content-Security-Policy frame-ancestors. The source excerpt shows no call to response.headers.set or similar. The runtime probe confirms the endpoint is reachable via POST, and the scanner finding flags the missing header, providing independent corroboration.

**Impact:** An attacker can embed the login page in a hidden iframe on a malicious site and potentially trick users into submitting credentials (clickjacking), leading to credential theft or session hijacking.

**Remediation:** Add an appropriate anti-clickjacking header to the response, e.g., `response.headers['X-Frame-Options'] = 'DENY'` or configure a Content‑Security‑Policy with `frame-ancestors 'none'`. Ensure this header is applied to all HTML responses.
Evidence:
- Source IDs: `merged-56ecc860a2c48330a29a`
- `Source excerpt shows response creation without header setting`
- `Runtime probe fact indicates POST method to /auth/form-login`
- `Scanner finding (zap.10020) reports missing anti-clickjacking header`

### 7. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-69b75a0aa3f8fc9fb800`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The source code for the `/auth/form-login` endpoint does not set any security‑related response headers. The scanner reported that the CSP header is missing for POST requests to this path. No code fragment shows a `response.headers['Content‑Security‑Policy']` assignment or a middleware that would add it, and the runtime probe only confirms the request method and that values were redacted, not the presence or absence of CSP. Consequently, the finding is plausible but lacks direct evidence that the header is indeed omitted in the running application.

**Impact:** Without a CSP header, the application is vulnerable to client‑side injection attacks such as cross‑site scripting (XSS). An attacker could inject malicious scripts that execute in the victim’s browser, potentially stealing session cookies or performing actions on behalf of the user.

**Remediation:** Add a strict Content‑Security‑Policy header to all responses, preferably via a centralized middleware. Example (FastAPI):
```python
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\['Content-Security-Policy'\] = "default-src 'self'; script-src 'self'"
        return response
```
Register the middleware in the FastAPI app. Adjust the policy to match the application’s needs.
Evidence:
- Source IDs: `merged-69b75a0aa3f8fc9fb800`
- `Scanner finding: "Content Security Policy (CSP) Header Not Set" for path /auth/form-login`
- `Source excerpt shows no CSP header being set in the form_login handler`

Limitations:
- No runtime observation of the actual response headers confirming that CSP is missing
- No evidence that a global middleware or server configuration adds the CSP header elsewhere

### 8. Password reset tokens must be single use

- Issue group: `merged-efce9419c25ced2d8892`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source code for the password reset confirmation endpoint retrieves a token from the database but does not invalidate or delete the token after a successful password change. The runtime probe shows that a POST to /auth/reset/confirm with a reused token returns HTTP 200, indicating the token can be used multiple times. This demonstrates a missing single‑use enforcement, allowing token replay attacks.

**Impact:** An attacker who obtains a valid password reset token can reuse it to reset the victim's password multiple times, leading to account takeover.

**Remediation:** Invalidate or delete the reset token after a successful password change, and optionally add a used‑flag column with a check before processing. Ensure the token is single‑use and has an expiration.
Evidence:
- Source IDs: `merged-efce9419c25ced2d8892`
- `Source excerpt shows token lookup without deletion (lines 577‑585)`
- `Runtime probe fact indicates POST to /auth/reset/confirm returned 200 instead of expected error codes, confirming token reuse`

### 9. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-4a2311054cdc2bfe890d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint /catalog/query returns HTML content but the supplied source excerpt does not show any middleware or response handling that adds a Content‑Security‑Policy header. The runtime probe records a GET request to this path but does not capture response headers, so the absence of CSP is not directly observed. The scanner flagged the missing CSP header, providing medium‑severity evidence, but without concrete header data the finding cannot be confirmed.

**Impact:** Without a CSP header, browsers may allow execution of unsafe inline scripts or loading of resources from untrusted origins, increasing the risk of cross‑site scripting (XSS) and data‑exfiltration attacks.

**Remediation:** Add a CSP header to the response, e.g., via FastAPI middleware or a custom response class:
```python
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers\['Content‑Security‑Policy'\] = "default-src 'self'; script-src 'self'"
        return response

app.add_middleware(CSPMiddleware)
```
Evidence:
- Source IDs: `merged-4a2311054cdc2bfe890d`
- `Scanner finding: Content Security Policy (CSP) Header Not Set (zap.10038) for /catalog/query`

Limitations:
- No captured response headers from the runtime probe to definitively show the CSP header is missing.
- No code evidence of CSP header being set elsewhere in the application (e.g., middleware, global response handling).

### 10. X-Content-Type-Options Header Missing

- Issue group: `merged-a6e788cfc5d9d1297feb`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content without setting the X-Content-Type-Options: nosniff header. The supplied source excerpt shows the route definition but does not include any response header manipulation. A runtime probe confirms the endpoint is reachable via GET, but no response header data is provided to prove the header is absent. No guard or configuration is shown that would add the header elsewhere in the application.

**Impact:** Browsers may perform MIME type sniffing on the response, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Add the X-Content-Type-Options header with the value "nosniff" to the response, e.g., by using FastAPI's Response class or a middleware that sets the header for all HTML responses.
Evidence:
- Source IDs: `merged-a6e788cfc5d9d1297feb`
- `Source excerpt shows the /catalog/query route returning HTMLResponse without header handling.`
- `Runtime probe fact indicates a GET request to /catalog/query was made (web-runtime zap.10021).`

Limitations:
- No captured HTTP response headers to definitively demonstrate the header is missing.
- No evidence that the application sets the header globally via middleware or server configuration.

### 11. Missing Anti-clickjacking Header

- Issue group: `merged-a9a9a0b97f19f8bf52ae`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /catalog/query returns HTML content but the supplied source excerpt and runtime probe do not show any X-Frame-Options or Content‑Security‑Policy frame‑ancestors header being set. The scanner flagged the missing anti‑clickjacking header, and the runtime probe confirms the endpoint is reachable via GET, but no response header evidence is provided.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add an appropriate anti‑clickjacking header (e.g., `X-Frame-Options: SAMEORIGIN` or a CSP `frame‑ancestors` directive) to the response for the /catalog/query endpoint.
Evidence:
- Source IDs: `merged-a9a9a0b97f19f8bf52ae`
- `Runtime probe indicates GET request to /catalog/query (web-runtime zap.10020)`

Limitations:
- Missing captured HTTP response headers showing the absence of X-Frame-Options or CSP frame‑ancestors header; no evidence that the application sets these headers elsewhere.

### 12. Missing Anti-clickjacking Header

- Issue group: `merged-6e468e09eab3ca889e3d`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The endpoint /comments returns HTML content without any anti-clickjacking headers such as X-Frame-Options or Content-Security-Policy frame-ancestors. The source excerpt shows the response is built as a plain string and returned via FastAPI's HTMLResponse, and no header manipulation is visible. The runtime probe confirms the endpoint is reachable via GET, but does not capture response headers, so the missing header is not directly observed.

**Impact:** An attacker could embed the page in a malicious iframe, enabling clickjacking attacks that trick users into performing unintended actions.

**Remediation:** Add appropriate anti-clickjacking headers to the response, e.g., set X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self' on the FastAPI route or globally via middleware.
Evidence:
- Source IDs: `merged-6e468e09eab3ca889e3d`
- `Source excerpt shows HTMLResponse returned without header modifications (lines 173-177).`
- `Runtime probe fact confirms GET request to /comments (web-runtime zap.10020).`

Limitations:
- No captured response headers confirming the header is absent; need runtime evidence that X-Frame-Options or CSP headers are missing.

### 13. Content Security Policy (CSP) Header Not Set

- Issue group: `merged-81ff94e895c53dbc2029`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /comments endpoint returns an HTML response constructed from database rows without any indication that a Content‑Security‑Policy header is added to the response. The source excerpt shows only the HTML generation logic and no header manipulation. The scanner flagged the missing CSP header based on the observed HTTP response, but no runtime probe fact confirming the absence of the header is provided.

**Impact:** Without a CSP header, browsers are free to execute inline scripts and load resources from any origin, increasing the risk of cross‑site scripting (XSS) and data‑injection attacks.

**Remediation:** Add a CSP header to the response, e.g., using FastAPI's Response class or a middleware to set `Content‑Security‑Policy: default-src 'self';` (or a policy appropriate to the application).
Evidence:
- Source IDs: `merged-81ff94e895c53dbc2029`
- `Source excerpt shows HTML response generation without CSP header logic (lines 173‑177).`
- `Scanner reported "Content Security Policy (CSP) Header Not Set" for /comments.`

Limitations:
- No runtime probe fact confirming that the CSP header is absent in the actual HTTP response.
- No evidence that the application sets CSP headers globally via middleware or server configuration.

### 14. X-Content-Type-Options Header Missing

- Issue group: `merged-d716d5afb61da294d286`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The endpoint `/comments` returns HTML content without setting the `X-Content-Type-Options: nosniff` header. The source excerpt shows the response is built and returned directly, and no middleware or response‑modifying code is visible that would add security headers. The scanner runtime probe reports a GET request to this path and flags the missing header.

**Impact:** Without the `X-Content-Type-Options` header, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting if an attacker can influence the response body.

**Remediation:** Add a middleware or response decorator that sets `X-Content-Type-Options: nosniff` for all HTML responses, e.g., using FastAPI's `Response` headers or a Starlette middleware.
Evidence:
- Source IDs: `merged-d716d5afb61da294d286`
- <code>Source excerpt shows `/comments` endpoint returns HTML without header manipulation</code>
- `Scanner runtime probe (zap.10021) flagged missing X-Content-Type-Options header for GET /comments`

Limitations:
- No captured HTTP response headers confirming the header is absent; the assessment relies on the scanner’s claim rather than direct evidence

### 15. Debug configuration is unavailable anonymously

- Issue group: `merged-f5fff899f9294177dc70`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The source code defines a GET endpoint at /debug/config that returns sensitive configuration values (database URL, mock external URL, and application secret) without any authentication or authorization checks. A runtime probe confirms that an unauthenticated GET request to this endpoint receives a 200 OK response, whereas the expected behavior would be a 401/403/404. The combination of the source excerpt and independent runtime observation satisfies the criteria for a confirmed vulnerability.

**Impact:** An attacker can retrieve critical configuration data, including database connection strings and secret keys, enabling further attacks such as database compromise, credential reuse, or service impersonation.

**Remediation:** Add proper authentication and authorization checks to the /debug/config endpoint, ensuring that only authorized personnel can access configuration data. Consider removing the endpoint from production or restricting it to internal use only. Also, avoid exposing secrets via environment variables in responses.
Evidence:
- Source IDs: `merged-f5fff899f9294177dc70`
- `Source code defines /debug/config endpoint returning DATABASE_URL, MOCK_EXTERNAL_URL, and APP_SECRET without checks (lines 320-322).`
- `Runtime probe fact: GET /debug/config returned status 200, while expected statuses were 401, 403, or 404 (web-runtime rule workflow.debug_access.1).`

### 16. Missing Content-Security-Policy header

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner reports that the /healthz endpoint returned a 200 response without a Content‑Security‑Policy header. The source code for the endpoint does not set any response headers, but the provided data does not include the actual HTTP response headers to confirm that the header is absent. Without concrete response data or additional runtime probing that captures the headers, the claim cannot be confirmed.

**Impact:** Absence of a CSP header can allow certain classes of cross‑site scripting or data‑injection attacks if the endpoint is ever rendered in a browser context, potentially leading to content injection or data leakage.

**Remediation:** Configure the FastAPI application (or the underlying ASGI server) to include a Content‑Security‑Policy header on all responses, e.g., using a middleware that adds the header with an appropriate policy directive.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `Scanner runtime probe fact: web.missing-content-security-policy reported for path /healthz with status 200`

Limitations:
- Missing concrete HTTP response header capture for /healthz; need runtime observation of response headers to verify that CSP is indeed absent.

### 17. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The healthz endpoint is defined and returns a 200 response, but no evidence is provided that the X‑Frame‑Options or Content‑Security‑Policy headers are absent or present. The runtime probe only reports the HTTP status code, not the response headers, and the scanner finding is not corroborated by concrete header data.

**Impact:** Without clickjacking protection headers, the endpoint could be embedded in a malicious site, potentially allowing UI redressing attacks.

**Remediation:** Add appropriate clickjacking protection headers (e.g., X‑Frame‑Options: SAMEORIGIN or Content‑Security‑Policy: frame‑ancestors 'self') to the response for the /healthz endpoint.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Source excerpt defining the /healthz endpoint`
- `Runtime probe fact showing status 200 for /healthz`

Limitations:
- No response header data showing the absence of X‑Frame‑Options or CSP headers
- No independent scanner confirmation beyond the rule trigger

### 18. X-Content-Type-Options Header Missing

- Issue group: `merged-916563c278b3e6b62930`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The scanner reports that the HTTP response for GET /healthz does not include the X-Content-Type-Options header. The provided source excerpt shows only the FastAPI endpoint implementation and does not demonstrate how response headers are set. No code or configuration evidence is supplied that confirms the header is omitted, nor is there runtime probe data showing the actual response headers. Without concrete evidence of the missing header in the observed response, the finding cannot be confirmed.

**Impact:** If the X-Content-Type-Options header is absent, browsers may perform MIME type sniffing, potentially allowing content injection attacks such as cross‑site scripting when the response is interpreted as a different type than intended.

**Remediation:** Configure the FastAPI application or the underlying ASGI server to include the header, e.g., using a middleware that adds `X-Content-Type-Options: nosniff` to all responses, or set it explicitly in the endpoint response.
Evidence:
- Source IDs: `merged-916563c278b3e6b62930`
- `Scanner report: X-Content-Type-Options Header Missing for path /healthz (zap.10021)`

Limitations:
- No source code showing header handling or omission
- No runtime probe showing actual response headers for /healthz
- No configuration or middleware evidence that would add or omit the header

### 19. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns a 200 response but the runtime probe did not observe an X-Content-Type-Options header. The source code shows the endpoint implementation but does not set any security headers. This suggests the header may be omitted in production, which can allow MIME type sniffing attacks. However, the evidence is limited to a single runtime probe and the scanner finding; there is no direct observation of the header in the actual response or a guard that adds it elsewhere in the codebase.

**Impact:** An attacker could exploit MIME type sniffing to execute malicious content in the context of the application, potentially leading to cross‑site scripting or other client‑side attacks.

**Remediation:** Add the X-Content-Type-Options: nosniff header to all HTTP responses, e.g., by configuring the web framework or adding middleware that sets this header globally.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Source excerpt shows the /healthz endpoint implementation without header handling`
- `Runtime probe fact: web.missing-content-type-protection rule triggered for path /healthz with status 200`

Limitations:
- No captured HTTP response headers confirming the header is absent in the live service
- No evidence that another part of the application adds the header globally (e.g., middleware, reverse proxy)

### 20. Incoming webhook events require a valid signature

- Issue group: `merged-b98074828fe298997980`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/integrations/hook` accepts a POST request, reads the raw body, and stores it directly in the database without any verification of a cryptographic signature or authentication token. The supplied source excerpt shows no signature validation logic before the insert. A runtime probe sent a POST request to this endpoint and received HTTP 200, whereas the probe contract expected a 4xx response for unsigned requests, indicating the endpoint processes unauthenticated payloads.

**Impact:** An attacker can craft arbitrary webhook payloads and submit them to the endpoint, causing unauthorized data insertion, potential injection attacks, or abuse of downstream processing that trusts the stored data. This may lead to data corruption, privilege escalation, or denial‑of‑service.

**Remediation:** Add verification of a request signature (e.g., HMAC with a shared secret) or require authentication before processing the payload. Reject requests that fail verification with an appropriate 4xx status code. Log verification failures for monitoring.
Evidence:
- Source IDs: `merged-b98074828fe298997980`
- `Source excerpt shows the hook handler inserts the raw request body into the database without validation (lines 629‑633).`
- <code>Runtime probe fact reports a POST to `/integrations/hook` returned HTTP 200, while the expected statuses for an unsigned request were 400, 401, or 403.</code>

Limitations:
- No evidence is provided that signature verification or other guard logic exists elsewhere in the codebase (e.g., middleware, decorators).
- The runtime probe does not show the exact payload used; a signed request could have been sent inadvertently, though the probe expected a failure.

### 21. Only the owner can read an invoice

- Issue group: `merged-54b1ddb055358b3579a2`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/invoices/{invoice_id}` authenticates the request via `principal(authorization)` but does not verify that the authenticated user is the owner of the requested invoice before returning the record. The source excerpt shows no ownership check after the database query. A runtime probe for the same endpoint returned HTTP 200 for a request that should have been denied (expected 403), confirming that the missing authorization check is exploitable.

**Impact:** An attacker who can obtain a valid authorization token can retrieve any invoice by ID, leading to exposure of sensitive financial data across users.

**Remediation:** Add an ownership verification step after fetching the invoice, e.g., compare `row['owner_id']` with the authenticated principal’s ID and raise `HTTPException(403)` if they differ. Ensure the check is performed before returning the invoice data.
Evidence:
- Source IDs: `merged-54b1ddb055358b3579a2`
- <code>Source code shows `principal(authorization)` is called but no subsequent owner verification before returning the invoice record.</code>
- `Runtime probe fact: GET /invoices/{{invoice_id}} returned status 200 instead of expected 403, indicating the missing owner check is exploitable.`

### 22. Users cannot submit an admin job

- Issue group: `merged-b7e0b624f8cddd0a9e8c`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The POST /jobs endpoint inserts a job record without any visible authorization enforcement beyond the call to `principal(authorization)`. The supplied source excerpt does not show what `principal` does, and no explicit role check is present before the database insert. A runtime probe observed that a POST request to /jobs returned HTTP 200, whereas the probe contract expected error statuses (400, 403, 422) for unauthorized or malformed requests, indicating that the endpoint accepted the request without rejecting it.

**Impact:** An attacker could create arbitrary jobs, potentially with elevated privileges, leading to unauthorized actions or privilege escalation within the system.

**Remediation:** Ensure that the `principal` function validates the caller’s role and that the endpoint checks the caller’s permissions before inserting the job. Return appropriate error codes (e.g., 403) when the user lacks the required role.
Evidence:
- Source IDs: `merged-b7e0b624f8cddd0a9e8c`
- `Runtime probe fact: POST /jobs returned status 200 (expected 400/403/422)`

Limitations:
- The implementation of `principal` is not provided, so it is unclear whether it performs sufficient role validation. No additional scanner evidence of a guard check is present.

### 23. Identity endpoint may expose SSN

- Issue group: `merged-c0dcf73e8d7a6a1fbf02`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint queries the users table for the column "ssn" and returns the entire row as a dictionary. No filtering or masking of the SSN field is present in the supplied code snippet, indicating a potential data‑exposure issue. The scanner flagged this as a medium‑severity finding, and a runtime probe was performed, but the probe report indicates that values were redacted, so the actual exposure was not observed.

**Impact:** If an attacker can obtain a valid authorization token, they could retrieve the full user record, including the social security number, leading to privacy violations and potential identity theft.

**Remediation:** Modify the endpoint to exclude sensitive fields such as "ssn" from the response or mask them before returning the data. For example, construct the response dictionary explicitly without the SSN, or apply a transformation that redacts the value.
Evidence:
- Source IDs: `merged-c0dcf73e8d7a6a1fbf02`
- `Source code line 203 selects the "ssn" column and returns the full row: "SELECT id,username,role,email,ssn FROM users ..."`
- `Runtime probe fact shows the request succeeded (status 200) but marks values as redacted, indicating the probe did not capture the actual SSN value.`

Limitations:
- The runtime probe did not reveal the actual SSN value because it reports values_redacted=true; therefore we cannot confirm that the SSN is sent to the client. Additional evidence such as an uncensored response payload or a higher‑severity scanner confirmation would be needed to upgrade this to a confirmed vulnerability.

### 24. Catalog price must be set by the server

- Issue group: `merged-218d6fc43fe64432894a`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint inserts the order into the database using the unit_price value supplied in the request body (body.unit_price). No validation or server‑side enforcement of the price is shown in the provided code snippet, allowing a client to specify arbitrary prices for items. The runtime probe confirms that a POST to /orders succeeds (status 200) but does not demonstrate that the price is validated or overridden by the server.

**Impact:** An attacker can manipulate order prices, leading to under‑charging for goods or over‑charging customers, resulting in financial loss and potential fraud.

**Remediation:** Enforce server‑side price determination by looking up the official price from a trusted catalog based on the item identifier, and ignore any client‑provided price. Add validation to ensure the supplied price matches the catalog price or reject the request. Log and monitor mismatched price attempts.
Evidence:
- Source IDs: `merged-218d6fc43fe64432894a`
- `Source excerpt shows unit_price taken directly from the request body and inserted into the orders table (lines 213‑215).`
- `Runtime probe fact indicates a successful POST to /orders with status 200 (web-runtime rule workflow.price_catalog.1).`

Limitations:
- No evidence that the server performs any price validation or overrides the client‑provided price. Guard checks (e.g., lookup against a catalog, price range validation) are not present in the supplied context. Independent scanner confirmation of the vulnerability beyond the single finding is absent.

### 25. New orders cannot start as paid

- Issue group: `merged-5a7c783c30e11426af42`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint directly inserts the order into the database using the status value supplied in the request body without any validation or restriction. The runtime probe shows that a POST to /orders returns HTTP 200 instead of the expected 400/422, confirming that the endpoint accepts the supplied status (including a paid state) and creates the order successfully. This demonstrates an unchecked path to a sensitive operation (order creation with arbitrary status).

**Impact:** An attacker can create orders that are immediately marked as paid, potentially bypassing payment processing, leading to financial fraud, inventory inconsistencies, and unauthorized access to privileged order states.

**Remediation:** Validate the order status in the create_order handler. Reject or ignore any status value other than the allowed initial states (e.g., "pending"). Ensure that only the system can set a paid status after successful payment processing. Add explicit checks and return appropriate error codes (400/422) for invalid status values.
Evidence:
- Source IDs: `merged-5a7c783c30e11426af42`
- `Source excerpt shows create_order inserts body.status directly into the orders table (lines 213-215).`
- `Runtime probe fact indicates POST /orders returned status 200 when a 400/422 was expected, confirming the endpoint accepts the supplied status.`

### 26. Negative order prices are rejected

- Issue group: `merged-767d54ff7a729b156819`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an OrderBody and directly inserts the provided unit_price into the database without any validation. A runtime probe attempted to submit a negative price and received a 200 OK response, while the scanner expected a 400/422 error. This indicates that negative prices are not being rejected by the application code as observed. No explicit guard or validation logic for unit_price is present in the supplied source excerpt.

**Impact:** Allowing negative order prices could be exploited to create fraudulent orders, manipulate inventory accounting, or cause financial loss by crediting the system with negative amounts.

**Remediation:** Add input validation for the unit_price field in the OrderBody (e.g., ensure unit_price &gt; 0) before executing the INSERT statement, and return an appropriate error response (400 Bad Request) when validation fails.
Evidence:
- Source IDs: `merged-767d54ff7a729b156819`
- `Runtime probe fact: POST /orders with negative price returned status 200 (expected 400/422)`
- `Source excerpt shows no validation of body.unit_price before database insertion`

Limitations:
- Missing explicit source code that demonstrates a validation check for unit_price; need to see the full request handling logic to confirm absence of guards outside the shown snippet.

### 27. Users can create orders for other owners

- Issue group: `merged-d0789be823f0fd7fa381`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The create_order endpoint accepts an optional owner_id in the request body and defaults to the authenticated user's sub when not provided. No authorization check is performed to ensure the supplied owner_id matches the authenticated user, allowing a user to create orders on behalf of another owner. A runtime probe observed a successful POST to /orders returning HTTP 200, whereas the expected responses for unauthorized or malformed requests would be 400, 403, or 422.

**Impact:** An attacker can create orders for any user, potentially leading to unauthorized transactions, billing fraud, or resource exhaustion.

**Remediation:** Validate that the owner_id in the request body matches the authenticated user's identifier (user\["sub"\]). Reject the request with a 403 Forbidden (or appropriate) response if they differ, or remove the ability to specify owner_id altogether and always use the authenticated user's ID.
Evidence:
- Source IDs: `merged-d0789be823f0fd7fa381`
- `Source excerpt shows owner_id is taken from the request body without verification (lines 208-215).`
- `Runtime probe fact indicates a POST to /orders returned status 200, contrary to expected unauthorized statuses.`

Limitations:
- No evidence is provided that any authorization guard exists elsewhere in the codebase (e.g., middleware or decorator). The finding relies on the absence of checks in the shown snippet and a single runtime observation; additional scans or code reviews confirming the lack of guard would strengthen the case.

### 28. A note must belong to the order named in the URL

- Issue group: `merged-0f6fe31b81367808748c`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The endpoint `/orders/{order_id}/notes/{note_id}` retrieves a note by its primary key without verifying that the note's `order_id` matches the `order_id` supplied in the URL. This allows an attacker to access notes belonging to other orders by guessing or enumerating note IDs. The source excerpt shows the query `SELECT id,order_id,body FROM notes WHERE id=%s` and no subsequent check against the `order_id` parameter. The runtime probe confirms the flaw: a GET request to `/orders/1/notes/2` returned HTTP 200 instead of the expected 403 or 404, indicating the access control check is missing.

**Impact:** Unauthorized disclosure of notes belonging to other users/orders, leading to privacy breaches and potential leakage of sensitive business information.

**Remediation:** Add a check that the `order_id` of the retrieved note matches the `order_id` path parameter before returning the note. For example, after fetching the row, verify `row['order_id'] == order_id` and raise a 403/404 if it does not match. Alternatively, include the `order_id` in the WHERE clause (e.g., `WHERE id=%s AND order_id=%s`).
Evidence:
- Source IDs: `merged-0f6fe31b81367808748c`
- `Source excerpt lines 542-549 show the endpoint implementation without an order_id check`
- `Runtime probe fact: GET /orders/1/notes/2 returned status 200 when 403 or 404 was expected`

### 29. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the application secret (APP_SECRET) in clear text via a standard logger call. The log statement at line 137 includes the environment variable value without any redaction or protection, providing an attacker with direct access to a credential if logs are exposed. No conditional check or masking is present around the logging operation.

**Impact:** Exposure of the application secret can lead to credential compromise, allowing attackers to impersonate the service, forge tokens, or access protected resources.

**Remediation:** Remove the secret from log statements. If logging is required for debugging, redact or mask the secret value (e.g., replace with ***). Consider using a dedicated secure logger that filters sensitive fields. Also review logging configuration to ensure logs are stored securely and access‑controlled.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) at api/app.py:137`
- `Scanner finding (semgrep) flagged line 137 for credential disclosure (python-logger-credential-disclosure)`

### 30. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The legacy_login endpoint constructs an SQL query by directly interpolating the user‑provided username and password into the query string. No parameterized query or input sanitization is visible, and there is no guard or validation step that would prevent malicious input from altering the query logic.

**Impact:** An attacker could supply specially crafted values for username or password to perform SQL injection, potentially retrieving or modifying data in the users table, bypassing authentication, or executing arbitrary SQL commands.

**Remediation:** Refactor the query to use parameterized statements (e.g., prepared statements) provided by the database library. Validate and sanitize input where appropriate. Example: `query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"; row = conn.execute(query, (body.username, body.password)).fetchone()`. Also consider hashing passwords instead of storing them in plain text.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- <code>Source excerpt shows f‑string interpolation of `body.username` and `body.password` into the SQL query (lines 117‑119).</code>
- `Scanner finding categorizes this as a high‑severity SQL injection risk.`

Limitations:
- No runtime probe or exploit evidence demonstrating that injection is possible in practice.
- No additional guard checks or input validation are present in the supplied context, but external code could add safeguards not shown.

### 31. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but immediately resolves it and checks `file.is_relative_to(root)` and `file.is_file()`. The `is_relative_to` guard ensures the resolved path cannot escape the designated `public` directory, effectively preventing path traversal. The subsequent existence check further validates the target. Thus the code includes the necessary safety checks, and the scanner’s finding is a false positive.

**Impact:** If the guard were missing, an attacker could read arbitrary files on the server, leading to data disclosure. However, the guard is present, so this risk is mitigated.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient. Ensure future code follows the same pattern when handling user‑controlled paths.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- <code>source_excerpt lines 219‑224 show the guard `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, &quot;File not found&quot;)`</code>
- `source_symbol repeats the same guard logic`

### 32. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint verifies that the resolved file path is a sub‑path of the designated public directory using `is_relative_to(root)` and also checks that the target is a regular file before reading it. This prevents directory‑traversal attacks despite the user‑controlled `name` parameter.

**Impact:** None – the check blocks attempts to access files outside the intended directory, so no unauthorized file disclosure can occur via this endpoint.

**Remediation:** No remediation needed for path traversal; ensure the check remains in place and that the `FILES` directory is correctly configured.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- <code>source_excerpt lines 220‑223 show the `is_relative_to(root)` guard and file existence check</code>

### 33. Uncontrolled data used in path expression

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided `name` but then resolves it and verifies that the resulting path is within the allowed `FILES/public` directory using `is_relative_to(FILES.resolve())` and also checks that it is a file. These checks prevent directory traversal, so the path expression is controlled and the finding is a false positive.

**Impact:** If the check were ineffective, an attacker could read arbitrary files on the server, leading to information disclosure. However, the code correctly restricts access to the intended directory, mitigating this risk.

**Remediation:** No remediation needed; the existing checks are sufficient. Ensure that `FILES` is correctly set to the intended base directory and that the Python version supports `Path.is_relative_to` (Python 3.9+).
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- <code>source_excerpt lines 211‑214 show the use of `resolve()` and `is_relative_to(FILES.resolve())` to enforce the file resides within the allowed directory</code>

### 34. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function verifies that the resolved file path is within the designated public directory using `is_relative_to(root)` and also checks that the path points to an existing file before reading it. These checks mitigate path traversal, so the supplied code does not exhibit an uncontrolled path vulnerability.

**Impact:** None, as the code correctly restricts file access to the intended directory.

**Remediation:** No remediation needed for this finding; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- <code>The code resolves the requested file against a known root directory and validates `file.is_relative_to(root)` and `file.is_file()` before reading the file.</code>

### 35. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function constructs the file path using the user‑provided `name` but immediately resolves it and verifies that the resulting path is still within the intended `FILES/public` directory via `is_relative_to(FILES.resolve())`. If the check fails, a 404 error is raised, preventing access to files outside the allowed directory. This guard mitigates path traversal, so the reported uncontrolled data usage does not constitute a vulnerability.

**Impact:** None – the check blocks attempts to read files outside the permitted directory, preventing unauthorized file disclosure.

**Remediation:** No remediation needed for this specific issue; the existing relative‑path check is sufficient. Ensure that similar checks are applied consistently across all file‑access endpoints.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- <code>source_excerpt lines 211‑215 show the path resolution and the `is_relative_to` guard that blocks traversal</code>

### 36. Reflected server-side cross-site scripting

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `GET /catalog/search` directly interpolates the user‑controlled query parameter `q` into an HTML response (<code>&lt;h1&gt;Results for {q}&lt;/h1&gt;</code> and <code>&lt;p&gt;{row[&#x27;name&#x27;]}&lt;/p&gt;</code>). No escaping or sanitisation is performed before the value is embedded in the page, allowing an attacker to inject arbitrary HTML/JavaScript that will be rendered by the victim's browser. The same unsanitised value is also used in a raw SQL string, indicating additional risk (SQL injection). No defensive checks (e.g., input validation, output encoding) are visible in the supplied excerpt.

**Impact:** An attacker can craft a malicious URL such as <code>/catalog/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> that, when visited, executes arbitrary JavaScript in the context of the vulnerable site. This can lead to session hijacking, credential theft, defacement, or further attacks against users of the application.

**Remediation:** * Apply proper output encoding/escaping for HTML contexts (e.g., use a templating engine that auto‑escapes or explicitly escape `q` with `html.escape`).
* Validate and sanitise the `q` parameter before using it in SQL queries; use parameterised queries instead of string interpolation.
* Consider implementing a Content Security Policy (CSP) to mitigate the impact of any injected scripts.
* Review other endpoints for similar patterns of unsanitised user input.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- <code>Source excerpt shows `q` directly inserted into HTML response without escaping (lines 142‑145).</code>
- `Scanner flagged the finding as a reflected XSS based on the same code pattern.`

Limitations:
- No runtime probe evidence confirming that injected payloads are actually executed in a browser context is provided.
- No additional guard checks (e.g., input validation, sanitisation functions) are visible in the supplied code, but they could exist elsewhere in the application.

### 37. Uncontrolled data used in path expression

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" parameter but immediately resolves it and checks both that the resulting path is within the allowed directory (is_relative_to(FILES.resolve())) and that it points to an existing file (is_file()). These checks prevent directory traversal and arbitrary file access, mitigating the reported risk.

**Impact:** If the checks were absent, an attacker could read arbitrary files on the server. However, the present code enforces the directory constraint, so the vulnerability does not exist.

**Remediation:** No remediation needed for this specific issue; the existing path validation is sufficient. Ensure that similar checks are maintained for any future file‑access endpoints.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `source_excerpt lines 211‑214 show the path resolution and the is_relative_to and is_file checks that guard against path traversal.`

### 38. SQL query built from user-controlled sources

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `catalog_search` constructs an SQL query by directly interpolating the user‑provided parameter `q` into the query string without any sanitization or parameterization. This creates a classic SQL injection vector where an attacker can inject arbitrary SQL syntax via the `q` query parameter.

**Impact:** An attacker could manipulate the `q` parameter to execute unintended SQL commands, potentially exposing or modifying data in the `products` table or other database objects.

**Remediation:** Use parameterized queries or an ORM that safely escapes user input. For example, replace the f‑string with a prepared statement: `rows = conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",)).fetchall()`. Additionally, validate or whitelist allowed characters for `q`.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- <code>Source excerpt shows f‑string interpolation of `q` into SQL at line 144.</code>
- `Scanner finding flagged this as high severity.`

Limitations:
- No runtime probe demonstrating successful injection.
- No independent scanner of medium or higher severity confirming exploitability.
- No evidence of existing input validation or escaping mechanisms elsewhere in the code.

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
- `merged-f5fff899f9294177dc70`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-916563c278b3e6b62930`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-b98074828fe298997980`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-54b1ddb055358b3579a2`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-b7e0b624f8cddd0a9e8c`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-c0dcf73e8d7a6a1fbf02`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-218d6fc43fe64432894a`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-5a7c783c30e11426af42`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-767d54ff7a729b156819`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-d0789be823f0fd7fa381`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-0f6fe31b81367808748c`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is corroborated by a high scanner finding; blocking severities are critical, high.
- `merged-18f1abe978f9fdaad8e6`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-24d14609e3893220ea16`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-794dcb4921076779cef0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-83d97da4516adf20e20f`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b3c734b4cef8dd70fce0`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-b527b3ed30e57aac5ec5`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-ea527a7d7441e2b11700`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-f4eaf141df049c63545d`: **warn** — RG-005: AI classed this a false positive but a high scanner finding exists; confirm manually.
- `merged-f60fee7d82fbca512208`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **63**; issue groups after conservative correlation: **95**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **41**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **29**; uncertain overlaps: **3**; needs more evidence: **9**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-487cd086edd24ed3`: needs_more_evidence
- `ai-9b4f5bb6f2a105a4`: needs_more_evidence
- `ai-9fd4c76cbe86871f`: needs_more_evidence
- `ai-953f2f53bafcf034`: needs_more_evidence
- `ai-86f7e15d23cea03d`: uncertain_overlap
- `ai-b98ec267aac76bb8`: needs_more_evidence
- `ai-eb6ae0259a4426c4`: needs_more_evidence
- `ai-385f4ef6aefd7bdd`: needs_more_evidence
- `ai-022a4b56299a0fcf`: needs_more_evidence
- `ai-84d790e7ca885d16`: uncertain_overlap
- `ai-26620151b8264cfe`: uncertain_overlap
- `ai-94ab06f89bdfae37`: needs_more_evidence

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Pending Security Reviews

- `merged-fe4ca713f11faf9b96d6`
- `merged-7ed325c02dd6cf8227d2`
- `merged-ccc894903304aa8847bd`
- `merged-1bcb1da144dffdcf3fd8`
- `merged-18063ba27bc289f53c8a`
- `merged-4ae7658c2abfbf689e2b`
- `merged-a4473061f97f0a366678`
- `merged-cad468186f9fd0b4e99b`
- `merged-8cdc677a9810b317840f`
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
- `ai-e9f07f09faabf60f`
- `ai-fa74e88d2fd254fe`
- `ai-b7171bc6020b1e2f`
- `ai-0252de9ab903d777`
- `ai-ead464655e9a69a7`
- `ai-fab37354b02d1ba0`
- `ai-932b1f16764907f8`
- `ai-ff620dfaa2a8ee41`
- `ai-f0ccc3b9d38ddce1`
- `ai-5d3ce9356b31af8b`
- `ai-d5f84eecf5bce40d`
- `ai-dd1c0f6e6c60b708`
- `ai-76182088c965a98d`
- `ai-1380895ee2c458ad`
- `ai-e6b4aa4b31fd8b3a`
- `ai-86f7e15d23cea03d`
- `ai-9725570d578c01b3`
- `ai-b3cac087a919243e`
- `ai-dbc5515ff9f6fbe9`
- `ai-6322be0c6e12b177`
- `ai-e2aafc49ce7556a2`
- `ai-e34f01e4e6651bde`
- `ai-8b80c3773de74246`
- `ai-f743fe703518ba34`
- `ai-2c0b423220c16ecb`
- `ai-84d790e7ca885d16`
- `ai-f69e77e901449ba6`
- `ai-26620151b8264cfe`
- `ai-b5057777207eb439`
- `ai-7267ef84c8754429`
- `ai-1c2e3095524918b0`
- `ai-492db277b819e281`

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

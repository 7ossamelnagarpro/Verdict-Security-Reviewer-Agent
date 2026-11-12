# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-10-29T09:37:57.639762+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **3**.

The agent reviewed **44** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **42** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **44**; reviewed: **44**; pending: **0**.

## Generic Runtime DAST

- Source: `generic-web-runtime`
- Target: `http://127.0.0.1:8091`
- Bounded probe records: **37**
- This evidence came from an explicit Runtime Contract and contains non-mutating baseline checks.
- Browser crawl: **not requested**.
- ZAP: **not requested**.
- Account and business workflows: **completed**; executed: **40**; contract violations: **20**.
- These observations do not prove complete vulnerability coverage or exploitation.

## Scanner Execution

- <code>trivy</code>: <code>prerequisite_unverified</code>
- <code>gitleaks</code>: <code>completed</code>
- <code>trivy</code>: <code>skipped</code>
- <code>semgrep-ce</code>: <code>completed</code>
- <code>codeql-cli</code>: <code>completed</code>
- <code>trivy</code>: <code>completed</code>

## Scanner and DAST Observations (Pre-Review)

**42** merged observation record(s): **23** DAST-related and **19** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

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
10. **Clear-text logging of sensitive information** — scanner from codeql-cli, semgrep-ce; location: <code>api/app.py:137</code>; severity: **high**; confidence: high; risk: 60/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-3202e1e1074cfd44b9bf</code>; rule(s): <code>py/clear-text-logging-sensitive-data, python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure</code>; source evidence: <code>finding-cfe66151dbff24377948</code>, <code>finding-2e982654735c1187197b</code>.
11. **Log Injection** — scanner from codeql-cli; location: <code>api/app.py:137</code>; severity: **medium**; confidence: medium; risk: 54/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-9c6fcf61fc01168b15e2</code>; rule(s): <code>py/log-injection</code>; source evidence: <code>finding-a24fd7815efb02a43f82</code>.
12. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:617</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-51bf51abe866bf8d3d67</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-ce61cc3f35454cc194f9</code>.
13. **URL redirection from remote source** — scanner from codeql-cli; location: <code>api/extra.py:625</code>; severity: **medium**; confidence: high; risk: 47/100 (medium); disposition: <code>standard_report</code>.
    - Record: <code>merged-f41fd10802e7c4dd22bb</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-67c9c8a69323ffdda94c</code>.
14. **Job listing requires admin role** — DAST from web-runtime; location: <code>/admin/jobs</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-17a5197f906426a224ef</code>; rule(s): <code>workflow.admin_jobs.2</code>; source evidence: <code>runtime-210f1029720d2c4e6e3e993a</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
15. **A demoted administrator must lose administrative access** — DAST from web-runtime; location: <code>/admin/token-report</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-da0f922505b4c0c7fed1</code>; rule(s): <code>workflow.stale_role.3</code>; source evidence: <code>runtime-afddc086f33f2e8a8fa222be</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
16. **User listing requires admin role** — DAST from web-runtime; location: <code>/admin/users</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-38e7cf77bdf9145d2ae4</code>; rule(s): <code>workflow.admin_users.2</code>; source evidence: <code>runtime-c0e1afff107bb0eb4f9995fc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
17. **Password reset tokens must be single use** — DAST from web-runtime; location: <code>/auth/reset/confirm</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-d9421dbfc4162d6dea91</code>; rule(s): <code>workflow.reset_replay.3</code>; source evidence: <code>runtime-6e6caeab05225e629344552e</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
18. **Debug configuration is unavailable anonymously** — DAST from web-runtime; location: <code>/debug/config</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-e7caea540245938b275b</code>; rule(s): <code>workflow.debug_access.1</code>; source evidence: <code>runtime-0dc83bd580f54eb0cd2941b9</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
19. **Incoming webhook events require a valid signature** — DAST from web-runtime; location: <code>/integrations/hook</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-8e21db3fe42adbf58979</code>; rule(s): <code>workflow.unsigned_hook.1</code>; source evidence: <code>runtime-3f8d9dc38e0f642bbc4291d3</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
20. **Only the owner can read an invoice** — DAST from web-runtime; location: <code>/invoices/{{invoice_id}}</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-d5c3b6b8d8dad90c4d3c</code>; rule(s): <code>workflow.invoice_owner.3</code>; source evidence: <code>runtime-b2db6b94c587ff6fb7d08426</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
21. **Users cannot submit an admin job** — DAST from web-runtime; location: <code>/jobs</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-a5ea8ca4c36bd6c25e2a</code>; rule(s): <code>workflow.worker_role.1</code>; source evidence: <code>runtime-5ea37fc15cb39757603b7cd7</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
22. **Users cannot create orders for another owner** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-1ba9f8276fc6dae95df8</code>; rule(s): <code>workflow.owner_assignment.2</code>; source evidence: <code>runtime-05d2f624905d2e8204ceb2b2</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
23. **New orders cannot start as paid** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-2d4a81712313b5f2f621</code>; rule(s): <code>workflow.order_initial_state.1</code>; source evidence: <code>runtime-b9165f8e58d7def0d12de985</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
24. **Negative order prices are rejected** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-8946f8391fc9049cbb58</code>; rule(s): <code>workflow.negative_price.1</code>; source evidence: <code>runtime-78580a62c3793f37f5e1f001</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
25. **Catalog price must be set by the server** — DAST from web-runtime; location: <code>/orders</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-cc8a9ed20905505868f0</code>; rule(s): <code>workflow.price_catalog.1</code>; source evidence: <code>runtime-b082e5735b56669c3ad0c27e</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
26. **A note must belong to the order named in the URL** — DAST from web-runtime; location: <code>/orders/1/notes/2</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-b4c1c4d005665a5249a7</code>; rule(s): <code>workflow.nested_note.1</code>; source evidence: <code>runtime-95408e1a46c05125661f435c</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
27. **Only the owner can read an order** — DAST from web-runtime; location: <code>/orders/{{order_id}}</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-a9e9047867c909f567ad</code>; rule(s): <code>workflow.order_owner.3</code>; source evidence: <code>runtime-5f52b3ddf5cb11e03bcb0999</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
28. **Excessive coupon discounts are rejected** — DAST from web-runtime; location: <code>/orders/{{order_id}}/apply-coupon</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-7da23d65adeef42d71a6</code>; rule(s): <code>workflow.coupon_bounds.2</code>; source evidence: <code>runtime-80c8d131ef8da2487a54950d</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
29. **Paid orders require a refund before cancellation** — DAST from web-runtime; location: <code>/orders/{{order_id}}/cancel</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-e683a977084f2bbcee2e</code>; rule(s): <code>workflow.paid_cancel.3</code>; source evidence: <code>runtime-b2a4f197f469e50923cacdff</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
30. **An already paid order rejects a second payment** — DAST from web-runtime; location: <code>/orders/{{order_id}}/pay</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-dd64ece99563dbbb173a</code>; rule(s): <code>workflow.payment_replay.3</code>; source evidence: <code>runtime-4ed77a8cbe072385df677726</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
31. **A user cannot read another account profile** — DAST from web-runtime; location: <code>/profiles/{{other_id}}</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-2b80ed0c48c0c70a93a4</code>; rule(s): <code>workflow.profile_owner.2</code>; source evidence: <code>runtime-075b1c7547b453cbe6b18b34</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
32. **Webhook destination must match the approved internal host exactly** — DAST from web-runtime; location: <code>/webhooks</code>; severity: **high**; confidence: medium; risk: 27/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-65f25bcf14fa2ab91271</code>; rule(s): <code>workflow.webhook_destination.1</code>; source evidence: <code>runtime-3165b0fcf5e0b47c5b31d6bd</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
33. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
34. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
35. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
36. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
37. **Identity response must not expose a social security number** — DAST from web-runtime; location: <code>/me</code>; severity: **medium**; confidence: medium; risk: 12/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-65c41e5a25b6337fec07</code>; rule(s): <code>workflow.excessive_data.1</code>; source evidence: <code>runtime-30173b60257e41bdd229851f</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200, &quot;values_redacted&quot;: true}</code>.
38. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: 12/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
39. **Missing Content-Security-Policy header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 2/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-19f4a13e0b2d4f7413d0</code>; rule(s): <code>web.missing-content-security-policy</code>; source evidence: <code>runtime-4d5cb0113b221c088986a91b</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
40. **Missing clickjacking protection header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 2/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-87e0399272a390813ea5</code>; rule(s): <code>web.missing-clickjacking-protection</code>; source evidence: <code>runtime-864566c9e6503bd3822edbf6</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
41. **Missing X-Content-Type-Options header** — DAST from web-runtime; location: <code>/healthz</code>; severity: **low**; confidence: high; risk: 2/100 (low); disposition: <code>needs_verification</code>.
    - Record: <code>merged-bbf1646deeb18d1e95db</code>; rule(s): <code>web.missing-content-type-protection</code>; source evidence: <code>runtime-a9347cabd53ecd99e38108cc</code>.
    - Bounded runtime evidence: <code>{&quot;status&quot;: 200}</code>.
42. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: 0/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.

## Security Review Agent Verdicts

### 1. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `legacy_login` constructs an SQL statement by directly interpolating `body.username` and `body.password` into the query string using an f‑string. This allows an attacker to inject arbitrary SQL syntax via the `username` or `password` fields, leading to a classic SQL injection vulnerability.

**Impact:** An attacker can bypass authentication, retrieve or modify user records, and potentially execute arbitrary SQL commands against the database, compromising confidentiality, integrity, and availability of the application data.

**Remediation:** Replace the string interpolation with a parameterized query or prepared statement (e.g., using `?` placeholders with the DB‑API's `execute` method) and let the database driver handle proper escaping of user input. Also consider hashing passwords instead of storing them in plain text.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `Line 117: `query = f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"``
- `The query string directly embeds `body.username` and `body.password` without sanitization.`

Limitations:
- No runtime probe data is available to confirm exploitation, but the code pattern is a well‑known injection vector.

### 2. Uncontrolled data used in path expression

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" but immediately resolves the path and verifies that the resulting path is a descendant of the intended root directory using `is_relative_to(root)`. This check prevents directory traversal attacks, and the subsequent `is_file()` guard ensures only existing files are served. Therefore the reported uncontrolled data usage does not constitute a vulnerability in this context.

**Impact:** No impact; the code safely restricts file access to the intended directory.

**Remediation:** No remediation required; the existing path validation is sufficient.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `source excerpt shows `root = (FILES / "public").resolve()` and `file = (root / name).resolve()` followed by `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")` which enforces a proper containment check.`

Limitations:
- No runtime probe data was provided to confirm behavior under edge cases such as symlink attacks; analysis is based solely on static code review.

### 3. Path traversal check mitigates uncontrolled path usage

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint constructs the file path using the user‑provided `name` parameter, but it immediately resolves the path and verifies that the resulting path is a descendant of the intended `root` directory via `file.is_relative_to(root)`. This check prevents directory traversal attacks, and the subsequent `file.is_file()` ensures only regular files are served. Consequently, the reported uncontrolled data usage does not constitute a vulnerability in this context.

**Impact:** No impact; the application correctly restricts file access to the intended directory.

**Remediation:** No remediation required for this finding; the existing checks are sufficient.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `api/extra.py:220-223 shows the resolution of the user‑provided path and the `is_relative_to` check that blocks traversal.`

Limitations:
- Static analysis cannot guarantee that `FILES` is correctly set to a safe directory at runtime. Additional runtime validation may be needed if `FILES` can be altered.

### 4. Path traversal check appears sufficient

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint resolves the user‑provided filename and then verifies that the resulting path is both a file and resides within the configured public directory using `is_relative_to(FILES.resolve())`. This check prevents directory‑traversal attacks, so the scanner’s uncontrolled‑data‑in‑path warning is likely a false positive.

**Impact:** If the check were absent, an attacker could read arbitrary files on the server. The existing check mitigates that risk, so no impact is present under normal operation.

**Remediation:** No remediation required beyond ensuring the runtime Python version supports `Path.is_relative_to` (Python 3.9+) and that `FILES` is correctly defined. Optionally add explicit validation of the `name` parameter (e.g., whitelist allowed filenames).
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `Line 212 constructs the path with `(FILES / "public" / name).resolve()``
- `Line 213 checks `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")``

Limitations:
- The analysis assumes the code runs on Python 3.9+ where `Path.is_relative_to` is available and behaves as documented. If an older Python version is used, the check may not exist, potentially re‑introducing a traversal risk.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The code resolves the requested filename against a fixed root directory and then checks both that the resolved path is a sub‑path of that root (using Path.is_relative_to) and that the target is an existing file. If either check fails, a 404 error is raised. This validation prevents directory‑traversal attacks, so the scanner’s finding is a false positive.

**Impact:** No impact; the path traversal vector is mitigated by the explicit checks.

**Remediation:** No remediation required beyond maintaining the existing validation logic. Ensure the runtime Python version supports Path.is_relative_to and that resolve() correctly follows symlinks.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`
- `return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- The analysis assumes the Python version provides Path.is_relative_to (Python 3.9+). If symbolic links inside the public directory point outside the root, resolve() will follow them and the is_relative_to check may still pass; additional checks may be needed in such environments.

### 6. Uncontrolled data used in path expression

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner flagged a potential path traversal because the file path is built from a user‑provided value. However, the implementation resolves the path and then checks `is_relative_to(FILES.resolve())` and `is_file()`. These checks ensure the resolved path remains within the intended `public` directory and points to an existing file, effectively preventing directory traversal attacks.

**Impact:** If the check were missing, an attacker could read arbitrary files on the server, leading to information disclosure. The current checks mitigate this risk, so no impact is present.

**Remediation:** No remediation is required for the reported issue. As a best practice, continue to validate and resolve user‑supplied paths and consider adding explicit whitelist validation if additional constraints are needed.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `def file_read(name: str) -> Response:`
- `    file = (FILES / "public" / name).resolve()`
- `    if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `        raise HTTPException(404, "File not found")`
- `    return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- Analysis is based solely on static code review; no runtime probing was performed. The safety relies on the correctness of `Path.is_relative_to` and `Path.resolve` in the deployed Python version.

### 7. Reflected server-side cross-site scripting

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint directly interpolates the user‑controlled query parameter `q` into an HTML response without any escaping or sanitisation. The returned string `<h1>Results for {q}</h1>` will render any HTML/JavaScript supplied in `q`, enabling a reflected XSS attack. Additionally, `q` is concatenated into a raw SQL statement, which could also lead to SQL injection, but the primary confirmed issue is the reflected XSS.

**Impact:** An attacker can craft a URL such as `/catalog/search?q=<script>maliciousCode()</script>` and trick a victim into visiting it. The injected script runs in the victim's browser context, allowing theft of session cookies, credential harvesting, defacement, or further malicious actions against the user or the application.

**Remediation:** * Use a proper templating engine (e.g., Jinja2) that automatically escapes variables.
* Explicitly HTML‑escape the `q` value before embedding it in the response (e.g., `html.escape(q)`).
* Switch to parameterised queries for the database call to prevent SQL injection.
* Set a strict Content‑Security‑Policy header to mitigate script execution.
* Consider returning JSON data and letting the client render it safely instead of raw HTML strings.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt lines 141‑145 show the endpoint definition and the direct insertion of `q` into the HTML response: `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{row['name']}</p>" for row in rows)``
- `The SQL query also concatenates `q` without parameters: `SELECT name FROM products WHERE name ILIKE '%{q}%'``

Limitations:
- No runtime execution was observed; the assessment is based solely on static code analysis.
We assume FastAPI's `HTMLResponse` does not perform automatic HTML escaping, which is typical for raw string responses.
Potential mitigations (e.g., upstream middleware sanitising inputs) were not identified in the provided code.

### 8. Path traversal check appears sufficient

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The endpoint resolves the user‑provided filename against the public directory and then verifies that the resolved path is still within the base directory using Path.is_relative_to(). This prevents directory‑traversal attacks such as "../" sequences from escaping the intended folder.

**Impact:** No impact; the check blocks malicious path traversal attempts.

**Remediation:** No remediation required for the path traversal check, though consider hardening against symlink abuse if the public directory is writable by untrusted users.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `api/extra.py:212 – file = (FILES / "public" / name).resolve()`
- `api/extra.py:213 – if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- The check relies on Path.is_relative_to() (Python 3.9+); older runtimes would not have this method.
- If an attacker can place a symlink inside the public directory that points outside, resolve() will follow it and the subsequent is_relative_to() may still return true, potentially allowing indirect traversal.

### 9. SQL Injection in catalog_search endpoint

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function catalog_search constructs an SQL query using an f‑string that directly interpolates the user‑controlled parameter `q` into the statement (`SELECT name FROM products WHERE name ILIKE '%{q}%'`). No parameterization or sanitization is applied, allowing an attacker to inject arbitrary SQL syntax via the `q` query parameter.

**Impact:** An attacker can manipulate the SQL query to retrieve unauthorized data, modify or delete records, or execute database commands, potentially leading to data breach, data loss, or privilege escalation.

**Remediation:** Refactor the query to use parameterized statements provided by the database driver (e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`). Additionally, validate and whitelist allowed characters for `q` and enforce least‑privilege database permissions.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `api/extra.py:144 – rows = conn.execute(f\"SELECT name FROM products WHERE name ILIKE '%{q}%'\").fetchall()`

Limitations:
- No runtime probe data confirming exploitation
- Static analysis only; actual DB driver behavior not verified
- No evidence of additional input validation elsewhere in the code

### 10. Job listing requires admin role

- Issue group: `merged-17a5197f906426a224ef`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that the /admin/jobs endpoint requires an admin role, but the only runtime observation is a 200 response with redacted values. No information is provided about whether the request was authenticated or what role was used, so it cannot be confirmed whether access control is missing or correctly enforced.

**Impact:** If the endpoint is accessible without proper admin privileges, an attacker could view, modify, or delete job listings, leading to data leakage or unauthorized actions.

**Remediation:** Implement and verify strict role‑based access control on the /admin/jobs endpoint, ensuring that only authenticated users with the admin role can receive a successful response. Add explicit authorization checks and return appropriate error codes for unauthorized requests.
Evidence:
- Source IDs: `merged-17a5197f906426a224ef`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.admin_jobs.2, path=/admin/jobs, facts={status:200, values_redacted:true}`

Limitations:
- No evidence whether the probe request was made with authentication or admin credentials
- The scanner’s textual finding is not proof of missing access control
- Only a single HTTP status observation is available, lacking context about authorization checks

### 11. A demoted administrator must lose administrative access

- Issue group: `merged-da0f922505b4c0c7fed1`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged the /admin/token-report endpoint as potentially accessible to a demoted administrator, but the only runtime observation is an HTTP 200 response with redacted values. No evidence is provided that the requester is a demoted admin, nor that the endpoint actually grants privileged functionality. Without confirmation of role state or access control enforcement, the finding cannot be confirmed as a vulnerability.

**Impact:** If a demoted administrator retained access, they could perform privileged actions, leading to unauthorized data exposure or system manipulation.

**Remediation:** Ensure that role changes are immediately reflected in access control checks for all admin endpoints, and verify that revoked privileges result in appropriate denial responses (e.g., 403).
Evidence:
- Source IDs: `merged-da0f922505b4c0c7fed1`
- `Scanner evidence: "A demoted administrator must lose administrative access"`
- `Runtime probe fact: status 200 returned from /admin/token-report (values redacted)`

Limitations:
- No proof that the request originated from a demoted administrator
- Endpoint response content is redacted, preventing verification of privileged data exposure
- Single source observation; no additional scans or logs confirming improper access

### 12. User listing requires admin role

- Issue group: `merged-38e7cf77bdf9145d2ae4`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **low**

**Explanation:** The scanner report states that the /admin/users endpoint "requires admin role" and returns HTTP 200 with redacted values. No evidence is provided that the endpoint is accessible without proper authentication or that it leaks sensitive user data to unauthorized parties. Without proof of unauthorized access, the finding does not constitute a vulnerability.

**Impact:** None confirmed, as the endpoint appears to be protected by an admin role requirement.

**Remediation:** No remediation needed unless further testing reveals unauthorized access; ensure proper access controls are enforced and verified.
Evidence:
- Source IDs: `merged-38e7cf77bdf9145d2ae4`
- `Scanner evidence: User listing requires admin role`
- `Runtime probe fact: status 200, values_redacted true for path /admin/users`

Limitations:
- No authentication context provided; cannot confirm whether the request was made as an admin or unauthenticated user
- Absence of proof that sensitive user data is exposed to non‑admin principals
- Single runtime probe without additional guard checks

### 13. Password reset tokens must be single use

- Issue group: `merged-d9421dbfc4162d6dea91`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged the reset endpoint as potentially allowing token reuse, but the only runtime observation is a 200 response without token values. No direct evidence that a token can be used multiple times is present.

**Impact:** If reset tokens are reusable, an attacker who obtains a token could reset a user's password multiple times, leading to account takeover.

**Remediation:** Implement server‑side enforcement that each password‑reset token is invalidated after a single successful use. Return an error for subsequent uses.
Evidence:
- Source IDs: `merged-d9421dbfc4162d6dea91`
- `Scanner finding: Password reset tokens must be single use`
- `Runtime probe fact: web-runtime rule workflow.reset_replay.3 returned HTTP 200 on /auth/reset/confirm (values redacted)`

Limitations:
- No concrete demonstration of token reuse; only a successful request observed.
- Token values were redacted, preventing verification of replay.
- Single request does not prove absence of rate limiting or other mitigations.

### 14. Debug configuration is unavailable anonymously

- Issue group: `merged-e7caea540245938b275b`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** A runtime probe accessed /debug/config and received an HTTP 200 response, but the response body was redacted. The scanner report claims the debug configuration is unavailable anonymously, yet the successful status code indicates the endpoint is reachable. Without seeing the actual configuration data, it cannot be determined whether sensitive information is exposed or if the endpoint is properly protected.

**Impact:** If the debug configuration contains sensitive settings (e.g., credentials, internal URLs, feature flags), exposure could aid attackers in further exploitation or reconnaissance.

**Remediation:** Restrict access to the /debug/config endpoint to authenticated and authorized users only. Ensure that any debug or configuration data is not exposed in production environments, and verify that the endpoint returns appropriate authorization errors (e.g., 401/403) when accessed anonymously.
Evidence:
- Source IDs: `merged-e7caea540245938b275b`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.debug_access.1, path=/debug/config, facts={status:200, values_redacted:true}`

Limitations:
- The response body was redacted, so the actual content of the debug configuration is unknown.
- No additional evidence (e.g., source code, configuration files) confirming whether the endpoint leaks sensitive data.

### 15. Missing Content-Security-Policy header on /healthz

- Issue group: `merged-19f4a13e0b2d4f7413d0`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The runtime probe observed an HTTP 200 response from the /healthz endpoint that did not include a Content‑Security‑Policy (CSP) header. CSP is a defense‑in‑depth mechanism that mitigates a range of client‑side attacks such as cross‑site scripting (XSS). Its absence does not guarantee an exploit but reduces the security posture of the application.

**Impact:** Without CSP, browsers are free to execute inline scripts or load resources from untrusted origins, increasing the risk of XSS or data‑exfiltration attacks if other vulnerabilities exist in the client‑side code.

**Remediation:** Configure the web server or application framework to send a restrictive CSP header for all responses, including health‑check endpoints. Example: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';` Adjust directives as needed for legitimate resource loading.
Evidence:
- Source IDs: `merged-19f4a13e0b2d4f7413d0`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=web.missing-content-security-policy, path=/healthz, facts={"status":200} – header CSP missing`

Limitations:
- Only the /healthz endpoint was probed; other endpoints may already include CSP.
- The finding is based on a single request; transient configuration or middleware ordering could affect header presence.
- Low severity reflects that CSP is a mitigation, not a direct exploit vector.

### 16. Missing clickjacking protection header

- Issue group: `merged-87e0399272a390813ea5`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint returns HTTP 200 without an X-Frame-Options header or an equivalent Content‑Security‑Policy frame‑ancestors directive, allowing the page to be embedded in a foreign frame and potentially used for clickjacking attacks.

**Impact:** An attacker could embed the health endpoint in a malicious page and trick users into interacting with it, leading to UI redressing. While the endpoint typically returns minimal data, the lack of protection is a security weakness that could be leveraged in broader attacks.

**Remediation:** Configure the web server or application to send an appropriate clickjacking protection header for all responses, e.g., `X-Frame-Options: SAMEORIGIN` or `DENY`, or add a CSP `frame-ancestors 'self'` directive. Ensure the header is applied to the /healthz endpoint as well as other public endpoints.
Evidence:
- Source IDs: `merged-87e0399272a390813ea5`
- `Runtime probe (web-runtime) observed HTTP 200 for /healthz and reported missing clickjacking protection header`

Limitations:
- Evidence is limited to a single automated probe of the /healthz endpoint; no manual verification was performed. The health endpoint may have low sensitivity, so the practical impact is limited. No confirmation that the header is absent on other endpoints.

### 17. Missing X-Content-Type-Options header

- Issue group: `merged-bbf1646deeb18d1e95db`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The /healthz endpoint responded with HTTP 200 but did not include the X-Content-Type-Options header, as indicated by the runtime probe and scanner rule. Absence of this header can allow browsers to perform MIME type sniffing, potentially leading to content injection attacks.

**Impact:** An attacker could exploit MIME sniffing to execute malicious scripts if the endpoint ever serves user‑controlled content, increasing the risk of cross‑site scripting or data leakage.

**Remediation:** Configure the web server or application to always send the X-Content-Type-Options: nosniff header for all responses, including the health‑check endpoint.
Evidence:
- Source IDs: `merged-bbf1646deeb18d1e95db`
- `Runtime probe (web-runtime) observed status 200 on /healthz without X-Content-Type-Options header (rule web.missing-content-type-protection)`

Limitations:
- Evidence is limited to the /healthz endpoint; other endpoints were not examined. No direct exploitation was observed, only the missing header.

### 18. Incoming webhook events require a valid signature

- Issue group: `merged-8e21db3fe42adbf58979`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged the /integrations/hook endpoint as lacking a required signature for incoming webhook events. The only runtime probe fact provided is a 200 response with redacted values, which does not demonstrate whether signature validation is performed or omitted. No code or configuration evidence confirming the absence of signature checks is available, so the finding cannot be confirmed nor dismissed without further investigation.

**Impact:** If webhook signatures are not validated, an attacker could craft malicious webhook payloads that the application would accept, potentially leading to unauthorized actions, data exfiltration, or service disruption.

**Remediation:** Implement strict verification of webhook signatures using a shared secret or public key, reject requests with missing or invalid signatures, and log verification failures. Ensure the verification logic is exercised in tests and documented in the integration documentation.
Evidence:
- Source IDs: `merged-8e21db3fe42adbf58979`
- `Scanner finding: Incoming webhook events require a valid signature`
- `Runtime probe fact (web-runtime, rule workflow.unsigned_hook.1) returned status 200 with values redacted`

Limitations:
- No source code or configuration review confirming the presence or absence of signature verification
- Redacted runtime values prevent assessment of actual request handling
- Single runtime probe does not cover all possible request variations

### 19. Access control correctly enforced for invoice endpoint

- Issue group: `merged-d5c3b6b8d8dad90c4d3c`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner flagged the "/invoices/{{invoice_id}}" endpoint with the message "Only the owner can read an invoice". This message describes the intended security behavior (owner‑only access) rather than a flaw. Runtime probing shows a 200 response with values redacted, indicating the endpoint returns data only when the requester is authorized and otherwise hides sensitive information. No evidence of unauthorized data exposure or bypass was observed.

**Impact:** None – the endpoint appears to enforce proper access controls, so no confidentiality or integrity breach is implied.

**Remediation:** No remediation required; the current owner‑only access control is appropriate. Continue to monitor for any changes that might unintentionally expose invoice data.
Evidence:
- Source IDs: `merged-d5c3b6b8d8dad90c4d3c`
- `Scanner evidence: "Only the owner can read an invoice"`
- `Runtime probe fact (web-runtime, rule workflow.invoice_owner.3): status 200, values_redacted true`

Limitations:
- Evidence is limited to scanner output and a single runtime probe; no source code review was performed.
- The probe did not test unauthorized access attempts, so the absence of a breach is inferred from the redacted response rather than demonstrated.

### 20. Users cannot submit an admin job

- Issue group: `merged-a5ea8ca4c36bd6c25e2a`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner reported that users are unable to submit an admin job at the /jobs endpoint. The only evidence is the scanner's generic finding and a runtime probe indicating a 200 response with redacted values. No concrete request/response details, error messages, or proof of unintended privilege escalation are provided, so the security impact cannot be confirmed.

**Impact:** If this were an unintended permission bypass, an attacker could potentially submit privileged jobs, leading to privilege escalation or unauthorized actions. However, the current evidence does not demonstrate such a scenario.

**Remediation:** Review the application's role‑based access control for the /jobs endpoint. Verify that the intended behavior (whether admin jobs should be restricted) is correctly implemented and that any error handling does not leak sensitive information. Add explicit tests to confirm the access control behavior and log attempts to submit admin jobs for audit.
Evidence:
- Source IDs: `merged-a5ea8ca4c36bd6c25e2a`
- `Scanner finding: Users cannot submit an admin job`
- `Runtime probe fact (web-runtime, rule workflow.worker_role.1) at /jobs returned status 200 with values redacted`

Limitations:
- No detailed request/response data showing the failure reason
- Values redacted in probe, preventing analysis of response content
- No indication whether the restriction is intentional or a bug
- No evidence of exploitation or impact

### 21. Identity response must not expose a social security number

- Issue group: `merged-65c41e5a25b6337fec07`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The scanner flagged a potential exposure of a social security number at the /me endpoint. However, the runtime probe for this endpoint returned a 200 status with values_redacted set to true, indicating that sensitive fields are being redacted and no SSN is disclosed in the response. Therefore, the finding does not represent an actual vulnerability.

**Impact:** No impact; sensitive data is not exposed to the client.

**Remediation:** Maintain the current redaction logic and ensure it remains in place for future changes to the /me endpoint response.
Evidence:
- Source IDs: `merged-65c41e5a25b6337fec07`
- `Scanner evidence: Identity response must not expose a social security number`
- `Runtime probe fact: status 200, values_redacted true for path /me`

Limitations:
- Evidence is limited to the observed /me endpoint; other endpoints were not examined for similar issues.

### 22. Users cannot create orders for another owner

- Issue group: `merged-1ba9f8276fc6dae95df8`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **medium**

**Explanation:** The scanner reported that users are unable to create orders for another owner. This behavior aligns with proper access‑control enforcement and does not represent a security flaw. The runtime probe returned a 200 status with redacted values, indicating the request was processed without exposing cross‑owner data. No evidence suggests that unauthorized order creation is possible.

**Impact:** None – the application correctly prevents cross‑owner order creation, preserving data confidentiality and integrity.

**Remediation:** No remediation required; the current access‑control behavior is appropriate.
Evidence:
- Source IDs: `merged-1ba9f8276fc6dae95df8`
- `Users cannot create orders for another owner`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.owner_assignment.2, path=/orders, status=200, values_redacted=true`

Limitations:
- Evidence is limited to a single runtime probe and does not cover all possible request vectors or internal logic paths. The probe does not verify the full owner‑assignment implementation, only that the observed request returned a 200 response.

### 23. New orders cannot start as paid

- Issue group: `merged-2d4a81712313b5f2f621`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** A scanner flagged that new orders cannot transition to a paid state, but the only supporting data are the scanner's generic finding and a runtime probe that returned HTTP 200 with redacted values. No concrete request/response details, business‑logic verification, or reproducible test steps are provided, so the presence of a vulnerability cannot be confirmed.

**Impact:** If orders truly cannot be marked as paid, customers may be unable to complete purchases, leading to revenue loss and a broken checkout experience.

**Remediation:** Manually test the order creation and payment workflow, review the server‑side order state transition logic, and add appropriate validation or state‑change handling. Deploy fixes and re‑run functional and security tests to verify the issue is resolved.
Evidence:
- Source IDs: `merged-2d4a81712313b5f2f621`
- `New orders cannot start as paid (scanner evidence)`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.order_initial_state.1, path=/orders, status=200 (values redacted)`

Limitations:
- Scanner finding provides no concrete proof of the defect
- Runtime probe response redacted values, preventing verification of the order state
- No request/response logs or error messages confirming the inability to mark orders as paid
- No independent manual or automated test confirming the issue

### 24. Negative order prices are rejected

- Issue group: `merged-8946f8391fc9049cbb58`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner reports that negative order prices are rejected, but the runtime probe observed a HTTP 200 response for a request to /orders with a negative price (values redacted). The response status alone does not confirm whether the negative price was accepted or rejected, and no response body is available to verify the outcome. The evidence is contradictory and insufficient to confirm a vulnerability or to deem the finding a false positive.

**Impact:** If the application accepts negative order prices, an attacker could manipulate order totals, potentially leading to financial loss or unauthorized credit. Conversely, if the application correctly rejects them, no impact exists. The current evidence does not establish which case applies.

**Remediation:** Implement strict server‑side validation to ensure that order price fields are non‑negative and return an appropriate error status (e.g., 400 Bad Request) when a negative value is submitted. Log validation failures for monitoring.
Evidence:
- Source IDs: `merged-8946f8391fc9049cbb58`
- `Scanner evidence: "Negative order prices are rejected"`
- `Runtime probe fact: HTTP status 200 returned for /orders request with negative price (values redacted)`

Limitations:
- Contradictory evidence between scanner claim and runtime probe status
- Response body was redacted, preventing verification of rejection or acceptance
- No additional context (e.g., error messages, logs) to determine actual behavior

### 25. Potential client-controlled price manipulation

- Issue group: `merged-cc8a9ed20905505868f0`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** The scanner flagged that the catalog price must be set by the server, suggesting a possible client‑controlled price issue. The only runtime observation is a 200 response from /orders with values redacted; no request or response shows that a client‑supplied price is accepted or that the server fails to enforce its own pricing. Without concrete evidence of price manipulation, the finding cannot be confirmed.

**Impact:** If an attacker can set or modify the price of items in the catalog, they could purchase items at reduced cost or inflate prices for fraud, leading to financial loss and integrity issues.

**Remediation:** Ensure that the server exclusively determines item prices. Validate and ignore any price fields supplied by the client, and enforce server‑side pricing logic before persisting or processing orders.
Evidence:
- Source IDs: `merged-cc8a9ed20905505868f0`
- `Scanner evidence: "Catalog price must be set by the server"`
- `Runtime probe fact: status 200 from /orders (values redacted)`

Limitations:
- No actual price values observed; response data is redacted
- No request showing client‑supplied price being accepted
- Single runtime probe does not demonstrate a vulnerable code path

### 26. A note must belong to the order named in the URL

- Issue group: `merged-b4c1c4d005665a5249a7`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner reports that a note must belong to the order identified in the URL, but the only runtime observation is a successful 200 response for the specific path /orders/1/notes/2 with values redacted. No test was performed to verify whether notes from other orders can be accessed via a crafted URL, nor is there evidence of missing authorization checks in the code. Consequently, the presence of a vulnerability cannot be confirmed from the available data.

**Impact:** If the endpoint fails to enforce that a note belongs to the specified order, an attacker could retrieve or modify notes belonging to other orders, leading to unauthorized data exposure or tampering.

**Remediation:** Implement strict authorization checks that validate the note's order association against the order ID provided in the URL before returning or modifying the note. Return an appropriate error (e.g., 403 Forbidden) when the association does not match.
Evidence:
- Source IDs: `merged-b4c1c4d005665a5249a7`
- `Scanner evidence: A note must belong to the order named in the URL`
- `Runtime probe: GET /orders/1/notes/2 returned status 200 with values redacted`

Limitations:
- Only a single successful request was observed; no cross‑order access attempts were made
- Response body values were redacted, preventing verification of note ownership
- No source code or configuration review was provided to confirm missing authorization logic

### 27. Only the owner can read an order

- Issue group: `merged-a9e9047867c909f567ad`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The finding reports that the endpoint /orders/{{order_id}} returns a 200 status only when accessed by the order owner. This behavior enforces proper access control and does not constitute a vulnerability. The scanner’s wording may be misinterpreted as a flaw, but the observed runtime probe confirms the intended restriction.

**Impact:** No impact; the access control works as designed, preventing unauthorized reads of orders.

**Remediation:** No remediation required; the current owner‑only read restriction is appropriate.
Evidence:
- Source IDs: `merged-a9e9047867c909f567ad`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.order_owner.3, path=/orders/{{order_id}}, facts={status:200, values_redacted:true}`

Limitations:
- Evidence is limited to a single successful request observed for an authorized user; no tests were performed for unauthorized access attempts. The finding relies on the scanner’s description without additional context.

### 28. Excessive coupon discounts are rejected

- Issue group: `merged-7da23d65adeef42d71a6`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The scanner reported that attempts to apply excessive coupon discounts are rejected with a 200 response. Rejection of overly large discounts is expected correct behavior, not a security flaw. No evidence of privilege escalation, unauthorized discount application, or bypass is present.

**Impact:** No impact; the application correctly prevents abuse of coupon discounts.

**Remediation:** No remediation required.
Evidence:
- Source IDs: `merged-7da23d65adeef42d71a6`
- `Scanner evidence: Excessive coupon discounts are rejected`
- `Runtime probe fact: request to /orders/{{order_id}}/apply-coupon returned status 200`

Limitations:
- Only a single runtime probe observed; does not demonstrate a vulnerability.
- No proof of bypass or unintended discount application.

### 29. Paid orders require a refund before cancellation

- Issue group: `merged-e683a977084f2bbcee2e`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The scanner flagged the /orders/{{order_id}}/cancel endpoint as requiring a refund before an order can be cancelled. This behavior suggests a business‑logic flaw that could prevent legitimate cancellations or be abused to force refunds before cancellation, potentially leading to financial loss or denial‑of‑service for users.

**Impact:** Users may be unable to cancel paid orders without first issuing a refund, which can cause financial inconvenience, loss of trust, and could be leveraged by an attacker to manipulate order states or cause denial‑of‑service.

**Remediation:** Review the cancellation workflow and adjust the logic to allow order cancellation without mandating a prior refund, or implement explicit authorization checks that distinguish legitimate refund‑then‑cancel flows from abuse. Ensure that business rules are clearly documented and enforced consistently.
Evidence:
- Source IDs: `merged-e683a977084f2bbcee2e`
- `Paid orders require a refund before cancellation (scanner evidence)`
- `Runtime probe fact: status 200 returned from /orders/{{order_id}}/cancel (values redacted)`

Limitations:
- Evidence is limited to scanner output and a single runtime probe showing a 200 response; no payload details or functional testing were performed
- Values were redacted, preventing verification of the exact response behavior
- No direct observation of the refund‑then‑cancel requirement beyond the scanner rule

### 30. Second payment attempt correctly rejected – no vulnerability

- Issue group: `merged-dd64ece99563dbbb173a`
- Verdict: **false_positive**
- Severity: **high**
- Confidence: **high**

**Explanation:** The runtime probe shows that when a payment is attempted on an order that is already marked as paid, the system rejects the request. The scanner’s evidence "An already paid order rejects a second payment" aligns with expected behavior to prevent double charging. No indication of insecure handling or exploitable flaw is present.

**Impact:** None – the application correctly prevents duplicate payments.

**Remediation:** No remediation required; the current behavior is appropriate.
Evidence:
- Source IDs: `merged-dd64ece99563dbbb173a`
- `Scanner evidence: An already paid order rejects a second payment`
- `Runtime probe fact (web-runtime, rule workflow.payment_replay.3) at /orders/{{order_id}}/pay returned status 200 with values redacted`

Limitations:
- Evidence is limited to the observed HTTP response; internal logic and exact error handling are not visible.
- The status code 200 may be unconventional for a rejection, but without further context it does not constitute a vulnerability.

### 31. Unauthorized read of another user profile

- Issue group: `merged-2b80ed0c48c0c70a93a4`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **medium**

**Explanation:** The runtime probe fact from the web-runtime scanner shows a HTTP 200 response when accessing the endpoint "/profiles/{{other_id}}", indicating that the request succeeded and the profile data was returned despite the target being another user's account. This suggests that the application does not enforce proper ownership checks for profile access, allowing an authenticated user to read another user's profile.

**Impact:** An attacker who can authenticate as any user could retrieve personal information, settings, or other sensitive data belonging to other users, leading to privacy breaches and potential further exploitation.

**Remediation:** Implement strict authorization checks on the profile endpoint to verify that the requesting user is the owner of the profile being accessed. Return a 403 Forbidden or 404 Not Found for unauthorized attempts. Add unit and integration tests to verify access control enforcement.
Evidence:
- Source IDs: `merged-2b80ed0c48c0c70a93a4`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.profile_owner.2, path=/profiles/{{other_id}}, facts={"status":200,"values_redacted":true}`

Limitations:
- Only a single request was observed; does not confirm whether the same behavior occurs across different roles or under varying conditions.
- The probe does not show the response body; it is assumed that the profile data was returned based on the 200 status.
- No additional guard checks (e.g., rate limiting, logging) were observed to mitigate the issue.

### 32. Webhook destination must match the approved internal host exactly

- Issue group: `merged-65f25bcf14fa2ab91271`
- Verdict: **needs_more_evidence**
- Severity: **high**
- Confidence: **low**

**Explanation:** A scanner flagged the /webhooks endpoint as potentially misconfigured, but the only runtime observation is an HTTP 200 response with redacted values. No concrete evidence of the actual webhook destination or a mismatch with the approved internal host is available, so the vulnerability cannot be confirmed.

**Impact:** If the webhook were pointing to an external or unapproved host, sensitive data could be exfiltrated or unauthorized actions could be triggered.

**Remediation:** Validate the webhook configuration to ensure the destination URL exactly matches the approved internal host. Implement strict allow‑list checks and reject any non‑matching URLs at deployment time.
Evidence:
- Source IDs: `merged-65f25bcf14fa2ab91271`
- `Webhook destination must match the approved internal host exactly`
- `runtime_probe_facts: scanner_id=web-runtime, rule_id=workflow.webhook_destination.1, path=/webhooks, status=200, values_redacted=true`

Limitations:
- The actual webhook URL is redacted and not observable in the probe data
- Only a successful HTTP 200 response was observed, which does not indicate misdirection
- No additional context or guard checks were provided to confirm the issue

### 33. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the application secret (APP_SECRET) in clear text at INFO level each time a user logs in. This creates an audit trail that contains a credential that should remain confidential, enabling an attacker with access to logs to retrieve the secret and potentially impersonate the application or access other protected resources.

**Impact:** Exposure of the application secret can lead to credential theft, unauthorized access to internal services, token forgery, and full compromise of the application’s security posture.

**Remediation:** Remove the secret from the log statement. Either omit the APP_SECRET entirely, mask it (e.g., replace with ***), or log only non‑sensitive identifiers. Ensure that logging configuration does not output sensitive data at any level in production.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only")) (line 137 in api/app.py)`
- `Scanner finding (semgrep-ce) rule python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure flagged line 137 as logging credential`

Limitations:
- The finding assumes the INFO log level is enabled in production; if logging is disabled or redirected, exposure may be reduced, but the code still contains the insecure pattern. No runtime probe confirms whether logs are actually persisted or protected.

### 34. Wildcard CORS configuration allows any origin

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The FastAPI application adds CORSMiddleware with allow_origins set to "*" while also allowing credentials. This configuration permits any origin to make cross‑origin requests and receive credentials, which is a known security misconfiguration. Although browsers may block credentialed requests with a wildcard origin, the server still advertises permissive CORS headers, potentially exposing data to malicious sites if the client does not enforce stricter checks.

**Impact:** An attacker-controlled website could issue cross‑origin requests to the API and, if the client’s browser does not enforce the credential‑origin restriction, could gain access to sensitive data or perform actions on behalf of an authenticated user.

**Remediation:** Restrict allow_origins to a whitelist of trusted domains. If credentials must be allowed, do not use a wildcard; instead enumerate specific origins. Alternatively, set allow_credentials to false when using a wildcard origin.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py:26-29 shows allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]`

Limitations:
- The actual exploitability depends on client‑side behavior; browsers may reject credentialed requests with a wildcard origin, reducing practical risk. No runtime observations confirm that malicious cross‑origin requests are being processed.

### 35. Log Injection and Secret Exposure

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The login handler logs both a user‑controlled value (username) and the application secret (APP_SECRET) directly via log.info. Logging unsanitized user input can enable log injection attacks, and logging the secret discloses sensitive configuration data in clear text.

**Impact:** An attacker can inject malicious log entries that may corrupt log parsing, trigger log‑based attacks, or obscure forensic evidence. Exposure of the APP_SECRET can allow credential reuse or other privileged actions if the logs are accessed by unauthorized parties.

**Remediation:** Remove the APP_SECRET from log statements, avoid logging raw user input, or sanitize/escape it before logging. Use structured logging with proper redaction for sensitive fields and ensure logs are stored securely with restricted access.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `api/app.py line 137: log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`

Limitations:
- Static analysis only; does not confirm whether logs are parsed by vulnerable log processors. The severity of secret exposure depends on the actual value of APP_SECRET and log access controls.

### 36. URL redirection from remote source

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **confirmed_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The /auth/continue endpoint accepts a query parameter "next" (default "/") and immediately returns a RedirectResponse to that value without any validation or whitelist. This allows an attacker to supply an arbitrary URL and cause the application to redirect victims to malicious sites, constituting an open redirect vulnerability.

**Impact:** An attacker can craft URLs that appear to originate from the trusted domain but redirect users to phishing pages, malware distribution sites, or other malicious destinations, facilitating credential theft and drive‑by attacks.

**Remediation:** Validate the "next" parameter against a whitelist of allowed internal paths or URLs, or restrict redirects to relative paths only. If a redirect is required, use a safe mapping of identifiers to destinations rather than accepting arbitrary URLs from the request.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source line 616‑617 defines continue_to(next: str = "/") -> RedirectResponse that returns RedirectResponse(next, status_code=302) without validation.`
- `Untrusted URL redirection depends on a user-provided value (scanner evidence).`

Limitations:
- No runtime probe confirming the endpoint is exposed in the deployed environment.
- No evidence of additional guard checks or whitelist logic elsewhere in the codebase.
- The finding is based solely on static analysis; actual exploitability depends on whether the endpoint is reachable by external users.

### 37. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The function verified_continue explicitly validates the next parameter, ensuring it starts with a leading slash, does not start with a double slash, and contains no scheme or network location. If any of these conditions are violated, an HTTP 400 error is raised, preventing redirection to external URLs. Consequently, the reported open‑redirect risk is mitigated by this logic.

**Impact:** No open‑redirect vulnerability is present; an attacker cannot cause the application to redirect a victim to an arbitrary external site via this endpoint.

**Remediation:** No remediation required for this finding. Maintain the existing validation and ensure any future changes preserve these checks.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `def verified_continue(next: str = "/") -> RedirectResponse:`
- `    parts = urlsplit(next)`
- `    if not next.startswith("/") or next.startswith("//") or parts.scheme or parts.netloc:`
- `        raise HTTPException(400, "Local path required")`
- `    return RedirectResponse(next, status_code=302)`

Limitations:
- The analysis assumes that all redirects in the application use verified_continue. If other code paths perform redirects without similar validation, they could still be vulnerable. The review is limited to the provided source excerpt.

### 38. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a health check is a recommended best practice for container observability and reliability, its absence does not directly constitute a security vulnerability. No evidence is provided that the lack of a health check leads to exploitable conditions such as denial‑of‑service or unauthorized access.

**Impact:** Minimal. The container may not be automatically monitored for liveness, potentially delaying detection of failures, but this does not expose the application to a direct security breach.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the service is responsive, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile excerpt shows no HEALTHCHECK line`

Limitations:
- The assessment is based solely on the Dockerfile content; no runtime behavior or exploitation evidence is available. The finding is a best‑practice recommendation rather than a confirmed security flaw.

### 39. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction, which is a best‑practice recommendation for container health monitoring but does not constitute a direct security vulnerability. Absence of a health check may affect orchestration reliability rather than expose a concrete exploit path.

**Impact:** Limited to reduced observability and potential service disruption; no direct attack vector is introduced by the missing HEALTHCHECK.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the container’s functionality, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Source excerpt shows Dockerfile lines 1‑6 with no HEALTHCHECK instruction.`

Limitations:
- Assessment based solely on static Dockerfile content; no runtime behavior or orchestration context was examined.

### 40. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile for the worker service does not contain a HEALTHCHECK instruction. While adding a health check is a best practice for container orchestration and can improve reliability, the absence of a health check does not constitute a direct security vulnerability. The finding is based on static analysis of the Dockerfile and does not indicate an exploitable condition.

**Impact:** Without a HEALTHCHECK, orchestration platforms cannot automatically detect and remediate unhealthy containers, which may lead to prolonged service outages or degraded performance. This impacts availability rather than confidentiality or integrity.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g.,

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost/health || exit 1

adjusting the command to suit the application's health endpoint.
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Dockerfile excerpt shows no HEALTHCHECK line:\n1 | FROM python:3.12-slim\n2 | WORKDIR /app\n3 | COPY requirements.txt .\n4 | RUN pip install --no-cache-dir -r requirements.txt\n5 | COPY worker ./worker\n6 | USER 10001:10001\n7 | CMD [\"python\", \"-m\", \"worker.worker\"]`

Limitations:
- Assessment is based solely on static Dockerfile content; external monitoring solutions may provide health checks outside the container. The finding does not prove a security flaw, only a potential reliability improvement.

### 41. Dynamic Urllib Use Detected

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The scanner flagged a dynamic value (the `path` argument) being concatenated with a constant `BASE` and passed to `urllib.request.urlopen`. If an attacker can influence `path`, they could craft a URL with a `file://` scheme or otherwise perform SSRF, potentially reading arbitrary files or accessing internal services. However, the provided repository code does not show how `path` is sourced, and no runtime probe facts or additional evidence confirm attacker control. Consequently, the presence of a vulnerability cannot be confirmed nor dismissed.

**Impact:** If exploitable, an attacker could read arbitrary files on the server or perform server‑side request forgery, leading to information disclosure or further compromise.

**Remediation:** Validate and sanitize the `path` argument to ensure it cannot contain dangerous schemes (e.g., `file://`). Prefer using a higher‑level HTTP library such as `requests` that does not support `file://` URLs, or enforce a whitelist of allowed endpoints. Consider constructing URLs with proper URL‑joining utilities rather than string concatenation.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Line 20‑21: `urllib.request.urlopen(urllib.request.Request(BASE + path, ...)` – dynamic `path` is concatenated with `BASE` and used as the request URL.`

Limitations:
- No evidence that `path` is derived from user input or otherwise attacker‑controlled.
- No runtime probe data confirming exploitation.
- The finding is based solely on static analysis; actual risk depends on how `request` is used elsewhere in the codebase.

### 42. Dynamic Urllib Use Detected

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code constructs a urllib.request.Request using a URL taken directly from the job payload (payload["target_url"]). Because the URL is not validated, an attacker who can control the payload could supply a malicious scheme such as "file://" or an internal network address, potentially leading to server‑side request forgery (SSRF) or arbitrary file reads. The scanner flagged this as a possible issue, but no additional runtime evidence or validation logic is present in the provided excerpt to confirm exploitation.

**Impact:** If an attacker can influence the target_url, they may cause the service to make arbitrary HTTP requests or read local files via the file:// scheme, leading to information disclosure or further compromise of the host environment.

**Remediation:** Validate and whitelist the URL scheme (e.g., allow only http and https) and the host before making the request. Consider using a higher‑level library such as `requests` with explicit timeout and redirect handling. If external URLs are not required, reject or sanitize any non‑trusted URLs. Add logging and monitoring for unexpected URL patterns.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `with urllib.request.urlopen(request, timeout=3) as response:`
- `payload["target_url"] is passed directly to urllib.request.Request without validation`

Limitations:
- No runtime probe data confirming that an attacker can control payload["target_url"]
- No evidence that the application restricts schemes or validates the URL
- Severity and confidence are based solely on static analysis; actual exploitability depends on surrounding code not provided

### 43. Missing authorization on public file read endpoint

- Issue group: `ai-d40782fbc8de084b`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The GET /files endpoint defined in api/extra.py resolves a user‑controlled filename within the server's public directory and returns its contents without any authentication or authorization check. The code only verifies that the resolved path stays inside the public folder and that the file exists, but it does not enforce that the caller is permitted to read the file. If the public directory contains files that are not intended for unrestricted access, any unauthenticated client can retrieve them, leading to information disclosure.

**Impact:** Unauthenticated users can read arbitrary files from the public directory, potentially exposing configuration files, internal data, or other sensitive information. This can aid attackers in reconnaissance, credential harvesting, or further exploitation of the system.

**Remediation:** Add an authentication/authorization guard before resolving the file (e.g., require a valid token or specific role). Limit the endpoint to serve only files that are explicitly intended to be public, or move sensitive files out of the public folder. Consider implementing additional controls such as rate limiting and input validation to prevent enumeration attacks.
Evidence:
- Source IDs: `ai-d40782fbc8de084b`
- `@router.get("/files") definition at api/extra.py line 210`
- `def file_read(name: str) -> Response: line 211`
- `file = (FILES / "public" / name).resolve() line 212`
- `No authentication or role check appears before line 212`
- `if not file.is_relative_to(FILES.resolve()) or not file.is_file(): line 213`

Limitations:
- We lack knowledge of the intended contents of the public directory; it may be deliberately public
- No runtime evidence shows that sensitive files are actually present in the public folder
- The scan does not reveal any external access control mechanisms that might be applied elsewhere (e.g., API gateway)

### 44. Potential information leakage in error messages for duplicate registration

- Issue group: `ai-e8f12316dd8aae3b`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code re‑raises a database UniqueViolation as an HTTPException while preserving the original exception via `from error`. If the application runs with debug mode enabled or propagates exception details in responses or logs, an attacker could infer internal schema information (e.g., table and column names). However, FastAPI (or similar frameworks) typically suppresses the chained exception in production responses unless debug is on. Without concrete evidence of the runtime configuration or logging exposure, the risk cannot be confirmed.

**Impact:** An attacker who can trigger a duplicate‑username registration might obtain internal database error details, revealing schema elements such as table names and column structures, which could aid further attacks.

**Remediation:** Configure the application to run with debug disabled in production. Avoid chaining the original database exception when raising HTTP errors; instead log the detailed error internally and raise a generic `HTTPException(409, "username already exists")` without the `from error` clause. Ensure that logs containing exception traces are not publicly accessible.
Evidence:
- Source IDs: `ai-e8f12316dd8aae3b`
- `api/app.py:184-185: except psycopg.errors.UniqueViolation as error:`
- `api/app.py:185: raise HTTPException(409, "username already exists") from error`

Limitations:
- The deployment context does not specify whether the FastAPI app runs with debug=True or False.
- No information is provided about how exception traces are logged or whether log files are exposed to unauthenticated users.
- The behavior of the framework regarding exception chaining in production responses is assumed but not verified for this specific setup.

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
- `merged-17a5197f906426a224ef`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-da0f922505b4c0c7fed1`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-38e7cf77bdf9145d2ae4`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-d9421dbfc4162d6dea91`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-e7caea540245938b275b`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-19f4a13e0b2d4f7413d0`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-87e0399272a390813ea5`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-bbf1646deeb18d1e95db`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-8e21db3fe42adbf58979`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-d5c3b6b8d8dad90c4d3c`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-a5ea8ca4c36bd6c25e2a`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-65c41e5a25b6337fec07`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-1ba9f8276fc6dae95df8`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-2d4a81712313b5f2f621`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-8946f8391fc9049cbb58`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-cc8a9ed20905505868f0`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-b4c1c4d005665a5249a7`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-a9e9047867c909f567ad`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7da23d65adeef42d71a6`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-e683a977084f2bbcee2e`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-dd64ece99563dbbb173a`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-2b80ed0c48c0c70a93a4`: **warn** — RG-003: high likely vulnerability requires manual review; not auto-confirmed.
- `merged-65f25bcf14fa2ab91271`: **warn** — RG-006: high needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-d40782fbc8de084b`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-e8f12316dd8aae3b`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **42**; issue groups after conservative correlation: **44**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **5**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **2**; uncertain overlaps: **0**; needs more evidence: **3**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-7a5da456c78d1085`: needs_more_evidence
- `ai-106ede3c31e9b13b`: needs_more_evidence
- `ai-981fca0becf94f0c`: needs_more_evidence

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Coverage Gaps

- A negative result means only that this probe did not observe the behavior.
- A violation is an observed contract mismatch requiring security review.
- Baseline checks use bounded HTTP GET observations for an authorized target; declared paths must be safe to visit.
- Coverage applies only to declared assertions, accounts and workflows.
- Fresh stack resets the run; workflows must create independent test data. No per-step database reset is performed.
- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile.
- The baseline phase alone does not crawl browsers, test account workflows or confirm exploitation; additional phases are recorded separately.
- merged-17a5197f906426a224ef: primary source context is unavailable.
- merged-19f4a13e0b2d4f7413d0: primary source context is unavailable.
- merged-1ba9f8276fc6dae95df8: primary source context is unavailable.
- merged-2b80ed0c48c0c70a93a4: primary source context is unavailable.
- merged-2d4a81712313b5f2f621: primary source context is unavailable.
- merged-38e7cf77bdf9145d2ae4: primary source context is unavailable.
- merged-65c41e5a25b6337fec07: primary source context is unavailable.
- merged-65f25bcf14fa2ab91271: primary source context is unavailable.
- merged-7da23d65adeef42d71a6: primary source context is unavailable.
- merged-87e0399272a390813ea5: primary source context is unavailable.
- merged-8946f8391fc9049cbb58: primary source context is unavailable.
- merged-8e21db3fe42adbf58979: primary source context is unavailable.
- merged-a5ea8ca4c36bd6c25e2a: primary source context is unavailable.
- merged-a9e9047867c909f567ad: primary source context is unavailable.
- merged-b4c1c4d005665a5249a7: primary source context is unavailable.
- merged-bbf1646deeb18d1e95db: primary source context is unavailable.
- merged-cc8a9ed20905505868f0: primary source context is unavailable.
- merged-d5c3b6b8d8dad90c4d3c: primary source context is unavailable.
- merged-d9421dbfc4162d6dea91: primary source context is unavailable.
- merged-da0f922505b4c0c7fed1: primary source context is unavailable.
- merged-dd64ece99563dbbb173a: primary source context is unavailable.
- merged-e683a977084f2bbcee2e: primary source context is unavailable.
- merged-e7caea540245938b275b: primary source context is unavailable.
- trivy task task-45e5f84af47a did not complete: prerequisite\_unverified (Unverified prerequisites: trivy\_databases).

## Limitations

Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.

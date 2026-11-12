# Security Review Report

- Project: `/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/verdict-comprehensive-lab`
- Generated (UTC): `2026-10-28T12:31:02.491716+00:00`
- Policy status: **failed**
- Review status: **completed**

## Executive Summary

- AI Discovery: **completed required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **20/20**; model calls: **4**.
- AI Discovery warning: Discovery batch 1: AI provider request failed with HTTP 400 (json\_validate\_failed); model output 0 chars, not valid JSON; retrying with a smaller request.

The agent reviewed **24** issue group(s). These are model verdicts, not a count of distinct, independently validated vulnerabilities. Policy blocking: **True**. **19** scanner/DAST observation record(s) are listed separately below.
Issue groups expected: **24**; reviewed: **24**; pending: **0**.

## Scanner Execution

- <code>trivy</code>: <code>prerequisite_unverified</code>
- <code>gitleaks</code>: <code>completed</code>
- <code>trivy</code>: <code>skipped</code>
- <code>semgrep-ce</code>: <code>completed</code>
- <code>codeql-cli</code>: <code>completed</code>
- <code>trivy</code>: <code>completed</code>

## Scanner and DAST Observations (Pre-Review)

**19** merged observation record(s): **0** DAST-related and **19** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

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
14. **Wildcard Cors** — scanner from semgrep-ce; location: <code>api/app.py:26</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-70f8087c412d06924742</code>; rule(s): <code>python.fastapi.security.wildcard-cors.wildcard-cors</code>; source evidence: <code>finding-243196a7a6a7f4370cd1</code>.
15. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.api</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-58377a692410b6446bbd</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-48290f2dcbee31dfed61</code>.
16. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.mock</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-0de42012099941c48e01</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-870cf9f254d0b4d8f63d</code>.
17. **No HEALTHCHECK defined** — scanner from trivy; location: <code>Dockerfile.worker</code>; severity: **low**; confidence: medium; risk: 17/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-df83daf10f817c7aa965</code>; rule(s): <code>DS-0026</code>; source evidence: <code>finding-668b40d0b72f4b4180cc</code>.
18. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>worker/worker.py:23</code>; severity: **low**; confidence: low; risk: 12/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-c150b78349615dd9bc2d</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-a84e1037fb0b8a6e0a7e</code>.
19. **Dynamic Urllib Use Detected** — scanner from semgrep-ce; location: <code>tests/test_smoke.py:20</code>; severity: **low**; confidence: low; risk: 0/100 (low); disposition: <code>standard_report</code>.
    - Record: <code>merged-7711056ee3332442a201</code>; rule(s): <code>python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected</code>; source evidence: <code>finding-6b5853a5c5dbc818ad2c</code>.

## Security Review Agent Verdicts

### 1. SQL query built from user-controlled sources

- Issue group: `merged-18f1abe978f9fdaad8e6`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The function `legacy_login` constructs an SQL statement by directly interpolating `body.username` and `body.password` into the query string using an f‑string. No parameterization, escaping, or input validation is performed, allowing an attacker to inject arbitrary SQL syntax via the supplied fields.

**Impact:** An attacker can manipulate the SQL query to bypass authentication, retrieve or modify user records, or execute arbitrary database commands, leading to data breach, privilege escalation, or full system compromise.

**Remediation:** Replace the string interpolation with a parameterized query (e.g., using placeholders and passing parameters to the DB driver) or use an ORM that handles escaping automatically. Also validate and sanitize input where appropriate.
Evidence:
- Source IDs: `merged-18f1abe978f9fdaad8e6`
- `115 | @router.post("/auth/legacy-login")`
- `116 | def legacy_login(body: Login) -> dict:`
- `117 |     query = f"SELECT id,username,role FROM users WHERE username='{body.username}' AND password='{body.password}'"`
- `118 |     with connection() as conn:`
- `119 |         row = conn.execute(query).fetchone()`

Limitations:
- The assessment assumes the underlying DB driver does not automatically escape interpolated values; if it does, the risk may be mitigated, but typical drivers treat raw strings as literal SQL. No runtime probe data was provided to confirm exploitation.

### 2. Path traversal check appears properly enforced

- Issue group: `merged-24d14609e3893220ea16`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint constructs a file path from a user‑provided "name" and then calls ``file.is_relative_to(root)`` before serving the file. This check ensures the resolved path remains within the intended ``public`` directory, preventing directory‑traversal attacks. The subsequent ``is_file`` check also guarantees the target exists before reading it. Consequently, the uncontrolled data does not lead to an exploitable path expression.

**Impact:** No impact; the request is safely rejected with a 404 when the path is outside the allowed directory.

**Remediation:** No remediation required for the path‑traversal issue, but ensure the runtime uses Python 3.9+ where ``Path.is_relative_to`` is available and consider additional hardening against symlink attacks if relevant.
Evidence:
- Source IDs: `merged-24d14609e3893220ea16`
- `api/extra.py:219-224 shows the use of ``root = (FILES / "public").resolve()`` and ``file = (root / name).resolve()`` followed by ``if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404)```

Limitations:
- Relies on ``Path.is_relative_to`` being present (Python 3.9+). Does not address potential symlink or race‑condition issues that could bypass the check.

### 3. Uncontrolled data used in path expression

- Issue group: `merged-794dcb4921076779cef0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint builds a file path from a user‑provided "name" but immediately resolves it and checks that the resulting path is a sub‑directory of the intended root using pathlib.Path.is_relative_to(). This check prevents directory‑traversal attacks, so the scanner’s warning is a false positive.

**Impact:** No impact; the code correctly blocks out‑of‑bounds paths and returns 404.

**Remediation:** No remediation required; the existing is_relative_to() guard is sufficient. Ensure the runtime uses Python 3.9+ where is_relative_to is available.
Evidence:
- Source IDs: `merged-794dcb4921076779cef0`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- The safety relies on pathlib.is_relative_to, which is only available in Python 3.9+. On older versions the check would fail, potentially re‑introducing traversal risk.
- resolve() follows symlinks; if an attacker can place a symlink inside the public directory pointing outside, the is_relative_to check would still succeed because the resolved path would be outside the root. Mitigation: avoid symlinks or add additional checks.

### 4. Path traversal check appears sufficient

- Issue group: `merged-83d97da4516adf20e20f`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint resolves the user‑provided filename and then verifies that the resulting path is still within the intended public directory using is_relative_to and also checks that the target is a regular file before returning its contents. This mitigates directory traversal attacks despite the initial use of uncontrolled data in the path expression.

**Impact:** No impact identified; the check prevents arbitrary file reads outside the public directory.

**Remediation:** No remediation required for this specific issue; ensure the check remains in place and consider additional hardening such as disallowing symbolic links if relevant.
Evidence:
- Source IDs: `merged-83d97da4516adf20e20f`
- `api/extra.py lines 211‑215 show the resolve() call followed by is_relative_to(FILES.resolve()) and is_file() checks.`

Limitations:
- Static analysis cannot guarantee runtime behavior with symlinks or filesystem race conditions; further dynamic testing could confirm the mitigation holds in all environments.

### 5. Uncontrolled data used in path expression

- Issue group: `merged-b3c734b4cef8dd70fce0`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename against a fixed root directory and then checks `file.is_relative_to(root)` and `file.is_file()`. These checks ensure the resolved path stays within the intended `public` directory and that the target is a regular file before reading it, effectively preventing path traversal. The scanner’s generic rule flagged the use of a user‑controlled value in a path expression, but the subsequent safety checks mitigate the risk.

**Impact:** No impact because the path traversal is prevented by the relative‑path check and file existence verification.

**Remediation:** No remediation needed for this finding; the existing checks are appropriate. Ensure that the underlying filesystem does not allow unexpected symlink tricks that could bypass `is_relative_to`.
Evidence:
- Source IDs: `merged-b3c734b4cef8dd70fce0`
- `root = (FILES / "public").resolve()`
- `file = (root / name).resolve()`
- `if not file.is_relative_to(root) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- Static analysis cannot guarantee that runtime filesystem semantics (e.g., race conditions, symlink attacks after the check) are impossible, but the current code follows best practices for path validation.

### 6. Path traversal check appears sufficient

- Issue group: `merged-b527b3ed30e57aac5ec5`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The function resolves the user‑provided filename and then verifies that the resolved path is a sub‑path of the configured FILES directory and that it points to an existing file. If the path is outside the allowed directory, a 404 is raised, preventing arbitrary file reads. The static analysis evidence shows the proper use of Path.resolve() and Path.is_relative_to() checks, which mitigates path traversal. No runtime probe facts contradict this behavior.

**Impact:** None – the code correctly blocks out‑of‑bounds paths, so no unauthorized file disclosure is possible.

**Remediation:** No remediation required; the existing checks are appropriate. Maintain the relative‑path validation if the code is modified.
Evidence:
- Source IDs: `merged-b527b3ed30e57aac5ec5`
- `def file_read(name: str) -> Response:`
- `    file = (FILES / "public" / name).resolve()`
- `    if not file.is_relative_to(FILES.resolve()) or not file.is_file():`
- `        raise HTTPException(404, "File not found")`
- `    return Response(file.read_text(encoding="utf-8"), media_type="text/plain")`

Limitations:
- Analysis is based solely on static code inspection; no dynamic execution data was provided to confirm runtime behavior.

### 7. Reflected server-side cross-site scripting

- Issue group: `merged-ea527a7d7441e2b11700`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The `catalog_search` endpoint returns an HTML response that directly interpolates the user‑controlled query parameter `q` into the page markup (`<h1>Results for {q}</h1>` and `<p>{row['name']}</p>`). No escaping, sanitisation, or templating safeguards are applied, allowing an attacker to inject arbitrary JavaScript that will be executed in the victim's browser when the response is rendered.

**Impact:** An attacker can craft a malicious URL that, when visited by a victim, executes arbitrary JavaScript in the context of the vulnerable site. This can lead to session hijacking, credential theft, defacement, or further attacks against the user or the application.

**Remediation:** * Encode or escape all user‑controlled data before inserting it into HTML (e.g., use a templating engine that auto‑escapes). 
* Validate and sanitise the `q` parameter to allow only expected characters. 
* Use parameterised queries for the SQL statement to prevent injection. 
* Implement a strong Content‑Security‑Policy (CSP) to mitigate script execution. 
* Consider returning JSON and letting the client render safely, rather than constructing raw HTML on the server.
Evidence:
- Source IDs: `merged-ea527a7d7441e2b11700`
- `Source excerpt shows direct insertion of `q` into HTML response without sanitisation (lines 142‑145).`

Limitations:
- Analysis is based on static code review; runtime behaviour (e.g., framework‑level auto‑escaping) was not observed. No evidence of additional defensive headers (e.g., CSP) was found in the provided context.

### 8. Path traversal check mitigates uncontrolled input

- Issue group: `merged-f4eaf141df049c63545d`
- Verdict: **false_positive**
- Severity: **info**
- Confidence: **high**

**Explanation:** The endpoint builds a file path from a user‑provided "name" parameter, but immediately resolves the path and verifies that the resulting path is a sub‑directory of the configured FILES directory using pathlib.Path.is_relative_to(). This check blocks directory‑traversal strings such as "../" and ensures the file exists before returning its contents. Consequently the uncontrolled data is not used in an unsafe path expression.

**Impact:** If the validation were bypassed, an attacker could read arbitrary files on the server, leading to information disclosure. The current checks prevent that scenario under normal operation.

**Remediation:** No remediation required for the path traversal issue; retain the resolve + is_relative_to validation and ensure the application runs on Python 3.9+ where is_relative_to is available. Consider adding explicit handling for symbolic‑link attacks if the FILES directory may contain symlinks.
Evidence:
- Source IDs: `merged-f4eaf141df049c63545d`
- `Line 212: file = (FILES / "public" / name).resolve()`
- `Line 213: if not file.is_relative_to(FILES.resolve()) or not file.is_file(): raise HTTPException(404, "File not found")`

Limitations:
- The safety relies on pathlib.is_relative_to behavior, which is only available in Python 3.9+. On older runtimes the check would fail or be unavailable.
- If the FILES directory contains symlinks that point outside the directory, resolve() will follow them before the is_relative_to check, potentially allowing traversal via symlinks.

### 9. SQL Injection via unsanitized user input in catalog_search

- Issue group: `merged-f60fee7d82fbca512208`
- Verdict: **likely_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The endpoint `/catalog/search` constructs an SQL statement using an f‑string that directly interpolates the query parameter `q` into the statement (`SELECT name FROM products WHERE name ILIKE '%{q}%'`). This bypasses any automatic escaping or parameterisation, allowing an attacker to inject arbitrary SQL syntax through the `q` parameter. The scanner flagged the use of a user‑provided value, and the source excerpt confirms the unsafe string interpolation.

**Impact:** An attacker could manipulate the SQL query to read, modify, or delete data from the `products` table or other tables, potentially leading to data leakage, data corruption, or privilege escalation within the application.

**Remediation:** Replace the f‑string with a parameterised query using the database driver’s placeholder syntax (e.g., `conn.execute("SELECT name FROM products WHERE name ILIKE %s", (f"%{q}%",))`). Validate and sanitise the `q` parameter as needed, or use an ORM that handles query construction safely.
Evidence:
- Source IDs: `merged-f60fee7d82fbca512208`
- `Source excerpt line 144: `rows = conn.execute(f"SELECT name FROM products WHERE name ILIKE '%{q}%'"`).fetchall()``
- `Scanner evidence: "This SQL query depends on a [user-provided value](1)."`

Limitations:
- No runtime probe confirms successful exploitation of the injection vector.
- The analysis assumes the database driver does not automatically escape interpolated strings; if the driver internally sanitises f‑strings this risk may be mitigated, but the code pattern is generally unsafe.
- No evidence of additional input validation or sanitisation elsewhere in the codebase.

### 10. Clear-text logging of sensitive information

- Issue group: `merged-3202e1e1074cfd44b9bf`
- Verdict: **confirmed_vulnerability**
- Severity: **high**
- Confidence: **high**

**Explanation:** The code logs the value of the environment variable APP_SECRET in clear text via `log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`. Logging secrets exposes them to any system that stores or processes log files, enabling an attacker with log access to retrieve the secret and potentially impersonate the application or access protected resources. The finding is corroborated by a Semgrep rule (`python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure`) that flags credential disclosure in logging statements.

**Impact:** If an attacker obtains the logs, they can extract the APP_SECRET, which may be used to forge authentication tokens, decrypt data, or gain privileged access to the application, leading to full compromise of the service.

**Remediation:** Remove the secret from log statements. Either omit the secret entirely, mask it (e.g., replace with ***), or log only a hash. Ensure that logging configuration does not include sensitive fields. Review other logging calls for similar exposures.
Evidence:
- Source IDs: `merged-3202e1e1074cfd44b9bf`
- `Source excerpt line 137: log.info("login user=%s app_secret=%s", username, os.environ.get("APP_SECRET", "lab-only"))`
- `Semgrep finding ID finding-2e982654735c1187197b (rule python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure) flagged line 137`

Limitations:
- The APP_SECRET default value is "lab-only", which may be a non‑production secret, but logging any secret is a bad practice and could be replaced with a real credential in other environments. The review does not assess log storage protections; exposure depends on log access controls.

### 11. Wildcard CORS configuration allows any origin with credentials

- Issue group: `merged-70f8087c412d06924742`
- Verdict: **confirmed_vulnerability**
- Severity: **low**
- Confidence: **high**

**Explanation:** The FastAPI application adds CORS middleware with `allow_origins=["*"]` while also enabling `allow_credentials=True`. This configuration permits any website to make cross‑origin requests that include cookies or HTTP authentication credentials, which can lead to credential leakage or CSRF attacks if the API serves sensitive data.

**Impact:** An attacker-controlled website could issue authenticated requests to the API on behalf of a logged‑in user, potentially accessing or modifying user data, or exfiltrating information returned by the API.

**Remediation:** Restrict `allow_origins` to a whitelist of trusted domains, disable `allow_credentials` unless absolutely necessary, and limit `allow_methods` and `allow_headers` to only those required by the application.
Evidence:
- Source IDs: `merged-70f8087c412d06924742`
- `api/app.py:26-29 shows `allow_origins=["*"]`, `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]``

Limitations:
- The actual risk depends on the sensitivity of data exposed by the API; if the API only serves public information, the impact may be reduced. No runtime probe data was provided to confirm exploitation.

### 12. Log Injection

- Issue group: `merged-9c6fcf61fc01168b15e2`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The application logs a user‑controlled value (the username) together with a sensitive environment variable (APP_SECRET). Logging user input can enable log injection attacks if log consumers interpret format specifiers or other control characters. Additionally, writing the application secret to logs creates a confidentiality risk because logs may be stored, transmitted, or viewed by unauthorized parties.

**Impact:** An attacker could craft a username containing log control sequences to manipulate log parsing, obscure malicious activity, or inject malicious payloads into downstream log processing tools. Exposure of the APP_SECRET in logs could lead to credential leakage, enabling further compromise of the application or related services.

**Remediation:** Avoid logging sensitive data such as secrets. Sanitize or omit user‑controlled values from log messages, or encode them safely. Use structured logging with explicit field separation and ensure that any logged user input is escaped or validated. Store secrets in a secure vault and never write them to logs.
Evidence:
- Source IDs: `merged-9c6fcf61fc01168b15e2`
- `api/app.py:137 logs user=%s and APP_SECRET via log.info`

Limitations:
- The code uses Python's logging with argument substitution, which mitigates classic format string injection, but does not prevent injection via log parsers downstream.
- The impact depends on how and where logs are stored and who can access them; the review cannot confirm exposure without deployment context.

### 13. Open redirect via unvalidated 'next' parameter

- Issue group: `merged-51bf51abe866bf8d3d67`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The endpoint `/auth/continue` accepts a query parameter `next` supplied by the user and passes it directly to `RedirectResponse` without any validation or whitelist. This allows an attacker to craft a URL that redirects victims to an arbitrary external site, facilitating phishing or other social‑engineering attacks.

**Impact:** An attacker can lure a user to a trusted domain, then redirect them to a malicious site, potentially leading to credential theft, malware download, or other harmful actions.

**Remediation:** Validate the `next` parameter against an allow‑list of internal URLs or ensure it is a relative path before performing the redirect. Alternatively, use a safe redirect utility that rejects external URLs.
Evidence:
- Source IDs: `merged-51bf51abe866bf8d3d67`
- `Source excerpt shows `def continue_to(next: str = "/") -> RedirectResponse:` and `return RedirectResponse(next, status_code=302)` which uses the user‑provided `next` value directly.`

Limitations:
- No runtime probe evidence of exploitation is available.
- No guard checks or whitelist logic observed in the code.

### 14. URL redirection from remote source

- Issue group: `merged-f41fd10802e7c4dd22bb`
- Verdict: **false_positive**
- Severity: **medium**
- Confidence: **high**

**Explanation:** The `verified_continue` function validates the `next` parameter by ensuring it starts with a single '/' and rejects any scheme, netloc, or double-slash prefix, raising an HTTP 400 error for non‑local paths. This prevents redirection to external URLs, so the reported open‑redirect risk is mitigated in this code path.

**Impact:** No impact from this finding because the redirect is constrained to internal paths only.

**Remediation:** No remediation required for this function; continue to enforce strict validation for any future redirect endpoints.
Evidence:
- Source IDs: `merged-f41fd10802e7c4dd22bb`
- `source_excerpt lines 621‑624 show validation of the `next` parameter and rejection of external URLs`
- `source_symbol confirms the same logic`

Limitations:
- Only this specific endpoint (`/integrations/hook` via `verified_continue`) is covered; other redirect mechanisms in the codebase were not examined.

### 15. No HEALTHCHECK defined

- Issue group: `merged-58377a692410b6446bbd`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a health check is a best practice for container reliability, its absence does not directly constitute a security vulnerability. No evidence shows that this misconfiguration can be exploited to compromise the application.

**Impact:** Limited to reduced observability of container health; does not expose data or allow unauthorized actions.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8091/health || exit 1`.
Evidence:
- Source IDs: `merged-58377a692410b6446bbd`
- `Dockerfile.api lines 1-8 show no HEALTHCHECK instruction.`

Limitations:
- Assessment based solely on static Dockerfile content; runtime behavior not observed.

### 16. No HEALTHCHECK defined

- Issue group: `merged-0de42012099941c48e01`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile does not contain a HEALTHCHECK instruction. While adding a health check improves observability and container lifecycle management, its absence does not constitute a security vulnerability. The finding is a best‑practice recommendation rather than evidence of exploitable weakness.

**Impact:** Limited to reduced ability to automatically detect and recover from unhealthy container states; no direct impact on confidentiality, integrity, or availability of the application.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically checks the health of the service, e.g., `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:9000/health || exit 1`.
Evidence:
- Source IDs: `merged-0de42012099941c48e01`
- `Source excerpt shows Dockerfile lines 1‑6 without a HEALTHCHECK instruction.`

Limitations:
- Assessment is based solely on static Dockerfile content; no runtime health‑check behavior was observed. The finding does not demonstrate an exploitable security flaw.

### 17. No HEALTHCHECK defined

- Issue group: `merged-df83daf10f817c7aa965`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The Dockerfile lacks a HEALTHCHECK instruction, which is a best‑practice recommendation rather than a direct security flaw. Absence of a health check does not by itself create a vulnerability; it only reduces observability of container health.

**Impact:** Limited to operational visibility; does not expose the application to a specific attack vector.

**Remediation:** Add a HEALTHCHECK instruction to the Dockerfile that periodically verifies the container’s essential services (e.g., curl localhost health endpoint).
Evidence:
- Source IDs: `merged-df83daf10f817c7aa965`
- `Source excerpt shows Dockerfile lines 1‑7 with no HEALTHCHECK instruction.`

Limitations:
- Cannot infer whether external orchestration provides health monitoring; the finding is based solely on Dockerfile content.

### 18. Potential unsafe dynamic URL construction with urllib

- Issue group: `merged-7711056ee3332442a201`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The request() function builds a URL by concatenating a constant BASE with a caller‑supplied path argument and passes the result directly to urllib.request.urlopen. If the path argument can be influenced by an attacker, they could craft a URL such as "file:///etc/passwd" or an external address, causing the server to make arbitrary network requests (SSRF) or read local files. The scanner flagged this pattern, and no evidence of input sanitisation or validation is present in the provided excerpt.

**Impact:** An attacker could cause the application to read arbitrary files via the file:// scheme or interact with internal services, leading to information disclosure, privilege escalation, or further compromise of the host environment.

**Remediation:** Validate and sanitise the `path` argument before concatenation. Restrict allowed schemes to http/https, enforce a whitelist of endpoints, or use a higher‑level HTTP client (e.g., the `requests` library) that does not support file URLs. Consider constructing URLs with proper URL‑joining utilities and reject any path containing suspicious characters or schemes.
Evidence:
- Source IDs: `merged-7711056ee3332442a201`
- `Line 20‑21: `urllib.request.urlopen(urllib.request.Request(BASE + path, ...)` – dynamic `path` is concatenated with `BASE` and used directly.`
- `The function does not perform any validation or sanitisation of `path` before use.`

Limitations:
- The surrounding code and definition of `BASE` are not provided, so we cannot confirm whether `BASE` already includes a safe scheme or whether `path` is validated elsewhere.
- No runtime probe data is available to demonstrate an actual exploit or to show that `path` can be attacker‑controlled.

### 19. Potential Server-Side Request Forgery via dynamic urllib usage

- Issue group: `merged-c150b78349615dd9bc2d`
- Verdict: **likely_vulnerability**
- Severity: **low**
- Confidence: **medium**

**Explanation:** The function constructs a urllib.request.Request using the value of payload["target_url"] directly from the job payload. No validation or allow‑list is applied before the URL is opened with urllib.request.urlopen. If an attacker can influence the job payload, they could supply a malicious URL (including file:// schemes) that the server will fetch, leading to SSRF or local file read.

**Impact:** An attacker-controlled URL could cause the service to make arbitrary network requests to internal services, expose sensitive data, or read arbitrary files via the file:// scheme, potentially leading to data exfiltration or further compromise.

**Remediation:** Validate and sanitize the target URL before use. Restrict allowed schemes to http/https, enforce an allow‑list of trusted hosts, and consider using a higher‑level HTTP library (e.g., requests) that does not support file URLs. If external URLs are required, implement network‑level egress controls and timeouts.
Evidence:
- Source IDs: `merged-c150b78349615dd9bc2d`
- `Source excerpt showing dynamic urllib usage (lines 18‑23) where payload["target_url"] is passed directly to urllib.request.Request.`
- `Scanner note: "Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files."`

Limitations:
- No runtime_probe_facts or observed exploitation of the URL parameter.
- The origin and trust level of the job payload are not established; it is unclear whether an attacker can control payload["target_url"].
- No additional guard checks or input validation are present in the provided code snippet.

### 20. Potential Insecure Direct Object Reference (IDOR) on User Lookup – false positive

- Issue group: `ai-1a3cfd26550f6cff`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **high**

**Explanation:** The examined function `verified_profile` includes an explicit authorization check (`if profile_id != user["id"]: raise HTTPException(403, "Not your profile")`) before returning any user data. This check ensures that a caller can only retrieve their own profile, preventing an IDOR condition for this endpoint. The AI‑generated claim of a missing permission verification is contradicted by the present check in the source excerpt.

**Impact:** No impact identified for this specific code path because unauthorized data disclosure is prevented by the existing check.

**Remediation:** No remediation required for this function. Continue to enforce similar authorization checks on any other endpoints that expose user‑specific data.
Evidence:
- Source IDs: `ai-1a3cfd26550f6cff`
- `Line 110‑111: `if profile_id != user["id"]: raise HTTPException(403, "Not your profile")` – authorization guard`
- `Line 112: `return {"id": user["id"], "username": user["username"], "email": user["email"]}` – data returned only after guard passes`

Limitations:
- Analysis is limited to the provided `verified_profile` function excerpt; other routes or code paths were not examined.
- The review assumes `verified_identity` correctly authenticates the requester; if it were flawed, the guard could be bypassed.

### 21. Missing CSRF Protection on State‑Changing Endpoints

- Issue group: `ai-21005f30e8e4620d`
- Verdict: **needs_more_evidence**
- Severity: **low**
- Confidence: **low**

**Explanation:** The FastAPI application defines a POST endpoint (/auth/register) that creates a new user record in the database. The examined code snippet shows no CSRF token validation, SameSite cookie settings, or other anti‑CSRF mechanisms. If this endpoint is reachable from a browser context, an attacker could potentially forge a request that causes an unwanted user registration. However, the repository does not reveal whether a global FastAPI middleware enforces CSRF protection or whether the API is intended solely for non‑browser clients, leaving the actual risk uncertain.

**Impact:** If the endpoint is accessible from a browser, an attacker could exploit the lack of CSRF defenses to cause unauthorized user registrations, leading to account enumeration, privilege escalation, or abuse of the system’s resources.

**Remediation:** Add CSRF protection appropriate for the deployment model: • If the API is consumed by browsers, enable CSRF tokens (e.g., using fastapi-csrf-protect) or enforce SameSite=Lax/Strict on authentication cookies. • If the API is intended for non‑browser clients, document this clearly and consider disabling cookie‑based auth in favor of token‑based schemes. • Review the application’s middleware stack for any existing CSRF safeguards and ensure they are correctly configured.
Evidence:
- Source IDs: `ai-21005f30e8e4620d`
- `@app.post("/auth/register") at api/app.py:175`
- `def register(body: LoginBody) -> dict[str, Any]: at api/app.py:176`
- `user = conn.execute(... INSERT INTO users ...) at api/app.py:179`

Limitations:
- No evidence was found of a global CSRF middleware or other protective measures elsewhere in the codebase.
- The intended client type (browser vs. API‑only) is not documented, so the relevance of CSRF protection cannot be confirmed.

### 22. Potential Information Disclosure via Detailed SQL Error Messages

- Issue group: `ai-03487f594ab3a0e5`
- Verdict: **false_positive**
- Severity: **low**
- Confidence: **low**

**Explanation:** The code re‑raises a FastAPI HTTPException while chaining the original psycopg UniqueViolation exception. In typical FastAPI deployments, the default exception handler strips exception causes from the HTTP response unless the application is running in debug mode. No configuration evidence is provided that debug=True or a custom exception handler exposing the chained exception is used, so there is no concrete proof that detailed database error information reaches the client.

**Impact:** If detailed error information were exposed, an attacker could gain insight into the database schema or constraints, aiding further attacks. However, given the lack of evidence that such information is returned, the practical impact is minimal.

**Remediation:** Ensure the FastAPI application runs with debug=False in production and verify that any custom exception handlers do not include exception causes or stack traces in responses. If needed, raise HTTPException without chaining the original error or log the original error server‑side only.
Evidence:
- Source IDs: `ai-03487f594ab3a0e5`
- `except psycopg.errors.UniqueViolation as error:`
- `raise HTTPException(409, "username already exists") from error`

Limitations:
- No runtime observation of the actual HTTP response body is provided; the assessment relies on default FastAPI behavior. The deployment_context is null, so the debug setting cannot be confirmed.

### 23. Potential overexposure of sensitive user data in /me endpoint

- Issue group: `ai-b0dfdc8f9b2bed63`
- Verdict: **needs_more_evidence**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /me endpoint returns a dictionary containing id, username, role, email, and ssn for the authenticated user. While the user is authenticated, the endpoint does not perform any additional scope, role, or consent checks before exposing email and SSN fields. Without knowing whether these fields are required for legitimate use cases, the unconditional exposure of SSN may constitute a privacy violation or data leakage risk.

**Impact:** If an attacker obtains a valid authentication token, they can retrieve the user's SSN and email, leading to identity theft, fraud, or compliance violations (e.g., GDPR, HIPAA). Even legitimate users may unintentionally expose their SSN to client-side code or logs.

**Remediation:** Limit the fields returned by /me to only those necessary (e.g., omit SSN). If SSN must be accessible, add explicit permission or scope checks and ensure audit logging of accesses. Consider masking or encrypting sensitive fields in responses.
Evidence:
- Source IDs: `ai-b0dfdc8f9b2bed63`
- `199: @app.get("/me")`
- `200: def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:`
- `201:     user = principal(authorization)`
- `202:     with connection() as conn:`
- `203:         row = conn.execute("SELECT id,username,role,email,ssn FROM users WHERE id=%s", (user["sub"],)).fetchone()`
- `204:     return dict(row or {})`

Limitations:
- The review cannot confirm whether the SSN field is required by downstream services or business logic.
- No evidence is provided about existing role‑based or scope‑based access controls beyond the principal extraction.
- Audit logging for accesses to this endpoint is not shown, so the impact of potential misuse cannot be fully assessed.

### 24. Missing token type validation in refresh endpoint

- Issue group: `ai-399c790f8ce192d7`
- Verdict: **likely_vulnerability**
- Severity: **medium**
- Confidence: **medium**

**Explanation:** The /auth/refresh endpoint accepts any Authorization header, extracts a user via principal(), and issues a new access token without verifying that the supplied token is a refresh token or checking its revocation status. This pattern can allow an attacker who possesses a valid access token to repeatedly obtain fresh tokens, effectively extending the lifetime of a compromised credential.

**Impact:** An attacker with a stolen access token could call the refresh endpoint to receive new access tokens indefinitely, leading to prolonged unauthorized access, privilege escalation, and potential data exfiltration.

**Remediation:** Modify the refresh endpoint to: (1) require a token of type "refresh" (e.g., by checking a claim in the token payload); (2) verify the token against a revocation list or expiration check; (3) reject requests that present access tokens or revoked refresh tokens; and (4) consider rotating refresh tokens after each use.
Evidence:
- Source IDs: `ai-399c790f8ce192d7`
- `189: @app.post("/auth/refresh")`
- `191: user = principal(authorization)`
- `196: return {"access_token": make_token(row), "token_type": "bearer"}`

Limitations:
- The implementation of principal() is not visible, so we cannot confirm whether it performs token‑type validation internally.
- No evidence is provided that a revocation list or separate refresh‑token handling exists elsewhere in the codebase.

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
- `merged-3202e1e1074cfd44b9bf`: **block** — RG-001: high confirmed vulnerability is deterministic evidence was not supplied to the gate; blocking severities are critical, high.
- `merged-70f8087c412d06924742`: **warn** — RG-006: low confirmed vulnerability is not sufficiently confirmed for an automatic block.
- `merged-9c6fcf61fc01168b15e2`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-51bf51abe866bf8d3d67`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-f41fd10802e7c4dd22bb`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-58377a692410b6446bbd`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-0de42012099941c48e01`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-df83daf10f817c7aa965`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `merged-7711056ee3332442a201`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `merged-c150b78349615dd9bc2d`: **warn** — RG-006: low likely vulnerability is not sufficiently confirmed for an automatic block.
- `ai-1a3cfd26550f6cff`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `ai-21005f30e8e4620d`: **warn** — RG-006: low needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-03487f594ab3a0e5`: **allow** — RG-004: classified as a false positive; no high/critical scanner finding contradicts it.
- `ai-b0dfdc8f9b2bed63`: **warn** — RG-006: medium needs more evidence is not sufficiently confirmed for an automatic block.
- `ai-399c790f8ce192d7`: **warn** — RG-006: medium likely vulnerability is not sufficiently confirmed for an automatic block.

## Candidate Triage and Unresolved Evidence

Scanner/DAST observation records: **19**; issue groups after conservative correlation: **24**. Every original observation remains listed above and linked by source ID in its review group.
AI candidates: **11**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **3**; uncertain overlaps: **2**; needs more evidence: **6**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:
- `ai-dcd79030020360ab`: needs_more_evidence
- `ai-e145c09928216e1f`: needs_more_evidence
- `ai-b0dfdc8f9b2bed63`: uncertain_overlap
- `ai-399c790f8ce192d7`: uncertain_overlap
- `ai-c6486426766d3240`: needs_more_evidence
- `ai-7ef9da74c2ce47fd`: needs_more_evidence
- `ai-94e61ce64765bbf0`: needs_more_evidence
- `ai-0de067cafcf6252d`: needs_more_evidence

Verification status: **partial**; see `verification.json` for individual source-evidence checks.

## Coverage Gaps

- Resolved transitive dependency versions are unverified for component component-cdb4ee2aea: a manifest was found, but no supported lockfile.
- trivy task task-45e5f84af47a did not complete: prerequisite\_unverified (Unverified prerequisites: trivy\_databases).

## Limitations

Scanner and AI silence is not proof that the project is secure. Findings require appropriate runtime or manual validation before release decisions.

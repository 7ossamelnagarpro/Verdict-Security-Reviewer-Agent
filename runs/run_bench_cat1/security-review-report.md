# 🛡️ Security Review Report

> ❔ **No reviewed findings — no conclusion about safety can be drawn**
>
> No dynamic testing (DAST) was performed; findings come from static analysis and AI review.

Project <code>/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/owasp-benchmark-python-cat1</code> · generated 2026-10-27 10:51 UTC · policy <code>incomplete</code> · review <code>not_run</code> · rules <code>release-gate-rules/2</code>

- AI Discovery: **incomplete required stage**; stage status: <code>blocked</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **0/21**; model calls: **1**.
- **This scan is incomplete.** Scanner and DAST observations remain available, but the required AI Discovery did not finish.
- AI Discovery warning: Discovery batch 1: AI provider request failed with HTTP 400

## Scorecard

| Issues reviewed | ⛔ Blocking | ⚠️ Manual review | ✅ Cleared | Scanners completed | Duplicates merged | DAST |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **0** | **0** | **0** | **0** | **3 / 3** | 28 → 22 | not run |

## 🎯 Fix first

Nothing met the automatic blocking criteria. This is not a security clearance.

**Then:**

1. Add authorised runtime testing (DAST) if the app can run in an isolated environment.

## Findings

No agent verdicts were produced. **22** scanner/DAST observation record(s) are listed in the appendix for investigation. The observations have not been cleared or confirmed by the agent, and this does not mean the project is secure.

## 🧭 Coverage & trust

| Scanner | Result | What it means |
|---|---|---|
| **Trivy · dependencies &amp; config**<br><code>trivy</code> | ➖ Not scheduled (<code>not_scheduled</code>) | Nothing applicable was found to scan, so this scanner did not run.<br>The scan plan has no Trivy task: no supported dependency manifest or lockfile, Dockerfile or compose file was found.<br>Dependency/SCA coverage is unknown for component component-cdb4ee2aea: no supported manifest or lockfile was found. |
| **CodeQL · SAST data-flow**<br><code>codeql-cli</code> | ✅ Completed (<code>completed</code>) | Results are included in this report.<br>CodeQL produced valid SARIF output<br>Scanner version not verified: CodeQL runtime version 2.27.2 differs from 2.27.1 (version check skipped) |
| **Gitleaks · secrets**<br><code>gitleaks</code> | ✅ Completed (<code>completed</code>) | Results are included in this report.<br>Gitleaks produced valid JSON output<br>Scanner version not verified: Gitleaks executable exists; runtime version could not be read (version check skipped) |
| **Semgrep CE · SAST patterns**<br><code>semgrep-ce</code> | ✅ Completed (<code>completed</code>) | Results are included in this report.<br>Semgrep produced valid JSON output |

3 of 3 applicable scanner task(s) completed. Registered but not scheduled (nothing to scan): trivy.

**Deduplication.** 28 raw scanner results → 22 root-cause records (6 duplicates merged: same vulnerability family, file and overlapping lines). Nothing is discarded; every raw result and rule id stays attached to its record.

**Known gaps** (each lowers confidence in a clean result for that area):

- Dependency/SCA coverage is unknown for component component-cdb4ee2aea: no supported manifest or lockfile was found.

## Appendix

### A. Release-gate decisions

No policy decisions were recorded.

### B. Scanner and DAST Observations (Pre-Review)

**22** merged observation record(s): **0** DAST-related and **22** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

<details><summary>Show all observations</summary>

| # | Observation | Origin | Evidence | Location | Severity | Confidence | Risk | Disposition |
|--:|---|---|--:|---|---|---|---|---|
| 1 | **Code injection** | scanner / codeql-cli, semgrep-ce | 2 | <code>testcode/BenchmarkTest00159.py:45</code> | critical | high | 100/100 (critical) | <code>deep_review</code> |
| 2 | **Uncontrolled command line** | scanner / codeql-cli, semgrep-ce | 4 | <code>testcode/BenchmarkTest00167.py:53</code> | critical | high | 100/100 (critical) | <code>deep_review</code> |
| 3 | **XPath query built from user-controlled sources** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00212.py:48</code> | critical | high | 84/100 (high) | <code>deep_review</code> |
| 4 | **URL redirection from remote source** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00151.py:64</code> | medium | high | 59/100 (medium) | <code>standard_report</code> |
| 5 | **Construction of a cookie using user-supplied input** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00721.py:57</code> | medium | high | 59/100 (medium) | <code>standard_report</code> |
| 6 | **Construction of a cookie using user-supplied input** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00808.py:58</code> | medium | high | 59/100 (medium) | <code>standard_report</code> |
| 7 | **URL redirection from remote source** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00068.py:49</code> | medium | high | 47/100 (medium) | <code>standard_report</code> |
| 8 | **Eval Detected** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00893.py:54-56</code> | high | low | 42/100 (medium) | <code>standard_report</code> |
| 9 | **Insecure Deserialization** | scanner / semgrep-ce | 2 | <code>testcode/BenchmarkTest00349.py:53</code> | medium | low | 39/100 (medium) | <code>standard_report</code> |
| 10 | **Avoid Pickle** | scanner / semgrep-ce | 2 | <code>testcode/BenchmarkTest01216.py:46</code> | medium | low | 39/100 (medium) | <code>standard_report</code> |
| 11 | **Subprocess Shell True** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00736.py:55</code> | low | medium | 33/100 (low) | <code>standard_report</code> |
| 12 | **Use Defused XML Parse** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00290.py:55</code> | medium | medium | 32/100 (low) | <code>standard_report</code> |
| 13 | **Insecure Hash Algorithm Sha1** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00714.py:54</code> | medium | medium | 32/100 (low) | <code>standard_report</code> |
| 14 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00205.py:45</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 15 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00205.py:46</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 16 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00290.py:45</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 17 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest01122.py:48</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 18 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest01122.py:49</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 19 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00012.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 20 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00068.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 21 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00721.py:57-60</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 22 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00808.py:58-61</code> | low | low | 12/100 (low) | <code>standard_report</code> |

Identifiers:

1. Record <code>merged-5bba528e8bd25247a105</code>; rule(s): <code>py/code-injection, python.lang.security.audit.exec-detected.exec-detected</code>; source evidence: <code>finding-c51f64f56bf084588c7d</code>, <code>finding-53749d44fc7b465dffe3</code>.
2. Record <code>merged-99b07b4e03a54e2874c3</code>; rule(s): <code>py/command-line-injection, python.flask.security.injection.subprocess-injection.subprocess-injection, python.lang.security.audit.subprocess-shell-true.subprocess-shell-true, python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use</code>; source evidence: <code>finding-f425eb43b47fc35efb15</code>, <code>finding-5fe46f80df228894127e</code>, <code>finding-67fd36c1f6e97dd883f9</code>, <code>finding-72566210125954f60afa</code>.
3. Record <code>merged-c6476ab34c8569ad07d1</code>; rule(s): <code>py/xpath-injection</code>; source evidence: <code>finding-f229340fc1808d8ec432</code>.
4. Record <code>merged-e04a2bab203e496a24e6</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-12bdc199a14df5faef91</code>.
5. Record <code>merged-033aebac980099fb12a6</code>; rule(s): <code>py/cookie-injection</code>; source evidence: <code>finding-0452a64d9b6b6382d1ea</code>.
6. Record <code>merged-c9aab428c22f431c75c6</code>; rule(s): <code>py/cookie-injection</code>; source evidence: <code>finding-d0fd164c3f9f7151f530</code>.
7. Record <code>merged-4d1ee3d289fcfcf5043e</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-1cb428fd8d6372a2aac6</code>.
8. Record <code>merged-8b5bb5b751bbeb3ccd89</code>; rule(s): <code>python.lang.security.audit.eval-detected.eval-detected</code>; source evidence: <code>finding-cffa0b20dafe50129576</code>.
9. Record <code>merged-a02132203a2601215740</code>; rule(s): <code>python.flask.security.insecure-deserialization.insecure-deserialization, python.lang.security.deserialization.pickle.avoid-pickle</code>; source evidence: <code>finding-a9424ff383f93318b759</code>, <code>finding-29013d91955669880aa3</code>.
10. Record <code>merged-5ef623b3093d5235915f</code>; rule(s): <code>python.flask.security.insecure-deserialization.insecure-deserialization, python.lang.security.deserialization.pickle.avoid-pickle</code>; source evidence: <code>finding-35ba295a585d5690038f</code>, <code>finding-4480b1e3c0cfbb41f7f5</code>.
11. Record <code>merged-1b85485232aeba51d3f6</code>; rule(s): <code>python.lang.security.audit.subprocess-shell-true.subprocess-shell-true</code>; source evidence: <code>finding-25ca75990c0a51d0d5d0</code>.
12. Record <code>merged-64caf4864cd787fb73fd</code>; rule(s): <code>python.lang.security.use-defused-xml-parse.use-defused-xml-parse</code>; source evidence: <code>finding-c81ef564aef3bce67989</code>.
13. Record <code>merged-42aa6797f66fce97d507</code>; rule(s): <code>python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1</code>; source evidence: <code>finding-0b6db23ebfe9065ec031</code>.
14. Record <code>merged-5c56fa4a013be9eef7d0</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-a003a27a0cb1a66d4ac4</code>.
15. Record <code>merged-673090543bb62bba96b3</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-d520228d40fec8284318</code>.
16. Record <code>merged-3bd5982f3ee4227621fa</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-7d2c79dcd3bc4531b279</code>.
17. Record <code>merged-064808129dd768f98f4c</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-75a61bb0b7666073da92</code>.
18. Record <code>merged-bd5da2dd15c1f5da9566</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-9466b83f365a894aff50</code>.
19. Record <code>merged-1d76b75e663e2ffb1829</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-e0cfe4ae4229faee0421</code>.
20. Record <code>merged-415c7fa8c4565aaab144</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-e483200da10057840320</code>.
21. Record <code>merged-150764bd1f8d7530fbfe</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-c487b9ba0f9ad46cd171</code>.
22. Record <code>merged-18779e73fbbe547b3aeb</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-c20e40d3bf497da0c602</code>.

</details>

### C. Candidate triage and unresolved evidence

Scanner/DAST observation records: **22**; issue groups after conservative correlation: **22**. Every original observation stays linked by source ID.
AI candidates: **0**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **0**; uncertain overlaps: **0**; needs more evidence: **0**; rejected: **0**.

Verification status: **partial**; see `verification.json` for source-evidence checks.

### D. Method and limitations

- Scanner and AI silence is not proof that the project is secure; validate before release decisions.
- Verdicts are produced by an AI model reading bounded code excerpts; they are not independently validated exploits.
- Severities and scores are triage aids, not CVSS ratings.
- No runtime/DAST evidence is included, so exploitability is inferred from code.

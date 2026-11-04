# 🛡️ Security Review Report

> ❔ **No reviewed findings — no conclusion about safety can be drawn**
>
> No dynamic testing (DAST) was performed; findings come from static analysis and AI review.

Project <code>/mnt/c/Users/ASUS/Downloads/2update/verdict-integrated/targets/owasp-benchmark-python</code> · generated 2026-10-25 10:00 UTC · policy <code>incomplete</code> · review <code>not_run</code> · rules <code>release-gate-rules/2</code>

- AI Discovery: **incomplete required stage**; stage status: <code>partial</code>; provider: <code>groq</code>; model: <code>openai/gpt-oss-120b</code>; targets inspected: **10/45**; model calls: **2**.
- **This scan is incomplete.** Scanner and DAST observations remain available, but the required AI Discovery did not finish.
- AI Discovery warning: Discovery batch 2: AI provider request failed with HTTP 413 (rate\_limit\_exceeded)

## Scorecard

| Issues reviewed | ⛔ Blocking | ⚠️ Manual review | ✅ Cleared | Scanners completed | Duplicates merged | DAST |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **0** | **0** | **0** | **0** | **3 / 3** | 63 → 51 | not run |

## 🎯 Fix first

Nothing met the automatic blocking criteria. This is not a security clearance.

**Then:**

1. Add authorised runtime testing (DAST) if the app can run in an isolated environment.

## Findings

No agent verdicts were produced. **51** scanner/DAST observation record(s) are listed in the appendix for investigation. The observations have not been cleared or confirmed by the agent, and this does not mean the project is secure.

## 🧭 Coverage & trust

| Scanner | Result | What it means |
|---|---|---|
| **CodeQL · SAST data-flow**<br><code>codeql-cli</code> | ✅ Completed (<code>completed</code>) | Results are included in this report.<br>CodeQL produced valid SARIF output<br>Scanner version not verified: CodeQL runtime version 2.27.2 differs from 2.27.1 (version check skipped) |
| **Gitleaks · secrets**<br><code>gitleaks</code> | ✅ Completed (<code>completed</code>) | Results are included in this report.<br>Gitleaks produced valid JSON output<br>Scanner version not verified: Gitleaks executable exists; runtime version could not be read (version check skipped) |
| **Semgrep CE · SAST patterns**<br><code>semgrep-ce</code> | ✅ Completed (<code>completed</code>) | Results are included in this report.<br>Semgrep produced valid JSON output |

3 of 3 applicable scanner task(s) completed.

**Deduplication.** 63 raw scanner results → 51 root-cause records (12 duplicates merged: same vulnerability family, file and overlapping lines). Nothing is discarded; every raw result and rule id stays attached to its record.

**Known gaps** (each lowers confidence in a clean result for that area):

- Dependency/SCA coverage is unknown for component component-cdb4ee2aea: no supported manifest or lockfile was found.

## Appendix

### A. Release-gate decisions

No policy decisions were recorded.

### B. Scanner and DAST Observations (Pre-Review)

**51** merged observation record(s): **0** DAST-related and **51** other scanner record(s). These are signals to assess, not confirmed independent vulnerabilities. Risk disposition describes routing, not an agent verdict.

<details><summary>Show all observations</summary>

| # | Observation | Origin | Evidence | Location | Severity | Confidence | Risk | Disposition |
|--:|---|---|--:|---|---|---|---|---|
| 1 | **Code injection** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00157.py:50</code> | critical | high | 100/100 (critical) | <code>deep_review</code> |
| 2 | **Code injection** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00158.py:56</code> | critical | high | 100/100 (critical) | <code>deep_review</code> |
| 3 | **Code injection** | scanner / codeql-cli, semgrep-ce | 2 | <code>testcode/BenchmarkTest00161.py:40</code> | critical | high | 100/100 (critical) | <code>deep_review</code> |
| 4 | **Uncontrolled command line** | scanner / codeql-cli, semgrep-ce | 2 | <code>testcode/BenchmarkTest00431.py:51</code> | critical | high | 100/100 (critical) | <code>deep_review</code> |
| 5 | **Uncontrolled command line** | scanner / codeql-cli, semgrep-ce | 2 | <code>testcode/BenchmarkTest00607.py:54</code> | critical | high | 96/100 (critical) | <code>deep_review</code> |
| 6 | **Deserialization of user-controlled data** | scanner / codeql-cli, semgrep-ce | 4 | <code>testcode/BenchmarkTest00510.py:46</code> | critical | high | 92/100 (critical) | <code>deep_review</code> |
| 7 | **Deserialization of user-controlled data** | scanner / codeql-cli, semgrep-ce | 3 | <code>testcode/BenchmarkTest00994.py:53</code> | critical | high | 92/100 (critical) | <code>deep_review</code> |
| 8 | **XPath query built from user-controlled sources** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00213.py:52</code> | critical | high | 84/100 (high) | <code>deep_review</code> |
| 9 | **Uncontrolled data used in path expression** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00088.py:52</code> | high | high | 82/100 (high) | <code>deep_review</code> |
| 10 | **Uncontrolled data used in path expression** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00182.py:49</code> | high | high | 82/100 (high) | <code>deep_review</code> |
| 11 | **XPath query built from user-controlled sources** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00546.py:48</code> | critical | high | 72/100 (high) | <code>deep_review</code> |
| 12 | **XML external entity expansion** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest01025.py:50</code> | critical | high | 72/100 (high) | <code>deep_review</code> |
| 13 | **Uncontrolled data used in path expression** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00523.py:44</code> | high | high | 70/100 (high) | <code>deep_review</code> |
| 14 | **XML internal entity expansion** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest01025.py:50</code> | high | high | 62/100 (medium) | <code>standard_report</code> |
| 15 | **Construction of a cookie using user-supplied input** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00721.py:57</code> | medium | high | 59/100 (medium) | <code>standard_report</code> |
| 16 | **Construction of a cookie using user-supplied input** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00811.py:58</code> | medium | high | 59/100 (medium) | <code>standard_report</code> |
| 17 | **URL redirection from remote source** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest01209.py:52</code> | medium | high | 59/100 (medium) | <code>standard_report</code> |
| 18 | **Construction of a cookie using user-supplied input** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00065.py:63</code> | medium | high | 47/100 (medium) | <code>standard_report</code> |
| 19 | **URL redirection from remote source** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00067.py:47</code> | medium | high | 47/100 (medium) | <code>standard_report</code> |
| 20 | **Construction of a cookie using user-supplied input** | scanner / codeql-cli | 1 | <code>testcode/BenchmarkTest00650.py:73</code> | medium | high | 47/100 (medium) | <code>standard_report</code> |
| 21 | **Eval Detected** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00157.py:49-51</code> | high | low | 42/100 (medium) | <code>standard_report</code> |
| 22 | **Eval Detected** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00158.py:55-57</code> | high | low | 42/100 (medium) | <code>standard_report</code> |
| 23 | **Exec Detected** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00894.py:43</code> | high | low | 42/100 (medium) | <code>standard_report</code> |
| 24 | **Raw HTML Format** | scanner / semgrep-ce | 2 | <code>testcode/BenchmarkTest00541.py:61-63</code> | medium | medium | 40/100 (medium) | <code>standard_report</code> |
| 25 | **Raw HTML Format** | scanner / semgrep-ce | 2 | <code>testcode/BenchmarkTest00541.py:65-67</code> | medium | medium | 40/100 (medium) | <code>standard_report</code> |
| 26 | **Raw HTML Format** | scanner / semgrep-ce | 2 | <code>testcode/BenchmarkTest01025.py:61-63</code> | medium | medium | 40/100 (medium) | <code>standard_report</code> |
| 27 | **Raw HTML Format** | scanner / semgrep-ce | 2 | <code>testcode/BenchmarkTest01025.py:65-67</code> | medium | medium | 40/100 (medium) | <code>standard_report</code> |
| 28 | **Subprocess Shell True** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00512.py:56</code> | low | medium | 33/100 (low) | <code>standard_report</code> |
| 29 | **Subprocess Shell True** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00736.py:55</code> | low | medium | 33/100 (low) | <code>standard_report</code> |
| 30 | **Use Defused XML Parse** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00457.py:48</code> | medium | medium | 32/100 (low) | <code>standard_report</code> |
| 31 | **Insecure Hash Function** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00874.py:57</code> | medium | medium | 32/100 (low) | <code>standard_report</code> |
| 32 | **Insecure Hash Function** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00973.py:61</code> | medium | medium | 32/100 (low) | <code>standard_report</code> |
| 33 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00205.py:45</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 34 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00205.py:46</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 35 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00206.py:45</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 36 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00206.py:46</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 37 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00457.py:44</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 38 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00541.py:42</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 39 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00541.py:43</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 40 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest01025.py:42</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 41 | **Use Defused XML** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest01025.py:43</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 42 | **Open Redirect** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest01209.py:31-52</code> | medium | low | 27/100 (low) | <code>standard_report</code> |
| 43 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00011.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 44 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00063.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 45 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00065.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 46 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00065.py:63-66</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 47 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00067.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 48 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00077.py:26-30</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 49 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00650.py:73-76</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 50 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00721.py:57-60</code> | low | low | 12/100 (low) | <code>standard_report</code> |
| 51 | **Secure Set Cookie** | scanner / semgrep-ce | 1 | <code>testcode/BenchmarkTest00811.py:58-61</code> | low | low | 12/100 (low) | <code>standard_report</code> |

Identifiers:

1. Record <code>merged-cd88912f8146c062dacf</code>; rule(s): <code>py/code-injection</code>; source evidence: <code>finding-009a1e60223d043f2cf8</code>.
2. Record <code>merged-93ccb9cb7ebc9422e31c</code>; rule(s): <code>py/code-injection</code>; source evidence: <code>finding-503cebd040543beb31d7</code>.
3. Record <code>merged-050536f628fbddaf1e1c</code>; rule(s): <code>py/code-injection, python.lang.security.audit.exec-detected.exec-detected</code>; source evidence: <code>finding-ba753b302a64cec3a6a7</code>, <code>finding-06782f54ff608e58472f</code>.
4. Record <code>merged-a1b9777f103958f5ab7e</code>; rule(s): <code>py/command-line-injection, python.lang.security.audit.subprocess-shell-true.subprocess-shell-true</code>; source evidence: <code>finding-ae724eb3fe6b7a0bb0f7</code>, <code>finding-8de78028889fe9981adb</code>.
5. Record <code>merged-009e23ebbe55e21c6bf6</code>; rule(s): <code>py/command-line-injection, python.lang.security.audit.subprocess-shell-true.subprocess-shell-true</code>; source evidence: <code>finding-b09f946d1643a35cc089</code>, <code>finding-1b87faa09f3ca8b6dd44</code>.
6. Record <code>merged-e3541edd3a1bee97e935</code>; rule(s): <code>py/unsafe-deserialization, python.django.security.audit.avoid-insecure-deserialization.avoid-insecure-deserialization, python.flask.security.insecure-deserialization.insecure-deserialization, python.lang.security.deserialization.pickle.avoid-pickle</code>; source evidence: <code>finding-f3f411cd87fb4440051e</code>, <code>finding-bd34cc18197c5674fc48</code>, <code>finding-48a4d41a0c563891a2dc</code>, <code>finding-a9170209f357396dd712</code>.
7. Record <code>merged-400abf28dca80b22eac6</code>; rule(s): <code>py/unsafe-deserialization, python.flask.security.insecure-deserialization.insecure-deserialization, python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load</code>; source evidence: <code>finding-f707c333f3f59481c9fb</code>, <code>finding-45b98bc610dc839c7bc7</code>, <code>finding-e699c351fb39a7bea1dd</code>.
8. Record <code>merged-45c2e411890b332b06f9</code>; rule(s): <code>py/xpath-injection</code>; source evidence: <code>finding-3a9499ac90c2ee4edeba</code>.
9. Record <code>merged-919caa004fdbceac06f2</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-be66bb048a9a80ca0e4b</code>.
10. Record <code>merged-c0e018ebfac46ce99f7a</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-ac04ad088b8a69111938</code>.
11. Record <code>merged-1970d12d68ceaafba0e8</code>; rule(s): <code>py/xpath-injection</code>; source evidence: <code>finding-f67c618ed3506f25b11d</code>.
12. Record <code>merged-d9a3103e3b61f4dae4ce</code>; rule(s): <code>py/xxe</code>; source evidence: <code>finding-4273d965e5be22f7d25e</code>.
13. Record <code>merged-9d738fad026bef853071</code>; rule(s): <code>py/path-injection</code>; source evidence: <code>finding-91fb928630f47bc85791</code>.
14. Record <code>merged-70dd3ccf4dc41b3e34bd</code>; rule(s): <code>py/xml-bomb</code>; source evidence: <code>finding-f8c89ee228e907f84479</code>.
15. Record <code>merged-033aebac980099fb12a6</code>; rule(s): <code>py/cookie-injection</code>; source evidence: <code>finding-0452a64d9b6b6382d1ea</code>.
16. Record <code>merged-263d0640bf3610037384</code>; rule(s): <code>py/cookie-injection</code>; source evidence: <code>finding-7abba6dc72c390b8304c</code>.
17. Record <code>merged-231be71fdd1bd02e0a45</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-83a709d6d669e9a5f191</code>.
18. Record <code>merged-a66c3f23191106bb0341</code>; rule(s): <code>py/cookie-injection</code>; source evidence: <code>finding-9251e2e563b9fb8fb7a7</code>.
19. Record <code>merged-873793ca5922fa6b7b9d</code>; rule(s): <code>py/url-redirection</code>; source evidence: <code>finding-a896fe5b430cb0aa7f33</code>.
20. Record <code>merged-e9491e0832b7f0dcbc76</code>; rule(s): <code>py/cookie-injection</code>; source evidence: <code>finding-223d3a5418d9cbeeed0e</code>.
21. Record <code>merged-41bdaddcc2c7e235d9dd</code>; rule(s): <code>python.lang.security.audit.eval-detected.eval-detected</code>; source evidence: <code>finding-12a7d61cda69f83a49e8</code>.
22. Record <code>merged-6e17d8a7ed920dfffa14</code>; rule(s): <code>python.lang.security.audit.eval-detected.eval-detected</code>; source evidence: <code>finding-d913fe0b6a847c746bb9</code>.
23. Record <code>merged-df2ab461064f6c7e1bd9</code>; rule(s): <code>python.lang.security.audit.exec-detected.exec-detected</code>; source evidence: <code>finding-b03d0f266de23134f622</code>.
24. Record <code>merged-6dd9a319e02dbca16dee</code>; rule(s): <code>python.django.security.injection.raw-html-format.raw-html-format, python.flask.security.injection.raw-html-concat.raw-html-format</code>; source evidence: <code>finding-8b1107bf496f3d44c2fd</code>, <code>finding-53b2266cd63857f1c867</code>.
25. Record <code>merged-a449e190a79978195506</code>; rule(s): <code>python.django.security.injection.raw-html-format.raw-html-format, python.flask.security.injection.raw-html-concat.raw-html-format</code>; source evidence: <code>finding-d20dbb107b0e6ae86663</code>, <code>finding-e3a581db7085150a6795</code>.
26. Record <code>merged-801988beb8cb31e505e2</code>; rule(s): <code>python.django.security.injection.raw-html-format.raw-html-format, python.flask.security.injection.raw-html-concat.raw-html-format</code>; source evidence: <code>finding-a71e2990b6838289e464</code>, <code>finding-e03998b418989a4fa00c</code>.
27. Record <code>merged-d0e83a8971a3076d5dca</code>; rule(s): <code>python.django.security.injection.raw-html-format.raw-html-format, python.flask.security.injection.raw-html-concat.raw-html-format</code>; source evidence: <code>finding-db584a3a1ea42dea514d</code>, <code>finding-83575777006f72f46225</code>.
28. Record <code>merged-ecfae281c92e48f47e88</code>; rule(s): <code>python.lang.security.audit.subprocess-shell-true.subprocess-shell-true</code>; source evidence: <code>finding-66ba4564b97c24bdfdbb</code>.
29. Record <code>merged-1b85485232aeba51d3f6</code>; rule(s): <code>python.lang.security.audit.subprocess-shell-true.subprocess-shell-true</code>; source evidence: <code>finding-25ca75990c0a51d0d5d0</code>.
30. Record <code>merged-6e94166c13c105743cd0</code>; rule(s): <code>python.lang.security.use-defused-xml-parse.use-defused-xml-parse</code>; source evidence: <code>finding-16828fc17d5459e205c3</code>.
31. Record <code>merged-6d81cccb1057a62d9ca9</code>; rule(s): <code>python.lang.security.insecure-hash-function.insecure-hash-function</code>; source evidence: <code>finding-f1ad9680b9df85760ddf</code>.
32. Record <code>merged-4dd2bd234bbe20759ce5</code>; rule(s): <code>python.lang.security.insecure-hash-function.insecure-hash-function</code>; source evidence: <code>finding-2d070b2abfbf42a7cacb</code>.
33. Record <code>merged-5c56fa4a013be9eef7d0</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-a003a27a0cb1a66d4ac4</code>.
34. Record <code>merged-673090543bb62bba96b3</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-d520228d40fec8284318</code>.
35. Record <code>merged-4cb8efbc15a10afc6cfb</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-76644c2fcb4646a2fed3</code>.
36. Record <code>merged-fde8dc9870f5f28223c1</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-08abdf53e807363e86ff</code>.
37. Record <code>merged-64071c15d675a3d3e8ea</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-ae05cf4f5a83110213fd</code>.
38. Record <code>merged-2435c0aa231f3cbd996b</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-c73534309b5efe50bab7</code>.
39. Record <code>merged-28bcb0bf656b7f9c4f4c</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-879085a08198403a7c94</code>.
40. Record <code>merged-9662931cbf4d201b6406</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-00cd5a6d1a90437238f5</code>.
41. Record <code>merged-c50c304da400148f5601</code>; rule(s): <code>python.lang.security.use-defused-xml.use-defused-xml</code>; source evidence: <code>finding-ddbc9c594047a5854067</code>.
42. Record <code>merged-59104315cc7fbecf816d</code>; rule(s): <code>python.flask.security.open-redirect.open-redirect</code>; source evidence: <code>finding-72a4a789bd186297d6bf</code>.
43. Record <code>merged-41b7fb14c2b705d2339a</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-4b48281d844c598343b0</code>.
44. Record <code>merged-92dea1df16ff88394d49</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-463d74412dc2dc39e054</code>.
45. Record <code>merged-a74d7166214d380a3685</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-bfe7f8ae7398ab2a670c</code>.
46. Record <code>merged-ceff5e102223acdb6280</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-f4dd059b243343fbadb7</code>.
47. Record <code>merged-38f328aee2c78d0858f8</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-a4103f2d45beb4fc32a1</code>.
48. Record <code>merged-16c43267d0930a4498e8</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-97fc31de78efc8859f2a</code>.
49. Record <code>merged-d22128425937cabb4b39</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-ec3314244ca7b7470fb1</code>.
50. Record <code>merged-150764bd1f8d7530fbfe</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-c487b9ba0f9ad46cd171</code>.
51. Record <code>merged-2dccd1ff04bde0963fda</code>; rule(s): <code>python.flask.security.audit.secure-set-cookie.secure-set-cookie</code>; source evidence: <code>finding-9476b1be63de3f02dd81</code>.

</details>

### C. Candidate triage and unresolved evidence

Scanner/DAST observation records: **51**; issue groups after conservative correlation: **52**. Every original observation stays linked by source ID.
AI candidates: **2**; scanner overlaps: **0**; AI overlaps: **0**; new candidates: **1**; uncertain overlaps: **0**; needs more evidence: **1**; rejected: **0**.

These AI candidates are not confirmed vulnerabilities and were not silently discarded:

- `ai-a433cd9eabd54f61`: needs\_more\_evidence at `helpers/db_sqlite.py:33`

Verification status: **partial**; see `verification.json` for source-evidence checks.

### D. Method and limitations

- Scanner and AI silence is not proof that the project is secure; validate before release decisions.
- Verdicts are produced by an AI model reading bounded code excerpts; they are not independently validated exploits.
- Severities and scores are triage aids, not CVSS ratings.
- No runtime/DAST evidence is included, so exploitability is inferred from code.

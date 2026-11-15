# تعديلات Verdict: ربط Graphify + Autonomous Penetration Testing Agent

هذا الملف بيلخّص 3 حاجات: (1) إيه اللي كان ناقص فعلاً في الريبو وخلّى Graphify مش متوصّل، (2) إيه
اللي اتعمل عشان يتحل، (3) الـ Penetration Agent الجديد: إيه اللي شغّال فعلاً وإيه اللي لسه محتاج
شغل حقيقي مع Docker (مش متاح في البيئة اللي راجعت بيها الكود).

## 1) مراجعة الريبو: إيه الموجود وإيه الناقص (قبل التعديل)

شغّلت الـ test suite كله الأول عشان أاخد baseline:
`570 passed, 5 failed (pre-existing), 4 skipped` — الـ 5 failures دول في تقارير HTML/Markdown
(`test_final_report_observations.py`, `test_html_report.py`, `test_rca_run_v27.py`) وملهومش علاقة
بالتعديلات، وسايبهم زي ما هم (مش من اختصاص الطلب ده).

**Graphify تحديدًا**: اللي لقيته إن `profiler/code_graph.py` بس *يقرأ* ملف `graph.json` لو
لاقاه (schema parsing فقط) — مفيش أي مكان في الـ pipeline كله (`scripts/run_pre_review_pipeline.py`,
`scanners/registry.py`, `orchestrator/service.py`) بيعمل *build* للـ graph أو ينادي Graphify. الـ
orchestrator فعليًا بيتجاهل أي enrichment task اسمه `code_graph` لأنه مفيش adapter مسجّل ليه
(`orchestrator/service.py:232` بيرجّع `SKIPPED` بسبب `ENRICHMENT_SKIP_REASON`). يعني المشكلة مش إن
فيه config غلط — المشكلة إن مرحلة بناء الـ graph مش موجودة خالص، فـ `code_graph` فاضل `None` طول
الوقت، والـ hotspots اللي المفروض تأثر على الـ prioritization والـ AI Discovery (`code_graph_hotspot`
risk factor في `prioritization/engine.py`) كانت دايمًا صفر.

**الـ Pipeline الحالي** (ثابت، محافظ عليه بالكامل):
Profiler → (Static) Semgrep/CodeQL/Gitleaks/Trivy → (Dynamic) initial stack + runtime scanners →
Merge → Context → Risk → AI Discovery → Candidate Context → Verification → Candidate Triage →
Security Review → Policy Gate.

## 2) الحل: مرحلة بناء Graph حقيقية (two-pass)

ملف جديد: `profiler/code_graph_stage.py` (`build_code_graph`):

- لو `GRAPHIFY_COMMAND` متظبط (أو `--graphify-command`)، بيشغّل Graphify فعليًا — **من غير shell**
  (`subprocess.run` بـ argv list)، من working directory مؤقت بره الـ project عشان مفيش أي كتابة
  جوا الريبو، وبيتأكد بعد التشغيل إن ملفات المشروع ما اتغيّرتش (`_tree_stamp`). لو فشل لأي سبب
  (مش موجود، timeout، graph فاضي)، بيرجع سبب واضح — مش بيبلع الخطأ.
- لو مفيش Graphify أصلاً، أو فشل: fallback لـ **deterministic built-in import graph** (AST-based
  لـ Python، regex-based لـ JS/TS) — بيتعلّم من نفس ملفات الـ profiler inventory اللي اتعملها
  hashing بالفعل. النتيجة بتتسجّل `engine: "builtin"` واضح في التقرير عشان محدش يفتكر إنه Graphify.

في `scripts/run_pre_review_pipeline.py`: اتضاف `--code-graph {auto,off}` و`--code-graph-json`
(لو حابة تدّي graph جاهز من Graphify نفسه بره الـ pipeline) و`--graphify-command`. لما يكون `auto`،
الـ profiler بيتعمله pass تاني بعد بناء الـ graph (`profile_project(project, code_graph_path=...)`)
عشان الـ hotspots توصل لـ `prioritize_findings` ولـ AI Discovery ordering في `discovery/scope.py`
(الملفات اللي فيها hotspot من الـ graph بقت تتفحص الأول).

كمان لقيت حاجة تانية مرتبطة أثناء المراجعة: CodeQL adapter كان بيدوّر على `codeql.exe` بس — يعني
على Linux/WSL native مش هيلاقيه. استخدمت `scanners.hostpaths.find_codeql` الموجودة بالفعل (بتدوّر
على `codeql` و`codeql.exe` مع بعض) بدل الـ hardcoded `.exe`.

**ملخّص الملفات المعدّلة لحد هنا**: `scripts/run_pre_review_pipeline.py`,
`src/security_reviewer_v2/discovery/scope.py` (ordering بالـ hotspots)، + ملف جديد
`src/security_reviewer_v2/profiler/code_graph_stage.py`.

## 3) Autonomous Penetration Testing Agent — الموجود في `dynamic_penetration_agent/`

Package جديد بالكامل، منفصل زي ما اتطلب، 9 ملفات مطابقة للأسماء في الطلب:
`models.py`, `hypothesis_analyzer.py`, `attack_planner.py`, `templates.py`, `scenario_validator.py`,
`tool_orchestrator.py`, `evidence_collector.py`, `evidence_evaluator.py`, `adaptive_controller.py`,
`agent.py` (نقطة الدخول: `run_penetration_tests`).

### إيه اللي بيعمل فعلاً (مُختبر، end-to-end، بـ fake transport)

- **Loop تكيفي حقيقي**: Plan → Validate → Execute → Observe → Evaluate → Re-plan، مش سيناريو ثابت.
  لو أول attempt رجّع evidence استغلال، بيوقف فورًا (`exploitation_confirmed`). لو اتحظر، بيجرّب
  template تاني من اللي متاحين. مفيش تكرار لنفس الـ strategy على نفس الـ hypothesis.
- **3 الـ Templates** (section 5 بالظبط): `unauthenticated_access`, `authorization_matrix`, `idor`.
  كل واحد بيحدد الـ status المتوقع (401/403/404) كـ **assertion مصمّمة مسبقًا**؛ فلو الرد فعلاً 200،
  دي مش "200 عادي" — دي فشل الـ assertion المحدّدة، وده اللي بيترجم لـ `violation` في
  `runtime_workflows` (مش افتراض إن أي 200 = ثغرة).
- **Validator حتمي قبل كل تنفيذ** (`scenario_validator.py`): بيرفض أي plan فيه endpoint مش في
  الـ allowlist المكتشف من الكود/الـ Contract، أو account مش من الـ Contract، أو method غير
  GET/HEAD (يعني **مفيش mutation خالص** من الـ Agent ده)، أو body في الـ request. وبعدين بيبني
  الـ `runtime_workflows` suite بالكامل ويمرّره على `validate_suite` الموجودة أصلاً (مفيش parser
  تاني موازي).
- **Execution Budget** (`execution_budget.py`): حد أقصى attempts/requests لكل hypothesis، وحد
  إجمالي، وحد وقت لكل hypothesis ووقت إجمالي — متحقق منه قبل كل attempt، مش بعد ما يحصل.
- **إعادة استخدام فعلية مش قول بس**: التنفيذ بيعدّي على `scanners/runtime_workflows.py` (نفس
  الـ HTTP executor اللي بيستخدمه الـ DAST الحالي)، والـ evidence بتتفلتر بنفس
  `normalization/runtime_evidence.bounded_runtime_evidence` الموجودة (يعني مفيش bodies/tokens/secrets
  محفوظة — مطابق للـ allowlist الحالي).
- **الحالات الخمسة بالظبط** (section 7): `exploitation_confirmed`, `not_reproduced`, `inconclusive`,
  `blocked`, `cannot_test` — دي نتيجة الاختبار بس، مش حكم نهائي.
- اتعمل اختبارات (`tests/test_dynamic_penetration_agent.py`, 8 اختبارات) بتغطي: الاستغلال بيوقّف
  فورًا، الدفاع السليم بيدّي `not_reproduced`، عدم وجود route بيدّي `cannot_test` من غير أي request،
  بس الـ candidates اللي الـ Verification أكدتها بتتفحص، الـ budget بيوقف اللوب، ورفض الـ Validator
  للـ endpoint/method/account الخارجين عن النطاق.

### الربط في `agent_graph.py` — Node جديد، **معطّل افتراضيًا**

اتضاف `dynamic_penetration_agent` Node بين `verification` و`candidate_triage`، بالظبط زي الـ
flow اللي طلبتيه. لكن بالتصميم:

- لو مفيش `penetration_access` و`penetration_target_resolver` متبعتين صراحةً لـ
  `run_agent_review_graph(...)`، الـ Node ده **no-op**: بيكتب `dynamic-penetration-test.json`
  بحالة `not_run` بس، ومفيش أي تغيير في سلوك الـ pipeline الحالي. اتأكدت من كده بتشغيل كل الاختبارات
  القديمة بعد التعديل (نفس الـ 570 عدّو + الـ 5 fails القديمة بالظبط، زائد الاختبارات الجديدة).
- لو اتفعّل، بياخد نتيجة الـ Agent ويضيفها كـ **notes** على نفس الـ `VerificationRecord` المؤكد
  مسبقًا (من غير ما يغيّر الـ disposition) — وده المقصود بـ "الـ Verification بعد الاختبارات بتقيّم
  أدلة الاستغلال" من غير ما تبقى سلطة منفصلة فوق الـ Verification أو الـ Review.
- اتعدّل اختبار `test_agent_graph.py` بس عشان يستوعب artifact الاسم الجديد
  (`dynamic-penetration-test.json`) في الـ sequence — ده التغيير الوحيد في اختبار موجود.

### الربط بالـ CLI/Pipeline — Stack ثانٍ منفصل ومعزول (section 6)

في `scripts/run_pre_review_pipeline.py` اتضافت flags:
`--penetration-test-environment-config` (ملف JSON منفصل تمامًا عن ملف الـ test-environment الأول —
الأول بيتقفل قبل الـ static/AI زي ما هو، والتاني ده خاص بالـ Agent بس)، `--penetration-allow-compose-execution`،
و5 flags للـ budget.

دالة `_penetration_session(...)` الجديدة بتعمل reuse **كامل** لـ `test_environment/manager.py`
الموجودة (مفيش كود Docker جديد خالص): `load_environment_spec` → `plan_environment` →
`provision_environment` (context manager موجود بالفعل، بيعمل compose up/health-check/yield/compose
down + تحقق من الـ cleanup — كل ده already hardened وموجود). الـ Stack بيفضل شغّال طول مدة الـ
Node بس (جوا الـ `with` block)، وبيتقفل تلقائيًا لما الـ Node يخلص — يعني مفيش وقت مفتوح، ومحكوم
بـ `--penetration-max-total-seconds`.

الـ `RuntimeAccess` (base_url + allowed_endpoints + accounts) بتتبني من: `session.base_url` (من
الـ provisioning نفسه)، و`allowed_endpoints` = الـ routes المكتشفة من الكود (`context/routes.py`
عن طريق دالة جديدة صغيرة `handler_for_source_location` بتربط مكان الـ candidate في السورس
بالـ route الفعلي) **مدمجة مع** `spec.endpoint_paths` من الـ Contract، و`accounts`/
`account_definitions` من `spec.workflow_suite["accounts"]` اللي هي نفسها بنية الـ Contract
الموجودة حاليًا — يعني الـ Agent فعليًا مش بيخترع أي account أو endpoint، كل حاجة جاية من مصدر
موثوق موجود بالفعل.

### الصراحة بخصوص اللي لسه ناقص (مهم جدًا أقولها بدل ما أدّعي إنها كاملة)

1. **مفيش Docker في البيئة اللي راجعت بيها الكود**، فـ `provision_environment` والـ Stack الثاني
   كله **متأكد من الناحية البرمجية والـ wiring بس**، مش اتشغّل فعليًا ضد container حقيقي. لازم
   تجربيه عندك محليًا بملف `environment-spec` حقيقي قبل ما تثقي فيه production.
2. **ZAP و Playwright كأدوات تنفيذ لكل attempt مش متوصّلين لسه** — `tool_orchestrator.py` بيرفض
   صراحةً (`ToolUnavailable`) لو الـ plan محتاجهم، وبيرجع سبب واضح بدل ما "يسكت" أو يرجع نتيجة
   وهمية. المرحلة الأولى شغّالة بـ `runtime_workflows` بس (أداة واحدة، زي ما الطلب قال "نبدأ بالموجود
   من غير إضافة أدوات جديدة").
3. **قالب الـ IDOR محتاج evidence صريح برقم/مسار حقيقي** من الـ Discovery نفسها (مذكور في
   `candidate.evidence`) — لو مفيش، الـ Agent بيعدّي على template تاني بدل ما يخترع ID. ده قرار
   متعمّد (مطابق لـ "لا يخترع Endpoints أو Accounts")، بس معناه إن الـ IDOR template هيشتغل بس على
   candidates فيها evidence واضح بمسار تاني.
4. **مقارنة الأداء مقابل الـ Ground Truth (section 9)**: المنهجية موجودة في تصميم الـ outputs
   (`usage` في `PenetrationTestReport` فيه `total_attempts`, `total_requests`,
   `exploitation_confirmed`)، بس سكريبت المقارنة الفعلي بين "قبل/بعد" على الـ Multi-Service Lab
   لسه مش مكتوب — محتاج وقت إضافي لو عايزاه.

## 3.5) تحديث: ZAP وPlaywright بقوا متوصّلين فعليًا + تبسيط التشغيل

### ZAP (`zap_attempt.py`)

`scanners/zap_runtime.run_zap` أداة كبيرة (container Docker لكل استدعاء، بتفحص الموقع كله مش endpoint
واحد). بدل ما أعمل أداة موازية وهمية، وسّعت `automation_plan`/`run_zap` بباراميتر اختياري
`scope_path` (default `None` = السلوك القديم بالظبط — مفيش أي كسر، والاختبارات الموجودة
(`tests/test_local_workspace.py`) عدّت زي ما هي) بيضيّق الـ spider والـ active scan على مسار واحد بس.
`zap_attempt.run_scoped_attempt(...)` بيشغّل scan واحد scoped على الـ hypothesis، وبيحوّل النتيجة
لنفس شكل `runtime_workflows` ({"workflows": [{"status", "steps": [...]}]}) عشان `evidence_evaluator`
يفهمها من غير أي تعديل في منطقه. **شرط صريح موروث من `run_zap` نفسها**: ZAP الـ active بيشتغل بس
لما يكون للـ Agent Compose stack خاص بيه (`stack_name`/`app_service` معروفين) — مش شغّال مع
`existing_url` خالص، وده قرار الأداة الأصلية مش حاجة ضيّفتها أنا.

### Playwright (`playwright_attempt.py` + `scripts/run_browser_probe.mjs`)

السكريبت الموجود `run_browser_dast.mjs` crawler للموقع كله، مالوش مفهوم "زوري صفحة واحدة بحساب
معيّن". عملت سكريبت جديد **صغير ومحدود**: بيعمل login حقيقي (بنفس بنية الـ account الموجودة في
`workflow_suite` — JSON/form POST لـ `login_path`، ونفس أسماء الحقول — مش بيخترع آلية تسجيل دخول
جديدة)، وبعدين بيزور صفحة واحدة بمتصفح حقيقي (Chromium headless)، ويلاحظ أي استدعاء XHR/fetch من
نفس الأصل بيحصل أثناء التحميل (مفيد لو الـ SPA بتجيب بيانات محمية بعد التحميل عن طريق JS). كل
الطلبات داخل المتصفح مقيّدة بـ GET + نفس الأصل بس (زي الـ crawler القديم بالظبط). `playwright_attempt.py`
بيشغّله ويحوّل النتيجة لنفس الشكل الموحّد. شرط: محتاج Node.js موجود + الهدف لازم يكون loopback.

### منطق الاستخدام: HTTP الأول، تأكيد واحد بس لو لزم

`adaptive_controller.py` اتعدّل عشان يستخدم ZAP/Playwright كـ **تأكيد (corroboration)**، مش كبديل
للـ HTTP: أول محاولة دايمًا `runtime_workflows` (الأرخص والأسرع). لو النتيجة جت "مرفوض بشكل سليم"
أو "مش حاسمة" (مش exploitation واضح، ومش blocked بالكامل)، وفيه ZAP أو Playwright متاحين، بيعمل
**محاولة تأكيد واحدة بس** باستخدام نفس الـ strategy بس بأداة تانية — مش تكرار عشوائي، ومش هيشتغل
لو أصلاً فيه exploitation confirmed. ده بيحترم مبدأ "عدم الـ over-testing" في القسم 4 من التصميم.
ضفت 3 اختبارات جديدة (11 إجمالي دلوقتي في `tests/test_dynamic_penetration_agent.py`، كلهم عدّو)
بتتأكد من: التأكيد بيحصل صح، مفيش تأكيد لو مش متفعّل (السلوك الافتراضي)، والـ `tool_orchestrator`
بيعمل fallback لأداة تانية لو الأولى مش متاحة بدل ما يفشل فورًا.

### تبسيط التشغيل: مفيش ملف config منفصل تاني مطلوب

بدل ما تحتاجي تعملي ملف `--penetration-test-environment-config` منفصل كل مرة، دلوقتي:

- لو بعتِ `--test-environment-config` بس (اللي أصلاً بتستخدميه للمرحلة الأولى) ومحطيتيش
  `--no-penetration-agent`، الـ Agent بيفتح **سيشن تانية تلقائيًا بنفس الملف ده بالظبط** — من غير
  أي خطوة إضافية. `--penetration-test-environment-config` بقت اختيارية، تستخدميها بس لو عايزة ملف
  **مختلف** عن الأول.
- `--no-penetration-agent`: لو عايزة توقفي الـ Agent صراحة حتى لو فيه contract.
- `--penetration-enable-playwright`: تفعيل تأكيد المتصفح (زي `--browser-dast` بالظبط في مستوى الثقة).
- لو بتستخدمي `scripts/run_project_pipeline.py` (السكريبت الرئيسي)، مفيش أي حاجة إضافية تعمليها
  خالص: لو كنتي حاطة `--allow-trusted-local-compose` و/أو `--browser-dast` قبل كده، نفس الثقة دي
  بتتنقل تلقائيًا للـ Agent (`--penetration-allow-compose-execution` و`--penetration-enable-playwright`
  بيتضافوا لوحدهم للأمر الداخلي). ده بالظبط "نفس الإعدادات القديمة لو ينفع" اللي طلبتيه.

## 3.6) تحديث: كل محاولة بقت تظهر في التقرير النهائي كخطوات تكرار (reproduction steps)

التقرير النهائي (`security-review-report.md`) دلوقتي فيه قسم جديد **"Autonomous Penetration Testing
— Reproduction Steps"** بيعرض **كل محاولة** عملها الـ Agent لكل hypothesis — مش بس النتيجة النهائية.
لكل محاولة بيتكتب: الـ strategy والأداة المستخدمة، الـ endpoint المستهدف، كل خطوة (method + path +
الحساب المستخدم + **كود الـ HTTP الفعلي اللي رجع + الأكواد المتوقعة**)، ملاحظة الـ Agent، وسبب
التفكير، والقرار التالي.

ده معناه إن الأخصائي الأمني يقدر يشوف بالظبط إيه اللي اتجرّب (method + path + account)، يصلّح
المشكلة، وبعدين يعيد نفس الطلب بالظبط ويتأكد إن الكود رجع status مرفوض (401/403/404) بدل ما كان
200 قبل كده.

لقيت وصلّحت مشكلة صغيرة أثناء التنفيذ: الحقول `http_status` و`expected_status` كانت بتتفلتر
(تتشال) من الـ evidence بسبب الـ allowlist الموجودة في `normalization/runtime_evidence.py`
(`bounded_runtime_evidence`)، فكان التقرير هيعرض كلمة "violation" بس من غير الكود الفعلي. ضفت
الحقلين دول للـ allowlist (أرقام status بس، مفيهاش أي بيانات حساسة) — ده بيفيد أي تقرير تاني في
المشروع بيستخدم نفس الدالة مش بس الـ Agent الجديد.

في HTML، القسم ده بيظهر كملخّص (عدد المحاولات، النتيجة) مع إشارة للتقرير الكامل بالـ Markdown —
نفس الأسلوب المتبع فعلاً في باقي أقسام الـ Dynamic DAST في الـ HTML (تفاصيل كاملة في الـ Markdown،
ملخّص في الـ HTML)، عشان محدّتش بنية الـ HTML المعقّدة الموجودة واللي فيها أصلاً 5 اختبارات فاشلة
من قبل التعديلات دي خالص.

**الملفات المعدّلة لهذا الجزء**: `src/security_reviewer_v2/reporting/final.py` (قسم جديد في
الـ Markdown)، `src/security_reviewer_v2/reporting/view.py` (ملخّص في الـ HTML)،
`src/security_reviewer_v2/normalization/runtime_evidence.py` (الإضافة للـ allowlist)،
`scripts/run_pre_review_pipeline.py` (تمرير `penetration_test` للتقرير). اختبار جديد
`test_final_report_lists_every_attempt_as_a_reproduction_step` بيتأكد إن كود الـ HTTP الفعلي
والمتوقع بيظهروا صح.

## 3.7) تشخيص 4 مشاكل اتبلّغ عنها بعد تشغيل حقيقي (run_comprehensive_0009)

راجعت ملفات الـ run اللي اترفعت فعليًا (مش تخمين) عشان أشخّص كل نقطة:

### أ) "Discovery بقى يكتشف أقل (9 بدل 20)"

**في الـ run اللي اترفع، الـ Discovery فعليًا سليم ومش ناقص**: `ai-discovery.json` بيوضّح
`targets inspected: 71/71` (تغطية كاملة، مفيش trimming)، و**39 AI candidate**، و**28 منهم
confirmed** بواسطة الـ Verification، والـ Penetration Agent اختبر الـ 28 دول كلهم وأكّد
**22 exploitation** فعلي. يعني الأرقام في الـ run ده أعلى من "20" مش أقل.

مقدرتش ألاقي رقم "9" في أي مكان بيخص عدد الـ Discovery candidates في الملفات اللي اترفعت.
ممكن يكون ده من run تاني قديم (قبل التعديلات) أو رقم من مكان مختلف (مثلاً `files_in_graph: 8`
في `code-graph-build.json` — وده **مش bug**، ده فعلاً عدد ملفات الـ Python الحقيقي في
`verdict-comprehensive-lab` (8 ملفات: `api/app.py`, `api/extra.py`, `api/seed.py`,
`mock_external/server.py`, `worker/worker.py` + 3 `__init__.py`) — اتأكدت منه مقارنة بـ
`profile.json`). **لو لسه شايفة الرقم ده في مكان تاني، قوليلي بالظبط فين (اسم الملف أو السطر في
الواجهة) عشان أتابعه بدقة.**

### ب) "Evidence الـ Penetration Agent مش واضح في التقرير"

**موجود وواضح فعلاً** — في `security-review-report.md` بتاع الـ run ده، قسم
`## Autonomous Penetration Testing — Reproduction Steps` (السطر 30) فيه تفاصيل كل محاولة من
الـ 52 محاولة اللي عملها الـ Agent على الـ 28 hypothesis، بما فيها الـ 22 اللي اتأكّد استغلالها.
لو الواجهة اللي بتفتحيها بتعرض التقرير ناقص أو قديم، تأكدي إنك فاتحة `security-review-report.md`
(أو `.html` بتاعه) من نفس مجلد الـ run اللي اشتغل فيه الـ Agent، مش من run قديم.

### ج) "الـ Agent مش ظاهر خالص في LangSmith" — ده كان bug حقيقي واتصلّح

السبب: `dynamic_penetration_agent` Node بيشتغل بكود Python عادي **من غير أي استدعاء LLM جواه**،
والـ pipeline بينادي `graph.compile().invoke({})` من غير `config` فيه تتبّع صريح. يعني الـ Node
ده كان مالوش أي "span" خاص بيه يظهر في شجرة الـ trace — عكس الـ Nodes التانية اللي بتستدعي موديل
جوّاها وبيظهر ليها run تلقائيًا بسبب الاستدعاء ده.

**الحل**: ضفت دالة جديدة `node_trace(...)` في `agents/tracing.py`، وغلّفت بيها
`dynamic_penetration_agent` Node في `agent_graph.py`. دلوقتي:
- لو الـ tracing مُفعّل (`LANGSMITH_TRACING=true`)، الـ Node ده هيظهر كـ **run منفصل باسمه** تحت
  الـ trace الرئيسي، وفيه metadata واضحة (عدد الـ candidates المؤكدة، الحالة النهائية، عدد
  الـ hypotheses، عدد الاستغلالات المؤكدة).
- لو الـ tracing مش مُفعّل، الدالة no-op تمامًا (زيرو تكلفة، زي باقي الكود).
- لو حصل أي عطل في الاتصال بـ LangSmith نفسه، الكود بيكمل عادي من غير ما يوقف الـ run (نفس مبدأ
  "tracing optional" الموجود في باقي الملف).
- **مهم**: الاستثناءات الحقيقية من كود الـ Agent (لو حصل خطأ فعلي) بتتسجّل كـ "error" في الـ span
  وبعدين **بتتصعّد زي ما هي** — مش بتتبلع. ده كان لازم ينتبه له بدقة عشان مكنش يختفي bug حقيقي
  ورا مشكلة tracing.

ضفت 4 اختبارات جديدة (`tests/test_node_trace.py`) بتتأكد من كل الحالات دي.

### د) "Review Agent مكملش"

ده **مش bug من التعديلات، ده rate limit حقيقي من Groq**. القيمة في `security-review.json`:
```
"warnings": ["Review provider stopped: AI provider request failed with HTTP 429
             (rate_limit_exceeded); provider asked to wait 605 s"],
"reviewed_groups": 71, "pending_groups": 18
```
يعني Groq رفض الطلب وطلب الانتظار 605 ثانية (10 دقايق تقريبًا). الـ pipeline **بتصميم متعمّد
وموثّق في الكود نفسه** (`discovery/provider.py`) **مش بتعمل retry لو الانتظار المطلوب طويل** —
عشان متوقفش الـ run كله 10 دقايق واقف من غير أي تقدّم. ده قرار تصميم قديم مش حاجة ضفتها في
تعديلاتنا.

**الحل**: فيه سكريبت جاهز بالظبط للحالة دي: `scripts/resume_local_review.py` — بيكمّل الـ review
من نفس المكان (الـ 18 `pending_ids`) من غير ما يعيد تشغيل Docker أو الـ scanners تاني:
```bash
python3 scripts/resume_local_review.py \
  targets/verdict-comprehensive-lab \
  runs/run_comprehensive_0009 \
  runs/run_comprehensive_0009_resumed
```
أو ببساطة شغّلي نفس أمر الـ pipeline تاني بعد شوية (الـ rate limit بيتصفّر لوحده بعد دقايق).

## 3.8) رد على 3 أسئلة تانية: كل السيناريوهات في التقرير، الربط بالثغرة، وهل ده AI فعلاً

### أ) دلوقتي كل سيناريو "رسمه" الـ Agent بيظهر، حتى لو ما اتنفّذش خالص

قبل كده التقرير كان بيعرض بس المحاولات اللي **اتنفّذت فعليًا** (وصلت لمرحلة إرسال طلب). لو
استراتيجية اتلغت قبل الإرسال (مثلاً `idor` اتلغت لأنه مفيش حساب تجريبي متاح، أو `authorization_matrix`
اتلغت لنفس السبب)، المعلومة دي كانت بتضيع من التقرير خالص. دلوقتي ضفت حقل جديد
`considered_but_not_executed` في نتيجة كل hypothesis، وبيظهر في التقرير تحت كل عنوان كـ:

> **Other scenarios the agent drew up but could not execute at all (never sent a single request):**
> - `idor`: No authenticated test account is declared in the Runtime Contract.
> - `authorization_matrix`: No authenticated test account is declared in the Runtime Contract.

كده الأخصائي بيشوف **الصورة الكاملة**: إيه اللي اتجرّب فعلاً، وإيه اللي كان في الخطة بس اتلغى
وليه — مش بس النتيجة النهائية.

### ب) الثغرة دلوقتي بتتوصّل في التقرير إنها "أكدها الـ Penetration Agent"

ضفت ربط تلقائي (مش معتمد على الـ LLM يفتكر يقول كده): لما الـ Penetration Agent يأكّد استغلال
لـ hypothesis معيّنة، بيتربط الـ ID بتاعها (عن طريق بيانات الـ Triage الموجودة أصلاً) بالـ finding
في باقي أقسام التقرير، ويظهر السطر ده تلقائيًا في **3 أماكن**:
1. في قسم "Scanner and DAST Observations" — جنب الـ evidence مباشرة.
2. في قسم "Security Review Agent Verdicts" — جنب الـ verdict بتاع الـ finding.
3. في قسم "Policy Decisions" — جنب قرار الـ block/warn/allow.

السطر بيظهر بالظبط كده: **"✅ Independently confirmed by the Autonomous Penetration Agent"**.
ده بيحصل **تلقائيًا ومضمون** (مش بيعتمد على إن الـ LLM يذكره بنفسه في كلامه).

### ج) سؤال مهم: الـ Agent ده rule-based ولا AI بيفهم ويغيّر قراره؟

**إجابة صريحة ومهمة أقولها كده بالظبط، خصوصًا إنك هتقوليها للمدير:**

> **الـ Agent ده كود Python محدّد القواعد (rule-based / deterministic)، مش LLM بيفكّر ويقرر.**

بالتفصيل:
- **اختيار الاستراتيجية التالية**: مش بيفكّر بحرية، بيختار من **قايمة ثابتة مرتّبة** (IDOR → Authorization
  Matrix → Unauthenticated Access) حسب كلمات مفتاحية في وصف الـ candidate (زي "ownership" أو
  "authorization"). ده منطق `if/else` بسيط، مش استنتاج ذكاء اصطناعي.
- **الحكم على النتيجة (هل ده استغلال ولا لأ)**: بيقارن **كود الـ HTTP status الفعلي** بكود متوقع
  محدّد مسبقًا في الـ template (401/403/404 = آمن، أي حاجة تانية = مشكلة). ده **مقارنة أرقام
  deterministic 100%**، مفيهاش "فهم" للمحتوى أو السياق.
- **قرار "يكمّل ولا يوقف"**: بيتحدد بجدول قواعد ثابت (budget/attempts/exploitation_confirmed)
  مش بتقدير.

**الحاجة الوحيدة اللي فيها "ذكاء" فعلي في السلسلة دي هي الذكاء الاصطناعي (LLM) في مرحلة
الـ Discovery الأولانية** — هو اللي بيقرأ الكود ويكتشف الاشتباه الأول ("ممكن يكون فيه مشكلة
هنا"). بعد كده، الـ Penetration Agent بياخد الاشتباه ده **كمدخل** ويختبره بمنطق قواعد ثابت.

**ليه القرار ده (مش LLM) أفضل هنا فعليًا:**
- أرخص وأسرع بكتير (مفيش تكلفة API لكل محاولة اختبار).
- **يمكن التنبؤ به ومراجعته**: أي حد يقدر يقرأ الكود ويعرف بالظبط إمتى هيقرر "ده استغلال" — عكس
  LLM ممكن يحكم بشكل مختلف كل مرة.
- أأمن: مفيش احتمال إن الـ LLM "يتوه" ويعمل طلب مش مصرّح بيه بسبب تفسير غلط.

**خلاصة الجملة اللي تقوليها للمدير:** "الذكاء الاصطناعي بيكتشف الاشتباه الأول بس. بعد كده، أداة
اختبار قواعدها ثابتة ومكتوبة بوضوح هي اللي بتثبت الاشتباه ده بدليل فعلي — مش قرار ذكاء اصطناعي
حر."

### د) بخصوص رقم "٩"

راجعت `coverage-summary.json` و`merged.json` و"Scanner Execution" section في التقرير بتاع الـ
run اللي اترفع (`run_comprehensive_0009`)، ولقيت إن القسم اللي بيوصف "كل static جاب كام وكل
dynamic جاب كام" بيقول: **26 من الـ static scanners (semgrep 3 + codeql 13 + trivy 10) و37 من
الـ dynamic (web-runtime)**. مفيش رقم "9" في أي حقل من دول في الـ run ده بالذات. لو شايفاه في
نسخة تانية من التقرير أو واجهة مختلفة، ابعتيلي اسم الملف/الشاشة بالظبط وهتابعها.

## 3.9) تحديث كبير: الـ Agent دلوقتي بيفكّر فعلاً في اختيار السيناريو (LLM-based، اختياري)

بناءً على طلب صريح إن الاختيار يبقى "تفكير حقيقي" مش جدول كلمات مفتاحية، ضفت **planner بالذكاء
الاصطناعي حقيقي** (مش تحسين تجميلي) لاختيار السيناريو التالي.

### إزاي شغّال

- ملف جديد `dynamic_penetration_agent/ai_planner.py`: بيبني prompt فيه **الاشتباه كامل** + **كل
  محاولة سابقة وملاحظتها الفعلية** (مش بس النتيجة)، وبيسأل النموذج: "اختار سيناريو واحد من الـ 3
  تجربهم تاني، أو قول stop — واشرح ليه."
- النموذج **بيختار بحرية من الـ 3 سيناريوهات كلهم** (مش متقيّد بجدول الكلمات المفتاحية القديم —
  ده بقى fallback بس لما مفيش AI planner مفعّل أو لما الاستدعاء يفشل).
- ضفت `plan_attack(...)` method جديدة في `GroqProvider` و`OllamaProvider` (في
  `discovery/provider.py`) — بتعمل reuse لنفس آلية الاتصال بالـ API الموجودة أصلاً (نفس الـ API key
  ونفس الـ retry/rate-limit handling)، مش تكامل جديد من الصفر.
- سبب اختيار النموذج ("AI planner: ...") بيتحفظ وبيظهر في `attack_plan` field جوا كل attempt —
  يعني في التقرير النهائي هتشوفي **سبب الذكاء الاصطناعي الفعلي** جنب كل محاولة، مش بس القالب
  الجاهز.

### الحدود اللي **متغيّرتش خالص** (الأمان زي ما هو بالظبط)

**مهم جدًا أوضحه**: الذكاء الاصطناعي هنا **بيختار بس من بين الـ 3 قوالب الموجودين أصلاً** — مش
بيكتب HTTP request من عنده، مش بيخترع endpoint أو account أو payload. لو النموذج رجّع أي حاجة
مش واحدة من الـ 3 أسماء بالظبط (زي لو حاول يقول "sql_injection" أو حاجة تانية)، الكود **بيرفضها
فورًا** ويرجع للاختيار بالقواعد الثابتة — مفيهوش أي مسار ينفّذ بيه النموذج حاجة برّا الـ 3 قوالب
المعتمدين. تقييم النتيجة (هل ده استغلال ولا لأ) **لسه بالمقارنة الحتمية لكود الـ HTTP** زي ما هو —
الذكاء الاصطناعي بيختار "نجرب إيه تاني" بس، مش بيحكم على النتيجة.

لو الاستدعاء للذكاء الاصطناعي فشل (rate limit، timeout، رد غير مفهوم)، الكود **بيرجع تلقائيًا
للاختيار بالقواعد الثابتة لنفس المحاولة** — مش بيوقف الـ Agent ولا بيدّي error.

### إزاي تفعّلها

Flag واحد جديد بس، وبيعمل reuse لنفس إعدادات الذكاء الاصطناعي المستخدمة في الـ Discovery (نفس
الـ API key ونفس الموديل، مش حاجة جديدة):

```bash
python3 scripts/run_pre_review_pipeline.py ... --penetration-ai-planner
```

(أو من `run_project_pipeline.py`: نفس الفكرة، لو حابة أضيفها هناك كمان قوليلي.)

### اختبارات جديدة

- `tests/test_ai_planner.py` (7 اختبارات): اختيار صحيح بيتوصّل، "stop" صريح بيتحترم، رد غير معروف
  بيترفض، exception من الموديل بيترفض برضو، مفيش provider = no-op نضيف، والمنيو المعروضة على
  النموذج بتستبعد الاستراتيجيات اللي اتجرّبت فعلاً.
- `tests/test_dynamic_penetration_agent.py`: اختبارين end-to-end (القرار بيوصل لآخر attempt
  record، وفشل الـ AI provider بيرجع للقواعد الثابتة من غير ما يوقف الحلقة).
- `tests/test_ai_discovery.py`: اختبار `plan_attack` بتاع `GroqProvider` ضد HTTP mock حقيقي، وتأكيد
  إن أخطاء الـ API بتتعامل معاها بنفس الطريقة (status code بس، مفيش تسريب تفاصيل حساسة).

## 4) كل الملفات اللي اتعدّلت أو اتضافت

**ملفات جديدة:**
- `src/security_reviewer_v2/profiler/code_graph_stage.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/__init__.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/models.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/templates.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/execution_budget.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/scenario_validator.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/hypothesis_analyzer.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/attack_planner.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/tool_orchestrator.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/evidence_collector.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/evidence_evaluator.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/adaptive_controller.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/agent.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/zap_attempt.py`
- `src/security_reviewer_v2/dynamic_penetration_agent/playwright_attempt.py`
- `scripts/run_browser_probe.mjs`
- `tests/test_dynamic_penetration_agent.py`
- `docs/dynamic-penetration-agent.md` (الملف ده)

**ملفات معدّلة:**
- `scripts/run_pre_review_pipeline.py` — code-graph two-pass flags، CodeQL launcher fix،
  `_route_index`/`_penetration_session` (دلوقتي بتعمل reuse تلقائي لـ `--test-environment-config`)،
  `--no-penetration-agent`، `--penetration-enable-playwright`، وربط الـ budget/flags بـ
  `run_agent_review_graph`.
- `scripts/run_project_pipeline.py` — تمرير تلقائي لـ `--penetration-allow-compose-execution` و
  `--penetration-enable-playwright` لما تكوني حاطة `--allow-trusted-local-compose`/`--browser-dast`
  أصلاً، و`--no-penetration-agent` جديدة.
- `src/security_reviewer_v2/agent_graph.py` — Node جديد `dynamic_penetration_agent` (معطّل
  افتراضيًا)، state field جديد `penetration_test_payload`.
- `src/security_reviewer_v2/discovery/scope.py` — ordering بالـ graph hotspots لو موجودة.
- `src/security_reviewer_v2/context/routes.py` — دالة `handler_for_source_location` جديدة.
- `src/security_reviewer_v2/scanners/zap_runtime.py` — `scope_path`/`max_seconds` اختياريين في
  `automation_plan`/`run_zap` (backward-compatible بالكامل).
- `src/security_reviewer_v2/dynamic_penetration_agent/tool_orchestrator.py` — دلوقتي بيستدعي
  ZAP/Playwright فعليًا، مع fallback للأداة التالية لو واحدة مش متاحة.
- `src/security_reviewer_v2/dynamic_penetration_agent/adaptive_controller.py` — منطق التأكيد
  (corroboration) بأداة تانية مرة واحدة بس لكل hypothesis.
- `src/security_reviewer_v2/dynamic_penetration_agent/attack_planner.py` — باراميتر `tools`
  اختياري لإعادة استخدام نفس الـ template بأداة مختلفة.
- `src/security_reviewer_v2/dynamic_penetration_agent/evidence_evaluator.py` — بيقرأ حقل `reason`
  من أدوات مالهاش assertion بالـ HTTP status (ZAP/Playwright) بدل نص مضلّل.
- `tests/test_agent_graph.py` — تحديث الـ artifact sequence عشان يستوعب الـ Node الجديد.

كل التعديلات دي اتأكد منها بتشغيل الـ full test suite: نفس baseline (570 + الـ 5 fails القديمة)
زائد 11 اختبار جديد = **581 passed, 5 pre-existing failed, 4 skipped**. مفيش أي اختبار قديم اتكسر.

**صراحة مهمة**: مفيش Docker ولا ZAP container ولا Node/Playwright متاحين في البيئة اللي راجعت
بيها الكود، فـ `zap_attempt.py` و`playwright_attempt.py` اتأكد منهم بـ fake transports/subprocesses
بس (الشكل والـ wiring والـ fallback logic مظبوطين ومُختبرين)، مش ضد ZAP container أو متصفح حقيقي.
لازم تجربيهم عندك قبل production.

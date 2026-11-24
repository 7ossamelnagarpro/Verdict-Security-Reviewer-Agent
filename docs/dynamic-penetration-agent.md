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

## 3.10) تحديث: Template رابع + طبقة "فهم" بالذكاء الاصطناعي للنتيجة (من غير ما نلغي الـ rule-based)

### أ) Template جديد: `privilege_escalation`

بناءً على طلب "زوّدوا الـ templates"، ضفت رابع: حساب **مش admin** (بناءً على حقل `role` اللي
أصلاً موجود في بنية الحسابات بتاعة الـ Runtime Contract — مش حقل مخترع) بيحاول يوصل لـ endpoint
المفروض يكون admin-only. نفس آلية `authorization_matrix` بالظبط (GET واحد، نفس أكواد الرفض)، بس
باسمه الخاص عشان التقرير يوضّح إن اللي اتجرّب تحديدًا هو تصعيد صلاحيات، مش مجرد وصول حساب تاني.

### ب) طبقة "فهم" بالذكاء الاصطناعي — بس **من غير ما تلغي كون القرار الفعلي rule-based**

هنا لازم أكون دقيق جدًا، لأن اللي طلبتيه فيه تناقض داخلي محتاج توضيح: **تقدري تخلّي الذكاء
الاصطناعي "يفهم" أكتر، بس مينفعش هو اللي يقرر "ده ثغرة ولا لأ" نهائيًا** — لأن ده بالظبط نوع
القرار اللي المفروض يفضل حتمي وقابل للتحقق (status code فعلي رجع كام، مش رأي نموذج). لو سبنا
الذكاء الاصطناعي يغيّر الحكم ده، بنرجع بالظبط للمشكلة اللي النظام كله مصمّم يتجنّبها: قرار أمني
حسّاس متغيّر من تشغيلة لتشغيلة.

**اللي عملته فعليًا (حل وسط صحيح هندسيًا):**

- الحكم الفعلي (هل ده `violation`/`passed`/`inconclusive`/`blocked`) **لسه بالمقارنة الحتمية
  لكود الـ HTTP بالظبط زي ما هو** — ده الحقيقة اللي مينفعش تتغيّر.
- ضفت طبقة جديدة (`ai_planner.interpret_evidence`): بعد ما الحكم الحتمي يتاخد، بتسأل الذكاء
  الاصطناعي "اقرا النتيجة دي واكتب سطر أو اتنين: هل الـ blocked ده شكله مؤقت يستاهل نجرب حاجة
  تانية؟ هل الـ denial ده شكله قوي؟" — **مفيش سلطة لتغيير الحكم خالص**، النموذج بس بيضيف تفسير
  نصّي.
- التفسير ده بيتحفظ جنب الملاحظة الأصلية في `agent_reasoning_summary`، وبعدين **بيدخل في الـ
  prompt بتاع اختيار الاستراتيجية الجاية** (`choose_next_strategy`) — يعني فعليًا بيأثر على "لو
  مش ثغرة، جرّب زاوية تانية" اللي طلبتيه، بس من غير ما يمس الحقيقة الحتمية.

يعني النتيجة: الذكاء الاصطناعي بقى **فاهم** (بمعنى إنه بيفسّر ويأثر على القرار التالي)، بس
**القرار النهائي على كل محاولة لسه rule-based 100%** — وده بالظبط اللي طلبتيه في آخر سطر ("يكون
ذاكر إنها rule-based").

### الحدود اللي اتأكدت منها بالاختبارات

- النموذج مينفعش يغيّر `evaluation.outcome` — مختبر صراحة (`test_ai_evidence_interpretation_enriches_the_attempt_without_changing_the_verdict`).
- لو النموذج فشل أو رجّع حاجة فاضية، مفيش تأثير خالص — الـ reasoning بيفضل زي ما هو.
- مفيش tool access للنموذج في الخطوة دي، ومفيش حاجة بترجع منه بتتفسّر كـ تعليمات.

### التفعيل

نفس الـ flag الموجود، مفيش حاجة جديدة تتضاف:
```bash
--penetration-ai-planner
```
دلوقتي الـ flag ده بيفعّل الحاجتين مع بعض (اختيار السيناريو + تفسير النتيجة) من نفس الـ provider.

### اختبارات جديدة

- `tests/test_ai_planner.py`: 3 اختبارات جديدة لـ `interpret_evidence` (تفسير بيترجع صح، فشل
  بيرجع None، مفيش provider = no-op).
- `tests/test_dynamic_penetration_agent.py`: اختبار end-to-end يتأكد إن التفسير بيوصل للتقرير
  **من غير** ما يغيّر النتيجة النهائية، واختبار الـ template الرابع.
- `tests/test_ai_discovery.py`: اختبار `GroqProvider.interpret_evidence` ضد HTTP mock.

## 3.11) تحديث كبير: من 4 templates لـ 10 — والأهم: مفيش حاجة فيهم "حرة"

بناءً على طلب صريح إن الـ Agent "يختار فعلاً من templates كتير مش كام واحد محدد" — لكن من غير ما
نلغي الـ validator أو نخلّي الموديل يخترع طلبات من صفر (ده طلب تاني رفضته بالتفصيل وشرحت ليه،
لأنه بيحوّل الأداة من "اختبار اختراق مصرّح به" لـ "أداة هجوم حر" — نفس القواعد اللي إحنا حطّيناها
من الأول في التصميم).

### الـ 6 templates الجداد (كلهم read-only، كلهم الـ path بتاعهم محسوب بكود ثابت مش بالموديل):

| Template | الفكرة |
|---|---|
| `head_method_bypass` | HEAD بدل GET — بعض الـ frameworks بتسجّل حماية على GET بس وتنسى HEAD |
| `trailing_slash_bypass` | إضافة/حذف `/` من آخر الـ path |
| `case_sensitivity_bypass` | تكبير حروف الـ path (`/orders` → `/ORDERS`) |
| `path_normalization_bypass` | إضافة `/x/..` قبل آخر segment — **بس بعد ما نتأكد رياضيًا (`posixpath.normpath`) إنه بيرجع لنفس الـ path الأصلي بالظبط** قبل ما نستخدمه خالص |
| `idor_parameter_pollution` | تكرار نفس query parameter بقيمتين (نفس الـ id اللي IDOR بيستخدمه من الـ evidence، مش id جديد) |
| `extension_suffix_bypass` | إضافة لاحقة من قايمة ثابتة صغيرة (`.json`, `.xml`, `.html`) — نفس فكرة ثغرات Rails/Sinatra القديمة |

كل الـ transforms دي في ملف جديد `path_variants.py` — دوال pure، بتاخد الـ endpoint المسموح بيه
وترجع variant منه بمنطق ثابت 100%، **الموديل مالوش أي دخل في حساب الـ path نفسه** — هو بس بيختار
اسم الـ template، والكود هو اللي بيحسب التفاصيل. ده الفرق الجوهري بين "يختار من قايمة كبيرة" و"يرسم
بنفسه" اللي طلبتيه في الرسالة اللي قبل كده.

### الـ budget الافتراضي اتزوّد

مع 10 templates بدل 4، رفعت `max_attempts_per_hypothesis` الافتراضي من 4 لـ 10 (ونفس الحاجة في
`--penetration-max-attempts-per-hypothesis`) — عشان الـ Agent يقدر فعليًا يجرّب أغلبهم قبل ما
يوصل للحد الأقصى.

### 2 bugs حقيقية لقيتهم أثناء التوسيع دي واتصلّحوا

لما زوّدت عدد الـ templates، ظهرت حالة جديدة مكنتش موجودة قبل كده: إن **آخر strategy اتحطّت في
`tried`** تبقى واحدة فشلت في التخطيط (زي `idor_parameter_pollution` لو مفيش evidence)، مش آخر
واحدة **اتنفّذت فعليًا**. ده كان بيسبّب مشكلتين:

1. قرار "نكمّل ولا نوقف" كان بياخد حكم آخر محاولة **اتحاولت** مش آخر محاولة **اتنفّذت** — فممكن
   يوقف غلط وهو لسه عنده نتيجة حقيقية صالحة للتأكيد بيها.
2. لو الـ ZAP/Playwright corroboration اتفعّلت، كانت بتحاول تأكّد على الـ strategy اللي **أصلاً ما
   اتنفّدتش خالص** (مفيش حاجة حقيقية تتأكّد).

صلّحتهم بإضافة متغيّرين منفصلين (`last_executed_evaluation`, `last_executed_strategy`) بيتبّعوا
بس المحاولات اللي فعلًا اتنفّذت، مش كل حاجة اتحاولت. ضفت 4 اختبارات جديدة (منهم واحد مخصص بالظبط
لإعادة إنتاج الـ bug ده والتأكد إنه ما يرجعش).

## 3.12) تصحيح + 2 مشاكل حقيقية اتصلّحوا (من مراجعة فعلية للكود، مش تخمين)

### أ) تصحيح: شروط تشغيل ZAP Active/Automated Scan

**كنت غلطانة في رد سابق** لما قلت إن `authorization_checks`/`mutating_checks` لازم تكون `true`.
راجعت الكود بالظبط في `run_project_pipeline.py` ولقيت **العكس تمامًا**:
```python
if spec.authorization_checks:
    raise ValueError("Generic authorization workflows need a project-specific adapter; "
                     "set checks.authorization to false for baseline DAST")
if spec.mutating_checks:
    raise ValueError("Generic mutating DAST is not enabled yet; set checks.mutating to false")
```
يعني للـ pipeline العام (`run_project_pipeline.py`)، الحقلين دول **لازم يكونوا `false`**، مش `true`.
اللي فعليًا بيشغّل ZAP active/automated scan هو: `mode: docker_compose` + `trust_level:
trusted_local_project` + `--allow-trusted-local-compose` + Docker CLI متاح + الـ stack بيعدّي الـ
health check. معلش على المعلومة الغلط اللي قلتها قبل كده.

### ب) ليه الثغرة اللي أكّدها الـ Penetration Agent بتظهر "not_detected" في التقييم

ده **bug حقيقي ومؤكد**، راجعته بالتفصيل في `scripts/evaluate_verdict_comprehensive.py`. السبب:

سكريبت التقييم (مختلف تمامًا عن الـ pipeline نفسه — ده أداة مقارنة منفصلة بعد الفحص) كان بيحسب
"detected" بس لو فيه **توقيع (rule_id + path) من سكانر أو workflow check معيّن** مطابق تمامًا لحالة
معروفة مسبقًا (`SIGNATURES` table). **مكنش بيعرف أصلاً إن `dynamic-penetration-test.json` موجود،
ولا كان بيدّي أي قيمة لو الـ Penetration Agent نفسه أكّد الاستغلال فعليًا** — حتى لو الدليل ده
أقوى بكتير من مجرد rule بتاعة سكانر.

**الحل**: ضفت مسار تاني مستقل في `evaluate()`: لو حالة معروفة مالهاش توقيع سكانر خالص، بس الـ
Penetration Agent وصل لـ `exploitation_confirmed` على **نفس الـ endpoint بالظبط** (بعد توحيد صيغة
الـ path، لأن الـ ground truth بيستخدم `{{param}}` والـ route index بيستخدم `{param}` والـ Agent
بيختبر قيمة حقيقية زي `/orders/5`)، تتحسب الحالة "detected" — **بمصدر منفصل وواضح**
(`"origin": "penetration_agent"`) مش متلخبط مع الـ strict signature audit، وفيه عدّاد جديد في
الملخص: `summary.detected_via_penetration_agent` يوضّح بالظبط كام حالة اتكشفت بالطريقة دي تحديدًا.

ضفت 3 اختبارات جديدة بتتأكد: التطابق صح بيحصل، endpoint مختلف ما بيحصلش تطابق غلط، ونتيجة
`not_reproduced` (مش `exploitation_confirmed`) ما بتتحسبش خالص.

### ج) ليه مكنتش شايفة "تفكير" الـ LLM في LangSmith — ده كان bug حقيقي واتصلّح

لأ، الـ Agent **فعليًا بيستخدم الذكاء الاصطناعي** (مش قواعد بس) — بس كان فيه فجوة حقيقية في
الـ tracing. لما ضفت `node_trace` قبل كده، كنت بس بغلّف الـ **Node كله** (`dynamic_penetration_agent`)
بـ span واحد — يعني في LangSmith كنتِ شايفة إنه "اشتغل" بس من غير ما تشوفي **كل استدعاء فعلي
للموديل لوحده** (أي سيناريو اختار وليه، وتفسيره لكل نتيجة).

**الحل**: دلوقتي كل استدعاء فعلي للذكاء الاصطناعي (اختيار السيناريو، وتفسير النتيجة) بقاله **span
منفصل باسمه الخاص**:
- `ai_planner.choose_next_strategy` — فيه الـ input (الاستراتيجيات اللي جُرّبت قبل كده) والـ output
  (القرار والسبب).
- `ai_planner.interpret_evidence` — فيه الحكم الحتمي والتفسير اللي الموديل كتبه.

كل الـ spans دي بتظهر **جوا** الـ span الرئيسي `dynamic_penetration_agent` في شجرة الـ trace —
يعني دلوقتي تقدري تفتحي أي محاولة وتشوفي بالظبط الموديل فكّر إيه وقرر إيه، مش بس إنه اشتغل.

ضفت اختبار جديد (`test_each_ai_call_gets_its_own_named_langsmith_span`) بيتأكد إن الـ spans دي
فعلًا بتتفتح لكل استدعاء.

## 3.13) رد على تشخيص "مشكلة Security Review وGraph وLangSmith" (5 نقط)

راجعت الكود بالتفصيل (`discovery/provider.py`'s `_groq_json_request`, و`reviewers/graph.py`)
قبل ما أرد، عشان الرد يبقى مبني على الكود الفعلي مش افتراضات.

**1-3) الفحص نجح، Review اتوقف عند 429، والاستكمال رجع 64/96** — مطابق تمامًا لما لقيته.

**4) "مشكلة في تصميم الـGraph"** — الجزء ده مش دقيق 100%. فعليًا فيه **نظام retry/backoff
متقدّم بالفعل** في `discovery/provider.py`:
- بيحترم `Retry-After` اللي الـ provider بيبعته (لحد سقف معيّن).
- بيعمل "pacing" استباقي: بيفتكر آخر rate-limit headers من آخر رد ناجح، ولو الطلب الجاي هيضرب
  الحد، بينام شوية **قبل** ما يبعت الطلب أصلاً (مش بعد ما يتعاقب).
- بيعمل retry لأخطاء الـ 5xx والشبكة بـ backoff.

**وبعد كل ده، `reviewers/graph.py` فعليًا مصمّم صح**: لما الـ retry الداخلي يفشل نهائيًا،
الـ `review_batch` بيمسك الخطأ وبيحوّل لـ `finalize` اللي بيحافظ على **كل** المراجعات اللي
خلصت، ويسجّل الباقي كـ `pending` بوضوح (مش بيدّعي إنها "آمنة")، ويخلّي الحالة `partial`. يعني
الحفاظ على الـ64 مراجعة ومنع الـ "آمن افتراضيًا" **موجود بالفعل** وده اللي شفتيه في الـ logs.

**المشكلة الحقيقية الوحيدة**: سقف الانتظار الواحد (90 ثانية) والسقف الإجمالي (600 ثانية) كانوا
**ثابتين في الكود (hardcoded)**، مش قابلين للتعديل. يعني لو الـ provider طلب انتظار 120 ثانية
(أكتر من 90 بس أقل بكتير من 600)، النظام كان بيفشل فورًا من غير حتى يجرّب ينتظرها، رغم إن
الانتظار ده كان ممكن يحل المشكلة فعليًا.

**الحل**: ضفت env variables اختيارية (الافتراضي **زي ما هو بالظبط**، مفيش تغيير سلوك لمين
مبيستخدمهمش):
```bash
export GROQ_SINGLE_RETRY_AFTER_CAP_SECONDS=150   # افتراضي 90
export GROQ_MAX_RATE_LIMIT_WAIT_SECONDS=1200      # افتراضي 600
```

**5) LangSmith منفصلة فعلاً ومفيش دليل إنها بتوقف المراجعة** — ده **صح 100%**، وأثبتّه عمليًا:
شغّلت الـ test suite كامل مع قطع الاتصال بـ LangSmith (نفس أخطاء الـ `ConnectionError` اللي
ظهرتلك)، والنتيجة **618 اختبار نجحوا بالظبط زي ما كانوا** — يعني فشل LangSmith اتأكد عمليًا إنه
معزول تمامًا ومبيأثرش على أي حاجة تانية.

**بخصوص "تكرار الطلبات اللي مش عارفين اتنفذت ولا لأ"**: الكود أصلاً بيحترم الفرق ده — خطأ **قبل**
وصول الرد (connection refused، DNS) بيتعاد المحاولة، لكن خطأ **بعد** ما الطلب اتبعت ورد جزئي
جه (response timeout، connection dropped) **ما بيتعادش** أبدًا، عشان ممكن يكون اتحاسب عليه
فعلاً. ده موجود ومُختبر من قبل، مش حاجة جديدة.

ضفت 3 اختبارات جديدة بتتأكد: السقف الجديد شغّال صح، والسقف القديم (الافتراضي) فاضل زي ما هو
لو الـ env vars مش متظبطة أو غلط.

## 3.14) مفتاح منفصل لكل Agent (OpenAI/OpenRouter جنب Groq) + الـ LLM بقى "باين" فعليًا في LangSmith

### أ) OpenAI وOpenRouter بقوا متاحين جنب Groq وOllama

ضفت `OpenAIProvider` و`OpenRouterProvider` في `discovery/provider.py` — **مش تكامل جديد من
الصفر**، دول subclasses من `GroqProvider` نفسها (بما إن الاتنين OpenAI-compatible APIs بنفس شكل
الطلب والرد بالظبط)، فبيورّثوا **كل** منطق الـ retry/backoff/pacing الموجود أصلاً مجانًا — الفرق
بينهم وبين Groq بس الـ endpoint والاسم. كل واحد بيقرا الـ API key بتاعه من env var خاص بيه:
`OPENAI_API_KEY`, `OPENROUTER_API_KEY` (زي `GROQ_API_KEY` بالظبط).

### ب) دلوقتي كل Agent (Discovery، Review، Penetration) له provider/key منفصل تمامًا

ده اللي كان ناقص فعليًا وسبب مشكلة الـ rate limit اللي واجهتيها: التلات Agents كانوا بيستخدموا
**نفس الـ provider object، نفس المفتاح** — فلو Groq ضرب rate limit، التلاتة بيتأثروا مع بعض.
دلوقتي كل واحد مستقل:

```bash
python scripts/run_project_pipeline.py ... \
  --ai-provider groq --ai-model openai/gpt-oss-120b \
  --review-ai-provider openai --review-ai-model gpt-4o-mini \
  --penetration-ai-provider openrouter --penetration-ai-model openai/gpt-oss-120b
```

لو مش حطّيتي `--review-ai-provider`/`--penetration-ai-provider`، بيرجعوا يستخدموا نفس إعدادات
الـ Discovery تلقائيًا (زي ما كان قبل كده بالظبط — مفيش كسر لأي سلوك قديم).

**لازم تحطّي الـ env vars الصح** حسب كل provider اخترتيه:
```bash
export GROQ_API_KEY=...
export OPENAI_API_KEY=...
export OPENROUTER_API_KEY=...
```

### ج) ليه مكنتش شايفة "تفكير" الموديل في الـ trace — bug حقيقي كمان، اتصلّح

كنت لاحظتي في الصورة إن الـ spans (`ai_planner.choose_next_strategy`, `ai_planner.interpret_evidence`)
شكلهم عاديين جدًا (بعضهم "0.00s")، مفيش فيهم حاجة تبان "تفكير". السبب الحقيقي: كنت مسجّلاهم كـ
`run_type="chain"` (نوع عام)، فـ LangSmith بيعرضهم كـ dict عادي مش كـ محادثة. **دلوقتي بقوا
`run_type="llm"`** مع الـ prompt والرد الفعليين بشكل `messages` — يعني LangSmith هيعرضهم بواجهة
المحادثة المخصصة للـ LLM (زي الشات)، فتقدري تفتحي أي span وتشوفي **بالظبط** السؤال اللي اتبعت
للموديل والرد اللي رجع — ده الفرق بين "اشتغل" و"نقدر نشوف إيه اللي فكّر فيه".

بخصوص الـ "0.00s": ده مش bug بالضرورة — Groq معروف بسرعته الفائقة (LPU hardware)، فـ
`interpret_evidence` (رد قصير، سطر أو اتنين) ممكن يرجع فعليًا في أقل من 100 مللي ثانية، واللي
بيبان "0.00" في العرض هو تقريب. بعد التعديل، هتقدري تتأكدي بنفسك من محتوى الرد الفعلي مش بس
المدة.

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

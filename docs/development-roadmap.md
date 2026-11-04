# Verdict Security Reviewer — Discovery & Coverage Development Roadmap

> هذه الوثيقة هي خطة التطوير المرجعية لزيادة تغطية اكتشاف الثغرات. لا تعتبر أي مرحلة مكتملة إلا بعد تنفيذها وإضافة اختبارات وقياس أثرها في الـEvaluation.

## الهدف

رفع جودة التغطية وتقليل المناطق غير المختبرة، مع الحفاظ على الفصل بين:

- **Scanners:** تحليل الكود، الـDependencies والـSecrets.
- **Discovery Agent:** فهم التطبيق وتحديد ما يجب اختباره.
- **Runtime runners:** تنفيذ DAST وZAP وBrowser وBusiness Workflows.
- **Review Agent:** تقييم الأدلة وتصنيف النتائج.
- **Policy engine:** اتخاذ قرار Allow / Warn / Block.

لا يثبت Discovery Agent وجود ثغرة بمفرده؛ دوره هو إنتاج خريطة وخطة اختبار أفضل.

## الـPipeline المستهدف

```text
Project intake
  -> Static scanners
  -> codebase-memory-mcp codebase intelligence
  -> Discovery Agent / Application Map
  -> DAST, Browser and Workflow test plan
  -> ZAP, Playwright and workflow execution
  -> Finding correlation and deduplication
  -> Review Agent assessment
  -> Policy decision
  -> Final report and evaluation
```

## مراحل التنفيذ

### المرحلة 1 — دمج codebase-memory-mcp

- إضافة Adapter داخل Verdict لتشغيل الفهرسة محليًا.
- فهرسة source code وdocumentation وDocker/Compose وCI/infrastructure.
- حفظ الـindex والـgraph كـevidence منفصل عن تقرير الثغرات.
- توثيق الإصدار، مسار الـindex، وحدود اللغات والملفات المدعومة.
- التحقق من الترخيص، التثبيت المحلي، وفشل الفهرسة بدون تعطيل بقية الـpipeline.

**تقدم التنفيذ:** تم تثبيت `codebase-memory-mcp 0.12.1` محليًا، وإعادة فهرسة
`verdict-comprehensive-lab` بنجاح. الفهرس يحتوي 263 عقدة و860 علاقة، مع صفر
ملفات غير مفهرسة وصفر أخطاء تحليل جزئية أو غير قابلة للاستخدام. يظل الفهرس في
ذاكرة التخزين المؤقت الخاصة بالأداة خارج المستودع، ولا يتحول إلى findings.

### المرحلة 2 — Application Map موحّد

إنشاء schema موحد لكل نقطة دخول يتضمن:

- Endpoint وHTTP method.
- Parameters وrequest body وresponse type.
- Authentication وrequired role.
- Service وdatabase interaction.
- Source file وline number.
- Business object والعلاقات المرتبطة به.

**تقدم التنفيذ:** يمرر الـpre-review pipeline أدلة Route المحدودة من الفهرس إلى
`build_application_map`. في آخر تحقق، أعاد الرسم البياني 71 route، طابق منها
الـApplication Map عدد 70، واحتفظ بمسار واحد غير مطابق كفجوة أدلة للمراجعة.

### المرحلة 3 — تطوير Discovery Agent

- دمج نتائج الـScanners مع Application Map.
- اكتشاف routes وmethods والـparameters الحساسة.
- اكتشاف الأدوار والحسابات ونقاط الإدارة.
- تتبع data flow من Endpoint إلى Service ثم Database.
- اكتشاف Frontend API calls وJavaScript-only routes.
- إنتاج routes وaccounts وworkflows مقترحة.
- إنتاج Coverage gaps قابلة للتنفيذ بدل تحذيرات عامة فقط.

**تقدم التنفيذ:** تم ربط Application Map المطابق للـprofiler snapshot
بترتيب ملفات الـDiscovery وبـprompt hints محدودة على الملفات المختارة.
يُحفظ في `ai-discovery.json` اقتراح مراجعة للمسارات والأدوار المحتملة
والـcross-account/state-changing workflows، مع أمثلة routes خارج نطاق
الفحص المخطط. الاقتراحات ليست findings ولا تُنفذ تلقائيًا. تتبع الـdata flow
الانتقالي واستخراج الحسابات الاختبارية الفعلية ما زالا غير مكتملين. أضيف
اكتشاف ساكن محدود لاستدعاءات `fetch` و`axios` ذات المسارات الثابتة؛
JavaScript-only routes التي لا تظهر كنص ثابت تحتاج Browser crawl.
لا يوجد قياس Recall جديد بعد.

**تحديث التغطية:** يفصل `ai-discovery.json` الآن بين `discovery_gaps`
التي تجعل المرحلة `partial`، و`inherited_limitations` القادمة من الأدوات
الأخرى، و`context_notes` الخاصة باختصار المعلومات الخلفية. ما زالت جميعها
ظاهرة في `coverage_gaps` للتدقيق، لكن الملاحظات الموروثة وحدها لا تعني أن
Discovery لم يُكمل أهدافه. يُحجز حيّز لتلميحات Application Map وFrontend
قبل بناء دفعة الـprompt، وتُصغَّر الدفعة تلقائيًا عند عدم كفاية الحيّز
للتلميحات أو أدلة الخطر، ضمن حد عدد الدفعات. هذا يقلل نقص السياق ولا يضمن
إلغاءه في المشاريع الكبيرة.
عند إعادة تخطيط أدلة فحص `verdict-comprehensive-lab` المحفوظة محليًا
باستخدام Provider اختباري لا يستدعي نموذجًا، وصلت ٦ تلميحات خريطة للدفعات
بدل صفر في الأثر السابق، وغُطيت الأهداف الـ٢٠ في ٣ دفعات دون
`discovery_gaps`. هذه محاكاة لميزانية الـprompt وليست فحصًا جديدًا أو
قياس Recall؛ يجب تأكيد الأثر في تشغيل فعلي لاحق.

**تحديث سياق المصدر:** تتبع Application Map الآن استدعاءات الدوال داخل الملف
نفسه حتى عمق 3 وبحد 20 دالة، ويسجل عمليات SQL المرشحة في تلك الدوال.
تصل هذه المعلومات إلى تلميحات Discovery مع وسمها كمرشحات؛ لا يثبت هذا
انتقال قيمة مدخلة بين الدوال، ولا يغطي الاستدعاءات بين الملفات.

### المرحلة 4 — توليد خطة الاختبار

تحويل اقتراحات Discovery Agent إلى:

- HTTP probes.
- ZAP scope.
- Browser crawl targets.
- Business workflows.
- Cross-user access tests.
- Role and privilege tests.
- Session/token and input-validation tests.

الخطط غير المصرح بها تحتاج مراجعة قبل التنفيذ. الـWorkflow المعرّف في عقد
اختبار موثوق على Docker مؤقت ينفّذ خطوات الكتابة تلقائيًا ضمن الحدود والتنظيف.

**تقدم التنفيذ:** يُكتب `discovery-test-plan.json` مع كل فحص جديد. يحتوي
مقترحات محدودة للمسارات، وZAP scope، وBrowser seeds، واختبارات الأدوار
والحسابات المتقاطعة وتغيير الحالة. لا تُنفذ هذه المقترحات تلقائيًا؛ يجب
تأكيد المسارات المتاحة، الحالات المتوقعة، الحسابات، أجسام الطلبات، وسياسة
التنظيف قبل إضافتها إلى Runtime Contract.

**تحديث:** يمكن تمرير خطة فحص سابقة تمت مراجعتها باستخدام
`--approved-discovery-plan` في فحص Compose مؤقت. يتحقق Verdict من بصمة
المشروع ومن تعريف المسار في المصدر، ثم يختار حتى 20 مسار GET بسيطًا ويضيفها
إلى فحص HTTP وزحف المتصفح. يسجل `approved-discovery-probes.json` الحالات
المرصودة. تبقى اختبارات الأدوار والكتابة معتمدة على قواعد Runtime Contract؛
المسار المقروء وحده لا يكفي لاستنتاج الاستجابة الأمنية المتوقعة.

### المرحلة 5 — توسيع Browser Agent

- استخدام Playwright لاكتشاف JavaScript-only routes.
- تنفيذ login والصفحات المحمية.
- التقاط API calls من المتصفح.
- اكتشاف forms والأزرار وتحويل الخطوات إلى workflow مقترح.
- فرض same-origin وtimeouts وrequest limits.
- منع العمليات التدميرية افتراضيًا وتشغيلها فقط على disposable stack بعد الموافقة.

**تقدم التنفيذ:** الزحف يسجل طلبات GET التي شاهدها المتصفح داخل نفس الـorigin،
وطرق/مسارات النماذج وأسماء حقولها فقط، من دون قيم الحقول أو نصوص الاستجابة
أو رؤوس المصادقة. عند تشغيل Workflows على Docker مؤقت، يسجل دخول حسابات
الاختبار الموجودة في العقد ويتحقق من هوية كل حساب، ثم يزور صفحاتها بجلسات
منفصلة. الطلبات التي تغيّر البيانات تُنفذها خطوات الـWorkflow المعرّفة،
ويظل إرسال النماذج والضغط العام على أزرار المتصفح غير مفعل لأن سلوكهما
وقواعد النجاح لا يمكن استنتاجها بأمان من DOM وحده. تظهر المسارات المرصودة
غير الموجودة في خريطة المصدر كمقترحات مراجعة.

### المرحلة 6 — Correlation وDeduplication

كل finding يجب أن يحتفظ بـ:

- المصدر: scanner أو agent أو runtime tool.
- Endpoint أو file location.
- Account/role.
- Request/response evidence.
- Source context.
- Confidence وlimitations.
- Related source IDs.

تُدمج الإشارات التي تصف المشكلة نفسها في Issue group واحد، ولا تُحسب الإشارة والـgroup كثغرتين مستقلتين.

### المرحلة 7 — تقوية Review Agent

- مراجعة الأدلة لا أسماء الأدوات فقط.
- التصنيف إلى Confirmed / Likely / False positive / Needs more evidence.
- عدم اعتبار اقتراح Discovery Agent أو Coverage gap دليل استغلال.
- إظهار سبب الحكم ومصدره ودرجة الثقة.
- الحفاظ على فصل الحكم النموذجي عن الإثبات المستقل.

### المرحلة 8 — Evaluation وBenchmark

إضافة benchmark يحتوي على:

- Static vulnerabilities.
- DAST vulnerabilities.
- IDOR/BOLA وPrivilege escalation.
- SQL injection وSecrets وDependency vulnerabilities.
- Browser-only workflows.
- Business-rule violations.
- False positives وnegative controls.

يجب حساب:

- Recall وPrecision.
- False-positive rate.
- Route وWorkflow وRole coverage.
- Evidence completeness.
- Source-context completeness.
- Discovery coverage وRuntime coverage.

**تحديث:** يعرض تقييم المختبر الشامل نسب تنفيذ المسارات المعلنة، وأهداف
Discovery، وخطوات الـWorkflow، وحسابات الاختبار والأدوار التي تم التحقق
منها، عند وجود مقام موثوق لكل نسبة. لا يزال Precision وFalse-positive rate
بحاجة إلى تدقيق مستقل للـsafe controls والنتائج الإضافية.

**خط أساس التقييم المحفوظ (2 نوفمبر 2026):** في فحص المختبر الشامل المحفوظ،
رُبطت 33 من 35 حالة إيجابية معروفة بنتائج راجعها Review Agent (94.29% كحد
أدنى)، بينما احتاجت حالتان إلى مراجعة أدلة إضافية. سُجلت استجابة وقت تشغيل
لـ41 من 70 مسارًا معلنًا في المصدر. نفذت 69/69 خطوة Workflow، وفُحصت
20/20 من أهداف Discovery، وتحقق 6/6 حسابات اختبار. لم يُقَس تحقق الأدوار
في هذا الفحص القديم لغياب وسم الدور من أدلته المحفوظة. يُخرج التقييم الآن
36 مجموعة أشار إليها Review Agent ولم ترتبط بتوقيع حالة إيجابية معروفة في
قائمة تدقيق منفصلة؛ هذه ليست إنذارات كاذبة تلقائيًا. تظل 27 حالة سليمة
بحاجة إلى تدقيق مستقل، لذلك لا تُحسب Precision أو False-positive rate بعد.

## ترتيب الأولويات

1. codebase-memory-mcp Adapter.
2. Application Map schema.
3. Discovery Agent enrichment.
4. Source context وتحسين deduplication.
5. Automatic workflow generation.
6. Multi-account وmulti-role testing.
7. Browser/Playwright expansion.
8. IDOR وprivilege/session test suites.
9. Benchmark وEvaluation dashboards.

## شروط إغلاق كل مرحلة

- اختبار سلوك جديد في `tests/`.
- تشغيل الاختبارات الحالية وعدم كسر الـpipeline.
- تحديث الـdocumentation والعقود ذات الصلة.
- تسجيل coverage impact في Evaluation.
- توضيح القيود المتبقية في التقرير.
- عدم اعتبار زيادة عدد النتائج نجاحًا بدون تحسن في Recall وEvidence quality.

## ملاحظات أمان وتشغيل

- التشغيل محليًا وعلى disposable Docker stack متى أمكن.
- عدم إرسال source code أو credentials إلى خدمة خارجية بدون موافقة.
- التعامل مع مخرجات الـAgents كبيانات غير موثوقة حتى يتم التحقق منها.
- موافقة المستخدم على فحص مشروع Docker الموثوق والعقد شرط مسبق؛ بعدها تُنفّذ
  خطوات الكتابة المعلنة تلقائيًا داخل stack مؤقت مع تنظيفه. لا تُنفّذ اقتراحات
  Discovery أو عمليات تدميرية غير معلنة تلقائيًا.
- لا يوجد فحص يضمن اكتشاف كل الثغرات؛ الهدف هو تقليل gaps وقياسها بصدق.

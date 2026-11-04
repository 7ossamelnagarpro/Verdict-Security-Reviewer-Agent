Copy these files over the same paths in the project.

  src/security_reviewer_v2/reporting/html_report.py     (rewritten: your report design + new charts, tree, side panel)
  src/security_reviewer_v2/reporting/view.py             (adds origins, found-by tree, agents, test runs, trace data)
  src/security_reviewer_v2/reporting/evaluation_html.py  (gauge chart, duplicates removed)
  src/security_reviewer_v2/scanners/web_runtime.py       (optional: records the request each baseline probe sends)
  scripts/evaluate_verdict_comprehensive.py, evaluate_verdict_multi_service.py  (pass the gauge, friendly name)
  tests/test_report_static_dynamic.py                    (new tests)

Delete if present: src/security_reviewer_v2/reporting/report_ui.py and docs/report-ui-spec.md (from the earlier redesign, no longer used).
samples/ are your own run (run_comprehensive_0001) re-rendered with the new code.

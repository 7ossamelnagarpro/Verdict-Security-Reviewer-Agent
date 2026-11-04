# Application Map (phase 2)

Every pipeline run now saves `application-map.json` beside the scan artifacts.
It is a deterministic inventory of *declared* entry points, not a list of
confirmed vulnerabilities or a guarantee of reachable runtime routes.

The map uses the existing bounded, read-only source-route discovery. Codebase
Memory indexing is enabled by default (unless `--no-codebase-memory` is provided);
when indexing succeeds, it also reads Route
nodes from the local graph. A method/path match is recorded separately from
a method/path/file match: the graph may omit a source file or normalize route
parameters to `{}`. Graph-only routes are listed under
`unmatched_graph_routes`, not silently promoted to verified source routes.

Each route records:

- HTTP method, path, source file, line and handler symbol when found;
- path parameters and conservative query-parameter candidates;
- declared request-body type and Pydantic fields, and response annotation or
  response class when present;
- candidate authentication-helper calls; an observed header alone does not
  prove an access check, and unknown required roles remain `null`;
- direct SQL call locations and literal table-name references (no query text);
- a path-derived business-object candidate and nested-path relationship
  candidates, both explicitly labelled as unverified;
- graph route/file corroboration flags and source confidence.

The `service` field remains `null` unless a later stage can establish a
deployment-to-code link. Transitive calls, dynamic routes, router prefixes,
JavaScript-only behavior and runtime authorization require separate evidence.
The map now feeds the Discovery Agent in phase 3 of the
[development roadmap](development-roadmap.md). It is accepted only when its
project root and profiler fingerprint match the current scan. Source-backed
routes raise the priority of their files in the bounded discovery scope. For
each batch, only routes whose declaration line lies inside a source window
actually included in that batch can appear as bounded, explicitly untrusted
prompt hints. Graph-only
routes are never promoted into the prompt or candidate scope.

`ai-discovery.json` includes `application_map_guidance`: up to 50 proposed
route checks and up to 10 examples of source-backed routes outside the
planned inspection scope. The checks identify possible cross-account,
role-based, input-boundary and state-changing workflow reviews. They are
**not** findings, executable tests, or proof of a missing check. Unknown
accounts and roles remain unknown; write operations still require a separate
approved runtime contract. The Discovery Agent's candidates continue through
source verification and the Review Agent before policy decisions.
Role words found in route or helper names are saved only as
`role_name_candidates`; suggested test-account scenarios are placeholders,
not discovered credentials or confirmed authorization policy.
The `usage.application_map_hints_in_initial_prompts` count measures how many
route hints actually fit the initial prompt batches; it is not a recall metric.

The Discovery stage also performs a bounded, read-only scan of profiled
JavaScript/TypeScript source files for literal same-origin `fetch()` and
`axios.<method>()` calls. Their paths and source lines appear under
`frontend_api_calls`. Calls without an *exact* method/path match in the source
map are labelled for runtime confirmation, not declared missing or vulnerable.
Only calls inside a selected source window may become prompt hints. Dynamic
URLs, computed methods, browser navigation and actual JavaScript-only routes
remain outside this static inventory.

This integration does not establish transitive endpoint-to-service/database
flow, browser-only routes, or actual runtime authorization. The stored route
and scope counts are coverage proxies, not measured vulnerability recall.
Recall and precision must be compared against ground truth in a later full
evaluation before claiming an improvement.

For the Comprehensive Lab snapshot tested during development, source discovery
found 70 routes. The local graph returned 71 Route nodes: 70 method/path
matches, 40 file-location matches, and one graph-only `ANY` route. These are
inventory counts, not vulnerability counts.

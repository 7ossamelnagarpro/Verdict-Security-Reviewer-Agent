# Project Profiler

The Project Profiler inspects the structure of a local project and creates an
explainable scan plan. It does not search for vulnerabilities, run scanners,
execute project code, install packages, build the project, access databases, or
use an LLM.

## Profile, plan, and execution

- **Project profile:** observed facts such as files, components, languages,
  frameworks, manifests, Git metadata, Docker/IaC/CI targets, warnings, and
  discovery coverage gaps.
- **Scan plan:** deterministic decisions describing which scanner task would be
  useful, why it was chosen, its targets and exclusions, and whether its
  prerequisites are available, missing, or still unverified.
- **Scan execution:** a later orchestrator responsibility. A `selected` or
  `needs_verification` task is not evidence that a scan ran or found nothing.

Profiling never produces a security score or a claim that a project is safe.
If source files have no supported dependency manifest, the profile records that
SCA coverage is unknown. A manifest without a supported lockfile can identify
declared packages, but resolved transitive versions remain unverified. The
human-readable report includes both discovery and scan-plan coverage gaps.
Runtime URLs, test accounts, and reachability are assessed only by later stages,
not by the profiler.

## Python API

```python
from security_reviewer_v2.profiler import profile_project

result = profile_project("path/to/project")
payload = result.to_dict()
```

Optional limits and policy can be provided explicitly:

```python
from security_reviewer_v2.profiler import ProfilerLimits, ProfilerPolicy

result = profile_project(
    "path/to/project",
    limits=ProfilerLimits(max_files=5_000, max_depth=20),
    policy=ProfilerPolicy(
        enabled_scanners=("semgrep-ce", "codeql-cli", "gitleaks"),
        disabled_scanners=("trivy",),
    ),
)
```

## CLI

After installing the package, use:

```text
security-project-profile PATH --output profile.json
```

When `--output` is provided, the CLI also writes a human-readable Markdown
report beside it using the same base name (for example, `profile.md`). Use
`--markdown-output PATH` to choose another Markdown path. The JSON remains the
canonical machine-readable result consumed by later stages; Markdown is a
presentation of the same `ProfileResult`.
The saved JSON also contains `project_snapshot`: the resolved root path,
SHA-256 hashes of inventoried files, and a scan-plan digest. The standalone
scanner stage checks this snapshot before using a saved plan, so moving the
artifact to another project or changing discovered files requires a fresh
profile. File contents are not stored in the snapshot. Generating it reads
inventoried files once; a partial profiler inventory remains partial.

From a source checkout, the equivalent module is:

```text
python -m security_reviewer_v2.profiler PATH --output profile.json
```

The CLI writes JSON and returns exit code `2` for invalid input or invalid
limits/policy. It does not invoke scanner executables.

An optional human review gate can be enabled with `--review`:

```text
security-project-profile PATH --output profile.json --review
```

The user can approve the planned tasks, request a broad coverage scan, or
cancel before scanner execution. The decision is recorded beside the JSON as
`profile-review-decision.json`. Broad mode does not claim that every file is
supported; it asks the later orchestrator to use all enabled, applicable
scanners while preserving coverage warnings.

### Large projects and bounded SAST

The profiler records the file count and byte size of every detected component.
When a component reaches the large-component thresholds, Semgrep tasks are
split into stable groups of source directories/files (eight targets by default).
This keeps one slow scope from delaying the whole project and makes retries
possible per group. CodeQL remains component-wide because splitting its source
root can remove cross-file data-flow edges. The generated tasks are marked with
`resource_class: "large"` and explain the scope in their reasons.

The defaults can be tuned explicitly:

```text
security-project-profile PATH --large-component-files 750 \
  --large-component-bytes 20971520 --sast-chunk-size 8
```

These controls do not make a partial profile complete. Any discovery or scan
scope skipped by a resource limit remains a visible coverage gap.

## Discovery and safety

Discovery uses a single bounded, sorted traversal. The default limits cover:

- total file count;
- maximum inventoried file size;
- maximum traversal depth;
- maximum bytes read per selected file;
- maximum selected-content bytes read in total;
- elapsed profiling time.

Only evidence-bearing files such as manifests and limited source files are read.
Binary-looking content is rejected. Paths in output are relative to the project
root. Symbolic links are not followed by default; when enabled, links resolving
outside the root remain blocked.

Secret candidate files, including `.env`, are listed by path only. Their values
are never placed in profiler output or logs.

## Exclusion policy

There is no universal security exclusion list. V2 keeps separate exclusions for:

- SAST;
- dependencies;
- secrets;
- configuration and Infrastructure as Code.

`.gitignore` is not treated as a security policy. In particular, `.env` remains
eligible for current-file secret scanning, and lockfiles remain eligible for
dependency analysis. Discovery-policy exclusions and resource/error skips are
reported separately with their effects on coverage.

Repository files cannot silently change system scan policy. Overrides are passed
through the trusted API/CLI, validated, and included in the resulting plan.

## Implemented detection scope

Language detection currently recognizes common source extensions for Python,
JavaScript, TypeScript, Java, Kotlin, Go, Ruby, C#, C/C++, Rust, Swift, PHP,
Scala, Elixir, Dart, and Lua. Recognition is not the same as scanner support;
unsupported languages are retained as coverage gaps.

Framework evidence is currently implemented for:

- Python: Flask, Django, FastAPI;
- JavaScript/TypeScript: Express, React, Next.js, Vue.

A declared dependency alone produces low confidence. A source import alone
produces medium confidence. Both together produce high confidence. Python
imports are parsed with `ast`; JavaScript/TypeScript uses limited import/require
patterns. Project code is never imported or executed.

Dependency parsing currently covers:

- `pyproject.toml` declarations;
- `requirements*.txt` constraints;
- `package.json` declarations;
- `package-lock.json` / `npm-shrinkwrap.json` resolved versions;
- `Pipfile.lock` resolved versions.

Other known manifests and lockfiles are detected and associated with components,
but are marked `detected_only` until a safe parser is implemented. The profiler
does not infer transitive or installed versions from declarations.

## Scanner capability registry

The offline registry is implemented in
`src/security_reviewer_v2/profiler/registry.py`. It has separately versioned
entries for Semgrep Community Edition, CodeQL CLI, Gitleaks, and Trivy. Entries
record editions, scan types, supported languages/ecosystems, targets, modes,
prerequisites, limitations, official references, verified versions, and the
verification date.

To add or update a scanner capability:

1. Verify the capability against official documentation.
2. Add or update one typed `ScannerCapability` entry.
3. Increment `REGISTRY_VERSION`.
4. Add planner tests for applicable, unavailable, and unsupported targets.
5. Do not treat runtime installation as verified merely because the registry
   documents a capability.

Runtime versions for Gitleaks and Trivy are intentionally marked unverified until
the later environment/orchestrator stage checks installed executables.

## Adding a detector

Add a detector only when it can provide bounded, deterministic evidence:

1. Define the supported filenames, extensions, or safe content indicators.
2. Reuse the existing inventory and bounded reader; do not traverse the tree
   again without a demonstrated need.
3. Return relative evidence paths and an explicit confidence level.
4. Record malformed or incomplete inputs as warnings/coverage gaps.
5. Add behavioral fixtures containing both positive and negative controls.

## Example: simple Python project

For a project with `pyproject.toml`, `app.py`, a Flask dependency, and a Flask
import, the profile reports Python and Flask with high-confidence evidence. The
plan contains complementary Semgrep and CodeQL SAST tasks, a Trivy dependency
task, and a current-file Gitleaks task. Runtime prerequisites remain
`needs_verification` unless a trusted caller supplies their state.

## Example: multi-component repository

For a workspace with `backend/pyproject.toml`, `frontend/package.json`, and
`infrastructure/main.tf`, the profile keeps the backend, frontend, and
infrastructure roots separate. Python SAST tasks target the backend, TypeScript
tasks target the frontend, and the Trivy misconfiguration task targets the IaC
file. Findings from one component are not attributed to every language in the
repository.

## Known limitations

- Component discovery supports manifest roots and npm-compatible workspace
  evidence but does not yet implement every build system's workspace semantics.
- Framework detection intentionally covers a small documented set.
- Several lockfile formats are detected but not fully parsed.
- Git metadata presence does not prove complete history; history remains
  unverified until execution setup.
- A Dockerfile is a configuration target, not proof that a container image
  exists.
- Time-based limits can make a profile partial; stable numeric limits are
  preferred for reproducible automation.
- Scanner selection documents intent only. Scanner installation, databases,
  query/rule packs, licenses, and actual execution are later-stage concerns.

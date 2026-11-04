"""Offline scanner capability registry used by the scan planner."""

from __future__ import annotations

from .models import ScannerCapability, ScanType

REGISTRY_VERSION = "2026.10.03-1"


def load_builtin_registry() -> tuple[ScannerCapability, ...]:
    """Return the validated, pinned capability snapshot.

    This function performs no network or executable access. Runtime availability
    and installed versions remain prerequisites for the later orchestrator.
    """
    capabilities = (
        ScannerCapability(
            scanner_id="idor-dast",
            display_name="Authorization Differential Probe",
            edition="Local educational adapter",
            scan_types=(ScanType.DAST,),
            languages=(),
            ecosystems=(),
            target_kinds=("runtime_api",),
            modes=("differential_authorization",),
            rule_references=("cross_user_resource_access",),
            prerequisites=("target_reachable", "test_identities", "safe_mode"),
            verified_version="1.0",
            capability_status="verified",
            limitations=(
                "Requires a running test target and at least two synthetic identities.",
                "The built-in probe is GET-only and does not prove authorization for every endpoint.",
                "Never run against systems without explicit authorization.",
            ),
            official_reference="https://cwe.mitre.org/data/definitions/639.html",
            verified_on="2026-10-03",
        ),
        ScannerCapability(
            scanner_id="semgrep-ce",
            display_name="Semgrep Community Edition",
            edition="Community Edition",
            scan_types=(ScanType.SAST,),
            languages=(
                "python",
                "javascript",
                "typescript",
                "java",
                "go",
                "ruby",
                "csharp",
                "kotlin",
                "rust",
            ),
            ecosystems=(),
            target_kinds=("source_tree",),
            modes=("community_registry_rules", "local_rules"),
            rule_references=("p/python", "p/security-audit", "p/owasp-top-ten"),
            prerequisites=("semgrep_executable", "semgrep_rules"),
            verified_version="1.178.0",
            capability_status="verified",
            limitations=(
                "Community rules vary in coverage and quality.",
                "Community Edition does not provide Semgrep Pro cross-file analysis.",
                "Selecting the scanner does not prove that an applicable rule exists.",
            ),
            official_reference="https://semgrep.dev/products/semgrep-vs-ce",
            verified_on="2026-10-01",
        ),
        ScannerCapability(
            scanner_id="codeql-cli",
            display_name="CodeQL CLI",
            edition="CLI for permitted local use",
            scan_types=(ScanType.SAST,),
            languages=(
                "python",
                "javascript",
                "typescript",
                "java",
                "kotlin",
                "go",
                "csharp",
                "cpp",
                "ruby",
                "rust",
                "swift",
            ),
            ecosystems=(),
            target_kinds=("source_tree",),
            modes=("standard_query_suite",),
            rule_references=("language_code_scanning_suite",),
            prerequisites=("codeql_executable", "language_query_pack"),
            verified_version="2.27.1",
            capability_status="verified",
            limitations=(
                "Some compiled languages require a build environment.",
                "Framework coverage differs by language and library.",
                "Licensing and permitted-use conditions must be checked for deployment context.",
            ),
            official_reference=(
                "https://codeql.github.com/docs/codeql-overview/"
                "supported-languages-and-frameworks/"
            ),
            verified_on="2026-10-01",
        ),
        ScannerCapability(
            scanner_id="gitleaks",
            display_name="Gitleaks",
            edition="Open source CLI",
            scan_types=(ScanType.SECRETS,),
            languages=(),
            ecosystems=(),
            target_kinds=("filesystem", "git_history"),
            modes=("directory", "git_history"),
            rule_references=("gitleaks_builtin_rules",),
            prerequisites=("gitleaks_executable",),
            verified_version="8.30.1",
            capability_status="verified",
            limitations=(
                "Pattern-based detection can produce false positives and false negatives.",
                "Git history mode requires usable Git metadata and history.",
            ),
            official_reference="https://github.com/gitleaks/gitleaks",
            verified_on="2026-10-02",
        ),
        ScannerCapability(
            scanner_id="trivy",
            display_name="Trivy",
            edition="Open source CLI",
            scan_types=(
                ScanType.SCA,
                ScanType.SECRETS,
                ScanType.MISCONFIGURATION,
                ScanType.CONTAINER_IMAGE,
            ),
            languages=(),
            ecosystems=(
                "python",
                "npm",
                "yarn",
                "pnpm",
                "go",
                "maven",
                "gradle",
                "ruby",
                "cargo",
            ),
            target_kinds=(
                "filesystem",
                "lockfile",
                "manifest",
                "iac",
                "dockerfile",
                "container_image",
            ),
            modes=("filesystem",),
            rule_references=("trivy_vulnerability_database", "trivy_builtin_checks"),
            prerequisites=("trivy_executable", "trivy_databases"),
            verified_version="0.75.0",
            capability_status="verified",
            limitations=(
                "Vulnerability scanning may require databases populated before offline use.",
                "Repository SCA coverage is strongest when supported lockfiles are present.",
                "A Dockerfile does not provide a built container image target.",
            ),
            official_reference="https://trivy.dev/docs/latest/target/repository/",
            verified_on="2026-10-02",
        ),
    )
    _validate_registry(capabilities)
    return capabilities


def _validate_registry(capabilities: tuple[ScannerCapability, ...]) -> None:
    seen: set[str] = set()
    for capability in capabilities:
        if not capability.scanner_id or capability.scanner_id in seen:
            raise ValueError(
                f"Invalid or duplicate scanner id: {capability.scanner_id!r}"
            )
        if not capability.scan_types:
            raise ValueError(f"Scanner {capability.scanner_id} has no scan type")
        if not capability.official_reference.startswith("https://"):
            raise ValueError(
                f"Scanner {capability.scanner_id} lacks an HTTPS reference"
            )
        seen.add(capability.scanner_id)

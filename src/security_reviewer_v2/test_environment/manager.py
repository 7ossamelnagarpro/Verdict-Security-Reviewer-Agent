"""Keep untrusted repository discovery separate from user-approved execution.

This first version supports an already-running loopback URL or an explicitly
supplied Docker Compose recipe. It does not infer commands from source files,
run them on the host, or treat containerization as a perfect sandbox.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, Mapping

from security_reviewer_v2.profiler.models import ProfileResult


SCHEMA_VERSION = "1.0"
_ENV_NAME = re.compile(r"SECURITY_TEST_[A-Z][A-Z0-9_]*\Z")
_SERVICE_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]*\Z")
_UNSAFE_SERVICE_KEYS = frozenset({
    "privileged", "devices", "device_cgroup_rules", "cap_add",
    "network_mode", "pid", "ipc", "uts", "userns_mode", "volumes_from",
    "env_file", "secrets", "configs", "extends", "develop", "logging",
    "container_name", "extra_hosts", "dns", "dns_search", "sysctls",
})


@dataclass(frozen=True)
class EnvironmentSpec:
    mode: str
    trust_level: str
    base_url: str
    health_path: str
    expected_status: int
    compose_file: str | None
    app_service: str | None
    required_env_names: tuple[str, ...]
    account_env_names: tuple[str, ...]
    authorization_checks: bool
    mutating_checks: bool
    authorized_for_testing: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EnvironmentPlan:
    schema_version: str
    mode: str
    status: str
    base_url: str
    evidence: tuple[str, ...]
    missing: tuple[str, ...]
    warnings: tuple[str, ...]
    compose_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TestEnvironmentSession:
    base_url: str
    mode: str
    project_name: str | None = None


def load_environment_spec(path: str | Path, *, project_root: str | Path) -> EnvironmentSpec:
    """Read an explicit user-supplied JSON file, never auto-discover one in a repo."""
    root = Path(project_root).resolve(strict=True)
    config = Path(path).resolve(strict=True)
    if config.is_relative_to(root):
        raise ValueError("Test-environment configuration must be outside the untrusted project root")
    if not config.is_file() or config.stat().st_size > 32 * 1024:
        raise ValueError("Test-environment configuration must be a JSON file of at most 32 KiB")
    payload = json.loads(config.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) - {"schema_version", "mode", "trust_level", "target", "compose", "accounts", "checks", "required_env", "authorized_for_testing"}:
        raise ValueError("Unknown or invalid test-environment configuration fields")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported test-environment schema version")
    if payload.get("authorized_for_testing") is not True:
        raise ValueError("Testing authorization must be explicitly true")
    mode = payload.get("mode")
    if mode not in {"existing_url", "docker_compose"}:
        raise ValueError("mode must be existing_url or docker_compose")
    trust_level = payload.get("trust_level", "untrusted")
    if trust_level not in {"untrusted", "trusted_lab"}:
        raise ValueError("trust_level must be untrusted or trusted_lab")
    if mode == "docker_compose" and trust_level != "trusted_lab":
        raise ValueError("Host Docker Compose is only allowed for an explicitly trusted_lab project; untrusted projects require a VM worker")
    target = _object(payload.get("target"), {"base_url", "health_path", "expected_status"}, "target")
    base_url = _loopback_url(target.get("base_url"))
    health_path = target.get("health_path", "/")
    if not isinstance(health_path, str) or not health_path.startswith("/") or health_path.startswith("//") or "#" in health_path:
        raise ValueError("health_path must be a local absolute path")
    expected_status = target.get("expected_status", 200)
    if type(expected_status) is not int or expected_status < 200 or expected_status >= 400:
        raise ValueError("expected_status must be a successful HTTP status")
    checks = _object(payload.get("checks", {}), {"authorization", "mutating"}, "checks")
    authorization = checks.get("authorization", False)
    mutating = checks.get("mutating", False)
    if type(authorization) is not bool or type(mutating) is not bool:
        raise ValueError("check flags must be booleans")
    accounts = payload.get("accounts", [])
    if not isinstance(accounts, list) or len(accounts) > 8:
        raise ValueError("accounts must be a list of at most eight test identities")
    account_names: list[str] = []
    for item in accounts:
        entry = _object(item, {"role", "username_env", "password_env"}, "account")
        if not isinstance(entry.get("role"), str) or not entry["role"]:
            raise ValueError("Each account needs a role")
        for field in ("username_env", "password_env"):
            value = entry.get(field)
            if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
                raise ValueError(f"{field} must name a SECURITY_TEST_ environment variable, not contain a credential")
            account_names.append(value)
    if authorization and len(accounts) < 2:
        raise ValueError("Authorization checks require at least two test identities")
    required_env = payload.get("required_env", [])
    if (not isinstance(required_env, list) or len(required_env) > 32
            or any(not isinstance(name, str) or not _ENV_NAME.fullmatch(name) for name in required_env)):
        raise ValueError("required_env must list SECURITY_TEST_ variable names, not values")
    compose = payload.get("compose")
    compose_file = app_service = None
    if mode == "docker_compose":
        if urllib.parse.urlsplit(base_url).hostname != "127.0.0.1":
            raise ValueError("docker_compose mode currently requires 127.0.0.1")
        data = _object(compose, {"file", "app_service"}, "compose")
        compose_file = _relative_compose_path(data.get("file"))
        app_service = data.get("app_service")
        if not isinstance(app_service, str) or not _SERVICE_NAME.fullmatch(app_service):
            raise ValueError("compose.app_service must be a service name")
    elif compose is not None:
        raise ValueError("compose is only valid for docker_compose mode")
    return EnvironmentSpec(mode, trust_level, base_url, health_path, expected_status, compose_file,
                           app_service, tuple(sorted(set(required_env))), tuple(sorted(set(account_names))), authorization,
                           mutating, True)


def plan_environment(
    spec: EnvironmentSpec, *, project_root: str | Path, profile: ProfileResult,
    environment: Mapping[str, str] | None = None, docker_executable: str | None = None,
) -> EnvironmentPlan:
    """Check evidence and prerequisites without executing project code."""
    root = Path(project_root).resolve(strict=True)
    variables = environment if environment is not None else os.environ
    evidence: list[str] = ["Explicit user authorization was supplied outside the project root."]
    needed_variables = set(spec.required_env_names)
    if spec.authorization_checks:
        needed_variables.update(spec.account_env_names)
    missing = [f"Required test variable is unset: {name}" for name in sorted(needed_variables)
               if not variables.get(name)]
    warnings: list[str] = []
    compose_sha256: str | None = None
    if profile.profile.completeness.value != "complete":
        warnings.append("Profiler inventory is partial; startup evidence may be incomplete.")
    if spec.mode == "existing_url":
        evidence.append("A loopback runtime URL was supplied; no application build is needed.")
    else:
        if spec.trust_level != "trusted_lab":
            missing.append("Untrusted project execution requires a VM worker; host Docker Compose is forbidden")
        assert spec.compose_file is not None
        compose_path = root / spec.compose_file
        if not compose_path.is_file() or compose_path.is_symlink() or not compose_path.resolve().is_relative_to(root):
            missing.append(f"Compose file is absent, a symlink, or outside the project: {spec.compose_file}")
        elif not any(item.path == spec.compose_file for item in profile.profile.inventory):
            missing.append(f"Profiler inventory did not include the selected Compose file: {spec.compose_file}")
        else:
            evidence.append(f"Profiler inventoried user-selected Compose file: {spec.compose_file}")
            if spec.compose_file not in profile.profile.targets.compose_files:
                warnings.append("The selected Compose filename is non-standard; execution requires Docker's own configuration validation.")
            try:
                compose_sha256 = hashlib.sha256(compose_path.read_bytes()).hexdigest()
            except OSError:
                missing.append(f"Compose file could not be read: {spec.compose_file}")
        if not (docker_executable or shutil.which("docker")):
            missing.append("Docker CLI is not available")
        else:
            evidence.append("Docker CLI executable is available; daemon and Compose configuration still need runtime verification.")
        warnings.append("Compose execution is opt-in and must pass a separate configuration safety check.")
    if spec.authorization_checks:
        warnings.append("Account references are checked for presence only; generic login/IDOR workflows are not yet implemented.")
    if spec.mutating_checks:
        warnings.append("Mutating checks require an isolated disposable target and a separate explicit scanner opt-in.")
    return EnvironmentPlan(SCHEMA_VERSION, spec.mode, "blocked" if missing else "ready_for_validation",
                           spec.base_url, tuple(evidence), tuple(missing), tuple(warnings), compose_sha256)


@contextmanager
def provision_environment(
    spec: EnvironmentSpec, plan: EnvironmentPlan, *, project_root: str | Path,
    allow_compose_execution: bool = False, docker_executable: str | None = None,
    runner=subprocess.run,
) -> Iterator[TestEnvironmentSession]:
    """Start a narrowly checked Compose stack or validate an existing URL.

    Compose is never run as a side effect of profiling or planning. The caller
    must explicitly opt in and must retain the context until scans finish.
    """
    if plan.status != "ready_for_validation":
        raise RuntimeError("Test environment is blocked; resolve prerequisites first")
    if plan.mode != spec.mode or plan.base_url != spec.base_url:
        raise RuntimeError("Environment plan does not match the supplied configuration")
    if spec.mode == "existing_url":
        _check_health(spec)
        yield TestEnvironmentSession(spec.base_url, spec.mode)
        return
    if spec.trust_level != "trusted_lab":
        raise RuntimeError("Untrusted projects cannot execute Docker Compose on the host; use a VM worker")
    if not allow_compose_execution:
        raise RuntimeError("Compose execution requires explicit opt-in")
    root = Path(project_root).resolve(strict=True)
    assert spec.compose_file is not None
    compose = root / spec.compose_file
    if not compose.is_file() or compose.is_symlink() or not compose.resolve().is_relative_to(root):
        raise RuntimeError("Compose file changed or escaped the project root")
    if not plan.compose_sha256 or hashlib.sha256(compose.read_bytes()).hexdigest() != plan.compose_sha256:
        raise RuntimeError("Compose file changed since the environment plan was created")
    docker = docker_executable or shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker CLI is not available")
    common = [docker, "compose", "-f", str(compose), "-p", "sr-test-" + secrets.token_hex(5)]
    docker_env = _docker_environment(spec)
    cleanup_error: RuntimeError | None = None
    startup_attempted = False
    try:
        configured = runner(common + ["config", "--format", "json"], cwd=root, capture_output=True,
                            text=True, timeout=30, check=False, env=docker_env)
        if configured.returncode != 0:
            raise RuntimeError("Docker Compose could not validate this project configuration")
        _validate_compose_config(json.loads(configured.stdout), spec, root, project_name=common[-1])
        startup_attempted = True
        started = runner(common + ["up", "--build", "--detach", "--wait"], cwd=root,
                         capture_output=True, text=True, timeout=900, check=False, env=docker_env)
        if started.returncode != 0:
            raise RuntimeError("Docker Compose failed to start the isolated test stack")
        _check_health(spec)
        yield TestEnvironmentSession(spec.base_url, spec.mode, common[-1])
    finally:
        # The unique Compose project name limits cleanup to this invocation.
        if startup_attempted:
            try:
                stopped = runner(common + ["down", "--volumes", "--remove-orphans"], cwd=root,
                                 capture_output=True, text=True, timeout=120, check=False, env=docker_env)
                if stopped.returncode != 0:
                    cleanup_error = RuntimeError(f"Test stack cleanup failed for {common[-1]}; inspect Docker manually")
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_error = RuntimeError(f"Test stack cleanup could not finish for {common[-1]}; inspect Docker manually")
                cleanup_error.__cause__ = error
        if cleanup_error is not None:
            raise cleanup_error


def _validate_compose_config(config: object, spec: EnvironmentSpec, root: Path,
                             *, project_name: str | None = None) -> None:
    """Reject dangerous host access; this is a bounded lab policy, not a VM."""
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("Docker Compose returned an invalid configuration")
    if set(config) - {"name", "services", "networks", "volumes"}:
        raise ValueError("Compose configuration uses unsupported top-level features")
    services = config["services"]
    if spec.app_service not in services:
        raise ValueError("Selected application service does not exist in Compose configuration")
    for name, service in services.items():
        if not isinstance(service, dict) or any(service.get(key) for key in _UNSAFE_SERVICE_KEYS):
            raise ValueError(f"Service {name} requests unsupported host or security features")
        if service.get("security_opt") not in (None, [], ["no-new-privileges:true"],
                                               ["no-new-privileges=true"], ["no-new-privileges"]):
            raise ValueError(f"Service {name} requests unsupported security options")
        for volume in service.get("volumes", []):
            if not isinstance(volume, dict) or volume.get("type") != "volume":
                raise ValueError("Bind mounts and host paths are not allowed in a test stack")
        build = service.get("build")
        if build:
            if not isinstance(build, dict) or any(key in build for key in (
                "ssh", "secrets", "additional_contexts", "privileged", "entitlements",
                "network", "dockerfile_inline",
            )):
                raise ValueError("Unsupported or privileged Compose build options")
            raw_context = build.get("context")
            if not isinstance(raw_context, str) or not raw_context:
                raise ValueError("Compose build context is missing")
            context_path = Path(raw_context)
            context = (context_path if context_path.is_absolute() else root / context_path).resolve()
            if not context.is_relative_to(root):
                raise ValueError("Build context escapes the project root")
            dockerfile = build.get("dockerfile", "Dockerfile")
            if not isinstance(dockerfile, str) or Path(dockerfile).is_absolute() or not (context / dockerfile).resolve().is_relative_to(root):
                raise ValueError("Dockerfile escapes the project root")
        for port in service.get("ports", []):
            if not isinstance(port, dict) or port.get("host_ip") != "127.0.0.1":
                raise ValueError("Published ports must bind to 127.0.0.1")
    for network in config.get("networks", {}).values():
        if (not isinstance(network, dict) or network.get("external") or network.get("driver_opts")
                or (network.get("name") and (not project_name or not str(network["name"]).startswith(project_name + "_")))):
            raise ValueError("External Compose networks are not allowed")
    for volume in config.get("volumes", {}).values():
        if (not isinstance(volume, dict) or volume.get("external") or volume.get("driver_opts")
                or (volume.get("name") and (not project_name or not str(volume["name"]).startswith(project_name + "_")))):
            raise ValueError("External or host-backed Compose volumes are not allowed")
    app_ports = services[spec.app_service].get("ports", [])
    expected_port = urllib.parse.urlsplit(spec.base_url).port
    if not any(str(port.get("published")) == str(expected_port) for port in app_ports):
        raise ValueError("Application service does not publish the declared loopback port")


def _docker_environment(spec: EnvironmentSpec) -> dict[str, str]:
    """Do not forward provider keys or arbitrary host secrets to Compose."""
    # Docker locates per-user CLI plugins (including Compose) under the home
    # directory. Keep only its location, not arbitrary user environment data.
    kept = {"PATH", "Path", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME"}
    approved = set(spec.required_env_names)
    if spec.authorization_checks:
        approved.update(spec.account_env_names)
    return {name: value for name, value in os.environ.items()
            if name in kept or name in approved}


def _check_health(spec: EnvironmentSpec) -> None:
    url = spec.base_url.rstrip("/") + spec.health_path
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=5) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("Test application health check could not connect") from error
    if status != spec.expected_status:
        raise RuntimeError(f"Test application health check returned HTTP {status}; expected {spec.expected_status}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _object(value: object, allowed: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError(f"{label} must be an object with recognized fields only")
    return value


def _relative_compose_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("Compose file must be a relative POSIX-style path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {".", ".."} for part in value.split("/")) or path.suffix not in {".yaml", ".yml"}:
        raise ValueError("Compose file must be a relative .yml or .yaml path inside the project")
    return path.as_posix()


def _loopback_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 300:
        raise ValueError("target.base_url must be a short loopback HTTP URL")
    parsed = urllib.parse.urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise ValueError("target.base_url must use a literal loopback IP and explicit port") from error
    if parsed.scheme != "http" or not address.is_loopback or port is None or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("target.base_url must be a loopback HTTP origin without credentials or path")
    return value.rstrip("/")

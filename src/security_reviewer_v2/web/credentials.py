"""OS credential vault only; no plaintext fallback."""
from __future__ import annotations

import os

SERVICE = "VerdictSecurityReviewer"


def _backend():
    import keyring
    backend = keyring.get_keyring()
    module = type(backend).__module__
    if not module.startswith(("keyring.backends.Windows", "keyring.backends.macOS", "keyring.backends.SecretService")):
        raise ValueError("An OS credential vault is unavailable. Set credentials in the launcher environment instead.")
    return backend


def set_secret(name: str, value: str) -> None:
    if not value or len(value) > 8192:
        raise ValueError("Enter a non-empty credential")
    _backend().set_password(SERVICE, name, value)


def get_secret(name: str) -> str | None:
    try:
        return _backend().get_password(SERVICE, name)
    except Exception:
        return None


def worker_environment(project_id: str | None = None, *, accounts=()) -> dict[str, str]:
    environment = os.environ.copy()
    groq = get_secret("groq")
    if groq:
        environment["GROQ_API_KEY"] = groq
    if project_id:
        from security_reviewer_v2.scanners.runtime_workflows import ID, env_name
        for actor in accounts:
            if not ID.fullmatch(actor):
                raise ValueError("Invalid test account ID")
            for field in ("username", "password"):
                value = get_secret(f"{project_id}:workflow:{actor}:{field}")
                if value:
                    environment[env_name(actor, field)] = value
        for field in ("username", "password"):
            value = get_secret(f"{project_id}:zap:{field}")
            if value:
                environment[f"SECURITY_TEST_ZAP_{field.upper()}"] = value
    return environment


def redact(text: str, environment: dict[str, str]) -> str:
    for name, value in environment.items():
        if value and len(value) >= 4 and (name.endswith(("_KEY", "_TOKEN", "_PASSWORD")) or name.startswith("SECURITY_TEST_")):
            text = text.replace(value, "[REDACTED]")
    return text

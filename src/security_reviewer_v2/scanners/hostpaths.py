"""Cross-environment helpers: tolerant version parsing and WSL path translation.

Root causes addressed here (see RCA notes in INTEGRATION_CHANGES.md):
* ``\\b\\d+\\.\\d+\\.\\d+\\b`` never matches ``v8.18.4`` (no word boundary between ``v`` and ``8``),
  so scanners that print a ``v`` prefix were reported as "version could not be read".
* A Windows ``.exe`` launched from WSL receives POSIX paths such as ``/mnt/c/...`` which
  Windows interprets as ``C:\\mnt\\c\\...``; CodeQL then fails with "does not exist".
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath

_VERSION = re.compile(r"(?<![\d.])v?(\d+\.\d+\.\d+)(?![\d.]*\d)")
_MNT = re.compile(r"^/mnt/([A-Za-z])(?:/(.*))?$", re.DOTALL)


def parse_version(text: str) -> str | None:
    """Return the first ``X.Y.Z`` in *text*, accepting an optional leading ``v``."""
    match = _VERSION.search(text or "")
    return match.group(1) if match else None


def needs_windows_paths(executable: str | Path) -> bool:
    """True when a Windows binary is being started from a POSIX interpreter (WSL interop)."""
    return PurePosixPath(str(executable).replace("\\", "/")).suffix.lower() in {".exe", ".bat", ".cmd"} and "/" in str(executable) and str(executable).startswith("/")


def to_windows_path(path: str) -> str:
    """Translate ``/mnt/c/x`` to ``C:\\x``; other POSIX paths go through ``wslpath -w`` when available."""
    match = _MNT.match(path)
    if match:
        rest = (match.group(2) or "").replace("/", "\\")
        return f"{match.group(1).upper()}:\\{rest}" if rest else f"{match.group(1).upper()}:\\"
    try:
        probe = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, timeout=10, check=False)
        translated = probe.stdout.strip()
        if probe.returncode == 0 and translated:
            return translated
    except (OSError, subprocess.TimeoutExpired):
        pass
    return path


def translate_arguments(executable: str | Path, arguments: tuple[str, ...]) -> tuple[str, ...]:
    """Rewrite absolute POSIX paths in *arguments* for a Windows executable; no-op otherwise."""
    if not needs_windows_paths(executable):
        return tuple(arguments)
    translated: list[str] = []
    for argument in arguments:
        prefix, separator, value = argument.partition("=")
        if separator and prefix.startswith("-") and value.startswith("/"):
            translated.append(prefix + "=" + _translate_value(value))
        elif argument.startswith("/"):
            translated.append(_translate_value(argument))
        else:
            translated.append(argument)
    return tuple(translated)


def _translate_value(value: str) -> str:
    if _MNT.match(value) or Path(value).parent.exists():
        return to_windows_path(value)
    return value


def _names(name: str) -> tuple[str, ...]:
    """Executable file names to try: native first, then the other platform's (WSL runs both)."""
    return (f"{name}.exe", f"{name}.cmd", name) if os.name == "nt" else (name, f"{name}.exe")


def find_in_dirs(name: str, *directories: Path | str) -> Path | None:
    """First existing executable called *name* (any platform spelling) inside *directories*."""
    for directory in directories:
        for candidate in _names(name):
            path = Path(directory) / candidate
            if path.is_file():
                return path
    return None


def resolve_tool(name: str, *fallback_directories: Path | str) -> Path | None:
    """PATH lookup first, then the given fallback directories; works on Windows, Linux, macOS and WSL."""
    found = shutil.which(name)
    return Path(found) if found else find_in_dirs(name, *fallback_directories)


def find_codeql(bundle: Path | str) -> Path | None:
    """CodeQL launcher inside a bundle: ``codeql`` (Linux/macOS), ``codeql.exe`` (Windows or WSL)."""
    return find_in_dirs("codeql", bundle)

"""Bounded, non-executing project file discovery."""

from __future__ import annotations

import fnmatch
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .models import (
    Completeness,
    FileCategory,
    FileRecord,
    InventorySummary,
    ProfilerLimits,
    ProfilerPolicy,
    SkipCause,
    SkippedItem,
)


SOURCE_EXTENSIONS = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".php": "php",
    ".scala": "scala",
    ".ex": "elixir",
    ".exs": "elixir",
    ".dart": "dart",
    ".lua": "lua",
}

MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "package.json",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "cargo.toml",
}

LOCKFILE_NAMES = {
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "gemfile.lock",
    "cargo.lock",
    "gradle.lockfile",
}

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".class",
    ".jar",
    ".pyc",
    ".woff",
    ".woff2",
}

CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".tf", ".json"}
VENDOR_PARTS = {"node_modules", "vendor", ".venv", "venv", "site-packages"}
GENERATED_PARTS = {"dist", "build", "coverage", ".next", "target", "generated"}
DEFAULT_SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "site-packages",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
}


class ProfilingInputError(ValueError):
    """Raised when the requested project root is invalid or unreadable."""


@dataclass
class DiscoveryResult:
    root: Path
    files: tuple[FileRecord, ...]
    absolute_paths: dict[str, Path]
    skipped: tuple[SkippedItem, ...]
    warnings: tuple[str, ...]
    completeness: Completeness
    summary: InventorySummary
    reader: "BoundedTextReader"


@dataclass
class BoundedTextReader:
    """Read only explicitly requested text with per-file and total budgets."""

    root: Path
    limits: ProfilerLimits
    total_bytes_read: int = 0
    manifest_bytes_read: int = 0
    truncated: set[str] = field(default_factory=set)
    cache: dict[str, str | None] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    resource_limit_hit: bool = False

    def read(self, relative_path: str, *, purpose: str = "source") -> str | None:
        """purpose="manifest" uses a larger cap and a separate pool (see limits)."""
        if relative_path in self.cache:
            return self.cache[relative_path]
        absolute = (self.root / relative_path).resolve(strict=False)
        if not absolute.is_relative_to(self.root):
            self.warnings.append(f"Refused to read outside project root: {relative_path}")
            self.cache[relative_path] = None
            return None
        try:
            size = absolute.stat().st_size
        except (OSError, FileNotFoundError) as error:
            self.warnings.append(f"Could not stat {relative_path}: {type(error).__name__}")
            self.cache[relative_path] = None
            return None
        manifest = purpose == "manifest"
        per_file = self.limits.max_manifest_read_bytes if manifest else self.limits.max_content_read_bytes
        pool = self.limits.max_total_manifest_bytes if manifest else self.limits.max_total_content_bytes
        used = self.manifest_bytes_read if manifest else self.total_bytes_read - self.manifest_bytes_read
        allowed = min(size, per_file)
        remaining = pool - used
        if remaining <= 0:
            self.resource_limit_hit = True
            self.warnings.append("Total content-read limit reached")
            self.cache[relative_path] = None
            return None
        allowed = min(allowed, remaining)
        try:
            with absolute.open("rb") as handle:
                raw = handle.read(allowed)
        except (OSError, PermissionError) as error:
            self.warnings.append(f"Could not read {relative_path}: {type(error).__name__}")
            self.cache[relative_path] = None
            return None
        self.total_bytes_read += len(raw)
        if manifest:
            self.manifest_bytes_read += len(raw)
        if size > allowed:
            self.resource_limit_hit = True
            self.truncated.add(relative_path)
            self.warnings.append(
                f"Content for {relative_path} was truncated at {allowed} bytes"
            )
        if b"\x00" in raw:
            self.warnings.append(f"Skipped binary-looking content: {relative_path}")
            self.cache[relative_path] = None
            return None
        text = raw.decode("utf-8", errors="replace")
        self.cache[relative_path] = text
        return text


def discover_project(
    project_path: str | Path,
    *,
    limits: ProfilerLimits,
    policy: ProfilerPolicy,
) -> DiscoveryResult:
    """Build a bounded inventory without executing project-controlled code."""
    limits.validate()
    policy.validate()
    raw_root = Path(project_path).expanduser()
    if not raw_root.exists():
        raise ProfilingInputError(f"Project path does not exist: {raw_root}")
    if not raw_root.is_dir():
        raise ProfilingInputError(f"Project path is not a directory: {raw_root}")
    root = raw_root.resolve()
    try:
        with os.scandir(root) as probe:
            next(probe, None)
    except (OSError, PermissionError) as error:
        raise ProfilingInputError(
            f"Project directory is not readable: {root} ({type(error).__name__})"
        ) from error

    start = time.monotonic()
    records: list[FileRecord] = []
    paths: dict[str, Path] = {}
    skipped: list[SkippedItem] = []
    warnings: list[str] = []
    partial = False
    stop = False
    visited_directories: set[Path] = {root}

    def add_skip(path: str, reason: str, cause: SkipCause) -> None:
        nonlocal partial
        skipped.append(SkippedItem(path=path, reason=reason, cause=cause))
        if cause in {SkipCause.RESOURCE_LIMIT, SkipCause.READ_ERROR, SkipCause.DISAPPEARED}:
            partial = True

    def walk(directory: Path, relative_directory: str, depth: int) -> None:
        nonlocal partial, stop
        if stop:
            return
        if time.monotonic() - start >= limits.timeout_seconds:
            add_skip(relative_directory or ".", "Profiling timeout reached", SkipCause.RESOURCE_LIMIT)
            stop = True
            return
        if depth > limits.max_depth:
            add_skip(relative_directory or ".", "Maximum traversal depth reached", SkipCause.RESOURCE_LIMIT)
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except FileNotFoundError:
            add_skip(relative_directory or ".", "Directory disappeared during traversal", SkipCause.DISAPPEARED)
            return
        except (OSError, PermissionError) as error:
            add_skip(
                relative_directory or ".",
                f"Directory could not be read: {type(error).__name__}",
                SkipCause.READ_ERROR,
            )
            return

        for entry in entries:
            if stop:
                return
            relative = f"{relative_directory}/{entry.name}" if relative_directory else entry.name
            relative = relative.replace("\\", "/")
            if _matches_any(relative, policy.additional_discovery_exclusions):
                add_skip(relative, "Explicit discovery policy exclusion", SkipCause.POLICY)
                continue
            try:
                is_link = entry.is_symlink()
            except OSError:
                add_skip(relative, "Entry disappeared during traversal", SkipCause.DISAPPEARED)
                continue
            if is_link:
                if not policy.allow_symlinks:
                    add_skip(relative, "Symbolic links are disabled by policy", SkipCause.SYMLINK)
                    continue
                try:
                    resolved = Path(entry.path).resolve(strict=True)
                except (OSError, RuntimeError):
                    add_skip(relative, "Symbolic link target is unavailable", SkipCause.READ_ERROR)
                    continue
                if not resolved.is_relative_to(root):
                    add_skip(relative, "Symbolic link resolves outside project root", SkipCause.OUTSIDE_ROOT)
                    continue
                if resolved.is_dir():
                    if resolved in visited_directories:
                        add_skip(relative, "Symbolic link cycle or duplicate target", SkipCause.POLICY)
                        continue
                    visited_directories.add(resolved)
                    walk(resolved, relative, depth + 1)
                    continue
            try:
                if entry.is_dir(follow_symlinks=policy.allow_symlinks):
                    if entry.name.casefold() in DEFAULT_SKIPPED_DIRECTORIES:
                        add_skip(relative, "Default discovery directory exclusion", SkipCause.POLICY)
                        continue
                    resolved_dir = Path(entry.path).resolve(strict=False)
                    if not resolved_dir.is_relative_to(root):
                        add_skip(relative, "Directory resolves outside project root", SkipCause.OUTSIDE_ROOT)
                        continue
                    if resolved_dir in visited_directories:
                        add_skip(relative, "Duplicate directory target", SkipCause.POLICY)
                        continue
                    visited_directories.add(resolved_dir)
                    walk(Path(entry.path), relative, depth + 1)
                    continue
                if not entry.is_file(follow_symlinks=policy.allow_symlinks):
                    add_skip(relative, "Entry is not a regular file", SkipCause.POLICY)
                    continue
                if len(records) >= limits.max_files:
                    add_skip(relative, "Maximum file count reached", SkipCause.RESOURCE_LIMIT)
                    stop = True
                    return
                stat = entry.stat(follow_symlinks=policy.allow_symlinks)
                if stat.st_size > limits.max_file_size_bytes:
                    add_skip(
                        relative,
                        f"File exceeds inventory size limit ({stat.st_size} bytes)",
                        SkipCause.RESOURCE_LIMIT,
                    )
                    continue
            except FileNotFoundError:
                add_skip(relative, "File disappeared during traversal", SkipCause.DISAPPEARED)
                continue
            except (OSError, PermissionError) as error:
                add_skip(relative, f"File metadata unavailable: {type(error).__name__}", SkipCause.READ_ERROR)
                continue

            category = classify_file(relative)
            suffix = Path(entry.name).suffix.casefold()
            records.append(
                FileRecord(
                    path=relative,
                    extension=suffix,
                    size_bytes=stat.st_size,
                    category=category,
                )
            )
            paths[relative] = Path(entry.path)

    walk(root, "", 0)
    records.sort(key=lambda item: item.path.casefold())
    skipped.sort(key=lambda item: (item.path.casefold(), item.cause.value))
    counts = Counter(item.category.value for item in records)
    reader = BoundedTextReader(root=root, limits=limits)
    summary = InventorySummary(
        total_files=len(records),
        total_bytes=sum(item.size_bytes for item in records),
        content_bytes_read=0,
        skipped_count=len(skipped),
        by_category=dict(sorted(counts.items())),
    )
    if not records and partial:
        completeness = Completeness.FAILED
    else:
        completeness = Completeness.PARTIAL if partial else Completeness.COMPLETE
    return DiscoveryResult(
        root=root,
        files=tuple(records),
        absolute_paths=paths,
        skipped=tuple(skipped),
        warnings=tuple(warnings),
        completeness=completeness,
        summary=summary,
        reader=reader,
    )


def classify_file(relative_path: str) -> FileCategory:
    path = Path(relative_path)
    lowered_parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    if lowered_parts & VENDOR_PARTS:
        return FileCategory.VENDOR
    if lowered_parts & GENERATED_PARTS or name.endswith((".generated.py", ".min.js")):
        return FileCategory.GENERATED
    if name in LOCKFILE_NAMES:
        return FileCategory.LOCKFILE
    if name in MANIFEST_NAMES or name.startswith("requirements") and suffix == ".txt":
        return FileCategory.DEPENDENCY_MANIFEST
    if suffix in BINARY_EXTENSIONS:
        return FileCategory.BINARY
    if suffix in SOURCE_EXTENSIONS:
        if _is_test_path(path):
            return FileCategory.TEST
        return FileCategory.SOURCE
    if (
        suffix in CONFIG_EXTENSIONS
        or name.startswith("dockerfile")
        or name in {".gitignore", ".env", ".env.example", "makefile"}
    ):
        return FileCategory.CONFIGURATION
    return FileCategory.UNKNOWN


def language_for_file(record: FileRecord) -> str | None:
    return SOURCE_EXTENSIONS.get(record.extension)


def _is_test_path(path: Path) -> bool:
    parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    return bool(parts & {"test", "tests", "spec", "specs", "__tests__"}) or name.startswith(
        ("test_", "spec_")
    ) or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))


def _matches_any(path: str, patterns: tuple[str, ...]) -> bool:
    normalized = path.replace("\\", "/")
    return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in patterns)


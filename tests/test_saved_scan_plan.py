"""Saved profiler artifacts remain usable by the standalone scanner stage."""

from __future__ import annotations

import json
import os

import pytest

from scripts.run_saved_scan_plan import load_saved_plan
from security_reviewer_v2.profiler import profile_project
from security_reviewer_v2.profiler.artifact import create_saved_profile_artifact
from security_reviewer_v2.profiler.cli import main as profiler_main


def save_profile(project, saved) -> None:
    result = profile_project(project)
    saved.write_text(
        json.dumps(create_saved_profile_artifact(result, project)), encoding="utf-8"
    )


def test_load_saved_plan_round_trips_profile_tasks(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"
    save_profile(project, saved)

    loaded = load_saved_plan(saved, project_root=project)

    assert loaded == profile_project(project).scan_plan


def test_load_saved_plan_rejects_different_project_root(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"
    save_profile(project, saved)

    with pytest.raises(ValueError, match="different project root"):
        load_saved_plan(saved, project_root=tmp_path / "different-project")


def test_same_folder_name_at_another_location_is_rejected(tmp_path) -> None:
    first = tmp_path / "first" / "project"
    second = tmp_path / "second" / "project"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (second / "app.py").write_text("print('hello')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"
    save_profile(first, saved)

    with pytest.raises(ValueError, match="different project root"):
        load_saved_plan(saved, project_root=second)


def test_same_size_source_change_even_with_original_timestamp_is_rejected(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    source.write_text("print('a')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"
    save_profile(project, saved)
    original = source.stat()
    source.write_text("print('b')\n", encoding="utf-8")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))

    with pytest.raises(ValueError, match="stale"):
        load_saved_plan(saved, project_root=project)


def test_new_file_and_edited_plan_are_rejected(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"
    save_profile(project, saved)
    (project / "new.py").write_text("print('new')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory changed"):
        load_saved_plan(saved, project_root=project)

    (project / "new.py").unlink()
    payload = json.loads(saved.read_text(encoding="utf-8"))
    payload["scan_plan"]["policy_version"] = "edited"
    saved.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        load_saved_plan(saved, project_root=project)


def test_legacy_profile_without_snapshot_requires_regeneration(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"
    saved.write_text(json.dumps(profile_project(project).to_dict()), encoding="utf-8")

    with pytest.raises(ValueError, match="rerun the profiler"):
        load_saved_plan(saved, project_root=project)


def test_profiler_cli_writes_a_snapshot_accepted_by_saved_scan_stage(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    saved = tmp_path / "profile.json"

    assert profiler_main([str(project), "--output", str(saved)]) == 0
    assert len(load_saved_plan(saved, project_root=project).tasks) > 0
    assert (tmp_path / "profile.md").is_file()

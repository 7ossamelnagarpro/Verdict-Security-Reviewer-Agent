"""The isolated pilot stages only reviewed files and rejects unsafe archives."""

from __future__ import annotations

import json
import hashlib
import stat
import zipfile
from pathlib import Path

import pytest

from scripts.hyperv_pilot_guest import extract_bounded, require_disconnected_network, sha256
from scripts.stage_hyperv_pilot import WHEEL_PREFIXES, stage
from scripts.hyperv_autoscan_guest import _validate_manifest
import scripts.run_pre_review_pipeline as pipeline_module
from scripts.run_pre_review_pipeline import main as pipeline_main
from security_reviewer_v2.test_environment.pilot_evidence import load_completed_pilot
from security_reviewer_v2.test_environment.isolated_runtime import load_isolated_runtime
from security_reviewer_v2.reporting.final import render_final_report


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    target = tmp_path / "target"
    (target / "files").mkdir(parents=True)
    (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    (target / "requirements.txt").write_text("Flask==3.1.3\n", encoding="utf-8")
    (target / "files" / "report.txt").write_text("fixture\n", encoding="utf-8")
    (target / "secret_do_not_serve.txt").write_text("demo only\n", encoding="utf-8")
    (target / "ground_truth.json").write_text('{"answer":"excluded"}', encoding="utf-8")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    for prefix in WHEEL_PREFIXES:
        suffix = "3.0.4-cp312-cp312-manylinux2014_x86_64.whl" if prefix == "markupsafe-" else "1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheels / f"{prefix}{suffix}", "w") as archive:
            archive.writestr(f"{prefix}module.py", "value = 1\n")
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    runner = tmp_path / "guest.py"
    runner.write_text("# trusted runner\n", encoding="utf-8")
    return target, wheels, exchange, runner


def test_stage_fixed_target_offline_without_ground_truth(tmp_path: Path) -> None:
    target, wheels, exchange, runner = _fixture(tmp_path)
    manifest = stage(target, wheels, exchange, "a0b1c2d3", runner)

    assert manifest["run_id"] == "a0b1c2d3"
    assert manifest["app_sha256"] == sha256(target / "app.py")
    assert len(manifest["files"]) == 8
    assert json.loads((exchange / "manifest.json").read_text()) == manifest
    with zipfile.ZipFile(exchange / "security-lab-web.zip") as archive:
        assert archive.namelist() == ["app.py", "requirements.txt", "files/report.txt",
                                      "secret_do_not_serve.txt"]
        assert "ground_truth.json" not in archive.namelist()


def test_stage_rejects_changed_requirements(tmp_path: Path) -> None:
    target, wheels, exchange, runner = _fixture(tmp_path)
    (target / "requirements.txt").write_text("unreviewed-package\n", encoding="utf-8")
    with pytest.raises(ValueError, match="reviewed"):
        stage(target, wheels, exchange, "a0b1c2d3", runner)
    assert list(exchange.iterdir()) == []


def test_stage_automatic_runtime_manifest(tmp_path: Path) -> None:
    target, wheels, exchange, runner = _fixture(tmp_path)
    stage(target, wheels, exchange, "a0b1c2d3", runner,
          automatic_runtime=True, mutating_checks=True)
    manifest = _validate_manifest(exchange)
    assert manifest["mode"] == "automatic_runtime_scan"
    assert manifest["mutating_checks"] is True


@pytest.mark.parametrize("member", ["../escape", "/absolute", "a:b"])
def test_guest_rejects_unsafe_archive_paths(tmp_path: Path, member: str) -> None:
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, "bad")
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        extract_bounded(archive_path, tmp_path / "out")
    assert not (tmp_path / "escape").exists()


def test_guest_rejects_archive_symlink(tmp_path: Path) -> None:
    archive_path = tmp_path / "link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(info, "../escape")
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        extract_bounded(archive_path, tmp_path / "out")


def test_guest_extracts_small_regular_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "small.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("files/data.txt", "okay")
    extract_bounded(archive_path, tmp_path / "out")
    assert (tmp_path / "out" / "files" / "data.txt").read_text() == "okay"


def test_guest_requires_all_non_loopback_links_down(tmp_path: Path) -> None:
    links = tmp_path / "net"
    (links / "lo").mkdir(parents=True)
    (links / "eth0").mkdir()
    (links / "eth0" / "operstate").write_text("down\n")
    require_disconnected_network(links)
    (links / "eth0" / "operstate").write_text("up\n")
    with pytest.raises(RuntimeError, match="network_link_present"):
        require_disconnected_network(links)


def _completed_evidence(tmp_path: Path) -> tuple[Path, Path, str]:
    repository = tmp_path / "reviewer"
    project = repository / "targets" / "security-lab-web"
    project.mkdir(parents=True)
    (project / "app.py").write_text("# fixed educational app\n", encoding="utf-8")
    run_id = "a0b1c2d3"
    result = repository / "reports" / "hyperv-pilot" / run_id
    result.mkdir(parents=True)
    app_hash = hashlib.sha256((project / "app.py").read_bytes()).hexdigest()
    (result / "guest-report.json").write_text(json.dumps({
        "schema_version": "1.0", "run_id": run_id, "target_id": "security-lab-web",
        "test_kind": "local_health_smoke_only", "status": "passed",
        "http_status": 200, "network_required": False, "app_sha256": app_hash,
    }), encoding="utf-8")
    (result / "lifecycle.json").write_text(json.dumps({
        "schema_version": "1.0", "run_id": run_id, "guest_status": "passed",
        "worker_removed": True, "base_checkpoint_unchanged": True,
        "base_disk_sha256_unchanged": True, "network_isolation": "no_vm_switch",
        "result": "guest-report.json",
    }), encoding="utf-8")
    return repository, project, run_id


def test_completed_pilot_import_is_health_evidence_only(tmp_path: Path) -> None:
    repository, project, run_id = _completed_evidence(tmp_path)
    result = load_completed_pilot(run_id, project_root=project, repository_root=repository)

    assert result["status"] == "passed"
    assert result["http_status"] == 200
    assert result["worker_removed"] is True
    assert "DAST" in result["limitations"][0]
    markdown = render_final_report(project=str(project), review={"status": "not_run"},
                                   policy={"status": "not_run"}, isolated_pilot=result)
    assert "Isolated VM Pilot Evidence" in markdown
    assert "not a vulnerability scan" in markdown


def test_completed_pilot_import_rejects_changed_source(tmp_path: Path) -> None:
    repository, project, run_id = _completed_evidence(tmp_path)
    (project / "app.py").write_text("# changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source changed"):
        load_completed_pilot(run_id, project_root=project, repository_root=repository)


@pytest.mark.parametrize("field", ["worker_removed", "base_checkpoint_unchanged",
                                     "base_disk_sha256_unchanged"])
def test_completed_pilot_import_rejects_bad_lifecycle(tmp_path: Path, field: str) -> None:
    repository, project, run_id = _completed_evidence(tmp_path)
    path = repository / "reports" / "hyperv-pilot" / run_id / "lifecycle.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="lifecycle"):
        load_completed_pilot(run_id, project_root=project, repository_root=repository)


def test_completed_pilot_import_rejects_wrong_project(tmp_path: Path) -> None:
    repository, project, run_id = _completed_evidence(tmp_path)
    other = repository / "targets" / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="fixed Security Lab Web"):
        load_completed_pilot(run_id, project_root=other, repository_root=repository)


def _completed_runtime(tmp_path: Path) -> tuple[Path, Path, str]:
    repository, project, run_id = _completed_evidence(tmp_path)
    result = repository / "reports" / "hyperv-autoscan" / run_id
    result.mkdir(parents=True)
    app_hash = hashlib.sha256((project / "app.py").read_bytes()).hexdigest()
    hashes = {}
    for filename, source in (("runtime.json", "web-runtime"),
                             ("authorization.json", "tt-authorization-runtime")):
        path = result / filename
        path.write_text(json.dumps({
            "schema_version": "1.0", "source": source,
            "target": "http://127.0.0.1:5000", "status": "completed",
            "results": [{"rule_id": "example", "path": "/", "vulnerable": True,
                         "severity": "medium", "confidence": "high"}],
        }), encoding="utf-8")
        hashes[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    (result / "guest-report.json").write_text(json.dumps({
        "schema_version": "1.0", "run_id": run_id, "target_id": "security-lab-web",
        "test_kind": "isolated_runtime_scan", "status": "passed", "http_status": 200,
        "network_required": False, "mutating_checks_enabled": False,
        "app_sha256": app_hash, "output_sha256": hashes,
        "probe_counts": {"runtime.json": 1, "authorization.json": 1},
    }), encoding="utf-8")
    (result / "lifecycle.json").write_text(json.dumps({
        "schema_version": "1.0", "run_id": run_id, "guest_status": "passed",
        "worker_removed": True, "base_checkpoint_unchanged": True,
        "base_disk_sha256_unchanged": True, "network_isolation": "no_vm_switch",
        "runtime_scan": True, "trusted_tools_matched": True,
        "result": "guest-report.json",
    }), encoding="utf-8")
    return repository, project, run_id


def test_automatic_runtime_import_and_report(tmp_path: Path) -> None:
    repository, project, run_id = _completed_runtime(tmp_path)
    result = load_isolated_runtime(run_id, project_root=project, repository_root=repository)
    assert result["probe_counts"] == {"runtime.json": 1, "authorization.json": 1}
    assert result["worker_removed"] is True
    markdown = render_final_report(project=str(project), review={"status": "not_run"},
                                   policy={"status": "not_run"}, isolated_runtime=result)
    assert "Automatic Isolated DAST" in markdown
    assert "web probes: **1**" in markdown


def test_automatic_runtime_import_rejects_tampered_probe(tmp_path: Path) -> None:
    repository, project, run_id = _completed_runtime(tmp_path)
    path = repository / "reports" / "hyperv-autoscan" / run_id / "runtime.json"
    path.write_text('{"status":"completed","results":[]}', encoding="utf-8")
    with pytest.raises(ValueError, match="did not match guest evidence"):
        load_isolated_runtime(run_id, project_root=project, repository_root=repository)


def test_pipeline_require_dast_rejects_health_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "output"
    monkeypatch.delenv("SECURITY_REVIEWER_RUNTIME_URL", raising=False)
    monkeypatch.setattr("sys.argv", ["run_pre_review_pipeline.py", str(project),
                                    "--output", str(output), "--require-dast"])
    with pytest.raises(SystemExit) as error:
        pipeline_main()
    assert error.value.code == 2
    assert not output.exists()


def test_pipeline_imports_isolated_dast_without_a_host_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, project, run_id = _completed_runtime(tmp_path)
    output = tmp_path / "pipeline-output"
    monkeypatch.delenv("SECURITY_REVIEWER_RUNTIME_URL", raising=False)
    monkeypatch.setattr(pipeline_module, "__file__",
                        str(repository / "scripts" / "run_pre_review_pipeline.py"))
    class Provider:
        name = "groq"
        model = "test-model"

        def discover(self, prompt: str, *, timeout_seconds: int | None, max_candidates: int):
            return {"candidates": [], "context_requests": []}, {"total_tokens": 1}

    monkeypatch.setattr(pipeline_module, "provider_from_environment", lambda *_: Provider())
    monkeypatch.setattr(pipeline_module, "run_security_review", lambda *_, **__: type(
        "Review", (), {"to_dict": lambda self: {"status": "completed", "reviews": [],
                                                  "usage": {"calls": 1}}})())
    monkeypatch.setattr("sys.argv", ["run_pre_review_pipeline.py", str(project),
                                    "--output", str(output), "--isolated-runtime-run-id", run_id,
                                    "--require-dast"])

    assert pipeline_module.main() == 0
    summary = json.loads((output / "pre-review-summary.json").read_text(encoding="utf-8"))
    assert summary["dast_requirement"] == {"requested": True, "satisfied": True}
    assert summary["isolated_runtime"]["status"] == "passed"
    assert summary["endpoint_coverage"]["status"] == "isolated_completed"
    assert summary["ai_discovery"]["required"] is True
    assert summary["ai_discovery"]["satisfied"] is True
    assert summary["ai_discovery"]["provider_calls"] > 0
    assert (output / "runtime-normalized.json").is_file()
    assert (output / "authorization-normalized.json").is_file()
    report = (output / "security-review-report.md").read_text(encoding="utf-8")
    assert "Scanner and DAST Observations (Pre-Review)" in report
    assert "**2** merged observation record(s)" in report
    assert "No agent verdicts were produced" in report
    assert "AI Discovery: **completed required stage**" in report


def test_partial_security_review_does_not_complete_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, project, run_id = _completed_runtime(tmp_path)
    output = tmp_path / "partial-review-output"
    monkeypatch.delenv("SECURITY_REVIEWER_RUNTIME_URL", raising=False)
    monkeypatch.setattr(pipeline_module, "__file__",
                        str(repository / "scripts" / "run_pre_review_pipeline.py"))

    class Provider:
        name = "groq"
        model = "test-model"

        def discover(self, prompt: str, *, timeout_seconds: int | None, max_candidates: int):
            return {"candidates": [], "context_requests": []}, {"total_tokens": 1}

    monkeypatch.setattr(pipeline_module, "provider_from_environment", lambda *_: Provider())
    monkeypatch.setattr(pipeline_module, "run_security_review", lambda *_, **__: type(
        "Review", (), {"to_dict": lambda self: {
            "status": "partial", "reviews": [], "pending_ids": ["runtime-group"],
            "warnings": ["Review provider stopped: HTTP 429"], "usage": {"calls": 1},
        }})())
    monkeypatch.setattr("sys.argv", ["run_pre_review_pipeline.py", str(project),
                                    "--output", str(output),
                                    "--isolated-runtime-run-id", run_id,
                                    "--require-dast"])

    assert pipeline_module.main() == 1
    summary = json.loads((output / "pre-review-summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "partial"
    assert summary["ai_discovery"]["satisfied"] is True
    assert summary["security_review"]["status"] == "partial"
    assert summary["security_review"]["satisfied"] is False
    assert (output / "security-review-report.md").is_file()


def test_full_scan_requires_ai_provider_before_writing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "output"
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("SECURITY_REVIEWER_RUNTIME_URL", raising=False)
    monkeypatch.setattr("sys.argv", ["run_pre_review_pipeline.py", str(project), "--output", str(output)])

    with pytest.raises(SystemExit) as error:
        pipeline_module.main()
    assert error.value.code == 2
    assert not output.exists()


def test_failed_ai_discovery_keeps_report_but_fails_full_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, project, run_id = _completed_runtime(tmp_path)
    output = tmp_path / "failed-output"
    monkeypatch.delenv("SECURITY_REVIEWER_RUNTIME_URL", raising=False)
    monkeypatch.setattr(pipeline_module, "__file__",
                        str(repository / "scripts" / "run_pre_review_pipeline.py"))
    class FailingProvider:
        name = "groq"
        model = "test-model"

        def discover(self, prompt: str, *, timeout_seconds: int | None, max_candidates: int):
            raise RuntimeError("test provider unavailable")

    monkeypatch.setattr(pipeline_module, "provider_from_environment", lambda *_: FailingProvider())
    monkeypatch.setattr("sys.argv", ["run_pre_review_pipeline.py", str(project),
                                    "--output", str(output), "--isolated-runtime-run-id", run_id,
                                    "--require-dast"])

    assert pipeline_module.main() == 1
    summary = json.loads((output / "pre-review-summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "partial"
    assert summary["ai_discovery"]["required"] is True
    assert summary["ai_discovery"]["satisfied"] is False
    assert summary["ai_discovery"]["failed_batches"] > 0
    assert (output / "runtime.json").exists()
    assert (output / "security-review-report.md").exists()
    assert "This scan is incomplete" in (output / "security-review-report.md").read_text(encoding="utf-8")

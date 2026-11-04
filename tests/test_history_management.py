"""History removal preserves evidence and cannot hide active/recoverable work."""

import re

import pytest

from security_reviewer_v2.web.app import create_app
from security_reviewer_v2.web.service import LocalService


def client_with_jobs(tmp_path):
    service = LocalService(tmp_path, root=tmp_path / "state")
    report = tmp_path / "report.json"
    report.write_text('{"evidence": "preserve me"}', encoding="utf-8")
    for identifier, status in (
        ("done", "completed"),
        ("failed", "failed"),
        ("live", "running"),
        ("cleanup", "cleanup_failed"),
    ):
        service.db.save(
            "jobs",
            {
                "id": identifier,
                "status": status,
                "mode": "project-full",
                "report_dir": str(tmp_path),
            },
        )
    client = create_app(tmp_path, store=service).test_client()
    page = client.get("/").get_data(as_text=True)
    token = re.search(r'name="verdict-token" content="([^"]+)"', page)[1]
    return service, client, {"X-Verdict-Token": token}, report


def test_remove_restore_preserves_reports_and_survives_restart(tmp_path):
    service, client, headers, report = client_with_jobs(tmp_path)
    assert (
        client.post("/api/jobs/done/remove", json={}, headers=headers).status_code
        == 200
    )
    assert "done" not in {j["id"] for j in client.get("/api/jobs").get_json()}
    assert [j["id"] for j in client.get("/api/jobs?removed=1").get_json()] == ["done"]
    assert report.read_text() == '{"evidence": "preserve me"}'
    assert LocalService(tmp_path, root=service.db.root).db.removed_history() == {"done"}
    assert (
        client.post("/api/jobs/done/restore", json={}, headers=headers).status_code
        == 200
    )
    assert "done" in {j["id"] for j in client.get("/api/jobs").get_json()}


def test_clear_only_finished_history_and_requires_csrf(tmp_path):
    _service, client, headers, report = client_with_jobs(tmp_path)
    assert client.post("/api/history/clear", json={}).status_code == 403
    response = client.post("/api/history/clear", json={}, headers=headers)
    assert response.get_json() == {"changed": 2, "reports_preserved": True}
    assert {j["id"] for j in client.get("/api/jobs").get_json()} == {"live", "cleanup"}
    assert report.is_file()
    assert (
        client.post("/api/history/clear", json={}, headers=headers).get_json()[
            "changed"
        ]
        == 0
    )


@pytest.mark.parametrize(
    "status", ["running", "queued", "cancelling", "cleanup_failed", "unknown"]
)
def test_unfinished_jobs_cannot_be_hidden(tmp_path, status):
    service, client, headers, _ = client_with_jobs(tmp_path)
    service.db.save(
        "jobs", {"id": "protected", "status": status, "mode": "project-full"}
    )
    assert (
        client.post("/api/jobs/protected/remove", json={}, headers=headers).status_code
        == 400
    )
    assert "protected" not in service.db.removed_history()

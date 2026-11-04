"""Saved-report re-verification must refuse a changed source snapshot."""

import hashlib
import os
from pathlib import Path

import pytest

from scripts.reverify_saved_discovery import _attest_snapshot


def test_saved_reverification_attests_source_hashes(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    profile = {
        "project_snapshot": {
            "root_path": os.path.normcase(str(tmp_path.resolve())),
            "files": [
                {
                    "path": "app.py",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ],
        }
    }
    _attest_snapshot(tmp_path.resolve(), profile)

    source.write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Source changed since the saved scan"):
        _attest_snapshot(tmp_path.resolve(), profile)

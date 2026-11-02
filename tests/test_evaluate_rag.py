from __future__ import annotations

import json

import pytest

from scripts.evaluate_rag import _write_result


def test_write_result_creates_new_artifact(tmp_path) -> None:
    path = tmp_path / "nested" / "result.json"
    _write_result(path, {"split": "dev", "score": 0.78})
    assert json.loads(path.read_text(encoding="utf-8")) == {"split": "dev", "score": 0.78}


def test_write_result_refuses_to_replace_existing_artifact(tmp_path) -> None:
    path = tmp_path / "result.json"
    path.write_text("original", encoding="utf-8")
    with pytest.raises(FileExistsError):
        _write_result(path, {"score": 0.99})
    assert path.read_text(encoding="utf-8") == "original"

"""Repository-wide pytest defaults that keep normal test runs offline."""
from __future__ import annotations

import os
import socket
from pathlib import Path
from uuid import uuid4

import pytest


ROOT = Path(__file__).resolve().parent
_TEST_BASETEMP: Path | None = None


def pytest_configure(config: pytest.Config) -> None:
    # Use a unique project-local directory so a reused Windows PID cannot
    # collide with a stale or ACL-restricted temp tree from an earlier run.
    global _TEST_BASETEMP
    basetemp = ROOT / f".pytest-tmp-{os.getpid()}-{uuid4().hex}"
    _TEST_BASETEMP = basetemp
    config.option.basetemp = str(basetemp)


@pytest.fixture(scope="session", autouse=True)
def initialize_pytest_temp_root(tmp_path_factory: pytest.TempPathFactory) -> None:
    # Initialize pytest's temp factory before any graph test writes its
    # isolated incident DB below basetemp. Otherwise the first tmp_path use
    # lazily clears that DB on Windows while SQLite still has it open.
    tmp_path_factory.getbasetemp()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        path = Path(str(item.path)).resolve()
        relative = path.relative_to(ROOT)
        if relative.parts[0] == "scripts" and path.name == "test_demo_actions.py":
            item.add_marker(pytest.mark.integration)
            item.add_marker(pytest.mark.requires_external)
        elif relative.parts[0] == "tests":
            if path.name == "test_e2e_pipeline.py":
                item.add_marker(pytest.mark.integration)
                item.add_marker(pytest.mark.slow)
            else:
                item.add_marker(pytest.mark.unit)
        elif relative.parts[0] == "scripts" and path.name == "test_firewall_connector.py":
            item.add_marker(pytest.mark.unit)


@pytest.fixture(autouse=True)
def disable_model_downloads_and_live_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests from discovering local credentials or downloading models."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "false")

    # Fail immediately if a test reaches an unmocked network boundary. The
    # live demo is explicitly marked requires_external and excluded by default.
    def reject_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network access is disabled in the offline pytest suite")

    monkeypatch.setattr(socket, "create_connection", reject_connect)
    monkeypatch.setattr(socket.socket, "connect", reject_connect)

    # Graph closure normally writes to data/incidents.db. Keep pipeline tests
    # from touching repository data; IncidentStore unit tests pass their own
    # explicit tmp_path database and remain unaffected.
    from models import incident_store

    monkeypatch.setattr(
        incident_store,
        "DEFAULT_DB_PATH",
        basetemp_path() / "app-db" / "incidents-test.db",
    )


def basetemp_path() -> Path:
    if _TEST_BASETEMP is None:
        raise RuntimeError("pytest basetemp was not initialized")
    return _TEST_BASETEMP

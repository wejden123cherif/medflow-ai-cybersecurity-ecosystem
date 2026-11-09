"""Repository-wide pytest defaults that keep ordinary tests offline and isolated."""
from __future__ import annotations

import os
import smtplib
import socket
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest


ROOT = Path(__file__).resolve().parent
_TEST_BASETEMP: Path | None = None

# Files whose tests have been reviewed as offline and deterministic. Other tests
# must opt into the integration/slow markers rather than inheriting `unit`.
SAFE_UNIT_TESTS = {
    "test_approval_gate.py",
    "test_closure_node.py",
    "test_correlation.py",
    "test_evaluate_rag.py",
    "test_ids_connector.py",
    "test_incident_model.py",
    "test_incident_store.py",
    "test_integrations.py",
    "test_playbook_loader.py",
    "test_rag_provenance.py",
    "test_reporting.py",
    "test_response_executor.py",
    "test_response_planner.py",
    "test_risk_node.py",
    "test_remote_exec.py",
    "test_suricata_collector.py",
    "test_wazuh_fallback.py",
    "test_verify_lab_ingestion.py",
    "test_architecture_split.py",
    "test_alert_ingestion.py",
    "test_cli_safety.py",
    "test_email_connector.py",
    "test_incident_email_dispatch.py",
}


# These values are installed before collection so config.load_dotenv() cannot
# load developer credentials into test processes. Per-test fixtures may replace
# them with explicit fake values.
SAFE_TEST_ENV = {
    "GROQ_API_KEY": "",
    "SMTP_HOST": "",
    "SMTP_PORT": "587",
    "SMTP_USER": "",
    "SMTP_PASSWORD": "",
    "SMTP_FROM": "test@invalid",
    "SOC_EMAIL": "soc@invalid",
    "SOC_EMAIL_ALLOWLIST": "",
    "EMAIL_MODE": "mock",
    "WAZUH_URL": "",
    "WAZUH_INDEXER_URL": "",
    "WAZUH_USER": "",
    "WAZUH_PASSWORD": "",
    "WAZUH_INDEXER_USER": "",
    "WAZUH_INDEXER_PASSWORD": "",
    "MEDFLOW_WAZUH_INDEXER_USER": "",
    "MEDFLOW_WAZUH_INDEXER_PASSWORD": "",
    "MISP_URL": "",
    "MISP_API_KEY": "",
    "ABUSEIPDB_API_KEY": "",
    "NVD_API_KEY": "",
    "TARGET_VM_HOST": "",
    "TARGET_VM_SSH_USER": "",
    "TARGET_VM_SSH_KEY_PATH": "",
}


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-external",
        action="store_true",
        default=False,
        help="allow collection of tests marked integration or requires_external",
    )


def pytest_configure(config: pytest.Config) -> None:
    global _TEST_BASETEMP
    basetemp = ROOT / f".pytest-tmp-{os.getpid()}-{uuid4().hex}"
    _TEST_BASETEMP = basetemp
    config.option.basetemp = str(basetemp)

    for key, value in SAFE_TEST_ENV.items():
        os.environ[key] = value
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    os.environ["HF_HOME"] = str(basetemp / "model-cache")
    os.environ["SENTENCE_TRANSFORMERS_HOME"] = str(basetemp / "model-cache" / "sentence-transformers")
    os.environ["SURICATA_EVE_PATH"] = str(basetemp / "suricata-eve.jsonl")
    os.environ["WAZUH_CHECKPOINT_PATH"] = str(basetemp / "wazuh-checkpoint.json")
    os.environ["SURICATA_CHECKPOINT_PATH"] = str(basetemp / "suricata-checkpoint.json")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        path = Path(str(item.path)).resolve()
        relative = path.relative_to(ROOT)

        if relative.parts[0] == "scripts" and path.name == "test_demo_actions.py":
            item.add_marker(pytest.mark.integration)
            item.add_marker(pytest.mark.requires_external)
        elif relative.parts[0] == "scripts" and path.name == "test_firewall_connector.py":
            item.add_marker(pytest.mark.unit)
        elif relative.parts[0] == "tests":
            if path.name == "test_e2e_pipeline.py":
                item.add_marker(pytest.mark.integration)
                item.add_marker(pytest.mark.slow)
            elif path.name == "test_rag_real_embeddings.py":
                item.add_marker(pytest.mark.integration)
                item.add_marker(pytest.mark.slow)
                item.add_marker(pytest.mark.requires_external)
            elif path.name in SAFE_UNIT_TESTS:
                item.add_marker(pytest.mark.unit)
            else:
                item.add_marker(pytest.mark.integration)
                item.add_marker(pytest.mark.slow)

        if item.get_closest_marker("requires_external") or item.get_closest_marker("integration"):
            if not config.getoption("--run-external"):
                item.add_marker(pytest.mark.skip(reason="requires explicit --run-external opt-in"))


@pytest.fixture(scope="session", autouse=True)
def initialize_pytest_temp_root(tmp_path_factory: pytest.TempPathFactory) -> None:
    tmp_path_factory.getbasetemp()


def _reject_external(*args: object, **kwargs: object) -> None:
    raise RuntimeError("External process/network/email access is disabled in ordinary pytest runs")


@pytest.fixture(autouse=True)
def disable_external_side_effects(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Block accidental live service, SSH, email, and model-download access."""
    for key, value in SAFE_TEST_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "false")
    monkeypatch.setenv("HF_HOME", str(basetemp_path() / "model-cache"))
    monkeypatch.setenv("SENTENCE_TRANSFORMERS_HOME", str(basetemp_path() / "model-cache" / "sentence-transformers"))
    monkeypatch.setenv("SURICATA_EVE_PATH", str(basetemp_path() / "suricata-eve.jsonl"))
    monkeypatch.setenv("WAZUH_CHECKPOINT_PATH", str(tmp_path / "wazuh-checkpoint.json"))
    monkeypatch.setenv("SURICATA_CHECKPOINT_PATH", str(tmp_path / "suricata-checkpoint.json"))

    monkeypatch.setattr(socket, "create_connection", _reject_external)
    monkeypatch.setattr(socket.socket, "connect", _reject_external)
    monkeypatch.setattr(subprocess, "run", _reject_external)
    monkeypatch.setattr(subprocess, "Popen", _reject_external)
    monkeypatch.setattr(os, "system", _reject_external)
    monkeypatch.setattr(smtplib, "SMTP", _reject_external)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _reject_external)

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

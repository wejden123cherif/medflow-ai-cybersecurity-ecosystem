from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import requests

from graphs.nodes.collection import collection_node
from graphs.nodes.risk import risk_assessment_node
from graphs.nodes.response_planner import response_planner_node
from graphs.threat_intel_graph import initialize_incident_node
from models.incident import Incident


class MockGroqClient:
    """Mock Groq client that returns pre-configured response for Response Planner."""
    response_content: str = (
        "<proposals>\n"
        "[\n"
        "  {\n"
        "    \"action\": \"NOTIFY_SOC\",\n"
        "    \"target\": \"SOC Team\",\n"
        "    \"reason\": \"Notify SOC about potential ransomware precursor activity.\"\n"
        "  }\n"
        "]\n"
        "</proposals>"
    )

    def __init__(self, *args, **kwargs):
        pass

    @property
    def chat(self):
        return self

    @property
    def completions(self):
        return self

    def create(self, *args, **kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=MockGroqClient.response_content)
                )
            ]
        )


@pytest.fixture
def mock_groq(monkeypatch):
    """Fixture to mock Groq API settings and client module."""
    from config import Settings
    monkeypatch.setattr(
        "config.load_settings",
        lambda: Settings(
            groq_api_key="mock-key",
            main_model="mock-model",
            secondary_model="mock-model",
            embedding_model="mock-embedding"
        )
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "groq",
        SimpleNamespace(Groq=MockGroqClient),
    )
    yield MockGroqClient


def test_wazuh_unreachable_fallback(monkeypatch) -> None:
    """
    Simulates Wazuh being unreachable (raises connection failure),
    verifies that collection node falls back to the simulated file,
    sets source='simulated', and logs the fallback event to the audit_log.
    """
    # 1. Force connection failure for any requests calls
    def mock_post_fail(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Wazuh Manager refused connection")

    monkeypatch.setattr(requests, "post", mock_post_fail)
    monkeypatch.setattr(requests, "get", mock_post_fail)
    monkeypatch.setenv("WAZUH_URL", "https://wazuh-live.example.com:55000")

    # 2. Run collection node with live scenario and fallback file path
    scenario_file = Path(__file__).resolve().parents[1] / "data" / "simulated_alerts" / "ryuk_scenario.json"
    state = {
        "scenario": "live",
        "scenario_file": str(scenario_file),
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "errors": [],
        "audit_log": [],
    }

    result = collection_node(state)

    # 3. Assertions
    assert result["source"] == "simulated"
    assert len(result["raw_alerts"]) > 0
    assert any("FALLBACK" in err for err in result["errors"])
    
    # Verify fallback event is logged in state's audit_log
    audit_log = result["audit_log"]
    assert len(audit_log) > 0
    fallback_entry = next((e for e in audit_log if e["action"] == "wazuh_fallback"), None)
    assert fallback_entry is not None
    assert "FALLBACK" in fallback_entry["justification"]
    assert "unreachable" in fallback_entry["justification"].lower() or "connection" in fallback_entry["justification"].lower()


def test_wazuh_reachable_live(monkeypatch) -> None:
    """
    Simulates Wazuh being reachable, verifies that source='wazuh_live'
    is set correctly and no fallback event is logged.
    """
    # 1. Mock Wazuh success
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    def mock_post_success(*args, **kwargs):
        return MockResponse({"data": {"token": "fake-token"}}, 200)

    def mock_get_success(*args, **kwargs):
        # Return a list of raw Wazuh alerts that match the normalization requirements
        return MockResponse({
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2026-07-08T16:00:00Z",
                        "rule": {
                            "id": "5715",
                            "level": 12,
                            "description": "Successful SSH login",
                            "groups": ["sshd", "authentication"]
                        },
                        "agent": {
                            "id": "002",
                            "name": "ehr-server-01",
                            "ip": "10.20.30.11"
                        },
                        "data": {
                            "srcip": "10.200.5.50"
                        },
                        "full_log": "Successful root login from 10.200.5.50"
                    }
                ]
            }
        }, 200)

    monkeypatch.setattr(requests, "post", mock_post_success)
    monkeypatch.setattr(requests, "get", mock_get_success)
    monkeypatch.setenv("WAZUH_URL", "https://wazuh-live.example.com:55000")

    # 2. Run collection node
    state = {
        "scenario": "live",
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "errors": [],
        "audit_log": [],
    }

    result = collection_node(state)

    # 3. Assertions
    assert result["source"] == "wazuh_live"
    assert len(result["raw_alerts"]) > 0
    assert not any("FALLBACK" in err for err in result["errors"])
    
    # Verify no fallback event is logged in state's audit_log
    audit_log = result["audit_log"]
    fallback_entry = next((e for e in audit_log if e["action"] == "wazuh_fallback"), None)
    assert fallback_entry is None


def test_downstream_consistency(monkeypatch) -> None:
    """
    Verifies that regardless of whether data came from live Wazuh or fallback simulation,
    the downstream initialized incident state (e.g. asset_criticality overrides)
    and risk assessments are identical given the same input data.
    """
    scenario_file = Path(__file__).resolve().parents[1] / "data" / "simulated_alerts" / "ryuk_scenario.json"
    with open(scenario_file, "r", encoding="utf-8") as f:
        ryuk_data = json.load(f)

    # 1. Get fallback result
    def mock_post_fail(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Wazuh Manager refused connection")

    monkeypatch.setattr(requests, "post", mock_post_fail)
    monkeypatch.setattr(requests, "get", mock_post_fail)
    monkeypatch.setenv("WAZUH_URL", "https://wazuh-live.example.com:55000")

    state = {
        "scenario": "live",
        "scenario_file": str(scenario_file),
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "errors": [],
        "audit_log": [],
    }
    fallback_collection = collection_node(state)
    fallback_incident = initialize_incident_node(fallback_collection)
    fallback_incident["confidence_score"] = 0.85
    fallback_risk = risk_assessment_node(fallback_incident)

    # 2. Get live result with EXACT same mock data wrapped in wazuh api response
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data

    def mock_post_success(*args, **kwargs):
        return MockResponse({"data": {"token": "fake-token"}}, 200)

    def mock_get_success(*args, **kwargs):
        formatted_alerts = []
        for alert in ryuk_data:
            # We map destination to name since collection_node does agent.get('name') for destination
            formatted_alerts.append({
                "timestamp": alert.get("timestamp"),
                "rule": {
                    "id": alert.get("rule_id"),
                    "level": alert.get("rule_level"),
                    "description": alert.get("rule_description"),
                    "groups": alert.get("rule_groups")
                },
                "agent": {
                    "id": alert.get("agent_id"),
                    "name": alert.get("destination"),
                    "ip": alert.get("agent_ip")
                },
                "data": {
                    "srcip": alert.get("source_ip")
                },
                "full_log": alert.get("full_log"),
                "raw_log": alert.get("raw_log")
            })
        return MockResponse({"data": {"affected_items": formatted_alerts}}, 200)

    monkeypatch.setattr(requests, "post", mock_post_success)
    monkeypatch.setattr(requests, "get", mock_get_success)

    live_state = {
        "scenario": "live",
        "scenario_file": str(scenario_file),
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "errors": [],
        "audit_log": [],
    }
    live_collection = collection_node(live_state)
    live_incident = initialize_incident_node(live_collection)
    live_incident["confidence_score"] = 0.85
    live_risk = risk_assessment_node(live_incident)

    # 3. Assertions
    # Asset criticality should be High because of ehr/medical devices in the alerts
    assert fallback_incident["asset_criticality"] == "High"
    assert live_incident["asset_criticality"] == "High"

    # Both paths should compute identical risk scores and priorities
    assert fallback_risk["risk_score"] == live_risk["risk_score"]
    assert fallback_risk["priority"] == live_risk["priority"]

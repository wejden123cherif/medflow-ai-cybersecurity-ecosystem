from __future__ import annotations

import os
import json
import tempfile
import pytest
from pathlib import Path
from collectors.suricata import SuricataCollector
from collectors import BaseCollector
from graphs.nodes.collection import collection_node


@pytest.fixture
def temp_eve_file():
    with tempfile.NamedTemporaryFile(suffix="_eve.json", mode="w+", delete=False, encoding="utf-8") as tmp:
        temp_path = tmp.name
    yield temp_path
    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_suricata_collector_missing_file() -> None:
    collector = SuricataCollector()
    # Temporarily force non-existent path
    os.environ["SURICATA_EVE_PATH"] = "non_existent_file.json"
    alerts, metadata = collector.collect()
    assert alerts is None
    assert "failure_reason" in metadata
    assert "non_existent_file.json" in metadata["failure_reason"]


def test_suricata_collector_normalization(temp_eve_file) -> None:
    # Write some mock eve.json lines (alert, and non-alert event types)
    mock_events = [
        # Non-alert event (should be ignored)
        {
            "timestamp": "2026-07-17T18:00:00.123456+0200",
            "flow_id": 11111,
            "event_type": "flow",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "proto": "TCP"
        },
        # Alert event 1: severity 1 (critical) with MITRE ID in signature
        {
            "timestamp": "2026-07-17T18:01:00.123456+0200",
            "flow_id": 22222,
            "event_type": "alert",
            "src_ip": "185.220.101.45",
            "dest_ip": "10.20.14.23",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2012345,
                "rev": 1,
                "signature": "ET POLICY Brute Force attempt T1110 detected",
                "category": "Attempted User Privilege Gain",
                "severity": 1
            }
        },
        # Alert event 2: severity 2 (high)
        {
            "timestamp": "2026-07-17T18:02:00.123456+0200",
            "flow_id": 33333,
            "event_type": "alert",
            "src_ip": "10.20.14.23",
            "dest_ip": "10.20.14.2",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2012346,
                "rev": 1,
                "signature": "ET MALWARE Suspicious Activity",
                "category": "A Network Trojan was detected",
                "severity": 2
            }
        },
        # Alert event 3: severity 3 (medium)
        {
            "timestamp": "2026-07-17T18:03:00.123456+0200",
            "flow_id": 44444,
            "event_type": "alert",
            "src_ip": "10.20.14.23",
            "dest_ip": "10.20.14.2",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2012347,
                "rev": 1,
                "signature": "ET SCAN Portscan",
                "category": "Generic Protocol Command Decode",
                "severity": 3
            }
        }
    ]

    with open(temp_eve_file, "w", encoding="utf-8") as f:
        for event in mock_events:
            f.write(json.dumps(event) + "\n")

    os.environ["SURICATA_EVE_PATH"] = temp_eve_file
    collector = SuricataCollector()
    alerts, metadata = collector.collect()

    assert alerts is not None
    assert len(alerts) == 3
    assert metadata["data_source"] == "suricata_live"
    assert metadata["source_system"] == "suricata"

    # Alert 1 checks
    assert alerts[0]["source_system"] == "suricata"
    assert alerts[0]["source_ip"] == "185.220.101.45"
    assert alerts[0]["destination"] == "10.20.14.23"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["technique_hint"] == "T1110"
    assert "Brute Force" in alerts[0]["event_type"]

    # Alert 2 checks
    assert alerts[1]["severity"] == "high"
    assert alerts[1]["technique_hint"] == "unknown"

    # Alert 3 checks
    assert alerts[2]["severity"] == "medium"


def test_suricata_collector_registration() -> None:
    # Ensure SuricataCollector is registered in BaseCollector subclasses
    subclasses = BaseCollector.__subclasses__()
    assert SuricataCollector in subclasses


def test_collection_node_with_suricata_and_wazuh_unreachable(monkeypatch, temp_eve_file) -> None:
    # 1. Force Wazuh to fail
    monkeypatch.setenv("WAZUH_URL", "https://wazuh-live.example.com:55000")
    monkeypatch.setattr("collectors.wazuh.WazuhCollector._collect_from_wazuh", lambda *args, **kwargs: (None, "Wazuh unreachable"))
    monkeypatch.setattr("collectors.wazuh.WazuhCollector._collect_from_wazuh_indexer", lambda *args: (None, {"failure_reason": "Indexer unreachable"}))

    # 2. Configure mock Suricata alerts
    mock_suricata_alert = {
        "timestamp": "2026-07-17T18:01:00.123456+0200",
        "flow_id": 99999,
        "event_type": "alert",
        "src_ip": "10.20.14.23",
        "dest_ip": "10.20.14.2",
        "alert": {
            "signature": "ET POLICY Access Blocked",
            "severity": 1
        }
    }
    with open(temp_eve_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(mock_suricata_alert) + "\n")
    monkeypatch.setenv("SURICATA_EVE_PATH", temp_eve_file)

    state = {
        "scenario": "live",
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "errors": [],
        "audit_log": [],
    }

    # 3. Run collection_node
    # Since Suricata succeeded but Wazuh failed, collection_node should collect Suricata alerts
    # and NOT trigger a simulated fallback (because any_success is True and alerts were gathered!)
    result = collection_node(state)
    assert result["source"] == "wazuh_live"
    assert len(result["raw_alerts"]) == 1
    assert result["raw_alerts"][0]["source_system"] == "suricata"
    
    # Audit log should show no fallback (since we successfully collected from Suricata)
    assert not any(entry["action"] == "wazuh_fallback" for entry in result["audit_log"])

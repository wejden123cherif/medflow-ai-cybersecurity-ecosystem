import pytest
from datetime import datetime, timezone
from graphs.nodes.correlation import _select_campaign_scope, correlation_node


def test_correlation_time_window_constraint():
    # Feed Correlation two alerts with the same technique (T1110) but timestamps 100+ hours apart
    alert1 = {
        "id": "ALERT-001",
        "timestamp": "2026-07-01T10:00:00Z",
        "source_ip": "10.0.0.1",
        "destination": "server-01",
        "event_type": "ssh_brute_force",
        "severity": "high",
        "risk_score": 80,
    }
    alert2 = {
        "id": "ALERT-002",
        "timestamp": "2026-07-06T14:00:00Z",  # 124 hours later (> 72 hours window)
        "source_ip": "10.0.0.1",
        "destination": "server-01",
        "event_type": "ssh_brute_force",
        "severity": "high",
        "risk_score": 80,
    }

    ioc1 = {
        "alert_id": "ALERT-001",
        "source_ip": "10.0.0.1",
        "technique_confirmed": "T1110",
        "confidence": 1.0,
    }
    ioc2 = {
        "alert_id": "ALERT-002",
        "source_ip": "10.0.0.1",
        "technique_confirmed": "T1110",
        "confidence": 1.0,
    }

    raw_alerts = [alert1, alert2]
    enriched_iocs = [ioc1, ioc2]

    # Select scope with default 72h window
    selected_alerts, selected_iocs, metadata = _select_campaign_scope(
        raw_alerts, enriched_iocs, window_hours=72
    )

    # Confirm they do NOT get merged into one campaign (only 1 alert/IOC selected, 1 excluded)
    assert len(selected_iocs) == 1
    assert len(metadata["excluded_alerts"]) == 1
    assert metadata["excluded_alerts"][0]["reason"] == "outside_correlation_window_or_host_scope"

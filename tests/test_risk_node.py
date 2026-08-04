from __future__ import annotations

import pytest
from graphs.nodes.risk import risk_assessment_node
from graphs.nodes.collection import collection_node


def test_wazuh_live_risk_computation() -> None:
    """
    Tests that a wazuh_live-sourced incident calculates risk score and priority correctly.
    
    Inputs:
      - source: wazuh_live
      - severity: 12 (norm = 12/15 = 0.80)
      - asset_criticality: High (weight = 3, norm = 3/4 = 0.75)
      - confidence_score: 0.80
    
    Formula calculation:
      risk_score = (0.80 * 0.4 + 0.75 * 0.35 + 0.80 * 0.25) * 100
                 = (0.32 + 0.2625 + 0.20) * 100
                 = 0.7825 * 100 = 78.25%
      Rounded risk_score = 78 (High Priority)
    """
    state = {
        "incident_id": "INC-LIVE-001",
        "timestamp": "2026-07-08T16:00:00Z",
        "incident_title": "Live SSH Compromise",
        "incident_category": "compromised_compromise",
        "incident_status": "investigating",
        "schema_version": "1.0.0",
        "source": "wazuh_live",
        "raw_alerts": [
            {
                "id": "WZ-001",
                "timestamp": "2026-07-08T16:00:00Z",
                "source_ip": "10.200.5.50",
                "destination": "ehr_database_server",
                "event_type": "Successful login",
                "wazuh_rule_id": "5715",
                "wazuh_rule_level": 12,
            }
        ],
        "rule_id": "5715",
        "logs": ["SSH Successful Root Login"],
        "severity": 12,
        "confidence_score": 0.80,
        "asset_criticality": "High",
        "affected_assets": ["ehr_database_server"],
        "affected_asset_type": "ehr",
        "potential_patient_impact": "High clinical risk",
    }

    result = risk_assessment_node(state)

    assert result["risk_score"] == 78
    assert result["priority"] == "High"
    assert result["requires_human_review"] is False
    
    # Verify audit log entry
    audit_log = result["audit_log"]
    assert len(audit_log) == 1
    assert audit_log[0]["actor"] == "system:risk_assessment_node"
    assert "Computed risk_score=78" in audit_log[0]["justification"]
    assert "Confidence override triggered: False" in audit_log[0]["justification"]


def test_simulated_scenario_risk_computation() -> None:
    """
    Tests that a simulated-sourced incident (reusing collection_node alerts)
    produces identical formula behavior to the wazuh_live test for equivalent inputs.
    
    Inputs:
      - source: simulated (loaded via collection_node)
      - severity: 12
      - asset_criticality: High
      - confidence_score: 0.80
      
    Expected:
      risk_score = 78
      priority = High
    """
    # 1. Run simulated collection node to retrieve alerts
    initial_state = {
        "scenario": "ryuk",
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "errors": [],
        "loop_count": 0,
        "enriched_iocs": [],
        "confidence_score": 0.0,
        "mitre_context": {},
        "campaign": {},
        "prediction": {},
        "report": "",
    }
    
    collection_result = collection_node(initial_state)
    raw_alerts = collection_result["raw_alerts"]

    # 2. Build IncidentState representing the active simulated scenario
    state = {
        "incident_id": "INC-SIM-001",
        "timestamp": raw_alerts[0]["timestamp"],
        "incident_title": "Simulated Ryuk Campaign",
        "incident_category": "ransomware",
        "incident_status": "investigating",
        "schema_version": "1.0.0",
        "source": "simulated",
        "raw_alerts": raw_alerts,
        "rule_id": "5715",
        "logs": [alert.get("raw_log", "") for alert in raw_alerts],
        "severity": 12,
        "confidence_score": 0.80,
        "asset_criticality": "High",
        "affected_assets": ["host-01"],
        "affected_asset_type": "medical_device",
        "potential_patient_impact": "High clinical risk",
    }

    result = risk_assessment_node(state)

    # Assert identical formula output
    assert result["risk_score"] == 78
    assert result["priority"] == "High"
    assert result["requires_human_review"] is False
    assert result["audit_log"][0]["actor"] == "system:risk_assessment_node"


def test_confidence_override() -> None:
    """
    Tests the confidence override safety rules.
    If confidence_score < 0.5:
      - requires_human_review flag must be set to True
      - priority is deliberately NOT capped: masking a real Critical-severity
        incident as Medium would hide a live threat. The requires_human_review
        flag is the correct operator signal for low-confidence incidents.

    Inputs:
      - severity: 15 (norm = 1.0)
      - asset_criticality: Critical (norm = 1.0)
      - confidence_score: 0.40 (norm = 0.40)

    Formula:
      raw_risk_score = (1.0 * 0.4 + 1.0 * 0.35 + 0.40 * 0.25) * 100
                     = (0.40 + 0.35 + 0.10) * 100 = 85.0% (Critical)

    Override:
      confidence 0.4 < 0.5 -> requires_human_review = True
      (priority is NOT demoted; see risk.py design note)
    """
    state = {
        "incident_id": "INC-LOW-CONF-001",
        "timestamp": "2026-07-08T16:00:00Z",
        "incident_title": "Low Confidence Attack",
        "incident_category": "compromised_compromise",
        "incident_status": "investigating",
        "schema_version": "1.0.0",
        "source": "simulated",
        "raw_alerts": [
            {
                "id": "WZ-002",
                "timestamp": "2026-07-08T16:00:00Z",
                "source_ip": "10.200.5.50",
                "destination": "ehr_database_server",
                "event_type": "Successful login",
                "wazuh_rule_id": "5715",
                "wazuh_rule_level": 15,
            }
        ],
        "rule_id": "5715",
        "logs": ["SSH login logs"],
        "severity": 15,
        "confidence_score": 0.40,
        "asset_criticality": "Critical",
        "affected_assets": ["ehr_database_server"],
        "affected_asset_type": "ehr",
        "potential_patient_impact": "High clinical risk",
    }

    result = risk_assessment_node(state)

    assert result["risk_score"] == 85
    # Priority is NOT capped: risk.py deliberately preserves the computed severity
    # so operators see the real threat level; requires_human_review is the gating signal.
    assert result["priority"] == "Critical"
    assert result["requires_human_review"] is True

    # Confirm log shows override active
    audit_log = result["audit_log"]
    assert "Confidence override triggered: True" in audit_log[0]["justification"]

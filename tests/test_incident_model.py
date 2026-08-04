from __future__ import annotations

from datetime import datetime
import pytest

from models.incident import AuditLogEntry, Incident, ResponseAction


def test_valid_incident_instantiation() -> None:
    """Tests that a realistic healthcare incident scenario compiles and validates correctly."""
    # Compromised infusion pump gateway scenario
    wazuh_alerts = [
        {
            "id": "WZ-001",
            "timestamp": "2026-07-08T16:00:00Z",
            "source_ip": "10.200.5.40",
            "destination": "infusion_pump_gateway_01",
            "event_type": "Multiple failed SSH login attempts",
            "wazuh_rule_id": "5712",
            "wazuh_rule_level": 10,
        },
        {
            "id": "WZ-002",
            "timestamp": "2026-07-08T16:05:00Z",
            "source_ip": "10.200.5.40",
            "destination": "infusion_pump_gateway_01",
            "event_type": "Successful SSH login after brute force",
            "wazuh_rule_id": "5715",
            "wazuh_rule_level": 14,
        }
    ]

    proposed_actions = [
        ResponseAction(
            action_id="ACT-001",
            action_type="network_isolation",
            target="10.200.5.40",
            status="proposed",
            justification="Isolate compromising IP to prevent further lateral movement",
            requested_by="detection_agent",
        )
    ]

    audit_trail = [
        AuditLogEntry(
            actor="system",
            timestamp="2026-07-08T16:05:05Z",
            action="incident_created",
            justification="Automatic creation from correlated Wazuh alerts",
        )
    ]

    incident = Incident(
        incident_id="INC-20260708-0001",
        timestamp="2026-07-08T16:05:05Z",
        title="Unauthorized Remote Access to Infusion Pump Gateway",
        category="compromised_compromise",
        status="investigating",
        schema_version="1.0.0",
        wazuh_alerts=wazuh_alerts,
        rule_id="5715",
        logs=["Syslog: Successful password login for root from 10.200.5.40"],
        severity=14,  # Critical
        confidence_score=0.92,
        asset_criticality="Critical",
        affected_assets=["infusion_pump_gateway_01"],
        proposed_actions=proposed_actions,
        affected_asset_type="medical_device",
        potential_patient_impact="High risk of direct clinical impact or medication dosage manipulation",
        audit_log=audit_trail,
    )

    # Validate that it passes validation on instantiation
    incident.validate()

    assert incident.severity_tier == "Critical"
    assert incident.asset_criticality == "Critical"
    assert len(incident.audit_log) == 1
    assert incident.audit_log[0].actor == "system"


def test_healthcare_criticality_override() -> None:
    """Tests that any direct patient-care system automatically overrides Low/Medium criticality to High."""
    wazuh_alerts = [
        {
            "id": "WZ-003",
            "timestamp": "2026-07-08T16:10:00Z",
            "source_ip": "10.200.5.41",
            "destination": "ehr_database_server",
            "event_type": "Unauthorized database connection",
            "wazuh_rule_id": "100200",
            "wazuh_rule_level": 5,
        }
    ]

    # Explicitly trying to map EHR system as Low criticality
    incident = Incident(
        incident_id="INC-20260708-0002",
        timestamp="2026-07-08T16:10:00Z",
        title="Database Access anomaly on EHR Server",
        category="intrusion",
        status="identified",
        schema_version="1.0.0",
        wazuh_alerts=wazuh_alerts,
        rule_id="100200",
        logs=["Audit log: root login from external subnet"],
        severity=5,
        confidence_score=0.75,
        asset_criticality="Low",  # Should be overridden to High due to EHR
        affected_assets=["ehr_database_server"],
        affected_asset_type="ehr",
        potential_patient_impact="Confidentiality breach of patient records",
    )

    # Check that it got automatically upgraded to High
    assert incident.asset_criticality == "High"

    # If we try to manually change it back to Medium, validate() must raise a ValueError
    incident.asset_criticality = "Medium"
    with pytest.raises(ValueError, match="Healthcare Safety Violation"):
        incident.validate()


def test_severity_out_of_bounds() -> None:
    """Tests that out of bounds severity levels raise value errors."""
    with pytest.raises(ValueError, match="is out of bounds"):
        Incident(
            incident_id="INC-0001",
            timestamp="2026-07-08T16:00:00Z",
            title="Invalid Severity",
            category="intrusion",
            status="identified",
            schema_version="1.0.0",
            wazuh_alerts=[],
            rule_id="1",
            logs=[],
            severity=16,  # Valid range is 0-15
        )


def test_confidence_score_out_of_bounds() -> None:
    """Tests that out of bounds confidence scores raise value errors."""
    with pytest.raises(ValueError, match="confidence_score must be between 0.0 and 1.0"):
        Incident(
            incident_id="INC-0001",
            timestamp="2026-07-08T16:00:00Z",
            title="Invalid Confidence",
            category="intrusion",
            status="identified",
            schema_version="1.0.0",
            wazuh_alerts=[],
            rule_id="1",
            logs=[],
            confidence_score=1.5,
        )


def test_audit_log_append_only() -> None:
    """Tests that the audit log enforces append-only semantics and blocks direct mutation/deletion."""
    incident = Incident(
        incident_id="INC-0001",
        timestamp="2026-07-08T16:00:00Z",
        title="Audit Log Test",
        category="intrusion",
        status="identified",
        schema_version="1.0.0",
        wazuh_alerts=[],
        rule_id="1",
        logs=[],
    )

    assert len(incident.audit_log) == 0

    # Add audit log entries via public api
    incident.add_audit_entry(
        actor="red_team_agent",
        action="simulation_started",
        justification="Verify boundary controls on target asset",
    )
    assert len(incident.audit_log) == 1
    assert incident.audit_log[0].actor == "red_team_agent"

    # Attemping to modify the exposed list in-place should have no effect on the object's internal list
    exposed_log = incident.audit_log
    exposed_log.clear()
    assert len(incident.audit_log) == 1

    # Attempting to assign directly to audit_log attribute should raise AttributeError
    with pytest.raises(AttributeError):
        incident.audit_log = []  # type: ignore

    # Attempting to modify frozen AuditLogEntry attributes should raise dataclass exceptions
    with pytest.raises(Exception):
        incident.audit_log[0].actor = "malicious_actor"  # type: ignore


def test_serialization() -> None:
    """Tests serialization and deserialization via to_dict and from_dict."""
    incident_dict = {
        "incident_id": "INC-0003",
        "timestamp": "2026-07-08T16:00:00Z",
        "title": "Serialization test",
        "category": "intrusion",
        "status": "closed",
        "schema_version": "1.0.0",
        "wazuh_alerts": [],
        "rule_id": "99",
        "logs": [],
        "evidence": [],
        "iocs": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "threat_actor": "Unattributed",
        "severity": 3,
        "severity_tier": "Low",
        "confidence_score": 0.4,
        "asset_criticality": "Low",
        "affected_assets": [],
        "proposed_actions": [],
        "approved_actions": [],
        "execution_results": [],
        "detection_time": "2026-07-08T16:00:00Z",
        "investigation_time": None,
        "response_time": None,
        "closure_time": "2026-07-08T16:30:00Z",
        "affected_asset_type": "workstation",
        "potential_patient_impact": "None",
        "audit_log": [
            {
                "actor": "admin",
                "timestamp": "2026-07-08T16:01:00Z",
                "action": "closed_incident",
                "justification": "False positive validation",
            }
        ]
    }

    # Reconstruct from dict
    incident = Incident.from_dict(incident_dict)
    incident.validate()

    assert incident.incident_id == "INC-0003"
    assert incident.status == "closed"
    assert len(incident.audit_log) == 1
    assert incident.audit_log[0].actor == "admin"

    # Serialize back and compare
    serialized = incident.to_dict()
    assert serialized["incident_id"] == "INC-0003"
    assert serialized["audit_log"][0]["actor"] == "admin"


def test_simulated_scenario_validation() -> None:
    """Loads a simulated attack JSON scenario from collection_node and validates Incident."""
    from graphs.nodes.collection import collection_node
    
    # Run simulated collection
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
    
    result = collection_node(initial_state)
    raw_alerts = result["raw_alerts"]
    assert len(raw_alerts) > 0
    
    # Verify they are simulated alerts
    assert all(alert.get("data_source") == "simulated" for alert in raw_alerts)
    
    # Process details for Incident
    logs = [alert.get("raw_log", "") for alert in raw_alerts]
    rule_ids = {str(alert.get("wazuh_rule_id", "")) for alert in raw_alerts if alert.get("wazuh_rule_id")}
    primary_rule_id = sorted(rule_ids)[0] if rule_ids else "unknown"
    
    mitre_techniques = sorted({alert.get("technique_hint") for alert in raw_alerts if alert.get("technique_hint") and alert.get("technique_hint") != "unknown"})

    # Check first alert's timestamp as incident timestamp
    incident_timestamp = raw_alerts[0].get("timestamp") or "2026-07-08T16:00:00Z"
    
    incident = Incident(
        incident_id="INC-RYUK-SIM-001",
        timestamp=incident_timestamp,
        title="Simulated Ryuk Ransomware Attack Campaign",
        category="ransomware",
        status="identified",
        schema_version="1.0.0",
        source="simulated",
        wazuh_alerts=raw_alerts,
        rule_id=primary_rule_id,
        logs=logs,
        mitre_techniques=mitre_techniques,
        severity=14,
        confidence_score=0.85,
        asset_criticality="High",
        affected_assets=["host-01"],
        affected_asset_type="medical_device",
        potential_patient_impact="High risk of disruption to clinical functions",
    )
    
    incident.validate()
    
    assert incident.source == "simulated"
    assert len(incident.wazuh_alerts) == len(raw_alerts)
    assert incident.schema_version == "1.0.0"


def test_incident_from_state_healthcare_override() -> None:
    """Verifies that Incident.from_state() correctly enforces and upgrades healthcare asset criticality."""
    # Build an IncidentState dict
    state = {
        "incident_id": "INC-STATE-OVERRIDE",
        "timestamp": "2026-07-08T16:00:00Z",
        "incident_title": "State Override Test",
        "incident_category": "compromised_compromise",
        "incident_status": "investigating",
        "schema_version": "1.0.0",
        "source": "simulated",
        "raw_alerts": [
            {
                "id": "WZ-999",
                "timestamp": "2026-07-08T16:00:00Z",
                "source_ip": "10.200.5.42",
                "destination": "infusion_pump_02",
                "event_type": "Malicious script executed",
                "wazuh_rule_id": "100300",
                "wazuh_rule_level": 11,
            }
        ],
        "rule_id": "100300",
        "logs": ["Malicious command on infusion_pump_02"],
        "severity": 11,
        "asset_criticality": "Low",  # Manually set to LOW
        "affected_assets": ["infusion_pump_02"],
        "affected_asset_type": "medical_device",
        "potential_patient_impact": "Disruption to infusion delivery",
    }
    
    # Call from_state
    incident = Incident.from_state(state)
    
    # Validate the resulting incident
    incident.validate()
    
    # Confirm healthcare override forced the criticality to High
    assert incident.asset_criticality == "High"
    assert incident.severity_tier == "High"



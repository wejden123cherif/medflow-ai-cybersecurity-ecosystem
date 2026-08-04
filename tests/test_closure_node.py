"""
tests/test_closure_node.py
--------------------------
Unit tests for graphs/nodes/closure.py (Incident Closure Node).
"""

from __future__ import annotations

import pytest
from graphs.nodes.closure import closure_node
from graphs.state import IncidentState


def _mock_state(**overrides) -> IncidentState:
    state: IncidentState = {
        "scenario": "brute_force",
        "raw_alerts": [
            {
                "id": "ALERT-001",
                "timestamp": "2026-07-28T10:00:00Z",
                "source_ip": "192.168.1.100",
                "event_type": "ssh_brute_force",
            }
        ],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "enriched_iocs": [],
        "confidence_score": 0.95,
        "mitre_context": {},
        "campaign": {},
        "prediction": {},
        "report": "Incident report body",
        "loop_count": 0,
        "errors": [],
        "incident_id": "INC-TEST-999",
        "incident_title": "SSH Brute Force",
        "incident_category": "Credential Access",
        "incident_status": "in_progress",
        "timestamp": "2026-07-28T10:00:00Z",
        "schema_version": "1.0",
        "source": "simulated",
        "severity": 10,
        "severity_tier": "High",
        "asset_criticality": "Medium",
        "affected_assets": ["ssh-gateway-01"],
        "risk_score": 75,
        "priority": "High",
        "requires_human_review": False,
        "matched_playbook": "credential_access",
        "matched_playbook_technique_id": "CREDENTIAL_ACCESS",
        "matched_playbook_technique_name": "Credential Access",
        "playbook_version": "1.0",
        "playbook_source": "yaml",
        "playbook_selected_by_technique": "T1110",
        "allowed_actions": [],
        "proposed_actions": [],
        "approved_actions": [],
        "acknowledged_actions": [],
        "rejected_actions": [],
        "executed_actions": [
            {"action_name": "DROP_CONNECTION", "status": "success", "details": "Rule added"}
        ],
        "failed_actions": [],
        "execution_summary": {"total_actions": 1, "successful": 1, "failed": 0},
        "approval_decisions": {},
        "approval_approver": "system",
        "execution_results": [],
        "planner_divergence_flag": False,
        "detection_time": "2026-07-28T10:00:00Z",
        "investigation_time": "2026-07-28T10:01:00Z",
        "response_time": None,
        "closure_time": None,
        "affected_asset_type": "gateway",
        "potential_patient_impact": "low",
        "audit_log": [],
    }
    state.update(overrides)
    return state


def test_closure_node_contained_status() -> None:
    state = _mock_state()
    res = closure_node(state)

    assert res["incident_status"] == "contained"
    assert res["closure_time"] is not None
    assert res["detection_time"] == "2026-07-28T10:00:00Z"
    assert res["response_time"] is not None
    assert any(entry["action"] == "INCIDENT_CLOSED" for entry in res["audit_log"])


def test_closure_node_partially_contained_status() -> None:
    state = _mock_state(
        executed_actions=[{"action_name": "DROP_CONNECTION", "status": "success"}],
        failed_actions=[{"action_name": "ISOLATE_ENDPOINT", "status": "failed"}],
    )
    res = closure_node(state)

    assert res["incident_status"] == "partially_contained"


def test_closure_node_remediation_failed_status() -> None:
    state = _mock_state(
        executed_actions=[],
        failed_actions=[{"action_name": "DROP_CONNECTION", "status": "failed"}],
    )
    res = closure_node(state)

    assert res["incident_status"] == "remediation_failed"


def test_closure_node_no_action_required() -> None:
    state = _mock_state(
        executed_actions=[],
        failed_actions=[],
    )
    res = closure_node(state)

    assert res["incident_status"] == "closed_no_remediation_required"

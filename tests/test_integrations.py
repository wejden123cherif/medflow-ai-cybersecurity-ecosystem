from __future__ import annotations

import json
import pytest
from integrations import FirewallConnector, EDRConnector
from graphs.nodes.response_executor import response_executor_node


def _action(
    action_id: str,
    action_type: str,
    *,
    target: str = "10.20.30.40",
    requires_approval: bool = False,
    decision: str = "approved",
) -> dict:
    return {
        "action_id": action_id,
        "action_type": action_type,
        "target": target,
        "status": decision,
        "justification": f"{action_type} proposed by planner.",
        "requested_by": "system:response_planner_node",
        "approved_by": "analyst-7" if decision == "approved" else "system:approval_node",
        "decision": decision,
        "decision_timestamp": "2026-07-17T10:05:00Z",
        "approval_justification": f"{action_type} decision justification.",
        "execution_result": None,
        "requires_approval": requires_approval,
        "reversible": True,
        "timestamp": "2026-07-17T10:00:00Z",
    }


def _base_state(**overrides) -> dict:
    state = {
        "incident_id": "INC-INT-001",
        "timestamp": "2026-07-17T10:00:00Z",
        "incident_title": "Integration Test",
        "incident_category": "ransomware",
        "incident_status": "investigating",
        "schema_version": "1.0.0",
        "source": "simulated",
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-17T09:58:00Z",
                "source_ip": "10.20.30.40",
                "destination": "ehr-fileserver-02",
                "event_type": "mass_file_modification",
            }
        ],
        "rule_id": "61809",
        "logs": ["mass file modification"],
        "severity": 15,
        "confidence_score": 0.9,
        "asset_criticality": "High",
        "affected_assets": ["ehr-fileserver-02"],
        "affected_asset_type": "ehr",
        "mitre_techniques": ["T1486"],
        "matched_playbook": "ransomware_impact",
        "playbook_version": "v1",
        "allowed_actions": [
            {"name": "BLOCK_IP", "risk_tier": 2, "requires_approval": False},
            {"name": "ISOLATE_ENDPOINT", "risk_tier": 3, "requires_approval": True},
            {"name": "KILL_PROCESS", "risk_tier": 3, "requires_approval": True},
            {"name": "REVOKE_SESSION", "risk_tier": 2, "requires_approval": False},
        ],
        "proposed_actions": [],
        "approved_actions": [],
        "acknowledged_actions": [],
        "rejected_actions": [],
        "executed_actions": [],
        "failed_actions": [],
        "execution_summary": {},
        "execution_results": [],
        "audit_log": [],
        "errors": [],
        "response_dry_run": False,
    }
    state.update(overrides)
    return state


def test_firewall_connector_direct() -> None:
    connector = FirewallConnector(host="fw-test.local")
    
    # Check health
    assert connector.check_health() is True
    
    # Success action
    action = {"action_type": "BLOCK_IP", "target": "192.168.1.100"}
    res = connector.execute_action(action)
    assert res["status"] == "success"
    assert "fw-test.local" in res["details"]
    assert "192.168.1.100" in res["details"]
    
    # Missing target
    action_no_target = {"action_type": "BLOCK_IP", "target": ""}
    res = connector.execute_action(action_no_target)
    assert res["status"] == "failed"
    assert res["error"] == "missing_target"
    
    # Unsupported action
    action_unsupported = {"action_type": "ISOLATE_ENDPOINT", "target": "10.0.0.1"}
    res = connector.execute_action(action_unsupported)
    assert res["status"] == "failed"
    assert res["error"] == "unsupported_action"

    # Health check disabled
    connector.enabled = False
    res = connector.execute_action(action)
    assert res["status"] == "failed"
    assert res["error"] == "service_unavailable"


def test_edr_connector_direct() -> None:
    connector = EDRConnector(host="edr-test.local")
    assert connector.check_health() is True

    # Isolate endpoint
    res = connector.execute_action({"action_type": "ISOLATE_ENDPOINT", "target": "ehr-host-01"})
    assert res["status"] == "success"
    assert "isolate" in res["details"].lower()
    
    # Kill process
    res = connector.execute_action({"action_type": "KILL_PROCESS", "target": "malware.exe"})
    assert res["status"] == "success"
    assert "terminated" in res["details"].lower()
    
    # Revoke session
    res = connector.execute_action({"action_type": "REVOKE_SESSION", "target": "session-xyz"})
    assert res["status"] == "success"
    assert "revoked" in res["details"].lower()

    # Unsupported action
    res = connector.execute_action({"action_type": "BLOCK_IP", "target": "10.0.0.1"})
    assert res["status"] == "failed"
    assert res["error"] == "unsupported_action"


def test_response_executor_routes_to_firewall_and_edr(monkeypatch) -> None:
    # 1. Test successful BLOCK_IP
    approved = [_action("ACT-FW", "BLOCK_IP", target="185.220.101.45")]
    state = _base_state(approved_actions=approved, proposed_actions=approved)
    result = response_executor_node(state)
    
    assert result["execution_summary"] == {"total_actions": 1, "successful": 1, "failed": 0, "skipped": 0}
    assert result["executed_actions"][0]["action_name"] == "BLOCK_IP"
    assert "blocked IP address" in result["executed_actions"][0]["details"]
    
    # 2. Test successful ISOLATE_ENDPOINT
    approved_edr = [_action("ACT-EDR", "ISOLATE_ENDPOINT", target="ehr-host-01")]
    state_edr = _base_state(approved_actions=approved_edr, proposed_actions=approved_edr)
    result_edr = response_executor_node(state_edr)
    
    assert result_edr["execution_summary"] == {"total_actions": 1, "successful": 1, "failed": 0, "skipped": 0}
    assert result_edr["executed_actions"][0]["action_name"] == "ISOLATE_ENDPOINT"
    assert "isolated endpoint" in result_edr["executed_actions"][0]["details"].lower()


def test_response_executor_handles_connector_unavailability(monkeypatch) -> None:
    # Force Firewall health check to fail
    monkeypatch.setattr(FirewallConnector, "check_health", lambda self: False)
    
    approved = [_action("ACT-FW-FAIL", "BLOCK_IP", target="185.220.101.45")]
    state = _base_state(approved_actions=approved, proposed_actions=approved)
    result = response_executor_node(state)
    
    assert result["execution_summary"] == {"total_actions": 1, "successful": 0, "failed": 1, "skipped": 0}
    assert result["failed_actions"][0]["action_name"] == "BLOCK_IP"
    assert result["failed_actions"][0]["error"] == "connector_unavailable"
    
    # Check that audit log recorded the failure
    audit = result["audit_log"]
    fail_entry = next((e for e in audit if e["action"] == "ACTION_EXECUTION_FAILED"), None)
    assert fail_entry is not None
    justification_data = json.loads(fail_entry["justification"])
    assert justification_data["error"] == "connector_unavailable"

from __future__ import annotations

from graphs.nodes.response_executor import response_executor_node


def _action(
    action_id: str,
    action_type: str,
    *,
    target: str = "system",
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
        "incident_id": "INC-EXEC-001",
        "timestamp": "2026-07-17T10:00:00Z",
        "incident_title": "Execution Test",
        "incident_category": "ransomware",
        "incident_status": "investigating",
        "schema_version": "1.0.0",
        "source": "simulated",
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-17T09:58:00Z",
                "source_ip": "185.220.101.45",
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
            {"name": "NOTIFY_SOC", "risk_tier": 1, "requires_approval": False},
            {"name": "BLOCK_IP", "risk_tier": 2, "requires_approval": False},
            {"name": "ISOLATE_ENDPOINT", "risk_tier": 3, "requires_approval": True},
            {"name": "UNSUPPORTED_TEST_ACTION", "risk_tier": 2, "requires_approval": False},
        ],
        "proposed_actions": [],
        "approved_actions": [],
        "acknowledged_actions": [],
        "rejected_actions": [],
        "executed_actions": [],
        "failed_actions": [],
        "execution_summary": {},
        "execution_results": [],
        "audit_log": [
            {
                "actor": "system:approval_node",
                "timestamp": "2026-07-17T10:06:00Z",
                "action": "approval_gate_completed",
                "justification": "Existing approval audit entry.",
            }
        ],
        "errors": [],
    }
    state.update(overrides)
    return state


def test_approved_tier1_action_executes_successfully() -> None:
    approved = [_action("ACT-1", "NOTIFY_SOC", target="SOC team", requires_approval=False)]
    result = response_executor_node(_base_state(approved_actions=approved, proposed_actions=approved))

    assert result["execution_summary"] == {"total_actions": 1, "successful": 1, "failed": 0, "skipped": 0}
    assert result["executed_actions"][0]["action_name"] == "NOTIFY_SOC"
    assert result["executed_actions"][0]["execution_status"] == "success"
    assert "ACTION_EXECUTED" in [entry["action"] for entry in result["audit_log"]]


def test_rejected_action_is_skipped() -> None:
    rejected = [_action("ACT-1", "ISOLATE_ENDPOINT", target="ehr-fileserver-02", requires_approval=True, decision="rejected")]
    result = response_executor_node(_base_state(rejected_actions=rejected, proposed_actions=rejected))

    assert result["execution_summary"] == {"total_actions": 1, "successful": 0, "failed": 0, "skipped": 1}
    assert result["execution_results"][0]["execution_status"] == "skipped"
    assert "rejected by the human approval gate" in result["execution_results"][0]["details"]


def test_action_requiring_approval_but_not_approved_is_blocked() -> None:
    pending = [_action("ACT-1", "ISOLATE_ENDPOINT", target="ehr-fileserver-02", requires_approval=True, decision="proposed")]
    result = response_executor_node(_base_state(proposed_actions=pending))

    assert result["execution_summary"]["skipped"] == 1
    assert result["execution_results"][0]["execution_status"] == "skipped"
    assert "not approved or acknowledged" in result["execution_results"][0]["details"]


def test_failed_execution_creates_audit_entry() -> None:
    approved = [_action("ACT-1", "UNSUPPORTED_TEST_ACTION", requires_approval=False)]
    result = response_executor_node(_base_state(approved_actions=approved, proposed_actions=approved))

    assert result["execution_summary"] == {"total_actions": 1, "successful": 0, "failed": 1, "skipped": 0}
    assert result["failed_actions"][0]["error"] == "unsupported_action"
    assert "ACTION_EXECUTION_FAILED" in [entry["action"] for entry in result["audit_log"]]


def test_execution_summary_counts_success_failed_and_skipped() -> None:
    approved = [
        _action("ACT-1", "NOTIFY_SOC", target="SOC team", requires_approval=False),
        _action("ACT-2", "UNSUPPORTED_TEST_ACTION", requires_approval=False),
    ]
    rejected = [_action("ACT-3", "ISOLATE_ENDPOINT", target="ehr-fileserver-02", requires_approval=True, decision="rejected")]
    result = response_executor_node(
        _base_state(
            approved_actions=approved,
            rejected_actions=rejected,
            proposed_actions=[*approved, *rejected],
        )
    )

    assert result["execution_summary"] == {"total_actions": 3, "successful": 1, "failed": 1, "skipped": 1}
    assert len(result["executed_actions"]) == 1
    assert len(result["failed_actions"]) == 1

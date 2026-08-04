from __future__ import annotations

import pytest

from graphs.nodes.approval import approval_node


def _action(
    action_id: str,
    action_type: str,
    *,
    requires_approval: bool,
    target: str = "system",
) -> dict:
    return {
        "action_id": action_id,
        "action_type": action_type,
        "target": target,
        "status": "proposed",
        "justification": f"Planner proposed {action_type}.",
        "requested_by": "system:response_planner_node",
        "approved_by": None,
        "execution_result": None,
        "requires_approval": requires_approval,
        "reversible": True,
        "timestamp": "2026-07-17T10:00:00Z",
    }


def _base_state(proposed_actions: list[dict], decisions: dict | None = None) -> dict:
    return {
        "incident_id": "INC-APPROVAL-001",
        "timestamp": "2026-07-17T10:00:00Z",
        "incident_title": "Approval Gate Test",
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
            {"name": "KILL_PROCESS", "risk_tier": 4, "requires_approval": True},
        ],
        "proposed_actions": proposed_actions,
        "approved_actions": [],
        "acknowledged_actions": [],
        "rejected_actions": [],
        "approval_decisions": decisions or {},
        "approval_approver": "analyst-7",
        "execution_results": [],
        "audit_log": [
            {
                "actor": "system:risk_assessment_node",
                "timestamp": "2026-07-17T10:01:00Z",
                "action": "risk_score_computed",
                "justification": "Existing risk audit entry.",
            },
            {
                "actor": "system:response_planner_node",
                "timestamp": "2026-07-17T10:02:00Z",
                "action": "response_planning_completed",
                "justification": "Existing planner audit entry.",
            },
        ],
        "errors": [],
    }


def test_full_approval_all_required_actions_approved() -> None:
    actions = [
        _action("ACT-1", "ISOLATE_ENDPOINT", target="ehr-fileserver-02", requires_approval=True),
        _action("ACT-2", "KILL_PROCESS", target="ehr-fileserver-02", requires_approval=True),
    ]
    state = _base_state(
        actions,
        {
            "ACT-1": {"decision": "approved", "justification": "Confirmed active encryption.", "approver": "analyst-7"},
            "ACT-2": {"decision": "approved", "justification": "Process hash confirmed malicious.", "approver": "analyst-7"},
        },
    )

    result = approval_node(state)

    assert result["proposed_actions"] == actions
    assert len(result["approved_actions"]) == 2
    assert result["acknowledged_actions"] == []
    assert result["rejected_actions"] == []
    assert all(action["approved_by"] == "analyst-7" for action in result["approved_actions"])
    assert all(action["decision"] == "approved" for action in result["approved_actions"])
    assert all(action["decision_timestamp"] for action in result["approved_actions"])


def test_partial_approval_and_rejection_requires_justification() -> None:
    actions = [
        _action("ACT-1", "ISOLATE_ENDPOINT", target="ehr-fileserver-02", requires_approval=True),
        _action("ACT-2", "KILL_PROCESS", target="ehr-fileserver-02", requires_approval=True),
    ]
    state = _base_state(
        actions,
        {
            "ACT-1": {"decision": "approved", "justification": "Containment approved.", "approver": "analyst-7"},
            "ACT-2": {"decision": "rejected", "justification": "Too risky for active EHR writes.", "approver": "analyst-7"},
        },
    )

    result = approval_node(state)

    assert [action["action_type"] for action in result["approved_actions"]] == ["ISOLATE_ENDPOINT"]
    assert [action["action_type"] for action in result["rejected_actions"]] == ["KILL_PROCESS"]
    assert result["rejected_actions"][0]["approval_justification"] == "Too risky for active EHR writes."

    bad_state = _base_state(
        actions,
        {
            "ACT-1": {"decision": "approved", "justification": "Containment approved.", "approver": "analyst-7"},
            "ACT-2": {"decision": "rejected", "justification": "", "approver": "analyst-7"},
        },
    )
    with pytest.raises(ValueError, match="requires a justification"):
        approval_node(bad_state)


def test_tier1_actions_never_block_on_interactive_input() -> None:
    actions = [_action("ACT-1", "NOTIFY_SOC", target="SOC team", requires_approval=False)]
    state = _base_state(actions)

    def fail_if_called(prompt: str) -> str:
        raise AssertionError(f"approval_node unexpectedly prompted: {prompt}")

    result = approval_node(state, input_func=fail_if_called)

    assert result["approved_actions"] == []
    assert len(result["acknowledged_actions"]) == 1
    assert result["acknowledged_actions"][0]["decision"] == "acknowledged"
    assert result["acknowledged_actions"][0]["approved_by"] == "system:approval_node"
    assert result["rejected_actions"] == []


def test_audit_log_accumulates_without_overwriting_existing_entries() -> None:
    actions = [
        _action("ACT-1", "NOTIFY_SOC", target="SOC team", requires_approval=False),
        _action("ACT-2", "ISOLATE_ENDPOINT", target="ehr-fileserver-02", requires_approval=True),
    ]
    state = _base_state(
        actions,
        {"ACT-2": {"decision": "rejected", "justification": "Clinical owner requested delay.", "approver": "charge-nurse"}},
    )

    result = approval_node(state)

    audit_actions = [entry["action"] for entry in result["audit_log"]]
    assert audit_actions[:2] == ["risk_score_computed", "response_planning_completed"]
    assert "response_action_acknowledged" in audit_actions
    assert "response_action_rejected" in audit_actions
    assert audit_actions[-1] == "approval_gate_completed"
    assert len(result["audit_log"]) == len(state["audit_log"]) + 3

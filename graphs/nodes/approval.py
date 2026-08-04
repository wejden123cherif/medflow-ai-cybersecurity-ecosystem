from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from graphs.state import IncidentState
from models.incident import Incident, ResponseAction


DecisionInput = Callable[[str], str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _action_label(action: dict[str, Any]) -> str:
    return f"{action.get('action_type', 'UNKNOWN')} on {action.get('target', 'unknown')}"


def _normalize_decision(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"y", "yes", "approve", "approved"}:
        return "approved"
    if normalized in {"n", "no", "reject", "rejected"}:
        return "rejected"
    raise ValueError("Decision must be approved/rejected or y/n.")


def _decision_from_map(action: dict[str, Any], decisions: dict[str, Any]) -> dict[str, str] | None:
    keys = [
        str(action.get("action_id", "")),
        str(action.get("action_type", "")),
        _action_label(action),
    ]
    for key in keys:
        if key in decisions:
            value = decisions[key]
            if isinstance(value, dict):
                return {
                    "decision": _normalize_decision(str(value.get("decision", ""))),
                    "justification": str(value.get("justification", "") or "").strip(),
                    "approver": str(value.get("approver", "") or "").strip(),
                }
            return {
                "decision": _normalize_decision(str(value)),
                "justification": "",
                "approver": "",
            }
    return None


def _with_decision_metadata(
    action: dict[str, Any],
    *,
    approver: str,
    decision: str,
    justification: str,
    timestamp: str,
) -> dict[str, Any]:
    if decision == "rejected" and not justification.strip():
        raise ValueError(f"Rejection for {_action_label(action)} requires a justification.")
    if decision in {"approved", "acknowledged"} and not justification.strip():
        justification = (
            "Approval acknowledged by playbook policy; no interactive approval required."
            if decision == "acknowledged"
            else "Approved by human approver."
        )

    result = dict(action)
    result["status"] = decision
    result["approved_by"] = approver
    result["decision"] = decision
    result["decision_timestamp"] = timestamp
    result["approval_justification"] = justification
    return result


def _prompt_for_decision(action: dict[str, Any], input_func: DecisionInput = input) -> dict[str, str]:
    label = _action_label(action)
    import sys
    # Non-interactive fallback: if running in background/CI/non-TTY without pre-seeded decisions, auto-reject for safety
    if input_func is input and (not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty()):
        return {
            "decision": "rejected",
            "justification": "Auto-rejected by Approval Gate: non-interactive environment detected without pre-seeded decision.",
            "approver": "system:auto_reject",
        }

    try:
        raw_decision = input_func(f"Approve {label}? [y/n]: ")
        decision = _normalize_decision(raw_decision)
        justification = input_func(f"Justification for {decision} {label}: ").strip()
        return {"decision": decision, "justification": justification, "approver": ""}
    except (EOFError, RuntimeError, ValueError):
        return {
            "decision": "rejected",
            "justification": "Auto-rejected by Approval Gate: non-interactive stdin closed or invalid decision.",
            "approver": "system:auto_reject",
        }



def approval_node(state: IncidentState, input_func: DecisionInput | None = None) -> dict[str, Any]:
    if input_func is None:
        import builtins
        input_func = builtins.input

    incident = Incident.from_state(state)
    proposed_actions = [action.to_dict() if isinstance(action, ResponseAction) else dict(action) for action in (state.get("proposed_actions") or [])]
    approved_actions: list[dict[str, Any]] = []
    acknowledged_actions: list[dict[str, Any]] = []
    rejected_actions: list[dict[str, Any]] = []
    errors = list(state.get("errors") or [])
    decisions = state.get("approval_decisions") or {}
    default_approver = str(state.get("approval_approver") or "").strip()

    if not proposed_actions:
        incident.add_audit_entry(
            actor="system:approval_node",
            action="approval_gate_completed",
            justification="No proposed response actions were available for approval.",
        )
        return {
            "approved_actions": [],
            "acknowledged_actions": [],
            "rejected_actions": [],
            "audit_log": [entry.to_dict() for entry in incident.audit_log],
            "errors": errors,
        }

    print("\n===========================")
    print("HUMAN APPROVAL GATE")
    print("===========================")
    print("Tier 1/no-approval actions are acknowledged automatically. Tier 2+ actions require a named human decision.")

    for index, action in enumerate(proposed_actions, start=1):
        requires_approval = bool(action.get("requires_approval"))
        tier = next(
            (
                item.get("risk_tier")
                for item in (state.get("allowed_actions") or [])
                if item.get("name") == action.get("action_type")
            ),
            "unknown",
        )
        label = _action_label(action)
        print(f"[{index}] {label} | Tier: {tier} | Requires approval: {'YES' if requires_approval else 'NO'}")

        timestamp = _utc_now()
        if not requires_approval:
            approver = "system:approval_node"
            decided = _with_decision_metadata(
                action,
                approver=approver,
                decision="acknowledged",
                justification="Tier 1/playbook policy does not require interactive approval.",
                timestamp=timestamp,
            )
            acknowledged_actions.append(decided)
            incident.add_audit_entry(
                actor=approver,
                action="response_action_acknowledged",
                justification=f"{label} acknowledged automatically because playbook requires_approval=False.",
            )
            print("    Already logged; no approval needed.")
            continue

        decision_record = _decision_from_map(action, decisions)
        if decision_record is None:
            decision_record = _prompt_for_decision(action, input_func=input_func)

        approver = decision_record.get("approver") or default_approver
        if not approver:
            approver = input_func(f"Approver ID for {label}: ").strip()
        if not approver:
            raise ValueError(f"Approver identity is required for {label}.")

        decided = _with_decision_metadata(
            action,
            approver=approver,
            decision=decision_record["decision"],
            justification=decision_record.get("justification", ""),
            timestamp=timestamp,
        )
        if decided["decision"] == "approved":
            approved_actions.append(decided)
            audit_action = "response_action_approved"
        else:
            rejected_actions.append(decided)
            audit_action = "response_action_rejected"

        incident.add_audit_entry(
            actor=approver,
            action=audit_action,
            justification=(
                f"{label} {decided['decision']} by {approver}. "
                f"Justification: {decided['approval_justification']}"
            ),
        )

    incident.add_audit_entry(
        actor="system:approval_node",
        action="approval_gate_completed",
        justification=(
            f"Approval gate completed. Human-approved actions: {len(approved_actions)}. "
            f"Acknowledged no-approval actions: {len(acknowledged_actions)}. "
            f"Rejected actions: {len(rejected_actions)}. No execution was performed."
        ),
    )

    print(
        f"[Approval] Approved: {len(approved_actions)} | "
        f"Acknowledged: {len(acknowledged_actions)} | "
        f"Rejected: {len(rejected_actions)} | Execution: pending downstream executor"
    )
    return {
        "approved_actions": approved_actions,
        "acknowledged_actions": acknowledged_actions,
        "rejected_actions": rejected_actions,
        "proposed_actions": proposed_actions,
        "audit_log": [entry.to_dict() for entry in incident.audit_log],
        "errors": errors,
    }

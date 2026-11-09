from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


CONTRACT_VERSION = "1.0"

EXECUTOR_CONTEXT_KEYS = (
    "scenario",
    "scenario_file",
    "incident_id",
    "incident_title",
    "incident_category",
    "incident_status",
    "timestamp",
    "schema_version",
    "source",
    "raw_alerts",
    "live_alerts",
    "simulated_alerts",
    "collection_metadata",
    "enriched_iocs",
    "confidence_score",
    "mitre_context",
    "campaign",
    "prediction",
    "report",
    "errors",
    "severity",
    "severity_tier",
    "asset_criticality",
    "affected_assets",
    "affected_asset_type",
    "potential_patient_impact",
    "risk_score",
    "priority",
    "requires_human_review",
    "rule_id",
    "logs",
    "mitre_techniques",
    "matched_playbook",
    "matched_playbook_technique_id",
    "matched_playbook_technique_name",
    "playbook_version",
    "playbook_source",
    "playbook_selected_by_technique",
    "allowed_actions",
    "proposed_actions",
    "approved_actions",
    "acknowledged_actions",
    "rejected_actions",
    "planner_divergence_flag",
    "detection_time",
    "investigation_time",
    "audit_log",
    "response_dry_run",
)


def _json_safe(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return _json_safe(value.to_dict())
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _assert_json_serializable(value: Any) -> None:
    json.dumps(value, sort_keys=True)


@dataclass(frozen=True)
class InvestigationHandoff:
    """Wire-safe payload passed from Investigator to Executor."""

    contract_version: str
    incident_id: str | None
    response_dry_run: bool
    approved_actions: list[dict[str, Any]]
    acknowledged_actions: list[dict[str, Any]]
    rejected_actions: list[dict[str, Any]]
    incident_context: dict[str, Any]

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> "InvestigationHandoff":
        context = {
            key: _json_safe(state.get(key))
            for key in EXECUTOR_CONTEXT_KEYS
            if key in state
        }
        payload = cls(
            contract_version=CONTRACT_VERSION,
            incident_id=_json_safe(state.get("incident_id")),
            response_dry_run=bool(state.get("response_dry_run", True)),
            approved_actions=_json_safe(list(state.get("approved_actions") or [])),
            acknowledged_actions=_json_safe(list(state.get("acknowledged_actions") or [])),
            rejected_actions=_json_safe(list(state.get("rejected_actions") or [])),
            incident_context=context,
        )
        _assert_json_serializable(payload.to_dict())
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "InvestigationHandoff":
        normalized = _json_safe(payload)
        handoff = cls(
            contract_version=str(normalized.get("contract_version") or CONTRACT_VERSION),
            incident_id=normalized.get("incident_id"),
            response_dry_run=bool(normalized.get("response_dry_run", True)),
            approved_actions=list(normalized.get("approved_actions") or []),
            acknowledged_actions=list(normalized.get("acknowledged_actions") or []),
            rejected_actions=list(normalized.get("rejected_actions") or []),
            incident_context=dict(normalized.get("incident_context") or {}),
        )
        _assert_json_serializable(handoff.to_dict())
        return handoff

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "incident_id": self.incident_id,
            "response_dry_run": self.response_dry_run,
            "approved_actions": self.approved_actions,
            "acknowledged_actions": self.acknowledged_actions,
            "rejected_actions": self.rejected_actions,
            "incident_context": self.incident_context,
        }


@dataclass(frozen=True)
class InvestigationResult:
    handoff: InvestigationHandoff
    investigation_state: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "handoff": self.handoff.to_dict(),
            "investigation_state": _json_safe(self.investigation_state),
        }
        _assert_json_serializable(payload)
        return payload


@dataclass(frozen=True)
class ExecutionResult:
    handoff: InvestigationHandoff
    execution_state: dict[str, Any]
    final_state: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "handoff": self.handoff.to_dict(),
            "execution_state": _json_safe(self.execution_state),
            "final_state": _json_safe(self.final_state),
        }
        _assert_json_serializable(payload)
        return payload

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ISO 8601 regex check
ISO_8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)

PATIENT_CARE_ASSET_TYPES = {
    "infusion_pump",
    "monitoring_device",
    "ehr",
    "clinical_system",
    "medical_device",
    "patient_monitor",
    "emr",
    "gateway"
}

PATIENT_CARE_KEYWORDS = [
    "infusion", "pump", "monitor", "ehr", "emr", "clinical", "patient", "icu", "critical_care"
]


def validate_timestamp(timestamp_str: str, field_name: str) -> None:
    """Validates that a timestamp string matches ISO 8601 format."""
    if not isinstance(timestamp_str, str):
        raise TypeError(f"Field '{field_name}' must be a string, got {type(timestamp_str).__name__}")
    if not ISO_8601_RE.match(timestamp_str):
        raise ValueError(f"Field '{field_name}' must be in ISO 8601 format (e.g. YYYY-MM-DDTHH:MM:SSZ), got '{timestamp_str}'")


@dataclass(frozen=True)
class AuditLogEntry:
    """
    Represents a immutable entry in the incident's audit log.
    Ensures accountability for all actions and justifications in compliance with healthcare regulations.
    """
    actor: str
    timestamp: str
    action: str
    justification: str

    def __post_init__(self) -> None:
        if not isinstance(self.actor, str) or not self.actor.strip():
            raise ValueError("Audit log 'actor' must be a non-empty string.")
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("Audit log 'action' must be a non-empty string.")
        if not isinstance(self.justification, str) or not self.justification.strip():
            raise ValueError("Audit log 'justification' must be a non-empty string.")
        validate_timestamp(self.timestamp, "AuditLogEntry.timestamp")

    def to_dict(self) -> dict[str, str]:
        return {
            "actor": self.actor,
            "timestamp": self.timestamp,
            "action": self.action,
            "justification": self.justification,
        }


@dataclass
class ResponseAction:
    """
    Represents a proposed or approved response action.
    Structural representation of active response actions without active execution logic.
    """
    action_id: str
    action_type: str
    target: str
    status: str  # e.g., proposed, approved, executed, failed, reverted
    justification: str
    requested_by: str
    approved_by: str | None = None
    decision: str | None = None
    decision_timestamp: str | None = None
    approval_justification: str | None = None
    execution_result: str | None = None
    requires_approval: bool | None = None
    reversible: bool | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))


    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or not self.action_id.strip():
            raise ValueError("ResponseAction 'action_id' must be a non-empty string.")
        if not isinstance(self.action_type, str) or not self.action_type.strip():
            raise ValueError("ResponseAction 'action_type' must be a non-empty string.")
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("ResponseAction 'target' must be a non-empty string.")
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("ResponseAction 'status' must be a non-empty string.")
        if not isinstance(self.justification, str) or not self.justification.strip():
            raise ValueError("ResponseAction 'justification' must be a non-empty string.")
        if not isinstance(self.requested_by, str) or not self.requested_by.strip():
            raise ValueError("ResponseAction 'requested_by' must be a non-empty string.")
        validate_timestamp(self.timestamp, "ResponseAction.timestamp")
        if self.decision_timestamp:
            validate_timestamp(self.decision_timestamp, "ResponseAction.decision_timestamp")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "status": self.status,
            "justification": self.justification,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "decision": self.decision,
            "decision_timestamp": self.decision_timestamp,
            "approval_justification": self.approval_justification,
            "execution_result": self.execution_result,
            "requires_approval": self.requires_approval,
            "reversible": self.reversible,
            "timestamp": self.timestamp,
        }


@dataclass
class Incident:
    """
    Canonical, validated, and persistable incident record.
    Enforces strong invariants for health-weighted asset criticality, derived severity tiers,
    and a strictly append-only audit trail.
    """
    incident_id: str
    timestamp: str
    title: str
    category: str
    status: str
    schema_version: str
    source: str  # wazuh_live or simulated

    # Detection context
    wazuh_alerts: list[dict[str, Any]]
    rule_id: str  # Primary triggering rule ID or concatenated representation
    logs: list[str]
    evidence: list[dict[str, Any]] = field(default_factory=list)

    # Threat Intelligence
    iocs: list[dict[str, Any]] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    threat_actor: str = "Unattributed"

    # Risk Metrics
    severity: int = 0  # 0-15 scale
    severity_tier: str = "Low"  # Derived tier
    confidence_score: float = 0.0  # 0.0 - 1.0, aggregated pipeline confidence
    asset_criticality: str = "Low"  # Low, Medium, High, Critical
    affected_assets: list[str] = field(default_factory=list)

    # Response Prep
    matched_playbook: str | None = None
    playbook_version: str | None = None
    allowed_actions: list[dict[str, Any]] = field(default_factory=list)
    proposed_actions: list[ResponseAction] = field(default_factory=list)
    approved_actions: list[ResponseAction] = field(default_factory=list)
    rejected_actions: list[ResponseAction] = field(default_factory=list)
    executed_actions: list[dict[str, Any]] = field(default_factory=list)
    failed_actions: list[dict[str, Any]] = field(default_factory=list)
    execution_summary: dict[str, Any] = field(default_factory=dict)
    execution_results: list[dict[str, Any]] = field(default_factory=list)

    # Timelines
    detection_time: str = ""
    investigation_time: str | None = None
    response_time: str | None = None
    closure_time: str | None = None

    # Healthcare Context
    affected_asset_type: str = "unknown"
    potential_patient_impact: str = "unknown"

    # Internal audit log storage to protect it from direct reassignment/mutation
    _audit_log: list[AuditLogEntry] = field(default_factory=list, init=False, repr=False)

    def __init__(
        self,
        incident_id: str,
        timestamp: str,
        title: str,
        category: str,
        status: str,
        schema_version: str,
        wazuh_alerts: list[dict[str, Any]],
        rule_id: str,
        logs: list[str],
        source: str = "simulated",
        evidence: list[dict[str, Any]] = None,
        iocs: list[dict[str, Any]] = None,
        mitre_tactics: list[str] = None,
        mitre_techniques: list[str] = None,
        threat_actor: str = "Unattributed",
        severity: int = 0,
        confidence_score: float = 0.0,
        asset_criticality: str = "Low",
        affected_assets: list[str] = None,
        matched_playbook: str | None = None,
        playbook_version: str | None = None,
        allowed_actions: list[dict[str, Any]] = None,
        proposed_actions: list[ResponseAction] = None,
        approved_actions: list[ResponseAction] = None,
        rejected_actions: list[ResponseAction] = None,
        executed_actions: list[dict[str, Any]] = None,
        failed_actions: list[dict[str, Any]] = None,
        execution_summary: dict[str, Any] = None,
        execution_results: list[dict[str, Any]] = None,
        detection_time: str = "",
        investigation_time: str | None = None,
        response_time: str | None = None,
        closure_time: str | None = None,
        affected_asset_type: str = "unknown",
        potential_patient_impact: str = "unknown",
        audit_log: list[AuditLogEntry | dict[str, Any]] = None,
    ) -> None:
        self.incident_id = incident_id
        self.timestamp = timestamp
        self.title = title
        self.category = category
        self.status = status
        self.schema_version = schema_version
        self.source = source
        self.wazuh_alerts = wazuh_alerts
        self.rule_id = rule_id
        self.logs = logs
        self.evidence = evidence or []
        self.iocs = iocs or []
        self.mitre_tactics = mitre_tactics or []
        self.mitre_techniques = mitre_techniques or []
        self.threat_actor = threat_actor
        self.severity = severity
        self.confidence_score = confidence_score
        self.asset_criticality = asset_criticality
        self.affected_assets = affected_assets or []
        self.matched_playbook = matched_playbook
        self.playbook_version = playbook_version
        self.allowed_actions = allowed_actions or []
        self.proposed_actions = proposed_actions or []
        self.approved_actions = approved_actions or []
        self.rejected_actions = rejected_actions or []
        self.executed_actions = executed_actions or []
        self.failed_actions = failed_actions or []
        self.execution_summary = execution_summary or {}
        self.execution_results = execution_results or []
        self.detection_time = detection_time or timestamp
        self.investigation_time = investigation_time
        self.response_time = response_time
        self.closure_time = closure_time
        self.affected_asset_type = affected_asset_type
        self.potential_patient_impact = potential_patient_impact

        # Derived tier assignment
        self.severity_tier = self._derive_severity_tier(severity)

        # Apply Healthcare Weighting Rule:
        # Defaults asset_criticality to High/Critical if any affected system involves direct patient-care.
        if self._is_patient_care_affected():
            if self.asset_criticality not in ("High", "Critical"):
                self.asset_criticality = "High"

        # Populate audit log safely
        self._audit_log = []
        if audit_log:
            for entry in audit_log:
                if isinstance(entry, AuditLogEntry):
                    self._audit_log.append(entry)
                elif isinstance(entry, dict):
                    self._audit_log.append(
                        AuditLogEntry(
                            actor=entry["actor"],
                            timestamp=entry["timestamp"],
                            action=entry["action"],
                            justification=entry["justification"],
                        )
                    )
                else:
                    raise TypeError("Audit log entry must be AuditLogEntry or dict.")

        # Perform initial validation
        self.validate()

    @property
    def audit_log(self) -> list[AuditLogEntry]:
        """Exposes a read-only list of audit log entries to enforce append-only behavior."""
        return list(self._audit_log)

    def add_audit_entry(self, actor: str, action: str, justification: str) -> None:
        """
        Appends a new record to the audit log.
        This is the exclusive, authorized mechanism to write log entries.
        """
        entry = AuditLogEntry(
            actor=actor,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            action=action,
            justification=justification,
        )
        self._audit_log.append(entry)

    def _derive_severity_tier(self, severity_level: int) -> str:
        if severity_level < 0 or severity_level > 15:
            raise ValueError(f"Severity level {severity_level} is out of bounds (0-15).")
        if severity_level <= 4:
            return "Low"
        elif severity_level <= 9:
            return "Medium"
        elif severity_level <= 12:
            return "High"
        else:
            return "Critical"

    def _is_patient_care_affected(self) -> bool:
        """Determines if the incident touches assets with direct patient-care contact."""
        if self.affected_asset_type.lower() in PATIENT_CARE_ASSET_TYPES:
            return True
        for asset in self.affected_assets:
            if any(kw in asset.lower() for kw in PATIENT_CARE_KEYWORDS):
                return True
        return False

    def validate(self) -> None:
        """
        Validates all constraints on the Incident record to ensure data integrity
        and safety in a healthcare environment.
        """
        # 1. Type validation
        if not isinstance(self.incident_id, str) or not self.incident_id.strip():
            raise ValueError("Incident incident_id must be a non-empty string.")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("Incident title must be a non-empty string.")
        if not isinstance(self.category, str) or not self.category.strip():
            raise ValueError("Incident category must be a non-empty string.")
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("Incident status must be a non-empty string.")
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("Incident schema_version must be a non-empty string.")
        if self.source not in ("wazuh_live", "simulated"):
            raise ValueError(f"Incident source must be 'wazuh_live' or 'simulated', got '{self.source}'.")

        # 2. Timestamp validations
        validate_timestamp(self.timestamp, "Incident.timestamp")
        validate_timestamp(self.detection_time, "Incident.detection_time")
        if self.investigation_time:
            validate_timestamp(self.investigation_time, "Incident.investigation_time")
        if self.response_time:
            validate_timestamp(self.response_time, "Incident.response_time")
        if self.closure_time:
            validate_timestamp(self.closure_time, "Incident.closure_time")

        # 3. Severity limits
        if not isinstance(self.severity, int):
            raise TypeError("Incident severity must be an integer.")
        if self.severity < 0 or self.severity > 15:
            raise ValueError(f"Incident severity must be between 0 and 15 inclusive, got {self.severity}.")

        # 4. Severity Tier matching derived tier
        expected_tier = self._derive_severity_tier(self.severity)
        if self.severity_tier != expected_tier:
            raise ValueError(f"Incident severity_tier '{self.severity_tier}' does not match severity level {self.severity} (expected '{expected_tier}').")

        # 5. Confidence Score range
        if not isinstance(self.confidence_score, (int, float)):
            raise TypeError("Incident confidence_score must be a float.")
        if self.confidence_score < 0.0 or self.confidence_score > 1.0:
            raise ValueError(f"Incident confidence_score must be between 0.0 and 1.0, got {self.confidence_score}.")

        # 6. Criticality enums
        valid_criticalities = {"Low", "Medium", "High", "Critical"}
        if self.asset_criticality not in valid_criticalities:
            raise ValueError(f"Incident asset_criticality must be one of {valid_criticalities}, got '{self.asset_criticality}'.")

        # 7. Healthcare specific weight checks
        if self._is_patient_care_affected() and self.asset_criticality not in ("High", "Critical"):
            raise ValueError(
                f"Healthcare Safety Violation: Direct patient-care systems (type='{self.affected_asset_type}', assets={self.affected_assets}) "
                f"cannot have a criticality tier of '{self.asset_criticality}'. It must be at least High/Critical."
            )

        # 8. List items type checks
        if not isinstance(self.wazuh_alerts, list):
            raise TypeError("wazuh_alerts must be a list.")
        if not isinstance(self.logs, list):
            raise TypeError("logs must be a list.")
        if self.matched_playbook is not None and not isinstance(self.matched_playbook, str):
            raise TypeError("matched_playbook must be a string or None.")
        if self.playbook_version is not None and not isinstance(self.playbook_version, str):
            raise TypeError("playbook_version must be a string or None.")
        if not isinstance(self.allowed_actions, list):
            raise TypeError("allowed_actions must be a list.")
        if not isinstance(self.proposed_actions, list) or not all(isinstance(a, ResponseAction) for a in self.proposed_actions):
            raise TypeError("proposed_actions must be a list of ResponseAction objects.")
        if not isinstance(self.approved_actions, list) or not all(isinstance(a, ResponseAction) for a in self.approved_actions):
            raise TypeError("approved_actions must be a list of ResponseAction objects.")
        if not isinstance(self.rejected_actions, list) or not all(isinstance(a, ResponseAction) for a in self.rejected_actions):
            raise TypeError("rejected_actions must be a list of ResponseAction objects.")
        if not isinstance(self.executed_actions, list):
            raise TypeError("executed_actions must be a list.")
        if not isinstance(self.failed_actions, list):
            raise TypeError("failed_actions must be a list.")
        if not isinstance(self.execution_summary, dict):
            raise TypeError("execution_summary must be a dict.")

    def to_dict(self) -> dict[str, Any]:
        """Serializes the incident instance to a dictionary for persistence/reporting."""
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "schema_version": self.schema_version,
            "source": self.source,
            "wazuh_alerts": self.wazuh_alerts,
            "rule_id": self.rule_id,
            "logs": self.logs,
            "evidence": self.evidence,
            "iocs": self.iocs,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "threat_actor": self.threat_actor,
            "severity": self.severity,
            "severity_tier": self.severity_tier,
            "confidence_score": self.confidence_score,
            "asset_criticality": self.asset_criticality,
            "affected_assets": self.affected_assets,
            "matched_playbook": self.matched_playbook,
            "playbook_version": self.playbook_version,
            "allowed_actions": self.allowed_actions,
            "proposed_actions": [action.to_dict() for action in self.proposed_actions],
            "approved_actions": [action.to_dict() for action in self.approved_actions],
            "rejected_actions": [action.to_dict() for action in self.rejected_actions],
            "executed_actions": self.executed_actions,
            "failed_actions": self.failed_actions,
            "execution_summary": self.execution_summary,
            "execution_results": self.execution_results,
            "detection_time": self.detection_time,
            "investigation_time": self.investigation_time,
            "response_time": self.response_time,
            "closure_time": self.closure_time,
            "affected_asset_type": self.affected_asset_type,
            "potential_patient_impact": self.potential_patient_impact,
            "audit_log": [entry.to_dict() for entry in self._audit_log],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        """Deserializes a dictionary to construct a validated Incident instance."""
        # Convert actions
        proposed = [ResponseAction(**act) if isinstance(act, dict) else act for act in data.get("proposed_actions", [])]
        approved = [ResponseAction(**act) if isinstance(act, dict) else act for act in data.get("approved_actions", [])]
        rejected = [ResponseAction(**act) if isinstance(act, dict) else act for act in data.get("rejected_actions", [])]
        
        # Convert audit logs
        raw_audit = data.get("audit_log", [])
        audit_objs = []
        for entry in raw_audit:
            if isinstance(entry, dict):
                audit_objs.append(
                    AuditLogEntry(
                        actor=entry["actor"],
                        timestamp=entry["timestamp"],
                        action=entry["action"],
                        justification=entry["justification"],
                    )
                )
            else:
                audit_objs.append(entry)

        return cls(
            incident_id=data["incident_id"],
            timestamp=data["timestamp"],
            title=data["title"],
            category=data["category"],
            status=data["status"],
            schema_version=data["schema_version"],
            source=data.get("source", "simulated"),
            wazuh_alerts=data["wazuh_alerts"],
            rule_id=data["rule_id"],
            logs=data["logs"],
            evidence=data.get("evidence"),
            iocs=data.get("iocs"),
            mitre_tactics=data.get("mitre_tactics"),
            mitre_techniques=data.get("mitre_techniques"),
            threat_actor=data.get("threat_actor", "Unattributed"),
            severity=data.get("severity", 0),
            confidence_score=data.get("confidence_score", 0.0),
            asset_criticality=data.get("asset_criticality", "Low"),
            affected_assets=data.get("affected_assets"),
            matched_playbook=data.get("matched_playbook"),
            playbook_version=data.get("playbook_version"),
            allowed_actions=data.get("allowed_actions"),
            proposed_actions=proposed,
            approved_actions=approved,
            rejected_actions=rejected,
            executed_actions=data.get("executed_actions"),
            failed_actions=data.get("failed_actions"),
            execution_summary=data.get("execution_summary"),
            execution_results=data.get("execution_results"),
            detection_time=data.get("detection_time", ""),
            investigation_time=data.get("investigation_time"),
            response_time=data.get("response_time"),
            closure_time=data.get("closure_time"),
            affected_asset_type=data.get("affected_asset_type", "unknown"),
            potential_patient_impact=data.get("potential_patient_impact", "unknown"),
            audit_log=audit_objs,
        )

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> Incident:
        """
        Constructs and validates a canonical Incident from an IncidentState dict.
        Reuses the constructor to enforce tier-derivation, healthcare overrides, and validation.
        """
        raw_alerts = state.get("raw_alerts") or []
        timestamp = state.get("timestamp") or (raw_alerts[0].get("timestamp") if raw_alerts else None) or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        # Rule ID extraction fallback
        rule_id = state.get("rule_id")
        if not rule_id and raw_alerts:
            rule_id = raw_alerts[0].get("wazuh_rule_id")
        if not rule_id:
            rule_id = "unknown"
            
        # Logs extraction fallback
        logs = state.get("logs")
        if not logs and raw_alerts:
            logs = [alert.get("raw_log", "") for alert in raw_alerts]
        if not logs:
            logs = []
            
        # Convert proposed/approved actions from dict to ResponseAction if they are dicts
        proposed_actions = None
        if state.get("proposed_actions") is not None:
            proposed_actions = []
            for act in state["proposed_actions"]:
                if isinstance(act, dict):
                    proposed_actions.append(ResponseAction(**act))
                else:
                    proposed_actions.append(act)
                    
        approved_actions = None
        if state.get("approved_actions") is not None:
            approved_actions = []
            for act in state["approved_actions"]:
                if isinstance(act, dict):
                    approved_actions.append(ResponseAction(**act))
                else:
                    approved_actions.append(act)

        rejected_actions = None
        if state.get("rejected_actions") is not None:
            rejected_actions = []
            for act in state["rejected_actions"]:
                if isinstance(act, dict):
                    rejected_actions.append(ResponseAction(**act))
                else:
                    rejected_actions.append(act)

        # Extraction from ThreatIntelState campaign/iocs if fields are empty
        iocs = state.get("enriched_iocs") or []
        mitre_tactics = state.get("mitre_tactics")
        if not mitre_tactics and state.get("campaign"):
            mitre_tactics = state.get("campaign", {}).get("confirmed_tactics")
        
        mitre_techniques = state.get("mitre_techniques")
        if not mitre_techniques and state.get("campaign"):
            mitre_techniques = state.get("campaign", {}).get("techniques_confirmed")

        threat_actor = state.get("threat_actor")
        if not threat_actor and state.get("campaign"):
            threat_actor = state.get("campaign", {}).get("attributed_actor")
        if not threat_actor:
            threat_actor = "Unattributed"

        return cls(
            incident_id=state.get("incident_id"),
            timestamp=timestamp,
            title=state.get("incident_title"),
            category=state.get("incident_category"),
            status=state.get("incident_status"),
            schema_version=state.get("schema_version"),
            source=state.get("source"),
            wazuh_alerts=raw_alerts,
            rule_id=rule_id,
            logs=logs,
            evidence=state.get("evidence"),
            iocs=iocs,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            threat_actor=threat_actor,
            severity=state.get("severity", 0),
            confidence_score=state.get("confidence_score", 0.0),
            asset_criticality=state.get("asset_criticality", "Low"),
            affected_assets=state.get("affected_assets"),
            matched_playbook=state.get("matched_playbook"),
            playbook_version=state.get("playbook_version"),
            allowed_actions=state.get("allowed_actions"),
            proposed_actions=proposed_actions,
            approved_actions=approved_actions,
            rejected_actions=rejected_actions,
            executed_actions=state.get("executed_actions"),
            failed_actions=state.get("failed_actions"),
            execution_summary=state.get("execution_summary"),
            execution_results=state.get("execution_results"),
            detection_time=state.get("detection_time", ""),
            investigation_time=state.get("investigation_time"),
            response_time=state.get("response_time"),
            closure_time=state.get("closure_time"),
            affected_asset_type=state.get("affected_asset_type", "unknown"),
            potential_patient_impact=state.get("potential_patient_impact", "unknown"),
            audit_log=state.get("audit_log"),
        )

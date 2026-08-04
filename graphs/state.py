from __future__ import annotations

from typing import TypedDict


class ThreatIntelState(TypedDict):
    scenario: str
    raw_alerts: list[dict]
    live_alerts: list[dict]
    simulated_alerts: list[dict]
    collection_metadata: dict
    enriched_iocs: list[dict]
    confidence_score: float
    mitre_context: dict
    campaign: dict
    prediction: dict
    report: str
    loop_count: int
    errors: list[str]


class IncidentState(ThreatIntelState):
    incident_id: str | None
    incident_title: str | None
    incident_category: str | None
    incident_status: str | None
    timestamp: str | None
    schema_version: str | None
    source: str | None
    confidence_score: float | None

    # Risk Assessment
    severity: int | None
    severity_tier: str | None
    asset_criticality: str | None
    affected_assets: list[str] | None
    risk_score: int | None
    priority: str | None
    requires_human_review: bool | None

    # Response Prep
    matched_playbook: str | None
    matched_playbook_technique_id: str | None
    matched_playbook_technique_name: str | None
    playbook_version: str | None
    playbook_source: str | None
    playbook_selected_by_technique: str | None
    allowed_actions: list[dict] | None
    proposed_actions: list[dict] | None
    approved_actions: list[dict] | None
    acknowledged_actions: list[dict] | None
    rejected_actions: list[dict] | None
    executed_actions: list[dict] | None
    failed_actions: list[dict] | None
    execution_summary: dict | None
    approval_decisions: dict | None
    approval_approver: str | None
    execution_results: list[dict] | None
    planner_divergence_flag: bool | None

    # Timelines
    detection_time: str | None
    investigation_time: str | None
    response_time: str | None
    closure_time: str | None

    # Healthcare Context
    affected_asset_type: str | None
    potential_patient_impact: str | None

    # Audit Trail
    audit_log: list[dict] | None

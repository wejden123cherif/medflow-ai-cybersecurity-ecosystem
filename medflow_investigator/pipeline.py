from __future__ import annotations

import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any

from langgraph.graph import END, StateGraph

from graphs.state import IncidentState, ThreatIntelState
from graphs.nodes.persistence import persist_live_incident_node
from medflow_contracts import InvestigationHandoff, InvestigationResult
from medflow_investigator.nodes import (
    approval_node,
    collection_node,
    correlation_node,
    ioc_enrichment_node,
    mitre_lookup_node,
    playbook_resolver_node,
    prediction_node,
    reporting_node,
    response_planner_node,
    risk_assessment_node,
)


def initialize_incident_node(state: ThreatIntelState) -> dict[str, Any]:
    """
    Convert investigation output into the incident fields required by response
    planning and executor handoff.
    """
    raw_alerts = state.get("raw_alerts") or []
    scenario = state.get("scenario", "ryuk")
    source = state.get("source", "simulated")
    errors = list(state.get("errors") or [])

    if raw_alerts:
        top_alert = raw_alerts[0]
        timestamp = top_alert.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        rule_id = top_alert.get("wazuh_rule_id") or top_alert.get("rule_id") or "unknown"
        severity = 0
        for alert in raw_alerts:
            val = alert.get("wazuh_rule_level")
            if val is None:
                val = alert.get("rule_level")
            if val is None and alert.get("source_type") == "wazuh":
                val = alert.get("severity_level")
            if val is None and alert.get("source_type") == "suricata":
                try:
                    val = {1: 15, 2: 12, 3: 8, 4: 4}.get(int(alert.get("severity_level")))
                except (TypeError, ValueError):
                    val = None
            try:
                if val is not None:
                    severity = max(severity, int(val))
            except (ValueError, TypeError):
                pass
        severity = max(0, min(15, severity))
    else:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        rule_id = "unknown"
        severity = 5

    collection_metadata = state.get("collection_metadata") or {}
    source_label = collection_metadata.get("data_source")
    stable_ids = sorted(str(alert.get("event_id") or alert.get("id") or "") for alert in raw_alerts if isinstance(alert, dict))
    if source_label in {"wazuh_live", "suricata_live", "mixed_live"} and stable_ids and all(stable_ids):
        evidence_fingerprint = hashlib.sha256("\n".join(stable_ids).encode("utf-8")).hexdigest()[:16].upper()
        incident_id = f"INC-LIVE-{evidence_fingerprint}"
    else:
        incident_id = f"INC-{scenario.upper()}-{uuid.uuid4().hex[:6].upper()}"
    incident_title = f"{scenario.title()} Campaign Detection"

    campaign = state.get("campaign") or {}
    incident_category = campaign.get("attack_type") or "intrusion"
    incident_status = "investigating"
    schema_version = "1.0.0"

    affected_assets = list({
        str(alert.get("destination"))
        for alert in raw_alerts
        if alert.get("destination") and str(alert.get("destination")).lower() != "unknown"
    })
    if not affected_assets:
        affected_assets = ["medflow-network-segment"]

    asset_type_priority = {
        "medical_device": 4,
        "ehr": 3,
        "workstation": 2,
        "web_application": 1,
    }
    affected_asset_type = "workstation"
    best_priority = 0
    for asset in affected_assets:
        asset_lower = asset.lower()
        if "pump" in asset_lower or "medical" in asset_lower or "infusion" in asset_lower:
            candidate = "medical_device"
        elif "ehr" in asset_lower or "fileserver" in asset_lower:
            candidate = "ehr"
        elif "portal" in asset_lower or "web" in asset_lower:
            candidate = "web_application"
        else:
            candidate = "workstation"
        if asset_type_priority.get(candidate, 0) > best_priority:
            best_priority = asset_type_priority[candidate]
            affected_asset_type = candidate

    if affected_asset_type == "ehr":
        potential_patient_impact = (
            "Potential impact on patient data availability and clinical database uptime. "
            "Patient data exposure is unconfirmed without exfiltration evidence."
        )
    elif affected_asset_type == "medical_device":
        potential_patient_impact = "High risk of direct clinical impact or medication dosage manipulation."
    else:
        potential_patient_impact = "Operational disruption and potential secondary risk to clinical workflows."

    asset_criticality = "High" if affected_asset_type in ("ehr", "medical_device") else "Low"
    logs = [alert.get("raw_log", alert.get("full_log", "")) for alert in raw_alerts]
    mitre_techniques = campaign.get("techniques_confirmed") or []

    return {
        "incident_id": incident_id,
        "incident_title": incident_title,
        "incident_category": incident_category,
        "incident_status": incident_status,
        "timestamp": timestamp,
        "schema_version": schema_version,
        "severity": severity,
        "asset_criticality": asset_criticality,
        "affected_assets": affected_assets,
        "affected_asset_type": affected_asset_type,
        "potential_patient_impact": potential_patient_impact,
        "rule_id": rule_id,
        "logs": logs,
        "mitre_techniques": mitre_techniques,
        "errors": errors,
        "source": source,
    }


def _initial_state(
    scenario: str,
    *,
    scenario_file: str | None,
    with_execution: bool,
) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "scenario_file": scenario_file,
        "raw_alerts": [],
        "live_alerts": [],
        "simulated_alerts": [],
        "collection_metadata": {},
        "enriched_iocs": [],
        "confidence_score": 0.0,
        "mitre_context": {},
        "campaign": {},
        "prediction": {},
        "report": "",
        "loop_count": 0,
        "errors": [],
        "audit_log": [],
        "matched_playbook": None,
        "matched_playbook_technique_id": None,
        "matched_playbook_technique_name": None,
        "playbook_version": None,
        "playbook_source": None,
        "playbook_selected_by_technique": None,
        "allowed_actions": [],
        "proposed_actions": [],
        "approved_actions": [],
        "acknowledged_actions": [],
        "rejected_actions": [],
        "executed_actions": [],
        "failed_actions": [],
        "execution_summary": {},
        "approval_decisions": {},
        "approval_approver": None,
        "execution_results": [],
        "response_dry_run": not with_execution,
    }


def run_investigation(
    scenario: str,
    scenario_file: str | None = None,
    with_response: bool = False,
    with_approval: bool = False,
    with_execution: bool = False,
) -> InvestigationResult:
    """
    Run the Investigator component through approval and return a wire-safe
    handoff for the Executor component.
    """
    with_approval = with_approval or with_execution
    with_response = with_response or with_approval

    workflow = StateGraph(IncidentState)
    workflow.add_node("collection", collection_node)
    workflow.add_node("ioc_enrichment", ioc_enrichment_node)
    workflow.add_node("mitre_lookup", mitre_lookup_node)
    workflow.add_node("correlation", correlation_node)
    workflow.add_node("prediction", prediction_node)
    workflow.add_node("reporting", reporting_node)
    workflow.add_node("initialize_incident", initialize_incident_node)
    workflow.add_node("risk_assessment", risk_assessment_node)
    workflow.add_node("playbook_resolver", playbook_resolver_node)
    workflow.add_node("persist_incident", persist_live_incident_node)

    if with_response:
        workflow.add_node("response_planner", response_planner_node)
    if with_approval:
        workflow.add_node("approval", approval_node)

    workflow.set_entry_point("collection")
    workflow.add_edge("collection", "ioc_enrichment")
    workflow.add_edge("ioc_enrichment", "mitre_lookup")
    workflow.add_edge("mitre_lookup", "correlation")
    workflow.add_edge("correlation", "prediction")
    workflow.add_edge("prediction", "reporting")
    workflow.add_edge("reporting", "initialize_incident")
    workflow.add_edge("initialize_incident", "risk_assessment")
    workflow.add_edge("risk_assessment", "playbook_resolver")
    workflow.add_edge("playbook_resolver", "persist_incident")

    if with_response:
        workflow.add_edge("persist_incident", "response_planner")
        if with_approval:
            workflow.add_edge("response_planner", "approval")
            workflow.add_edge("approval", END)
        else:
            workflow.add_edge("response_planner", END)
    else:
        workflow.add_edge("persist_incident", END)

    app = workflow.compile()
    state = app.invoke(_initial_state(scenario, scenario_file=scenario_file, with_execution=with_execution))
    handoff = InvestigationHandoff.from_state(state)
    return InvestigationResult(handoff=handoff, investigation_state=state)

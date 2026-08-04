from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from langgraph.graph import StateGraph, END

from graphs.state import IncidentState, ThreatIntelState
from graphs.nodes.collection import collection_node
from graphs.nodes.ioc_enrichment import ioc_enrichment_node
from graphs.nodes.mitre_lookup import mitre_lookup_node
from graphs.nodes.correlation import correlation_node
from graphs.nodes.prediction import prediction_node
from graphs.nodes.reporting import reporting_node
from graphs.nodes.risk import risk_assessment_node
from graphs.nodes.playbook_resolver import playbook_resolver_node
from graphs.nodes.response_planner import response_planner_node
from graphs.nodes.approval import approval_node
from graphs.nodes.response_executor import response_executor_node
from graphs.nodes.closure import closure_node


def initialize_incident_node(state: ThreatIntelState) -> dict[str, Any]:
    """
    Orchestrates the conversion from ThreatIntelState to IncidentState fields
    in a deterministic, unified manner. Ensures identical field population
    for both live-Wazuh and fallback paths.
    """
    raw_alerts = state.get("raw_alerts") or []
    scenario = state.get("scenario", "ryuk")
    source = state.get("source", "simulated")
    errors = list(state.get("errors") or [])

    # 1. Base metadata
    if raw_alerts:
        top_alert = raw_alerts[0]
        timestamp = top_alert.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        rule_id = top_alert.get("wazuh_rule_id") or top_alert.get("rule_id") or "unknown"
        
        # Calculate maximum severity level (0-15) from alerts
        severity = 0
        for alert in raw_alerts:
            val = alert.get("wazuh_rule_level")
            if val is None:
                val = alert.get("rule_level")
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

    incident_id = f"INC-{scenario.upper()}-{uuid.uuid4().hex[:6].upper()}"
    incident_title = f"{scenario.title()} Campaign Detection"
    
    campaign = state.get("campaign") or {}
    incident_category = campaign.get("attack_type") or "intrusion"
    incident_status = "investigating"
    schema_version = "1.0.0"

    # 2. Affected Assets extraction
    affected_assets = list({
        str(alert.get("destination"))
        for alert in raw_alerts
        if alert.get("destination") and str(alert.get("destination")).lower() != "unknown"
    })
    if not affected_assets:
        affected_assets = ["medflow-network-segment"]

    # 3. Determine Affected Asset Type — scan ALL assets, prefer most critical type
    # Priority: medical_device > ehr > workstation/server > web_application
    ASSET_TYPE_PRIORITY = {
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
        if ASSET_TYPE_PRIORITY.get(candidate, 0) > best_priority:
            best_priority = ASSET_TYPE_PRIORITY[candidate]
            affected_asset_type = candidate

    # 4. Set potential patient impact description
    if affected_asset_type == "ehr":
        potential_patient_impact = (
            "Potential impact on patient data availability and clinical database uptime. "
            "Patient data exposure is unconfirmed without exfiltration evidence."
        )
    elif affected_asset_type == "medical_device":
        potential_patient_impact = "High risk of direct clinical impact or medication dosage manipulation."
    else:
        potential_patient_impact = "Operational disruption and potential secondary risk to clinical workflows."

    # 5. Determine base asset criticality
    # Also run through the Incident constructor logic to get the validated/overridden value
    asset_criticality = "Low"
    if affected_asset_type in ("ehr", "medical_device"):
        asset_criticality = "High"  # Will be confirmed/elevated by Incident constructor

    logs = [alert.get("raw_log", alert.get("full_log", "")) for alert in raw_alerts]

    # Pull techniques confirmed by the campaign node
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


def run_threat_intel(
    scenario: str,
    scenario_file: str | None = None,
    with_response: bool = False,
    with_approval: bool = False,
    with_execution: bool = False,
) -> dict[str, Any]:
    """
    Builds and executes the threat intelligence LangGraph workflow.
    
    If with_response is True, compiles and executes the graph through the
    response planner node. If with_approval is True, response planning is
    enabled and the graph blocks at the human approval gate after planning.
    Otherwise, runs only the threat intelligence enrichment and assessment
    pipeline.
    """
    with_approval = with_approval or with_execution
    with_response = with_response or with_approval
    workflow = StateGraph(IncidentState)

    # 1. Add Nodes
    workflow.add_node("collection", collection_node)
    workflow.add_node("ioc_enrichment", ioc_enrichment_node)
    workflow.add_node("mitre_lookup", mitre_lookup_node)
    workflow.add_node("correlation", correlation_node)
    workflow.add_node("prediction", prediction_node)
    workflow.add_node("reporting", reporting_node)
    workflow.add_node("initialize_incident", initialize_incident_node)
    workflow.add_node("risk_assessment", risk_assessment_node)
    workflow.add_node("playbook_resolver", playbook_resolver_node)
    workflow.add_node("closure", closure_node)
    
    if with_response:
        workflow.add_node("response_planner", response_planner_node)
    if with_approval:
        workflow.add_node("approval", approval_node)
    if with_execution:
        workflow.add_node("response_executor", response_executor_node)

    # 2. Define Edges
    workflow.set_entry_point("collection")
    workflow.add_edge("collection", "ioc_enrichment")
    workflow.add_edge("ioc_enrichment", "mitre_lookup")
    workflow.add_edge("mitre_lookup", "correlation")
    workflow.add_edge("correlation", "prediction")
    workflow.add_edge("prediction", "reporting")
    workflow.add_edge("reporting", "initialize_incident")
    workflow.add_edge("initialize_incident", "risk_assessment")
    workflow.add_edge("risk_assessment", "playbook_resolver")
    
    if with_response:
        workflow.add_edge("playbook_resolver", "response_planner")
        if with_approval:
            workflow.add_edge("response_planner", "approval")
            if with_execution:
                workflow.add_edge("approval", "response_executor")
                workflow.add_edge("response_executor", "closure")
            else:
                workflow.add_edge("approval", "closure")
        else:
            workflow.add_edge("response_planner", "closure")
    else:
        workflow.add_edge("playbook_resolver", "closure")

    workflow.add_edge("closure", END)

    app = workflow.compile()

    initial_state = {
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
        "response_dry_run": not with_execution,  # False = live connectors, True = dry-run simulation
    }

    return app.invoke(initial_state)

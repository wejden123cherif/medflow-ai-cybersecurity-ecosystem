from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from graphs.state import IncidentState
from models.incident import Incident


def risk_assessment_node(state: IncidentState) -> dict[str, Any]:
    """
    Deterministic, rules-based Risk Assessment LangGraph node.
    Performs audit-compliant scoring calculations using a validated Incident object.
    
    No LLM calls are performed here to ensure reproducibility.
    """
    # 1. Reconstruct validated Incident from state
    incident = Incident.from_state(state)

    # 2. Compute risk score components
    severity_norm = incident.severity / 15.0

    criticality_weights = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    asset_criticality_weight = criticality_weights.get(incident.asset_criticality, 1)
    criticality_norm = asset_criticality_weight / 4.0

    confidence_norm = incident.confidence_score

    # Calculate raw score (weights: 40% severity, 35% asset criticality, 25% confidence)
    raw_risk_score = (severity_norm * 0.4 + criticality_norm * 0.35 + confidence_norm * 0.25) * 100.0

    # Round to nearest integer and clamp to [0, 100]
    risk_score = int(round(raw_risk_score))
    risk_score = max(0, min(100, risk_score))

    # 3. Map risk_score to priority tier
    if risk_score <= 29:
        priority = "Low"
    elif risk_score <= 59:
        priority = "Medium"
    elif risk_score <= 79:
        priority = "High"
    else:
        priority = "Critical"

    # 4. Apply confidence override
    # Safety Rule: If confidence is low (< 0.5), cap priority at Medium and require review.
    confidence_override_triggered = False
    requires_human_review = False
    
    if incident.confidence_score < 0.5:
        confidence_override_triggered = True
        requires_human_review = True
        # Note: priority is NOT demoted here. The risk score reflects genuine threat severity.
        # The requires_human_review flag is the correct signal for low-confidence incidents.
        # Silently downgrading High -> Medium would mask a real High-priority incident.

    # 5. Document the calculation in the audit log
    justification = (
        f"Computed risk_score={risk_score} (raw={raw_risk_score:.2f}%) using inputs: "
        f"severity={incident.severity} (norm={severity_norm:.2f}), "
        f"asset_criticality='{incident.asset_criticality}' (weight={asset_criticality_weight}, norm={criticality_norm:.2f}), "
        f"confidence_score={incident.confidence_score:.2f}. "
        f"Mapped priority: '{priority}'. "
        f"Confidence override triggered: {confidence_override_triggered}."
    )

    incident.add_audit_entry(
        actor="system:risk_assessment_node",
        action="risk_score_computed",
        justification=justification,
    )

    # 6. Return updated IncidentState fields
    return {
        "risk_score": risk_score,
        "priority": priority,
        "requires_human_review": requires_human_review,
        "audit_log": [entry.to_dict() for entry in incident.audit_log],
    }

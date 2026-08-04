from __future__ import annotations

from typing import Any

from config import ROOT_DIR
from graphs.nodes.mitre_lookup import _kill_chain_position
from graphs.state import IncidentState
from models.incident import Incident
from playbooks.loader import load_all_playbooks, playbook_for_technique


PLAYBOOKS_DIR = ROOT_DIR / "playbooks"


def _serialize_actions(playbook: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": action["name"],
            "risk_tier": action["risk_tier"],
            "requires_approval": action["requires_approval"],
            "reversible": action["reversible"],
            "asset_criticality_restrictions": action["asset_criticality_restrictions"],
        }
        for action in playbook.get("actions", [])
    ]


def resolve_playbook_for_incident(incident: Incident) -> dict[str, Any]:
    """
    Deterministically select the response playbook for a validated incident.

    No LLM is involved. The highest kill-chain-position confirmed technique is
    selected first, then exact-list playbook matching is applied with DEFAULT as
    the loader-enforced fallback.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)
    sorted_techniques = sorted(
        incident.mitre_techniques or [],
        key=lambda technique: _kill_chain_position(technique),
        reverse=True,
    )
    selected_technique = sorted_techniques[0] if sorted_techniques else "UNKNOWN"
    playbook = playbook_for_technique(selected_technique, playbooks)

    return {
        "matched_playbook": playbook.get("playbook_id"),
        "matched_playbook_technique_id": playbook.get("mitre_technique_id"),
        "matched_playbook_technique_name": playbook.get("mitre_technique_name"),
        "playbook_version": playbook.get("playbook_version"),
        "playbook_source": playbook.get("_source_path"),
        "playbook_selected_by_technique": selected_technique,
        "allowed_actions": _serialize_actions(playbook),
    }


def playbook_resolver_node(state: IncidentState) -> dict[str, Any]:
    incident = Incident.from_state(state)
    resolved = resolve_playbook_for_incident(incident)
    incident.add_audit_entry(
        actor="system:playbook_resolver_node",
        action="playbook_resolved",
        justification=(
            f"Technique '{resolved['playbook_selected_by_technique']}' resolved to "
            f"playbook '{resolved['matched_playbook']}' "
            f"({resolved['matched_playbook_technique_id']}) "
            f"version '{resolved['playbook_version']}'."
        ),
    )
    resolved["audit_log"] = [entry.to_dict() for entry in incident.audit_log]
    print(
        f"[Playbook Resolver] Technique '{resolved['playbook_selected_by_technique']}' -> "
        f"playbook '{resolved['matched_playbook']}' {resolved['playbook_version']}"
    )
    return resolved

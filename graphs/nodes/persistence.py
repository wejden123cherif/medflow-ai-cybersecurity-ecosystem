"""Persist live investigation evidence before any response approval step."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from graphs.state import IncidentState

logger = logging.getLogger("medflow.graphs.nodes.persistence")


def acknowledge_persisted_events(state: dict[str, Any]) -> None:
    """Advance collector checkpoints only after the incident transaction commits."""
    event_ids_by_source: dict[str, list[str]] = {"wazuh": [], "suricata": []}
    for alert in state.get("raw_alerts") or []:
        if not isinstance(alert, dict):
            continue
        source_type = str(alert.get("source_type") or "").lower()
        event_id = str(alert.get("event_id") or alert.get("id") or "")
        if source_type in event_ids_by_source and event_id:
            event_ids_by_source[source_type].append(event_id)
    for source_type, event_ids in event_ids_by_source.items():
        if not event_ids:
            continue
        try:
            if source_type == "wazuh":
                from collectors.wazuh import WazuhCollector
                acknowledged = WazuhCollector().acknowledge_event_ids(event_ids)
            else:
                from collectors.suricata import SuricataCollector
                acknowledged = SuricataCollector().acknowledge_event_ids(event_ids)
            logger.info("Acknowledged %d persisted %s alert event(s).", acknowledged, source_type)
        except Exception as exc:
            logger.warning("Could not acknowledge persisted %s alert events (%s).", source_type, type(exc).__name__)


def persist_live_incident_node(state: IncidentState) -> dict[str, Any]:
    """Save live evidence and queue/deliver eligible mail before optional approval."""
    metadata = state.get("collection_metadata") or {}
    if metadata.get("data_source") not in {"wazuh_live", "suricata_live", "mixed_live"}:
        return {}

    try:
        from models.incident_store import IncidentStore
        store = IncidentStore()
    except Exception as exc:
        logger.error("Could not initialize incident persistence (%s); source evidence remains pending.", type(exc).__name__)
        return {}
    persisted_state = dict(state)
    audit_log = list(state.get("audit_log") or [])
    audit_log.append({
        "actor": "system:incident_persistence_node",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "action": "INCIDENT_PERSISTED",
        "justification": "Live normalized evidence and risk assessment were saved before response planning or approval.",
    })
    persisted_state["audit_log"] = audit_log

    try:
        from integrations.email.incident_dispatch import eligible_recipient
        try:
            recipient = eligible_recipient(persisted_state)
        except Exception as exc:
            logger.warning("SOC notification policy evaluation failed (%s).", type(exc).__name__)
            recipient = None
        if recipient:
            store.save_incident(persisted_state, notification_recipient=recipient)
        else:
            store.save_incident(persisted_state)
    except Exception as exc:
        logger.error("Live incident persistence failed (%s); source evidence remains pending.", type(exc).__name__)
        return {}

    # The transaction and outbox row are durable before checkpoint or SMTP work.
    acknowledge_persisted_events(state)
    if recipient:
        try:
            from integrations.email.incident_dispatch import dispatch_pending_notifications
            dispatch_pending_notifications(store, incident_id=str(state.get("incident_id") or ""))
        except Exception as exc:
            logger.warning("Could not dispatch persisted incident notification (%s).", type(exc).__name__)
    return {"audit_log": audit_log}

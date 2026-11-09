"""Fresh-evidence policy and durable outbox dispatch for real incidents."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from config import load_settings
from integrations.email.connector import EmailConnector
from models.incident_store import IncidentStore

logger = logging.getLogger("medflow.integrations.email.incident_dispatch")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def eligible_recipient(state: dict[str, Any], *, now: datetime | None = None) -> str | None:
    """Return the configured allowlisted recipient only for a fresh, severe live incident."""
    settings = load_settings()
    allowed = {str(value).strip().casefold() for value in settings.soc_email_allowlist if str(value).strip()}
    recipient = str(settings.soc_email or "").strip()
    if not recipient or recipient.casefold() not in allowed:
        return None
    if state.get("collection_metadata", {}).get("data_source") not in {"wazuh_live", "suricata_live", "mixed_live"}:
        return None
    try:
        incident_severity = int(state.get("severity") or 0)
        if incident_severity < settings.email_min_severity:
            return None
    except (TypeError, ValueError):
        return None

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    oldest = current.astimezone(timezone.utc) - timedelta(minutes=settings.email_max_evidence_age_minutes)
    # Allow at most two minutes of sensor clock skew into the future.
    newest = current.astimezone(timezone.utc) + timedelta(minutes=2)
    for alert in state.get("raw_alerts") or []:
        if not isinstance(alert, dict) or alert.get("source_type") not in {"wazuh", "suricata"}:
            continue
        event_id = str(alert.get("event_id") or "").casefold()
        if any(marker in event_id for marker in ("fixture", "simulated", "medflow-test", "lab-test")):
            continue
        event_time = _parse_timestamp(alert.get("source_event_timestamp"))
        if event_time is None or not oldest <= event_time <= newest:
            continue
        try:
            level = int(alert.get("severity_level"))
            if alert.get("source_type") == "suricata":
                level = {1: 15, 2: 12, 3: 8, 4: 4}.get(level, 0)
            if level >= settings.email_min_severity:
                return recipient
        except (TypeError, ValueError):
            continue
    return None


def dispatch_pending_notifications(store: IncidentStore, *, incident_id: str | None = None) -> int:
    """Attempt queued notifications; failures remain durable and retryable."""
    connector = EmailConnector()
    connector.notification_store = store
    sent_or_attempted = 0
    for row in store.list_pending_notifications():
        if incident_id and row["incident_id"] != incident_id:
            continue
        result = connector.execute_action(
            {"action_type": "NOTIFY_SOC", "target": row["recipient"]},
            {**row["incident"], "incident_id": row["incident_id"], "notification_kind": "incident"},
        )
        sent_or_attempted += 1
        if result.get("status") != "success":
            # Connector persists a sanitized failure status for later retry.
            logger.warning("SOC incident notification attempt failed (%s).", result.get("error", "delivery_failed"))
    return sent_or_attempted


def retry_pending_notifications() -> int:
    """Retry the durable outbox at the start of a normal execution cycle."""
    try:
        return dispatch_pending_notifications(IncidentStore())
    except Exception as exc:
        logger.warning("Could not process SOC notification outbox (%s).", type(exc).__name__)
        return 0

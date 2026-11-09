"""
graphs/nodes/closure.py
-----------------------
Incident Closure and Metric Tracking LangGraph node for MedFlow AI.

Responsibilities:
  1. Computes ISO 8601 timestamps for incident lifecycle events:
     - `closure_time`: Current UTC timestamp when node executes.
     - `detection_time`: Preserves initial alert/detection timestamp.
     - `investigation_time`: Preserves assessment/planning timestamp.
     - `response_time`: Calculates delta duration (e.g. "3.45s") from detection to closure.

  2. Evaluates response execution outcomes to determine final `incident_status`:
     - `"contained"`: All executed actions succeeded (with zero failures).
     - `"partially_contained"`: Some actions succeeded, but some failed.
     - `"remediation_failed"`: Actions were attempted but all failed.
     - `"closed_no_remediation_required"`: Observational/investigatory only (no write actions needed).

  3. Records audit log entry with actor `system:closure_node` for regulatory compliance.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from graphs.state import IncidentState
from models.incident import Incident

logger = logging.getLogger("medflow.graphs.nodes.closure")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str or not isinstance(dt_str, str):
        return None
    try:
        clean_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_str)
    except Exception:
        return None


def _response_report_appendix(state: IncidentState) -> str:
    report = str(state.get("report") or "").rstrip()
    if not report:
        return report

    def labels(actions: list[dict[str, Any]]) -> str:
        return ", ".join(
            f"{action.get('action_type') or action.get('action_name') or action.get('action')} on {action.get('target') or 'unspecified target'}"
            for action in actions
        ) or "None"

    proposed = list(state.get("proposed_actions") or [])
    acknowledged = list(state.get("acknowledged_actions") or [])
    approved = list(state.get("approved_actions") or [])
    rejected = list(state.get("rejected_actions") or [])
    results = list(state.get("execution_results") or [])
    is_dry_run = bool(state.get("response_dry_run", False))
    succeeded = [item for item in results if item.get("execution_status", item.get("status")) == "success"]
    skipped = [item for item in results if item.get("execution_status", item.get("status")) == "skipped"]
    failed = [item for item in results if item.get("execution_status", item.get("status")) == "failed"]

    if is_dry_run:
        outcomes = (
            "Executed in the environment: None (DRY RUN).\n"
            f"Dry-run simulations recorded: {labels(succeeded)}\n"
            f"Skipped: {labels(skipped)}\n"
            f"Failed: {labels(failed)}\n"
            "No external connector was called and no system was changed."
        )
    else:
        outcomes = (
            f"Execution successes: {labels(succeeded)}\n"
            f"Skipped: {labels(skipped)}\n"
            f"Failed: {labels(failed)}"
        )

    return (
        f"{report}\n\n10. RESPONSE ACTION STATUS\n"
        f"Execution mode: {'DRY RUN' if is_dry_run else 'LIVE'}\n"
        f"Proposed: {labels(proposed)}\n"
        f"Acknowledged: {labels(acknowledged)}\n"
        f"Approved: {labels(approved)}\n"
        f"Rejected: {labels(rejected)}\n"
        f"{outcomes}"
    )


def closure_node(state: IncidentState) -> dict[str, Any]:
    """
    LangGraph node for closing incidents and computing timeline/MTTR metrics.
    """
    logger.info("Executing Incident Closure Node...")

    closure_time = _utc_now_iso()

    # 1. Determine detection_time & investigation_time
    detection_time_str = (
        state.get("detection_time")
        or state.get("created_at")
        or state.get("timestamp")
    )
    if not detection_time_str:
        raw_alerts = state.get("raw_alerts") or []
        if raw_alerts and isinstance(raw_alerts[0], dict) and raw_alerts[0].get("timestamp"):
            detection_time_str = str(raw_alerts[0]["timestamp"])
        else:
            detection_time_str = closure_time

    investigation_time_str = state.get("investigation_time") or closure_time

    # 2. Calculate MTTR / Response duration metrics
    dt_closure = _parse_iso_datetime(closure_time)
    dt_detection = _parse_iso_datetime(detection_time_str)

    if dt_closure and dt_detection:
        delta_seconds = max(0.0, (dt_closure - dt_detection).total_seconds())
        if delta_seconds < 60:
            response_time_str = f"{delta_seconds:.2f}s"
        elif delta_seconds < 3600:
            minutes = int(delta_seconds // 60)
            seconds = delta_seconds % 60
            response_time_str = f"{minutes}m {seconds:.1f}s"
        else:
            hours = int(delta_seconds // 3600)
            minutes = int((delta_seconds % 3600) // 60)
            response_time_str = f"{hours}h {minutes}m"
    else:
        delta_seconds = 0.0
        response_time_str = "0.00s"

    # 3. Determine final incident_status
    executed_actions = state.get("executed_actions") or []
    failed_actions = state.get("failed_actions") or []
    execution_summary = state.get("execution_summary") or {}

    total_executed = len(executed_actions)
    total_failed = len(failed_actions)

    dry_run = bool(state.get("response_dry_run", False))
    if dry_run:
        final_status = "dry_run_completed"
    elif total_executed > 0 and total_failed == 0:
        final_status = "contained"
    elif total_executed > 0 and total_failed > 0:
        final_status = "partially_contained"
    elif total_executed == 0 and total_failed > 0:
        final_status = "remediation_failed"
    else:
        final_status = "closed_no_remediation_required"

    # 4. Update Audit Trail via Incident model
    try:
        incident = Incident.from_state(state)
        action_count_label = "simulated" if dry_run else "succeeded"
        justification = (
            f"Incident closed with status '{final_status}'. "
            f"Metrics: detection={detection_time_str}, closure={closure_time}, "
            f"response_time={response_time_str} ({delta_seconds:.2f}s). "
            f"Execution summary: {total_executed} {action_count_label}, {total_failed} failed."
        )
        incident.add_audit_entry(
            actor="system:closure_node",
            action="INCIDENT_CLOSED",
            justification=justification,
        )
        audit_log_dicts = [entry.to_dict() for entry in incident.audit_log]
    except Exception as exc:
        logger.warning(f"Could not update Incident audit model in closure_node: {exc}")
        existing_audit = list(state.get("audit_log") or [])
        existing_audit.append({
            "actor": "system:closure_node",
            "timestamp": closure_time,
            "action": "INCIDENT_CLOSED",
            "justification": f"Incident closed with status '{final_status}'. Response duration: {response_time_str}.",
        })
        audit_log_dicts = existing_audit

    logger.info(f"Incident {state.get('incident_id')} status updated to '{final_status}' (response_time={response_time_str})")

    out_state = {
        "incident_status": final_status,
        "closure_time": closure_time,
        "detection_time": detection_time_str,
        "investigation_time": investigation_time_str,
        "response_time": response_time_str,
        "audit_log": audit_log_dicts,
        "report": _response_report_appendix(state),
    }

    # 5. Persist final incident state to SQLite store
    notification_recipient = None
    persisted = False
    try:
        from models.incident_store import IncidentStore
        from integrations.email.incident_dispatch import eligible_recipient
        store = IncidentStore()
        merged_state = {**state, **out_state}
        try:
            notification_recipient = eligible_recipient(merged_state)
        except Exception as policy_exc:
            # Configuration/policy failures must never block durable incident persistence.
            logger.warning("SOC notification policy evaluation failed (%s).", type(policy_exc).__name__)
            notification_recipient = None
        if notification_recipient:
            store.save_incident(merged_state, notification_recipient=notification_recipient)
        else:
            store.save_incident(merged_state)
        persisted = True
        # The live investigator may already have persisted/acknowledged these
        # events before the approval workflow. This idempotent pass also covers
        # executor-only handoffs that reached closure without that earlier save.
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
                logger.warning("Could not acknowledge persisted %s alert events: %s", source_type, type(exc).__name__)
    except Exception as exc:
        logger.warning(f"Could not persist incident state in closure_node: {exc}")

    if persisted and notification_recipient:
        try:
            from integrations.email.incident_dispatch import dispatch_pending_notifications
            dispatch_pending_notifications(store, incident_id=str(state.get("incident_id") or ""))
        except Exception as exc:
            # Persistence and its notification outbox row have already committed.
            logger.warning("Could not dispatch persisted incident notification (%s).", type(exc).__name__)

    return out_state


from __future__ import annotations

import json
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from config import ROOT_DIR
from graphs.state import ThreatIntelState
from models.alert import normalize_alert, stable_event_id, validate_normalized_alert

ALERT_FILE = ROOT_DIR / "data" / "simulated_alerts" / "ryuk_scenario.json"
DEFAULT_MAX_LIVE_ALERTS_PER_INVESTIGATION = 100
MAX_LIVE_ALERTS_PER_INVESTIGATION = 1000
DEFAULT_MAX_LIVE_EVENT_AGE_DAYS = 365


def _max_live_alerts_per_investigation() -> int:
    try:
        configured = int(os.getenv(
            "MEDFLOW_MAX_LIVE_ALERTS_PER_INVESTIGATION",
            str(DEFAULT_MAX_LIVE_ALERTS_PER_INVESTIGATION),
        ))
    except ValueError:
        configured = DEFAULT_MAX_LIVE_ALERTS_PER_INVESTIGATION
    return min(max(configured, 1), MAX_LIVE_ALERTS_PER_INVESTIGATION)


def _max_live_event_age_days() -> int:
    try:
        configured = int(os.getenv(
            "MEDFLOW_MAX_LIVE_EVENT_AGE_DAYS",
            str(DEFAULT_MAX_LIVE_EVENT_AGE_DAYS),
        ))
    except ValueError:
        configured = DEFAULT_MAX_LIVE_EVENT_AGE_DAYS
    return min(max(configured, 1), 3650)


def _bound_live_alert_batch(
    alerts: list[dict], *, now_utc: datetime | None = None,
) -> tuple[list[dict], int, int]:
    """Keep graph work bounded, prioritizing the newest source evidence.

    Unselected events remain in their collector's durable pending queue and are
    not acknowledged by this investigation.
    """
    now_utc = now_utc or datetime.now(timezone.utc)
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)
    cutoff = now_utc.astimezone(timezone.utc) - timedelta(days=_max_live_event_age_days())
    eligible: list[dict] = []
    stale_count = 0
    for alert in alerts:
        value = str(alert.get("source_event_timestamp") or alert.get("timestamp") or "").strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        try:
            timestamp = datetime.fromisoformat(value) if value else None
        except ValueError:
            timestamp = None
        if timestamp is not None:
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            if timestamp.astimezone(timezone.utc) < cutoff:
                stale_count += 1
                continue
        eligible.append(alert)

    limit = _max_live_alerts_per_investigation()
    ordered = sorted(
        eligible,
        key=lambda alert: (
            str(alert.get("source_event_timestamp") or alert.get("timestamp") or ""),
            int(alert.get("risk_score", 0) or 0),
        ),
        reverse=True,
    )
    return ordered[:limit], max(0, len(ordered) - limit), stale_count


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_legacy_event(alert: dict[str, Any], *, source_type: str) -> dict[str, Any]:
    evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else dict(alert)
    source_timestamp = alert.get("source_event_timestamp") or alert.get("timestamp") or alert.get("@timestamp")
    event_id = alert.get("event_id") or alert.get("id") or stable_event_id(source_type, None, evidence)
    attributes = {
        key: value for key, value in alert.items()
        if key not in {"schema_version", "event_id", "id", "source_type", "source_system", "source_event_timestamp", "timestamp", "received_timestamp", "severity", "severity_level", "rule_id", "source_ip", "destination_ip", "destination", "source_sensor", "event_type", "description", "evidence", "raw_log"}
    }
    attributes.setdefault("data_source", "simulated" if source_type == "simulated" else f"{source_type}_live")
    normalized = normalize_alert(
        source_type=source_type,
        event_id=str(event_id),
        source_event_timestamp=source_timestamp,
        severity=alert.get("severity"),
        severity_level=alert.get("severity_level", alert.get("wazuh_rule_level")),
        rule_id=alert.get("rule_id") or alert.get("wazuh_rule_id") or alert.get("suricata_signature_id"),
        source_ip=alert.get("source_ip"),
        destination_ip=alert.get("destination_ip"),
        destination=alert.get("destination"),
        source_sensor=alert.get("source_sensor") or alert.get("agent_name"),
        event_type=alert.get("event_type") or alert.get("rule_description"),
        evidence=evidence,
        raw_log=alert.get("raw_log") or alert.get("full_log"),
        received_timestamp=alert.get("received_timestamp"),
        attributes=attributes,
    )
    return validate_normalized_alert(normalized)


def _collect_live_alerts() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    from collectors.suricata import SuricataCollector
    from collectors.wazuh import WazuhCollector

    all_alerts: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    failures: list[str] = []
    for collector_type in (WazuhCollector, SuricataCollector):
        collector = collector_type()
        try:
            alerts, source_meta = collector.collect()
        except Exception:
            alerts, source_meta = None, {"failure_code": "collector_unexpected_error"}
        safe_meta = dict(source_meta) if isinstance(source_meta, dict) else {"failure_code": "invalid_collector_metadata"}
        metadata.append(safe_meta)
        if alerts:
            all_alerts.extend(alerts)
        elif alerts is None:
            source = getattr(collector_type, "name", collector_type.__name__.replace("Collector", "").lower())
            code = safe_meta.get("failure_code", "collection_failed")
            failures.append(f"{source}:{code}")
    return all_alerts, metadata, failures


def collection_node(state: ThreatIntelState) -> dict[str, Any]:
    errors = list(state.get("errors", []))
    scenario = state.get("scenario", "ryuk")
    scenario_file_value = state.get("scenario_file")
    fallback_file = Path(scenario_file_value) if scenario_file_value else ALERT_FILE
    audit_log = list(state.get("audit_log", []) or [])
    collection_metadata: dict[str, Any] = {
        "scenario": scenario,
        "data_source": "simulated",
        "source_systems": ["simulated"],
        "source_file": fallback_file.name,
    }

    live_events: list[dict[str, Any]] = []
    collector_metadata: list[dict[str, Any]] = []
    failures: list[str] = []
    if scenario == "live":
        live_events, collector_metadata, failures = _collect_live_alerts()

    parsed_alerts: list[dict[str, Any]] = []
    if live_events:
        malformed = duplicates = 0
        seen_ids: set[str] = set()
        for index, event in enumerate(live_events, start=1):
            try:
                source_type = str(event.get("source_type") or event.get("source_system") or "").lower()
                if source_type not in {"wazuh", "suricata"}:
                    raise ValueError("invalid_source_type")
                normalized = validate_normalized_alert(event) if "event_id" in event else _normalize_legacy_event(event, source_type=source_type)
            except (ValueError, TypeError):
                malformed += 1
                continue
            if normalized["event_id"] in seen_ids:
                duplicates += 1
                continue
            seen_ids.add(normalized["event_id"])
            normalized["data_source"] = f"{source_type}_live"
            normalized.setdefault("risk_reasons", [])
            parsed_alerts.append(normalized)

        selected_event_count = len(parsed_alerts)
        deferred_event_count = 0
        stale_event_count = 0
        if parsed_alerts:
            parsed_alerts, deferred_event_count, stale_event_count = _bound_live_alert_batch(parsed_alerts)
        if stale_event_count:
            errors.append(
                f"[Collection] Deferred {stale_event_count} live event(s) older than "
                f"MEDFLOW_MAX_LIVE_EVENT_AGE_DAYS={_max_live_event_age_days()}; "
                "they remain in the collector checkpoint."
            )
        source_types = sorted({item["source_type"] for item in parsed_alerts})
        source_label = (
            "mixed_live" if len(source_types) > 1
            else f"{source_types[0]}_live" if source_types
            else "simulated"
        )
        if parsed_alerts:
            collection_metadata = {
                "scenario": scenario,
                "data_source": source_label,
                "source_systems": source_types,
                "collector_metadata": collector_metadata,
                "malformed_event_count": malformed,
                "duplicate_event_count": duplicates,
                "available_event_count": selected_event_count,
                "selected_event_count": len(parsed_alerts),
                "deferred_event_count": deferred_event_count,
                "stale_event_count": stale_event_count,
            }
            errors.extend(f"[Collection] {item}" for item in failures)
            source = source_label
            live_alerts = parsed_alerts
            simulated_alerts: list[dict[str, Any]] = []
        else:
            live_alerts = []
            simulated_alerts = []
            source = "simulated"
    else:
        live_alerts = []
        simulated_alerts = []
        source = "simulated"

    if not live_alerts:
        if scenario == "live":
            fallback_reason = " | ".join(failures) if failures else "no_live_alerts"
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            fallback_msg = (
                f"[Collection] FALLBACK at {now_utc}: {fallback_reason}. "
                f"using simulated scenario '{fallback_file.name}'."
            )
            errors.append(fallback_msg)
            audit_log.append({
                "actor": "system:collection_node",
                "timestamp": now_utc,
                "action": "wazuh_fallback",
                "justification": fallback_msg,
            })
            collection_metadata = {
                "scenario": scenario,
                "data_source": "simulated",
                "source_systems": ["simulated"],
                "source_file": fallback_file.name,
                "fallback_reason": fallback_reason,
                "fallback_at": now_utc,
                "collector_metadata": collector_metadata,
            }

        try:
            source_events = json.loads(fallback_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            errors.append(f"[Collection] Failed to load simulated input '{fallback_file.name}'.")
            return {
                "raw_alerts": [], "live_alerts": [], "simulated_alerts": [],
                "collection_metadata": collection_metadata, "errors": errors,
                "audit_log": audit_log, "source": "simulated", "schema_version": "1.0.0",
            }
        if not isinstance(source_events, list):
            errors.append("[Collection] Simulated input must contain a JSON array of events.")
            source_events = []
        collection_metadata["scenario_file_sha256"] = _file_sha256(fallback_file)
        collection_metadata["source_file_path"] = str(fallback_file)
        for index, event in enumerate(source_events, start=1):
            try:
                parsed_alerts.append(_normalize_legacy_event(event, source_type="simulated"))
            except (ValueError, TypeError):
                errors.append(f"[Collection] Skipped simulated event #{index}: invalid required fields.")
        simulated_alerts = parsed_alerts
        live_alerts = []
        source = "simulated"

    parsed_alerts.sort(
        key=lambda alert: (
            int(alert.get("risk_score", 0) or 0),
            int(alert.get("wazuh_rule_level", 0) or 0),
            str(alert.get("source_event_timestamp", "")),
        ),
        reverse=True,
    )
    return {
        "raw_alerts": parsed_alerts,
        "live_alerts": live_alerts,
        "simulated_alerts": simulated_alerts,
        "collection_metadata": collection_metadata,
        "errors": errors,
        "source": source,
        "schema_version": "1.0.0",
        "audit_log": audit_log,
    }

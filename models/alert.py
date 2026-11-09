from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

ALERT_SCHEMA_VERSION = "1.0.0"
ALLOWED_SOURCE_TYPES = {"wazuh", "suricata", "simulated"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing_event_timestamp")
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid_event_timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stable_event_id(source_type: str, identity: object | None, evidence: dict[str, Any]) -> str:
    if identity is not None and str(identity).strip():
        value = str(identity).strip()
    else:
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        value = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{source_type}:{value}"


def _optional_ip(value: object) -> str | None:
    if value is None or not str(value).strip():
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def normalize_alert(
    *,
    source_type: str,
    event_id: str,
    source_event_timestamp: object,
    severity: str | None,
    severity_level: int | float | None,
    rule_id: object | None,
    source_ip: object | None,
    destination_ip: object | None,
    destination: object | None,
    source_sensor: object | None,
    event_type: object | None,
    evidence: dict[str, Any],
    raw_log: object | None = None,
    received_timestamp: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kind = str(source_type).strip().lower()
    if kind not in ALLOWED_SOURCE_TYPES:
        raise ValueError("invalid_source_type")
    if not isinstance(evidence, dict):
        raise ValueError("invalid_evidence")
    if not event_id or not str(event_id).strip():
        raise ValueError("missing_event_id")

    event_timestamp = normalize_timestamp(source_event_timestamp)
    received = normalize_timestamp(received_timestamp) if received_timestamp else utc_now()
    event_text = str(event_type).strip() if event_type is not None else ""
    log_text = str(raw_log) if raw_log is not None else json.dumps(
        evidence, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    record: dict[str, Any] = dict(attributes or {})
    record.update({
        "schema_version": ALERT_SCHEMA_VERSION,
        "event_id": str(event_id),
        "id": str(event_id),  # Legacy graph and incident-model alias.
        "source_type": kind,
        "source_system": kind,
        "source_sensor": str(source_sensor).strip() if source_sensor else None,
        "source_event_timestamp": event_timestamp,
        "timestamp": event_timestamp,  # Legacy graph alias.
        "received_timestamp": received,
        "severity": str(severity).lower() if severity else None,
        "severity_level": severity_level,
        "rule_id": str(rule_id) if rule_id is not None else None,
        "source_ip": _optional_ip(source_ip),
        "destination_ip": _optional_ip(destination_ip),
        "destination": str(destination).strip() if destination else _optional_ip(destination_ip),
        "event_type": event_text or None,
        "description": event_text or None,
        "evidence": evidence,
        "raw_log": log_text,
    })
    return record


def validate_normalized_alert(record: object) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("alert_not_object")
    required = ("event_id", "source_type", "source_event_timestamp", "received_timestamp", "evidence")
    if any(key not in record for key in required):
        raise ValueError("alert_missing_required_field")
    if record.get("source_type") not in ALLOWED_SOURCE_TYPES:
        raise ValueError("invalid_source_type")
    if not isinstance(record.get("evidence"), dict):
        raise ValueError("invalid_evidence")
    normalize_timestamp(record["source_event_timestamp"])
    normalize_timestamp(record["received_timestamp"])
    if not str(record.get("event_id") or "").strip():
        raise ValueError("missing_event_id")
    return record
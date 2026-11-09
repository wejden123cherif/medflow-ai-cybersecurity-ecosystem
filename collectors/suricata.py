from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from collectors.base import BaseCollector
from collectors.checkpoints import (
    CheckpointIOError,
    PendingQueueFull,
    acknowledge_pending_events,
    checkpoint_failure_details,
    append_pending_events,
    load_checkpoint,
    write_checkpoint,
)
from config import ROOT_DIR
from models.alert import normalize_alert, stable_event_id

DEFAULT_SURICATA_EVE_PATH = "/var/log/suricata/eve.json"
MAX_RECORD_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 20 * 1024 * 1024
MAX_BATCH_RECORDS = 10000


class SuricataCollector(BaseCollector):
    def __init__(self) -> None:
        self.eve_path = Path(os.getenv("SURICATA_EVE_PATH", DEFAULT_SURICATA_EVE_PATH)).expanduser()
        self.sensor_id = os.getenv("SURICATA_SENSOR_ID", "").strip() or None
        try:
            max_records = int(os.getenv("SURICATA_MAX_RECORDS", str(MAX_BATCH_RECORDS)))
        except ValueError:
            max_records = MAX_BATCH_RECORDS
        self.max_records = min(max(max_records, 1), MAX_BATCH_RECORDS)
        self.checkpoint_path = Path(os.getenv(
            "SURICATA_CHECKPOINT_PATH", str(ROOT_DIR / "data" / "collector-checkpoints" / "suricata.json")
        )).expanduser()

    def collect(self) -> tuple[list[dict] | None, dict]:
        metadata: dict[str, Any] = {"data_source": "suricata_live", "source_system": "suricata", "source_type": "suricata"}
        if not self.eve_path.is_file():
            metadata["failure_code"] = "eve_file_missing"
            metadata["failure_reason"] = f"Suricata EVE log not found at {self.eve_path}"
            return None, metadata
        try:
            checkpoint = load_checkpoint(self.checkpoint_path)
            records, new_checkpoint, counts = self._read_records(checkpoint)
        except PendingQueueFull:
            metadata["failure_code"] = "pending_queue_full"
            metadata["failure_reason"] = "Unacknowledged events fill the durable pending queue; the file cursor was not advanced."
            return None, metadata
        except CheckpointIOError as exc:
            metadata.update(checkpoint_failure_details(exc))
            return None, metadata
        except ValueError:
            metadata["failure_code"] = "checkpoint_invalid"
            metadata["failure_reason"] = "Suricata checkpoint is malformed."
            return None, metadata
        except OSError:
            metadata["failure_code"] = "eve_file_io_error"
            metadata["failure_reason"] = "Suricata EVE file could not be read."
            return None, metadata
        try:
            write_checkpoint(self.checkpoint_path, new_checkpoint)
        except CheckpointIOError as exc:
            metadata.update(checkpoint_failure_details(exc))
            return None, metadata
        except OSError as exc:
            metadata.update(checkpoint_failure_details(exc))
            return None, metadata
        metadata.update(counts, success=True)
        return records, metadata

    def acknowledge_event_ids(self, event_ids: list[str]) -> int:
        checkpoint = load_checkpoint(self.checkpoint_path)
        acknowledged = acknowledge_pending_events(checkpoint, event_ids)
        if acknowledged:
            write_checkpoint(self.checkpoint_path, checkpoint)
        return acknowledged

    def _read_records(self, checkpoint: dict[str, Any]) -> tuple[list[dict], dict[str, Any], dict[str, Any]]:
        records: list[dict] = []
        malformed = duplicate = alerts_seen = 0
        partial = rotated = False
        stat = self.eve_path.stat()
        file_identity = f"{stat.st_dev}:{stat.st_ino}"
        try:
            offset = max(0, int(checkpoint.get("offset", 0)))
        except (TypeError, ValueError):
            offset = 0
        if checkpoint.get("file_identity") != file_identity or stat.st_size < offset:
            rotated = bool(checkpoint.get("file_identity") or offset)
            offset = 0
        seen_ids = checkpoint.get("seen_event_ids", [])
        seen = set(str(item) for item in seen_ids) if isinstance(seen_ids, list) else set()
        pending = checkpoint.get("pending_events", [])
        if isinstance(pending, list):
            seen.update(
                str(item.get("event_id")) for item in pending
                if isinstance(item, dict) and item.get("event_id")
            )
        start_offset = offset
        batch_records = 0

        with self.eve_path.open("rb") as stream:
            stream.seek(offset)
            while stream.tell() - start_offset < MAX_BATCH_BYTES and batch_records < self.max_records:
                line_start = stream.tell()
                line = stream.readline(MAX_RECORD_BYTES + 1)
                if not line:
                    break
                if not line.endswith(b"\n"):
                    if len(line) <= MAX_RECORD_BYTES:
                        stream.seek(line_start)
                        partial = True
                        break
                    consumed = len(line)
                    discarded = False
                    while consumed <= MAX_BATCH_BYTES:
                        remainder = stream.readline(min(65536, MAX_BATCH_BYTES - consumed + 1))
                        if not remainder:
                            stream.seek(line_start)
                            partial = True
                            break
                        consumed += len(remainder)
                        if remainder.endswith(b"\n"):
                            malformed += 1
                            batch_records += 1
                            discarded = True
                            break
                    if partial:
                        break
                    if not discarded:
                        stream.seek(line_start)
                        partial = True
                        break
                    continue
                batch_records += 1
                if len(line) > MAX_RECORD_BYTES:
                    malformed += 1
                    continue
                try:
                    event = json.loads(line.decode("utf-8").strip())
                except (UnicodeDecodeError, json.JSONDecodeError):
                    malformed += 1
                    continue
                if not isinstance(event, dict) or event.get("event_type") != "alert":
                    continue
                alerts_seen += 1
                record = self._normalize_event(event)
                if record is None:
                    malformed += 1
                    continue
                event_id = record["event_id"]
                if event_id in seen:
                    duplicate += 1
                    continue
                records.append(record)
                seen.add(event_id)
            new_offset = stream.tell()

        new_checkpoint = {
            "version": 1,
            "source": "suricata",
            "file_identity": file_identity,
            "offset": new_offset,
            "seen_event_ids": seen_ids,
            "pending_events": pending if isinstance(pending, list) else [],
        }
        pending_records = append_pending_events(new_checkpoint, records)
        return pending_records, new_checkpoint, {
            "records_processed": batch_records,
            "alerts_seen": alerts_seen,
            "malformed_records": malformed,
            "duplicate_events": duplicate,
            "pending_event_count": len(pending_records),
            "new_events_queued": len(records),
            "partial_record_pending": partial,
            "rotation_detected": rotated,
        }

    def _normalize_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        alert = event.get("alert")
        if not isinstance(alert, dict):
            return None
        try:
            severity_level = int(alert.get("severity"))
        except (TypeError, ValueError):
            return None
        severity = {1: "critical", 2: "high", 3: "medium"}.get(severity_level, "low")
        signature = alert.get("signature")
        signature_id = alert.get("signature_id")
        gid = alert.get("gid")
        revision = alert.get("rev")
        rule_id = f"{gid}:{signature_id}:{revision}" if signature_id is not None else None
        technique = "unknown"
        if signature:
            match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", str(signature))
            if match:
                technique = match.group(0)
        identity = event.get("event_id") or event.get("id")
        sensor = event.get("host") or self.sensor_id or "unspecified"
        identity = f"{sensor}:{identity}" if identity is not None else None
        event_id = stable_event_id("suricata", identity, event)
        try:
            return normalize_alert(
                source_type="suricata", event_id=event_id,
                source_event_timestamp=event.get("timestamp"), severity=severity,
                severity_level=severity_level, rule_id=rule_id,
                source_ip=event.get("src_ip"), destination_ip=event.get("dest_ip"),
                destination=event.get("dest_ip"), source_sensor=event.get("host") or self.sensor_id,
                event_type=signature or alert.get("category"), evidence=event,
                attributes={
                    "data_source": "suricata_live",
                    "suricata_signature_id": str(signature_id) if signature_id is not None else None,
                    "suricata_gid": gid,
                    "suricata_revision": revision,
                    "signature_category": alert.get("category"),
                    "alert_action": alert.get("action"),
                    "flow_id": event.get("flow_id"),
                    "technique_hint": technique,
                    "risk_score": max(0, 100 - min(4, severity_level) * 20),
                    "risk_priority": "high" if severity_level <= 2 else "low",
                    "risk_reasons": ["suricata_alert"],
                },
            )
        except ValueError:
            return None

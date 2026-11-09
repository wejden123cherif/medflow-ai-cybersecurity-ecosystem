"""Explicit, read-only lab collector smoke test; never runs during pytest."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
CHECKPOINT_ROOT = ROOT / "data" / "lab-ingestion-checkpoints"
PRODUCTION_CHECKPOINTS = {
    (ROOT / "data" / "collector-checkpoints" / "wazuh.json").resolve(),
    (ROOT / "data" / "collector-checkpoints" / "suricata.json").resolve(),
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-lab-read-only", action="store_true", help="explicitly enable bounded read-only collection")
    parser.add_argument("--confirm-authorized-read-only", action="store_true", help="attest the configured Indexer account and EVE access are read-only")
    parser.add_argument("--confirm-trusted-tls", action="store_true", help="attest the endpoint certificate is trusted by the configured CA/system store")
    parser.add_argument("--max-events", type=int, default=25, help="maximum Wazuh hits and Suricata EVE records per poll (1..500)")
    parser.add_argument("--lookback-days", type=int, default=1, help="Wazuh Indexer time window (1..7 days)")
    return parser


def _event_metadata(alert: dict, *, observed_at: datetime | None = None) -> dict:
    """Return identifiers and provenance fields only; never serialize evidence/raw logs."""
    observed = observed_at or datetime.now(timezone.utc)
    source_time = alert.get("source_event_timestamp")
    try:
        parsed = datetime.fromisoformat(str(source_time).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_seconds = max(0, int((observed - parsed.astimezone(timezone.utc)).total_seconds()))
        freshness = "fresh_within_15m" if age_seconds <= 900 else "historical_over_15m"
    except (TypeError, ValueError):
        age_seconds, freshness = None, "unknown_timestamp"

    marker = " ".join(str(alert.get(key) or "") for key in ("event_type", "rule_id")).upper()
    if alert.get("source_type") == "simulated":
        provenance = "simulated_fixture"
    elif "MEDFLOW-TEST" in marker or "TEST" in marker:
        provenance = "source_record_with_test_marker"
    else:
        provenance = "source_record_replay_status_unknown"

    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    return {
        "event_id": alert.get("event_id"),
        "source_type": alert.get("source_type"),
        "source_system": alert.get("source_system"),
        "source_sensor": alert.get("source_sensor"),
        "source_event_timestamp": source_time,
        "received_timestamp": alert.get("received_timestamp"),
        "age_seconds_at_verification": age_seconds,
        "timestamp_freshness": freshness,
        "provenance_class": provenance,
        "index": evidence.get("_index") if alert.get("source_type") == "wazuh" else None,
        "rule_id": alert.get("rule_id"),
        "source_ip": alert.get("source_ip"),
        "destination_ip": alert.get("destination_ip"),
    }


def _summary(source: str, alerts: list[dict] | None, metadata: dict, elapsed: float, poll: int) -> dict:
    valid = invalid = 0
    if alerts:
        from models.alert import validate_normalized_alert

        for alert in alerts:
            try:
                validate_normalized_alert(alert)
                valid += 1
            except (TypeError, ValueError):
                invalid += 1
    return {
        "source": source,
        "poll": poll,
        "source_label": metadata.get("data_source", f"{source}_live"),
        "success": metadata.get("success", alerts is not None),
        "events_returned": len(alerts or []),
        "valid_events": valid,
        "validation_failures": invalid + int(metadata.get("malformed_records", 0)),
        "duplicate_count": int(metadata.get("duplicate_count", metadata.get("duplicate_events", 0))),
        "new_events_queued": int(metadata.get("new_events_queued", 0)),
        "pending_event_count": int(metadata.get("pending_event_count", 0)),
        "failure_code": metadata.get("failure_code"),
        "elapsed_seconds": round(elapsed, 3),
        "events": [_event_metadata(item) for item in (alerts or [])],
    }


def _load_config() -> tuple[dict[str, str], list[str]]:
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env", override=False)
    except ImportError:
        pass

    values = {
        "url": os.getenv("WAZUH_INDEXER_URL", "").strip(),
        "username": os.getenv("MEDFLOW_WAZUH_INDEXER_USER", "").strip() or os.getenv("WAZUH_INDEXER_USER", "").strip(),
        "password": os.getenv("MEDFLOW_WAZUH_INDEXER_PASSWORD", "") or os.getenv("WAZUH_INDEXER_PASSWORD", ""),
        "tls": os.getenv("WAZUH_VERIFY_TLS", "true").strip().lower() not in {"0", "false", "no", "off"},
        "ca_bundle": os.getenv("WAZUH_CA_BUNDLE", "").strip(),
        "eve_path": os.getenv("SURICATA_EVE_PATH", "").strip(),
    }
    missing = []
    parsed = urlparse(values["url"])
    if parsed.scheme != "https" or not parsed.netloc:
        missing.append("WAZUH_INDEXER_URL (HTTPS endpoint)")
    if not values["username"]:
        missing.append("WAZUH_INDEXER_USER")
    elif values["username"].casefold() in {"admin", "administrator", "root"}:
        missing.append("WAZUH_INDEXER_USER (dedicated read-only account required; administrator account rejected)")
    if not values["password"]:
        missing.append("WAZUH_INDEXER_PASSWORD")
    if not values["tls"]:
        missing.append("WAZUH_VERIFY_TLS=true")
    if not values["ca_bundle"] or not Path(values["ca_bundle"]).expanduser().is_file() or not os.access(Path(values["ca_bundle"]).expanduser(), os.R_OK):
        missing.append("WAZUH_CA_BUNDLE (readable CA certificate required for strict TLS)")
    eve_path = Path(values["eve_path"]).expanduser()
    if not values["eve_path"] or not eve_path.is_file() or not os.access(eve_path, os.R_OK):
        missing.append("SURICATA_EVE_PATH (readable EVE JSONL file)")
    return values, missing


def _check_checkpoint_isolation(paths: list[Path]) -> None:
    resolved = {path.resolve() for path in paths}
    if resolved & PRODUCTION_CHECKPOINTS:
        raise RuntimeError("isolated_checkpoint_path_conflicts_with_production")


def main() -> int:
    args = _parser().parse_args()
    if not args.live_lab_read_only or not args.confirm_authorized_read_only or not args.confirm_trusted_tls:
        print("Read-only lab mode is disabled. Supply all three explicit confirmation flags to continue.")
        return 2
    if os.getenv("MEDFLOW_ENABLE_READ_ONLY_LAB_INGESTION") != "1":
        print("Set MEDFLOW_ENABLE_READ_ONLY_LAB_INGESTION=1 explicitly to enable this script.")
        return 2
    if not 1 <= args.max_events <= 500 or not 1 <= args.lookback_days <= 7:
        print("Bounds rejected: max-events must be 1..500 and lookback-days must be 1..7.")
        return 2

    values, missing = _load_config()
    if missing:
        print(json.dumps({"ready": False, "missing_prerequisites": missing}, indent=2))
        return 2

    CHECKPOINT_ROOT.mkdir(parents=True, exist_ok=True)
    result = {"ready": True, "checkpoint_mode": "temporary_isolated_no_ack", "sources": []}
    with tempfile.TemporaryDirectory(prefix="readonly-", dir=CHECKPOINT_ROOT) as temporary:
        wazuh_checkpoint = Path(temporary) / "wazuh-checkpoint.json"
        suricata_checkpoint = Path(temporary) / "suricata-checkpoint.json"
        _check_checkpoint_isolation([wazuh_checkpoint, suricata_checkpoint])
        os.environ["WAZUH_URL"] = ""  # use the documented read-only Indexer query path only
        os.environ["WAZUH_INDEXER_URL"] = values["url"]
        os.environ["WAZUH_INDEXER_USER"] = values["username"]
        os.environ["WAZUH_INDEXER_PASSWORD"] = values["password"]
        os.environ["WAZUH_CA_BUNDLE"] = str(Path(values["ca_bundle"]).expanduser())
        os.environ["WAZUH_VERIFY_TLS"] = "true"
        os.environ["WAZUH_PAGE_SIZE"] = str(args.max_events)
        os.environ["WAZUH_MAX_PAGES"] = "1"
        os.environ["WAZUH_LOOKBACK_DAYS"] = str(args.lookback_days)
        os.environ["WAZUH_API_TIMEOUT"] = "5"
        os.environ["WAZUH_MAX_RETRIES"] = "1"
        os.environ["WAZUH_CHECKPOINT_PATH"] = str(wazuh_checkpoint)
        os.environ["SURICATA_EVE_PATH"] = str(Path(values["eve_path"]).expanduser())
        os.environ["SURICATA_MAX_RECORDS"] = str(args.max_events)
        os.environ["SURICATA_CHECKPOINT_PATH"] = str(suricata_checkpoint)

        from collectors.suricata import SuricataCollector
        from collectors.wazuh import WazuhCollector

        collectors = [("wazuh", WazuhCollector()), ("suricata", SuricataCollector())]
        first_results: dict[str, list[dict] | None] = {}
        for source, collector in collectors:
            method = collector.collect_indexer if source == "wazuh" else collector.collect
            started = time.perf_counter()
            alerts, metadata = method()
            result["sources"].append(_summary(source, alerts, metadata, time.perf_counter() - started, 1))
            first_results[source] = alerts

        for source, collector in collectors:
            method = collector.collect_indexer if source == "wazuh" else collector.collect
            started = time.perf_counter()
            alerts, metadata = method()
            summary = _summary(source, alerts, metadata, time.perf_counter() - started, 2)
            first_ids = {item.get("event_id") for item in (first_results[source] or [])}
            second_ids = {item.get("event_id") for item in (alerts or [])}
            summary["replay_ids_stable"] = first_ids == second_ids
            summary["new_events_on_second_poll"] = int(metadata.get("new_events_queued", 0))
            result["sources"].append(summary)

    result["total_events_returned_first_poll"] = sum(item["events_returned"] for item in result["sources"] if item["poll"] == 1)
    result["production_checkpoint_modified"] = False
    result["incident_database_accessed"] = False
    result["acknowledged"] = False
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if all(item["success"] for item in result["sources"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())

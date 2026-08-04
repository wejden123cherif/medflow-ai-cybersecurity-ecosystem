from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone

from config import ROOT_DIR
from graphs.state import ThreatIntelState


ALERT_FILE = ROOT_DIR / "data" / "simulated_alerts" / "ryuk_scenario.json"
REQUIRED_ALERT_FIELDS = {
    "id",
    "timestamp",
    "source_ip",
    "destination",
    "event_type",
    "severity",
    "raw_log",
}


def _file_sha256(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collection_node(state: ThreatIntelState) -> dict:
    from pathlib import Path
    errors = list(state.get("errors", []))
    parsed_alerts: list[dict] = []
    loaded_live = False
    scenario = state.get("scenario", "ryuk")
    scenario_file_val = state.get("scenario_file")
    fallback_file = Path(scenario_file_val) if scenario_file_val else ALERT_FILE
    audit_log = list(state.get("audit_log", []) or [])

    collection_metadata = {
        "scenario": scenario,
        "data_source": "simulated",
        "source_file": fallback_file.name,
    }

    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT_DIR / ".env")
    except ImportError:
        pass

    collected_alerts = []
    metadata_list = []
    failure_reasons = []

    if scenario == "live":
        from collectors import BaseCollector
        collectors = [cls() for cls in BaseCollector.__subclasses__()]
        
        for collector in collectors:
            try:
                alerts, meta = collector.collect()
                if alerts is not None:
                    collected_alerts.extend(alerts)
                    metadata_list.append(meta)
                else:
                    reason = meta.get("failure_reason") or "Skipped or not configured"
                    failure_reasons.append(f"{collector.__class__.__name__}: {reason}")
            except Exception as exc:
                reason = f"Exception: {exc}"
                failure_reasons.append(f"{collector.__class__.__name__}: {reason}")

    if scenario == "live" and collected_alerts:
        loaded_live = True
        collection_metadata = {
            "scenario": scenario,
            "data_source": "wazuh_live",
        }
        for meta in metadata_list:
            collection_metadata.update(meta)
    else:
        if scenario == "live":
            fallback_reason = " | ".join(failure_reasons) if failure_reasons else "No live collectors available"
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            fallback_msg = (
                f"[Collection] FALLBACK at {now_utc}: {fallback_reason}. "
                f"Falling back to simulated scenario '{fallback_file.name}'."
            )
            print(fallback_msg)
            errors.append(fallback_msg)
            collection_metadata = {
                "scenario": scenario,
                "data_source": "simulated",
                "source_file": fallback_file.name,
                "fallback_reason": fallback_reason,
                "fallback_at": now_utc,
            }
            audit_log.append({
                "actor": "system:collection_node",
                "timestamp": now_utc,
                "action": "wazuh_fallback",
                "justification": fallback_msg,
            })

        try:
            alerts = json.loads(fallback_file.read_text(encoding="utf-8"))
            collection_metadata["source_file_path"] = str(fallback_file)
            collection_metadata["scenario_file_sha256"] = _file_sha256(fallback_file)
            collected_alerts = alerts
        except Exception as exc:
            errors.append(f"[Collection] Failed to load {fallback_file.name}: {exc}")
            return {
                "raw_alerts": parsed_alerts,
                "live_alerts": [],
                "simulated_alerts": [],
                "collection_metadata": collection_metadata,
                "errors": errors,
                "audit_log": audit_log,
            }

    if not isinstance(collected_alerts, list):
        errors.append(f"[Collection] Expected alert list, got {type(collected_alerts).__name__}")
        return {
            "raw_alerts": parsed_alerts,
            "live_alerts": [],
            "simulated_alerts": [],
            "collection_metadata": collection_metadata,
            "errors": errors,
            "audit_log": audit_log,
        }

    for index, alert in enumerate(collected_alerts, start=1):
        if not isinstance(alert, dict):
            errors.append(f"[Collection] Skipped alert #{index}: expected object, got {type(alert).__name__}")
            continue

        missing_fields = sorted(REQUIRED_ALERT_FIELDS - set(alert))
        if missing_fields:
            errors.append(
                f"[Collection] Skipped alert {alert.get('id', f'#{index}')}: "
                f"missing required fields {', '.join(missing_fields)}"
            )
            continue

        parsed_alert = dict(alert)
        if loaded_live:
            parsed_alert.setdefault("data_source", "wazuh_live")
            parsed_alert.setdefault("source_system", "wazuh")
            parsed_alert.setdefault("risk_reasons", [])
        else:
            parsed_alert["data_source"] = "simulated"
            parsed_alert["source_system"] = f"{fallback_file.name}_json"
            parsed_alert.setdefault("risk_reasons", ["simulated_scenario"])
        parsed_alerts.append(parsed_alert)

    if loaded_live:
        parsed_alerts.sort(
            key=lambda alert: (
                int(alert.get("risk_score", 0) or 0),
                int(alert.get("wazuh_rule_level", 0) or 0),
                str(alert.get("timestamp", "")),
            ),
            reverse=True,
        )

    if loaded_live:
        agent_names = sorted(
            {
                str(alert.get("agent_name", "unknown"))
                for alert in parsed_alerts
                if alert.get("agent_name")
            }
        )
        agent_label = ", ".join(agent_names[:3]) or "unknown"
        if len(agent_names) > 3:
            agent_label += f" +{len(agent_names) - 3} more"
        print(f"[Collection] Loaded {len(parsed_alerts)} LIVE alerts from collectors (agents: {agent_label})")
        if parsed_alerts:
            top_alert = parsed_alerts[0]
            print(
                "[Collection] Top live alert: "
                f"risk={top_alert.get('risk_score', 0)} "
                f"priority={top_alert.get('risk_priority', 'low')} "
                f"rule={top_alert.get('wazuh_rule_id', 'unknown')} "
                f"{top_alert.get('event_type', 'unknown')}"
            )
    else:
        print(f"[Collection] Loaded {len(parsed_alerts)} alerts from {fallback_file.name} (simulated)")

    return {
        "raw_alerts": parsed_alerts,
        "live_alerts": parsed_alerts if loaded_live else [],
        "simulated_alerts": [] if loaded_live else parsed_alerts,
        "collection_metadata": collection_metadata,
        "errors": errors,
        "source": "wazuh_live" if loaded_live else "simulated",
        "schema_version": "1.0.0",
        "audit_log": audit_log,
    }

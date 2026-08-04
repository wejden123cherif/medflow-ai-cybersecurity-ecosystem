import os
import json
import re
from collectors.base import BaseCollector

DEFAULT_SURICATA_EVE_PATH = "/var/log/suricata/eve.json"

class SuricataCollector(BaseCollector):
    def collect(self) -> tuple[list[dict] | None, dict]:
        """Reads Suricata EVE logs and normalizes them into MedFlow alerts."""
        eve_path = os.getenv("SURICATA_EVE_PATH", DEFAULT_SURICATA_EVE_PATH)
        metadata = {
            "data_source": "suricata_live",
            "source_system": "suricata",
            "eve_path": eve_path,
        }

        if not os.path.exists(eve_path):
            return None, {"failure_reason": f"Suricata EVE log not found at {eve_path}"}

        alerts = []
        try:
            with open(eve_path, "r", encoding="utf-8") as f:
                for index, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if entry.get("event_type") != "alert":
                        continue

                    alert_data = entry.get("alert", {})
                    
                    raw_sev = alert_data.get("severity", 3)
                    try:
                        sev_int = int(raw_sev)
                    except (TypeError, ValueError):
                        sev_int = 3

                    if sev_int == 1:
                        severity = "critical"
                    elif sev_int == 2:
                        severity = "high"
                    elif sev_int == 3:
                        severity = "medium"
                    else:
                        severity = "low"

                    signature = alert_data.get("signature", "")
                    technique_hint = "unknown"
                    match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", signature)
                    if match:
                        technique_hint = match.group(0)

                    alerts.append({
                        "id": f"SR-{index:03d}",
                        "timestamp": entry.get("timestamp", ""),
                        "source_ip": entry.get("src_ip", "unknown"),
                        "destination": entry.get("dest_ip", "unknown"),
                        "event_type": signature or "unknown",
                        "severity": severity,
                        "raw_log": json.dumps(entry)[:500],
                        "technique_hint": technique_hint,
                        "source_system": "suricata",
                        "data_source": "suricata_live",
                        "risk_score": 0,
                        "risk_priority": "low",
                        "risk_reasons": ["suricata_alert"],
                    })

            return alerts, metadata
        except Exception as e:
            print(f"[Collection] Suricata collector error: {e}")
            return None, {"failure_reason": f"Suricata collector error: {e}"}

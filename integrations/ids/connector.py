"""
integrations/ids/connector.py
------------------------------
IDS/IPS Response Connector for MedFlow AI.

Supports triggering actions on Suricata via the Unix socket
or REST API (e.g., reloading rules, dropping connections).

Currently implemented as a mock connector.
Future implementations can integrate with:
  - Suricata Unix socket (suricatasc)
  - Suricata REST API (suricata-update, EVE subscribe)
  - Snort inline mode
  - Zeek scripting
"""

import logging
from typing import Any

from integrations.base import ResponseConnector

logger = logging.getLogger("medflow.integrations.ids")


class IDSConnector(ResponseConnector):
    """
    Mock IDS/IPS Connector.

    Supported actions:
      - RELOAD_RULES  : Reload detection rules on the IDS engine
      - DROP_CONNECTION: Force drop of a specific flow/connection
      - ADD_RULE      : Dynamically add a detection rule
    """

    SUPPORTED_ACTIONS = {"RELOAD_RULES", "DROP_CONNECTION", "ADD_RULE"}

    def __init__(self, socket_path: str = "/var/run/suricata/suricata-command.socket") -> None:
        self.socket_path = socket_path
        self.enabled = True

    def check_health(self) -> bool:
        """Simulate health check against the Suricata socket/API."""
        return self.enabled and bool(self.socket_path)

    def execute_action(self, action: dict[str, Any], incident_context: dict[str, Any] | None = None) -> dict[str, Any]:
        action_type = str(action.get("action_type") or action.get("action") or "").strip().upper()
        target = str(action.get("target") or "").strip()

        logger.info(f"Attempting IDS action {action_type} for target {target!r}")

        if not self.check_health():
            logger.error("IDSConnector health check failed — Suricata socket unavailable.")
            return {
                "status": "failed",
                "details": "IDSConnector is unreachable (Suricata socket not found).",
                "error": "service_unavailable",
            }

        if action_type not in self.SUPPORTED_ACTIONS:
            return {
                "status": "failed",
                "details": f"Action '{action_type}' is not supported by IDSConnector.",
                "error": "unsupported_action",
            }

        import subprocess
        from pathlib import Path

        # Real execution logic
        if action_type == "RELOAD_RULES":
            try:
                result = subprocess.run(
                    ["docker", "-H", "npipe:////./pipe/docker_engine", "exec", "medflow-suricata", "suricatasc", "-c", "reload-rules"],
                    capture_output=True, text=True, check=True
                )
                details = f"Successfully reloaded Suricata rules via suricatasc. Output: {result.stdout.strip()}"
            except Exception as e:
                return {"status": "failed", "details": f"Failed to reload rules: {e}", "error": "execution_failed"}

        elif action_type == "DROP_CONNECTION" or action_type == "ADD_RULE":
            rule = action.get("rule")
            if action_type == "DROP_CONNECTION":
                if not target:
                    return {"status": "failed", "details": "Target IP missing.", "error": "missing_target"}
                # Strip port if target is IP:port — Suricata source address must be bare IP
                clean_ip = target.split(":")[0] if ":" in target else target
                import time
                sid = 9100000 + int(time.time()) % 100000  # unique per run to avoid dup-sig errors
                rule = f'drop ip {clean_ip} any -> any any (msg:"MedFlow Auto-Drop {clean_ip}"; sid:{sid}; rev:1;)'
            
            if not rule:
                return {"status": "failed", "details": "No rule content provided.", "error": "missing_rule"}

            try:
                # Path relative to project root
                rules_file = Path("suricata/rules/local.rules")
                if not rules_file.exists():
                    rules_file.parent.mkdir(parents=True, exist_ok=True)
                    rules_file.touch()

                with open(rules_file, "a") as f:
                    f.write(f"\n{rule}\n")

                # Reload Suricata via suricatasc inside the container
                # The socket lives at /var/run/suricata-command.socket inside the container
                result = subprocess.run(
                    ["docker", "-H", "npipe:////./pipe/docker_engine", "exec", "medflow-suricata",
                     "suricatasc", "-c", "reload-rules", "/var/run/suricata-command.socket"],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    logger.warning(f"suricatasc reload returned non-zero: {result.stderr.strip()}")
                    details = f"Rule written to disk but suricatasc reload failed (container may be restarting): {result.stderr.strip()}. Rule: {rule}"
                else:
                    details = f"Successfully staged new rule and reloaded Suricata: {rule}"
            except Exception as e:
                return {"status": "failed", "details": f"Failed to add rule: {e}", "error": "execution_failed"}
        else:
            details = f"Executed {action_type} on IDSConnector."

        logger.info(details)
        return {
            "status": "success",
            "details": details,
        }


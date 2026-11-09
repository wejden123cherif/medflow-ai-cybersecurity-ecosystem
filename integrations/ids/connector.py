"""
integrations/ids/connector.py
------------------------------
Remote IDS/IPS Response Connector for MedFlow AI.

Suricata remediation is executed on the configured target VM through SSH, not
on the MedFlow host. Rule staging writes to the target VM's local.rules file and
reloads the Suricata container on VM 2.
"""

from __future__ import annotations

import logging
import shlex
import time
from typing import Any, Callable

from integrations.base import ResponseConnector
from integrations.remote_exec import run_remote_command

logger = logging.getLogger("medflow.integrations.ids")


class IDSConnector(ResponseConnector):
    """
    Remote IDS/IPS Connector.

    Supported actions:
      - RELOAD_RULES    : Reload detection rules on the IDS engine.
      - DROP_CONNECTION : Add a Suricata drop rule for an IP, then reload.
      - ADD_RULE        : Dynamically add a supplied Suricata rule, then reload.
    """

    SUPPORTED_ACTIONS = {"RELOAD_RULES", "DROP_CONNECTION", "ADD_RULE"}

    def __init__(
        self,
        socket_path: str = "/var/run/suricata/suricata-command.socket",
        rules_file: str = "suricata/rules/local.rules",
        remote_runner: Callable[[list[str], int], dict[str, Any]] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.rules_file = rules_file
        self.enabled = True
        self._remote_runner = remote_runner or run_remote_command

    def check_health(self) -> bool:
        """Check if connector is enabled and has a Suricata socket path configured."""
        return self.enabled and bool(self.socket_path)

    def _run_remote(self, command: list[str], timeout: int = 10) -> dict[str, Any]:
        return self._remote_runner(command, timeout)

    @staticmethod
    def _command_error(result: dict[str, Any], fallback: str) -> str:
        return "ssh_connection_failed" if result.get("connection_failed") else fallback

    def _reload_rules(self) -> dict[str, Any]:
        return self._run_remote(
            [
                "docker",
                "exec",
                "medflow-suricata",
                "suricatasc",
                "-c",
                "reload-rules",
                self.socket_path,
            ],
            timeout=15,
        )

    def _append_rule(self, rule: str) -> dict[str, Any]:
        quoted_rule = shlex.quote(f"\n{rule}\n")
        quoted_path = shlex.quote(self.rules_file)
        script = (
            f"mkdir -p $(dirname {quoted_path}) && "
            f"touch {quoted_path} && "
            f"printf %s {quoted_rule} >> {quoted_path}"
        )
        return self._run_remote(["sh", "-c", script])

    def execute_action(self, action: dict[str, Any], incident_context: dict[str, Any] | None = None) -> dict[str, Any]:
        action_type = str(action.get("action_type") or action.get("action") or "").strip().upper()
        target = str(action.get("target") or "").strip()

        logger.info(f"Attempting IDS action {action_type} for target {target!r}")

        if not self.check_health():
            logger.error("IDSConnector health check failed: Suricata socket unavailable.")
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

        if action_type == "RELOAD_RULES":
            result = self._reload_rules()
            if result.get("success"):
                details = f"Successfully reloaded Suricata rules on target VM. Output: {result.get('stdout', '').strip()}"
                logger.info(details)
                return {"status": "success", "details": details}

            stderr = result.get("stderr", "").strip()
            err = f"Failed to reload Suricata rules on target VM: {stderr}"
            logger.error(err)
            return {"status": "failed", "details": err, "error": self._command_error(result, "execution_failed")}

        rule = action.get("rule") or target
        if action_type == "DROP_CONNECTION":
            if not target:
                return {"status": "failed", "details": "Target IP missing.", "error": "missing_target"}
            clean_ip = target.split(":")[0] if ":" in target else target
            sid = 9100000 + int(time.time()) % 100000
            rule = f'drop ip {clean_ip} any -> any any (msg:"MedFlow Auto-Drop {clean_ip}"; sid:{sid}; rev:1;)'

        if not rule:
            return {"status": "failed", "details": "No rule content provided.", "error": "missing_rule"}

        append_result = self._append_rule(str(rule))
        if not append_result.get("success"):
            stderr = append_result.get("stderr", "").strip()
            err = f"Failed to add Suricata rule on target VM: {stderr}"
            logger.error(err)
            return {"status": "failed", "details": err, "error": self._command_error(append_result, "execution_failed")}

        reload_result = self._reload_rules()
        if reload_result.get("success"):
            details = f"Successfully staged new rule on target VM and reloaded Suricata: {rule}"
            logger.info(details)
            return {"status": "success", "details": details}

        stderr = reload_result.get("stderr", "").strip()
        logger.warning(f"suricatasc reload returned non-zero on target VM: {stderr}")
        details = f"Rule written on target VM but suricatasc reload failed: {stderr}. Rule: {rule}"
        return {
            "status": "failed",
            "details": details,
            "error": self._command_error(reload_result, "reload_failed"),
        }

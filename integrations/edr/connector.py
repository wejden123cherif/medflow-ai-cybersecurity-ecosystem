import logging
from typing import Any
from integrations.base import ResponseConnector

logger = logging.getLogger("medflow.integrations.edr")

class EDRConnector(ResponseConnector):
    def __init__(self, host: str = "mock-edr.local", token: str = "mock-token") -> None:
        self.host = host
        self.token = token
        self.enabled = True

    def check_health(self) -> bool:
        """Simulate health checking of EDR controller API."""
        return self.enabled and bool(self.host)

    def execute_action(self, action: dict[str, Any], incident_context: dict[str, Any] | None = None) -> dict[str, Any]:
        action_type = str(action.get("action_type") or action.get("action") or "").strip().upper()
        target = str(action.get("target") or "").strip()

        logger.info(f"Attempting EDR action {action_type} for target {target}")

        if not self.check_health():
            logger.error("EDRConnector health check failed, service unavailable.")
            return {
                "status": "failed",
                "details": "EDRConnector is unreachable or unconfigured.",
                "error": "service_unavailable",
            }

        supported_actions = {"ISOLATE_ENDPOINT", "KILL_PROCESS", "REVOKE_SESSION"}
        if action_type not in supported_actions:
            return {
                "status": "failed",
                "details": f"Action {action_type} not supported by EDRConnector.",
                "error": "unsupported_action",
            }

        if not target:
            return {
                "status": "failed",
                "details": f"Target for {action_type} is missing.",
                "error": "missing_target",
            }

        if action_type == "ISOLATE_ENDPOINT":
            details = f"Successfully isolated endpoint {target} via mock EDRConnector."
        elif action_type == "KILL_PROCESS":
            details = f"Successfully terminated process {target} via mock EDRConnector."
        else:  # REVOKE_SESSION
            details = f"Successfully revoked session for {target} via mock EDRConnector."

        logger.info(details)
        return {
            "status": "success",
            "details": details,
        }

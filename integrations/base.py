from abc import ABC, abstractmethod
from typing import Any

class ResponseConnector(ABC):
    @abstractmethod
    def execute_action(self, action: dict[str, Any], incident_context: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Executes a response action.

        Args:
            action: Dict containing action details (action_type, target, etc.)
            incident_context: Optional context about the incident

        Returns:
            A dictionary with the execution result:
            {
                "status": "success" | "failed",
                "details": str,
                "error": str (optional)
            }
        """
        pass

    @abstractmethod
    def check_health(self) -> bool:
        """
        Checks health/connectivity of the connector.

        Returns:
            True if healthy, False otherwise.
        """
        pass

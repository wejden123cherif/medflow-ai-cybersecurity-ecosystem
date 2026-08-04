from abc import ABC, abstractmethod

class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> tuple[list[dict] | None, dict]:
        """
        Collects alerts from the source system.

        Returns:
            A tuple of (alerts, metadata):
            - alerts: A list of normalized alert dicts if collection was successful,
                      or None if the collector was skipped, unconfigured, or failed.
            - metadata: A dictionary containing details about the collection process,
                        including errors/reasons if it failed.
        """
        pass

from __future__ import annotations

from typing import Any

from medflow_executor import run_execution
from medflow_investigator import initialize_incident_node, run_investigation


def run_threat_intel(
    scenario: str,
    scenario_file: str | None = None,
    with_response: bool = False,
    with_approval: bool = False,
    with_execution: bool = False,
) -> dict[str, Any]:
    """
    Compatibility entry point for the original single-process workflow.

    The implementation now crosses the same serializable Investigator ->
    Executor handoff that a future distributed deployment would use.
    """
    investigation = run_investigation(
        scenario,
        scenario_file=scenario_file,
        with_response=with_response,
        with_approval=with_approval,
        with_execution=with_execution,
    )
    execution = run_execution(investigation)
    return execution.final_state


__all__ = ["initialize_incident_node", "run_threat_intel"]

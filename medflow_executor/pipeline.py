from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from graphs.state import IncidentState
from medflow_contracts import ExecutionResult, InvestigationHandoff, InvestigationResult
from medflow_executor.nodes import closure_node, response_executor_node


def _coerce_handoff(investigation_result: InvestigationResult | InvestigationHandoff | dict[str, Any]) -> InvestigationHandoff:
    if isinstance(investigation_result, InvestigationResult):
        return investigation_result.handoff
    if isinstance(investigation_result, InvestigationHandoff):
        return investigation_result
    if "handoff" in investigation_result and isinstance(investigation_result["handoff"], dict):
        return InvestigationHandoff.from_dict(investigation_result["handoff"])
    return InvestigationHandoff.from_dict(investigation_result)


def _state_from_handoff(handoff: InvestigationHandoff) -> dict[str, Any]:
    state = dict(handoff.incident_context)
    state["approved_actions"] = list(handoff.approved_actions)
    state["acknowledged_actions"] = list(handoff.acknowledged_actions)
    state["rejected_actions"] = list(handoff.rejected_actions)
    state["response_dry_run"] = bool(handoff.response_dry_run)
    state.setdefault("executed_actions", [])
    state.setdefault("failed_actions", [])
    state.setdefault("execution_summary", {})
    state.setdefault("execution_results", [])
    state.setdefault("audit_log", [])
    state.setdefault("errors", [])
    return state


def run_execution(
    investigation_result: InvestigationResult | InvestigationHandoff | dict[str, Any],
    *,
    retry_notifications: bool = True,
) -> ExecutionResult:
    """
    Run the Executor component from the serializable Investigator handoff.

    This function is intentionally small and wire-friendly: callers may pass the
    handoff dataclass directly or the JSON-decoded dict that would arrive over a
    future network boundary.
    """
    if retry_notifications:
        from integrations.email.incident_dispatch import retry_pending_notifications
        retry_pending_notifications()
    handoff = _coerce_handoff(investigation_result)
    workflow = StateGraph(IncidentState)
    should_run_response_executor = bool(
        handoff.incident_context.get("proposed_actions")
        or handoff.approved_actions
        or handoff.acknowledged_actions
        or handoff.rejected_actions
    )

    if should_run_response_executor:
        workflow.add_node("response_executor", response_executor_node)
        workflow.add_node("closure", closure_node)
        workflow.set_entry_point("response_executor")
        workflow.add_edge("response_executor", "closure")
    else:
        workflow.add_node("closure", closure_node)
        workflow.set_entry_point("closure")

    workflow.add_edge("closure", END)

    app = workflow.compile()
    initial_state = _state_from_handoff(handoff)
    final_state = app.invoke(initial_state)
    execution_state = {
        "execution_results": final_state.get("execution_results") or [],
        "executed_actions": final_state.get("executed_actions") or [],
        "failed_actions": final_state.get("failed_actions") or [],
        "execution_summary": final_state.get("execution_summary") or {},
        "incident_status": final_state.get("incident_status"),
        "closure_time": final_state.get("closure_time"),
        "response_time": final_state.get("response_time"),
        "audit_log": final_state.get("audit_log") or [],
    }
    return ExecutionResult(handoff=handoff, execution_state=execution_state, final_state=final_state)

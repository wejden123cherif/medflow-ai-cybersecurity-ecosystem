from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from graphs.state import IncidentState
from models.incident import Incident, ResponseAction


EXECUTOR_ACTOR = "response_executor"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _action_name(action: dict[str, Any]) -> str:
    return str(action.get("action_type") or action.get("action") or action.get("name") or "").strip().upper()


def _action_result(
    action: dict[str, Any],
    *,
    status: str,
    details: str,
    error: str = "",
) -> dict[str, Any]:
    timestamp = _utc_now()
    action_name = _action_name(action)
    return {
        "action": action_name,
        "action_name": action_name,
        "action_id": action.get("action_id"),
        "target": action.get("target"),
        "status": status,
        "execution_status": status,
        "timestamp": timestamp,
        "executed_at": timestamp,
        "executor": EXECUTOR_ACTOR,
        "details": details,
        "result": details,
        "error": error,
    }


class ResponseExecutor:
    """Safe response executor routing approved actions to integration connectors."""

    def __init__(self, *, dry_run: bool = True) -> None:
        from integrations import FirewallConnector, EDRConnector, IDSConnector
        from integrations.email.connector import EmailConnector
        self.dry_run = dry_run
        self.firewall = FirewallConnector()
        self.edr = EDRConnector()
        self.ids = IDSConnector()
        self.email = EmailConnector()

        self.handlers: dict[str, Callable[[dict[str, Any], dict[str, Any] | None], dict[str, Any]]] = {
            "NOTIFY_SOC": self._notify_soc,
            "CREATE_REPORT": self._create_report,
            "LOG_EVENT": self._log_event,
            "COLLECT_FORENSICS": self._collect_forensics,
            "BLOCK_IP": self._block_ip,
            "REVOKE_SESSION": self._revoke_session,
            "ISOLATE_ENDPOINT": self._isolate_endpoint,
            "DISABLE_ACCOUNT": self._disable_account,
            "KILL_PROCESS": self._kill_process,
            "PATCH_SYSTEM": self._patch_system,
            # IDS actions
            "RELOAD_RULES": self._reload_rules,
            "DROP_CONNECTION": self._drop_connection,
            "ADD_RULE": self._add_rule,
        }

    def execute(self, action: dict[str, Any], incident_context: dict[str, Any] | None = None) -> dict[str, Any]:
        action_name = _action_name(action)
        handler = self.handlers.get(action_name)
        if not handler:
            return _action_result(
                action,
                status="failed",
                details=f"No handler exists for action {action_name or 'UNKNOWN'}.",
                error="unsupported_action",
            )
        if self.dry_run:
            return _action_result(
                action,
                status="success",
                details=(
                    f"[DRY RUN] Would execute {action_name} on {action.get('target')}. "
                    "No external connector was called and no system was changed."
                ),
            )
        try:
            return handler(action, incident_context)
        except Exception as exc:
            return _action_result(
                action,
                status="failed",
                details=f"Handler for {action_name} failed.",
                error=str(exc),
            )

    def _notify_soc(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.email.check_health():
            return _action_result(
                action,
                status="failed",
                details="EmailConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.email.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _create_report(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        return _action_result(action, status="success", details="Simulated incident report creation completed.")

    def _log_event(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        return _action_result(action, status="success", details="Simulated response event logged.")

    def _collect_forensics(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        return _action_result(action, status="success", details=f"Simulated forensic collection queued for {action.get('target')}.")

    def _block_ip(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.firewall.check_health():
            return _action_result(
                action,
                status="failed",
                details="FirewallConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.firewall.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _revoke_session(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.edr.check_health():
            return _action_result(
                action,
                status="failed",
                details="EDRConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.edr.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _isolate_endpoint(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.edr.check_health():
            return _action_result(
                action,
                status="failed",
                details="EDRConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.edr.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _disable_account(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        return _action_result(action, status="success", details=f"Simulated account disable staged for {action.get('target')}; no account was changed.")

    def _kill_process(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.edr.check_health():
            return _action_result(
                action,
                status="failed",
                details="EDRConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.edr.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _patch_system(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        return _action_result(action, status="success", details=f"Simulated patch operation staged for {action.get('target')}; no system was modified.")

    def _reload_rules(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.ids.check_health():
            return _action_result(
                action,
                status="failed",
                details="IDSConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.ids.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _drop_connection(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.ids.check_health():
            return _action_result(
                action,
                status="failed",
                details="IDSConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.ids.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )

    def _add_rule(self, action: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.ids.check_health():
            return _action_result(
                action,
                status="failed",
                details="IDSConnector is unreachable or unconfigured.",
                error="connector_unavailable",
            )
        res = self.ids.execute_action(action, context)
        return _action_result(
            action,
            status=res["status"],
            details=res["details"],
            error=res.get("error", ""),
        )


def _action_allowed_by_policy(action: dict[str, Any], allowed_actions: list[dict[str, Any]]) -> bool:
    action_name = _action_name(action)
    return any(str(item.get("name", "")).upper() == action_name for item in allowed_actions or [])


def _is_execution_eligible(action: dict[str, Any]) -> bool:
    decision = str(action.get("decision") or action.get("status") or "").lower()
    requires_approval = bool(action.get("requires_approval"))
    if requires_approval:
        return decision == "approved"
    return decision in {"acknowledged", "approved"}


def _dedupe_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for action in actions:
        key = str(action.get("action_id") or f"{_action_name(action)}:{action.get('target')}")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)
    return deduped


def _execution_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total_actions": len(results),
        "successful": sum(1 for result in results if result.get("execution_status") == "success"),
        "failed": sum(1 for result in results if result.get("execution_status") == "failed"),
        "skipped": sum(1 for result in results if result.get("execution_status") == "skipped"),
    }


def _audit_execution(incident: Incident, *, event_type: str, action: dict[str, Any], result: dict[str, Any]) -> None:
    incident.add_audit_entry(
        actor=EXECUTOR_ACTOR,
        action=event_type,
        justification=json.dumps(
            {
                "action": _action_name(action),
                "action_id": action.get("action_id"),
                "target": action.get("target"),
                "result": result.get("execution_status"),
                "timestamp": result.get("executed_at"),
                "details": result.get("details"),
                "error": result.get("error"),
            },
            sort_keys=True,
        ),
    )


def response_executor_node(state: IncidentState) -> dict[str, Any]:
    incident = Incident.from_state(state)
    allowed_actions = list(state.get("allowed_actions") or [])
    dry_run = bool(state.get("response_dry_run", True))
    executor = ResponseExecutor(dry_run=dry_run)

    approved = [action.to_dict() if isinstance(action, ResponseAction) else dict(action) for action in (state.get("approved_actions") or [])]
    acknowledged = [action.to_dict() if isinstance(action, ResponseAction) else dict(action) for action in (state.get("acknowledged_actions") or [])]
    rejected = [action.to_dict() if isinstance(action, ResponseAction) else dict(action) for action in (state.get("rejected_actions") or [])]
    proposed = [action.to_dict() if isinstance(action, ResponseAction) else dict(action) for action in (state.get("proposed_actions") or [])]

    executable_keys = {str(action.get("action_id") or f"{_action_name(action)}:{action.get('target')}") for action in approved + acknowledged}
    rejected_keys = {str(action.get("action_id") or f"{_action_name(action)}:{action.get('target')}") for action in rejected}
    considered = _dedupe_actions(approved + acknowledged + rejected + proposed)

    results: list[dict[str, Any]] = []
    for action in considered:
        action_key = str(action.get("action_id") or f"{_action_name(action)}:{action.get('target')}")
        if action_key in rejected_keys:
            result = _action_result(
                action,
                status="skipped",
                details="Action was rejected by the human approval gate and was not executed.",
            )
            _audit_execution(incident, event_type="ACTION_EXECUTION_SKIPPED", action=action, result=result)
            results.append(result)
            continue

        if action_key not in executable_keys or not _is_execution_eligible(action):
            result = _action_result(
                action,
                status="skipped",
                details="Action was not approved or acknowledged by the approval gate.",
            )
            _audit_execution(incident, event_type="ACTION_EXECUTION_SKIPPED", action=action, result=result)
            results.append(result)
            continue

        if not _action_allowed_by_policy(action, allowed_actions):
            result = _action_result(
                action,
                status="skipped",
                details="Action is not authorized by the resolved playbook policy.",
                error="unauthorized_action",
            )
            _audit_execution(incident, event_type="ACTION_EXECUTION_SKIPPED", action=action, result=result)
            results.append(result)
            continue

        result = executor.execute(action, incident_context=state)
        if dry_run:
            print(
                "[Response Executor][DRY RUN] "
                f"{result.get('action_name')} on {result.get('target')}: {result.get('details')}"
            )
        _audit_execution(
            incident,
            event_type="ACTION_EXECUTED" if result.get("execution_status") == "success" else "ACTION_EXECUTION_FAILED",
            action=action,
            result=result,
        )
        results.append(result)

    executed_actions = [result for result in results if result.get("execution_status") == "success"]
    failed_actions = [result for result in results if result.get("execution_status") == "failed"]
    summary = _execution_summary(results)
    print(
        "[Response Executor] "
        f"mode={'dry-run' if dry_run else 'live'} "
        f"success={summary['successful']} failed={summary['failed']} skipped={summary['skipped']}"
    )
    return {
        "execution_results": results,
        "executed_actions": executed_actions,
        "failed_actions": failed_actions,
        "execution_summary": summary,
        "audit_log": [entry.to_dict() for entry in incident.audit_log],
    }

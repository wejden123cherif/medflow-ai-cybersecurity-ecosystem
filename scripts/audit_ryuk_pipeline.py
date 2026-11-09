"""Run the actual Ryuk Investigator/Executor graphs with offline service stubs.

This creates sanitized evidence at ``audit/ryuk_pipeline_evidence.json``. The
response graph is always invoked in dry-run mode and socket connections are
blocked for the duration of the run.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SCENARIO = ROOT / "data" / "simulated_alerts" / "ryuk_scenario.json"
AUDIT_DIR = ROOT / "audit"
EVIDENCE_FILE = AUDIT_DIR / "ryuk_pipeline_evidence.json"


def _network_blocked(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("Network access blocked by the Ryuk audit harness")


def _agent_stub(*_args: object, **_kwargs: object) -> dict:
    response = {
        "actor_name": "Unattributed",
        "malware_associated": "Unknown",
        "confidence": 0.0,
        "summary": "No external actor evidence; deterministic audit stub.",
    }
    return {"messages": [SimpleNamespace(content=json.dumps(response))]}


def _rag_stub(question: str, *_args: object, **_kwargs: object) -> str:
    if "Next adversary behavior" in question:
        return "No retrieved technique evidence; deterministic audit stub."
    return (
        "Preserve forensic evidence, validate backups from a clean source, "
        "and coordinate patient-care continuity planning."
    )


def _node_trace(patches: list[object], module: object, names: list[str], trace: list[str]) -> None:
    for name in names:
        original = getattr(module, name)

        def traced(state: dict, _original=original, _name=name):
            trace.append(_name)
            return _original(state)

        patches.append(patch.object(module, name, traced))


def _sanitize_logs(stdout: str) -> list[str]:
    prefixes = (
        "[Collection]", "[IOC Enrichment]", "[MITRE Lookup]", "[Correlation]",
        "[Prediction]", "[Reporting]", "[Playbook Resolver]", "[Response Planner]",
        "[Response Executor]", "[Closure]",
    )
    result = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith(prefixes):
            continue
        line = re.sub(r"INC-RYUK-[A-F0-9]+", "INC-RYUK-[REDACTED]", line)
        line = re.sub(r"ACT-[A-F0-9]+", "ACT-[REDACTED]", line)
        line = line.replace(str(ROOT), "<PROJECT>")
        result.append(line)
    return result


def run_audit() -> dict:
    started = time.perf_counter()
    raw_scenario = json.loads(SCENARIO.read_text(encoding="utf-8"))
    from medflow_investigator import run_investigation
    from medflow_executor import run_execution
    from models import incident_store
    from graphs.nodes.mitre_metadata import get_technique_metadata
    from graphs.nodes.reporting import _timeline
    from graphs.nodes.response_executor import ResponseExecutor
    from playbooks.loader import is_action_permitted, load_all_playbooks, playbook_by_id
    from integrations.firewall.connector import FirewallConnector
    import medflow_investigator.pipeline as investigator_pipeline
    import medflow_executor.pipeline as executor_pipeline

    trace: list[str] = []
    active_patches: list[object] = []
    _node_trace(
        active_patches,
        investigator_pipeline,
        [
            "collection_node", "ioc_enrichment_node", "mitre_lookup_node", "correlation_node",
            "prediction_node", "reporting_node", "initialize_incident_node", "risk_assessment_node",
            "playbook_resolver_node", "response_planner_node", "approval_node",
        ],
        trace,
    )
    _node_trace(active_patches, executor_pipeline, ["response_executor_node", "closure_node"], trace)

    run_temp = ROOT / f".pytest-tmp-ryuk-audit-{os.getpid()}-{uuid4().hex}"
    run_temp.mkdir()
    output = io.StringIO()
    try:
        for item in active_patches:
            item.start()
        with (
            patch.object(socket, "create_connection", _network_blocked),
            patch.object(socket.socket, "connect", _network_blocked),
            patch("graphs.nodes.ioc_enrichment._misp_preflight", return_value=(False, "MISP disabled by audit harness")),
            patch("graphs.nodes.ioc_enrichment.ChatGroq", return_value=object()),
            patch("graphs.nodes.ioc_enrichment.create_react_agent", side_effect=lambda *_a, **_k: SimpleNamespace(invoke=_agent_stub)),
            patch(
                "graphs.nodes.prediction._query_rag_with_evidence",
                side_effect=lambda question, *args, **kwargs: (_rag_stub(question, *args, **kwargs), []),
            ),
            patch("graphs.nodes.prediction._query_rag", side_effect=_rag_stub),
            patch("graphs.nodes.reporting._generate_narrative_with_retry", side_effect=RuntimeError("audit stub: Groq unavailable")),
            patch("time.sleep", return_value=None),
            patch.object(incident_store, "DEFAULT_DB_PATH", run_temp / "incidents.db"),
            contextlib.redirect_stdout(output),
        ):
            os.environ["GROQ_API_KEY"] = ""
            os.environ["MEDFLOW_SIMULATED_IOC_CACHE"] = "0"
            investigation = run_investigation(
                "ryuk", scenario_file=None, with_response=True, with_approval=True, with_execution=False
            )
            investigation_state = investigation.investigation_state
            execution = run_execution(investigation)
            final_state = execution.final_state
    finally:
        for item in reversed(active_patches):
            item.stop()

    elapsed = round(time.perf_counter() - started, 3)
    campaign = investigation_state.get("campaign", {})
    iocs_by_id = {str(ioc.get("alert_id", "")): ioc for ioc in investigation_state.get("enriched_iocs", [])}
    mappings = []
    for alert in raw_scenario:
        ioc = iocs_by_id.get(str(alert["id"]), {})
        technique = str(ioc.get("technique_confirmed") or "")
        mappings.append(
            {
                "alert_id": alert["id"],
                "timestamp": alert["timestamp"],
                "rule_id": alert.get("rule_id"),
                "event_type": alert.get("event_type"),
                "observed_technique_id": technique or None,
                "observed_technique_name": get_technique_metadata(technique).get("name") if technique else None,
                "enrichment_status": ioc.get("technique_source", "not_enriched"),
                "evidence_status": ioc.get("evidence_status", "uncertain"),
            }
        )

    playbook = playbook_by_id(
        investigation_state.get("matched_playbook"),
        load_all_playbooks(ROOT / "playbooks"),
    ) or {"actions": []}
    handler_names = set(ResponseExecutor(dry_run=True).handlers)
    action_tiers = {action["name"]: action["risk_tier"] for action in playbook.get("actions", [])}
    firewall_calls: list[list[str]] = []
    protected_ipv6_result = FirewallConnector(
        remote_runner=lambda command, _timeout=10: firewall_calls.append(command) or {"success": True, "returncode": 0}
    ).execute_action({"action_type": "BLOCK_IP", "target": "::1"})
    actions = []
    results_by_id = {str(result.get("action_id")): result for result in final_state.get("execution_results", [])}
    approval_by_id = {
        str(action.get("action_id")): action
        for action in (investigation_state.get("acknowledged_actions", [])
                       + investigation_state.get("approved_actions", [])
                       + investigation_state.get("rejected_actions", []))
    }
    for action in investigation_state.get("proposed_actions", []):
        action_id = str(action.get("action_id"))
        decision = approval_by_id.get(action_id, {})
        result = results_by_id.get(action_id, {})
        actions.append(
            {
                "action": action.get("action_type"),
                "tier": action_tiers.get(action.get("action_type")),
                "target": action.get("target"),
                "requires_approval": action.get("requires_approval"),
                "approval_decision": decision.get("decision", "pending"),
                "executor_status": result.get("execution_status", "not_run"),
                "dry_run_mode": bool(investigation.handoff.response_dry_run),
                "executor_result_is_dry_run": bool(result.get("details", "").startswith("[DRY RUN]")),
                "execution_details": result.get("details", ""),
                "handler_exists": action.get("action_type") in handler_names,
            }
        )

    session_target_fields = {
        "username", "user_name", "user", "account", "account_name",
        "account_id", "user_id", "session", "session_id", "session_identifier",
    }
    evidence_session_targets = {
        str(value).strip().casefold()
        for alert in investigation_state.get("raw_alerts", []) or []
        for key, value in alert.items()
        if str(key).casefold() in session_target_fields and str(value or "").strip()
    }
    revoke_session_targets_valid = all(
        str(action.get("target") or "").strip().casefold() in evidence_session_targets
        for action in investigation_state.get("proposed_actions", [])
        if str(action.get("action_type") or "").upper() == "REVOKE_SESSION"
    )

    ransomware = playbook
    safety_checks = {
        "isolate_endpoint_critical_permitted": is_action_permitted(ransomware, "ISOLATE_ENDPOINT", "Critical"),
        "kill_process_high_permitted": is_action_permitted(ransomware, "KILL_PROCESS", "High"),
        "notify_soc_critical_permitted": is_action_permitted(ransomware, "NOTIFY_SOC", "Critical"),
        "ipv6_loopback_block_rejected": protected_ipv6_result.get("error") == "protected_ip_blocked",
        "ipv6_loopback_remote_calls": len(firewall_calls),
        "revoke_session_has_evidence_backed_target": revoke_session_targets_valid,
    }
    report = final_state.get("report", investigation_state.get("report", ""))
    timeline = _timeline(investigation_state)
    report_time_lines = [
        line.strip()
        for line in report.splitlines()
        if re.match(r"- 202\d-\d\d-\d\dT", line.strip())
    ]
    correlated_ids = set(campaign.get("correlated_alert_ids", []))
    timeline_ids = {str(row.get("alert_id", "")) for row in timeline}
    node_names = [name.removesuffix("_node") for name in trace]
    evidence = {
        "audit": {
            "scenario_file": SCENARIO.name,
            "scenario_sha256": investigation_state.get("collection_metadata", {}).get("scenario_file_sha256"),
            "source": investigation_state.get("source"),
            "external_services": "stubbed; socket connections blocked",
            "response_mode": "dry_run",
            "duration_seconds": elapsed,
        },
        "scenario_input": [
            {
                "alert_id": alert.get("id"), "timestamp": alert.get("timestamp"),
                "source_ip": alert.get("source_ip"), "destination": alert.get("destination"),
                "rule_id": alert.get("rule_id"), "event_type": alert.get("event_type"),
            }
            for alert in raw_scenario
        ],
        "node_trace": {"executed": node_names, "skipped": [], "failed": []},
        "technique_mapping": {
            "per_alert": mappings,
            "primary_playbook_technique": investigation_state.get("playbook_selected_by_technique"),
            "primary_playbook_technique_name": investigation_state.get("matched_playbook_technique_name"),
            "confirmed_campaign_techniques": campaign.get("techniques_confirmed", []),
        },
        "correlation_and_timeline": {
            "correlated_alert_ids": sorted(correlated_ids),
            "excluded_alerts": campaign.get("excluded_alerts", []),
            "timeline_alert_ids": [row.get("alert_id") for row in timeline],
            "timeline_rows": timeline,
            "report_timeline_row_count": len(report_time_lines),
            "timeline_matches_correlated_scope": timeline_ids <= correlated_ids,
        },
        "prediction": investigation_state.get("prediction", {}),
        "incident": {
            "incident_id": "INC-RYUK-[REDACTED]" if final_state.get("incident_id") else None,
            "severity": final_state.get("severity"),
            "asset_criticality": final_state.get("asset_criticality"),
            "risk_score": final_state.get("risk_score"),
            "priority": final_state.get("priority"),
            "response_dry_run": final_state.get("response_dry_run"),
            "risk_formula": "round((severity/15*0.40 + criticality_weight/4*0.35 + confidence*0.25)*100); High=3, Critical=4",
            "confidence_score": final_state.get("confidence_score"),
            "campaign_stage": campaign.get("current_stage"),
        },
        "playbook_and_response": {
            "playbook_id": investigation_state.get("matched_playbook"),
            "selected_by_technique": investigation_state.get("playbook_selected_by_technique"),
            "action_tiers": action_tiers,
            "playbook_actions_without_executor_handler": sorted(set(action_tiers) - handler_names),
            "proposed_actions": actions,
            "proposed_actions_without_executor_handler": [item["action"] for item in actions if not item["handler_exists"]],
            "safety_checks": safety_checks,
            "execution_summary": final_state.get("execution_summary"),
            "closure_status": final_state.get("incident_status"),
        },
        "report": report,
        "report_consistency": {
            "report_includes_aggregate_risk_score": str(final_state.get("risk_score")) in report,
            "report_mentions_dry_run": "dry run" in report.lower(),
            "report_describes_executed_enforcement": any(token in report.lower() for token in ("blocked successfully", "endpoint isolated", "account disabled")),
            "report_distinguishes_proposed_approved_and_dry_run_results": all(
                token in report.lower()
                for token in ("proposed:", "acknowledged:", "approved:", "dry-run simulations recorded:")
            ),
            "report_timeline_line_count_matches_scoped_alert_count": len(report_time_lines) == len(correlated_ids),
        },
        "sanitized_logs": _sanitize_logs(output.getvalue()),
        "limitations": [
            "IOC attribution, RAG, and narrative generation used deterministic stubs; no external threat-intel or LLM conclusions are represented as live results.",
            "No live connector handler was called; executor action records are dry-run acknowledgments only.",
        ],
    }
    AUDIT_DIR.mkdir(exist_ok=True)
    EVIDENCE_FILE.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    return evidence


if __name__ == "__main__":
    result = run_audit()
    summary = {
        "evidence_file": str(EVIDENCE_FILE.relative_to(ROOT)),
        "nodes_executed": len(result["node_trace"]["executed"]),
        "correlated_alerts": len(result["correlation_and_timeline"]["correlated_alert_ids"]),
        "predicted_next_techniques": result["prediction"].get("predicted_next_techniques"),
        "risk_score": result["incident"].get("risk_score"),
        "execution_summary": result["playbook_and_response"].get("execution_summary"),
        "duration_seconds": result["audit"]["duration_seconds"],
    }
    print(json.dumps(summary, indent=2))

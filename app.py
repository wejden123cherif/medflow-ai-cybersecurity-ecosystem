from __future__ import annotations

import argparse
import os
import sys
import time

# Fix UnicodeEncodeError on Windows (cp1252 default) when the pipeline
# or LLM responses contain non-ASCII characters (en-dashes, arrows, etc.).
# Set at both environment level (affects child processes/submodules) and
# stream level (affects this process's stdout/stderr directly).
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from config import (
    ACTOR_DB_DIR,
    ATTACK_DB_DIR,
    DETECTION_DB_DIR,
    ENTERPRISE_ATTACK_JSON,
    MITRE_CTI_DIR,
    MODEL_CACHE_DIR,
    REDTEAM_DB_DIR,
    ROOT_DIR,
    VECTOR_DB_DIR,
    ensure_project_dirs,
    load_settings,
)


AGENTS = ("redteam", "cti", "attribution", "detection")
DATABASES = ("attack", "redteam", "actor", "detection")


def _coerce_action(action: object) -> dict[str, object]:
    if isinstance(action, dict):
        return action
    if hasattr(action, "to_dict"):
        return action.to_dict()
    return {
        "action_type": getattr(action, "action_type", str(action)),
        "requires_approval": getattr(action, "requires_approval", None),
        "reversible": getattr(action, "reversible", None),
    }


def _friendly_playbook_name(playbook: dict[str, object] | None) -> str:
    if not playbook:
        return "Default"
    technique_id = str(playbook.get("mitre_technique_id") or "DEFAULT")
    if technique_id.upper() == "DEFAULT":
        return "Default"
    if "RANSOMWARE" in technique_id.upper():
        return "Ransomware"
    return technique_id.replace("_", " ").title()


def format_response_plan_demo(state: dict[str, object], playbook_name: str = "Default", playbook: dict[str, object] | None = None) -> str:
    incident_title = str(state.get("incident_title") or state.get("title") or "Unknown Incident")
    risk_score = state.get("risk_score") or 0
    priority = state.get("priority") or "Unknown"
    proposed_actions = list(state.get("proposed_actions") or [])

    action_lines: list[str] = []
    for action in proposed_actions:
        action_data = _coerce_action(action)
        action_type = str(action_data.get("action_type") or action_data.get("name") or "UNKNOWN_ACTION").upper()
        requires_approval = action_data.get("requires_approval")
        if requires_approval is None:
            approval_text = "UNKNOWN"
        else:
            approval_text = "YES" if bool(requires_approval) else "NO"

        tier = "unknown"
        if playbook:
            for playbook_action in playbook.get("actions", []) or []:
                if playbook_action.get("name") == action_data.get("action_type") or playbook_action.get("name") == action_data.get("name"):
                    tier = str(playbook_action.get("risk_tier", "unknown"))
                    break

        action_lines.extend(
            [
                f"[ ] {action_type}",
                f"    Tier: {tier}",
                f"    Approval Required: {approval_text}",
                "",
            ]
        )

    if not action_lines:
        action_lines = ["None proposed.", ""]

    require_human_approval = bool(state.get("planner_divergence_flag")) or any(
        bool(_coerce_action(action).get("requires_approval")) for action in proposed_actions
    )
    execution_summary = state.get("execution_summary") or {}
    if int(execution_summary.get("total_actions", 0) or 0) > 0:
        status = "DRY-RUN EXECUTION COMPLETE"
    elif state.get("approved_actions") or state.get("acknowledged_actions") or state.get("rejected_actions"):
        status = "APPROVAL GATE COMPLETE"
    else:
        status = "WAITING FOR HUMAN APPROVAL" if require_human_approval else "READY FOR REVIEW"

    return "\n".join(
        [
            "===========================",
            "INCIDENT RESPONSE PLAN",
            "===========================",
            "",
            "Incident:",
            incident_title,
            "",
            "Risk:",
            f"{priority} ({risk_score})",
            "",
            "Playbook:",
            playbook_name or _friendly_playbook_name(playbook),
            "",
            "Recommended Actions:",
            "",
            *action_lines,
            "STATUS:",
            status,
        ]
    )


def status() -> None:
    ensure_project_dirs()
    settings = load_settings()
    print(f"Project root: {ROOT_DIR}")
    print(f"MITRE CTI repo: {MITRE_CTI_DIR}")
    print(f"MITRE enterprise bundle ready: {ENTERPRISE_ATTACK_JSON.exists()}")
    print(f"Vector DB root: {VECTOR_DB_DIR}")
    print(f"Model cache: {MODEL_CACHE_DIR}")
    print(f"Groq key configured: {bool(settings.groq_api_key)}")
    print(f"Main model: {settings.main_model}")
    print(f"Secondary model: {settings.secondary_model}")
    print(f"Embedding model: {settings.embedding_model}")
    print("Vector DB folders:")
    for path in (ATTACK_DB_DIR, REDTEAM_DB_DIR, ACTOR_DB_DIR, DETECTION_DB_DIR):
        print(f"  - {path}")


def model_from_choice(choice: str) -> str:
    settings = load_settings()
    if choice == "main":
        return settings.main_model
    if choice == "secondary":
        return settings.secondary_model
    return choice


def ask(agent: str, question: str, model_choice: str) -> None:
    model = model_from_choice(model_choice)
    if agent == "redteam":
        from agents.redteam_agent import ask as ask_agent
    elif agent == "cti":
        from agents.cti_agent import ask as ask_agent
    elif agent == "attribution":
        from agents.attribution_agent import ask as ask_agent
    elif agent == "detection":
        from agents.detection_agent import ask as ask_agent
    else:
        raise ValueError(f"Unknown agent: {agent}")
    print(ask_agent(question, model=model))


def raw_search(database: str, question: str, show_all: bool = False) -> None:
    from rag.similarity_search import DATABASES as DB_PATHS
    from rag.similarity_search import format_results, similarity_search

    results = similarity_search(question, DB_PATHS[database], n_results=5)
    print(format_results(results, top_only=not show_all))


def compare(agent: str, question: str) -> None:
    settings = load_settings()
    for label, model in (("main", settings.main_model), ("secondary", settings.secondary_model)):
        started = time.perf_counter()
        print(f"\n=== {label.upper()} MODEL: {model} ===\n")
        ask(agent, question, model)
        elapsed = time.perf_counter() - started
        print(f"\nResponse time: {elapsed:.2f}s")


def investigate(
    scenario: str,
    scenario_file: str | None = None,
    with_response: bool = False,
    with_approval: bool = False,
    execute_response: bool = False,
) -> None:
    from graphs.threat_intel_graph import run_threat_intel
    from playbooks.loader import load_all_playbooks, playbook_by_id

    # If scenario_file is provided, force scenario to 'live' to run live-first logic
    actual_scenario = "live" if scenario_file else scenario
    response_requested = with_response or with_approval or execute_response
    approval_requested = with_approval or execute_response or with_response
    execution_requested = execute_response or with_response

    final_state = run_threat_intel(
        actual_scenario,
        scenario_file=scenario_file,
        with_response=response_requested,
        with_approval=approval_requested,
        with_execution=execution_requested,
    )
    campaign = final_state.get("campaign", {})
    prediction = final_state.get("prediction", {})
    collection_metadata = final_state.get("collection_metadata", {})

    print("\n" + "=" * 60)
    print("INVESTIGATION SUMMARY")
    print("=" * 60)
    
    # Report live wazuh usage or fallback status
    source = final_state.get("source", "unknown")
    fallback_reason = collection_metadata.get("fallback_reason")
    if fallback_reason:
        print(f"Data Source: FALLBACK (Live Wazuh failed: {fallback_reason})")
        print(f"Fallback File: {collection_metadata.get('source_file')}")
    else:
        print(f"Data source: {collection_metadata.get('data_source', 'unknown')} ({source})")

    print(f"Alerts collected: {len(final_state.get('raw_alerts', []))}")
    print(f"Live alerts: {len(final_state.get('live_alerts', []))}")
    print(f"Simulated alerts: {len(final_state.get('simulated_alerts', []))}")
    if collection_metadata.get("min_rule_level") is not None:
        print(f"Wazuh min rule level: {collection_metadata.get('min_rule_level')}")
        print(f"Wazuh recent window: {collection_metadata.get('recent_hours')}h")
        print(f"Wazuh lookback window: {collection_metadata.get('lookback_days')}d")
        print(f"Wazuh selected window: {collection_metadata.get('selected_window', 'unknown')}")
        print(f"Wazuh lookback matches: {collection_metadata.get('lookback_alert_count', 0)}")
        print(f"Wazuh excluded rule IDs: {', '.join(collection_metadata.get('excluded_rule_ids', [])) or 'none'}")
        print(f"Wazuh excluded groups: {', '.join(collection_metadata.get('excluded_groups', [])) or 'none'}")
        top_alerts = sorted(
            final_state.get("raw_alerts", []),
            key=lambda alert: int(alert.get("risk_score", 0) or 0),
            reverse=True,
        )[:3]
        if top_alerts:
            print("Top risk alerts:")
            for alert in top_alerts:
                print(
                    "  - "
                    f"risk={alert.get('risk_score', 0)} "
                    f"priority={alert.get('risk_priority', 'unknown')} | "
                    f"rule={alert.get('wazuh_rule_id', 'unknown')} | "
                    f"{alert.get('event_type', 'unknown')}"
                )
    print(f"IOCs enriched: {len(final_state.get('enriched_iocs', []))}")
    print(f"Average confidence score: {final_state.get('confidence_score', 0.0):.2f}")
    if campaign:
        print(f"Campaign stage: {campaign.get('current_stage', 'Unknown')}")
        print(f"Attack type: {campaign.get('attack_type', 'Unknown')}")
        print(f"Attributed actor: {campaign.get('attributed_actor', 'Unknown')}")
        print(f"Campaign confidence: {campaign.get('campaign_confidence', 0.0):.0%}")
        print(f"Time to next stage: {prediction.get('time_to_next_stage', 'Unknown')}")

    print("\nConfirmed IOCs:")
    for ioc in final_state.get("enriched_iocs", []):
        print(
            "- "
            f"Technique: {ioc.get('technique_confirmed', 'Unknown')} | "
            f"Actor: {ioc.get('actor_name', 'Unknown')} | "
            f"Confidence: {ioc.get('confidence', 0.0):.2f}"
        )

    # Risk & Response details
    print("\n" + "=" * 60)
    print("RISK ASSESSMENT & RESPONSE DETAILS")
    print("=" * 60)
    risk_score = final_state.get("risk_score")
    priority = final_state.get("priority")
    print(f"Risk Score: {risk_score}")
    print(f"Priority: {priority}")
    
    # Display the canonical playbook selected by the resolver node.
    playbook_name = final_state.get("matched_playbook_technique_id") or "DEFAULT"
    selected_playbook = None
    try:
        selected_playbook = playbook_by_id(
            str(final_state.get("matched_playbook") or ""),
            load_all_playbooks(ROOT_DIR / "playbooks"),
        )
    except Exception:
        pass
    print(f"Matched Playbook: {playbook_name}")
    if final_state.get("matched_playbook"):
        print(
            "Playbook Policy: "
            f"{final_state.get('matched_playbook')} {final_state.get('playbook_version')}"
        )

    # Asset Criticality + Override Fired check
    asset_criticality = final_state.get("asset_criticality", "Low")
    affected_asset_type = final_state.get("affected_asset_type", "unknown")
    override_fired = affected_asset_type in ("ehr", "medical_device")
    override_str = " [HEALTHCARE CRITICALITY OVERRIDE FIRED]" if override_fired else ""
    print(f"Asset Criticality: {asset_criticality}{override_str}")
    print(f"Affected Asset Type: {affected_asset_type}")

    if response_requested:
        print("\n" + format_response_plan_demo(final_state, playbook_name=_friendly_playbook_name(selected_playbook), playbook=selected_playbook))
        print("\nProposed Actions:")
        proposed_actions = final_state.get("proposed_actions") or []
        if not proposed_actions:
            print("  None proposed.")
        for action in proposed_actions:
            action_data = _coerce_action(action)
            print(f"  - Action: {action_data.get('action_type')}")
            print(f"    Target: {action_data.get('target')}")
            print(f"    Justification: {action_data.get('justification')}")
            print(f"    Requires Approval: {action_data.get('requires_approval')}")
            print(f"    Reversible: {action_data.get('reversible')}")

        if approval_requested:
            approved_actions = final_state.get("approved_actions") or []
            acknowledged_actions = final_state.get("acknowledged_actions") or []
            rejected_actions = final_state.get("rejected_actions") or []
            print("\nAcknowledged Actions (No Approval Required):")
            if not acknowledged_actions:
                print("  None.")
            for action in acknowledged_actions:
                action_data = _coerce_action(action)
                print(
                    "  - "
                    f"{action_data.get('action_type')} on {action_data.get('target')} | "
                    f"decision={action_data.get('decision')} | "
                    f"by={action_data.get('approved_by')}"
                )
                print(f"    Justification: {action_data.get('approval_justification')}")

            print("\nApproved Actions (Human Approved):")
            if not approved_actions:
                print("  None.")
            for action in approved_actions:
                action_data = _coerce_action(action)
                print(
                    "  - "
                    f"{action_data.get('action_type')} on {action_data.get('target')} | "
                    f"decision={action_data.get('decision')} | "
                    f"by={action_data.get('approved_by')}"
                )
                print(f"    Justification: {action_data.get('approval_justification')}")

            print("\nRejected Actions:")
            if not rejected_actions:
                print("  None.")
            for action in rejected_actions:
                action_data = _coerce_action(action)
                print(
                    "  - "
                    f"{action_data.get('action_type')} on {action_data.get('target')} | "
                    f"by={action_data.get('approved_by')}"
                )
                print(f"    Justification: {action_data.get('approval_justification')}")

            if execution_requested:
                summary = final_state.get("execution_summary") or {}
                execution_results = final_state.get("execution_results") or []
                print("\nExecution Report:")
                print(
                    "  "
                    f"total={summary.get('total_actions', 0)} "
                    f"successful={summary.get('successful', 0)} "
                    f"failed={summary.get('failed', 0)} "
                    f"skipped={summary.get('skipped', 0)}"
                )
                if not execution_results:
                    print("  No execution results.")
                for result in execution_results:
                    print(
                        "  - "
                        f"{result.get('action_name') or result.get('action')} on {result.get('target')} | "
                        f"{result.get('execution_status')}"
                    )
                    print(f"    {result.get('details')}")
    else:
        print("\nProposed Actions: (Skipped, use --with-response to include approval and dry-run execution)")

    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE REPORT")
    print("=" * 60)
    print(final_state.get("report", ""))

    errors = final_state.get("errors", [])
    if errors:
        print("\nWARNINGS")
        for error in errors:
            print(f"  - {error}")


def main() -> None:
    parser = argparse.ArgumentParser(description="MedFlow AI Cybersecurity Ecosystem")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show project setup status.")

    ask_parser = subparsers.add_parser("ask", help="Ask a MedFlow agent.")
    ask_parser.add_argument("--agent", choices=AGENTS, required=True)
    ask_parser.add_argument("--model", default="main", help="Use 'main', 'secondary', or an explicit Groq model ID.")
    ask_parser.add_argument("question")

    search_parser = subparsers.add_parser("search", help="Raw ChromaDB similarity search with no LLM.")
    search_parser.add_argument("--db", choices=DATABASES, required=True)
    search_parser.add_argument("--all", action="store_true", help="Show all top-5 results instead of just the best match.")
    search_parser.add_argument("question")

    compare_parser = subparsers.add_parser("compare", help="Ask one agent with both main and secondary models.")
    compare_parser.add_argument("--agent", choices=AGENTS, required=True)
    compare_parser.add_argument("question")

    investigate_parser = subparsers.add_parser("investigate", help="Run the LangGraph threat investigation workflow.")
    investigate_parser.add_argument("--scenario", default="ryuk", help="Scenario name to investigate.")
    investigate_parser.add_argument("--file", help="Path to simulated alerts file (triggers wazuh-live-with-fallback test).")
    investigate_parser.add_argument("--with-response", action="store_true", help="Run the full response flow: planner, interactive approval gate, and dry-run executor.")
    investigate_parser.add_argument("--with-approval", action="store_true", help="Include response planning and block for human approval decisions.")
    investigate_parser.add_argument("--execute-response", action="store_true", help="Run the safe dry-run response executor after approval.")

    args = parser.parse_args()
    if args.command == "status":
        status()
    elif args.command == "ask":
        ask(args.agent, args.question, args.model)
    elif args.command == "search":
        raw_search(args.db, args.question, show_all=args.all)
    elif args.command == "compare":
        compare(args.agent, args.question)
    elif args.command == "investigate":
        investigate(
            args.scenario,
            scenario_file=args.file,
            with_response=args.with_response,
            with_approval=args.with_approval,
            execute_response=args.execute_response,
        )


if __name__ == "__main__":
    main()

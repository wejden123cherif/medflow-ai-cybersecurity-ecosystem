"""
scripts/test_demo_actions.py
-----------------------------
End-to-end demo test for the supervisor demonstration.

Tests two real actions:
  1. DROP_CONNECTION  — writes a drop rule to suricata/rules/local.rules
                        and calls suricatasc reload-rules on the running
                        medflow-suricata Docker container.
  2. NOTIFY_SOC       — generates an LLM-written incident email and
                        sends it to cherifwejden7@gmail.com via Gmail SMTP.

Before running:
  - Set SMTP_USER and SMTP_PASSWORD in .env
    (SMTP_PASSWORD must be a Gmail App Password, not your Gmail password)
  - Ensure medflow-suricata container is running:
      cd suricata && docker-compose up -d
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from graphs.nodes.response_executor import response_executor_node
from graphs.state import IncidentState
from models.incident import ResponseAction


def test_demo_actions() -> None:
    print("Constructing mock brute-force incident state...")

    approved_actions = [
        ResponseAction(
            action_id="ACT-IDS-DROP",
            action_type="DROP_CONNECTION",
            target="192.168.1.100",
            status="approved",
            justification="Drop active connection from brute-forcing IP",
            requested_by="System",
            requires_approval=False,
        ),
        ResponseAction(
            action_id="ACT-EMAIL-SOC",
            action_type="NOTIFY_SOC",
            target="cherifwejden7@gmail.com",
            status="approved",
            justification="Notify SOC of the brute-force incident",
            requested_by="System",
            requires_approval=False,
        ),
    ]

    state: IncidentState = {
        "incident_id": "INC-DEMO-001",
        "created_at": "2026-07-28T10:00:00Z",
        "incident_status": "in_progress",
        "severity": 10,
        "incident_title": "SSH Brute Force — Credential Access",
        "description": "Repeated failed SSH login attempts from external IP 192.168.1.100.",
        "incident_category": "Credential Access",
        "schema_version": "1.0",
        "source": "simulated",
        "campaign": {
            "current_stage": "Credential Access",
            "attributed_actor": "Unknown Brute-Forcer",
            "attack_type": "ssh_brute_force",
            "techniques_confirmed": ["T1110", "T1110.001"],
        },
        "affected_assets": ["ssh-gateway-01"],
        "confidence_score": 0.92,
        "allowed_actions": [{"name": "DROP_CONNECTION"}, {"name": "NOTIFY_SOC"}],
        "approved_actions": approved_actions,
        "response_dry_run": False,  # LIVE MODE — real connectors
    }

    print("\nExecuting response node in LIVE mode...")
    results = response_executor_node(state)

    print("\n" + "=" * 60)
    print("EXECUTION SUMMARY")
    print("=" * 60)
    print(json.dumps(results["execution_summary"], indent=2))

    print("\nSUCCESSFUL ACTIONS:")
    for action in results.get("executed_actions", []):
        print(f"  [OK] {action['action_name']}: {action['details']}")

    print("\nFAILED ACTIONS:")
    for action in results.get("failed_actions", []):
        print(f"  [!!] {action['action_name']}: {action['details']}")
        if action.get("error"):
            print(f"    Error code: {action['error']}")

    # Verify rule on disk
    rules_path = os.path.join(os.path.dirname(__file__), "..", "suricata", "rules", "local.rules")
    print("\nSURICATA RULE VERIFICATION (local.rules tail):")
    try:
        with open(rules_path) as f:
            lines = f.readlines()
        for line in lines[-6:]:
            print(" ", line.rstrip())
    except FileNotFoundError:
        print("  (local.rules not found)")


if __name__ == "__main__":
    test_demo_actions()

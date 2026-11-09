"""Offline response demonstration. This script is safe to run directly."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from graphs.nodes.response_executor import response_executor_node
from graphs.state import IncidentState
from models.incident import ResponseAction


def test_demo_actions() -> None:
    actions = [
        ResponseAction(
            action_id="ACT-IDS-DROP",
            action_type="DROP_CONNECTION",
            target="192.0.2.100:45231",
            status="approved",
            justification="Demonstrate an approved response preview.",
            requested_by="demo-analyst",
            requires_approval=True,
        ),
        ResponseAction(
            action_id="ACT-EMAIL-SOC",
            action_type="NOTIFY_SOC",
            target="SOC team",
            status="approved",
            justification="Demonstrate a notification preview.",
            requested_by="demo-analyst",
            requires_approval=True,
        ),
    ]
    state: IncidentState = {
        "incident_id": "INC-DEMO-OFFLINE",
        "created_at": "2026-07-28T10:00:00Z",
        "incident_status": "in_progress",
        "severity": 8,
        "incident_title": "Simulated SSH Brute Force",
        "description": "Simulated repeated failed SSH login attempts.",
        "incident_category": "Credential Access",
        "schema_version": "1.0",
        "source": "simulated",
        "allowed_actions": [{"name": "DROP_CONNECTION"}, {"name": "NOTIFY_SOC"}],
        "approved_actions": actions,
        "proposed_actions": actions,
        "response_dry_run": True,
    }

    results = response_executor_node(state)
    print(json.dumps(results["execution_summary"], indent=2))
    for result in results.get("execution_results", []):
        print(f"{result['action_name']}: {result['execution_status']} — {result['details']}")


if __name__ == "__main__":
    test_demo_actions()
"""
tests/test_e2e_pipeline.py
==========================
End-to-End integration tests for the MedFlow AI incident response pipeline.

These tests run the FULL graph from collection_node → ... → response_executor_node
without mocking intermediate nodes. Each test seeds the approval gate with
pre-determined decisions so the graph never blocks on input().

Coverage areas:
  1. Full ryuk scenario: simulated data → execution (happy path)
  2. Node handoff contract: every adjacent pair of nodes must not drop
     required state keys.
  3. Audit trail completeness: audit_log must contain entries from all
     major pipeline stages.
  4. Non-interactive safety: graph must never call input() when
     approval_decisions are pre-seeded.
  5. Execution counts: at least one action must be executed (Tier 1).
  6. Fallback path: no LLM key → deterministic proposals must still work.
  7. Credential access scenario playbook routing.
  8. Execution summary consistency: successful + failed + skipped == total.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "simulated_alerts"
RYUK_FILE = DATA_DIR / "ryuk_scenario.json"


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _MockGroqClient:
    """
    Stand-in for groq.Groq that returns a fixed Tier-1 NOTIFY_SOC proposal.
    Used for mocking the response_planner_node's direct groq.Groq() call.
    """

    def __init__(self, *args, **kwargs):
        pass

    @property
    def chat(self):
        return self

    @property
    def completions(self):
        return self

    def create(self, *args, **kwargs):
        payload = (
            "<proposals>\n"
            "[\n"
            '  {"action": "NOTIFY_SOC", "target": "SOC Team",'
            ' "reason": "E2E test deterministic proposal."}\n'
            "]\n"
            "</proposals>"
        )
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=payload))]
        )


def _make_mock_chat_groq():
    """
    Create a MagicMock that mimics ChatGroq + create_react_agent for ioc_enrichment.
    The mock agent returns a valid (but empty) enrichment result.
    """
    mock_llm = MagicMock()
    mock_agent = MagicMock()
    mock_agent.invoke.return_value = {
        "messages": [
            MagicMock(content='{"technique": "T1486", "actor": "unknown", "cves": []}')
        ]
    }
    return mock_llm, mock_agent


# ---------------------------------------------------------------------------
# Core fixture: patch all external I/O for a full graph run
# ---------------------------------------------------------------------------

@pytest.fixture()
def patch_all_llm(monkeypatch):
    """
    Patch every LLM call in the pipeline so no real API key is needed:
      1. groq.Groq → _MockGroqClient (used by response_planner_node)
      2. ChatGroq + create_react_agent in ioc_enrichment_node → mock agent
      3. config.load_settings → returns a Settings with a dummy key
    """
    from config import Settings

    monkeypatch.setattr(
        "config.load_settings",
        lambda: Settings(
            groq_api_key="mock-key-e2e",
            main_model="mock-model",
            secondary_model="mock-model",
            embedding_model="mock-embedding",
        ),
    )
    # Mock groq.Groq for the response_planner (direct groq usage)
    monkeypatch.setitem(
        __import__("sys").modules,
        "groq",
        SimpleNamespace(Groq=_MockGroqClient),
    )

    # Mock ChatGroq and create_react_agent at the ioc_enrichment_node module level
    mock_llm, mock_agent = _make_mock_chat_groq()
    with (
        patch("graphs.nodes.ioc_enrichment.ChatGroq", return_value=mock_llm),
        patch("graphs.nodes.ioc_enrichment.create_react_agent", return_value=mock_agent),
    ):
        yield


@pytest.fixture()
def full_pipeline_result(patch_all_llm):
    """Run the complete ryuk graph with execution and return final state."""
    from graphs.threat_intel_graph import run_threat_intel

    return run_threat_intel(
        scenario="ryuk",
        scenario_file=str(RYUK_FILE),
        with_response=True,
        with_approval=True,
        with_execution=True,
    )


# ---------------------------------------------------------------------------
# 1. Full pipeline smoke test — ryuk scenario → execution
# ---------------------------------------------------------------------------

class TestFullPipelineRyukExecution:
    """Run the entire graph with execution enabled and verify output schema."""

    def test_incident_id_is_generated(self, full_pipeline_result):
        r = full_pipeline_result
        assert r.get("incident_id"), "incident_id must be set"
        assert r["incident_id"].startswith("INC-RYUK-")

    def test_raw_alerts_populated(self, full_pipeline_result):
        assert len(full_pipeline_result.get("raw_alerts", [])) > 0

    def test_source_is_simulated(self, full_pipeline_result):
        assert full_pipeline_result.get("source") == "simulated"

    def test_risk_score_is_set(self, full_pipeline_result):
        rs = full_pipeline_result.get("risk_score")
        assert isinstance(rs, int)
        assert 0 <= rs <= 100

    def test_playbook_is_resolved(self, full_pipeline_result):
        assert full_pipeline_result.get("matched_playbook") is not None

    def test_proposed_actions_are_non_empty(self, full_pipeline_result):
        assert len(full_pipeline_result.get("proposed_actions", [])) > 0

    def test_execution_summary_present(self, full_pipeline_result):
        summary = full_pipeline_result.get("execution_summary", {})
        assert "total_actions" in summary
        assert "successful" in summary
        assert "failed" in summary
        assert "skipped" in summary

    def test_at_least_one_action_executed(self, full_pipeline_result):
        # NOTIFY_SOC is Tier 1 (no approval required) → always executes
        assert full_pipeline_result["execution_summary"].get("successful", 0) >= 1

    def test_executed_actions_have_correct_schema(self, full_pipeline_result):
        for action in full_pipeline_result.get("executed_actions", []):
            assert isinstance(action, dict)
            assert "action_name" in action
            assert "execution_status" in action
            assert action["execution_status"] == "success"

    def test_audit_log_is_non_empty(self, full_pipeline_result):
        audit_log = full_pipeline_result.get("audit_log", [])
        assert isinstance(audit_log, list)
        assert len(audit_log) >= 3

    def test_errors_is_a_list(self, full_pipeline_result):
        assert isinstance(full_pipeline_result.get("errors", []), list)

    def test_collection_metadata_has_scenario(self, full_pipeline_result):
        meta = full_pipeline_result.get("collection_metadata", {})
        assert meta.get("scenario") == "ryuk"

    def test_summary_counts_are_self_consistent(self, full_pipeline_result):
        s = full_pipeline_result.get("execution_summary", {})
        total = s.get("total_actions", 0)
        assert s.get("successful", 0) + s.get("failed", 0) + s.get("skipped", 0) == total

    def test_executed_actions_count_matches_summary(self, full_pipeline_result):
        s = full_pipeline_result.get("execution_summary", {})
        assert len(full_pipeline_result.get("executed_actions", [])) == s.get("successful", 0)
        assert len(full_pipeline_result.get("failed_actions", [])) == s.get("failed", 0)


# ---------------------------------------------------------------------------
# 2. Audit trail completeness
# ---------------------------------------------------------------------------

class TestAuditTrailCoverage:
    """Verify the audit log captures events from every major pipeline stage."""

    def test_risk_score_computation_is_audited(self, full_pipeline_result):
        actions = [e.get("action", "") for e in full_pipeline_result.get("audit_log", [])]
        assert any("risk_score_computed" in a for a in actions)

    def test_playbook_resolution_is_audited(self, full_pipeline_result):
        actions = [e.get("action", "") for e in full_pipeline_result.get("audit_log", [])]
        assert any("playbook_resolved" in a for a in actions)

    def test_planning_completion_is_audited(self, full_pipeline_result):
        actions = [e.get("action", "") for e in full_pipeline_result.get("audit_log", [])]
        assert any("response_planning_completed" in a for a in actions)

    def test_approval_gate_completion_is_audited(self, full_pipeline_result):
        actions = [e.get("action", "") for e in full_pipeline_result.get("audit_log", [])]
        assert any("approval_gate_completed" in a for a in actions)

    def test_action_execution_is_audited(self, full_pipeline_result):
        actions = [e.get("action", "") for e in full_pipeline_result.get("audit_log", [])]
        assert any(
            "ACTION_EXECUTED" in a or "ACTION_EXECUTION_FAILED" in a or "ACTION_EXECUTION_SKIPPED" in a
            for a in actions
        )

    def test_audit_log_has_timestamps(self, full_pipeline_result):
        for entry in full_pipeline_result.get("audit_log", []):
            assert "timestamp" in entry, f"Audit entry missing timestamp: {entry}"

    def test_audit_log_has_actors(self, full_pipeline_result):
        for entry in full_pipeline_result.get("audit_log", []):
            assert "actor" in entry, f"Audit entry missing actor: {entry}"


# ---------------------------------------------------------------------------
# 3. Node-to-node state handoff contracts
# ---------------------------------------------------------------------------

class TestNodeHandoffContracts:
    """
    Verify that each node's output contains the fields consumed by the next.
    Runs nodes in isolation with realistic inputs to catch key-name mismatches.
    """

    def _make_base_state(self) -> dict[str, Any]:
        with open(RYUK_FILE, encoding="utf-8") as f:
            raw_alerts = json.load(f)
        return {
            "scenario": "ryuk",
            "source": "simulated",
            "raw_alerts": raw_alerts,
            "live_alerts": [],
            "simulated_alerts": raw_alerts,
            "collection_metadata": {"scenario": "ryuk", "data_source": "simulated"},
            "enriched_iocs": [],
            "confidence_score": 0.85,
            "mitre_context": {},
            "campaign": {"attack_type": "ransomware", "techniques_confirmed": ["T1486"]},
            "prediction": {},
            "report": "",
            "loop_count": 0,
            "errors": [],
            "audit_log": [],
            "matched_playbook": None,
            "matched_playbook_technique_id": None,
            "matched_playbook_technique_name": None,
            "playbook_version": None,
            "playbook_source": None,
            "playbook_selected_by_technique": None,
            "allowed_actions": [],
            "proposed_actions": [],
            "approved_actions": [],
            "acknowledged_actions": [],
            "rejected_actions": [],
            "executed_actions": [],
            "failed_actions": [],
            "execution_summary": {},
            "approval_decisions": {},
            "approval_approver": None,
            "execution_results": [],
        }

    def test_initialize_incident_produces_required_fields(self):
        from graphs.threat_intel_graph import initialize_incident_node

        out = initialize_incident_node(self._make_base_state())
        required = {
            "incident_id", "incident_title", "incident_category",
            "incident_status", "timestamp", "schema_version",
            "severity", "asset_criticality", "affected_assets",
        }
        assert not (required - set(out)), f"Missing: {required - set(out)}"

    def test_risk_node_produces_required_fields(self):
        from graphs.threat_intel_graph import initialize_incident_node
        from graphs.nodes.risk import risk_assessment_node

        base = self._make_base_state()
        inc = {**base, **initialize_incident_node(base)}
        out = risk_assessment_node(inc)

        assert "risk_score" in out
        assert "priority" in out
        assert "requires_human_review" in out
        assert "audit_log" in out

    def test_playbook_resolver_produces_required_fields(self):
        from graphs.threat_intel_graph import initialize_incident_node
        from graphs.nodes.risk import risk_assessment_node
        from graphs.nodes.playbook_resolver import playbook_resolver_node

        base = self._make_base_state()
        inc = {**base, **initialize_incident_node(base)}
        risk = {**inc, **risk_assessment_node(inc)}
        out = playbook_resolver_node(risk)

        assert out.get("matched_playbook") is not None
        assert "allowed_actions" in out
        assert isinstance(out["allowed_actions"], list)
        assert len(out["allowed_actions"]) > 0

    def test_response_planner_produces_proposed_actions(self, patch_all_llm):
        from graphs.threat_intel_graph import initialize_incident_node
        from graphs.nodes.risk import risk_assessment_node
        from graphs.nodes.playbook_resolver import playbook_resolver_node
        from graphs.nodes.response_planner import response_planner_node

        base = self._make_base_state()
        inc = {**base, **initialize_incident_node(base)}
        risk = {**inc, **risk_assessment_node(inc)}
        pb = {**risk, **playbook_resolver_node(risk)}
        out = response_planner_node(pb)

        assert "proposed_actions" in out
        assert isinstance(out["proposed_actions"], list)
        assert len(out["proposed_actions"]) >= 1

    def test_proposed_actions_have_required_keys(self, patch_all_llm):
        from graphs.threat_intel_graph import initialize_incident_node
        from graphs.nodes.risk import risk_assessment_node
        from graphs.nodes.playbook_resolver import playbook_resolver_node
        from graphs.nodes.response_planner import response_planner_node

        base = self._make_base_state()
        inc = {**base, **initialize_incident_node(base)}
        risk = {**inc, **risk_assessment_node(inc)}
        pb = {**risk, **playbook_resolver_node(risk)}
        planner_out = response_planner_node(pb)

        required_action_keys = {
            "action_id", "action_type", "target",
            "status", "requires_approval", "reversible",
        }
        for action in planner_out["proposed_actions"]:
            missing = required_action_keys - set(action)
            assert not missing, f"Action missing keys {missing}: {action}"

    def test_approval_gate_auto_acknowledges_tier1(self):
        """Approval gate must auto-acknowledge Tier-1 (requires_approval=False) actions."""
        from graphs.nodes.approval import approval_node

        base = self._make_base_state()
        base.update({
            "incident_id": "INC-HANDOFF-001",
            "incident_title": "Handoff Test",
            "incident_category": "ransomware",
            "incident_status": "investigating",
            "timestamp": "2026-07-17T10:00:00Z",
            "schema_version": "1.0.0",
            "severity": 12,
            "asset_criticality": "High",
            "affected_assets": ["ehr-fileserver-02"],
            "matched_playbook": "ransomware_impact",
            "playbook_version": "v1",
            "allowed_actions": [
                {"name": "NOTIFY_SOC", "risk_tier": 1, "requires_approval": False},
            ],
            "proposed_actions": [{
                "action_id": "ACT-H-001",
                "action_type": "NOTIFY_SOC",
                "target": "SOC Team",
                "status": "proposed",
                "justification": "Tier 1 handoff test.",
                "requested_by": "system:response_planner_node",
                "requires_approval": False,
                "reversible": True,
                "timestamp": "2026-07-17T10:00:00Z",
                "approved_by": "", "decision": "",
                "decision_timestamp": "", "approval_justification": "",
                "execution_result": None,
            }],
        })
        out = approval_node(base)
        assert "acknowledged_actions" in out
        assert "approved_actions" in out
        assert "rejected_actions" in out
        assert isinstance(out["audit_log"], list)
        # NOTIFY_SOC is Tier-1 → auto-acknowledged
        assert len(out["acknowledged_actions"]) == 1

    def test_executor_receives_acknowledged_actions(self):
        """Executor must execute auto-acknowledged Tier-1 actions."""
        from graphs.nodes.response_executor import response_executor_node

        base = self._make_base_state()
        base.update({
            "incident_id": "INC-HANDOFF-002",
            "incident_title": "Executor Handoff Test",
            "incident_category": "ransomware",
            "incident_status": "investigating",
            "timestamp": "2026-07-17T10:00:00Z",
            "schema_version": "1.0.0",
            "severity": 12,
            "asset_criticality": "High",
            "affected_assets": ["ehr-fileserver-02"],
            "matched_playbook": "ransomware_impact",
            "playbook_version": "v1",
            "allowed_actions": [
                {"name": "NOTIFY_SOC", "risk_tier": 1, "requires_approval": False},
            ],
            "proposed_actions": [{
                "action_id": "ACT-H-002",
                "action_type": "NOTIFY_SOC",
                "target": "SOC Team",
                "status": "acknowledged",
                "decision": "acknowledged",
                "justification": "Auto-acknowledged.",
                "requested_by": "system:response_planner_node",
                "approved_by": "system:approval_node",
                "requires_approval": False,
                "reversible": True,
                "timestamp": "2026-07-17T10:00:00Z",
                "decision_timestamp": "2026-07-17T10:01:00Z",
                "approval_justification": "Tier 1.",
                "execution_result": None,
            }],
            "acknowledged_actions": [{
                "action_id": "ACT-H-002",
                "action_type": "NOTIFY_SOC",
                "target": "SOC Team",
                "status": "acknowledged",
                "decision": "acknowledged",
                "justification": "Auto-acknowledged.",
                "requested_by": "system:response_planner_node",
                "approved_by": "system:approval_node",
                "requires_approval": False,
                "reversible": True,
                "timestamp": "2026-07-17T10:00:00Z",
                "decision_timestamp": "2026-07-17T10:01:00Z",
                "approval_justification": "Tier 1.",
                "execution_result": None,
            }],
            "audit_log": [],
        })
        out = response_executor_node(base)
        assert out["execution_summary"]["successful"] >= 1
        assert any(
            a.get("action_name") == "NOTIFY_SOC"
            for a in out.get("executed_actions", [])
        )


# ---------------------------------------------------------------------------
# 4. Non-interactive safety test
# ---------------------------------------------------------------------------

class TestNonInteractiveSafety:
    """The graph must NEVER call input() when decisions are pre-seeded."""

    def test_approval_node_does_not_call_input_when_decisions_seeded(self, monkeypatch):
        from graphs.nodes.approval import approval_node

        def _never_called(prompt: str = "") -> str:
            raise RuntimeError(f"input() was called: {prompt!r}")

        monkeypatch.setattr("builtins.input", _never_called)

        state = {
            "incident_id": "INC-SAFE-001",
            "incident_title": "Non-interactive Safety Test",
            "incident_category": "ransomware",
            "incident_status": "investigating",
            "timestamp": "2026-07-17T10:00:00Z",
            "schema_version": "1.0.0",
            "source": "simulated",
            "severity": 15,
            "asset_criticality": "High",
            "affected_assets": ["ehr-fileserver-02"],
            "matched_playbook": "ransomware_impact",
            "playbook_version": "v1",
            "raw_alerts": [],
            "audit_log": [],
            "errors": [],
            "allowed_actions": [
                {"name": "NOTIFY_SOC", "risk_tier": 1, "requires_approval": False},
                {"name": "ISOLATE_ENDPOINT", "risk_tier": 3, "requires_approval": True},
            ],
            "proposed_actions": [
                {
                    "action_id": "ACT-SAFE-001",
                    "action_type": "NOTIFY_SOC",
                    "target": "SOC Team",
                    "status": "proposed",
                    "justification": "Alert the SOC.",
                    "requested_by": "system:response_planner_node",
                    "requires_approval": False,
                    "reversible": True,
                    "timestamp": "2026-07-17T10:00:00Z",
                    "approved_by": "", "decision": "",
                    "decision_timestamp": "", "approval_justification": "",
                    "execution_result": None,
                },
                {
                    "action_id": "ACT-SAFE-002",
                    "action_type": "ISOLATE_ENDPOINT",
                    "target": "ehr-fileserver-02",
                    "status": "proposed",
                    "justification": "Contain ransomware.",
                    "requested_by": "system:response_planner_node",
                    "requires_approval": True,
                    "reversible": True,
                    "timestamp": "2026-07-17T10:00:00Z",
                    "approved_by": "", "decision": "",
                    "decision_timestamp": "", "approval_justification": "",
                    "execution_result": None,
                },
            ],
            "approval_decisions": {
                "ACT-SAFE-002": {
                    "decision": "approved",
                    "justification": "Pre-seeded for CI.",
                    "approver": "ci-analyst",
                },
            },
            "approval_approver": "ci-analyst",
        }

        result = approval_node(state)
        # Must not raise; must resolve correctly
        assert len(result["acknowledged_actions"]) == 1   # NOTIFY_SOC
        assert len(result["approved_actions"]) == 1       # ISOLATE_ENDPOINT

    def test_full_pipeline_with_empty_decisions_does_not_call_input(
        self, monkeypatch, patch_all_llm
    ):
        """
        With no pre-seeded decisions, all requires_approval=True actions should
        be skipped/rejected — the graph must not hang on input().
        """
        def _never_called(prompt: str = "") -> str:
            raise RuntimeError(f"Full pipeline called input(): {prompt!r}")

        monkeypatch.setattr("builtins.input", _never_called)

        from graphs.threat_intel_graph import run_threat_intel

        result = run_threat_intel(
            scenario="ryuk",
            scenario_file=str(RYUK_FILE),
            with_response=True,
            with_approval=True,
            with_execution=True,
        )
        assert result.get("incident_id") is not None
        assert isinstance(result.get("execution_summary"), dict)


# ---------------------------------------------------------------------------
# 5. Graceful degradation — no LLM key → deterministic fallback
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    """
    When the LLM API key is absent, the pipeline must still complete and
    fall back to deterministic Tier-1 proposals.
    """

    def test_pipeline_completes_with_no_llm_key(self, monkeypatch):
        from config import Settings

        monkeypatch.setattr(
            "config.load_settings",
            lambda: Settings(
                groq_api_key="",
                main_model="",
                secondary_model="",
                embedding_model="mock-embedding",
            ),
        )
        def mock_input(prompt: str = "") -> str:
            prompt_lower = prompt.lower()
            if "approve" in prompt_lower:
                return "y"
            elif "justification" in prompt_lower:
                return "test-justification"
            elif "approver id" in prompt_lower:
                return "test-approver"
            return "yes"
        monkeypatch.setattr("builtins.input", mock_input)

        # Still mock ChatGroq + create_react_agent so ioc_enrichment doesn't crash
        mock_llm, mock_agent = _make_mock_chat_groq()
        with (
            patch("graphs.nodes.ioc_enrichment.ChatGroq", return_value=mock_llm),
            patch("graphs.nodes.ioc_enrichment.create_react_agent", return_value=mock_agent),
        ):
            from graphs.threat_intel_graph import run_threat_intel
            result = run_threat_intel(
                scenario="ryuk",
                scenario_file=str(RYUK_FILE),
                with_response=True,
                with_approval=True,
                with_execution=True,
            )

        assert result.get("incident_id") is not None
        proposed = result.get("proposed_actions", [])
        assert any(
            str(a.get("action_type") or a.get("action", "")).upper() == "NOTIFY_SOC"
            for a in proposed
        ), f"Fallback must include NOTIFY_SOC, got: {[a.get('action_type') for a in proposed]}"

    def test_pipeline_executes_tier1_without_llm(self, monkeypatch):
        """Even without an LLM, at least one Tier-1 action must be executed."""
        from config import Settings

        monkeypatch.setattr(
            "config.load_settings",
            lambda: Settings(
                groq_api_key="",
                main_model="",
                secondary_model="",
                embedding_model="mock-embedding",
            ),
        )
        def mock_input(prompt: str = "") -> str:
            prompt_lower = prompt.lower()
            if "approve" in prompt_lower:
                return "y"
            elif "justification" in prompt_lower:
                return "test-justification"
            elif "approver id" in prompt_lower:
                return "test-approver"
            return "yes"
        monkeypatch.setattr("builtins.input", mock_input)

        mock_llm, mock_agent = _make_mock_chat_groq()
        with (
            patch("graphs.nodes.ioc_enrichment.ChatGroq", return_value=mock_llm),
            patch("graphs.nodes.ioc_enrichment.create_react_agent", return_value=mock_agent),
        ):
            from graphs.threat_intel_graph import run_threat_intel
            result = run_threat_intel(
                scenario="ryuk",
                scenario_file=str(RYUK_FILE),
                with_response=True,
                with_approval=True,
                with_execution=True,
            )
        assert result["execution_summary"].get("successful", 0) >= 1


# ---------------------------------------------------------------------------
# 6. Credential access scenario playbook routing
# ---------------------------------------------------------------------------

class TestCredentialAccessScenario:
    """Verify T1110.003 routes to credential_access playbook and proposes Tier-1 actions."""

    def _cred_state(self) -> dict[str, Any]:
        return {
            "incident_id": "INC-CRED-001",
            "incident_title": "Credential Access Brute Force",
            "incident_category": "credential_access",
            "incident_status": "investigating",
            "timestamp": "2026-07-17T10:00:00Z",
            "schema_version": "1.0.0",
            "source": "simulated",
            "severity": 10,
            "confidence_score": 0.75,
            "asset_criticality": "High",
            "affected_assets": ["ehr-server-01"],
            "affected_asset_type": "ehr",
            "potential_patient_impact": "EHR access risk.",
            "mitre_techniques": ["T1110.003"],
            "rule_id": "5710",
            "logs": ["SSH brute force"],
            "raw_alerts": [],
            "audit_log": [],
            "errors": [],
            "matched_playbook": None,
            "matched_playbook_technique_id": None,
            "matched_playbook_technique_name": None,
            "playbook_version": None,
            "playbook_source": None,
            "playbook_selected_by_technique": None,
            "allowed_actions": [],
            "proposed_actions": [],
            "approved_actions": [],
            "acknowledged_actions": [],
            "rejected_actions": [],
            "executed_actions": [],
            "failed_actions": [],
            "execution_summary": {},
            "approval_decisions": {},
            "approval_approver": None,
            "execution_results": [],
            "enriched_iocs": [],
        }

    def test_credential_access_playbook_selected(self):
        from graphs.nodes.playbook_resolver import playbook_resolver_node

        out = playbook_resolver_node(self._cred_state())
        assert out.get("matched_playbook") == "credential_access", (
            f"T1110.003 should map to credential_access, got: {out.get('matched_playbook')}"
        )

    def test_credential_access_has_notify_soc(self):
        from graphs.nodes.playbook_resolver import playbook_resolver_node

        out = playbook_resolver_node(self._cred_state())
        names = [a["name"] for a in out["allowed_actions"]]
        assert "NOTIFY_SOC" in names

    def test_credential_access_has_revoke_session(self):
        from graphs.nodes.playbook_resolver import playbook_resolver_node

        out = playbook_resolver_node(self._cred_state())
        names = [a["name"] for a in out["allowed_actions"]]
        assert "REVOKE_SESSION" in names

    def test_credential_access_planner_proposes_notify_soc(self, patch_all_llm):
        from graphs.nodes.playbook_resolver import playbook_resolver_node
        from graphs.nodes.risk import risk_assessment_node
        from graphs.nodes.response_planner import response_planner_node

        base = self._cred_state()
        base["risk_score"] = 55
        base["priority"] = "Medium"
        base["requires_human_review"] = False
        risk_out = risk_assessment_node({**base, "severity": 10})
        pb_out = playbook_resolver_node({**base, **risk_out})
        planner_out = response_planner_node({**base, **risk_out, **pb_out})

        proposed_names = [
            str(a.get("action_type") or a.get("action", "")).upper()
            for a in planner_out.get("proposed_actions", [])
        ]
        assert "NOTIFY_SOC" in proposed_names, (
            f"Credential access should propose NOTIFY_SOC, got: {proposed_names}"
        )


# ---------------------------------------------------------------------------
# 7. Execution summary consistency — standalone (no full graph needed)
# ---------------------------------------------------------------------------

class TestExecutionSummaryConsistency:
    """
    Verify execution_summary counts are always consistent:
    successful + failed + skipped == total_actions.
    """

    def _action(
        self,
        action_id: str,
        action_type: str,
        *,
        target: str = "system",
        requires_approval: bool = False,
        decision: str = "acknowledged",
    ) -> dict:
        return {
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "status": decision,
            "justification": f"{action_type} test.",
            "requested_by": "system:response_planner_node",
            "approved_by": "system:approval_node",
            "decision": decision,
            "decision_timestamp": "2026-07-17T10:05:00Z",
            "approval_justification": "E2E summary test.",
            "execution_result": None,
            "requires_approval": requires_approval,
            "reversible": True,
            "timestamp": "2026-07-17T10:00:00Z",
        }

    def _base_state(self, **overrides) -> dict:
        state = {
            "incident_id": "INC-SUMMARY-001",
            "timestamp": "2026-07-17T10:00:00Z",
            "incident_title": "Summary Test",
            "incident_category": "ransomware",
            "incident_status": "investigating",
            "schema_version": "1.0.0",
            "source": "simulated",
            "raw_alerts": [],
            "rule_id": "61809",
            "logs": [],
            "severity": 15,
            "confidence_score": 0.9,
            "asset_criticality": "High",
            "affected_assets": ["ehr-fileserver-02"],
            "affected_asset_type": "ehr",
            "mitre_techniques": ["T1486"],
            "matched_playbook": "ransomware_impact",
            "playbook_version": "v1",
            "allowed_actions": [
                {"name": "NOTIFY_SOC", "risk_tier": 1, "requires_approval": False},
                {"name": "BLOCK_IP", "risk_tier": 2, "requires_approval": False},
                {"name": "ISOLATE_ENDPOINT", "risk_tier": 3, "requires_approval": True},
            ],
            "proposed_actions": [],
            "approved_actions": [],
            "acknowledged_actions": [],
            "rejected_actions": [],
            "executed_actions": [],
            "failed_actions": [],
            "execution_summary": {},
            "execution_results": [],
            "audit_log": [],
            "errors": [],
        }
        state.update(overrides)
        return state

    def test_counts_add_up_for_mixed_result(self):
        from graphs.nodes.response_executor import response_executor_node

        ack = [self._action("A1", "NOTIFY_SOC", target="SOC Team")]
        rejected = [self._action("A2", "ISOLATE_ENDPOINT", target="ehr", requires_approval=True, decision="rejected")]
        proposed = [*ack, *rejected]

        result = response_executor_node(
            self._base_state(
                acknowledged_actions=ack,
                rejected_actions=rejected,
                proposed_actions=proposed,
            )
        )
        s = result["execution_summary"]
        assert s["successful"] + s["failed"] + s["skipped"] == s["total_actions"]

    def test_successful_count_equals_executed_actions_len(self):
        from graphs.nodes.response_executor import response_executor_node

        ack = [self._action("A1", "NOTIFY_SOC", target="SOC Team")]
        result = response_executor_node(
            self._base_state(
                acknowledged_actions=ack,
                proposed_actions=ack,
            )
        )
        s = result["execution_summary"]
        assert len(result["executed_actions"]) == s["successful"]

    def test_failed_count_equals_failed_actions_len(self):
        from graphs.nodes.response_executor import response_executor_node

        # Use an unsupported action to force a failure
        ack = [self._action("A1", "UNSUPPORTED_XYZ")]
        result = response_executor_node(
            self._base_state(
                acknowledged_actions=ack,
                proposed_actions=ack,
                allowed_actions=[
                    {"name": "UNSUPPORTED_XYZ", "risk_tier": 1, "requires_approval": False},
                ],
            )
        )
        s = result["execution_summary"]
        assert len(result["failed_actions"]) == s["failed"]

    def test_audit_log_grows_across_all_stages(self, full_pipeline_result):
        """Full pipeline audit_log must contain entries from multiple actors."""
        audit_log = full_pipeline_result.get("audit_log", [])
        actors = {e.get("actor", "") for e in audit_log}
        # Expect entries from risk, playbook resolver, planner, approval, executor
        assert len(actors) >= 3, (
            f"Expected audit entries from ≥3 distinct actors, got: {actors}"
        )

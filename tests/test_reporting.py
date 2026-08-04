from types import SimpleNamespace

from graphs.nodes.correlation import correlation_node
from graphs.nodes.collection import collection_node
from graphs.nodes.ioc_enrichment import (
    _MISP_PREFLIGHT_CACHE,
    _actor_signature_from_alert,
    _candidate_technique,
    _fallback_ioc,
    _invoke_agent_with_retry,
    _persistent_ioc_cache_key,
    _simulated_cache_enabled,
    ioc_enrichment_node,
)
from graphs.nodes.reporting import (
    _build_report_prompt,
    _fallback_report,
    _format_attack_timeline_section,
    _format_recommended_actions_section,
    _generate_report_with_retry,
    _timeline,
)
from graphs.nodes.tools.external_tools import lookup_actor_profile


def test_live_low_confidence_prompt_uses_cautious_language():
    state = {
        "collection_metadata": {"data_source": "wazuh_live"},
        "campaign": {"campaign_confidence": 0.65, "kill_chain_position": 7},
        "raw_alerts": [{"id": "A1"}],
        "enriched_iocs": [],
    }

    prompt = _build_report_prompt(state)

    assert "preliminary evidence suggests" in prompt.lower()
    assert "do not claim confirmed ransomware" in prompt.lower()
    assert "insufficient confirmed evidence" in prompt.lower()
    assert "attack timeline" not in prompt.lower()


def test_timeline_does_not_display_raw_technique_hint_without_enrichment():
    state = {
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-04T10:00:00Z",
                "technique_hint": "T1531",
            }
        ],
        "enriched_iocs": [],
    }

    assert _timeline(state)[0]["technique"] == "none confirmed"


def test_fallback_healthcare_impact_is_insufficient_evidence_statement():
    state = {
        "collection_metadata": {"data_source": "wazuh_live"},
        "confidence_score": 0.0,
        "campaign": {
            "current_stage": "Insufficient Evidence",
            "techniques_confirmed": [],
            "campaign_confidence": 0.0,
        },
        "prediction": {
            "predicted_next_techniques": [],
            "note": "No prediction possible without at least one confirmed technique",
        },
        "raw_alerts": [{"id": "A1", "technique_hint": "T1531"}],
        "enriched_iocs": [],
    }

    report = _fallback_report(state)

    assert "No specific healthcare-impact scenario can be projected" in report
    assert "Ryuk" not in report
    assert "T1531" not in report


def test_candidate_technique_does_not_infer_impact_for_generic_syscheck():
    alert = {
        "event_type": "Integrity checksum changed.",
        "raw_log": "Syscheck Integrity checksum changed",
    }

    # _is_generic_fim_event guard ensures bare syscheck events return ("", 0.0)
    # rather than false-positive matching T1495 (Firmware Corruption) via semantic search.
    technique, score = _candidate_technique(alert)
    assert technique == "" and score == 0.0


def test_lookup_actor_profile_is_repeatable_without_corroborating_indicator():
    payload = {
        "technique_id": "T1110",
        "source_ip": "::1",
        "corroborating_evidence": "N/A - internal/reserved address for ::1",
    }

    results = [lookup_actor_profile.invoke(payload) for _ in range(10)]

    assert len(set(results)) == 1
    assert '"actor_name": "Unattributed"' in results[0]
    assert '"confidence": 0.0' in results[0]


def test_candidate_technique_skips_vss_idle_timeout_service_message():
    alert = {
        "event_type": "The VSS service is shutting down due to idle timeout",
        "raw_log": "The VSS service is shutting down due to idle timeout",
        "wazuh_rule_id": "7036",
        "wazuh_rule_level": 4,
        "technique_hint": "unknown",
        "source_system": "wazuh",
    }

    # _candidate_technique returns (technique, score); VSS idle-timeout should yield no technique.
    technique, score = _candidate_technique(alert)
    assert technique == ""


def test_candidate_technique_prefers_native_wazuh_mitre_tag():
    alert = {
        "event_type": "Multiple Windows Logon Failures",
        "raw_log": "Logon failure: unknown user name or bad password",
        "wazuh_rule_id": "60204",
        "wazuh_rule_level": 5,
        "technique_hint": "T1110",
        "source_system": "wazuh",
    }

    # _candidate_technique returns (technique, similarity_score); verify technique matches.
    technique, score = _candidate_technique(alert)
    assert technique == "T1110"


def test_fallback_ioc_preserves_structural_technique_confidence():
    alert = {
        "id": "A1",
        "source_ip": "10.20.14.23",
        "destination": "ehr-fileserver-02",
        "event_type": "mass_file_modification",
        "severity": "critical",
        "decoder": "fim",
        "rule_groups": ["ransomware", "impact"],
        "raw_log": "mass file changes",
    }

    technique, score = _candidate_technique(alert)
    fallback = _fallback_ioc(alert, ConnectionError("tool unavailable"), technique, score)

    assert fallback["technique_confirmed"] == "T1486"
    assert fallback["confidence"] == 1.0
    assert fallback["technique_confidence"] == 1.0
    assert fallback["actor_confidence"] == 0.0


def test_correlation_uses_confirmed_tactics_for_stage_assessment():
    state = {
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-06T08:00:00Z",
                "source_ip": "::1",
                "destination": "host",
                "event_type": "Logon failure: bad password",
            },
            {
                "id": "A2",
                "timestamp": "2026-07-06T08:01:00Z",
                "source_ip": "::1",
                "destination": "host",
                "event_type": "Authentication failure",
            },
        ],
        "enriched_iocs": [
            {"alert_id": "A1", "source_ip": "::1", "technique_confirmed": "T1110", "actor_name": "Unattributed", "confidence": 0.0},
            {"alert_id": "A2", "source_ip": "::1", "technique_confirmed": "T1531", "actor_name": "Unattributed", "confidence": 0.0},
        ],
        "mitre_context": {
            "T1110": {"kill_chain_position": 5, "tactic": "Credential Access"},
            "T1531": {"kill_chain_position": 7, "tactic": "Impact"},
        },
    }

    campaign = correlation_node(state)["campaign"]

    assert campaign["attack_type"] == "brute_force_attempt"
    assert campaign["kill_chain_position"] == 7
    assert campaign["current_stage"] == "Impact"
    assert campaign["confirmed_tactics"] == ["Credential Access", "Impact"]
    assert "Impact" in campaign["stage_reasoning"]
    assert campaign["attributed_actor"] == "Unattributed"
    assert campaign["source_ip_is_internal"] is True


def test_correlation_confirms_compromise_after_successful_login():
    state = {
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-06T09:00:00Z",
                "source_ip": "203.0.113.10",
                "destination": "host",
                "event_type": "Successful login",
            },
            {
                "id": "A2",
                "timestamp": "2026-07-06T09:01:00Z",
                "source_ip": "203.0.113.10",
                "destination": "host",
                "event_type": "File modified on host",
            },
        ],
        "enriched_iocs": [
            {"alert_id": "A1", "source_ip": "203.0.113.10", "technique_confirmed": "T1078", "actor_name": "Unattributed", "confidence": 0.8},
            {"alert_id": "A2", "source_ip": "203.0.113.10", "technique_confirmed": "T1486", "actor_name": "Unattributed", "confidence": 0.9},
        ],
        "mitre_context": {
            "T1078": {"kill_chain_position": 2, "tactic": "Initial Access"},
            "T1486": {"kill_chain_position": 7, "tactic": "Impact"},
        },
    }

    campaign = correlation_node(state)["campaign"]

    assert campaign["attack_type"] == "confirmed_compromise"
    assert campaign["kill_chain_position"] == 7
    assert campaign["current_stage"] == "Impact"


def test_correlation_uses_highest_kill_chain_position_not_discovery_priority():
    state = {
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-06T09:00:00Z",
                "source_ip": "10.0.0.5",
                "destination": "network",
                "event_type": "Internal port scan",
            },
            {
                "id": "A2",
                "timestamp": "2026-07-06T09:10:00Z",
                "source_ip": "10.0.0.5",
                "destination": "file-server",
                "event_type": "Mass encryption",
            },
            {
                "id": "A3",
                "timestamp": "2026-07-06T09:11:00Z",
                "source_ip": "10.0.0.5",
                "destination": "domain-controller",
                "event_type": "Shadow copy deletion",
            },
        ],
        "enriched_iocs": [
            {"alert_id": "A1", "source_ip": "10.0.0.5", "technique_confirmed": "T1046", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "A2", "source_ip": "10.0.0.5", "technique_confirmed": "T1486", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "A3", "source_ip": "10.0.0.5", "technique_confirmed": "T1490", "actor_name": "Unattributed", "confidence": 1.0},
        ],
        "mitre_context": {
            "T1046": {"kill_chain_position": 2, "tactic": "Discovery"},
            "T1486": {"kill_chain_position": 7, "tactic": "Impact"},
            "T1490": {"kill_chain_position": 7, "tactic": "Impact"},
        },
    }

    campaign = correlation_node(state)["campaign"]

    assert campaign["current_stage"] == "Impact"
    assert campaign["kill_chain_position"] == 7
    assert "highest-position confirmed technique(s) are T1486, T1490" in campaign["stage_reasoning"]
    assert "highest confirmed tactic is Discovery" not in campaign["stage_reasoning"]


def test_correlation_does_not_merge_replayed_alerts_or_wazuh_housekeeping():
    state = {
        "collection_metadata": {"data_source": "wazuh_live"},
        "raw_alerts": [
            {
                "id": "OLD-PCAP",
                "timestamp": "2014-02-07T04:32:00Z",
                "source_ip": "192.168.56.101",
                "destination": "old-test-vm",
                "event_type": "Suricata alert: Nmap scan",
                "source_system": "suricata",
                "decoder": "suricata",
                "risk_score": 80,
            },
            {
                "id": "REAL-T1046",
                "timestamp": "2026-07-20T12:00:00+0200",
                "source_ip": "10.10.2.44",
                "destination": "ehr-segment",
                "event_type": "Suricata alert: Network scan",
                "source_system": "suricata",
                "decoder": "suricata",
                "risk_score": 90,
            },
            {
                "id": "WAZUH-ROOTCHECK",
                "timestamp": "2026-07-20T12:05:00Z",
                "source_ip": "127.0.0.1",
                "destination": "wazuh-manager",
                "event_type": "OSSEC rootcheck scan ended",
                "source_system": "wazuh",
                "decoder": "rootcheck",
                "rule_groups": ["ossec", "rootcheck"],
                "wazuh_rule_id": "510",
                "risk_score": 95,
            },
            {
                "id": "WAZUH-LOGROTATE",
                "timestamp": "2026-07-20T12:06:00Z",
                "source_ip": "127.0.0.1",
                "destination": "wazuh-manager",
                "event_type": "OSSEC log rotation notice",
                "source_system": "wazuh",
                "decoder": "ossec",
                "rule_groups": ["ossec"],
                "wazuh_rule_id": "591",
                "risk_score": 95,
            },
        ],
        "enriched_iocs": [
            {"alert_id": "OLD-PCAP", "source_ip": "192.168.56.101", "technique_confirmed": "T1046", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "REAL-T1046", "source_ip": "10.10.2.44", "technique_confirmed": "T1046", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "WAZUH-ROOTCHECK", "source_ip": "127.0.0.1", "technique_confirmed": "T1531", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "WAZUH-LOGROTATE", "source_ip": "127.0.0.1", "technique_confirmed": "T1486", "actor_name": "Ryuk", "confidence": 1.0},
        ],
        "mitre_context": {
            "T1046": {"kill_chain_position": 2, "tactic": "Discovery"},
            "T1531": {"kill_chain_position": 7, "tactic": "Impact"},
            "T1486": {"kill_chain_position": 7, "tactic": "Impact"},
        },
    }

    campaign = correlation_node(state)["campaign"]

    assert campaign["correlation_window_hours"] == 72
    assert campaign["correlated_alert_ids"] == ["REAL-T1046"]
    assert campaign["alerts_count"] == 1
    assert campaign["techniques_confirmed"] == ["T1046"]
    assert campaign["current_stage"] == "Initial Access"
    assert campaign["confirmed_tactics"] == ["Discovery"]
    assert campaign["target_asset"] == "ehr-segment"
    assert campaign["attack_start"] == "2026-07-20T10:00:00Z"
    assert campaign["attack_latest"] == "2026-07-20T10:00:00Z"
    excluded = {item["alert_id"]: item["reason"] for item in campaign["excluded_alerts"]}
    assert excluded["OLD-PCAP"] == "outside_correlation_window_or_host_scope"
    assert excluded["WAZUH-ROOTCHECK"] == "wazuh_operational_noise"
    assert excluded["WAZUH-LOGROTATE"] == "wazuh_operational_noise"


def test_reporting_timeline_uses_only_correlated_campaign_alerts():
    state = {
        "campaign": {
            "correlated_alert_ids": ["REAL-T1046"],
            "techniques_confirmed": ["T1046"],
        },
        "raw_alerts": [
            {"id": "OLD-PCAP", "timestamp": "2014-02-07T04:32:00Z", "source_ip": "192.168.56.101", "destination": "old-test-vm", "event_type": "Old replay"},
            {"id": "REAL-T1046", "timestamp": "2026-07-20T12:00:00Z", "source_ip": "10.10.2.44", "destination": "ehr-segment", "event_type": "Suricata alert: Network scan"},
            {"id": "WAZUH-ROOTCHECK", "timestamp": "2026-07-20T12:05:00Z", "source_ip": "127.0.0.1", "destination": "wazuh-manager", "event_type": "Rootcheck heartbeat"},
        ],
        "enriched_iocs": [
            {"alert_id": "OLD-PCAP", "technique_confirmed": "T1046", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "REAL-T1046", "technique_confirmed": "T1046", "actor_name": "Unattributed", "confidence": 1.0},
            {"alert_id": "WAZUH-ROOTCHECK", "technique_confirmed": "T1486", "actor_name": "Ryuk", "confidence": 1.0},
        ],
    }

    timeline = _format_attack_timeline_section(state)

    assert "REAL-T1046" not in timeline
    assert "Suricata alert: Network scan" in timeline
    assert "Old replay" not in timeline
    assert "Rootcheck heartbeat" not in timeline
    assert "T1486" not in timeline


def test_fallback_report_does_not_call_loopback_attacker_infrastructure():
    state = {
        "collection_metadata": {"data_source": "wazuh_live"},
        "confidence_score": 0.0,
        "campaign": {
            "current_stage": "Impact",
            "kill_chain_position": 7,
            "techniques_confirmed": ["T1110", "T1531"],
            "attacker_ip": "::1",
            "source_ip_is_internal": True,
            "target_asset": "wejden-cherif",
            "attributed_actor": "Unattributed",
            "campaign_confidence": 0.25,
        },
        "prediction": {},
        "raw_alerts": [],
        "enriched_iocs": [],
    }

    report = _fallback_report(state)

    assert "attacker infrastructure is ::1" not in report
    assert "source address is ::1 (internal or loopback telemetry)" in report
    # Report uses title-case with colon: "Kill chain position: 7/7"
    assert "Kill chain position: 7/7" in report


def test_recommended_actions_strip_sources_summary_leakage():
    state = {
        "prediction": {
            "recommended_immediate_actions": (
                "Isolate affected hosts.\n"
                "| Column | Value |\n"
                "SOURCES SUMMARY (computed automatically, not self-reported by the model)\n"
                "Retrieved from database and used in this answer: T1486\n"
                "Used in this answer but NOT found in retrieved context: T1490\n"
            )
        }
    }

    section = _format_recommended_actions_section(state)

    assert "Isolate affected hosts" in section
    assert "SOURCES SUMMARY" not in section
    assert "Retrieved from database" not in section


def test_ryuk_actor_signature_is_grounded_in_ransom_note_extension():
    alert = {
        "event_type": "mass_file_modification",
        "rule_description": "FIM: Mass file rename/modification consistent with ransomware encryption",
        "full_log": "File integrity monitor: New extension observed: .RyukReadMe",
        "raw_log": '{"data":{"new_extension":".RyukReadMe"}}',
    }

    actor_name, malware, confidence, summary = _actor_signature_from_alert(alert, "T1486")

    assert actor_name == "Ryuk"
    assert malware == "Ryuk"
    assert confidence < 1.0
    assert ".RyukReadMe" in alert["full_log"]
    assert "Local ransomware signature evidence" in summary


def test_collection_records_simulated_scenario_hash():
    result = collection_node(
        {
            "scenario": "ryuk",
            "raw_alerts": [],
            "live_alerts": [],
            "simulated_alerts": [],
            "collection_metadata": {},
            "errors": [],
            "audit_log": [],
        }
    )

    metadata = result["collection_metadata"]

    assert metadata["data_source"] == "simulated"
    assert len(metadata["scenario_file_sha256"]) == 64
    assert metadata["source_file"] == "ryuk_scenario.json"


def test_simulated_collection_does_not_set_placeholder_risk_fields():
    result = collection_node(
        {
            "scenario": "ryuk",
            "raw_alerts": [],
            "live_alerts": [],
            "simulated_alerts": [],
            "collection_metadata": {},
            "errors": [],
            "audit_log": [],
        }
    )

    assert len(result["raw_alerts"]) > 0
    assert all("risk_score" not in alert for alert in result["raw_alerts"])
    assert all("risk_priority" not in alert for alert in result["raw_alerts"])


def test_attack_timeline_marks_unscored_when_alert_risk_missing():
    state = {
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-07-04T10:00:00Z",
                "source_ip": "10.0.0.1",
                "destination": "host",
                "event_type": "Test event",
                "raw_log": "Test log",
            }
        ],
        "enriched_iocs": [],
    }

    report_section = _format_attack_timeline_section(state)

    assert "risk=unscored" in report_section


def test_simulated_ioc_cache_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MEDFLOW_SIMULATED_IOC_CACHE", raising=False)

    enabled, scenario_hash = _simulated_cache_enabled(
        {
            "collection_metadata": {
                "data_source": "simulated",
                "scenario_file_sha256": "a" * 64,
            },
            "live_alerts": [],
        }
    )

    assert enabled is False
    assert scenario_hash == ""


def test_simulated_ioc_cache_can_be_enabled_explicitly(monkeypatch):
    monkeypatch.setenv("MEDFLOW_SIMULATED_IOC_CACHE", "1")

    enabled, scenario_hash = _simulated_cache_enabled(
        {
            "collection_metadata": {
                "data_source": "simulated",
                "scenario_file_sha256": "a" * 64,
            },
            "live_alerts": [],
        }
    )

    assert enabled is True
    assert scenario_hash == "a" * 64


def test_simulated_ioc_cache_is_never_enabled_for_live_wazuh(monkeypatch):
    monkeypatch.setenv("MEDFLOW_SIMULATED_IOC_CACHE", "1")
    enabled, scenario_hash = _simulated_cache_enabled(
        {
            "collection_metadata": {
                "data_source": "wazuh_live",
                "scenario_file_sha256": "a" * 64,
            },
            "live_alerts": [{"id": "WZ-001"}],
        }
    )

    assert enabled is False
    assert scenario_hash == ""


def test_persistent_ioc_cache_key_uses_scenario_hash_and_alert_id():
    key = _persistent_ioc_cache_key({"id": "1740421567.887891"}, "abc123")

    assert key == "abc123:1740421567.887891"


def test_ioc_enrichment_skips_query_misp_when_preflight_unavailable(monkeypatch):
    captured_tool_names = []

    class FakeLlm:
        def __init__(self, *args, **kwargs):
            pass

    class FakeAgent:
        def invoke(self, payload):
            return {
                "messages": [
                    SimpleNamespace(
                        content='{"actor_name": "Unattributed", "malware_associated": "Unknown", "confidence": 0.0, "summary": "ok"}',
                        name=None,
                        type="ai",
                    )
                ]
            }

    def fake_create_react_agent(llm, tools):
        captured_tool_names.append([getattr(tool, "name", "") for tool in tools])
        return FakeAgent()

    _MISP_PREFLIGHT_CACHE.clear()
    monkeypatch.delenv("MISP_API_KEY", raising=False)
    monkeypatch.setattr("graphs.nodes.ioc_enrichment.ChatGroq", FakeLlm)
    monkeypatch.setattr("graphs.nodes.ioc_enrichment.create_react_agent", fake_create_react_agent)
    monkeypatch.setattr("graphs.nodes.ioc_enrichment.time.sleep", lambda *_args, **_kwargs: None)

    result = ioc_enrichment_node(
        {
            "collection_metadata": {"data_source": "wazuh_live"},
            "raw_alerts": [
                {
                    "id": "A1",
                    "source_ip": "10.0.0.5",
                    "destination": "host",
                    "event_type": "Multiple Windows Logon Failures",
                    "severity": "high",
                    "decoder": "sshd",
                    "rule_groups": ["authentication_failed"],
                    "raw_log": "Logon failure: bad password",
                }
            ],
            "live_alerts": [{"id": "A1"}],
            "errors": [],
        }
    )

    assert result["enriched_iocs"][0]["technique_confirmed"] == "T1110"
    assert captured_tool_names
    assert all("query_misp" not in names for names in captured_tool_names)


def test_invoke_agent_with_retry_retries_connection_errors_before_succeeding():
    class FakeAgent:
        def __init__(self):
            self.calls = 0

        def invoke(self, payload):
            self.calls += 1
            if self.calls < 3:
                raise ConnectionError("temporary connection error")
            return {"messages": [SimpleNamespace(content='{"actor_name": "Unattributed", "malware_associated": "Unknown", "confidence": 0.0, "summary": "ok"}', name=None, type="ai")]}

    agent = FakeAgent()
    result = _invoke_agent_with_retry(agent, "prompt", max_attempts=3, base_delay=0)

    assert agent.calls == 3
    assert result["messages"][0].content.startswith('{"actor_name"')


def test_generate_report_with_retry_suppresses_intermediate_failure_warning_when_retry_succeeds(monkeypatch):
    class FakeClient:
        calls = 0

        def __init__(self, *args, **kwargs):
            type(self).calls += 1

        @property
        def chat(self):
            return self

        @property
        def completions(self):
            return self

        def create(self, *args, **kwargs):
            if self.calls == 1:
                raise ConnectionError("temporary network issue")
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="EXECUTIVE SUMMARY\nSummary text.\n\nHEALTHCARE IMPACT\nImpact text."))]
            )

    monkeypatch.setitem(__import__("sys").modules, "groq", SimpleNamespace(Groq=FakeClient))

    narrative = _generate_report_with_retry(
        "{}",
        model="test-model",
        api_key="test-key",
        max_attempts=2,
        base_delay=0,
    )

    assert narrative["executive_summary"] == "Summary text."
    assert narrative["healthcare_impact"] == "Impact text."


def test_deterministic_attack_stage_matches_campaign_state():
    from graphs.nodes.reporting import _assemble_report, _build_deterministic_sections, reporting_node

    state = {
        "collection_metadata": {"data_source": "simulated_json"},
        "confidence_score": 0.9,
        "campaign": {
            "current_stage": "Impact",
            "kill_chain_position": 7,
            "techniques_confirmed": ["T1486"],
            "attributed_actor": "Ryuk",
            "campaign_confidence": 0.85,
            "stage_reasoning": "Encryption activity confirmed.",
        },
        "prediction": {
            "predicted_next_techniques": ["T1490"],
            "time_to_next_stage": "Immediate",
            "prediction_confidence": 0.7,
        },
        "raw_alerts": [
            {
                "id": "A1",
                "timestamp": "2026-06-24T09:00:00Z",
                "source_ip": "10.0.0.5",
                "destination": "ehr-server",
                "event_type": "Encryption detected",
            }
        ],
        "enriched_iocs": [
            {"alert_id": "A1", "technique_confirmed": "T1486", "actor_name": "Ryuk", "confidence": 0.9}
        ],
        "mitre_context": {
            "T1486": {
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "detection_guidance": "Monitor for mass file extension changes.",
            }
        },
        "errors": [],
    }

    sections = _build_deterministic_sections(state)
    report = _assemble_report(
        {"executive_summary": "Summary.", "healthcare_impact": "Impact narrative."},
        sections,
    )

    assert "Stage: Impact" in report
    assert "Kill chain position: 7/7" in report
    assert "T1486 (Data Encrypted for Impact)" in report
    assert "Detection rule for T1486" in report

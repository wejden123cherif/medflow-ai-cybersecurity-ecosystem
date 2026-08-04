"""
tests/test_ids_connector.py
Tests for the IDS/Suricata integration connector.
"""

import pytest
from integrations.ids.connector import IDSConnector


@pytest.fixture
def connector():
    return IDSConnector(socket_path="/var/run/suricata/test.socket")


class TestIDSConnectorHealth:
    def test_check_health_enabled(self, connector):
        assert connector.check_health() is True

    def test_check_health_disabled(self, connector):
        connector.enabled = False
        assert connector.check_health() is False

    def test_check_health_no_socket(self):
        c = IDSConnector(socket_path="")
        assert c.check_health() is False


class TestIDSConnectorReloadRules:
    def test_reload_rules_success(self, connector):
        result = connector.execute_action({"action_type": "RELOAD_RULES"})
        assert result["status"] == "success"
        assert "reload" in result["details"].lower()

    def test_reload_rules_unhealthy(self, connector):
        connector.enabled = False
        result = connector.execute_action({"action_type": "RELOAD_RULES"})
        assert result["status"] == "failed"
        assert result["error"] == "service_unavailable"


class TestIDSConnectorDropConnection:
    def test_drop_connection_success(self, connector):
        result = connector.execute_action(
            {"action_type": "DROP_CONNECTION", "target": "192.168.1.100:45231"}
        )
        assert result["status"] == "success"
        assert "192.168.1.100:45231" in result["details"]

    def test_drop_connection_missing_target(self, connector):
        result = connector.execute_action({"action_type": "DROP_CONNECTION", "target": ""})
        assert result["status"] == "failed"
        assert result["error"] == "missing_target"

    def test_drop_connection_unhealthy(self, connector):
        connector.enabled = False
        result = connector.execute_action(
            {"action_type": "DROP_CONNECTION", "target": "10.0.0.1"}
        )
        assert result["status"] == "failed"
        assert result["error"] == "service_unavailable"


class TestIDSConnectorAddRule:
    def test_add_rule_with_rule_field(self, connector):
        result = connector.execute_action(
            {
                "action_type": "ADD_RULE",
                "rule": 'alert tcp any any -> any any (msg:"Test Rule"; sid:99999; rev:1;)',
            }
        )
        assert result["status"] == "success"
        assert "staged" in result["details"].lower()

    def test_add_rule_with_target_as_rule(self, connector):
        result = connector.execute_action(
            {
                "action_type": "ADD_RULE",
                "target": 'alert icmp any any -> any any (msg:"ICMP Test"; sid:99998; rev:1;)',
            }
        )
        assert result["status"] == "success"

    def test_add_rule_missing_rule(self, connector):
        result = connector.execute_action({"action_type": "ADD_RULE"})
        assert result["status"] == "failed"
        assert result["error"] == "missing_rule"


class TestIDSConnectorUnsupportedAction:
    def test_unsupported_action(self, connector):
        result = connector.execute_action({"action_type": "BLOCK_IP", "target": "1.2.3.4"})
        assert result["status"] == "failed"
        assert result["error"] == "unsupported_action"

    def test_unknown_action(self, connector):
        result = connector.execute_action({"action_type": "NUKE_EVERYTHING"})
        assert result["status"] == "failed"
        assert "not supported" in result["details"].lower()


class TestIDSInIntegrationsPackage:
    def test_ids_connector_importable_from_package(self):
        from integrations import IDSConnector
        c = IDSConnector()
        assert c.check_health() is True

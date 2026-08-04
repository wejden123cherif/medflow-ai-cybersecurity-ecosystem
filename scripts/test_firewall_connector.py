"""
scripts/test_firewall_connector.py
-----------------------------------
Test suite for real iptables FirewallConnector.

Verifies:
  1. Safety check — refuses to block IPs in PROTECTED_IPS.
  2. Idempotency check — detects existing rules without error.
  3. Execution & Unblock helper interface.
  4. Error handling for invalid/missing targets and unsupported actions.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from integrations.firewall.connector import FirewallConnector


class TestFirewallConnector(unittest.TestCase):

    def setUp(self) -> None:
        self.connector = FirewallConnector(protected_ips=["192.168.1.1", "10.0.0.1"])

    def test_health_check(self) -> None:
        self.assertTrue(self.connector.check_health())
        self.connector.enabled = False
        self.assertFalse(self.connector.check_health())

    def test_missing_target(self) -> None:
        self.connector.enabled = True
        res = self.connector.execute_action({"action_type": "BLOCK_IP", "target": ""})
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["error"], "missing_target")

    def test_unsupported_action(self) -> None:
        res = self.connector.execute_action({"action_type": "KILL_PROCESS", "target": "10.0.0.5"})
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["error"], "unsupported_action")

    def test_safety_check_refusal(self) -> None:
        """Verify that protected IPs (127.0.0.1, 192.168.1.1, etc.) are strictly refused."""
        for protected_ip in ["127.0.0.1", "192.168.1.1", "10.0.0.1", "127.0.0.1:8080"]:
            res = self.connector.execute_action({"action_type": "BLOCK_IP", "target": protected_ip})
            self.assertEqual(res["status"], "failed", f"Failed to reject protected IP {protected_ip}")
            self.assertEqual(res["error"], "protected_ip_blocked")
            self.assertIn("PROTECTED_IPS", res["details"])

    @patch("integrations.firewall.connector.FirewallConnector._has_iptables", return_value=True)
    @patch("subprocess.run")
    def test_idempotent_skip(self, mock_run: MagicMock, mock_has_iptables: MagicMock) -> None:
        """Verify that if iptables -C returns 0 (already blocked), no -A command is run."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        res = self.connector.execute_action({"action_type": "BLOCK_IP", "target": "198.51.100.44"})
        self.assertEqual(res["status"], "success")
        self.assertTrue(res.get("already_blocked"))
        self.assertIn("already blocked", res["details"])

    @patch("integrations.firewall.connector.FirewallConnector._has_iptables", return_value=True)
    @patch("subprocess.run")
    def test_successful_rule_addition(self, mock_run: MagicMock, mock_has_iptables: MagicMock) -> None:
        """Verify successful iptables -A execution when rule does not exist."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="no matching rule"),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        res = self.connector.execute_action({"action_type": "BLOCK_IP", "target": "198.51.100.55"})
        self.assertEqual(res["status"], "success")
        self.assertIn("Successfully blocked IP address 198.51.100.55", res["details"])

    @patch("integrations.firewall.connector.FirewallConnector._has_iptables", return_value=True)
    @patch("subprocess.run")
    def test_unblock_ip_success(self, mock_run: MagicMock, mock_has_iptables: MagicMock) -> None:
        """Verify unblock_ip runs iptables -D when rule exists."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        res = self.connector.unblock_ip("198.51.100.55")
        self.assertEqual(res["status"], "success")
        self.assertIn("Successfully removed iptables DROP rule", res["details"])


if __name__ == "__main__":
    unittest.main()

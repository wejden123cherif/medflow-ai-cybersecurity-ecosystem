"""
integrations/firewall/connector.py
------------------------------------
Remote iptables Firewall Response Connector for MedFlow AI.

Executes iptables rules on the configured target VM to block malicious source IPs.
All rule checks and changes run through integrations.remote_exec so MedFlow can
run on a host machine while remediation happens on VM 2.
"""

from __future__ import annotations

import logging
import os
import ipaddress
from typing import Any, Callable

from config import load_settings
from integrations.base import ResponseConnector
from integrations.remote_exec import run_remote_command

logger = logging.getLogger("medflow.integrations.firewall")


class FirewallConnector(ResponseConnector):
    """
    Remote VM Firewall Connector using iptables.

    Supported actions:
      - BLOCK_IP  : Adds iptables INPUT DROP rule for the specified target IP.
      - BLOCK_SSH : Adds port-22-scoped INPUT DROP rule for the specified IP.
    """

    SUPPORTED_ACTIONS = {"BLOCK_IP", "BLOCK_SSH"}

    def __init__(
        self,
        protected_ips: list[str] | None = None,
        host: str | None = None,
        remote_runner: Callable[[list[str], int], dict[str, Any]] | None = None,
    ) -> None:
        self.enabled = True
        self.host = host or "target-vm"
        self._custom_protected_ips = protected_ips
        self._remote_runner = remote_runner or run_remote_command

    def _get_protected_ips(self) -> set[str]:
        """Load protected IPs from config/env + defaults."""
        protected = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
        if self._custom_protected_ips:
            protected.update(self._custom_protected_ips)

        env_raw = os.getenv("PROTECTED_IPS", "")
        if env_raw:
            protected.update(item.strip() for item in env_raw.split(",") if item.strip())

        try:
            settings = load_settings()
            protected.update(settings.protected_ips)
        except Exception:
            pass

        return {self._clean_ip(ip) for ip in protected}

    def check_health(self) -> bool:
        """Check if connector is enabled."""
        return self.enabled

    def _get_iptables_cmd_prefix(self) -> list[str]:
        """Use non-interactive sudo on the target VM."""
        return ["sudo", "-n", "iptables"]

    def _run_remote(self, command: list[str], timeout: int = 10) -> dict[str, Any]:
        return self._remote_runner(command, timeout)

    @staticmethod
    def _clean_ip(ip: str) -> str:
        value = str(ip or "").strip()
        if value.startswith("[") and "]" in value:
            end = value.index("]")
            host, suffix = value[1:end], value[end + 1:]
            if not suffix or (suffix.startswith(":") and suffix[1:].isdigit()):
                try:
                    return ipaddress.ip_address(host).compressed
                except ValueError:
                    return value
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            if ":" in value:
                host, separator, port = value.rpartition(":")
                if separator and port.isdigit():
                    try:
                        return ipaddress.ip_address(host).compressed
                    except ValueError:
                        pass
            return value

    @staticmethod
    def _command_error(result: dict[str, Any], fallback: str) -> str:
        return "ssh_connection_failed" if result.get("connection_failed") else fallback

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an iptables DROP rule for the target IP already exists on VM 2.
        Runs: iptables -C INPUT -s <ip> -j DROP (returncode 0 means rule exists)
        """
        clean_ip = self._clean_ip(ip)
        cmd = self._get_iptables_cmd_prefix() + ["-C", "INPUT", "-s", clean_ip, "-j", "DROP"]
        result = self._run_remote(cmd)
        if result.get("connection_failed"):
            logger.error(f"SSH failed while checking iptables rule for {clean_ip}: {result.get('stderr', '').strip()}")
        return result.get("returncode") == 0

    def is_ssh_blocked(self, ip: str) -> bool:
        """
        Check if a port-22-scoped iptables DROP rule already exists on VM 2.
        Runs: iptables -C INPUT -p tcp --dport 22 -s <ip> -j DROP
        """
        clean_ip = self._clean_ip(ip)
        cmd = self._get_iptables_cmd_prefix() + [
            "-C", "INPUT", "-p", "tcp", "--dport", "22", "-s", clean_ip, "-j", "DROP"
        ]
        result = self._run_remote(cmd)
        if result.get("connection_failed"):
            logger.error(f"SSH failed while checking SSH iptables rule for {clean_ip}: {result.get('stderr', '').strip()}")
        return result.get("returncode") == 0

    def unblock_ssh(self, ip: str) -> dict[str, Any]:
        """Remove the port-22-scoped iptables DROP rule for an IP on VM 2."""
        clean_ip = self._clean_ip(ip)
        if not clean_ip:
            return {"status": "failed", "details": "Target IP missing.", "error": "missing_target"}

        if not self.is_ssh_blocked(clean_ip):
            details = f"IP {clean_ip} has no SSH block rule in target VM iptables."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        cmd = self._get_iptables_cmd_prefix() + [
            "-D", "INPUT", "-p", "tcp", "--dport", "22", "-s", clean_ip, "-j", "DROP"
        ]
        result = self._run_remote(cmd)
        if result.get("success"):
            details = f"Successfully removed SSH iptables DROP rule for {clean_ip} on target VM."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        stderr = result.get("stderr", "").strip()
        err = f"Failed to delete SSH iptables rule for {clean_ip}: {stderr}"
        logger.error(err)
        return {"status": "failed", "details": err, "error": self._command_error(result, "iptables_delete_failed")}

    def unblock_ip(self, ip: str) -> dict[str, Any]:
        """Remove an iptables DROP rule for target IP on VM 2."""
        clean_ip = self._clean_ip(ip)
        if not clean_ip:
            return {"status": "failed", "details": "Target IP missing.", "error": "missing_target"}

        if not self.is_ip_blocked(clean_ip):
            details = f"IP {clean_ip} is not currently blocked in target VM iptables."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        cmd = self._get_iptables_cmd_prefix() + ["-D", "INPUT", "-s", clean_ip, "-j", "DROP"]
        result = self._run_remote(cmd)
        if result.get("success"):
            details = f"Successfully removed iptables DROP rule for {clean_ip} on target VM."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        stderr = result.get("stderr", "").strip()
        err = f"Failed to delete iptables rule for {clean_ip}: {stderr}"
        logger.error(err)
        return {"status": "failed", "details": err, "error": self._command_error(result, "iptables_delete_failed")}

    def execute_action(self, action: dict[str, Any], incident_context: dict[str, Any] | None = None) -> dict[str, Any]:
        action_type = str(action.get("action_type") or action.get("action") or "").strip().upper()
        target = str(action.get("target") or "").strip()

        logger.info(f"Attempting firewall action {action_type} for target {target!r}")

        if not self.check_health():
            logger.error("FirewallConnector health check failed, service unavailable.")
            return {
                "status": "failed",
                "details": "FirewallConnector is unreachable or unconfigured.",
                "error": "service_unavailable",
            }

        if action_type not in self.SUPPORTED_ACTIONS:
            return {
                "status": "failed",
                "details": f"Action {action_type} not supported by FirewallConnector.",
                "error": "unsupported_action",
            }

        if not target:
            return {
                "status": "failed",
                "details": "Target IP address is missing.",
                "error": "missing_target",
            }

        clean_ip = self._clean_ip(target)

        protected_ips = self._get_protected_ips()
        if clean_ip in protected_ips:
            msg = (
                f"SAFETY REFUSAL: Target IP '{clean_ip}' is in the PROTECTED_IPS list! "
                f"Action {action_type} aborted to prevent admin lockout."
            )
            logger.critical(msg)
            return {
                "status": "failed",
                "details": msg,
                "error": "protected_ip_blocked",
            }

        if action_type == "BLOCK_SSH":
            if self.is_ssh_blocked(clean_ip):
                details = f"SSH port already blocked for {clean_ip} in target VM iptables (idempotent skip)."
                logger.info(details)
                return {"status": "success", "details": details, "target": clean_ip, "already_blocked": True}

            cmd = self._get_iptables_cmd_prefix() + [
                "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", clean_ip, "-j", "DROP"
            ]
            result = self._run_remote(cmd)
            if result.get("success"):
                details = (
                    f"Successfully blocked SSH (TCP/22) from {clean_ip} via target VM iptables. "
                    f"Other traffic from this IP is unaffected."
                )
                logger.info(details)
                return {"status": "success", "details": details, "target": clean_ip}

            stderr = result.get("stderr", "").strip()
            err = f"Failed to execute SSH iptables DROP for {clean_ip}: {stderr}"
            logger.error(err)
            return {"status": "failed", "details": err, "error": self._command_error(result, "iptables_execution_failed")}

        if self.is_ip_blocked(clean_ip):
            details = f"IP address {clean_ip} is already blocked in target VM iptables (idempotent skip)."
            logger.info(details)
            return {
                "status": "success",
                "details": details,
                "target": clean_ip,
                "already_blocked": True,
            }

        cmd = self._get_iptables_cmd_prefix() + ["-A", "INPUT", "-s", clean_ip, "-j", "DROP"]
        result = self._run_remote(cmd)
        if result.get("success"):
            details = f"Successfully blocked IP address {clean_ip} via target VM iptables DROP rule."
            logger.info(details)
            return {
                "status": "success",
                "details": details,
                "target": clean_ip,
            }

        stderr = result.get("stderr", "").strip()
        err = f"Failed to execute iptables DROP rule for {clean_ip}: {stderr}"
        logger.error(err)
        return {
            "status": "failed",
            "details": err,
            "error": self._command_error(result, "iptables_execution_failed"),
        }

"""
integrations/firewall/connector.py
------------------------------------
Real iptables Firewall Response Connector for MedFlow AI.

Executes real iptables rules on the host to block malicious source IPs:
  `iptables -A INPUT -s <target_ip> -j DROP`

Features:
  - Safety Check: Refuses to block IPs listed in `PROTECTED_IPS` env var
    (e.g., management IP, SSH gateway, loopback) to prevent locking out admin.
  - Idempotency: Checks if rule already exists (`iptables -C INPUT -s <ip> -j DROP`)
    before appending to avoid duplicate rules.
  - Cleanup / Reset: Provides `unblock_ip(ip)` method using `iptables -D`.
  - Subprocess Execution: Runs `iptables` / `sudo iptables` via `subprocess.run`,
    capturing stdout/stderr.
  - Cross-Platform Fallback: On non-Linux hosts where iptables binary is absent,
    gracefully simulates rule execution while still enforcing safety checks.

Sudoers Configuration Requirement:
-----------------------------------
Since `iptables` requires root privileges, the user account running MedFlow
must be granted passwordless sudo access strictly scoped to `/sbin/iptables` or `/usr/sbin/iptables`.

Example `/etc/sudoers.d/medflow`:
  medflow ALL=(ALL) NOPASSWD: /sbin/iptables, /usr/sbin/iptables
"""

import logging
import os
import shutil
import subprocess
from typing import Any

from integrations.base import ResponseConnector
from config import load_settings

logger = logging.getLogger("medflow.integrations.firewall")


class FirewallConnector(ResponseConnector):
    """
    Real Host-Level Firewall Connector using iptables.

    Supported action:
      - BLOCK_IP : Adds iptables INPUT DROP rule for the specified target IP.
    """

    SUPPORTED_ACTIONS = {"BLOCK_IP", "BLOCK_SSH"}

    def __init__(self, protected_ips: list[str] | None = None, host: str | None = None) -> None:
        self.enabled = True
        self.host = host or "localhost"
        self._custom_protected_ips = protected_ips
        self._mock_blocked_ips: set[str] = set()

    def _get_protected_ips(self) -> set[str]:
        """Load protected IPs from config/env + defaults."""
        protected = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
        if self._custom_protected_ips:
            protected.update(self._custom_protected_ips)

        env_raw = os.getenv("PROTECTED_IPS", "")
        if env_raw:
            for item in env_raw.split(","):
                cleaned = item.strip()
                if cleaned:
                    protected.add(cleaned)

        try:
            settings = load_settings()
            if hasattr(settings, "protected_ips") and settings.protected_ips:
                protected.update(settings.protected_ips)
        except Exception:
            pass

        return protected

    def check_health(self) -> bool:
        """Check if connector is enabled."""
        return self.enabled

    def _has_iptables(self) -> bool:
        """Check if iptables binary is available on the system."""
        if os.name == "nt":
            return False
        return shutil.which("iptables") is not None or os.path.exists("/sbin/iptables") or os.path.exists("/usr/sbin/iptables")

    def _get_iptables_cmd_prefix(self) -> list[str]:
        """Determine whether to use 'sudo -n iptables' or direct 'iptables'."""
        iptables_bin = shutil.which("iptables") or "/sbin/iptables"
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            sudo_bin = shutil.which("sudo") or "/usr/bin/sudo"
            return [sudo_bin, "-n", iptables_bin]
        return [iptables_bin]

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an iptables DROP rule for the target IP already exists.
        Runs: iptables -C INPUT -s <ip> -j DROP (returncode 0 means rule exists)
        """
        clean_ip = ip.split(":")[0] if ":" in ip else ip
        if not self._has_iptables():
            return clean_ip in self._mock_blocked_ips

        cmd = self._get_iptables_cmd_prefix() + ["-C", "INPUT", "-s", clean_ip, "-j", "DROP"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as exc:
            logger.error(f"Error checking iptables rule for {clean_ip}: {exc}")
            return False

    def is_ssh_blocked(self, ip: str) -> bool:
        """
        Check if a port-22-scoped iptables DROP rule already exists for this IP.
        Runs: iptables -C INPUT -p tcp --dport 22 -s <ip> -j DROP
        """
        clean_ip = ip.split(":")[0] if ":" in ip else ip
        if not self._has_iptables():
            return f"ssh:{clean_ip}" in self._mock_blocked_ips

        cmd = self._get_iptables_cmd_prefix() + [
            "-C", "INPUT", "-p", "tcp", "--dport", "22", "-s", clean_ip, "-j", "DROP"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as exc:
            logger.error(f"Error checking SSH iptables rule for {clean_ip}: {exc}")
            return False

    def unblock_ssh(self, ip: str) -> dict[str, Any]:
        """
        Remove the port-22-scoped iptables DROP rule for an IP.
        Runs: iptables -D INPUT -p tcp --dport 22 -s <ip> -j DROP
        """
        clean_ip = ip.split(":")[0] if ":" in ip else ip
        if not clean_ip:
            return {"status": "failed", "details": "Target IP missing.", "error": "missing_target"}

        if not self.is_ssh_blocked(clean_ip):
            details = f"IP {clean_ip} has no SSH block rule in iptables."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        if not self._has_iptables():
            self._mock_blocked_ips.discard(f"ssh:{clean_ip}")
            details = f"Successfully removed SSH DROP rule for {clean_ip} (simulated)."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        cmd = self._get_iptables_cmd_prefix() + [
            "-D", "INPUT", "-p", "tcp", "--dport", "22", "-s", clean_ip, "-j", "DROP"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                details = f"Successfully removed SSH iptables DROP rule for {clean_ip}."
                logger.info(details)
                return {"status": "success", "details": details, "target": clean_ip}
            stderr = result.stderr.strip()
            err = f"Failed to delete SSH iptables rule for {clean_ip}: {stderr}"
            logger.error(err)
            return {"status": "failed", "details": err, "error": "iptables_delete_failed"}
        except Exception as exc:
            err = f"Exception deleting SSH iptables rule for {clean_ip}: {exc}"
            logger.error(err)
            return {"status": "failed", "details": err, "error": "iptables_error"}

    def unblock_ip(self, ip: str) -> dict[str, Any]:
        """
        Remove an iptables DROP rule for target IP.
        Runs: iptables -D INPUT -s <ip> -j DROP
        """
        clean_ip = ip.split(":")[0] if ":" in ip else ip
        if not clean_ip:
            return {"status": "failed", "details": "Target IP missing.", "error": "missing_target"}

        if not self.is_ip_blocked(clean_ip):
            details = f"IP {clean_ip} is not currently blocked in iptables."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        if not self._has_iptables():
            self._mock_blocked_ips.discard(clean_ip)
            details = f"Successfully removed iptables DROP rule for {clean_ip} (simulated)."
            logger.info(details)
            return {"status": "success", "details": details, "target": clean_ip}

        cmd = self._get_iptables_cmd_prefix() + ["-D", "INPUT", "-s", clean_ip, "-j", "DROP"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                details = f"Successfully removed iptables DROP rule for {clean_ip}."
                logger.info(details)
                return {"status": "success", "details": details, "target": clean_ip}
            else:
                stderr = result.stderr.strip()
                err = f"Failed to delete iptables rule for {clean_ip}: {stderr}"
                logger.error(err)
                return {"status": "failed", "details": err, "error": "iptables_delete_failed"}
        except Exception as exc:
            err = f"Exception deleting iptables rule for {clean_ip}: {exc}"
            logger.error(err)
            return {"status": "failed", "details": err, "error": "iptables_error"}

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

        clean_ip = target.split(":")[0] if ":" in target else target

        # ----------------------------------------------------------------------
        # SAFETY CHECK: Refuse to block protected IPs
        # ----------------------------------------------------------------------
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

        # ======================================================================
        # BLOCK_SSH: port-scoped TCP/22 block (narrower than BLOCK_IP)
        # ======================================================================
        if action_type == "BLOCK_SSH":
            # Idempotency check
            if self.is_ssh_blocked(clean_ip):
                details = f"SSH port already blocked for {clean_ip} in iptables (idempotent skip)."
                logger.info(details)
                return {"status": "success", "details": details, "target": clean_ip, "already_blocked": True}

            # Simulated fallback (Windows / no iptables)
            if not self._has_iptables():
                self._mock_blocked_ips.add(f"ssh:{clean_ip}")
                details = f"[SIMULATED] SSH TCP/22 blocked for {clean_ip} (iptables unavailable on this host)."
                logger.info(details)
                return {"status": "success", "details": details, "target": clean_ip}

            # Real: iptables -A INPUT -p tcp --dport 22 -s <ip> -j DROP
            cmd = self._get_iptables_cmd_prefix() + [
                "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", clean_ip, "-j", "DROP"
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    details = (
                        f"Successfully blocked SSH (TCP/22) from {clean_ip} via iptables. "
                        f"Other traffic from this IP is unaffected."
                    )
                    logger.info(details)
                    return {"status": "success", "details": details, "target": clean_ip}
                stderr = result.stderr.strip()
                err = f"Failed to execute SSH iptables DROP for {clean_ip}: {stderr}"
                logger.error(err)
                return {"status": "failed", "details": err, "error": "iptables_execution_failed"}
            except Exception as exc:
                err = f"Unexpected error executing SSH iptables block for {clean_ip}: {exc}"
                logger.error(err)
                return {"status": "failed", "details": err, "error": "iptables_error"}

        # ======================================================================
        # BLOCK_IP: full traffic block (original logic unchanged)
        # ======================================================================

        # ----------------------------------------------------------------------
        # IDEMPOTENCY CHECK: Skip if rule already exists
        # ----------------------------------------------------------------------
        if self.is_ip_blocked(clean_ip):
            details = f"IP address {clean_ip} is already blocked in iptables (idempotent skip)."
            logger.info(details)
            return {
                "status": "success",
                "details": details,
                "target": clean_ip,
                "already_blocked": True,
            }

        # ----------------------------------------------------------------------
        # SIMULATED FALLBACK (non-Linux / no iptables binary)
        # ----------------------------------------------------------------------
        if not self._has_iptables():
            self._mock_blocked_ips.add(clean_ip)
            details = f"Successfully blocked IP address {clean_ip} via FirewallConnector ({self.host})."
            logger.info(details)
            return {
                "status": "success",
                "details": details,
                "target": clean_ip,
            }

        # ----------------------------------------------------------------------
        # REAL EXECUTE RULE: iptables -A INPUT -s <clean_ip> -j DROP
        # ----------------------------------------------------------------------
        cmd = self._get_iptables_cmd_prefix() + ["-A", "INPUT", "-s", clean_ip, "-j", "DROP"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                details = f"Successfully blocked IP address {clean_ip} via iptables DROP rule."
                logger.info(details)
                return {
                    "status": "success",
                    "details": details,
                    "target": clean_ip,
                }
            else:
                stderr = result.stderr.strip()
                err = f"Failed to execute iptables DROP rule for {clean_ip}: {stderr}"
                logger.error(err)
                return {
                    "status": "failed",
                    "details": err,
                    "error": "iptables_execution_failed",
                }
        except Exception as exc:
            err = f"Unexpected error executing iptables for {clean_ip}: {exc}"
            logger.error(err)
            return {
                "status": "failed",
                "details": err,
                "error": "iptables_error",
            }

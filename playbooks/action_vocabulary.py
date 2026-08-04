"""
playbooks/action_vocabulary.py
==============================
Single source of truth for all permitted response action names across
the MedFlow AI Cybersecurity Ecosystem.

Design intent
-------------
Every component that proposes, validates, or eventually executes a
response action — the Playbook Loader (Phase 2), the Response Planner
Agent (Phase 3), and the Active Response Executor (Phase 5) — MUST
reference this enum rather than using raw strings.  This prevents
"action name drift" where different subsystems invent slightly different
names (e.g. "block_ip" vs "BLOCK_IP" vs "block-ip") for the same
concept.

Risk tiers (contextual reference, enforced per playbook YAML)
-------------------------------------------------------------
  Tier 1 — Observational / notification only (zero operational impact)
  Tier 2 — Network-layer controls (may disrupt connectivity)
  Tier 3 — Host-level containment (significant operational impact)
  Tier 4 — Identity / process termination (high operational impact)
"""
from __future__ import annotations

from enum import Enum


class ResponseActionType(str, Enum):
    """
    Exhaustive, canonical vocabulary of response action types.

    Adding a new action to this ecosystem REQUIRES adding it here first.
    Playbook YAMLs reference these names exactly (case-sensitive).
    """

    # ------------------------------------------------------------------ #
    #  Tier 1 — Safe / observational actions (no operational side-effects) #
    # ------------------------------------------------------------------ #
    NOTIFY_SOC = "NOTIFY_SOC"
    """Alert SOC analysts via ticketing/SIEM notification.  No system changes."""

    CREATE_REPORT = "CREATE_REPORT"
    """Generate a structured incident report artifact. No system changes."""

    LOG_EVENT = "LOG_EVENT"
    """Append a forensic log entry to the incident audit trail. No system changes."""

    MONITOR_ACCOUNT = "MONITOR_ACCOUNT"
    """Increase telemetry/alerting sensitivity on a specific user account."""

    COLLECT_FORENSICS = "COLLECT_FORENSICS"
    """Trigger memory / disk snapshot collection on a host for later analysis."""

    # ------------------------------------------------------------------ #
    #  Tier 2 — Network-layer controls (reversible, moderate disruption)   #
    # ------------------------------------------------------------------ #
    BLOCK_IP = "BLOCK_IP"
    """Add an IP address or CIDR block to the network deny-list (firewall rule)."""

    BLOCK_SSH = "BLOCK_SSH"
    """
    Block all TCP traffic on port 22 from a specific source IP via iptables.
    Narrower than BLOCK_IP: only SSH is blocked; the attacker's other traffic
    (e.g., web browsing through the same NAT) is unaffected, preventing
    collateral disruption to legitimate clinicians on shared NAT gateways.
    Used by the SSH Brute Force playbook as the primary containment action.
    """

    DROP_CONNECTION = "DROP_CONNECTION"
    """
    Force-drop an active network connection from an attacker IP by injecting
    a Suricata 'drop' rule into local.rules and reloading the IDS engine.
    Targets the attacker's active session — no impact on legitimate traffic.
    """

    ADD_RULE = "ADD_RULE"
    """
    Dynamically add a custom Suricata detection/enforcement rule to local.rules
    and reload the IDS engine. More flexible than DROP_CONNECTION; allows
    arbitrary rule expressions.
    """

    QUARANTINE_EMAIL = "QUARANTINE_EMAIL"
    """Move a suspicious e-mail message to the quarantine folder."""

    RESET_MFA = "RESET_MFA"
    """Force a multi-factor-authentication token reset for a user."""

    REVOKE_SESSION = "REVOKE_SESSION"
    """Immediately invalidate all active authentication sessions for a user."""

    # ------------------------------------------------------------------ #
    #  Tier 3 — Host-level containment (significant operational impact)    #
    # ------------------------------------------------------------------ #
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    """
    Network-isolate a host.  On patient-care assets this can disrupt
    clinical operations; requires explicit human approval.
    """

    PATCH_SYSTEM = "PATCH_SYSTEM"
    """Apply a security patch or hotfix to a host. May require a brief restart."""

    # ------------------------------------------------------------------ #
    #  Tier 4 — Identity / process termination (highest operational impact) #
    # ------------------------------------------------------------------ #
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    """
    Disable a user or service account entirely.  On clinical systems a
    service account may be the only authentication path for a medical device.
    """

    KILL_PROCESS = "KILL_PROCESS"
    """
    Forcibly terminate a running process.  On patient-care devices this
    could interrupt active treatments; Tier 4, always requires approval.
    """


# Convenience set for O(1) membership tests in the validator
VALID_ACTION_NAMES: frozenset[str] = frozenset(e.value for e in ResponseActionType)

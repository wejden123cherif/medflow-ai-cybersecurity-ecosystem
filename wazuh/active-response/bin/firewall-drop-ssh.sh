#!/bin/bash
# =============================================================================
# MedFlow AI — Wazuh Active Response: SSH Brute Force Block
# =============================================================================
#
# Script: firewall-drop-ssh.sh
# Triggered by: Wazuh rule 5712 (SSHD brute force threshold exceeded)
#
# What it does
# -------------
# Adds a port-22-scoped iptables DROP rule for the attacker's source IP:
#   iptables -I INPUT -p tcp --dport 22 -s <attacker_ip> -j DROP
#
# This is narrower than a full BLOCK_IP (-A INPUT -s <ip> -j DROP):
#   - Only TCP/22 (SSH) from the attacker is dropped.
#   - The attacker IP can still reach HTTPS (443), HTTP (80) etc.,
#     which is important in hospital NAT environments where multiple
#     users share the same external IP.
#
# Wazuh integration
# ------------------
# Wazuh passes the attacker IP as $SRCIP (environment variable).
# The script is called with the action as the first argument:
#   add    → block the IP
#   delete → unblock the IP (used for time-based unblocking)
#
# Wazuh calls this script at:
#   /var/ossec/active-response/bin/firewall-drop-ssh.sh
#
# The script must be installed on each monitored agent, or on the
# Wazuh Manager if the response target is the manager itself.
#
# Safety guards
# --------------
# - Skips loopback (127.x.x.x) and RFC1918 private ranges to prevent
#   blocking internal clinical systems.
# - Checks for empty SRCIP before executing any iptables command.
# - Logs all actions to /var/ossec/logs/active-responses.log
#
# Reversal
# ---------
# To unblock manually:
#   iptables -D INPUT -p tcp --dport 22 -s <ip> -j DROP
# Wazuh will call this script with "delete" argument after the timeout
# configured in ossec.conf (<timeout>).
# =============================================================================

LOCAL=$(dirname "$0")
LOG_FILE="/var/ossec/logs/active-responses.log"
ACTION="$1"      # "add" or "delete"
SRCIP="$SRCIP"   # Set by Wazuh from the alert's source IP field

# ─── Logging helper ───────────────────────────────────────────────────────────
log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') firewall-drop-ssh: $1" >> "$LOG_FILE"
}

# ─── Validate input ───────────────────────────────────────────────────────────
if [ -z "$SRCIP" ]; then
    log "ERROR: SRCIP is empty — no action taken."
    exit 1
fi

if [ -z "$ACTION" ]; then
    log "ERROR: ACTION argument missing (expected 'add' or 'delete') — no action taken."
    exit 1
fi

# ─── Safety: skip loopback and RFC1918 private ranges ─────────────────────────
is_protected() {
    local ip="$1"
    # Loopback
    echo "$ip" | grep -qE '^127\.' && return 0
    # RFC1918
    echo "$ip" | grep -qE '^10\.' && return 0
    echo "$ip" | grep -qE '^172\.(1[6-9]|2[0-9]|3[01])\.' && return 0
    echo "$ip" | grep -qE '^192\.168\.' && return 0
    # Link-local
    echo "$ip" | grep -qE '^169\.254\.' && return 0
    return 1
}

if is_protected "$SRCIP"; then
    log "SAFETY SKIP: $SRCIP is a protected/private IP — SSH block refused."
    exit 0
fi

# ─── Ensure iptables is available ─────────────────────────────────────────────
IPTABLES=$(command -v iptables 2>/dev/null || echo "/sbin/iptables")
if [ ! -x "$IPTABLES" ]; then
    log "ERROR: iptables not found at $IPTABLES — cannot execute action '$ACTION' for $SRCIP."
    exit 1
fi

# ─── Execute ──────────────────────────────────────────────────────────────────
if [ "$ACTION" = "add" ]; then
    # Idempotency: check if the rule already exists
    if $IPTABLES -C INPUT -p tcp --dport 22 -s "$SRCIP" -j DROP 2>/dev/null; then
        log "INFO: SSH DROP rule for $SRCIP already exists (idempotent skip)."
        exit 0
    fi

    # Insert at position 1 (highest priority, evaluated first)
    if $IPTABLES -I INPUT 1 -p tcp --dport 22 -s "$SRCIP" -j DROP; then
        log "SUCCESS: Blocked SSH (TCP/22) from $SRCIP — rule inserted at INPUT position 1."
    else
        log "ERROR: Failed to add SSH iptables DROP rule for $SRCIP."
        exit 1
    fi

elif [ "$ACTION" = "delete" ]; then
    if $IPTABLES -C INPUT -p tcp --dport 22 -s "$SRCIP" -j DROP 2>/dev/null; then
        if $IPTABLES -D INPUT -p tcp --dport 22 -s "$SRCIP" -j DROP; then
            log "SUCCESS: Removed SSH DROP rule for $SRCIP (timeout/unblock)."
        else
            log "ERROR: Failed to remove SSH iptables DROP rule for $SRCIP."
            exit 1
        fi
    else
        log "INFO: No SSH DROP rule found for $SRCIP — nothing to remove."
    fi

else
    log "ERROR: Unknown action '$ACTION' — expected 'add' or 'delete'."
    exit 1
fi

exit 0

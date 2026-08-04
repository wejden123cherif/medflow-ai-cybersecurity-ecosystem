#!/bin/bash
set -e

# Auto-detect default active network interface if SURICATA_IFACE is not set
IFACE="${SURICATA_IFACE:-}"

if [ -z "$IFACE" ]; then
    IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1)
fi

if [ -z "$IFACE" ]; then
    # Fallback search if no default route
    IFACE=$(ip link show | grep -E '^[0-9]+: (ens|eth|enp)' | awk -F': ' '{print $2}' | head -n1)
fi

if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi

echo "========================================================"
echo "Starting Suricata IDS on interface: ${IFACE}"
echo "========================================================"

exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --set vars.address-groups.HOME_NET=any -l /var/log/suricata/

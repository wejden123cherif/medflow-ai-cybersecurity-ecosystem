#!/bin/bash
# MedFlow custom active response for SSH brute-force detection.
# This is intentionally lightweight and project-owned so it can be versioned with the
# MedFlow repository instead of living in an external upstream wazuh-docker clone.

# shellcheck disable=SC2034
RULE_ID="${1:-5712}"
SRC_IP="${2:-0.0.0.0}"

logger "MedFlow active response triggered for rule ${RULE_ID} from ${SRC_IP}"

# This project keeps the active response intentionally conservative. A real environment can
# replace this stub with a firewall or host-level block action appropriate to the deployment.
exit 0

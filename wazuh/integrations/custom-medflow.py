#!/usr/bin/env python3
"""Minimal MedFlow custom integration for Suricata/Wazuh alert ingestion.

This file is intentionally small and repository-friendly. It is designed to be mounted
inside the Wazuh manager container and can be expanded with richer MedFlow alert routing
logic later. The critical part is that the manager is configured to ingest Suricata event
logs and to forward them to MedFlow-specific processing.
"""

from __future__ import annotations

import json
from pathlib import Path

SURICATA_LOG = Path('/var/log/suricata/eve.json')


def main() -> int:
    if not SURICATA_LOG.exists():
        return 0

    try:
        with SURICATA_LOG.open('r', encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if payload.get('event_type'):
                    print(json.dumps(payload, separators=(',', ':')))
    except OSError:
        return 0

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

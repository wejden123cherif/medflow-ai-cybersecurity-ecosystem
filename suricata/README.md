# Suricata integration

This directory contains the repository's Linux-oriented Suricata container configuration and rule examples. It is separate from the Windows Docker Desktop SSH lab sensor, which is maintained outside this repository.

## Files

- `Dockerfile` builds the Suricata image.
- `docker-compose.yml` runs the repository sensor with Linux host networking.
- `suricata.yaml` enables EVE JSON output and configures capture interfaces.
- `rules/local.rules` contains the repository's custom demonstration rules.
- `pcap/test.pcap` is a maintained offline capture fixture; it is not evidence of live traffic.

The Compose sensor uses `network_mode: host`, which is intended for Linux. Docker Desktop on Windows does not expose host packet capture in the same way. Do not treat this container's existing EVE file as proof that it inspected Windows loopback or SSH traffic.

## EVE collection

Suricata writes EVE JSONL to `/var/log/suricata/eve.json` inside its container. The repository Suricata Compose file mounts `suricata/logs` for that sensor. The isolated lab sensor instead writes the reported file `suricata/lab-logs/eve.json`; the root MedFlow Compose service mounts that directory read-only into the app and sets `SURICATA_EVE_PATH=/app/suricata/lab-logs/eve.json`.

Confirm the active sensor, interface, file timestamp, and source path before using a live investigation. Do not edit historical event timestamps or generate traffic outside the authorized lab process.

## Rules

The checked-in `rules/local.rules` includes demonstration rules such as ICMP SID `9000001`, network-scan SID `9000002`, and SSH connection-pattern SID `9000003`. These are distinct from the separate lab rule SID `9900003` reported in `suricata/lab-logs/eve.json`. The lab SID detects repeated SSH connections, not necessarily failed passwords. Wazuh authentication rule `5760` provides endpoint authentication evidence when its agent and manager are configured to collect it.

The Suricata response adapter exists under `integrations/ids/`, but live rule changes or drops have not been verified end to end. Review approval, lab scope, and rollback before enabling any live response.

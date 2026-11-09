# Wazuh and Suricata deployment notes

This document describes the source paths and the lab evidence that has been reported. It does not claim that a live AI investigation, automatic incident email, or containment has completed end to end.

## Deployment boundaries

- The root `docker-compose.yml` includes optional Wazuh services and a Suricata service intended for a Linux host. The Suricata service uses host networking, which does not provide equivalent packet capture on Docker Desktop for Windows.
- The Windows SSH lab and dedicated Suricata sensor may be separate, user-maintained Compose projects. Their definitions and credentials are not included in this repository.
- A local upstream Wazuh Docker clone may exist at `wazuh/wazuh-docker/`; the clone and its generated TLS material are excluded from Git. Do not commit private keys, certificates, passwords, or raw event logs from that deployment.
- MISP is configured as an optional external service; the root Compose file does not start it.

## Suricata EVE paths

For the isolated Windows lab, the observed host file is `suricata/lab-logs/eve.json`. The root MedFlow service configuration points to `/app/suricata/lab-logs/eve.json` and mounts the host lab log directory read-only at `/app/suricata/lab-logs`.

The Linux-oriented root Suricata configuration may instead write `suricata/logs/eve.json`. Do not assume those are the same sensor or data source. Confirm which EVE file belongs to the active lab sensor before investigating it. The MedFlow collector reads complete JSONL records and maintains its own offset and pending-event checkpoint.

## Wazuh configuration

The MedFlow process uses `WAZUH_URL`, `WAZUH_USER`, `WAZUH_PASSWORD`, `WAZUH_INDEXER_URL`, and the Indexer credentials from local environment configuration. The collector uses bounded, read-only alert queries. Keep TLS verification enabled; use `WAZUH_CA_BUNDLE` only for a trusted CA file readable at the configured path. Do not paste credentials into documentation, shell transcripts, or logs.

The Wazuh manager must be configured to read the correct EVE path if Suricata events are also being forwarded through Wazuh. The tracked manager template is `wazuh/config/wazuh_manager.conf`; local external Compose mounts may differ and must be checked against the active deployment before changing or restarting Wazuh.

## Reported lab evidence

- A genuine SSH authentication failure matched Wazuh rule `5760` and was visible in the Wazuh Dashboard.
- The dedicated lab Suricata sensor produced SID `9900003`. This rule signals repeated SSH connection activity and does not independently prove failed authentication.
- Local read-only MedFlow ingestion retrieved Wazuh alerts and Suricata signature `1:9900003:1`.
- The MedFlow container was verified to read the lab EVE path through a read-only bind mount.

These checks verify sensor/collector access, not incident correlation, incident persistence, automatic SMTP delivery, or live containment. Verify each of those separately before describing the project as end-to-end operational.

## Safe verification

Validate the Compose file without changing services:

```powershell
docker compose config --quiet
```

Check the app health endpoint:

```powershell
Invoke-RestMethod -Uri http://localhost:8000/health
```

The opt-in `scripts/verify_lab_ingestion.py` performs bounded read-only collection using temporary checkpoints. It requires `MEDFLOW_ENABLE_READ_ONLY_LAB_INGESTION=1` plus `--live-lab-read-only`, `--confirm-authorized-read-only`, and `--confirm-trusted-tls`; its `--max-events` and `--lookback-days` options bound collection. Review its help and the configured endpoint/CA before running it. It must not be used to generate traffic or invoke notifications/response actions.

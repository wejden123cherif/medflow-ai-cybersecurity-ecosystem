# Wazuh + Suricata Deployment for MedFlow

## Purpose

Document the deployment steps and validation for ingesting Suricata `eve.json` into Wazuh and confirming MedFlow can consume alerts without any code changes.

## Architecture

- Wazuh single-node stack is deployed from `wazuh/wazuh-docker/single-node/docker-compose.yml`.
- The Wazuh manager container mounts Suricata logs from the repository path `suricata/logs`.
- Wazuh is configured to read Suricata JSON alerts from `/var/log/suricata/eve.json` using the Wazuh localfile JSON input.
- MedFlow uses its existing Wazuh collector configuration in `.env` to query the Wazuh manager and indexer.

## Key Configuration

### Wazuh manager compose mount

In `wazuh/wazuh-docker/single-node/docker-compose.yml`, the manager service mounts Suricata logs:

```yaml
      - ../../../suricata/logs:/var/log/suricata:ro
```

### Wazuh manager JSON ingestion config

In `wazuh/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`, add a localfile block for Suricata:

```xml
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
    <alias>Suricata eve.json</alias>
  </localfile>
```

This tells Wazuh to consume Suricata alerts in JSON format from the mounted `eve.json` file.

### MedFlow environment

MedFlow reads Wazuh settings from `.env` via `config.py`.
The relevant values are already configured as:

```ini
WAZUH_URL=https://localhost:56000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=SecretPassword
```

No MedFlow Python code changes were required for this integration.

## Deployment Steps

1. Start the Wazuh single-node stack:
   ```powershell
   cd wazuh/wazuh-docker/single-node
   docker compose up -d
   ```

2. Ensure Suricata is running and writing `eve.json` to `suricata/logs/eve.json`.

3. Confirm the Wazuh manager has the Suricata logs mounted and can read the file.

4. If Wazuh manager configuration was changed, restart the stack:
   ```powershell
   docker compose restart wazuh.manager
   ```

## Validation

### Wazuh manager local alert ingestion

Confirmed Suricata-originated alerts in the Wazuh alerts JSON log with decoded rule metadata:

- `Suricata: Alert - MEDFLOW T1046 Network Service Scanning Attempt`
- `Suricata: Alert - MEDFLOW-TEST ICMP Ping Detected`

Example log entries were found in `/var/ossec/logs/alerts/alerts.json`.

### Wazuh indexer API

The indexer exposed alert indices and contained Suricata alerts in `wazuh-alerts-4.x-2026.07.20`.

Recent indexed alert hits included Suricata signatures and rule groups:

- `Suricata: Alert - MEDFLOW T1046 Network Service Scanning Attempt`
- `Suricata: Alert - MEDFLOW-TEST ICMP Ping Detected`

### MedFlow live investigation

`python app.py investigate --scenario live --with-response` successfully executed and collected live alerts from Wazuh.

Results showed:

- `Data source: wazuh_live`
- `Alerts collected: 21`
- `Live alerts: 21`
- Top risk alerts and a generated incident response plan were produced.

## Notes

- Wazuh manager API at `https://localhost:56000` may be unavailable if the Wazuh manager service is not yet ready; MedFlow falls back to querying the indexer when necessary.
- Current verification demonstrates end-to-end alert ingestion and MedFlow consumption without altering MedFlow Python source code.

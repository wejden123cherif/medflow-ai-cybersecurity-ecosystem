# Suricata IDS — MedFlow AI Integration

This directory contains the Suricata IDS Docker setup for the **MedFlow AI Cybersecurity Ecosystem**.

## Directory Structure

```
suricata/
├── Dockerfile           # Builds Suricata from Ubuntu 22.04 + OISF PPA
├── docker-compose.yml   # Launches Suricata as a service
├── suricata.yaml        # Suricata configuration (eve-log enabled)
├── rules/
│   └── local.rules      # Custom MITRE ATT&CK-mapped detection rules
├── logs/                # Volume mount — eve.json written here at runtime
│   └── .gitkeep
└── README.md
```

## How It Works

1. **Suricata** runs as a Docker container in `network_mode: host`, sniffing live network traffic.
2. It writes **JSON alerts** to `/var/log/suricata/eve.json` inside the container.
3. This path is **volume-mounted** to `./logs/eve.json` on the host filesystem.
4. **MedFlow** reads `eve.json` via the `SURICATA_EVE_PATH` environment variable using `collectors/suricata.py`.

## Getting Started

### 1. Start Suricata

```bash
cd suricata/
docker-compose up -d
```

### 2. Verify it's running

```bash
docker-compose ps
docker logs medflow-suricata
```

### 3. Check eve.json is being generated

```bash
tail -f suricata/logs/eve.json
```

### 4. Configure MedFlow

Ensure your `.env` file contains:

```env
SURICATA_EVE_PATH=suricata/logs/eve.json
```

This is the path the `SuricataCollector` reads from.

## Custom Rules

Rules are in `rules/local.rules`. They include detections for:

| SID     | Technique     | Description                      |
|---------|---------------|----------------------------------|
| 9000001 | —             | ICMP ping (connectivity test)    |
| 9000002 | T1046         | Network Service Scanning         |
| 9000003 | T1110         | SSH Brute Force                  |
| 9000004 | T1110.001     | RDP Brute Force                  |
| 9000005 | T1071.001     | Suspicious HTTP User-Agent       |
| 9000006 | T1041         | Large Outbound Data Exfiltration |
| 9000007 | T1190         | SQL Injection Attempt            |
| 9000008 | T1059         | Remote Code Execution via HTTP   |
| 9000009 | T1071.004     | DNS Tunneling (Long Query)       |
| 9000010 | T1498         | UDP Flood DoS Attack             |

## MITRE ATT&CK Mapping

The `SuricataCollector` (`collectors/suricata.py`) automatically extracts MITRE technique IDs from the rule `msg` field using the pattern `T\d{4}`. MedFlow uses this for triage and enrichment.

## Future Connectors

The Suricata IDS integration in `integrations/ids/` (planned) can use the Suricata Unix socket or REST API to dynamically load/reload rules and query alert statistics without parsing eve.json.

## Stopping Suricata

```bash
cd suricata/
docker-compose down
```

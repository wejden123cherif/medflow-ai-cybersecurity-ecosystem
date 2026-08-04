# MedFlow AI Cybersecurity Ecosystem

MedFlow is an AI-powered incident response platform that combines LangGraph, RAG, MITRE ATT&CK CTI, Wazuh integration, Suricata detection, and automated response execution.

## Deployment architecture

The stack is intentionally split into separate services rather than putting everything in a single container.

```text
Attacker VM (Hydra) --> Suricata IDS --> Wazuh Manager --> MedFlow app
                                       |
                                   Wazuh Indexer / Dashboard

MedFlow app:
  - FastAPI API (`api.py`)
  - CLI (`app.py`)
  - LangGraph investigation flow
  - MITRE CTI + vector DB + RAG logic
  - alert collection and response automation
```

### Service layout

- `medflow` container: the main Python app that investigates incidents, queries Wazuh, builds response plans, and serves the API.
- `wazuh.manager` container: manager and API layer for Wazuh.
- `wazuh.indexer` container: alert storage and search backend for Wazuh.
- `wazuh.dashboard` container: Wazuh UI.
- `suricata` container: IDS sensor that writes Suricata EVE logs into a mounted log directory.

This is the best realistic SOC architecture for this project because Wazuh and Suricata are independent operational services with different responsibilities, data flows, and lifecycle needs.

## Main entry points

- `app.py` – CLI entry point for status checks, searches, and investigation runs.
- `api.py` – FastAPI webhook service and health endpoint.
- `graphs/threat_intel_graph.py` – incident response workflow orchestrator.
- `config.py` – environment settings and persistent-data paths.

## Operational requirements

The project assumes:

- Python 3.10+ at the host or in the app container
- Git access for the MITRE CTI repo clone
- a valid Groq API key
- Docker and Docker Compose on the defender VM
- a Wazuh-enabled alert ingestion path from Suricata into Wazuh

## Required data and persistent storage

The app expects persistent folders for:

- `data/mitre-cti/` – MITRE CTI data download
- `vector_dbs/` – generated Chroma databases
- `.cache/` – embedding model cache
- `suricata/logs/` – Suricata EVE output
- `logs/` – app runtime logs

These are persisted via Docker volumes and mounted paths in Compose.

## Environment variables

Copy `.env.example` to `.env` and populate it before starting the stack.

Required values include:

```env
GROQ_API_KEY=your_key
WAZUH_URL=https://wazuh.manager:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-
WAZUH_INDEXER_URL=https://wazuh.indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=SecretPassword
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASSWORD=your_password
SMTP_FROM=medflow-ai-soc@gmail.com
SOC_EMAIL=ops@example.com
```

## Quick start

On a fresh Ubuntu VM:

```bash
git clone <repo-url>
cd <repo-folder>
cp .env.example .env
# edit .env with your credentials and local values

python scripts/bootstrap_external_services.py
# this creates Suricata folders and clones wazuh-docker + misp-docker if missing

docker compose up -d --build
```

Then verify:

```bash
docker compose ps
curl http://localhost:8000/health
curl -k https://localhost:56000
curl -k https://localhost:9200
```

## Service lifecycle

```bash
docker compose up -d

docker compose logs -f medflow
docker compose logs -f wazuh.manager
docker compose logs -f suricata

docker compose down
```

## How MedFlow receives alerts

1. Suricata detects suspicious traffic and writes `eve.json` into `suricata/logs`.
2. The Wazuh manager is configured to ingest the Suricata JSON stream.
3. MedFlow queries Wazuh via its collectors and normalizes the alerts into the incident graph.
4. The LangGraph workflow correlates those alerts with MITRE ATT&CK, vector DB context, and possible response actions.
5. Recommended response actions can be executed or staged through the MedFlow response layer.

## Reproducible initialization

The app startup script initializes data automatically when missing:

- downloads the MITRE CTI repo if absent
- builds the vector databases if absent
- prints the project status
- starts the API server

This is handled by [docker/init-medflow.sh](docker/init-medflow.sh) and the Docker startup command.

## Git hygiene

The following must not be committed:

- `.env`
- `.venv/`
- `data/mitre-cti/`
- `vector_dbs/`
- generated logs
- cache files

Repository content is kept to source code, Docker config, setup scripts, and docs.

## Notes

This architecture is suitable for a lab or SOC-style deployment. For a hardened production environment, add TLS certificates, network segmentation, secret rotation, and stronger IAM rules around the Wazuh stack and the MedFlow API.

## Safety note

This project is intended for defensive, authorized cybersecurity work and controlled lab environments.

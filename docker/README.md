# Docker deployment notes

This repository supports a production-oriented multi-container deployment for the MedFlow SOC stack.

## Service layout

- medflow: main Python application, FastAPI API, LangGraph workflows, RAG, investigation engine
- wazuh.manager: manager service that ingests alerts and exposes the Wazuh API
- wazuh.indexer: search/index store for alert data
- wazuh.dashboard: dashboard UI
- suricata: IDS sensor that writes eve.json to the shared log volume

## Important architecture choice

Wazuh and Suricata should not run in the same Python app container. They are independent services with different operational responsibilities and lifecycle requirements.

The recommended production pattern is:

- MedFlow application in its own container
- Wazuh manager + indexer + dashboard in separate containers
- Suricata in its own dedicated IDS container
- Shared Docker volumes for logs, CTI, vector data, and caches
- Docker networks for internal service communication

This structure matches a realistic SOC deployment model and keeps the MedFlow platform from becoming a monolith.

## Operational notes

- Fresh environments clone the repo and run `docker compose up -d --build`.
- `docker/init-medflow.sh` populates MITRE CTI and vector DBs if they are missing.
- Wazuh and Suricata data is persisted to Docker volumes and mounted host paths for alert replay/inspection.
- Secrets live in `.env`; `.env` is never committed.

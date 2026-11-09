# Docker deployment notes

The root `docker-compose.yml` defines these services:

- `medflow`: Python application, FastAPI health/webhook endpoints, investigators, collectors, and response workflow.
- `wazuh.manager`, `wazuh.indexer`, and `wazuh.dashboard`: the optional Wazuh services described by the root Compose file.
- `suricata`: a separate IDS container configured for Linux host networking.

The user-maintained Windows SSH lab and its dedicated sensor may use separate Compose projects that are not stored in this repository. The root Compose file does not define an SSH target or a MISP service. Do not assume Compose service names or networking are shared across projects; verify the actual Docker network and configured endpoints.

## Safe app-only operation

After the approved telemetry services are running and reachable, validate configuration with `docker compose config --quiet`. To build/start only the app service without touching its dependencies:

```powershell
docker compose up -d --build --no-deps medflow
```

The container health check is `GET /health` on port `8000`. The root Compose file mounts `suricata/lab-logs` read-only at `/app/suricata/lab-logs` and sets `SURICATA_EVE_PATH` to the mounted EVE file. Suricata host networking in the root file is intended for Linux; Docker Desktop on Windows does not provide equivalent packet capture.

The app startup script downloads MITRE CTI data and builds vector indexes when their volumes are empty. Avoid recreating a populated app container casually: the Compose file persists the cache, vector DBs, MITRE subdirectory, and logs, but the incident SQLite store and collector checkpoints default elsewhere under `/app/data` and currently lack an explicit persistent mount.

## Configuration and security

- Store credentials in a local `.env`, based on `.env.example`; never commit that file.
- Compose requires Wazuh API, Indexer, and Dashboard passwords as explicitly configured values; it has no password defaults.
- Keep Wazuh/MISP certificate verification enabled. Mount a private CA certificate read-only and use its in-container path if the system trust store does not recognize it.
- Treat raw EVE records, SQLite incidents/outbox, and checkpoints as sensitive local data.
- Do not expose the unauthenticated webhook beyond a trusted lab network.
- The CLI executor is dry-run. Containment requires an explicit human decision; live connector scope and rollback remain pending review.

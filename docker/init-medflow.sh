#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/app"
mkdir -p "$APP_DIR/logs" "$APP_DIR/.cache/huggingface" "$APP_DIR/vector_dbs"

if [ ! -d "$APP_DIR/data/mitre-cti/.git" ] && [ ! -f "$APP_DIR/data/mitre-cti/enterprise-attack/enterprise-attack.json" ]; then
  echo "MITRE CTI data missing; downloading..."
  python "$APP_DIR/scripts/download_mitre.py"
fi

if [ ! -d "$APP_DIR/vector_dbs/attack_db" ] || [ ! -d "$APP_DIR/vector_dbs/redteam_db" ] || [ ! -d "$APP_DIR/vector_dbs/actor_db" ] || [ ! -d "$APP_DIR/vector_dbs/detection_db" ]; then
  echo "Vector database folders missing; generating..."
  python "$APP_DIR/scripts/build_attack_db.py"
  python "$APP_DIR/scripts/build_redteam_db.py"
  python "$APP_DIR/scripts/build_actor_db.py"
  python "$APP_DIR/scripts/build_detection_db.py"
fi

python "$APP_DIR/app.py" status || true
exec python -m uvicorn api:app --host 0.0.0.0 --port 8000

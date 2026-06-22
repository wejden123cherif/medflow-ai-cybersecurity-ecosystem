from __future__ import annotations

import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from config import ACTOR_DB_DIR, ENTERPRISE_ATTACK_JSON, ensure_project_dirs, load_settings
from rag.pipeline import actor_documents, build_collection, load_mitre_bundle


def main() -> None:
    ensure_project_dirs()
    settings = load_settings()
    bundle = load_mitre_bundle(ENTERPRISE_ATTACK_JSON)
    count = build_collection(ACTOR_DB_DIR, actor_documents(bundle), settings.embedding_model)
    print(f"Built actor_db: {count} documents")


if __name__ == "__main__":
    main()

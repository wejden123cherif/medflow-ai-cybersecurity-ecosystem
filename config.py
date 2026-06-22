from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_args, **_kwargs) -> bool:
        return False


ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
MITRE_CTI_DIR = DATA_DIR / "mitre-cti"
VECTOR_DB_DIR = ROOT_DIR / "vector_dbs"
MODEL_CACHE_DIR = ROOT_DIR / ".cache" / "huggingface"

ATTACK_DB_DIR = VECTOR_DB_DIR / "attack_db"
REDTEAM_DB_DIR = VECTOR_DB_DIR / "redteam_db"
ACTOR_DB_DIR = VECTOR_DB_DIR / "actor_db"
DETECTION_DB_DIR = VECTOR_DB_DIR / "detection_db"

ENTERPRISE_ATTACK_JSON = MITRE_CTI_DIR / "enterprise-attack" / "enterprise-attack.json"

os.environ.setdefault("HF_HOME", str(MODEL_CACHE_DIR))
os.environ.setdefault("SENTENCE_TRANSFORMERS_HOME", str(MODEL_CACHE_DIR / "sentence-transformers"))


@dataclass(frozen=True)
class Settings:
    groq_api_key: str | None
    main_model: str
    secondary_model: str
    embedding_model: str


def resolve_embedding_model(model_name: str) -> str:
    cache_repo = MODEL_CACHE_DIR / "sentence-transformers" / f"models--{model_name.replace('/', '--')}"
    snapshots_dir = cache_repo / "snapshots"
    if snapshots_dir.exists():
        snapshots = [path for path in snapshots_dir.iterdir() if path.is_dir()]
        if snapshots:
            return str(sorted(snapshots, key=lambda path: path.stat().st_mtime, reverse=True)[0])
    return model_name


def load_settings() -> Settings:
    load_dotenv(ROOT_DIR / ".env")
    embedding_model = os.getenv("MEDFLOW_EMBEDDING_MODEL", "BAAI/bge-base-en-v1.5")
    return Settings(
        groq_api_key=os.getenv("GROQ_API_KEY") or None,
        main_model=os.getenv("GROQ_MAIN_MODEL", "qwen/qwen3-32b"),
        secondary_model=os.getenv("GROQ_SECONDARY_MODEL", "llama-3.1-8b-instant"),
        embedding_model=resolve_embedding_model(embedding_model),
    )


def ensure_project_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    VECTOR_DB_DIR.mkdir(exist_ok=True)
    MODEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for db_dir in (ATTACK_DB_DIR, REDTEAM_DB_DIR, ACTOR_DB_DIR, DETECTION_DB_DIR):
        db_dir.mkdir(parents=True, exist_ok=True)
